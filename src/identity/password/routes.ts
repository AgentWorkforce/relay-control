import type { IncomingMessage, ServerResponse } from "node:http";
import { z } from "zod";
import { hashSecret } from "../../crypto.js";
import { ACCOUNT_SCOPE, type ControlPlaneStore, type Principal } from "../../store.js";
import { clientIp, cookieRequestAllowed, RateLimiter } from "../../auth/device-approval.js";
import { emailDomain, normalizeEmailAddress, type PasswordConfig } from "../config.js";
import { passwordAlreadyRegisteredEmail, passwordResetEmail, passwordVerifyEmail, type Mailer } from "../mailer.js";
import { IdentityError, type IdentityStore, type SignInResult } from "../store.js";
import type { PasswordHasher } from "./hashing.js";
import { checkPasswordPolicy, hibpCheck, POLICY_MESSAGES, type HibpFetch } from "./policy.js";
import {
  accountSubject,
  ipSubject,
  LOCKOUT,
  REGISTRATION_TTL_MS,
  RESET_TTL_MS,
  SetupRefused,
  type PasswordStore,
} from "./store.js";

/**
 * Email + password sign-in API (docs/identity.md, "Password sign-in"):
 *
 *   POST /api/v1/auth/password/register        {email, invite?} -> 202, always (verification email)
 *   POST /api/v1/auth/password/verify          {token} -> 200 {setupToken} (sh_ps_, 15 minutes)
 *   POST /api/v1/auth/password/set             {token, password} -> 200 + session cookie
 *                                              {password} + account session -> 200 (first password)
 *   POST /api/v1/auth/password/login           200 + session cookie | 401 invalid_credentials
 *   POST /api/v1/auth/password/reset           202, always
 *   POST /api/v1/auth/password/reset/complete  200 (every session and pending grant revoked)
 *
 * With password sign-in disabled each answers 404 signin_method_disabled.
 * Nothing here logs a password, a pepper or a token.
 */

export const PASSWORD_PATH_PREFIX = "/api/v1/auth/password/";

export class PasswordHttpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

const INVALID_CREDENTIALS = "Incorrect email or password.";
const RATE = {
  mailPerIp: { limit: 10, windowMs: 10 * 60 * 1_000 },
  mailPerAddress: { limit: 3, windowMs: 10 * 60 * 1_000 },
  tokenPerIp: { limit: 30, windowMs: 5 * 60 * 1_000 },
  /** In-memory, in front of the Postgres lockout: bounds DB and argon2id work per IP. */
  loginPerIp: { limit: 60, windowMs: 60 * 1_000 },
  personalOrgPerAddress: { limit: 3, windowMs: 60 * 60 * 1_000 },
  personalOrgPerIp: { limit: 10, windowMs: 60 * 60 * 1_000 },
};

// Bounded so a huge body cannot buy extra hashing work; the policy caps
// passwords at 128 code points, so a longer one is simply never valid.
const Secret = z.string().max(1_024);
const Login = z.object({ email: z.string().max(320), password: Secret }).strict();
const Token = z.string().max(256);
const Register = z.object({ email: z.string().max(320), invite: Token.optional() }).strict();
const TokenOnly = z.object({ token: Token }).strict();
const SetPassword = z.object({ token: Token.optional(), password: Secret }).strict();
const ResetRequest = z.object({ email: z.string().max(320) }).strict();
const ResetComplete = z.object({ token: Token, password: Secret }).strict();
const INVITE_TOKEN = /^sh_inv_[A-Za-z0-9_-]{20,200}$/;
const TOKEN_GONE = "This link has expired or was already used. Register again.";
const ALREADY_SET = "This address already has a password. Sign in, or reset the password instead.";

function parse<T>(schema: z.ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new PasswordHttpError(400, "invalid_request", issue ? `${issue.path.join(".") || "body"}: ${issue.message}` : "Invalid request body");
  }
  return parsed.data;
}

function sendJson(response: ServerResponse, status: number, body: unknown, cookies: string[] = []): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...(cookies.length ? { "set-cookie": cookies } : {}),
  });
  response.end(JSON.stringify(body));
}

export function disabledMethod(response: ServerResponse, method: "password" | "email_link"): void {
  sendJson(response, 404, {
    error: "signin_method_disabled",
    message: method === "password" ? "Password sign-in is not enabled on this installation." : "Email sign-in links are not enabled on this installation.",
  });
}

export type PasswordRoutesInput = {
  config: PasswordConfig;
  hasher: PasswordHasher;
  passwords: PasswordStore;
  identityStore: IdentityStore;
  controlStore: ControlPlaneStore;
  mailer: Mailer;
  dashboardOrigin: string;
  sessionCookie: (tokens: SignInResult["tokens"]) => string;
  clearSessionCookie: () => string;
  /** Test seam for the Have I Been Pwned range API. */
  hibpFetch?: HibpFetch;
  now?: () => number;
  log: (message: string, fields?: Record<string, unknown>) => void;
};

export type PasswordRouteHelpers = {
  requestObject: (request: IncomingMessage) => Promise<Record<string, unknown>>;
  siteBaseUrl: (request: IncomingMessage) => string;
  browserOrigins: readonly string[];
  /** Resolves the bearer or session cookie; throws 401 without one. */
  authenticate: (request: IncomingMessage) => Promise<{ kind: "bootstrap" } | { kind: "user"; principal: Principal }>;
};

export type PasswordRoutes = {
  handle(request: IncomingMessage, response: ServerResponse, path: string, helpers: PasswordRouteHelpers): Promise<boolean>;
  /**
   * The /login page form: the same checks, lockout and audit as the JSON
   * login. Null means refused (the caller shows the generic message).
   */
  formLogin(request: IncomingMessage, input: { email: string; password: string; invite: string | null }): Promise<SignInResult | null>;
  /** Retention sweep (see PasswordStore.sweep). */
  sweep(): Promise<void>;
  /** Resolves when background mail work (register, reset) has finished. */
  idle(): Promise<void>;
};

export function createPasswordRoutes(input: PasswordRoutesInput): PasswordRoutes {
  const { hasher, passwords, identityStore, controlStore, mailer, log } = input;
  const limiter = new RateLimiter(() => input.now?.() ?? Date.now());
  const background = new Set<Promise<void>>();
  // Compute the dummy hash now so the first unknown-account login is not slower.
  void hasher.dummyVerify("warm-up").catch(() => undefined);

  function limited(key: string, rule: { limit: number; windowMs: number }): boolean {
    return !limiter.consume(key, rule.limit, rule.windowMs).allowed;
  }

  /** Runs mail work after the response so its timing reveals nothing. */
  function later(label: string, work: () => Promise<void>): void {
    const task = work().catch((error: unknown) => {
      log(`${label} failed`, { error: error instanceof Error ? error.message : String(error) });
    }).finally(() => background.delete(task));
    background.add(task);
  }

  async function policyOrThrow(password: string, email: string): Promise<void> {
    const violation = checkPasswordPolicy(password, email);
    if (violation) throw new PasswordHttpError(400, violation, POLICY_MESSAGES[violation]);
    if (!input.config.hibp) return;
    const result = await hibpCheck(password, input.hibpFetch ? { fetch: input.hibpFetch } : {});
    if (result === "breached") throw new PasswordHttpError(400, "password_breached", POLICY_MESSAGES.password_breached);
    if (result === "unavailable") {
      // Fail open: the bundled list still applied. Recorded for the operator.
      await passwords.audit({ userId: null, action: "password.hibp.unavailable", target: `domain=${emailDomain(email)}` });
    }
  }

  async function signInFor(
    request: IncomingMessage,
    email: string,
    inviteTokenHash: string | null,
    onSignedIn?: (tx: Parameters<PasswordStore["redeemSetup"]>[0], userId: string) => Promise<void>,
  ): Promise<SignInResult> {
    return identityStore.signIn({
      email,
      name: null,
      inviteTokenHash,
      ...(onSignedIn ? { onSignedIn } : {}),
      method: "password",
      emailVerified: true,
      beforePersonalOrganization: () => {
        if (limited(`personal-org-addr:${email}`, RATE.personalOrgPerAddress) || limited(`personal-org-ip:${clientIp(request)}`, RATE.personalOrgPerIp)) {
          throw new IdentityError(429, "rate_limited", "Too many new organizations were created. Try again later.");
        }
      },
    });
  }

  function signedIn(response: ServerResponse, result: SignInResult): void {
    sendJson(response, 200, {
      userId: result.userId,
      email: result.email,
      organizationId: result.organizationId,
      workspaceId: result.workspaceId,
    }, [input.sessionCookie(result.tokens)]);
  }

  async function audit(userId: string | null, action: string, target: string): Promise<void> {
    await passwords.audit({ userId, action, target });
  }

  /**
   * One password attempt. A per-IP in-memory limit comes first (429), then
   * the attempt is reserved against the account and IP counters (refused
   * outright inside a lock), then checked. An unknown address and a wrong
   * password both cost one argon2id verification, so neither the answer nor
   * its timing separates them. A locked attempt skips argon2id: whether a
   * lock is in force is not an account secret (the lock follows from the
   * caller's own attempts), and skipping it keeps a locked flood cheap.
   */
  async function attempt(request: IncomingMessage, rawEmail: string, password: string, inviteTokenHash: string | null): Promise<SignInResult | null> {
    const ip = clientIp(request).slice(0, 64);
    if (limited(`pw-login-ip:${ip}`, RATE.loginPerIp)) {
      throw new IdentityError(429, "rate_limited", "Too many sign-in attempts. Try again in a minute.");
    }
    const email = normalizeEmailAddress(rawEmail);
    const rules = [{ subject: ipSubject(ip), rule: LOCKOUT.ip }, ...(email ? [{ subject: accountSubject(email), rule: LOCKOUT.account }] : [])];
    const [reservation, credential] = await Promise.all([
      passwords.reserveAttempt(rules),
      email ? passwords.credentialByEmail(email) : Promise.resolve(null),
    ]);
    const fail = async (reason: string) => {
      if (reservation.allowed) {
        for (const lock of reservation.locks) {
          const kind = lock.subject.startsWith("account:") ? "account" : "ip";
          await audit(credential?.userId ?? null, "login.lockout",
            `scope=${kind} ${kind === "account" ? `email=${email}` : `ip=${ip}`} until=${lock.until.toISOString()}`);
        }
      }
      await audit(credential?.userId ?? null, "login.password.failure", `email=${email ?? "invalid"} ip=${ip} reason=${reason}`);
      return null;
    };
    if (!reservation.allowed) return fail("locked");
    if (!credential) {
      await hasher.dummyVerify(password);
      return fail(email ? "unknown_account" : "invalid_email");
    }
    const outcome = await hasher.verify(password, credential);
    if (!outcome.ok) return fail("wrong_password");
    const result = await signInFor(request, email!, inviteTokenHash);
    await passwords.clearSubject(passwords.executor, accountSubject(email!));
    await passwords.refundAttempt(ipSubject(ip), LOCKOUT.ip);
    if (outcome.needsRehash) {
      // Parameters were raised or the pepper rotated: upgrade while the
      // plaintext is at hand. A concurrent change wins (compare-and-set).
      await passwords.rehash(credential.userId, credential.hash, await hasher.hash(password));
    }
    await audit(result.userId, "login.password.success", `email=${email} ip=${ip}${outcome.needsRehash ? " rehashed=true" : ""}`);
    return result;
  }

  async function login(request: IncomingMessage, response: ServerResponse, body: z.infer<typeof Login>): Promise<void> {
    const result = await attempt(request, body.email, body.password, null);
    if (!result) {
      sendJson(response, 401, { error: "invalid_credentials", message: INVALID_CREDENTIALS });
      return;
    }
    signedIn(response, result);
  }

  async function register(request: IncomingMessage, response: ServerResponse, body: z.infer<typeof Register>, siteName: string): Promise<void> {
    const email = normalizeEmailAddress(body.email);
    if (!email) throw new PasswordHttpError(400, "email_invalid", "That email address is not valid.");
    const invite = body.invite && INVITE_TOKEN.test(body.invite) ? body.invite : null;
    const ip = clientIp(request);
    if (!limited(`pw-mail-ip:${ip}`, RATE.mailPerIp) && !limited(`pw-mail-addr:${email}`, RATE.mailPerAddress)) {
      later("password registration", async () => {
        if (!await identityStore.passwordRegistrationEligible(email)) return;
        if (await passwords.credentialByEmail(email)) {
          await mailer.send(passwordAlreadyRegisteredEmail({ to: email, url: `${input.dashboardOrigin}/password/reset`, siteName }));
          return;
        }
        const token = await passwords.createRegistration({ email, inviteTokenHash: invite ? hashSecret(invite) : null });
        await mailer.send(passwordVerifyEmail({
          to: email,
          url: `${input.dashboardOrigin}/password/verify?token=${encodeURIComponent(token)}`,
          siteName,
          expiresInMinutes: REGISTRATION_TTL_MS / 60_000,
        }));
      });
    }
    // The same answer whether or not the address may register.
    sendJson(response, 202, { status: "verification_sent" });
  }

  function tokenLimit(request: IncomingMessage): void {
    if (limited(`pw-token-ip:${clientIp(request)}`, RATE.tokenPerIp)) {
      throw new PasswordHttpError(429, "rate_limited", "Too many attempts. Try again in a few minutes.");
    }
  }

  async function verify(request: IncomingMessage, response: ServerResponse, body: z.infer<typeof TokenOnly>): Promise<void> {
    tokenLimit(request);
    const verified = await passwords.verifyRegistration(body.token);
    if (!verified) throw new PasswordHttpError(410, "token_invalid", TOKEN_GONE);
    if ("refused" in verified) throw new PasswordHttpError(409, "password_already_set", ALREADY_SET);
    await audit(null, "password.registration.verified", `email=${verified.email}`);
    sendJson(response, 200, { status: "verified", email: verified.email, setupToken: verified.setupToken, expiresAt: verified.expiresAt.toISOString() });
  }

  async function setPassword(request: IncomingMessage, response: ServerResponse, body: z.infer<typeof SetPassword>, helpers: PasswordRouteHelpers): Promise<void> {
    tokenLimit(request);
    if (body.token !== undefined) {
      // Registration: the set-password token from verify.
      const setup = await passwords.peekSetup(body.token);
      if (!setup) throw new PasswordHttpError(410, "token_invalid", TOKEN_GONE);
      await policyOrThrow(body.password, setup.email);
      const stored = await hasher.hash(body.password);
      const token = body.token;
      let result: SignInResult;
      try {
        // Spending the token, creating the account and writing the credential
        // commit together or not at all.
        result = await signInFor(request, setup.email, setup.inviteTokenHash, async (tx, userId) => {
          await passwords.redeemSetup(tx, token, userId, stored);
          await passwords.clearSubject(tx, accountSubject(setup.email));
        });
      } catch (error) {
        if (error instanceof SetupRefused) {
          throw error.reason === "token_invalid"
            ? new PasswordHttpError(410, "token_invalid", TOKEN_GONE)
            : new PasswordHttpError(409, "password_already_set", ALREADY_SET);
        }
        throw error;
      }
      await audit(result.userId, "password.registration.completed", `email=${setup.email}`);
      signedIn(response, result);
      return;
    }
    // A signed-in person who has no password yet (they signed in with SSO or
    // an email link). Replacing an existing password is a reset.
    const auth = await helpers.authenticate(request);
    if (auth.kind !== "user") throw new PasswordHttpError(403, "reauthentication_required", "Sign in to the dashboard to set a password.");
    const principal = auth.principal;
    if (!principal.scopes.includes(ACCOUNT_SCOPE) || principal.pendingHandoff || principal.handoff) {
      throw new PasswordHttpError(403, "reauthentication_required", "Sign in to the dashboard to set a password.");
    }
    await policyOrThrow(body.password, principal.email);
    const stored = await hasher.hash(body.password);
    if (!await passwords.insertFirstCredential(passwords.executor, principal.userId, stored)) {
      throw new PasswordHttpError(409, "password_already_set", "You already have a password. Use reset to change it.");
    }
    await audit(principal.userId, "password.set", `email=${principal.email}`);
    sendJson(response, 200, { status: "password_set" });
  }

  async function resetRequest(request: IncomingMessage, response: ServerResponse, body: z.infer<typeof ResetRequest>, siteName: string): Promise<void> {
    const email = normalizeEmailAddress(body.email);
    const ip = clientIp(request);
    if (email && !limited(`pw-mail-ip:${ip}`, RATE.mailPerIp) && !limited(`pw-mail-addr:${email}`, RATE.mailPerAddress)) {
      later("password reset request", async () => {
        const created = await passwords.createReset(email);
        if (!created) return;
        await passwords.audit({ userId: created.userId, action: "password.reset.requested", target: `email=${email} ip=${ip.slice(0, 64)}` });
        await mailer.send(passwordResetEmail({
          to: email,
          url: `${input.dashboardOrigin}/password/reset?token=${encodeURIComponent(created.token)}`,
          siteName,
          expiresInMinutes: RESET_TTL_MS / 60_000,
        }));
      });
    }
    // Identical for unknown, malformed, rate-limited and real addresses.
    sendJson(response, 202, { status: "reset_requested" });
  }

  async function resetComplete(request: IncomingMessage, response: ServerResponse, body: z.infer<typeof ResetComplete>): Promise<void> {
    tokenLimit(request);
    const owner = await passwords.peekReset(body.token);
    if (!owner) throw new PasswordHttpError(410, "token_invalid", "This reset link has expired or was already used. Request a new one.");
    await policyOrThrow(body.password, owner.email);
    const stored = await hasher.hash(body.password);
    let revoked = { sessions: 0, mcpGrants: 0, deviceAuthorizations: 0, mcpCodes: 0 };
    const completed = await passwords.completeReset(body.token, stored, async (tx, userId) => {
      // One transaction: every session and MCP grant ends, and nothing the
      // person approved but nobody collected yet can still be redeemed.
      const sessions = await controlStore.revokeAllForUser(tx, userId, "password_reset");
      const pending = await controlStore.voidPendingAuthorizationsForUser(tx, userId);
      revoked = { ...sessions, ...pending };
    });
    if (!completed) throw new PasswordHttpError(410, "token_invalid", "This reset link has expired or was already used. Request a new one.");
    await passwords.audit({
      userId: completed.userId,
      action: "password.reset.completed",
      target: `email=${completed.email} sessions_revoked=${revoked.sessions} mcp_grants_revoked=${revoked.mcpGrants} device_authorizations_expired=${revoked.deviceAuthorizations} mcp_codes_voided=${revoked.mcpCodes}`,
    });
    sendJson(response, 200, { status: "password_reset", revoked }, [input.clearSessionCookie()]);
  }

  return {
    async handle(request, response, path, helpers) {
      if (!path.startsWith(PASSWORD_PATH_PREFIX)) return false;
      const route = path.slice(PASSWORD_PATH_PREFIX.length);
      if (!["login", "register", "verify", "set", "reset", "reset/complete"].includes(route)) return false;
      if (request.method !== "POST") throw new PasswordHttpError(405, "method_not_allowed", "Use POST");
      // Browser-only JSON: an allowed Origin (or same-origin fetch) and a JSON body.
      if (!cookieRequestAllowed(request, helpers.browserOrigins)) {
        throw new PasswordHttpError(403, "csrf_rejected", "Cross-origin request refused");
      }
      const raw = await helpers.requestObject(request);
      const siteName = new URL(helpers.siteBaseUrl(request)).host;
      if (route === "login") await login(request, response, parse(Login, raw));
      else if (route === "register") await register(request, response, parse(Register, raw), siteName);
      else if (route === "verify") await verify(request, response, parse(TokenOnly, raw));
      else if (route === "set") await setPassword(request, response, parse(SetPassword, raw), helpers);
      else if (route === "reset") await resetRequest(request, response, parse(ResetRequest, raw), siteName);
      else await resetComplete(request, response, parse(ResetComplete, raw));
      return true;
    },
    async formLogin(request, form) {
      const invite = form.invite && INVITE_TOKEN.test(form.invite) ? hashSecret(form.invite) : null;
      return attempt(request, form.email.slice(0, 320), form.password.slice(0, 1_024), invite);
    },
    async sweep() {
      const swept = await passwords.sweep();
      if (swept.attempts + swept.registrations + swept.setups + swept.resets > 0) log("password retention sweep", swept);
    },
    async idle() {
      while (background.size) await Promise.allSettled([...background]);
    },
  };
}
