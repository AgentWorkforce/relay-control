import type { IncomingMessage, ServerResponse } from "node:http";
import { z } from "zod";
import { hashSecret } from "../../crypto.js";
import type { ControlPlaneStore } from "../../store.js";
import { clientIp, cookieRequestAllowed, forwardedForUntrusted, limiterKey, RateLimiter } from "../../auth/device-approval.js";
import { emailDomain, normalizeEmailAddress, type PasswordConfig } from "../config.js";
import {
  accountLockedEmail,
  passwordAddedEmail,
  passwordAlreadyRegisteredEmail,
  passwordChangedEmail,
  passwordResetEmail,
  passwordVerifyEmail,
  type Mailer,
} from "../mailer.js";
import { IdentityError, type IdentityStore, type SignInResult } from "../store.js";
import { HasherBusy, type PasswordHasher, type StoredPassword } from "./hashing.js";
import { checkPasswordPolicy, hibpCheck, POLICY_MESSAGES, type HibpFetch } from "./policy.js";
import {
  accountKeySubject,
  accountSubject,
  CredentialChanged,
  ipSubject,
  LOCKOUT,
  REGISTRATION_TTL_MS,
  RESET_TTL_MS,
  SetupRefused,
  type Lock,
  type PasswordStore,
} from "./store.js";

/**
 * Email + password sign-in API (docs/identity.md, "Password sign-in"):
 *
 *   POST /api/v1/auth/password/register        {email, invite?} -> 202, always (verification email)
 *   POST /api/v1/auth/password/verify          {token} -> 200 {setupToken} (sh_ps_, 15 minutes)
 *   POST /api/v1/auth/password/set             {token, password} -> 200 + session cookie
 *   POST /api/v1/auth/password/login           200 + session cookie | 401 invalid_credentials
 *   POST /api/v1/auth/password/reset           202, always
 *   POST /api/v1/auth/password/reset/complete  200 (every session and pending grant revoked)
 *
 * The emailed links open server pages instead (/login/password/verify and
 * /login/password/reset, token in the URL fragment); identity/routes.ts
 * serves them through the form* functions below.
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
  // Registration and reset mail have separate buckets, so asking for one
  // never uses up the other.
  mailRegisterPerIp: { limit: 10, windowMs: 10 * 60 * 1_000 },
  mailRegisterPerAddress: { limit: 3, windowMs: 10 * 60 * 1_000 },
  mailResetPerIp: { limit: 10, windowMs: 10 * 60 * 1_000 },
  mailResetPerAddress: { limit: 3, windowMs: 10 * 60 * 1_000 },
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
const SetPassword = z.object({ token: Token, password: Secret }).strict();
const ResetRequest = z.object({ email: z.string().max(320) }).strict();
const ResetComplete = z.object({ token: Token, password: Secret }).strict();
const INVITE_TOKEN = /^sh_inv_[A-Za-z0-9_-]{20,200}$/;
const TOKEN_GONE = "This link has expired or was already used. Register again.";
const ALREADY_SET = "This address already has a password. Sign in, or reset the password instead.";
const RESET_GONE = "This reset link has expired or was already used. Request a new one.";
const BUSY = "The server is busy. Try again in a moment.";

/** Every argon2id slot is busy: answer at once, without hashing. */
function busy(): IdentityError {
  return new IdentityError(429, "rate_limited", BUSY);
}

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
  /** Server pages that the emailed links open (fragment carries the token). */
  pageOrigin?: string;
  /** Test seam for the Have I Been Pwned range API. */
  hibpFetch?: HibpFetch;
  now?: () => number;
  log: (message: string, fields?: Record<string, unknown>) => void;
};

export type PasswordRouteHelpers = {
  requestObject: (request: IncomingMessage) => Promise<Record<string, unknown>>;
  siteBaseUrl: (request: IncomingMessage) => string;
  browserOrigins: readonly string[];
};

export type PasswordRoutes = {
  handle(request: IncomingMessage, response: ServerResponse, path: string, helpers: PasswordRouteHelpers): Promise<boolean>;
  /**
   * The /login page form: the same checks, lockout and audit as the JSON
   * login. Null means refused (the caller shows the generic message).
   */
  formLogin(request: IncomingMessage, input: { email: string; password: string; invite: string | null }): Promise<SignInResult | null>;
  /**
   * The /login/password/verify page: redeems a verification link (sh_pv_)
   * and sets the first password. Throws PasswordHttpError or IdentityError.
   */
  formCompleteRegistration(request: IncomingMessage, input: { token: string; password: string }, siteName: string): Promise<SignInResult>;
  /** The /login/password/reset page without a token: the same as POST .../reset. */
  formResetRequest(request: IncomingMessage, email: string, siteName: string): void;
  /** The /login/password/reset page with a token. Throws PasswordHttpError or IdentityError. */
  formCompleteReset(request: IncomingMessage, input: { token: string; password: string }, siteName: string): Promise<Revoked>;
  /** Retention sweep (see PasswordStore.sweep). */
  sweep(): Promise<void>;
  /** Resolves when background mail work (register, reset) has finished. */
  idle(): Promise<void>;
};

export type Revoked = { sessions: number; mcpGrants: number; desktopRelayIdentities: number; deviceAuthorizations: number; mcpCodes: number };

export function createPasswordRoutes(input: PasswordRoutesInput): PasswordRoutes {
  const { hasher, passwords, identityStore, controlStore, mailer, log } = input;
  const pageOrigin = input.pageOrigin ?? input.dashboardOrigin;
  const resetPage = `${pageOrigin}/login/password/reset`;
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
        if (limited(`personal-org-addr:${email}`, RATE.personalOrgPerAddress) || limited(`personal-org-ip:${limiterKey(clientIp(request))}`, RATE.personalOrgPerIp)) {
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
   * One audit event per lock this attempt started or extended (attempts
   * refused inside a lock write nothing). An account-wide lock also emails
   * the owner, at most once a day.
   */
  async function lockEngaged(lock: Lock, email: string | null, ip: string, userId: string | null, siteName: string): Promise<void> {
    const until = lock.until.toISOString();
    if (lock.subject.startsWith("account-key:")) {
      await audit(userId, "login.lockout", `scope=account_key email=${email} ip=${ip} until=${until}`);
    } else if (lock.subject.startsWith("account:")) {
      await audit(userId, "login.lockout", `scope=account email=${email} until=${until}`);
      const to = email!;
      later("account lockout notice", async () => {
        if (!await passwords.claimLockoutNotice(to)) return;
        await mailer.send(accountLockedEmail({ to, url: resetPage, siteName }));
      });
    } else {
      await audit(userId, "login.lockout", `scope=ip ip=${ip} until=${until}`);
    }
  }

  /**
   * One password attempt. A per-IP in-memory limit comes first (429), and
   * a 429 when every argon2id slot is busy; then the attempt is reserved
   * against three counters (refused outright, with no audit row, inside a
   * lock): the account and client key, the account across all clients, and
   * the client key across all accounts (skipped while X-Forwarded-For
   * cannot be trusted, see clientIp). Then it is checked. An unknown address
   * and a wrong password both cost one argon2id verification, so neither the
   * answer nor its timing separates them. A locked attempt skips argon2id:
   * whether a lock is in force is not an account secret, and skipping it
   * keeps a locked flood cheap.
   */
  async function attempt(
    request: IncomingMessage,
    rawEmail: string,
    password: string,
    inviteTokenHash: string | null,
    siteName: string,
  ): Promise<SignInResult | null> {
    // The full address goes into audit records; limits use its key (IPv6 /64).
    const ip = clientIp(request).slice(0, 64);
    const key = limiterKey(ip);
    if (limited(`pw-login-ip:${key}`, RATE.loginPerIp)) {
      throw new IdentityError(429, "rate_limited", "Too many sign-in attempts. Try again in a minute.");
    }
    if (!hasher.hasCapacity) throw busy();
    const email = normalizeEmailAddress(rawEmail);
    // Behind an unconfigured proxy every client has the proxy's address, so
    // an IP lock would lock everyone; it is skipped until the setting is
    // fixed (the account rules still apply).
    const ipRule = forwardedForUntrusted(request) ? [] : [{ subject: ipSubject(key), rule: LOCKOUT.ip }];
    const rules = [
      ...ipRule,
      ...(email ? [
        { subject: accountKeySubject(email, key), rule: LOCKOUT.accountKey },
        { subject: accountSubject(email), rule: LOCKOUT.account },
      ] : []),
    ];
    const [reservation, credential] = await Promise.all([
      passwords.reserveAttempt(rules),
      email ? passwords.credentialByEmail(email) : Promise.resolve(null),
    ]);
    if (!reservation.allowed) return null;
    for (const lock of reservation.locks) await lockEngaged(lock, email, ip, credential?.userId ?? null, siteName);
    const fail = async (reason: string) => {
      await audit(credential?.userId ?? null, "login.password.failure", `email=${email ?? "invalid"} ip=${ip} reason=${reason}`);
      return null;
    };
    let outcome: { ok: boolean; needsRehash: boolean };
    try {
      if (!credential) {
        await hasher.dummyVerify(password);
        return fail(email ? "unknown_account" : "invalid_email");
      }
      outcome = await hasher.verify(password, credential);
    } catch (error) {
      if (error instanceof HasherBusy) throw busy();
      throw error;
    }
    if (!outcome.ok) return fail("wrong_password");
    let result: SignInResult;
    try {
      // Inside the sign-in transaction, which holds the identity lock a
      // reset also takes: the hash must still be the one just verified, or
      // the session rolls back (see PasswordStore.completeReset).
      result = await signInFor(request, email!, inviteTokenHash, (tx, userId) => passwords.assertCredentialUnchanged(tx, userId, credential.hash));
    } catch (error) {
      if (error instanceof CredentialChanged) return fail("credential_changed");
      throw error;
    }
    await passwords.clearSubject(passwords.executor, accountKeySubject(email!, key));
    await passwords.clearSubject(passwords.executor, accountSubject(email!));
    if (ipRule.length) await passwords.refundAttempt(ipSubject(key), LOCKOUT.ip);
    let rehashed = false;
    if (outcome.needsRehash) {
      // Parameters were raised or the pepper rotated: upgrade while the
      // plaintext is at hand. A concurrent change wins (compare-and-set).
      // Skipped when the hasher is busy; the next sign-in tries again.
      try {
        rehashed = await passwords.rehash(credential.userId, credential.hash, await hasher.hash(password));
      } catch (error) {
        if (!(error instanceof HasherBusy)) throw error;
      }
    }
    await audit(result.userId, "login.password.success", `email=${email} ip=${ip}${rehashed ? " rehashed=true" : ""}`);
    return result;
  }

  async function login(request: IncomingMessage, response: ServerResponse, body: z.infer<typeof Login>, siteName: string): Promise<void> {
    const result = await attempt(request, body.email, body.password, null, siteName);
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
    const key = limiterKey(clientIp(request));
    if (!limited(`pw-mail-register-ip:${key}`, RATE.mailRegisterPerIp) && !limited(`pw-mail-register-addr:${email}`, RATE.mailRegisterPerAddress)) {
      later("password registration", async () => {
        if (!await identityStore.passwordRegistrationEligible(email)) return;
        if (await passwords.credentialByEmail(email)) {
          await mailer.send(passwordAlreadyRegisteredEmail({ to: email, url: resetPage, siteName }));
          return;
        }
        const token = await passwords.createRegistration({ email, inviteTokenHash: invite ? hashSecret(invite) : null });
        await mailer.send(passwordVerifyEmail({
          to: email,
          // In the fragment: never sent to a server, so never in an access log.
          url: `${pageOrigin}/login/password/verify#token=${encodeURIComponent(token)}`,
          siteName,
          expiresInMinutes: REGISTRATION_TTL_MS / 60_000,
        }));
      });
    }
    // The same answer whether or not the address may register.
    sendJson(response, 202, { status: "verification_sent" });
  }

  function tokenLimit(request: IncomingMessage): void {
    if (limited(`pw-token-ip:${limiterKey(clientIp(request))}`, RATE.tokenPerIp)) {
      throw new PasswordHttpError(429, "rate_limited", "Too many attempts. Try again in a few minutes.");
    }
  }

  async function redeemRegistration(token: string): Promise<{ email: string; setupToken: string; expiresAt: Date }> {
    const verified = await passwords.verifyRegistration(token);
    if (!verified) throw new PasswordHttpError(410, "token_invalid", TOKEN_GONE);
    if ("refused" in verified) throw new PasswordHttpError(409, "password_already_set", ALREADY_SET);
    await audit(null, "password.registration.verified", `email=${verified.email}`);
    return verified;
  }

  async function verify(request: IncomingMessage, response: ServerResponse, body: z.infer<typeof TokenOnly>): Promise<void> {
    tokenLimit(request);
    const verified = await redeemRegistration(body.token);
    sendJson(response, 200, { status: "verified", email: verified.email, setupToken: verified.setupToken, expiresAt: verified.expiresAt.toISOString() });
  }

  async function hashOrBusy(password: string): Promise<StoredPassword> {
    try {
      return await hasher.hash(password);
    } catch (error) {
      if (error instanceof HasherBusy) throw new PasswordHttpError(429, "rate_limited", BUSY);
      throw error;
    }
  }

  /**
   * Spends a set-password token, creates the account if needed and writes
   * the first credential, all in the sign-in transaction; then tells the
   * address a password was added.
   */
  async function finishRegistration(
    request: IncomingMessage,
    setupToken: string,
    setup: { email: string; inviteTokenHash: string | null },
    stored: StoredPassword,
    siteName: string,
  ): Promise<SignInResult> {
    let result: SignInResult;
    try {
      // Spending the token, creating the account and writing the credential
      // commit together or not at all.
      result = await signInFor(request, setup.email, setup.inviteTokenHash, async (tx, userId) => {
        await passwords.redeemSetup(tx, setupToken, userId, stored);
        await passwords.clearAccount(tx, setup.email);
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
    const to = setup.email;
    later("password added notice", async () => {
      await mailer.send(passwordAddedEmail({ to, url: resetPage, siteName }));
    });
    return result;
  }

  async function setPassword(request: IncomingMessage, response: ServerResponse, body: z.infer<typeof SetPassword>, siteName: string): Promise<void> {
    tokenLimit(request);
    const setup = await passwords.peekSetup(body.token);
    if (!setup) throw new PasswordHttpError(410, "token_invalid", TOKEN_GONE);
    await policyOrThrow(body.password, setup.email);
    const stored = await hashOrBusy(body.password);
    signedIn(response, await finishRegistration(request, body.token, setup, stored, siteName));
  }

  async function completeRegistration(request: IncomingMessage, form: { token: string; password: string }, siteName: string): Promise<SignInResult> {
    tokenLimit(request);
    // Checked before the link is spent, so a rejected password can be retried.
    const pending = await passwords.peekRegistration(form.token);
    if (!pending) throw new PasswordHttpError(410, "token_invalid", TOKEN_GONE);
    await policyOrThrow(form.password, pending.email);
    const stored = await hashOrBusy(form.password);
    const verified = await redeemRegistration(form.token);
    const setup = await passwords.peekSetup(verified.setupToken);
    if (!setup) throw new PasswordHttpError(410, "token_invalid", TOKEN_GONE);
    return finishRegistration(request, verified.setupToken, setup, stored, siteName);
  }

  function requestReset(request: IncomingMessage, rawEmail: string, siteName: string): void {
    const email = normalizeEmailAddress(rawEmail);
    const ip = clientIp(request).slice(0, 64);
    const key = limiterKey(ip);
    if (!email || limited(`pw-mail-reset-ip:${key}`, RATE.mailResetPerIp) || limited(`pw-mail-reset-addr:${email}`, RATE.mailResetPerAddress)) return;
    later("password reset request", async () => {
      const created = await passwords.createReset(email);
      if (!created) return;
      await passwords.audit({ userId: created.userId, action: "password.reset.requested", target: `email=${email} ip=${ip}` });
      await mailer.send(passwordResetEmail({
        to: email,
        url: `${resetPage}#token=${encodeURIComponent(created.token)}`,
        siteName,
        expiresInMinutes: RESET_TTL_MS / 60_000,
      }));
    });
  }

  async function resetRequest(request: IncomingMessage, response: ServerResponse, body: z.infer<typeof ResetRequest>, siteName: string): Promise<void> {
    requestReset(request, body.email, siteName);
    // Identical for unknown, malformed, rate-limited and real addresses.
    sendJson(response, 202, { status: "reset_requested" });
  }

  async function finishReset(request: IncomingMessage, form: { token: string; password: string }, siteName: string): Promise<Revoked> {
    tokenLimit(request);
    const owner = await passwords.peekReset(form.token);
    if (!owner) throw new PasswordHttpError(410, "token_invalid", RESET_GONE);
    await policyOrThrow(form.password, owner.email);
    const stored = await hashOrBusy(form.password);
    let revoked: Revoked = { sessions: 0, mcpGrants: 0, desktopRelayIdentities: 0, deviceAuthorizations: 0, mcpCodes: 0 };
    const completed = await passwords.completeReset(form.token, stored, async (tx, userId) => {
      // One transaction: every session, MCP grant and Desktop relay identity
      // token ends, and nothing the person approved but nobody collected yet
      // can still be redeemed.
      const sessions = await controlStore.revokeAllForUser(tx, userId, "password_reset");
      const pending = await controlStore.voidPendingAuthorizationsForUser(tx, userId);
      revoked = { ...sessions, ...pending };
    });
    if (!completed) throw new PasswordHttpError(410, "token_invalid", RESET_GONE);
    await passwords.audit({
      userId: completed.userId,
      action: "password.reset.completed",
      target: `email=${completed.email} sessions_revoked=${revoked.sessions} mcp_grants_revoked=${revoked.mcpGrants} desktop_relay_identities_deleted=${revoked.desktopRelayIdentities} device_authorizations_expired=${revoked.deviceAuthorizations} mcp_codes_voided=${revoked.mcpCodes}`,
    });
    const to = completed.email;
    later("password changed notice", async () => {
      await mailer.send(passwordChangedEmail({ to, url: resetPage, siteName }));
    });
    return revoked;
  }

  async function resetComplete(request: IncomingMessage, response: ServerResponse, body: z.infer<typeof ResetComplete>, siteName: string): Promise<void> {
    const revoked = await finishReset(request, body, siteName);
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
      if (route === "login") await login(request, response, parse(Login, raw), siteName);
      else if (route === "register") await register(request, response, parse(Register, raw), siteName);
      else if (route === "verify") await verify(request, response, parse(TokenOnly, raw));
      else if (route === "set") await setPassword(request, response, parse(SetPassword, raw), siteName);
      else if (route === "reset") await resetRequest(request, response, parse(ResetRequest, raw), siteName);
      else await resetComplete(request, response, parse(ResetComplete, raw), siteName);
      return true;
    },
    async formLogin(request, form) {
      const invite = form.invite && INVITE_TOKEN.test(form.invite) ? hashSecret(form.invite) : null;
      return attempt(request, form.email.slice(0, 320), form.password.slice(0, 1_024), invite, new URL(pageOrigin).host);
    },
    async formCompleteRegistration(request, form, siteName) {
      return completeRegistration(request, { token: form.token.slice(0, 256), password: form.password.slice(0, 1_024) }, siteName);
    },
    formResetRequest(request, email, siteName) {
      requestReset(request, email.slice(0, 320), siteName);
    },
    async formCompleteReset(request, form, siteName) {
      return finishReset(request, { token: form.token.slice(0, 256), password: form.password.slice(0, 1_024) }, siteName);
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
