import type { IncomingMessage, ServerResponse } from "node:http";
import { z } from "zod";
import { hashSecret } from "../../crypto.js";
import type { ControlPlaneStore } from "../../store.js";
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
  type PasswordStore,
} from "./store.js";

/**
 * Email + password sign-in API (docs/identity.md, "Password sign-in"):
 *
 *   POST /api/v1/auth/password/register        202, always (verification email)
 *   POST /api/v1/auth/password/verify          200 + session cookie
 *   POST /api/v1/auth/password/login           200 + session cookie | 401 invalid_credentials
 *   POST /api/v1/auth/password/reset           202, always
 *   POST /api/v1/auth/password/reset/complete  200 (every session revoked)
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
  personalOrgPerAddress: { limit: 3, windowMs: 60 * 60 * 1_000 },
  personalOrgPerIp: { limit: 10, windowMs: 60 * 60 * 1_000 },
};

// Bounded so a huge body cannot buy extra hashing work; the policy caps
// passwords at 128 code points, so a longer one is simply never valid.
const Secret = z.string().max(1_024);
const Login = z.object({ email: z.string().max(320), password: Secret }).strict();
const Register = z.object({ email: z.string().max(320), password: Secret, invite: z.string().max(256).optional() }).strict();
const TokenOnly = z.object({ token: z.string().max(256) }).strict();
const ResetRequest = z.object({ email: z.string().max(320) }).strict();
const ResetComplete = z.object({ token: z.string().max(256), password: Secret }).strict();

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

export type PasswordRoutes = {
  handle(request: IncomingMessage, response: ServerResponse, path: string, helpers: {
    requestObject: (request: IncomingMessage) => Promise<Record<string, unknown>>;
    siteBaseUrl: (request: IncomingMessage) => string;
    browserOrigins: readonly string[];
  }): Promise<boolean>;
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

  async function signInFor(request: IncomingMessage, email: string, inviteTokenHash: string | null): Promise<SignInResult> {
    return identityStore.signIn({
      email,
      name: null,
      inviteTokenHash,
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

  async function countFailure(email: string | null, ip: string, reason: string, userId: string | null): Promise<void> {
    const subjects: Array<[string, { free: number }, "account" | "ip"]> = [[ipSubject(ip), LOCKOUT.ip, "ip"]];
    if (email) subjects.unshift([accountSubject(email), LOCKOUT.account, "account"]);
    for (const [subject, rule, kind] of subjects) {
      const lockedUntil = await passwords.recordFailure(subject, rule);
      if (lockedUntil) {
        await passwords.audit({
          userId,
          action: "login.lockout",
          target: `scope=${kind} ${kind === "account" ? `email=${email}` : `ip=${ip}`} until=${lockedUntil.toISOString()}`,
        });
      }
    }
    await passwords.audit({ userId, action: "login.password.failure", target: `email=${email ?? "invalid"} ip=${ip} reason=${reason}` });
  }

  async function login(request: IncomingMessage, response: ServerResponse, body: z.infer<typeof Login>): Promise<void> {
    const ip = clientIp(request).slice(0, 64);
    const email = normalizeEmailAddress(body.email);
    const subjects = [ipSubject(ip), ...(email ? [accountSubject(email)] : [])];
    const [locked, credential] = await Promise.all([
      passwords.locked(subjects),
      email ? passwords.credentialByEmail(email) : Promise.resolve(null),
    ]);
    // Unknown address, wrong password and a lock all answer the same 401
    // after one argon2id verification, so neither the answer nor its timing
    // tells them apart.
    const refuse = () => sendJson(response, 401, { error: "invalid_credentials", message: INVALID_CREDENTIALS });
    if (locked) {
      await hasher.dummyVerify(body.password);
      await passwords.audit({ userId: credential?.userId ?? null, action: "login.password.failure", target: `email=${email ?? "invalid"} ip=${ip} reason=locked` });
      refuse();
      return;
    }
    if (!credential) {
      await hasher.dummyVerify(body.password);
      await countFailure(email, ip, email ? "unknown_account" : "invalid_email", null);
      refuse();
      return;
    }
    const outcome = await hasher.verify(body.password, credential);
    if (!outcome.ok) {
      await countFailure(email, ip, "wrong_password", credential.userId);
      refuse();
      return;
    }
    const result = await signInFor(request, email!, null);
    await passwords.clearSubject(passwords.executor, accountSubject(email!));
    if (outcome.needsRehash) {
      // Parameters were raised or the pepper rotated: upgrade while the
      // plaintext is at hand. A concurrent change wins (compare-and-set).
      await passwords.rehash(credential.userId, credential.hash, await hasher.hash(body.password));
    }
    await passwords.audit({ userId: result.userId, action: "login.password.success", target: `email=${email} ip=${ip}${outcome.needsRehash ? " rehashed=true" : ""}` });
    signedIn(response, result);
  }

  async function register(request: IncomingMessage, response: ServerResponse, body: z.infer<typeof Register>, siteName: string): Promise<void> {
    const email = normalizeEmailAddress(body.email);
    if (!email) throw new PasswordHttpError(400, "email_invalid", "That email address is not valid.");
    await policyOrThrow(body.password, email);
    const invite = body.invite && /^sh_inv_[A-Za-z0-9_-]{20,200}$/.test(body.invite) ? body.invite : null;
    const ip = clientIp(request);
    if (!limited(`pw-mail-ip:${ip}`, RATE.mailPerIp) && !limited(`pw-mail-addr:${email}`, RATE.mailPerAddress)) {
      later("password registration", async () => {
        if (!await identityStore.passwordRegistrationEligible(email)) return;
        if (await passwords.credentialByEmail(email)) {
          await mailer.send(passwordAlreadyRegisteredEmail({ to: email, url: `${input.dashboardOrigin}/password/reset`, siteName }));
          return;
        }
        const token = await passwords.createRegistration({
          email,
          stored: await hasher.hash(body.password),
          inviteTokenHash: invite ? hashSecret(invite) : null,
        });
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

  async function verify(request: IncomingMessage, response: ServerResponse, body: z.infer<typeof TokenOnly>): Promise<void> {
    if (limited(`pw-token-ip:${clientIp(request)}`, RATE.tokenPerIp)) {
      throw new PasswordHttpError(429, "rate_limited", "Too many attempts. Try again in a few minutes.");
    }
    const consumed = await passwords.consumeRegistration(body.token);
    if (!consumed) throw new PasswordHttpError(410, "token_invalid", "This link has expired or was already used. Register again.");
    if (await passwords.credentialByEmail(consumed.email)) {
      // Setting a password over an existing one is a reset, which also signs out everywhere.
      throw new PasswordHttpError(409, "password_already_set", "This address already has a password. Reset it instead.");
    }
    const result = await signInFor(request, consumed.email, consumed.inviteTokenHash);
    await passwords.upsertCredential(passwords.executor, result.userId, consumed.stored);
    await passwords.clearSubject(passwords.executor, accountSubject(consumed.email));
    await passwords.audit({ userId: result.userId, action: "password.registration.completed", target: `email=${consumed.email}` });
    signedIn(response, result);
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
    if (limited(`pw-token-ip:${clientIp(request)}`, RATE.tokenPerIp)) {
      throw new PasswordHttpError(429, "rate_limited", "Too many attempts. Try again in a few minutes.");
    }
    const owner = await passwords.peekReset(body.token);
    if (!owner) throw new PasswordHttpError(410, "token_invalid", "This reset link has expired or was already used. Request a new one.");
    await policyOrThrow(body.password, owner.email);
    const stored = await hasher.hash(body.password);
    let revoked = { sessions: 0, mcpGrants: 0 };
    const completed = await passwords.completeReset(body.token, stored, async (tx, userId) => {
      revoked = await controlStore.revokeAllForUser(tx, userId, "password_reset");
    });
    if (!completed) throw new PasswordHttpError(410, "token_invalid", "This reset link has expired or was already used. Request a new one.");
    await passwords.audit({
      userId: completed.userId,
      action: "password.reset.completed",
      target: `email=${completed.email} sessions_revoked=${revoked.sessions} mcp_grants_revoked=${revoked.mcpGrants}`,
    });
    sendJson(response, 200, { status: "password_reset", sessionsRevoked: revoked.sessions + revoked.mcpGrants }, [input.clearSessionCookie()]);
  }

  return {
    async handle(request, response, path, helpers) {
      if (!path.startsWith(PASSWORD_PATH_PREFIX)) return false;
      const route = path.slice(PASSWORD_PATH_PREFIX.length);
      if (!["login", "register", "verify", "reset", "reset/complete"].includes(route)) return false;
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
      else if (route === "reset") await resetRequest(request, response, parse(ResetRequest, raw), siteName);
      else await resetComplete(request, response, parse(ResetComplete, raw));
      return true;
    },
    async idle() {
      while (background.size) await Promise.allSettled([...background]);
    },
  };
}
