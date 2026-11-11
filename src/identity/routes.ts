import type { IncomingMessage, ServerResponse } from "node:http";
import { z } from "zod";
import { decryptSecret, encryptSecret, hashSecret, secureEqual, type EncryptionKeyring } from "../crypto.js";
import { ACCOUNT_SCOPE, DASHBOARD_DEVICE_CLIENT, type ControlPlaneStore, type Principal } from "../store.js";
import { clientIp, cookieRequestAllowed, limiterKey, RateLimiter, safeNextPath } from "../auth/device-approval.js";
import { emailDomain, type IdentityConfig } from "./config.js";
import { inviteEmail, signInEmail, type Mailer } from "./mailer.js";
import { OidcClient, OidcError, pkcePair, randomState } from "./oidc.js";
import { cloudPathForNext } from "../auth/desktop-login.js";
import { confirmEmailPage, loginPage, messagePage, PAGE_CSP, passwordLinkPage, type InviteBanner } from "./pages.js";
import { IdentityError, IdentityStore, type Role } from "./store.js";
import type { Database } from "../database.js";
import { PasswordHasher } from "./password/hashing.js";
import { PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH, type HibpFetch } from "./password/policy.js";
import { createPasswordRoutes, disabledMethod, PASSWORD_PATH_PREFIX, PasswordHttpError, type PasswordRoutes } from "./password/routes.js";
import { PasswordStore } from "./password/store.js";

type JsonObject = Record<string, unknown>;
type Auth = { kind: "bootstrap" } | { kind: "user"; principal: Principal };

const SESSION_COOKIE = "agent_relay_session";
const DEVICE_COOKIE = "agent_relay_device";
const OIDC_COOKIE = "agent_relay_oidc";
const MICROSOFT_COOKIE = "agent_relay_microsoft";
const OIDC_ATTEMPT_TTL_MS = 10 * 60 * 1_000;
/** Password sign-in retention sweep (login attempts, spent tokens). */
const SWEEP_INTERVAL_MS = 60 * 60 * 1_000;
const RATE = {
  oidcStart: { limit: 30, windowMs: 5 * 60 * 1_000 },
  callback: { limit: 30, windowMs: 5 * 60 * 1_000 },
  emailPerIp: { limit: 10, windowMs: 10 * 60 * 1_000 },
  emailPerAddress: { limit: 3, windowMs: 10 * 60 * 1_000 },
  verify: { limit: 30, windowMs: 5 * 60 * 1_000 },
  invite: { limit: 60, windowMs: 60 * 60 * 1_000 },
  /** Multi mode: personal organizations created at sign-in. */
  personalOrgPerAddress: { limit: 3, windowMs: 60 * 60 * 1_000 },
  personalOrgPerIp: { limit: 10, windowMs: 60 * 60 * 1_000 },
  settings: { limit: 60, windowMs: 60 * 60 * 1_000 },
  /** Multi mode: self-serve POST /api/v1/organizations. */
  organizationPerUser: { limit: 5, windowMs: 60 * 60 * 1_000 },
  organizationPerIp: { limit: 20, windowMs: 60 * 60 * 1_000 },
};

const OrganizationCreate = z.object({
  name: z.string().trim().min(1).max(120),
}).passthrough();

const InstallationSettingsPatch = z.object({
  personalOrgSignupEnabled: z.boolean().nullable().optional(),
  selfServeOrganizationsEnabled: z.boolean().nullable().optional(),
}).strict();

function parseBody<T>(schema: z.ZodType<T>, body: unknown): T {
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new IdentityHttpError(400, "invalid_request", issue ? `${issue.path.join(".") || "body"}: ${issue.message}` : "Invalid request body");
  }
  return parsed.data;
}

export type IdentityRouteHelpers = {
  organizationAccess: (request: IncomingMessage, organizationId: string, admin?: boolean) => Promise<Auth>;
  authenticate: (request: IncomingMessage) => Promise<Auth>;
  /** Like authenticate, but also accepts the bootstrap bearer. */
  authenticateWithBootstrap: (request: IncomingMessage) => Promise<Auth>;
  requestObject: (request: IncomingMessage) => Promise<JsonObject>;
  bearer: (request: IncomingMessage) => string | null;
  /** The configured origin (dashboard or public API) the request arrived on. */
  siteBaseUrl: (request: IncomingMessage) => string;
  browserOrigins: readonly string[];
};

export class IdentityHttpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

function cookie(request: IncomingMessage, name: string): string | null {
  for (const part of (request.headers.cookie ?? "").split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0 || part.slice(0, separator).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(separator + 1).trim());
    } catch {
      return null;
    }
  }
  return null;
}

function setCookie(name: string, value: string, path: string, maxAge: number): string {
  return `${name}=${encodeURIComponent(value)}; Path=${path}; Max-Age=${maxAge}; Secure; HttpOnly; SameSite=Lax`;
}

function clearCookie(name: string, path: string): string {
  return `${name}=; Path=${path}; Max-Age=0; Secure; HttpOnly; SameSite=Lax`;
}

function sendHtml(response: ServerResponse, status: number, body: string, cookies: string[] = [], csp = PAGE_CSP): void {
  response.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": csp,
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    ...(cookies.length ? { "set-cookie": cookies } : {}),
  });
  response.end(body);
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  response.end(JSON.stringify(body));
}

function redirect(response: ServerResponse, status: 302 | 303, location: string, cookies: string[] = []): void {
  response.writeHead(status, {
    location,
    "cache-control": "no-store",
    "referrer-policy": "no-referrer",
    ...(cookies.length ? { "set-cookie": cookies } : {}),
  });
  response.end();
}

async function formBody(request: IncomingMessage): Promise<URLSearchParams> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > 16 * 1024) throw new IdentityHttpError(413, "payload_too_large", "Form too large");
    chunks.push(buffer);
  }
  const type = request.headers["content-type"]?.split(";")[0]?.trim().toLowerCase();
  if (type !== "application/x-www-form-urlencoded") throw new IdentityHttpError(415, "unsupported_media_type", "Expected a form post");
  return new URLSearchParams(Buffer.concat(chunks).toString("utf8"));
}

function inviteParam(value: string | null): string | null {
  return value && /^sh_inv_[A-Za-z0-9_-]{20,200}$/.test(value) ? value : null;
}

export type IdentityModule = {
  config: IdentityConfig;
  store: IdentityStore;
  handle(
    request: IncomingMessage,
    response: ServerResponse,
    path: string,
    publicPath: string,
    url: URL,
    helpers: IdentityRouteHelpers,
  ): Promise<boolean>;
  /** Owner-guarded membership change audit (called by the memberships routes). */
  auditMembership(input: { organizationId: string; auth: Auth; action: string; target: string }): Promise<void>;
  /** Resolves once background sign-in mail work has finished (tests, shutdown). */
  idle(): Promise<void>;
  /** Starts the hourly retention sweep (password sign-in state); stop() ends it. */
  start(): void;
  stop(): void;
  /** One retention sweep now (tests). */
  sweep(): Promise<void>;
};

export function createIdentityModule(input: {
  config: IdentityConfig;
  identityStore: IdentityStore;
  controlStore: ControlPlaneStore;
  keyring: EncryptionKeyring;
  dashboardUrl: string;
  mailer: Mailer | null;
  oidcClient?: OidcClient | null;
  /** Test seam like oidcClient, for SELFHOST_MICROSOFT_* (default: from config.microsoft). */
  microsoftClient?: OidcClient | null;
  /** Needed when password sign-in is enabled (its Postgres state). */
  database?: Database;
  /** Test seam: the Have I Been Pwned range fetch (SELFHOST_PASSWORD_HIBP=on). */
  hibpFetch?: HibpFetch;
  /** Test seam: the argon2id hasher (default: one per module, sharing the process-wide slots). */
  passwordHasher?: PasswordHasher;
  now?: () => number;
  log?: (message: string, fields?: Record<string, unknown>) => void;
}): IdentityModule {
  const { config, identityStore: store, controlStore, keyring, mailer } = input;
  const now = () => input.now?.() ?? Date.now();
  const log = input.log ?? ((message, fields) => console.log(`[selfhost-api] ${message}`, fields ?? {}));
  const limiter = new RateLimiter(now);
  const oidc = input.oidcClient !== undefined ? input.oidcClient : config.oidc ? new OidcClient(config.oidc) : null;
  const microsoft = input.microsoftClient !== undefined
    ? input.microsoftClient
    : config.microsoft ? new OidcClient(config.microsoft) : null;
  /** The browser OIDC providers: /login/<slug>/start and /login/<slug>/callback. */
  type Provider = {
    slug: "oidc" | "microsoft";
    client: OidcClient | null;
    cookie: string;
    method: "oidc" | "microsoft";
    notConfigured: { title: string; message: string };
  };
  const providers: Provider[] = [
    {
      slug: "oidc",
      client: oidc,
      cookie: OIDC_COOKIE,
      method: "oidc",
      notConfigured: { title: "Single sign-on is not configured", message: "Ask your administrator to configure an OIDC identity provider." },
    },
    {
      slug: "microsoft",
      client: microsoft,
      cookie: MICROSOFT_COOKIE,
      method: "microsoft",
      notConfigured: { title: "Microsoft sign-in is not configured", message: "Ask your administrator to configure Microsoft sign-in." },
    },
  ];
  const dashboardOrigin = new URL(input.dashboardUrl).origin;
  // PAGE_CSP loads no images: only /login gets one, from the logo's own origin.
  const coBrand = config.logoUrl ? { logoUrl: config.logoUrl, orgName: config.loginOrgName } : null;
  const loginCsp = config.logoUrl ? `${PAGE_CSP}; img-src ${new URL(config.logoUrl).origin}` : PAGE_CSP;
  /**
   * The dashboard's forgot-password and register pages, keeping where the
   * person was going. A `next` under /api/v1 moves to /cloud/api/v1, the only
   * mount a separate dashboard host routes to this service.
   */
  function passwordPageLinks(next: string, invite: string | null): { forgot: string; register: string } {
    const query = new URLSearchParams({ next: cloudPathForNext(next) });
    if (invite) query.set("invite", invite);
    const dashboard = new URL(input.dashboardUrl);
    const base = `${dashboard.origin}${dashboard.pathname.replace(/\/+$/, "")}`;
    return { forgot: `${base}/#/forgot-password?${query}`, register: `${base}/#/register?${query}` };
  }
  const emailLogin = config.emailLogin && mailer !== null;
  let passwordRoutes: PasswordRoutes | null = null;
  if (config.signinMethods.includes("password") && config.password && mailer) {
    if (!input.database) throw new Error("password sign-in needs the database");
    passwordRoutes = createPasswordRoutes({
      config: config.password,
      hasher: input.passwordHasher ?? new PasswordHasher(config.password),
      passwords: new PasswordStore(input.database, input.now ? { now: input.now } : {}),
      identityStore: store,
      controlStore,
      mailer,
      sessionCookie: (tokens) => sessionCookie(tokens),
      clearSessionCookie: () => clearCookie(SESSION_COOKIE, "/cloud"),
      ...(input.hibpFetch ? { hibpFetch: input.hibpFetch } : {}),
      ...(input.now ? { now: input.now } : {}),
      log,
    });
  }
  let sweepTimer: NodeJS.Timeout | null = null;
  const signinMethods = [
    ...(emailLogin ? ["email_link" as const] : []),
    ...(passwordRoutes ? ["password" as const] : []),
  ];

  function limited(key: string, rule: { limit: number; windowMs: number }): boolean {
    return !limiter.consume(key, rule.limit, rule.windowMs).allowed;
  }

  function inviteUrl(token: string): string {
    return `${dashboardOrigin}/login?invite=${encodeURIComponent(token)}`;
  }

  function sessionCookie(tokens: { accessToken: string; accessTokenExpiresAt: string }): string {
    const maxAge = Math.max(1, Math.floor((Date.parse(tokens.accessTokenExpiresAt) - now()) / 1_000));
    return setCookie(SESSION_COOKIE, tokens.accessToken, "/cloud", maxAge);
  }

  function sameOriginForm(request: IncomingMessage, helpers: IdentityRouteHelpers): boolean {
    const origin = request.headers.origin;
    if (typeof origin === "string" && origin && origin !== "null") return helpers.browserOrigins.includes(origin);
    return request.headers["sec-fetch-site"] === "same-origin";
  }

  async function banner(token: string | null): Promise<InviteBanner | null> {
    if (!token) return null;
    const found = await store.describeInvitation(token);
    if (!found) return { kind: "invalid", message: "This invite link is not valid. Ask for a new invite." };
    if (found.status === "accepted") return { kind: "invalid", message: "This invite has already been accepted. Sign in to continue." };
    if (found.status === "revoked") return { kind: "invalid", message: "This invite has been canceled. Ask for a new invite." };
    if (found.status === "expired") return { kind: "invalid", message: "This invite has expired. Ask for a new invite." };
    return { kind: "valid", organizationName: found.organizationName, inviterName: found.inviterName, role: found.role, email: found.email };
  }

  async function sendInvite(invitation: { email: string; role: Role; expiresAt: string }, token: string, organizationId: string, auth: Auth): Promise<"sent" | "failed" | "not_configured"> {
    if (!mailer) return "not_configured";
    try {
      const organizationName = await store.organizationName(organizationId) ?? "your organization";
      const inviter = auth.kind === "user" ? auth.principal.name || auth.principal.email : null;
      const hours = Math.round(config.inviteTtlMs / 3_600_000);
      await mailer.send(inviteEmail({
        to: invitation.email,
        organizationName,
        inviterName: inviter,
        role: invitation.role,
        url: inviteUrl(token),
        expiresInText: hours % 24 === 0 ? `${hours / 24} day${hours === 24 ? "" : "s"}` : `${hours} hours`,
      }));
      return "sent";
    } catch (error) {
      // Recipient domain only, never the address or the link.
      log("invite email failed", { domain: emailDomain(invitation.email), error: error instanceof Error ? error.message : String(error) });
      return "failed";
    }
  }

  function signInErrorPage(response: ServerResponse, error: unknown, back: string, provider: Provider = providers[0]!): void {
    const clear = clearCookie(provider.cookie, `/login/${provider.slug}`);
    if (error instanceof IdentityError) {
      sendHtml(response, error.status, messagePage({ title: error.code === "not_ready" ? "Almost ready" : "Unable to sign in", message: error.message, back }), [clear]);
      return;
    }
    if (error instanceof OidcError) {
      log(`${provider.slug} sign-in failed`, { code: error.code, error: error.message });
      sendHtml(response, 502, messagePage({ title: "Unable to sign in", message: error.message, back }), [clear]);
      return;
    }
    throw error;
  }

  function actorFor(auth: Auth): { kind: "user"; userId: string; role: Role } | { kind: "bootstrap" } {
    return auth.kind === "user" ? { kind: "user", userId: auth.principal.userId, role: auth.principal.role } : { kind: "bootstrap" };
  }

  /** GET /login/<slug>/start: PKCE + state + nonce in an encrypted cookie, then the provider. */
  async function providerStart(request: IncomingMessage, response: ServerResponse, url: URL, helpers: IdentityRouteHelpers, provider: Provider): Promise<void> {
    const client = provider.client;
    if (!client) {
      sendHtml(response, 404, messagePage(provider.notConfigured));
      return;
    }
    if (limited(`${provider.slug}-start:${limiterKey(clientIp(request))}`, RATE.oidcStart)) {
      sendHtml(response, 429, messagePage({ title: "Too many attempts", message: "Too many sign-in attempts. Try again in a few minutes." }));
      return;
    }
    const next = safeNextPath(url.searchParams.get("next"));
    const invite = inviteParam(url.searchParams.get("invite"));
    const redirectUri = client.config.redirectUrl ?? `${helpers.siteBaseUrl(request)}/login/${provider.slug}/callback`;
    const pkce = pkcePair();
    const attempt = {
      p: `${provider.slug}-attempt`,
      state: randomState(),
      nonce: randomState(),
      verifier: pkce.verifier,
      next,
      invite,
      redirectUri,
      exp: now() + OIDC_ATTEMPT_TTL_MS,
    };
    let location: string;
    try {
      const described = invite ? await store.describeInvitation(invite) : null;
      location = await client.authorizationUrl({
        redirectUri,
        state: attempt.state,
        nonce: attempt.nonce,
        codeChallenge: pkce.challenge,
        ...(described?.status === "pending" ? { loginHint: described.email } : {}),
      });
    } catch (error) {
      signInErrorPage(response, error, `/login?next=${encodeURIComponent(next)}`, provider);
      return;
    }
    redirect(response, 302, location, [
      setCookie(provider.cookie, encryptSecret(JSON.stringify(attempt), keyring.active), `/login/${provider.slug}`, OIDC_ATTEMPT_TTL_MS / 1_000),
    ]);
  }

  /** GET /login/<slug>/callback: checks the attempt, exchanges the code and signs in. */
  async function providerCallback(request: IncomingMessage, response: ServerResponse, url: URL, provider: Provider): Promise<void> {
    const client = provider.client!;
    const clear = clearCookie(provider.cookie, `/login/${provider.slug}`);
    if (limited(`${provider.slug}-callback:${limiterKey(clientIp(request))}`, RATE.callback)) {
      sendHtml(response, 429, messagePage({ title: "Too many attempts", message: "Too many sign-in attempts. Try again in a few minutes." }));
      return;
    }
    let attempt: { p: string; state: string; nonce: string; verifier: string; next: string; invite: string | null; redirectUri: string; exp: number } | null = null;
    try {
      const raw = cookie(request, provider.cookie);
      attempt = raw ? JSON.parse(decryptSecret(raw, keyring)) : null;
    } catch {
      attempt = null;
    }
    const back = `/login?next=${encodeURIComponent(attempt?.next ?? "/")}${attempt?.invite ? `&invite=${encodeURIComponent(attempt.invite)}` : ""}`;
    const state = url.searchParams.get("state") ?? "";
    if (!attempt || attempt.p !== `${provider.slug}-attempt` || attempt.exp < now() || !state || !secureEqual(state, attempt.state)) {
      sendHtml(response, 400, messagePage({ title: "Sign-in expired", message: "This sign-in attempt expired or was started in another browser. Start again." , back }), [clear]);
      return;
    }
    const idpError = url.searchParams.get("error");
    if (idpError) {
      const cancelled = idpError === "access_denied";
      sendHtml(response, 400, messagePage({
        title: cancelled ? "Sign-in cancelled" : "Unable to sign in",
        message: cancelled ? "You cancelled the sign-in." : `The identity provider returned an error (${idpError.slice(0, 64).replace(/[^\w.-]/g, "")}).`,
        back,
      }), [clear]);
      return;
    }
    const code = url.searchParams.get("code");
    if (!code) {
      sendHtml(response, 400, messagePage({ title: "Unable to sign in", message: "The identity provider returned no authorization code.", back }), [clear]);
      return;
    }
    try {
      const identity = await client.complete({ code, redirectUri: attempt.redirectUri, codeVerifier: attempt.verifier, nonce: attempt.nonce });
      const allowed = client.config.allowedDomains;
      if (allowed.length && !allowed.includes(emailDomain(identity.email))) {
        throw new IdentityError(403, "domain_not_allowed", `Accounts from ${emailDomain(identity.email)} can't sign in here. Use your ${allowed.join(" or ")} account.`);
      }
      const result = await store.signIn({
        email: identity.email,
        name: identity.name,
        inviteTokenHash: attempt.invite ? hashSecret(attempt.invite) : null,
        method: provider.method,
        emailVerified: identity.emailVerified,
        beforePersonalOrganization: () => {
          if (limited(`personal-org-addr:${identity.email.toLowerCase()}`, RATE.personalOrgPerAddress) || limited(`personal-org-ip:${limiterKey(clientIp(request))}`, RATE.personalOrgPerIp)) {
            throw new IdentityError(429, "rate_limited", "Too many new organizations were created. Try again later.");
          }
        },
      });
      if (result.joined) log("member joined", { via: result.joined.via, role: result.joined.role, domain: emailDomain(result.email) });
      redirect(response, 303, attempt.next, [sessionCookie(result.tokens), clear]);
    } catch (error) {
      signInErrorPage(response, error, back, provider);
    }
  }

  async function handle(
    request: IncomingMessage,
    response: ServerResponse,
    path: string,
    publicPath: string,
    url: URL,
    helpers: IdentityRouteHelpers,
  ): Promise<boolean> {
    const method = request.method ?? "GET";

    // ---- sign-in page ------------------------------------------------------
    if (method === "GET" && publicPath === "/login") {
      const next = safeNextPath(url.searchParams.get("next"));
      const invite = inviteParam(url.searchParams.get("invite"));
      const started = await controlStore.startDeviceAuthorization(DASHBOARD_DEVICE_CLIENT, null, { reserved: true });
      const cookies = [setCookie(
        DEVICE_COOKIE,
        started.deviceCode,
        "/login",
        Math.max(1, Math.floor((Date.parse(started.expiresAt) - now()) / 1_000)),
      )];
      sendHtml(response, 200, loginPage({
        next,
        invite,
        banner: await banner(invite ?? (url.searchParams.has("invite") ? "invalid" : null)),
        oidc: oidc ? { displayName: oidc.config.displayName } : null,
        microsoft: microsoft ? { displayName: microsoft.config.displayName } : null,
        emailLogin,
        password: passwordRoutes !== null,
        passwordLinks: passwordRoutes ? passwordPageLinks(next, invite) : null,
        // Only a password form can produce this redirect.
        notice: passwordRoutes !== null && url.searchParams.get("error") === "invalid_credentials"
          ? { kind: "error", text: "Incorrect email or password." }
          : null,
        userCode: started.userCode,
        pollIntervalMs: Math.max(1, started.intervalSeconds) * 1_000,
        coBrand,
      }), cookies, loginCsp);
      return true;
    }

    // ---- OIDC and Microsoft ------------------------------------------------------
    for (const provider of providers) {
      if (method === "GET" && publicPath === `/login/${provider.slug}/start`) {
        await providerStart(request, response, url, helpers, provider);
        return true;
      }
      if (method === "GET" && publicPath === `/login/${provider.slug}/callback`) {
        if (!provider.client) return false;
        await providerCallback(request, response, url, provider);
        return true;
      }
    }

    // ---- password form (the /login page) ---------------------------------------
    // Lets CLI login (/cloud/api/v1/cli/login) and Desktop browser login,
    // which both land on /login, work with SELFHOST_SIGNIN_METHODS=password.
    if (method === "POST" && publicPath === "/login/password") {
      if (!passwordRoutes) {
        disabledMethod(response, "password");
        return true;
      }
      if (!sameOriginForm(request, helpers)) {
        sendHtml(response, 403, messagePage({ title: "Unable to sign in", message: "Cross-origin request refused." }));
        return true;
      }
      const form = await formBody(request);
      const next = safeNextPath(form.get("next"));
      const invite = inviteParam(form.get("invite"));
      const back = `/login?next=${encodeURIComponent(next)}${invite ? `&invite=${encodeURIComponent(invite)}` : ""}`;
      try {
        const result = await passwordRoutes.formLogin(request, {
          email: form.get("email") ?? "",
          password: form.get("password") ?? "",
          invite,
        }, helpers.siteBaseUrl(request));
        if (!result) {
          redirect(response, 303, `${back}&error=invalid_credentials`);
          return true;
        }
        redirect(response, 303, next, [sessionCookie(result.tokens)]);
      } catch (error) {
        signInErrorPage(response, error, back);
      }
      return true;
    }

    // ---- emailed password links (token in the URL fragment) ----------------------
    if (publicPath === "/login/password/verify" || publicPath === "/login/password/reset") {
      const kind = publicPath === "/login/password/verify" ? "verify" as const : "reset" as const;
      if (method !== "GET" && method !== "POST") return false;
      if (!passwordRoutes) {
        disabledMethod(response, "password");
        return true;
      }
      if (method === "GET") {
        sendHtml(response, 200, passwordLinkPage({ kind, minLength: PASSWORD_MIN_LENGTH }));
        return true;
      }
      if (!sameOriginForm(request, helpers)) {
        sendHtml(response, 403, messagePage({ title: "Unable to continue", message: "Cross-origin request refused." }));
        return true;
      }
      const form = await formBody(request);
      const site = helpers.siteBaseUrl(request);
      const token = (form.get("token") ?? "").slice(0, 256);
      const password = form.get("password") ?? "";
      if (kind === "reset" && !token) {
        passwordRoutes.formResetRequest(request, form.get("email") ?? "", site);
        sendHtml(response, 200, messagePage({
          title: "Check your email",
          kind: "ok",
          message: "If that address has a password here, we've sent it a reset link. It works once and expires in 30 minutes.",
        }));
        return true;
      }
      try {
        if (kind === "verify") {
          const result = await passwordRoutes.formCompleteRegistration(request, { token, password }, site);
          redirect(response, 303, "/", [sessionCookie(result.tokens)]);
        } else {
          await passwordRoutes.formCompleteReset(request, { token, password }, site);
          sendHtml(response, 200, messagePage({
            title: "Password changed",
            kind: "ok",
            message: "Your password was changed and every session was signed out. Sign in with the new password.",
          }), [clearCookie(SESSION_COOKIE, "/cloud")]);
        }
      } catch (error) {
        const known = identityErrorResponse(error);
        if (!known) throw error;
        // A rejected password (policy, breach list) keeps the link usable:
        // render the form again with the token in it.
        if (known.status === 400) {
          sendHtml(response, 400, passwordLinkPage({ kind, token, minLength: PASSWORD_MIN_LENGTH, notice: { kind: "error", text: known.body.message } }));
        } else {
          sendHtml(response, known.status, messagePage({
            title: known.status === 410 ? "Link expired" : "Unable to continue",
            message: known.body.message,
            back: kind === "reset" ? "/login/password/reset" : "/login",
          }));
        }
      }
      return true;
    }

    // ---- email sign-in links ---------------------------------------------------
    if (method === "POST" && publicPath === "/login/email") {
      if (!emailLogin) {
        disabledMethod(response, "email_link");
        return true;
      }
      if (!sameOriginForm(request, helpers)) {
        sendHtml(response, 403, messagePage({ title: "Unable to sign in", message: "Cross-origin request refused." }));
        return true;
      }
      const form = await formBody(request);
      const next = safeNextPath(form.get("next"));
      const invite = inviteParam(form.get("invite"));
      const email = (form.get("email") ?? "").trim().toLowerCase().slice(0, 320);
      const back = `/login?next=${encodeURIComponent(next)}${invite ? `&invite=${encodeURIComponent(invite)}` : ""}`;
      if (limited(`email-ip:${limiterKey(clientIp(request))}`, RATE.emailPerIp) || limited(`email-addr:${email}`, RATE.emailPerAddress)) {
        sendHtml(response, 429, messagePage({ title: "Too many attempts", message: "Too many sign-in emails were requested. Try again in a few minutes.", back }));
        return true;
      }
      const token = await store.createEmailLogin({ email, inviteToken: invite, next });
      if (token) {
        try {
          await mailer!.send(signInEmail({
            to: email,
            url: `${helpers.siteBaseUrl(request)}/login/email/verify?token=${encodeURIComponent(token)}`,
            siteName: new URL(helpers.siteBaseUrl(request)).host,
          }));
        } catch (error) {
          log("sign-in email failed", { domain: emailDomain(email), error: error instanceof Error ? error.message : String(error) });
        }
      }
      // The same answer whether or not the address may sign in.
      sendHtml(response, 200, messagePage({
        title: "Check your email",
        kind: "ok",
        message: `If ${email || "that address"} can sign in here, we've sent it a sign-in link. It works once and expires in 15 minutes.`,
        back,
      }));
      return true;
    }

    if (method === "GET" && publicPath === "/login/email/verify") {
      if (!emailLogin) {
        disabledMethod(response, "email_link");
        return true;
      }
      const token = url.searchParams.get("token") ?? "";
      const email = await store.peekEmailLogin(token);
      if (!email) {
        sendHtml(response, 410, messagePage({ title: "Link expired", message: "This sign-in link has expired or was already used. Request a new one." }));
        return true;
      }
      // A confirmation click, so mail scanners that prefetch links don't spend it.
      sendHtml(response, 200, confirmEmailPage({ email, token }));
      return true;
    }

    if (method === "POST" && publicPath === "/login/email/verify") {
      if (!emailLogin) {
        disabledMethod(response, "email_link");
        return true;
      }
      if (!sameOriginForm(request, helpers)) {
        sendHtml(response, 403, messagePage({ title: "Unable to sign in", message: "Cross-origin request refused." }));
        return true;
      }
      if (limited(`email-verify:${limiterKey(clientIp(request))}`, RATE.verify)) {
        sendHtml(response, 429, messagePage({ title: "Too many attempts", message: "Too many sign-in attempts. Try again in a few minutes." }));
        return true;
      }
      const form = await formBody(request);
      const consumed = await store.consumeEmailLogin(form.get("token") ?? "");
      if (!consumed) {
        sendHtml(response, 410, messagePage({ title: "Link expired", message: "This sign-in link has expired or was already used. Request a new one." }));
        return true;
      }
      try {
        const result = await store.signIn({
          email: consumed.email,
          name: null,
          inviteTokenHash: consumed.inviteTokenHash,
          method: "email",
          emailVerified: true,
          beforePersonalOrganization: () => {
            if (limited(`personal-org-addr:${consumed.email}`, RATE.personalOrgPerAddress) || limited(`personal-org-ip:${limiterKey(clientIp(request))}`, RATE.personalOrgPerIp)) {
              throw new IdentityError(429, "rate_limited", "Too many new organizations were created. Try again later.");
            }
          },
        });
        if (result.joined) log("member joined", { via: result.joined.via, role: result.joined.role, domain: emailDomain(result.email) });
        redirect(response, 303, safeNextPath(consumed.next), [sessionCookie(result.tokens)]);
      } catch (error) {
        signInErrorPage(response, error, "/login");
      }
      return true;
    }

    // ---- API: public login configuration (no auth, no secrets) -----------------
    if (method === "GET" && path === "/api/v1/auth/login-config") {
      sendJson(response, 200, {
        methods: signinMethods,
        oidc: oidc ? { displayName: oidc.config.displayName } : null,
        microsoft: microsoft ? { displayName: microsoft.config.displayName } : null,
        logo_url: config.logoUrl,
        // Shown beside the logo, so it is only public once a logo is set.
        org_name: config.logoUrl ? config.loginOrgName : null,
        // Whether only some email domains may join (never the list itself).
        allowed_domain_hint: config.autoJoinDomains.length > 0 || (oidc?.config.allowedDomains.length ?? 0) > 0,
        password_policy: passwordRoutes ? { min_length: PASSWORD_MIN_LENGTH, max_length: PASSWORD_MAX_LENGTH } : null,
      });
      return true;
    }

    // ---- API: email + password sign-in --------------------------------------------
    if (path.startsWith(PASSWORD_PATH_PREFIX)) {
      if (!passwordRoutes) {
        disabledMethod(response, "password");
        return true;
      }
      if (await passwordRoutes.handle(request, response, path, helpers)) return true;
    }

    // ---- API: sign-in methods (for the dashboard) ------------------------------
    if (method === "GET" && path === "/api/v1/auth/methods") {
      const auth = await helpers.authenticate(request);
      void auth;
      sendJson(response, 200, {
        oidc: oidc ? { displayName: oidc.config.displayName, allowedDomains: oidc.config.allowedDomains } : null,
        microsoft: microsoft ? { displayName: microsoft.config.displayName } : null,
        emailLink: emailLogin,
        password: passwordRoutes !== null,
        inviteEmail: mailer !== null,
        autoJoinDomains: config.autoJoinDomains,
        inviteTtlHours: Math.round(config.inviteTtlMs / 3_600_000),
      });
      return true;
    }

    // ---- API: self-serve organizations (multi mode) -------------------------------
    // The bootstrap bearer (and single mode) fall through to the operator
    // route in app.ts. A signed-in user creates an organization they own,
    // with a Default workspace, when the installation allows it.
    if (path === "/api/v1/organizations" && method === "POST" && config.tenancy.mode === "multi") {
      const auth = await helpers.authenticateWithBootstrap(request);
      if (auth.kind === "bootstrap") return false;
      if (!helpers.bearer(request) && !cookieRequestAllowed(request, helpers.browserOrigins)) {
        throw new IdentityHttpError(403, "csrf_rejected", "Cross-origin request refused");
      }
      // Creating an organization is an account action: only the browser
      // account session carries it, never a CLI, Desktop or legacy token.
      if (!auth.principal.scopes.includes(ACCOUNT_SCOPE) || auth.principal.pendingHandoff || auth.principal.handoff) {
        throw new IdentityHttpError(403, "reauthentication_required", "Sign in to the dashboard to create an organization");
      }
      const body = parseBody(OrganizationCreate, await helpers.requestObject(request));
      if (limited(`organization-user:${auth.principal.userId}`, RATE.organizationPerUser) || limited(`organization-ip:${limiterKey(clientIp(request))}`, RATE.organizationPerIp)) {
        throw new IdentityHttpError(429, "rate_limited", "Too many new organizations were created. Try again later.");
      }
      const created = await store.createOrganizationForUser({
        userId: auth.principal.userId,
        email: auth.principal.email,
        name: body.name,
      });
      sendJson(response, 201, created);
      return true;
    }

    // ---- API: installation settings (bootstrap bearer only) ------------------------
    if (path === "/api/v1/installation/settings" && (method === "GET" || method === "PATCH")) {
      const auth = await helpers.authenticateWithBootstrap(request);
      if (auth.kind !== "bootstrap") throw new IdentityHttpError(403, "forbidden", "Bootstrap token required");
      if (method === "GET") {
        sendJson(response, 200, await store.installationSettings());
        return true;
      }
      if (limited("installation-settings", RATE.settings)) {
        throw new IdentityHttpError(429, "rate_limited", "Too many settings changes. Try again later.");
      }
      const patch = parseBody(InstallationSettingsPatch, await helpers.requestObject(request));
      const settings = await store.updateInstallationSettings(patch);
      const organizationId = await store.bootstrapOrganizationId();
      if (organizationId) {
        await store.audit({
          organizationId,
          actor: { kind: "bootstrap" },
          action: "installation.settings",
          target: JSON.stringify(patch),
        });
      }
      sendJson(response, 200, settings);
      return true;
    }

    // ---- API: operator-assigned auto-join domains (DG-002) ------------------------
    // Assigning a domain lets every verified address at it join the
    // organization, so only the installation operator (bootstrap bearer) may
    // do it; organization owners get 403. Members may read the list.
    const domainList = /^\/api\/v1\/organizations\/([^/]+)\/domains$/.exec(path);
    const domainItem = /^\/api\/v1\/organizations\/([^/]+)\/domains\/([^/]+)$/.exec(path);
    if (domainList && method === "GET") {
      const organizationId = decodeURIComponent(domainList[1]!);
      await helpers.organizationAccess(request, organizationId);
      sendJson(response, 200, { organizationId, domains: await store.listDomains(organizationId) });
      return true;
    }
    if (domainItem && (method === "PUT" || method === "DELETE")) {
      const organizationId = decodeURIComponent(domainItem[1]!);
      const auth = await helpers.authenticateWithBootstrap(request);
      if (auth.kind !== "bootstrap") {
        throw new IdentityHttpError(403, "forbidden", "Only the installation operator (bootstrap token) can assign auto-join domains");
      }
      if (config.tenancy.mode === "single") {
        // Single mode: SELFHOST_AUTO_JOIN_DOMAINS is the authority and each
        // bootstrap pass rewrites these rows to match it (DG-004).
        throw new IdentityHttpError(409, "domains_managed_by_env", "SELFHOST_TENANCY=single: set SELFHOST_AUTO_JOIN_DOMAINS and restart to change auto-join domains");
      }
      const domain = decodeURIComponent(domainItem[2]!);
      if (method === "PUT") {
        const assigned = await store.assignDomain({ organizationId, domain, actor: { kind: "bootstrap" } });
        sendJson(response, assigned.created ? 201 : 200, { organizationId, domain: assigned.domain });
        return true;
      }
      const removed = await store.removeDomain({ organizationId, domain, actor: { kind: "bootstrap" } });
      if (!removed) throw new IdentityHttpError(404, "domain_not_found", "That domain is not assigned to this organization");
      response.statusCode = 204;
      response.end();
      return true;
    }

    // ---- API: invitations ----------------------------------------------------------
    const collection = /^\/api\/v1\/organizations\/([^/]+)\/invitations$/.exec(path);
    const item = /^\/api\/v1\/organizations\/([^/]+)\/invitations\/([^/]+)$/.exec(path);
    const link = /^\/api\/v1\/organizations\/([^/]+)\/invitations\/([^/]+)\/link$/.exec(path);
    if (!collection && !item && !link) return false;
    const organizationId = decodeURIComponent((collection ?? item ?? link)![1]!);
    const mutating = method !== "GET";
    const auth = await helpers.organizationAccess(request, organizationId, true);
    // A bodiless DELETE carries no content type; its Origin must still match.
    const csrfOk = method === "DELETE"
      ? sameOriginForm(request, helpers)
      : cookieRequestAllowed(request, helpers.browserOrigins);
    if (mutating && !helpers.bearer(request) && !csrfOk) {
      throw new IdentityHttpError(403, "csrf_rejected", "Cross-origin request refused");
    }
    if (mutating && auth.kind === "user" && limited(`invite:${auth.principal.userId}`, RATE.invite)) {
      throw new IdentityHttpError(429, "rate_limited", "Too many invitation changes. Try again later.");
    }
    if (collection && method === "GET") {
      sendJson(response, 200, { invitations: await store.listInvitations(organizationId) });
      return true;
    }
    if (collection && method === "POST") {
      const body = await helpers.requestObject(request);
      const email = typeof body.email === "string" ? body.email : "";
      const role = (typeof body.role === "string" ? body.role : "member") as Role;
      if (role !== "owner" && role !== "admin" && role !== "member") {
        throw new IdentityHttpError(400, "invalid_request", "role must be owner, admin, or member");
      }
      const created = await store.createInvitation({ organizationId, email, role, actor: actorFor(auth) });
      const emailDelivery = await sendInvite(created.invitation, created.token, organizationId, auth);
      sendJson(response, 201, { invitation: created.invitation, inviteUrl: inviteUrl(created.token), emailDelivery });
      return true;
    }
    if (item && method === "DELETE") {
      await store.revokeInvitation({ organizationId, id: decodeURIComponent(item[2]!), actor: actorFor(auth) });
      sendJson(response, 200, { revoked: true });
      return true;
    }
    if (link && method === "POST") {
      const body = await helpers.requestObject(request);
      const rotated = await store.rotateInvitation({ organizationId, id: decodeURIComponent(link[2]!), actor: actorFor(auth) });
      const emailDelivery = body.send === true
        ? await sendInvite(rotated.invitation, rotated.token, organizationId, auth)
        : "skipped";
      sendJson(response, 200, { invitation: rotated.invitation, inviteUrl: inviteUrl(rotated.token), emailDelivery });
      return true;
    }
    throw new IdentityHttpError(405, "method_not_allowed", "Method not allowed");
  }

  return {
    config,
    store,
    handle,
    async auditMembership({ organizationId, auth, action, target }) {
      await store.audit({
        organizationId,
        actor: auth.kind === "user" ? { kind: "user", userId: auth.principal.userId } : { kind: "bootstrap" },
        action,
        target,
      });
    },
    async idle() {
      await passwordRoutes?.idle();
    },
    start() {
      if (!passwordRoutes || sweepTimer) return;
      const sweep = () => {
        void passwordRoutes!.sweep().catch((error: unknown) => {
          log("password retention sweep failed", { error: error instanceof Error ? error.message : String(error) });
        });
      };
      sweep();
      sweepTimer = setInterval(sweep, SWEEP_INTERVAL_MS);
      sweepTimer.unref();
    },
    stop() {
      if (sweepTimer) clearInterval(sweepTimer);
      sweepTimer = null;
    },
    async sweep() {
      await passwordRoutes?.sweep();
    },
  };
}

export function identityErrorResponse(error: unknown): { status: number; body: { error: string; message: string } } | null {
  if (error instanceof IdentityHttpError || error instanceof IdentityError || error instanceof PasswordHttpError) {
    return { status: error.status, body: { error: error.code, message: error.message } };
  }
  return null;
}
