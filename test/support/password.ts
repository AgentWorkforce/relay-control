import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type test from "node:test";
import { createApp } from "../../src/app.js";
import type { SelfhostConfig } from "../../src/config.js";
import { migrate } from "../../src/migrations.js";
import { ControlPlaneStore } from "../../src/store.js";
import { ARGON2_BASELINE, loadIdentityConfig, type PasswordConfig } from "../../src/identity/config.js";
import { IdentityStore } from "../../src/identity/store.js";
import { createIdentityModule } from "../../src/identity/routes.js";
import { bootstrapOnce, relaycastProvisioner } from "../../src/identity/bootstrap.js";
import type { Mailer, OutgoingEmail } from "../../src/identity/mailer.js";
import type { HibpFetch } from "../../src/identity/password/policy.js";
import type { PasswordHasher } from "../../src/identity/password/hashing.js";
import { close, listen, PGliteDatabase } from "./harness.js";

/** Shared harness for the password sign-in tests (one control plane per test). */

export const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
export const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
export const RELAYCAST_SECRET = "relaycast-internal-secret-0123456789abcdef";
export const PASSWORD = "correct horse battery staple";
export const SMTP = { SELFHOST_SMTP_HOST: "smtp.acme.test", SELFHOST_EMAIL_FROM: "Relay <relay@acme.test>" };
export const API = "/api/v1/auth/password";

/** A pepper file as an operator should write it: owner-only (0600). */
export function pepperFile(content: string, mode = 0o600): string {
  const file = join(mkdtempSync(join(tmpdir(), "pepper-")), "pepper");
  writeFileSync(file, content, { mode });
  chmodSync(file, mode);
  return file;
}

// ---- fakes and harness -------------------------------------------------------------

export function fakeRelaycast() {
  let creates = 0;
  return createServer((req, res) => {
    res.writeHead(req.headers.authorization === `Bearer ${RELAYCAST_SECRET}` ? 201 : 401, { "content-type": "application/json" });
    creates += 1;
    res.end(JSON.stringify({ ok: true, data: { workspace_id: `9900${creates}`, api_key: `ar_ws_test_key_${creates}`, name: "Default" } }));
  });
}

export function fakeMailer(): Mailer & { sent: OutgoingEmail[] } {
  const mailer = {
    sent: [] as OutgoingEmail[],
    async send(message: OutgoingEmail) {
      mailer.sent.push(message);
    },
  };
  return mailer;
}

export function passwordConfig(overrides: Partial<PasswordConfig> = {}): PasswordConfig {
  return { argon2: { ...ARGON2_BASELINE }, peppers: [], currentPepperVersion: null, hibp: false, ...overrides };
}

export type Res = { status: number; body: any; text: string; cookies: Record<string, string> };

export async function call(origin: string, path: string, init: {
  method?: string;
  cookie?: string;
  json?: unknown;
  form?: Record<string, string>;
  ip?: string;
  bearer?: string;
  originHeader?: string | null;
} = {}): Promise<Res & { location: string | null }> {
  const headers: Record<string, string> = {};
  if (init.cookie) headers.cookie = init.cookie;
  if (init.bearer) headers.authorization = `Bearer ${init.bearer}`;
  if (init.ip) headers["x-forwarded-for"] = init.ip;
  let body: string | undefined;
  if (init.json !== undefined) {
    headers["content-type"] = "application/json";
    body = JSON.stringify(init.json);
  } else if (init.form) {
    headers["content-type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(init.form).toString();
  }
  const method = init.method ?? (init.json !== undefined || init.form ? "POST" : "GET");
  if (init.originHeader !== null && method !== "GET") headers.origin = init.originHeader ?? origin;
  const response = await fetch(`${origin}${path}`, { method, headers, body, redirect: "manual" });
  const text = await response.text();
  let parsed: any = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }
  const cookies: Record<string, string> = {};
  for (const line of response.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const index = pair!.indexOf("=");
    cookies[pair!.slice(0, index)] = decodeURIComponent(pair!.slice(index + 1));
  }
  return { status: response.status, body: parsed, text, cookies, location: response.headers.get("location") };
}

export async function setup(t: test.TestContext, options: {
  env?: Record<string, string>;
  hibpFetch?: HibpFetch;
  trustedProxies?: string | null;
  passwordHasher?: PasswordHasher;
  dashboardUrl?: string;
  /** false: no SMTP and no mailer (SELFHOST_SIGNIN_METHODS=password). */
  smtp?: boolean;
} = {}) {
  // The tests stand behind one proxy (they send X-Forwarded-For) unless a
  // test asks otherwise; the variable is read per request.
  const previousProxies = process.env.SELFHOST_TRUSTED_PROXIES;
  const proxies = options.trustedProxies === undefined ? "1" : options.trustedProxies;
  if (proxies === null) delete process.env.SELFHOST_TRUSTED_PROXIES;
  else process.env.SELFHOST_TRUSTED_PROXIES = proxies;
  t.after(() => {
    if (previousProxies === undefined) delete process.env.SELFHOST_TRUSTED_PROXIES;
    else process.env.SELFHOST_TRUSTED_PROXIES = previousProxies;
  });
  const database = new PGliteDatabase();
  await migrate(database);
  const relaycast = fakeRelaycast();
  const relaycastUrl = await listen(relaycast);
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: origin,
    relaycastUrl,
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.selfhosted.test",
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: "https://history.selfhosted.test", secret: "session-read-secret-".repeat(2) },
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: null,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: options.dashboardUrl ?? `${origin}/`,
    port: 0,
    host: "127.0.0.1",
  };
  const identityConfig = loadIdentityConfig({
    SELFHOST_BOOTSTRAP_ORG_NAME: "Acme",
    SELFHOST_BOOTSTRAP_ADMIN_EMAIL: "admin@acme.test",
    SELFHOST_AUTO_JOIN_DOMAINS: "acme.test",
    SELFHOST_SIGNIN_METHODS: options.smtp === false ? "password" : "email_link,password",
    RELAYCAST_INTERNAL_SECRET: RELAYCAST_SECRET,
    // Required (explicitly, even 0) whenever password sign-in is on.
    SELFHOST_TRUSTED_PROXIES: proxies ?? "0",
    ...(options.smtp === false ? {} : SMTP),
    ...options.env,
  });
  const clock = { now: Date.now() };
  const mailer = fakeMailer();
  const store = new ControlPlaneStore(database, KEYRING, 0, { tenancy: identityConfig.tenancy.mode });
  const bootstrap = identityConfig.bootstrap!;
  const identityStore = new IdentityStore(database, KEYRING, {
    inviteTtlMs: identityConfig.inviteTtlMs,
    autoJoinDomains: identityConfig.autoJoinDomains,
    tenancy: identityConfig.tenancy,
    issueSession: (tx, session) => store.issueBrowserSession(tx, session),
    adminEmails: bootstrap.adminEmails.filter((email) => email !== bootstrap.adminEmail),
  });
  const identity = createIdentityModule({
    config: identityConfig,
    identityStore,
    controlStore: store,
    database,
    keyring: KEYRING,
    dashboardUrl: config.dashboardUrl,
    mailer: options.smtp === false ? null : mailer,
    now: () => clock.now,
    log: () => undefined,
    ...(options.hibpFetch ? { hibpFetch: options.hibpFetch } : {}),
    ...(options.passwordHasher ? { passwordHasher: options.passwordHasher } : {}),
  });
  control.on("request", createApp({ config, store, identity }));
  t.after(async () => {
    await close(control);
    await close(relaycast);
    await database.close();
  });
  assert.equal(await bootstrapOnce({
    bootstrap,
    store: identityStore,
    provisioner: relaycastProvisioner(relaycastUrl, RELAYCAST_SECRET),
    log: () => undefined,
  }), "done");
  return { database, origin, mailer, identity, identityStore, store, clock };
}

export type Ctx = Awaited<ReturnType<typeof setup>>;

/** The token of an emailed password link: in the fragment, never the query. */
export function linkToken(message: OutgoingEmail, path: string): string {
  const url = new URL(/https?:\/\/\S+/.exec(message.text)![0]);
  assert.equal(url.pathname, path);
  assert.equal(url.search, "", "the token must not be in the query string");
  const token = new URLSearchParams(url.hash.slice(1)).get("token");
  assert.ok(token, "the link carries #token=");
  return token;
}

export function sessionCookie(res: Res): string {
  assert.ok(res.cookies.agent_relay_session, res.text);
  return `agent_relay_session=${encodeURIComponent(res.cookies.agent_relay_session!)}`;
}

export async function session(ctx: Ctx, cookie: string): Promise<Res> {
  return call(ctx.origin, "/cloud/api/auth/session", { cookie });
}

/** Registers an address and returns the token from its verification email. */
export async function verifyLink(ctx: Ctx, email: string, invite?: string): Promise<string> {
  const before = ctx.mailer.sent.length;
  const asked = await call(ctx.origin, `${API}/register`, { json: { email, ...(invite ? { invite } : {}) } });
  assert.equal(asked.status, 202, asked.text);
  await ctx.identity.idle();
  assert.equal(ctx.mailer.sent.length, before + 1);
  return linkToken(ctx.mailer.sent.at(-1)!, "/login/password/verify");
}

/** Registers and verifies an address; returns the set-password token. */
export async function setupToken(ctx: Ctx, email: string, invite?: string): Promise<string> {
  const verified = await call(ctx.origin, `${API}/verify`, { json: { token: await verifyLink(ctx, email, invite) } });
  assert.equal(verified.status, 200, verified.text);
  return verified.body.setupToken;
}

/** Register, verify, set the password; returns the signed-in response. */
export async function registerVerified(ctx: Ctx, email: string, password = PASSWORD, invite?: string): Promise<Res> {
  const set = await call(ctx.origin, `${API}/set`, { json: { token: await setupToken(ctx, email, invite), password } });
  assert.equal(set.status, 200, set.text);
  return set;
}

export async function login(ctx: Ctx, email: string, password: string, ip = "198.51.100.7"): Promise<Res> {
  return call(ctx.origin, "/api/v1/auth/password/login", { json: { email, password }, ip });
}

export async function auditActions(ctx: Ctx): Promise<Array<{ action: string; target: string | null }>> {
  const result = await ctx.database.query<{ action: string; target: string | null }>(
    "SELECT action, target FROM admin_audit_events ORDER BY created_at, id",
  );
  return result.rows;
}
