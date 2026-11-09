import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { ARGON2_BASELINE, loadIdentityConfig, parsePepperFile, type PasswordConfig } from "../src/identity/config.js";
import { IdentityStore } from "../src/identity/store.js";
import { createIdentityModule } from "../src/identity/routes.js";
import { bootstrapOnce, relaycastProvisioner } from "../src/identity/bootstrap.js";
import type { Mailer, OutgoingEmail } from "../src/identity/mailer.js";
import { PasswordHasher, parsePhcParams } from "../src/identity/password/hashing.js";
import {
  checkPasswordPolicy,
  commonPasswordSet,
  hibpCheck,
  isCommonPassword,
  type HibpFetch,
} from "../src/identity/password/policy.js";
import { lockDelayMs, LOCKOUT, RESET_TTL_MS } from "../src/identity/password/store.js";
import { close, listen, PGliteDatabase } from "./support/harness.js";

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const RELAYCAST_SECRET = "relaycast-internal-secret-0123456789abcdef";
const PASSWORD = "correct horse battery staple";
const SMTP = { SELFHOST_SMTP_HOST: "smtp.acme.test", SELFHOST_EMAIL_FROM: "Relay <relay@acme.test>" };

// ---- fakes and harness -------------------------------------------------------------

function fakeRelaycast() {
  let creates = 0;
  return createServer((req, res) => {
    res.writeHead(req.headers.authorization === `Bearer ${RELAYCAST_SECRET}` ? 201 : 401, { "content-type": "application/json" });
    creates += 1;
    res.end(JSON.stringify({ ok: true, data: { workspace_id: `9900${creates}`, api_key: `ar_ws_test_key_${creates}`, name: "Default" } }));
  });
}

function fakeMailer(): Mailer & { sent: OutgoingEmail[] } {
  const mailer = {
    sent: [] as OutgoingEmail[],
    async send(message: OutgoingEmail) {
      mailer.sent.push(message);
    },
  };
  return mailer;
}

function passwordConfig(overrides: Partial<PasswordConfig> = {}): PasswordConfig {
  return { argon2: { ...ARGON2_BASELINE }, peppers: [], currentPepperVersion: null, hibp: false, ...overrides };
}

type Res = { status: number; body: any; text: string; cookies: Record<string, string> };

async function call(origin: string, path: string, init: {
  method?: string;
  cookie?: string;
  json?: unknown;
  ip?: string;
  originHeader?: string | null;
} = {}): Promise<Res> {
  const headers: Record<string, string> = {};
  if (init.cookie) headers.cookie = init.cookie;
  if (init.ip) headers["x-forwarded-for"] = init.ip;
  let body: string | undefined;
  if (init.json !== undefined) {
    headers["content-type"] = "application/json";
    body = JSON.stringify(init.json);
  }
  const method = init.method ?? (init.json !== undefined ? "POST" : "GET");
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
  return { status: response.status, body: parsed, text, cookies };
}

async function setup(t: test.TestContext, options: { env?: Record<string, string>; hibpFetch?: HibpFetch } = {}) {
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
    relayauthUrl: "http://relayauth.invalid",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.selfhosted.test",
    relayauthApiKey: "rak_test",
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: null,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${origin}/`,
    port: 0,
    host: "127.0.0.1",
  };
  const identityConfig = loadIdentityConfig({
    SELFHOST_BOOTSTRAP_ORG_NAME: "Acme",
    SELFHOST_BOOTSTRAP_ADMIN_EMAIL: "admin@acme.test",
    SELFHOST_AUTO_JOIN_DOMAINS: "acme.test",
    SELFHOST_SIGNIN_METHODS: "email_link,password",
    RELAYCAST_INTERNAL_SECRET: RELAYCAST_SECRET,
    ...SMTP,
    ...options.env,
  });
  const clock = { now: Date.now() };
  const mailer = fakeMailer();
  const store = new ControlPlaneStore(database, KEYRING, 0, { tenancy: identityConfig.tenancy.mode });
  const bootstrap = identityConfig.bootstrap!;
  const identityStore = new IdentityStore(database, KEYRING, {
    inviteTtlMs: identityConfig.inviteTtlMs,
    autoJoinDomains: identityConfig.autoJoinDomains,
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
    mailer,
    now: () => clock.now,
    log: () => undefined,
    ...(options.hibpFetch ? { hibpFetch: options.hibpFetch } : {}),
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

type Ctx = Awaited<ReturnType<typeof setup>>;

function linkToken(message: OutgoingEmail, path: string): string {
  const url = new URL(/https?:\/\/\S+/.exec(message.text)![0]);
  assert.equal(url.pathname, path);
  return url.searchParams.get("token")!;
}

function sessionCookie(res: Res): string {
  assert.ok(res.cookies.agent_relay_session, res.text);
  return `agent_relay_session=${encodeURIComponent(res.cookies.agent_relay_session!)}`;
}

async function session(ctx: Ctx, cookie: string): Promise<Res> {
  return call(ctx.origin, "/cloud/api/auth/session", { cookie });
}

/** Registers and verifies a password; returns the signed-in response. */
async function registerVerified(ctx: Ctx, email: string, password = PASSWORD): Promise<Res> {
  const before = ctx.mailer.sent.length;
  const asked = await call(ctx.origin, "/api/v1/auth/password/register", { json: { email, password } });
  assert.equal(asked.status, 202, asked.text);
  await ctx.identity.idle();
  assert.equal(ctx.mailer.sent.length, before + 1);
  const token = linkToken(ctx.mailer.sent.at(-1)!, "/password/verify");
  const verified = await call(ctx.origin, "/api/v1/auth/password/verify", { json: { token } });
  assert.equal(verified.status, 200, verified.text);
  return verified;
}

async function login(ctx: Ctx, email: string, password: string, ip = "198.51.100.7"): Promise<Res> {
  return call(ctx.origin, "/api/v1/auth/password/login", { json: { email, password }, ip });
}

async function auditActions(ctx: Ctx): Promise<Array<{ action: string; target: string | null }>> {
  const result = await ctx.database.query<{ action: string; target: string | null }>(
    "SELECT action, target FROM selfhost_admin_audit_events ORDER BY created_at, id",
  );
  return result.rows;
}

// ---- hashing ---------------------------------------------------------------------

test("hashing: argon2id at the OWASP baseline, a fresh salt per hash, constant-time verify", async () => {
  const hasher = new PasswordHasher(passwordConfig());
  const one = await hasher.hash(PASSWORD);
  const two = await hasher.hash(PASSWORD);
  assert.match(one.hash, /^\$argon2id\$v=19\$m=19456,t=2,p=1\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/);
  assert.notEqual(one.hash, two.hash, "a random salt per password");
  assert.equal(one.params, "m=19456,t=2,p=1");
  assert.equal(one.pepperVersion, null);
  assert.deepEqual(parsePhcParams(one.hash), { memoryCost: 19456, timeCost: 2, parallelism: 1 });
  assert.deepEqual(await hasher.verify(PASSWORD, one), { ok: true, needsRehash: false });
  assert.deepEqual(await hasher.verify("not the password at all", one), { ok: false, needsRehash: false });
  assert.deepEqual(await hasher.verify(PASSWORD, { hash: "garbage", pepperVersion: null }), { ok: false, needsRehash: false });
});

test("hashing: env overrides may only raise the argon2id parameters", () => {
  const base = { ...SMTP, SELFHOST_SIGNIN_METHODS: "password" };
  assert.deepEqual(loadIdentityConfig(base).password!.argon2, ARGON2_BASELINE);
  assert.deepEqual(loadIdentityConfig({
    ...base,
    SELFHOST_PASSWORD_ARGON2_MEMORY_KIB: "65536",
    SELFHOST_PASSWORD_ARGON2_TIME_COST: "3",
    SELFHOST_PASSWORD_ARGON2_PARALLELISM: "2",
  }).password!.argon2, { memoryCost: 65536, timeCost: 3, parallelism: 2 });
  assert.throws(() => loadIdentityConfig({ ...base, SELFHOST_PASSWORD_ARGON2_MEMORY_KIB: "4096" }), /can only be raised/);
  assert.throws(() => loadIdentityConfig({ ...base, SELFHOST_PASSWORD_ARGON2_TIME_COST: "1" }), /can only be raised/);
  assert.throws(() => loadIdentityConfig({ ...base, SELFHOST_PASSWORD_ARGON2_PARALLELISM: "0" }), /can only be raised/);
  assert.throws(() => loadIdentityConfig({ ...base, SELFHOST_PASSWORD_HIBP: "maybe" }), /on or off/);
  assert.equal(loadIdentityConfig(base).password!.hibp, false, "HIBP is off by default");
});

test("hashing: raised parameters mark an older hash for re-hash", async () => {
  const old = await new PasswordHasher(passwordConfig()).hash(PASSWORD);
  const raised = new PasswordHasher(passwordConfig({ argon2: { ...ARGON2_BASELINE, timeCost: 3 } }));
  assert.deepEqual(await raised.verify(PASSWORD, old), { ok: true, needsRehash: true });
  const fresh = await raised.hash(PASSWORD);
  assert.equal(fresh.params, "m=19456,t=3,p=1");
  assert.deepEqual(await raised.verify(PASSWORD, fresh), { ok: true, needsRehash: false });
});

test("pepper: versioned file, HMAC before hashing, rotation re-hashes, a dropped pepper cannot verify", async () => {
  const v1 = "a".repeat(32);
  const v2 = "b".repeat(40);
  assert.deepEqual(parsePepperFile(`${v1}\n`).map((p) => p.version), [1]);
  assert.deepEqual(parsePepperFile(`# rotated\n1:${v1}\nv2:${v2}\n`).map((p) => p.version), [2, 1]);
  assert.throws(() => parsePepperFile("1:short"), /at least 32 bytes/);
  assert.throws(() => parsePepperFile(`1:${v1}\n1:${v2}`), /repeats version 1/);
  assert.throws(() => parsePepperFile(`${v1}\n${v2}`), /<version>:<secret>/);
  assert.throws(() => parsePepperFile("\n# nothing\n"), /empty/);

  const dir = mkdtempSync(join(tmpdir(), "pepper-"));
  const file = join(dir, "pepper");
  writeFileSync(file, `1:${v1}\n2:${v2}\n`);
  const loaded = loadIdentityConfig({ ...SMTP, SELFHOST_SIGNIN_METHODS: "password", SELFHOST_PASSWORD_PEPPER_FILE: file }).password!;
  assert.equal(loaded.currentPepperVersion, 2);

  const unpeppered = await new PasswordHasher(passwordConfig()).hash(PASSWORD);
  const onlyV1 = new PasswordHasher(passwordConfig({ peppers: parsePepperFile(`1:${v1}`), currentPepperVersion: 1 }));
  const peppered = await onlyV1.hash(PASSWORD);
  assert.equal(peppered.pepperVersion, 1);
  // The stored hash is of HMAC(pepper, password): without the pepper it does not verify.
  assert.equal((await new PasswordHasher(passwordConfig()).verify(PASSWORD, { hash: peppered.hash, pepperVersion: null })).ok, false);
  // Adding a pepper re-hashes unpeppered hashes on the next sign-in.
  assert.deepEqual(await onlyV1.verify(PASSWORD, unpeppered), { ok: true, needsRehash: true });
  // Rotating to v2 keeps v1 hashes working and marks them for re-hash.
  const rotated = new PasswordHasher(loaded);
  assert.deepEqual(await rotated.verify(PASSWORD, peppered), { ok: true, needsRehash: true });
  assert.equal((await rotated.hash(PASSWORD)).pepperVersion, 2);
  // Once v1 is removed from the file its hashes no longer verify.
  const v2only = new PasswordHasher(passwordConfig({ peppers: parsePepperFile(`2:${v2}`), currentPepperVersion: 2 }));
  assert.deepEqual(await v2only.verify(PASSWORD, peppered), { ok: false, needsRehash: false });
});

// ---- policy ------------------------------------------------------------------------

test("policy: 12-128 code points, no composition rules, bundled common list, email local part", () => {
  const set = commonPasswordSet();
  assert.ok(set.size >= 9_000 && set.size <= 10_001, `bundled list size ${set.size}`);
  assert.ok([...set].every((entry) => entry === entry.toLowerCase()), "entries are lowercase");
  assert.ok(set.has("password") && set.has("unbelievable"));

  assert.equal(checkPasswordPolicy("short pass", "a@b.test"), "password_too_short");
  assert.equal(checkPasswordPolicy("x".repeat(129), "a@b.test"), "password_too_long");
  assert.equal(checkPasswordPolicy("🙂".repeat(12), "a@b.test"), null, "lengths count code points");
  assert.equal(checkPasswordPolicy("🙂".repeat(11), "a@b.test"), "password_too_short");
  assert.equal(checkPasswordPolicy("x".repeat(128), "a@b.test"), null);
  assert.equal(checkPasswordPolicy("alllowercaseletters", "a@b.test"), null, "no composition rules");
  assert.equal(checkPasswordPolicy("Unbelievable", "a@b.test"), "password_common", "case-insensitive match");
  assert.equal(checkPasswordPolicy("sunshine2024!!", "a@b.test"), "password_common", "a common word plus a short suffix");
  assert.equal(isCommonPassword("sunshine and showers"), false);
  assert.equal(checkPasswordPolicy("my name is Margaret ok", "margaret@acme.test"), "password_contains_email");
  assert.equal(checkPasswordPolicy("jo is a fine passphrase", "jo@acme.test"), null, "very short local parts are ignored");
});

test("HIBP: k-anonymity range lookup; breached, clean and unreachable", async () => {
  const digest = createHash("sha1").update(PASSWORD).digest("hex").toUpperCase();
  const asked: string[] = [];
  const fake = (rows: string): HibpFetch => async (url, init) => {
    asked.push(url);
    assert.equal(init.headers["add-padding"], "true");
    return { ok: true, status: 200, text: async () => rows };
  };
  assert.equal(await hibpCheck(PASSWORD, { fetch: fake(`0000000000000000000000000000000000A:0\r\n${digest.slice(5)}:42`) }), "breached");
  assert.equal(asked.at(-1), `https://api.pwnedpasswords.com/range/${digest.slice(0, 5)}`, "only the 5-character prefix leaves");
  assert.ok(!asked.at(-1)!.includes(digest.slice(5)));
  assert.equal(await hibpCheck(PASSWORD, { fetch: fake(`${digest.slice(5)}:0`) }), "clean", "padding rows (count 0) do not count");
  assert.equal(await hibpCheck(PASSWORD, { fetch: async () => ({ ok: false, status: 503, text: async () => "" }) }), "unavailable");
  assert.equal(await hibpCheck(PASSWORD, { fetch: async () => { throw new Error("offline"); } }), "unavailable");
});

// ---- config, login-config and disabled methods ----------------------------------------

test("config: SELFHOST_SIGNIN_METHODS, logo URL and admin email lists", () => {
  assert.deepEqual(loadIdentityConfig({}).signinMethods, []);
  assert.deepEqual(loadIdentityConfig({ ...SMTP, SELFHOST_EMAIL_LOGIN: "true" }).signinMethods, ["email_link"], "email_link by default");
  const both = loadIdentityConfig({ ...SMTP, SELFHOST_SIGNIN_METHODS: "password, email_link" });
  assert.deepEqual(both.signinMethods, ["password", "email_link"]);
  assert.equal(both.emailLogin, true);
  assert.equal(loadIdentityConfig({ ...SMTP, SELFHOST_SIGNIN_METHODS: "password" }).emailLogin, false);
  assert.throws(() => loadIdentityConfig({ ...SMTP, SELFHOST_SIGNIN_METHODS: "sms" }), /email_link and\/or password/);
  assert.throws(() => loadIdentityConfig({ SELFHOST_SIGNIN_METHODS: "password" }), /SMTP/);
  assert.throws(() => loadIdentityConfig({ ...SMTP, SELFHOST_EMAIL_LOGIN: "true", SELFHOST_SIGNIN_METHODS: "password" }), /conflicts/);

  assert.equal(loadIdentityConfig({ SELFHOST_LOGIN_LOGO_URL: "https://cdn.example.test/logo.svg" }).logoUrl, "https://cdn.example.test/logo.svg");
  assert.throws(() => loadIdentityConfig({ SELFHOST_LOGIN_LOGO_URL: "http://cdn.example.test/logo.svg" }), /https/);
  assert.throws(() => loadIdentityConfig({ SELFHOST_LOGIN_LOGO_URL: "https://user:pw@cdn.example.test/logo.svg" }), /credentials/);
  assert.throws(() => loadIdentityConfig({ SELFHOST_LOGIN_LOGO_URL: "javascript:alert(1)" }), /https/);
  assert.throws(() => loadIdentityConfig({ SELFHOST_LOGIN_LOGO_URL: "logo.svg" }), /absolute https URL/);

  const listed = loadIdentityConfig({ SELFHOST_BOOTSTRAP_ORG_NAME: "Acme", SELFHOST_ADMIN_EMAILS: "Ann@Acme.test, bo@acme.test,ann@acme.test" });
  assert.deepEqual(listed.bootstrap!.adminEmails, ["ann@acme.test", "bo@acme.test"]);
  assert.equal(listed.bootstrap!.adminEmail, null);
  const aliased = loadIdentityConfig({ SELFHOST_BOOTSTRAP_ORG_NAME: "Acme", SELFHOST_BOOTSTRAP_ADMIN_EMAIL: "root@acme.test", SELFHOST_ADMIN_EMAILS: "bo@acme.test" });
  assert.deepEqual(aliased.bootstrap!.adminEmails, ["root@acme.test", "bo@acme.test"]);
  assert.throws(() => loadIdentityConfig({ SELFHOST_ADMIN_EMAILS: "bo@acme.test" }), /SELFHOST_BOOTSTRAP_ORG_NAME/);
  assert.throws(() => loadIdentityConfig({ SELFHOST_BOOTSTRAP_ORG_NAME: "Acme", SELFHOST_ADMIN_EMAILS: "not-an-email" }), /email addresses/);
});

test("login-config: public, lists methods, logo and domain hint, never secrets", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "pepper-"));
  writeFileSync(join(dir, "pepper"), "1:" + "s".repeat(40));
  const ctx = await setup(t, { env: { SELFHOST_LOGIN_LOGO_URL: "https://cdn.example.test/logo.svg", SELFHOST_PASSWORD_PEPPER_FILE: join(dir, "pepper") } });
  const res = await call(ctx.origin, "/api/v1/auth/login-config");
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, {
    methods: ["email_link", "password"],
    oidc: null,
    logo_url: "https://cdn.example.test/logo.svg",
    allowed_domain_hint: true,
    password_policy: { min_length: 12, max_length: 128 },
  });
  assert.ok(!res.text.includes("sss"), "no pepper");
  assert.ok(!res.text.includes("acme.test"), "the hint is a boolean, not the domain list");
  assert.equal((await call(ctx.origin, "/cloud/api/v1/auth/login-config")).status, 200, "also on the /cloud alias");
});

test("disabled methods answer 404 signin_method_disabled", async (t) => {
  const linkOnly = await setup(t, { env: { SELFHOST_SIGNIN_METHODS: "email_link", SELFHOST_AUTO_JOIN_DOMAINS: "" } });
  for (const route of ["login", "register", "verify", "reset", "reset/complete"]) {
    const res = await call(linkOnly.origin, `/api/v1/auth/password/${route}`, { json: {} });
    assert.equal(res.status, 404, route);
    assert.equal(res.body.error, "signin_method_disabled");
  }
  const config = await call(linkOnly.origin, "/api/v1/auth/login-config");
  assert.deepEqual(config.body.methods, ["email_link"]);
  assert.equal(config.body.allowed_domain_hint, false);
  assert.equal(config.body.password_policy, null);

  const passwordOnly = await setup(t, { env: { SELFHOST_SIGNIN_METHODS: "password" } });
  const post = await call(passwordOnly.origin, "/login/email", { method: "POST", json: { email: "admin@acme.test" } });
  assert.equal(post.status, 404);
  assert.equal(post.body.error, "signin_method_disabled");
  const verify = await call(passwordOnly.origin, "/login/email/verify?token=x");
  assert.equal(verify.status, 404);
  assert.equal(verify.body.error, "signin_method_disabled");
  assert.deepEqual((await call(passwordOnly.origin, "/api/v1/auth/login-config")).body.methods, ["password"]);
});

// ---- registration and verification --------------------------------------------------

test("registration: verified email first, eligible addresses only, identical 202s", async (t) => {
  const ctx = await setup(t);
  const asked = await call(ctx.origin, "/api/v1/auth/password/register", { json: { email: "Dev@Acme.test", password: PASSWORD } });
  assert.equal(asked.status, 202);
  const stranger = await call(ctx.origin, "/api/v1/auth/password/register", { json: { email: "dev@elsewhere.test", password: PASSWORD } });
  assert.equal(stranger.status, 202);
  assert.equal(stranger.text, asked.text, "the same answer for an address that may not register");
  await ctx.identity.idle();
  assert.equal(ctx.mailer.sent.length, 1, "only the eligible address gets mail");
  assert.equal(ctx.mailer.sent[0]!.to, "dev@acme.test");
  assert.ok(!ctx.mailer.sent[0]!.text.includes(PASSWORD));
  const token = linkToken(ctx.mailer.sent[0]!, "/password/verify");

  // The password does nothing until the address is verified.
  assert.equal((await login(ctx, "dev@acme.test", PASSWORD)).status, 401);
  const pending = await ctx.database.query<{ password_hash: string; token_hash: string }>("SELECT password_hash, token_hash FROM selfhost_password_registrations");
  assert.match(pending.rows[0]!.password_hash, /^\$argon2id\$/);
  assert.notEqual(pending.rows[0]!.token_hash, token, "only the token hash is stored");

  const crossSite = await call(ctx.origin, "/api/v1/auth/password/verify", { json: { token }, originHeader: "https://evil.example" });
  assert.equal(crossSite.status, 403);
  const verified = await call(ctx.origin, "/api/v1/auth/password/verify", { json: { token } });
  assert.equal(verified.status, 200, verified.text);
  assert.equal(verified.body.email, "dev@acme.test");
  assert.equal(verified.body.accessToken, undefined, "the token travels only in the HttpOnly cookie");
  assert.equal((await session(ctx, sessionCookie(verified))).status, 200);
  assert.equal((await call(ctx.origin, "/api/v1/auth/password/verify", { json: { token } })).body.error, "token_invalid", "single use");

  const signedIn = await login(ctx, "DEV@acme.test", PASSWORD);
  assert.equal(signedIn.status, 200, signedIn.text);
  assert.equal((await session(ctx, sessionCookie(signedIn))).status, 200);

  // Registering again mails a reset pointer instead of a link.
  await call(ctx.origin, "/api/v1/auth/password/register", { json: { email: "dev@acme.test", password: "another long passphrase" } });
  await ctx.identity.idle();
  assert.equal(ctx.mailer.sent.length, 2);
  assert.match(ctx.mailer.sent[1]!.text, /already has one/);
  assert.doesNotMatch(ctx.mailer.sent[1]!.text, /token=/);
  assert.equal((await login(ctx, "dev@acme.test", PASSWORD)).status, 200, "the password did not change");
});

test("registration: invitees may register; policy errors are reported before any mail", async (t) => {
  const ctx = await setup(t, { env: { SELFHOST_AUTO_JOIN_DOMAINS: "" } });
  const orgs = await call(ctx.origin, "/api/v1/organizations", { method: "GET" });
  void orgs;
  const organization = (await ctx.database.query<{ id: string }>("SELECT id FROM selfhost_organizations")).rows[0]!.id;
  // Not invited and no auto-join domain: no mail.
  await call(ctx.origin, "/api/v1/auth/password/register", { json: { email: "guest@partner.test", password: PASSWORD } });
  await ctx.identity.idle();
  assert.equal(ctx.mailer.sent.length, 0);
  await ctx.identityStore.createInvitation({ organizationId: organization, email: "guest@partner.test", role: "member", actor: { kind: "bootstrap" } });
  const invited = await registerVerified(ctx, "guest@partner.test");
  assert.equal(invited.body.organizationId, organization);

  for (const [password, code] of [["short", "password_too_short"], ["Unbelievable", "password_common"], ["guest-partner password!", "password_contains_email"]] as const) {
    const res = await call(ctx.origin, "/api/v1/auth/password/register", { json: { email: "guest@partner.test", password } });
    assert.equal(res.status, 400, password);
    assert.equal(res.body.error, code);
  }
});

test("registration: pending links expire and only the newest works", async (t) => {
  const ctx = await setup(t);
  await call(ctx.origin, "/api/v1/auth/password/register", { json: { email: "ex@acme.test", password: PASSWORD } });
  await call(ctx.origin, "/api/v1/auth/password/register", { json: { email: "ex@acme.test", password: PASSWORD } });
  await ctx.identity.idle();
  const [first, second] = ctx.mailer.sent.map((m) => linkToken(m, "/password/verify"));
  assert.equal((await call(ctx.origin, "/api/v1/auth/password/verify", { json: { token: first } })).status, 410);
  ctx.clock.now += 61 * 60 * 1_000;
  const expired = await call(ctx.origin, "/api/v1/auth/password/verify", { json: { token: second } });
  assert.equal(expired.status, 410);
  assert.equal(expired.body.error, "token_invalid");
});

test("HIBP on: breached passwords refused; unreachable fails open with an audit event; off never calls out", async (t) => {
  const digest = createHash("sha1").update(PASSWORD).digest("hex").toUpperCase();
  let mode: "breached" | "down" = "breached";
  let calls = 0;
  const hibpFetch: HibpFetch = async () => {
    calls += 1;
    if (mode === "down") throw new Error("unreachable");
    return { ok: true, status: 200, text: async () => `${digest.slice(5)}:7` };
  };
  const on = await setup(t, { env: { SELFHOST_PASSWORD_HIBP: "on" }, hibpFetch });
  const breached = await call(on.origin, "/api/v1/auth/password/register", { json: { email: "h@acme.test", password: PASSWORD } });
  assert.equal(breached.status, 400);
  assert.equal(breached.body.error, "password_breached");
  mode = "down";
  const open = await call(on.origin, "/api/v1/auth/password/register", { json: { email: "h@acme.test", password: PASSWORD } });
  assert.equal(open.status, 202);
  assert.ok((await auditActions(on)).some((e) => e.action === "password.hibp.unavailable"));
  assert.equal(calls, 2);

  const off = await setup(t, { hibpFetch });
  assert.equal((await call(off.origin, "/api/v1/auth/password/register", { json: { email: "h@acme.test", password: PASSWORD } })).status, 202);
  assert.equal(calls, 2, "HIBP is off by default");
});

// ---- login, lockout and enumeration -------------------------------------------------------

test("login: unknown, wrong and locked answer the same 401 invalid_credentials", async (t) => {
  const ctx = await setup(t);
  await registerVerified(ctx, "lock@acme.test");
  const unknown = await login(ctx, "nobody@acme.test", PASSWORD);
  const wrong = await login(ctx, "lock@acme.test", "wrong password here");
  const malformed = await login(ctx, "not-an-email", PASSWORD);
  for (const res of [unknown, wrong, malformed]) {
    assert.equal(res.status, 401);
    assert.deepEqual(res.body, { error: "invalid_credentials", message: "Incorrect email or password." });
  }
  // Four more failures reach the free allowance (5); the sixth locks.
  for (let i = 0; i < 4; i += 1) assert.equal((await login(ctx, "lock@acme.test", `wrong password ${i}!`)).status, 401);
  assert.equal((await login(ctx, "lock@acme.test", "wrong password again")).status, 401);
  const locked = await login(ctx, "lock@acme.test", PASSWORD);
  assert.equal(locked.status, 401, "the right password is refused while locked");
  assert.deepEqual(locked.body, wrong.body);
  assert.equal(locked.text, wrong.text);
  // A lock on an unknown address looks the same.
  for (let i = 0; i < 6; i += 1) await login(ctx, "ghost@acme.test", PASSWORD);
  assert.equal((await login(ctx, "ghost@acme.test", PASSWORD)).text, locked.text);

  // After the backoff the right password works and clears the counter.
  ctx.clock.now += lockDelayMs(6, LOCKOUT.account.free) + 1_000;
  const after = await login(ctx, "lock@acme.test", PASSWORD);
  assert.equal(after.status, 200, after.text);
  const rows = await ctx.database.query("SELECT 1 FROM selfhost_login_attempts WHERE subject = 'account:lock@acme.test'");
  assert.equal(rows.rows.length, 0);

  const actions = await auditActions(ctx);
  assert.ok(actions.some((e) => e.action === "login.lockout" && e.target!.includes("scope=account")));
  assert.ok(actions.some((e) => e.action === "login.password.failure" && e.target!.includes("reason=locked")));
  assert.ok(actions.some((e) => e.action === "login.password.failure" && e.target!.includes("reason=unknown_account")));
  assert.ok(actions.some((e) => e.action === "login.password.success"));
  for (const event of actions) assert.ok(!(event.target ?? "").includes(PASSWORD) && !(event.target ?? "").includes("wrong password"), "no secrets in audit");
});

test("lockout: exponential backoff with a cap, per IP as well as per account", async (t) => {
  assert.equal(lockDelayMs(5, 5), 0);
  assert.equal(lockDelayMs(6, 5), 30_000);
  assert.equal(lockDelayMs(7, 5), 60_000);
  assert.equal(lockDelayMs(8, 5), 120_000);
  assert.equal(lockDelayMs(50, 5), 15 * 60_000, "capped");

  const ctx = await setup(t);
  await registerVerified(ctx, "ip@acme.test");
  // Spraying many addresses from one IP locks that IP, not the accounts.
  for (let i = 0; i <= LOCKOUT.ip.free; i += 1) await login(ctx, `spray${i}@acme.test`, PASSWORD, "203.0.113.9");
  assert.equal((await login(ctx, "ip@acme.test", PASSWORD, "203.0.113.9")).status, 401);
  assert.equal((await login(ctx, "ip@acme.test", PASSWORD, "203.0.113.10")).status, 200, "another IP is unaffected");
  assert.ok((await auditActions(ctx)).some((e) => e.action === "login.lockout" && e.target!.includes("scope=ip")));
  // Idle for a whole window, the IP starts over.
  ctx.clock.now += LOCKOUT.windowMs + 60_000;
  assert.equal((await login(ctx, "ip@acme.test", PASSWORD, "203.0.113.9")).status, 200);
});

test("login: unknown accounts spend a comparable argon2id verification", async (t) => {
  const ctx = await setup(t);
  await registerVerified(ctx, "timing@acme.test");
  const timed = async (email: string) => {
    const started = performance.now();
    await login(ctx, email, "a wrong password for timing", `192.0.2.${Math.floor(Math.random() * 200)}`);
    return performance.now() - started;
  };
  await timed("warmup@acme.test");
  let unknown = 0;
  let wrong = 0;
  for (let i = 0; i < 3; i += 1) {
    unknown += await timed(`missing${i}@acme.test`);
    wrong += await timed("timing@acme.test");
  }
  // Generous bounds for a shared CI host: both paths include one hash.
  assert.ok(unknown > wrong * 0.4, `unknown ${unknown.toFixed(1)}ms vs wrong ${wrong.toFixed(1)}ms`);
});

test("login: re-hashes on success when the pepper version changed", async (t) => {
  const dir = mkdtempSync(join(tmpdir(), "pepper-"));
  writeFileSync(join(dir, "pepper"), "3:" + "p".repeat(40));
  const ctx = await setup(t, { env: { SELFHOST_PASSWORD_PEPPER_FILE: join(dir, "pepper") } });
  await registerVerified(ctx, "re@acme.test");
  const user = (await ctx.database.query<{ id: string }>("SELECT id FROM selfhost_users WHERE email = 're@acme.test'")).rows[0]!.id;
  // Simulate a hash made before the pepper existed.
  const legacy = await new PasswordHasher(passwordConfig()).hash(PASSWORD);
  await ctx.database.query("UPDATE selfhost_password_credentials SET password_hash = $2, pepper_version = NULL WHERE user_id = $1", [user, legacy.hash]);
  assert.equal((await login(ctx, "re@acme.test", PASSWORD)).status, 200);
  const row = (await ctx.database.query<{ password_hash: string; pepper_version: number | null; params: string }>(
    "SELECT password_hash, pepper_version, params FROM selfhost_password_credentials WHERE user_id = $1", [user],
  )).rows[0]!;
  assert.equal(row.pepper_version, 3);
  assert.notEqual(row.password_hash, legacy.hash);
  assert.equal(row.params, "m=19456,t=2,p=1");
  assert.equal((await login(ctx, "re@acme.test", PASSWORD)).status, 200);
  assert.ok((await auditActions(ctx)).some((e) => e.action === "login.password.success" && e.target!.includes("rehashed=true")));
});

// ---- reset ----------------------------------------------------------------------------

test("reset: identical 202s, single-use 30-minute token, revokes every session", async (t) => {
  const ctx = await setup(t);
  const registered = await registerVerified(ctx, "rs@acme.test");
  const first = sessionCookie(registered);
  const second = sessionCookie(await login(ctx, "rs@acme.test", PASSWORD));
  const sent = ctx.mailer.sent.length;

  const known = await call(ctx.origin, "/api/v1/auth/password/reset", { json: { email: "rs@acme.test" } });
  const unknown = await call(ctx.origin, "/api/v1/auth/password/reset", { json: { email: "nobody@acme.test" } });
  const malformed = await call(ctx.origin, "/api/v1/auth/password/reset", { json: { email: "nope" } });
  for (const res of [known, unknown, malformed]) {
    assert.equal(res.status, 202);
    assert.equal(res.text, known.text);
  }
  await ctx.identity.idle();
  assert.equal(ctx.mailer.sent.length, sent + 1, "mail only for an address with a password");
  const token = linkToken(ctx.mailer.sent.at(-1)!, "/password/reset");
  const stored = await ctx.database.query<{ token_hash: string; expires_at: Date; created_at: Date }>("SELECT token_hash, expires_at FROM selfhost_password_reset_tokens");
  assert.notEqual(stored.rows[0]!.token_hash, token, "stored only as a hash");
  assert.ok(new Date(stored.rows[0]!.expires_at).getTime() - ctx.clock.now <= RESET_TTL_MS + 1_000);
  assert.equal(RESET_TTL_MS, 30 * 60 * 1_000);

  const weak = await call(ctx.origin, "/api/v1/auth/password/reset/complete", { json: { token, password: "Unbelievable" } });
  assert.equal(weak.status, 400);
  assert.equal(weak.body.error, "password_common");
  const NEW = "a brand new long passphrase";
  const done = await call(ctx.origin, "/api/v1/auth/password/reset/complete", { json: { token, password: NEW } });
  assert.equal(done.status, 200, done.text);
  assert.equal(done.body.status, "password_reset");
  assert.ok(done.body.sessionsRevoked >= 2);
  assert.equal((await session(ctx, first)).status, 401, "existing sessions are revoked");
  assert.equal((await session(ctx, second)).status, 401);
  const reasons = await ctx.database.query<{ revoked_reason: string }>("SELECT DISTINCT revoked_reason FROM selfhost_token_sessions WHERE revoked_at IS NOT NULL");
  assert.deepEqual(reasons.rows.map((r) => r.revoked_reason), ["password_reset"]);
  assert.equal((await call(ctx.origin, "/api/v1/auth/password/reset/complete", { json: { token, password: NEW } })).status, 410, "single use");
  assert.equal((await login(ctx, "rs@acme.test", PASSWORD)).status, 401, "the old password no longer works");
  assert.equal((await login(ctx, "rs@acme.test", NEW)).status, 200);

  // Expiry.
  await call(ctx.origin, "/api/v1/auth/password/reset", { json: { email: "rs@acme.test" } });
  await ctx.identity.idle();
  const late = linkToken(ctx.mailer.sent.at(-1)!, "/password/reset");
  ctx.clock.now += RESET_TTL_MS + 1_000;
  const expired = await call(ctx.origin, "/api/v1/auth/password/reset/complete", { json: { token: late, password: "yet another passphrase" } });
  assert.equal(expired.status, 410);
  assert.equal(expired.body.error, "token_invalid");

  const actions = (await auditActions(ctx)).map((e) => e.action);
  assert.ok(actions.includes("password.reset.requested"));
  assert.ok(actions.includes("password.reset.completed"));
});

// ---- admin emails -------------------------------------------------------------------------

test("admin emails: the first to verify becomes owner, the rest admin", async (t) => {
  const ctx = await setup(t, {
    env: { SELFHOST_BOOTSTRAP_ADMIN_EMAIL: "", SELFHOST_ADMIN_EMAILS: "first@partner.test,second@partner.test", SELFHOST_AUTO_JOIN_DOMAINS: "" },
  });
  const owners = await ctx.database.query("SELECT 1 FROM selfhost_organization_memberships WHERE role = 'owner'");
  assert.equal(owners.rows.length, 0, "no owner until an admin email verifies");
  // The second listed address verifies first and becomes owner.
  const second = await registerVerified(ctx, "second@partner.test");
  const first = await registerVerified(ctx, "first@partner.test");
  const role = async (email: string) => (await ctx.database.query<{ role: string }>(
    "SELECT m.role FROM selfhost_organization_memberships m JOIN selfhost_users u ON u.id = m.user_id WHERE u.email = $1", [email],
  )).rows[0]?.role;
  assert.equal(await role("second@partner.test"), "owner");
  assert.equal(await role("first@partner.test"), "admin");
  assert.equal(second.body.organizationId, first.body.organizationId);
  const actions = (await auditActions(ctx)).map((e) => e.action);
  assert.ok(actions.includes("membership.admin_email_owner"));
  assert.ok(actions.includes("membership.admin_email_admin"));
  // A grant is recorded once: a later demotion is not undone by signing in again.
  await ctx.database.query(
    "UPDATE selfhost_organization_memberships SET role = 'member' WHERE user_id = (SELECT id FROM selfhost_users WHERE email = 'first@partner.test')",
  );
  assert.equal((await login(ctx, "first@partner.test", PASSWORD)).status, 200);
  assert.equal(await role("first@partner.test"), "member");
});

test("openapi.yaml documents login-config and every password route", async () => {
  const { readFile } = await import("node:fs/promises");
  const spec = await readFile(new URL("../openapi.yaml", import.meta.url), "utf8");
  for (const path of ["login-config", "password/register", "password/verify", "password/login", "password/reset", "password/reset/complete"]) {
    assert.ok(spec.includes(`\n  /api/v1/auth/${path}:\n`), path);
  }
  for (const code of ["invalid_credentials", "signin_method_disabled", "password_common", "token_invalid", "password_already_set"]) {
    assert.ok(spec.includes(code), code);
  }
});
