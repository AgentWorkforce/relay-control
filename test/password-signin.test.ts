import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import test from "node:test";
import { parse as parseYaml } from "yaml";
import { ARGON2_BASELINE, loadIdentityConfig, parsePepperFile } from "../src/identity/config.js";
import { PasswordHasher, parsePhcParams } from "../src/identity/password/hashing.js";
import {
  checkPasswordPolicy,
  commonPasswordSet,
  hibpCheck,
  isCommonPassword,
  type HibpFetch,
} from "../src/identity/password/policy.js";
import { lockDelayMs, LOCKOUT, REGISTRATION_TTL_MS, RESET_TTL_MS, SETUP_TTL_MS } from "../src/identity/password/store.js";
import {
  API,
  auditActions,
  call,
  linkToken,
  login,
  passwordConfig,
  PASSWORD,
  pepperFile,
  registerVerified,
  session,
  sessionCookie,
  setup,
  setupToken,
  SMTP,
  verifyLink,
} from "./support/password.js";

// Registration, login, lockout and reset. Hardening (concurrency, proxies,
// pepper file permissions, revocation, rate limits, the /login form and
// retention) is in password-hardening.test.ts.

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
  const base = { ...SMTP, SELFHOST_SIGNIN_METHODS: "password", SELFHOST_TRUSTED_PROXIES: "0" };
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
  assert.deepEqual(parsePepperFile(`v1:${v1}\n`).map((p) => p.version), [1]);
  assert.deepEqual(parsePepperFile(`# rotated\nv1:${v1}\nv2:${v2}\n`).map((p) => p.version), [2, 1]);
  assert.throws(() => parsePepperFile("v1:short"), /at least 32 bytes/);
  assert.throws(() => parsePepperFile(`v1:${v1}\nv1:${v2}`), /repeats version 1/);
  // Every line needs the v<n>: prefix: a bare secret (or one that happens to
  // contain a colon) is never read as a version.
  assert.throws(() => parsePepperFile(v1), /v<version>:<secret>/);
  assert.throws(() => parsePepperFile(`1:${v1}`), /v<version>:<secret>/);
  assert.throws(() => parsePepperFile(`v1:${v1}\n${v2}`), /v<version>:<secret>/);
  assert.throws(() => parsePepperFile("\n# nothing\n"), /empty/);

  const file = pepperFile(`v1:${v1}\nv2:${v2}\n`);
  const loaded = loadIdentityConfig({ ...SMTP, SELFHOST_SIGNIN_METHODS: "password", SELFHOST_TRUSTED_PROXIES: "0", SELFHOST_PASSWORD_PEPPER_FILE: file }).password!;
  assert.equal(loaded.currentPepperVersion, 2);

  const unpeppered = await new PasswordHasher(passwordConfig()).hash(PASSWORD);
  const onlyV1 = new PasswordHasher(passwordConfig({ peppers: parsePepperFile(`v1:${v1}`), currentPepperVersion: 1 }));
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
  const v2only = new PasswordHasher(passwordConfig({ peppers: parsePepperFile(`v2:${v2}`), currentPepperVersion: 2 }));
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
  const both = loadIdentityConfig({ ...SMTP, SELFHOST_SIGNIN_METHODS: "password, email_link", SELFHOST_TRUSTED_PROXIES: "1" });
  assert.deepEqual(both.signinMethods, ["password", "email_link"]);
  assert.equal(both.emailLogin, true);
  assert.equal(loadIdentityConfig({ ...SMTP, SELFHOST_SIGNIN_METHODS: "password", SELFHOST_TRUSTED_PROXIES: "0" }).emailLogin, false);
  assert.throws(() => loadIdentityConfig({ ...SMTP, SELFHOST_SIGNIN_METHODS: "sms" }), /email_link and\/or password/);
  // Password sign-in needs no SMTP (only register and reset do); email links do.
  assert.deepEqual(loadIdentityConfig({ SELFHOST_SIGNIN_METHODS: "password", SELFHOST_TRUSTED_PROXIES: "0" }).signinMethods, ["password"]);
  assert.throws(() => loadIdentityConfig({ SELFHOST_SIGNIN_METHODS: "email_link" }), /SMTP/);
  assert.throws(() => loadIdentityConfig({ SELFHOST_SIGNIN_METHODS: "password,email_link", SELFHOST_TRUSTED_PROXIES: "0" }), /SMTP/);
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

test("config: password sign-in needs SELFHOST_TRUSTED_PROXIES set explicitly, even to 0", () => {
  const password = { ...SMTP, SELFHOST_SIGNIN_METHODS: "password" };
  // Unset: refuse to start, naming the variable.
  assert.throws(() => loadIdentityConfig(password), /SELFHOST_TRUSTED_PROXIES must be set explicitly, even to 0/);
  // Empty (and blank) count as not set.
  assert.throws(() => loadIdentityConfig({ ...password, SELFHOST_TRUSTED_PROXIES: "" }), /SELFHOST_TRUSTED_PROXIES must be set explicitly/);
  assert.throws(() => loadIdentityConfig({ ...password, SELFHOST_TRUSTED_PROXIES: "  " }), /SELFHOST_TRUSTED_PROXIES must be set explicitly/);
  // The literal 0 is an explicit answer: valid, zero hops.
  assert.deepEqual(loadIdentityConfig({ ...password, SELFHOST_TRUSTED_PROXIES: "0" }).signinMethods, ["password"]);
  assert.ok(loadIdentityConfig({ ...password, SELFHOST_TRUSTED_PROXIES: "1" }).password);
  // Bad values keep the existing message.
  for (const bad of ["-1", "100", "one", "1.5"]) {
    assert.throws(() => loadIdentityConfig({ ...password, SELFHOST_TRUSTED_PROXIES: bad }), /SELFHOST_TRUSTED_PROXIES must be an integer from 0 to 99/, bad);
  }
  // Without password sign-in the variable stays optional (default 0).
  assert.deepEqual(loadIdentityConfig({ ...SMTP, SELFHOST_SIGNIN_METHODS: "email_link" }).signinMethods, ["email_link"]);
});

test("/login: co-brands under the Agent Relay lockup and allows only the logo's origin", async (t) => {
  const ctx = await setup(t, { env: { SELFHOST_LOGIN_LOGO_URL: "https://cdn.example.test/logo.svg", SELFHOST_LOGIN_ORG_NAME: "Example <Corp>" } });
  const response = await fetch(`${ctx.origin}/login`);
  const html = await response.text();
  assert.match(response.headers.get("content-security-policy") ?? "", /; img-src https:\/\/cdn\.example\.test$/);
  assert.match(html, /class="mark"/);
  assert.match(html, /class="wordmark"[\s\S]*<div class="cobrand"><span>for<\/span><img src="https:\/\/cdn\.example\.test\/logo\.svg" alt="" referrerpolicy="no-referrer"><strong>Example &lt;Corp&gt;<\/strong>/);
  // Option B, the "for" line: the Agent Relay lockup, then one line naming the customer, in one flush-left column, with no rule.
  assert.match(html, /<header class="brand"><span class="lockup"><svg[^>]*class="mark"[\s\S]*class="wordmark"[\s\S]*<\/span><div class="cobrand"><span>for<\/span>/);
  assert.doesNotMatch(html, /<hr>/);
  assert.match(html, /\.brand\{display:flex;flex-direction:column;align-items:flex-start/);
  assert.doesNotMatch(html, /grid-column/);
});

test("/login: uses the Agent Relay brand palette with explicit link colours", async (t) => {
  const ctx = await setup(t);
  const html = await (await fetch(`${ctx.origin}/login`)).text();
  for (const token of ["--bg:#f9fafb", "--card:#fff", "--border:#d7e0e8", "--link:#2f6f9f", "--bg:#101c29", "--card:#182838", "--border:#30485e", "--link:#80bfe5"]) {
    assert.ok(html.includes(token), token);
  }
  assert.match(html, /a\{color:var\(--link\)/);
  assert.match(html, /a:visited\{color:var\(--link\)\}/);
  assert.doesNotMatch(html, /#fafaf9|#0c0a09|#1c1917/);
});

test("/login: without a logo shows only Agent Relay and publishes no name", async (t) => {
  const ctx = await setup(t, { env: { SELFHOST_LOGIN_ORG_NAME: "Example Corp" } });
  const response = await fetch(`${ctx.origin}/login`);
  const html = await response.text();
  assert.doesNotMatch(response.headers.get("content-security-policy") ?? "", /img-src/);
  assert.match(html, /class="wordmark"/);
  assert.doesNotMatch(html, /class="cobrand"|<hr>|Example Corp/);
  assert.equal((await call(ctx.origin, "/api/v1/auth/login-config")).body.org_name, null);
});

test("SELFHOST_LOGIN_ORG_NAME falls back to the bootstrap organization", () => {
  const bootstrap = { SELFHOST_BOOTSTRAP_ORG_NAME: "Example Corp", SELFHOST_BOOTSTRAP_ADMIN_EMAIL: "ops@example.test" };
  assert.equal(loadIdentityConfig(bootstrap).loginOrgName, "Example Corp");
  assert.equal(loadIdentityConfig({ ...bootstrap, SELFHOST_LOGIN_ORG_NAME: "  Example Labs " }).loginOrgName, "Example Labs");
  assert.equal(loadIdentityConfig({}).loginOrgName, null);
});

test("login-config: public, lists methods, logo and domain hint, never secrets", async (t) => {
  const ctx = await setup(t, { env: { SELFHOST_LOGIN_LOGO_URL: "https://cdn.example.test/logo.svg", SELFHOST_PASSWORD_PEPPER_FILE: pepperFile("v1:" + "s".repeat(40)) } });
  const res = await call(ctx.origin, "/api/v1/auth/login-config");
  assert.equal(res.status, 200);
  assert.deepEqual(res.body, {
    methods: ["email_link", "password"],
    oidc: null,
    microsoft: null,
    logo_url: "https://cdn.example.test/logo.svg",
    org_name: "Acme",
    allowed_domain_hint: true,
    password_policy: { min_length: 12, max_length: 128 },
    password_self_service: true,
    setup_key: false,
  });
  assert.ok(!res.text.includes("sss"), "no pepper");
  assert.ok(!res.text.includes("acme.test"), "the hint is a boolean, not the domain list");
  assert.equal((await call(ctx.origin, "/cloud/api/v1/auth/login-config")).status, 200, "also on the /cloud alias");
});

test("disabled methods answer 404 signin_method_disabled", async (t) => {
  const linkOnly = await setup(t, { env: { SELFHOST_SIGNIN_METHODS: "email_link", SELFHOST_AUTO_JOIN_DOMAINS: "" } });
  for (const route of ["login", "register", "verify", "set", "reset", "reset/complete"]) {
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

test("registration: register takes no password; verify proves the address and mints a 15-minute set-password token", async (t) => {
  const ctx = await setup(t);
  const asked = await call(ctx.origin, `${API}/register`, { json: { email: "Dev@Acme.test" } });
  assert.equal(asked.status, 202);
  const stranger = await call(ctx.origin, `${API}/register`, { json: { email: "dev@elsewhere.test" } });
  assert.equal(stranger.status, 202);
  assert.equal(stranger.text, asked.text, "the same answer for an address that may not register");
  const withPassword = await call(ctx.origin, `${API}/register`, { json: { email: "dev@acme.test", password: PASSWORD } });
  assert.equal(withPassword.status, 400, "a password is never accepted before the address is proven");
  await ctx.identity.idle();
  assert.equal(ctx.mailer.sent.length, 1, "only the eligible address gets mail");
  assert.equal(ctx.mailer.sent[0]!.to, "dev@acme.test");
  const token = linkToken(ctx.mailer.sent[0]!, "/login/password/verify");
  const pending = await ctx.database.query<{ token_hash: string }>("SELECT token_hash FROM password_registrations");
  assert.notEqual(pending.rows[0]!.token_hash, token, "only the token hash is stored");
  const columns = await ctx.database.query<{ column_name: string }>(
    "SELECT column_name FROM information_schema.columns WHERE table_name = 'password_registrations'",
  );
  assert.ok(!columns.rows.some((c) => c.column_name.includes("password")), "a pending registration holds no password");

  const crossSite = await call(ctx.origin, `${API}/verify`, { json: { token }, originHeader: "https://evil.example" });
  assert.equal(crossSite.status, 403);
  assert.equal(crossSite.body.error, "csrf_rejected");
  const verified = await call(ctx.origin, `${API}/verify`, { json: { token } });
  assert.equal(verified.status, 200, verified.text);
  assert.equal(verified.body.status, "verified");
  assert.equal(verified.body.email, "dev@acme.test");
  assert.match(verified.body.setupToken, /^sh_ps_/);
  assert.ok(Date.parse(verified.body.expiresAt) - ctx.clock.now <= SETUP_TTL_MS + 1_000);
  assert.equal(SETUP_TTL_MS, 15 * 60 * 1_000);
  assert.equal(verified.cookies.agent_relay_session, undefined, "verify alone signs nobody in");
  assert.equal((await ctx.database.query("SELECT 1 FROM users WHERE email = 'dev@acme.test'")).rows.length, 0, "no account yet");
  const again = await call(ctx.origin, `${API}/verify`, { json: { token } });
  assert.equal(again.status, 410, "single use");
  assert.equal(again.body.error, "token_invalid");
  assert.equal((await login(ctx, "dev@acme.test", PASSWORD)).status, 401);

  const setup_ = verified.body.setupToken as string;
  const weak = await call(ctx.origin, `${API}/set`, { json: { token: setup_, password: "Unbelievable" } });
  assert.equal(weak.status, 400);
  assert.equal(weak.body.error, "password_common");
  const set = await call(ctx.origin, `${API}/set`, { json: { token: setup_, password: PASSWORD } });
  assert.equal(set.status, 200, set.text);
  assert.equal(set.body.email, "dev@acme.test");
  assert.equal(set.body.accessToken, undefined, "the token travels only in the HttpOnly cookie");
  assert.equal((await session(ctx, sessionCookie(set))).status, 200);
  const reused = await call(ctx.origin, `${API}/set`, { json: { token: setup_, password: "another long passphrase" } });
  assert.equal(reused.status, 410, "the set-password token is single use");
  assert.equal(reused.body.error, "token_invalid");

  const signedIn = await login(ctx, "DEV@acme.test", PASSWORD);
  assert.equal(signedIn.status, 200, signedIn.text);
  assert.equal((await session(ctx, sessionCookie(signedIn))).status, 200);

  // The address hears that a password was added (in case it was not them).
  await ctx.identity.idle();
  assert.equal(ctx.mailer.sent.length, 2);
  const added = ctx.mailer.sent[1]!;
  assert.equal(added.to, "dev@acme.test");
  assert.equal(added.subject, "A password was added to your Agent Relay account");
  assert.equal(new URL(/https?:\/\/\S+/.exec(added.text)![0]).pathname, "/login/password/reset");
  assert.doesNotMatch(added.text, /token=/);

  // Registering again mails a reset pointer instead of a link.
  await call(ctx.origin, `${API}/register`, { json: { email: "dev@acme.test" } });
  await ctx.identity.idle();
  assert.equal(ctx.mailer.sent.length, 3);
  assert.match(ctx.mailer.sent[2]!.text, /already has one/);
  assert.doesNotMatch(ctx.mailer.sent[2]!.text, /token=/);
  assert.equal((await login(ctx, "dev@acme.test", PASSWORD)).status, 200, "the password did not change");
  const actions = (await auditActions(ctx)).map((e) => e.action);
  assert.ok(actions.includes("password.registration.verified"));
  assert.ok(actions.includes("password.registration.completed"));
});

test("registration: invitees may register (invite carried through verify); policy errors come from set", async (t) => {
  const ctx = await setup(t, { env: { SELFHOST_AUTO_JOIN_DOMAINS: "" } });
  const organization = (await ctx.database.query<{ id: string }>("SELECT id FROM organizations")).rows[0]!.id;
  // Not invited and no auto-join domain: no mail.
  await call(ctx.origin, `${API}/register`, { json: { email: "guest@partner.test" } });
  await ctx.identity.idle();
  assert.equal(ctx.mailer.sent.length, 0);
  await ctx.identityStore.createInvitation({ organizationId: organization, email: "guest@partner.test", role: "member", actor: { kind: "bootstrap" } });
  const token = await setupToken(ctx, "guest@partner.test");
  for (const [password, code] of [["short", "password_too_short"], ["Unbelievable", "password_common"], ["guest-partner password!", "password_contains_email"]] as const) {
    const res = await call(ctx.origin, `${API}/set`, { json: { token, password } });
    assert.equal(res.status, 400, password);
    assert.equal(res.body.error, code);
  }
  const invited = await call(ctx.origin, `${API}/set`, { json: { token, password: PASSWORD } });
  assert.equal(invited.status, 200, invited.text);
  assert.equal(invited.body.organizationId, organization);
});

test("registration: a newer link leaves older ones working until one is used; links expire; so do set-password tokens", async (t) => {
  const ctx = await setup(t);
  const first = await verifyLink(ctx, "ex@acme.test");
  const second = await verifyLink(ctx, "ex@acme.test");
  // Asking again must not cancel a link someone is about to use.
  const used = await call(ctx.origin, `${API}/verify`, { json: { token: first } });
  assert.equal(used.status, 200, "an older link still works after a newer request");
  // Using one link voids the address's others.
  assert.equal((await call(ctx.origin, `${API}/verify`, { json: { token: second } })).status, 410);
  const third = await verifyLink(ctx, "ex@acme.test");
  ctx.clock.now += REGISTRATION_TTL_MS + 60_000;
  const expired = await call(ctx.origin, `${API}/verify`, { json: { token: third } });
  assert.equal(expired.status, 410);
  assert.equal(expired.body.error, "token_invalid");

  // A second verification retires the first set-password token.
  const olderSetup = await setupToken(ctx, "ex@acme.test");
  const newerSetup = await setupToken(ctx, "ex@acme.test");
  assert.equal((await call(ctx.origin, `${API}/set`, { json: { token: olderSetup, password: PASSWORD } })).status, 410);
  ctx.clock.now += SETUP_TTL_MS + 1_000;
  const late = await call(ctx.origin, `${API}/set`, { json: { token: newerSetup, password: PASSWORD } });
  assert.equal(late.status, 410, "15 minutes at most");
  assert.equal(late.body.error, "token_invalid");
  assert.equal((await ctx.database.query("SELECT 1 FROM users WHERE email = 'ex@acme.test'")).rows.length, 0, "nothing was created");
  assert.equal((await call(ctx.origin, `${API}/set`, { json: { token: "sh_ps_" + "x".repeat(300), password: PASSWORD } })).status, 400, "tokens are at most 256 characters");
});

test("set-password: only with a token; an account without a password gets one, then every pending link is void", async (t) => {
  const ctx = await setup(t);
  // Signed in another way (an email link): an account with no password.
  const linked = await ctx.identityStore.signIn({ email: "sso@acme.test", name: null, inviteTokenHash: null, method: "email", emailVerified: true });
  const cookie = `agent_relay_session=${encodeURIComponent(linked.tokens.accessToken)}`;
  // A session alone never sets a password: the token (proof of the inbox) is required.
  for (const path of [`/cloud${API}/set`, `${API}/set`]) {
    const viaSession = await call(ctx.origin, path, { json: { password: PASSWORD }, cookie });
    assert.equal(viaSession.status, 400, path);
    assert.equal(viaSession.body.error, "invalid_request");
  }
  const laterLink = await verifyLink(ctx, "sso@acme.test");
  const setup_ = await setupToken(ctx, "sso@acme.test");
  const set = await call(ctx.origin, `${API}/set`, { json: { token: setup_, password: PASSWORD } });
  assert.equal(set.status, 200, set.text);
  assert.equal(set.body.userId, linked.userId, "the existing account gets the password");
  assert.equal((await login(ctx, "sso@acme.test", PASSWORD)).status, 200);
  // The other pending link was voided when the password was set.
  const verifyLate = await call(ctx.origin, `${API}/verify`, { json: { token: laterLink } });
  assert.equal(verifyLate.status, 410);
  assert.equal(verifyLate.body.error, "token_invalid");
  const reuse = await call(ctx.origin, `${API}/set`, { json: { token: setup_, password: "a different passphrase" } });
  assert.equal(reuse.status, 410);
  assert.equal((await login(ctx, "sso@acme.test", PASSWORD)).status, 200, "unchanged");
  const actions = (await auditActions(ctx)).map((e) => e.action);
  assert.ok(!actions.includes("password.set.from_session"));
  await ctx.identity.idle();
  const notice = ctx.mailer.sent.filter((mail) => mail.to === "sso@acme.test" && mail.subject === "A password was added to your Agent Relay account");
  assert.equal(notice.length, 1, "the account address is told a password was added");
  assert.match(notice[0]!.text, /If this was not you, reset your password\./);
  assert.match(notice[0]!.text, /\/login\/password\/reset/);
});

test("HIBP on: breached passwords refused at set; unreachable fails open with an audit event; off never calls out", async (t) => {
  const digest = createHash("sha1").update(PASSWORD).digest("hex").toUpperCase();
  let mode: "breached" | "down" = "breached";
  let calls = 0;
  const hibpFetch: HibpFetch = async () => {
    calls += 1;
    if (mode === "down") throw new Error("unreachable");
    return { ok: true, status: 200, text: async () => `${digest.slice(5)}:7` };
  };
  const on = await setup(t, { env: { SELFHOST_PASSWORD_HIBP: "on" }, hibpFetch });
  const token = await setupToken(on, "h@acme.test");
  assert.equal(calls, 0, "register and verify never call out");
  const breached = await call(on.origin, `${API}/set`, { json: { token, password: PASSWORD } });
  assert.equal(breached.status, 400);
  assert.equal(breached.body.error, "password_breached");
  mode = "down";
  const open = await call(on.origin, `${API}/set`, { json: { token, password: PASSWORD } });
  assert.equal(open.status, 200, open.text);
  assert.ok((await auditActions(on)).some((e) => e.action === "password.hibp.unavailable"));
  assert.equal(calls, 2);

  const off = await setup(t, { hibpFetch });
  await registerVerified(off, "h@acme.test");
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
  // Four more failures use up the free allowance (5); the fifth starts a lock.
  for (let i = 0; i < 4; i += 1) assert.equal((await login(ctx, "lock@acme.test", `wrong password ${i}!`)).status, 401);
  const locked = await login(ctx, "lock@acme.test", PASSWORD);
  assert.equal(locked.status, 401, "the right password is refused while locked");
  assert.deepEqual(locked.body, wrong.body);
  assert.equal(locked.text, wrong.text);
  // A lock on an unknown address looks the same.
  for (let i = 0; i < 5; i += 1) await login(ctx, "ghost@acme.test", PASSWORD);
  assert.equal((await login(ctx, "ghost@acme.test", PASSWORD)).text, locked.text);

  // After the backoff the right password works and clears the counter.
  const lockRow = await ctx.database.query<{ failures: number }>("SELECT failures FROM login_attempts WHERE subject = 'account-key:lock@acme.test|198.51.100.7'");
  assert.equal(lockRow.rows[0]!.failures, 5, "an attempt refused inside a lock is not counted");
  ctx.clock.now += lockDelayMs(5, LOCKOUT.accountKey.free) + 1_000;
  const after = await login(ctx, "lock@acme.test", PASSWORD);
  assert.equal(after.status, 200, after.text);
  const rows = await ctx.database.query("SELECT subject FROM login_attempts WHERE subject LIKE '%lock@acme.test%'");
  assert.deepEqual(rows.rows, [], "a successful sign-in clears the account's counters");

  const actions = await auditActions(ctx);
  assert.ok(actions.some((e) => e.action === "login.lockout" && e.target!.includes("scope=account_key")));
  assert.ok(!actions.some((e) => e.target?.includes("reason=locked")), "refused attempts write no audit row");
  assert.ok(actions.some((e) => e.action === "login.password.failure" && e.target!.includes("reason=unknown_account")));
  assert.ok(actions.some((e) => e.action === "login.password.success"));
  for (const event of actions) assert.ok(!(event.target ?? "").includes(PASSWORD) && !(event.target ?? "").includes("wrong password"), "no secrets in audit");
});

test("lockout: exponential backoff with a cap, per IP as well as per account", async (t) => {
  assert.equal(lockDelayMs(4, 5), 0);
  assert.equal(lockDelayMs(5, 5), 30_000, "the attempt that uses the last free slot starts the lock");
  assert.equal(lockDelayMs(6, 5), 60_000);
  assert.equal(lockDelayMs(7, 5), 120_000);
  assert.equal(lockDelayMs(50, 5), 15 * 60_000, "capped");

  const ctx = await setup(t);
  await registerVerified(ctx, "ip@acme.test");
  // Spraying many addresses from one IP locks that IP, not the accounts.
  for (let i = 0; i < LOCKOUT.ip.free; i += 1) await login(ctx, `spray${i}@acme.test`, PASSWORD, "203.0.113.9");
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
  const ctx = await setup(t, { env: { SELFHOST_PASSWORD_PEPPER_FILE: pepperFile("v3:" + "p".repeat(40)) } });
  await registerVerified(ctx, "re@acme.test");
  const user = (await ctx.database.query<{ id: string }>("SELECT id FROM users WHERE email = 're@acme.test'")).rows[0]!.id;
  // Simulate a hash made before the pepper existed.
  const legacy = await new PasswordHasher(passwordConfig()).hash(PASSWORD);
  await ctx.database.query("UPDATE password_credentials SET password_hash = $2, pepper_version = NULL WHERE user_id = $1", [user, legacy.hash]);
  assert.equal((await login(ctx, "re@acme.test", PASSWORD)).status, 200);
  const row = (await ctx.database.query<{ password_hash: string; pepper_version: number | null; params: string }>(
    "SELECT password_hash, pepper_version, params FROM password_credentials WHERE user_id = $1", [user],
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
  await ctx.identity.idle();
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
  const token = linkToken(ctx.mailer.sent.at(-1)!, "/login/password/reset");
  const stored = await ctx.database.query<{ token_hash: string; expires_at: Date; created_at: Date }>("SELECT token_hash, expires_at FROM password_reset_tokens");
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
  assert.ok(done.body.revoked.sessions >= 2);
  assert.equal((await session(ctx, first)).status, 401, "existing sessions are revoked");
  assert.equal((await session(ctx, second)).status, 401);
  const reasons = await ctx.database.query<{ revoked_reason: string }>("SELECT DISTINCT revoked_reason FROM token_sessions WHERE revoked_at IS NOT NULL");
  assert.deepEqual(reasons.rows.map((r) => r.revoked_reason), ["password_reset"]);
  assert.equal((await call(ctx.origin, "/api/v1/auth/password/reset/complete", { json: { token, password: NEW } })).status, 410, "single use");
  assert.equal((await login(ctx, "rs@acme.test", PASSWORD)).status, 401, "the old password no longer works");
  assert.equal((await login(ctx, "rs@acme.test", NEW)).status, 200);
  // The address is told the password changed.
  await ctx.identity.idle();
  const changed = ctx.mailer.sent.at(-1)!;
  assert.equal(changed.to, "rs@acme.test");
  assert.equal(changed.subject, "Your Agent Relay password was changed");
  assert.match(changed.text, /If this was not you, reset your password now\./);
  assert.doesNotMatch(changed.text, /token=/);

  // Expiry.
  await call(ctx.origin, "/api/v1/auth/password/reset", { json: { email: "rs@acme.test" } });
  await ctx.identity.idle();
  const late = linkToken(ctx.mailer.sent.at(-1)!, "/login/password/reset");
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
  const owners = await ctx.database.query("SELECT 1 FROM organization_memberships WHERE role = 'owner'");
  assert.equal(owners.rows.length, 0, "no owner until an admin email verifies");
  // The second listed address verifies first and becomes owner.
  const second = await registerVerified(ctx, "second@partner.test");
  const first = await registerVerified(ctx, "first@partner.test");
  const role = async (email: string) => (await ctx.database.query<{ role: string }>(
    "SELECT m.role FROM organization_memberships m JOIN users u ON u.id = m.user_id WHERE u.email = $1", [email],
  )).rows[0]?.role;
  assert.equal(await role("second@partner.test"), "owner");
  assert.equal(await role("first@partner.test"), "admin");
  assert.equal(second.body.organizationId, first.body.organizationId);
  const actions = (await auditActions(ctx)).map((e) => e.action);
  assert.ok(actions.includes("membership.admin_email_owner"));
  assert.ok(actions.includes("membership.admin_email_admin"));
  // A grant is recorded once: a later demotion is not undone by signing in again.
  await ctx.database.query(
    "UPDATE organization_memberships SET role = 'member' WHERE user_id = (SELECT id FROM users WHERE email = 'first@partner.test')",
  );
  assert.equal((await login(ctx, "first@partner.test", PASSWORD)).status, 200);
  assert.equal(await role("first@partner.test"), "member");
});

test("openapi.yaml documents login-config and every password route", async () => {
  const { readFile } = await import("node:fs/promises");
  const spec = parseYaml(await readFile(new URL("../openapi.yaml", import.meta.url), "utf8"));
  for (const path of ["login-config", "password/register", "password/verify", "password/set", "password/login", "password/reset", "password/reset/complete"]) {
    assert.ok(spec.paths[`/api/v1/auth/${path}`], path);
  }
  const body = (path: string) => spec.paths[`/api/v1/auth/password/${path}`].post.requestBody.content["application/json"].schema;
  const register = body("register");
  assert.deepEqual(Object.keys(register.properties).sort(), ["email", "invite"], "register takes no password");
  assert.equal(register.additionalProperties, false);
  assert.equal(register.properties.invite.maxLength, 256);
  assert.equal(body("verify").properties.token.maxLength, 256);
  assert.equal(body("reset/complete").properties.token.maxLength, 256);
  assert.deepEqual([...body("set").required].sort(), ["password", "token"], "no session-only set path");
  assert.equal(body("set").properties.token.maxLength, 256);
  const verified = spec.paths["/api/v1/auth/password/verify"].post.responses["200"].content["application/json"].schema;
  assert.ok(verified.required.includes("setupToken"));
  for (const status of ["200", "400", "409", "410", "429"]) assert.ok(spec.paths["/api/v1/auth/password/set"].post.responses[status], `set ${status}`);
  for (const path of ["login", "set", "reset/complete"]) assert.ok(spec.paths[`/api/v1/auth/password/${path}`].post.responses["429"], `${path} 429 (busy)`);
  const reset = spec.paths["/api/v1/auth/password/reset/complete"].post.responses["200"].content["application/json"].schema;
  assert.deepEqual(Object.keys(reset.properties.revoked.properties).sort(), ["desktopRelayIdentities", "deviceAuthorizations", "mcpCodes", "mcpGrants", "sessions"]);
  const text = await readFile(new URL("../openapi.yaml", import.meta.url), "utf8");
  for (const code of ["invalid_credentials", "signin_method_disabled", "password_common", "token_invalid", "password_already_set", "csrf_rejected", "rate_limited"]) {
    assert.ok(text.includes(code), code);
  }
});
