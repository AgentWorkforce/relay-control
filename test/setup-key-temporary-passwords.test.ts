import assert from "node:assert/strict";
import test from "node:test";
import { loadIdentityConfig } from "../src/identity/config.js";
import { SETUP_KEY_TTL_MS, TEMPORARY_PASSWORD_TTL_MS } from "../src/identity/password/store.js";
import {
  API,
  auditActions,
  BOOTSTRAP,
  call,
  login,
  PASSWORD,
  registerVerified,
  session,
  sessionCookie,
  setup,
  type Ctx,
} from "./support/password.js";

// First-time setup without email: the one-time setup key for the bootstrap
// admin, and temporary passwords an owner or admin sets for members.

const SETUP_KEY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const ADMIN = "admin@acme.test";
const NEW_PASSWORD = "violet harbor lantern ninety";

async function noSmtp(t: test.TestContext, env: Record<string, string> = {}): Promise<Ctx> {
  return setup(t, { smtp: false, env: { SELFHOST_SETUP_KEY: SETUP_KEY, ...env } });
}

async function useSetupKey(ctx: Ctx, setupKey: string, password = PASSWORD, ip = "198.51.100.20") {
  return call(ctx.origin, `${API}/setup-key`, { json: { setupKey, password }, ip });
}

async function organizationId(ctx: Ctx): Promise<string> {
  return (await ctx.identityStore.bootstrapOrganizationId())!;
}

/** The bootstrap admin, signed in through the setup key. */
async function ownerCookie(ctx: Ctx): Promise<string> {
  const res = await useSetupKey(ctx, SETUP_KEY);
  assert.equal(res.status, 200, res.text);
  return sessionCookie(res);
}

async function invite(ctx: Ctx, cookie: string, email: string, role = "member", extra: Record<string, unknown> = { temporaryPassword: true }) {
  return call(ctx.origin, `/cloud/api/v1/organizations/${await organizationId(ctx)}/invitations`, { cookie, json: { email, role, ...extra } });
}

async function change(ctx: Ctx, email: string, currentPassword: string, newPassword: string, ip = "198.51.100.30") {
  return call(ctx.origin, `${API}/change`, { json: { email, currentPassword, newPassword }, ip });
}

/** Invites `email` with a temporary password and has them choose `password`. */
async function joinWithTemporary(ctx: Ctx, cookie: string, email: string, role = "member", password = NEW_PASSWORD): Promise<string> {
  const invited = await invite(ctx, cookie, email, role);
  assert.equal(invited.status, 201, invited.text);
  const changed = await change(ctx, email, invited.body.temporaryPassword, password);
  assert.equal(changed.status, 200, changed.text);
  return sessionCookie(changed);
}

async function userId(ctx: Ctx, email: string): Promise<string> {
  return (await ctx.database.query<{ id: string }>("SELECT id FROM users WHERE email = $1", [email])).rows[0]!.id;
}

// ---- config ----------------------------------------------------------------------------

test("config: SELFHOST_SETUP_KEY is random-length checked and needs the bootstrap admin and password sign-in", () => {
  const base = { SELFHOST_BOOTSTRAP_ORG_NAME: "Acme", SELFHOST_BOOTSTRAP_ADMIN_EMAIL: ADMIN, SELFHOST_SIGNIN_METHODS: "password", SELFHOST_TRUSTED_PROXIES: "0" };
  assert.equal(loadIdentityConfig({ ...base, SELFHOST_SETUP_KEY: SETUP_KEY }).setupKey, SETUP_KEY);
  assert.equal(loadIdentityConfig(base).setupKey, null, "there is no default key");
  assert.throws(() => loadIdentityConfig({ ...base, SELFHOST_SETUP_KEY: "short" }), /32-256 bytes/);
  assert.throws(() => loadIdentityConfig({ ...base, SELFHOST_SETUP_KEY: `${SETUP_KEY} x` }), /without spaces/);
  assert.throws(() => loadIdentityConfig({ ...base, SELFHOST_SIGNIN_METHODS: "", SELFHOST_SETUP_KEY: SETUP_KEY }), /include password/);
  assert.throws(() => loadIdentityConfig({ SELFHOST_SIGNIN_METHODS: "password", SELFHOST_TRUSTED_PROXIES: "0", SELFHOST_SETUP_KEY: SETUP_KEY }), /SELFHOST_BOOTSTRAP_ADMIN_EMAIL/);
});

// ---- setup key ---------------------------------------------------------------------------

test("setup key: offered on /login and in login-config only before the admin's first sign-in; no SMTP needed", async (t) => {
  const ctx = await noSmtp(t);
  const page = await call(ctx.origin, "/login");
  assert.equal(page.status, 200);
  assert.match(page.text, /First-time setup: enter the setup key/);
  assert.match(page.text, /name="setup_key"/);
  assert.ok(!page.text.includes(SETUP_KEY), "the key is never rendered");
  assert.ok(!page.text.includes("Forgot password?"), "no emailed links without SMTP");
  const config = await call(ctx.origin, "/api/v1/auth/login-config");
  assert.equal(config.body.setup_key, true);
  assert.equal(config.body.password_self_service, false);
  assert.deepEqual(config.body.methods, ["password"]);

  // Register and reset need email.
  for (const route of ["register", "reset"]) {
    const res = await call(ctx.origin, `${API}/${route}`, { json: { email: "someone@acme.test" } });
    assert.equal(res.status, 404, route);
    assert.equal(res.body.error, "email_not_configured");
  }

  const cookie = await ownerCookie(ctx);
  const me = await session(ctx, cookie);
  assert.equal(me.status, 200, me.text);
  assert.ok(!(await call(ctx.origin, "/login")).text.includes("setup_key"), "gone after the first sign-in");
  assert.equal((await call(ctx.origin, "/api/v1/auth/login-config")).body.setup_key, false);

  // The password it set signs in from now on.
  assert.equal((await login(ctx, ADMIN, PASSWORD)).status, 200);
});

test("setup key: burned after use, a rejected password does not spend it, never logged or audited in clear", async (t) => {
  const ctx = await noSmtp(t);
  const weak = await useSetupKey(ctx, SETUP_KEY, "short");
  assert.equal(weak.status, 400);
  assert.equal(weak.body.error, "password_too_short", "the existing 12-128 policy applies");
  assert.equal(weak.cookies.agent_relay_session, undefined, "no session before a password is set");
  const ok = await useSetupKey(ctx, SETUP_KEY);
  assert.equal(ok.status, 200, ok.text);
  assert.equal(ok.body.email, ADMIN);
  const again = await useSetupKey(ctx, SETUP_KEY, "another long passphrase", "198.51.100.21");
  assert.equal(again.status, 401);
  assert.equal(again.body.error, "setup_key_invalid");
  const rows = await ctx.database.query<{ used_at: Date | null }>("SELECT used_at FROM setup_keys");
  assert.equal(rows.rows.length, 1);
  assert.ok(rows.rows[0]!.used_at);
  const stored = await ctx.database.query<{ key_hash: string }>("SELECT key_hash FROM setup_keys");
  assert.notEqual(stored.rows[0]!.key_hash, SETUP_KEY, "only a hash is stored");
  const audit = await auditActions(ctx);
  assert.ok(audit.some((row) => row.action === "setup_key.used" && row.target?.includes(`email=${ADMIN}`)));
  assert.ok(audit.every((row) => !row.target?.includes(SETUP_KEY)), "the key is never in the audit log");
});

test("setup key: wrong keys are audited and rate-limited per client", async (t) => {
  const ctx = await noSmtp(t);
  const ip = "203.0.113.9";
  for (let i = 0; i < 5; i += 1) {
    const res = await useSetupKey(ctx, `wrong-${i}-`.padEnd(64, "x"), PASSWORD, ip);
    assert.equal(res.status, 401, `attempt ${i}`);
    assert.equal(res.body.error, "setup_key_invalid");
  }
  const locked = await useSetupKey(ctx, SETUP_KEY, PASSWORD, ip);
  assert.equal(locked.status, 429, "the client is locked out, even with the right key");
  const audit = await auditActions(ctx);
  assert.equal(audit.filter((row) => row.action === "setup_key.failure").length, 5);
  assert.ok(audit.some((row) => row.action === "setup_key.lockout" && row.target?.includes(`ip=${ip}`)));
  // Another client is unaffected and the key still works.
  assert.equal((await useSetupKey(ctx, SETUP_KEY, PASSWORD, "198.51.100.40")).status, 200);
});

test("setup key: expires 24 hours after it is first recorded, even unused; a restart does not renew it", async (t) => {
  const ctx = await noSmtp(t);
  assert.equal((await call(ctx.origin, "/api/v1/auth/login-config")).body.setup_key, true, "recorded now");
  ctx.clock.now += SETUP_KEY_TTL_MS + 1_000;
  assert.equal((await call(ctx.origin, "/api/v1/auth/login-config")).body.setup_key, false);
  assert.ok(!(await call(ctx.origin, "/login")).text.includes("setup_key"));
  assert.equal((await useSetupKey(ctx, SETUP_KEY)).status, 401);
  // The configured key's row survives the retention sweep, so the same
  // SELFHOST_SETUP_KEY is never recorded again with fresh hours.
  ctx.clock.now += 30 * 24 * 60 * 60 * 1_000;
  await ctx.identity.sweep();
  assert.equal((await ctx.database.query("SELECT 1 FROM setup_keys")).rows.length, 1);
});

test("setup key: refused and revoked once the admin has signed in another way", async (t) => {
  const ctx = await noSmtp(t);
  // As if the admin had already signed in (SSO, say).
  await ctx.database.query("UPDATE users SET last_organization_id = $2 WHERE email = $1", [ADMIN, await organizationId(ctx)]);
  assert.equal((await call(ctx.origin, "/api/v1/auth/login-config")).body.setup_key, false);
  assert.equal((await useSetupKey(ctx, SETUP_KEY)).status, 401);
  assert.ok((await auditActions(ctx)).some((row) => row.action === "setup_key.revoked"));
});

test("setup key: the /login form checks the key, then forces a password before any session", async (t) => {
  const ctx = await noSmtp(t);
  const wrong = await call(ctx.origin, "/login/setup", { form: { setup_key: "nope".padEnd(64, "n"), next: "/" } });
  assert.equal(wrong.status, 303);
  assert.match(wrong.location!, /error=setup_key_invalid/);
  const step = await call(ctx.origin, "/login/setup", { form: { setup_key: SETUP_KEY, next: "/" } });
  assert.equal(step.status, 200);
  assert.match(step.text, /Set the administrator password/);
  assert.equal(step.cookies.agent_relay_session, undefined);
  const weak = await call(ctx.origin, "/login/setup", { form: { setup_key: SETUP_KEY, password: "short", next: "/" } });
  assert.equal(weak.status, 400);
  assert.match(weak.text, /at least 12 characters/);
  const done = await call(ctx.origin, "/login/setup", { form: { setup_key: SETUP_KEY, password: PASSWORD, next: "/" } });
  assert.equal(done.status, 303, done.text);
  assert.equal(done.location, "/");
  assert.equal((await session(ctx, sessionCookie(done))).status, 200);
  const cross = await call(ctx.origin, "/login/setup", { form: { setup_key: SETUP_KEY }, originHeader: "https://evil.test" });
  assert.equal(cross.status, 403);
});

test("setup key: the operator can mint one with the bootstrap bearer; it replaces the configured key; the bearer still works after", async (t) => {
  const ctx = await noSmtp(t);
  const anonymous = await call(ctx.origin, "/api/v1/installation/setup-key", { method: "POST", json: {} });
  assert.equal(anonymous.status, 401);
  const minted = await call(ctx.origin, "/api/v1/installation/setup-key", { method: "POST", bearer: BOOTSTRAP, json: {} });
  assert.equal(minted.status, 201, minted.text);
  assert.match(minted.body.setupKey, /^sh_sk_/);
  assert.equal(minted.body.email, ADMIN);
  assert.equal((await useSetupKey(ctx, SETUP_KEY)).status, 401, "the configured key was revoked");
  assert.equal((await useSetupKey(ctx, minted.body.setupKey, PASSWORD, "198.51.100.41")).status, 200);
  const late = await call(ctx.origin, "/api/v1/installation/setup-key", { method: "POST", bearer: BOOTSTRAP, json: {} });
  assert.equal(late.status, 409);
  assert.equal(late.body.error, "admin_already_signed_in");
  // Break-glass is unaffected.
  assert.equal((await call(ctx.origin, "/api/v1/organizations", { bearer: BOOTSTRAP })).status, 200);
});

test("setup key: without SELFHOST_SETUP_KEY nothing is offered until the operator mints one", async (t) => {
  const ctx = await setup(t, { smtp: false });
  assert.equal((await call(ctx.origin, "/api/v1/auth/login-config")).body.setup_key, false);
  assert.ok(!(await call(ctx.origin, "/login")).text.includes("setup_key"));
});

// ---- temporary passwords ----------------------------------------------------------------

test("temporary password: set on invite, returned once, forces a change, single use; no email needed", async (t) => {
  const ctx = await noSmtp(t);
  const owner = await ownerCookie(ctx);
  const invited = await invite(ctx, owner, "new@acme.test");
  assert.equal(invited.status, 201, invited.text);
  assert.equal(invited.body.emailDelivery, "not_configured");
  const temporary = invited.body.temporaryPassword as string;
  assert.ok(temporary.length >= 12);
  assert.ok(invited.body.temporaryPasswordExpiresAt);
  const stored = await ctx.database.query<{ password_hash: string }>("SELECT password_hash FROM temporary_passwords");
  assert.match(stored.rows[0]!.password_hash, /^\$argon2id\$/, "hashed at rest");

  const first = await login(ctx, "new@acme.test", temporary);
  assert.equal(first.status, 403);
  assert.equal(first.body.error, "password_change_required");
  assert.equal(first.cookies.agent_relay_session, undefined, "no session with a temporary password");

  assert.equal((await change(ctx, "new@acme.test", "not the temporary one", NEW_PASSWORD)).status, 401);
  const same = await change(ctx, "new@acme.test", temporary, temporary);
  assert.equal(same.status, 400);
  assert.equal(same.body.error, "password_unchanged");
  assert.equal((await change(ctx, "new@acme.test", temporary, "short")).body.error, "password_too_short");
  const changed = await change(ctx, "new@acme.test", temporary, NEW_PASSWORD);
  assert.equal(changed.status, 200, changed.text);
  assert.equal((await session(ctx, sessionCookie(changed))).status, 200);

  // Spent: neither a login nor another change accepts it.
  assert.equal((await login(ctx, "new@acme.test", temporary)).status, 401);
  assert.equal((await change(ctx, "new@acme.test", temporary, "yet another long passphrase")).status, 401);
  assert.equal((await login(ctx, "new@acme.test", NEW_PASSWORD)).status, 200);

  const audit = await auditActions(ctx);
  for (const action of ["password.temporary.create", "login.temporary_password.accepted", "password.temporary.changed"]) {
    assert.ok(audit.some((row) => row.action === action), action);
  }
  assert.ok(audit.every((row) => !row.target?.includes(temporary)), "never the password");
});

test("temporary password: set later for an existing member; expires after 72 hours by default", async (t) => {
  const ctx = await noSmtp(t);
  const owner = await ownerCookie(ctx);
  await joinWithTemporary(ctx, owner, "member@acme.test");
  const memberId = await userId(ctx, "member@acme.test");
  const path = `/cloud/api/v1/organizations/${await organizationId(ctx)}/memberships/${memberId}/temporary-password`;

  const reset = await call(ctx.origin, path, { cookie: owner, json: {} });
  assert.equal(reset.status, 201, reset.text);
  assert.equal(reset.body.email, "member@acme.test");
  assert.equal(Date.parse(reset.body.expiresAt) - ctx.clock.now, TEMPORARY_PASSWORD_TTL_MS);
  // Until it is used, the member's own password still works.
  assert.equal((await login(ctx, "member@acme.test", NEW_PASSWORD)).status, 200);
  const changed = await change(ctx, "member@acme.test", reset.body.temporaryPassword, "quiet orchard copper forty");
  assert.equal(changed.status, 200, changed.text);
  assert.equal((await login(ctx, "member@acme.test", NEW_PASSWORD, "198.51.100.50")).status, 401, "the old password is replaced");

  const short = await call(ctx.origin, path, { cookie: owner, json: { expiresInHours: 1 } });
  assert.equal(short.status, 201);
  const expiring = await call(ctx.origin, path, { cookie: owner, json: {} });
  assert.equal((await login(ctx, "member@acme.test", short.body.temporaryPassword)).status, 401, "a newer one replaces the older");
  ctx.clock.now += TEMPORARY_PASSWORD_TTL_MS + 1_000;
  assert.equal((await login(ctx, "member@acme.test", expiring.body.temporaryPassword)).status, 401, "expired");
  assert.equal((await change(ctx, "member@acme.test", expiring.body.temporaryPassword, "a passphrase after expiry")).status, 401);
  assert.equal((await call(ctx.origin, path, { cookie: owner, json: { expiresInHours: 1000 } })).status, 400);
});

test("temporary password: owners and admins only; admins only for members; not across organizations", async (t) => {
  const ctx = await noSmtp(t);
  const owner = await ownerCookie(ctx);
  const org = await organizationId(ctx);
  const member = await joinWithTemporary(ctx, owner, "member@acme.test");
  const admin = await joinWithTemporary(ctx, owner, "second-admin@acme.test", "admin");
  const ownerId = await userId(ctx, ADMIN);
  const memberId = await userId(ctx, "member@acme.test");
  const temporaryFor = (id: string) => `/cloud/api/v1/organizations/${org}/memberships/${id}/temporary-password`;

  const byMember = await call(ctx.origin, temporaryFor(ownerId), { cookie: member, json: {} });
  assert.equal(byMember.status, 403, "members cannot");
  assert.equal((await invite(ctx, member, "x@acme.test")).status, 403);

  const adminOnOwner = await call(ctx.origin, temporaryFor(ownerId), { cookie: admin, json: {} });
  assert.equal(adminOnOwner.status, 403, "an admin cannot take over an owner");
  assert.equal(adminOnOwner.body.error, "forbidden");
  assert.equal((await invite(ctx, admin, "another-admin@acme.test", "admin")).status, 403, "nor mint an admin's");
  assert.equal((await call(ctx.origin, temporaryFor(memberId), { cookie: admin, json: {} })).status, 201, "an admin may reset a member");

  assert.equal((await call(ctx.origin, temporaryFor(memberId), { json: {}, originHeader: null })).status, 401, "anonymous");
  assert.equal((await call(ctx.origin, temporaryFor(memberId), { cookie: owner, json: {}, originHeader: "https://evil.test" })).status, 403, "CSRF");
  assert.equal((await call(ctx.origin, temporaryFor("00000000-0000-4000-8000-000000000042"), { cookie: owner, json: {} })).status, 404);

  // Someone who also belongs to another organization changes their own password.
  const otherOrg = "00000000-0000-4000-8000-000000000099";
  await ctx.database.query("INSERT INTO organizations (id, name) VALUES ($1, 'Other')", [otherOrg]);
  await ctx.database.query("INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, 'owner')", [otherOrg, memberId]);
  const cross = await call(ctx.origin, temporaryFor(memberId), { cookie: owner, json: {} });
  assert.equal(cross.status, 409);
  assert.equal(cross.body.error, "member_of_other_organizations");

  // The operator's bootstrap bearer may set one too.
  const operator = await call(ctx.origin, `/api/v1/organizations/${org}/memberships/${await userId(ctx, "second-admin@acme.test")}/temporary-password`, { bearer: BOOTSTRAP, json: {} });
  assert.equal(operator.status, 201, operator.text);
});

test("temporary password: for an open invite later; canceling the invite cancels it; the /login form forces the change", async (t) => {
  const ctx = await noSmtp(t);
  const owner = await ownerCookie(ctx);
  const org = await organizationId(ctx);
  const plain = await invite(ctx, owner, "later@acme.test", "member", {});
  assert.equal(plain.status, 201);
  assert.equal(plain.body.temporaryPassword, undefined, "none unless asked");
  const set = await call(ctx.origin, `/cloud/api/v1/organizations/${org}/invitations/${plain.body.invitation.id}/temporary-password`, { cookie: owner, json: {} });
  assert.equal(set.status, 201, set.text);

  const page = await call(ctx.origin, "/login/password", { form: { email: "later@acme.test", password: set.body.temporaryPassword, next: "/" } });
  assert.equal(page.status, 200, page.text);
  assert.match(page.text, /Choose a new password/);
  assert.equal(page.cookies.agent_relay_session, undefined);
  const done = await call(ctx.origin, "/login/password/change", {
    form: { email: "later@acme.test", current: set.body.temporaryPassword, password: NEW_PASSWORD, next: "/" },
  });
  assert.equal(done.status, 303, done.text);
  assert.equal((await session(ctx, sessionCookie(done))).status, 200);

  const canceled = await invite(ctx, owner, "canceled@acme.test");
  const revoke = await call(ctx.origin, `/cloud/api/v1/organizations/${org}/invitations/${canceled.body.invitation.id}`, { method: "DELETE", cookie: owner });
  assert.equal(revoke.status, 200, revoke.text);
  assert.equal((await login(ctx, "canceled@acme.test", canceled.body.temporaryPassword)).status, 401);
});

test("temporary password: with SMTP configured, emailed verification and invites are unchanged", async (t) => {
  const ctx = await setup(t);
  assert.equal((await call(ctx.origin, "/api/v1/auth/login-config")).body.password_self_service, true);
  const owner = sessionCookie(await registerVerified(ctx, ADMIN));
  const before = ctx.mailer.sent.length;
  const invited = await invite(ctx, owner, "mailed@acme.test");
  assert.equal(invited.status, 201, invited.text);
  assert.equal(invited.body.emailDelivery, "sent");
  await ctx.identity.idle();
  assert.equal(ctx.mailer.sent.length, before + 1, "only the invite email");
  assert.ok(ctx.mailer.sent.every((message) => !message.text.includes(invited.body.temporaryPassword)), "never emailed");
  // Registration still verifies the address by email.
  const register = await call(ctx.origin, `${API}/register`, { json: { email: "self@acme.test" } });
  assert.equal(register.status, 202);
  await ctx.identity.idle();
  assert.match(ctx.mailer.sent.at(-1)!.text, /\/login\/password\/verify#token=/);
  assert.equal((await call(ctx.origin, "/login")).text.includes("Forgot password?"), true);
});

test("openapi.yaml documents the setup key and temporary password routes", async () => {
  const { readFile } = await import("node:fs/promises");
  const { parse } = await import("yaml");
  const spec = parse(await readFile(new URL("../openapi.yaml", import.meta.url), "utf8"));
  for (const path of [
    "/api/v1/auth/password/change",
    "/api/v1/auth/password/setup-key",
    "/api/v1/installation/setup-key",
    "/api/v1/organizations/{organizationId}/memberships/{userId}/temporary-password",
    "/api/v1/organizations/{organizationId}/invitations/{invitationId}/temporary-password",
  ]) {
    assert.ok(spec.paths[path]?.post, path);
  }
  assert.ok(spec.components.schemas.LoginConfig.required.includes("setup_key"));
  assert.ok(spec.components.schemas.LoginConfig.required.includes("password_self_service"));
});
