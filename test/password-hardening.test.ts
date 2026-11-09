import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { trustedProxyHops } from "../src/auth/device-approval.js";
import { loadIdentityConfig } from "../src/identity/config.js";
import { lockDelayMs, LOCKOUT } from "../src/identity/password/store.js";
import {
  API,
  auditActions,
  call,
  linkToken,
  login,
  PASSWORD,
  pepperFile,
  registerVerified,
  session,
  sessionCookie,
  setup,
  SMTP,
  verifyLink,
} from "./support/password.js";

const loadConfigProxies = (value: string | undefined) => trustedProxyHops(value === undefined ? {} : { SELFHOST_TRUSTED_PROXIES: value });

// ---- concurrency, proxies and pepper ----------------------------------------------------

test("lockout: a parallel burst gets no more than the free allowance", async (t) => {
  const ctx = await setup(t);
  await registerVerified(ctx, "burst@acme.test");
  const burst = await Promise.all(Array.from({ length: 12 }, (_, i) => login(ctx, "burst@acme.test", `wrong password number ${i}`)));
  assert.ok(burst.every((res) => res.status === 401));
  const row = await ctx.database.query<{ failures: number; locked_until: Date | null }>(
    "SELECT failures, locked_until FROM selfhost_login_attempts WHERE subject = 'account-key:burst@acme.test|198.51.100.7'",
  );
  assert.equal(row.rows[0]!.failures, LOCKOUT.accountKey.free, "attempts are reserved before argon2id, not counted after it");
  assert.ok(row.rows[0]!.locked_until);
  const events = await auditActions(ctx);
  const reasons = events
    .filter((e) => e.action === "login.password.failure" && e.target!.includes("burst@acme.test"))
    .map((e) => /reason=(\w+)/.exec(e.target!)![1]);
  assert.deepEqual(reasons, Array(LOCKOUT.accountKey.free).fill("wrong_password"), "only five passwords were checked; refused attempts write nothing");
  assert.equal(events.filter((e) => e.action === "login.lockout").length, 1, "one lockout event when the lock engaged");
  assert.equal((await login(ctx, "burst@acme.test", PASSWORD)).status, 401, "still locked");

  // Past the free allowance each lock admits one attempt, even a parallel
  // one; the success clears the account counters for what follows.
  ctx.clock.now += lockDelayMs(LOCKOUT.accountKey.free, LOCKOUT.accountKey.free) + 1_000;
  const after = await Promise.all(Array.from({ length: 3 }, () => login(ctx, "burst@acme.test", PASSWORD)));
  assert.deepEqual(after.map((res) => res.status).sort(), [200, 401, 401]);
  assert.equal((await login(ctx, "burst@acme.test", PASSWORD)).status, 200);
});

test("login: more than 60 attempts a minute from one IP answer 429 rate_limited before the lockout", async (t) => {
  const ctx = await setup(t);
  const statuses: number[] = [];
  for (let i = 0; i < 61; i += 1) statuses.push((await login(ctx, `flood${i}@acme.test`, "wrong password here", "198.51.100.61")).status);
  assert.ok(statuses.slice(0, 60).every((status) => status === 401));
  const refused = await login(ctx, "flood-last@acme.test", "wrong password here", "198.51.100.61");
  assert.equal(refused.status, 429);
  assert.equal(refused.body.error, "rate_limited");
  assert.equal((await login(ctx, "flood-other@acme.test", "wrong password here", "198.51.100.62")).status, 401, "other addresses are unaffected");
  ctx.clock.now += 61_000;
  assert.equal((await login(ctx, "flood-later@acme.test", "wrong password here", "198.51.100.61")).status, 401, "the window resets");
});

test("lockout: a locked IP spraying new addresses does not grow selfhost_login_attempts", async (t) => {
  const ctx = await setup(t);
  for (let i = 0; i < LOCKOUT.ip.free; i += 1) await login(ctx, `spray${i}@acme.test`, "wrong password here", "198.51.100.90");
  const count = async () => Number((await ctx.database.query<{ n: string }>("SELECT count(*) AS n FROM selfhost_login_attempts")).rows[0]!.n);
  const before = await count();
  const ipRow = async () => (await ctx.database.query<{ failures: number }>(
    "SELECT failures FROM selfhost_login_attempts WHERE subject LIKE 'ip:%'")).rows[0]!.failures;
  const failuresBefore = await ipRow();
  for (let i = 0; i < 10; i += 1) {
    assert.equal((await login(ctx, `fresh${i}@acme.test`, "wrong password here", "198.51.100.90")).status, 401);
  }
  assert.equal(await count(), before, "locked attempts insert no rows");
  assert.equal(await ipRow(), failuresBefore, "and count nothing");
});

test("client IP: X-Forwarded-For is ignored unless SELFHOST_TRUSTED_PROXIES says how many proxies to trust", async (t) => {
  {
    // No trusted proxy and no header: the socket address is the client, and
    // the IP lock applies.
    const ctx = await setup(t, { trustedProxies: "0" });
    await registerVerified(ctx, "direct@acme.test");
    const direct = (email: string, password: string) => call(ctx.origin, `${API}/login`, { json: { email, password } });
    for (let i = 0; i < LOCKOUT.ip.free; i += 1) await direct(`spray${i}@acme.test`, PASSWORD);
    assert.equal((await direct("direct@acme.test", PASSWORD)).status, 401, "the IP is locked");
    assert.ok((await auditActions(ctx)).some((e) => e.action === "login.lockout" && e.target!.includes("scope=ip")));
  }
  for (const proxies of [null, "0"]) {
    // No trusted proxy but X-Forwarded-For present: the header is not
    // trusted, so the IP lock is keyed by the socket address, whatever the
    // header says (test/password-lockout.test.ts covers the counts).
    const ctx = await setup(t, { trustedProxies: proxies });
    await registerVerified(ctx, "spoof@acme.test");
    for (let i = 0; i < LOCKOUT.ip.free + 5; i += 1) await login(ctx, `spray${i}@acme.test`, "wrong password here", `203.0.113.${i + 1}`);
    assert.equal((await login(ctx, "spoof@acme.test", PASSWORD, "198.51.100.200")).status, 401, `proxies=${proxies}: the socket address is locked`);
    const ipRows = await ctx.database.query<{ subject: string }>("SELECT subject FROM selfhost_login_attempts WHERE subject LIKE 'ip:%'");
    assert.deepEqual(ipRows.rows.map((r) => r.subject), ["ip:127.0.0.1"], "only the socket address is counted");
    const events = await auditActions(ctx);
    assert.ok(events.some((e) => e.action === "login.lockout" && e.target!.includes("scope=ip ip=127.0.0.1")), `proxies=${proxies}`);
    assert.ok(!events.some((e) => /203\.0\.113\./.test(e.target ?? "")), "the forged header was not used, even in audit");
    // Each sprayed address is still counted per account.
    const accountKeys = await ctx.database.query("SELECT subject FROM selfhost_login_attempts WHERE subject LIKE 'account-key:spray0@%'");
    assert.equal(accountKeys.rows.length, 1);
  }
  // One trusted proxy: the last X-Forwarded-For entry is the client.
  const behind = await setup(t, { trustedProxies: "1" });
  await registerVerified(behind, "proxied@acme.test");
  for (let i = 0; i < LOCKOUT.ip.free; i += 1) {
    await call(behind.origin, `${API}/login`, { json: { email: `spray${i}@acme.test`, password: PASSWORD }, ip: `203.0.113.${i + 1}, 192.0.2.50` });
  }
  assert.equal((await login(behind, "proxied@acme.test", PASSWORD, "192.0.2.50")).status, 401);
  assert.equal((await login(behind, "proxied@acme.test", PASSWORD, "192.0.2.51")).status, 200);
  assert.throws(() => loadConfigProxies("-1"), /SELFHOST_TRUSTED_PROXIES/);
  assert.throws(() => loadConfigProxies("two"), /SELFHOST_TRUSTED_PROXIES/);
  assert.equal(loadConfigProxies(undefined), 0, "default 0: the socket address");
});

test("pepper file: refused when group/other may read it; wrong passwords still fail with a pepper", async (t) => {
  const secret = "q".repeat(40);
  const base = { ...SMTP, SELFHOST_SIGNIN_METHODS: "password", SELFHOST_TRUSTED_PROXIES: "0" };
  for (const mode of [0o644, 0o640, 0o604]) {
    assert.throws(() => loadIdentityConfig({ ...base, SELFHOST_PASSWORD_PEPPER_FILE: pepperFile(`v1:${secret}`, mode) }), /group or others.*chmod 600/, mode.toString(8));
  }
  assert.equal(loadIdentityConfig({ ...base, SELFHOST_PASSWORD_PEPPER_FILE: pepperFile(`v1:${secret}`, 0o400) }).password!.currentPepperVersion, 1);
  assert.throws(() => loadIdentityConfig({ ...base, SELFHOST_PASSWORD_PEPPER_FILE: mkdtempSync(join(tmpdir(), "pepper-dir-")) }), /regular file/);

  const ctx = await setup(t, { env: { SELFHOST_PASSWORD_PEPPER_FILE: pepperFile(`v1:${secret}`) } });
  await registerVerified(ctx, "pep@acme.test");
  const stored = await ctx.database.query<{ pepper_version: number }>(
    "SELECT c.pepper_version FROM selfhost_password_credentials c JOIN selfhost_users u ON u.id = c.user_id WHERE u.email = 'pep@acme.test'",
  );
  assert.equal(stored.rows[0]!.pepper_version, 1);
  const wrong = await login(ctx, "pep@acme.test", "not the right passphrase");
  assert.equal(wrong.status, 401);
  assert.equal(wrong.body.error, "invalid_credentials");
  assert.equal((await login(ctx, "pep@acme.test", PASSWORD)).status, 200);
});

// ---- reset revokes everything ---------------------------------------------------------

test("reset: revokes CLI, Desktop and browser sessions and MCP grants; expires approved device codes; voids MCP codes", async (t) => {
  const ctx = await setup(t);
  const browser = sessionCookie(await registerVerified(ctx, "all@acme.test"));
  const member = (await ctx.database.query<{ id: string; organization_id: string; workspace_id: string }>(
    `SELECT u.id, m.organization_id, w.id AS workspace_id FROM selfhost_users u
       JOIN selfhost_organization_memberships m ON m.user_id = u.id
       JOIN selfhost_workspaces w ON w.organization_id = m.organization_id
      WHERE u.email = 'all@acme.test' LIMIT 1`,
  )).rows[0]!;
  const approve = async () => {
    const started = await ctx.store.startDeviceAuthorization("relay-cli");
    assert.equal(await ctx.store.decideDeviceAuthorization({ userCode: started.userCode, approve: true, userId: member.id, workspaceId: member.workspace_id }), "approved");
    return started.deviceCode;
  };
  // A CLI session (collected), a Desktop session, and an approval nobody collected yet.
  const cliPoll = await ctx.store.pollDeviceAuthorization(await approve());
  assert.equal(cliPoll.kind, "issued");
  const cli = (cliPoll as { tokens: { accessToken: string; refreshToken: string } }).tokens;
  const desktop = await ctx.store.issueDesktopSession({ userId: member.id, organizationId: member.organization_id, workspaceId: member.workspace_id, tokenFamilyId: randomUUID() });
  const uncollected = await approve();
  // An MCP OAuth grant and an authorization code not redeemed yet.
  await ctx.database.query("INSERT INTO selfhost_mcp_oauth_clients (client_id, client_name, redirect_uris) VALUES ('mcp-client', 'Editor', ARRAY['http://127.0.0.1/cb'])");
  const grantId = randomUUID();
  const familyId = randomUUID();
  await ctx.database.query(
    `INSERT INTO selfhost_mcp_oauth_grants (id, client_id, user_id, organization_id, workspace_id, agent_name, scopes, resource, token_family_id)
     VALUES ($1, 'mcp-client', $2, $3, $4, 'editor', ARRAY['relay:mcp'], 'https://mcp.example.test', $5)`,
    [grantId, member.id, member.organization_id, member.workspace_id, familyId],
  );
  // A live MCP OAuth session in the grant's token family.
  await ctx.database.query(
    `INSERT INTO selfhost_mcp_oauth_sessions
       (id, grant_id, token_family_id, user_id, organization_id, workspace_id, scopes, access_token_hash, refresh_token_hash,
        access_token_expires_at, refresh_token_expires_at, created_at, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, ARRAY['relay:mcp'], $7, $8, now() + interval '1 hour', now() + interval '30 days', now(), now())`,
    [randomUUID(), grantId, familyId, member.id, member.organization_id, member.workspace_id, "a".repeat(64), "b".repeat(64)],
  );
  await ctx.database.query(
    `INSERT INTO selfhost_mcp_oauth_authorization_codes
       (code_hash, client_id, user_id, organization_id, workspace_id, agent_name, redirect_uri, code_challenge, scopes, resource, expires_at)
     VALUES ($1, 'mcp-client', $2, $3, $4, 'editor', 'http://127.0.0.1/cb', 'challenge', ARRAY['relay:mcp'], 'https://mcp.example.test', now() + interval '5 minutes')`,
    ["c".repeat(64), member.id, member.organization_id, member.workspace_id],
  );
  // A Desktop relay identity (an agent token Relaycast minted for this person).
  await ctx.database.query(
    `INSERT INTO selfhost_desktop_relay_identities
       (id, workspace_id, organization_id, user_id, relaycast_workspace_id, source_id, agent_name, agent_remote_id, address, token_ciphertext)
     VALUES ($1, $2, $3, $4, 'rc-ws', $5, 'desktop-agent', 'remote-1', 'desktop-agent@host', 'ciphertext')`,
    [randomUUID(), member.workspace_id, member.organization_id, member.id, randomUUID()],
  );
  // A person messaging identity is not a session: kept.
  await ctx.database.query(
    `INSERT INTO selfhost_person_identities (id, workspace_id, user_id, agent_name, agent_remote_id, token_ciphertext, relaycast_workspace_id)
     VALUES ($1, $2, $3, 'all', 'human-1', 'ciphertext', 'rc-ws')`,
    [randomUUID(), member.workspace_id, member.id],
  );
  const identitiesBefore = Number((await ctx.database.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM selfhost_person_identities WHERE user_id = $1", [member.id])).rows[0]!.n);
  assert.ok(await ctx.store.authenticateAccessToken(cli.accessToken));
  assert.ok(await ctx.store.authenticateAccessToken(desktop.accessToken));

  await call(ctx.origin, `${API}/reset`, { json: { email: "all@acme.test" } });
  await ctx.identity.idle();
  const token = linkToken(ctx.mailer.sent.at(-1)!, "/login/password/reset");
  const done = await call(ctx.origin, `${API}/reset/complete`, { json: { token, password: "a brand new long passphrase" } });
  assert.equal(done.status, 200, done.text);
  assert.equal(done.body.revoked.sessions, 3, "browser, CLI and Desktop");
  assert.equal(done.body.revoked.mcpGrants, 1);
  assert.equal(done.body.revoked.desktopRelayIdentities, 1);
  assert.equal(done.body.revoked.deviceAuthorizations, 1);
  assert.equal(done.body.revoked.mcpCodes, 1);

  assert.equal((await session(ctx, browser)).status, 401);
  assert.equal(await ctx.store.authenticateAccessToken(cli.accessToken), null, "CLI session revoked");
  assert.equal(await ctx.store.authenticateAccessToken(desktop.accessToken), null, "Desktop session revoked");
  assert.equal(await ctx.store.refresh(cli.refreshToken), null, "and cannot be refreshed");
  const late = await ctx.store.pollDeviceAuthorization(uncollected);
  assert.equal(late.kind, "error", "an approval nobody collected cannot be collected after the reset");
  assert.equal((late as { error: string }).error, "expired_token");
  const grant = await ctx.database.query<{ revoked_reason: string | null }>("SELECT revoked_reason FROM selfhost_mcp_oauth_grants WHERE id = $1", [grantId]);
  assert.equal(grant.rows[0]!.revoked_reason, "password_reset");
  const family = await ctx.database.query<{ revoked_at: Date | null; revoked_reason: string | null }>(
    "SELECT revoked_at, revoked_reason FROM selfhost_mcp_oauth_sessions WHERE grant_id = $1", [grantId]);
  assert.ok(family.rows[0]!.revoked_at, "the grant's MCP session family is revoked with it");
  assert.equal(family.rows[0]!.revoked_reason, "oauth_grant_password_reset");
  const tombstone = await ctx.database.query<{ user_id: string; token_family_id: string; reason: string }>(
    "SELECT user_id, token_family_id, reason FROM selfhost_mcp_oauth_revocations WHERE grant_id = $1", [grantId]);
  assert.equal(tombstone.rows.length, 1, "a revocation tombstone drives Relaycast teardown");
  assert.deepEqual(tombstone.rows[0], { user_id: member.id, token_family_id: familyId, reason: "password_reset" });
  const code = await ctx.database.query<{ consumed_at: Date | null; live: boolean }>(
    "SELECT consumed_at, expires_at > now() AS live FROM selfhost_mcp_oauth_authorization_codes");
  assert.equal(code.rows[0]!.live, false, "the unredeemed MCP code is void (expired)");
  assert.equal(code.rows[0]!.consumed_at, null, "and not marked as redeemed");
  const audit = (await auditActions(ctx)).find((e) => e.action === "password.reset.completed");
  assert.match(audit!.target!, /sessions_revoked=3 mcp_grants_revoked=1 desktop_relay_identities_deleted=1 device_authorizations_expired=1 mcp_codes_voided=1/);
  const relayIdentities = await ctx.database.query("SELECT id FROM selfhost_desktop_relay_identities WHERE user_id = $1", [member.id]);
  assert.equal(relayIdentities.rows.length, 0, "Desktop relay identities are deleted");
  const identitiesAfter = Number((await ctx.database.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM selfhost_person_identities WHERE user_id = $1", [member.id])).rows[0]!.n);
  assert.equal(identitiesBefore, 1);
  assert.equal(identitiesAfter, identitiesBefore, "person messaging identities are not touched");
});

// ---- rate limits and the /login page ------------------------------------------------------

test("token routes are rate limited per IP (429 rate_limited)", async (t) => {
  const ctx = await setup(t);
  const statuses: number[] = [];
  for (let i = 0; i < 31; i += 1) {
    statuses.push((await call(ctx.origin, `${API}/verify`, { json: { token: `sh_pv_${"x".repeat(30)}` }, ip: "203.0.113.77" })).status);
  }
  assert.deepEqual([...new Set(statuses.slice(0, 30))], [410]);
  const limited = await call(ctx.origin, `${API}/set`, { json: { token: `sh_ps_${"x".repeat(30)}`, password: PASSWORD }, ip: "203.0.113.77" });
  assert.equal(statuses[30], 429);
  assert.equal(limited.status, 429);
  assert.equal(limited.body.error, "rate_limited");
  const reset = await call(ctx.origin, `${API}/reset/complete`, { json: { token: `sh_pr_${"x".repeat(30)}`, password: PASSWORD }, ip: "203.0.113.77" });
  assert.equal(reset.status, 429);
  assert.equal((await call(ctx.origin, `${API}/verify`, { json: { token: `sh_pv_${"x".repeat(30)}` }, ip: "203.0.113.78" })).status, 410, "another IP is unaffected");
});

test("every password route refuses cross-site and non-JSON requests (403 csrf_rejected)", async (t) => {
  const ctx = await setup(t);
  for (const route of ["login", "register", "verify", "set", "reset", "reset/complete"]) {
    const crossSite = await call(ctx.origin, `${API}/${route}`, { json: { email: "x@acme.test" }, originHeader: "https://evil.example" });
    assert.equal(crossSite.status, 403, route);
    assert.equal(crossSite.body.error, "csrf_rejected", route);
    const form = await call(ctx.origin, `${API}/${route}`, { form: { email: "x@acme.test" } });
    assert.equal(form.status, 403, `${route} form`);
    assert.equal(form.body.error, "csrf_rejected");
  }
});

test("/login page: the invalid_credentials notice only shows when password sign-in is enabled", async (t) => {
  const ctx = await setup(t, { env: { SELFHOST_SIGNIN_METHODS: "email_link" } });
  const page = await call(ctx.origin, "/login?error=invalid_credentials");
  assert.equal(page.status, 200);
  assert.doesNotMatch(page.text, /Incorrect email or password\./);
});

test("/login page: password form posts to /login/password and signs in with a cookie", async (t) => {
  const ctx = await setup(t);
  await registerVerified(ctx, "form@acme.test");
  const page = await call(ctx.origin, "/login?next=%2Fcloud%2Fsettings");
  assert.equal(page.status, 200);
  assert.match(page.text, /<form method="post" action="\/login\/password">/);
  assert.match(page.text, /type="password" name="password"[^>]*autocomplete="current-password"/);
  assert.match(page.text, /name="next" value="\/cloud\/settings"/);

  const wrong = await call(ctx.origin, "/login/password", { form: { email: "form@acme.test", password: "not the password", next: "/cloud/settings" } });
  assert.equal(wrong.status, 303);
  assert.equal(wrong.location, "/login?next=%2Fcloud%2Fsettings&error=invalid_credentials");
  assert.equal(wrong.cookies.agent_relay_session, undefined);
  assert.match((await call(ctx.origin, wrong.location!)).text, /Incorrect email or password\./);

  const crossSite = await call(ctx.origin, "/login/password", { form: { email: "form@acme.test", password: PASSWORD }, originHeader: "https://evil.example" });
  assert.equal(crossSite.status, 403);
  const ok = await call(ctx.origin, "/login/password", { form: { email: "form@acme.test", password: PASSWORD, next: "/cloud/settings" } });
  assert.equal(ok.status, 303);
  assert.equal(ok.location, "/cloud/settings");
  assert.equal((await session(ctx, sessionCookie(ok))).status, 200);
  const offsite = await call(ctx.origin, "/login/password", { form: { email: "form@acme.test", password: PASSWORD, next: "//evil.example/" } });
  assert.equal(offsite.location, "/", "next stays on this site");
  // The form shares the JSON route's lockout and audit.
  assert.ok((await auditActions(ctx)).some((e) => e.action === "login.password.failure" && e.target!.includes("email=form@acme.test")));

  const linkOnly = await setup(t, { env: { SELFHOST_SIGNIN_METHODS: "email_link" } });
  assert.doesNotMatch((await call(linkOnly.origin, "/login")).text, /action="\/login\/password"/);
  assert.equal((await call(linkOnly.origin, "/login/password", { form: { email: "a@acme.test", password: PASSWORD } })).status, 404);
});

// ---- retention -----------------------------------------------------------------------------

test("retention: idle login attempts after 24 hours, spent or expired tokens after 7 days", async (t) => {
  const ctx = await setup(t);
  await registerVerified(ctx, "keep@acme.test");
  await login(ctx, "keep@acme.test", "a wrong passphrase");
  await verifyLink(ctx, "pending@acme.test");
  await call(ctx.origin, `${API}/reset`, { json: { email: "keep@acme.test" } });
  await ctx.identity.idle();
  const count = async (table: string) => Number((await ctx.database.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${table}`)).rows[0]!.n);
  const tables = ["selfhost_login_attempts", "selfhost_password_registrations", "selfhost_password_setup_tokens", "selfhost_password_reset_tokens"];
  const before = await Promise.all(tables.map(count));
  assert.ok(before.every((n) => n > 0), String(before));

  await ctx.identity.sweep();
  assert.deepEqual(await Promise.all(tables.map(count)), before, "nothing recent is deleted");
  ctx.clock.now += 25 * 60 * 60 * 1_000;
  await ctx.identity.sweep();
  assert.equal(await count("selfhost_login_attempts"), 0, "idle attempt rows go after 24 hours");
  assert.ok((await count("selfhost_password_registrations")) > 0, "tokens are kept for 7 days");
  ctx.clock.now += 7 * 24 * 60 * 60 * 1_000;
  await ctx.identity.sweep();
  assert.deepEqual(await Promise.all(tables.map(count)), [0, 0, 0, 0]);
  assert.equal(await count("selfhost_password_credentials"), 1, "credentials are never swept");
});
