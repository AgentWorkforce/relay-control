import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { ApiTokenStore } from "../src/admin/api-tokens.js";
import { createAdminModule } from "../src/admin/routes.js";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * Desktop enrollment keys (docs/identity.md, "Desktop enrollment keys"):
 * an owner/admin mints a one-time sh_ek_ key for an employee, the installer
 * exchanges it once for a device session.
 */

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const SERVICE = "internal-service-token-that-is-at-least-32-bytes";
const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const HISTORY = "https://history.selfhosted.test";
const DEVICE_SCOPES = ["cli:auth", "rth:read", "rth:sync", "rth:acquire"];
const EXCHANGE = "/api/v1/auth/enrollment/token";
const DAY_MS = 24 * 60 * 60 * 1000;

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");

async function setup(t: TestContext) {
  const database = new PGliteDatabase();
  await migrate(database);
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: origin,
    relaycastUrl: "http://relaycast.invalid",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: HISTORY,
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: HISTORY, secret: "r".repeat(32) },
    introspectSecret: INTROSPECT_SECRET,
    introspectAudiences: [HISTORY],
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: SERVICE,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${origin}/dashboard/`,
    port: 0,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, KEYRING, 0);
  const admin = createAdminModule({ config, database, keyring: KEYRING });
  control.on("request", createApp({ config, store, admin }));
  t.after(async () => {
    await close(control);
    await database.close();
  });

  const org = await request(origin, "/api/v1/organizations", {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Acme", ownerEmail: "owner@acme.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const organizationId = org.body.id as string;
  const ownerId = org.body.owner.id as string;
  const created = await request(origin, `/api/v1/organizations/${organizationId}/workspaces`, {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "primary", relaycastApiKey: "rk_primary" },
  });
  assert.equal(created.status, 201);
  const workspaceId = created.body.id as string;
  const base = `/api/v1/workspaces/${workspaceId}/deployment-api-tokens`;

  const deviceToken = async (userId: string) => {
    const started = await request(origin, "/api/v1/auth/device/start", { method: "POST", body: {} });
    const approved = await request(origin, "/api/v1/auth/device/approve", {
      method: "POST",
      token: BOOTSTRAP,
      body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: workspaceId },
    });
    assert.equal(approved.status, 200);
    const issued = await request(origin, "/api/v1/auth/device/token", {
      method: "POST",
      body: { device_code: started.body.device_code },
    });
    assert.equal(issued.status, 200);
    return issued.body.access_token as string;
  };
  const owner = await deviceToken(ownerId);
  const mint = (body: Record<string, unknown>) => request(origin, base, { method: "POST", token: owner, body });
  const mintKey = async (email: string, extra: Record<string, unknown> = {}) => {
    const answer = await mint({ label: "laptop rollout", purpose: "desktop-enrollment", email, ...extra });
    assert.equal(answer.status, 201, `mint ${email}: ${answer.status} ${answer.body?.error ?? ""}`);
    return answer.body as { id: string; accessToken: string } & Record<string, any>;
  };
  const exchange = (key: unknown, extra: Record<string, unknown> = {}) =>
    request(origin, EXCHANGE, {
      method: "POST",
      body: { enrollment_key: key, client_name: "Agent Relay Desktop", desktop_host_name: "build-01", ...extra },
    });
  const addMember = async (email: string) => {
    const added = await request(origin, `/api/v1/organizations/${organizationId}/memberships`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { email, name: email, role: "member" },
    });
    assert.equal(added.status, 200);
    return added.body.userId as string;
  };
  const audit = async () => {
    const listed = await request(origin, `/api/v1/workspaces/${workspaceId}/admin/audit`, { token: owner });
    assert.equal(listed.status, 200);
    return listed.body.events as Array<{ actorKind: string; actorId: string | null; action: string; target: string | null }>;
  };
  const session = async (accessToken: string) =>
    (await database.query<{
      id: string;
      label: string;
      scopes: string[];
      user_id: string;
      desktop_host_name: string | null;
      desktop_verified_at: Date | null;
      provisioned_by_token_id: string | null;
      revoked_at: Date | null;
      revoked_reason: string | null;
    }>(
      `SELECT id, label, scopes, user_id, desktop_host_name, desktop_verified_at,
              provisioned_by_token_id, revoked_at, revoked_reason
         FROM token_sessions WHERE access_token_hash = $1`,
      [sha256(accessToken)],
    )).rows[0];
  return {
    database, origin, organizationId, ownerId, workspaceId, base, owner,
    deviceToken, mint, mintKey, exchange, addMember, audit, session,
  };
}

test("mint: binds an existing member by normalized email, default 7 days, record fields", async (t) => {
  const env = await setup(t);
  const memberId = await env.addMember("member@acme.test");
  const before = Date.now();
  const key = await env.mintKey("  Member@ACME.test ");
  assert.match(key.accessToken, /^sh_ek_/);
  assert.equal(key.tokenPrefix, key.accessToken.slice(0, "sh_ek_".length + 4));
  assert.equal(key.purpose, "desktop-enrollment");
  assert.deepEqual(key.scopes, []);
  assert.equal(key.userId, memberId);
  assert.equal(key.userEmail, "member@acme.test");
  assert.equal(key.mcpConsent, null);
  assert.equal(key.exchangedAt, null);
  assert.equal(key.exchangedHostName, null);
  assert.equal(key.agent_name, null);
  assert.equal(key.aud, null);
  const lifetime = Date.parse(key.accessTokenExpiresAt) - before;
  assert.ok(lifetime > 7 * DAY_MS - 60_000 && lifetime <= 7 * DAY_MS + 60_000, "default expiry is 7 days");

  const listed = await request(env.origin, env.base, { token: env.owner });
  const row = (listed.body.tokens as Array<Record<string, any>>).find((token) => token.id === key.id)!;
  assert.equal(row.userId, memberId);
  assert.equal(row.userEmail, "member@acme.test");
  assert.equal("accessToken" in row, false);

  const withConsent = await env.mintKey("member@acme.test", { mcpConsent: "admin", expiryDays: 30 });
  assert.equal(withConsent.mcpConsent, "admin");
  const events = await env.audit();
  assert.equal(events.some((event) => event.action === "membership.provision"), false, "existing member: no provision");
  const created = events.find((event) => event.action === "api_token.create" && event.target?.startsWith(withConsent.id));
  assert.equal(created?.target, `${withConsent.id} (desktop-enrollment: user ${memberId} mcpConsent=admin)`);
});

test("mint: a new email pre-creates the user and a member membership, audited membership.provision", async (t) => {
  const env = await setup(t);
  const key = await env.mintKey("new.hire@acme.test");
  assert.ok(key.userId);
  const memberships = await request(env.origin, `/api/v1/organizations/${env.organizationId}/memberships`, {
    token: BOOTSTRAP,
  });
  assert.equal(memberships.status, 200);
  const added = (memberships.body.memberships as Array<Record<string, any>>)
    .find((membership) => membership.userId === key.userId);
  assert.ok(added, "membership created");
  assert.equal(added.role, "member");
  assert.equal(added.email, "new.hire@acme.test");
  const passwords = await env.database.query(
    "SELECT 1 FROM password_credentials WHERE user_id = $1",
    [key.userId],
  );
  assert.equal(passwords.rows.length, 0, "no password");

  const provision = (await env.audit()).find((event) => event.action === "membership.provision");
  assert.ok(provision);
  assert.equal(provision.actorKind, "user");
  assert.equal(provision.actorId, env.ownerId);
  assert.equal(provision.target, `${key.userId} new.hire@acme.test role member`);

  // A second key for the same person reuses the user, no second provision.
  const again = await env.mintKey("new.hire@acme.test");
  assert.equal(again.userId, key.userId);
  assert.equal((await env.audit()).filter((event) => event.action === "membership.provision").length, 1);
});

test("mint: expiry bounds, neverExpires, email and mcpConsent per purpose", async (t) => {
  const env = await setup(t);
  const refused = async (body: Record<string, unknown>, label: string) => {
    const answer = await env.mint(body);
    assert.equal(answer.status, 400, label);
    assert.equal(answer.body.error, "invalid_request", label);
  };
  const enrollment = { label: "k", purpose: "desktop-enrollment", email: "x@acme.test" };
  await refused({ ...enrollment, expiryDays: 31 }, "31 days");
  await refused({ ...enrollment, expiryDays: 0 }, "0 days");
  await refused({ ...enrollment, neverExpires: true }, "neverExpires");
  await refused({ ...enrollment, mcpConsent: "user" }, "unknown consent");
  await refused({ label: "k", purpose: "desktop-enrollment" }, "missing email");
  await refused({ label: "k", purpose: "desktop-enrollment", email: "not-an-email" }, "bad email");
  await refused({ label: "k", purpose: "deployment", email: "x@acme.test" }, "email on deployment");
  await refused({ label: "k", purpose: "workflow", mcpConsent: "admin" }, "mcpConsent on workflow");
  const ok = await env.mintKey("x@acme.test", { expiryDays: 1, neverExpires: false });
  assert.ok(ok.accessTokenExpiresAt);
});

test("exchange: device/token shape and scopes; consent decides Desktop verification", async (t) => {
  const env = await setup(t);
  const memberId = await env.addMember("member@acme.test");
  const plain = await env.mintKey("member@acme.test");
  const exchanged = await env.exchange(plain.accessToken);
  assert.equal(exchanged.status, 200);
  assert.equal(exchanged.headers.get("cache-control"), "no-store");
  assert.deepEqual(Object.keys(exchanged.body).sort(), [
    "access_token", "access_token_expires_at", "api_url", "refresh_token", "refresh_token_expires_at", "scope", "token_type",
  ]);
  assert.equal(exchanged.body.token_type, "Bearer");
  assert.equal(exchanged.body.api_url, `${env.origin}/cloud`);
  assert.deepEqual(exchanged.body.scope.split(" ").sort(), [...DEVICE_SCOPES].sort());
  const row = (await env.session(exchanged.body.access_token))!;
  assert.equal(row.user_id, memberId);
  assert.equal(row.label, "Agent Relay Desktop");
  assert.deepEqual([...row.scopes].sort(), [...DEVICE_SCOPES].sort());
  assert.equal(row.desktop_host_name, "build-01");
  assert.equal(row.desktop_verified_at, null, "no consent: unverified like a device-code session");
  assert.equal(row.provisioned_by_token_id, plain.id);

  const keyRow = (await request(env.origin, env.base, { token: env.owner })).body.tokens
    .find((token: Record<string, any>) => token.id === plain.id);
  assert.ok(keyRow.exchangedAt);
  assert.equal(keyRow.exchangedHostName, "build-01");
  assert.ok(keyRow.lastUsedAt);

  const consented = await env.mintKey("member@acme.test", { mcpConsent: "admin" });
  const verified = await env.exchange(consented.accessToken, { desktop_host_name: "build-02" });
  assert.equal(verified.status, 200);
  const verifiedRow = (await env.session(verified.body.access_token))!;
  assert.ok(verifiedRow.desktop_verified_at, "admin consent: Desktop-verified");
  assert.equal(verifiedRow.desktop_host_name, "build-02");

  // The cloud mount serves the same route.
  const third = await env.mintKey("member@acme.test");
  const viaCloud = await request(env.origin, `/cloud${EXCHANGE}`, {
    method: "POST",
    body: { enrollment_key: third.accessToken, client_name: "Agent Relay Desktop", desktop_host_name: "build-03" },
  });
  assert.equal(viaCloud.status, 200);
});

test("exchange: spent, expired, revoked and unknown keys get one identical invalid_grant", async (t) => {
  const env = await setup(t);
  await env.addMember("member@acme.test");
  const spent = await env.mintKey("member@acme.test");
  assert.equal((await env.exchange(spent.accessToken)).status, 200);
  const expired = await env.mintKey("member@acme.test");
  await env.database.query(
    "UPDATE workspace_api_tokens SET expires_at = now() - interval '1 minute' WHERE id = $1",
    [expired.id],
  );
  const revoked = await env.mintKey("member@acme.test");
  assert.equal((await request(env.origin, `${env.base}/${revoked.id}`, { method: "DELETE", token: env.owner })).status, 204);

  const answers = [];
  for (const key of [spent.accessToken, expired.accessToken, revoked.accessToken, `sh_ek_${"0".repeat(43)}`]) {
    const answer = await env.exchange(key);
    assert.equal(answer.status, 400);
    assert.equal(answer.headers.get("cache-control"), "no-store");
    answers.push(answer.raw);
  }
  assert.deepEqual(JSON.parse(answers[0]!), {
    error: "invalid_grant",
    error_description: "Enrollment key is invalid, expired, revoked or already used",
  });
  assert.equal(new Set(answers).size, 1, "one body whatever the reason");

  // Malformed requests are invalid_request, never a lookup.
  const workspaceKey = (await env.mint({ label: "ci", purpose: "deployment" })).body.accessToken as string;
  for (const [body, label] of [
    [{ enrollment_key: workspaceKey, client_name: "Desktop", desktop_host_name: "h" }, "sh_wk_ key"],
    [{ enrollment_key: spent.accessToken, desktop_host_name: "h" }, "no client_name"],
    [{ enrollment_key: spent.accessToken, client_name: "Desktop" }, "no host"],
    [{ enrollment_key: spent.accessToken, client_name: "relay-dashboard", desktop_host_name: "h" }, "reserved name"],
  ] as const) {
    const answer = await request(env.origin, EXCHANGE, { method: "POST", body });
    assert.equal(answer.status, 400, label);
    assert.equal(answer.body.error, "invalid_request", label);
  }
});

test("exchange: 10 per client address per 5 minutes, then 429 slow_down", async (t) => {
  const env = await setup(t);
  const unknown = `sh_ek_${"1".repeat(43)}`;
  for (let attempt = 0; attempt < 10; attempt += 1) {
    assert.equal((await env.exchange(unknown)).status, 400);
  }
  const limited = await env.exchange(unknown);
  assert.equal(limited.status, 429);
  assert.equal(limited.body.error, "slow_down");
  assert.ok(limited.headers.get("retry-after"));
});

test("exchange audit: actor is the employee, target has key id, ip and host, never the key", async (t) => {
  const env = await setup(t);
  const memberId = await env.addMember("member@acme.test");
  const key = await env.mintKey("member@acme.test");
  assert.equal((await env.exchange(key.accessToken)).status, 200);
  const events = await env.audit();
  const exchange = events.find((event) => event.action === "enrollment_key.exchange");
  assert.ok(exchange);
  assert.equal(exchange.actorKind, "user");
  assert.equal(exchange.actorId, memberId);
  assert.match(exchange.target ?? "", new RegExp(`^${key.id} ip=\\S+ host=build-01$`));
  assert.ok(/ip=(127\.0\.0\.1|::1|::ffff:127\.0\.0\.1)/.test(exchange.target ?? ""), "loopback client address");
  const secret = key.accessToken.slice("sh_ek_".length);
  const everything = JSON.stringify(events);
  assert.equal(everything.includes(key.accessToken), false);
  assert.equal(everything.includes(secret), false);
});

test("refresh keeps the provisioning link; whoami shows it; admin revoke ends the session", async (t) => {
  const env = await setup(t);
  await env.addMember("member@acme.test");
  const key = await env.mintKey("member@acme.test", { mcpConsent: "admin" });
  const issued = await env.exchange(key.accessToken);
  assert.equal(issued.status, 200);
  const refreshed = await request(env.origin, "/api/v1/auth/token/refresh", {
    method: "POST",
    body: { refreshToken: issued.body.refresh_token },
  });
  assert.equal(refreshed.status, 200);
  const access = refreshed.body.accessToken as string;
  assert.equal((await env.session(access))?.provisioned_by_token_id, key.id);

  const whoami = await request(env.origin, "/api/v1/auth/whoami", { token: access });
  assert.equal(whoami.status, 200);
  const provisioning = whoami.body.provisioning;
  assert.equal(provisioning.kind, "enrollment_key");
  assert.equal(provisioning.keyId, key.id);
  assert.equal(provisioning.label, "laptop rollout");
  assert.equal(provisioning.mcpConsent, "admin");
  assert.equal(provisioning.mintedBy.id, env.ownerId);
  assert.equal(provisioning.mintedAt, key.createdAt);
  assert.ok(provisioning.exchangedAt);
  const ownerWhoami = await request(env.origin, "/api/v1/auth/whoami", { token: env.owner });
  assert.equal(ownerWhoami.body.provisioning, null);

  assert.equal((await request(env.origin, `${env.base}/${key.id}`, { method: "DELETE", token: env.owner })).status, 204);
  assert.equal((await request(env.origin, "/api/v1/auth/whoami", { token: access })).status, 401);
  const row = (await env.session(access))!;
  assert.ok(row.revoked_at);
  assert.equal(row.revoked_reason, "enrollment_key_revoked");
  const again = await request(env.origin, "/api/v1/auth/token/refresh", {
    method: "POST",
    body: { refreshToken: refreshed.body.refreshToken },
  });
  assert.equal(again.status, 403);
  const revoke = (await env.audit()).find((event) => event.action === "api_token.revoke");
  assert.match(revoke?.target ?? "", new RegExp(`^${key.id} \\(desktop-enrollment: user [0-9a-f-]+\\) sessions=1$`));
});

test("/api/v1/me/enrollment-keys: the employee lists and revokes only their own keys", async (t) => {
  const env = await setup(t);
  const memberId = await env.addMember("member@acme.test");
  const otherId = await env.addMember("other@acme.test");
  const mine = await env.mintKey("member@acme.test", { mcpConsent: "admin" });
  const theirs = await env.mintKey("other@acme.test");
  const issued = await env.exchange(mine.accessToken);
  const employee = issued.body.access_token as string;
  const otherToken = await env.deviceToken(otherId);

  assert.equal((await request(env.origin, "/api/v1/me/enrollment-keys")).status, 401);
  const listed = await request(env.origin, "/api/v1/me/enrollment-keys", { token: employee });
  assert.equal(listed.status, 200);
  assert.equal(listed.headers.get("cache-control"), "no-store");
  assert.equal(listed.body.keys.length, 1);
  const summary = listed.body.keys[0];
  assert.deepEqual(Object.keys(summary).sort(), [
    "createdAt", "exchangedAt", "exchangedHostName", "expiresAt", "id", "label", "mcpConsent", "mintedBy", "status",
  ]);
  assert.equal(summary.id, mine.id);
  assert.equal(summary.mcpConsent, "admin");
  assert.equal(summary.exchangedHostName, "build-01");
  assert.equal(summary.mintedBy.id, env.ownerId);
  assert.equal(JSON.stringify(listed.body).includes(mine.accessToken), false);

  // Someone else's key, or a non-UUID id, is a 404.
  const foreign = await request(env.origin, `/api/v1/me/enrollment-keys/${theirs.id}`, { method: "DELETE", token: employee });
  assert.equal(foreign.status, 404);
  assert.equal(foreign.body.error, "token_not_found");
  assert.equal((await request(env.origin, "/api/v1/me/enrollment-keys/nope", { method: "DELETE", token: employee })).status, 404);
  const otherList = await request(env.origin, "/api/v1/me/enrollment-keys", { token: otherToken });
  assert.deepEqual(otherList.body.keys.map((key: { id: string }) => key.id), [theirs.id]);

  const deleted = await request(env.origin, `/api/v1/me/enrollment-keys/${mine.id}`, { method: "DELETE", token: employee });
  assert.equal(deleted.status, 204);
  assert.equal((await request(env.origin, "/api/v1/auth/whoami", { token: employee })).status, 401, "own session revoked");
  const revoke = (await env.audit()).find((event) => event.action === "api_token.revoke");
  assert.equal(revoke?.actorId, memberId, "the employee is the actor");
  const status = (await request(env.origin, env.base, { token: env.owner })).body.tokens
    .find((token: Record<string, any>) => token.id === mine.id).status;
  assert.equal(status, "revoked");
  assert.equal((await request(env.origin, `/api/v1/me/enrollment-keys/${theirs.id}`, { method: "DELETE", token: otherToken })).status, 204);
});

test("membership removal revokes the member's unexchanged keys", async (t) => {
  const env = await setup(t);
  const memberId = await env.addMember("member@acme.test");
  const unexchanged = await env.mintKey("member@acme.test");
  const exchanged = await env.mintKey("member@acme.test");
  const issued = await env.exchange(exchanged.accessToken);
  assert.equal(issued.status, 200);
  const removed = await request(env.origin, `/api/v1/organizations/${env.organizationId}/memberships/${memberId}`, {
    method: "DELETE",
    token: BOOTSTRAP,
  });
  assert.ok(removed.status === 200 || removed.status === 204, `remove: ${removed.status}`);
  const tokens = (await request(env.origin, env.base, { token: env.owner })).body.tokens as Array<Record<string, any>>;
  assert.equal(tokens.find((token) => token.id === unexchanged.id)!.status, "revoked");
  assert.equal((await env.exchange(unexchanged.accessToken)).status, 400);
  assert.equal((await request(env.origin, "/api/v1/auth/whoami", { token: issued.body.access_token })).status, 401);
  const revokes = (await env.audit()).filter((event) => event.action === "api_token.revoke");
  assert.ok(revokes.some((event) => event.target?.startsWith(unexchanged.id) && event.target.endsWith(" reason=member_removed")));
});

test("the key is never a bearer: workspace token gates, introspection and admin routes refuse it", async (t) => {
  const env = await setup(t);
  await env.addMember("member@acme.test");
  const key = await env.mintKey("member@acme.test");
  const apiTokens = new ApiTokenStore(env.database);
  assert.equal(await apiTokens.authenticate(key.accessToken), null);
  const verdict = await request(env.origin, "/internal/v1/auth/introspect", {
    method: "POST",
    token: INTROSPECT_SECRET,
    body: { token: key.accessToken, aud: HISTORY, workspace: env.workspaceId },
  });
  assert.equal(verdict.status, 200);
  assert.deepEqual(verdict.body, { active: false, reason: "wrong-kind" });
  assert.equal((await request(env.origin, env.base, { token: key.accessToken })).status, 401);
  assert.equal((await request(env.origin, "/api/v1/auth/whoami", { token: key.accessToken })).status, 401);
  assert.equal((await request(env.origin, "/api/v1/me/enrollment-keys", { token: key.accessToken })).status, 401);
  // Still exchangeable afterwards: none of the refusals spent it.
  assert.equal((await env.exchange(key.accessToken)).status, 200);
});

test("discovery: capabilities advertise enrollment_keys (login-config: setup-key-temporary-passwords.test.ts)", async (t) => {
  const env = await setup(t);
  const capabilities = await request(env.origin, "/api/v1/capabilities", { token: env.owner });
  assert.equal(capabilities.status, 200);
  assert.equal(capabilities.body.capabilities.enrollment_keys, true);
});
