import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { enrollmentLimits } from "../src/admin/api-tokens.js";
import { createAdminModule } from "../src/admin/routes.js";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * Per-person desktop enrollment keys (docs/identity.md, "Desktop enrollment
 * keys"): maxUses, the expiry ceilings, policyConsent and the managed
 * session it yields (docs/workspace-policy.md, "managed"). Same harness as
 * desktop-enrollment-keys.test.ts.
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
  const accessMe = (token: string) =>
    request(origin, `/api/v1/workspaces/${workspaceId}/access/me`, { token });
  const introspect = (token: string) =>
    request(origin, "/internal/v1/auth/introspect", {
      method: "POST",
      token: INTROSPECT_SECRET,
      body: { token, aud: HISTORY, workspace: workspaceId },
    });
  const keyRow = async (id: string) =>
    ((await request(origin, base, { token: owner })).body.tokens as Array<Record<string, any>>)
      .find((token) => token.id === id)!;
  return {
    database, origin, organizationId, ownerId, workspaceId, base, owner,
    deviceToken, mint, mintKey, exchange, addMember, audit, session, accessMe, introspect, keyRow,
  };
}

const ENV_NAMES = [
  "SELFHOST_ENROLLMENT_MAX_USES",
  "SELFHOST_ENROLLMENT_MAX_DAYS",
  "SELFHOST_ENROLLMENT_MULTI_USE_MAX_DAYS",
  "SELFHOST_ENROLLMENT_SELF_MINT_MAX_DAYS",
] as const;

/** Sets (or, with undefined, clears) an env var for one test and restores it after. */
function withEnv(t: TestContext, name: (typeof ENV_NAMES)[number], value: string | undefined) {
  const previous = process.env[name];
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
  t.after(() => {
    if (previous === undefined) delete process.env[name];
    else process.env[name] = previous;
  });
}

/** Every test starts from the defaults, whatever the runner's environment holds. */
function clearEnv(t: TestContext) {
  for (const name of ENV_NAMES) withEnv(t, name, undefined);
}

const expiryDays = (key: Record<string, any>) =>
  Math.round((Date.parse(key.accessTokenExpiresAt) - Date.parse(key.createdAt)) / DAY_MS);

test("enrollmentLimits: defaults, strict parsing and clamping", (t) => {
  clearEnv(t);
  assert.deepEqual(enrollmentLimits({}), { maxUses: 50, maxDays: 30, multiUseMaxDays: 90, selfMintMaxDays: 7 });
  assert.deepEqual(enrollmentLimits({
    SELFHOST_ENROLLMENT_MAX_USES: "5",
    SELFHOST_ENROLLMENT_MAX_DAYS: " 10 ",
    SELFHOST_ENROLLMENT_MULTI_USE_MAX_DAYS: "120",
    SELFHOST_ENROLLMENT_SELF_MINT_MAX_DAYS: "3",
  }), { maxUses: 5, maxDays: 10, multiUseMaxDays: 120, selfMintMaxDays: 3 });
  // Clamped to the database range (max_uses <= 500) and the 365-day token ceiling.
  assert.deepEqual(enrollmentLimits({
    SELFHOST_ENROLLMENT_MAX_USES: "9999",
    SELFHOST_ENROLLMENT_MAX_DAYS: "1000",
    SELFHOST_ENROLLMENT_MULTI_USE_MAX_DAYS: "1000",
    SELFHOST_ENROLLMENT_SELF_MINT_MAX_DAYS: "1000",
  }), { maxUses: 500, maxDays: 365, multiUseMaxDays: 365, selfMintMaxDays: 365 });
  for (const bad of ["", "0", "-3", "abc", "5.5", "1e2", "0x10", "+4", "99999999999999999999"]) {
    assert.equal(enrollmentLimits({ SELFHOST_ENROLLMENT_MAX_USES: bad }).maxUses, 50, `maxUses ${JSON.stringify(bad)}`);
    assert.equal(enrollmentLimits({ SELFHOST_ENROLLMENT_MAX_DAYS: bad }).maxDays, 30, `maxDays ${JSON.stringify(bad)}`);
  }
});

test("default: single-use, list shows maxUses 1 / useCount, second exchange is invalid_grant", async (t) => {
  clearEnv(t);
  const env = await setup(t);
  await env.addMember("member@acme.test");
  const key = await env.mintKey("member@acme.test");
  assert.equal(key.maxUses, 1);
  assert.equal(key.useCount, 0);
  assert.equal(key.policyConsent, null);
  const before = await env.keyRow(key.id);
  assert.equal(before.maxUses, 1);
  assert.equal(before.useCount, 0);
  assert.equal(before.policyConsent, null);
  assert.equal(before.status, "active");

  assert.equal((await env.exchange(key.accessToken)).status, 200);
  const after = await env.keyRow(key.id);
  assert.equal(after.useCount, 1);
  assert.equal(after.status, "exchanged");
  assert.equal(after.exchangedHostName, "build-01");
  assert.ok(after.exchangedAt);

  const again = await env.exchange(key.accessToken, { desktop_host_name: "build-02" });
  assert.equal(again.status, 400);
  assert.equal(again.body.error, "invalid_grant");
  assert.equal((await env.keyRow(key.id)).useCount, 1);
});

test("maxUses 3: three exchanges on three hosts, the fourth is invalid_grant", async (t) => {
  clearEnv(t);
  const env = await setup(t);
  const memberId = await env.addMember("member@acme.test");
  const key = await env.mintKey("member@acme.test", { maxUses: 3 });
  assert.equal(key.maxUses, 3);
  assert.equal(key.useCount, 0);

  const sessions: string[] = [];
  let previousExchangedAt: string | null = null;
  for (const [index, host] of ["laptop-a", "laptop-b", "laptop-c"].entries()) {
    const answer = await env.exchange(key.accessToken, { desktop_host_name: host });
    assert.equal(answer.status, 200, host);
    const row = (await env.session(answer.body.access_token))!;
    assert.equal(row.user_id, memberId, host);
    assert.equal(row.desktop_host_name, host);
    assert.equal(row.provisioned_by_token_id, key.id);
    sessions.push(row.id);

    const listed = await env.keyRow(key.id);
    assert.equal(listed.useCount, index + 1, host);
    assert.equal(listed.maxUses, 3);
    // exchanged_* name the latest exchange.
    assert.equal(listed.exchangedHostName, host);
    assert.ok(listed.exchangedAt);
    if (previousExchangedAt) assert.ok(Date.parse(listed.exchangedAt) >= Date.parse(previousExchangedAt));
    previousExchangedAt = listed.exchangedAt;
    assert.equal(listed.status, index < 2 ? "active" : "exchanged", host);
  }
  assert.equal(new Set(sessions).size, 3, "one session per exchange");
  const stored = (await env.database.query<{ exchanged_session_id: string; use_count: number }>(
    "SELECT exchanged_session_id, use_count FROM workspace_api_tokens WHERE id = $1",
    [key.id],
  )).rows[0]!;
  assert.equal(stored.exchanged_session_id, sessions[2]);
  assert.equal(Number(stored.use_count), 3);

  const fourth = await env.exchange(key.accessToken, { desktop_host_name: "laptop-d" });
  assert.equal(fourth.status, 400);
  assert.deepEqual(fourth.body, {
    error: "invalid_grant",
    error_description: "Enrollment key is invalid, expired, revoked or already used",
  });
  assert.equal((await env.keyRow(key.id)).useCount, 3);
});

test("maxUses: ceiling 50 by default, SELFHOST_ENROLLMENT_MAX_USES overrides it, bad values refused", async (t) => {
  clearEnv(t);
  const env = await setup(t);
  await env.addMember("member@acme.test");
  assert.equal((await env.mintKey("member@acme.test", { maxUses: 50 })).maxUses, 50);
  for (const bad of [51, 0, -1, 1.5, "3", true, 500]) {
    const answer = await env.mint({ label: "l", purpose: "desktop-enrollment", email: "member@acme.test", maxUses: bad });
    assert.equal(answer.status, 400, `maxUses ${JSON.stringify(bad)}`);
    assert.equal(answer.body.error, "invalid_request");
  }
  // Explicit null is the same as absent: single-use.
  assert.equal((await env.mintKey("member@acme.test", { maxUses: null })).maxUses, 1);

  withEnv(t, "SELFHOST_ENROLLMENT_MAX_USES", "5");
  assert.equal((await env.mintKey("member@acme.test", { maxUses: 5 })).maxUses, 5);
  const above = await env.mint({ label: "l", purpose: "desktop-enrollment", email: "member@acme.test", maxUses: 6 });
  assert.equal(above.status, 400);
  assert.equal(above.body.error, "invalid_request");

  // Above the database range: clamped to 500.
  process.env.SELFHOST_ENROLLMENT_MAX_USES = "100000";
  assert.equal((await env.mintKey("member@acme.test", { maxUses: 500 })).maxUses, 500);
  const over = await env.mint({ label: "l", purpose: "desktop-enrollment", email: "member@acme.test", maxUses: 501 });
  assert.equal(over.status, 400);

  // Unparseable: the default.
  process.env.SELFHOST_ENROLLMENT_MAX_USES = "lots";
  assert.equal((await env.mintKey("member@acme.test", { maxUses: 50 })).maxUses, 50);
  assert.equal((await env.mint({
    label: "l", purpose: "desktop-enrollment", email: "member@acme.test", maxUses: 51,
  })).status, 400);
});

test("maxUses and policyConsent are refused on every other purpose", async (t) => {
  clearEnv(t);
  const env = await setup(t);
  for (const extra of [{ maxUses: 1 }, { maxUses: 3 }, { policyConsent: "admin" }]) {
    for (const purpose of ["deployment", "workflow"]) {
      const answer = await env.mint({ label: "ci", purpose, ...extra });
      assert.equal(answer.status, 400, `${purpose} ${JSON.stringify(extra)}`);
      assert.equal(answer.body.error, "invalid_request");
    }
  }
  // Absent, they are fine, and the list shows the neutral values.
  const plain = await env.mint({ label: "ci", purpose: "deployment" });
  assert.equal(plain.status, 201);
  const row = await env.keyRow(plain.body.id);
  assert.equal(row.maxUses, 1);
  assert.equal(row.useCount, 0);
  assert.equal(row.policyConsent, null);
  // The database holds the same line.
  await assert.rejects(env.database.query(
    "UPDATE workspace_api_tokens SET max_uses = 2 WHERE id = $1", [plain.body.id],
  ));
  await assert.rejects(env.database.query(
    "UPDATE workspace_api_tokens SET policy_consent = 'admin' WHERE id = $1", [plain.body.id],
  ));
});

test("expiry: single-use ceiling 30 days, multi-use 90, both env overridable", async (t) => {
  clearEnv(t);
  const env = await setup(t);
  await env.addMember("member@acme.test");
  const mintWith = (extra: Record<string, unknown>) =>
    env.mint({ label: "l", purpose: "desktop-enrollment", email: "member@acme.test", ...extra });

  assert.equal(expiryDays(await env.mintKey("member@acme.test")), 7, "single-use default");
  assert.equal(expiryDays(await env.mintKey("member@acme.test", { maxUses: 2 })), 7, "multi-use default");
  assert.equal(expiryDays(await env.mintKey("member@acme.test", { expiryDays: 30 })), 30);
  const single31 = await mintWith({ expiryDays: 31 });
  assert.equal(single31.status, 400);
  assert.equal(single31.body.error, "invalid_request");
  assert.equal(expiryDays(await env.mintKey("member@acme.test", { maxUses: 2, expiryDays: 90 })), 90);
  const multi91 = await mintWith({ maxUses: 2, expiryDays: 91 });
  assert.equal(multi91.status, 400);
  assert.equal(multi91.body.error, "invalid_request");
  assert.equal((await mintWith({ neverExpires: true, maxUses: 2 })).status, 400);

  withEnv(t, "SELFHOST_ENROLLMENT_MAX_DAYS", "10");
  withEnv(t, "SELFHOST_ENROLLMENT_MULTI_USE_MAX_DAYS", "120");
  assert.equal(expiryDays(await env.mintKey("member@acme.test", { expiryDays: 10 })), 10);
  assert.equal((await mintWith({ expiryDays: 11 })).status, 400);
  assert.equal(expiryDays(await env.mintKey("member@acme.test", { maxUses: 2, expiryDays: 120 })), 120);
  assert.equal((await mintWith({ maxUses: 2, expiryDays: 121 })).status, 400);

  // A ceiling below the 7-day default lowers the default too.
  process.env.SELFHOST_ENROLLMENT_MAX_DAYS = "3";
  assert.equal(expiryDays(await env.mintKey("member@acme.test")), 3);
  assert.equal((await mintWith({ expiryDays: 4 })).status, 400);
  // The self-mint ceiling is defined but does not touch admin mints.
  process.env.SELFHOST_ENROLLMENT_MAX_DAYS = "30";
  withEnv(t, "SELFHOST_ENROLLMENT_SELF_MINT_MAX_DAYS", "1");
  assert.equal(expiryDays(await env.mintKey("member@acme.test", { expiryDays: 30 })), 30);
});

test("policyConsent: \"admin\" accepted and listed, anything else refused", async (t) => {
  clearEnv(t);
  const env = await setup(t);
  await env.addMember("member@acme.test");
  const key = await env.mintKey("member@acme.test", { policyConsent: "admin", maxUses: 2 });
  assert.equal(key.policyConsent, "admin");
  assert.equal((await env.keyRow(key.id)).policyConsent, "admin");
  const created = (await env.audit()).find((event) => event.action === "api_token.create" && event.target?.startsWith(key.id));
  assert.ok(created);
  assert.match(created.target ?? "", / maxUses=2 policyConsent=admin\)$/);
  for (const bad of ["Admin", "user", "", true, 1, ["admin"], { admin: true }]) {
    const answer = await env.mint({ label: "l", purpose: "desktop-enrollment", email: "member@acme.test", policyConsent: bad });
    assert.equal(answer.status, 400, `policyConsent ${JSON.stringify(bad)}`);
    assert.equal(answer.body.error, "invalid_request");
  }
  // Explicit null is the same as absent.
  assert.equal((await env.mintKey("member@acme.test", { policyConsent: null })).policyConsent, null);
});

test("managed: access/me, exchange response and introspection follow the key's policy consent", async (t) => {
  clearEnv(t);
  const env = await setup(t);
  const memberId = await env.addMember("member@acme.test");
  const consenting = await env.mintKey("member@acme.test", { policyConsent: "admin", maxUses: 2 });
  const plain = await env.mintKey("member@acme.test");

  const managedExchange = await env.exchange(consenting.accessToken);
  assert.equal(managedExchange.status, 200);
  assert.equal(managedExchange.body.managed, true);
  assert.equal(managedExchange.body.policy_revision, 1);
  assert.equal(managedExchange.body.workspace_policy.managed, true);
  assert.equal(managedExchange.body.workspace_policy.revision, 1);
  assert.equal(managedExchange.body.workspace_policy.version, 2);
  const plainExchange = await env.exchange(plain.accessToken, { desktop_host_name: "build-02" });
  assert.equal(plainExchange.status, 200);
  assert.equal(plainExchange.body.managed, false);
  assert.equal(plainExchange.body.policy_revision, 1);
  assert.equal(plainExchange.body.workspace_policy.managed, false);
  const deviceFlow = await env.deviceToken(memberId);

  const cases = [
    [managedExchange.body.access_token as string, true, "consenting key"],
    [plainExchange.body.access_token as string, false, "plain key"],
    [deviceFlow, false, "device flow"],
  ] as const;
  for (const [token, managed, label] of cases) {
    const me = await env.accessMe(token);
    assert.equal(me.status, 200, label);
    assert.equal(me.body.workspace_policy.managed, managed, label);
    assert.ok(Array.isArray(me.body.workspace_policy.consent), label);
    assert.deepEqual(me.body.workspace_policy.consent, [], label);
    const verdict = await env.introspect(token);
    assert.equal(verdict.status, 200, label);
    assert.equal(verdict.body.active, true, label);
    assert.equal(verdict.body.managed, managed, label);
    assert.deepEqual(verdict.body.workspace_policy, { revision: 1 }, label);
  }

  // A refresh keeps the provisioning link, so the session stays managed.
  const refreshed = await request(env.origin, "/api/v1/auth/token/refresh", {
    method: "POST",
    body: { refreshToken: managedExchange.body.refresh_token },
  });
  assert.equal(refreshed.status, 200, refreshed.raw);
  assert.equal((await env.accessMe(refreshed.body.accessToken)).body.workspace_policy.managed, true);
  assert.equal((await env.introspect(refreshed.body.accessToken)).body.managed, true);

  // policy_revision follows the organization's workspace policy.
  const put = await request(env.origin, `/api/v1/organizations/${env.organizationId}/workspace-policy`, {
    method: "PUT",
    token: BOOTSTRAP,
    body: { sections: { spawn: { locked: { accept_spawns: false } } } },
  });
  assert.equal(put.status, 200, put.raw);
  const second = await env.exchange(consenting.accessToken, { desktop_host_name: "build-03" });
  assert.equal(second.status, 200);
  assert.equal(second.body.managed, true);
  assert.equal(second.body.policy_revision, 2);
  assert.equal(second.body.workspace_policy.revision, 2);
  // The owner's own device session is not managed either.
  assert.equal((await env.accessMe(env.owner)).body.workspace_policy.managed, false);
});

test("exchange audit: host, use count and Desktop client version", async (t) => {
  clearEnv(t);
  const env = await setup(t);
  const memberId = await env.addMember("member@acme.test");
  const key = await env.mintKey("member@acme.test", { maxUses: 3 });
  const exchangeAs = (host: string, userAgent?: string) =>
    request(env.origin, EXCHANGE, {
      method: "POST",
      body: { enrollment_key: key.accessToken, client_name: "Agent Relay Desktop", desktop_host_name: host },
      ...(userAgent ? { headers: { "user-agent": userAgent } } : {}),
    });
  assert.equal((await exchangeAs("laptop-a", "AgentRelayDesktop/1.2.3")).status, 200);
  assert.equal((await exchangeAs("laptop-b", "AgentRelayDesktop/2.0.0-beta.1 (darwin; arm64)")).status, 200);
  assert.equal((await exchangeAs("laptop-c", "Mozilla/5.0 AgentRelayDesktop/9.9.9")).status, 200);

  const events = (await env.audit()).filter((event) => event.action === "enrollment_key.exchange");
  assert.equal(events.length, 3);
  for (const event of events) {
    assert.equal(event.actorKind, "user");
    assert.equal(event.actorId, memberId);
  }
  const targets = events.map((event) => event.target ?? "").sort();
  const at = (host: string) => targets.find((target) => target.includes(` host=${host} `))!;
  assert.match(at("laptop-a"), new RegExp(`^${key.id} ip=\\S+ host=laptop-a use=1/3 client=1\\.2\\.3$`));
  assert.match(at("laptop-b"), new RegExp(`^${key.id} ip=\\S+ host=laptop-b use=2/3 client=2\\.0\\.0-beta\\.1$`));
  // Only a leading AgentRelayDesktop/<version> counts.
  assert.match(at("laptop-c"), new RegExp(`^${key.id} ip=\\S+ host=laptop-c use=3/3 client=unknown$`));
  const secret = key.accessToken.slice("sh_ek_".length);
  assert.equal(JSON.stringify(events).includes(secret), false, "the key never reaches the audit");
});
