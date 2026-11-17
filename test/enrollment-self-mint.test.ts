import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { MAX_UNEXCHANGED_ENROLLMENT_KEYS, SELF_MINTED_ENROLLMENT_KEY_LABEL } from "../src/admin/api-tokens.js";
import { createAdminModule } from "../src/admin/routes.js";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";
import { call, registerVerified, sessionCookie, setup as passwordSetup } from "./support/password.js";

/**
 * Member self-mint of desktop enrollment keys (docs/identity.md, "Member
 * self-mint"): POST /api/v1/me/enrollment-keys mints a single-use key for the
 * caller's own next machine. Consent is inherited from the key that
 * provisioned the calling session and never raised; at most
 * MAX_UNEXCHANGED_ENROLLMENT_KEYS unexchanged keys per person;
 * SELFHOST_ENROLLMENT_SELF_RENEWAL=false turns the route off. Same harness
 * as enrollment-key-uses.test.ts.
 */

const SELF_MINT = "/api/v1/me/enrollment-keys";
const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const SERVICE = "internal-service-token-that-is-at-least-32-bytes";
const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const HISTORY = "https://history.selfhosted.test";
const EXCHANGE = "/api/v1/auth/enrollment/token";
const DAY_MS = 24 * 60 * 60 * 1000;

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");

async function setup(t: TestContext, overrides: Partial<SelfhostConfig> = {}) {
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
    ...overrides,
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
  const selfMint = (token: string, body: Record<string, unknown> = {}) =>
    request(origin, SELF_MINT, { method: "POST", token, body });
  return {
    selfMint,
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

/** A member signed in on Desktop from an admin-minted key; returns the session token. */
async function enrolledMember(env: Awaited<ReturnType<typeof setup>>, extra: Record<string, unknown> = {}) {
  const userId = await env.addMember("member@acme.test");
  const key = await env.mintKey("member@acme.test", extra);
  const exchanged = await env.exchange(key.accessToken);
  assert.equal(exchanged.status, 200);
  return { userId, key, token: exchanged.body.access_token as string };
}

test("self-mint: 201 admin-mint shape, single use, own user, inherits admin/admin consent", async (t) => {
  clearEnv(t);
  const env = await setup(t);
  const { userId, key: source, token } = await enrolledMember(env, { mcpConsent: "admin", policyConsent: "admin" });

  const minted = await env.selfMint(token, { label: "new laptop" });
  assert.equal(minted.status, 201, minted.body?.error);
  assert.equal(minted.headers.get("cache-control"), "no-store");
  assert.match(minted.body.accessToken, /^sh_ek_/);
  assert.equal(minted.body.purpose, "desktop-enrollment");
  assert.equal(minted.body.label, "new laptop");
  assert.equal(minted.body.maxUses, 1);
  assert.equal(minted.body.useCount, 0);
  assert.equal(minted.body.mcpConsent, "admin");
  assert.equal(minted.body.policyConsent, "admin");
  assert.equal(minted.body.userId, userId);
  assert.equal(minted.body.userEmail, "member@acme.test");
  assert.equal(expiryDays(minted.body), 7, "defaults to the self-mint ceiling");

  // The admin list shows it as the member's own key.
  const row = await env.keyRow(minted.body.id);
  assert.equal(row.maxUses, 1);
  assert.equal(row.status, "active");

  // Audited as enrollment_key.self_mint by the member, naming the source key.
  const event = (await env.audit()).find((entry) => entry.action === "enrollment_key.self_mint");
  assert.ok(event, "enrollment_key.self_mint recorded");
  assert.equal(event.actorKind, "user");
  assert.equal(event.actorId, userId);
  assert.equal(
    event.target,
    `${minted.body.id} (desktop-enrollment: user ${userId} mcpConsent=admin policyConsent=admin from=${source.id})`,
  );

  // It exchanges once, for the same person, and the new session can self-mint in turn.
  const exchanged = await env.exchange(minted.body.accessToken, { desktop_host_name: "laptop-2" });
  assert.equal(exchanged.status, 200);
  const session = (await env.session(exchanged.body.access_token))!;
  assert.equal(session.user_id, userId);
  assert.equal(session.provisioned_by_token_id, minted.body.id);
  assert.equal((await env.exchange(minted.body.accessToken, { desktop_host_name: "laptop-3" })).status, 400);
  const next = await env.selfMint(exchanged.body.access_token);
  assert.equal(next.status, 201);
  assert.equal(next.body.label, SELF_MINTED_ENROLLMENT_KEY_LABEL);
  assert.equal(next.body.mcpConsent, "admin");
  assert.equal(next.body.policyConsent, "admin");

  // GET lists the self-minted keys beside the admin-minted one.
  const listed = await request(env.origin, SELF_MINT, { token });
  assert.equal(listed.status, 200);
  const mine = listed.body.keys.find((entry: { id: string }) => entry.id === minted.body.id);
  assert.equal(mine.maxUses, 1);
  assert.equal(mine.useCount, 1);
  assert.equal(mine.policyConsent, "admin");
  assert.equal(mine.mintedBy.id, userId);
});

test("self-mint: consent is never raised; only label and expiryDays are accepted", async (t) => {
  clearEnv(t);
  const env = await setup(t);
  const { token } = await enrolledMember(env);

  for (const body of [
    { mcpConsent: "admin" },
    { policyConsent: "admin" },
    { maxUses: 1 },
    { email: "owner@acme.test" },
    { purpose: "desktop-enrollment" },
    { label: "x", workspaceId: env.workspaceId },
  ]) {
    const refused = await env.selfMint(token, body);
    assert.equal(refused.status, 400, JSON.stringify(body));
    assert.equal(refused.body.error, "invalid_request", JSON.stringify(body));
  }
  for (const label of ["", 7, "x".repeat(129)]) {
    const refused = await env.selfMint(token, { label });
    assert.equal(refused.status, 400, JSON.stringify(label));
    assert.equal(refused.body.error, "invalid_request");
  }

  const minted = await env.selfMint(token);
  assert.equal(minted.status, 201);
  assert.equal(minted.body.mcpConsent, null);
  assert.equal(minted.body.policyConsent, null);
  const event = (await env.audit()).find((entry) => entry.action === "enrollment_key.self_mint");
  assert.doesNotMatch(event?.target ?? "", /Consent=/);
});

test("self-mint: mcpConsent-only key passes on mcpConsent alone", async (t) => {
  clearEnv(t);
  const env = await setup(t);
  const { token } = await enrolledMember(env, { mcpConsent: "admin" });
  const minted = await env.selfMint(token);
  assert.equal(minted.status, 201);
  assert.equal(minted.body.mcpConsent, "admin");
  assert.equal(minted.body.policyConsent, null);
});

test("self-mint: a session not provisioned by a key (device flow) yields no consent", async (t) => {
  clearEnv(t);
  const env = await setup(t);
  const memberId = await env.addMember("member@acme.test");
  const token = await env.deviceToken(memberId);
  const minted = await env.selfMint(token);
  assert.equal(minted.status, 201);
  assert.equal(minted.body.mcpConsent, null);
  assert.equal(minted.body.policyConsent, null);
  assert.equal(minted.body.maxUses, 1);
  const exchanged = await env.exchange(minted.body.accessToken);
  assert.equal(exchanged.status, 200);
  assert.equal((await env.session(exchanged.body.access_token))!.user_id, memberId);
  const event = (await env.audit()).find((entry) => entry.action === "enrollment_key.self_mint");
  assert.equal(event?.target, `${minted.body.id} (desktop-enrollment: user ${memberId})`);
});

test("self-mint: expiryDays defaults to and is capped at the self-mint ceiling", async (t) => {
  clearEnv(t);
  const env = await setup(t);
  const { token } = await enrolledMember(env);

  assert.equal(expiryDays((await env.selfMint(token)).body), 7);
  assert.equal(expiryDays((await env.selfMint(token, { expiryDays: 2 })).body), 2);
  for (const bad of [8, 0, -1, 1.5, "3"]) {
    const refused = await env.selfMint(token, { expiryDays: bad });
    assert.equal(refused.status, 400, JSON.stringify(bad));
    assert.equal(refused.body.error, "invalid_request");
  }

  withEnv(t, "SELFHOST_ENROLLMENT_SELF_MINT_MAX_DAYS", "3");
  assert.equal(expiryDays((await env.selfMint(token)).body), 3);
  assert.equal((await env.selfMint(token, { expiryDays: 4 })).status, 400);
});

test("self-mint: a lower SELFHOST_ENROLLMENT_MAX_DAYS caps the self-mint ceiling too", async (t) => {
  clearEnv(t);
  const env = await setup(t);
  const { token } = await enrolledMember(env);
  withEnv(t, "SELFHOST_ENROLLMENT_MAX_DAYS", "2");
  assert.equal(expiryDays((await env.selfMint(token)).body), 2);
  assert.equal((await env.selfMint(token, { expiryDays: 3 })).status, 400);
});

test("self-mint: the sixth unexchanged key is 409 self_mint_limit until one is used or revoked", async (t) => {
  clearEnv(t);
  const env = await setup(t);
  const { token } = await enrolledMember(env);
  // The exchanged source key does not count; admin-minted keys do.
  for (let index = 0; index < MAX_UNEXCHANGED_ENROLLMENT_KEYS - 1; index += 1) {
    await env.mintKey("member@acme.test");
  }
  const fifth = await env.selfMint(token);
  assert.equal(fifth.status, 201);

  const sixth = await env.selfMint(token);
  assert.equal(sixth.status, 409);
  assert.equal(sixth.body.error, "self_mint_limit");
  assert.equal(
    (await env.audit()).filter((entry) => entry.action === "enrollment_key.self_mint").length,
    1,
    "the refused mint is not audited",
  );
  // The cap is on self-mint only: an admin can still mint.
  await env.mintKey("member@acme.test");

  // Revoking one is not enough while six are held; revoking two frees one slot.
  const revoke = (id: string) => request(env.origin, `${SELF_MINT}/${id}`, { method: "DELETE", token });
  const extra = (await request(env.origin, SELF_MINT, { token })).body.keys
    .filter((entry: { status: string }) => entry.status === "active")
    .map((entry: { id: string }) => entry.id) as string[];
  assert.equal(extra.length, MAX_UNEXCHANGED_ENROLLMENT_KEYS + 1);
  assert.equal((await revoke(extra[0]!)).status, 204);
  assert.equal((await env.selfMint(token)).status, 409);
  assert.equal((await revoke(extra[1]!)).status, 204);
  const afterRevoke = await env.selfMint(token);
  assert.equal(afterRevoke.status, 201);
  assert.equal((await env.selfMint(token)).status, 409);

  // Exchanging one also frees a slot.
  assert.equal((await env.exchange(afterRevoke.body.accessToken, { desktop_host_name: "laptop-2" })).status, 200);
  assert.equal((await env.selfMint(token)).status, 201);

  // Another person is not affected by this person's keys.
  const otherId = await env.addMember("other@acme.test");
  assert.equal((await env.selfMint(await env.deviceToken(otherId))).status, 201);
});

test("self-mint: 10 per hour per person, then 429 rate_limited", async (t) => {
  clearEnv(t);
  const env = await setup(t);
  const { token } = await enrolledMember(env);
  // Exchange each key so the unexchanged cap never applies.
  for (let index = 0; index < 10; index += 1) {
    const minted = await env.selfMint(token);
    assert.equal(minted.status, 201, `mint ${index + 1}`);
    assert.equal((await env.exchange(minted.body.accessToken, { desktop_host_name: `host-${index}` })).status, 200);
  }
  const limited = await env.selfMint(token);
  assert.equal(limited.status, 429);
  assert.equal(limited.body.error, "rate_limited");
});

test("self-mint: no token is 401; SELFHOST_ENROLLMENT_SELF_RENEWAL=false is 403 self_mint_disabled", async (t) => {
  clearEnv(t);
  const env = await setup(t, { enrollmentSelfRenewal: false });
  const { token } = await enrolledMember(env);
  assert.equal((await request(env.origin, SELF_MINT, { method: "POST", body: {} })).status, 401);

  const refused = await env.selfMint(token);
  assert.equal(refused.status, 403);
  assert.equal(refused.body.error, "self_mint_disabled");
  assert.equal((await env.audit()).some((entry) => entry.action === "enrollment_key.self_mint"), false);
  // Listing and revoking own keys stay available.
  assert.equal((await request(env.origin, SELF_MINT, { token })).status, 200);

  const capabilities = await request(env.origin, "/api/v1/capabilities", { token });
  assert.equal(capabilities.status, 200);
  assert.equal(capabilities.body.capabilities.enrollment_self_mint, false);
  assert.equal(capabilities.body.capabilities.enrollment_keys, true);
});

test("self-mint: capabilities report enrollment_self_mint true by default", async (t) => {
  clearEnv(t);
  const env = await setup(t);
  const { token } = await enrolledMember(env);
  const capabilities = await request(env.origin, "/api/v1/capabilities", { token });
  assert.equal(capabilities.body.capabilities.enrollment_self_mint, true);
});

test("self-mint: a member's browser account session mints through /cloud with a same-origin cookie", async (t) => {
  const ctx = await passwordSetup(t);
  const cookie = sessionCookie(await registerVerified(ctx, "member@acme.test"));
  assert.equal((await call(ctx.origin, "/api/v1/auth/login-config")).body.enrollment_self_mint, true);

  const crossSite = await call(ctx.origin, `/cloud${SELF_MINT}`, {
    cookie,
    json: {},
    originHeader: "https://evil.example",
  });
  assert.equal(crossSite.status, 403);
  assert.equal(crossSite.body.error, "csrf_rejected");

  const minted = await call(ctx.origin, `/cloud${SELF_MINT}`, { cookie, json: { label: "browser" } });
  assert.equal(minted.status, 201, minted.text);
  assert.equal(minted.body.maxUses, 1);
  assert.equal(minted.body.mcpConsent, null);
  assert.equal(minted.body.policyConsent, null);
  assert.match(minted.body.accessToken, /^sh_ek_/);
});

test("self-mint: login-config reports enrollment_self_mint false when the switch is off", async (t) => {
  const ctx = await passwordSetup(t, { enrollmentSelfRenewal: false });
  const config = await call(ctx.origin, "/api/v1/auth/login-config");
  assert.equal(config.status, 200);
  assert.equal(config.body.enrollment_self_mint, false);
  assert.equal(config.body.enrollment_keys, true);

  const cookie = sessionCookie(await registerVerified(ctx, "member@acme.test"));
  const refused = await call(ctx.origin, `/cloud${SELF_MINT}`, { cookie, json: {} });
  assert.equal(refused.status, 403);
  assert.equal(refused.body.error, "self_mint_disabled");
});
