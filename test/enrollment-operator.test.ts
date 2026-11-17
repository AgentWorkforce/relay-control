import assert from "node:assert/strict";
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
 * Enrollment operator tokens (docs/identity.md, "Desktop enrollment keys"):
 * an owner/admin mints one sh_wk_ token of purpose enrollment-operator; an
 * MDM script presents it to mint, list and revoke its own desktop-enrollment
 * keys, and to nothing else.
 */

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const SERVICE = "internal-service-token-that-is-at-least-32-bytes";
const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const HISTORY = "https://history.selfhosted.test";
const DEVICE_SCOPES = ["cli:auth", "rth:read", "rth:sync", "rth:acquire"];
const EXCHANGE = "/api/v1/auth/enrollment/token";

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
  const newWorkspace = async (name: string) => {
    const created = await request(origin, `/api/v1/organizations/${organizationId}/workspaces`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { name, relaycastApiKey: `rk_${name}` },
    });
    assert.equal(created.status, 201);
    return created.body.id as string;
  };
  const workspaceId = await newWorkspace("primary");
  const base = `/api/v1/workspaces/${workspaceId}/deployment-api-tokens`;

  const started = await request(origin, "/api/v1/auth/device/start", { method: "POST", body: {} });
  const approved = await request(origin, "/api/v1/auth/device/approve", {
    method: "POST",
    token: BOOTSTRAP,
    body: { action: "approve", user_code: started.body.user_code, user_id: ownerId, workspace_id: workspaceId },
  });
  assert.equal(approved.status, 200);
  const issued = await request(origin, "/api/v1/auth/device/token", {
    method: "POST",
    body: { device_code: started.body.device_code },
  });
  assert.equal(issued.status, 200);
  const owner = issued.body.access_token as string;

  const mintOperator = async (label = "mdm rollout") => {
    const answer = await request(origin, base, {
      method: "POST",
      token: owner,
      body: { label, purpose: "enrollment-operator" },
    });
    assert.equal(answer.status, 201, `mint operator: ${answer.status} ${answer.body?.error ?? ""}`);
    return answer.body as { id: string; accessToken: string } & Record<string, any>;
  };
  const operatorMint = (operator: string, body: Record<string, unknown>, path = base) =>
    request(origin, path, { method: "POST", token: operator, body });
  const operatorKey = async (operator: string, email: string, extra: Record<string, unknown> = {}) => {
    const answer = await operatorMint(operator, { label: "fleet", purpose: "desktop-enrollment", email, ...extra });
    assert.equal(answer.status, 201, `operator mint ${email}: ${answer.status} ${answer.body?.error ?? ""}`);
    return answer.body as { id: string; accessToken: string } & Record<string, any>;
  };
  const exchange = (key: unknown) =>
    request(origin, EXCHANGE, {
      method: "POST",
      body: { enrollment_key: key, client_name: "Agent Relay Desktop", desktop_host_name: "build-01" },
    });
  const audit = async () => {
    const listed = await request(origin, `/api/v1/workspaces/${workspaceId}/admin/audit`, { token: owner });
    assert.equal(listed.status, 200);
    return listed.body.events as Array<{ actorKind: string; actorId: string | null; action: string; target: string | null }>;
  };
  return {
    database, origin, organizationId, ownerId, workspaceId, base, owner,
    newWorkspace, mintOperator, operatorMint, operatorKey, exchange, audit,
  };
}

test("owner mints an enrollment-operator token: sh_wk_, enrollment:mint only, never forever", async (t) => {
  const env = await setup(t);
  const operator = await env.mintOperator();
  assert.match(operator.accessToken, /^sh_wk_/);
  assert.equal(operator.purpose, "enrollment-operator");
  assert.deepEqual(operator.scopes, ["enrollment:mint"]);
  assert.equal(operator.agent_name, null);
  assert.equal(operator.aud, null);
  assert.equal(operator.userId, null);
  assert.equal(operator.mintedByTokenId, null);
  assert.equal(operator.createdBy.id, env.ownerId);
  assert.ok(operator.accessTokenExpiresAt, "expires by default");

  const forever = await request(env.origin, env.base, {
    method: "POST",
    token: env.owner,
    body: { label: "forever", purpose: "enrollment-operator", neverExpires: true },
  });
  assert.equal(forever.status, 400);
  const withEmail = await request(env.origin, env.base, {
    method: "POST",
    token: env.owner,
    body: { label: "x", purpose: "enrollment-operator", email: "member@acme.test" },
  });
  assert.equal(withEmail.status, 400);
});

test("operator mints a key without a device sign-in; the key exchanges for a normal device session", async (t) => {
  const env = await setup(t);
  const operator = await env.mintOperator();
  const key = await env.operatorKey(operator.accessToken, "new.hire@acme.test", { mcpConsent: "admin" });
  assert.match(key.accessToken, /^sh_ek_/);
  assert.equal(key.purpose, "desktop-enrollment");
  assert.equal(key.mintedByTokenId, operator.id);
  assert.equal(key.createdBy, null, "no user minted it");
  assert.equal(key.mcpConsent, "admin");
  assert.equal(key.userEmail, "new.hire@acme.test");

  const exchanged = await env.exchange(key.accessToken);
  assert.equal(exchanged.status, 200);
  assert.deepEqual(exchanged.body.scope.split(" ").sort(), [...DEVICE_SCOPES].sort());
  const whoami = await request(env.origin, "/api/v1/auth/whoami", { token: exchanged.body.access_token });
  assert.equal(whoami.status, 200);
  assert.equal(whoami.body.provisioning.keyId, key.id);
  assert.equal(whoami.body.provisioning.mintedBy, null);

  // The owner still sees and can revoke it.
  const listed = await request(env.origin, `${env.base}?purpose=desktop-enrollment`, { token: env.owner });
  const row = listed.body.tokens.find((token: { id: string }) => token.id === key.id);
  assert.equal(row.mintedByTokenId, operator.id);
  assert.equal(row.status, "exchanged");
  assert.equal((await request(env.origin, `${env.base}/${key.id}`, { method: "DELETE", token: env.owner })).status, 204);
  assert.equal((await request(env.origin, "/api/v1/auth/whoami", { token: exchanged.body.access_token })).status, 401);
});

test("operator mint refuses every purpose but desktop-enrollment", async (t) => {
  const env = await setup(t);
  const operator = await env.mintOperator();
  const count = async () =>
    Number((await env.database.query<{ n: string }>("SELECT count(*) AS n FROM workspace_api_tokens")).rows[0]!.n);
  const before = await count();
  for (const purpose of [undefined, "deployment", "workflow", "agent-runtime", "relay-node", "enrollment-operator", "bogus"]) {
    const answer = await env.operatorMint(operator.accessToken, { label: "nope", purpose, nodeName: "n1" });
    assert.equal(answer.status, 403, String(purpose));
    assert.equal(answer.body.error, "enrollment_operator_scope", String(purpose));
  }
  assert.equal(await count(), before, "nothing was minted");
});

test("operator list: only its own keys, and only with ?purpose=desktop-enrollment", async (t) => {
  const env = await setup(t);
  const operator = await env.mintOperator();
  const other = await env.mintOperator("second mdm");
  const mine = await env.operatorKey(operator.accessToken, "a@acme.test");
  await env.operatorKey(other.accessToken, "b@acme.test");
  const ownerKey = await request(env.origin, env.base, {
    method: "POST",
    token: env.owner,
    body: { label: "by hand", purpose: "desktop-enrollment", email: "c@acme.test" },
  });
  assert.equal(ownerKey.status, 201);

  const listed = await request(env.origin, `${env.base}?purpose=desktop-enrollment`, { token: operator.accessToken });
  assert.equal(listed.status, 200);
  assert.deepEqual(listed.body.tokens.map((token: { id: string }) => token.id), [mine.id]);
  assert.equal("accessToken" in listed.body.tokens[0], false);

  for (const query of ["", "?purpose=deployment", "?purpose=enrollment-operator", "?purpose=bogus"]) {
    const refused = await request(env.origin, `${env.base}${query}`, { token: operator.accessToken });
    assert.equal(refused.status, 403, query);
    assert.equal(refused.body.error, "enrollment_operator_scope", query);
  }
});

test("operator revoke: its own key (with the sessions), any other id is 404", async (t) => {
  const env = await setup(t);
  const operator = await env.mintOperator();
  const other = await env.mintOperator("second mdm");
  const mine = await env.operatorKey(operator.accessToken, "a@acme.test");
  const theirs = await env.operatorKey(other.accessToken, "b@acme.test");
  const ownerKey = await request(env.origin, env.base, {
    method: "POST",
    token: env.owner,
    body: { label: "by hand", purpose: "desktop-enrollment", email: "c@acme.test" },
  });
  const session = (await env.exchange(mine.accessToken)).body.access_token as string;
  const live = async () =>
    (await env.database.query("SELECT 1 FROM workspace_api_tokens WHERE revoked_at IS NULL")).rows.length;
  const liveBefore = await live();

  const revoke = (id: string) =>
    request(env.origin, `${env.base}/${id}`, { method: "DELETE", token: operator.accessToken });
  for (const id of [theirs.id, ownerKey.body.id, other.id, operator.id, "not-a-uuid"]) {
    const refused = await revoke(id);
    assert.equal(refused.status, 404, id);
    assert.equal(refused.body.error, "token_not_found", id);
  }
  assert.equal(await live(), liveBefore, "nothing was revoked");

  assert.equal((await revoke(mine.id)).status, 204);
  assert.equal((await request(env.origin, "/api/v1/auth/whoami", { token: session })).status, 401);
  assert.equal((await revoke(mine.id)).status, 404, "already revoked");
  const listed = await request(env.origin, `${env.base}?purpose=desktop-enrollment`, { token: operator.accessToken });
  assert.equal(listed.body.tokens[0].status, "revoked");
});

test("the operator token is no other credential: admin and runtime routes 401, introspection wrong-kind", async (t) => {
  const env = await setup(t);
  const operator = await env.mintOperator();
  const token = operator.accessToken;
  const ws = `/api/v1/workspaces/${env.workspaceId}`;
  for (const [method, path] of [
    ["GET", `${ws}/admin/audit`],
    ["GET", `${ws}/secrets`],
    ["GET", `${ws}/integrations`],
    ["GET", `/api/v1/organizations/${env.organizationId}/memberships`],
    ["PATCH", `/api/v1/organizations/${env.organizationId}`],
    ["GET", "/api/v1/auth/whoami"],
    ["GET", "/api/v1/me/enrollment-keys"],
  ] as const) {
    const answer = await request(env.origin, path, { method, token, ...(method === "PATCH" ? { body: { name: "x" } } : {}) });
    assert.equal(answer.status, 401, `${method} ${path}`);
  }
  const runtime = await request(env.origin, `/internal/v1/workspaces/${env.workspaceId}/environment`, { token });
  assert.equal(runtime.status, 401);

  const verdict = await request(env.origin, "/internal/v1/auth/introspect", {
    method: "POST",
    token: INTROSPECT_SECRET,
    body: { token, aud: HISTORY, workspace: env.workspaceId },
  });
  assert.equal(verdict.status, 200);
  assert.deepEqual(verdict.body, { active: false, reason: "wrong-kind" });

  // Other sh_wk_ purposes still get the plain 401 on the token routes.
  const deployment = await request(env.origin, env.base, {
    method: "POST",
    token: env.owner,
    body: { label: "ci", purpose: "deployment" },
  });
  assert.equal(deployment.status, 201);
  const ci = deployment.body.accessToken as string;
  assert.equal((await request(env.origin, `${env.base}?purpose=desktop-enrollment`, { token: ci })).status, 401);
  assert.equal((await env.operatorMint(ci, { label: "x", purpose: "desktop-enrollment", email: "a@acme.test" })).status, 401);
  assert.equal((await request(env.origin, `${env.base}/${deployment.body.id}`, { method: "DELETE", token: ci })).status, 401);
});

test("revoked, expired and other-workspace operator tokens are 401", async (t) => {
  const env = await setup(t);
  const body = { label: "fleet", purpose: "desktop-enrollment", email: "a@acme.test" };

  const otherWorkspace = await env.newWorkspace("secondary");
  const otherBase = `/api/v1/workspaces/${otherWorkspace}/deployment-api-tokens`;
  // The owner's device session is bound to the primary workspace, so the
  // other workspace's operator token is minted through the store.
  const foreign = await new ApiTokenStore(env.database).create({
    workspaceId: otherWorkspace,
    organizationId: env.organizationId,
    label: "secondary mdm",
    purpose: "enrollment-operator",
    expiryDays: undefined,
    neverExpires: undefined,
    actor: { kind: "user", userId: env.ownerId },
  });
  const wrong = await env.operatorMint(foreign.accessToken, body);
  assert.equal(wrong.status, 401, "another workspace's operator");
  assert.equal(
    (await request(env.origin, `${env.base}?purpose=desktop-enrollment`, { token: foreign.accessToken })).status,
    401,
  );
  assert.equal((await env.operatorMint(foreign.accessToken, body, otherBase)).status, 201, "its own workspace");

  const revoked = await env.mintOperator();
  assert.equal((await env.operatorMint(revoked.accessToken, body)).status, 201);
  assert.equal((await request(env.origin, `${env.base}/${revoked.id}`, { method: "DELETE", token: env.owner })).status, 204);
  assert.equal((await env.operatorMint(revoked.accessToken, body)).status, 401);
  assert.equal(
    (await request(env.origin, `${env.base}?purpose=desktop-enrollment`, { token: revoked.accessToken })).status,
    401,
  );

  const expired = await env.mintOperator();
  await env.database.query(
    "UPDATE workspace_api_tokens SET expires_at = now() - interval '1 minute' WHERE id = $1",
    [expired.id],
  );
  assert.equal((await env.operatorMint(expired.accessToken, body)).status, 401);
});

test("audit: operator actions carry the token actor", async (t) => {
  const env = await setup(t);
  const operator = await env.mintOperator();
  const key = await env.operatorKey(operator.accessToken, "new.hire@acme.test");
  assert.equal(
    (await request(env.origin, `${env.base}/${key.id}`, { method: "DELETE", token: operator.accessToken })).status,
    204,
  );
  const events = await env.audit();
  const byAction = (action: string) => events.find((event) => event.action === action && event.target?.includes(key.userId));
  const created = byAction("api_token.create")!;
  assert.equal(created.actorKind, "token");
  assert.equal(created.actorId, operator.id);
  assert.equal(created.target, `${key.id} (desktop-enrollment: user ${key.userId})`);
  const provision = byAction("membership.provision")!;
  assert.equal(provision.actorKind, "token");
  assert.equal(provision.actorId, operator.id);
  const revoked = byAction("api_token.revoke")!;
  assert.equal(revoked.actorKind, "token");
  assert.equal(revoked.actorId, operator.id);
  assert.equal(revoked.target, `${key.id} (desktop-enrollment: user ${key.userId}) sessions=0`);
  const operatorCreated = events.find((event) => event.action === "api_token.create" && event.target === `${operator.id} (enrollment-operator)`);
  assert.equal(operatorCreated?.actorKind, "user");
  assert.equal(operatorCreated?.actorId, env.ownerId);
});
