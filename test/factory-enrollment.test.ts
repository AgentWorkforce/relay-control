import assert from "node:assert/strict";
import test from "node:test";
import { ApiTokenStore } from "../src/admin/api-tokens.js";
import { acceptedAudiences, introspect } from "../src/auth/introspect.js";
import { loadConfig, loadFactoryConfig } from "../src/config.js";
import { decryptSecret, hashSecret } from "../src/crypto.js";
import { cleanupWorkspaceFactory, createFactoryModule } from "../src/factory/routes.js";
import { ACQUISITION_DRAIN_MAX_MS } from "../src/factory/service.js";
import {
  assertNoSecrets,
  FACTORY_KEY,
  FACTORY_KEY_2,
  factoryPath,
  INTERNAL,
  PUBLIC_URL,
  removeMember,
  startFactoryEnv,
  type FactoryEnv,
} from "./factory-helpers.js";

const ACQUISITION = "https://acquisition.selfhosted.company";

const connectionPath = (env: FactoryEnv) => factoryPath(env.workspaceId, "/connection");
const rotatePath = (env: FactoryEnv) => factoryPath(env.workspaceId, "/connection/acquisition/rotate");
const revokePath = (env: FactoryEnv) => factoryPath(env.workspaceId, "/connection/acquisition/revoke");

async function connect(env: FactoryEnv, token = env.ownerToken, key = FACTORY_KEY) {
  const response = await env.api(connectionPath(env), { method: "PUT", token, body: { key } });
  assert.equal(response.status, 200, JSON.stringify(response.body));
  return response;
}

async function operators(env: FactoryEnv) {
  const result = await env.database.query<Record<string, any>>(
    "SELECT * FROM factory_acquisition_operators WHERE workspace_id = $1 ORDER BY created_at, id",
    [env.workspaceId],
  );
  return result.rows;
}

async function acquisitionTokens(env: FactoryEnv) {
  const result = await env.database.query<Record<string, any>>(
    "SELECT * FROM workspace_api_tokens WHERE workspace_id = $1 AND purpose = 'acquisition-operator' ORDER BY created_at, id",
    [env.workspaceId],
  );
  return result.rows;
}

async function auditActions(env: FactoryEnv) {
  const result = await env.database.query<{ action: string; target: string | null; actor_kind: string }>(
    "SELECT action, target, actor_kind FROM admin_audit_events WHERE workspace_id = $1 ORDER BY created_at, id",
    [env.workspaceId],
  );
  return result.rows;
}

/** Introspects the plaintext held in the row's envelope, as the acquisition service would. */
async function introspectRow(env: FactoryEnv, row: Record<string, any>, aud = ACQUISITION) {
  const token = decryptSecret(row.token_envelope, env.config.encryptionKeyring);
  assert.ok(token.startsWith("sh_wk_"));
  assert.equal(hashSecret(token), (await env.database.query<{ token_hash: string }>(
    "SELECT token_hash FROM workspace_api_tokens WHERE id = $1", [row.token_id],
  )).rows[0]!.token_hash);
  const apiTokens = new ApiTokenStore(env.database, () => acceptedAudiences(env.config));
  return { token, result: await introspect(env.config, env.store, { token, aud }, apiTokens) };
}

const workspaceToken = (env: FactoryEnv) => new ApiTokenStore(env.database).create({
  workspaceId: env.workspaceId,
  organizationId: env.organizationId,
  label: "ci",
  purpose: "agent-runtime",
  expiryDays: 1,
  neverExpires: undefined,
  actor: { kind: "user", userId: env.ownerId },
});

test("1+10: owner connect mints one never-expiring acquisition-operator token, enrols it and never returns it", async (t) => {
  const env = await startFactoryEnv(t, { acquisitionOrigin: ACQUISITION });
  const connected = await connect(env);

  const tokens = await acquisitionTokens(env);
  assert.equal(tokens.length, 1);
  const token = tokens[0]!;
  assert.equal(token.aud, ACQUISITION);
  assert.deepEqual(token.scopes, ["acquisition:operate"]);
  assert.equal(token.expires_at, null);
  assert.equal(token.revoked_at, null);
  assert.equal(token.label, "Factory acquisition operator");
  assert.equal(token.created_by_user_id, env.ownerId);

  const rows = await operators(env);
  assert.equal(rows.length, 1);
  const row = rows[0]!;
  assert.equal(row.state, "enrolled");
  assert.equal(row.token_id, token.id);
  assert.equal(row.acquisition_origin, ACQUISITION);
  assert.equal(row.control_origin, new URL(PUBLIC_URL).origin);
  assert.equal(row.organization_id, env.organizationId);
  assert.equal(row.created_by_user_id, env.ownerId);
  assert.equal(row.token_prefix, token.token_prefix);
  assert.equal(row.reason, null);

  assert.equal(connected.body.acquisition.state, "enrolled");
  assert.equal(connected.body.acquisition.token_prefix, token.token_prefix);
  assert.equal(typeof connected.body.acquisition.created_at, "string");

  const { token: plaintext, result } = await introspectRow(env, row);
  assert.ok(!row.token_envelope.includes(plaintext), "envelope is encrypted");
  const summary = await env.api(connectionPath(env), { token: env.ownerToken });
  for (const body of [connected.body, summary.body, env.logs]) {
    assert.ok(!JSON.stringify(body).includes(plaintext), "the token is never returned or logged");
    assertNoSecrets(env, body);
  }
  assert.deepEqual(summary.body.acquisition, connected.body.acquisition);

  // 10: what the acquisition service's verifier sees.
  assert.equal(result.active, true);
  if (result.active) {
    assert.equal(result.principal_type, "service");
    assert.ok(result.scopes.includes("acquisition:operate"));
    assert.equal(result.aud, ACQUISITION);
    assert.equal(result.workspace, env.workspaceId);
    assert.equal(result.org, env.organizationId);
  }
  const wrongAud = await introspectRow(env, row, "https://history.selfhosted.company");
  assert.deepEqual(wrongAud.result, { active: false, reason: "audience" });

  const audit = await auditActions(env);
  const create = audit.find((event) => event.action === "api_token.create");
  assert.equal(create?.target, `${token.id} (acquisition-operator -> ${ACQUISITION})`);
  const enrol = audit.find((event) => event.action === "factory.acquisition.enrol");
  assert.equal(enrol?.target, `${token.id} (acquisition-operator)`);
  assert.equal(enrol?.actor_kind, "user");
  assert.ok(!JSON.stringify(audit).includes(plaintext));
});

test("2-5: members, workspace and internal tokens, revoked sessions and cross-site cookies cannot enrol, rotate or revoke", async (t) => {
  const env = await startFactoryEnv(t, { acquisitionOrigin: ACQUISITION });

  // 2: a member is refused before anything is written.
  const member = await env.api(connectionPath(env), { method: "PUT", token: env.memberToken, body: { key: FACTORY_KEY } });
  assert.equal(member.status, 403);
  for (const path of [rotatePath(env), revokePath(env)]) {
    assert.equal((await env.api(path, { method: "POST", token: env.memberToken, body: {} })).status, 403);
  }
  assert.equal((await operators(env)).length, 0);
  assert.equal((await acquisitionTokens(env)).length, 0);

  // 3: service credentials are refused on all three writes.
  const { accessToken } = await workspaceToken(env);
  for (const token of [accessToken, INTERNAL]) {
    const put = await env.api(connectionPath(env), { method: "PUT", token, body: { key: FACTORY_KEY } });
    assert.equal(put.status, 403);
    assert.equal(put.body.error, "factory_workspace_token");
    for (const path of [rotatePath(env), revokePath(env)]) {
      const refused = await env.api(path, { method: "POST", token, body: {} });
      assert.equal(refused.status, 403);
      assert.equal(refused.body.error, "factory_workspace_token");
    }
  }

  // 5: a cookie write from a foreign origin is refused; same-site is accepted.
  const cookie = { cookie: `agent_relay_session=${encodeURIComponent(env.ownerToken)}`, "content-type": "application/json" };
  const foreign = await env.api(`/cloud${connectionPath(env)}`, {
    method: "PUT",
    headers: { ...cookie, origin: "https://evil.example" },
    raw: JSON.stringify({ key: FACTORY_KEY }),
  });
  assert.equal(foreign.status, 403);
  assert.equal(foreign.body.error, "csrf_rejected");
  for (const path of [rotatePath(env), revokePath(env)]) {
    const refused = await env.api(`/cloud${path}`, { method: "POST", headers: { ...cookie, origin: "https://evil.example" }, raw: "{}" });
    assert.equal(refused.status, 403);
    assert.equal(refused.body.error, "csrf_rejected");
  }
  assert.equal((await operators(env)).length, 0);
  const sameSite = await env.api(`/cloud${connectionPath(env)}`, {
    method: "PUT",
    headers: { ...cookie, origin: new URL(PUBLIC_URL).origin },
    raw: JSON.stringify({ key: FACTORY_KEY }),
  });
  assert.equal(sameSite.status, 200, JSON.stringify(sameSite.body));
  assert.equal((await operators(env)).length, 1);

  // 4: a revoked sh_at_ session is 401 everywhere.
  await env.database.query("UPDATE token_sessions SET revoked_at = now() WHERE access_token_hash = $1", [hashSecret(env.adminToken)]);
  assert.equal((await env.api(connectionPath(env), { method: "PUT", token: env.adminToken, body: { key: FACTORY_KEY } })).status, 401);
  for (const path of [rotatePath(env), revokePath(env)]) {
    assert.equal((await env.api(path, { method: "POST", token: env.adminToken, body: {} })).status, 401);
  }
  assert.equal((await operators(env)).length, 1);
  assert.equal((await acquisitionTokens(env)).length, 1);
});

test("6: with no acquisition origin connect works, mints nothing and reports unconfigured; the routes answer 409", async (t) => {
  const env = await startFactoryEnv(t);
  const connected = await connect(env);
  assert.deepEqual(connected.body.acquisition, { state: "unconfigured" });
  assert.equal((await acquisitionTokens(env)).length, 0);
  assert.equal((await operators(env)).length, 0);
  for (const path of [rotatePath(env), revokePath(env)]) {
    const refused = await env.api(path, { method: "POST", token: env.ownerToken, body: {} });
    assert.equal(refused.status, 409);
    assert.equal(refused.body.error, "acquisition_unconfigured");
  }
  assert.equal(env.module.worker.started, false);
});

test("7: config reads SELFHOST_ACQUISITION_ORIGIN only with Factory on and fails closed naming the variables", () => {
  const audiences = { introspectSecret: "i".repeat(32), introspectAudiences: ["https://history.selfhosted.company", ACQUISITION] };
  const on = { SELFHOST_FACTORY_ENABLED: "true", SELFHOST_ACQUISITION_ORIGIN: `${ACQUISITION}/` };
  assert.equal(loadFactoryConfig(on, audiences).acquisitionOrigin, ACQUISITION);
  assert.equal(loadFactoryConfig({ SELFHOST_FACTORY_ENABLED: "true" }, audiences).acquisitionOrigin, undefined);
  // Factory off: the origin is not read at all, even when it would be invalid.
  assert.equal(loadFactoryConfig({ SELFHOST_ACQUISITION_ORIGIN: "not a url" }, { introspectSecret: null, introspectAudiences: [] }).acquisitionOrigin, undefined);
  assert.throws(
    () => loadFactoryConfig(on, { introspectSecret: null, introspectAudiences: audiences.introspectAudiences }),
    /RELAYCONTROL_INTROSPECT_SECRET/,
  );
  assert.throws(
    () => loadFactoryConfig(on, { ...audiences, introspectAudiences: ["https://history.selfhosted.company"] }),
    (error: Error) => /SELFHOST_ACQUISITION_ORIGIN/.test(error.message) && /SELFHOST_INTROSPECT_AUDIENCES/.test(error.message),
  );
  assert.throws(
    () => loadFactoryConfig({ ...on, SELFHOST_ACQUISITION_ORIGIN: "https://acquisition.example/path" }, audiences),
    /SELFHOST_ACQUISITION_ORIGIN/,
  );

  // Through loadConfig, with the rest of a complete environment.
  const complete = {
    DATABASE_URL: "postgres://control:secret@postgres/control",
    SELFHOST_PUBLIC_URL: "https://control.internal.example",
    RELAYCAST_URL: "http://relaycast.relay.svc.cluster.local",
    RELAYCAST_PUBLIC_URL: "https://relaycast.selfhosted.company",
    SESSION_READ_API_URL: "http://reader.sessions.svc.cluster.local:8080",
    SESSION_READ_API_PUBLIC_URL: "https://history.selfhosted.company",
    SESSION_READ_API_SECRET: "reader-control-secret-".repeat(2),
    RELAYCONTROL_INTROSPECT_SECRET: "i".repeat(32),
    SELFHOST_BOOTSTRAP_TOKEN: "b".repeat(32),
    SELFHOST_ENCRYPTION_KEY_ID: "test-key",
    SELFHOST_ENCRYPTION_KEY: "00".repeat(32),
    ...on,
  };
  assert.throws(
    () => loadConfig(complete),
    (error: Error) => /SELFHOST_ACQUISITION_ORIGIN/.test(error.message) && /SELFHOST_INTROSPECT_AUDIENCES/.test(error.message),
  );
  const loaded = loadConfig({ ...complete, SELFHOST_INTROSPECT_AUDIENCES: `https://history.selfhosted.company,${ACQUISITION}` });
  assert.equal(loaded.factory?.acquisitionOrigin, ACQUISITION);
  const { RELAYCONTROL_INTROSPECT_SECRET: _secret, ...withoutSecret } = complete;
  assert.throws(() => loadConfig(withoutSecret), /RELAYCONTROL_INTROSPECT_SECRET/);
  assert.equal(loadConfig({ ...complete, SELFHOST_FACTORY_ENABLED: "false" }).factory?.acquisitionOrigin, undefined);
});

test("8: replacing the key keeps the same enrollment and token", async (t) => {
  const env = await startFactoryEnv(t, { acquisitionOrigin: ACQUISITION });
  await connect(env);
  const [before] = await operators(env);
  const replaced = await connect(env, env.ownerToken, FACTORY_KEY_2);
  const rows = await operators(env);
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.id, before!.id);
  assert.equal(rows[0]!.token_id, before!.token_id);
  assert.equal(rows[0]!.state, "enrolled");
  assert.equal((await acquisitionTokens(env)).length, 1);
  assert.equal(replaced.body.acquisition.state, "enrolled");
  assert.equal((await auditActions(env)).filter((event) => event.action === "factory.acquisition.enrol").length, 1);
});

test("9: disconnect drains in the same transaction; the reconciler then revokes the token", async (t) => {
  const env = await startFactoryEnv(t, { acquisitionOrigin: ACQUISITION });
  await connect(env);
  const disconnected = await env.api(connectionPath(env), { method: "DELETE", token: env.ownerToken });
  assert.equal(disconnected.status, 204);
  const [row] = await operators(env);
  assert.equal(row!.state, "draining");
  assert.equal(row!.reason, "disconnect");
  assert.ok(row!.drain_started_at);
  // Draining keeps the token usable for outstanding obligations.
  assert.equal((await introspectRow(env, row!)).result.active, true);
  const summary = await env.api(connectionPath(env), { token: env.ownerToken });
  assert.equal(summary.body.connected, false);
  assert.equal(summary.body.acquisition.state, "draining");

  assert.equal(await env.module.service.reconcileAcquisition(50), 1);
  const [revoked] = await operators(env);
  assert.equal(revoked!.state, "revoked");
  assert.equal(revoked!.reason, "disconnect");
  assert.equal(revoked!.stranded_count, 0);
  assert.ok(revoked!.revoked_at);
  assert.deepEqual((await introspectRow(env, revoked!)).result, { active: false, reason: "revoked" });
  const audit = (await auditActions(env)).filter((event) => event.action === "factory.acquisition.revoke");
  assert.equal(audit.length, 1);
  assert.equal(audit[0]!.actor_kind, "service");
  assert.equal(audit[0]!.target, `${row!.token_id} (acquisition-operator; reason=disconnect; stranded=0)`);
  assert.equal(await env.module.service.reconcileAcquisition(50), 0);
});

test("11: rotate enrols a new token and drains the old one; the reconciler revokes only the old one", async (t) => {
  const env = await startFactoryEnv(t, { acquisitionOrigin: ACQUISITION });
  await connect(env);
  const rotated = await env.api(rotatePath(env), { method: "POST", token: env.adminToken, body: {} });
  assert.equal(rotated.status, 200, JSON.stringify(rotated.body));
  const rows = await operators(env);
  assert.equal(rows.length, 2);
  const [old, fresh] = rows;
  assert.equal(old!.state, "draining");
  assert.equal(old!.reason, "rotate");
  assert.equal(fresh!.state, "enrolled");
  assert.notEqual(fresh!.token_id, old!.token_id);
  assert.equal(rotated.body.acquisition.state, "enrolled");
  assert.equal(rotated.body.acquisition.token_prefix, fresh!.token_prefix);
  const { token } = await introspectRow(env, fresh!);
  assert.ok(!JSON.stringify(rotated.body).includes(token));
  assert.equal((await auditActions(env)).filter((event) => event.action === "factory.acquisition.rotate").length, 1);

  assert.equal(await env.module.service.reconcileAcquisition(50), 1);
  const after = await operators(env);
  assert.equal(after[0]!.state, "revoked");
  assert.equal(after[0]!.reason, "rotate");
  assert.equal(after[1]!.state, "enrolled");
  assert.equal((await introspectRow(env, after[0]!)).result.active, false);
  assert.equal((await introspectRow(env, after[1]!)).result.active, true);
});

test("11b: a draining token past ACQUISITION_DRAIN_MAX_MS is revoked by the reconciler", async (t) => {
  const env = await startFactoryEnv(t, { acquisitionOrigin: ACQUISITION });
  await connect(env);
  assert.equal((await env.api(connectionPath(env), { method: "DELETE", token: env.ownerToken })).status, 204);
  await env.database.query(
    "UPDATE factory_acquisition_operators SET drain_started_at = now() - ($1::bigint * interval '1 millisecond')",
    [ACQUISITION_DRAIN_MAX_MS + 60_000],
  );
  assert.equal(await env.module.service.reconcileAcquisition(50), 1);
  assert.equal((await operators(env))[0]!.state, "revoked");
});

test("12: explicit revoke revokes every enrolled and draining token; a later connect enrols afresh", async (t) => {
  const env = await startFactoryEnv(t, { acquisitionOrigin: ACQUISITION });
  // Not connected yet: nothing to revoke.
  const early = await env.api(revokePath(env), { method: "POST", token: env.ownerToken, body: {} });
  assert.equal(early.status, 404);
  assert.equal(early.body.error, "factory_not_connected");
  const earlyRotate = await env.api(rotatePath(env), { method: "POST", token: env.ownerToken, body: {} });
  assert.equal(earlyRotate.status, 404);
  assert.equal(earlyRotate.body.error, "factory_not_connected");

  await connect(env);
  assert.equal((await env.api(rotatePath(env), { method: "POST", token: env.ownerToken, body: {} })).status, 200);
  const revoked = await env.api(revokePath(env), { method: "POST", token: env.adminToken, body: {} });
  assert.equal(revoked.status, 200, JSON.stringify(revoked.body));
  assert.equal(revoked.body.acquisition.state, "revoked");
  const rows = await operators(env);
  assert.equal(rows.length, 2);
  for (const row of rows) {
    assert.equal(row.state, "revoked");
    assert.equal(row.reason, "admin");
    assert.equal((await introspectRow(env, row)).result.active, false);
  }
  assert.ok((await acquisitionTokens(env)).every((token) => token.revoked_at !== null));
  const audit = (await auditActions(env)).filter((event) => event.action === "factory.acquisition.revoke");
  assert.equal(audit.length, 2);
  assert.ok(audit.every((event) => event.actor_kind === "user" && event.target?.endsWith("; reason=admin; stranded=0)")));
  assert.equal(await env.module.service.reconcileAcquisition(50), 0);

  const again = await connect(env);
  assert.equal(again.body.acquisition.state, "enrolled");
  const after = await operators(env);
  assert.equal(after.length, 3);
  assert.equal(after.filter((row) => row.state === "enrolled").length, 1);
  assert.equal((await introspectRow(env, after.find((row) => row.state === "enrolled")!)).result.active, true);
});

test("12b: a token revoked through the API tokens routes is reported revoked and re-enrolled on connect", async (t) => {
  const env = await startFactoryEnv(t, { acquisitionOrigin: ACQUISITION });
  await connect(env);
  const [row] = await operators(env);
  const revoked = await new ApiTokenStore(env.database).revoke({
    workspaceId: env.workspaceId,
    organizationId: env.organizationId,
    tokenId: row!.token_id,
    actor: { kind: "user", userId: env.ownerId },
  });
  assert.equal(revoked, true);
  const summary = await env.api(connectionPath(env), { token: env.ownerToken });
  assert.equal(summary.body.acquisition.state, "revoked");
  const again = await connect(env);
  assert.equal(again.body.acquisition.state, "enrolled");
  const rows = await operators(env);
  assert.equal(rows.length, 2);
  assert.equal(rows[0]!.state, "revoked");
  assert.equal(rows[0]!.reason, "token_revoked");
  assert.equal(rows[1]!.state, "enrolled");
});

test("13: removing the connection owner and workspace cleanup drain the enrollment in the same transaction", async (t) => {
  const env = await startFactoryEnv(t, { acquisitionOrigin: ACQUISITION });
  await connect(env, env.adminToken);
  assert.equal((await removeMember(env, env.adminId)).status, 204);
  let [row] = await operators(env);
  assert.equal(row!.state, "draining");
  assert.equal(row!.reason, "member_removed");
  assert.equal((await introspectRow(env, row!)).result.active, true);

  // A member who did not own the connection leaves the enrollment alone.
  await connect(env);
  assert.equal((await removeMember(env, env.memberId)).status, 204);
  const rows = await operators(env);
  assert.deepEqual(rows.map((r) => r.state), ["draining", "enrolled"]);

  await env.database.transaction((tx) => cleanupWorkspaceFactory(tx, env.workspaceId));
  const drained = await operators(env);
  assert.deepEqual(drained.map((r) => [r.state, r.reason]), [["draining", "member_removed"], ["draining", "workspace_deleted"]]);
  [row] = drained.slice(1);
  assert.equal((await introspectRow(env, row!)).result.active, true);
  assert.equal(await env.module.service.reconcileAcquisition(50), 2);
  assert.ok((await operators(env)).every((r) => r.state === "revoked"));
});

test("14: with Factory off the worker only reconciles, and it still revokes a drained token", async (t) => {
  const env = await startFactoryEnv(t, { acquisitionOrigin: ACQUISITION });
  await connect(env);
  assert.equal((await env.api(connectionPath(env), { method: "DELETE", token: env.ownerToken })).status, 204);
  const [row] = await operators(env);
  assert.equal(row!.state, "draining");

  const off = createFactoryModule({
    config: {
      ...env.config,
      factory: { enabled: false, apiUrl: env.config.factory!.apiUrl, historyIntervalMs: env.config.factory!.historyIntervalMs },
    },
    database: env.database,
    messaging: { database: env.database, keyring: env.config.encryptionKeyring, relaycastUrl: env.config.relaycastUrl },
    browserOrigins: [new URL(PUBLIC_URL).origin],
    log: () => {},
  });
  t.after(() => off.stop());
  assert.equal(off.enabled, false);
  assert.equal(off.worker.started, false);
  off.start();
  assert.equal(off.worker.started, true);
  assert.equal(env.module.worker.started, false);
  assert.equal(await off.service.reconcileAcquisition(50), 1);
  const [revoked] = await operators(env);
  assert.equal(revoked!.state, "revoked");
  assert.equal(revoked!.reason, "disconnect");
});
