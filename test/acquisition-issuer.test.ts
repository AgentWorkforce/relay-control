import assert from "node:assert/strict";
import { createHash, createPublicKey, generateKeyPairSync, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { parse as parseYaml } from "yaml";
import { createApp } from "../src/app.js";
import { createAdminModule } from "../src/admin/routes.js";
import { loadAcquisitionIssuerConfig, type SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { hashSecret } from "../src/crypto.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";
import {
  AcquisitionAssertionError,
  verifyAcquisitionAssertion,
  type AcquisitionOperation,
} from "./support/pipeline-acquisition-assertion.js";
import { parsePinnedKeys } from "./support/pipeline-key-registry.js";

/**
 * Dormant cloud-class acquisition assertion issuer. Every envelope it issues
 * is verified with a verbatim copy of the pipeline verifier
 * (relayhistory-pipeline #331 f4919c6e) against the published key, parsed the
 * way the pipeline parses ACQUISITION_PINNED_KEYS.
 */

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const SERVICE = "internal-service-token-that-is-at-least-32-bytes";
const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 6) } };
const HISTORY = "https://history.selfhosted.test";
const ACQUISITION = "https://acquisition.selfhosted.test";
const KEY_ID = "relaycontrol-acq-2026-11";

function pemKey(): string {
  return generateKeyPairSync("ed25519").privateKey.export({ format: "pem", type: "pkcs8" }).toString();
}

function rawPublic(pem: string): string {
  return createPublicKey(pem).export({ format: "der", type: "spki" }).subarray(12).toString("base64");
}

const AUDIENCES = { introspectSecret: INTROSPECT_SECRET, introspectAudiences: [HISTORY, ACQUISITION] };
function issuerEnv(extra: Record<string, string> = {}): Record<string, string> {
  return {
    SELFHOST_ACQUISITION_ISSUER_ENABLED: "true",
    SELFHOST_ACQUISITION_ORIGIN: "HTTPS://Acquisition.SelfHosted.test:443/",
    SELFHOST_ACQUISITION_ISSUER_KEY_ID: KEY_ID,
    SELFHOST_ACQUISITION_ISSUER_PRIVATE_KEY: PEM,
    ...extra,
  };
}
const PEM = pemKey();

async function deviceToken(origin: string, userId: string, workspaceId: string): Promise<string> {
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
  assert.match(issued.body.scope as string, /rth:acquire/);
  return issued.body.access_token as string;
}

/** A dashboard browser session (scope `account`, no rth:acquire), returned as its raw token. */
async function browserToken(origin: string, userId: string, workspaceId: string): Promise<string> {
  const login = await fetch(`${origin}/login`);
  const code = (await login.text()).match(/<code>([A-Z0-9]{4}-[A-Z0-9]{4})<\/code>/)?.[1];
  assert(code);
  const deviceCookie = login.headers.get("set-cookie")!.split(";")[0]!;
  const approved = await request(origin, "/api/v1/auth/device/approve", {
    method: "POST",
    token: BOOTSTRAP,
    body: { action: "approve", user_code: code, user_id: userId, workspace_id: workspaceId },
  });
  assert.equal(approved.status, 200);
  const poll = await request(origin, "/login/poll", { method: "POST", cookie: deviceCookie });
  const session = poll.headers.get("set-cookie")?.match(/agent_relay_session=([^;]+)/)?.[1];
  assert(session);
  return decodeURIComponent(session);
}

async function setup(t: TestContext, enabled = true) {
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
    ...AUDIENCES,
    acquisitionIssuer: enabled ? loadAcquisitionIssuerConfig(issuerEnv(), AUDIENCES) : null,
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
  const workspaces: string[] = [];
  for (const name of ["primary", "other"]) {
    const created = await request(origin, `/api/v1/organizations/${org.body.id}/workspaces`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { name, relaycastApiKey: `rk_${name}` },
    });
    assert.equal(created.status, 201);
    workspaces.push(created.body.id as string);
  }
  const workspaceId = workspaces[0]!;
  const organizationId = org.body.id as string;
  const ownerId = org.body.owner.id as string;
  const owner = await deviceToken(origin, ownerId, workspaceId);
  const mintOperator = async (aud: string, workspace = workspaceId) => {
    const session = workspace === workspaceId ? owner : await deviceToken(origin, ownerId, workspace);
    const created = await request(origin, `/api/v1/workspaces/${workspace}/deployment-api-tokens`, {
      method: "POST",
      token: session,
      body: { label: "acquisition operator", purpose: "acquisition-operator", aud },
    });
    assert.equal(created.status, 201);
    return created.body.accessToken as string;
  };
  return {
    database,
    origin,
    organizationId,
    workspaceId,
    otherWorkspaceId: workspaces[1]!,
    ownerId,
    owner,
    operator: enabled ? await mintOperator(ACQUISITION) : "",
    mintOperator,
    issue: (kind: string, body: unknown, token?: string, prefix = "") =>
      request(origin, `${prefix}/api/v1/acquisition/assertions/${kind}`, { method: "POST", token, body }),
  };
}

type Ctx = Awaited<ReturnType<typeof setup>>;

function installBody(ctx: Ctx, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    aud: ACQUISITION,
    operationUuid: randomUUID(),
    orgId: ctx.organizationId,
    workspaceId: ctx.workspaceId,
    source: "claude-code",
    sessionId: "session-1",
    revision: "2",
    expectedRevision: "1",
    expectedOwnerEpoch: "0",
    expectedPredecessorGrantId: "",
    ownerKind: "cloud",
    ownerUserId: ctx.ownerId,
    ownerOriginId: "origin-1",
    bindingUuid: randomUUID(),
    installationId: "",
    grantSha256: createHash("sha256").update("grant").digest("hex"),
    expiresAt: "2026-12-01T00:00:00Z",
    ...extra,
  };
}

function revokeBody(ctx: Ctx, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    aud: ACQUISITION,
    operationUuid: randomUUID(),
    orgId: ctx.organizationId,
    workspaceId: ctx.workspaceId,
    source: "claude-code",
    sessionId: "session-1",
    revision: "3",
    targetGrantId: randomUUID(),
    targetOwnerEpoch: "1",
    targetOwnerKind: "cloud",
    targetBindingUuid: randomUUID(),
    targetInstallationId: "",
    ...extra,
  };
}

/** The pipeline's view: the published keys as ACQUISITION_PINNED_KEYS, verified with its verifier. */
async function pipelineVerify(ctx: Ctx, kind: AcquisitionOperation, envelope: unknown) {
  const keys = await request(ctx.origin, "/api/v1/acquisition/issuer-keys");
  const registry = parsePinnedKeys(JSON.stringify(keys.body.keys));
  return verifyAcquisitionAssertion(kind, envelope, registry, (scope, issuerKeyId) =>
    scope.orgId === ctx.organizationId && scope.workspaceId === ctx.workspaceId && issuerKeyId === KEY_ID);
}

function refusedByPipeline(fn: () => unknown): void {
  assert.throws(fn, (error: unknown) => error instanceof AcquisitionAssertionError);
}

test("disabled: every acquisition route is 404 not_found and nothing is mounted", async (t) => {
  const ctx = await setup(t, false);
  const operator = await ctx.mintOperator(HISTORY);
  for (const prefix of ["", "/cloud"]) {
    const keys = await request(ctx.origin, `${prefix}/api/v1/acquisition/issuer-keys`);
    assert.equal(keys.status, 404, prefix);
    assert.deepEqual(keys.body, { error: { code: "not_found" } });
    for (const kind of ["install", "revoke", "rebind", "other"]) {
      for (const token of [operator, ctx.owner, undefined]) {
        const issued = await ctx.issue(kind, installBody(ctx), token, prefix);
        assert.equal(issued.status, 404, `${prefix} ${kind}`);
        assert.deepEqual(issued.body, { error: { code: "not_found" } });
      }
    }
  }
  assert.equal((await request(ctx.origin, "/api/v1/acquisition")).status, 404);
});

test("issuer keys: the raw Ed25519 key in ACQUISITION_PINNED_KEYS shape, no-store", async (t) => {
  const ctx = await setup(t);
  for (const prefix of ["", "/cloud"]) {
    const keys = await request(ctx.origin, `${prefix}/api/v1/acquisition/issuer-keys`);
    assert.equal(keys.status, 200);
    assert.equal(keys.headers.get("cache-control"), "no-store");
    assert.deepEqual(keys.body, { keys: [{ issuerKeyId: KEY_ID, issuerClass: "cloud", publicKeyBase64: rawPublic(PEM) }] });
    const registry = parsePinnedKeys(JSON.stringify(keys.body.keys));
    assert.equal(registry.get(KEY_ID)?.ownerKind, "cloud");
    assert(!keys.raw.includes("PRIVATE"));
  }
  const post = await request(ctx.origin, "/api/v1/acquisition/issuer-keys", { method: "POST", body: {} });
  assert.equal(post.status, 405);
  assert.equal(post.headers.get("allow"), "GET");
  const get = await request(ctx.origin, "/api/v1/acquisition/assertions/install", { token: ctx.operator });
  assert.equal(get.status, 405);
  assert.equal(get.headers.get("allow"), "POST");
});

test("service principal: install, revoke and reserved revoke verify with the pipeline codec", async (t) => {
  const ctx = await setup(t);
  const body = installBody(ctx);
  const installed = await ctx.issue("install", body, ctx.operator);
  assert.equal(installed.status, 200, installed.raw);
  assert.equal(installed.headers.get("cache-control"), "no-store");
  assert.equal(installed.body.kind, "install");
  assert.equal(installed.body.issuerKeyId, KEY_ID);
  assert(Number.isFinite(Date.parse(installed.body.issuedAt)));
  assert.equal(installed.body.revokeEnvelope, undefined);
  const { aud: _aud, ...unsigned } = body;
  const verified = await pipelineVerify(ctx, "install", installed.body.envelope);
  assert.deepEqual(
    { ...verified.payload },
    { ...unsigned, issuerKeyId: KEY_ID, evidenceSha256: installed.body.envelope.payload.evidenceSha256,
      requestSha256: installed.body.envelope.payload.requestSha256 },
  );
  assert.equal(installed.body.envelope.signature.length, 86);

  // The client may echo the active key id; any other is refused.
  assert.equal((await ctx.issue("install", installBody(ctx, { issuerKeyId: KEY_ID }), ctx.operator)).status, 200);
  const otherKey = await ctx.issue("install", installBody(ctx, { issuerKeyId: "elsewhere" }), ctx.operator);
  assert.equal(otherKey.status, 400);
  assert.equal(otherKey.body.error.code, "invalid_request");

  const revoked = await ctx.issue("revoke", revokeBody(ctx), ctx.operator);
  assert.equal(revoked.status, 200, revoked.raw);
  assert.equal((await pipelineVerify(ctx, "revoke", revoked.body.envelope)).kind, "revoke");

  // Reserved revoke: a second envelope, fresh operation, target from the install.
  const reserveBody = installBody(ctx, {
    reserveRevoke: true,
    reservedRevoke: { revision: "3", targetGrantId: randomUUID(), targetOwnerEpoch: "1" },
  });
  const reserved = await ctx.issue("install", reserveBody, ctx.operator);
  assert.equal(reserved.status, 200, reserved.raw);
  await pipelineVerify(ctx, "install", reserved.body.envelope);
  const revoke = await pipelineVerify(ctx, "revoke", reserved.body.revokeEnvelope);
  const fields = reserveBody.reservedRevoke as Record<string, string>;
  assert.notEqual(revoke.payload.operationUuid, reserveBody.operationUuid);
  assert.equal(revoke.payload.targetGrantId, fields.targetGrantId);
  assert.equal(revoke.payload.targetOwnerEpoch, "1");
  assert.equal(revoke.payload.revision, "3");
  assert.equal(revoke.payload.targetOwnerKind, "cloud");
  assert.equal(revoke.payload.targetBindingUuid, reserveBody.bindingUuid);
  assert.equal(revoke.payload.targetInstallationId, "");
  assert.equal(revoke.payload.sessionId, "session-1");
  const chosen = randomUUID();
  const withUuid = await ctx.issue("install", installBody(ctx, {
    reserveRevoke: true,
    reservedRevoke: { ...fields, operationUuid: chosen },
  }), ctx.operator);
  assert.equal(withUuid.body.revokeEnvelope.payload.operationUuid, chosen);

  for (const [what, extra] of [
    ["missing reservedRevoke", { reserveRevoke: true }],
    ["reservedRevoke without the flag", { reservedRevoke: fields }],
    ["incomplete reservedRevoke", { reserveRevoke: true, reservedRevoke: { revision: "3", targetGrantId: randomUUID() } }],
    ["unknown reservedRevoke key", { reserveRevoke: true, reservedRevoke: { ...fields, ownerKind: "cloud" } }],
    ["reused operationUuid", { reserveRevoke: true, operationUuid: chosen, reservedRevoke: { ...fields, operationUuid: chosen } }],
    ["invalid revoke field", { reserveRevoke: true, reservedRevoke: { ...fields, targetOwnerEpoch: "0" } }],
    ["non-boolean flag", { reserveRevoke: "true", reservedRevoke: fields }],
  ] as const) {
    const refused = await ctx.issue("install", installBody(ctx, extra), ctx.operator);
    assert.equal(refused.status, 400, what);
    assert.equal(refused.body.error.code, "invalid_request", what);
  }
  const onRevoke = await ctx.issue("revoke", revokeBody(ctx, { reserveRevoke: true, reservedRevoke: fields }), ctx.operator);
  assert.equal(onRevoke.status, 400);

  // Audited without signatures or digests; nothing else is stored.
  const audit = await ctx.database.query<{ action: string; target: string; actor_kind: string }>(
    "SELECT action, target, actor_kind FROM admin_audit_events WHERE action = 'acquisition.assertion.issued'",
  );
  assert.equal(audit.rows.length, 5);
  assert(audit.rows.every((row) => row.actor_kind === "service"));
  assert(audit.rows.some((row) => row.target.includes(`install ${body.operationUuid as string} key ${KEY_ID}`)));
  const raw = JSON.stringify(audit.rows);
  assert(!raw.includes(installed.body.envelope.signature));
  assert(!raw.includes(installed.body.envelope.payload.evidenceSha256));
});

test("tampered envelopes fail the pipeline verifier", async (t) => {
  const ctx = await setup(t);
  const installed = await ctx.issue("install", installBody(ctx), ctx.operator);
  const envelope = installed.body.envelope;
  await pipelineVerify(ctx, "install", envelope);
  const keys = parsePinnedKeys(JSON.stringify((await request(ctx.origin, "/api/v1/acquisition/issuer-keys")).body.keys));
  const verify = (kind: AcquisitionOperation, value: unknown) => verifyAcquisitionAssertion(kind, value, keys, () => true);
  refusedByPipeline(() => verify("install", { ...envelope, payload: { ...envelope.payload, ownerUserId: "someone-else" } }));
  refusedByPipeline(() => verify("install", { ...envelope, payload: { ...envelope.payload, sessionId: "session-2" } }));
  refusedByPipeline(() => verify("install", { ...envelope, payload: { ...envelope.payload, evidenceSha256: "0".repeat(64) } }));
  const flipped = Buffer.from(envelope.signature, "base64url");
  flipped[0] = flipped[0]! ^ 1;
  refusedByPipeline(() => verify("install", { ...envelope, signature: flipped.toString("base64url") }));
  refusedByPipeline(() => verify("revoke", envelope));
  // Another key under the same id is not this issuer.
  const foreign = parsePinnedKeys(JSON.stringify([{ issuerKeyId: KEY_ID, issuerClass: "cloud", publicKeyBase64: rawPublic(pemKey()) }]));
  refusedByPipeline(() => verifyAcquisitionAssertion("install", envelope, foreign, () => true));
});

test("desktop user with rth:acquire: own install (and its reserved revoke) only", async (t) => {
  const ctx = await setup(t);
  const desktop = ctx.owner;
  const installed = await ctx.issue("install", installBody(ctx, {
    reserveRevoke: true,
    reservedRevoke: { revision: "3", targetGrantId: randomUUID(), targetOwnerEpoch: "1" },
  }), desktop, "/cloud");
  assert.equal(installed.status, 200, installed.raw);
  await pipelineVerify(ctx, "install", installed.body.envelope);
  await pipelineVerify(ctx, "revoke", installed.body.revokeEnvelope);
  const audit = await ctx.database.query<{ actor_kind: string; actor_id: string }>(
    "SELECT actor_kind, actor_id FROM admin_audit_events WHERE action = 'acquisition.assertion.issued'",
  );
  assert.deepEqual(audit.rows, [{ actor_kind: "user", actor_id: ctx.ownerId }]);

  const someoneElse = await ctx.issue("install", installBody(ctx, { ownerUserId: "another-user" }), desktop);
  assert.equal(someoneElse.status, 403);
  assert.equal(someoneElse.body.error.code, "not_authorized");
  const revoke = await ctx.issue("revoke", revokeBody(ctx), desktop);
  assert.equal(revoke.status, 403);
  assert.equal(revoke.body.error.code, "not_authorized");
  const noAud = await ctx.issue("install", installBody(ctx, { aud: undefined }), desktop);
  assert.equal(noAud.status, 400);
});

test("refusals: principals, audience, scope, class and rebind", async (t) => {
  const ctx = await setup(t);
  const expect = async (response: Awaited<ReturnType<Ctx["issue"]>>, status: number, code: string, what: string) => {
    assert.equal(response.status, status, `${what}: ${response.raw}`);
    assert.equal(response.body.error.code, code, what);
  };
  const browser = await browserToken(ctx.origin, ctx.ownerId, ctx.workspaceId);
  const historyOperator = await ctx.mintOperator(HISTORY);
  const elsewhereOperator = await ctx.mintOperator(ACQUISITION, ctx.otherWorkspaceId);
  const agent = await request(ctx.origin, `/api/v1/workspaces/${ctx.workspaceId}/deployment-api-tokens`, {
    method: "POST",
    token: ctx.owner,
    body: { label: "files", purpose: "relayfile-agent", agent_name: "builder", aud: ACQUISITION },
  });
  assert.equal(agent.status, 201);
  const deployment = await request(ctx.origin, `/api/v1/workspaces/${ctx.workspaceId}/deployment-api-tokens`, {
    method: "POST",
    token: ctx.owner,
    body: { label: "deploy", purpose: "deployment" },
  });
  assert.equal(deployment.status, 201);

  for (const [what, token] of [
    ["browser session (scope account)", browser],
    ["operator token for another audience", historyOperator],
    ["relayfile agent token", agent.body.accessToken as string],
    ["workspace API token of another purpose", deployment.body.accessToken as string],
    ["internal service token", SERVICE],
    ["bootstrap token", BOOTSTRAP],
  ] as const) {
    await expect(await ctx.issue("install", installBody(ctx), token), 403, "not_authorized", what);
  }
  await expect(await ctx.issue("install", installBody(ctx), undefined), 401, "unauthorized", "no bearer");
  await expect(await ctx.issue("install", installBody(ctx), "sh_at_unknown"), 401, "unauthorized", "unknown token");
  await expect(await ctx.issue("install", installBody(ctx), "garbage"), 401, "unauthorized", "unknown prefix");
  await expect(await ctx.issue("install", installBody(ctx), "sh_wk_unknown"), 401, "unauthorized", "unknown workspace API token");
  const revokedDesktop = await deviceToken(ctx.origin, ctx.ownerId, ctx.workspaceId);
  await ctx.database.query("UPDATE token_sessions SET revoked_at = now() WHERE access_token_hash = $1", [hashSecret(revokedDesktop)]);
  await expect(await ctx.issue("install", installBody(ctx), revokedDesktop), 401, "unauthorized", "revoked desktop token");
  await expect(await ctx.issue("install", installBody(ctx, { aud: HISTORY }), ctx.operator), 403, "not_authorized", "body aud");
  await expect(await ctx.issue("install", installBody(ctx, { aud: HISTORY }), ctx.owner), 403, "not_authorized", "desktop body aud");
  await expect(await ctx.issue("install", installBody(ctx, { orgId: "other-org" }), ctx.operator), 403, "not_authorized", "org mismatch");
  await expect(
    await ctx.issue("install", installBody(ctx, { workspaceId: ctx.otherWorkspaceId }), ctx.operator),
    403, "not_authorized", "workspace mismatch",
  );
  await expect(await ctx.issue("install", installBody(ctx), elsewhereOperator), 403, "not_authorized", "operator of the other workspace");
  await expect(
    await ctx.issue("revoke", revokeBody(ctx, { workspaceId: ctx.otherWorkspaceId }), ctx.operator),
    403, "not_authorized", "revoke workspace mismatch",
  );

  await expect(
    await ctx.issue("install", installBody(ctx, { ownerKind: "native", bindingUuid: "", installationId: randomUUID() }), ctx.operator),
    400, "invalid_request", "native install",
  );
  await expect(
    await ctx.issue("revoke", revokeBody(ctx, { targetOwnerKind: "native", targetBindingUuid: "", targetInstallationId: randomUUID() }), ctx.operator),
    400, "invalid_request", "native revoke",
  );
  const { grantSha256: _grant, ...missing } = installBody(ctx);
  await expect(await ctx.issue("install", missing, ctx.operator), 400, "invalid_request", "missing field");
  await expect(await ctx.issue("install", installBody(ctx, { extra: "x" }), ctx.operator), 400, "invalid_request", "unknown field");
  await expect(await ctx.issue("install", installBody(ctx, { revision: 2 }), ctx.operator), 400, "invalid_request", "number revision");
  await expect(await ctx.issue("install", installBody(ctx, { expiresAt: "2026-12-01T00:00:00.000Z" }), ctx.operator), 400, "invalid_request", "expiry spelling");
  const notJson = await request(ctx.origin, "/api/v1/acquisition/assertions/install", {
    method: "POST", token: ctx.operator, rawBody: "[]", contentType: "application/json",
  });
  await expect(notJson, 400, "invalid_request", "array body");

  for (const token of [ctx.operator, ctx.owner]) {
    await expect(await ctx.issue("rebind", {}, token), 409, "native_receiver_contract_pending", "rebind");
  }
  await expect(await ctx.issue("rebind", {}, browser), 403, "not_authorized", "rebind unauthenticated");
  await expect(await ctx.issue("other", installBody(ctx), ctx.operator), 404, "not_found", "unknown kind");

  const audit = await ctx.database.query("SELECT 1 FROM admin_audit_events WHERE action = 'acquisition.assertion.issued'");
  assert.equal(audit.rows.length, 0, "nothing refused is audited as issued");
});

test("issuer config: off by default, fail closed naming variables, never values", () => {
  // Off: nothing else is read, so an invalid key cannot break startup.
  for (const flag of [undefined, "", "false"]) {
    assert.equal(loadAcquisitionIssuerConfig({
      SELFHOST_ACQUISITION_ISSUER_ENABLED: flag,
      SELFHOST_ACQUISITION_ISSUER_PRIVATE_KEY: "garbage",
      SELFHOST_ACQUISITION_ORIGIN: "not a url",
    }, AUDIENCES), null);
  }
  assert.throws(() => loadAcquisitionIssuerConfig({ SELFHOST_ACQUISITION_ISSUER_ENABLED: "yes" }, AUDIENCES),
    /SELFHOST_ACQUISITION_ISSUER_ENABLED must be true or false/);

  const loaded = loadAcquisitionIssuerConfig(issuerEnv(), AUDIENCES)!;
  assert.equal(loaded.origin, ACQUISITION);
  assert.equal(loaded.keyId, KEY_ID);
  assert.deepEqual(loaded.publishedKeys, [{ issuerKeyId: KEY_ID, issuerClass: "cloud", publicKeyBase64: rawPublic(PEM) }]);

  const secretValue = "s3cr3t-not-a-key-value";
  const refusals: Array<[Record<string, string>, typeof AUDIENCES | { introspectSecret: null; introspectAudiences: string[] }, RegExp]> = [
    [{ SELFHOST_ACQUISITION_ORIGIN: "" }, AUDIENCES, /SELFHOST_ACQUISITION_ORIGIN is required/],
    [{ SELFHOST_ACQUISITION_ORIGIN: "https://acquisition.selfhosted.test/v1" }, AUDIENCES, /SELFHOST_ACQUISITION_ORIGIN must be an http\(s\) origin/],
    [{ SELFHOST_ACQUISITION_ORIGIN: "https://elsewhere.test" }, AUDIENCES, /must be listed in SELFHOST_INTROSPECT_AUDIENCES/],
    [{}, { introspectSecret: null, introspectAudiences: AUDIENCES.introspectAudiences }, /RELAYCONTROL_INTROSPECT_SECRET is required/],
    [{ SELFHOST_ACQUISITION_ISSUER_KEY_ID: "" }, AUDIENCES, /SELFHOST_ACQUISITION_ISSUER_KEY_ID is required/],
    [{ SELFHOST_ACQUISITION_ISSUER_KEY_ID: "a\u0001b" }, AUDIENCES, /SELFHOST_ACQUISITION_ISSUER_KEY_ID must be/],
    [{ SELFHOST_ACQUISITION_ISSUER_KEY_ID: "x".repeat(513) }, AUDIENCES, /SELFHOST_ACQUISITION_ISSUER_KEY_ID must be/],
    [{ SELFHOST_ACQUISITION_ISSUER_PRIVATE_KEY: "" }, AUDIENCES, /SELFHOST_ACQUISITION_ISSUER_PRIVATE_KEY \(or _FILE\) is required/],
    [{ SELFHOST_ACQUISITION_ISSUER_PRIVATE_KEY: secretValue }, AUDIENCES, /SELFHOST_ACQUISITION_ISSUER_PRIVATE_KEY must be an unencrypted PKCS#8 PEM Ed25519/],
    [{
      SELFHOST_ACQUISITION_ISSUER_PRIVATE_KEY: generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey
        .export({ format: "pem", type: "pkcs8" }).toString(),
    }, AUDIENCES, /must be an unencrypted PKCS#8 PEM Ed25519/],
    [{ SELFHOST_ACQUISITION_ISSUER_PREVIOUS_PUBLIC_KEYS: "{" }, AUDIENCES, /PREVIOUS_PUBLIC_KEYS must be a JSON array/],
    [{ SELFHOST_ACQUISITION_ISSUER_PREVIOUS_PUBLIC_KEYS: JSON.stringify([{ issuerKeyId: KEY_ID, publicKeyBase64: rawPublic(pemKey()) }]) }, AUDIENCES, /repeats an issuerKeyId/],
    [{ SELFHOST_ACQUISITION_ISSUER_PREVIOUS_PUBLIC_KEYS: JSON.stringify([{ issuerKeyId: "old", publicKeyBase64: rawPublic(PEM) }]) }, AUDIENCES, /repeats a public key/],
    [{ SELFHOST_ACQUISITION_ISSUER_PREVIOUS_PUBLIC_KEYS: JSON.stringify([{ issuerKeyId: "old", publicKeyBase64: "AAAA" }]) }, AUDIENCES, /base64 of a raw 32-byte/],
    [{ SELFHOST_ACQUISITION_ISSUER_PREVIOUS_PUBLIC_KEYS: JSON.stringify([{ issuerKeyId: "old", publicKeyBase64: rawPublic(pemKey()), issuerClass: "cloud" }]) }, AUDIENCES, /exactly issuerKeyId and publicKeyBase64/],
  ];
  for (const [extra, audiences, message] of refusals) {
    assert.throws(() => loadAcquisitionIssuerConfig(issuerEnv(extra), audiences), (error: Error) => {
      assert.match(error.message, message);
      assert(!error.message.includes(secretValue) && !error.message.includes("BEGIN"), "never the value");
      return true;
    });
  }

  const previous = rawPublic(pemKey());
  const rotated = loadAcquisitionIssuerConfig(issuerEnv({
    SELFHOST_ACQUISITION_ISSUER_PREVIOUS_PUBLIC_KEYS: JSON.stringify([{ issuerKeyId: "relaycontrol-acq-2026-10", publicKeyBase64: previous }]),
  }), AUDIENCES)!;
  assert.deepEqual(rotated.publishedKeys.map((key) => key.issuerKeyId), [KEY_ID, "relaycontrol-acq-2026-10"]);
  // The published set is exactly what the pipeline pins.
  assert.equal(parsePinnedKeys(JSON.stringify(rotated.publishedKeys)).size, 2);
});

test("openapi documents the acquisition issuer routes", () => {
  const spec = parseYaml(readFileSync(new URL("../openapi.yaml", import.meta.url), "utf8"));
  assert(spec.paths["/api/v1/acquisition/issuer-keys"]?.get);
  for (const kind of ["install", "revoke", "rebind"]) {
    assert(spec.paths[`/api/v1/acquisition/assertions/${kind}`]?.post, kind);
  }
});
