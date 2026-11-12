import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage } from "node:http";
import test, { type TestContext } from "node:test";
import { Ajv2020 } from "ajv/dist/2020.js";
import { parse as parseYaml } from "yaml";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * The sessions pipeline verifies relaycontrol access tokens through
 * POST /internal/v1/auth/introspect: its ingest edge accepts the caller's own
 * `sh_at_` token that the relayhistory/session sync route hands back.
 */

const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const INTERNAL = "internal-service-token-at-least-32-bytes!";
const HISTORY_PUBLIC = "https://history.selfhosted.test";

type Logged = { level: string; text: string };

/** Captures console output for the duration of a test. */
function captureLogs(t: TestContext): Logged[] {
  const logged: Logged[] = [];
  for (const level of ["log", "info", "warn", "error", "debug"] as const) {
    t.mock.method(console, level, (...args: unknown[]) => {
      logged.push({ level, text: args.map((arg) => typeof arg === "string" ? arg : JSON.stringify(arg)).join(" ") });
    });
  }
  return logged;
}

/**
 * A sessions pipeline ingest-edge double: every upload re-introspects the
 * bearer at relaycontrol for the requested workspace (fail closed).
 */
async function startIngestEdge(t: TestContext, control: () => string) {
  const uploads: Array<{ workspace: string | null; active: boolean }> = [];
  let origin = "";
  const server = createServer(async (incoming: IncomingMessage, response) => {
    for await (const _chunk of incoming) { /* drain */ }
    const url = new URL(incoming.url!, origin);
    response.setHeader("content-type", "application/json");
    const send = (status: number, body: unknown) => {
      response.statusCode = status;
      response.end(JSON.stringify(body));
    };
    const bearer = /^Bearer (.+)$/.exec(incoming.headers.authorization ?? "")?.[1];
    const workspace = url.searchParams.get("workspace");
    if (incoming.method !== "POST" || url.pathname !== "/v1/ingest" || !bearer || !workspace) {
      send(404, { error: "not_found" });
      return;
    }
    const verdict = await request(control(), "/internal/v1/auth/introspect", {
      method: "POST",
      token: INTROSPECT_SECRET,
      body: { token: bearer, aud: HISTORY_PUBLIC, workspace },
    });
    const active = verdict.status === 200 && verdict.body.active === true;
    uploads.push({ workspace, active });
    send(active ? 202 : 401, active ? { accepted: true } : { error: "unauthorized" });
  });
  origin = await listen(server);
  t.after(() => close(server));
  return { origin, uploads };
}

async function setup(
  t: TestContext,
  options: { introspectSecret?: string | null; introspectAudiences?: string[] } = {},
) {
  let controlOrigin = "";
  const history = await startIngestEdge(t, () => controlOrigin);
  const database = new PGliteDatabase();
  await migrate(database);
  const config: SelfhostConfig = {
    databaseUrl: "unused-in-test",
    publicBaseUrl: "https://control.internal.example",
    relaycastUrl: "http://relaycast.internal",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayhistoryUrl: history.origin,
    relayhistoryPublicUrl: HISTORY_PUBLIC,
    sessionReadApi: { url: history.origin, publicUrl: HISTORY_PUBLIC, secret: "session-read-secret-".repeat(2) },
    introspectSecret: options.introspectSecret === undefined ? INTROSPECT_SECRET : options.introspectSecret,
    ...(options.introspectAudiences ? { introspectAudiences: options.introspectAudiences } : {}),
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    internalServiceToken: INTERNAL,
    oauthRedirectUrl: "https://control.internal.example/api/v1/integrations/oauth/callback",
    dashboardUrl: "https://control.internal.example/",
    port: 3000,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  const control = createServer(createApp({ config, store }));
  controlOrigin = await listen(control);
  t.after(async () => {
    await close(control);
    await database.close();
  });

  const org = await request(controlOrigin, "/api/v1/organizations", {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Tenant", ownerEmail: "owner@example.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const workspace = async (name: string) => {
    const created = await request(controlOrigin, `/api/v1/organizations/${org.body.id}/workspaces`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { name, relaycastApiKey: `rk_${name}` },
    });
    assert.equal(created.status, 201);
    return created.body.id as string;
  };
  const alpha = await workspace("alpha");
  const beta = await workspace("beta");
  const ownerId = org.body.owner.id as string;
  const login = async (workspaceId: string, userId = ownerId) => {
    const started = await request(controlOrigin, "/api/v1/auth/device/start", {
      method: "POST",
      body: { client_name: "introspect-test" },
    });
    const approved = await request(controlOrigin, "/api/v1/auth/device/approve", {
      method: "POST",
      token: BOOTSTRAP,
      body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: workspaceId },
    });
    assert.equal(approved.status, 200);
    const tokens = await request(controlOrigin, "/api/v1/auth/device/token", {
      method: "POST",
      body: { device_code: started.body.device_code },
    });
    assert.equal(tokens.status, 200);
    return {
      accessToken: tokens.body.access_token as string,
      refreshToken: tokens.body.refresh_token as string,
    };
  };
  const introspect = (body: unknown, secret: string | null = INTROSPECT_SECRET) =>
    request(controlOrigin, "/internal/v1/auth/introspect", {
      method: "POST",
      ...(secret ? { token: secret } : {}),
      body,
    });
  const member = async (email: string) => {
    const added = await request(controlOrigin, `/api/v1/organizations/${org.body.id}/memberships`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { email, name: email, role: "member" },
    });
    assert.equal(added.status, 200);
    return added.body.userId as string;
  };
  return {
    origin: controlOrigin,
    database,
    store,
    member,
    history,
    alpha,
    beta,
    ownerId,
    organizationId: org.body.id as string,
    login,
    introspect,
  };
}

/** The published 200 schema for POST /internal/v1/auth/introspect (openapi.yaml). */
function introspectionResponseValidator() {
  const spec = parseYaml(readFileSync(new URL("../openapi.yaml", import.meta.url), "utf8"));
  const ajv = new Ajv2020({ strict: false, validateFormats: false });
  ajv.addSchema({ $id: "openapi", components: spec.components });
  const schema = spec.paths["/internal/v1/auth/introspect"].post.responses["200"].content["application/json"].schema;
  // Component refs resolve against the spec's own components.
  return ajv.compile(JSON.parse(JSON.stringify(schema).replaceAll('"#/components/', '"openapi#/components/')));
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

test("introspection describes an active access token and rotates token_id on refresh", async (t) => {
  const env = await setup(t);
  const { accessToken, refreshToken } = await env.login(env.alpha);
  const session = (await env.database.query<{ created_at: Date; access_token_expires_at: Date; access_token_hash: string }>(
    "SELECT created_at, access_token_expires_at, access_token_hash FROM token_sessions WHERE access_token_hash = $1",
    [sha256(accessToken)],
  )).rows[0]!;

  const active = await env.introspect({ token: accessToken, aud: HISTORY_PUBLIC, workspace: env.alpha });
  assert.equal(active.status, 200);
  assert.equal(active.headers.get("cache-control"), "no-store");
  const expectedTokenId = sha256(`selfhost-token-id:${session.access_token_hash}`).slice(0, 32);
  assert.deepEqual(active.body, {
    active: true,
    sub: env.ownerId,
    email: "owner@example.test",
    principal_type: "desktop-user",
    agent_name: null,
    machine_id: null,
    org: env.organizationId,
    workspace: env.alpha,
    role: "owner",
    scopes: ["cli:auth", "rth:read", "rth:sync", "rth:acquire"],
    aud: HISTORY_PUBLIC,
    iat: Math.floor(new Date(session.created_at).getTime() / 1_000),
    exp: Math.floor(new Date(session.access_token_expires_at).getTime() / 1_000),
    token_id: expectedTokenId,
    capture_policy: { version: 1, revision: 1, settings: {} },
  });
  assert.equal("product_id" in active.body, false);
  assert.match(active.body.token_id, /^[0-9a-f]{32}$/);

  // Stable for the token's life.
  const again = await env.introspect({ token: accessToken, aud: HISTORY_PUBLIC, workspace: env.alpha });
  assert.equal(again.body.token_id, expectedTokenId);

  // Refresh: a new token_id and iat from last_refreshed_at; the old token is gone.
  await env.database.query(
    "UPDATE token_sessions SET created_at = created_at - interval '1 hour' WHERE access_token_hash = $1",
    [sha256(accessToken)],
  );
  const refreshed = await request(env.origin, "/api/v1/auth/token/refresh", {
    method: "POST",
    body: { refreshToken },
  });
  assert.equal(refreshed.status, 200);
  const next = refreshed.body.accessToken as string;
  const row = (await env.database.query<{ last_refreshed_at: Date; created_at: Date }>(
    "SELECT last_refreshed_at, created_at FROM token_sessions WHERE access_token_hash = $1",
    [sha256(next)],
  )).rows[0]!;
  const rotated = await env.introspect({ token: next, aud: HISTORY_PUBLIC, workspace: env.alpha });
  assert.equal(rotated.body.active, true);
  assert.notEqual(rotated.body.token_id, expectedTokenId);
  assert.equal(rotated.body.token_id, sha256(`selfhost-token-id:${sha256(next)}`).slice(0, 32));
  assert.equal(rotated.body.iat, Math.floor(new Date(row.last_refreshed_at).getTime() / 1_000));
  assert.notEqual(rotated.body.iat, Math.floor(new Date(row.created_at).getTime() / 1_000));
  assert.deepEqual(
    (await env.introspect({ token: accessToken, aud: HISTORY_PUBLIC, workspace: env.alpha })).body,
    { active: false, reason: "unknown" },
  );
});

test("introspection names exactly one inactive reason, in contract order", async (t) => {
  const env = await setup(t);
  const alpha = await env.login(env.alpha);
  const inactive = async (token: string, reason: string, aud = HISTORY_PUBLIC, workspace = env.alpha) => {
    const result = await env.introspect({ token, aud, workspace });
    assert.equal(result.status, 200, reason);
    assert.deepEqual(result.body, { active: false, reason }, `${reason}: ${token.slice(0, 6)}`);
  };

  // Never looked up as user tokens, even if well-formed for their own kind.
  for (const token of [alpha.refreshToken, BOOTSTRAP, INTERNAL, INTROSPECT_SECRET, "sh_dc_x", "nt_live_abcdefgh"]) {
    await inactive(token, "wrong-kind");
  }
  await inactive("sh_at_does-not-exist", "unknown");
  // A workspace API token with no such record is unknown, not another kind.
  await inactive("sh_wk_workspace-token", "unknown");
  // wrong-kind wins over everything else.
  await inactive(alpha.refreshToken, "wrong-kind", "https://elsewhere.test", env.beta);

  await inactive(alpha.accessToken, "audience", "https://elsewhere.test");
  await inactive(alpha.accessToken, "audience", "not a url");
  await inactive(alpha.accessToken, "audience", "ftp://history.selfhosted.test");
  await inactive(alpha.accessToken, "workspace", HISTORY_PUBLIC, env.beta);
  // audience is checked before workspace.
  await inactive(alpha.accessToken, "audience", "https://elsewhere.test", env.beta);

  const expiring = await env.login(env.alpha);
  await env.database.query(
    "UPDATE token_sessions SET access_token_expires_at = now() - interval '1 second' WHERE access_token_hash = $1",
    [sha256(expiring.accessToken)],
  );
  await inactive(expiring.accessToken, "expired");
  // expired is checked before audience and workspace.
  await inactive(expiring.accessToken, "expired", "https://elsewhere.test", env.beta);

  const revoked = await env.login(env.alpha);
  const revoke = await request(env.origin, "/api/v1/auth/token/revoke", { method: "POST", token: revoked.accessToken });
  assert.equal(revoke.status, 200);
  await inactive(revoked.accessToken, "revoked");
  // revoked is checked before expired.
  await env.database.query(
    "UPDATE token_sessions SET access_token_expires_at = now() - interval '1 second' WHERE access_token_hash = $1",
    [sha256(revoked.accessToken)],
  );
  await inactive(revoked.accessToken, "revoked");

  // The first token is untouched by all of the above.
  const still = await env.introspect({ token: alpha.accessToken, aud: HISTORY_PUBLIC, workspace: env.alpha });
  assert.equal(still.body.active, true);
});

test("introspection requires its own secret and a well-formed body", async (t) => {
  const logged = captureLogs(t);
  const env = await setup(t);
  const { accessToken } = await env.login(env.alpha);
  const body = { token: accessToken, aud: HISTORY_PUBLIC, workspace: env.alpha };

  logged.length = 0;
  for (const secret of [null, "wrong", INTERNAL, BOOTSTRAP, accessToken, `${INTROSPECT_SECRET}x`]) {
    const result = await env.introspect(body, secret);
    assert.equal(result.status, 401, String(secret));
    assert.equal(result.body.error, "unauthorized");
    assert.equal(typeof result.body.message, "string");
    assert.equal("active" in result.body, false);
  }
  assert.equal(logged.length, 6, "one line per failed authentication");
  for (const line of logged) assert.match(line.text, /token introspection rejected/);

  const malformed: Array<{ rawBody?: string; body?: unknown }> = [
    { rawBody: "{not json" },
    { rawBody: "" },
    { body: [] },
    { body: "token" },
    { body: null },
    { body: {} },
    { body: { aud: HISTORY_PUBLIC, workspace: env.alpha } },
    { body: { token: accessToken, workspace: env.alpha } },
    { body: { token: 1, aud: HISTORY_PUBLIC, workspace: env.alpha } },
    { body: { token: accessToken, aud: [HISTORY_PUBLIC], workspace: env.alpha } },
    { body: { token: accessToken, aud: HISTORY_PUBLIC, workspace: { id: env.alpha } } },
    { body: { token: "", aud: HISTORY_PUBLIC, workspace: env.alpha } },
    { body: { ...body, padding: "x".repeat(16 * 1024) } },
  ];
  for (const [index, entry] of malformed.entries()) {
    const result = await request(env.origin, "/internal/v1/auth/introspect", {
      method: "POST",
      token: INTROSPECT_SECRET,
      ...(entry.rawBody !== undefined
        ? { rawBody: entry.rawBody, contentType: "application/json" }
        : { body: entry.body }),
    });
    assert.equal(result.status, 400, `malformed body #${index}`);
    assert.equal(result.body.error, "invalid_request");
  }

  // Only POST, and never through the /cloud alias.
  assert.equal((await request(env.origin, "/internal/v1/auth/introspect", { token: INTROSPECT_SECRET })).status, 404);
  assert.equal((await request(env.origin, "/cloud/internal/v1/auth/introspect", {
    method: "POST",
    token: INTROSPECT_SECRET,
    body,
  })).status, 404);
  assert.equal((await request(env.origin, "/cloud/api/v1/auth/introspect", {
    method: "POST",
    token: INTROSPECT_SECRET,
    body,
  })).status, 404);
});

test("introspection is a 404 like any unknown route while its secret is unset", async (t) => {
  const env = await setup(t, { introspectSecret: null });
  const { accessToken } = await env.login(env.alpha);
  const unknownRoute = await request(env.origin, "/internal/v1/auth/no-such-route", { method: "POST", token: "x" });
  for (const secret of [INTROSPECT_SECRET, null, "anything"]) {
    const result = await env.introspect({ token: accessToken, aud: HISTORY_PUBLIC, workspace: env.alpha }, secret);
    assert.equal(result.status, 404);
    assert.deepEqual(result.body, unknownRoute.body);
  }
});

test("introspection audiences compare normalized origins and echo the configured value", async (t) => {
  const defaults = await setup(t);
  const { accessToken } = await defaults.login(defaults.alpha);
  for (const aud of [
    HISTORY_PUBLIC,
    `${HISTORY_PUBLIC}/`,
    "https://HISTORY.SelfHosted.TEST",
    "HTTPS://history.selfhosted.test:443/",
    `${HISTORY_PUBLIC}/v1/ingest?x=1`,
  ]) {
    const result = await defaults.introspect({ token: accessToken, aud, workspace: defaults.alpha });
    assert.equal(result.body.active, true, aud);
    assert.equal(result.body.aud, HISTORY_PUBLIC, aud);
  }
  for (const aud of ["http://history.selfhosted.test", "https://history.selfhosted.test:8443", "https://u:p@history.selfhosted.test"]) {
    const result = await defaults.introspect({ token: accessToken, aud, workspace: defaults.alpha });
    assert.deepEqual(result.body, { active: false, reason: "audience" }, aud);
  }

  const custom = await setup(t, {
    introspectAudiences: ["http://relayhistory.history.svc.cluster.local:8080", "https://Files.Selfhosted.test"],
  });
  const own = await custom.login(custom.alpha);
  const internal = await custom.introspect({
    token: own.accessToken,
    aud: "http://RELAYHISTORY.history.svc.cluster.local:8080/",
    workspace: custom.alpha,
  });
  assert.equal(internal.body.aud, "http://relayhistory.history.svc.cluster.local:8080");
  const files = await custom.introspect({ token: own.accessToken, aud: "https://files.selfhosted.test", workspace: custom.alpha });
  assert.equal(files.body.aud, "https://Files.Selfhosted.test");
  // The default audience is replaced, not extended.
  assert.deepEqual(
    (await custom.introspect({ token: own.accessToken, aud: HISTORY_PUBLIC, workspace: custom.alpha })).body,
    { active: false, reason: "audience" },
  );
});

test("readyz lists exactly the audiences introspection accepts, never the secret", async (t) => {
  const env = await setup(t, { introspectAudiences: ["https://Files.Selfhosted.test:443/", "http://history.svc:8080"] });
  const ready = await request(env.origin, "/readyz");
  assert.equal(ready.status, 200);
  assert.deepEqual(ready.body, {
    status: "ready",
    introspection: { enabled: true, audiences: ["https://files.selfhosted.test", "http://history.svc:8080"], outageHoldMs: 0 },
    // No features wired: core only.
    capabilities: { flows: false, relayfile: false, chief: false, usage: false, launch: false, usage_people: false, events_shim: false, session_delete: false },
  });
  assert.equal(JSON.stringify(ready.body).includes(INTROSPECT_SECRET), false);
  const { accessToken } = await env.login(env.alpha);
  for (const aud of ready.body.introspection.audiences as string[]) {
    const result = await env.introspect({ token: accessToken, aud, workspace: env.alpha });
    assert.equal(result.body.active, true, aud);
  }
  const unlisted = await env.introspect({ token: accessToken, aud: "https://files.selfhosted.test:8443", workspace: env.alpha });
  assert.deepEqual(unlisted.body, { active: false, reason: "audience" });

  const defaults = await setup(t);
  assert.deepEqual((await request(defaults.origin, "/readyz")).body.introspection, { enabled: true, audiences: [HISTORY_PUBLIC], outageHoldMs: 0 });
  const off = await setup(t, { introspectSecret: null });
  assert.deepEqual((await request(off.origin, "/readyz")).body.introspection, { enabled: false, audiences: [], outageHoldMs: 0 });
});

test("introspection responses and server logs never contain token material", async (t) => {
  const logged = captureLogs(t);
  const env = await setup(t);
  const { accessToken, refreshToken } = await env.login(env.alpha);
  const responses: string[] = [];
  for (const body of [
    { token: accessToken, aud: HISTORY_PUBLIC, workspace: env.alpha },
    { token: accessToken, aud: "https://elsewhere.test", workspace: env.alpha },
    { token: accessToken, aud: HISTORY_PUBLIC, workspace: env.beta },
    { token: refreshToken, aud: HISTORY_PUBLIC, workspace: env.alpha },
  ]) {
    responses.push((await env.introspect(body)).raw);
    responses.push((await env.introspect(body, "wrong-secret")).raw);
  }
  responses.push((await request(env.origin, "/internal/v1/auth/introspect", {
    method: "POST",
    token: INTROSPECT_SECRET,
    rawBody: `{"token":"${accessToken}"`,
    contentType: "application/json",
  })).raw);
  const forbidden = [accessToken, refreshToken, sha256(accessToken), sha256(refreshToken), INTROSPECT_SECRET];
  const output = [...responses, ...logged.map((line) => line.text)].join("\n");
  for (const secret of forbidden) assert.equal(output.includes(secret), false);
  assert(logged.length > 0, "failed authentications were logged");
});

test("the ingest edge verifies the sync credential through introspection, and revocation cuts it off", async (t) => {
  const logged = captureLogs(t);
  const env = await setup(t);
  const { accessToken } = await env.login(env.alpha);
  const sync = await request(env.origin, `/api/v1/workspaces/${env.alpha}/relayhistory/session`, {
    method: "POST",
    token: accessToken,
    body: { mode: "sync" },
  });
  assert.equal(sync.status, 200, sync.raw);
  assert.equal(sync.body.accessToken, accessToken);
  assert.equal(sync.body.baseUrl, HISTORY_PUBLIC);

  const upload = (workspace: string) => fetch(`${env.history.origin}/v1/ingest?workspace=${workspace}`, {
    method: "POST",
    headers: { authorization: `Bearer ${sync.body.accessToken}`, "content-type": "application/json" },
    body: "{}",
  });
  assert.equal((await upload(env.alpha)).status, 202);
  // The credential is bound to its workspace.
  assert.equal((await upload(env.beta)).status, 401);
  await request(env.origin, "/api/v1/auth/token/revoke", { method: "POST", token: accessToken });
  assert.equal((await upload(env.alpha)).status, 401);
  assert.deepEqual(env.history.uploads, [
    { workspace: env.alpha, active: true },
    { workspace: env.beta, active: false },
    { workspace: env.alpha, active: false },
  ]);
  const output = logged.map((line) => line.text).join("\n");
  assert.equal(output.includes(accessToken), false);
});

test("introspection verifies a supplied machine against the token user's node claims", async (t) => {
  const env = await setup(t);
  const otherId = await env.member("other@example.test");
  const own = await env.login(env.alpha);
  const claim = (workspaceId: string, nodeId: string, userId = env.ownerId) =>
    env.store.claimNode({
      workspaceId,
      organizationId: env.organizationId,
      relaycastWorkspaceId: `rc_${workspaceId}`,
      nodeId,
      nodeName: nodeId,
      userId,
    });
  await claim(env.alpha, "node-owned:1");
  await claim(env.alpha, "node.others_1", otherId);
  await claim(env.beta, "node-beta-only");
  const body = (machine?: string) => ({
    token: own.accessToken,
    aud: HISTORY_PUBLIC,
    workspace: env.alpha,
    ...(machine === undefined ? {} : { machine }),
  });

  // (1) Owned by the token's user in the token's workspace: echoed.
  const owned = await env.introspect(body("node-owned:1"));
  assert.equal(owned.status, 200);
  assert.equal(owned.body.active, true);
  assert.equal(owned.body.machine_id, "node-owned:1");
  assert.equal(owned.body.sub, env.ownerId);

  // (5) Absent: active, read-only principal.
  const absent = await env.introspect(body());
  assert.equal(absent.body.active, true);
  assert.equal(absent.body.machine_id, null);
  const { machine_id: _owned, ...ownedRest } = owned.body;
  const { machine_id: _absent, ...absentRest } = absent.body;
  assert.deepEqual(ownedRest, absentRest, "only machine_id differs");

  // (2) Another user's claim in this workspace.
  assert.deepEqual((await env.introspect(body("node.others_1"))).body, { active: false, reason: "machine_not_owned" });
  // (3) No claim anywhere.
  assert.deepEqual((await env.introspect(body("node-nobody"))).body, { active: false, reason: "machine_unclaimed" });
  // (4) Claimed only in another workspace of the install.
  assert.deepEqual(
    (await env.introspect(body("node-beta-only"))).body,
    { active: false, reason: "machine_workspace_mismatch" },
  );
  // The same claimant's beta claim does not verify it for an alpha token,
  // but a beta token for the same user does.
  const betaToken = await env.login(env.beta);
  const inBeta = await env.introspect({ token: betaToken.accessToken, aud: HISTORY_PUBLIC, workspace: env.beta, machine: "node-beta-only" });
  assert.equal(inBeta.body.machine_id, "node-beta-only");
  assert.deepEqual(
    (await env.introspect({ token: betaToken.accessToken, aud: HISTORY_PUBLIC, workspace: env.beta, machine: "node-owned:1" })).body,
    { active: false, reason: "machine_workspace_mismatch" },
  );
  // A claim in this workspace wins over one elsewhere: reported as not owned.
  await claim(env.beta, "node.others_1");
  assert.deepEqual((await env.introspect(body("node.others_1"))).body, { active: false, reason: "machine_not_owned" });
});

test("introspection answers machine_unclaimed once a machine's claim is released", async (t) => {
  const env = await setup(t);
  const own = await env.login(env.alpha);
  await env.store.claimNode({
    workspaceId: env.alpha,
    organizationId: env.organizationId,
    relaycastWorkspaceId: `rc_${env.alpha}`,
    nodeId: "node-released",
    nodeName: "laptop",
    userId: env.ownerId,
  });
  const body = { token: own.accessToken, aud: HISTORY_PUBLIC, workspace: env.alpha, machine: "node-released" };
  assert.equal((await env.introspect(body)).body.machine_id, "node-released");
  await env.store.releaseNode({
    workspaceId: env.alpha,
    organizationId: env.organizationId,
    nodeId: "node-released",
    actorUserId: env.ownerId,
  });
  assert.deepEqual((await env.introspect(body)).body, { active: false, reason: "machine_unclaimed" });
});

test("an inactive token never reveals machine state: the token reason wins", async (t) => {
  const env = await setup(t);
  const claimFor = (nodeId: string) => env.store.claimNode({
    workspaceId: env.alpha,
    organizationId: env.organizationId,
    relaycastWorkspaceId: `rc_${env.alpha}`,
    nodeId,
    nodeName: nodeId,
    userId: env.ownerId,
  });
  await claimFor("node-owned");
  const inactive = async (token: string, machine: string, reason: string, aud = HISTORY_PUBLIC, workspace = env.alpha) => {
    const result = await env.introspect({ token, aud, workspace, machine });
    assert.equal(result.status, 200);
    assert.deepEqual(result.body, { active: false, reason }, `${reason} with ${machine}`);
  };

  const expiring = await env.login(env.alpha);
  await env.database.query(
    "UPDATE token_sessions SET access_token_expires_at = now() - interval '1 second' WHERE access_token_hash = $1",
    [sha256(expiring.accessToken)],
  );
  const revoked = await env.login(env.alpha);
  assert.equal((await request(env.origin, "/api/v1/auth/token/revoke", { method: "POST", token: revoked.accessToken })).status, 200);
  const live = await env.login(env.alpha);

  for (const machine of ["node-owned", "node-nobody"]) {
    await inactive(expiring.accessToken, machine, "expired");
    await inactive(revoked.accessToken, machine, "revoked");
    await inactive(live.refreshToken, machine, "wrong-kind");
    await inactive("sh_at_does-not-exist", machine, "unknown");
    await inactive(live.accessToken, machine, "audience", "https://elsewhere.test");
    await inactive(live.accessToken, machine, "workspace", HISTORY_PUBLIC, env.beta);
  }
  assert.equal((await env.introspect({ token: live.accessToken, aud: HISTORY_PUBLIC, workspace: env.alpha, machine: "node-owned" })).body.machine_id, "node-owned");
});

test("introspection rejects a malformed machine with 400 invalid_request", async (t) => {
  const env = await setup(t);
  const { accessToken } = await env.login(env.alpha);
  await env.store.claimNode({
    workspaceId: env.alpha,
    organizationId: env.organizationId,
    relaycastWorkspaceId: `rc_${env.alpha}`,
    nodeId: "node-owned",
    nodeName: "laptop",
    userId: env.ownerId,
  });
  const base = { token: accessToken, aud: HISTORY_PUBLIC, workspace: env.alpha };
  for (const machine of ["", " node-owned", "node-owned ", "node owned", "node/owned", "x".repeat(201), null, 1, true, ["node-owned"], { id: "node-owned" }]) {
    const result = await env.introspect({ ...base, machine });
    assert.equal(result.status, 400, JSON.stringify(machine));
    assert.equal(result.body.error, "invalid_request");
    assert.match(result.body.message, /machine/);
    assert.equal("active" in result.body, false);
  }
  // The longest well-formed id is accepted (and simply unclaimed).
  assert.deepEqual(
    (await env.introspect({ ...base, machine: "x".repeat(200) })).body,
    { active: false, reason: "machine_unclaimed" },
  );
});

test("introspection without a workspace answers for the token session's workspace (v1.2)", async (t) => {
  const env = await setup(t);
  const own = await env.login(env.alpha);
  const base = { token: own.accessToken, aud: HISTORY_PUBLIC };

  const withWorkspace = await env.introspect({ ...base, workspace: env.alpha });
  assert.equal(withWorkspace.status, 200);
  assert.equal(withWorkspace.body.active, true);

  // (1) Absent: active, the response workspace is the session's, and the
  // answer is otherwise identical to one for the right workspace.
  const absent = await env.introspect(base);
  assert.equal(absent.status, 200);
  assert.equal(absent.body.workspace, env.alpha);
  assert.deepEqual(absent.body, withWorkspace.body);

  // (2) null is the same as absent.
  const nulled = await env.introspect({ ...base, workspace: null });
  assert.equal(nulled.status, 200);
  assert.deepEqual(nulled.body, withWorkspace.body);

  // A beta session answers for beta when the workspace is omitted.
  const beta = await env.login(env.beta);
  const betaAbsent = await env.introspect({ token: beta.accessToken, aud: HISTORY_PUBLIC });
  assert.equal(betaAbsent.body.active, true);
  assert.equal(betaAbsent.body.workspace, env.beta);

  // (3) A supplied wrong workspace is still reason workspace; a padded right
  // one is trimmed and accepted.
  assert.deepEqual((await env.introspect({ ...base, workspace: env.beta })).body, { active: false, reason: "workspace" });
  assert.deepEqual((await env.introspect({ ...base, workspace: ` ${env.alpha} ` })).body, withWorkspace.body);

  // Token checks still come first without a workspace; aud stays mandatory.
  assert.deepEqual((await env.introspect({ ...base, aud: "https://elsewhere.test" })).body, { active: false, reason: "audience" });
  assert.deepEqual(
    (await env.introspect({ token: own.refreshToken, aud: HISTORY_PUBLIC })).body,
    { active: false, reason: "wrong-kind" },
  );
  assert.equal((await env.introspect({ token: own.accessToken })).status, 400);
  assert.equal((await env.introspect({ token: own.accessToken, workspace: env.alpha })).status, 400);

  // (4) Supplied but not a non-empty string: 400.
  for (const workspace of ["", "   ", 1, true, [env.alpha], { id: env.alpha }]) {
    const result = await env.introspect({ ...base, workspace });
    assert.equal(result.status, 400, JSON.stringify(workspace));
    assert.equal(result.body.error, "invalid_request");
    assert.match(result.body.message, /workspace/);
    assert.equal("active" in result.body, false);
  }
});

test("introspection without a workspace verifies machines in the session's workspace", async (t) => {
  const env = await setup(t);
  const own = await env.login(env.alpha);
  const claim = (workspaceId: string, nodeId: string) =>
    env.store.claimNode({
      workspaceId,
      organizationId: env.organizationId,
      relaycastWorkspaceId: `rc_${workspaceId}`,
      nodeId,
      nodeName: nodeId,
      userId: env.ownerId,
    });
  await claim(env.alpha, "node-alpha");
  await claim(env.beta, "node-beta-only");
  const base = { token: own.accessToken, aud: HISTORY_PUBLIC };

  // (5) Owned in the session's workspace: active with machine_id.
  const owned = await env.introspect({ ...base, machine: "node-alpha" });
  assert.equal(owned.status, 200);
  assert.equal(owned.body.active, true);
  assert.equal(owned.body.machine_id, "node-alpha");
  assert.equal(owned.body.workspace, env.alpha);
  assert.deepEqual(owned.body, (await env.introspect({ ...base, workspace: env.alpha, machine: "node-alpha" })).body);
  assert.equal((await env.introspect({ ...base, workspace: null, machine: "node-alpha" })).body.machine_id, "node-alpha");

  // Claimed only in another workspace: mismatch, as with the workspace sent.
  assert.deepEqual(
    (await env.introspect({ ...base, machine: "node-beta-only" })).body,
    { active: false, reason: "machine_workspace_mismatch" },
  );
  assert.deepEqual(
    (await env.introspect({ ...base, machine: "node-nobody" })).body,
    { active: false, reason: "machine_unclaimed" },
  );
});

test("introspection refuses a second organization in single tenancy and allows it in multi", async (t) => {
  const env = await setup(t);
  const { accessToken } = await env.login(env.alpha);
  await env.database.query(
    "INSERT INTO organizations (id, name) VALUES ($1, 'Other')",
    ["00000000-0000-4000-8000-000000000002"],
  );
  const single = await env.introspect({ token: accessToken, aud: HISTORY_PUBLIC });
  assert.deepEqual(single.body, { active: false, reason: "unknown" });

  const multi = new ControlPlaneStore(
    env.database,
    { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    0,
    { tenancy: "multi" },
  );
  const session = await multi.introspectAccessToken(accessToken);
  assert.equal(session?.organizationId, env.organizationId);
  assert.equal(session?.workspaceId, env.alpha);
  assert.equal(await multi.introspectAccessToken("sh_at_not-a-real-token"), null);
});

test("introspection reports the live organization role, for add-on admin decisions", async (t) => {
  const env = await setup(t);
  const { accessToken: ownerToken } = await env.login(env.alpha);
  const active = await env.introspect({ token: ownerToken, aud: HISTORY_PUBLIC });
  assert.equal(active.body.role, "owner");

  const memberId = await env.member("member@example.test");
  await env.database.query(
    "UPDATE token_sessions SET user_id = $1 WHERE access_token_hash = $2",
    [memberId, sha256(ownerToken)],
  );
  const asMember = await env.introspect({ token: ownerToken, aud: HISTORY_PUBLIC });
  assert.equal(asMember.body.active, true);
  assert.equal(asMember.body.role, "member");

  await env.database.query(
    "UPDATE organization_memberships SET role = 'admin' WHERE user_id = $1",
    [memberId],
  );
  const promoted = await env.introspect({ token: ownerToken, aud: HISTORY_PUBLIC });
  assert.equal(promoted.body.role, "admin");
});

test("introspection carries the organization's served capture policy, read live", async (t) => {
  const env = await setup(t);
  const { accessToken } = await env.login(env.alpha);
  const unset = await env.introspect({ token: accessToken, aud: HISTORY_PUBLIC });
  assert.deepEqual(unset.body.capture_policy, { version: 1, revision: 1, settings: {} });

  const policyPath = `/api/v1/organizations/${env.organizationId}/capture-policy`;
  const set = await request(env.origin, policyPath, {
    method: "PUT",
    token: BOOTSTRAP,
    body: { settings: { user_retroactive_delete: false, upload_control: "operator" } },
  });
  assert.equal(set.status, 200);
  const enforced = await env.introspect({ token: accessToken, aud: HISTORY_PUBLIC });
  // The served projection, as GET .../capture-policy answers it (the default oops window included).
  assert.deepEqual(enforced.body.capture_policy, (await request(env.origin, policyPath, { token: BOOTSTRAP })).body);
  assert.deepEqual(enforced.body.capture_policy, {
    version: 1,
    revision: 2,
    settings: { user_retroactive_delete: false, upload_control: "operator", oops_window_seconds: 900 },
  });

  // sharing_mode new: the time it became new rides along (the pipeline refuses older sessions).
  assert.equal((await request(env.origin, policyPath, {
    method: "PUT", token: BOOTSTRAP, body: { settings: { sharing_mode: "new" } },
  })).status, 200);
  const sharingNew = await env.introspect({ token: accessToken, aud: HISTORY_PUBLIC });
  assert.deepEqual(sharingNew.body.capture_policy, (await request(env.origin, policyPath, { token: BOOTSTRAP })).body);
  assert.ok(!Number.isNaN(Date.parse(sharingNew.body.capture_policy.sharing_mode_since)));

  const cleared = await request(env.origin, policyPath, { method: "DELETE", token: BOOTSTRAP });
  assert.equal(cleared.status, 200);
  const after = await env.introspect({ token: accessToken, aud: HISTORY_PUBLIC });
  assert.deepEqual(after.body.capture_policy, { version: 1, revision: 4, settings: {} });

  // Inactive answers never carry it.
  const inactive = await env.introspect({ token: "sh_at_not-a-real-token", aud: HISTORY_PUBLIC });
  assert.deepEqual(inactive.body, { active: false, reason: "unknown" });

  // Every answer above matches the published response schema (additionalProperties: false).
  const validate = introspectionResponseValidator();
  for (const answer of [unset, enforced, sharingNew, after, inactive]) {
    assert.ok(validate(answer.body), JSON.stringify(validate.errors));
  }
});

test("an unexchanged desktop handoff is not introspectable, and its exchanged pair is", async (t) => {
  const env = await setup(t);
  const pending = await env.store.issueDesktopHandoff({
    userId: env.ownerId,
    organizationId: env.organizationId,
    workspaceId: env.alpha,
    codeChallenge: "a".repeat(43),
  });
  const refused = await env.introspect({ token: pending.accessToken, aud: HISTORY_PUBLIC });
  assert.equal(refused.status, 200);
  assert.deepEqual(refused.body, { active: false, reason: "unknown" });

  const issued = await env.store.exchangeDesktopHandoff(pending.accessToken, () => true);
  assert(issued);
  const active = await env.introspect({ token: issued.accessToken, aud: HISTORY_PUBLIC });
  assert.equal(active.body.active, true);
  assert.equal(active.body.role, "owner");
});
