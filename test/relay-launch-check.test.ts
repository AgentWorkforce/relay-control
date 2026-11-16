import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { NO_FEATURES } from "../src/features.js";
import { relayLaunchCheck } from "../src/mcp/relay-launch-check.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { createRelaycastWorld } from "./support/relaycast-world.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * Gate-only installs (SELFHOST_RELAYGATE_PUBLIC_URL): relaygate's POST /v1/check
 * sees every agent launch, with a one-use Control-minted `sh_at_` for the
 * launching person, before Control reserves, mints or sends anything.
 */

const PUBLIC_ORIGIN = "https://control.internal.example";
const GATE = "https://gate.selfhosted.test";
const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const MCP_PATH = "/api/v1/mcp/shared-sessions";
const FIRST_KEY = "rk_live_first";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const TASK = "  Review the diff\nand say hello  ";

type GateMode = "allow" | "denied" | "classified" | "unavailable" | "throw" | "odd" | "text";
type CheckRequest = { authorization: string; contentType: string; body: unknown };

function node(id: string, name: string) {
  return {
    id, name, live: true, handlers_live: true, active_agents: 0, max_agents: 0, reserved_agents: 0,
    capabilities: ["codex"].map(harness => ({ name: `spawn:${harness}`, metadata: { configured: { node_kind: "desktop" } } })),
    tags: [],
  };
}

async function setup(t: TestContext, options: { gate?: boolean } = {}) {
  const agents: unknown[] = [];
  const world = createRelaycastWorld(agents);
  const gate = { mode: "allow" as GateMode, checks: [] as CheckRequest[] };
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    const headers = new Headers(init?.headers);
    const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (url.origin === GATE && url.pathname === "/v1/check" && init?.method === "POST") {
      gate.checks.push({ authorization: headers.get("authorization") ?? "", contentType: headers.get("content-type") ?? "",
        body: JSON.parse(String(init.body)) });
      switch (gate.mode) {
        case "allow": return json(200, { decision: "allow" });
        case "denied": return json(403, { error: "relaygate_denied" });
        case "classified": return json(403, { error: "relaygate_classified" });
        case "unavailable": return json(503, { error: "relaygate_unavailable" });
        case "odd": return json(200, { decision: "maybe" });
        case "text": return new Response("<html>bad gateway</html>", { status: 200 });
        case "throw": throw new TypeError("fetch failed");
      }
    }
    if (url.pathname === "/v1/agents" && (init?.method ?? "GET") === "GET") return json(200, { ok: true, data: agents });
    if (url.pathname === "/v1/agents/presence") return json(200, { ok: true, data: [] });
    const body = typeof init?.body === "string" && init.body ? JSON.parse(init.body) as Record<string, any> : null;
    const handled = await world.handle(init?.method ?? "GET", url.pathname, url.searchParams,
      (headers.get("authorization") ?? "").replace(/^Bearer /, ""), body, headers.get("idempotency-key"));
    return handled ? json(handled.status, handled.body) : json(404, { ok: false, error: { code: "not_found" } });
  }) as typeof fetch;
  const database = new PGliteDatabase();
  await migrate(database);
  const config: SelfhostConfig = {
    databaseUrl: "unused-in-test",
    publicBaseUrl: PUBLIC_ORIGIN,
    relaycastUrl: "http://relaycast.internal",
    relaycastPublicUrl: "https://cast.selfhosted.example",
    relayhistoryUrl: "http://history.invalid",
    relayhistoryPublicUrl: "https://history.selfhosted.test",
    sessionReadApi: { url: "http://history.invalid", publicUrl: "https://history.selfhosted.test", secret: "session-read-secret-session-read-secret-" },
    introspectSecret: INTROSPECT_SECRET,
    introspectAudiences: [GATE],
    ...(options.gate ?? true ? { relaygatePublicUrl: `${GATE}/` } : {}),
    bootstrapToken: "bootstrap-token-that-is-at-least-32-bytes",
    encryptionKeyring: KEYRING,
    internalServiceToken: "service-token-that-is-at-least-32-bytes",
    oauthRedirectUrl: `${PUBLIC_ORIGIN}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${PUBLIC_ORIGIN}/`,
    port: 3000,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  const server = createServer(createApp({ config, store, messagingFetch: fetchImpl, features: { ...NO_FEATURES, launch: true } }));
  const origin = await listen(server);
  t.after(async () => { await close(server); await database.close(); });
  const post = async (path: string, body: Record<string, unknown>, token = config.bootstrapToken) =>
    request(origin, path, { method: "POST", token, body }) as Promise<{ status: number; body: Record<string, any> }>;
  const org = await post("/api/v1/organizations", { name: "Tenant", ownerEmail: "owner@example.test", ownerName: "Owner" });
  assert.equal(org.status, 201);
  const workspace = await post(`/api/v1/organizations/${org.body.id}/workspaces`, {
    name: "Primary", relaycastWorkspaceId: "rc-first", relaycastApiKey: FIRST_KEY,
  });
  assert.equal(workspace.status, 201);
  const ownerId = org.body.owner.id as string;
  const orgId = org.body.id as string;
  const workspaceId = workspace.body.id as string;

  const introspect = (body: Record<string, unknown>) =>
    request(origin, "/internal/v1/auth/introspect", { method: "POST", token: INTROSPECT_SECRET, body }) as
      Promise<{ status: number; body: Record<string, any> }>;
  const count = async (table: string) => (await database.query(`SELECT 1 FROM ${table}`)).rows.length;
  const audits = async (action: string) => (await database.query<{ actor_id: string; target: string; workspace_id: string }>(
    "SELECT actor_id, target, workspace_id FROM admin_audit_events WHERE action = $1", [action])).rows;
  const spawnsSent = () => world.bodies.filter(body => body.path === "/v1/actions/spawn/invoke").length;

  const connect = async () => {
    const started = await post("/api/v1/auth/device/start", { client_name: "mcp-test" });
    const approved = await post("/api/v1/auth/device/approve", {
      action: "approve", user_code: started.body.user_code, user_id: ownerId, workspace_id: workspaceId,
    });
    assert.equal(approved.status, 200);
    const tokens = await post("/api/v1/auth/device/token", { device_code: started.body.device_code });
    assert.equal(tokens.status, 200);
    const callerToken = tokens.body.access_token as string;
    const client = new Client({ name: "mcp-test", version: "1.0.0" });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${origin}${MCP_PATH}`),
      { requestInit: { headers: { authorization: `Bearer ${callerToken}` } } }));
    t.after(() => client.close());
    return { client, callerToken };
  };
  await database.query(
    `INSERT INTO fleet_node_owners (id, workspace_id, organization_id, relaycast_workspace_id, node_id, node_name, user_id)
     VALUES ($1, $2, $3, 'rc-first', 'node-1', 'node-1', $4)`, [randomUUID(), workspaceId, orgId, ownerId]);
  world.nodes.set(FIRST_KEY, [node("node-1", "studio-desktop")]);

  const spawn = (client: Client, key: string) => client.callTool({ name: "spawn_relay_agent", arguments: {
    name: "reviewer-1", cli: "codex", target_node: "node-1", task: TASK, worker_cwd: "/work/app", idempotency_key: key,
  } });

  return { gate, world, store, database, introspect, count, audits, spawnsSent, connect, spawn, ownerId, orgId, workspaceId };
}

/** The check's bearer, after asserting it was a fresh sh_at_ and not the caller's own credential. */
function checkToken(check: CheckRequest, callerToken: string): string {
  assert.match(check.authorization, /^Bearer sh_at_/);
  const token = check.authorization.slice("Bearer ".length);
  assert.notEqual(token, callerToken);
  return token;
}

test("the launch-check session has no scopes, introspects active for the launching user, and revoke ends it", async (t) => {
  const env = await setup(t);
  const before = Date.now();
  const { accessToken } = await env.store.issueLaunchCheckSession({ userId: env.ownerId, organizationId: env.orgId, workspaceId: env.workspaceId });
  assert.match(accessToken, /^sh_at_/);
  const row = (await env.database.query<{ scopes: string[]; label: string; access_token_expires_at: Date; refresh_token_expires_at: Date }>(
    "SELECT scopes, label, access_token_expires_at, refresh_token_expires_at FROM token_sessions WHERE label = 'relay-launch-check'")).rows;
  assert.equal(row.length, 1);
  assert.deepEqual(row[0]!.scopes, []);
  for (const expiry of [row[0]!.access_token_expires_at, row[0]!.refresh_token_expires_at]) {
    const ms = new Date(expiry).getTime() - before;
    assert.ok(ms > 0 && ms <= 61_000, `expires in ${ms} ms`);
  }

  const active = await env.introspect({ token: accessToken, aud: GATE, workspace: env.workspaceId });
  assert.equal(active.status, 200);
  assert.equal(active.body.active, true);
  assert.equal(active.body.principal_type, "desktop-user");
  assert.equal(active.body.sub, env.ownerId);
  assert.equal(active.body.org, env.orgId);
  assert.equal(active.body.workspace, env.workspaceId);
  assert.deepEqual(active.body.scopes, []);
  assert.ok(active.body.exp - active.body.iat <= 60);

  assert.equal(await env.store.revoke(accessToken), true);
  assert.deepEqual((await env.introspect({ token: accessToken, aud: GATE })).body, { active: false, reason: "revoked" });
  assert.equal(await env.store.authenticateAccessToken(accessToken), null);
});

test("an allowed check lets the launch proceed and revokes the check token", async (t) => {
  const env = await setup(t);
  const { client, callerToken } = await env.connect();
  const spawned = await env.spawn(client, "check-allow");
  assert.notEqual(spawned.isError, true, JSON.stringify(spawned.content));
  assert.equal((spawned.structuredContent as Record<string, any>).status, "accepted");

  assert.equal(env.gate.checks.length, 1);
  const check = env.gate.checks[0]!;
  assert.equal(check.contentType, "application/json");
  assert.deepEqual(check.body, { op: "w", resource: { kind: "stream", id: `node:${env.workspaceId}/studio-desktop` }, content: TASK });
  const token = checkToken(check, callerToken);
  assert.equal(await env.store.authenticateAccessToken(token), null);
  assert.equal((await env.introspect({ token, aud: GATE })).body.reason, "revoked");

  assert.equal(await env.count("relay_spawns"), 1);
  assert.equal(await env.count("relay_launch_credentials"), 1);
  assert.equal(env.spawnsSent(), 1);
  assert.equal((await env.audits("relay_launch.check.denied")).length, 0);
  assert.equal((await env.audits("relay_launch.check.unavailable")).length, 0);

  // A same-key replay returns the receipt without a second check.
  await env.spawn(client, "check-allow");
  assert.equal(env.gate.checks.length, 1);
});

for (const [mode, code] of [["denied", "relaygate_denied"], ["classified", "relaygate_classified"]] as const) {
  test(`a ${mode} check refuses the launch (${code}) before anything is reserved or sent`, async (t) => {
    const env = await setup(t);
    env.gate.mode = mode;
    const { client, callerToken } = await env.connect();
    const refused = await env.spawn(client, `check-${mode}`);
    assert.equal(refused.isError, true);
    const error = (refused.structuredContent as { error: Record<string, any> }).error;
    assert.equal(error.code, code);
    assert.equal(error.retryable, false);
    assert.equal(error.node, "studio-desktop");
    assert.equal(JSON.stringify(refused).includes("sh_at_"), false);

    assert.equal(await env.count("relay_spawns"), 0);
    assert.equal(await env.count("relay_launch_credentials"), 0);
    assert.equal(env.spawnsSent(), 0);
    const token = checkToken(env.gate.checks[0]!, callerToken);
    assert.equal(await env.store.authenticateAccessToken(token), null);

    const rows = await env.audits("relay_launch.check.denied");
    assert.equal(rows.length, 1);
    assert.equal(rows[0]!.actor_id, env.ownerId);
    assert.equal(rows[0]!.workspace_id, env.workspaceId);
    assert.equal(rows[0]!.target, `node=studio-desktop code=${code} status=403`);

    // Nothing was cached: the same key is checked again once relaygate allows it.
    env.gate.mode = "allow";
    const retried = await env.spawn(client, `check-${mode}`);
    assert.equal((retried.structuredContent as Record<string, any>).status, "accepted");
    assert.equal(env.gate.checks.length, 2);
  });
}

for (const mode of ["unavailable", "throw", "odd", "text"] as const) {
  test(`an unanswered check (${mode}) refuses the launch as relaygate_unavailable, retryable`, async (t) => {
    const env = await setup(t);
    env.gate.mode = mode;
    const { client, callerToken } = await env.connect();
    const refused = await env.spawn(client, `check-${mode}`);
    assert.equal(refused.isError, true);
    const error = (refused.structuredContent as { error: Record<string, any> }).error;
    assert.equal(error.code, "relaygate_unavailable");
    assert.equal(error.retryable, true);
    assert.equal(error.message, "relaygate is unavailable; retry later");

    assert.equal(await env.count("relay_spawns"), 0);
    assert.equal(await env.count("relay_launch_credentials"), 0);
    assert.equal(env.spawnsSent(), 0);
    const token = checkToken(env.gate.checks[0]!, callerToken);
    assert.equal(await env.store.authenticateAccessToken(token), null);
    const rows = await env.audits("relay_launch.check.unavailable");
    assert.equal(rows.length, 1);
    assert.match(rows[0]!.target, /^node=studio-desktop status=/);
    assert.equal(rows[0]!.target.includes("Review the diff"), false);
  });
}

test("without SELFHOST_RELAYGATE_PUBLIC_URL there is no launch check", async (t) => {
  const env = await setup(t, { gate: false });
  env.gate.mode = "denied";
  const { client } = await env.connect();
  const spawned = await env.spawn(client, "check-off");
  assert.notEqual(spawned.isError, true, JSON.stringify(spawned.content));
  assert.equal(env.gate.checks.length, 0);
  assert.equal(await env.count("relay_spawns"), 1);
  assert.equal(env.spawnsSent(), 1);
  assert.equal((await env.database.query("SELECT 1 FROM token_sessions WHERE label = 'relay-launch-check'")).rows.length, 0);
});

test("relayLaunchCheck maps odd answers, normalises the URL and never logs the token or task", async () => {
  const issued: string[] = [];
  const revoked: string[] = [];
  const logged: unknown[] = [];
  const audited: unknown[][] = [];
  const answer = { status: 403, body: JSON.stringify({ error: "something_new" }) };
  const urls: string[] = [];
  const check = relayLaunchCheck({
    relaygatePublicUrl: "https://gate.example.test//",
    store: {
      issueLaunchCheckSession: async () => { const token = `sh_at_${issued.length}`; issued.push(token); return { accessToken: token }; },
      revoke: async token => { revoked.push(token); return true; },
    },
    database: { query: async (_sql: string, params?: unknown[]) => { audited.push(params ?? []); return { rows: [] } as any; }, exec: async () => {} },
    fetchImpl: (async (url: string) => { urls.push(String(url)); return new Response(answer.body, { status: answer.status }); }) as typeof fetch,
    log: (message, fields) => logged.push([message, fields]),
  });
  const input = { userId: "u", organizationId: "o", workspaceId: "w", nodeName: "n", task: "secret task text" };
  assert.deepEqual(await check.check(input), { decision: "deny", code: "relaygate_denied" });
  Object.assign(answer, { status: 500, body: "{}" });
  assert.deepEqual(await check.check(input), { decision: "unavailable" });
  Object.assign(answer, { status: 403, body: "not json" });
  assert.deepEqual(await check.check(input), { decision: "deny", code: "relaygate_denied" });
  // relaygate's own answers about this check: a rejected token or body is final, not an outage.
  Object.assign(answer, { status: 401, body: JSON.stringify({ error: "relaygate_unauthenticated" }) });
  assert.deepEqual(await check.check(input), { decision: "deny", code: "relaygate_denied" });
  Object.assign(answer, { status: 400, body: JSON.stringify({ error: "relaygate_bad_request" }) });
  assert.deepEqual(await check.check(input), { decision: "deny", code: "relaygate_denied" });
  Object.assign(answer, { status: 200, body: JSON.stringify({ decision: "allow" }) });
  assert.deepEqual(await check.check(input), { decision: "allow" });
  assert.deepEqual(urls, Array(6).fill("https://gate.example.test/v1/check"));
  assert.deepEqual(revoked, issued);
  assert.equal(logged.length, 5);
  assert.equal(audited.length, 5);
  assert.equal(JSON.stringify(audited).includes("status=401"), true);
  const leaked = JSON.stringify([logged, audited]);
  assert.equal(leaked.includes("sh_at_"), false);
  assert.equal(leaked.includes("secret task text"), false);

  // A failed mint is unavailable and leaves nothing to revoke.
  const failing = relayLaunchCheck({
    relaygatePublicUrl: "https://gate.example.test",
    store: { issueLaunchCheckSession: async () => { throw new Error("membership gone"); }, revoke: async () => { throw new Error("unreachable"); } },
    database: { query: async () => ({ rows: [] }) as any, exec: async () => {} },
    fetchImpl: (async () => { throw new Error("unreachable"); }) as typeof fetch,
    log: () => {},
  });
  assert.deepEqual(await failing.check(input), { decision: "unavailable" });
});
