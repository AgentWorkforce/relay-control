import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { NO_FEATURES } from "../src/features.js";
import { relayLaunchCredentials } from "../src/mcp/relay-launch-credentials.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { createRelaycastWorld } from "./support/relaycast-world.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * Gate-only installs (SELFHOST_RELAYGATE_PUBLIC_URL): every agent launch gets
 * a one-time `sh_lt_` launch credential that relaygate introspects (and so
 * burns) at POST /internal/v1/auth/introspect.
 */

const PUBLIC_ORIGIN = "https://control.internal.example";
const GATE = "https://gate.selfhosted.test";
const FILES = "https://files.selfhosted.test";
const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const MCP_PATH = "/api/v1/mcp/shared-sessions";
const FIRST_KEY = "rk_live_first";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };

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
  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    const headers = new Headers(init?.headers);
    const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
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
    introspectAudiences: [GATE, FILES],
    ...(options.gate ?? true ? { relaygatePublicUrl: GATE } : {}),
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
  const other = await post(`/api/v1/organizations/${org.body.id}/workspaces`, {
    name: "Other", relaycastWorkspaceId: "rc-other", relaycastApiKey: "rk_live_other",
  });
  assert.equal(other.status, 201);
  const ownerId = org.body.owner.id as string;
  const orgId = org.body.id as string;
  const workspaceId = workspace.body.id as string;
  const credentials = relayLaunchCredentials(database, KEYRING);

  /** A journaled launch row plus its credential, without going through Relaycast. */
  const issue = async (agentName = "reviewer-1", nodeName = "studio-desktop") => {
    const spawnId = randomUUID();
    await database.query(
      `INSERT INTO relay_spawns (id, workspace_id, user_id, authority_hash, relaycast_workspace_id, actor_id, idempotency_hash,
         request_hash, agent_name, cli, node_id, state, audit)
       VALUES ($1, $2, $3, 'authority', 'rc-first', 'actor', $4, 'request', $5, 'codex', 'node-1', 'reserved', '[]'::jsonb)`,
      [spawnId, workspaceId, ownerId, randomUUID(), agentName]);
    const issued = await credentials.issue({ spawnId, workspaceId, organizationId: orgId, userId: ownerId, nodeName, agentName });
    const token = await credentials.sealedFor(spawnId);
    assert.ok(token?.startsWith("sh_lt_"));
    return { spawnId, issued, token: token! };
  };
  const introspect = (body: Record<string, unknown>) =>
    request(origin, "/internal/v1/auth/introspect", { method: "POST", token: INTROSPECT_SECRET, body }) as
      Promise<{ status: number; body: Record<string, any> }>;
  const redeemedAt = async (spawnId: string) => (await database.query<{ redeemed_at: Date | null; token_ciphertext: string | null }>(
    "SELECT redeemed_at, token_ciphertext FROM relay_launch_credentials WHERE spawn_id = $1", [spawnId])).rows[0]!;
  const audits = async (action: string) => (await database.query<{ actor_id: string; target: string; workspace_id: string }>(
    "SELECT actor_id, target, workspace_id FROM admin_audit_events WHERE action = $1", [action])).rows;

  const connect = async () => {
    const started = await post("/api/v1/auth/device/start", { client_name: "mcp-test" });
    const approved = await post("/api/v1/auth/device/approve", {
      action: "approve", user_code: started.body.user_code, user_id: ownerId, workspace_id: workspaceId,
    });
    assert.equal(approved.status, 200);
    const tokens = await post("/api/v1/auth/device/token", { device_code: started.body.device_code });
    assert.equal(tokens.status, 200);
    const client = new Client({ name: "mcp-test", version: "1.0.0" });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${origin}${MCP_PATH}`),
      { requestInit: { headers: { authorization: `Bearer ${tokens.body.access_token as string}` } } }));
    t.after(() => client.close());
    return client;
  };
  const claim = (nodeId: string) => database.query(
    `INSERT INTO fleet_node_owners (id, workspace_id, organization_id, relaycast_workspace_id, node_id, node_name, user_id)
     VALUES ($1, $2, $3, 'rc-first', $4, $4, $5)`, [randomUUID(), workspaceId, orgId, nodeId, ownerId]);

  return { world, database, credentials, issue, introspect, redeemedAt, audits, connect, claim,
    ownerId, orgId, workspaceId, otherWorkspaceId: other.body.id as string };
}

test("an issued launch credential introspects once as relay_launch, then never again", async (t) => {
  const env = await setup(t);
  const { spawnId, issued, token } = await env.issue();
  const answer = await env.introspect({ token, aud: `${GATE}/v1/agent/register`, workspace: env.workspaceId });
  assert.equal(answer.status, 200);
  const iat = answer.body.iat as number;
  assert.deepEqual(answer.body, {
    active: true,
    sub: env.ownerId,
    email: null,
    principal_type: "relay_launch",
    agent_name: "reviewer-1",
    node_name: "studio-desktop",
    machine_id: null,
    org: env.orgId,
    workspace: env.workspaceId,
    scopes: ["relay:agent:enrol"],
    aud: GATE,
    iat,
    exp: Math.floor(issued.expiresAt.getTime() / 1_000),
    token_id: issued.id,
  });
  assert.ok(Math.abs(answer.body.exp - (iat + 600)) <= 1);
  assert.ok(Math.abs(iat - Date.now() / 1_000) < 60);

  // Burned: the sealed copy is gone and a second presentation is inactive.
  const burned = await env.redeemedAt(spawnId);
  assert.ok(burned.redeemed_at);
  assert.equal(burned.token_ciphertext, null);
  assert.equal(await env.credentials.sealedFor(spawnId), null);
  assert.deepEqual((await env.introspect({ token, aud: GATE })).body, { active: false, reason: "revoked" });

  const issuedAudit = await env.audits("relay_launch.credential.issued");
  const redeemedAudit = await env.audits("relay_launch.credential.redeemed");
  assert.equal(issuedAudit.length, 1);
  assert.equal(redeemedAudit.length, 1);
  for (const row of [...issuedAudit, ...redeemedAudit]) {
    assert.equal(row.actor_id, env.ownerId);
    assert.equal(row.workspace_id, env.workspaceId);
    assert.match(row.target, new RegExp(`spawn=${spawnId} node=studio-desktop agent=reviewer-1`));
    assert.equal(row.target.includes("sh_lt_"), false);
  }
  assert.match(issuedAudit[0]!.target, /expires=/);
});

test("an expired launch credential is inactive and is not burned", async (t) => {
  const env = await setup(t);
  const { spawnId, token } = await env.issue();
  await env.database.query("UPDATE relay_launch_credentials SET expires_at = now() - interval '1 second' WHERE spawn_id = $1", [spawnId]);
  assert.deepEqual((await env.introspect({ token, aud: GATE })).body, { active: false, reason: "expired" });
  assert.equal((await env.redeemedAt(spawnId)).redeemed_at, null);
  assert.equal(await env.credentials.sealedFor(spawnId), null);
  assert.equal((await env.audits("relay_launch.credential.redeemed")).length, 0);
});

test("a wrong audience, workspace or machine is inactive and leaves the credential redeemable", async (t) => {
  const env = await setup(t);
  const { spawnId, token } = await env.issue();
  assert.deepEqual((await env.introspect({ token, aud: "https://elsewhere.example" })).body, { active: false, reason: "audience" });
  assert.deepEqual((await env.introspect({ token, aud: GATE, workspace: env.otherWorkspaceId })).body,
    { active: false, reason: "workspace" });
  assert.deepEqual((await env.introspect({ token, aud: GATE, machine: "node-1" })).body,
    { active: false, reason: "machine_not_owned" });
  assert.equal((await env.redeemedAt(spawnId)).redeemed_at, null);
  assert.equal(await env.credentials.sealedFor(spawnId), token);
  // Still good for the right caller.
  assert.equal((await env.introspect({ token, aud: GATE })).body.active, true);
});

test("an unknown sh_lt_ is unknown and other prefixes keep their answers", async (t) => {
  const env = await setup(t);
  assert.deepEqual((await env.introspect({ token: "sh_lt_not-a-real-token", aud: GATE })).body, { active: false, reason: "unknown" });
  const { token } = await env.issue();
  assert.deepEqual((await env.introspect({ token: token.replace(/^sh_lt_/, "sh_xx_"), aud: GATE })).body,
    { active: false, reason: "wrong-kind" });
  assert.deepEqual((await env.introspect({ token: token.replace(/^sh_lt_/, "sh_rt_"), aud: GATE })).body,
    { active: false, reason: "wrong-kind" });
});

test("two concurrent introspections of one credential answer active once", async (t) => {
  const env = await setup(t);
  const { token } = await env.issue();
  const answers = await Promise.all([env.introspect({ token, aud: GATE }), env.introspect({ token, aud: GATE })]);
  assert.equal(answers.filter(answer => answer.body.active === true).length, 1);
  assert.equal((await env.audits("relay_launch.credential.redeemed")).length, 1);
});

test("spawn through the MCP launch tool mints one credential bound to the launch, never sent to Relaycast", async (t) => {
  const env = await setup(t);
  env.world.nodes.set(FIRST_KEY, [node("node-1", "studio-desktop")]);
  await env.claim("node-1");
  const client = await env.connect();
  const spawned = await client.callTool({ name: "spawn_relay_agent", arguments: {
    name: "reviewer-1", cli: "codex", target_node: "node-1", task: "Say hello", worker_cwd: "/work/app", idempotency_key: "launch-key-1",
  } });
  assert.notEqual(spawned.isError, true, JSON.stringify(spawned.content));
  const receipt = spawned.structuredContent as Record<string, any>;
  assert.equal(JSON.stringify(spawned).includes("sh_lt_"), false);

  const rows = await env.database.query<Record<string, any>>("SELECT * FROM relay_launch_credentials");
  assert.equal(rows.rows.length, 1);
  const row = rows.rows[0]!;
  assert.equal(row.spawn_id, receipt.spawn_id);
  assert.equal(row.node_name, "studio-desktop");
  assert.equal(row.agent_name, "reviewer-1");
  assert.equal(row.user_id, env.ownerId);
  assert.equal(row.workspace_id, env.workspaceId);
  assert.equal(row.organization_id, env.orgId);

  const sent = env.world.bodies.filter(body => body.path === "/v1/actions/spawn/invoke");
  assert.equal(sent.length, 1);
  assert.equal(JSON.stringify(env.world.bodies).includes("sh_lt_"), false);

  const token = await env.credentials.sealedFor(receipt.spawn_id);
  assert.ok(token);
  assert.equal(JSON.stringify(env.world.bodies).includes(token), false);
  assert.equal((await env.introspect({ token, aud: GATE })).body.principal_type, "relay_launch");
  assert.equal((await env.audits("relay_launch.credential.issued")).length, 1);
  assert.equal((await env.audits("relay_launch.credential.redeemed")).length, 1);

  // A same-key replay returns the receipt without minting again.
  await client.callTool({ name: "spawn_relay_agent", arguments: {
    name: "reviewer-1", cli: "codex", target_node: "node-1", task: "Say hello", worker_cwd: "/work/app", idempotency_key: "launch-key-1",
  } });
  assert.equal((await env.database.query("SELECT 1 FROM relay_launch_credentials")).rows.length, 1);
});

test("a launch Relaycast rejects outright discards its credential", async (t) => {
  const env = await setup(t);
  env.world.nodes.set(FIRST_KEY, [node("node-1", "studio-desktop")]);
  await env.claim("node-1");
  const client = await env.connect();
  env.world.spawnOutcome.mode = "rejected";
  const rejected = await client.callTool({ name: "spawn_relay_agent", arguments: {
    name: "reviewer-1", cli: "codex", target_node: "node-1", task: "Say hello", idempotency_key: "launch-key-2",
  } });
  assert.equal((rejected.structuredContent as Record<string, any>).status, "failed");
  // Minted before the send, then discarded once Relaycast refused it.
  assert.equal((await env.audits("relay_launch.credential.issued")).length, 1);
  assert.equal((await env.database.query("SELECT 1 FROM relay_launch_credentials")).rows.length, 0);
});

test("without SELFHOST_RELAYGATE_PUBLIC_URL a launch mints nothing and sh_lt_ is unknown", async (t) => {
  const env = await setup(t, { gate: false });
  env.world.nodes.set(FIRST_KEY, [node("node-1", "studio-desktop")]);
  await env.claim("node-1");
  const client = await env.connect();
  const spawned = await client.callTool({ name: "spawn_relay_agent", arguments: {
    name: "reviewer-1", cli: "codex", target_node: "node-1", task: "Say hello", idempotency_key: "launch-key-3",
  } });
  assert.notEqual(spawned.isError, true, JSON.stringify(spawned.content));
  assert.equal((await env.database.query("SELECT 1 FROM relay_launch_credentials")).rows.length, 0);
  assert.equal((await env.audits("relay_launch.credential.issued")).length, 0);
  // Even a credential that exists is not honoured while the gate is off.
  const { token } = await env.issue();
  assert.deepEqual((await env.introspect({ token, aud: GATE })).body, { active: false, reason: "unknown" });
});
