import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { createServer, type Server } from "node:http";
import test, { type TestContext } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createApp } from "../src/app.js";
import { loadSpawnMemoryPolicy, type SelfhostConfig } from "../src/config.js";
import { NO_FEATURES } from "../src/features.js";
import { migrate } from "../src/migrations.js";
import { launcherName } from "../src/mcp/relay-participants.js";
import { ControlPlaneStore } from "../src/store.js";
import { copilotDesktopSetup, identitiesPath } from "./support/copilot-desktop.js";
import { createRelaycastWorld } from "./support/relaycast-world.js";
import { PGliteDatabase, request } from "./support/harness.js";

/** SELFHOST_FEATURES=launch: the agent launch MCP tools (docs/agent-launch.md). */

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert(address && typeof address === "object");
  return `http://127.0.0.1:${address.port}`;
}

const PUBLIC_ORIGIN = "https://control.internal.example";
const MCP_PATH = "/api/v1/mcp/shared-sessions";
const FIRST_KEY = "rk_live_first";
const OTHER_KEY = "rk_live_other";

function node(id: string, name: string, options: { kind?: "desktop" | "broker" | null; teammates?: boolean; live?: boolean;
  harnesses?: string[]; max?: number; active?: number; memory?: { availableGiB: number; totalGiB: number } } = {}) {
  const configured: Record<string, unknown> = {};
  // A fresh relay-node sample (metadata.live) when the test gives one.
  const live = options.memory ? { live: { observed_at: new Date().toISOString(), resources: { cpus: 8, load_1m: 1,
    memory_available_bytes: options.memory.availableGiB * 1024 ** 3, memory_total_bytes: options.memory.totalGiB * 1024 ** 3 } } } : {};
  if (options.kind !== null) configured.node_kind = options.kind ?? "desktop";
  if (options.teammates !== undefined) configured.teammates = options.teammates;
  return {
    id, name, live: options.live ?? true, handlers_live: options.live ?? true,
    active_agents: options.active ?? 0, max_agents: options.max ?? 0, reserved_agents: 0,
    capabilities: (options.harnesses ?? ["codex", "claude"]).map(harness => ({ name: `spawn:${harness}`, metadata: { configured, ...live } })),
    tags: ["repo:acme/app"],
  };
}

async function setup(t: TestContext, options: { launch?: boolean; env?: Record<string, string> } = {}) {
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
    bootstrapToken: "bootstrap-token-that-is-at-least-32-bytes",
    encryptionKeyring: { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    internalServiceToken: "service-token-that-is-at-least-32-bytes",
    oauthRedirectUrl: `${PUBLIC_ORIGIN}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${PUBLIC_ORIGIN}/`,
    port: 3000,
    host: "127.0.0.1",
    ...(options.env ? { spawnMemoryPolicy: loadSpawnMemoryPolicy(options.env) } : {}),
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  const features = { ...NO_FEATURES, launch: options.launch ?? true };
  const server = createServer(createApp({ config, store, messagingFetch: fetchImpl, features }));
  const origin = await listen(server);
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await database.close();
  });
  const post = async (path: string, body: Record<string, unknown>, token = config.bootstrapToken) => {
    const response = await fetch(`${origin}${path}`, {
      method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" }, body: JSON.stringify(body),
    });
    return { status: response.status, body: await response.json() as Record<string, any> };
  };
  const org = await post("/api/v1/organizations", { name: "Tenant", ownerEmail: "owner@example.test", ownerName: "Owner" });
  assert.equal(org.status, 201);
  const workspace = await post(`/api/v1/organizations/${org.body.id}/workspaces`, {
    name: "Primary", relaycastWorkspaceId: "rc-first", relaycastApiKey: FIRST_KEY,
  });
  assert.equal(workspace.status, 201);
  const other = await post(`/api/v1/organizations/${org.body.id}/workspaces`, {
    name: "Other", relaycastWorkspaceId: "rc-other", relaycastApiKey: OTHER_KEY,
  });
  assert.equal(other.status, 201);
  const ownerId = org.body.owner.id as string;
  const started = await post("/api/v1/auth/device/start", { client_name: "mcp-test" });
  const approved = await post("/api/v1/auth/device/approve", {
    action: "approve", user_code: started.body.user_code, user_id: ownerId, workspace_id: workspace.body.id,
  });
  assert.equal(approved.status, 200);
  const tokens = await post("/api/v1/auth/device/token", { device_code: started.body.device_code });
  assert.equal(tokens.status, 200);
  const workspaceId = workspace.body.id as string;
  const orgId = org.body.id as string;
  /** Records a fleet_node_owners claim directly (the claim route is covered by its own tests). */
  const claim = async (nodeId: string, userId = ownerId, relaycastWorkspaceId = "rc-first", onWorkspace = workspaceId) => {
    await database.query(
      `INSERT INTO fleet_node_owners (id, workspace_id, organization_id, relaycast_workspace_id, node_id, node_name, user_id)
       VALUES ($1, $2, $3, $4, $5, $5, $6)`, [randomUUID(), onWorkspace, orgId, relaycastWorkspaceId, nodeId, userId]);
  };
  const setRole = (role: "owner" | "admin" | "member") => database.query(
    "UPDATE organization_memberships SET role = $1 WHERE organization_id = $2 AND user_id = $3", [role, orgId, ownerId]);
  const connect = async () => {
    const client = new Client({ name: "mcp-test", version: "1.0.0" });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${origin}${MCP_PATH}`),
      { requestInit: { headers: { authorization: `Bearer ${tokens.body.access_token as string}` } } }));
    t.after(() => client.close());
    return client;
  };
  return { world, database, workspaceId, otherWorkspaceId: other.body.id as string, orgId, ownerId, claim, setRole, connect };
}

type Env = Awaited<ReturnType<typeof setup>>;
type ToolResult = Awaited<ReturnType<Client["callTool"]>>;
function data(result: ToolResult): Record<string, any> {
  assert.notEqual(result.isError, true, JSON.stringify(result.content));
  return result.structuredContent as Record<string, any>;
}
function errorText(result: ToolResult): string {
  assert.equal(result.isError, true, JSON.stringify(result.content));
  return (result.content as Array<{ text: string }>)[0]!.text;
}
function assertNoSecrets(env: Env, result: unknown): void {
  const text = JSON.stringify(result);
  for (const agent of env.world.agents.values()) assert.equal(text.includes(agent.token), false, agent.name);
  assert.equal(text.includes(FIRST_KEY), false);
  assert.equal(text.includes("at_secret"), false);
}
const LAUNCH_TOOLS = ["get_relay_spawn_status", "list_relay_spawn_targets", "release_relay_agent", "spawn_relay_agent"];
const launch = (target_node: string, extra: Record<string, unknown> = {}) => ({
  name: "reviewer-1", cli: "codex", target_node, task: "Say hello", worker_cwd: "/work/app", idempotency_key: "launch-key-1", ...extra,
});

test("launch off (default): no launch tools, can_launch false, and the group explains how to enable it", async (t) => {
  const env = await setup(t, { launch: false });
  const client = await env.connect();
  const names = (await client.listTools()).tools.map(tool => tool.name);
  for (const name of LAUNCH_TOOLS) assert.equal(names.includes(name), false, name);
  const report = data(await client.callTool({ name: "describe_capabilities", arguments: {} }));
  assert.equal(report.workspace.can_launch, false);
  const group = report.groups.find((item: { id: string }) => item.id === "hosted_launch");
  assert.equal(group.status, "unavailable");
  assert.match(group.how_to_enable, /SELFHOST_FEATURES/);
});

test("launch on: owner sees the tools and can_launch true; a member is refused on every call", async (t) => {
  const env = await setup(t);
  const client = await env.connect();
  const names = (await client.listTools()).tools.map(tool => tool.name);
  for (const name of LAUNCH_TOOLS) assert.ok(names.includes(name), name);
  const report = data(await client.callTool({ name: "describe_capabilities", arguments: {} }));
  assert.equal(report.workspace.can_launch, true);
  assert.equal(report.groups.find((item: { id: string }) => item.id === "hosted_launch").status, "available");

  await env.setRole("admin");
  assert.equal(data(await client.callTool({ name: "describe_capabilities", arguments: {} })).workspace.can_launch, true);

  // Role is reread on every request: demotion takes effect on the next call.
  await env.setRole("member");
  const demoted = data(await client.callTool({ name: "describe_capabilities", arguments: {} }));
  assert.equal(demoted.workspace.can_launch, false);
  assert.equal(demoted.groups.find((item: { id: string }) => item.id === "hosted_launch").status, "restricted");
  env.world.nodes.set(FIRST_KEY, [node("node-1", "studio-desktop")]);
  await env.claim("node-1");
  assert.match(errorText(await client.callTool({ name: "list_relay_spawn_targets", arguments: {} })), /owners and admins/);
  assert.match(errorText(await client.callTool({ name: "spawn_relay_agent", arguments: launch("node-1") })), /owners and admins/);
  assert.equal(env.world.bodies.some(body => body.path === "/v1/actions/spawn/invoke"), false);
  assert.equal((await env.database.query("SELECT 1 FROM relay_spawns")).rows.length, 0);
});

test("targets: only this workspace's relay nodes and claims; unclaimed desktops and teammates without opt-in are not allowed", async (t) => {
  const env = await setup(t);
  // A second member of the organization owns one node.
  const otherUser = randomUUID();
  await env.database.query("INSERT INTO users (id, email, name) VALUES ($1, 'mate@example.test', 'Mate')", [otherUser]);
  await env.database.query("INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, 'member')", [env.orgId, otherUser]);
  env.world.nodes.set(FIRST_KEY, [
    node("mine", "my-desktop"),
    node("mate-closed", "mate-desktop"),
    node("mate-open", "mate-open-desktop", { teammates: true }),
    node("unclaimed", "loose-desktop"),
    node("legacy", "legacy-node", { kind: null }),
    node("broker", "shared-broker", { kind: "broker" }),
    node("asleep", "asleep-desktop", { live: false }),
  ]);
  env.world.nodes.set(OTHER_KEY, [node("foreign", "other-workspace-desktop")]);
  await env.claim("mine");
  await env.claim("mate-closed", otherUser);
  await env.claim("mate-open", otherUser);
  // A claim recorded for another workspace's relay never applies here.
  await env.claim("unclaimed", env.ownerId, "rc-other", env.otherWorkspaceId);
  const client = await env.connect();
  const result = await client.callTool({ name: "list_relay_spawn_targets", arguments: {} });
  assertNoSecrets(env, result);
  const targets = data(result).targets as Array<Record<string, any>>;
  const byId = new Map(targets.map(target => [target.target_node, target]));
  assert.deepEqual([...byId.keys()].sort(), ["broker", "legacy", "mate-closed", "mate-open", "mine", "unclaimed"]);
  assert.equal(targets[0]!.target_node, "mine");
  assert.equal(byId.get("mine")!.allowed, true);
  assert.equal(byId.get("mine")!.owner.is_you, true);
  assert.equal(byId.get("mine")!.kind, "desktop");
  assert.deepEqual(byId.get("mine")!.harnesses, ["codex", "claude"]);
  assert.deepEqual(byId.get("mine")!.repositories, ["acme/app"]);
  assert.equal(byId.get("mine")!.available_slots, null);
  assert.equal(byId.get("mate-closed")!.allowed, false);
  assert.equal(byId.get("mate-open")!.allowed, true);
  assert.equal(byId.get("unclaimed")!.allowed, false);
  assert.equal(byId.get("unclaimed")!.owner, null);
  assert.equal(byId.get("legacy")!.allowed, false);
  assert.equal(byId.get("broker")!.allowed, true);
  // The other workspace's node is never listed, and its key is never used.
  assert.equal(env.world.bodies.filter(body => body.path === "/v1/nodes").length, 1);
});

test("spawn, status and release: journaled before send, ready only when correlated, released by exact identity", async (t) => {
  const env = await setup(t);
  env.world.nodes.set(FIRST_KEY, [node("node-1", "studio-desktop")]);
  await env.claim("node-1");
  const client = await env.connect();
  const spawned = await client.callTool({ name: "spawn_relay_agent", arguments: launch("node-1") });
  assertNoSecrets(env, spawned);
  const receipt = data(spawned);
  assert.equal(receipt.status, "accepted");
  assert.equal(receipt.target_node, "node-1");
  const sent = env.world.bodies.filter(body => body.path === "/v1/actions/spawn/invoke");
  assert.equal(sent.length, 1);
  // The native selector is the node name; the launch carries verify_ready.
  assert.deepEqual(sent[0]!.body!.input, { name: "reviewer-1", cli: "codex", task: "Say hello", target_node: "studio-desktop",
    worker_cwd: "/work/app", verify_ready: true });
  // Sent as the owner's launcher participant, never as a person.
  const launcher = env.world.agents.get(launcherName(env.ownerId))!;
  assert.ok(launcher);
  const invocation = env.world.invocations.get([...env.world.invocations.keys()][0]!)!;
  assert.equal(invocation.caller_id, launcher.id);
  // A plain hosted session names no requester: the keys are absent, not null.
  assert.equal("requester_agent_id" in invocation, false);
  assert.equal("requester_name" in invocation, false);

  // Same key, same request: the receipt, never a second launch.
  assert.equal(data(await client.callTool({ name: "spawn_relay_agent", arguments: launch("node-1") })).spawn_id, receipt.spawn_id);
  assert.equal(env.world.bodies.filter(body => body.path === "/v1/actions/spawn/invoke").length, 1);
  // Same key, different request: refused.
  assert.match(errorText(await client.callTool({ name: "spawn_relay_agent", arguments: launch("node-1", { task: "Other" }) })),
    /different launch/);

  const status = data(await client.callTool({ name: "get_relay_spawn_status", arguments: { spawn_id: receipt.spawn_id } }));
  assert.equal(status.status, "ready");
  assert.equal(status.ready, true);
  assert.match(status.address, /^reviewer-1@/);

  // The launcher cannot be left while it owns a live launch.
  assert.match(errorText(await client.callTool({ name: "leave_relay", arguments: { as: launcherName(env.ownerId) } })), /Release them/);

  const workerId = env.world.agents.get("reviewer-1")!.id;
  const released = data(await client.callTool({ name: "release_relay_agent", arguments: { spawn_id: receipt.spawn_id } }));
  assert.equal(released.status, "released");
  assert.equal(env.world.agents.has("reviewer-1"), false);
  const exact = env.world.bodies.find(body => body.path === "/v1/agents/release-exact" && body.body?.name === "reviewer-1")!;
  assert.equal(exact.body!.expected_agent_id, workerId);
  // Repeat-safe.
  assert.equal(data(await client.callTool({ name: "release_relay_agent", arguments: { spawn_id: receipt.spawn_id } })).status, "released");
  const rows = await env.database.query<{ state: string; workspace_id: string }>("SELECT state, workspace_id FROM relay_spawns");
  assert.deepEqual(rows.rows.map(row => [row.state, row.workspace_id]), [["released", env.workspaceId]]);
});

test("a desktop-linked chat's launch names it as the requester; the launcher stays the caller", async (t) => {
  const env = await copilotDesktopSetup(t, { features: { ...NO_FEATURES, launch: true } });
  // Desktop signs in and syncs the chat's own relay identity; a native MCP session links to it.
  const parent = await env.desktopSignIn();
  const chat = env.world.addAgent("desk-chat", {
    source: "relay-desktop", owner_hash: createHash("sha256").update(env.ownerId).digest("hex") });
  const address = `desk-chat@cloud-${chat.id}`;
  const synced = await request(env.origin, identitiesPath(env.workspaceId), { method: "PUT", token: parent.accessToken,
    body: { source_id: randomUUID(), identities: [{ name: chat.name, address, agent_id: chat.id, token: chat.token }] } });
  assert.equal(synced.status, 200, synced.raw);
  env.world.nodes.set("rk_primary", [node("node-1", "studio-desktop")]);
  await env.database.query(
    `INSERT INTO fleet_node_owners (id, workspace_id, organization_id, relaycast_workspace_id, node_id, node_name, user_id)
     VALUES ($1, $2, $3, 'rw_primary', 'node-1', 'node-1', $4)`, [randomUUID(), env.workspaceId, env.orgId, env.ownerId]);
  const client = new Client({ name: "mcp-test", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${env.origin}${MCP_PATH}`),
    { requestInit: { headers: { authorization: `Bearer ${await env.deviceLogin()}` } } }));
  t.after(() => client.close());
  assert.equal(data(await client.callTool({ name: "join_relay", arguments: { desktop_address: address } })).linked, "desktop");

  assert.equal(data(await client.callTool({ name: "spawn_relay_agent", arguments: launch("node-1") })).status, "accepted");
  const invocation = [...env.world.invocations.values()][0]!;
  assert.equal(invocation.requester_agent_id, chat.id);
  assert.equal(invocation.requester_name, "desk-chat");
  assert.equal("requester_agent_id" in invocation.input, false);
  // Still sent as the owner's launcher participant, never as the chat.
  assert.equal(invocation.caller_id, env.world.agents.get(launcherName(env.ownerId))!.id);
  assert.notEqual(invocation.caller_id, chat.id);
});

test("another connection cannot read or release a launch, even for the same user", async (t) => {
  const env = await setup(t);
  env.world.nodes.set(FIRST_KEY, [node("node-1", "studio-desktop")]);
  await env.claim("node-1");
  const first = await env.connect();
  const receipt = data(await first.callTool({ name: "spawn_relay_agent", arguments: launch("node-1") }));
  const second = await env.connect();
  assert.match(errorText(await second.callTool({ name: "get_relay_spawn_status", arguments: { spawn_id: receipt.spawn_id } })), /not owned/);
  assert.match(errorText(await second.callTool({ name: "release_relay_agent", arguments: { spawn_id: receipt.spawn_id } })), /not owned/);
  assert.equal(env.world.agents.has("reviewer-1"), true);
});

test("admission refusals: not allowed, offline, harness, unknown target; nothing is journaled or sent", async (t) => {
  const env = await setup(t);
  env.world.nodes.set(FIRST_KEY, [
    node("unclaimed", "loose-desktop"),
    node("asleep", "asleep-desktop", { live: false }),
    node("codex-only", "codex-desktop", { harnesses: ["codex"] }),
    node("alt", "alt-desktop"),
  ]);
  env.world.nodes.set(OTHER_KEY, [node("foreign", "foreign-desktop")]);
  await env.claim("asleep");
  await env.claim("codex-only");
  await env.claim("alt");
  // Claimed in the other workspace: still unreachable from this one.
  await env.claim("foreign", env.ownerId, "rc-other", env.otherWorkspaceId);
  const client = await env.connect();
  const refusal = async (args: Record<string, unknown>) => {
    const result = await client.callTool({ name: "spawn_relay_agent", arguments: args });
    assert.equal(result.isError, true);
    return (result.structuredContent as { error: Record<string, any> }).error;
  };
  const notAllowed = await refusal(launch("unclaimed"));
  assert.equal(notAllowed.code, "spawn_target_not_allowed");
  assert.equal(notAllowed.retryable, false);
  assert.deepEqual(notAllowed.alternatives.map((item: { target_node: string }) => item.target_node).sort(), ["alt", "codex-only"]);
  assert.equal((await refusal(launch("asleep"))).code, "spawn_target_offline");
  const harness = await refusal(launch("codex-only", { cli: "claude", idempotency_key: "launch-key-2" }));
  assert.equal(harness.code, "spawn_harness_unavailable");
  assert.deepEqual(harness.advertised, ["codex"]);
  assert.equal((await refusal(launch("foreign"))).code, "spawn_target_unavailable");
  assert.equal(env.world.bodies.some(body => body.path === "/v1/actions/spawn/invoke"), false);
  assert.equal((await env.database.query("SELECT 1 FROM relay_spawns")).rows.length, 0);
});

test("a failed native launch is terminal with a redacted failure; a rejected send fails without retrying", async (t) => {
  const env = await setup(t);
  env.world.nodes.set(FIRST_KEY, [node("node-1", "studio-desktop")]);
  await env.claim("node-1");
  const client = await env.connect();
  env.world.spawnOutcome.mode = "failed";
  const receipt = data(await client.callTool({ name: "spawn_relay_agent", arguments: launch("node-1") }));
  const status = await client.callTool({ name: "get_relay_spawn_status", arguments: { spawn_id: receipt.spawn_id } });
  assertNoSecrets(env, status);
  assert.equal(status.isError, true);
  assert.equal((status.structuredContent as Record<string, any>).status, "failed");
  assert.equal((status.structuredContent as Record<string, any>).error.code, "spawn_failed");

  env.world.spawnOutcome.mode = "rejected";
  const rejected = await client.callTool({ name: "spawn_relay_agent", arguments: launch("node-1", { idempotency_key: "launch-key-3" }) });
  assert.equal(rejected.isError, true);
  const body = rejected.structuredContent as Record<string, any>;
  assert.equal(body.status, "failed");
  assert.equal(body.error.code, "spawn_capacity_exceeded");
  assert.equal(env.world.bodies.filter(item => item.path === "/v1/actions/spawn/invoke").length, 2);
});

test("a ready worker missing from the roster is never marked released without proof", async (t) => {
  const env = await setup(t);
  env.world.nodes.set(FIRST_KEY, [node("node-1", "studio-desktop")]);
  await env.claim("node-1");
  const client = await env.connect();
  const receipt = data(await client.callTool({ name: "spawn_relay_agent", arguments: launch("node-1") }));
  assert.equal(data(await client.callTool({ name: "get_relay_spawn_status", arguments: { spawn_id: receipt.spawn_id } })).status, "ready");
  env.world.agents.delete("reviewer-1");
  assert.match(errorText(await client.callTool({ name: "release_relay_agent", arguments: { spawn_id: receipt.spawn_id } })),
    /absent without a verified release/);
  const rows = await env.database.query<{ state: string }>("SELECT state FROM relay_spawns");
  assert.deepEqual(rows.rows.map(row => row.state), ["ready"]);
});

test("a lost release response is recovered by replaying the same key, even after the worker is gone", async (t) => {
  const env = await setup(t);
  env.world.nodes.set(FIRST_KEY, [node("node-1", "studio-desktop")]);
  await env.claim("node-1");
  const client = await env.connect();
  const receipt = data(await client.callTool({ name: "spawn_relay_agent", arguments: launch("node-1") }));
  assert.equal(data(await client.callTool({ name: "get_relay_spawn_status", arguments: { spawn_id: receipt.spawn_id } })).status, "ready");
  // Relaycast stops the worker but the response is lost.
  env.world.failNext("POST", "/v1/agents/release-exact", 502, { after: true });
  errorText(await client.callTool({ name: "release_relay_agent", arguments: { spawn_id: receipt.spawn_id } }));
  assert.equal(env.world.agents.has("reviewer-1"), false);
  const released = data(await client.callTool({ name: "release_relay_agent", arguments: { spawn_id: receipt.spawn_id } }));
  assert.equal(released.status, "released");
  const keys = env.world.bodies.filter(body => body.path === "/v1/agents/release-exact" && body.body?.name === "reviewer-1");
  assert.equal(keys.length, 2, "the replay reused the original request");
});

test("a failed exact release can be retried with a new attempt; the worker binding is kept", async (t) => {
  const env = await setup(t);
  env.world.nodes.set(FIRST_KEY, [node("node-1", "studio-desktop")]);
  await env.claim("node-1");
  const client = await env.connect();
  const receipt = data(await client.callTool({ name: "spawn_relay_agent", arguments: launch("node-1") }));
  assert.equal(data(await client.callTool({ name: "get_relay_spawn_status", arguments: { spawn_id: receipt.spawn_id } })).status, "ready");
  env.world.releaseOutcome.mode = "failed";
  const failed = data(await client.callTool({ name: "release_relay_agent", arguments: { spawn_id: receipt.spawn_id } }));
  assert.equal(failed.status, "releasing");
  assert.match(failed.note, /retry/);
  assert.equal(env.world.agents.has("reviewer-1"), true);
  env.world.releaseOutcome.mode = "completed";
  const released = data(await client.callTool({ name: "release_relay_agent", arguments: { spawn_id: receipt.spawn_id } }));
  assert.equal(released.status, "released");
  assert.equal(env.world.agents.has("reviewer-1"), false);
});

test("memory enforce: a desktop without the memory is refused with spawn_memory_low and the one that fits as the alternative", async (t) => {
  const env = await setup(t, { env: { SELFHOST_SPAWN_MEMORY_POLICY: "enforce" } });
  env.world.nodes.set(FIRST_KEY, [
    node("small", "small-desktop", { memory: { availableGiB: 2.5, totalGiB: 16 } }),
    node("large", "large-desktop", { memory: { availableGiB: 30, totalGiB: 64 } }),
  ]);
  await env.claim("small");
  await env.claim("large");
  const client = await env.connect();
  const report = data(await client.callTool({ name: "describe_capabilities", arguments: {} }));
  assert.equal(report.workspace.spawn_memory_policy, "enforce");

  const listed = data(await client.callTool({ name: "list_relay_spawn_targets", arguments: { harness: "claude" } }));
  assert.equal(listed.memory_policy, "enforce");
  assert.deepEqual(listed.targets.map((item: { target_node: string }) => item.target_node), ["large", "small"]);
  const small = listed.targets[1];
  assert.equal(small.admissible, false);
  assert.equal(small.memory.tier, "low");
  assert.match(small.why, /Not enough memory: 2\.5 GB free of 16 GB; it keeps 2 GB free and claude needs 1\.5 GB\./);
  assert.match(errorText(await client.callTool({ name: "list_relay_spawn_targets", arguments: { harness: "Not A Harness" } })),
    /harness|Invalid/);

  const refused = await client.callTool({ name: "spawn_relay_agent", arguments: launch("small", { cli: "claude" }) });
  assert.equal(refused.isError, true);
  const error = (refused.structuredContent as { error: Record<string, any> }).error;
  assert.equal(error.code, "spawn_memory_low");
  assert.equal(error.retryable, true);
  assert.equal(error.message, 'Node "small-desktop" has 2.5 GB free; launching claude needs 1.5 GB on top of the 2 GB it keeps free.');
  assert.equal(error.memory.reason, "available");
  assert.equal(error.memory.floor_bytes, 2 * 1024 ** 3);
  assert.deepEqual(error.alternatives.map((item: { target_node: string }) => item.target_node), ["large"]);
  assert.equal("retry_after_seconds" in error, false);
  // Refused before anything is journaled or sent.
  assert.equal(env.world.bodies.some(body => body.path === "/v1/actions/spawn/invoke"), false);
  assert.equal((await env.database.query("SELECT 1 FROM relay_spawns")).rows.length, 0);

  assert.equal(data(await client.callTool({ name: "spawn_relay_agent", arguments: launch("large", { cli: "claude" }) })).status, "accepted");
});

test("memory enforce: with no alternative the refusal suggests when to retry", async (t) => {
  const env = await setup(t, { env: { SELFHOST_SPAWN_MEMORY_POLICY: "enforce" } });
  env.world.nodes.set(FIRST_KEY, [node("small", "small-desktop", { memory: { availableGiB: 2.5, totalGiB: 16 } })]);
  await env.claim("small");
  const client = await env.connect();
  const error = (await client.callTool({ name: "spawn_relay_agent", arguments: launch("small", { cli: "claude" }) }))
    .structuredContent as { error: Record<string, any> };
  assert.equal(error.error.code, "spawn_memory_low");
  assert.deepEqual(error.error.alternatives, []);
  assert.equal(error.error.retry_after_seconds, 30);
});

test("memory observe (default): memory is reported but the same launch is accepted", async (t) => {
  const env = await setup(t);
  env.world.nodes.set(FIRST_KEY, [node("small", "small-desktop", { memory: { availableGiB: 2.5, totalGiB: 16 } })]);
  await env.claim("small");
  const client = await env.connect();
  assert.equal(data(await client.callTool({ name: "describe_capabilities", arguments: {} })).workspace.spawn_memory_policy, "observe");
  const listed = data(await client.callTool({ name: "list_relay_spawn_targets", arguments: {} }));
  assert.equal(listed.memory_policy, "observe");
  // Observe refuses nothing, so the target is admissible; memory says what enforce would do.
  assert.equal(listed.targets[0].admissible, true);
  assert.equal(listed.targets[0].memory.admissible, false);
  assert.equal(listed.targets[0].memory.need_bytes, 1.5 * 1024 ** 3);
  assert.equal(data(await client.callTool({ name: "spawn_relay_agent", arguments: launch("small", { cli: "claude" }) })).status, "accepted");
});

test("memory off: no memory fields, today's output", async (t) => {
  const env = await setup(t, { env: { SELFHOST_SPAWN_MEMORY_POLICY: "off" } });
  env.world.nodes.set(FIRST_KEY, [node("small", "small-desktop", { memory: { availableGiB: 2.5, totalGiB: 16 } })]);
  await env.claim("small");
  const client = await env.connect();
  const listed = data(await client.callTool({ name: "list_relay_spawn_targets", arguments: {} }));
  assert.equal("memory_policy" in listed, false);
  assert.equal("memory" in listed.targets[0], false);
  assert.equal(listed.targets[0].why, "Your computer.");
  assert.equal(data(await client.callTool({ name: "spawn_relay_agent", arguments: launch("small", { cli: "claude" }) })).status, "accepted");
});
