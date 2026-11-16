import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import { signWebhook } from "../src/amp/webhook.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { REPLICA_MCP_READY } from "../src/replicas/mcp.js";
import { planToolGroups } from "../src/mcp/catalog.js";
import type { McpContext } from "../src/mcp/context.js";
import { registerReplicasTools } from "../src/replicas/mcp-tools.js";
import { createReplicasModule } from "../src/replicas/module.js";
import { ReplicasRuntimeError, type ReplicasRuntime } from "../src/replicas/runtime.js";
import { bindReplica, decrypt, relayFor } from "../src/replicas/service.js";
import { ControlPlaneStore } from "../src/store.js";
import { apiClient, BOOTSTRAP, close, listen, PGliteDatabase, type Api } from "./flows-helpers.js";
import { createRelaycastWorld, type RelaycastWorld } from "./support/relaycast-world.js";

const REPLICAS_KEY = "replicas_key_" + "k".repeat(32);
const ENVIRONMENT = "11111111-1111-4111-8111-111111111111";
const SERVICE_TOKEN = "service-token-that-is-at-least-32-bytes";

/** A fake Replicas provider: replicas, their chats, exec commands and injected chat messages. */
function createProvider() {
  const replicas = new Map<string, { status: string; chatId: string; harness: string }>();
  const execs: Array<{ id: string; command: string }> = [];
  const messages: Array<{ id: string; chatId: string; text: string }> = [];
  const calls: string[] = [];
  const mode = { mcp: "ok" as "ok" | "fail", message: "ok" as "ok" | "rejected" };
  let sequence = 0;
  const runtime = {
    identity: async () => ({ organization: { id: "replicas-org", name: "Org" } }),
    environments: async (key: string) => {
      assert.equal(key, REPLICAS_KEY);
      calls.push("environments");
      return { environments: [{ id: ENVIRONMENT, name: "default" }] };
    },
    create: async (key: string, input: { coding_agent: string; message: string }) => {
      assert.equal(key, REPLICAS_KEY);
      calls.push("create");
      const id = randomUUID();
      replicas.set(id, { status: "active", chatId: randomUUID(), harness: input.coding_agent });
      return { replica: { id, name: "r", status: "active" } };
    },
    get: async (_key: string, id: string) => {
      calls.push("get");
      const replica = replicas.get(id)!;
      return { replica: { id, name: "r", status: replica.status, chats: [{ id: replica.chatId, provider: replica.harness }] } };
    },
    wake: async () => null,
    sleep: async (_key: string, id: string) => {
      calls.push("sleep");
      replicas.get(id)!.status = "sleeping";
      return null;
    },
    exec: async (_key: string, id: string, command: string) => {
      execs.push({ id, command });
      if (command.includes("mcp.py")) {
        return mode.mcp === "ok"
          ? { exit_code: 0, timed_out: false, output: `${REPLICA_MCP_READY}\n` }
          : { exit_code: 1, timed_out: false, output: "provider stderr with a token" };
      }
      return { exit_code: 0, timed_out: false, output: "ready\n" };
    },
    message: async (_key: string, id: string, chatId: string, text: string) => {
      if (mode.message === "rejected") throw new ReplicasRuntimeError("rejected", "replicas_http_404", 404);
      messages.push({ id, chatId, text });
      return { status: "queued", message_id: `pm_${++sequence}` };
    },
    list: async () => ({ replicas: [], page: 1, total_pages: 0 }),
    history: async () => ({ events: [] }),
  };
  return { runtime: runtime as unknown as ReplicasRuntime, replicas, execs, messages, calls, mode };
}

/** The shared fake Relaycast, plus the roster list it does not serve itself. */
function relaycastFetch(world: RelaycastWorld, roster: unknown[]): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    const headers = new Headers(init?.headers);
    const bearer = (headers.get("authorization") ?? "").replace(/^Bearer /, "");
    const json = (status: number, payload: unknown) => new Response(JSON.stringify(payload), {
      status, headers: { "content-type": "application/json" },
    });
    if ((init?.method ?? "GET") === "GET" && url.pathname === "/v1/agents" && bearer.startsWith("rk_")) {
      return json(200, { ok: true, data: roster });
    }
    const body = typeof init?.body === "string" && init.body ? JSON.parse(init.body) as Record<string, any> : null;
    const handled = await world.handle(init?.method ?? "GET", url.pathname, url.searchParams, bearer, body, headers.get("idempotency-key"));
    return handled ? json(handled.status, handled.body) : json(404, { ok: false, error: { code: "not_found" } });
  }) as typeof fetch;
}

async function start(t: TestContext, enabled = true) {
  const database = new PGliteDatabase();
  await migrate(database);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: "https://control.selfhosted.company",
    relaycastUrl: "http://relaycast.relay.svc.cluster.local",
    relaycastPublicUrl: "https://relaycast.selfhosted.company",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.selfhosted.company",
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: "https://history.selfhosted.company", secret: "session-read-secret-".repeat(2) },
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    port: 3000,
    host: "127.0.0.1",
    internalServiceToken: SERVICE_TOKEN,
    oauthRedirectUrl: "https://control.selfhosted.company/api/v1/integrations/oauth/callback",
    dashboardUrl: "https://control.selfhosted.company/",
  };
  const roster: unknown[] = [];
  const world = createRelaycastWorld(roster);
  const messagingFetch = relaycastFetch(world, roster);
  const provider = createProvider();
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  const replicas = createReplicasModule({
    replicas: { enabled }, config, database, relaycastFetch: messagingFetch, runtime: provider.runtime,
  });
  const remoteAgentFetch = (async (input: string | URL | Request) => {
    if (String(input).endsWith("/whoami")) return Response.json({ organization: { id: "replicas-org", name: "Org" } });
    throw new Error("Unexpected provider request");
  }) as typeof fetch;
  const server = createServer(createApp({ config, store, replicas, messagingFetch, remoteAgentFetch }));
  const api = apiClient(await listen(server));
  t.after(async () => {
    await close(server);
    await database.close();
  });
  return { database, world, roster, provider, replicas, api, ...await seed(api) };
}

async function seed(api: Api) {
  const org = await api("/api/v1/organizations", {
    method: "POST", token: BOOTSTRAP, body: { name: "Acme", ownerEmail: "owner@acme.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const organizationId = org.body.id as string;
  const created = await api(`/api/v1/organizations/${organizationId}/workspaces`, {
    method: "POST", token: BOOTSTRAP, body: { name: "primary", relaycastWorkspaceId: "rc-primary", relaycastApiKey: "rk_live_primary" },
  });
  assert.equal(created.status, 201);
  const workspaceId = created.body.id as string;
  const member = await api(`/api/v1/organizations/${organizationId}/memberships`, {
    method: "POST", token: BOOTSTRAP, body: { email: "member@acme.test", name: "member", role: "member" },
  });
  assert.equal(member.status, 200);
  const login = async (userId: string) => {
    const started = await api("/api/v1/auth/device/start", { method: "POST", body: {} });
    const approved = await api("/api/v1/auth/device/approve", {
      method: "POST", token: BOOTSTRAP,
      body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: workspaceId },
    });
    assert.equal(approved.status, 200);
    const token = await api("/api/v1/auth/device/token", { method: "POST", body: { device_code: started.body.device_code } });
    assert.equal(token.status, 200);
    return token.body.access_token as string;
  };
  return {
    organizationId, workspaceId, ownerId: org.body.owner.id as string, memberId: member.body.userId as string,
    ownerToken: await login(org.body.owner.id as string),
    memberToken: await login(member.body.userId as string),
  };
}

test("Replicas bridge: spawn, MCP provisioning retry, capability, relay events, dashboard and release", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, memberToken, world, provider, database } = env;
  const base = `/api/v1/workspaces/${workspaceId}/replicas`;
  const connections = `/api/v1/workspaces/${workspaceId}/remote-agent-connections`;
  let spawnId = "";
  let agent = "";
  let secret = "";

  await t.test("the connection advertises the relay binding when Replicas is enabled", async () => {
    const saved = await api(`${connections}/replicas`, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
    assert.equal(saved.status, 200, saved.text);
    const listed = await api(connections, { token: ownerToken });
    assert.equal(listed.status, 200);
    const replicas = listed.body.providers.find((p: any) => p.id === "replicas");
    assert.equal(replicas.capabilities.relayBinding, true);
    assert.ok(listed.body.providers.filter((p: any) => p.id !== "replicas").every((p: any) => !p.capabilities.relayBinding));
  });

  await t.test("members and unauthenticated callers are refused before provider I/O", async () => {
    const before = provider.calls.length;
    assert.equal((await api(base)).status, 401);
    const refused = await api(`${base}/environments`, { token: memberToken });
    assert.equal(refused.status, 403);
    assert.match(refused.body.error, /owners and admins/);
    assert.equal((await api(`${base}/spawns`, { method: "POST", token: memberToken, body: {} })).status, 403);
    assert.equal((await api(`${base}/environments`, { token: SERVICE_TOKEN })).status, 403);
    assert.equal(provider.calls.length, before);
  });

  await t.test("environments come from the workspace key", async () => {
    const listed = await api(`${base}/environments`, { token: ownerToken });
    assert.equal(listed.status, 200, listed.text);
    assert.deepEqual(listed.body, { environments: [{ id: ENVIRONMENT, name: "default" }] });
    assert.equal(listed.headers.get("cache-control"), "no-store");
  });

  await t.test("spawn creates the replica; a failed MCP install reports a structured provisioning_error", async () => {
    world.addAgent("peer");
    provider.mode.mcp = "fail";
    const body = { client_request_id: "req-1", environment_id: ENVIRONMENT, name: "worker", task: "Fix the flaky test", report_to: "peer" };
    const spawned = await api(`${base}/spawns`, { method: "POST", token: ownerToken, body });
    assert.equal(spawned.status, 201, spawned.text);
    assert.equal(spawned.body.status, "preparing");
    spawnId = spawned.body.spawn_id;
    agent = `replicas-${spawnId.replaceAll("-", "").slice(0, 16)}`;
    // The same request id replays the same launch; different options under it are refused.
    assert.equal((await api(`${base}/spawns`, { method: "POST", token: ownerToken, body })).body.spawn_id, spawnId);
    assert.equal((await api(`${base}/spawns`, { method: "POST", token: ownerToken, body: { ...body, task: "other" } })).status, 409);
    assert.equal(provider.calls.filter((call) => call === "create").length, 1);

    const failed = await api(`${base}/spawns/${spawnId}`, { token: ownerToken });
    assert.equal(failed.status, 200, failed.text);
    assert.equal(failed.body.status, "binding");
    assert.deepEqual(failed.body.provisioning_error, { code: "relay_mcp_provisioning_failed", stage: "relay_mcp", retryable: true });
    assert.equal(failed.text.includes("provider stderr"), false);
    assert.equal(provider.messages.length, 0, "the task is not dispatched without the MCP");
    assert.ok(world.agents.has(agent));

    const dashboard = await api(base, { token: ownerToken });
    assert.equal(dashboard.status, 200);
    assert.equal(dashboard.body.connection.keyHint, "…kkkk");
    assert.equal(dashboard.text.includes(REPLICAS_KEY), false);
    assert.equal(dashboard.body.spawns[0].id, spawnId);
    assert.equal(dashboard.body.spawns[0].provisioning_error.code, "relay_mcp_provisioning_failed");
  });

  await t.test("a status retry provisions the MCP, subscribes and dispatches the task once", async () => {
    provider.mode.mcp = "ok";
    const bound = await api(`${base}/spawns/${spawnId}`, { token: ownerToken });
    assert.equal(bound.status, 200, bound.text);
    assert.equal(bound.body.status, "bound", bound.text);
    assert.deepEqual(bound.body.binding, { state: "bound", agent });
    assert.equal(bound.body.provisioning_error, undefined);
    assert.equal(provider.messages.length, 1);
    assert.match(provider.messages[0]!.text, new RegExp(`You are on Agent Relay as ${agent}\\.`));
    assert.match(provider.messages[0]!.text, /report to peer through Agent Relay/);
    assert.match(provider.messages[0]!.text, /Fix the flaky test$/);
    assert.equal(world.subscriptions.size, 2);
    for (const subscription of world.subscriptions.values()) {
      assert.equal(subscription.url, `https://control.selfhosted.company/api/v1/replicas/relay-events/${spawnId}`);
    }
    const again = await api(`${base}/spawns/${spawnId}`, { token: ownerToken });
    assert.equal(again.body.status, "bound");
    assert.equal(provider.messages.length, 1);

    // The helper install carries only the capability URL and secret, never a provider or Relay key.
    for (const exec of provider.execs) {
      assert.equal(exec.command.includes(REPLICAS_KEY), false);
      assert.equal(exec.command.includes("rk_live_primary"), false);
      assert.equal(exec.command.includes(world.agents.get(agent)!.token), false);
    }
    const audit = await database.query<{ action: string }>(
      "SELECT action FROM admin_audit_events WHERE action LIKE 'replicas.%'");
    const actions = audit.rows.map((row) => row.action);
    for (const action of ["replicas.spawn.created", "replicas.mcp.failed", "replicas.mcp.provisioned", "replicas.spawn.bound"]) {
      assert.ok(actions.includes(action), action);
    }
    const row = await database.query<{ helper_ciphertext: string }>("SELECT helper_ciphertext FROM replica_spawns WHERE id = $1", [spawnId]);
    secret = decrypt(env.replicas.deps, row.rows[0]!.helper_ciphertext);
  });

  await t.test("the capability lists agents and sends as the bound identity only", async () => {
    const path = `/api/v1/replicas/agents/${spawnId}/messages`;
    assert.equal((await api(path, { method: "POST", body: { action: "list_relay_agents" } })).status, 401);
    assert.equal((await api(path, { method: "POST", token: "x".repeat(43), body: { action: "list_relay_agents" } })).status, 401);
    assert.equal((await api(path, { method: "POST", token: ownerToken, body: { action: "list_relay_agents" } })).status, 401);
    const listed = await api(path, { method: "POST", token: secret, body: { action: "list_relay_agents" } });
    assert.equal(listed.status, 200, listed.text);
    assert.equal(listed.body.agent, agent);
    assert.ok(listed.body.agents.some((entry: any) => entry.name === "peer"));
    assert.equal((await api(path, { method: "POST", token: secret, body: { action: "spawn_relay_agent" } })).status, 400);

    const requestId = randomUUID();
    const sent = await api(path, { method: "POST", token: secret, body: { to: "peer", text: "done", request_id: requestId } });
    assert.equal(sent.status, 200, sent.text);
    const retried = await api(path, { method: "POST", token: secret, body: { to: "peer", text: "done", request_id: requestId } });
    assert.equal(retried.status, 200);
    const delivered = world.pending("peer");
    assert.equal(delivered.length, 1, "a retried request id is one message");
    assert.equal(delivered[0]!.message.agent_name, agent);
    assert.equal((await api(path, { method: "POST", token: secret, body: { to: "peer", text: "x" } })).status, 400);

    const used = await database.query("SELECT 1 FROM admin_audit_events WHERE action = 'replicas.capability.used'");
    assert.ok(used.rows.length >= 3);
    const leaked = await database.query("SELECT 1 FROM admin_audit_events WHERE coalesce(target, '') LIKE $1", [`%${secret}%`]);
    assert.equal(leaked.rows.length, 0);
  });

  await t.test("signed relay events reach the chat once; unsigned or forged ones do not", async () => {
    const subscription = [...world.subscriptions.values()].find((item) => item.events.includes("dm.received"))!;
    const path = `/api/v1/replicas/relay-events/${spawnId}`;
    const event = JSON.stringify({ type: "dm.received", data: { to: agent, message: { id: "9001", agent_name: "peer", text: "status?" } } });
    const signed = (body: string, key = subscription.secret) => {
      const id = `msg_${randomUUID()}`;
      const ts = Math.floor(Date.now() / 1000);
      return { "webhook-id": id, "webhook-timestamp": String(ts), "webhook-signature": signWebhook(key, id, ts, body) };
    };
    assert.equal((await api(path, { method: "POST", raw: event })).status, 401);
    assert.equal((await api(path, { method: "POST", raw: event, headers: signed(event, "whsec_" + Buffer.alloc(32, 1).toString("base64")) })).status, 401);
    const before = provider.messages.length;
    const delivered = await api(path, { method: "POST", raw: event, headers: signed(event) });
    assert.equal(delivered.status, 200, delivered.text);
    assert.deepEqual(delivered.body, { ok: true, delivered: true });
    assert.equal(provider.messages.length, before + 1);
    const prompt = provider.messages.at(-1)!.text;
    assert.match(prompt, /^\[via Agent Relay — from "peer" to @replicas-[0-9a-f]{16}; message 9001\]/);
    assert.match(prompt, /send_relay_message/);
    assert.match(prompt, /status\?$/);
    const duplicate = await api(path, { method: "POST", raw: event, headers: signed(event) });
    assert.deepEqual(duplicate.body, { ok: true, duplicate: true });
    assert.equal(provider.messages.length, before + 1);
    const other = JSON.stringify({ type: "dm.received", data: { to: "someone-else", message: { id: "9002", agent_name: "peer", text: "hi" } } });
    assert.deepEqual((await api(path, { method: "POST", raw: other, headers: signed(other) })).body, { ok: true, delivered: false });
  });

  await t.test("release revokes the capability first, then removes subscriptions, identity and compute", async () => {
    assert.equal((await api(`${base}/spawns/${spawnId}`, { method: "DELETE", token: memberToken })).status, 403);
    const released = await api(`${base}/spawns/${spawnId}`, { method: "DELETE", token: ownerToken });
    assert.equal(released.status, 200, released.text);
    assert.equal(released.body.released, true);
    assert.equal(world.subscriptions.size, 0);
    assert.equal(world.agents.has(agent), false);
    assert.ok(provider.calls.includes("sleep"));
    const path = `/api/v1/replicas/agents/${spawnId}/messages`;
    assert.equal((await api(path, { method: "POST", token: secret, body: { action: "list_relay_agents" } })).status, 401);
    const stored = await database.query<{ state: string; helper_hash: string | null; token_ciphertext: string | null }>(
      "SELECT state, helper_hash, token_ciphertext FROM replica_spawns WHERE id = $1", [spawnId]);
    assert.equal(stored.rows[0]!.state, "gone");
    assert.equal(stored.rows[0]!.helper_hash, null);
    assert.equal(stored.rows[0]!.token_ciphertext, null);
    const repeat = await api(`${base}/spawns/${spawnId}`, { method: "DELETE", token: ownerToken });
    assert.equal(repeat.status, 200);
    assert.ok((await database.query("SELECT 1 FROM admin_audit_events WHERE action = 'replicas.spawn.released'")).rows.length >= 1);
    assert.deepEqual((await api(base, { token: ownerToken })).body.spawns, []);
  });
});

test("Replicas off: every bridge route is 404 before auth and the connection has no relay binding", async (t) => {
  const { api, workspaceId, ownerToken, provider } = await start(t, false);
  for (const [method, path] of [
    ["GET", `/api/v1/workspaces/${workspaceId}/replicas`],
    ["POST", `/api/v1/workspaces/${workspaceId}/replicas/spawns`],
    ["POST", `/api/v1/replicas/agents/${randomUUID()}/messages`],
    ["POST", `/api/v1/replicas/relay-events/${randomUUID()}`],
  ] as const) {
    const response = await api(path, { method, ...(method === "POST" ? { body: {} } : {}) });
    assert.equal(response.status, 404, path);
  }
  assert.equal((await api(`/api/v1/workspaces/${workspaceId}/remote-agent-connections/replicas`, {
    method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } })).status, 200);
  const listed = await api(`/api/v1/workspaces/${workspaceId}/remote-agent-connections`, { token: ownerToken });
  assert.equal(listed.body.providers.find((p: any) => p.id === "replicas").capabilities.relayBinding, false);
  assert.equal(provider.calls.length, 0);
});

test("Replicas MCP tools exist only when enabled and re-read the person's role", async (t) => {
  assert.equal(planToolGroups().some((entry) => entry.group === "replicas"), false);
  assert.deepEqual(planToolGroups({ replicas: true }).find((entry) => entry.group === "replicas")?.tools, [
    "list_replicas_environments", "spawn_replica", "get_replica_spawn", "recover_replica_spawn", "bind_replica", "release_replica"]);
  const env = await start(t);
  assert.equal((await env.api(`/api/v1/workspaces/${env.workspaceId}/remote-agent-connections/replicas`, {
    method: "POST", token: env.ownerToken, body: { key: REPLICAS_KEY } })).status, 200);
  type Tool = { schema: { inputSchema: Record<string, unknown> }; handler: (args: any) => Promise<any> };
  const toolsFor = (userId: string) => {
    const tools = new Map<string, Tool>();
    const server = { registerTool: (name: string, schema: Tool["schema"], handler: Tool["handler"]) => tools.set(name, { schema, handler }) };
    const context = {
      principal: { userId, workspaceId: env.workspaceId, organizationId: env.organizationId, role: "owner", scopes: ["cli:auth"] },
      workspace: { id: env.workspaceId, organizationId: env.organizationId },
    } as unknown as McpContext;
    registerReplicasTools(server as never, context, env.replicas.deps);
    return tools;
  };
  const memberTools = toolsFor(env.memberId);
  assert.equal(memberTools.size, 6);
  for (const tool of memberTools.values()) {
    assert.equal(Object.keys(tool.schema.inputSchema).some((key) => /user|role|workspace|org/i.test(key)), false);
  }
  // The context claims "owner"; the database role decides.
  const refused = await memberTools.get("list_replicas_environments")!.handler({});
  assert.equal(refused.isError, true);
  assert.match(refused.content[0].text, /owners and admins/);
  const listed = await toolsFor(env.ownerId).get("list_replicas_environments")!.handler({});
  assert.equal(listed.isError, undefined);
  assert.deepEqual(listed.structuredContent, { environments: [{ id: ENVIRONMENT, name: "default" }] });
});

test("Replicas bridge: unpinned relay, live delivery while MCP setup is retried, one MCP entry across rebinds", async (t) => {
  const env = await start(t);
  const { api, workspaceId, organizationId, ownerId, ownerToken, world, provider, database } = env;
  const deps = env.replicas.deps;
  const base = `/api/v1/workspaces/${workspaceId}/replicas`;
  assert.equal((await api(`/api/v1/workspaces/${workspaceId}/remote-agent-connections/replicas`, {
    method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } })).status, 200);
  world.addAgent("peer");
  const scope = { workspaceId, userId: ownerId };

  await t.test("an unpinned relay (null or undefined) resolves the canonical workspace relay; a pin stays strict", async () => {
    assert.equal((await relayFor(deps, database, scope, null)).relaycastWorkspaceId, "rc-primary");
    assert.equal((await relayFor(deps, database, scope, undefined)).relaycastWorkspaceId, "rc-primary");
    assert.equal((await relayFor(deps, database, scope, "rc-primary")).relaycastWorkspaceId, "rc-primary");
    await assert.rejects(relayFor(deps, database, scope, "rc-other"), { status: 409, message: /relay is unavailable/ });
  });

  const spawned = await api(`${base}/spawns`, { method: "POST", token: ownerToken,
    body: { client_request_id: "req-live", environment_id: ENVIRONMENT, name: "w", task: "t" } });
  assert.equal(spawned.status, 201, spawned.text);
  const spawnId = spawned.body.spawn_id as string;
  const capability = `/api/v1/replicas/agents/${spawnId}/messages`;
  let secret = "";

  await t.test("first bind of a row with a null relay pin binds through the canonical relay", async () => {
    const before = await database.query<{ relay_workspace_id: string | null }>(
      "SELECT relay_workspace_id FROM replica_spawns WHERE id = $1", [spawnId]);
    assert.equal(before.rows[0]!.relay_workspace_id, null);
    const bound = await api(`${base}/spawns/${spawnId}`, { token: ownerToken });
    assert.equal(bound.body.status, "bound", bound.text);
    assert.equal(bound.body.error, undefined);
    const row = await database.query<{ relay_workspace_id: string; helper_ciphertext: string }>(
      "SELECT relay_workspace_id, helper_ciphertext FROM replica_spawns WHERE id = $1", [spawnId]);
    assert.equal(row.rows[0]!.relay_workspace_id, "rc-primary");
    secret = decrypt(deps, row.rows[0]!.helper_ciphertext);
    // A persisted pin that no longer matches is refused, never re-resolved to another relay.
    await database.query("UPDATE replica_spawns SET relay_workspace_id = 'rc-other' WHERE id = $1", [spawnId]);
    const crossed = await api(capability, { method: "POST", token: secret, body: { to: "peer", text: "x", request_id: randomUUID() } });
    assert.equal(crossed.status, 409);
    assert.equal(world.pending("peer").length, 0);
    await database.query("UPDATE replica_spawns SET relay_workspace_id = 'rc-primary' WHERE id = $1", [spawnId]);
  });

  await t.test("a status read of a bound replica whose MCP setup fails keeps helper sends and signed delivery live", async () => {
    await database.query("UPDATE replica_spawns SET input = input - 'relay_mcp_version' WHERE id = $1", [spawnId]);
    provider.mode.mcp = "fail";
    const pending = await api(`${base}/spawns/${spawnId}`, { token: ownerToken });
    assert.equal(pending.status, 200, pending.text);
    assert.equal(pending.body.status, "binding");
    assert.equal(pending.body.provisioning_error.code, "relay_mcp_provisioning_failed");
    const stored = await database.query<{ state: string }>("SELECT state FROM replica_spawns WHERE id = $1", [spawnId]);
    assert.equal(stored.rows[0]!.state, "bound");
    // Settings (the workspace list) and the launch view report the same native readiness.
    const listed = (await api(base, { token: ownerToken })).body.spawns.find((item: any) => item.id === spawnId);
    assert.equal(listed.status, pending.body.status);
    assert.equal(listed.input, undefined);
    const sent = await api(capability, { method: "POST", token: secret, body: { to: "peer", text: "still here", request_id: randomUUID() } });
    assert.equal(sent.status, 200, sent.text);
    assert.equal(world.pending("peer").length, 1);
    const subscription = [...world.subscriptions.values()].find((item) => item.events.includes("dm.received"))!;
    const agent = `replicas-${spawnId.replaceAll("-", "").slice(0, 16)}`;
    const event = JSON.stringify({ type: "dm.received", data: { to: agent, message: { id: "7001", agent_name: "peer", text: "ping" } } });
    const id = `msg_${randomUUID()}`;
    const ts = Math.floor(Date.now() / 1000);
    const delivered = await api(`/api/v1/replicas/relay-events/${spawnId}`, { method: "POST", raw: event,
      headers: { "webhook-id": id, "webhook-timestamp": String(ts), "webhook-signature": signWebhook(subscription.secret, id, ts, event) } });
    assert.deepEqual(delivered.body, { ok: true, delivered: true });
    provider.mode.mcp = "ok";
    const healed = await api(`${base}/spawns/${spawnId}`, { token: ownerToken });
    assert.equal(healed.body.status, "bound");
    assert.equal(healed.body.provisioning_error, undefined);
    assert.equal((await api(base, { token: ownerToken })).body.spawns.find((item: any) => item.id === spawnId).status, "bound");
  });

  await t.test("a rebind reuses the one agent-relay-replica MCP entry; release still revokes at once", async () => {
    const replicaId = (await database.query<{ replica_id: string; chat_id: string }>(
      "SELECT replica_id, chat_id FROM replica_spawns WHERE id = $1", [spawnId])).rows[0]!;
    assert.equal((await api(`${base}/spawns/${spawnId}`, { method: "DELETE", token: ownerToken })).status, 200);
    assert.equal((await api(capability, { method: "POST", token: secret, body: { action: "list_relay_agents" } })).status, 401);
    provider.replicas.get(replicaId.replica_id)!.status = "active";
    const actor = { workspaceId, userId: ownerId, organizationId };
    const rebound = await bindReplica(deps, actor, { replica_id: replicaId.replica_id, chat_id: replicaId.chat_id }) as { status: string; spawn_id: string };
    assert.equal(rebound.status, "bound");
    assert.notEqual(rebound.spawn_id, spawnId);
    const installs = provider.execs.filter((item) => item.id === replicaId.replica_id && item.command.includes("mcp.py"));
    assert.equal(installs.length, 4, "first bind, failed retry, healed retry and the rebind each ran the installer");
    const names = new Set<string>();
    for (const exec of installs) {
      const encoded = /b64decode\([^A-Za-z0-9+/=]*([A-Za-z0-9+/=]{20,})/.exec(exec.command)![1]!;
      names.add(JSON.parse(Buffer.from(encoded, "base64").toString("utf8")).name);
    }
    assert.deepEqual([...names], ["agent-relay-replica"]);
    // The rebind's installer is told every launch recorded for this replica, so a
    // verified per-launch entry left by an older installer is removed.
    assert.deepEqual(new Set(JSON.parse(Buffer.from(/b64decode\([^A-Za-z0-9+/=]*([A-Za-z0-9+/=]{20,})/.exec(installs.at(-1)!.command)![1]!, "base64").toString("utf8")).legacy_names),
      new Set([`agent-relay-${spawnId}`, `agent-relay-${rebound.spawn_id}`]));
    // The old capability stays revoked; only the rebind's capability works.
    assert.equal((await api(capability, { method: "POST", token: secret, body: { action: "list_relay_agents" } })).status, 401);
    const fresh = await database.query<{ helper_ciphertext: string }>("SELECT helper_ciphertext FROM replica_spawns WHERE id = $1", [rebound.spawn_id]);
    const next = decrypt(deps, fresh.rows[0]!.helper_ciphertext);
    assert.notEqual(next, secret);
    const listed = await api(`/api/v1/replicas/agents/${rebound.spawn_id}/messages`, { method: "POST", token: next, body: { action: "list_relay_agents" } });
    assert.equal(listed.status, 200, listed.text);
  });
});
