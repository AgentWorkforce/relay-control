import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { createReplicasModule } from "../src/replicas/module.js";
import { ReplicasRuntimeError, type ReplicasRuntime } from "../src/replicas/runtime.js";
import { recoverReplica } from "../src/replicas/service.js";
import { ControlPlaneStore } from "../src/store.js";
import { apiClient, BOOTSTRAP, close, listen, PGliteDatabase, type Api } from "./flows-helpers.js";
import { createRelaycastWorld, type RelaycastWorld } from "./support/relaycast-world.js";

const ISSUER = "https://api.replicas.dev";
const PUBLIC = "https://control.selfhosted.company";
const MCP_URL = `${PUBLIC}/api/v1/replicas/mcp`;
const REPLICAS_KEY = "replicas_key_" + "k".repeat(32);
const PROVIDER_ORG = "0a0a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a0a";
const ENV_A = "1a1a1a1a-1a1a-4a1a-8a1a-1a1a1a1a1a1a";
const ENV_B = "2b2b2b2b-2b2b-4b2b-8b2b-2b2b2b2b2b2b";
const ENV_C = "3c3c3c3c-3c3c-4c3c-8c3c-3c3c3c3c3c3c";
const SERVICE_TOKEN = "service-token-that-is-at-least-32-bytes";
const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });

function identityFetch(): typeof fetch {
  return (async (input: string | URL | Request) => {
    const url = String(input);
    if (url === `${ISSUER}/.well-known/openid-configuration`) return Response.json({ issuer: ISSUER, jwks_uri: `${ISSUER}/jwks` });
    if (url === `${ISSUER}/jwks`) return Response.json({ keys: [{ ...keys.publicKey.export({ format: "jwk" }), kid: "k1", alg: "RS256", use: "sig" }] });
    return new Response("{}", { status: 404 });
  }) as typeof fetch;
}

function token(claims: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  const enc = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const signing = `${enc({ alg: "RS256", kid: "k1" })}.${enc({
    iss: ISSUER, aud: MCP_URL, exp: now + 600, iat: now, jti: randomUUID(),
    organization_id: PROVIDER_ORG, environment_id: ENV_A, workspace_id: claims.workspace_id ?? WORKSPACE_1,
    creator_id: "creator-owner", creator_email: "owner@acme.test", ...claims,
  })}`;
  return `${signing}.${sign("RSA-SHA256", Buffer.from(signing), keys.privateKey).toString("base64url")}`;
}
const WORKSPACE_1 = "4d4d4d4d-4d4d-4d4d-8d4d-4d4d4d4d4d4d";
const WORKSPACE_2 = "5e5e5e5e-5e5e-4e5e-8e5e-5e5e5e5e5e5e";

function createProvider() {
  const environments = [{ id: ENV_A, name: "alpha" }, { id: ENV_B, name: "beta" }];
  const registered: Array<{ environmentId: string; id: string; body: any }> = [];
  const removed: string[] = [];
  const mode = { register: "ok" as "ok" | "fail", discover: "ok" as "ok" | "fail" };
  const runtime = {
    identity: async () => ({ organization: { id: PROVIDER_ORG, name: "Org" } }),
    environments: async () => ({ environments }),
    allEnvironments: async (key: string) => {
      assert.equal(key, REPLICAS_KEY);
      if (mode.discover === "fail") throw new ReplicasRuntimeError("unknown", "replicas_timeout");
      return { environments: [...environments], complete: true };
    },
    registerEnvironmentMcp: async (key: string, environmentId: string, body: unknown) => {
      assert.equal(key, REPLICAS_KEY);
      if (mode.register === "fail") throw new ReplicasRuntimeError("unknown", "replicas_timeout");
      const id = `mcp_${registered.length + 1}`;
      registered.push({ environmentId, id, body });
      return { id };
    },
    removeEnvironmentMcp: async (_key: string, _environmentId: string, id: string) => {
      removed.push(id);
      return null;
    },
    sleep: async () => {
      throw new Error("environment bindings never sleep compute");
    },
    exec: async () => {
      throw new Error("environment bindings never exec");
    },
  };
  return { runtime: runtime as unknown as ReplicasRuntime, environments, registered, removed, mode };
}

function relaycastFetch(world: RelaycastWorld, roster: unknown[]): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    const headers = new Headers(init?.headers);
    const bearer = (headers.get("authorization") ?? "").replace(/^Bearer /, "");
    const json = (status: number, payload: unknown) => new Response(JSON.stringify(payload), {
      status, headers: { "content-type": "application/json" },
    });
    if ((init?.method ?? "GET") === "GET" && url.pathname === "/v1/agents" && bearer.startsWith("rk_")) return json(200, { ok: true, data: roster });
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
    publicBaseUrl: PUBLIC,
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
    oauthRedirectUrl: `${PUBLIC}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${PUBLIC}/`,
  };
  const roster: unknown[] = [];
  const world = createRelaycastWorld(roster);
  const messagingFetch = relaycastFetch(world, roster);
  const provider = createProvider();
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  const replicas = createReplicasModule({
    replicas: { enabled }, config, database, relaycastFetch: messagingFetch, runtime: provider.runtime, identityFetch: identityFetch(),
  });
  const remoteAgentFetch = (async (input: string | URL | Request) => {
    if (String(input).endsWith("/whoami")) return Response.json({ organization: { id: PROVIDER_ORG, name: "Org" } });
    throw new Error("Unexpected provider request");
  }) as typeof fetch;
  const server = createServer(createApp({ config, store, replicas, messagingFetch, remoteAgentFetch }));
  const api = apiClient(await listen(server));
  t.after(async () => {
    await close(server);
    await database.close();
  });
  return { database, world, provider, replicas, api, ...await seed(api) };
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
    const issued = await api("/api/v1/auth/device/token", { method: "POST", body: { device_code: started.body.device_code } });
    assert.equal(issued.status, 200);
    return issued.body.access_token as string;
  };
  return {
    organizationId, workspaceId, ownerId: org.body.owner.id as string, memberId: member.body.userId as string,
    ownerToken: await login(org.body.owner.id as string), memberToken: await login(member.body.userId as string),
  };
}

const MCP_HEADERS = { accept: "application/json, text/event-stream" };
let rpcSequence = 0;
async function rpc(api: Api, bearer: string | null, method: string, params: Record<string, unknown> = {}) {
  return api("/api/v1/replicas/mcp", {
    method: "POST", ...(bearer ? { token: bearer } : {}), headers: MCP_HEADERS,
    body: { jsonrpc: "2.0", id: ++rpcSequence, method, params },
  });
}
const callTool = (api: Api, bearer: string, name: string, args: Record<string, unknown> = {}) =>
  rpc(api, bearer, "tools/call", { name, arguments: args });

async function count(env: Awaited<ReturnType<typeof start>>, sql: string, params: unknown[] = []) {
  return (await env.database.query<{ n: number }>(`SELECT count(*)::int AS n FROM (${sql}) q`, params)).rows[0]!.n;
}
const spawns = (env: Awaited<ReturnType<typeof start>>) =>
  count(env, "SELECT 1 FROM replica_spawns WHERE source = 'environment_identity' AND state <> 'gone'");

test("off: the endpoint answers 404 before authentication", async (t) => {
  const env = await start(t, false);
  const response = await rpc(env.api, token(), "tools/list");
  assert.equal(response.status, 404);
});

test("environment-level MCP: discovery, policies, admission order, enrolment, tools, release and revive", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, memberToken, ownerId, memberId, provider, world, database } = env;
  const base = `/api/v1/workspaces/${workspaceId}/replicas`;
  const connections = `/api/v1/workspaces/${workspaceId}/remote-agent-connections`;

  await t.test("connect discovers environments disabled and reports each", async () => {
    const saved = await api(`${connections}/replicas`, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
    assert.equal(saved.status, 200, saved.text);
    assert.equal(saved.body.connection.providerAccount, PROVIDER_ORG);
    assert.deepEqual(saved.body.environmentDiscovery, {
      status: "ok",
      environments: [
        { environmentId: ENV_A, name: "alpha", status: "discovered" },
        { environmentId: ENV_B, name: "beta", status: "discovered" },
      ],
    });
    assert.equal(provider.registered.length, 0, "connect registers nothing");
    const listed = await api(`${base}/environments`, { token: ownerToken });
    assert.equal(listed.status, 200, listed.text);
    assert.equal(listed.body.mcpUrl, MCP_URL);
    assert.equal(listed.body.allEnvironments, false);
    assert.deepEqual(listed.body.environments.map((item: any) => [item.environmentId, item.status, item.enabled]),
      [[ENV_A, "disabled", false], [ENV_B, "disabled", false]]);
    assert.equal((await api(`${base}/environments`, { token: memberToken })).status, 403);
  });

  await t.test("a not-enabled environment is refused and nothing is enrolled", async () => {
    const response = await rpc(api, token(), "tools/list");
    assert.equal(response.status, 403, response.text);
    assert.equal(response.body.error.message, "replica_environment_not_enabled");
    assert.equal(await spawns(env), 0);
    const audits = await database.query<{ target: string }>("SELECT target FROM admin_audit_events WHERE action = 'replicas.identity.refused'");
    assert.deepEqual(audits.rows.map((row) => row.target), ["replica_environment_not_enabled"]);
  });

  await t.test("an invalid or missing token is 401 and never audited", async () => {
    for (const bearer of [null, "not-a-jwt", token({ aud: `${PUBLIC}/api/v1/mcp` })]) {
      const response = await rpc(api, bearer, "tools/list");
      assert.equal(response.status, 401);
      assert.equal(response.body.error.message, "replica_identity_invalid");
      assert.match(response.headers.get("www-authenticate") ?? "", /^Bearer/);
    }
    // A person credential is not a workspace identity.
    assert.equal((await rpc(api, ownerToken, "tools/list")).status, 401);
    assert.equal(await count(env, "SELECT 1 FROM admin_audit_events WHERE action = 'replicas.identity.refused'"), 1);
  });

  await t.test("PUT validates creators and enables the policy", async () => {
    const path = `${base}/environments/${ENV_A}`;
    assert.equal((await api(path, { method: "PUT", token: memberToken, body: { enabled: true } })).status, 403);
    assert.equal((await api(path, { method: "PUT", token: ownerToken, body: { bogus: 1 } })).status, 400);
    const duplicate = await api(path, { method: "PUT", token: ownerToken,
      body: { creators: [{ creatorId: "c", userId: ownerId }, { creatorId: "c", userId: memberId }] } });
    assert.equal(duplicate.status, 400);
    const stranger = await api(path, { method: "PUT", token: ownerToken, body: { creators: [{ creatorId: "c", userId: randomUUID() }] } });
    assert.equal(stranger.status, 400);
    assert.equal((await api(`${base}/environments/${randomUUID()}`, { method: "PUT", token: ownerToken, body: { enabled: true } })).status, 404);
    const enabled = await api(path, { method: "PUT", token: ownerToken, body: { enabled: true } });
    assert.equal(enabled.status, 200, enabled.text);
    assert.equal(enabled.body.environment.status, "enabled");
  });

  await t.test("a missing or null creator mapping is refused without enrolment", async () => {
    let response = await rpc(api, token(), "tools/list");
    assert.equal(response.status, 403);
    assert.equal(response.body.error.message, "replica_creator_not_allowed");
    response = await rpc(api, token({ creator_id: null }), "tools/list");
    assert.equal(response.body.error.message, "replica_creator_not_allowed");
    assert.equal(await spawns(env), 0);
  });

  await t.test("a mapped creator enrols once; later calls reuse the binding", async () => {
    const mapped = await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken,
      body: { creators: [{ creatorId: "creator-owner", userId: ownerId }, { creatorId: "creator-member", userId: memberId }] } });
    assert.equal(mapped.status, 200, mapped.text);
    const listed = await rpc(api, token(), "tools/list");
    assert.equal(listed.status, 200, listed.text);
    assert.deepEqual(listed.body.result.tools.map((tool: any) => tool.name).sort(),
      ["check_relay_inbox", "list_relay_agents", "send_relay_message"]);
    const agent = `replicas-${WORKSPACE_1.replaceAll("-", "").slice(0, 16)}`;
    const rows = await database.query<any>("SELECT * FROM replica_spawns WHERE source = 'environment_identity'");
    assert.equal(rows.rows.length, 1);
    const row = rows.rows[0];
    assert.equal(row.replica_id, WORKSPACE_1);
    assert.equal(row.user_id, ownerId);
    assert.equal(row.agent_name, agent);
    assert.equal(row.state, "bound");
    assert.equal(row.environment_id, ENV_A);
    assert.equal(row.issuer, ISSUER);
    assert.equal(world.agents.get(agent)?.metadata.replicas_spawn_id, row.id);
    const agents = await callTool(api, token(), "list_relay_agents");
    assert.equal(agents.status, 200, agents.text);
    assert.equal(agents.body.result.structuredContent.agent, agent);
    assert.equal(await spawns(env), 1);
    assert.equal(await count(env, "SELECT 1 FROM admin_audit_events WHERE action = 'replicas.identity.enrolled'"), 1);
    // The creator hint is masked.
    const creators = await api(`${base}/environments`, { token: ownerToken });
    const policy = creators.body.environments.find((item: any) => item.environmentId === ENV_A);
    assert.equal(policy.bindings, 1);
    assert.equal(policy.creators.find((item: any) => item.creatorId === "creator-owner").emailHint, "o…@acme.test");
    assert.doesNotMatch(creators.text, /owner@acme\.test/);
  });

  await t.test("tools: send, inbox and acknowledge through the bound identity", async () => {
    const peer = world.addAgent("peer");
    const sent = await callTool(api, token(), "send_relay_message", { to: "peer", text: "hello from the replica" });
    assert.equal(sent.status, 200, sent.text);
    assert.notEqual(sent.body.result.isError, true, sent.text);
    assert.ok([...world.messages.values()].some((message) => message.text === "hello from the replica"));
    const agent = `replicas-${WORKSPACE_1.replaceAll("-", "").slice(0, 16)}`;
    await world.handle("POST", "/v1/dm", new URLSearchParams(), peer.token, { to: agent, text: "ping" }, null);
    const inbox = await callTool(api, token(), "check_relay_inbox");
    assert.equal(inbox.status, 200, inbox.text);
    const messages = inbox.body.result.structuredContent.messages as any[];
    assert.ok(messages.length >= 1, inbox.text);
    assert.ok(messages.some((message) => JSON.stringify(message).includes("ping")), inbox.text);
    const ids = world.deliveries.filter((delivery) => delivery.agent === agent && !delivery.acked).map((delivery) => delivery.id);
    assert.ok(ids.length >= 1);
    const acked = await callTool(api, token(), "check_relay_inbox", { acknowledge: ids });
    assert.equal(acked.status, 200, acked.text);
    assert.notEqual(acked.body.result.isError, true, acked.text);
    assert.ok(world.deliveries.filter((delivery) => ids.includes(delivery.id)).every((delivery) => delivery.acked));
  });

  await t.test("membership is re-read on every call", async () => {
    const memberToken2 = token({ workspace_id: WORKSPACE_2, creator_id: "creator-member" });
    assert.equal((await rpc(api, memberToken2, "tools/list")).status, 200);
    assert.equal(await spawns(env), 2);
    await database.query("DELETE FROM organization_memberships WHERE user_id = $1", [memberId]);
    const refused = await callTool(api, memberToken2, "list_relay_agents");
    assert.equal(refused.status, 403);
    assert.equal(refused.body.error.message, "replica_creator_not_allowed");
  });

  await t.test("disabling the environment refuses existing bindings", async () => {
    assert.equal((await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken, body: { enabled: false } })).status, 200);
    const refused = await callTool(api, token(), "list_relay_agents");
    assert.equal(refused.body.error.message, "replica_environment_not_enabled");
    assert.equal((await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken, body: { enabled: true } })).status, 200);
    assert.equal((await callTool(api, token(), "list_relay_agents")).status, 200);
  });

  await t.test("release writes a tombstone; only an admin revive re-admits", async () => {
    const row = (await database.query<{ id: string }>("SELECT id FROM replica_spawns WHERE replica_id = $1 AND state <> 'gone'", [WORKSPACE_1])).rows[0]!;
    const released = await api(`${base}/spawns/${row.id}`, { method: "DELETE", token: ownerToken });
    assert.equal(released.status, 200, released.text);
    const refused = await rpc(api, token(), "tools/list");
    assert.equal(refused.status, 403);
    assert.equal(refused.body.error.message, "replica_released");
    // The tombstone is checked first: it still wins once the environment is disabled.
    assert.equal((await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken, body: { enabled: false } })).status, 200);
    assert.equal((await rpc(api, token(), "tools/list")).body.error.message, "replica_released");
    assert.equal((await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken, body: { enabled: true } })).status, 200);
    assert.equal(await count(env, "SELECT 1 FROM replica_spawns WHERE replica_id = $1 AND state <> 'gone'", [WORKSPACE_1]), 0);
    const actor = { userId: ownerId, workspaceId, organizationId: env.organizationId };
    await assert.rejects(recoverReplica(env.replicas.deps, actor, row.id, WORKSPACE_1), /revive/i);
    await assert.rejects(recoverReplica(env.replicas.deps, { ...actor, userId: memberId }, row.id, WORKSPACE_1, { revive: true }));
    const revived = await recoverReplica(env.replicas.deps, actor, row.id, WORKSPACE_1, { revive: true });
    assert.equal((revived as any).revived, true);
    assert.equal(await count(env, "SELECT 1 FROM admin_audit_events WHERE action = 'replicas.identity.revived'"), 1);
    assert.equal((await rpc(api, token(), "tools/list")).status, 200);
    assert.equal(await count(env, "SELECT 1 FROM replica_spawns WHERE replica_id = $1 AND state <> 'gone'", [WORKSPACE_1]), 1);
  });

  await t.test("environment-mcp registers entries, all:true covers later environments, delete removes them", async () => {
    assert.equal((await api(`${base}/environment-mcp`, { method: "POST", token: ownerToken, body: { environmentIds: [] } })).status, 400);
    const all = await api(`${base}/environment-mcp`, { method: "POST", token: ownerToken, body: { all: true } });
    assert.equal(all.status, 200, all.text);
    assert.deepEqual(all.body.environments.map((item: any) => [item.environmentId, item.status]).sort(),
      [[ENV_A, "registered"], [ENV_B, "registered"]]);
    assert.deepEqual(provider.registered[0]!.body, {
      name: "agent-relay-replica", transport: "http",
      config: { url: MCP_URL, headers: {}, auth: { type: "workspace_identity", audience: MCP_URL } },
    });
    // Repeat registers nothing new.
    await api(`${base}/environment-mcp`, { method: "POST", token: ownerToken, body: { environmentIds: [ENV_A] } });
    assert.equal(provider.registered.length, 2);
    provider.environments.push({ id: ENV_C, name: "gamma" });
    provider.mode.register = "fail";
    const synced = await api(`${base}/environments/sync`, { method: "POST", token: ownerToken });
    assert.equal(synced.status, 200, synced.text);
    assert.deepEqual(synced.body.environments, [{ environmentId: ENV_C, status: "registration_failed", retryable: true }]);
    provider.mode.register = "ok";
    const retried = await api(`${base}/environment-mcp`, { method: "POST", token: ownerToken, body: { environmentIds: [ENV_C] } });
    assert.deepEqual(retried.body.environments, [{ environmentId: ENV_C, status: "registered" }]);
    const removed = await api(`${base}/environment-mcp`, { method: "DELETE", token: ownerToken, body: { environmentIds: [ENV_B] } });
    assert.equal(removed.status, 200, removed.text);
    assert.deepEqual(removed.body.environments, [{ environmentId: ENV_B, status: "disabled" }]);
    assert.deepEqual(provider.removed, ["mcp_2"]);
    const listed = await api(`${base}/environments`, { token: ownerToken });
    assert.deepEqual(listed.body.environments.map((item: any) => [item.environmentId, item.status]),
      [[ENV_A, "registered"], [ENV_B, "disabled"], [ENV_C, "registered"]]);
  });

  await t.test("disconnect removes entries, disables every policy and refuses tokens", async () => {
    const disconnected = await api(`${connections}/replicas`, { method: "DELETE", token: ownerToken });
    assert.equal(disconnected.status, 200, disconnected.text);
    assert.equal(provider.removed.length, 3);
    assert.equal(await count(env, "SELECT 1 FROM replica_environment_policies WHERE enabled"), 0);
    assert.equal(await count(env, "SELECT 1 FROM replica_environment_policies WHERE registered_mcp_id IS NOT NULL"), 0);
    const refused = await rpc(api, token(), "tools/list");
    assert.equal(refused.status, 403);
    assert.equal(refused.body.error.message, "replica_environment_not_enabled");
  });
});
