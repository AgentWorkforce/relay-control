import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { createReplicasModule } from "../src/replicas/module.js";
import { ReplicasRuntimeError, type ReplicasRuntime } from "../src/replicas/runtime.js";
import { ProvisionError, type RelaycastProvisioner } from "../src/identity/bootstrap.js";
import { recoverReplica, releaseReplica, spawnReplica, type ReplicasDeps } from "../src/replicas/service.js";
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
  // The provider's current MCP entries per environment.
  const entries = new Map<string, Array<Record<string, unknown>>>();
  const entriesOf = (environmentId: string) => entries.get(environmentId) ?? (entries.set(environmentId, []), entries.get(environmentId)!);
  // fail: a timeout with nothing created; lost: created, then the answer is lost; conflict: 409 (the entry may exist).
  const mode = { register: "ok" as "ok" | "fail" | "reject" | "lost" | "conflict", discover: "ok" as "ok" | "fail" };
  const runtime = {
    identity: async () => ({ organization: { id: PROVIDER_ORG, name: "Org" } }),
    environments: async () => ({ environments }),
    allEnvironments: async (key: string) => {
      assert.equal(key, REPLICAS_KEY);
      if (mode.discover === "fail") throw new ReplicasRuntimeError("unknown", "replicas_timeout");
      return { environments: [...environments], complete: true };
    },
    listEnvironmentMcps: async (key: string, environmentId: string) => {
      assert.equal(key, REPLICAS_KEY);
      return entriesOf(environmentId).map((entry) => structuredClone(entry));
    },
    registerEnvironmentMcp: async (key: string, environmentId: string, body: any) => {
      assert.equal(key, REPLICAS_KEY);
      if (mode.register === "fail") throw new ReplicasRuntimeError("unknown", "replicas_timeout");
      if (mode.register === "reject") throw new ReplicasRuntimeError("rejected", "replicas_rejected", 422);
      if (mode.register === "conflict") throw new ReplicasRuntimeError("rejected", "replicas_rejected", 409);
      const id = `mcp_${registered.length + 1}`;
      registered.push({ environmentId, id, body });
      entriesOf(environmentId).push({ id, organization_id: PROVIDER_ORG, environment_id: environmentId, ...structuredClone(body) });
      if (mode.register === "lost") throw new ReplicasRuntimeError("unknown", "replicas_timeout");
      return { id };
    },
    removeEnvironmentMcp: async (_key: string, environmentId: string, id: string) => {
      removed.push(id);
      entries.set(environmentId, entriesOf(environmentId).filter((entry) => entry.id !== id));
      return null;
    },
    sleep: async () => {
      throw new Error("environment bindings never sleep compute");
    },
    exec: async () => {
      throw new Error("environment bindings never exec");
    },
  };
  return { runtime: runtime as unknown as ReplicasRuntime, environments, registered, removed, mode, entriesOf };
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

type StartOptions = {
  /** The store's Relaycast provisioner: an unbound workspace binds through it. */
  relaycastProvisioner?: RelaycastProvisioner;
  /** The Replicas module's lazy binding: "store" wires the store's, a function replaces it; unset leaves it absent. */
  relaycastBinding?: "store" | ReplicasDeps["relaycastBinding"];
};

async function start(t: TestContext, enabled = true, issuerFetch: typeof fetch = identityFetch(),
  rateLimits?: Parameters<typeof createReplicasModule>[0]["rateLimits"], options: StartOptions = {}) {
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
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0,
    options.relaycastProvisioner ? { relaycastProvisioner: options.relaycastProvisioner } : {});
  const relaycastBinding: ReplicasDeps["relaycastBinding"] = options.relaycastBinding === "store"
    ? (id) => store.relaycastBinding(id) : options.relaycastBinding;
  const replicas = createReplicasModule({
    replicas: { enabled }, config, database, relaycastFetch: messagingFetch, runtime: provider.runtime, identityFetch: issuerFetch,
    ...(rateLimits ? { rateLimits } : {}),
    ...(relaycastBinding ? { relaycastBinding } : {}),
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

  await t.test("connect discovers, enables and registers every environment and reports each", async () => {
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
    assert.deepEqual(saved.body.environmentSetup, {
      allEnvironments: true,
      environments: [{ environmentId: ENV_A, status: "registered" }, { environmentId: ENV_B, status: "registered" }],
    });
    assert.deepEqual(provider.registered.map((item) => [item.environmentId, item.id]), [[ENV_A, "mcp_1"], [ENV_B, "mcp_2"]]);
    const defaults = await api(`${base}/environment-policies`, { token: ownerToken });
    assert.equal(defaults.body.allEnvironments, true);
    assert.deepEqual(defaults.body.environments.map((item: any) => [item.environmentId, item.status, item.enabled]),
      [[ENV_A, "registered", true], [ENV_B, "registered", true]]);
    // Turning the default off disables and unregisters everything (the precondition for the subtests below).
    const off = await api(`${base}/environment-mcp`, { method: "DELETE", token: ownerToken, body: { all: true } });
    assert.equal(off.status, 200, off.text);
    assert.deepEqual(provider.removed, ["mcp_1", "mcp_2"]);
    const listed = await api(`${base}/environment-policies`, { token: ownerToken });
    assert.equal(listed.status, 200, listed.text);
    assert.equal(listed.body.mcpUrl, MCP_URL);
    assert.equal(listed.body.allEnvironments, false);
    assert.equal(listed.body.principal, null);
    assert.equal(listed.body.organizationShared, false);
    assert.deepEqual(listed.body.environments.map((item: any) => [item.environmentId, item.status, item.enabled, item.pendingCreators]),
      [[ENV_A, "disabled", false, []], [ENV_B, "disabled", false, []]]);
    assert.equal((await api(`${base}/environment-policies`, { token: memberToken })).status, 403);
    // The live provider list keeps its own route and shape.
    const live = await api(`${base}/environments`, { token: ownerToken });
    assert.deepEqual(live.body, { environments: [{ id: ENV_A, name: "alpha" }, { id: ENV_B, name: "beta" }] });
  });

  await t.test("a not-enabled environment is refused, nothing is enrolled and the scope-less refusal is not audited", async () => {
    const response = await rpc(api, token(), "tools/list");
    assert.equal(response.status, 403, response.text);
    assert.equal(response.body.error.message, "replica_environment_not_enabled");
    assert.equal(await spawns(env), 0);
    // No tenant is known for this token: a foreign organization cannot fill the audit log.
    assert.equal(await count(env, "SELECT 1 FROM admin_audit_events WHERE action = 'replicas.identity.refused'"), 0);
    assert.equal(await count(env, "SELECT 1 FROM replica_environment_creator_requests"), 0);
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
    assert.equal(await count(env, "SELECT 1 FROM admin_audit_events WHERE action = 'replicas.identity.refused'"), 0);
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

  await t.test("a missing or null creator mapping is refused without enrolment and an unmapped creator becomes pending", async () => {
    let response = await rpc(api, token(), "tools/list");
    assert.equal(response.status, 403);
    assert.equal(response.body.error.message, "replica_creator_not_allowed");
    response = await rpc(api, token({ creator_id: null }), "tools/list");
    assert.equal(response.body.error.message, "replica_creator_not_allowed");
    assert.equal(await spawns(env), 0);
    // Scoped refusals are audited.
    assert.equal(await count(env, "SELECT 1 FROM admin_audit_events WHERE action = 'replicas.identity.refused'"), 2);
    let view = await api(`${base}/environment-policies`, { token: ownerToken });
    let pending = view.body.environments.find((item: any) => item.environmentId === ENV_A).pendingCreators;
    // A null creator is never recorded; the hint is masked.
    assert.equal(pending.length, 1);
    assert.deepEqual({ ...pending[0], lastSeenAt: typeof pending[0].lastSeenAt },
      { creatorId: "creator-owner", emailHint: "o…@acme.test", lastSeenAt: "string", count: 1 });
    assert.doesNotMatch(view.text, /owner@acme\.test/);
    // Bounded to the 50 most recent per policy.
    const policyId = (await database.query<{ id: string }>("SELECT id FROM replica_environment_policies WHERE environment_id = $1", [ENV_A])).rows[0]!.id;
    await database.query(`INSERT INTO replica_environment_creator_requests (policy_id, creator_id, last_seen_at)
      SELECT $1, 'old-' || n, now() - interval '1 day' - n * interval '1 minute' FROM generate_series(1, 50) n`, [policyId]);
    // A pending creator is written at most once per minute: a refusal within the minute writes nothing.
    await rpc(api, token(), "tools/list");
    view = await api(`${base}/environment-policies`, { token: ownerToken });
    pending = view.body.environments.find((item: any) => item.environmentId === ENV_A).pendingCreators;
    assert.equal(pending.length, 51);
    assert.equal(pending[0].count, 1);
    await database.query("UPDATE replica_environment_creator_requests SET last_seen_at = now() - interval '2 minutes' WHERE creator_id = 'creator-owner'");
    await rpc(api, token(), "tools/list");
    view = await api(`${base}/environment-policies`, { token: ownerToken });
    pending = view.body.environments.find((item: any) => item.environmentId === ENV_A).pendingCreators;
    assert.equal(pending.length, 50);
    assert.deepEqual([pending[0].creatorId, pending[0].count], ["creator-owner", 2]);
    assert.ok(!pending.some((item: any) => item.creatorId === "old-50"), "the oldest request is dropped");
    assert.ok(pending.every((item: any, index: number) => index === 0 || item.lastSeenAt <= pending[index - 1].lastSeenAt));
  });

  await t.test("a mapped creator enrols once; later calls reuse the binding", async () => {
    const mapped = await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken,
      body: { creators: [{ creatorId: "creator-owner", userId: ownerId }, { creatorId: "creator-member", userId: memberId }] } });
    assert.equal(mapped.status, 200, mapped.text);
    // Mapping a creator clears its pending request; the others stay.
    assert.equal(mapped.body.environment.pendingCreators.length, 49);
    assert.ok(!mapped.body.environment.pendingCreators.some((item: any) => item.creatorId === "creator-owner"));
    await database.query("DELETE FROM replica_environment_creator_requests");
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
    // RFC 7235: the scheme is case-insensitive, any whitespace follows it.
    const lower = await api("/api/v1/replicas/mcp", { method: "POST", headers: { ...MCP_HEADERS, authorization: `bearer \t ${token()}` },
      body: { jsonrpc: "2.0", id: ++rpcSequence, method: "tools/list", params: {} } });
    assert.equal(lower.status, 200, lower.text);
    // The creator hint is masked.
    const creators = await api(`${base}/environment-policies`, { token: ownerToken });
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

  await t.test("an environment-identity binding in another workspace is replica_owned_elsewhere", async () => {
    const other = await api(`/api/v1/organizations/${env.organizationId}/workspaces`, {
      method: "POST", token: BOOTSTRAP, body: { name: "secondary", relaycastWorkspaceId: "rc-secondary", relaycastApiKey: "rk_live_secondary" },
    });
    assert.equal(other.status, 201, other.text);
    const row = (await database.query<{ id: string }>("SELECT id FROM replica_spawns WHERE replica_id = $1 AND state <> 'gone'", [WORKSPACE_1])).rows[0]!;
    await database.query("UPDATE replica_spawns SET workspace_id = $2 WHERE id = $1", [row.id, other.body.id]);
    const refused = await callTool(api, token(), "list_relay_agents");
    assert.equal(refused.status, 403, refused.text);
    assert.equal(refused.body.error.message, "replica_owned_elsewhere");
    await database.query("UPDATE replica_spawns SET workspace_id = $2 WHERE id = $1", [row.id, workspaceId]);
  });

  await t.test("disabling the environment releases its bindings without a tombstone; enabling re-enrols", async () => {
    const agent = `replicas-${WORKSPACE_1.replaceAll("-", "").slice(0, 16)}`;
    const before = (await database.query<{ id: string }>("SELECT id FROM replica_spawns WHERE replica_id = $1 AND state <> 'gone'", [WORKSPACE_1])).rows[0]!;
    assert.equal(await spawns(env), 2);
    assert.equal((await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken, body: { enabled: false } })).status, 200);
    assert.equal(await spawns(env), 0);
    assert.equal(world.agents.has(agent), false, "the Relay identity is retired");
    assert.equal(await count(env, "SELECT 1 FROM replica_identity_tombstones"), 0);
    assert.equal(await count(env, "SELECT 1 FROM hosted_relay_participants WHERE agent_name = $1", [agent]), 0);
    const refused = await callTool(api, token(), "list_relay_agents");
    assert.equal(refused.body.error.message, "replica_environment_not_enabled");
    assert.equal((await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken, body: { enabled: true } })).status, 200);
    assert.equal((await callTool(api, token(), "list_relay_agents")).status, 200);
    const after = (await database.query<{ id: string }>("SELECT id FROM replica_spawns WHERE replica_id = $1 AND state <> 'gone'", [WORKSPACE_1])).rows[0]!;
    assert.notEqual(after.id, before.id, "a fresh binding");
    assert.equal(world.agents.get(agent)?.metadata.replicas_spawn_id, after.id);
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
    assert.equal(provider.registered.length, 4);
    provider.environments.push({ id: ENV_C, name: "gamma" });
    provider.mode.register = "fail";
    const synced = await api(`${base}/environments/sync`, { method: "POST", token: ownerToken });
    assert.equal(synced.status, 200, synced.text);
    // A timeout leaves the provider outcome unknown.
    assert.deepEqual(synced.body.environments, [{ environmentId: ENV_C, status: "registration_unconfirmed", retryable: true }]);
    // While the outcome is unknown every enable is read-only: nothing is sent again.
    provider.mode.register = "reject";
    const readOnly = await api(`${base}/environment-mcp`, { method: "POST", token: ownerToken, body: { environmentIds: [ENV_C] } });
    assert.deepEqual(readOnly.body.environments, [{ environmentId: ENV_C, status: "registration_unconfirmed", retryable: true }]);
    // The explicit retry sends it again; a definite provider rejection created nothing and clears the intent.
    const rejected = await api(`${base}/environments/${ENV_C}`, { method: "PUT", token: ownerToken, body: { retry_registration: true } });
    assert.equal(rejected.status, 200, rejected.text);
    assert.equal(rejected.body.environment.status, "enabled");
    provider.mode.register = "ok";
    const retried = await api(`${base}/environment-mcp`, { method: "POST", token: ownerToken, body: { environmentIds: [ENV_C] } });
    assert.deepEqual(retried.body.environments, [{ environmentId: ENV_C, status: "registered" }]);
    const removed = await api(`${base}/environment-mcp`, { method: "DELETE", token: ownerToken, body: { environmentIds: [ENV_B] } });
    assert.equal(removed.status, 200, removed.text);
    assert.deepEqual(removed.body.environments, [{ environmentId: ENV_B, status: "disabled" }]);
    assert.deepEqual(provider.removed, ["mcp_1", "mcp_2", "mcp_4"]);
    const listed = await api(`${base}/environment-policies`, { token: ownerToken });
    assert.deepEqual(listed.body.environments.map((item: any) => [item.environmentId, item.status]),
      [[ENV_A, "registered"], [ENV_B, "disabled"], [ENV_C, "registered"]]);
  });

  await t.test("disconnect disables every policy, releases bindings, removes entries and refuses tokens", async () => {
    const disconnected = await api(`${connections}/replicas`, { method: "DELETE", token: ownerToken });
    assert.equal(disconnected.status, 200, disconnected.text);
    assert.equal(provider.removed.length, 5);
    assert.equal(await count(env, "SELECT 1 FROM replica_environment_policies WHERE enabled"), 0);
    assert.equal(await count(env, "SELECT 1 FROM replica_environment_policies WHERE registered_mcp_id IS NOT NULL"), 0);
    assert.equal(await spawns(env), 0);
    const refused = await rpc(api, token(), "tools/list");
    assert.equal(refused.status, 403);
    assert.equal(refused.body.error.message, "replica_environment_not_enabled");
  });
});

test("an unreadable issuer is 503 without a challenge; a bad signature stays 401", async (t) => {
  const down = await start(t, true, (async () => new Response("{}", { status: 500 })) as typeof fetch);
  const unavailable = await rpc(down.api, token(), "tools/list");
  assert.equal(unavailable.status, 503, unavailable.text);
  assert.equal(unavailable.body.error.message, "replica_identity_unavailable");
  assert.equal(unavailable.headers.get("www-authenticate"), null);
  const up = await start(t);
  const valid = token();
  const forged = `${valid.slice(0, valid.lastIndexOf("."))}.${Buffer.alloc(256, 1).toString("base64url")}`;
  const refused = await rpc(up.api, forged, "tools/list");
  assert.equal(refused.status, 401, refused.text);
  assert.ok(refused.headers.get("www-authenticate"));
});

test("a concurrent enable in another workspace is enabled_elsewhere, not a 500", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, database, provider } = env;
  const saved = await api(`/api/v1/workspaces/${workspaceId}/remote-agent-connections/replicas`, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
  assert.equal(saved.status, 200, saved.text);
  // Start from disabled policies: turn the connect default off.
  assert.equal((await api(`/api/v1/workspaces/${workspaceId}/replicas/environment-mcp`, { method: "DELETE", token: ownerToken, body: { all: true } })).status, 200);
  provider.registered.length = 0;
  const other = await api(`/api/v1/organizations/${env.organizationId}/workspaces`, {
    method: "POST", token: BOOTSTRAP, body: { name: "secondary", relaycastWorkspaceId: "rc-secondary", relaycastApiKey: "rk_live_secondary" },
  });
  assert.equal(other.status, 201, other.text);
  await database.query(`INSERT INTO replica_environment_policies (id, workspace_id, issuer, provider_organization_id, environment_id)
    VALUES (gen_random_uuid(), $1, $2, $3, $4)`, [other.body.id, ISSUER, PROVIDER_ORG, ENV_A]);
  // Simulates the other workspace enabling ENV_A after this workspace's pre-check: the unique index decides.
  await database.query(`CREATE FUNCTION race_enable() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      UPDATE replica_environment_policies SET enabled = true WHERE workspace_id = '${other.body.id}' AND environment_id = NEW.environment_id;
      RETURN NEW;
    END $$`);
  await database.query(`CREATE TRIGGER race_enable BEFORE UPDATE ON replica_environment_policies FOR EACH ROW
    WHEN (NEW.enabled AND NOT OLD.enabled AND NEW.workspace_id = '${workspaceId}' AND NEW.environment_id = '${ENV_A}') EXECUTE FUNCTION race_enable()`);
  const enabled = await api(`/api/v1/workspaces/${workspaceId}/replicas/environment-mcp`, { method: "POST", token: ownerToken,
    body: { environmentIds: [ENV_A, ENV_B] } });
  assert.equal(enabled.status, 200, enabled.text);
  assert.deepEqual(enabled.body.environments, [
    { environmentId: ENV_A, status: "enabled_elsewhere" },
    { environmentId: ENV_B, status: "registered" },
  ]);
  assert.deepEqual(provider.registered.map((item) => item.environmentId), [ENV_B]);
  assert.equal(await count(env, "SELECT 1 FROM replica_environment_policies WHERE workspace_id = $1 AND enabled", [workspaceId]), 1);
});

test("the environment-level MCP is rate limited per verified identity, with a coarse per-IP guard", async (t) => {
  const minute = 60_000;
  // Per identity: the organization and the VM. Another VM of the same organization from the same IP still answers.
  const env = await start(t, true, identityFetch(), { ip: { limit: 1_000, windowMs: minute }, identity: { limit: 3, windowMs: minute } });
  const first = token();
  const second = token({ workspace_id: WORKSPACE_2 });
  for (let index = 0; index < 3; index++) {
    const answered = await rpc(env.api, first, "tools/list");
    assert.notEqual(answered.status, 429, answered.text);
  }
  const limited = await rpc(env.api, first, "tools/list");
  assert.equal(limited.status, 429, limited.text);
  assert.deepEqual(limited.body.error, { code: -32000, message: "rate_limited" });
  assert.ok(Number(limited.headers.get("retry-after")) >= 1);
  const other = await rpc(env.api, second, "tools/list");
  assert.notEqual(other.status, 429, other.text);
  // An unverified caller never reaches the identity quota; the IP guard holds a flood.
  const guarded = await start(t, true, identityFetch(), { ip: { limit: 5, windowMs: minute } });
  for (let index = 0; index < 5; index++) {
    assert.equal((await rpc(guarded.api, null, "tools/list")).status, 401);
  }
  const flooded = await rpc(guarded.api, token(), "tools/list");
  assert.equal(flooded.status, 429, flooded.text);
  assert.deepEqual(flooded.body.error, { code: -32000, message: "rate_limited" });
  assert.ok(Number(flooded.headers.get("retry-after")) >= 1);
});

async function connectAndEnable(env: Awaited<ReturnType<typeof start>>) {
  const { api, workspaceId, ownerToken } = env;
  const saved = await api(`/api/v1/workspaces/${workspaceId}/remote-agent-connections/replicas`, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
  assert.equal(saved.status, 200, saved.text);
  // The connect enables every environment; opt ENV_B out so only ENV_A is enabled.
  const optedOut = await api(`/api/v1/workspaces/${workspaceId}/replicas/environment-mcp`, { method: "DELETE", token: ownerToken, body: { environmentIds: [ENV_B] } });
  assert.equal(optedOut.status, 200, optedOut.text);
  const enabled = await api(`/api/v1/workspaces/${workspaceId}/replicas/environments/${ENV_A}`, { method: "PUT", token: ownerToken, body: { enabled: true } });
  assert.equal(enabled.status, 200, enabled.text);
}

const binding = async (env: Awaited<ReturnType<typeof start>>, replicaId: string) => (await env.database.query<any>(
  "SELECT id, user_id, input FROM replica_spawns WHERE source = 'environment_identity' AND replica_id = $1 AND state <> 'gone'", [replicaId])).rows[0];

test("VM principal: null and unmapped creators act as the explicit principal; changes release only principal bindings", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, memberToken, ownerId, memberId, database } = env;
  const base = `/api/v1/workspaces/${workspaceId}/replicas`;
  await connectAndEnable(env);
  const W3 = randomUUID();
  const W4 = randomUUID();

  await t.test("without a principal a null creator is refused", async () => {
    const refused = await rpc(api, token({ creator_id: null }), "tools/list");
    assert.equal(refused.status, 403);
    assert.equal(refused.body.error.message, "replica_creator_not_allowed");
    assert.equal(await spawns(env), 0);
  });

  await t.test("the principal route is admin-only, strict and member-only", async () => {
    const path = `${base}/environment-principal`;
    assert.equal((await api(path, { method: "PUT", token: memberToken, body: { userId: memberId } })).status, 403);
    assert.equal((await api(path, { method: "PUT", token: ownerToken, body: { userId: memberId, extra: 1 } })).status, 400);
    assert.equal((await api(path, { method: "PUT", token: ownerToken, body: {} })).status, 400);
    const stranger = await api(path, { method: "PUT", token: ownerToken, body: { userId: randomUUID() } });
    assert.equal(stranger.status, 400, stranger.text);
    const set = await api(path, { method: "PUT", token: ownerToken, body: { userId: memberId } });
    assert.equal(set.status, 200, set.text);
    assert.deepEqual(set.body.principal, { userId: memberId, member: true });
    assert.equal(set.body.organizationShared, false);
    assert.equal(await count(env, "SELECT 1 FROM admin_audit_events WHERE action = 'replicas.environment.principal_updated'"), 1);
  });

  await t.test("a null creator is admitted as the principal", async () => {
    const listed = await rpc(api, token({ creator_id: null }), "tools/list");
    assert.equal(listed.status, 200, listed.text);
    const row = await binding(env, WORKSPACE_1);
    assert.equal(row.user_id, memberId);
    assert.equal(row.input.acts_as, "principal");
    assert.equal(row.input.creator_id, null);
  });

  await t.test("an unmapped creator is admitted as the principal and listed as pending", async () => {
    const unmapped = token({ workspace_id: W3, creator_id: "creator-owner" });
    assert.equal((await rpc(api, unmapped, "tools/list")).status, 200);
    const row = await binding(env, W3);
    assert.deepEqual([row.user_id, row.input.acts_as, row.input.creator_id], [memberId, "principal", "creator-owner"]);
    const view = await api(`${base}/environment-policies`, { token: ownerToken });
    const pending = view.body.environments.find((item: any) => item.environmentId === ENV_A).pendingCreators;
    assert.deepEqual(pending.map((item: any) => item.creatorId), ["creator-owner"]);
  });

  await t.test("mapping a creator releases its principal binding; it re-enrols as the mapped member", async () => {
    const before = await binding(env, W3);
    const mapped = await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken,
      body: { creators: [{ creatorId: "creator-owner", userId: ownerId }] } });
    assert.equal(mapped.status, 200, mapped.text);
    assert.equal(await binding(env, W3), undefined, "the principal binding is released");
    assert.equal(await count(env, "SELECT 1 FROM replica_identity_tombstones"), 0);
    assert.ok(await binding(env, WORKSPACE_1), "a null-creator principal binding is untouched");
    const unmapped = token({ workspace_id: W3, creator_id: "creator-owner" });
    assert.equal((await callTool(api, unmapped, "list_relay_agents")).status, 200);
    const after = await binding(env, W3);
    assert.notEqual(after.id, before.id);
    assert.deepEqual([after.user_id, after.input.acts_as, after.input.creator_id], [ownerId, "creator", "creator-owner"]);
    // Re-saving the same mapping releases nothing.
    await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken, body: { creators: [{ creatorId: "creator-owner", userId: ownerId }] } });
    assert.equal((await binding(env, W3)).id, after.id);
  });

  await t.test("changing the principal releases principal bindings only; they re-enrol as the new principal", async () => {
    assert.equal((await rpc(api, token({ workspace_id: W4, creator_id: "creator-x" }), "tools/list")).status, 200);
    assert.equal(await spawns(env), 3);
    const changed = await api(`${base}/environment-principal`, { method: "PUT", token: ownerToken, body: { userId: ownerId } });
    assert.equal(changed.status, 200, changed.text);
    assert.deepEqual(changed.body.principal, { userId: ownerId, member: true });
    assert.equal(await binding(env, WORKSPACE_1), undefined);
    assert.equal(await binding(env, W4), undefined);
    assert.equal((await binding(env, W3)).input.acts_as, "creator", "a mapped binding is kept");
    assert.equal((await rpc(api, token({ creator_id: null }), "tools/list")).status, 200);
    assert.equal((await binding(env, WORKSPACE_1)).user_id, ownerId);
  });

  await t.test("clearing the principal releases its bindings and refuses null creators again", async () => {
    const cleared = await api(`${base}/environment-principal`, { method: "PUT", token: ownerToken, body: { userId: null } });
    assert.equal(cleared.status, 200, cleared.text);
    assert.equal(cleared.body.principal, null);
    assert.equal(await binding(env, WORKSPACE_1), undefined);
    const refused = await rpc(api, token({ creator_id: null }), "tools/list");
    assert.equal(refused.status, 403);
    assert.equal(refused.body.error.message, "replica_creator_not_allowed");
  });

  await t.test("enable with principalUserId sets the principal in the same request; a non-member is 400", async () => {
    const stranger = await api(`${base}/environment-mcp`, { method: "POST", token: ownerToken,
      body: { environmentIds: [ENV_B], principalUserId: randomUUID() } });
    assert.equal(stranger.status, 400, stranger.text);
    assert.equal(await count(env, "SELECT 1 FROM replica_environment_policies WHERE environment_id = $1 AND enabled", [ENV_B]), 0);
    // The delete body stays a plain selection.
    assert.equal((await api(`${base}/environment-mcp`, { method: "DELETE", token: ownerToken,
      body: { environmentIds: [ENV_B], principalUserId: memberId } })).status, 400);
    const enabled = await api(`${base}/environment-mcp`, { method: "POST", token: ownerToken,
      body: { environmentIds: [ENV_B], principalUserId: memberId } });
    assert.equal(enabled.status, 200, enabled.text);
    assert.deepEqual(enabled.body.environments, [{ environmentId: ENV_B, status: "registered" }]);
    const view = await api(`${base}/environment-policies`, { token: ownerToken });
    assert.deepEqual(view.body.principal, { userId: memberId, member: true });
    assert.equal((await rpc(api, token({ creator_id: null, environment_id: ENV_B }), "tools/list")).status, 200);
    assert.equal((await binding(env, WORKSPACE_1)).user_id, memberId);
  });

  await t.test("a principal who left the organization admits nobody", async () => {
    await database.query("DELETE FROM organization_memberships WHERE user_id = $1", [memberId]);
    const refused = await callTool(api, token({ creator_id: null, environment_id: ENV_B }), "list_relay_agents");
    assert.equal(refused.status, 403, refused.text);
    assert.equal(refused.body.error.message, "replica_creator_not_allowed");
    const view = await api(`${base}/environment-policies`, { token: ownerToken });
    assert.deepEqual(view.body.principal, { userId: memberId, member: false });
  });
});

test("an organization connected in two workspaces is refused, never enabled, and shown as shared", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, ownerId, database } = env;
  const base = `/api/v1/workspaces/${workspaceId}/replicas`;
  await connectAndEnable(env);
  await api(`${base}/environment-principal`, { method: "PUT", token: ownerToken, body: { userId: ownerId } });
  assert.equal((await rpc(api, token(), "tools/list")).status, 200);
  const other = await api(`/api/v1/organizations/${env.organizationId}/workspaces`, {
    method: "POST", token: BOOTSTRAP, body: { name: "secondary", relaycastWorkspaceId: "rc-secondary", relaycastApiKey: "rk_live_secondary" },
  });
  assert.equal(other.status, 201, other.text);
  // The same provider organization connected in a second workspace (account case differs).
  await database.query(`INSERT INTO remote_agent_connections (workspace_id, provider, key_ciphertext, key_hint, provider_account)
    SELECT $2, provider, key_ciphertext, key_hint, upper(provider_account) FROM remote_agent_connections WHERE workspace_id = $1 AND provider = 'replicas'`,
  [workspaceId, other.body.id]);
  const refused = await callTool(api, token(), "list_relay_agents");
  assert.equal(refused.status, 403, refused.text);
  assert.equal(refused.body.error.message, "organization_shared");
  // The candidate's scope is known, so the refusal is audited.
  assert.equal(await count(env, "SELECT 1 FROM admin_audit_events WHERE action = 'replicas.identity.refused' AND workspace_id = $1", [workspaceId]), 1);
  const put = await api(`${base}/environments/${ENV_B}`, { method: "PUT", token: ownerToken, body: { enabled: true } });
  assert.equal(put.status, 409, put.text);
  assert.equal(put.body.error, "This Replicas organization is connected in another workspace.");
  const enabled = await api(`${base}/environment-mcp`, { method: "POST", token: ownerToken, body: { environmentIds: [ENV_B] } });
  assert.equal(enabled.status, 200, enabled.text);
  assert.deepEqual(enabled.body.environments, [{ environmentId: ENV_B, status: "organization_shared", retryable: false }]);
  assert.equal(await count(env, "SELECT 1 FROM replica_environment_policies WHERE environment_id = $1 AND enabled", [ENV_B]), 0);
  const view = await api(`${base}/environment-policies`, { token: ownerToken });
  assert.equal(view.body.organizationShared, true);
  await database.query("DELETE FROM remote_agent_connections WHERE workspace_id = $1", [other.body.id]);
  assert.equal((await callTool(api, token(), "list_relay_agents")).status, 200);
});

test("registration reads entries first, reuses a match, never overwrites a conflict and reads back after create", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, provider, database } = env;
  const path = `/api/v1/workspaces/${workspaceId}/replicas/environment-mcp`;
  const saved = await api(`/api/v1/workspaces/${workspaceId}/remote-agent-connections/replicas`, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
  assert.equal(saved.status, 200, saved.text);
  // Start from disabled, unregistered policies: turn the connect default off; sync then enables nothing.
  assert.equal((await api(path, { method: "DELETE", token: ownerToken, body: { all: true } })).status, 200);
  provider.environments.push({ id: ENV_C, name: "gamma" });
  const synced = await api(`/api/v1/workspaces/${workspaceId}/replicas/environments/sync`, { method: "POST", token: ownerToken });
  assert.deepEqual(synced.body.environments, []);
  provider.registered.length = 0;
  provider.removed.length = 0;
  const entry = (environmentId: string, id: string, config: Record<string, unknown> = {}) => ({
    id, organization_id: PROVIDER_ORG, environment_id: environmentId, name: "agent-relay-replica", transport: "http",
    config: { url: MCP_URL, headers: {}, auth: { type: "workspace_identity", audience: MCP_URL }, ...config },
  });
  const stored = async (environmentId: string) => (await database.query<{ registered_mcp_id: string | null }>(
    "SELECT registered_mcp_id FROM replica_environment_policies WHERE environment_id = $1", [environmentId])).rows[0]!.registered_mcp_id;

  // A matching entry is reused.
  provider.entriesOf(ENV_A).push(entry(ENV_A, "existing_a"), { ...entry(ENV_A, "other"), name: "something-else" });
  let result = await api(path, { method: "POST", token: ownerToken, body: { environmentIds: [ENV_A] } });
  assert.deepEqual(result.body.environments, [{ environmentId: ENV_A, status: "registered" }]);
  assert.equal(await stored(ENV_A), "existing_a");
  assert.equal(provider.registered.length, 0);

  // A same-name entry with another config, or two of them, is never overwritten.
  provider.entriesOf(ENV_B).push(entry(ENV_B, "foreign_b", { url: "https://elsewhere.invalid/mcp" }));
  provider.entriesOf(ENV_C).push(entry(ENV_C, "dup_1"), entry(ENV_C, "dup_2"));
  result = await api(path, { method: "POST", token: ownerToken, body: { environmentIds: [ENV_B, ENV_C] } });
  assert.deepEqual(result.body.environments, [
    { environmentId: ENV_B, status: "registration_failed", retryable: false },
    { environmentId: ENV_C, status: "registration_failed", retryable: false },
  ]);
  assert.equal(provider.registered.length, 0);
  assert.equal(provider.entriesOf(ENV_B)[0]!.id, "foreign_b");

  // A lost create answer is confirmed by reading the entry back.
  provider.entriesOf(ENV_B).length = 0;
  provider.mode.register = "lost";
  result = await api(path, { method: "POST", token: ownerToken, body: { environmentIds: [ENV_B] } });
  assert.deepEqual(result.body.environments, [{ environmentId: ENV_B, status: "registered" }]);
  assert.equal(await stored(ENV_B), "mcp_1");

  // A 409 on create reads back the entry that already exists.
  provider.entriesOf(ENV_C).length = 0;
  provider.entriesOf(ENV_C).push({ ...entry(ENV_C, "raced_c"), organization_id: PROVIDER_ORG.toUpperCase() });
  await database.query("UPDATE replica_environment_policies SET registered_mcp_id = NULL WHERE environment_id = $1", [ENV_C]);
  provider.mode.register = "conflict";
  const list = provider.runtime.listEnvironmentMcps;
  let reads = 0;
  // The first read misses the entry (it lands concurrently); the read-back finds it.
  (provider.runtime as any).listEnvironmentMcps = async (key: string, environmentId: string) =>
    environmentId === ENV_C && reads++ === 0 ? [] : list(key, environmentId);
  result = await api(path, { method: "POST", token: ownerToken, body: { environmentIds: [ENV_C] } });
  assert.deepEqual(result.body.environments, [{ environmentId: ENV_C, status: "registered" }]);
  assert.equal(await stored(ENV_C), "raced_c");
});

test("all environments by default: sync enables new ones, opt-outs stick, the default can be turned off and on, reconnect restores it", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, provider, database } = env;
  const base = `/api/v1/workspaces/${workspaceId}/replicas`;
  const connection = `/api/v1/workspaces/${workspaceId}/remote-agent-connections/replicas`;
  const states = async () => (await api(`${base}/environment-policies`, { token: ownerToken })).body.environments
    .map((item: any) => [item.environmentId, item.status]);
  const saved = await api(connection, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
  assert.equal(saved.status, 200, saved.text);
  assert.deepEqual(saved.body.environmentSetup.environments.map((item: any) => item.status), ["registered", "registered"]);

  // An environment opted out with PUT stays disabled on sync; a newly discovered one is enabled.
  const optOut = await api(`${base}/environments/${ENV_B}`, { method: "PUT", token: ownerToken, body: { enabled: false } });
  assert.equal(optOut.status, 200, optOut.text);
  provider.environments.push({ id: ENV_C, name: "gamma" });
  let synced = await api(`${base}/environments/sync`, { method: "POST", token: ownerToken });
  assert.equal(synced.status, 200, synced.text);
  assert.equal(synced.body.allEnvironments, true);
  assert.deepEqual(synced.body.environments, [{ environmentId: ENV_C, status: "registered" }]);
  assert.deepEqual(await states(), [[ENV_A, "registered"], [ENV_B, "disabled"], [ENV_C, "registered"]]);

  // Sync re-registers an enabled policy whose entry is missing, never a disabled one.
  await database.query("UPDATE replica_environment_policies SET registered_mcp_id = NULL WHERE environment_id = $1", [ENV_A]);
  provider.entriesOf(ENV_A).length = 0;
  synced = await api(`${base}/environments/sync`, { method: "POST", token: ownerToken });
  assert.deepEqual(synced.body.environments, [{ environmentId: ENV_A, status: "registered" }]);
  assert.deepEqual(await states(), [[ENV_A, "registered"], [ENV_B, "disabled"], [ENV_C, "registered"]]);

  // With the default off, sync enables nothing new.
  assert.equal((await api(`${base}/environment-mcp`, { method: "DELETE", token: ownerToken, body: { all: true } })).status, 200);
  provider.environments.push({ id: "env-delta", name: "delta" });
  synced = await api(`${base}/environments/sync`, { method: "POST", token: ownerToken });
  assert.equal(synced.status, 200, synced.text);
  assert.equal(synced.body.allEnvironments, false);
  assert.deepEqual(synced.body.environments, []);
  assert.equal(await count(env, "SELECT 1 FROM replica_environment_policies WHERE enabled"), 0);

  // Turning it back on re-enables everything, including the opted-out environment.
  const all = await api(`${base}/environment-mcp`, { method: "POST", token: ownerToken, body: { all: true } });
  assert.equal(all.status, 200, all.text);
  assert.deepEqual((await states()).sort(), [[ENV_A, "registered"], [ENV_B, "registered"], [ENV_C, "registered"], ["env-delta", "registered"]].sort());

  // Disconnect then reconnect: the flag is true again and every environment is enabled again.
  assert.equal((await api(connection, { method: "DELETE", token: ownerToken })).status, 200);
  assert.equal(await count(env, "SELECT 1 FROM replica_environment_policies WHERE enabled"), 0);
  assert.equal(await count(env, "SELECT 1 FROM replica_environment_settings WHERE NOT all_environments"), 1);
  const again = await api(connection, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
  assert.equal(again.status, 200, again.text);
  assert.equal(again.body.environmentSetup.allEnvironments, true);
  assert.ok(again.body.environmentSetup.environments.every((item: any) => item.status === "registered"));
  assert.equal(await count(env, "SELECT 1 FROM replica_environment_policies WHERE enabled AND registered_mcp_id IS NOT NULL"), 4);
  assert.equal(await count(env, "SELECT 1 FROM replica_environment_settings WHERE all_environments"), 1);
});

test("connect with the organization already connected in another workspace is refused and saves nothing", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, provider, database } = env;
  const connection = `/api/v1/workspaces/${workspaceId}/remote-agent-connections/replicas`;
  const other = await api(`/api/v1/organizations/${env.organizationId}/workspaces`, {
    method: "POST", token: BOOTSTRAP, body: { name: "secondary", relaycastWorkspaceId: "rc-secondary", relaycastApiKey: "rk_live_secondary" },
  });
  assert.equal(other.status, 201, other.text);
  await database.query(`INSERT INTO remote_agent_connections (workspace_id, provider, key_ciphertext, key_hint, provider_account)
    VALUES ($1, 'replicas', 'x', 'x', $2)`, [other.body.id, PROVIDER_ORG]);
  const refused = await api(connection, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
  assert.equal(refused.status, 403, refused.text);
  assert.equal(refused.body.error, "organization_shared");
  assert.equal(await count(env, "SELECT 1 FROM remote_agent_connections WHERE workspace_id = $1 AND provider = 'replicas'", [workspaceId]), 0);
  assert.equal(await count(env, "SELECT 1 FROM replica_environment_policies WHERE workspace_id = $1", [workspaceId]), 0);
  assert.equal(provider.registered.length, 0);
  // A re-connect in the losing workspace (a row saved before this rule) is refused the same way and keeps the old row.
  await database.query(`INSERT INTO remote_agent_connections (workspace_id, provider, key_ciphertext, key_hint, provider_account)
    VALUES ($1, 'replicas', 'x', 'x', $2)`, [workspaceId, PROVIDER_ORG]);
  const reconnect = await api(connection, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
  assert.equal(reconnect.status, 403, reconnect.text);
  assert.equal(reconnect.body.error, "organization_shared");
  assert.equal(await count(env, "SELECT 1 FROM remote_agent_connections WHERE workspace_id = $1 AND key_ciphertext = 'x'", [workspaceId]), 1);
  assert.equal(provider.registered.length, 0);
  await database.query("DELETE FROM remote_agent_connections WHERE workspace_id = $1", [workspaceId]);
  // Once the other workspace disconnects, the connect succeeds and enables both.
  await database.query("DELETE FROM remote_agent_connections WHERE workspace_id = $1", [other.body.id]);
  const saved = await api(connection, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
  assert.equal(saved.status, 200, saved.text);
  assert.equal(saved.body.connection.providerAccount, PROVIDER_ORG);
  assert.deepEqual(saved.body.environmentSetup.environments, [{ environmentId: ENV_A, status: "registered" }, { environmentId: ENV_B, status: "registered" }]);
  assert.deepEqual(provider.registered.map((item) => item.environmentId).sort(), [ENV_A, ENV_B]);
});

test("a re-connect (key rotation) keeps per-environment opt-outs and a default turned off", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, provider } = env;
  const base = `/api/v1/workspaces/${workspaceId}/replicas`;
  const connection = `/api/v1/workspaces/${workspaceId}/remote-agent-connections/replicas`;
  const states = async () => (await api(`${base}/environment-policies`, { token: ownerToken })).body.environments
    .map((item: any) => [item.environmentId, item.status]).sort();
  assert.equal((await api(connection, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } })).status, 200);
  assert.equal((await api(`${base}/environments/${ENV_B}`, { method: "PUT", token: ownerToken, body: { enabled: false } })).status, 200);

  // The rotation runs the sync semantics: the opt-out stays, a new environment is enabled under the default.
  provider.environments.push({ id: ENV_C, name: "gamma" });
  let rotated = await api(connection, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
  assert.equal(rotated.status, 200, rotated.text);
  assert.deepEqual(rotated.body.environmentSetup, { allEnvironments: true, environments: [{ environmentId: ENV_C, status: "registered" }] });
  assert.deepEqual(await states(), [[ENV_A, "registered"], [ENV_B, "disabled"], [ENV_C, "registered"]].sort());
  assert.equal(await count(env, "SELECT 1 FROM admin_audit_events WHERE action = 'replicas.environment.all_enabled'"), 1);

  // With the default off, a rotation turns nothing back on.
  assert.equal((await api(`${base}/environment-mcp`, { method: "DELETE", token: ownerToken, body: { all: true } })).status, 200);
  const registered = provider.registered.length;
  rotated = await api(connection, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
  assert.equal(rotated.status, 200, rotated.text);
  assert.deepEqual(rotated.body.environmentSetup, { allEnvironments: false, environments: [] });
  assert.equal((await api(`${base}/environment-policies`, { token: ownerToken })).body.allEnvironments, false);
  assert.equal(await count(env, "SELECT 1 FROM replica_environment_policies WHERE enabled"), 0);
  assert.equal(provider.registered.length, registered);
});

test("disconnect then connect enables every environment again, including opted-out ones", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken } = env;
  const base = `/api/v1/workspaces/${workspaceId}/replicas`;
  const connection = `/api/v1/workspaces/${workspaceId}/remote-agent-connections/replicas`;
  assert.equal((await api(connection, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } })).status, 200);
  assert.equal((await api(`${base}/environment-mcp`, { method: "DELETE", token: ownerToken, body: { environmentIds: [ENV_B] } })).status, 200);
  assert.equal((await api(connection, { method: "DELETE", token: ownerToken })).status, 200);
  const again = await api(connection, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
  assert.equal(again.status, 200, again.text);
  assert.deepEqual(again.body.environmentSetup, {
    allEnvironments: true,
    environments: [{ environmentId: ENV_A, status: "registered" }, { environmentId: ENV_B, status: "registered" }],
  });
  assert.equal(await count(env, "SELECT 1 FROM replica_environment_policies WHERE enabled AND registered_mcp_id IS NOT NULL"), 2);
});

test("a failed default enable is retried by sync and by a re-connect; an opt-out is not", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, provider, database } = env;
  const base = `/api/v1/workspaces/${workspaceId}/replicas`;
  const connection = `/api/v1/workspaces/${workspaceId}/remote-agent-connections/replicas`;
  const views = async () => (await api(`${base}/environment-policies`, { token: ownerToken })).body.environments
    .map((item: any) => [item.environmentId, item.status, item.optedOut]);
  await database.query("CREATE FUNCTION fail_enable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'enable failed'; END $$");
  const failEnable = (environmentId: string) => database.query(`CREATE TRIGGER fail_enable BEFORE UPDATE ON replica_environment_policies
    FOR EACH ROW WHEN (NEW.enabled AND NOT OLD.enabled AND NEW.environment_id = '${environmentId}') EXECUTE FUNCTION fail_enable()`);
  const allow = () => database.query("DROP TRIGGER fail_enable ON replica_environment_policies");

  await failEnable(ENV_B);
  const saved = await api(connection, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
  assert.equal(saved.status, 200, saved.text);
  assert.deepEqual(saved.body.environmentSetup.environments, [
    { environmentId: ENV_A, status: "registration_failed", retryable: true },
    { environmentId: ENV_B, status: "registration_failed", retryable: true },
  ]);
  assert.deepEqual(await views(), [[ENV_A, "disabled", false], [ENV_B, "disabled", false]]);
  await allow();
  let synced = await api(`${base}/environments/sync`, { method: "POST", token: ownerToken });
  assert.equal(synced.status, 200, synced.text);
  assert.deepEqual(synced.body.environments, [{ environmentId: ENV_A, status: "registered" }, { environmentId: ENV_B, status: "registered" }]);

  // A re-connect retries a default enable that failed on the previous re-connect.
  provider.environments.push({ id: ENV_C, name: "gamma" });
  await failEnable(ENV_C);
  let rotated = await api(connection, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
  assert.equal(rotated.status, 200, rotated.text);
  assert.deepEqual(rotated.body.environmentSetup.environments, [{ environmentId: ENV_C, status: "registration_failed", retryable: true }]);
  await allow();
  rotated = await api(connection, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
  assert.deepEqual(rotated.body.environmentSetup.environments, [{ environmentId: ENV_C, status: "registered" }]);

  // Opt-outs (PUT and DELETE) survive sync and re-connect.
  assert.equal((await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken, body: { enabled: false } })).status, 200);
  assert.equal((await api(`${base}/environment-mcp`, { method: "DELETE", token: ownerToken, body: { environmentIds: [ENV_B] } })).status, 200);
  synced = await api(`${base}/environments/sync`, { method: "POST", token: ownerToken });
  assert.deepEqual(synced.body.environments, []);
  rotated = await api(connection, { method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
  assert.deepEqual(rotated.body.environmentSetup.environments, []);
  assert.deepEqual(await views(), [[ENV_A, "disabled", true], [ENV_B, "disabled", true], [ENV_C, "registered", false]]);

  // An explicit enable clears one opt-out; POST {all: true} clears every one.
  assert.equal((await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken, body: { enabled: true } })).status, 200);
  assert.deepEqual(await views(), [[ENV_A, "registered", false], [ENV_B, "disabled", true], [ENV_C, "registered", false]]);
  assert.equal((await api(`${base}/environment-mcp`, { method: "DELETE", token: ownerToken, body: { all: true } })).status, 200);
  assert.deepEqual(await views(), [[ENV_A, "disabled", false], [ENV_B, "disabled", true], [ENV_C, "disabled", false]]);
  assert.equal((await api(`${base}/environment-mcp`, { method: "POST", token: ownerToken, body: { all: true } })).status, 200);
  assert.deepEqual(await views(), [[ENV_A, "registered", false], [ENV_B, "registered", false], [ENV_C, "registered", false]]);
});

test("a retired binding's leftover Relay agent is cleaned up on the replica's next call; a foreign agent still blocks", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, ownerId, world, database } = env;
  const base = `/api/v1/workspaces/${workspaceId}/replicas`;
  await connectAndEnable(env);
  assert.equal((await api(`${base}/environment-principal`, { method: "PUT", token: ownerToken, body: { userId: ownerId } })).status, 200);
  assert.equal((await rpc(api, token(), "tools/list")).status, 200);
  const agent = `replicas-${WORKSPACE_1.replaceAll("-", "").slice(0, 16)}`;
  const first = await binding(env, WORKSPACE_1);

  // The disable commits; the Relay release after it fails and leaves the agent behind.
  world.failNext("POST", "/v1/agents/release-exact", 503);
  assert.equal((await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken, body: { enabled: false } })).status, 200);
  assert.equal(world.agents.get(agent)?.metadata.replicas_spawn_id, first.id, "the retired binding's agent survived");
  assert.equal((await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken, body: { enabled: true } })).status, 200);

  // The retry fails again: a retryable 503, never replica_already_bound, and nothing is enrolled.
  world.failNext("POST", "/v1/agents/release-exact", 503);
  const retry = await callTool(api, token(), "list_relay_agents");
  assert.equal(retry.status, 503, retry.text);
  assert.equal(await binding(env, WORKSPACE_1), undefined);

  const listed = await callTool(api, token(), "list_relay_agents");
  assert.equal(listed.status, 200, listed.text);
  const second = await binding(env, WORKSPACE_1);
  assert.notEqual(second.id, first.id);
  assert.equal(world.agents.get(agent)?.metadata.replicas_spawn_id, second.id);
  const retired = (await database.query<any>("SELECT input FROM replica_spawns WHERE id = $1", [first.id])).rows[0];
  assert.equal(retired.input.cleanup_complete, true);

  // An agent bridging another replica, or claiming a gone binding of another replica, is not a predecessor.
  world.addAgent("foreign-bridge", { replica_id: WORKSPACE_2, replicas_spawn_id: randomUUID() });
  let refused = await callTool(api, token({ workspace_id: WORKSPACE_2 }), "list_relay_agents");
  assert.equal(refused.status, 409, refused.text);
  assert.equal(refused.body.error.message, "replica_already_bound");
  world.agents.get("foreign-bridge")!.metadata.replicas_spawn_id = first.id;
  refused = await callTool(api, token({ workspace_id: WORKSPACE_2 }), "list_relay_agents");
  assert.equal(refused.status, 409, refused.text);
  assert.equal(refused.body.error.message, "replica_already_bound");
});

/* ------------------------------------------------------------------ */
/* Unbound workspaces: the enrolment provisions the lazy Relay binding */
/* ------------------------------------------------------------------ */

/** A Relaycast provisioner that counts creates; `fail` makes the next creates refuse. */
function provisionerStub() {
  const state = { calls: 0, fail: null as null | "refused" | "plain" };
  const provisioner: RelaycastProvisioner = {
    async create() {
      state.calls += 1;
      if (state.fail === "refused") throw new ProvisionError("Relaycast refused the workspace create", false);
      if (state.fail === "plain") throw new Error("socket hang up");
      return { id: "rw_lazy_replicas", apiKey: "rk_lazy_replicas" };
    },
    async remove() {},
  };
  return { provisioner, state };
}

/**
 * Connects Replicas and enables ENV_A while the workspace is still bound (every
 * REST workspace route resolves the workspace's Relay binding itself), sets
 * the owner as VM principal unless `principal` is false, then drops the
 * workspace's Relay pair so it looks like an imported, not yet bound workspace.
 */
async function unboundWorkspace(env: Awaited<ReturnType<typeof start>>, principal = true) {
  await connectAndEnable(env);
  if (principal) {
    const set = await env.api(`/api/v1/workspaces/${env.workspaceId}/replicas/environment-principal`, {
      method: "PUT", token: env.ownerToken, body: { userId: env.ownerId } });
    assert.equal(set.status, 200, set.text);
  }
  await env.database.query("UPDATE workspaces SET relaycast_workspace_id = NULL, relaycast_api_key_ciphertext = NULL WHERE id = $1", [env.workspaceId]);
}

const workspacePair = async (env: Awaited<ReturnType<typeof start>>) => (await env.database.query<{
  relaycast_workspace_id: string | null; relaycast_api_key_ciphertext: string | null }>(
  "SELECT relaycast_workspace_id, relaycast_api_key_ciphertext FROM workspaces WHERE id = $1", [env.workspaceId])).rows[0]!;
const identityRows = async (env: Awaited<ReturnType<typeof start>>) => (await env.database.query<any>(
  "SELECT * FROM replica_spawns WHERE source = 'environment_identity' ORDER BY created_at, id")).rows;
const PROVISIONING_FAILED = "relay_mcp_provisioning_failed";
const PROVISIONING_TEXT = "Agent Relay MCP provisioning failed. Retry the MCP call from the same replica.";

test("unbound workspace: the first admitted call provisions the Relay binding once, then enrols and serves", async (t) => {
  const stub = provisionerStub();
  const env = await start(t, true, identityFetch(), undefined, { relaycastProvisioner: stub.provisioner, relaycastBinding: "store" });
  await unboundWorkspace(env);
  assert.equal((await workspacePair(env)).relaycast_workspace_id, null);

  const listed = await rpc(env.api, token(), "tools/list");
  assert.equal(listed.status, 200, listed.text);
  assert.deepEqual(listed.body.result.tools.map((tool: any) => tool.name).sort(),
    ["check_relay_inbox", "list_relay_agents", "send_relay_message"]);
  assert.equal(stub.state.calls, 1);
  const pair = await workspacePair(env);
  assert.equal(pair.relaycast_workspace_id, "rw_lazy_replicas");
  assert.ok(pair.relaycast_api_key_ciphertext);
  const rows = await identityRows(env);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].state, "bound");
  assert.equal(rows[0].relay_workspace_id, "rw_lazy_replicas");
  assert.equal(rows[0].last_error, null);
  const agent = `replicas-${WORKSPACE_1.replaceAll("-", "").slice(0, 16)}`;
  assert.equal(env.world.agents.get(agent)?.metadata.replicas_spawn_id, rows[0].id);

  // Later calls reuse the binding and never provision again.
  const agents = await callTool(env.api, token(), "list_relay_agents");
  assert.equal(agents.status, 200, agents.text);
  assert.equal(agents.body.result.structuredContent.agent, agent);
  assert.equal(stub.state.calls, 1);
  assert.equal((await identityRows(env)).length, 1);
});

test("unbound workspace: a failed provisioning answers a retryable 503, keeps the reserved row and a later call reuses it", async (t) => {
  const stub = provisionerStub();
  const env = await start(t, true, identityFetch(), undefined, { relaycastProvisioner: stub.provisioner, relaycastBinding: "store" });
  await unboundWorkspace(env);

  for (const [index, fail] of (["refused", "plain"] as const).entries()) {
    stub.state.fail = fail;
    const failed = await rpc(env.api, token(), "tools/list");
    assert.equal(failed.status, 503, failed.text);
    assert.equal(failed.body.error.code, -32000);
    assert.equal(failed.body.error.message, PROVISIONING_FAILED);
    assert.equal(failed.headers.get("retry-after"), "5");
    // One provisioning attempt per request.
    assert.equal(stub.state.calls, index + 1);
    const rows = await identityRows(env);
    assert.equal(rows.length, 1, "the reserved row is kept, never duplicated");
    assert.deepEqual([rows[0].state, rows[0].relay_workspace_id, rows[0].token_ciphertext, rows[0].last_error],
      ["binding", null, null, PROVISIONING_TEXT]);
    assert.equal((await workspacePair(env)).relaycast_workspace_id, null);
  }
  const reserved = (await identityRows(env))[0];

  stub.state.fail = null;
  const listed = await rpc(env.api, token(), "tools/list");
  assert.equal(listed.status, 200, listed.text);
  assert.equal(stub.state.calls, 3);
  const rows = await identityRows(env);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].id, reserved.id, "the reserved row is enrolled");
  assert.deepEqual([rows[0].state, rows[0].relay_workspace_id, rows[0].last_error], ["bound", "rw_lazy_replicas", null]);
  assert.equal((await workspacePair(env)).relaycast_workspace_id, "rw_lazy_replicas");
});

test("unbound workspace: a binding that does not persist is called once and answers a retryable 503", async (t) => {
  let calls = 0;
  const env = await start(t, true, identityFetch(), undefined, {
    relaycastBinding: async () => {
      calls += 1;
      return { relaycastWorkspaceId: "rw_ghost", relaycastApiKey: "rk_ghost" };
    },
  });
  await unboundWorkspace(env);
  const failed = await rpc(env.api, token(), "tools/list");
  assert.equal(failed.status, 503, failed.text);
  assert.equal(failed.body.error.message, PROVISIONING_FAILED);
  assert.equal(failed.headers.get("retry-after"), "5");
  assert.equal(calls, 1, "never a second create in the same request");
  const rows = await identityRows(env);
  assert.equal(rows.length, 1);
  assert.deepEqual([rows[0].state, rows[0].relay_workspace_id, rows[0].last_error], ["binding", null, PROVISIONING_TEXT]);
  assert.equal((await workspacePair(env)).relaycast_workspace_id, null);
});

test("unbound workspace: a replica refused by policy reserves and provisions nothing", async (t) => {
  const stub = provisionerStub();
  const env = await start(t, true, identityFetch(), undefined, { relaycastProvisioner: stub.provisioner, relaycastBinding: "store" });
  // No principal and an unmapped creator: refused before enrolment.
  await unboundWorkspace(env, false);
  const refused = await rpc(env.api, token(), "tools/list");
  assert.equal(refused.status, 403, refused.text);
  assert.equal(refused.body.error.message, "replica_creator_not_allowed");
  assert.equal(stub.state.calls, 0);
  assert.equal((await identityRows(env)).length, 0);
  assert.equal((await workspacePair(env)).relaycast_workspace_id, null);
});

test("unbound workspace: without a configured binding the call answers a retryable 503 and keeps the reserved row", async (t) => {
  const env = await start(t);
  await unboundWorkspace(env);
  for (let call = 0; call < 2; call++) {
    const failed = await rpc(env.api, token(), "tools/list");
    assert.equal(failed.status, 503, failed.text);
    assert.equal(failed.body.error.message, PROVISIONING_FAILED);
    assert.equal(failed.headers.get("retry-after"), "5");
  }
  const rows = await identityRows(env);
  assert.equal(rows.length, 1);
  assert.deepEqual([rows[0].state, rows[0].relay_workspace_id, rows[0].last_error], ["binding", null, PROVISIONING_TEXT]);
  assert.equal((await workspacePair(env)).relaycast_workspace_id, null);
});

test("unbound workspace: the API launch path and release are lookup-only and never provision", async (t) => {
  const stub = provisionerStub();
  const env = await start(t, true, identityFetch(), undefined, { relaycastProvisioner: stub.provisioner, relaycastBinding: "store" });
  await unboundWorkspace(env);
  const actor = { userId: env.ownerId, workspaceId: env.workspaceId, organizationId: env.organizationId };
  // Service calls directly: the REST workspace routes resolve the workspace binding before reaching Replicas.
  await assert.rejects(
    spawnReplica(env.replicas.deps, actor, { client_request_id: "lazy-launch", environment_id: ENV_A, name: "lazy", task: "work" }),
    (error: any) => error.status === 409 && error.message === "The replica's relay is unavailable.",
  );
  assert.equal(await count(env, "SELECT 1 FROM replica_spawns WHERE source = 'spawn'"), 0);

  // A reserved row left by a failed provisioning releases cleanly without Relay.
  stub.state.fail = "refused";
  assert.equal((await rpc(env.api, token(), "tools/list")).status, 503);
  assert.equal(stub.state.calls, 1);
  const reserved = (await identityRows(env))[0];
  assert.equal(reserved.relay_workspace_id, null);
  stub.state.fail = null;
  const released = await releaseReplica(env.replicas.deps, actor, reserved.id);
  assert.equal(released.released, true);
  const row = (await identityRows(env))[0];
  assert.equal(row.state, "gone");
  assert.equal(row.input.cleanup_complete, true);
  assert.equal(stub.state.calls, 1, "release never provisions");
  assert.equal((await workspacePair(env)).relaycast_workspace_id, null);
  // The release tombstones the replica: it stays refused and nothing is provisioned for it.
  const refused = await rpc(env.api, token(), "tools/list");
  assert.equal(refused.status, 403, refused.text);
  assert.equal(refused.body.error.message, "replica_released");
  assert.equal(stub.state.calls, 1);
});
