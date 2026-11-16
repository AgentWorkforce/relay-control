import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { createReplicasModule } from "../src/replicas/module.js";
import { ReplicasRuntimeError, type ReplicasRuntime } from "../src/replicas/runtime.js";
import { syncEnvironments } from "../src/replicas/environments.js";
import { encrypt, releaseReplica, recoverReplica } from "../src/replicas/service.js";
import { REPLICAS_SYNC_SERVICE, ReplicasSyncSweep } from "../src/replicas/sync-sweep.js";
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
  const slept: string[] = [];
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
    sleep: async (_key: string, replicaId: string) => {
      slept.push(replicaId);
      return null;
    },
    exec: async () => {
      throw new Error("environment bindings never exec");
    },
  };
  return { runtime: runtime as unknown as ReplicasRuntime, environments, registered, removed, slept, mode, entriesOf };
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

async function start(t: TestContext, enabled = true, issuerFetch: typeof fetch = identityFetch()) {
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
    replicas: { enabled }, config, database, relaycastFetch: messagingFetch, runtime: provider.runtime, identityFetch: issuerFetch,
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
  return { database, world, roster, provider, replicas, api, store, ...await seed(api) };
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
  const login = async (userId: string, target = workspaceId) => {
    const started = await api("/api/v1/auth/device/start", { method: "POST", body: {} });
    const approved = await api("/api/v1/auth/device/approve", {
      method: "POST", token: BOOTSTRAP,
      body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: target },
    });
    assert.equal(approved.status, 200);
    const issued = await api("/api/v1/auth/device/token", { method: "POST", body: { device_code: started.body.device_code } });
    assert.equal(issued.status, 200);
    return issued.body.access_token as string;
  };
  return {
    organizationId, workspaceId, ownerId: org.body.owner.id as string, memberId: member.body.userId as string,
    ownerToken: await login(org.body.owner.id as string), memberToken: await login(member.body.userId as string), login,
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

type Env = Awaited<ReturnType<typeof start>>;
async function count(env: Env, sql: string, params: unknown[] = []) {
  return (await env.database.query<{ n: number }>(`SELECT count(*)::int AS n FROM (${sql}) q`, params)).rows[0]!.n;
}
const connect = (env: Env, workspaceId = env.workspaceId, bearer = env.ownerToken) =>
  env.api(`/api/v1/workspaces/${workspaceId}/remote-agent-connections/replicas`, { method: "POST", token: bearer, body: { key: REPLICAS_KEY } });

const mapOwner = async (env: Env, workspaceId = env.workspaceId, bearer = env.ownerToken) => {
  const mapped = await env.api(`/api/v1/workspaces/${workspaceId}/replicas/environments/${ENV_A}`, {
    method: "PUT", token: bearer, body: { enabled: true, creators: [{ creatorId: "creator-owner", userId: env.ownerId }] },
  });
  assert.equal(mapped.status, 200, mapped.text);
};

async function launchRow(env: Env, source: "spawn" | "bind", replicaId: string, state = "bound") {
  const id = randomUUID();
  await env.database.query(
    `INSERT INTO replica_spawns (id, workspace_id, organization_id, user_id, client_request_id, source, input, replica_id, chat_id, state)
     VALUES ($1, $2, $3, $4, $5, $6, '{}'::jsonb, $7, $8, $9)`,
    [id, env.workspaceId, env.organizationId, env.ownerId, `request-${id}`, source, replicaId, randomUUID(), state],
  );
  return id;
}
const tombstones = async (env: Env) => (await env.database.query<{
  issuer: string; provider_organization_id: string; provider_workspace_id: string; workspace_id: string | null; reason: string;
}>("SELECT issuer, provider_organization_id, provider_workspace_id, workspace_id, reason FROM replica_identity_tombstones ORDER BY provider_workspace_id")).rows;
const callTool = (api: Api, bearer: string, name: string, args: Record<string, unknown> = {}) =>
  rpc(api, bearer, "tools/call", { name, arguments: args });
const serviceActor = (env: Env) => ({ userId: "", workspaceId: env.workspaceId, organizationId: env.organizationId, service: REPLICAS_SYNC_SERVICE });
const IDENTITY_CONFIG = { url: MCP_URL, headers: {}, auth: { type: "workspace_identity", audience: MCP_URL } };
const policyRow = async (env: Env, environmentId: string) => (await env.database.query<any>(
  "SELECT * FROM replica_environment_policies WHERE workspace_id = $1 AND environment_id = $2", [env.workspaceId, environmentId])).rows[0];
/** Counts every create the provider receives, whatever its outcome. */
function countCreates(env: Env) {
  const calls: string[] = [];
  const runtime = env.replicas.deps.replicas;
  const register = runtime.registerEnvironmentMcp.bind(runtime);
  runtime.registerEnvironmentMcp = (key, environmentId, body) => { calls.push(environmentId); return register(key, environmentId, body); };
  return calls;
}
const views = async (env: Env) => (await env.api(`/api/v1/workspaces/${env.workspaceId}/replicas/environment-policies`, { token: env.ownerToken }))
  .body.environments.map((item: any) => [item.environmentId, item.status]);

test("persisted create intent: automatic runs only relist while a create is unconfirmed; a person run may create again", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, provider } = env;
  assert.equal((await connect(env)).status, 200);
  const creates = countCreates(env);
  provider.environments.push({ id: ENV_C, name: "gamma" });
  provider.mode.register = "fail";
  const first = await syncEnvironments(env.replicas.deps, serviceActor(env));
  assert.deepEqual(first.environments, [{ environmentId: ENV_C, status: "registration_unconfirmed", retryable: true }]);
  assert.deepEqual(creates, [ENV_C]);
  assert.equal((await policyRow(env, ENV_C)).create_unconfirmed, true, "an unknown create outcome sets the intent");

  // Automatic runs with a complete, empty listing never create again.
  provider.mode.register = "ok";
  const sweep = new ReplicasSyncSweep({ replicas: env.replicas.deps, intervalSeconds: 30 });
  t.after(() => sweep.stop());
  await sweep.tick();
  const again = await syncEnvironments(env.replicas.deps, serviceActor(env));
  assert.deepEqual(again.environments, [{ environmentId: ENV_C, status: "registration_unconfirmed", retryable: true }]);
  assert.deepEqual(creates, [ENV_C]);
  assert.deepEqual(await views(env), [[ENV_A, "registered"], [ENV_B, "registered"], [ENV_C, "registration_unconfirmed"]]);

  // The lost create shows up later: the next automatic run records it and clears the intent.
  provider.entriesOf(ENV_C).push({ id: "mcp_late", organization_id: PROVIDER_ORG, environment_id: ENV_C,
    name: "agent-relay-replica", transport: "http", config: structuredClone(IDENTITY_CONFIG) });
  await sweep.tick();
  let row = await policyRow(env, ENV_C);
  assert.equal(row.registered_mcp_id, "mcp_late");
  assert.equal(row.create_unconfirmed, false);
  assert.deepEqual(creates, [ENV_C]);

  // A person sync after a complete, empty listing creates exactly once more.
  const ENV_D = "4e4e4e4e-4e4e-4e4e-8e4e-4e4e4e4e4e4e";
  provider.environments.push({ id: ENV_D, name: "delta" });
  provider.mode.register = "fail";
  await sweep.tick();
  assert.equal((await policyRow(env, ENV_D)).create_unconfirmed, true);
  provider.mode.register = "ok";
  await sweep.tick();
  assert.deepEqual(creates, [ENV_C, ENV_D]);
  const synced = await api(`/api/v1/workspaces/${workspaceId}/replicas/environments/sync`, { method: "POST", token: ownerToken });
  assert.equal(synced.status, 200, synced.text);
  assert.deepEqual(synced.body.environments, [{ environmentId: ENV_D, status: "registered" }]);
  assert.deepEqual(creates, [ENV_C, ENV_D, ENV_D]);
  row = await policyRow(env, ENV_D);
  assert.ok(row.registered_mcp_id);
  assert.equal(row.create_unconfirmed, false);

  // A definite rejection clears the intent.
  const ENV_E = "5f5f5f5f-5f5f-4f5f-8f5f-5f5f5f5f5f5f";
  provider.environments.push({ id: ENV_E, name: "epsilon" });
  provider.mode.register = "reject";
  await sweep.tick();
  assert.equal((await policyRow(env, ENV_E)).create_unconfirmed, false);
  assert.equal((await policyRow(env, ENV_E)).registered_mcp_id, null);
});

const AGENT = `replicas-${WORKSPACE_1.replaceAll("-", "").slice(0, 16)}`;
const liveBinding = async (env: Env) => (await env.database.query<any>(
  "SELECT id, user_id, input FROM replica_spawns WHERE source = 'environment_identity' AND replica_id = $1 AND state <> 'gone'", [WORKSPACE_1])).rows[0];
const spawnRow = async (env: Env, id: string) => (await env.database.query<any>("SELECT * FROM replica_spawns WHERE id = $1", [id])).rows[0];

test("removing a creator mapping releases its binding: it enrols as the principal, or is refused without one", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, ownerId, memberId, world } = env;
  const base = `/api/v1/workspaces/${workspaceId}/replicas`;
  assert.equal((await connect(env)).status, 200);
  await mapOwner(env);
  assert.equal((await rpc(api, token(), "tools/list")).status, 200);
  const first = await liveBinding(env);
  assert.equal(first.input.acts_as, "creator");
  assert.equal(first.user_id, ownerId);
  assert.equal(world.agents.get(AGENT)?.metadata.replicas_spawn_id, first.id);

  const unmapped = await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken, body: { creators: [] } });
  assert.equal(unmapped.status, 200, unmapped.text);
  assert.equal(await liveBinding(env), undefined);
  assert.equal(world.agents.get(AGENT), undefined, "the old Relay agent is retired");
  assert.equal((await spawnRow(env, first.id)).input.cleanup_complete, true);
  const refused = await rpc(api, token(), "tools/list");
  assert.equal(refused.status, 403, refused.text);
  assert.equal(refused.body.error.message, "replica_creator_not_allowed");

  assert.equal((await api(`${base}/environment-principal`, { method: "PUT", token: ownerToken, body: { userId: memberId } })).status, 200);
  assert.equal((await rpc(api, token(), "tools/list")).status, 200);
  const second = await liveBinding(env);
  assert.equal(second.input.acts_as, "principal");
  assert.equal(second.user_id, memberId);
});

test("sweep cleanup retry: an incomplete Relay release is retried with backoff", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, world, database } = env;
  const base = `/api/v1/workspaces/${workspaceId}/replicas`;
  assert.equal((await connect(env)).status, 200);
  await mapOwner(env);
  assert.equal((await rpc(api, token(), "tools/list")).status, 200);
  const first = await liveBinding(env);
  const releases: string[] = [];
  const relaycast = env.replicas.deps.relaycast;
  const release = relaycast.releaseHosted.bind(relaycast);
  relaycast.releaseHosted = (...args) => { releases.push(args[1]); return release(...args); };
  const events: Array<{ code: string; spawnId?: string }> = [];
  const sweep = new ReplicasSyncSweep({ replicas: env.replicas.deps, intervalSeconds: 30, log: (event) => events.push(event) });
  t.after(() => sweep.stop());

  // The disable commits; the Relay release after it answers 503.
  world.failNext("POST", "/v1/agents/release-exact", 503);
  assert.equal((await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken, body: { enabled: false } })).status, 200);
  let row = await spawnRow(env, first.id);
  assert.equal(row.state, "gone");
  assert.notEqual(row.input.cleanup_complete, true);
  assert.ok(world.agents.get(AGENT));

  // Relay healthy again: one sweep tick completes the cleanup.
  await sweep.tick();
  row = await spawnRow(env, first.id);
  assert.equal(row.input.cleanup_complete, true);
  assert.equal(row.input.cleanup_attempts, 1);
  assert.ok(row.input.cleanup_last_attempt_at);
  assert.equal(world.agents.get(AGENT), undefined);
  assert.equal(events.length, 0);

  // A row that keeps failing backs off.
  assert.equal((await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken, body: { enabled: true } })).status, 200);
  assert.equal((await rpc(api, token(), "tools/list")).status, 200);
  const second = await liveBinding(env);
  world.failNext("POST", "/v1/agents/release-exact", 503);
  assert.equal((await api(`${base}/environments/${ENV_A}`, { method: "PUT", token: ownerToken, body: { enabled: false } })).status, 200);
  releases.length = 0;
  world.failNext("POST", "/v1/agents/release-exact", 503);
  await sweep.tick();
  assert.deepEqual(releases, [AGENT]);
  assert.deepEqual(events.map((event) => [event.code, event.spawnId]), [["replicas_cleanup_failed", second.id]]);
  row = await spawnRow(env, second.id);
  assert.equal(row.input.cleanup_attempts, 1);
  assert.notEqual(row.input.cleanup_complete, true);
  await sweep.tick();
  assert.deepEqual(releases, [AGENT], "skipped before its backoff elapses");
  assert.equal((await spawnRow(env, second.id)).input.cleanup_attempts, 1);
  // Once the backoff elapsed it is retried and completes.
  await database.query(`UPDATE replica_spawns SET input = jsonb_set(input, '{cleanup_last_attempt_at}', to_jsonb($2::text)) WHERE id = $1`,
    [second.id, new Date(Date.now() - 61_000).toISOString()]);
  await sweep.tick();
  assert.deepEqual(releases, [AGENT, AGENT]);
  row = await spawnRow(env, second.id);
  assert.equal(row.input.cleanup_complete, true);
  assert.equal(row.input.cleanup_attempts, 2);
  assert.equal(world.agents.get(AGENT), undefined);
});
