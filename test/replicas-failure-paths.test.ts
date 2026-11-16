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
  // discover: revoked = 401, unavailable = 503, partial = an incomplete listing (more pages than the bound).
  const mode = { register: "ok" as "ok" | "fail" | "reject" | "lost" | "conflict",
    discover: "ok" as "ok" | "fail" | "revoked" | "unavailable" | "partial" };
  const runtime = {
    identity: async () => ({ organization: { id: PROVIDER_ORG, name: "Org" } }),
    environments: async () => ({ environments }),
    allEnvironments: async (key: string) => {
      assert.equal(key, REPLICAS_KEY);
      if (mode.discover === "fail") throw new ReplicasRuntimeError("unknown", "replicas_timeout");
      if (mode.discover === "revoked") throw new ReplicasRuntimeError("rejected", "replicas_http_401", 401);
      if (mode.discover === "unavailable") throw new ReplicasRuntimeError("rejected", "replicas_http_503", 503);
      return { environments: [...environments], complete: mode.discover !== "partial" };
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

test("access-revoked latch: a provider 401 refuses every token until a 2xx environments list or a re-connect", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, provider, database } = env;
  assert.equal((await connect(env)).status, 200);
  await mapOwner(env);
  assert.equal((await rpc(api, token(), "tools/list")).status, 200);
  const sweep = new ReplicasSyncSweep({ replicas: env.replicas.deps, intervalSeconds: 30 });
  t.after(() => sweep.stop());
  const latch = async () => (await database.query<{ access_revoked_at: Date | null; access_error: string | null }>(
    "SELECT access_revoked_at, access_error FROM remote_agent_connections WHERE workspace_id = $1 AND provider = 'replicas'",
    [workspaceId])).rows[0]!;
  const refusedNow = async () => {
    const refused = await rpc(api, token(), "tools/list");
    assert.equal(refused.status, 403, refused.text);
    assert.equal(refused.body.error.message, "replica_environment_not_enabled");
  };

  // A 401 on an automatic sync latches the connection: the token is refused.
  provider.mode.discover = "revoked";
  await sweep.tick();
  const first = await latch();
  assert.ok(first.access_revoked_at);
  assert.match(first.access_error!, /HTTP 401/);
  await refusedNow();
  const listed = await api(`/api/v1/workspaces/${workspaceId}/remote-agent-connections`, { token: ownerToken });
  const replicas = listed.body.providers.find((item: any) => item.id === "replicas");
  assert.equal(replicas.connection.accessRevoked.since, new Date(first.access_revoked_at!).toISOString());
  const policies = await api(`/api/v1/workspaces/${workspaceId}/replicas/environment-policies`, { token: ownerToken });
  assert.equal(policies.body.accessRevoked.since, new Date(first.access_revoked_at!).toISOString());
  assert.deepEqual(policies.body.environments.map((item: any) => [item.environmentId, item.status]),
    [[ENV_A, "access_revoked"], [ENV_B, "access_revoked"]]);

  // A following 503 proves nothing: still refused, the first timestamp kept.
  provider.mode.discover = "unavailable";
  await sweep.tick();
  assert.equal((await latch()).access_revoked_at!.getTime(), first.access_revoked_at!.getTime());
  await refusedNow();
  // Another 401 keeps the first timestamp too.
  provider.mode.discover = "revoked";
  await sweep.tick();
  assert.equal((await latch()).access_revoked_at!.getTime(), first.access_revoked_at!.getTime());

  // A 2xx environments list clears it: admitted again.
  provider.mode.discover = "ok";
  await sweep.tick();
  assert.equal((await latch()).access_revoked_at, null);
  assert.equal((await latch()).access_error, null);
  assert.equal((await rpc(api, token(), "tools/list")).status, 200);

  // A 401 inside a locked step that rolls back still latches (recover reads the replica).
  const spawnId = await launchRow(env, "spawn", randomUUID(), "creating");
  await database.query("UPDATE replica_spawns SET replica_id = NULL WHERE id = $1", [spawnId]);
  const runtime = env.replicas.deps.replicas as unknown as Record<string, unknown>;
  runtime.get = async () => { throw new ReplicasRuntimeError("rejected", "replicas_http_403", 403); };
  await assert.rejects(recoverReplica(env.replicas.deps, { userId: env.ownerId, workspaceId, organizationId: env.organizationId },
    spawnId, randomUUID()));
  assert.match((await latch()).access_error!, /HTTP 403/);
  await refusedNow();

  // A successful re-connect clears it, even when its own discovery is unavailable.
  provider.mode.discover = "unavailable";
  assert.equal((await connect(env)).status, 200);
  assert.equal((await latch()).access_revoked_at, null);
  assert.equal((await rpc(api, token(), "tools/list")).status, 200);
});

test("discovery-away fencing: a complete listing without an enabled environment refuses it until it is listed again", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, provider, database } = env;
  const base = `/api/v1/workspaces/${workspaceId}/replicas`;
  provider.environments.push({ id: ENV_C, name: "gamma" });
  assert.equal((await connect(env)).status, 200);
  await mapOwner(env);
  assert.equal((await api(`${base}/environments/${ENV_B}`, {
    method: "PUT", token: ownerToken, body: { enabled: true, creators: [{ creatorId: "creator-owner", userId: env.ownerId }] },
  })).status, 200);
  assert.equal((await rpc(api, token(), "tools/list")).status, 200);
  // ENV_C is opted out by the admin; ENV_B lost its registration and is due for a retry.
  assert.equal((await api(`${base}/environments/${ENV_C}`, { method: "PUT", token: ownerToken, body: { enabled: false } })).status, 200);
  assert.equal((await policyRow(env, ENV_C)).opted_out, true);
  provider.entriesOf(ENV_B).length = 0;
  await database.query("UPDATE replica_environment_policies SET registered_mcp_id = NULL WHERE workspace_id = $1 AND environment_id = $2",
    [workspaceId, ENV_B]);
  const creates = countCreates(env);
  const sweep = new ReplicasSyncSweep({ replicas: env.replicas.deps, intervalSeconds: 30 });
  t.after(() => sweep.stop());
  const listOnly = (...ids: string[]) => {
    const all = [{ id: ENV_A, name: "alpha" }, { id: ENV_B, name: "beta" }, { id: ENV_C, name: "gamma" }];
    provider.environments.splice(0, provider.environments.length, ...all.filter((item) => ids.includes(item.id)));
  };

  // A partial or failed listing without ENV_A changes nothing.
  listOnly(ENV_B);
  for (const mode of ["partial", "fail", "unavailable"] as const) {
    provider.mode.discover = mode;
    await syncEnvironments(env.replicas.deps, serviceActor(env));
    assert.equal((await policyRow(env, ENV_A)).discovery_missing_since, null, mode);
    assert.equal((await rpc(api, token(), "tools/list")).status, 200, mode);
  }
  creates.length = 0;
  await database.query("UPDATE replica_environment_policies SET registered_mcp_id = NULL WHERE workspace_id = $1 AND environment_id = $2",
    [workspaceId, ENV_B]);
  provider.entriesOf(ENV_B).length = 0;

  // A complete listing without ENV_A (and ENV_C): ENV_A is fenced and refused, ENV_B still registers.
  provider.mode.discover = "ok";
  await sweep.tick();
  const fenced = await policyRow(env, ENV_A);
  assert.ok(fenced.discovery_missing_since);
  assert.equal(fenced.enabled, true);
  assert.equal(fenced.opted_out, false);
  const refused = await rpc(api, token(), "tools/list");
  assert.equal(refused.status, 403, refused.text);
  assert.equal(refused.body.error.message, "replica_environment_not_enabled");
  assert.deepEqual(creates, [ENV_B]);
  assert.ok((await policyRow(env, ENV_B)).registered_mcp_id);
  const otherEnvironment = await rpc(api, token({ environment_id: ENV_B, workspace_id: WORKSPACE_2 }), "tools/list");
  assert.equal(otherEnvironment.status, 200, otherEnvironment.text);
  // The opted-out ENV_C was not enabled, so it is not fenced, and its opt-out survives.
  const optedOut = await policyRow(env, ENV_C);
  assert.equal(optedOut.discovery_missing_since, null);
  assert.equal(optedOut.opted_out, true);
  const view = await api(`${base}/environment-policies`, { token: ownerToken });
  const viewA = view.body.environments.find((item: any) => item.environmentId === ENV_A);
  assert.equal(viewA.status, "discovery_missing");
  assert.equal(viewA.discoveryMissingSince, new Date(fenced.discovery_missing_since).toISOString());
  // A later complete listing keeps the first timestamp.
  await sweep.tick();
  assert.equal((await policyRow(env, ENV_A)).discovery_missing_since.getTime(), fenced.discovery_missing_since.getTime());

  // Listed again: the fence is lifted and ENV_A admits; ENV_C stays opted out.
  listOnly(ENV_A, ENV_B, ENV_C);
  await sweep.tick();
  assert.equal((await policyRow(env, ENV_A)).discovery_missing_since, null);
  assert.equal((await rpc(api, token(), "tools/list")).status, 200);
  const after = await policyRow(env, ENV_C);
  assert.equal(after.opted_out, true);
  assert.equal(after.enabled, false);
  assert.deepEqual(creates, [ENV_B]);
});

test("launch create: an unknown create outcome stays creating; a same-id retry never creates again; recover needs a positive marker", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, ownerId, organizationId } = env;
  assert.equal((await connect(env)).status, 200);
  const runtime = env.replicas.deps.replicas as unknown as Record<string, unknown>;
  const replicaId = randomUUID();
  const chatId = randomUUID();
  const creates: string[] = [];
  const history: Array<{ type: string; payload: Record<string, unknown> }> = [];
  let found = false;
  runtime.create = async (_key: string, input: { message: string }) => {
    creates.push(input.message);
    throw new ReplicasRuntimeError("unknown", "replicas_http_503", 503);
  };
  runtime.get = async (_key: string, id: string) => {
    if (!found) throw new ReplicasRuntimeError("rejected", "replicas_http_404", 404);
    return { replica: { id, name: "worker", status: "active", chats: [{ id: chatId, provider: "claude" }] } };
  };
  runtime.history = async () => ({ events: history });
  runtime.wake = async () => null;
  runtime.exec = async () => ({ exit_code: 0, timed_out: false, output: "ready\n" });

  // The provider answers 503: the row stays creating without a replica id.
  const body = { client_request_id: "launch-1", environment_id: ENV_A, name: "worker", task: "Fix the flaky test" };
  const spawned = await api(`/api/v1/workspaces/${workspaceId}/replicas/spawns`, { method: "POST", token: ownerToken, body });
  assert.ok(spawned.status < 300, spawned.text);
  const spawnId = spawned.body.spawn_id as string;
  let row = await spawnRow(env, spawnId);
  assert.equal(row.state, "creating");
  assert.equal(row.replica_id, null);
  assert.equal(creates.length, 1);
  assert.equal(spawned.body.outcome_unknown, true);

  // A retry under the same request id returns the same launch and never POSTs again.
  const retried = await api(`/api/v1/workspaces/${workspaceId}/replicas/spawns`, { method: "POST", token: ownerToken, body });
  assert.equal(retried.body.spawn_id, spawnId, retried.text);
  assert.equal(creates.length, 1);
  assert.equal((await spawnRow(env, spawnId)).state, "creating");

  // Recover with a 404 from get throws and leaves the row creating.
  const actor = { userId: ownerId, workspaceId, organizationId };
  await assert.rejects(recoverReplica(env.replicas.deps, actor, spawnId, replicaId));
  row = await spawnRow(env, spawnId);
  assert.equal(row.state, "creating");
  assert.equal(row.replica_id, null);

  // The replica turns up with the launch marker in its original chat: recover advances the row.
  found = true;
  history.push({ type: "claude-user", payload: { message: { content: creates[0] } } });
  const recovered = await recoverReplica(env.replicas.deps, actor, spawnId, replicaId);
  assert.equal(recovered.spawn_id, spawnId);
  row = await spawnRow(env, spawnId);
  assert.notEqual(row.state, "creating");
  assert.equal(row.replica_id, replicaId);
  assert.equal(row.chat_id, chatId);
  assert.equal(creates.length, 1);
});

// The unique live-row indexes on replica_spawns are exact-case, so an older and a newer live row of the
// same replica coexist in one workspace only under different replica_id casing (provider canonical vs claims).
const backdate = (env: Env, id: string, before: string) => env.database.query(
  "UPDATE replica_spawns SET created_at = (SELECT created_at FROM replica_spawns WHERE id = $2) - interval '1 minute' WHERE id = $1", [id, before]);

test("releasing an older bind row keeps a newer environment-identity binding of the same replica live and unfenced", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerId } = env;
  assert.equal((await connect(env)).status, 200);
  await mapOwner(env);
  const actor = { userId: ownerId, workspaceId, organizationId: env.organizationId };

  // (a) An API bind row is older than the environment-identity binding the MCP call uses.
  assert.equal((await rpc(api, token(), "tools/list")).status, 200);
  const newer = await liveBinding(env);
  assert.ok(newer);
  const bound = await launchRow(env, "bind", WORKSPACE_1.toUpperCase());
  await backdate(env, bound, newer.id);

  await releaseReplica(env.replicas.deps, actor, bound);
  assert.equal((await spawnRow(env, bound)).state, "gone");
  assert.equal((await spawnRow(env, bound)).input.released, true);
  assert.equal((await liveBinding(env))?.id, newer.id, "the newer binding stays live");
  assert.deepEqual(await tombstones(env), [], "the older release writes no tombstone");
  assert.equal((await rpc(api, token(), "tools/list")).status, 200, "admission still succeeds");
  assert.equal((await liveBinding(env))?.id, newer.id);

  // Releasing the newer row does tombstone the replica.
  await releaseReplica(env.replicas.deps, actor, newer.id);
  assert.deepEqual(await tombstones(env), [{
    issuer: ISSUER, provider_organization_id: PROVIDER_ORG, provider_workspace_id: WORKSPACE_1, workspace_id: workspaceId, reason: "released",
  }]);
  assert.equal((await rpc(api, token(), "tools/list")).body.error.message, "replica_released");
});

test("releasing an older environment-identity binding keeps a newer bind row of the same replica live and unfenced", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerId } = env;
  assert.equal((await connect(env)).status, 200);
  await mapOwner(env);
  const actor = { userId: ownerId, workspaceId, organizationId: env.organizationId };

  // (b) An environment-identity binding first, then a later bind of the same replica.
  assert.equal((await rpc(api, token(), "tools/list")).status, 200);
  const older = await liveBinding(env);
  assert.ok(older);
  const bound = await launchRow(env, "bind", WORKSPACE_1.toUpperCase());

  await releaseReplica(env.replicas.deps, actor, older.id);
  assert.equal((await spawnRow(env, older.id)).state, "gone");
  assert.equal((await spawnRow(env, older.id)).input.released, true);
  assert.equal((await spawnRow(env, bound)).state, "bound", "the newer bind row stays live");
  assert.deepEqual(await tombstones(env), [], "the older release writes no tombstone");
  assert.equal((await rpc(api, token(), "tools/list")).status, 200, "admission still succeeds (it reuses the bind row)");
  assert.equal((await spawnRow(env, bound)).state, "bound");

  // Releasing the newer row does tombstone the replica.
  await releaseReplica(env.replicas.deps, actor, bound);
  assert.deepEqual(await tombstones(env), [{
    issuer: ISSUER, provider_organization_id: PROVIDER_ORG, provider_workspace_id: WORKSPACE_1, workspace_id: workspaceId, reason: "released",
  }]);
  assert.equal((await rpc(api, token(), "tools/list")).body.error.message, "replica_released");
});

test("a revived release keeps an older policy-retired binding's release from re-fencing the replica", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerId } = env;
  assert.equal((await connect(env)).status, 200);
  await mapOwner(env);
  const actor = { userId: ownerId, workspaceId, organizationId: env.organizationId };
  const fence = [{
    issuer: ISSUER, provider_organization_id: PROVIDER_ORG, provider_workspace_id: WORKSPACE_1, workspace_id: workspaceId, reason: "released",
  }];

  // A: an environment-identity binding, then retired by policy (gone, no released marker).
  assert.equal((await rpc(api, token(), "tools/list")).status, 200);
  const older = await liveBinding(env);
  assert.ok(older);
  await env.database.query("UPDATE replica_spawns SET state = 'gone' WHERE id = $1", [older.id]);
  assert.equal((await spawnRow(env, older.id)).input.released, undefined);

  // B: a newer bind of the same replica, explicitly released, then explicitly revived.
  const bound = await launchRow(env, "bind", WORKSPACE_1);
  await backdate(env, older.id, bound);
  await releaseReplica(env.replicas.deps, actor, bound);
  assert.deepEqual(await tombstones(env), fence);
  const revived = await recoverReplica(env.replicas.deps, actor, bound, WORKSPACE_1, { revive: true });
  assert.equal((revived as { revived?: boolean }).revived, true);
  assert.deepEqual(await tombstones(env), []);
  const revivedRow = await spawnRow(env, bound);
  assert.equal(revivedRow.state, "gone");
  assert.equal(revivedRow.input.released, true);
  assert.ok(revivedRow.input.revived_at, "the revive is persisted on the row");

  // Releasing A before the next call re-enrols must not undo the revive.
  await releaseReplica(env.replicas.deps, actor, older.id);
  assert.equal((await spawnRow(env, older.id)).state, "gone");
  assert.equal((await spawnRow(env, older.id)).input.released, true);
  assert.deepEqual(await tombstones(env), [], "the older release writes no tombstone");
  await releaseReplica(env.replicas.deps, actor, older.id);
  assert.deepEqual(await tombstones(env), [], "a repeat release of A stays a no-op");

  // The next admitted call enrols C; releasing C fences the replica again.
  assert.equal((await rpc(api, token(), "tools/list")).status, 200);
  const enrolled = await liveBinding(env);
  assert.ok(enrolled);
  assert.notEqual(enrolled.id, older.id);
  assert.notEqual(enrolled.id, bound);
  await releaseReplica(env.replicas.deps, actor, enrolled.id);
  assert.deepEqual(await tombstones(env), fence);
  assert.equal((await rpc(api, token(), "tools/list")).body.error.message, "replica_released");
});

const secondWorkspace = async (env: Env) => {
  const created = await env.api(`/api/v1/organizations/${env.organizationId}/workspaces`, {
    method: "POST", token: BOOTSTRAP, body: { name: "secondary", relaycastWorkspaceId: "rc-secondary", relaycastApiKey: "rk_live_secondary" },
  });
  assert.equal(created.status, 201, created.text);
  const workspaceId = created.body.id as string;
  return { workspaceId, ownerToken: await env.login(env.ownerId, workspaceId) };
};

test("workspace deletion tombstones a retired environment identity: the replica is refused in the next workspace", async (t) => {
  const env = await start(t);
  const { api, workspaceId, store } = env;
  assert.equal((await connect(env)).status, 200);
  await mapOwner(env);
  assert.equal((await rpc(api, token(), "tools/list")).status, 200);
  const binding = await liveBinding(env);
  assert.ok(binding);
  // Retired by policy: gone, no released marker, no tombstone.
  await env.database.query("UPDATE replica_spawns SET state = 'gone' WHERE id = $1", [binding.id]);
  assert.equal((await spawnRow(env, binding.id)).input.released, undefined);
  assert.deepEqual(await tombstones(env), []);

  const next = await secondWorkspace(env);
  assert.equal(await store.deleteWorkspace({ organizationId: env.organizationId, workspaceId, allowLast: true, actor: { kind: "bootstrap" } }), "deleted");
  assert.equal(await count(env, "SELECT 1 FROM replica_spawns WHERE id = $1", [binding.id]), 0);
  assert.deepEqual(await tombstones(env), [{
    issuer: ISSUER, provider_organization_id: PROVIDER_ORG, provider_workspace_id: WORKSPACE_1, workspace_id: null, reason: "workspace_deleted",
  }]);
  env.world.agents.clear();
  env.roster.length = 0;

  assert.equal((await connect(env, next.workspaceId, next.ownerToken)).status, 200);
  await mapOwner(env, next.workspaceId, next.ownerToken);
  const refused = await rpc(api, token(), "tools/list");
  assert.equal(refused.status, 403, refused.text);
  assert.equal(refused.body.error.message, "replica_released");
  assert.equal(await count(env, "SELECT 1 FROM replica_spawns WHERE workspace_id = $1", [next.workspaceId]), 0);
});

test("a disconnected workspace keeps its replica: another workspace is refused replica_owned_elsewhere, a re-connect admits it", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken } = env;
  const connection = (id: string) => `/api/v1/workspaces/${id}/remote-agent-connections/replicas`;
  assert.equal((await connect(env)).status, 200);
  await mapOwner(env);
  assert.equal((await rpc(api, token(), "tools/list")).status, 200);
  assert.ok(await liveBinding(env));

  assert.equal((await api(connection(workspaceId), { method: "DELETE", token: ownerToken })).status, 200);
  assert.equal(await liveBinding(env), undefined, "the disconnect retires the binding");
  assert.deepEqual(await tombstones(env), []);

  const next = await secondWorkspace(env);
  assert.equal((await connect(env, next.workspaceId, next.ownerToken)).status, 200);
  await mapOwner(env, next.workspaceId, next.ownerToken);
  const refused = await rpc(api, token(), "tools/list");
  assert.equal(refused.status, 403, refused.text);
  assert.equal(refused.body.error.message, "replica_owned_elsewhere");
  assert.equal(await count(env, "SELECT 1 FROM replica_spawns WHERE workspace_id = $1", [next.workspaceId]), 0);

  // Back in the owning workspace, its own retired rows are not "elsewhere".
  assert.equal((await api(connection(next.workspaceId), { method: "DELETE", token: next.ownerToken })).status, 200);
  assert.equal((await connect(env)).status, 200);
  await mapOwner(env);
  const admitted = await rpc(api, token(), "tools/list");
  assert.equal(admitted.status, 200, admitted.text);
  assert.equal((await liveBinding(env))?.user_id, env.ownerId);
});
