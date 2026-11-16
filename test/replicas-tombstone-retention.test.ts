import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { createReplicasModule } from "../src/replicas/module.js";
import { ReplicasRuntimeError, type ReplicasRuntime } from "../src/replicas/runtime.js";
import { loadReplicasConfig } from "../src/replicas/config.js";
import { admitIdentity, IdentityRefusal } from "../src/replicas/environments.js";
import { encrypt, releaseReplica, recoverReplica } from "../src/replicas/service.js";
import { ReplicasSyncSweep } from "../src/replicas/sync-sweep.js";
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

test("config: SELFHOST_REPLICAS_SYNC_INTERVAL_SECONDS defaults to 60, clamps to 30, 0 is off", () => {
  assert.equal(loadReplicasConfig({}).syncIntervalSeconds, 60);
  assert.equal(loadReplicasConfig({ SELFHOST_REPLICAS_SYNC_INTERVAL_SECONDS: "10" }).syncIntervalSeconds, 30);
  assert.equal(loadReplicasConfig({ SELFHOST_REPLICAS_SYNC_INTERVAL_SECONDS: "45" }).syncIntervalSeconds, 45);
  assert.equal(loadReplicasConfig({ SELFHOST_REPLICAS_SYNC_INTERVAL_SECONDS: "0" }).syncIntervalSeconds, 0);
  assert.throws(() => loadReplicasConfig({ SELFHOST_REPLICAS_SYNC_INTERVAL_SECONDS: "-5" }), /whole number/);
  assert.throws(() => loadReplicasConfig({ SELFHOST_REPLICAS_SYNC_INTERVAL_SECONDS: "1m" }), /whole number/);
});

test("a per-launch release (REST and MCP) tombstones its replica; revive re-admits it", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, ownerId, memberId, provider } = env;
  assert.equal((await connect(env)).status, 200);
  await mapOwner(env);
  const actor = { userId: ownerId, workspaceId, organizationId: env.organizationId };

  // REST release of a spawn row: the tombstone commits with the revoke, before compute cleanup.
  const spawned = await launchRow(env, "spawn", WORKSPACE_1.toUpperCase());
  const released = await api(`/api/v1/workspaces/${workspaceId}/replicas/spawns/${spawned}`, { method: "DELETE", token: ownerToken });
  assert.equal(released.status, 200, released.text);
  assert.deepEqual(provider.slept, [WORKSPACE_1.toUpperCase()]);
  assert.deepEqual(await tombstones(env), [{
    issuer: ISSUER, provider_organization_id: PROVIDER_ORG, provider_workspace_id: WORKSPACE_1, workspace_id: workspaceId, reason: "released",
  }]);
  const refused = await rpc(api, token({ workspace_id: WORKSPACE_1 }), "tools/list");
  assert.equal(refused.status, 403);
  assert.equal(refused.body.error.message, "replica_released");

  // The MCP release_replica path (releaseReplica) for a bound chat.
  const bound = await launchRow(env, "bind", WORKSPACE_2);
  await releaseReplica(env.replicas.deps, actor, bound);
  assert.equal((await tombstones(env)).length, 2);
  assert.equal((await rpc(api, token({ workspace_id: WORKSPACE_2 }), "tools/list")).body.error.message, "replica_released");
  // A repeat release keeps the tombstone (idempotent).
  await releaseReplica(env.replicas.deps, actor, bound);
  assert.equal((await tombstones(env)).length, 2);

  // Revive: owner/admin only, the replica id must match, the same audit event.
  await assert.rejects(recoverReplica(env.replicas.deps, { ...actor, userId: memberId }, spawned, WORKSPACE_1, { revive: true }));
  await assert.rejects(recoverReplica(env.replicas.deps, actor, spawned, WORKSPACE_2, { revive: true }), /another replica/);
  const revived = await recoverReplica(env.replicas.deps, actor, spawned, WORKSPACE_1, { revive: true });
  assert.equal((revived as any).revived, true);
  assert.equal(await count(env, "SELECT 1 FROM admin_audit_events WHERE action = 'replicas.identity.revived' AND target = $1", [spawned]), 1);
  assert.deepEqual((await tombstones(env)).map((row) => row.provider_workspace_id), [WORKSPACE_2]);
  assert.equal((await rpc(api, token({ workspace_id: WORKSPACE_1 }), "tools/list")).status, 200);
  assert.equal(await count(env, "SELECT 1 FROM replica_spawns WHERE source = 'environment_identity' AND replica_id = $1 AND state <> 'gone'", [WORKSPACE_1]), 1);
  // A second revive finds nothing to remove.
  assert.equal(((await recoverReplica(env.replicas.deps, actor, spawned, WORKSPACE_1, { revive: true })) as any).revived, false);
});

test("a repeated release (REST and MCP) of a revived per-launch replica keeps it revived", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, ownerId } = env;
  assert.equal((await connect(env)).status, 200);
  await mapOwner(env);
  const actor = { userId: ownerId, workspaceId, organizationId: env.organizationId };

  const spawned = await launchRow(env, "spawn", WORKSPACE_1);
  const route = `/api/v1/workspaces/${workspaceId}/replicas/spawns/${spawned}`;
  assert.equal((await api(route, { method: "DELETE", token: ownerToken })).status, 200);
  assert.equal((await tombstones(env)).length, 1);
  const revived = await recoverReplica(env.replicas.deps, actor, spawned, WORKSPACE_1, { revive: true });
  assert.equal((revived as any).revived, true);
  assert.deepEqual(await tombstones(env), []);

  // The released row stays gone; repeating its release is a no-op and writes no tombstone.
  const again = await api(route, { method: "DELETE", token: ownerToken });
  assert.equal(again.status, 200, again.text);
  await releaseReplica(env.replicas.deps, actor, spawned);
  assert.deepEqual(await tombstones(env), []);
  assert.equal(await count(env, "SELECT 1 FROM replica_spawns WHERE id = $1 AND state = 'gone'", [spawned]), 1);

  // The revived replica is still admitted and enrols again.
  assert.equal((await rpc(api, token({ workspace_id: WORKSPACE_1 }), "tools/list")).status, 200);
  assert.equal(await count(env, "SELECT 1 FROM replica_spawns WHERE source = 'environment_identity' AND replica_id = $1 AND state <> 'gone'", [WORKSPACE_1]), 1);
});

test("an explicit release tombstones a binding a disable left gone without one; a repeat is a no-op", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken, database } = env;
  assert.equal((await connect(env)).status, 200);
  await mapOwner(env);
  assert.equal((await rpc(api, token({ workspace_id: WORKSPACE_1 }), "tools/list")).status, 200);
  const binding = (await database.query<{ id: string }>(
    "SELECT id FROM replica_spawns WHERE workspace_id = $1 AND source = 'environment_identity' AND state <> 'gone'", [workspaceId])).rows[0]!;

  // A disable releases the binding without a tombstone.
  const disabled = await api(`/api/v1/workspaces/${workspaceId}/replicas/environments/${ENV_A}`, {
    method: "PUT", token: ownerToken, body: { enabled: false },
  });
  assert.equal(disabled.status, 200, disabled.text);
  assert.equal(await count(env, "SELECT 1 FROM replica_spawns WHERE id = $1 AND state = 'gone'", [binding.id]), 1);
  assert.deepEqual(await tombstones(env), []);

  // The first explicit release still writes the tombstone.
  const route = `/api/v1/workspaces/${workspaceId}/replicas/spawns/${binding.id}`;
  const released = await api(route, { method: "DELETE", token: ownerToken });
  assert.equal(released.status, 200, released.text);
  assert.deepEqual(await tombstones(env), [{
    issuer: ISSUER, provider_organization_id: PROVIDER_ORG, provider_workspace_id: WORKSPACE_1, workspace_id: workspaceId, reason: "released",
  }]);
  // A repeat is a no-op: still exactly one tombstone row.
  const again = await api(route, { method: "DELETE", token: ownerToken });
  assert.equal(again.status, 200, again.text);
  assert.equal((await tombstones(env)).length, 1);
});

test("tombstones survive workspace deletion; only the org's connected workspace admin revives them", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerId, memberId, database, store } = env;
  const secondary = await api(`/api/v1/organizations/${env.organizationId}/workspaces`, {
    method: "POST", token: BOOTSTRAP, body: { name: "secondary", relaycastWorkspaceId: "rc-secondary", relaycastApiKey: "rk_live_secondary" },
  });
  assert.equal(secondary.status, 201, secondary.text);
  const next = secondary.body.id as string;
  assert.equal((await connect(env)).status, 200);
  await mapOwner(env);
  assert.equal((await rpc(api, token({ workspace_id: WORKSPACE_1 }), "tools/list")).status, 200);
  assert.equal(await count(env, "SELECT 1 FROM replica_spawns WHERE source = 'environment_identity' AND state <> 'gone'"), 1);

  const binding = (await database.query<{ id: string; user_id: string; agent_name: string; agent_remote_id: string }>(
    "SELECT id, user_id, agent_name, agent_remote_id FROM replica_spawns WHERE workspace_id = $1 AND source = 'environment_identity'",
    [workspaceId])).rows[0]!;
  assert.equal(await count(env,
    "SELECT 1 FROM hosted_relay_participants WHERE workspace_id = $1 AND user_id = $2 AND agent_name = $3 AND agent_remote_id = $4",
    [workspaceId, binding.user_id, binding.agent_name, binding.agent_remote_id]), 1);

  // An environment-identity binding does not restrict deletion: it is tombstoned and retired with it.
  const actor = { kind: "bootstrap" as const };
  assert.equal(await store.deleteWorkspace({ organizationId: env.organizationId, workspaceId, allowLast: true, actor }), "deleted");
  assert.equal(await count(env, "SELECT 1 FROM replica_spawns WHERE id = $1", [binding.id]), 0);
  assert.equal(await count(env,
    "SELECT 1 FROM hosted_relay_participants WHERE workspace_id = $1 AND user_id = $2 AND agent_name = $3 AND agent_remote_id = $4",
    [workspaceId, binding.user_id, binding.agent_name, binding.agent_remote_id]), 0);
  // The deleted workspace's Relay workspace goes with it (this fake shares one agent namespace).
  env.world.agents.clear();
  env.roster.length = 0;
  assert.deepEqual(await tombstones(env), [{
    issuer: ISSUER, provider_organization_id: PROVIDER_ORG, provider_workspace_id: WORKSPACE_1, workspace_id: null, reason: "workspace_deleted",
  }]);
  // Policies stay with the workspace.
  assert.equal(await count(env, "SELECT 1 FROM replica_environment_policies"), 0);
  const refused = await rpc(api, token({ workspace_id: WORKSPACE_1 }), "tools/list");
  assert.equal(refused.status, 403);
  assert.equal(refused.body.error.message, "replica_released");
  assert.equal(await count(env, "SELECT 1 FROM admin_audit_events WHERE action = 'replicas.identity.refused'"), 0);

  // The organization is connected again in another workspace: the orphan is still refused.
  const ownerToken = await env.login(ownerId, next);
  const memberToken = await env.login(memberId, next);
  assert.equal((await connect(env, next, ownerToken)).status, 200);
  await mapOwner(env, next, ownerToken);
  assert.equal((await rpc(api, token({ workspace_id: WORKSPACE_1 }), "tools/list")).body.error.message, "replica_released");
  const route = (id: string) => `/api/v1/workspaces/${next}/replicas/environment-tombstones/${id}`;
  assert.equal((await api(route(WORKSPACE_1), { method: "DELETE", token: memberToken })).status, 403);
  assert.equal((await api(route(randomUUID()), { method: "DELETE", token: ownerToken })).status, 404);
  assert.equal((await api(route("not-a-uuid"), { method: "DELETE", token: ownerToken })).status, 404);
  // An orphan of another provider organization is not this connection's to revive.
  const foreign = "6f6f6f6f-6f6f-4f6f-8f6f-6f6f6f6f6f6f";
  await database.query(`INSERT INTO replica_identity_tombstones (issuer, provider_organization_id, provider_workspace_id, workspace_id, reason)
    VALUES ($1, $2, $3, NULL, 'workspace_deleted')`, [ISSUER, foreign, WORKSPACE_2]);
  assert.equal((await api(route(WORKSPACE_2), { method: "DELETE", token: ownerToken })).status, 404);
  const revived = await api(route(WORKSPACE_1.toUpperCase()), { method: "DELETE", token: ownerToken });
  assert.equal(revived.status, 200, revived.text);
  assert.deepEqual(revived.body, { providerWorkspaceId: WORKSPACE_1, revived: true });
  assert.equal(await count(env,
    "SELECT 1 FROM admin_audit_events WHERE action = 'replicas.identity.revived' AND workspace_id = $1 AND actor_kind = 'user' AND actor_id = $2",
    [next, ownerId]), 1);
  assert.equal((await api(route(WORKSPACE_1), { method: "DELETE", token: ownerToken })).status, 404);
  // A tombstone still held by a workspace is not an orphan.
  const released = (await database.query<{ n: number }>("SELECT count(*)::int AS n FROM replica_identity_tombstones WHERE workspace_id IS NOT NULL")).rows[0]!.n;
  assert.equal(released, 0);
  const readmitted = await rpc(api, token({ workspace_id: WORKSPACE_1 }), "tools/list");
  assert.equal(readmitted.status, 200, readmitted.text);
  assert.equal(await count(env, "SELECT 1 FROM replica_spawns WHERE workspace_id = $1 AND replica_id = $2 AND state <> 'gone'", [next, WORKSPACE_1]), 1);
});

test("a launch record still restricts workspace deletion and writes no tombstone", async (t) => {
  const env = await start(t);
  const { api, workspaceId, store } = env;
  assert.equal((await connect(env)).status, 200);
  await mapOwner(env);
  assert.equal((await rpc(api, token({ workspace_id: WORKSPACE_1 }), "tools/list")).status, 200);
  const launched = await launchRow(env, "spawn", WORKSPACE_2);
  const actor = { kind: "bootstrap" as const };
  assert.equal(await store.deleteWorkspace({ organizationId: env.organizationId, workspaceId, allowLast: true, actor }), "in_use");
  assert.equal((await tombstones(env)).length, 0);
  // The whole deletion rolled back: the launch row and the environment identity are both kept.
  assert.equal(await count(env, "SELECT 1 FROM replica_spawns WHERE id = $1", [launched]), 1);
  assert.equal(await count(env, "SELECT 1 FROM replica_spawns WHERE source = 'environment_identity' AND state <> 'gone'"), 1);
});

test("the orphan revive refuses a tombstone still held by a workspace", async (t) => {
  const env = await start(t);
  const { api, workspaceId, ownerToken } = env;
  assert.equal((await connect(env)).status, 200);
  await env.database.query(`INSERT INTO replica_identity_tombstones (issuer, provider_organization_id, provider_workspace_id, workspace_id, reason)
    VALUES ($1, $2, $3, $4, 'released')`, [ISSUER, PROVIDER_ORG, WORKSPACE_1, workspaceId]);
  const response = await api(`/api/v1/workspaces/${workspaceId}/replicas/environment-tombstones/${WORKSPACE_1}`, { method: "DELETE", token: ownerToken });
  assert.equal(response.status, 404);
  assert.equal((await tombstones(env)).length, 1);
});

test("sync sweep: every all-environments connection, service actor, no overlap, errors do not stop it", async (t) => {
  const env = await start(t);
  const { api, workspaceId, provider, database } = env;
  assert.equal((await connect(env)).status, 200);
  assert.deepEqual(provider.registered.map((item) => item.environmentId), [ENV_A, ENV_B]);
  // A second workspace whose connection cannot be read (its sealed key is broken) and no settings row (= all on).
  const broken = await api(`/api/v1/organizations/${env.organizationId}/workspaces`, {
    method: "POST", token: BOOTSTRAP, body: { name: "broken", relaycastWorkspaceId: "rc-broken", relaycastApiKey: "rk_live_broken" },
  });
  assert.equal(broken.status, 201, broken.text);
  await database.query(`INSERT INTO remote_agent_connections (workspace_id, provider, key_ciphertext, key_hint, provider_account)
    VALUES ($1, 'replicas', 'x', 'x', $2)`, [broken.body.id, "7a7a7a7a-7a7a-4a7a-8a7a-7a7a7a7a7a7a"]);
  provider.environments.push({ id: ENV_C, name: "gamma" });
  const events: Array<{ code: string; workspaceId?: string }> = [];
  const sweep = new ReplicasSyncSweep({ replicas: env.replicas.deps, intervalSeconds: 30, log: (event) => events.push(event) });
  t.after(() => sweep.stop());
  const first = sweep.tick();
  assert.equal(sweep.tick(), first, "a run never overlaps the previous one");
  await first;
  assert.deepEqual(events, [{ code: "replicas_sync_failed", workspaceId: broken.body.id }]);
  assert.deepEqual(provider.registered.map((item) => item.environmentId), [ENV_A, ENV_B, ENV_C]);
  assert.equal(await count(env, "SELECT 1 FROM replica_environment_policies WHERE workspace_id = $1 AND enabled", [workspaceId]), 3);
  assert.equal(await count(env,
    "SELECT 1 FROM admin_audit_events WHERE action = 'replicas.environment.enabled' AND actor_kind = 'service' AND actor_id = 'replicas-sync'"), 1);
  // The principal is never inferred.
  assert.equal(await count(env, "SELECT 1 FROM replica_environment_settings WHERE principal_user_id IS NOT NULL"), 0);

  // Default off: the workspace is skipped.
  await database.query("UPDATE replica_environment_settings SET all_environments = false WHERE workspace_id = $1", [workspaceId]);
  provider.environments.push({ id: "4e4e4e4e-4e4e-4e4e-8e4e-4e4e4e4e4e4e", name: "delta" });
  await sweep.tick();
  assert.equal(await count(env, "SELECT 1 FROM replica_environment_policies WHERE workspace_id = $1", [workspaceId]), 3);
  assert.equal(provider.registered.length, 3);

  // A stopped sweep runs nothing; interval 0 never starts.
  await sweep.stop();
  await database.query("UPDATE replica_environment_settings SET all_environments = true WHERE workspace_id = $1", [workspaceId]);
  await sweep.tick();
  assert.equal(provider.registered.length, 3);
  const off = new ReplicasSyncSweep({ replicas: env.replicas.deps, intervalSeconds: 0 });
  off.start();
  await off.stop();
  assert.equal(provider.registered.length, 3);
});

/** A bound API launch of WORKSPACE_1 owned by the member (not the principal, not a mapped creator). */
async function reuseSetup(t: TestContext) {
  const env = await start(t);
  const { api, workspaceId, ownerToken, ownerId, memberId, organizationId, database } = env;
  assert.equal((await connect(env)).status, 200);
  await mapOwner(env);
  const principal = await api(`/api/v1/workspaces/${workspaceId}/replicas/environment-principal`, { method: "PUT", token: ownerToken, body: { userId: ownerId } });
  assert.equal(principal.status, 200, principal.text);
  const id = randomUUID();
  const input = { environment_id: ENV_A, name: "worker", task: "Fix the build", coding_agent: "claude" };
  await database.query(
    `INSERT INTO replica_spawns (id, workspace_id, organization_id, user_id, client_request_id, source, input, replica_id, chat_id, state,
       relay_workspace_id, agent_name, agent_remote_id, token_ciphertext)
     VALUES ($1, $2, $3, $4, $5, 'spawn', $6::jsonb, $7, $8, 'bound', 'rc-primary', 'worker-agent', 'remote-1', $9)`,
    [id, workspaceId, organizationId, memberId, `request-${id}`, JSON.stringify(input), WORKSPACE_1, randomUUID(),
      encrypt(env.replicas.deps, "launch-token")],
  );
  const relayCalls: string[] = [];
  const relaycast = env.replicas.deps.relaycast;
  const register = relaycast.registerHosted.bind(relaycast);
  const recover = relaycast.recoverHosted.bind(relaycast);
  relaycast.registerHosted = (...args) => { relayCalls.push("registerHosted"); return register(...args); };
  relaycast.recoverHosted = (...args) => { relayCalls.push("recoverHosted"); return recover(...args); };
  const claims = { issuer: ISSUER, organizationId: PROVIDER_ORG, environmentId: ENV_A, workspaceId: WORKSPACE_1,
    creatorId: null, creatorEmail: null, jti: randomUUID() };
  return { env, id, input, relayCalls, claims };
}

test("an environment identity reuses the live API binding of the same VM", async (t) => {
  const { env, id, input, relayCalls, claims } = await reuseSetup(t);
  const row = await admitIdentity(env.replicas.deps, claims);
  assert.equal(row.id, id);
  assert.equal(row.user_id, env.memberId);
  assert.equal(row.source, "spawn");
  assert.equal(row.state, "bound");
  assert.equal(row.agent_name, "worker-agent");
  assert.deepEqual(row.input, input);
  assert.equal(await count(env, "SELECT 1 FROM replica_spawns"), 1);
  assert.deepEqual(relayCalls, []);
  assert.equal(await count(env, "SELECT 1 FROM admin_audit_events WHERE action = 'replicas.identity.enrolled'"), 0);
  // The tools act as the launch binding.
  const listed = await rpc(env.api, token({ workspace_id: WORKSPACE_1, creator_id: null }), "tools/call", { name: "list_relay_agents", arguments: {} });
  assert.equal(listed.status, 200, listed.text);
  assert.equal(listed.body.result.structuredContent.agent, "worker-agent");
  assert.equal(await count(env, "SELECT 1 FROM replica_spawns"), 1);

  // A launch still preparing is a retryable 503, not a refusal or an enrolment.
  await env.database.query("UPDATE replica_spawns SET state = 'binding' WHERE id = $1", [id]);
  await assert.rejects(admitIdentity(env.replicas.deps, claims), (error: unknown) =>
    !(error instanceof IdentityRefusal) && (error as { status?: number }).status === 503);
  assert.equal(await count(env, "SELECT 1 FROM replica_spawns"), 1);
  assert.deepEqual(relayCalls, []);
  await env.database.query("UPDATE replica_spawns SET state = 'bound' WHERE id = $1", [id]);

  // A live launch of the same replica in another workspace is still replica_already_bound.
  const other = await env.api(`/api/v1/organizations/${env.organizationId}/workspaces`, {
    method: "POST", token: BOOTSTRAP, body: { name: "secondary", relaycastWorkspaceId: "rc-secondary", relaycastApiKey: "rk_live_secondary" },
  });
  assert.equal(other.status, 201, other.text);
  await env.database.query("UPDATE replica_spawns SET workspace_id = $2 WHERE id = $1", [id, other.body.id]);
  await assert.rejects(admitIdentity(env.replicas.deps, claims), (error: unknown) =>
    error instanceof IdentityRefusal && error.code === "replica_already_bound" && error.status === 409);
});

test("no fallback to the workspace principal after the binding owner leaves", async (t) => {
  const { env, relayCalls, claims } = await reuseSetup(t);
  await env.database.query("DELETE FROM organization_memberships WHERE organization_id = $1 AND user_id = $2", [env.organizationId, env.memberId]);
  await assert.rejects(admitIdentity(env.replicas.deps, claims), (error: unknown) =>
    error instanceof IdentityRefusal && error.code === "replica_creator_not_allowed" && error.status === 403);
  assert.equal(await count(env, "SELECT 1 FROM replica_spawns"), 1);
  assert.equal((await tombstones(env)).length, 0);
  assert.deepEqual(relayCalls, []);
  assert.equal(await count(env,
    "SELECT 1 FROM admin_audit_events WHERE action = 'replicas.identity.refused' AND target = 'replica_creator_not_allowed' AND workspace_id = $1",
    [env.workspaceId]), 1);
});

test("connect reports provisioning_error when environment setup failed and keeps the connection", async (t) => {
  await t.test("discovery failed: retryable, no environments", async (t) => {
    const env = await start(t);
    env.provider.mode.discover = "fail";
    const saved = await connect(env);
    assert.equal(saved.status, 200, saved.text);
    assert.deepEqual(saved.body.provisioning_error, {
      code: "replica_environment_setup_failed", stage: "environment_setup", retryable: true, environments: [],
    });
    assert.equal(await count(env, "SELECT 1 FROM remote_agent_connections WHERE workspace_id = $1", [env.workspaceId]), 1);
  });
  await t.test("registration timed out: retryable, the environments listed", async (t) => {
    const env = await start(t);
    env.provider.mode.register = "fail";
    const saved = await connect(env);
    assert.equal(saved.status, 200, saved.text);
    assert.deepEqual(saved.body.provisioning_error, {
      code: "replica_environment_setup_failed", stage: "environment_setup", retryable: true, environments: [ENV_A, ENV_B],
    });
  });
  await t.test("organization shared: not retryable", async (t) => {
    const env = await start(t);
    const other = await env.api(`/api/v1/organizations/${env.organizationId}/workspaces`, {
      method: "POST", token: BOOTSTRAP, body: { name: "other", relaycastWorkspaceId: "rc-other", relaycastApiKey: "rk_live_other" },
    });
    await env.database.query(`INSERT INTO remote_agent_connections (workspace_id, provider, key_ciphertext, key_hint, provider_account)
      VALUES ($1, 'replicas', 'x', 'x', $2)`, [other.body.id, PROVIDER_ORG]);
    const saved = await connect(env);
    assert.equal(saved.status, 200, saved.text);
    assert.deepEqual(saved.body.provisioning_error, {
      code: "replica_environment_setup_failed", stage: "environment_setup", retryable: false, environments: [ENV_A, ENV_B],
    });
    assert.equal(await count(env, "SELECT 1 FROM remote_agent_connections WHERE workspace_id = $1", [env.workspaceId]), 1);
  });
  await t.test("success: no provisioning_error", async (t) => {
    const env = await start(t);
    const saved = await connect(env);
    assert.equal(saved.status, 200, saved.text);
    assert.equal("provisioning_error" in saved.body, false);
  });
});
