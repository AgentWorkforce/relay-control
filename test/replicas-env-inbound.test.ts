import assert from "node:assert/strict";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { signWebhook } from "../src/amp/webhook.js";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { reconcileReplicaInbound } from "../src/replicas/inbound.js";
import { createReplicasModule } from "../src/replicas/module.js";
import { ReplicasRuntimeError, type ReplicasRuntime } from "../src/replicas/runtime.js";
import {
  bindReplica,
  claimDeliveryInTx,
  injectDeliveryInTx,
  releaseReplica,
  ReplicasError,
  spawnReplica,
  withReplicasLock,
  type ReplicasActor,
  type SpawnRow,
} from "../src/replicas/service.js";
import { ControlPlaneStore } from "../src/store.js";
import { apiClient, BOOTSTRAP, close, listen, PGliteDatabase, type Api } from "./flows-helpers.js";
import { createRelaycastWorld, type RelaycastWorld } from "./support/relaycast-world.js";

/**
 * Push delivery for environment-identity bindings: chat selection, the
 * checks before every push, no waking of sleeping compute, duplicates and
 * release. The harness mirrors replicas-env-mcp.test.ts.
 */

const ISSUER = "https://api.replicas.dev";
const PUBLIC = "https://control.selfhosted.company";
const MCP_URL = `${PUBLIC}/api/v1/replicas/mcp`;
const REPLICAS_KEY = "replicas_key_" + "k".repeat(32);
const PROVIDER_ORG = "0a0a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a0a";
const ENV_A = "1a1a1a1a-1a1a-4a1a-8a1a-1a1a1a1a1a1a";
const ENV_B = "2b2b2b2b-2b2b-4b2b-8b2b-2b2b2b2b2b2b";
const WORKSPACE_1 = "4d4d4d4d-4d4d-4d4d-8d4d-4d4d4d4d4d4d";
const CHAT_1 = "6f6f6f6f-6f6f-4f6f-8f6f-6f6f6f6f6f6f";
const CHAT_2 = "7a7a7a7a-7a7a-4a7a-8a7a-7a7a7a7a7a7a";
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

function token(claims: Record<string, unknown> = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const enc = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const signing = `${enc({ alg: "RS256", kid: "k1" })}.${enc({
    iss: ISSUER, aud: MCP_URL, exp: now + 600, iat: now, jti: randomUUID(),
    organization_id: PROVIDER_ORG, environment_id: ENV_A, workspace_id: WORKSPACE_1,
    creator_id: "creator-owner", creator_email: "owner@acme.test", ...claims,
  })}`;
  return `${signing}.${sign("RSA-SHA256", Buffer.from(signing), keys.privateKey).toString("base64url")}`;
}

type FakeReplica = { status: string; chats: Array<{ id: string; provider: string }> };

/** The provider: environments and their MCP entries, plus replica reads, messages and lifecycle calls. */
function createProvider() {
  const environments = [{ id: ENV_A, name: "alpha" }, { id: ENV_B, name: "beta" }];
  const entries = new Map<string, Array<Record<string, unknown>>>();
  const entriesOf = (environmentId: string) => entries.get(environmentId) ?? (entries.set(environmentId, []), entries.get(environmentId)!);
  const replicas = new Map<string, FakeReplica>();
  const messages: Array<{ replicaId: string; chatId: string; text: string }> = [];
  const calls: string[] = [];
  let registered = 0;
  const runtime = {
    identity: async () => ({ organization: { id: PROVIDER_ORG, name: "Org" } }),
    environments: async () => ({ environments }),
    allEnvironments: async () => ({ environments: [...environments], complete: true }),
    listEnvironmentMcps: async (_key: string, environmentId: string) => entriesOf(environmentId).map((entry) => structuredClone(entry)),
    registerEnvironmentMcp: async (_key: string, environmentId: string, body: Record<string, unknown>) => {
      const id = `mcp_${++registered}`;
      entriesOf(environmentId).push({ id, organization_id: PROVIDER_ORG, environment_id: environmentId, ...structuredClone(body) });
      return { id };
    },
    removeEnvironmentMcp: async (_key: string, environmentId: string, id: string) => {
      entries.set(environmentId, entriesOf(environmentId).filter((entry) => entry.id !== id));
      return null;
    },
    get: async (key: string, id: string) => {
      assert.equal(key, REPLICAS_KEY);
      calls.push("get");
      const replica = replicas.get(id.toLowerCase());
      if (!replica) throw new ReplicasRuntimeError("rejected", "replicas_http_404", 404);
      return { replica: { id, name: "replica", status: replica.status, chats: replica.chats.map((chat) => ({ ...chat })) } };
    },
    message: async (key: string, replicaId: string, chatId: string, text: string) => {
      assert.equal(key, REPLICAS_KEY);
      calls.push("message");
      messages.push({ replicaId, chatId, text });
      return { status: "queued", message_id: `pm_${messages.length}` };
    },
    wake: async () => {
      calls.push("wake");
      return null;
    },
    sleep: async () => {
      throw new Error("environment bindings never sleep compute");
    },
    exec: async () => {
      throw new Error("environment bindings never exec");
    },
  };
  return { runtime: runtime as unknown as ReplicasRuntime, replicas, messages, calls };
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

async function start(t: TestContext) {
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
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0, {});
  const replicas = createReplicasModule({
    replicas: { enabled: true }, config, database, relaycastFetch: messagingFetch, runtime: provider.runtime, identityFetch: identityFetch(),
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
  const seeded = await seed(api);
  const owner: ReplicasActor = { userId: seeded.ownerId, workspaceId: seeded.workspaceId, organizationId: seeded.organizationId };
  const member: ReplicasActor = { userId: seeded.memberId, workspaceId: seeded.workspaceId, organizationId: seeded.organizationId };
  return { database, world, provider, replicas, deps: replicas.deps, api, owner, member, ...seeded };
}
type Env = Awaited<ReturnType<typeof start>>;

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
  const started = await api("/api/v1/auth/device/start", { method: "POST", body: {} });
  const approved = await api("/api/v1/auth/device/approve", {
    method: "POST", token: BOOTSTRAP,
    body: { action: "approve", user_code: started.body.user_code, user_id: org.body.owner.id, workspace_id: workspaceId },
  });
  assert.equal(approved.status, 200);
  const issued = await api("/api/v1/auth/device/token", { method: "POST", body: { device_code: started.body.device_code } });
  assert.equal(issued.status, 200);
  return {
    organizationId, workspaceId, ownerId: org.body.owner.id as string, memberId: member.body.userId as string,
    ownerToken: issued.body.access_token as string,
  };
}

const MCP_HEADERS = { accept: "application/json, text/event-stream" };
let rpcSequence = 0;
const listTools = (api: Api, bearer: string) => api("/api/v1/replicas/mcp", {
  method: "POST", token: bearer, headers: MCP_HEADERS,
  body: { jsonrpc: "2.0", id: ++rpcSequence, method: "tools/list", params: {} },
});

const spawnRow = async (env: Env, id: string): Promise<SpawnRow> =>
  (await env.database.query<SpawnRow>("SELECT * FROM replica_spawns WHERE id = $1", [id])).rows[0]!;
const subscriptionsOf = (env: Env, spawnId: string) =>
  [...env.world.subscriptions.values()].filter((item) => item.url === `${PUBLIC}/api/v1/replicas/relay-events/${spawnId}`);
const deliveryOf = async (env: Env, spawnId: string, messageId: string) =>
  (await env.database.query<{ state: string; last_error: string | null }>(
    "SELECT state, last_error FROM replica_deliveries WHERE spawn_id = $1 AND message_id = $2", [spawnId, messageId])).rows[0];

/**
 * Connects the provider key (every environment enabled by default), maps
 * the token's creator to the owner and enrols WORKSPACE_1 through the
 * environment-level MCP. Waits for the reconcile that admission starts.
 */
async function enrol(env: Env, replica: FakeReplica): Promise<SpawnRow> {
  const { api, workspaceId, ownerToken, ownerId } = env;
  env.provider.replicas.set(WORKSPACE_1, replica);
  const saved = await api(`/api/v1/workspaces/${workspaceId}/remote-agent-connections/replicas`, {
    method: "POST", token: ownerToken, body: { key: REPLICAS_KEY } });
  assert.equal(saved.status, 200, saved.text);
  const mapped = await api(`/api/v1/workspaces/${workspaceId}/replicas/environments/${ENV_A}`, {
    method: "PUT", token: ownerToken, body: { enabled: true, creators: [{ creatorId: "creator-owner", userId: ownerId }] } });
  assert.equal(mapped.status, 200, mapped.text);
  const listed = await listTools(api, token());
  assert.equal(listed.status, 200, listed.text);
  const id = (await env.database.query<{ id: string }>(
    "SELECT id FROM replica_spawns WHERE source = 'environment_identity' AND state <> 'gone'")).rows[0]!.id;
  for (let attempt = 0; attempt < 200; attempt++) {
    const row = await spawnRow(env, id);
    if (row.input.relay_inbound_checked_at) return row;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.fail("the admission reconcile did not finish");
}

/** One signed Relay event to the binding's webhook (a fresh webhook id per call: Relay's redelivery of the same message). */
async function push(env: Env, row: SpawnRow, messageId: string, text = "status?") {
  const subscription = subscriptionsOf(env, row.id).find((item) => item.events.includes("dm.received"));
  assert.ok(subscription, "the binding has its direct-message subscription");
  const event = JSON.stringify({ type: "dm.received", data: { to: row.agent_name, message: { id: messageId, agent_name: "peer", text } } });
  const id = `msg_${randomUUID()}`;
  const ts = Math.floor(Date.now() / 1000);
  return env.api(`/api/v1/replicas/relay-events/${row.id}`, { method: "POST", raw: event,
    headers: { "webhook-id": id, "webhook-timestamp": String(ts), "webhook-signature": signWebhook(subscription.secret, id, ts, event) } });
}

/** The webhook's two locked steps without its signature or targeting: claim, then inject. */
async function deliver(env: Env, row: SpawnRow, messageId: string) {
  const scope = { workspaceId: row.workspace_id, organizationId: row.organization_id };
  const claim = await withReplicasLock(env.deps, scope, (tx) => claimDeliveryInTx(tx, row.id, messageId));
  if (claim.kind !== "claimed") return claim;
  return withReplicasLock(env.deps, scope, (tx) => injectDeliveryInTx(env.deps, tx, row.id,
    { messageId, sender: "peer", type: "dm.received", text: "status?", threadId: null }));
}

test("a sole chat is selected automatically and pushes reach it once", async (t) => {
  const env = await start(t);
  let row = await enrol(env, { status: "active", chats: [{ id: CHAT_1, provider: "claude" }] });

  await t.test("the sole chat is selected and both subscriptions are created", async () => {
    assert.equal(row.chat_id, CHAT_1);
    assert.equal(row.input.relay_inbound_error, null);
    assert.ok(row.subscription_id && row.mention_subscription_id && row.hook_ciphertext);
    const subscriptions = subscriptionsOf(env, row.id);
    assert.equal(subscriptions.length, 2);
    assert.deepEqual(subscriptions.map((item) => item.events).sort(), [["dm.received", "thread.reply"], ["message.created"]]);
    assert.deepEqual(subscriptions.find((item) => item.events.includes("message.created"))!.filter, { mentions: row.agent_name });
    // A repeated reconcile creates nothing new.
    await reconcileReplicaInbound(env.deps, row.id);
    assert.equal(subscriptionsOf(env, row.id).length, 2);
    assert.equal(env.provider.calls.includes("wake"), false);
  });

  await t.test("an environment webhook is injected once and its prompt has no helper line", async () => {
    const delivered = await push(env, row, "9001");
    assert.equal(delivered.status, 200, delivered.text);
    assert.deepEqual(delivered.body, { ok: true, delivered: true });
    assert.equal(env.provider.messages.length, 1);
    const sent = env.provider.messages[0]!;
    assert.equal(sent.replicaId.toLowerCase(), WORKSPACE_1);
    assert.equal(sent.chatId, CHAT_1);
    assert.match(sent.text, /^\[via Agent Relay — from "peer" to @replicas-[0-9a-f]{16}; message 9001\]/);
    assert.match(sent.text, /send_relay_message/);
    assert.doesNotMatch(sent.text, /terminal fallback|message\.py|agent-relay-replicas/);
    assert.match(sent.text, /status\?$/);
    assert.equal((await deliveryOf(env, row.id, "9001"))?.state, "sent");
  });

  await t.test("a duplicate delivery returns the prior state with no second message", async () => {
    const duplicate = await push(env, row, "9001");
    assert.equal(duplicate.status, 200, duplicate.text);
    assert.deepEqual(duplicate.body, { ok: true, duplicate: true, prior: "confirmed" });
    assert.equal(env.provider.messages.length, 1);
  });

  await t.test("sleeping compute answers replica_chat_inactive with no wake and no message", async () => {
    env.provider.replicas.set(WORKSPACE_1, { status: "sleeping", chats: [{ id: CHAT_1, provider: "claude" }] });
    const before = env.provider.calls.length;
    const refused = await push(env, row, "9002");
    assert.equal(refused.status, 503, refused.text);
    assert.deepEqual(refused.body, { ok: false, retry: true });
    assert.deepEqual(env.provider.calls.slice(before), ["get"]);
    assert.equal(env.provider.messages.length, 1);
    assert.deepEqual(await deliveryOf(env, row.id, "9002"), { state: "retrying", last_error: "replica_chat_inactive" });
    assert.equal((await spawnRow(env, row.id)).input.relay_inbound_error, "replica_chat_inactive");
    // A reconcile while asleep records the same code and wakes nothing.
    await reconcileReplicaInbound(env.deps, row.id);
    assert.equal(env.provider.calls.includes("wake"), false);
    assert.equal((await spawnRow(env, row.id)).input.relay_inbound_error, "replica_chat_inactive");
    // Relay's later retry of the same message is delivered once the replica is awake again.
    env.provider.replicas.set(WORKSPACE_1, { status: "active", chats: [{ id: CHAT_1, provider: "claude" }] });
    const retried = await push(env, row, "9002");
    assert.deepEqual(retried.body, { ok: true, delivered: true });
    assert.equal(env.provider.messages.length, 2);
    assert.equal((await spawnRow(env, row.id)).input.relay_inbound_error, null);
    assert.equal(env.provider.calls.includes("wake"), false);
  });

  await t.test("each failed persisted check refuses the injection", async () => {
    const messages = env.provider.messages.length;
    const refused = async (messageId: string, code: string) => {
      const outcome = await deliver(env, row, messageId);
      assert.deepEqual(outcome, { state: "retrying", code });
      assert.equal(env.provider.messages.length, messages);
      assert.deepEqual(await deliveryOf(env, row.id, messageId), { state: "retrying", last_error: code });
      assert.equal((await spawnRow(env, row.id)).input.relay_inbound_error, code);
    };

    // A revoked policy.
    await env.database.query("UPDATE replica_environment_policies SET enabled = false WHERE workspace_id = $1 AND environment_id = $2",
      [env.workspaceId, ENV_A]);
    await refused("9101", "replica_environment_not_enabled");
    await env.database.query("UPDATE replica_environment_policies SET enabled = true WHERE workspace_id = $1 AND environment_id = $2",
      [env.workspaceId, ENV_A]);

    // A tombstone, also through the webhook.
    await env.database.query(`INSERT INTO replica_identity_tombstones (issuer, provider_organization_id, provider_workspace_id, workspace_id, reason)
      VALUES ($1, $2, $3, $4, 'test')`, [ISSUER, PROVIDER_ORG, WORKSPACE_1, env.workspaceId]);
    await refused("9102", "replica_released");
    const webhook = await push(env, row, "9103");
    assert.equal(webhook.status, 503, webhook.text);
    assert.deepEqual(webhook.body, { ok: false, retry: true });
    assert.equal(env.provider.messages.length, messages);
    await env.database.query("DELETE FROM replica_identity_tombstones");

    // An unbound workspace (no Relay binding).
    const relay = (await env.database.query<{ relaycast_workspace_id: string; relaycast_api_key_ciphertext: string }>(
      "SELECT relaycast_workspace_id, relaycast_api_key_ciphertext FROM workspaces WHERE id = $1", [env.workspaceId])).rows[0]!;
    await env.database.query("UPDATE workspaces SET relaycast_workspace_id = NULL, relaycast_api_key_ciphertext = NULL WHERE id = $1", [env.workspaceId]);
    await refused("9104", "replica_inbound_unavailable");
    await env.database.query("UPDATE workspaces SET relaycast_workspace_id = $2, relaycast_api_key_ciphertext = $3 WHERE id = $1",
      [env.workspaceId, relay.relaycast_workspace_id, relay.relaycast_api_key_ciphertext]);

    // Nothing is left refused: the next delivery goes through.
    assert.deepEqual(await deliver(env, row, "9105"), { state: "sent" });
    assert.equal(env.provider.messages.length, messages + 1);
    assert.equal((await spawnRow(env, row.id)).input.relay_inbound_error, null);
  });

  await t.test("release deletes both subscriptions and leaves the compute alone", async () => {
    row = await spawnRow(env, row.id);
    assert.equal(subscriptionsOf(env, row.id).length, 2);
    const secret = subscriptionsOf(env, row.id).find((item) => item.events.includes("dm.received"))!.secret;
    const released = await releaseReplica(env.deps, env.owner, row.id);
    assert.equal(released.released, true);
    assert.equal(subscriptionsOf(env, row.id).length, 0);
    const gone = await spawnRow(env, row.id);
    assert.equal(gone.state, "gone");
    assert.equal(gone.hook_ciphertext, null);
    assert.equal(env.provider.calls.includes("wake"), false);
    // A push after release, signed with the old secret, finds no binding.
    const event = JSON.stringify({ type: "dm.received", data: { to: row.agent_name, message: { id: "9201", agent_name: "peer", text: "x" } } });
    const id = `msg_${randomUUID()}`;
    const ts = Math.floor(Date.now() / 1000);
    const late = await env.api(`/api/v1/replicas/relay-events/${row.id}`, { method: "POST", raw: event,
      headers: { "webhook-id": id, "webhook-timestamp": String(ts), "webhook-signature": signWebhook(secret, id, ts, event) } });
    assert.equal(late.status, 410);
  });
});

test("a former-member creator refuses the injection", async (t) => {
  const env = await start(t);
  const row = await enrol(env, { status: "active", chats: [{ id: CHAT_1, provider: "claude" }] });
  await env.database.query("DELETE FROM organization_memberships WHERE user_id = $1", [env.ownerId]);
  const outcome = await deliver(env, row, "9301");
  assert.deepEqual(outcome, { state: "retrying", code: "replica_creator_not_allowed" });
  assert.equal(env.provider.messages.length, 0);
  assert.deepEqual(await deliveryOf(env, row.id, "9301"), { state: "retrying", last_error: "replica_creator_not_allowed" });
});

test("several chats need a selection through bind_replica, which is then immutable", async (t) => {
  const env = await start(t);
  const row = await enrol(env, { status: "active", chats: [{ id: CHAT_1, provider: "claude" }, { id: CHAT_2, provider: "codex" }] });

  assert.equal(row.chat_id, null);
  assert.equal(row.input.relay_inbound_error, "replica_chat_selection_required");
  assert.equal(subscriptionsOf(env, row.id).length, 0, "no subscription before a chat is selected");

  const waiting = await deliver(env, row, "9401");
  assert.deepEqual(waiting, { state: "retrying", code: "replica_chat_selection_required" });
  assert.equal(env.provider.messages.length, 0);

  // Only a workspace owner/admin who is the binding's person selects.
  await assert.rejects(bindReplica(env.deps, env.member, { replica_id: WORKSPACE_1, chat_id: CHAT_2 }),
    (error: unknown) => error instanceof ReplicasError && error.status === 403);

  const selected = await bindReplica(env.deps, env.owner, { replica_id: WORKSPACE_1, chat_id: CHAT_2.toUpperCase() });
  assert.equal(selected.spawn_id, row.id);
  assert.equal(selected.chat_id, CHAT_2);
  assert.deepEqual(selected.inbound_delivery, { status: "configured" });
  let current = await spawnRow(env, row.id);
  assert.equal(current.chat_id, CHAT_2);
  assert.equal(current.input.relay_inbound_error, null);
  assert.equal(subscriptionsOf(env, row.id).length, 2);
  const audited = () => env.database.query("SELECT 1 FROM admin_audit_events WHERE action = 'replicas.chat.selected'");
  assert.equal((await audited()).rows.length, 1);

  // Immutable: another chat is refused; the same chat again is a no-op.
  await assert.rejects(bindReplica(env.deps, env.owner, { replica_id: WORKSPACE_1, chat_id: CHAT_1 }),
    (error: unknown) => error instanceof ReplicasError && error.status === 409 && /cannot be changed/.test(error.message));
  const again = await bindReplica(env.deps, env.owner, { replica_id: WORKSPACE_1, chat_id: CHAT_2 });
  assert.equal(again.chat_id, CHAT_2);
  assert.equal((await audited()).rows.length, 1);
  assert.equal(subscriptionsOf(env, row.id).length, 2);
  current = await spawnRow(env, row.id);
  assert.equal(current.chat_id, CHAT_2);

  // The waiting message is delivered to the selected chat on Relay's retry.
  assert.deepEqual(await deliver(env, current, "9401"), { state: "sent" });
  assert.deepEqual(env.provider.messages.map((message) => message.chatId), [CHAT_2]);
  assert.equal(env.provider.calls.includes("wake"), false);
});

test("launch idempotency ignores the inbound delivery bookkeeping", async (t) => {
  const env = await start(t);
  const saved = await env.api(`/api/v1/workspaces/${env.workspaceId}/remote-agent-connections/replicas`, {
    method: "POST", token: env.ownerToken, body: { key: REPLICAS_KEY } });
  assert.equal(saved.status, 200, saved.text);
  const launch = { environment_id: ENV_A, name: "worker", task: "Fix the flaky test", coding_agent: "claude" };
  const id = randomUUID();
  await env.database.query(
    `INSERT INTO replica_spawns (id, workspace_id, organization_id, user_id, client_request_id, source, input, replica_id, chat_id, state)
     VALUES ($1, $2, $3, $4, 'req-inbound', 'spawn', $5::jsonb, $6, $7, 'bound')`,
    [id, env.workspaceId, env.organizationId, env.ownerId, JSON.stringify({ ...launch, relay_mcp_version: 1,
      relay_inbound_checked_at: new Date().toISOString(), relay_inbound_error: "replica_chat_inactive", relay_inbound_cursor: 42 }),
    randomUUID(), CHAT_1],
  );
  const repeated = await spawnReplica(env.deps, env.owner, { client_request_id: "req-inbound", ...launch });
  assert.equal(repeated.spawn_id, id);
  await assert.rejects(spawnReplica(env.deps, env.owner, { client_request_id: "req-inbound", ...launch, task: "Something else" }),
    (error: unknown) => error instanceof ReplicasError && error.status === 409);
  assert.equal(env.provider.calls.length, 0);
});
