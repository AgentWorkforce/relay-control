/**
 * Factory test harness: a control plane with the Factory flag on, a fake
 * Factory API server and a fake Relaycast server (both real HTTP servers),
 * and an installation seeded with an owner, a second admin and a member.
 */
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { TestContext } from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { createFactoryModule, type FactoryModule } from "../src/factory/routes.js";
import { mintReplyBearer } from "../src/factory/reply-capability.js";
import { encryptSecret } from "../src/crypto.js";
import type { FactoryServiceDeps } from "../src/factory/service.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { apiClient, BOOTSTRAP, close, listen, PGliteDatabase, type Api } from "./flows-helpers.js";

export const FACTORY_KEY = "fk_live_primary_key_0001";
export const FACTORY_KEY_2 = "fk_live_replacement_key_02";
export const INTERNAL = "internal-service-token-that-is-at-least-32-bytes";
export const PUBLIC_URL = "https://control.selfhosted.company";

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

function send(response: ServerResponse, status: number, body?: unknown) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(body === undefined ? "" : JSON.stringify(body));
}

// ------------------------------------------------------------------ Factory

export type FakeSession = { id: string; computerId: string; title: string; messageCount: number };
export type FakeFactory = {
  keys: Set<string>;
  computers: Array<{ id: string; name: string; status: string }>;
  sessions: Map<string, FakeSession>;
  /** Accepted injections, in order. */
  injected: Array<{ sessionId: string; computerId: string; text: string; key: string }>;
  posts: number;
  /** Next inject POSTs: "ok", "500" (accepted-or-not unknown), "409" (definite reject). */
  injectMode: "ok" | "500" | "409" | "429";
  /** When set, GET /api/v0/sessions/{id} answers this status (a pre-write failure). */
  sessionGetStatus: number | null;
  /** When set, the next inject POST waits for this before answering (the POST has arrived). */
  holdInject: Promise<void> | null;
  onInjectArrived: (() => void) | null;
  unreachable: Set<string>;
  requests: string[];
  /**
   * One-shot holds of a provider read (the connect/bind key check or session
   * re-verification): the next matching request calls `onArrived`, then
   * waits for the promise before answering.
   */
  holdComputers: { until: Promise<void>; onArrived: () => void } | null;
  holdSessionGet: { until: Promise<void>; onArrived: () => void } | null;
};

/** Arms a one-shot hold; resolves `arrived` when the held request reaches the fake, `release()` lets it answer. */
export function providerHold() {
  let release!: () => void;
  let arrivedResolve!: () => void;
  const until = new Promise<void>((resolve) => { release = resolve; });
  const arrived = new Promise<void>((resolve) => { arrivedResolve = resolve; });
  return { hold: { until, onArrived: arrivedResolve }, arrived, release };
}

export async function startFakeFactory(t: TestContext) {
  const state: FakeFactory = {
    keys: new Set([FACTORY_KEY, FACTORY_KEY_2]),
    computers: [{ id: "cmp-1", name: "Laptop", status: "active" }, { id: "cmp-2", name: "Desktop", status: "active" }],
    sessions: new Map([
      ["sess-a", { id: "sess-a", computerId: "cmp-1", title: "Session A", messageCount: 3 }],
      ["sess-b", { id: "sess-b", computerId: "cmp-1", title: "Session B", messageCount: 1 }],
      ["sess-c", { id: "sess-c", computerId: "cmp-2", title: "Session C", messageCount: 0 }],
    ]),
    injected: [],
    posts: 0,
    injectMode: "ok",
    sessionGetStatus: null,
    holdInject: null,
    onInjectArrived: null,
    unreachable: new Set(),
    requests: [],
    holdComputers: null,
    holdSessionGet: null,
  };
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://factory");
    state.requests.push(`${request.method} ${url.pathname}`);
    const key = /^Bearer (.+)$/.exec(request.headers.authorization ?? "")?.[1] ?? "";
    if (!state.keys.has(key)) return send(response, 401, { error: "unauthorized" });
    if (request.method === "GET" && url.pathname === "/api/v0/computers") {
      const hold = state.holdComputers;
      if (hold) {
        state.holdComputers = null;
        hold.onArrived();
        await hold.until;
      }
      return send(response, 200, { computers: state.computers });
    }
    const computerId = url.searchParams.get("computerId") ?? "";
    if (request.method === "GET" && url.pathname === "/api/v0/sessions") {
      if (state.unreachable.has(computerId)) return send(response, 503, {});
      const sessions = [...state.sessions.values()].filter((row) => row.computerId === computerId)
        .map((row) => ({ sessionId: row.id, computerId: row.computerId, title: row.title }));
      return send(response, 200, { sessions, pagination: { hasMore: false, nextCursor: null } });
    }
    const one = /^\/api\/v0\/sessions\/([^/]+)$/.exec(url.pathname);
    if (request.method === "GET" && one) {
      const hold = state.holdSessionGet;
      if (hold) {
        state.holdSessionGet = null;
        hold.onArrived();
        await hold.until;
      }
      if (state.sessionGetStatus) return send(response, state.sessionGetStatus, {});
      const row = state.sessions.get(decodeURIComponent(one[1]!));
      if (!row) return send(response, 404, {});
      return send(response, 200, {
        sessionId: row.id, computerId: row.computerId, updatedAt: 1, messageCount: row.messageCount,
      });
    }
    const post = /^\/api\/v0\/sessions\/([^/]+)\/messages$/.exec(url.pathname);
    if (request.method === "POST" && post) {
      state.posts++;
      const body = JSON.parse(await readBody(request)) as { text: string; computerId: string };
      state.onInjectArrived?.();
      if (state.holdInject) await state.holdInject;
      if (state.injectMode === "500") return send(response, 500, {});
      if (state.injectMode === "409") return send(response, 409, {});
      if (state.injectMode === "429") return send(response, 429, {});
      const sessionId = decodeURIComponent(post[1]!);
      state.injected.push({ sessionId, computerId: body.computerId, text: body.text, key });
      const session = state.sessions.get(sessionId);
      if (session) session.messageCount++;
      return send(response, 200, { messageId: `fm-${state.posts}`, status: "running" });
    }
    send(response, 404, {});
  });
  const origin = await listen(server);
  t.after(() => close(server));
  return { state, origin };
}

// ---------------------------------------------------------------- Relaycast

export type FakeAgent = { id: string; name: string; token: string; key: string; metadata: Record<string, unknown> };
export type FakeRelay = {
  agents: Map<string, FakeAgent>;
  inbox: Map<string, Array<{ id: string; message: { id: string; agent_name: string; agent_id: string; text: string } }>>;
  acked: string[];
  replies: Array<{ token: string; parentId: string; text: string; idempotencyKey: string }>;
  repliesByKey: Map<string, { id: string; conversation_id: string }>;
  dms: Array<{ token: string; to: string; text: string }>;
  released: string[];
  registered: number;
  recovered: number;
  failRelease: boolean;
  failRegister: boolean;
  failReply: boolean;
  /** Every release-exact request, in arrival order. */
  releaseRequests: Array<{ name: string; expectedAgentId: string }>;
  /** When set, the next release-exact request waits for this before it looks the agent up (one-shot). */
  holdRelease: Promise<void> | null;
  onReleaseArrived: (() => void) | null;
  /** Answer 404 when the expected agent id is not the live agent of that name (instead of a completed no-op). */
  releaseAbsentAs404: boolean;
};

let counter = 0;

export async function startFakeRelay(t: TestContext) {
  const state: FakeRelay = {
    agents: new Map(),
    inbox: new Map(),
    acked: [],
    replies: [],
    repliesByKey: new Map(),
    dms: [],
    released: [],
    registered: 0,
    recovered: 0,
    failRelease: false,
    failRegister: false,
    failReply: false,
    releaseRequests: [],
    holdRelease: null,
    onReleaseArrived: null,
    releaseAbsentAs404: false,
  };
  const byToken = (token: string) => [...state.agents.values()].find((agent) => agent.token === token);
  const server = createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://relay");
    const token = /^Bearer (.+)$/.exec(request.headers.authorization ?? "")?.[1] ?? "";
    const raw = await readBody(request);
    const body = raw ? JSON.parse(raw) as Record<string, any> : {};
    if (request.method === "POST" && url.pathname === "/v1/agents") {
      if (state.failRegister) return send(response, 500, {});
      if (state.agents.has(body.name)) return send(response, 409, { error: { code: "name_taken" } });
      state.registered++;
      const agent = { id: `ag-${++counter}`, name: body.name, token: `at_${counter}_${Math.random()}`, key: token, metadata: body.metadata ?? {} };
      state.agents.set(agent.name, agent);
      return send(response, 201, { data: { id: agent.id, name: agent.name, token: agent.token } });
    }
    if (request.method === "POST" && url.pathname === "/v1/agents/release-exact") {
      state.releaseRequests.push({ name: body.name, expectedAgentId: body.expected_agent_id });
      const hold = state.holdRelease;
      if (hold) {
        state.holdRelease = null;
        state.onReleaseArrived?.();
        await hold;
      }
      if (state.failRelease) return send(response, 500, {});
      // Fenced by id: a different agent now holding the name is never deleted.
      const agent = state.agents.get(body.name);
      if (agent && agent.id === body.expected_agent_id) {
        state.agents.delete(body.name);
        state.released.push(agent.id);
      } else if (state.releaseAbsentAs404) {
        return send(response, 404, { error: { code: "agent_not_found" } });
      }
      return send(response, 200, { data: { status: "completed" } });
    }
    const takeover = /^\/v1\/agents\/([^/]+)\/takeover$/.exec(url.pathname);
    if (request.method === "POST" && takeover) {
      const agent = state.agents.get(decodeURIComponent(takeover[1]!));
      if (!agent || agent.id !== body.expected_agent_id) return send(response, 409, {});
      state.recovered++;
      agent.token = `at_recovered_${++counter}`;
      return send(response, 200, { data: { token: agent.token, agent_id: agent.id } });
    }
    const agentPath = /^\/v1\/agents\/([^/]+)$/.exec(url.pathname);
    if (request.method === "GET" && agentPath) {
      const agent = state.agents.get(decodeURIComponent(agentPath[1]!));
      if (!agent) return send(response, 404, {});
      return send(response, 200, { data: { id: agent.id, name: agent.name, metadata: agent.metadata } });
    }
    if (request.method === "GET" && url.pathname === "/v1/deliveries") {
      const agent = byToken(token);
      if (!agent) return send(response, 401, {});
      return send(response, 200, { data: (state.inbox.get(agent.name) ?? []).filter((row) => !state.acked.includes(row.id)) });
    }
    const ack = /^\/v1\/deliveries\/([^/]+)\/ack$/.exec(url.pathname);
    if (request.method === "POST" && ack) {
      state.acked.push(decodeURIComponent(ack[1]!));
      return send(response, 200, { data: { ok: true } });
    }
    const reply = /^\/v1\/messages\/([^/]+)\/replies$/.exec(url.pathname);
    if (request.method === "POST" && reply) {
      if (!byToken(token)) return send(response, 401, {});
      if (state.failReply) return send(response, 503, {});
      const idempotencyKey = String(request.headers["idempotency-key"] ?? "");
      state.replies.push({ token, parentId: decodeURIComponent(reply[1]!), text: body.text, idempotencyKey });
      const prior = state.repliesByKey.get(idempotencyKey);
      const result = prior ?? { id: `rm-${++counter}`, conversation_id: "conv-1" };
      state.repliesByKey.set(idempotencyKey, result);
      return send(response, 201, { data: { ...result, text: body.text } });
    }
    if (request.method === "POST" && url.pathname === "/v1/dm") {
      if (!byToken(token)) return send(response, 401, {});
      state.dms.push({ token, to: body.to, text: body.text });
      return send(response, 201, { data: { conversation_id: "conv-n", message: { id: `dm-${++counter}`, agent_name: "x", text: body.text } } });
    }
    send(response, 404, {});
  });
  const origin = await listen(server);
  t.after(() => close(server));
  return { state, origin };
}

/** Queues one inbound Relay message for a hosted agent. */
export function queueRelayMessage(relay: FakeRelay, agentName: string, message: { id: string; from?: string; text: string }) {
  const list = relay.inbox.get(agentName) ?? [];
  list.push({
    id: `dl-${message.id}`,
    message: { id: message.id, agent_name: message.from ?? "alice", agent_id: "ag-alice", text: message.text },
  });
  relay.inbox.set(agentName, list);
}

// ------------------------------------------------------------ control plane

export type FactoryEnv = Awaited<ReturnType<typeof startFactoryEnv>>;

export async function startFactoryEnv(t: TestContext, options: {
  enabled?: boolean;
  hooks?: Pick<FactoryServiceDeps, "beforeFinalWrite"> & { beforeInboxInsert?: () => Promise<void> };
  /** Override the internal service token (null: unset). */
  internalToken?: string | null;
} = {}) {
  const factory = await startFakeFactory(t);
  const relay = await startFakeRelay(t);
  const database = new PGliteDatabase();
  await migrate(database);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: PUBLIC_URL,
    relaycastUrl: relay.origin,
    relaycastPublicUrl: "https://relaycast.selfhosted.company",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.selfhosted.company",
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: "https://history.selfhosted.company", secret: "session-read-secret-".repeat(2) },
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    port: 3000,
    host: "127.0.0.1",
    internalServiceToken: options.internalToken === undefined ? INTERNAL : options.internalToken,
    oauthRedirectUrl: `${PUBLIC_URL}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${PUBLIC_URL}/`,
    factory: { enabled: options.enabled ?? true, apiUrl: factory.origin, historyIntervalMs: 300_000 },
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  const logs: Array<Record<string, unknown>> = [];
  const module: FactoryModule = createFactoryModule({
    config,
    database,
    messaging: { database, keyring: config.encryptionKeyring, relaycastUrl: config.relaycastUrl },
    browserOrigins: [new URL(PUBLIC_URL).origin],
    log: (fields) => logs.push(fields),
    hooks: options.hooks,
  });
  const server = createServer(createApp({ config, store, factory: module }));
  const origin = await listen(server);
  t.after(async () => {
    await module.stop();
    await close(server);
    await database.close();
  });
  const api = apiClient(origin);
  const tenant = await seedFactoryTenant(api);
  return { factory: factory.state, relay: relay.state, database, module, api, origin, logs, config, ...tenant };
}

async function seedFactoryTenant(api: Api) {
  const org = await api("/api/v1/organizations", {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Acme", ownerEmail: "owner@acme.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const organizationId = org.body.id as string;
  const workspace = async (name: string, key: string) => {
    const created = await api(`/api/v1/organizations/${organizationId}/workspaces`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { name, relaycastWorkspaceId: `rc-${name}`, relaycastApiKey: key },
    });
    assert.equal(created.status, 201);
    return created.body.id as string;
  };
  const workspaceId = await workspace("primary", "rk_live_primary");
  const otherWorkspaceId = await workspace("other", "rk_live_other");
  const addMember = async (email: string, role: string) => {
    const member = await api(`/api/v1/organizations/${organizationId}/memberships`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { email, name: email, role },
    });
    assert.equal(member.status, 200);
    return member.body.userId as string;
  };
  const adminId = await addMember("admin@acme.test", "admin");
  const memberId = await addMember("member@acme.test", "member");
  const login = async (userId: string, target: string) => {
    const started = await api("/api/v1/auth/device/start", { method: "POST", body: {} });
    const approved = await api("/api/v1/auth/device/approve", {
      method: "POST",
      token: BOOTSTRAP,
      body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: target },
    });
    assert.equal(approved.status, 200);
    const token = await api("/api/v1/auth/device/token", { method: "POST", body: { device_code: started.body.device_code } });
    assert.equal(token.status, 200);
    return token.body.access_token as string;
  };
  const ownerId = org.body.owner.id as string;
  return {
    organizationId,
    workspaceId,
    otherWorkspaceId,
    ownerId,
    adminId,
    memberId,
    ownerToken: await login(ownerId, workspaceId),
    ownerOtherToken: await login(ownerId, otherWorkspaceId),
    adminToken: await login(adminId, workspaceId),
    adminOtherToken: await login(adminId, otherWorkspaceId),
    memberToken: await login(memberId, workspaceId),
    login,
  };
}

export const factoryPath = (workspaceId: string, rest: string) => `/api/v1/workspaces/${workspaceId}/factory${rest}`;

/** Connects Factory and binds one session as `token`; returns the binding. */
export async function connectAndBind(env: FactoryEnv, options: { token?: string; workspaceId?: string; sessionId?: string; computerId?: string; key?: string } = {}) {
  const token = options.token ?? env.ownerToken;
  const workspaceId = options.workspaceId ?? env.workspaceId;
  const connected = await env.api(factoryPath(workspaceId, "/connection"), { method: "PUT", token, body: { key: options.key ?? FACTORY_KEY } });
  assert.equal(connected.status, 200, JSON.stringify(connected.body));
  const bound = await env.api(factoryPath(workspaceId, "/bindings"), {
    method: "POST",
    token,
    body: { session_id: options.sessionId ?? "sess-a", computer_id: options.computerId ?? "cmp-1" },
  });
  assert.equal(bound.status, 201, JSON.stringify(bound.body));
  return bound.body as { binding_id: string; session_id: string; agent: { name: string; id: string } };
}

export async function bindingRow(env: FactoryEnv, id: string) {
  const result = await env.database.query<Record<string, any>>("SELECT * FROM factory_bindings WHERE id = $1", [id]);
  assert.ok(result.rows[0], `binding ${id} not found`);
  return result.rows[0];
}

export async function deliveryRows(env: FactoryEnv, bindingId: string) {
  const result = await env.database.query<Record<string, any>>(
    "SELECT * FROM factory_deliveries WHERE binding_id = $1 ORDER BY created_at, message_id",
    [bindingId],
  );
  return result.rows;
}

/** Fails if any response or log carries a secret this harness minted or configured. */
export function assertNoSecrets(env: FactoryEnv, value: unknown) {
  const text = JSON.stringify(value);
  const secrets = [
    FACTORY_KEY, FACTORY_KEY_2, "rk_live_primary", "rk_live_other", "whsec_", "factory_helper_", "factory_reply_",
    ...[...env.relay.agents.values()].map((agent) => agent.token),
  ];
  for (const secret of secrets) assert.ok(!text.includes(secret), `secret-shaped value ${secret.slice(0, 12)} leaked`);
}

/**
 * Seeds a claimed delivery holding a live reply bearer, the state the worker
 * leaves after a successful Factory POST. Used by tests that exercise the
 * reply and teardown paths independently of the worker loop.
 */
export async function seedDelivery(env: FactoryEnv, bindingId: string, options: {
  messageId?: string; state?: "pending" | "sending" | "delivered" | "unknown" | "rejected"; expiresInMs?: number; sender?: string;
} = {}) {
  const { bearer, hash } = mintReplyBearer();
  const messageId = options.messageId ?? `msg-${Math.random().toString(36).slice(2, 10)}`;
  const payload = encryptSecret(JSON.stringify({ sender: options.sender ?? "lead", text: "hello droid" }), env.config.encryptionKeyring.active);
  await env.database.query(
    `INSERT INTO factory_deliveries
       (binding_id, message_id, workspace_id, organization_id, relay_delivery_id, sender_agent_name,
        payload_envelope, state, attempts, reply_hash, reply_expires_at)
     SELECT id, $2, workspace_id, organization_id, $3, $4, $5, $6, 1, $7, now() + ($8::bigint * interval '1 millisecond')
       FROM factory_bindings WHERE id = $1`,
    [bindingId, messageId, `dlv-${messageId}`, options.sender ?? "lead", payload, options.state ?? "delivered", hash, options.expiresInMs ?? 3_600_000],
  );
  return { bearer, hash, messageId };
}

export const replyPath = (bindingId: string) => `/api/v1/factory-sessions/agents/${bindingId}/messages`;

/** Parses the reply bearer out of an injected Factory message. */
export function bearerFrom(text: string): string {
  const match = /Authorization: Bearer ([A-Za-z0-9_-]+)"/.exec(text);
  assert.ok(match, "injected text carries a reply bearer");
  return match[1]!;
}

export const removeMember = (env: FactoryEnv, userId: string) =>
  env.api(`/api/v1/organizations/${env.organizationId}/memberships/${userId}`, { method: "DELETE", token: env.ownerToken });

export const jobPath = "/internal/v1/factory/job";
