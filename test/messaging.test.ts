import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server } from "node:http";
import test from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { ApiTokenStore } from "../src/admin/api-tokens.js";
import { createApp } from "../src/app.js";
import { hashSecret } from "../src/crypto.js";
import type { SelfhostConfig } from "../src/config.js";
import type { Database, SqlExecutor, SqlResult } from "../src/database.js";
import { SendAbandoned } from "../src/messaging/http.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";

class PGliteDatabase implements Database {
  constructor(readonly client = new PGlite()) {}

  async query<T extends Record<string, unknown>>(sql: string, params: unknown[] = []): Promise<SqlResult<T>> {
    const result = params.length > 0 ? await this.client.query<T>(sql, params) : await this.client.query<T>(sql);
    return { rows: result.rows };
  }

  async transaction<T>(run: (transaction: SqlExecutor) => Promise<T>): Promise<T> {
    return this.client.transaction(async (transaction) => run({
      query: async <R extends Record<string, unknown>>(sql: string, params: unknown[] = []) => {
        const result = params.length > 0 ? await transaction.query<R>(sql, params) : await transaction.query<R>(sql);
        return { rows: result.rows };
      },
      exec: async (sql: string) => {
        await transaction.exec(sql);
      },
    }));
  }

  async close(): Promise<void> {
    await this.client.close();
  }

  async exec(sql: string): Promise<void> {
    await this.client.exec(sql);
  }
}

type AgentRecord = {
  id: string;
  name: string;
  token: string;
  metadata: Record<string, unknown>;
  apiKey: string;
};

type StoredMessage = {
  id: string;
  conversationId: string;
  sender: string;
  text: string;
  createdAt: string;
  idempotencyKey: string;
};

type RelayState = {
  agents: Map<string, AgentRecord>;
  tokenOwner: Map<string, string>;
  messages: StoredMessage[];
  byKey: Map<string, StoredMessage>;
  refused: Set<string>;
  dropped: Set<string>;
  deliveries: Array<{ id: string; sender: string }>;
  acked: string[];
  registerCalls: number;
  dmCalls: number;
  takeoverCalls: number;
  revokeCalls: number;
  deleteCalls: number;
  readTokens: string[];
  dmTokens: string[];
  registerKeys: string[];
  admission: boolean;
  failRevoke: boolean;
  malformedNext: boolean;
  rejectNext: string | null;
  /** When false, a repeated Idempotency-Key stores another message. */
  dedup: boolean;
  /** The next DM waits here after it is counted and before it is stored. */
  holdDm: Promise<void> | null;
  leak: string;
};

function conversationId(left: string, right: string): string {
  return [left, right].sort().join("|");
}

function relayState(): RelayState {
  const state: RelayState = {
    agents: new Map(),
    tokenOwner: new Map(),
    messages: [],
    byKey: new Map(),
    refused: new Set(),
    dropped: new Set(),
    deliveries: [],
    acked: [],
    registerCalls: 0,
    dmCalls: 0,
    takeoverCalls: 0,
    revokeCalls: 0,
    deleteCalls: 0,
    readTokens: [],
    dmTokens: [],
    registerKeys: [],
    admission: false,
    failRevoke: false,
    malformedNext: false,
    rejectNext: null,
    dedup: true,
    holdDm: null,
    leak: "ar_ag_should_not_leak",
  };
  seed(state, "helper", "ag_helper", "at_helper");
  seed(state, "helper2", "ag_helper2", "at_helper2");
  return state;
}

function seed(state: RelayState, name: string, id: string, token: string): void {
  state.agents.set(name, { id, name, token, metadata: { source: "seed" }, apiKey: "seed" });
  state.tokenOwner.set(token, name);
}

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

function bearer(request: IncomingMessage): string {
  const header = request.headers.authorization ?? "";
  return header.startsWith("Bearer ") ? header.slice("Bearer ".length) : "";
}

function sendJson(response: import("node:http").ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

function createRelay(state: RelayState) {
  return createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://relaycast.internal");
    const body = await readBody(request);
    const token = bearer(request);
    const parsed = body ? JSON.parse(body) as Record<string, unknown> : {};
    const name = decodeURIComponent(url.pathname.split("/")[3] ?? "");

    if (request.method === "POST" && url.pathname === "/v1/agents") {
      state.registerCalls += 1;
      state.registerKeys.push(token);
      if (state.admission) {
        sendJson(response, 409, { error: { code: "admission", message: "register_human admission is full" } });
        return;
      }
      const agentName = String(parsed.name);
      if (state.agents.has(agentName)) {
        sendJson(response, 409, { error: { code: "agent_already_exists", message: "name taken" } });
        return;
      }
      const metadata = parsed.metadata && typeof parsed.metadata === "object" ? parsed.metadata as Record<string, unknown> : {};
      const created: AgentRecord = {
        id: `ag_${state.registerCalls}`,
        name: agentName,
        token: `ar_ag_${state.registerCalls}`,
        metadata,
        apiKey: token,
      };
      state.agents.set(agentName, created);
      state.tokenOwner.set(created.token, agentName);
      sendJson(response, 201, { data: { id: created.id, name: created.name, token: created.token } });
      return;
    }

    if (request.method === "GET" && url.pathname.startsWith("/v1/agents/") && !url.pathname.endsWith("/takeover")) {
      if (state.dropped.has(name)) {
        sendJson(response, 404, { error: { code: "not_found", message: "missing" } });
        return;
      }
      const agent = state.agents.get(name);
      if (!agent) {
        sendJson(response, 404, { error: { code: "not_found", message: "missing" } });
        return;
      }
      sendJson(response, 200, { data: { id: agent.id, name: agent.name, metadata: agent.metadata } });
      return;
    }

    if (request.method === "POST" && url.pathname.endsWith("/takeover")) {
      state.takeoverCalls += 1;
      const agent = state.agents.get(name);
      if (!agent || agent.id !== parsed.expected_agent_id) {
        sendJson(response, 409, { error: { code: "agent_identity_conflict", message: "conflict" } });
        return;
      }
      const issued = `ar_ag_takeover_${state.takeoverCalls}`;
      agent.token = issued;
      state.tokenOwner.set(issued, agent.name);
      sendJson(response, 200, { data: { agent_id: agent.id, name: agent.name, token: issued } });
      return;
    }

    if (request.method === "POST" && url.pathname.endsWith("/revoke-token")) {
      state.revokeCalls += 1;
      if (state.failRevoke) {
        state.failRevoke = false;
        sendJson(response, 500, { error: { code: "unavailable", message: state.leak } });
        return;
      }
      const agent = state.agents.get(name);
      if (!agent) {
        sendJson(response, 404, { error: { code: "not_found", message: "missing" } });
        return;
      }
      state.refused.add(agent.token);
      sendJson(response, 200, { data: { ok: true } });
      return;
    }

    if (request.method === "DELETE" && url.pathname.startsWith("/v1/agents/")) {
      state.deleteCalls += 1;
      state.agents.delete(name);
      sendJson(response, 200, { data: { ok: true } });
      return;
    }

    if (request.method === "POST" && url.pathname === "/v1/dm") {
      state.dmCalls += 1;
      state.dmTokens.push(token);
      if (state.holdDm) {
        const held = state.holdDm;
        state.holdDm = null;
        await held;
      }
      const key = String(request.headers["idempotency-key"] ?? "");
      const scopedKey = `${token}\n${key}`;
      const replay = state.dedup && key ? state.byKey.get(scopedKey) : undefined;
      if (replay) {
        sendJson(response, 201, { data: { conversation_id: replay.conversationId, message: { id: replay.id, text: replay.text, agent_name: replay.sender } } });
        return;
      }
      if (state.refused.has(token) || !state.tokenOwner.has(token)) {
        sendJson(response, 401, { error: { code: "unauthorized", message: "refused" } });
        return;
      }
      const sender = state.tokenOwner.get(token)!;
      const to = String(parsed.to);
      if (!state.agents.has(to) || state.dropped.has(to)) {
        sendJson(response, 404, { error: { code: "agent_not_found", message: "missing" } });
        return;
      }
      if (state.rejectNext) {
        const code = state.rejectNext;
        state.rejectNext = null;
        sendJson(response, code === "rejected" ? 400 : 429, { error: { code, message: state.leak } });
        return;
      }
      const message: StoredMessage = {
        id: `m${state.messages.length + 1}`,
        conversationId: conversationId(sender, to),
        sender,
        text: String(parsed.text),
        createdAt: new Date(Date.UTC(2026, 10, 6, 0, 0, state.messages.length)).toISOString(),
        idempotencyKey: key,
      };
      state.messages.push(message);
      if (state.dedup && key) state.byKey.set(scopedKey, message);
      if (state.malformedNext) {
        state.malformedNext = false;
        response.writeHead(201, { "content-type": "application/json" });
        response.end("not-json");
        return;
      }
      sendJson(response, 201, {
        data: { conversation_id: message.conversationId, message: { id: message.id, text: message.text, agent_name: sender } },
      });
      return;
    }

    if (request.method === "GET" && url.pathname === "/v1/dm/conversations") {
      state.readTokens.push(token);
      const sender = state.tokenOwner.get(token);
      const peers = new Set(state.messages.flatMap((message) => {
        const [left, right] = message.conversationId.split("|");
        if (left !== sender && right !== sender) return [];
        return [left === sender ? right : left];
      }));
      sendJson(response, 200, {
        data: [...peers].map((peer) => ({
          id: conversationId(sender ?? "", peer ?? ""),
          type: "1:1",
          participants: [{ agent_name: sender }, { agent_name: peer }],
        })),
      });
      return;
    }

    if (request.method === "GET" && /\/v1\/dm\/[^/]+\/messages$/.test(url.pathname)) {
      const id = decodeURIComponent(url.pathname.split("/")[3] ?? "");
      const limit = Number(url.searchParams.get("limit") ?? "50");
      const before = url.searchParams.get("before");
      let items = state.messages.filter((message) => message.conversationId === id)
        .sort((left, right) => left.createdAt.localeCompare(right.createdAt) || left.id.localeCompare(right.id));
      if (before) {
        const index = items.findIndex((message) => message.id === before);
        items = index >= 0 ? items.slice(0, index) : [];
      }
      const page = items.slice(-limit);
      sendJson(response, 200, {
        data: page.map((message) => ({ id: message.id, text: message.text, agent_name: message.sender, created_at: message.createdAt })),
      });
      return;
    }

    if (request.method === "GET" && url.pathname === "/v1/deliveries") {
      sendJson(response, 200, { data: state.deliveries.map((delivery) => ({ id: delivery.id, message: { agent_name: delivery.sender } })) });
      return;
    }

    if (request.method === "POST" && url.pathname.endsWith("/ack")) {
      state.acked.push(decodeURIComponent(url.pathname.split("/")[3] ?? ""));
      sendJson(response, 200, { data: { ok: true } });
      return;
    }

    sendJson(response, 404, { error: { code: "not_found", message: "missing" } });
  });
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert(address && typeof address === "object");
  return `http://127.0.0.1:${address.port}`;
}

async function close(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
}

type RequestOptions = {
  method?: string;
  token?: string;
  cookie?: string;
  body?: Record<string, unknown>;
  rawBody?: string;
  origin?: string | false;
  contentType?: string;
  secFetchSite?: string;
};

async function jsonRequest(
  baseUrl: string,
  path: string,
  options: RequestOptions = {},
): Promise<{ status: number; body: Record<string, any> }> {
  const headers: Record<string, string> = {};
  if (options.token) headers.authorization = `Bearer ${options.token}`;
  if (options.cookie) headers.cookie = options.cookie;
  const method = options.method ?? "GET";
  const hasBody = options.body !== undefined || options.rawBody !== undefined;
  if (hasBody) headers["content-type"] = options.contentType ?? "application/json";
  if (options.secFetchSite) headers["sec-fetch-site"] = options.secFetchSite;
  if (options.origin) headers.origin = options.origin;
  else if (options.cookie && method !== "GET" && options.origin !== false && !options.secFetchSite) {
    headers.origin = "https://control.internal.example";
  }
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    ...(options.rawBody !== undefined ? { body: options.rawBody } : {}),
    ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) as Record<string, any> : {} };
}

type Hooks = {
  beforeDispatch?: () => Promise<void> | void;
  afterUpstream?: () => Promise<void> | void;
  afterRemoteRegister?: () => Promise<void> | void;
  afterIdentityStaged?: () => Promise<void> | void;
  beforeMembershipRecheck?: (tx: SqlExecutor) => Promise<void> | void;
};

async function harness(t: { after: (fn: () => Promise<void>) => void }, options?: { claimLeaseMs?: number }) {
  const state = relayState();
  const hooks: Hooks = {};
  const relaycast = createRelay(state);
  const relaycastOrigin = await listen(relaycast);
  const database = new PGliteDatabase();
  let control: Server | undefined;
  t.after(async () => {
    if (control) await close(control);
    await close(relaycast);
    await database.close();
  });
  await migrate(database);
  const config: SelfhostConfig = {
    databaseUrl: "unused-in-test",
    publicBaseUrl: "https://control.internal.example",
    relaycastUrl: relaycastOrigin,
    relaycastPublicUrl: "https://cast.selfhosted.example",
    relayauthUrl: "http://relayauth.invalid",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.selfhosted.example",
    relayauthApiKey: "rak_test",
    bootstrapToken: "bootstrap-token-that-is-at-least-32-bytes",
    encryptionKeyring: { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    internalServiceToken: "service-token-that-is-at-least-32-bytes",
    oauthRedirectUrl: "https://control.internal.example/api/v1/integrations/oauth/callback",
    dashboardUrl: "https://control.internal.example/",
    port: 3000,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  control = createServer(createApp({
    config,
    store,
    messaging: {
      claimLeaseMs: options?.claimLeaseMs,
      beforeDispatch: () => hooks.beforeDispatch?.(),
      afterUpstream: () => hooks.afterUpstream?.(),
      afterRemoteRegister: () => hooks.afterRemoteRegister?.(),
      afterIdentityStaged: () => hooks.afterIdentityStaged?.(),
      beforeMembershipRecheck: (tx) => hooks.beforeMembershipRecheck?.(tx),
    },
  }));
  const origin = await listen(control);
  const org = await jsonRequest(origin, "/api/v1/organizations", {
    method: "POST",
    token: config.bootstrapToken,
    body: { name: "Tenant", ownerEmail: "owner@example.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const workspace = await jsonRequest(origin, `/api/v1/organizations/${org.body.id}/workspaces`, {
    method: "POST",
    token: config.bootstrapToken,
    body: { name: "Primary", relaycastWorkspaceId: "rc-first", relaycastApiKey: "rk_live_first" },
  });
  assert.equal(workspace.status, 201);
  const other = await jsonRequest(origin, `/api/v1/organizations/${org.body.id}/workspaces`, {
    method: "POST",
    token: config.bootstrapToken,
    body: { name: "Other", relaycastWorkspaceId: "rc-other", relaycastApiKey: "rk_live_other" },
  });
  assert.equal(other.status, 201);

  async function signIn(userId: string, workspaceId = workspace.body.id as string): Promise<string> {
    const started = await jsonRequest(origin, "/api/v1/auth/device/start", {
      method: "POST",
      body: { client_name: "messaging-test" },
    });
    assert.equal(started.status, 201);
    const approved = await jsonRequest(origin, "/api/v1/auth/device/approve", {
      method: "POST",
      token: config.bootstrapToken,
      body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: workspaceId },
    });
    assert.equal(approved.status, 200);
    const tokenResponse = await jsonRequest(origin, "/api/v1/auth/device/token", {
      method: "POST",
      body: { device_code: started.body.device_code },
    });
    assert.equal(tokenResponse.status, 200);
    return tokenResponse.body.access_token as string;
  }

  const userId = org.body.owner.id as string;
  const accessToken = await signIn(userId);
  return {
    state, hooks, origin, config, database, orgId: org.body.id as string,
    workspaceId: workspace.body.id as string, otherWorkspaceId: other.body.id as string,
    userId, accessToken, signIn,
  };
}

function credentialPath(workspaceId: string, cloud = false): string {
  return `${cloud ? "/cloud" : ""}/api/v1/workspaces/${workspaceId}/messaging/identity/credential`;
}

function threadPath(workspaceId: string, peer: string, cloud = false): string {
  return `${cloud ? "/cloud" : ""}/api/v1/workspaces/${workspaceId}/messaging/conversations/${peer}`;
}

test("person messaging round trip reads both authors and refuses the wrong caller", async (t) => {
  const fx = await harness(t);
  const agentTokens = new ApiTokenStore(fx.database);
  const agentToken = await agentTokens.create({
    workspaceId: fx.workspaceId,
    organizationId: fx.orgId,
    label: "agent",
    purpose: "agent-runtime",
    expiryDays: 1,
    neverExpires: undefined,
    actor: { kind: "user", userId: fx.userId },
  });
  const refused = await jsonRequest(fx.origin, credentialPath(fx.workspaceId, true), { method: "POST", token: agentToken.accessToken });
  assert.equal(refused.status, 403);
  const serviceRefused = await jsonRequest(fx.origin, credentialPath(fx.workspaceId), { method: "POST", token: fx.config.internalServiceToken! });
  assert.equal(serviceRefused.status, 403);
  const wrongWorkspace = await jsonRequest(fx.origin, `/api/v1/workspaces/${fx.otherWorkspaceId}/messaging/people`, { token: fx.accessToken });
  assert.equal(wrongWorkspace.status, 404);

  const credential = await jsonRequest(fx.origin, credentialPath(fx.workspaceId), { method: "POST", token: fx.accessToken });
  assert.equal(credential.status, 200);
  assert.equal(credential.body.identity.token, "ar_ag_1");
  assert.equal(credential.body.identity.relaycastUrl, "https://cast.selfhosted.example");
  assert.equal(fx.state.registerCalls, 1);
  const stored = await fx.database.query<{ token_ciphertext: string }>(
    "SELECT token_ciphertext FROM selfhost_person_identities WHERE user_id = $1",
    [fx.userId],
  );
  assert.equal(stored.rows.length, 1);
  assert.equal(stored.rows[0]?.token_ciphertext.includes("ar_ag_1"), false);

  const people = await jsonRequest(fx.origin, `/cloud/api/v1/workspaces/${fx.workspaceId}/messaging/people`, {
    cookie: `agent_relay_session=${fx.accessToken}`,
  });
  assert.equal(people.status, 200);
  assert.equal(JSON.stringify(people.body).includes("ar_ag_1"), false);
  assert.equal(people.body.people[0].handle, `@${credential.body.identity.name}`);

  const send = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper", true), {
    method: "POST",
    cookie: `agent_relay_session=${fx.accessToken}`,
    body: { text: "hello", clientMessageId: "client-msg-1" },
  });
  assert.equal(send.status, 201);
  assert.equal(send.body.message.id, "m1");
  assert.equal(fx.state.dmCalls, 1);
  assert.equal(fx.state.messages[0]?.idempotencyKey, `selfhost-dm:${fx.userId}:client-msg-1`);
  const again = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper", true), {
    method: "POST",
    cookie: `agent_relay_session=${fx.accessToken}`,
    body: { text: "hello", clientMessageId: "client-msg-1" },
  });
  assert.equal(again.status, 200);
  assert.equal(again.body.duplicate, true);
  assert.equal(fx.state.dmCalls, 1);

  const ownerName = credential.body.identity.name as string;
  fx.state.messages.push({
    id: "m-in",
    conversationId: conversationId(ownerName, "helper"),
    sender: "helper",
    text: "from helper",
    createdAt: "2026-11-06T00:00:02.000Z",
    idempotencyKey: "",
  });
  fx.state.deliveries.push({ id: "del-helper", sender: "helper" }, { id: "del-other", sender: "helper2" });
  const thread = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper", true), {
    cookie: `agent_relay_session=${fx.accessToken}`,
  });
  assert.equal(thread.status, 200);
  assert.equal(thread.body.you, ownerName);
  assert.equal(thread.body.messages.length, 2);
  assert.equal(thread.body.messages.find((message: { text: string }) => message.text === "from helper").mine, false);
  assert.equal(thread.body.messages.find((message: { text: string }) => message.text === "hello").mine, true);
  assert.deepEqual(fx.state.acked, ["del-helper"]);
});

test("parallel duplicates make one upstream call, and a fingerprint mismatch does not", async (t) => {
  const fx = await harness(t);
  const first = await jsonRequest(fx.origin, credentialPath(fx.workspaceId), { method: "POST", token: fx.accessToken });
  assert.equal(first.status, 200);
  const path = threadPath(fx.workspaceId, "helper");
  const [left, right] = await Promise.all([
    jsonRequest(fx.origin, path, { method: "POST", token: fx.accessToken, body: { text: "once", clientMessageId: "parallel-1" } }),
    jsonRequest(fx.origin, path, { method: "POST", token: fx.accessToken, body: { text: "once", clientMessageId: "parallel-1" } }),
  ]);
  assert.deepEqual([left.status, right.status].sort(), [200, 201]);
  assert.equal(fx.state.dmCalls, 1);
  assert.equal(left.body.message.id, right.body.message.id);

  const changed = await jsonRequest(fx.origin, path, {
    method: "POST",
    token: fx.accessToken,
    body: { text: "different", clientMessageId: "parallel-1" },
  });
  assert.equal(changed.status, 409);
  assert.equal(changed.body.error, "idempotency_conflict");
  const otherPeer = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper2"), {
    method: "POST",
    token: fx.accessToken,
    body: { text: "once", clientMessageId: "parallel-1" },
  });
  assert.equal(otherPeer.status, 409);
  assert.equal(otherPeer.body.error, "idempotency_conflict");
  assert.equal(fx.state.dmCalls, 1);
  assert.equal(fx.state.messages.length, 1);
});

test("a crashed or delayed send is not dispatched again without a receipt", async (t) => {
  const fx = await harness(t, { claimLeaseMs: 0 });
  fx.state.dedup = false;
  assert.equal((await jsonRequest(fx.origin, credentialPath(fx.workspaceId), { method: "POST", token: fx.accessToken })).status, 200);
  let crash: "before" | "after" | "" = "before";
  fx.hooks.beforeDispatch = () => {
    if (crash !== "before") return;
    crash = "";
    throw new SendAbandoned();
  };
  const path = threadPath(fx.workspaceId, "helper");
  const abandoned = await jsonRequest(fx.origin, path, {
    method: "POST",
    token: fx.accessToken,
    body: { text: "before", clientMessageId: "crash-before" },
  });
  assert.equal(abandoned.status, 502);
  assert.equal(abandoned.body.error, "send_uncertain");
  assert.equal(fx.state.dmCalls, 0);
  const retried = await jsonRequest(fx.origin, path, {
    method: "POST",
    token: fx.accessToken,
    body: { text: "before", clientMessageId: "crash-before" },
  });
  assert.equal(retried.status, 502);
  assert.equal(retried.body.error, "send_uncertain");
  assert.equal(fx.state.dmCalls, 0);
  assert.match(retried.body.message as string, /will not be sent again/);
  const fresh = await jsonRequest(fx.origin, path, {
    method: "POST",
    token: fx.accessToken,
    body: { text: "before", clientMessageId: "crash-before-new" },
  });
  assert.equal(fresh.status, 201);
  assert.equal(fx.state.dmCalls, 1);

  crash = "after";
  fx.hooks.afterUpstream = () => {
    if (crash !== "after") return;
    crash = "";
    throw new SendAbandoned();
  };
  const accepted = await jsonRequest(fx.origin, path, {
    method: "POST",
    token: fx.accessToken,
    body: { text: "after", clientMessageId: "crash-after" },
  });
  assert.equal(accepted.status, 502);
  assert.equal(accepted.body.error, "send_uncertain");
  assert.equal(fx.state.messages.length, 2);
  const reconciled = await jsonRequest(fx.origin, path, {
    method: "POST",
    token: fx.accessToken,
    body: { text: "after", clientMessageId: "crash-after" },
  });
  assert.equal(reconciled.status, 502);
  assert.equal(reconciled.body.error, "send_uncertain");
  assert.equal(fx.state.dmCalls, 2);
  assert.equal(fx.state.messages.length, 2);

  let releaseHold: () => void = () => {};
  fx.state.holdDm = new Promise<void>((resolve) => {
    releaseHold = resolve;
  });
  const delayed = jsonRequest(fx.origin, path, {
    method: "POST",
    token: fx.accessToken,
    body: { text: "held", clientMessageId: "held-msg-1" },
  });
  for (let i = 0; i < 50 && fx.state.dmCalls < 3; i += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(fx.state.dmCalls, 3);
  const overlapped = await jsonRequest(fx.origin, path, {
    method: "POST",
    token: fx.accessToken,
    body: { text: "held", clientMessageId: "held-msg-1" },
  });
  assert.equal(overlapped.status, 502);
  assert.equal(overlapped.body.error, "send_uncertain");
  assert.equal(fx.state.dmCalls, 3);
  assert.equal(fx.state.messages.length, 2);
  releaseHold();
  const finished = await delayed;
  assert.equal(finished.status, 201);
  assert.equal(fx.state.dmCalls, 3);
  assert.equal(fx.state.messages.length, 3);
  const settled = await jsonRequest(fx.origin, path, {
    method: "POST",
    token: fx.accessToken,
    body: { text: "held", clientMessageId: "held-msg-1" },
  });
  assert.equal(settled.status, 200);
  assert.equal(settled.body.duplicate, true);
  assert.equal(settled.body.message.id, finished.body.message.id);
  assert.equal(fx.state.dmCalls, 3);
});

test("cookie writes require the existing origin guard and bearer still works", async (t) => {
  const fx = await harness(t);
  const cookie = `agent_relay_session=${fx.accessToken}`;
  const evil = await jsonRequest(fx.origin, credentialPath(fx.workspaceId, true), {
    method: "POST",
    cookie,
    origin: "https://evil.internal.example",
    contentType: "text/plain",
    rawBody: "{}",
  });
  assert.equal(evil.status, 403);
  assert.equal(evil.body.error, "csrf_rejected");
  const crossSite = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper", true), {
    method: "POST",
    cookie,
    origin: false,
    secFetchSite: "cross-site",
    body: { text: "hello", clientMessageId: "csrf-msg-1" },
  });
  assert.equal(crossSite.status, 403);
  assert.equal(crossSite.body.error, "csrf_rejected");
  const form = await jsonRequest(fx.origin, credentialPath(fx.workspaceId, true), {
    method: "POST",
    cookie,
    contentType: "application/x-www-form-urlencoded",
    rawBody: "{}",
  });
  assert.equal(form.status, 403);
  assert.equal(fx.state.registerCalls, 0);
  assert.equal(fx.state.dmCalls, 0);
  const bearer = await jsonRequest(fx.origin, credentialPath(fx.workspaceId), { method: "POST", token: fx.accessToken });
  assert.equal(bearer.status, 200);
  assert.equal(typeof bearer.body.identity.token, "string");
  const trusted = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper", true), {
    method: "POST",
    cookie,
    body: { text: "hello", clientMessageId: "csrf-msg-1" },
  });
  assert.equal(trusted.status, 201);
});

test("identity creation recovers a lost response and skips a foreign name", async (t) => {
  const fx = await harness(t);
  let lost = 1;
  fx.hooks.afterRemoteRegister = () => {
    if (lost-- > 0) throw new Error("lost response");
  };
  const failed = await jsonRequest(fx.origin, credentialPath(fx.workspaceId), { method: "POST", token: fx.accessToken });
  assert.equal(failed.status, 502);
  const rows = await fx.database.query("SELECT id FROM selfhost_person_identities");
  assert.equal(rows.rows.length, 0);
  const recovered = await jsonRequest(fx.origin, credentialPath(fx.workspaceId), { method: "POST", token: fx.accessToken });
  assert.equal(recovered.status, 200);
  assert.equal(fx.state.takeoverCalls, 1);
  assert.equal(recovered.body.identity.token, "ar_ag_takeover_1");
  assert.equal((await fx.database.query("SELECT id FROM selfhost_person_identities")).rows.length, 1);

  const staged = await harness(t);
  let stagedFailures = 1;
  staged.hooks.afterIdentityStaged = () => {
    if (stagedFailures-- > 0) throw new Error("rolled back");
  };
  assert.equal((await jsonRequest(staged.origin, credentialPath(staged.workspaceId), { method: "POST", token: staged.accessToken })).status, 502);
  assert.equal((await staged.database.query("SELECT id FROM selfhost_person_identities")).rows.length, 0);
  const stagedRetry = await jsonRequest(staged.origin, credentialPath(staged.workspaceId), { method: "POST", token: staged.accessToken });
  assert.equal(stagedRetry.status, 200);
  assert.equal(staged.state.takeoverCalls, 1);

  const foreign = await harness(t);
  foreign.state.agents.set("owner", {
    id: "ag_foreign",
    name: "owner",
    token: "ar_ag_foreign",
    metadata: { source: "cloud-person", role: "person", cloud_workspace_id: "elsewhere", cloud_user_id: "someone-else" },
    apiKey: "rk_live_first",
  });
  const minted = await jsonRequest(foreign.origin, credentialPath(foreign.workspaceId), { method: "POST", token: foreign.accessToken });
  assert.equal(minted.status, 200);
  assert.notEqual(minted.body.identity.agentId, "ag_foreign");
  assert.equal(foreign.state.takeoverCalls, 0);

  const [left, right] = await Promise.all([
    jsonRequest(foreign.origin, credentialPath(foreign.workspaceId), { method: "POST", token: foreign.accessToken }),
    jsonRequest(foreign.origin, credentialPath(foreign.workspaceId), { method: "POST", token: foreign.accessToken }),
  ]);
  assert.equal(left.status, 200);
  assert.equal(right.status, 200);
  assert.equal(left.body.identity.token, right.body.identity.token);

  const concurrent = await harness(t);
  const [firstMint, secondMint] = await Promise.all([
    jsonRequest(concurrent.origin, credentialPath(concurrent.workspaceId), { method: "POST", token: concurrent.accessToken }),
    jsonRequest(concurrent.origin, credentialPath(concurrent.workspaceId), { method: "POST", token: concurrent.accessToken }),
  ]);
  assert.equal(firstMint.status, 200);
  assert.equal(secondMint.status, 200);
  assert.equal(firstMint.body.identity.agentId, secondMint.body.identity.agentId);
  assert.equal(firstMint.body.identity.token, secondMint.body.identity.token);
  assert.equal(concurrent.state.registerCalls, 1);
});

test("rebinding the relay workspace does not reuse the previous token or send", async (t) => {
  const fx = await harness(t);
  const minted = await jsonRequest(fx.origin, credentialPath(fx.workspaceId), { method: "POST", token: fx.accessToken });
  const oldToken = minted.body.identity.token as string;
  const sent = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper"), {
    method: "POST",
    token: fx.accessToken,
    body: { text: "in-a", clientMessageId: "rebind-msg-1" },
  });
  assert.equal(sent.status, 201);
  const rebound = await jsonRequest(fx.origin, `/api/v1/organizations/${fx.orgId}/workspaces/${fx.workspaceId}`, {
    method: "PUT",
    token: fx.config.bootstrapToken,
    body: { relaycastWorkspaceId: "rc-b", relaycastApiKey: "rk_live_b" },
  });
  assert.equal(rebound.status, 200);
  const hidden = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper"), { token: fx.accessToken });
  assert.equal(hidden.status, 200);
  assert.equal(hidden.body.you, null);
  assert.deepEqual(hidden.body.messages, []);
  assert.equal(fx.state.readTokens.includes(oldToken), false);
  const reminted = await jsonRequest(fx.origin, credentialPath(fx.workspaceId), { method: "POST", token: fx.accessToken });
  assert.equal(reminted.status, 200);
  assert.notEqual(reminted.body.identity.token, oldToken);
  assert.equal(fx.state.registerKeys.at(-1), "rk_live_b");
  const sendsBefore = fx.state.dmTokens.length;
  const again = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper"), {
    method: "POST",
    token: fx.accessToken,
    body: { text: "in-a", clientMessageId: "rebind-msg-1" },
  });
  assert.equal(again.status, 201);
  assert.notEqual(again.body.message.id, sent.body.message.id);
  assert.equal(fx.state.dmTokens.slice(sendsBefore).includes(oldToken), false);
  assert.equal(fx.state.dmTokens.at(-1), reminted.body.identity.token);
});

test("a refused token is recovered once, and a foreign replacement is not taken over", async (t) => {
  const fx = await harness(t);
  const minted = await jsonRequest(fx.origin, credentialPath(fx.workspaceId), { method: "POST", token: fx.accessToken });
  const token = minted.body.identity.token as string;
  const name = minted.body.identity.name as string;
  fx.state.refused.add(token);
  const sent = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper"), {
    method: "POST",
    token: fx.accessToken,
    body: { text: "rotated", clientMessageId: "rotate-msg-1" },
  });
  assert.equal(sent.status, 201);
  assert.equal(fx.state.takeoverCalls, 1);
  assert.equal(fx.state.messages.length, 1);
  const second = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper"), {
    method: "POST",
    token: fx.accessToken,
    body: { text: "again", clientMessageId: "rotate-msg-2" },
  });
  assert.equal(second.status, 201);
  assert.equal(fx.state.takeoverCalls, 1);

  const removed = await harness(t);
  const gone = await jsonRequest(removed.origin, credentialPath(removed.workspaceId), { method: "POST", token: removed.accessToken });
  removed.state.dropped.add(gone.body.identity.name as string);
  removed.state.agents.delete(gone.body.identity.name as string);
  removed.state.refused.add(gone.body.identity.token as string);
  const recreated = await jsonRequest(removed.origin, threadPath(removed.workspaceId, "helper"), {
    method: "POST",
    token: removed.accessToken,
    body: { text: "recreated", clientMessageId: "delete-msg-1" },
  });
  assert.equal(recreated.status, 201);
  assert.notEqual(recreated.body.you, "");
  assert.equal(removed.state.takeoverCalls, 0);

  const replaced = await harness(t);
  const original = await jsonRequest(replaced.origin, credentialPath(replaced.workspaceId), { method: "POST", token: replaced.accessToken });
  const agent = replaced.state.agents.get(original.body.identity.name as string);
  assert.ok(agent);
  agent.id = "ag_replaced";
  agent.metadata = { source: "cloud-person", role: "person", cloud_workspace_id: "elsewhere", cloud_user_id: "other-user" };
  replaced.state.refused.add(original.body.identity.token as string);
  const conflict = await jsonRequest(replaced.origin, threadPath(replaced.workspaceId, "helper"), {
    method: "POST",
    token: replaced.accessToken,
    body: { text: "nope", clientMessageId: "foreign-msg-1" },
  });
  assert.equal(conflict.status, 409);
  assert.equal(conflict.body.error, "foreign_identity");
  assert.equal(replaced.state.takeoverCalls, 0);
  assert.equal(replaced.state.messages.length, 0);
  assert.equal(name.length > 0, true);
});

test("removing a member revokes the human credential and drops them from the directory", async (t) => {
  const fx = await harness(t);
  const owner = await jsonRequest(fx.origin, credentialPath(fx.workspaceId), { method: "POST", token: fx.accessToken });
  assert.equal(owner.status, 200);
  const membership = await jsonRequest(fx.origin, `/api/v1/organizations/${fx.orgId}/memberships`, {
    method: "POST",
    token: fx.config.bootstrapToken,
    body: { email: "ada@example.test", name: "Ada", role: "member" },
  });
  assert.equal(membership.status, 200);
  const memberToken = await fx.signIn(membership.body.userId as string);
  const member = await jsonRequest(fx.origin, credentialPath(fx.workspaceId), { method: "POST", token: memberToken });
  assert.equal(member.status, 200);
  const memberUserId = membership.body.userId as string;
  await fx.database.query(
    "UPDATE selfhost_person_identities SET relaycast_workspace_id = 'stale-binding' WHERE user_id = $1",
    [memberUserId],
  );
  const hidden = await jsonRequest(fx.origin, `/api/v1/workspaces/${fx.workspaceId}/messaging/people`, { token: fx.accessToken });
  assert.equal(hidden.body.people.some((person: { userId: string }) => person.userId === memberUserId), false);
  await fx.database.query(
    "UPDATE selfhost_person_identities SET relaycast_workspace_id = 'rc-first' WHERE user_id = $1",
    [memberUserId],
  );
  const visible = await jsonRequest(fx.origin, `/api/v1/workspaces/${fx.workspaceId}/messaging/people`, { token: fx.accessToken });
  assert.equal(visible.body.people.some((person: { userId: string }) => person.userId === memberUserId), true);

  const removed = await jsonRequest(fx.origin, `/api/v1/organizations/${fx.orgId}/memberships/${memberUserId}`, {
    method: "DELETE",
    token: fx.config.bootstrapToken,
  });
  assert.equal(removed.status, 204);
  assert.equal(fx.state.revokeCalls, 1);
  assert.equal(fx.state.deleteCalls, 1);
  const directory = await jsonRequest(fx.origin, `/api/v1/workspaces/${fx.workspaceId}/messaging/people`, { token: fx.accessToken });
  assert.equal(directory.body.people.some((person: { userId: string }) => person.userId === memberUserId), false);
  assert.equal(directory.body.people.some((person: { userId: string }) => person.userId === fx.userId), true);
  const direct = await fetch(`${fx.config.relaycastUrl}/v1/dm`, {
    method: "POST",
    headers: { authorization: `Bearer ${member.body.identity.token}`, "content-type": "application/json" },
    body: JSON.stringify({ to: "helper", text: "still here" }),
  });
  assert.equal(direct.status, 401);
  const identities = await fx.database.query("SELECT id FROM selfhost_person_identities WHERE user_id = $1", [memberUserId]);
  assert.equal(identities.rows.length, 0);

  const flaky = await harness(t);
  const flakyMember = await jsonRequest(flaky.origin, `/api/v1/organizations/${flaky.orgId}/memberships`, {
    method: "POST",
    token: flaky.config.bootstrapToken,
    body: { email: "bea@example.test", name: "Bea", role: "member" },
  });
  const beaToken = await flaky.signIn(flakyMember.body.userId as string);
  assert.equal((await jsonRequest(flaky.origin, credentialPath(flaky.workspaceId), { method: "POST", token: beaToken })).status, 200);
  flaky.state.failRevoke = true;
  const queued = await jsonRequest(flaky.origin, `/api/v1/organizations/${flaky.orgId}/memberships/${flakyMember.body.userId}`, {
    method: "DELETE",
    token: flaky.config.bootstrapToken,
  });
  assert.equal(queued.status, 204);
  const waiting = await flaky.database.query("SELECT id FROM selfhost_person_revocations WHERE user_id = $1", [flakyMember.body.userId]);
  assert.equal(waiting.rows.length, 1);
  await jsonRequest(flaky.origin, `/api/v1/workspaces/${flaky.workspaceId}/messaging/people`, { token: flaky.accessToken });
  const drained = await flaky.database.query("SELECT id FROM selfhost_person_revocations WHERE user_id = $1", [flakyMember.body.userId]);
  assert.equal(drained.rows.length, 0);
  assert.equal(flaky.state.revokeCalls, 2);

  const raced = await harness(t);
  raced.hooks.beforeMembershipRecheck = async (tx) => {
    await tx.query("DELETE FROM selfhost_organization_memberships WHERE user_id = $1", [raced.userId]);
  };
  const blocked = await jsonRequest(raced.origin, credentialPath(raced.workspaceId), { method: "POST", token: raced.accessToken });
  assert.equal(blocked.status, 403);
  assert.equal(JSON.stringify(blocked.body).includes("ar_ag_"), false);
  assert.equal((await raced.database.query("SELECT id FROM selfhost_person_identities")).rows.length, 0);
  assert.equal(raced.state.revokeCalls, 1);
});

test("reads do not mint, malformed paths are 400, and send errors keep their codes", async (t) => {
  const fx = await harness(t);
  const empty = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper"), { token: fx.accessToken });
  assert.equal(empty.status, 200);
  assert.equal(empty.body.you, null);
  assert.deepEqual(empty.body.messages, []);
  assert.equal(empty.body.earlier, null);
  const invalid = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper"), {
    method: "POST",
    token: fx.accessToken,
    body: { text: "", clientMessageId: "short" },
  });
  assert.equal(invalid.status, 400);
  assert.equal(invalid.body.error, "invalid_message");
  assert.equal(fx.state.registerCalls, 0);

  for (const path of [
    `/api/v1/workspaces/%E0%A4%A/messaging/people`,
    `/cloud/api/v1/workspaces/%E0%A4%A/messaging/people`,
    `/api/v1/workspaces/${fx.workspaceId}/messaging/conversations/%E0%A4%A`,
    `/cloud/api/v1/workspaces/${fx.workspaceId}/messaging/conversations/%ZZ`,
  ]) {
    const response = await jsonRequest(fx.origin, path, { token: fx.accessToken });
    assert.equal(response.status, 400, path);
    assert.equal(response.body.error, "invalid_recipient");
  }
  assert.equal(fx.state.registerCalls, 0);

  const minted = await jsonRequest(fx.origin, credentialPath(fx.workspaceId), { method: "POST", token: fx.accessToken });
  assert.equal(minted.status, 200);
  const longOk = "a".repeat(4001);
  const maxOk = "b".repeat(16_000);
  const tooLong = "c".repeat(16_001);
  assert.equal((await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper"), {
    method: "POST", token: fx.accessToken, body: { text: longOk, clientMessageId: "length-msg-1" },
  })).status, 201);
  assert.equal((await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper"), {
    method: "POST", token: fx.accessToken, body: { text: maxOk, clientMessageId: "length-msg-2" },
  })).status, 201);
  const rejected = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper"), {
    method: "POST", token: fx.accessToken, body: { text: tooLong, clientMessageId: "length-msg-3" },
  });
  assert.equal(rejected.status, 400);
  assert.match(rejected.body.message as string, /16000/);

  const missing = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "missing"), {
    method: "POST", token: fx.accessToken, body: { text: "hi", clientMessageId: "missing-msg-1" },
  });
  assert.equal(missing.status, 404);
  assert.equal(missing.body.error, "recipient_not_found");
  const missingAgain = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "missing"), {
    method: "POST", token: fx.accessToken, body: { text: "hi", clientMessageId: "missing-msg-1" },
  });
  assert.equal(missingAgain.status, 404);

  fx.state.rejectNext = "rejected";
  const explicit = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper"), {
    method: "POST", token: fx.accessToken, body: { text: "no", clientMessageId: "reject-msg-1" },
  });
  assert.equal(explicit.status, 502);
  assert.equal(explicit.body.error, "upstream_unavailable");
  assert.equal(JSON.stringify(explicit.body).includes(fx.state.leak), false);

  fx.state.rejectNext = "rate";
  const limited = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper"), {
    method: "POST", token: fx.accessToken, body: { text: "later", clientMessageId: "rate-msg-1" },
  });
  assert.equal(limited.status, 502);
  assert.equal(limited.body.error, "upstream_unavailable");
  assert.equal(JSON.stringify(limited.body).includes(fx.state.leak), false);
  const callsAfterRate = fx.state.dmCalls;
  const rateRetry = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper"), {
    method: "POST", token: fx.accessToken, body: { text: "later", clientMessageId: "rate-msg-1" },
  });
  assert.equal(rateRetry.status, 201);
  assert.equal(fx.state.dmCalls, callsAfterRate + 1);

  fx.state.malformedNext = true;
  const uncertain = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper"), {
    method: "POST", token: fx.accessToken, body: { text: "maybe", clientMessageId: "malformed-msg-1" },
  });
  assert.equal(uncertain.status, 502);
  assert.equal(uncertain.body.error, "send_uncertain");
  const callsAtUncertain = fx.state.dmCalls;
  fx.state.dedup = false;
  const confirmed = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper"), {
    method: "POST", token: fx.accessToken, body: { text: "maybe", clientMessageId: "malformed-msg-1" },
  });
  assert.equal(confirmed.status, 502);
  assert.equal(confirmed.body.error, "send_uncertain");
  assert.equal(fx.state.dmCalls, callsAtUncertain);
  assert.equal(fx.state.messages.filter((message) => message.idempotencyKey.endsWith("malformed-msg-1")).length, 1);
  fx.state.dedup = true;

  const ownerName = minted.body.identity.name as string;
  for (let index = 0; index < 60; index += 1) {
    fx.state.messages.push({
      id: `page-${index}`,
      conversationId: conversationId(ownerName, "helper2"),
      sender: index % 2 === 0 ? ownerName : "helper2",
      text: `page ${index}`,
      createdAt: `2026-11-07T00:${String(index).padStart(2, "0")}:00.000Z`,
      idempotencyKey: "",
    });
  }
  const page = await jsonRequest(fx.origin, threadPath(fx.workspaceId, "helper2"), { token: fx.accessToken });
  assert.equal(page.body.messages.length, 50);
  assert.equal(typeof page.body.earlier, "string");
  const earlier = await jsonRequest(fx.origin, `${threadPath(fx.workspaceId, "helper2")}?before=${page.body.earlier}`, { token: fx.accessToken });
  const firstIds = new Set((page.body.messages as Array<{ id: string }>).map((message) => message.id));
  const olderIds = (earlier.body.messages as Array<{ id: string }>).map((message) => message.id);
  assert.equal(olderIds.some((id) => firstIds.has(id)), false);
  assert.equal(firstIds.size + olderIds.length, 60);
});

test("register_human admission stays a typed conflict", async (t) => {
  const fx = await harness(t);
  fx.state.admission = true;
  const full = await jsonRequest(fx.origin, credentialPath(fx.workspaceId), { method: "POST", token: fx.accessToken });
  assert.equal(full.status, 409);
  assert.equal(full.body.error, "register_human_admission");
  assert.equal((await fx.database.query("SELECT id FROM selfhost_person_identities")).rows.length, 0);
});

// ---- GET /resolve: the workspace-wide Relaycast key (Cloud parity) ----------

function resolvePath(workspaceId: string, cloud = false): string {
  return `${cloud ? "/cloud" : ""}/api/v1/workspaces/${workspaceId}/resolve`;
}

async function resolveAudits(database: Database) {
  return (await database.query<Record<string, unknown>>(
    "SELECT * FROM selfhost_admin_audit_events WHERE action = 'workspace.relaycast_key.resolved' ORDER BY created_at",
  )).rows;
}

async function dropCliAuth(database: Database, token: string): Promise<void> {
  const updated = await database.query(
    "UPDATE selfhost_token_sessions SET scopes = ARRAY['rth:read']::text[] WHERE access_token_hash = $1 RETURNING id",
    [hashSecret(token)],
  );
  assert.equal(updated.rows.length, 1);
}

async function addMember(fx: Awaited<ReturnType<typeof harness>>, email: string): Promise<{ userId: string; token: string }> {
  const membership = await jsonRequest(fx.origin, `/api/v1/organizations/${fx.orgId}/memberships`, {
    method: "POST",
    token: fx.config.bootstrapToken,
    body: { email, name: email, role: "member" },
  });
  assert.equal(membership.status, 200);
  const userId = membership.body.userId as string;
  return { userId, token: await fx.signIn(userId) };
}

test("resolve: an owner cli:auth bearer receives the key", async (t) => {
  const fx = await harness(t);
  const resolved = await jsonRequest(fx.origin, resolvePath(fx.workspaceId), { token: fx.accessToken });
  assert.equal(resolved.status, 200);
  assert.deepEqual(Object.keys(resolved.body).sort(), [
    "cloudWorkspaceId", "name", "organizationId", "provisioned", "relaycastApiKey",
    "relaycastWorkspaceId", "urls", "workspaceId",
  ]);
  assert.equal(resolved.body.relaycastApiKey, "rk_live_first");
});

test("resolve: a plain member with cli:auth still receives the key", async (t) => {
  const fx = await harness(t);
  const member = await addMember(fx, "member@example.test");
  const resolved = await jsonRequest(fx.origin, resolvePath(fx.workspaceId), { token: member.token });
  assert.equal(resolved.status, 200);
  assert.equal(resolved.body.relaycastApiKey, "rk_live_first");
});

test("resolve: a cli:auth session cookie on /cloud receives the key", async (t) => {
  const fx = await harness(t);
  const resolved = await jsonRequest(fx.origin, resolvePath(fx.workspaceId, true), {
    cookie: `agent_relay_session=${fx.accessToken}`,
  });
  assert.equal(resolved.status, 200);
  assert.equal(resolved.body.relaycastApiKey, "rk_live_first");
});

test("resolve: a bearer without cli:auth is 403 with no key", async (t) => {
  const fx = await harness(t);
  const control = await fx.signIn(fx.userId);
  const lowScope = await fx.signIn(fx.userId);
  await dropCliAuth(fx.database, lowScope);
  assert.equal((await jsonRequest(fx.origin, resolvePath(fx.workspaceId), { token: control })).status, 200);
  const denied = await jsonRequest(fx.origin, resolvePath(fx.workspaceId), { token: lowScope });
  assert.equal(denied.status, 403);
  assert.equal(denied.body.error, "forbidden");
  assert.equal("relaycastApiKey" in denied.body, false);
});

test("resolve: a low-scope token sent as a same-origin /cloud cookie is 403", async (t) => {
  const fx = await harness(t);
  const lowScope = await fx.signIn(fx.userId);
  await dropCliAuth(fx.database, lowScope);
  const denied = await jsonRequest(fx.origin, resolvePath(fx.workspaceId, true), {
    cookie: `agent_relay_session=${lowScope}`,
    origin: "https://control.internal.example",
    secFetchSite: "same-origin",
  });
  assert.equal(denied.status, 403);
  assert.equal(denied.body.error, "forbidden");
  assert.equal("relaycastApiKey" in denied.body, false);
});

test("resolve: a workspace sh_wk_ token is 403", async (t) => {
  const fx = await harness(t);
  const created = await new ApiTokenStore(fx.database).create({
    workspaceId: fx.workspaceId,
    organizationId: fx.orgId,
    label: "agent",
    purpose: "agent-runtime",
    expiryDays: 1,
    neverExpires: undefined,
    actor: { kind: "user", userId: fx.userId },
  });
  assert.ok(created.accessToken.startsWith("sh_wk_"));
  const denied = await jsonRequest(fx.origin, resolvePath(fx.workspaceId), { token: created.accessToken });
  assert.equal(denied.status, 403);
  assert.equal("relaycastApiKey" in denied.body, false);
});

test("resolve: the internal service token is 403", async (t) => {
  const fx = await harness(t);
  const denied = await jsonRequest(fx.origin, resolvePath(fx.workspaceId), { token: fx.config.internalServiceToken! });
  assert.equal(denied.status, 403);
  assert.equal("relaycastApiKey" in denied.body, false);
});

test("resolve: the bootstrap token is not a user and gets no key", async (t) => {
  const fx = await harness(t);
  const denied = await jsonRequest(fx.origin, resolvePath(fx.workspaceId), { token: fx.config.bootstrapToken });
  assert.equal(denied.status, 401);
  assert.equal("relaycastApiKey" in denied.body, false);
});

test("resolve: a token bound to workspace A cannot resolve workspace B", async (t) => {
  const fx = await harness(t);
  const boundToOther = await fx.signIn(fx.userId, fx.otherWorkspaceId);
  const own = await jsonRequest(fx.origin, resolvePath(fx.otherWorkspaceId), { token: boundToOther });
  assert.equal(own.status, 200);
  assert.equal(own.body.relaycastApiKey, "rk_live_other");
  const cross = await jsonRequest(fx.origin, resolvePath(fx.otherWorkspaceId), { token: fx.accessToken });
  assert.equal(cross.status, 404);
  assert.equal("relaycastApiKey" in cross.body, false);
});

test("resolve: a revoked token gets no key", async (t) => {
  const fx = await harness(t);
  const token = await fx.signIn(fx.userId);
  assert.equal((await jsonRequest(fx.origin, resolvePath(fx.workspaceId), { token })).status, 200);
  const revoked = await jsonRequest(fx.origin, "/api/v1/auth/token/revoke", { method: "POST", token });
  assert.equal(revoked.status, 200);
  const denied = await jsonRequest(fx.origin, resolvePath(fx.workspaceId), { token });
  assert.equal(denied.status, 401);
  assert.equal("relaycastApiKey" in denied.body, false);
});

test("resolve: a removed member gets no key", async (t) => {
  const fx = await harness(t);
  const member = await addMember(fx, "leaver@example.test");
  assert.equal((await jsonRequest(fx.origin, resolvePath(fx.workspaceId), { token: member.token })).status, 200);
  const removed = await jsonRequest(fx.origin, `/api/v1/organizations/${fx.orgId}/memberships/${member.userId}`, {
    method: "DELETE",
    token: fx.config.bootstrapToken,
  });
  assert.equal(removed.status, 204);
  const denied = await jsonRequest(fx.origin, resolvePath(fx.workspaceId), { token: member.token });
  assert.ok(denied.status === 401 || denied.status === 404, String(denied.status));
  assert.equal("relaycastApiKey" in denied.body, false);
});

test("resolve: each disclosure writes one secret-free audit row", async (t) => {
  const fx = await harness(t);
  assert.equal((await resolveAudits(fx.database)).length, 0);
  const resolved = await jsonRequest(fx.origin, resolvePath(fx.workspaceId), { token: fx.accessToken });
  assert.equal(resolved.status, 200);
  const rows = await resolveAudits(fx.database);
  assert.equal(rows.length, 1);
  const row = rows[0]!;
  assert.equal(row.actor_kind, "user");
  assert.equal(row.actor_id, fx.userId);
  assert.equal(row.workspace_id, fx.workspaceId);
  assert.equal(row.organization_id, fx.orgId);
  assert.match(String(row.target), /^session:[0-9a-f-]{36}$/);
  const serialized = JSON.stringify(row);
  assert.equal(serialized.includes("rk_live_first"), false);
  assert.equal(serialized.includes(fx.accessToken), false);
  assert.equal(serialized.includes(hashSecret(fx.accessToken)), false);
});

test("resolve: a refusal writes no audit row", async (t) => {
  const fx = await harness(t);
  const lowScope = await fx.signIn(fx.userId);
  await dropCliAuth(fx.database, lowScope);
  const created = await new ApiTokenStore(fx.database).create({
    workspaceId: fx.workspaceId,
    organizationId: fx.orgId,
    label: "agent",
    purpose: "agent-runtime",
    expiryDays: 1,
    neverExpires: undefined,
    actor: { kind: "user", userId: fx.userId },
  });
  for (const token of [lowScope, created.accessToken, fx.config.internalServiceToken!, fx.config.bootstrapToken]) {
    const denied = await jsonRequest(fx.origin, resolvePath(fx.workspaceId), { token });
    assert.notEqual(denied.status, 200);
  }
  assert.equal((await jsonRequest(fx.origin, resolvePath(fx.otherWorkspaceId), { token: fx.accessToken })).status, 404);
  assert.equal((await resolveAudits(fx.database)).length, 0);
});
