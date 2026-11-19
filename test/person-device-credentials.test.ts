import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import test from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { hashSecret } from "../src/crypto.js";
import type { SqlExecutor } from "../src/database.js";
import {
  DEVICE_TOKEN_TTL_SECONDS,
  deviceId,
  deviceName,
  deviceTokenExpiry,
  isMissingDeviceTokenRoute,
  isValidDeviceId,
} from "../src/messaging/device-credentials.js";
import { RelaycastCallError } from "../src/messaging/relaycast.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase } from "./support/harness.js";

/**
 * A Relaycast with person agents, their workspace-key routes and per-device
 * tokens. A device token acts as its agent at GET /v1/agent until it is
 * revoked, replaced by a newer mint for the same device, or the agent is
 * taken over. Unknown routes answer Relaycast's own "Route not found" 404.
 */
type Agent = { id: string; name: string; token: string; metadata: Record<string, unknown> };
type DeviceToken = { token: string; device: Record<string, unknown> };
type Answer = { status: number; body: unknown };

type RelayState = {
  agents: Map<string, Agent>;
  /** Live tokens (agent and device) to the agent name they act as. */
  tokenOwner: Map<string, string>;
  /** `${agentName}\n${deviceId}` to that device's live token. */
  deviceTokens: Map<string, DeviceToken>;
  registerCalls: number;
  takeoverCalls: number;
  probeCalls: number;
  /** Every device-token mint request body, in order. */
  mints: Array<Record<string, unknown>>;
  /** The device id of every device-token DELETE, in order. */
  deviceDeletes: string[];
  /** Answers for the next mints, used before the normal behaviour. */
  mintAnswers: Answer[];
  /** `undefined` answers now + ttl_seconds; a string or null is sent as `expires_at`. */
  mintExpiresAt: string | null | undefined;
  /** Device-token DELETEs to fail with a 500 before they succeed. */
  deleteFailures: number;
  /** GET /v1/agent drops the connection. */
  probeDown: boolean;
  /** Answers for the next GET /v1/agent calls, used before the normal behaviour. */
  probeAnswers: Answer[];
  /** Relaycast issues device tokens in two shapes; Control must not depend on either. */
  deviceTokenPrefix: "at_live_dv_" | "ar_ad_";
  /** Every device token issued, in order. */
  issuedTokens: string[];
  /** Device-token DELETEs are accepted and never answered. */
  deleteHangs: boolean;
};

function relayState(): RelayState {
  return {
    agents: new Map(),
    tokenOwner: new Map(),
    deviceTokens: new Map(),
    registerCalls: 0,
    takeoverCalls: 0,
    probeCalls: 0,
    mints: [],
    deviceDeletes: [],
    mintAnswers: [],
    mintExpiresAt: undefined,
    deleteFailures: 0,
    probeDown: false,
    probeAnswers: [],
    deviceTokenPrefix: "at_live_dv_",
    issuedTokens: [],
    deleteHangs: false,
  };
}

/** Whether `value` carries any device token the relay issued. */
function mentionsIssuedToken(state: RelayState, value: unknown): boolean {
  const serialized = typeof value === "string" ? value : JSON.stringify(value);
  return state.issuedTokens.some((token) => serialized.includes(token));
}

/** Relaycast's device name cleaning: control characters to spaces, whitespace collapsed, trimmed, at most 80. */
function relayCleanName(name: unknown): string {
  return String(name).replace(/\p{Cc}/gu, " ").replace(/\s+/g, " ").trim().slice(0, 80);
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

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
}

const ROUTE_NOT_FOUND = { error: { code: "not_found", message: "Route not found" } };

function dropDeviceTokens(state: RelayState, agentName: string): void {
  for (const [key, entry] of state.deviceTokens) {
    if (key.startsWith(`${agentName}\n`)) {
      state.tokenOwner.delete(entry.token);
      state.deviceTokens.delete(key);
    }
  }
}

function createRelay(state: RelayState) {
  return createServer(async (request, response) => {
    const url = new URL(request.url ?? "/", "http://relaycast.internal");
    const raw = await readBody(request);
    const parsed = raw ? JSON.parse(raw) as Record<string, unknown> : {};
    const token = bearer(request);
    const mint = /^\/v1\/agents\/([^/]+)\/device-tokens$/.exec(url.pathname);
    const revoke = /^\/v1\/agents\/([^/]+)\/device-tokens\/([^/]+)$/.exec(url.pathname);
    const agentPath = /^\/v1\/agents\/([^/]+)(\/takeover|\/revoke-token)?$/.exec(url.pathname);

    if (request.method === "POST" && url.pathname === "/v1/agents") {
      state.registerCalls += 1;
      const name = String(parsed.name);
      if (state.agents.has(name)) {
        sendJson(response, 409, { error: { code: "agent_already_exists", message: "name taken" } });
        return;
      }
      const metadata = parsed.metadata && typeof parsed.metadata === "object" ? parsed.metadata as Record<string, unknown> : {};
      const agent = { id: `ag_${state.registerCalls}`, name, token: `ar_ag_${state.registerCalls}`, metadata };
      state.agents.set(name, agent);
      state.tokenOwner.set(agent.token, name);
      sendJson(response, 201, { data: { id: agent.id, name: agent.name, token: agent.token } });
      return;
    }

    if (request.method === "GET" && url.pathname === "/v1/agent") {
      state.probeCalls += 1;
      if (state.probeDown) {
        response.socket?.destroy();
        return;
      }
      const probeAnswer = state.probeAnswers.shift();
      if (probeAnswer) {
        sendJson(response, probeAnswer.status, probeAnswer.body);
        return;
      }
      const owner = state.tokenOwner.get(token);
      const agent = owner ? state.agents.get(owner) : undefined;
      if (!agent) {
        sendJson(response, 401, { error: { code: "unauthorized", message: "invalid token" } });
        return;
      }
      sendJson(response, 200, { data: { id: agent.id, name: agent.name, type: "human", channels: [] } });
      return;
    }

    if (request.method === "POST" && mint) {
      state.mints.push(parsed);
      const answer = state.mintAnswers.shift();
      if (answer) {
        sendJson(response, answer.status, answer.body);
        return;
      }
      const agent = state.agents.get(decodeURIComponent(mint[1]!));
      if (!agent) {
        sendJson(response, 404, { error: { code: "agent_not_found", message: "Agent not found" } });
        return;
      }
      if (parsed.agent_id !== agent.id) {
        sendJson(response, 409, { error: { code: "agent_identity_conflict", message: "Agent id does not match" } });
        return;
      }
      const asked = parsed.device as Record<string, unknown>;
      if (asked.id === "direct" || asked.id === "unknown") {
        sendJson(response, 400, { error: { code: "invalid_request", message: "Reserved device id" } });
        return;
      }
      const device = { id: asked.id, name: relayCleanName(asked.name), kind: asked.kind };
      const key = `${agent.name}\n${String(device.id)}`;
      const previous = state.deviceTokens.get(key);
      if (previous) state.tokenOwner.delete(previous.token);
      const issued = `${state.deviceTokenPrefix}${state.mints.length}`;
      state.issuedTokens.push(issued);
      state.deviceTokens.set(key, { token: issued, device });
      state.tokenOwner.set(issued, agent.name);
      const expiresAt = state.mintExpiresAt === undefined
        ? new Date(Date.now() + Number(parsed.ttl_seconds) * 1000).toISOString()
        : state.mintExpiresAt;
      sendJson(response, 201, { data: { agent_id: agent.id, device, token: issued, expires_at: expiresAt } });
      return;
    }

    if (request.method === "DELETE" && revoke) {
      const deviceIdValue = decodeURIComponent(revoke[2]!);
      state.deviceDeletes.push(deviceIdValue);
      // Left open; the harness closes every connection at the end of the test.
      if (state.deleteHangs) return;
      if (state.deleteFailures > 0) {
        state.deleteFailures -= 1;
        sendJson(response, 500, { error: { code: "unavailable", message: "try later" } });
        return;
      }
      const key = `${decodeURIComponent(revoke[1]!)}\n${deviceIdValue}`;
      const entry = state.deviceTokens.get(key);
      if (!entry) {
        sendJson(response, 404, { error: { code: "not_found", message: "Device token not found" } });
        return;
      }
      state.tokenOwner.delete(entry.token);
      state.deviceTokens.delete(key);
      sendJson(response, 200, { data: { ok: true } });
      return;
    }

    if (agentPath) {
      const name = decodeURIComponent(agentPath[1]!);
      const agent = state.agents.get(name);
      if (request.method === "GET" && !agentPath[2]) {
        if (!agent) {
          sendJson(response, 404, { error: { code: "agent_not_found", message: "Agent not found" } });
          return;
        }
        sendJson(response, 200, { data: { id: agent.id, name: agent.name, metadata: agent.metadata } });
        return;
      }
      if (request.method === "POST" && agentPath[2] === "/takeover") {
        state.takeoverCalls += 1;
        if (!agent || agent.id !== parsed.expected_agent_id) {
          sendJson(response, 409, { error: { code: "agent_identity_conflict", message: "conflict" } });
          return;
        }
        state.tokenOwner.delete(agent.token);
        dropDeviceTokens(state, agent.name);
        agent.token = `ar_ag_takeover_${state.takeoverCalls}`;
        state.tokenOwner.set(agent.token, agent.name);
        sendJson(response, 200, { data: { agent_id: agent.id, name: agent.name, token: agent.token } });
        return;
      }
      if (request.method === "POST" && agentPath[2] === "/revoke-token") {
        if (agent) state.tokenOwner.delete(agent.token);
        sendJson(response, agent ? 200 : 404, agent ? { data: { ok: true } } : { error: { code: "agent_not_found", message: "Agent not found" } });
        return;
      }
      if (request.method === "DELETE" && !agentPath[2]) {
        if (agent) {
          state.tokenOwner.delete(agent.token);
          dropDeviceTokens(state, agent.name);
          state.agents.delete(name);
        }
        sendJson(response, 200, { data: { ok: true } });
        return;
      }
    }

    sendJson(response, 404, ROUTE_NOT_FOUND);
  });
}

async function jsonRequest(
  baseUrl: string,
  path: string,
  options: { method?: string; token?: string; cookie?: string; body?: unknown; rawBody?: string } = {},
): Promise<{ status: number; body: Record<string, any>; headers: Headers }> {
  const headers: Record<string, string> = {};
  const method = options.method ?? "GET";
  if (options.token) headers.authorization = `Bearer ${options.token}`;
  if (options.cookie) headers.cookie = options.cookie;
  if (options.cookie && method !== "GET") headers.origin = "https://control.internal.example";
  const payload = options.rawBody ?? (options.body !== undefined ? JSON.stringify(options.body) : undefined);
  // Cookie writes must declare JSON (the CSRF guard), with or without a body.
  const cookieWrite = Boolean(options.cookie) && method !== "GET";
  if (payload !== undefined || cookieWrite) headers["content-type"] = "application/json";
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers,
    ...(payload !== undefined ? { body: payload } : {}),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) as Record<string, any> : {}, headers: response.headers };
}

type Hooks = {
  beforeDeviceSave?: (tx: SqlExecutor) => Promise<void> | void;
  afterDeviceMint?: (tx: SqlExecutor) => Promise<void> | void;
};
type SignIn = { accessToken: string; refreshToken: string; sessionId: string };

async function harness(
  t: { after: (fn: () => Promise<void>) => void },
  options?: { config?: Partial<SelfhostConfig>; signOutRevokeTimeoutMs?: number },
) {
  const state = relayState();
  const hooks: Hooks = {};
  const warnings: Array<{ message: string; fields: Record<string, string> }> = [];
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
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.selfhosted.example",
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: "https://history.selfhosted.example", secret: "session-read-secret-".repeat(2) },
    bootstrapToken: "bootstrap-token-that-is-at-least-32-bytes",
    encryptionKeyring: { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    internalServiceToken: "service-token-that-is-at-least-32-bytes",
    oauthRedirectUrl: "https://control.internal.example/api/v1/integrations/oauth/callback",
    dashboardUrl: "https://control.internal.example/",
    port: 3000,
    host: "127.0.0.1",
    ...options?.config,
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  control = createServer(createApp({
    config,
    store,
    messaging: {
      beforeDeviceSave: (tx) => hooks.beforeDeviceSave?.(tx),
      afterDeviceMint: (tx) => hooks.afterDeviceMint?.(tx),
      ...(options?.signOutRevokeTimeoutMs !== undefined ? { signOutRevokeTimeoutMs: options.signOutRevokeTimeoutMs } : {}),
      warn: (message, fields) => { warnings.push({ message, fields }); },
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
  const workspaceId = workspace.body.id as string;
  const userId = org.body.owner.id as string;

  async function signIn(forUser = userId): Promise<SignIn> {
    const started = await jsonRequest(origin, "/api/v1/auth/device/start", {
      method: "POST",
      body: { client_name: "device-credential-test" },
    });
    assert.equal(started.status, 201);
    const approved = await jsonRequest(origin, "/api/v1/auth/device/approve", {
      method: "POST",
      token: config.bootstrapToken,
      body: { action: "approve", user_code: started.body.user_code, user_id: forUser, workspace_id: workspaceId },
    });
    assert.equal(approved.status, 200);
    const issued = await jsonRequest(origin, "/api/v1/auth/device/token", {
      method: "POST",
      body: { device_code: started.body.device_code },
    });
    assert.equal(issued.status, 200);
    const accessToken = issued.body.access_token as string;
    return {
      accessToken,
      refreshToken: issued.body.refresh_token as string,
      sessionId: await sessionOf(accessToken),
    };
  }

  async function sessionOf(accessToken: string): Promise<string> {
    const found = await database.query<{ id: string }>(
      "SELECT id FROM token_sessions WHERE access_token_hash = $1",
      [hashSecret(accessToken)],
    );
    assert.equal(found.rows.length, 1);
    return found.rows[0]!.id;
  }

  function credential(auth: { token: string } | { cookie: string }, body?: { json: unknown } | { raw: string }) {
    const cloud = "cookie" in auth;
    return jsonRequest(
      origin,
      `${cloud ? "/cloud" : ""}/api/v1/workspaces/${workspaceId}/messaging/identity/credential`,
      {
        method: "POST",
        ...auth,
        ...(body && "json" in body ? { body: body.json } : {}),
        ...(body && "raw" in body ? { rawBody: body.raw } : {}),
      },
    );
  }

  async function deviceRows() {
    return (await database.query<{
      device_id: string;
      device_name: string;
      device_kind: string;
      session_id: string | null;
      agent_remote_id: string;
      token_ciphertext: string;
      expired: boolean;
      revoked: boolean;
      upstream_revoked: boolean;
    }>(
      `SELECT device_id, device_name, device_kind, session_id, agent_remote_id, token_ciphertext,
              expires_at <= now() AS expired, revoked_at IS NOT NULL AS revoked,
              upstream_revoked_at IS NOT NULL AS upstream_revoked
         FROM person_device_credentials ORDER BY created_at`,
    )).rows;
  }

  return {
    state, hooks, warnings, origin, config, database, store, workspaceId, userId,
    orgId: org.body.id as string, signIn, sessionOf, credential, deviceRows,
  };
}

/** Whether Relaycast still accepts `token` as its agent. */
async function relayAccepts(relaycastUrl: string, token: string): Promise<boolean> {
  const response = await fetch(`${relaycastUrl}/v1/agent`, { headers: { authorization: `Bearer ${token}` } });
  await response.text();
  return response.status === 200;
}

test("a browser session gets the web device and each bearer sign-in its own device token for one agent", async (t) => {
  const fx = await harness(t);
  const first = await fx.signIn();
  const second = await fx.signIn();

  const web = await fx.credential({ cookie: `agent_relay_session=${first.accessToken}` });
  assert.equal(web.status, 200);
  assert.deepEqual(web.body.identity.device, { id: "web", name: "web", kind: "web" });

  const one = await fx.credential({ token: first.accessToken });
  const two = await fx.credential({ token: second.accessToken });
  assert.equal(one.status, 200);
  assert.equal(two.status, 200);
  assert.equal(one.body.identity.device.kind, "cli");
  assert.equal(one.body.identity.device.id, deviceId("cli", "cli", first.sessionId));
  assert.equal(two.body.identity.device.id, deviceId("cli", "cli", second.sessionId));
  assert.notEqual(one.body.identity.device.id, two.body.identity.device.id);
  assert.notEqual(one.body.identity.token, two.body.identity.token);
  assert.notEqual(one.body.identity.token, web.body.identity.token);
  // One person agent behind all three devices; no device gets the shared agent token.
  assert.equal(fx.state.registerCalls, 1);
  for (const answer of [web, one, two]) {
    assert.equal(answer.body.identity.agentId, "ag_1");
    assert.equal(answer.body.identity.name, one.body.identity.name);
    assert.notEqual(answer.body.identity.token, "ar_ag_1");
    assert.equal(answer.body.identity.relaycastUrl, "https://cast.selfhosted.example");
    assert.equal(typeof answer.body.identity.expiresAt, "string");
  }
  // Every mint names the agent, the device and the TTL.
  assert.equal(fx.state.mints.length, 3);
  for (const body of fx.state.mints) {
    assert.equal(body.agent_id, "ag_1");
    assert.equal(body.ttl_seconds, DEVICE_TOKEN_TTL_SECONDS);
  }
  assert.deepEqual(fx.state.mints[1]!.device, one.body.identity.device);

  const rows = await fx.deviceRows();
  assert.equal(rows.length, 3);
  assert.deepEqual(rows.map((row) => row.session_id), [null, first.sessionId, second.sessionId]);
  for (const row of rows) assert.equal(mentionsIssuedToken(fx.state, row.token_ciphertext), false);
});

test("a stored device token is reused until the renew margin, and a refresh keeps the device", async (t) => {
  const fx = await harness(t);
  const signIn = await fx.signIn();
  const minted = await fx.credential({ token: signIn.accessToken });
  assert.equal(minted.status, 200);
  const again = await fx.credential({ token: signIn.accessToken });
  assert.equal(again.body.identity.token, minted.body.identity.token);
  assert.equal(again.body.identity.expiresAt, minted.body.identity.expiresAt);
  assert.equal(fx.state.mints.length, 1);
  // The stored token is probed on every serve; nothing is cached.
  assert.equal(fx.state.probeCalls, 1);
  assert.equal((await fx.credential({ token: signIn.accessToken })).status, 200);
  assert.equal(fx.state.probeCalls, 2);

  const refreshed = await jsonRequest(fx.origin, "/api/v1/auth/token/refresh", {
    method: "POST",
    body: { refreshToken: signIn.refreshToken },
  });
  assert.equal(refreshed.status, 200);
  assert.equal(await fx.sessionOf(refreshed.body.accessToken as string), signIn.sessionId);
  const afterRefresh = await fx.credential({ token: refreshed.body.accessToken as string });
  assert.equal(afterRefresh.status, 200);
  assert.equal(afterRefresh.body.identity.device.id, minted.body.identity.device.id);
  assert.equal(afterRefresh.body.identity.token, minted.body.identity.token);
  assert.equal(fx.state.mints.length, 1);

  await fx.database.query("UPDATE person_device_credentials SET expires_at = now() + interval '30 minutes'");
  const renewed = await fx.credential({ token: refreshed.body.accessToken as string });
  assert.equal(renewed.status, 200);
  assert.equal(fx.state.mints.length, 2);
  assert.notEqual(renewed.body.identity.token, minted.body.identity.token);
  assert.equal(renewed.body.identity.device.id, minted.body.identity.device.id);
  assert.equal((await fx.deviceRows()).length, 1);
});

test("the device comes from the session row, a client-sent device is ignored, and the name Relaycast returns is served", async (t) => {
  const fx = await harness(t);
  const signIn = await fx.signIn();
  // Relaycast collapses the runs of spaces that Control's own cleaning keeps.
  const hostName = "Ada's   MacBook  Pro";
  await fx.database.query("UPDATE token_sessions SET desktop_host_name = $2 WHERE id = $1", [signIn.sessionId, hostName]);
  const answer = await fx.credential({ token: signIn.accessToken }, {
    json: { device: { id: "unknown", name: "Evil", kind: "web" }, name: "Evil", deviceId: "direct" },
  });
  assert.equal(answer.status, 200);
  const expected = { id: deviceId(hostName, "desktop", signIn.sessionId), name: "Ada's MacBook Pro", kind: "desktop" };
  assert.deepEqual(answer.body.identity.device, expected);
  assert.match(answer.body.identity.device.id as string, /^ada-s-macbook-pro-[0-9a-f]{8}$/);
  // The mint asked for the session's device, not the body's.
  assert.equal(fx.state.mints.length, 1);
  assert.deepEqual(fx.state.mints[0]!.device, { ...expected, name: hostName });
  const [row] = await fx.deviceRows();
  assert.equal(row!.device_name, "Ada's MacBook Pro");
  assert.equal(row!.device_kind, "desktop");
  // A stored token is served with the stored, returned name.
  const again = await fx.credential({ token: signIn.accessToken });
  assert.equal(again.status, 200);
  assert.equal(fx.state.mints.length, 1);
  assert.deepEqual(again.body.identity.device, expected);
});

test("device names are cut on a grapheme boundary and stripped of control and bidi characters", () => {
  assert.equal(deviceName("a".repeat(79) + "\u{1F44D}", "desktop"), "a".repeat(79));
  const accented = "é".repeat(41);
  const cutAccents = deviceName(accented, "desktop");
  assert.equal(cutAccents.length, 80);
  assert.equal(cutAccents, "é".repeat(40));
  const family = "\u{1F468}\u200D\u{1F469}\u200D\u{1F467}\u200D\u{1F466}";
  assert.equal(family.length, 11);
  assert.equal(deviceName(family.repeat(8), "desktop"), family.repeat(7));
  assert.equal(deviceName("Ada\u0000\u202E Box\u2066", "desktop"), "Ada Box");
  assert.equal(deviceName("  \u0007 ", "desktop"), "desktop");
  assert.equal(deviceName(null, "cli"), "cli");
  for (const name of [deviceName(family.repeat(8), "desktop"), cutAccents]) {
    assert.equal(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(name), false);
  }
});

test("device ids follow Relaycast's rule and never take a reserved id", () => {
  for (const id of ["web", "cli-0a1b2c3d", "a".repeat(64)]) assert.equal(isValidDeviceId(id), true, id);
  for (const id of ["unknown", "direct", "", "A", "a_b", "a b", "a".repeat(65)]) assert.equal(isValidDeviceId(id), false, id);
  for (const name of ["unknown", "direct", "Unknown", "DIRECT"]) {
    const id = deviceId(name, "cli", "session-1");
    assert.equal(isValidDeviceId(id), true, id);
    assert.notEqual(id, "unknown");
    assert.notEqual(id, "direct");
  }
  assert.match(deviceId("\u{1F600}\u{1F600}", "desktop", "session-1"), /^desktop-[0-9a-f]{8}$/);
  assert.equal(deviceId("x".repeat(200), "cli", "session-1").length <= 64, true);
  assert.notEqual(deviceId("host", "desktop", "session-1"), deviceId("host", "desktop", "session-2"));
});

test("the stored expiry is the earlier of Relaycast's and the TTL asked for", async (t) => {
  const now = new Date("2026-11-19T12:00:00.000Z");
  const asked = new Date(now.getTime() + DEVICE_TOKEN_TTL_SECONDS * 1000);
  assert.equal(deviceTokenExpiry("2026-11-19T14:00:00.000Z", now).toISOString(), "2026-11-19T14:00:00.000Z");
  assert.equal(deviceTokenExpiry("2026-12-19T12:00:00.000Z", now).toISOString(), asked.toISOString());
  assert.equal(deviceTokenExpiry(null, now).toISOString(), asked.toISOString());
  assert.equal(deviceTokenExpiry("not a date", now).toISOString(), asked.toISOString());

  const fx = await harness(t);
  const signIn = await fx.signIn();
  const early = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString();
  fx.state.mintExpiresAt = early;
  const shortLived = await fx.credential({ token: signIn.accessToken });
  assert.equal(shortLived.status, 200);
  assert.equal(shortLived.body.identity.expiresAt, early);

  const other = await fx.signIn();
  fx.state.mintExpiresAt = null;
  const before = Date.now();
  const unreported = await fx.credential({ token: other.accessToken });
  assert.equal(unreported.status, 200);
  const expiresAt = Date.parse(unreported.body.identity.expiresAt as string);
  assert.equal(expiresAt >= before + DEVICE_TOKEN_TTL_SECONDS * 1000, true);
  assert.equal(expiresAt <= Date.now() + DEVICE_TOKEN_TTL_SECONDS * 1000, true);
});

test("a refused stored token is re-minted and an unreachable probe serves the unexpired stored token", async (t) => {
  const fx = await harness(t);
  const signIn = await fx.signIn();
  const minted = await fx.credential({ token: signIn.accessToken });
  assert.equal(minted.status, 200);

  fx.state.probeDown = true;
  const served = await fx.credential({ token: signIn.accessToken });
  assert.equal(served.status, 200);
  assert.equal(served.body.identity.token, minted.body.identity.token);
  assert.equal(fx.state.mints.length, 1);
  fx.state.probeDown = false;

  fx.state.tokenOwner.delete(minted.body.identity.token as string);
  const reminted = await fx.credential({ token: signIn.accessToken });
  assert.equal(reminted.status, 200);
  assert.equal(fx.state.mints.length, 2);
  assert.notEqual(reminted.body.identity.token, minted.body.identity.token);
  assert.equal(await relayAccepts(fx.config.relaycastUrl, reminted.body.identity.token as string), true);
});

function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

test("a reported refused token that matches the stored one is re-minted without a probe", async (t) => {
  const fx = await harness(t);
  // The other upstream token shape; nothing in Control reads the prefix.
  fx.state.deviceTokenPrefix = "ar_ad_";
  const signIn = await fx.signIn();
  const minted = await fx.credential({ token: signIn.accessToken });
  assert.equal(minted.status, 200);
  assert.match(minted.body.identity.token as string, /^ar_ad_/);
  // Outside the 30 second window of the first mint.
  await fx.database.query("UPDATE person_device_credentials SET minted_at = now() - interval '1 minute'");
  const probes = fx.state.probeCalls;

  const reminted = await fx.credential({ token: signIn.accessToken }, {
    json: { refusedTokenSha256: sha256Hex(minted.body.identity.token as string) },
  });
  assert.equal(reminted.status, 200);
  assert.equal(fx.state.mints.length, 2);
  assert.equal(fx.state.probeCalls, probes);
  assert.notEqual(reminted.body.identity.token, minted.body.identity.token);
  assert.equal(reminted.body.identity.device.id, minted.body.identity.device.id);
  assert.equal(await relayAccepts(fx.config.relaycastUrl, reminted.body.identity.token as string), true);
  assert.equal(await relayAccepts(fx.config.relaycastUrl, minted.body.identity.token as string), false);
  assert.equal((await fx.deviceRows()).length, 1);
});

test("a second reported refusal of a device token within 30 seconds of its mint gets 429 with Retry-After", async (t) => {
  const fx = await harness(t);
  const signIn = await fx.signIn();
  const minted = await fx.credential({ token: signIn.accessToken });
  assert.equal(minted.status, 200);

  const limited = await fx.credential({ token: signIn.accessToken }, {
    json: { refusedTokenSha256: sha256Hex(minted.body.identity.token as string) },
  });
  assert.equal(limited.status, 429);
  assert.equal(limited.body.error, "rate_limited");
  const retryAfter = Number(limited.headers.get("retry-after"));
  assert.equal(Number.isInteger(retryAfter) && retryAfter >= 1 && retryAfter <= 30, true, String(retryAfter));
  assert.equal(mentionsIssuedToken(fx.state, limited.body), false);
  assert.equal(fx.state.mints.length, 1);

  // Once the window has passed the report re-mints; reporting the new token at once is limited again.
  await fx.database.query("UPDATE person_device_credentials SET minted_at = now() - interval '31 seconds'");
  const reminted = await fx.credential({ token: signIn.accessToken }, {
    json: { refusedTokenSha256: sha256Hex(minted.body.identity.token as string) },
  });
  assert.equal(reminted.status, 200);
  assert.equal(fx.state.mints.length, 2);
  const again = await fx.credential({ token: signIn.accessToken }, {
    json: { refusedTokenSha256: sha256Hex(reminted.body.identity.token as string) },
  });
  assert.equal(again.status, 429);
  assert.equal(fx.state.mints.length, 2);

  // The window is per device: another sign-in of the same person is not limited.
  const other = await fx.signIn();
  const otherMinted = await fx.credential({ token: other.accessToken });
  assert.equal(otherMinted.status, 200);
  assert.equal(fx.state.mints.length, 3);
});

test("a reported refused token that does not match the stored one takes the normal path", async (t) => {
  const fx = await harness(t);
  const signIn = await fx.signIn();
  const minted = await fx.credential({ token: signIn.accessToken });
  assert.equal(minted.status, 200);
  const probes = fx.state.probeCalls;

  const served = await fx.credential({ token: signIn.accessToken }, { json: { refusedTokenSha256: sha256Hex("at_live_dv_stale") } });
  assert.equal(served.status, 200);
  assert.equal(served.body.identity.token, minted.body.identity.token);
  assert.equal(fx.state.mints.length, 1);
  assert.equal(fx.state.probeCalls, probes + 1);

  // A stored token Relaycast refuses is still dropped by the probe, without the 30 second limit.
  fx.state.tokenOwner.delete(minted.body.identity.token as string);
  const reminted = await fx.credential({ token: signIn.accessToken }, { json: { refusedTokenSha256: sha256Hex("at_live_dv_stale") } });
  assert.equal(reminted.status, 200);
  assert.equal(fx.state.mints.length, 2);
  assert.notEqual(reminted.body.identity.token, minted.body.identity.token);
});

test("a malformed credential request body is refused with 400 before anything is registered or minted", async (t) => {
  const fx = await harness(t);
  const signIn = await fx.signIn();
  const hash = sha256Hex("at_live_dv_1");
  for (const raw of [
    "not json",
    "[]",
    "null",
    "\"text\"",
    "42",
    JSON.stringify({ refusedTokenSha256: hash.toUpperCase() }),
    JSON.stringify({ refusedTokenSha256: hash.slice(1) }),
    JSON.stringify({ refusedTokenSha256: `${hash}0` }),
    JSON.stringify({ refusedTokenSha256: "" }),
    JSON.stringify({ refusedTokenSha256: 42 }),
    JSON.stringify({ refusedTokenSha256: [hash] }),
  ]) {
    const refused = await fx.credential({ token: signIn.accessToken }, { raw });
    assert.equal(refused.status, 400, raw);
    assert.equal(refused.body.error, "invalid_request", raw);
  }
  assert.equal(fx.state.registerCalls, 0);
  assert.equal(fx.state.mints.length, 0);
  assert.equal((await fx.deviceRows()).length, 0);
});

test("no body, an empty object, a null report or unknown keys leave the credential request unchanged", async (t) => {
  const fx = await harness(t);
  const signIn = await fx.signIn();
  const minted = await fx.credential({ token: signIn.accessToken });
  assert.equal(minted.status, 200);
  const bodies = [
    { raw: "" },
    { raw: "  \n" },
    { json: {} },
    { json: { refusedTokenSha256: null } },
    { json: { refused: true, client: "test" } },
  ];
  for (const body of bodies) {
    const served = await fx.credential({ token: signIn.accessToken }, body);
    assert.equal(served.status, 200, JSON.stringify(body));
    assert.equal(served.body.identity.token, minted.body.identity.token);
  }
  assert.equal(fx.state.mints.length, 1);
  assert.equal(fx.state.probeCalls, bodies.length);
});

test("a device revoked while its sign-in still authenticates answers 403 device_revoked", async (t) => {
  const fx = await harness(t);
  const signIn = await fx.signIn();
  const minted = await fx.credential({ token: signIn.accessToken });
  assert.equal(minted.status, 200);
  await fx.database.query("UPDATE person_device_credentials SET revoked_at = now() WHERE session_id = $1", [signIn.sessionId]);

  const revoked = await fx.credential({ token: signIn.accessToken });
  assert.equal(revoked.status, 403);
  assert.equal(revoked.body.error, "device_revoked");
  const reported = await fx.credential({ token: signIn.accessToken }, {
    json: { refusedTokenSha256: sha256Hex(minted.body.identity.token as string) },
  });
  assert.equal(reported.status, 403);
  assert.equal(reported.body.error, "device_revoked");
  assert.equal(mentionsIssuedToken(fx.state, [revoked.body, reported.body]), false);
  assert.equal(fx.state.mints.length, 1);

  // The web device is bound to no sign-in: a revoked web row is minted again for the browser session.
  const web = await fx.credential({ cookie: `agent_relay_session=${signIn.accessToken}` });
  assert.equal(web.status, 200);
  await fx.database.query("UPDATE person_device_credentials SET revoked_at = now() WHERE device_id = 'web'");
  const webAgain = await fx.credential({ cookie: `agent_relay_session=${signIn.accessToken}` });
  assert.equal(webAgain.status, 200);
  assert.notEqual(webAgain.body.identity.token, web.body.identity.token);
});

test("a probe answered device_token_forbidden is an upstream error, never a re-mint", async (t) => {
  const fx = await harness(t);
  const signIn = await fx.signIn();
  const minted = await fx.credential({ token: signIn.accessToken });
  assert.equal(minted.status, 200);
  fx.state.probeAnswers.push({
    status: 403,
    body: { error: { code: "device_token_forbidden", message: "Device tokens cannot use this route" } },
  });
  const failed = await fx.credential({ token: signIn.accessToken });
  assert.equal(failed.status, 502);
  assert.equal(failed.body.error, "upstream_unavailable");
  assert.equal(fx.state.mints.length, 1);
  const [row] = await fx.deviceRows();
  assert.equal(row!.revoked, false);
});

test("Desktop handoff tokens never hold a messaging credential", async (t) => {
  const fx = await harness(t);
  const handoff = await fx.store.issueDesktopHandoff({
    userId: fx.userId,
    organizationId: fx.orgId,
    workspaceId: fx.workspaceId,
    codeChallenge: "c".repeat(43),
    consentedHostName: "Studio",
  });
  const pending = await fx.credential({ token: handoff.accessToken });
  assert.equal(pending.status, 403);
  assert.equal(pending.body.error, "handoff_not_exchanged");

  const exchanged = await fx.store.exchangeDesktopHandoff(handoff.accessToken, () => true);
  assert(exchanged);
  const spent = await fx.credential({ token: handoff.accessToken });
  assert.equal(spent.status, 403);
  assert.equal(spent.body.error, "handoff_not_capable");
  assert.equal(fx.state.mints.length, 0);
  assert.equal(JSON.stringify([pending.body, spent.body]).includes("ar_ag_"), false);

  const session = await fx.credential({ token: exchanged.accessToken });
  assert.equal(session.status, 200);
  assert.equal(session.body.identity.device.kind, "desktop");
  assert.equal(session.body.identity.device.name, "Studio");
  assert.equal(session.body.identity.device.id, deviceId("Studio", "desktop", exchanged.sessionId));
});

test("the shared-token fallback needs Relaycast's exact missing-route answer and the expected agent", async () => {
  const routeMissing = JSON.stringify(ROUTE_NOT_FOUND);
  const agent = async () => ({ id: "ag_1" });
  assert.equal(await isMissingDeviceTokenRoute(new RelaycastCallError(404, routeMissing), agent, "ag_1"), true);
  assert.equal(
    await isMissingDeviceTokenRoute(
      new RelaycastCallError(404, JSON.stringify({ error: "not_found", message: "Route not found" })),
      agent,
      "ag_1",
    ),
    true,
  );
  const refused: Array<[string, unknown, () => Promise<{ id: string } | null>]> = [
    ["other message", new RelaycastCallError(404, JSON.stringify({ error: { code: "not_found", message: "Agent not found" } })), agent],
    ["other code", new RelaycastCallError(404, JSON.stringify({ error: { code: "agent_not_found", message: "Route not found" } })), agent],
    ["no body", new RelaycastCallError(404, ""), agent],
    ["not JSON", new RelaycastCallError(404, "Route not found"), agent],
    ["405", new RelaycastCallError(405, routeMissing), agent],
    ["500", new RelaycastCallError(500, routeMissing, true), agent],
    ["transport", new RelaycastCallError(0, "", true), agent],
    ["agent missing", new RelaycastCallError(404, routeMissing), async () => null],
    ["agent replaced", new RelaycastCallError(404, routeMissing), async () => ({ id: "ag_2" })],
    ["lookup failed", new RelaycastCallError(404, routeMissing), async () => { throw new RelaycastCallError(0, "", true); }],
    ["not a Relaycast answer", new Error("Route not found"), agent],
  ];
  for (const [label, error, findAgent] of refused) {
    assert.equal(await isMissingDeviceTokenRoute(error, findAgent, "ag_1"), false, label);
  }
});

test("a Relaycast without device tokens serves the shared token and logs the fallback", async (t) => {
  const fx = await harness(t);
  const signIn = await fx.signIn();
  fx.state.mintAnswers.push({ status: 404, body: ROUTE_NOT_FOUND });
  // A reported refused-token hash plays no part in the fallback.
  const shared = await fx.credential({ token: signIn.accessToken }, { json: { refusedTokenSha256: sha256Hex("ar_ag_1") } });
  assert.equal(shared.status, 200);
  assert.equal(shared.body.identity.token, "ar_ag_1");
  assert.equal(shared.body.identity.agentId, "ag_1");
  assert.equal("device" in shared.body.identity, false);
  assert.equal("expiresAt" in shared.body.identity, false);
  assert.equal(fx.warnings.length, 1);
  assert.match(fx.warnings[0]!.message, /device credential fallback/);
  assert.deepEqual(fx.warnings[0]!.fields, { workspaceId: fx.workspaceId, deviceKind: "cli" });
  assert.equal(JSON.stringify(fx.warnings).includes("ar_ag_"), false);
  assert.equal((await fx.deviceRows()).length, 0);

  // Any other refusal of the mint is an upstream failure, never the shared token.
  for (const answer of [
    { status: 404, body: { error: { code: "not_found", message: "Not here" } } },
    { status: 405, body: ROUTE_NOT_FOUND },
    { status: 500, body: { error: { code: "internal", message: "boom" } } },
    { status: 400, body: { error: { code: "invalid_request", message: "bad device" } } },
    { status: 409, body: { error: { code: "not_a_person_agent", message: "not a person" } } },
  ]) {
    fx.state.mintAnswers.push(answer);
    const failed = await fx.credential({ token: signIn.accessToken });
    assert.equal(failed.status, 502, JSON.stringify(answer));
    assert.equal(failed.body.error, "upstream_unavailable");
    assert.equal(JSON.stringify(failed.body).includes("ar_ag_"), false);
  }
  assert.equal(fx.warnings.length, 1);
});

test("a mint answer naming another agent is refused", async (t) => {
  const fx = await harness(t);
  const signIn = await fx.signIn();
  fx.state.mintAnswers.push({
    status: 201,
    body: { data: { agent_id: "ag_other", device: {}, token: "at_live_dv_foreign", expires_at: null } },
  });
  const refused = await fx.credential({ token: signIn.accessToken });
  assert.equal(refused.status, 502);
  assert.equal(refused.body.error, "upstream_unavailable");
  assert.equal(JSON.stringify(refused.body).includes("at_live_dv_foreign"), false);
  assert.equal((await fx.deviceRows()).length, 0);
});

test("a mint answer naming another device id or kind is refused", async (t) => {
  const fx = await harness(t);
  const signIn = await fx.signIn();
  const asked = { id: deviceId("cli", "cli", signIn.sessionId), name: "cli", kind: "cli" };
  for (const device of [{ ...asked, id: "other-device" }, { ...asked, kind: "desktop" }, { name: "cli" }]) {
    fx.state.mintAnswers.push({
      status: 201,
      body: { data: { agent_id: "ag_1", device, token: "ar_ad_foreign", expires_at: null } },
    });
    const refused = await fx.credential({ token: signIn.accessToken });
    assert.equal(refused.status, 502, JSON.stringify(device));
    assert.equal(refused.body.error, "upstream_unavailable");
    assert.equal(JSON.stringify(refused.body).includes("ar_ad_foreign"), false);
  }
  assert.equal((await fx.deviceRows()).length, 0);
});

test("an identity refusal of the mint recovers the person agent once and expires stored device tokens", async (t) => {
  for (const refusal of [
    { status: 409, body: { error: { code: "agent_identity_conflict", message: "conflict" } } },
    { status: 404, body: { error: { code: "agent_not_found", message: "Agent not found" } } },
  ]) {
    const fx = await harness(t);
    const first = await fx.signIn();
    const second = await fx.signIn();
    const stored = await fx.credential({ token: first.accessToken });
    assert.equal(stored.status, 200);

    fx.state.mintAnswers.push(refusal);
    const recovered = await fx.credential({ token: second.accessToken });
    assert.equal(recovered.status, 200, refusal.body.error.code);
    assert.equal(fx.state.takeoverCalls, 1);
    assert.equal(fx.state.mints.length, 3);
    assert.equal(recovered.body.identity.agentId, "ag_1");
    // The takeover ended every device token of the agent; the stored one is expired, not served.
    const firstRow = (await fx.deviceRows()).find((row) => row.session_id === first.sessionId);
    assert.equal(firstRow!.expired, true);
    const reminted = await fx.credential({ token: first.accessToken });
    assert.equal(reminted.status, 200);
    assert.notEqual(reminted.body.identity.token, stored.body.identity.token);
    assert.equal(fx.state.mints.length, 4);

    // A second refusal after the one recovery is an upstream failure.
    const third = await fx.signIn();
    fx.state.mintAnswers.push(refusal, refusal);
    const failed = await fx.credential({ token: third.accessToken });
    assert.equal(failed.status, 502);
    assert.equal(fx.state.takeoverCalls, 2);
  }
});

test("ending a sign-in revokes its device token, retried by the sweep after an upstream failure", async (t) => {
  const fx = await harness(t);
  const ended = await fx.signIn();
  const other = await fx.signIn();
  const minted = await fx.credential({ token: ended.accessToken });
  assert.equal(minted.status, 200);
  const kept = await fx.credential({ token: other.accessToken });
  assert.equal(kept.status, 200);

  fx.state.deleteFailures = 1;
  const signOut = await jsonRequest(fx.origin, "/api/v1/auth/token/revoke", {
    method: "POST",
    body: { token: ended.accessToken },
  });
  assert.equal(signOut.status, 200);
  assert.deepEqual(fx.state.deviceDeletes, [minted.body.identity.device.id]);
  let row = (await fx.deviceRows()).find((candidate) => candidate.session_id === ended.sessionId)!;
  assert.equal(row.revoked, true);
  assert.equal(row.upstream_revoked, false);
  assert.equal(await relayAccepts(fx.config.relaycastUrl, minted.body.identity.token as string), true);

  const people = await jsonRequest(fx.origin, `/api/v1/workspaces/${fx.workspaceId}/messaging/people`, { token: other.accessToken });
  assert.equal(people.status, 200);
  assert.deepEqual(fx.state.deviceDeletes, [minted.body.identity.device.id, minted.body.identity.device.id]);
  row = (await fx.deviceRows()).find((candidate) => candidate.session_id === ended.sessionId)!;
  assert.equal(row.upstream_revoked, true);
  assert.equal(await relayAccepts(fx.config.relaycastUrl, minted.body.identity.token as string), false);

  // The other sign-in's device is untouched.
  const live = (await fx.deviceRows()).find((candidate) => candidate.session_id === other.sessionId)!;
  assert.equal(live.revoked, false);
  assert.equal(await relayAccepts(fx.config.relaycastUrl, kept.body.identity.token as string), true);
  assert.equal(fx.state.deviceDeletes.length, 2);
});

test("a sign-in that ends while its device token is minted gets 401 and the token is revoked upstream", async (t) => {
  const fx = await harness(t);
  const signIn = await fx.signIn();
  fx.hooks.afterDeviceMint = async (tx) => {
    fx.hooks.afterDeviceMint = undefined;
    // The token is saved before the session is checked.
    const saved = await tx.query("SELECT 1 FROM person_device_credentials WHERE session_id = $1 AND revoked_at IS NULL", [signIn.sessionId]);
    assert.equal(saved.rows.length, 1);
    await tx.query("UPDATE token_sessions SET revoked_at = now() WHERE id = $1", [signIn.sessionId]);
  };
  const refused = await fx.credential({ token: signIn.accessToken });
  assert.equal(refused.status, 401);
  assert.equal(refused.body.error, "unauthorized");
  assert.equal(mentionsIssuedToken(fx.state, refused.body), false);
  assert.equal(fx.state.mints.length, 1);
  assert.equal(fx.state.deviceDeletes.length, 1);
  assert.equal(await relayAccepts(fx.config.relaycastUrl, fx.state.issuedTokens[0]!), false);
  const [row] = await fx.deviceRows();
  assert.equal(row!.revoked, true);
  assert.equal(row!.upstream_revoked, true);
});

test("a sign-in row deleted while its device token is minted gets 401 and the token is recorded revoked and revoked upstream", async (t) => {
  const fx = await harness(t);
  const signIn = await fx.signIn();
  // PGlite runs a transaction on its only connection, so the delete that
  // would come from another connection runs on the mint's transaction,
  // after the mint and before the session row is locked.
  fx.hooks.beforeDeviceSave = async (tx) => {
    fx.hooks.beforeDeviceSave = undefined;
    await tx.query("DELETE FROM token_sessions WHERE id = $1", [signIn.sessionId]);
  };
  const refused = await fx.credential({ token: signIn.accessToken });
  assert.equal(refused.status, 401);
  assert.equal(refused.body.error, "unauthorized");
  assert.equal(mentionsIssuedToken(fx.state, refused.body), false);
  assert.equal(fx.state.mints.length, 1);
  assert.equal(fx.state.deviceDeletes.length, 1);
  assert.equal(await relayAccepts(fx.config.relaycastUrl, fx.state.issuedTokens[0]!), false);
  const rows = await fx.deviceRows();
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.session_id, null);
  assert.equal(rows[0]!.revoked, true);
  assert.equal(rows[0]!.upstream_revoked, true);
});

test("a membership that ends while a bearer device token is minted gets 401, since its sign-in goes with it, and the token is revoked upstream", async (t) => {
  const fx = await harness(t);
  const signIn = await fx.signIn();
  fx.hooks.afterDeviceMint = async (tx) => {
    fx.hooks.afterDeviceMint = undefined;
    // The token is saved before the session and membership are checked.
    const saved = await tx.query("SELECT 1 FROM person_device_credentials WHERE session_id = $1 AND revoked_at IS NULL", [signIn.sessionId]);
    assert.equal(saved.rows.length, 1);
    // Removing the membership deletes the person's sign-ins and, with them, the saved row.
    await tx.query("DELETE FROM organization_memberships WHERE user_id = $1", [fx.userId]);
  };
  const refused = await fx.credential({ token: signIn.accessToken });
  assert.equal(refused.status, 401);
  assert.equal(refused.body.error, "unauthorized");
  assert.equal(mentionsIssuedToken(fx.state, refused.body), false);
  assert.equal(fx.state.deviceDeletes.length, 1);
  assert.equal(await relayAccepts(fx.config.relaycastUrl, fx.state.issuedTokens[0]!), false);
  const rows = await fx.deviceRows();
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.session_id, null);
  assert.equal(rows[0]!.revoked, true);
  assert.equal(rows[0]!.upstream_revoked, true);
});

test("a membership that ends while the web device token is minted gets 403 and the token is revoked upstream", async (t) => {
  const fx = await harness(t);
  const signIn = await fx.signIn();
  fx.hooks.afterDeviceMint = async (tx) => {
    fx.hooks.afterDeviceMint = undefined;
    // The web row is bound to no sign-in, so the membership re-check is its only guard.
    const saved = await tx.query("SELECT 1 FROM person_device_credentials WHERE device_id = 'web' AND revoked_at IS NULL");
    assert.equal(saved.rows.length, 1);
    await tx.query("DELETE FROM organization_memberships WHERE user_id = $1", [fx.userId]);
  };
  const refused = await fx.credential({ cookie: `agent_relay_session=${signIn.accessToken}` });
  assert.equal(refused.status, 403);
  assert.equal(refused.body.error, "forbidden");
  assert.equal(mentionsIssuedToken(fx.state, refused.body), false);
  assert.deepEqual(fx.state.deviceDeletes, ["web"]);
  assert.equal(await relayAccepts(fx.config.relaycastUrl, fx.state.issuedTokens[0]!), false);
  const [row] = await fx.deviceRows();
  assert.equal(row!.revoked, true);
  assert.equal(row!.upstream_revoked, true);
});

test("sign-out answers 200 when Relaycast never answers the device-token revoke", async (t) => {
  const fx = await harness(t, { signOutRevokeTimeoutMs: 50 });
  const signIn = await fx.signIn();
  const minted = await fx.credential({ token: signIn.accessToken });
  assert.equal(minted.status, 200);

  fx.state.deleteHangs = true;
  const signOut = await jsonRequest(fx.origin, "/api/v1/auth/token/revoke", {
    method: "POST",
    body: { token: signIn.accessToken },
  });
  assert.equal(signOut.status, 200);
  assert.deepEqual(fx.state.deviceDeletes, [minted.body.identity.device.id]);
  // The aborted revoke leaves the row pending for the sweep.
  const [row] = await fx.deviceRows();
  assert.equal(row!.revoked, true);
  assert.equal(row!.upstream_revoked, false);
});

test("a gate-only install mints no device token", async (t) => {
  const fx = await harness(t, { config: { relaygatePublicUrl: "https://gate.selfhosted.example" } });
  const signIn = await fx.signIn();
  const withheld = await fx.credential({ token: signIn.accessToken });
  assert.equal(withheld.status, 403);
  assert.equal(withheld.body.error, "gate_only");
  // The body is not read on a gate-only install.
  const withBody = await fx.credential({ token: signIn.accessToken }, { raw: "not json" });
  assert.equal(withBody.status, 403);
  assert.equal(withBody.body.error, "gate_only");
  assert.equal(fx.state.registerCalls, 0);
  assert.equal(fx.state.mints.length, 0);
  assert.equal((await fx.deviceRows()).length, 0);
});

test("the device kind column accepts only desktop, cli and web", async (t) => {
  const fx = await harness(t);
  const insert = (kind: string) => fx.database.query(
    `INSERT INTO person_device_credentials
       (id, workspace_id, user_id, device_id, device_name, device_kind, session_id, relaycast_workspace_id,
        agent_name, agent_remote_id, token_ciphertext, expires_at)
     VALUES ($1, $2, $3, $4, 'name', $5, NULL, 'rc-first', 'agent', 'ag_1', 'ciphertext', now() + interval '1 hour')`,
    [randomUUID(), fx.workspaceId, fx.userId, `device-${kind}`, kind],
  );
  await insert("web");
  await assert.rejects(insert("phone"));
});
