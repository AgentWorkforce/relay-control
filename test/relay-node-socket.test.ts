import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import test, { type TestContext } from "node:test";
import { WebSocket, WebSocketServer, type RawData } from "ws";
import { createApp } from "../src/app.js";
import { createAdminModule } from "../src/admin/routes.js";
import type { SelfhostConfig } from "../src/config.js";
import { relayLaunchCredentials } from "../src/mcp/relay-launch-credentials.js";
import { migrate } from "../src/migrations.js";
import { sanitizeCloseCode } from "../src/relay-node/socket.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * Gate-only relay-node socket bridge: GET /relay-node/v1/ws
 * (docs/relay-node-credential.md, "Gate-only installs").
 */

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const HISTORY = "https://history.selfhosted.test";
const NODE_TOKEN = "nt_live_bridge_secret";

/** Frames received on one socket, awaited in order. */
class Inbox {
  private frames: string[] = [];
  private waiters: Array<(frame: string) => void> = [];
  constructor(socket: WebSocket) {
    socket.on("message", (data: RawData) => this.push(Buffer.isBuffer(data) ? data.toString("utf8") : String(data)));
  }
  private push(frame: string) {
    const waiter = this.waiters.shift();
    if (waiter) waiter(frame);
    else this.frames.push(frame);
  }
  next(timeoutMs = 3_000): Promise<string> {
    const ready = this.frames.shift();
    if (ready !== undefined) return Promise.resolve(ready);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("no frame")), timeoutMs);
      this.waiters.push((frame) => { clearTimeout(timer); resolve(frame); });
    });
  }
  get pending() { return this.frames.length; }
}

const closed = (socket: WebSocket) => new Promise<number>((resolve) => socket.once("close", (code) => resolve(code)));

async function connect(url: string, token?: string): Promise<{ status: number; socket?: WebSocket; inbox?: Inbox }> {
  const socket = new WebSocket(url, token ? { headers: { authorization: `Bearer ${token}` } } : {});
  const inbox = new Inbox(socket);
  return new Promise((resolve, reject) => {
    socket.once("open", () => resolve({ status: 101, socket, inbox }));
    socket.once("unexpected-response", (_request, response) => {
      resolve({ status: response.statusCode ?? 0 });
      response.resume();
      socket.terminate();
    });
    socket.once("error", (error) => reject(error));
  });
}

async function until(check: () => Promise<boolean>, timeoutMs = 3_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (await check()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.fail("condition not reached");
}

async function setup(t: TestContext, options: { gate?: boolean } = {}) {
  // Captured server logs: nothing may contain a credential.
  const logs: string[] = [];
  for (const method of ["log", "warn", "error", "info", "debug"] as const) {
    t.mock.method(console, method, (...args: unknown[]) => { logs.push(args.map((arg) => {
      try { return typeof arg === "string" ? arg : JSON.stringify(arg); } catch { return String(arg); }
    }).join(" ")); });
  }

  // Fake Relaycast: HTTP enrolment plus the node socket at /v1/node/ws.
  const upstreamUrls: string[] = [];
  const upstreamSockets: WebSocket[] = [];
  const upstreamInboxes: Inbox[] = [];
  let onUpstream: (() => void) | null = null;
  const relaycast = createServer((incoming: IncomingMessage, response: ServerResponse) => {
    incoming.resume();
    incoming.on("end", () => {
      response.writeHead(201, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true, data: { id: "rc-node-1", name: "node-a", token: NODE_TOKEN } }));
    });
  });
  const upstreamServer = new WebSocketServer({ noServer: true });
  relaycast.on("upgrade", (incoming, socket, head) => {
    upstreamUrls.push(incoming.url ?? "");
    upstreamServer.handleUpgrade(incoming, socket, head, (ws) => {
      upstreamSockets.push(ws);
      upstreamInboxes.push(new Inbox(ws));
      onUpstream?.();
    });
  });
  const relaycastOrigin = await listen(relaycast);

  const database = new PGliteDatabase();
  await migrate(database);
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: origin,
    relaycastUrl: relaycastOrigin,
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: HISTORY,
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: HISTORY, secret: "r".repeat(32) },
    introspectSecret: "introspect-secret-that-is-at-least-32-bytes",
    introspectAudiences: [HISTORY],
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: "internal-service-token-that-is-at-least-32-bytes",
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${origin}/dashboard/`,
    port: 0,
    host: "127.0.0.1",
    ...(options.gate ?? true ? { relaygatePublicUrl: "https://gate.selfhosted.test" } : {}),
  };
  const store = new ControlPlaneStore(database, KEYRING, 0);
  const admin = createAdminModule({ config, database, keyring: KEYRING });
  const app = createApp({ config, store, admin });
  control.on("request", app);
  control.on("upgrade", (incoming, socket, head) => app.handleUpgrade(incoming, socket, head));
  const clients: WebSocket[] = [];
  t.after(async () => {
    for (const client of clients) client.terminate();
    app.closeUpgrades();
    for (const socket of upstreamSockets) socket.terminate();
    upstreamServer.close();
    await close(control);
    await close(relaycast);
    await database.close();
  });

  const org = await request(origin, "/api/v1/organizations", {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Acme", ownerEmail: "owner@acme.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const created = await request(origin, `/api/v1/organizations/${org.body.id}/workspaces`, {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "primary", relaycastApiKey: "rk_primary" },
  });
  assert.equal(created.status, 201, created.raw);
  const workspaceId = created.body.id as string;
  const ownerId = org.body.owner.id as string;
  const organizationId = org.body.id as string;
  const started = await request(origin, "/api/v1/auth/device/start", { method: "POST", body: {} });
  await request(origin, "/api/v1/auth/device/approve", {
    method: "POST",
    token: BOOTSTRAP,
    body: { action: "approve", user_code: started.body.user_code, user_id: ownerId, workspace_id: workspaceId },
  });
  const owner = (await request(origin, "/api/v1/auth/device/token", {
    method: "POST",
    body: { device_code: started.body.device_code },
  })).body.access_token as string;
  const mintNode = async (nodeName = "node-a") => {
    const answer = await request(origin, `/api/v1/workspaces/${workspaceId}/deployment-api-tokens`, {
      method: "POST", token: owner, body: { label: "relay node", purpose: "relay-node", nodeName },
    });
    assert.equal(answer.status, 201, answer.raw);
    return answer.body.accessToken as string;
  };
  const enrol = async (token: string, name = "node-a") => {
    const response = await fetch(`${origin}/relay-node/v1/nodes`, {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ name }),
    });
    const raw = await response.text();
    assert.equal(response.status, 201, raw);
    assert(!raw.includes(NODE_TOKEN));
  };
  const wsUrl = `${origin.replace(/^http/, "ws")}/relay-node/v1/ws`;
  return {
    database, origin, workspaceId, ownerId, organizationId, logs, upstreamUrls, upstreamSockets, upstreamInboxes,
    mintNode, enrol, wsUrl,
    /** Opens the bridge and waits for the matching upstream socket. */
    open: async (token: string) => {
      const before = upstreamSockets.length;
      const upstreamReady = new Promise<void>((resolve) => {
        if (upstreamSockets.length > before) resolve();
        else onUpstream = () => { if (upstreamSockets.length > before) resolve(); };
      });
      const opened = await connect(wsUrl, token);
      assert.equal(opened.status, 101);
      clients.push(opened.socket!);
      await upstreamReady;
      return {
        client: opened.socket!, clientInbox: opened.inbox!,
        upstream: upstreamSockets[before]!, upstreamInbox: upstreamInboxes[before]!,
      };
    },
    launch: async (invocationId: string | null, state = "accepted", nodeName = "node-a") => {
      const spawnId = randomUUID();
      await database.query(
        `INSERT INTO relay_spawns (id, workspace_id, user_id, authority_hash, relaycast_workspace_id, actor_id, idempotency_hash,
           request_hash, agent_name, cli, node_id, state, invocation_id, audit)
         VALUES ($1, $2, $3, 'authority', 'rc-ws', 'actor', $4, 'request', 'worker', 'claude', 'rc-node-1', $5, $6, '[]'::jsonb)`,
        [spawnId, workspaceId, ownerId, randomUUID(), state, invocationId]);
      const credentials = relayLaunchCredentials(database, KEYRING);
      await credentials.issue({ spawnId, workspaceId, organizationId, userId: ownerId, nodeName, agentName: "worker" });
      const token = await credentials.sealedFor(spawnId);
      assert.ok(token?.startsWith("sh_lt_"));
      return { spawnId, token: token!, credentials };
    },
  };
}

test("upgrade refusals: 404 off gate-only or on another path, 401 without a live token, 403 before enrolment", async (t) => {
  const plain = await setup(t, { gate: false });
  const plainToken = await plain.mintNode();
  assert.equal((await connect(plain.wsUrl, plainToken)).status, 404);

  const ctx = await setup(t);
  const token = await ctx.mintNode();
  assert.equal((await connect(`${ctx.origin.replace(/^http/, "ws")}/relay-node/v1/other`, token)).status, 404);
  assert.equal((await connect(ctx.wsUrl)).status, 401);
  assert.equal((await connect(ctx.wsUrl, "sh_wk_not_a_live_token")).status, 401);
  // A token in the query string is never read.
  assert.equal((await connect(`${ctx.wsUrl}?token=${token}`)).status, 401);
  assert.equal((await connect(ctx.wsUrl, token)).status, 403);
  assert.equal(ctx.upstreamUrls.length, 0);

  // A stored token the keyring cannot read: 403, the node must re-enrol.
  await ctx.enrol(token);
  await ctx.database.query("UPDATE relay_node_credentials SET token_ciphertext = 'v1.unknown-key.AAAA.AAAA.AAAA'");
  assert.equal((await connect(ctx.wsUrl, token)).status, 403);
  assert.equal(ctx.upstreamUrls.length, 0);
});

test("bridge: frames relay both ways, spawn invocations carry the launch credential, deliver is dropped", async (t) => {
  const ctx = await setup(t);
  const token = await ctx.mintNode();
  await ctx.enrol(token);
  const { client, clientInbox, upstream, upstreamInbox } = await ctx.open(token);

  // The upstream socket is Relaycast's node socket opened with the stored node token.
  assert.equal(ctx.upstreamUrls.length, 1);
  const upstreamUrl = new URL(ctx.upstreamUrls[0]!, "http://relaycast.test");
  assert.equal(upstreamUrl.pathname, "/v1/node/ws");
  assert.equal(upstreamUrl.searchParams.get("token"), NODE_TOKEN);

  // Node -> Relaycast: unchanged; register updates last_heartbeat_at.
  const register = JSON.stringify({ type: "node.register", name: "node-a", capabilities: ["spawn:claude"] });
  client.send(register);
  assert.equal(await upstreamInbox.next(), register);
  const reply = JSON.stringify({ type: "reply", ok: true });
  upstream.send(reply);
  assert.equal(await clientInbox.next(), reply);
  const heartbeatAt = async () => (await ctx.database.query<{ last_heartbeat_at: Date | null }>(
    "SELECT last_heartbeat_at FROM relay_node_credentials WHERE node_name = 'node-a'")).rows[0]!.last_heartbeat_at;
  await until(async () => (await heartbeatAt()) !== null);

  // Throttled per connection: a heartbeat right after register does not write again.
  await ctx.database.query("UPDATE relay_node_credentials SET last_heartbeat_at = NULL");
  const heartbeat = JSON.stringify({ type: "node.heartbeat", active_agents: 0 });
  client.send(heartbeat);
  assert.equal(await upstreamInbox.next(), heartbeat);
  for (const frame of ["not json", "[1,2]", JSON.stringify({ type: "delivery.ack", delivery_id: "d-1" })]) {
    client.send(frame);
    assert.equal(await upstreamInbox.next(), frame);
  }
  assert.equal(await heartbeatAt(), null);

  // Relaycast -> node: a spawn invocation journaled for this node carries the launch credential.
  const launch = await ctx.launch("inv-1");
  const invoke = { type: "action.invoke", invocation_id: "inv-1", action: "spawn:claude", input: { name: "worker", task: "t" } };
  upstream.send(JSON.stringify(invoke));
  const attached = JSON.parse(await clientInbox.next());
  assert.deepEqual(attached, { ...invoke, input: { ...invoke.input, launch_credential: launch.token } });
  // Attaching does not burn it: relaygate's introspection does.
  assert.equal(await launch.credentials.sealedFor(launch.spawnId), launch.token);

  // Unknown invocation, deliver, release, ping, non-JSON: unchanged or dropped, in order.
  const unknown = JSON.stringify({ ...invoke, invocation_id: "inv-unknown" });
  const deliver = JSON.stringify({ type: "deliver", delivery_id: "d-2", message: { text: "hi" } });
  const release = JSON.stringify({ type: "action.invoke", invocation_id: "inv-1", action: "release", input: { name: "worker" } });
  const ping = JSON.stringify({ type: "ping" });
  for (const frame of [unknown, deliver, release, deliver, ping, "plain text"]) upstream.send(frame);
  assert.equal(await clientInbox.next(), unknown);
  assert.equal(await clientInbox.next(), release);
  assert.equal(await clientInbox.next(), ping);
  assert.equal(await clientInbox.next(), "plain text");

  // A spawn for another node's launch is not edited.
  await ctx.launch("inv-other", "accepted", "node-b");
  const other = JSON.stringify({ ...invoke, invocation_id: "inv-other" });
  upstream.send(other);
  assert.equal(await clientInbox.next(), other);

  // Relaycast may dispatch before Control records the invocation id: the bridge waits for it.
  const racing = await ctx.launch(null, "reserved");
  const raced = { ...invoke, invocation_id: "inv-race" };
  upstream.send(JSON.stringify(raced));
  await new Promise((resolve) => setTimeout(resolve, 200));
  await ctx.database.query("UPDATE relay_spawns SET invocation_id = 'inv-race', state = 'accepted' WHERE id = $1", [racing.spawnId]);
  assert.deepEqual(JSON.parse(await clientInbox.next()),
    { ...raced, input: { ...raced.input, launch_credential: racing.token } });

  // Relaycast closing ends the client with its code.
  const clientClosed = closed(client);
  upstream.close(4001, "bye");
  assert.equal(await clientClosed, 4001);

  // A second connection: its first heartbeat writes last_heartbeat_at.
  const second = await ctx.open(token);
  second.client.send(heartbeat);
  assert.equal(await second.upstreamInbox.next(), heartbeat);
  await until(async () => (await heartbeatAt()) !== null);
  // An abnormal upstream drop reaches the node as 1011.
  const secondClosed = closed(second.client);
  second.upstream.terminate();
  assert.equal(await secondClosed, 1011);

  // Audit rows, and no credential anywhere in audit or logs.
  await until(async () => (await ctx.database.query(
    "SELECT 1 FROM admin_audit_events WHERE action = 'relay_node.socket.closed'")).rows.length === 2);
  const audit = (await ctx.database.query<{ action: string; target: string }>(
    "SELECT action, target FROM admin_audit_events WHERE action LIKE 'relay_node.%' ORDER BY created_at")).rows;
  const actions = audit.map((row) => row.action);
  assert.equal(actions.filter((action) => action === "relay_node.socket.opened").length, 2);
  assert(audit.some((row) => row.action === "relay_node.launch_credential.attached"
    && row.target === `node=node-a spawn=${launch.spawnId}`));
  assert(audit.some((row) => row.target === "node=node-a code=4001"));
  assert(audit.some((row) => row.target === "node=node-a code=1011"));
  const everything = [...ctx.logs, ...audit.map((row) => `${row.action} ${row.target}`)].join("\n");
  for (const secret of [NODE_TOKEN, launch.token, racing.token, token]) assert(!everything.includes(secret));
});

test("bridge: a node closing ends the upstream socket", async (t) => {
  const ctx = await setup(t);
  const token = await ctx.mintNode();
  await ctx.enrol(token);
  const { client, upstream } = await ctx.open(token);
  const upstreamClosed = closed(upstream);
  client.close(1000);
  assert.equal(await upstreamClosed, 1000);
});

test("close codes: 1005/1006/1015 and unknown codes become 1011", () => {
  for (const code of [1000, 1001, 1008, 1011, 3000, 4001, 4999]) assert.equal(sanitizeCloseCode(code), code);
  for (const code of [1004, 1005, 1006, 1015, 999, 2000, 5000]) assert.equal(sanitizeCloseCode(code), 1011);
});
