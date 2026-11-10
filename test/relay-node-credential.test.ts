import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import { createAdminModule } from "../src/admin/routes.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * relay-node workspace API tokens and the /relay-node/v1 broker
 * (docs/relay-node-credential.md).
 */

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const SERVICE = "internal-service-token-that-is-at-least-32-bytes";
const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const HISTORY = "https://history.selfhosted.test";
const NODE_SCOPES = ["relay:workspace:read", "relay:nodes:read", "relay:nodes:enroll", "relay:agents:read"];
const WORKSPACE_KEY = "rk_primary";

type RelaycastCall = { method: string; url: string; headers: IncomingMessage["headers"]; body: string };
type Reply = { status: number; body?: unknown; raw?: string; headers?: Record<string, string> };

async function deviceToken(origin: string, userId: string, workspaceId: string): Promise<string> {
  const started = await request(origin, "/api/v1/auth/device/start", { method: "POST", body: {} });
  const approved = await request(origin, "/api/v1/auth/device/approve", {
    method: "POST",
    token: BOOTSTRAP,
    body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: workspaceId },
  });
  assert.equal(approved.status, 200);
  const issued = await request(origin, "/api/v1/auth/device/token", {
    method: "POST",
    body: { device_code: started.body.device_code },
  });
  assert.equal(issued.status, 200);
  return issued.body.access_token as string;
}

async function setup(t: TestContext) {
  // Fake Relaycast: records every call; `reply` picks the answer per call.
  const calls: RelaycastCall[] = [];
  let reply: (call: RelaycastCall) => Reply = () => ({ status: 200, body: { ok: true, data: {} } });
  const relaycast = createServer((incoming: IncomingMessage, response: ServerResponse) => {
    const chunks: Buffer[] = [];
    incoming.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
    incoming.on("end", () => {
      const call = {
        method: incoming.method ?? "GET",
        url: incoming.url ?? "/",
        headers: incoming.headers,
        body: Buffer.concat(chunks).toString("utf8"),
      };
      calls.push(call);
      const answer = reply(call);
      response.writeHead(answer.status, { "content-type": "application/json", ...answer.headers });
      response.end(answer.raw ?? JSON.stringify(answer.body ?? {}));
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
    introspectSecret: INTROSPECT_SECRET,
    introspectAudiences: [HISTORY],
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: SERVICE,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${origin}/dashboard/`,
    port: 0,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, KEYRING, 0);
  const admin = createAdminModule({ config, database, keyring: KEYRING });
  control.on("request", createApp({ config, store, admin }));
  let relaycastOpen = true;
  const stopRelaycast = async () => {
    if (!relaycastOpen) return;
    relaycastOpen = false;
    await close(relaycast);
  };
  t.after(async () => {
    await close(control);
    await stopRelaycast();
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
    body: { name: "primary", relaycastApiKey: WORKSPACE_KEY },
  });
  assert.equal(created.status, 201, created.raw);
  const workspaceId = created.body.id as string;
  const base = `/api/v1/workspaces/${workspaceId}/deployment-api-tokens`;
  const owner = await deviceToken(origin, org.body.owner.id, workspaceId);
  calls.length = 0;
  const mint = (body: Record<string, unknown>) => request(origin, base, { method: "POST", token: owner, body });
  return {
    database,
    origin,
    base,
    owner,
    workspaceId,
    calls,
    stopRelaycast,
    setReply: (next: (call: RelaycastCall) => Reply) => { reply = next; },
    mint,
    mintNode: async (nodeName = "node-a", extra: Record<string, unknown> = {}) => {
      const answer = await mint({ label: "relay node", purpose: "relay-node", nodeName, ...extra });
      assert.equal(answer.status, 201, answer.raw);
      return answer.body as { id: string; accessToken: string } & Record<string, any>;
    },
    /** Calls the broker with optional extra headers. */
    broker: async (path: string, token: string | undefined, init: { method?: string; body?: string; headers?: Record<string, string> } = {}) => {
      const response = await fetch(`${origin}${path}`, {
        method: init.method ?? "GET",
        headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...init.headers },
        body: init.body,
        redirect: "manual",
      });
      const raw = await response.text();
      let body: Record<string, any> = {};
      try { body = raw ? JSON.parse(raw) : {}; } catch { body = {}; }
      return { status: response.status, body, raw, headers: response.headers };
    },
  };
}

// ------------------------------------------------------------ minting

test("relay-node tokens: fixed scopes, nodeName stored, listed and audited, several per node", async (t) => {
  const ctx = await setup(t);
  const first = await ctx.mintNode("node-a");
  assert.match(first.accessToken, /^sh_wk_/);
  assert.equal(first.purpose, "relay-node");
  assert.deepEqual(first.scopes, NODE_SCOPES);
  assert.equal(first.nodeName, "node-a");
  assert.equal(first.agent_name, "node-a");
  assert.equal(first.aud, null);
  // Default expiry is 90 days.
  const days = (Date.parse(first.accessTokenExpiresAt) - Date.now()) / 86_400_000;
  assert(days > 89.9 && days <= 90, `expiry ${days}`);

  // Rotation: a successor for the same node coexists with its predecessor.
  const second = await ctx.mintNode("node-a", { expiryDays: 365 });
  assert.notEqual(second.id, first.id);

  const deployment = await ctx.mint({ label: "ci", purpose: "deployment" });
  assert.equal(deployment.status, 201);
  assert.equal(deployment.body.nodeName, null);
  assert.equal(deployment.body.agent_name, null);

  const listed = await request(ctx.origin, ctx.base, { token: ctx.owner });
  assert.equal(listed.status, 200);
  assert(!listed.raw.includes(first.accessToken));
  const rows = listed.body.tokens.filter((row: any) => row.nodeName === "node-a");
  assert.equal(rows.length, 2);
  assert(rows.every((row: any) => row.status === "active" && row.agent_name === "node-a"));

  const audit = await request(ctx.origin, `/api/v1/workspaces/${ctx.workspaceId}/admin/audit`, { token: ctx.owner });
  assert(audit.raw.includes(`${first.id} (relay-node: node-a)`));
  assert(!audit.raw.includes(first.accessToken));

  // Revoke the predecessor: it stops working at the broker, the successor keeps working.
  ctx.setReply(() => ({ status: 200, body: { ok: true, data: { id: "rw-1", name: "Relay WS" } } }));
  assert.equal((await request(ctx.origin, `${ctx.base}/${first.id}`, { method: "DELETE", token: ctx.owner })).status, 204);
  assert.equal((await ctx.broker("/relay-node/v1/workspace", first.accessToken)).status, 401);
  assert.equal((await ctx.broker("/relay-node/v1/workspace", second.accessToken)).status, 200);
  const relisted = await request(ctx.origin, ctx.base, { token: ctx.owner });
  assert.equal(relisted.body.tokens.find((row: any) => row.id === first.id).status, "revoked");
});

test("relay-node mint rules: nodeName required and validated, aud/neverExpires/scopes refused", async (t) => {
  const ctx = await setup(t);
  const body = (extra: Record<string, unknown>) => ({ label: "n", purpose: "relay-node", nodeName: "node-a", ...extra });
  for (const nodeName of [undefined, "", "has space", "x".repeat(201), 42, "a/b"]) {
    const bad = await ctx.mint(body({ nodeName }));
    assert.equal(bad.status, 400, `nodeName ${String(nodeName)}`);
    assert.equal(bad.body.error, "invalid_request");
  }
  for (const extra of [
    { aud: HISTORY },
    { aud: null },
    { neverExpires: true },
    { scopes: NODE_SCOPES },
    { scope: "relay:nodes:read" },
    { agent_name: "node-a" },
    { expiryDays: 366 },
    { expiryDays: 0 },
  ]) {
    assert.equal((await ctx.mint(body(extra))).status, 400, JSON.stringify(extra));
  }
  // nodeName belongs to relay-node only.
  for (const purpose of ["deployment", "workflow", "agent-runtime"]) {
    assert.equal((await ctx.mint({ label: "x", purpose, nodeName: "node-a" })).status, 400, purpose);
  }
  // The table constraint backs the same rule.
  await assert.rejects(ctx.database.query(
    `INSERT INTO workspace_api_tokens (id, workspace_id, label, purpose, scopes, token_hash, token_prefix)
     VALUES (gen_random_uuid(), $1, 'x', 'relay-node', ARRAY['relay:nodes:read'], 'h', 'sh_wk_xxxx')`,
    [ctx.workspaceId],
  ));
});

test("a relay-node token never passes the workspace API token gate; others still do", async (t) => {
  const ctx = await setup(t);
  const node = await ctx.mintNode();
  const deployment = (await ctx.mint({ label: "ci", purpose: "deployment" })).body.accessToken as string;
  const runtime = (await ctx.mint({ label: "rt", purpose: "agent-runtime" })).body.accessToken as string;

  const environment = `/internal/v1/workspaces/${ctx.workspaceId}/environment`;
  assert.equal((await request(ctx.origin, environment, { token: runtime })).status, 200);
  assert.equal((await request(ctx.origin, environment, { token: node.accessToken })).status, 401);

  // Person-only route: a deployment token is recognised (403), a relay-node token is not a credential (401).
  const resolve = `/api/v1/workspaces/${ctx.workspaceId}/resolve`;
  assert.equal((await request(ctx.origin, resolve, { token: deployment })).status, 403);
  const refused = await request(ctx.origin, resolve, { token: node.accessToken });
  assert.equal(refused.status, 401);
  assert(!refused.raw.includes(WORKSPACE_KEY));
  assert.equal((await request(ctx.origin, ctx.base, { token: node.accessToken })).status, 401);

  // Introspection: like every other non-introspectable purpose.
  const introspected = await request(ctx.origin, "/internal/v1/auth/introspect", {
    method: "POST",
    token: INTROSPECT_SECRET,
    body: { token: node.accessToken, aud: HISTORY },
  });
  assert.equal(introspected.status, 200);
  assert.deepEqual(introspected.body, { active: false, reason: "wrong-kind" });
  assert.equal(ctx.calls.length, 0);
});

// ------------------------------------------------------------ broker

test("broker authentication: only a live relay-node token, else 401 token_invalid", async (t) => {
  const ctx = await setup(t);
  ctx.setReply(() => ({ status: 200, body: { ok: true, data: { id: "rw-1", name: "Relay WS" } } }));
  const live = await ctx.mintNode();
  const deployment = (await ctx.mint({ label: "ci", purpose: "deployment" })).body.accessToken as string;
  const runtime = (await ctx.mint({ label: "rt", purpose: "agent-runtime" })).body.accessToken as string;
  const revoked = await ctx.mintNode();
  await request(ctx.origin, `${ctx.base}/${revoked.id}`, { method: "DELETE", token: ctx.owner });
  const expired = await ctx.mintNode();
  await ctx.database.query("UPDATE workspace_api_tokens SET expires_at = now() - interval '1 second' WHERE id = $1", [expired.id]);

  for (const token of [undefined, "sh_wk_unknown", deployment, runtime, revoked.accessToken, expired.accessToken, ctx.owner, BOOTSTRAP, SERVICE]) {
    for (const path of ["/relay-node/v1/workspace", "/relay-node/v1/anything"]) {
      const answer = await ctx.broker(path, token);
      assert.equal(answer.status, 401, `${path} ${String(token).slice(0, 10)}`);
      assert.equal(answer.body.error.code, "token_invalid");
      assert.equal(answer.body.ok, false);
      assert.equal(answer.headers.get("cache-control"), "no-store");
    }
  }
  assert.equal(ctx.calls.length, 0);

  const before = (await ctx.database.query<{ last_used_at: Date | null }>(
    "SELECT last_used_at FROM workspace_api_tokens WHERE id = $1", [live.id])).rows[0]!.last_used_at;
  assert.equal(before, null);
  assert.equal((await ctx.broker("/relay-node/v1/workspace", live.accessToken)).status, 200);
  const after = (await ctx.database.query<{ last_used_at: Date | null }>(
    "SELECT last_used_at FROM workspace_api_tokens WHERE id = $1", [live.id])).rows[0]!.last_used_at;
  assert.notEqual(after, null);
});

test("broker GET routes run against Relaycast with the stored key", async (t) => {
  const ctx = await setup(t);
  const node = await ctx.mintNode();
  ctx.setReply((call) => {
    if (call.url === "/v1/workspace") {
      return { status: 200, body: { ok: true, data: { id: "rw-1", name: "Relay WS", api_key: "rk_leak", plan: "x" } } };
    }
    return { status: 200, body: { ok: true, data: { echo: call.url } } };
  });

  const workspace = await ctx.broker("/relay-node/v1/workspace", node.accessToken);
  assert.equal(workspace.status, 200);
  assert.deepEqual(workspace.body, { ok: true, data: { id: "rw-1", name: "Relay WS" } });
  assert.equal(workspace.headers.get("cache-control"), "no-store");
  assert(!workspace.raw.includes(WORKSPACE_KEY) && !workspace.raw.includes(ctx.workspaceId));

  const nodes = await ctx.broker("/relay-node/v1/nodes?status=online&limit=5&cursor=c1&evil=1&workspace_id=x", node.accessToken);
  assert.equal(nodes.status, 200);
  assert.deepEqual(nodes.body, { ok: true, data: { echo: "/v1/nodes?status=online&limit=5&cursor=c1" } });

  const one = await ctx.broker("/relay-node/v1/nodes/node%20b%3Ax", node.accessToken);
  assert.deepEqual(one.body.data, { echo: "/v1/nodes/node%20b%3Ax" });

  const agents = await ctx.broker("/relay-node/v1/agents?limit=2&other=3", node.accessToken);
  assert.deepEqual(agents.body.data, { echo: "/v1/agents?limit=2" });

  const agent = await ctx.broker("/relay-node/v1/agents/builder-1", node.accessToken);
  assert.deepEqual(agent.body.data, { echo: "/v1/agents/builder-1" });

  assert.deepEqual(ctx.calls.map((call) => `${call.method} ${call.url}`), [
    "GET /v1/workspace",
    "GET /v1/nodes?status=online&limit=5&cursor=c1",
    "GET /v1/nodes/node%20b%3Ax",
    "GET /v1/agents?limit=2",
    "GET /v1/agents/builder-1",
  ]);
  for (const call of ctx.calls) {
    assert.equal(call.headers.authorization, `Bearer ${WORKSPACE_KEY}`);
  }
});

test("broker POST nodes enrolls only the token's own node and forwards node headers", async (t) => {
  const ctx = await setup(t);
  const node = await ctx.mintNode("node-a");
  ctx.setReply(() => ({ status: 201, body: { ok: true, data: { id: "n-1", name: "node-a", token: "rn_secret" } } }));

  for (const body of [{ name: "node-b" }, {}, { name: 7 }, [{ name: "node-a" }]]) {
    const refused = await ctx.broker("/relay-node/v1/nodes", node.accessToken, {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
    });
    assert.equal(refused.status, 403, JSON.stringify(body));
    assert.equal(refused.body.error.code, "node_mismatch");
    assert.equal(refused.body.ok, false);
  }
  assert.equal(ctx.calls.length, 0);

  const raw = JSON.stringify({ name: "node-a", capabilities: { spawn: true }, labels: ["a"] });
  const enrolled = await ctx.broker("/relay-node/v1/nodes", node.accessToken, {
    method: "POST",
    body: raw,
    headers: {
      "content-type": "application/json",
      "idempotency-key": "idem-123",
      "x-relaycast-node-token": "rn_existing",
      "x-other": "dropped",
    },
  });
  assert.equal(enrolled.status, 201);
  assert.deepEqual(enrolled.body, { ok: true, data: { id: "n-1", name: "node-a", token: "rn_secret" } });
  assert.equal(enrolled.headers.get("cache-control"), "no-store");
  assert.equal(ctx.calls.length, 1);
  const call = ctx.calls[0]!;
  assert.equal(call.method, "POST");
  assert.equal(call.url, "/v1/nodes");
  assert.equal(call.body, raw);
  assert.equal(call.headers.authorization, `Bearer ${WORKSPACE_KEY}`);
  assert.equal(call.headers["idempotency-key"], "idem-123");
  assert.equal(call.headers["x-relaycast-node-token"], "rn_existing");
  assert.equal(call.headers["content-type"], "application/json");
  assert.equal(call.headers["x-other"], undefined);

  // A 409 from Relaycast passes through.
  ctx.setReply(() => ({ status: 409, body: { ok: false, error: { code: "conflict" } } }));
  const conflict = await ctx.broker("/relay-node/v1/nodes", node.accessToken, { method: "POST", body: raw });
  assert.equal(conflict.status, 409);
  assert.deepEqual(conflict.body, { ok: false, error: { code: "conflict" } });

  // Malformed JSON: refused before anything is forwarded.
  const before = ctx.calls.length;
  assert.equal((await ctx.broker("/relay-node/v1/nodes", node.accessToken, { method: "POST", body: "{" })).status, 400);
  assert.equal(ctx.calls.length, before);
});

test("broker refuses everything outside the allowlist with 403 scope_denied", async (t) => {
  const ctx = await setup(t);
  const node = await ctx.mintNode();
  const cases: Array<[string, string]> = [
    ["GET", "/relay-node/v1"],
    ["GET", "/relay-node/v1/channels"],
    ["GET", "/relay-node/v1/messages"],
    ["POST", "/relay-node/v1/workspace"],
    ["PATCH", "/relay-node/v1/workspace"],
    ["DELETE", "/relay-node/v1/nodes/node-a"],
    ["PUT", "/relay-node/v1/nodes/node-a"],
    ["POST", "/relay-node/v1/agents"],
    ["DELETE", "/relay-node/v1/agents/a"],
    ["GET", "/relay-node/v1/nodes/node-a/tokens"],
    ["GET", "/relay-node/v1/agents/a/b"],
    ["GET", "/relay-node/v1/workspace/stream"],
  ];
  for (const [method, path] of cases) {
    const answer = await ctx.broker(path, node.accessToken, { method });
    assert.equal(answer.status, 403, `${method} ${path}`);
    assert.equal(answer.body.error.code, "scope_denied", `${method} ${path}`);
  }
  assert.equal(ctx.calls.length, 0);
  // Not reachable through the /cloud alias.
  const aliased = await ctx.broker("/cloud/relay-node/v1/workspace", node.accessToken);
  assert.notEqual(aliased.status, 200);
  assert(!aliased.raw.includes("token_invalid"));
});

test("broker maps Relaycast failures: refused stored key and outages are 502, other statuses pass through", async (t) => {
  const ctx = await setup(t);
  const node = await ctx.mintNode();
  const get = (path = "/relay-node/v1/nodes/node-a") => ctx.broker(path, node.accessToken);

  ctx.setReply(() => ({ status: 401, body: { ok: false, error: { code: "unauthorized" } } }));
  for (const path of ["/relay-node/v1/workspace", "/relay-node/v1/nodes/node-a"]) {
    const answer = await get(path);
    assert.equal(answer.status, 502, `401 ${path}`);
    assert.equal(answer.body.error.code, "relaycast_unavailable");
  }
  // A 403 is Relaycast's decision about the request (suspended workspace, node ownership): passed through.
  ctx.setReply(() => ({ status: 403, body: { ok: false, error: { code: "workspace_suspended" } } }));
  const forbidden = await get();
  assert.equal(forbidden.status, 403);
  assert.deepEqual(forbidden.body, { ok: false, error: { code: "workspace_suspended" } });

  ctx.setReply(() => ({ status: 200, raw: "<html>not json</html>" }));
  assert.equal((await get()).status, 502);
  ctx.setReply(() => ({ status: 200, body: { ok: true, data: { name: "no id" } } }));
  assert.equal((await get("/relay-node/v1/workspace")).status, 502);
  ctx.setReply(() => ({ status: 302, raw: "", headers: { location: "http://elsewhere.invalid/" } }));
  assert.equal((await get()).status, 502);

  ctx.setReply(() => ({ status: 404, body: { ok: false, error: { code: "not_found" } } }));
  const missing = await get();
  assert.equal(missing.status, 404);
  assert.deepEqual(missing.body, { ok: false, error: { code: "not_found" } });

  ctx.setReply(() => ({ status: 429, body: { ok: false, error: { code: "rate_limited" } }, headers: { "retry-after": "7" } }));
  const limited = await get("/relay-node/v1/agents");
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get("retry-after"), "7");
  assert.deepEqual(limited.body, { ok: false, error: { code: "rate_limited" } });

  ctx.setReply(() => ({ status: 503, body: { ok: false, error: { code: "unavailable" } } }));
  assert.equal((await get()).status, 503);

  // Empty answer: not JSON.
  ctx.setReply(() => ({ status: 200, raw: "" }));
  assert.equal((await get("/relay-node/v1/nodes")).status, 502);

  // Relaycast down entirely.
  await ctx.stopRelaycast();
  const down = await get();
  assert.equal(down.status, 502);
  assert.equal(down.body.error.code, "relaycast_unavailable");
  assert(!down.raw.includes(WORKSPACE_KEY));
});
