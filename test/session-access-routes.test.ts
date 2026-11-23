import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { AGENT_IDENTITY_TOOLS, SESSION_ACCESS_TOOLS, STAFF_READ_GRANT_TOOLS } from "../src/mcp/catalog.js";
import { agentIdentityAllows, staffReadGrantAllows } from "../src/mcp/routes.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase } from "./support/harness.js";

/**
 * Session access management end to end (docs/sessions-read-api.md, "Session
 * access"): the four MCP tools and the four dashboard routes, through real
 * Control HTTP admission, against a stub relaygate that serves both the
 * read-session mint and the access routes.
 */

const MCP_PATH = "/api/v1/mcp/shared-sessions";
const SESSION = "fake-session-1";
const LOST = "fake-session-lost";
const SECRET = "fake-reader-issuer-secret-".repeat(2);
const KEYRING = { active: { id: "fake-key", key: Buffer.alloc(32, 7) } };

type Upstream = {
  method: string;
  path: string;
  query: URLSearchParams;
  bearer: string | undefined;
  body: Record<string, unknown>;
};

/** relaygate stand-in: one policy per session, versioned, with history. */
function relaygateStub() {
  const mints: Array<Record<string, unknown>> = [];
  const access: Upstream[] = [];
  const issued = new Set<string>();
  const policies = new Map<string, { version: number; mode: string; acl: unknown[]; users: unknown[]; label: string | null }>();
  const history: Array<Record<string, unknown>> = [];
  /** Who relaygate records as the actor of the next change (`ctl:<userId>` for a Control person). */
  const actor = { id: "agent-7", name: null as string | null };
  /** Per-path forced answers: status, or "drop" to destroy the connection. */
  const forced = new Map<string, number | "drop">();
  let serial = 0;
  const policyOf = (sessionId: string) => {
    let policy = policies.get(sessionId);
    if (!policy) {
      policy = { version: 1, mode: "640", acl: [{ gid: 12, perm: "r" }], users: [], label: null };
      policies.set(sessionId, policy);
    }
    return policy;
  };
  const answer = (sessionId: string, reset = false) => {
    const policy = policyOf(sessionId);
    return {
      runtime: !reset, ...(reset ? { reset: true } : {}),
      access: { sessionId, gid: 7, ...policy, updatedAt: "2026-01-01T00:00:00.000Z" },
    };
  };
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const raw = Buffer.concat(chunks).toString("utf8");
    const body = raw ? JSON.parse(raw) as Record<string, unknown> : {};
    res.setHeader("content-type", "application/json");
    if (url.pathname.startsWith("/internal/v1/session-read/sessions")) {
      assert.equal(req.headers.authorization, `Bearer ${SECRET}`);
      mints.push(body);
      serial++;
      const accessToken = `rth_at_read_${String(serial).padEnd(43, "a")}`;
      issued.add(accessToken);
      res.end(JSON.stringify({
        sessionId: `fake-reader-session-${serial}`, userId: body.userId, orgId: body.orgId, workspaceId: body.workspaceId,
        audience: body.audience, scopes: ["rth:read"], accessToken,
        refreshToken: `rth_rt_read_${String(serial).padEnd(43, "r")}`,
        accessTokenExpiresAt: new Date(Date.now() + 600_000).toISOString(),
        refreshTokenExpiresAt: new Date(Date.now() + 86_400_000).toISOString(), tokenType: "Bearer",
      }));
      return;
    }
    const match = /^\/v1\/sessions\/([^/]+)\/access(?:\/(reset|history))?$/.exec(url.pathname);
    assert.ok(match, `unexpected upstream path ${url.pathname}`);
    access.push({ method: req.method ?? "", path: url.pathname, query: url.searchParams, bearer: req.headers.authorization, body });
    const sessionId = decodeURIComponent(match[1]!);
    const force = forced.get(`${req.method} ${sessionId}`);
    if (force === "drop") {
      req.socket.destroy();
      return;
    }
    if (typeof force === "number") {
      res.statusCode = force;
      res.end(JSON.stringify({ error: { code: "forced", message: "forced" } }));
      return;
    }
    const bearer = req.headers.authorization?.replace(/^Bearer /, "") ?? "";
    if (!issued.has(bearer)) {
      res.statusCode = 401;
      res.end(JSON.stringify({ error: { code: "unauthorized" } }));
      return;
    }
    const policy = policyOf(sessionId);
    if (match[2] === "history") {
      res.end(JSON.stringify({ rows: history.filter((row) => row.session_id === sessionId) }));
      return;
    }
    if (req.method === "GET") {
      res.end(JSON.stringify(answer(sessionId)));
      return;
    }
    if (body.expectedVersion !== policy.version) {
      res.statusCode = 409;
      res.end(JSON.stringify({ error: { code: "conflict", message: "stale" }, currentVersion: policy.version }));
      return;
    }
    // relaygate records no before state for a session's first change.
    const first = !history.some((row) => row.session_id === sessionId);
    const before = first ? null : { mode: policy.mode, gid: 7, acl: policy.acl, users: policy.users, label: policy.label };
    const reset = match[2] === "reset";
    if (reset) Object.assign(policy, { mode: "640", acl: [], users: [], label: null });
    else {
      if (body.mode !== undefined) policy.mode = body.mode as string;
      if (body.acl !== undefined) policy.acl = body.acl as unknown[];
      if (body.users !== undefined) policy.users = body.users as unknown[];
      if (body.label !== undefined) policy.label = body.label as string | null;
    }
    policy.version++;
    history.push({
      seq: history.length + 1, at: "2026-01-01T00:00:00.000Z", session_id: sessionId, actor_id: actor.id,
      actor_name: actor.name, version: policy.version, reason: body.reason,
      before, after: reset ? { reset: true } : { mode: policy.mode, gid: 7, acl: policy.acl, users: policy.users, label: policy.label },
    });
    res.end(JSON.stringify(answer(sessionId, reset)));
  });
  return { server, mints, access, forced, policies, history, actor };
}

/**
 * configured: false turns reader-kind mints off (the public URL stays set).
 * sessionsOnly: no SELFHOST_RELAYGATE_PUBLIC_URL, mints still carry the reader kind.
 */
async function setup(t: TestContext, options: { configured?: boolean; sessionsOnly?: boolean } = {}) {
  const gate = relaygateStub();
  const gateUrl = await listen(gate.server);
  const database = new PGliteDatabase();
  await migrate(database);
  const store = new ControlPlaneStore(database, KEYRING, 0, { tenancy: "multi" });
  const org = await store.createOrganization({ name: "Fake Org", ownerEmail: "owner@example.test", ownerName: "Fake Owner" });
  const workspace = await store.createWorkspace({ organizationId: org.id, name: "Fake Workspace", relaycastApiKey: "fake-relay-key" });
  const teammate = await store.putMembership({
    organizationId: org.id, email: "teammate@example.test", name: "Fake Teammate", role: "member", operator: true,
  }) as { userId: string };
  const former = await store.putMembership({
    organizationId: org.id, email: "former@example.test", name: "Fake Former", role: "member", operator: true,
  }) as { userId: string };
  await store.deleteMembership(org.id, former.userId);
  await store.createOrganization({ name: "Other Org", ownerEmail: "outsider@example.test", ownerName: "Fake Outsider" });
  const pair = await database.transaction((tx) => store.issueBrowserSession(tx, {
    userId: org.owner.id, organizationId: org.id, workspaceId: workspace.id, label: "fake-session-access",
  }));
  const control = createServer();
  const controlUrl = await listen(control);
  const configured = options.configured ?? true;
  const config: SelfhostConfig = {
    databaseUrl: "unused", publicBaseUrl: controlUrl, relaycastUrl: "http://unused.test",
    relaycastPublicUrl: "https://relay.selfhosted.company", relayhistoryUrl: gateUrl, relayhistoryPublicUrl: gateUrl,
    bootstrapToken: "fake-bootstrap-token-".repeat(3), encryptionKeyring: KEYRING, internalServiceToken: null,
    oauthRedirectUrl: `${controlUrl}/unused`, dashboardUrl: controlUrl, host: "127.0.0.1", port: 3000,
    sessionReadApi: { url: gateUrl, publicUrl: gateUrl, secret: SECRET, mintReaderKind: configured },
    sessionReadMcpReads: true,
    relaygatePublicUrl: options.sessionsOnly ? null : "https://gate.selfhosted.company",
  };
  control.on("request", createApp({ config, store }));
  t.after(async () => {
    control.closeAllConnections();
    gate.server.closeAllConnections();
    await close(control);
    await close(gate.server as Server);
    await database.close();
  });
  const rpc = async (method: string, params?: Record<string, unknown>) => {
    const response = await fetch(`${controlUrl}${MCP_PATH}`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${pair.accessToken}`, "content-type": "application/json",
        accept: "application/json, text/event-stream",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, ...(params ? { params } : {}) }),
    });
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) as any : null };
  };
  const tool = async (name: string, args: Record<string, unknown>) => {
    const answer = await rpc("tools/call", { name, arguments: args });
    assert.equal(answer.status, 200, `${name}: ${answer.status}`);
    return answer.body.result as { isError?: boolean; structuredContent: any };
  };
  const route = (suffix: string) => `/api/v1/workspaces/${workspace.id}/sessions/${encodeURIComponent(SESSION)}/access${suffix}`;
  /** A dashboard route as a device (bearer) or a browser (cookie, with an Origin). */
  const http = async (method: string, path: string, init: { body?: unknown; cookie?: boolean; origin?: string } = {}) => {
    const headers: Record<string, string> = {};
    if (init.cookie) headers.cookie = `agent_relay_session=${pair.accessToken}`;
    else headers.authorization = `Bearer ${pair.accessToken}`;
    if (init.origin) headers.origin = init.origin;
    if (init.body !== undefined) headers["content-type"] = "application/json";
    const response = await fetch(`${controlUrl}${init.cookie ? `/cloud${path}` : path}`, {
      method, headers, ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
    });
    const text = await response.text();
    return { status: response.status, body: text ? JSON.parse(text) as any : null };
  };
  return {
    gate, controlUrl, pair, org, workspace, teammate, former, rpc, tool, route, http,
    ownerId: org.owner.id,
  };
}

const upstreamPatches = (env: Awaited<ReturnType<typeof setup>>) => env.gate.access.filter((call) => call.method !== "GET");

test("MCP: the four tools run as the person, with the person's own read token", async (t) => {
  const env = await setup(t);
  env.gate.actor.name = `ctl:${env.ownerId}`;
  const listed = await env.rpc("tools/list");
  const names = (listed.body.result.tools as Array<{ name: string }>).map((tool) => tool.name);
  for (const name of SESSION_ACCESS_TOOLS) assert.ok(names.includes(name), `${name} listed`);

  const got = await env.tool("get_session_access", { session_id: SESSION });
  assert.equal(got.isError, undefined);
  assert.equal(got.structuredContent.outcome, "ok");
  assert.equal(got.structuredContent.access.version, 1);
  assert.deepEqual(got.structuredContent.access.groups, [{ gid: 12, perm: "r" }]);

  // No expected_version: Control reads the version first, then PATCHes with it.
  const before = env.gate.access.length;
  const set = await env.tool("set_session_access", {
    session_id: SESSION, mode: "000",
    members: [{ email: "TEAMMATE@example.test", perm: "r" }], groups: [{ gid: 12, perm: "r" }],
    reason: "restrict to the review group",
  });
  assert.equal(set.structuredContent.outcome, "ok");
  assert.equal(set.structuredContent.access.version, 2);
  assert.deepEqual(set.structuredContent.access.members, [
    { user_id: env.teammate.userId, email: "teammate@example.test", name: "Fake Teammate", perm: "r", member: true },
  ]);
  const calls = env.gate.access.slice(before);
  assert.deepEqual(calls.map((call) => call.method), ["GET", "PATCH"]);
  assert.deepEqual(calls[1]!.body, {
    mode: "000", acl: [{ gid: 12, perm: "r" }], users: [{ userId: env.teammate.userId, perm: "r" }],
    expectedVersion: 1, reason: "restrict to the review group",
  });
  const sent = JSON.stringify(calls[1]!.body).toLowerCase();
  assert.ok(!sent.includes("teammate@example.test") && !sent.includes("fake teammate"), "only user ids go upstream");

  const history = await env.tool("get_session_access_history", { session_id: SESSION });
  assert.equal(history.structuredContent.outcome, "ok");
  assert.equal(history.structuredContent.rows.length, 1);
  const row = history.structuredContent.rows[0];
  assert.equal(row.reason, "restrict to the review group");
  assert.deepEqual([row.actor_id, row.actor_name], ["agent-7", `ctl:${env.ownerId}`]);
  assert.deepEqual(row.actor, { user_id: env.ownerId, email: "owner@example.test", name: "Fake Owner", member: true });
  assert.equal(row.before, null, "the first change has no before state");
  assert.deepEqual(row.after.members, [
    { user_id: env.teammate.userId, email: "teammate@example.test", name: "Fake Teammate", perm: "r", member: true },
  ]);
  assert.equal(history.structuredContent.next_after, null);

  const reset = await env.tool("reset_session_access", { session_id: SESSION, reason: "back to defaults", expected_version: 2 });
  assert.equal(reset.structuredContent.outcome, "ok");
  assert.equal(reset.structuredContent.access.reset, true);

  // Every mint named this person and reader kind mcp; every access call
  // carried a minted read token, never the caller's Control token or the
  // issuer secret.
  assert.ok(env.gate.mints.length >= 1);
  for (const mint of env.gate.mints) {
    assert.equal(mint.userId, env.ownerId);
    assert.equal(mint.workspaceId, env.workspace.id);
    assert.equal(mint.reader_kind, "mcp");
  }
  for (const call of env.gate.access) {
    assert.match(call.bearer!, /^Bearer rth_at_read_/);
    assert.notEqual(call.bearer, `Bearer ${env.pair.accessToken}`);
    assert.ok(!call.bearer!.includes(SECRET));
    assert.equal(call.query.get("workspace"), null);
  }
});

test("MCP: refusals map to typed outcomes and nothing unresolved goes upstream", async (t) => {
  const env = await setup(t);
  // Unknown email and another organization's member: refused, nothing sent.
  for (const email of ["nobody@example.test", "outsider@example.test"]) {
    const refused = await env.tool("set_session_access", {
      session_id: SESSION, members: [{ email, perm: "r" }], reason: "share", expected_version: 1,
    });
    assert.equal(refused.isError, true);
    assert.equal(refused.structuredContent.outcome, "unknown_members");
    assert.deepEqual(refused.structuredContent.emails, [email]);
  }
  // Validation refusals.
  for (const args of [
    { mode: "778", reason: "x" },
    { mode: "640", reason: "x".repeat(201) },
    { reason: "nothing to change" },
  ]) {
    const refused = await env.tool("set_session_access", { session_id: SESSION, ...args });
    assert.equal(refused.structuredContent.outcome, "invalid_request", JSON.stringify(args));
  }
  assert.equal(env.gate.access.length, 0, "no upstream call for a refused input");

  // 409: conflict with the current version, one PATCH, no retry.
  const stale = await env.tool("set_session_access", { session_id: SESSION, mode: "600", reason: "x", expected_version: 0 });
  assert.equal(stale.structuredContent.outcome, "conflict");
  assert.equal(stale.structuredContent.current_version, 1);
  assert.equal(upstreamPatches(env).length, 1);

  env.gate.forced.set(`GET ${SESSION}`, 404);
  assert.equal((await env.tool("get_session_access", { session_id: SESSION })).structuredContent.outcome, "not_found");
  env.gate.forced.set(`GET ${SESSION}`, 403);
  assert.equal((await env.tool("get_session_access", { session_id: SESSION })).structuredContent.outcome, "not_access_admin");

  // A lost PATCH: outcome_unknown after exactly one PATCH. A lost read: unavailable.
  env.gate.forced.set(`PATCH ${LOST}`, "drop");
  const lost = await env.tool("set_session_access", { session_id: LOST, mode: "600", reason: "x", expected_version: 1 });
  assert.equal(lost.structuredContent.outcome, "outcome_unknown");
  assert.equal(env.gate.access.filter((call) => call.method === "PATCH" && call.path.includes(LOST)).length, 1);
  env.gate.forced.set(`GET ${LOST}`, "drop");
  assert.equal((await env.tool("get_session_access", { session_id: LOST })).structuredContent.outcome, "unavailable");
});

test("MCP: a former member's grant is shown as member:false", async (t) => {
  const env = await setup(t);
  env.gate.policies.set(SESSION, {
    version: 3, mode: "000", acl: [],
    users: [{ userId: env.former.userId, perm: "r" }, { userId: env.teammate.userId, perm: "rw" }], label: null,
  });
  const got = await env.tool("get_session_access", { session_id: SESSION });
  assert.deepEqual(got.structuredContent.access.members, [
    { user_id: env.former.userId, perm: "r", member: false },
    { user_id: env.teammate.userId, email: "teammate@example.test", name: "Fake Teammate", perm: "rw", member: true },
  ]);
});

test("MCP: history actors for a current member, a former member and a non-Control name", async (t) => {
  const env = await setup(t);
  const row = (seq: number, actorName: string | null) => ({
    seq, at: "2026-01-01T00:00:00.000Z", session_id: SESSION, actor_id: `agent-${seq}`, actor_name: actorName,
    version: seq + 1, reason: "x", before: null,
    after: { mode: "000", gid: 7, acl: [], users: [{ userId: env.former.userId, perm: "r" }], label: null },
  });
  env.gate.history.push(row(1, `ctl:${env.teammate.userId}`), row(2, `ctl:${env.former.userId}`), row(3, "gate-operator"));
  const history = await env.tool("get_session_access_history", { session_id: SESSION });
  assert.equal(history.structuredContent.outcome, "ok");
  assert.deepEqual(history.structuredContent.rows.map((entry: any) => entry.actor), [
    { user_id: env.teammate.userId, email: "teammate@example.test", name: "Fake Teammate", member: true },
    { user_id: env.former.userId, member: false },
    null,
  ]);
  assert.deepEqual(history.structuredContent.rows[2].actor_name, "gate-operator");
  assert.deepEqual(history.structuredContent.rows[0].after.members, [{ user_id: env.former.userId, perm: "r", member: false }]);

  const dashboard = await env.http("GET", env.route("/history"));
  assert.equal(dashboard.status, 200);
  assert.deepEqual(dashboard.body.rows.map((entry: any) => entry.actor), [
    { userId: env.teammate.userId, email: "teammate@example.test", name: "Fake Teammate", member: true },
    { userId: env.former.userId, member: false },
    null,
  ]);
  assert.deepEqual(dashboard.body.rows.map((entry: any) => entry.before), [null, null, null]);
});

test("MCP: staff read grants and agent identity tokens never reach the session access tools", () => {
  for (const name of SESSION_ACCESS_TOOLS) {
    assert.ok(!(STAFF_READ_GRANT_TOOLS as readonly string[]).includes(name));
    assert.ok(!(AGENT_IDENTITY_TOOLS as readonly string[]).includes(name));
    const body = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: { session_id: SESSION } } };
    assert.equal(staffReadGrantAllows(body), false, name);
    assert.equal(agentIdentityAllows(body), false, name);
  }
});

test("dashboard: the four routes for a device, with the person's own read token", async (t) => {
  const env = await setup(t);
  env.gate.actor.name = `ctl:${env.ownerId}`;
  const got = await env.http("GET", env.route(""));
  assert.equal(got.status, 200);
  assert.equal(got.body.access.version, 1);

  const set = await env.http("PATCH", env.route(""), {
    body: { mode: "000", members: [{ email: "teammate@example.test", perm: "r" }], reason: "restrict" },
  });
  assert.equal(set.status, 200);
  assert.equal(set.body.access.version, 2);
  assert.deepEqual(set.body.access.members, [
    { userId: env.teammate.userId, email: "teammate@example.test", name: "Fake Teammate", perm: "r", member: true },
  ]);
  const patch = upstreamPatches(env)[0]!;
  assert.deepEqual(patch.body, { mode: "000", users: [{ userId: env.teammate.userId, perm: "r" }], expectedVersion: 1, reason: "restrict" });
  assert.ok(!JSON.stringify(patch.body).includes("@"), "no email upstream");

  const history = await env.http("GET", `${env.route("/history")}?after=0&limit=10`);
  assert.equal(history.status, 200);
  assert.equal(history.body.rows.length, 1);
  assert.equal(history.body.nextAfter, null);
  assert.deepEqual(history.body.rows[0].actor, { userId: env.ownerId, email: "owner@example.test", name: "Fake Owner", member: true });
  assert.equal(history.body.rows[0].before, null);
  const historyCall = env.gate.access.find((call) => call.path.endsWith("/history"))!;
  assert.equal(historyCall.query.get("after"), "0");
  assert.equal(historyCall.query.get("limit"), "10");

  const reset = await env.http("POST", env.route("/reset"), { body: { reason: "defaults", expectedVersion: 2 } });
  assert.equal(reset.status, 200);
  assert.equal(reset.body.access.reset, true);

  for (const mint of env.gate.mints) {
    assert.equal(mint.userId, env.ownerId);
    assert.equal(mint.reader_kind, "device");
  }
  for (const call of env.gate.access) {
    assert.match(call.bearer!, /^Bearer rth_at_read_/);
    assert.notEqual(call.bearer, `Bearer ${env.pair.accessToken}`);
  }
});

test("dashboard: answers for each outcome", async (t) => {
  const env = await setup(t);
  const unknown = await env.http("PATCH", env.route(""), {
    body: { members: [{ email: "outsider@example.test", perm: "r" }, { email: "nobody@example.test", perm: "r" }], reason: "x" },
  });
  assert.equal(unknown.status, 400);
  assert.equal(unknown.body.error, "unknown_members");
  assert.deepEqual(unknown.body.emails, ["outsider@example.test", "nobody@example.test"]);
  for (const body of [{ mode: "999", reason: "x" }, { mode: "640", reason: "" }, { reason: "x" }, { mode: "640", reason: "x", extra: 1 }]) {
    const refused = await env.http("PATCH", env.route(""), { body });
    assert.equal(refused.status, 400, JSON.stringify(body));
    assert.equal(refused.body.error, "invalid_request");
  }
  assert.equal(env.gate.access.length, 0);

  const stale = await env.http("PATCH", env.route(""), { body: { mode: "600", reason: "x", expectedVersion: 0 } });
  assert.equal(stale.status, 409);
  assert.deepEqual([stale.body.error, stale.body.currentVersion], ["conflict", 1]);
  assert.equal(upstreamPatches(env).length, 1);

  env.gate.forced.set(`GET ${SESSION}`, 404);
  assert.equal((await env.http("GET", env.route(""))).status, 404);
  env.gate.forced.set(`GET ${SESSION}`, 403);
  const forbidden = await env.http("GET", env.route(""));
  assert.deepEqual([forbidden.status, forbidden.body.error], [403, "not_access_admin"]);
  env.gate.forced.set(`GET ${SESSION}`, 502);
  const down = await env.http("GET", env.route(""));
  assert.deepEqual([down.status, down.body.error], [503, "session_access_unavailable"]);

  const lostPath = `/api/v1/workspaces/${env.workspace.id}/sessions/${LOST}/access`;
  env.gate.forced.set(`PATCH ${LOST}`, "drop");
  const lost = await env.http("PATCH", lostPath, { body: { mode: "600", reason: "x", expectedVersion: 1 } });
  assert.deepEqual([lost.status, lost.body.error], [504, "session_access_outcome_unknown"]);
  assert.equal(env.gate.access.filter((call) => call.method === "PATCH" && call.path.includes(LOST)).length, 1);
  env.gate.forced.set(`GET ${LOST}`, "drop");
  assert.equal((await env.http("GET", lostPath)).status, 503);

  const badQuery = await env.http("GET", `${env.route("/history")}?limit=abc`);
  assert.equal(badQuery.status, 400);
});

test("dashboard: a cookie PATCH or POST needs an allowed Origin", async (t) => {
  const env = await setup(t);
  const patch = { mode: "600", reason: "x", expectedVersion: 1 };
  for (const [method, suffix, body] of [["PATCH", "", patch], ["POST", "/reset", { reason: "x", expectedVersion: 1 }]] as const) {
    const refused = await env.http(method, env.route(suffix), { cookie: true, origin: "https://elsewhere.example.test", body });
    assert.deepEqual([refused.status, refused.body.error], [403, "csrf_rejected"], method);
  }
  assert.equal(env.gate.access.length, 0);
  const allowed = await env.http("PATCH", env.route(""), { cookie: true, origin: env.controlUrl, body: patch });
  assert.equal(allowed.status, 200);
  const read = await env.http("GET", env.route(""), { cookie: true });
  assert.equal(read.status, 200);
  assert.ok(env.gate.mints.every((mint) => mint.reader_kind === "browser"));
});

test("dashboard: a staff read grant is refused", async (t) => {
  const env = await setup(t);
  const response = await fetch(`${env.controlUrl}${env.route("")}`, {
    headers: { authorization: `Bearer sh_sr_${"a".repeat(43)}` },
  });
  assert.equal(response.status, 401);
  await response.body?.cancel();
  assert.equal(env.gate.access.length, 0);
});

test("not configured: tools are not listed and the routes refuse", async (t) => {
  const env = await setup(t, { configured: false });
  const listed = await env.rpc("tools/list");
  const names = (listed.body.result.tools as Array<{ name: string }>).map((tool) => tool.name);
  for (const name of SESSION_ACCESS_TOOLS) assert.ok(!names.includes(name), `${name} not listed`);
  for (const [method, suffix, body] of [
    ["GET", "", undefined], ["PATCH", "", { mode: "600", reason: "x" }],
    ["POST", "/reset", { reason: "x" }], ["GET", "/history", undefined],
  ] as const) {
    const refused = await env.http(method, env.route(suffix), body ? { body } : {});
    assert.deepEqual([refused.status, refused.body.error], [404, "session_access_not_configured"], `${method} ${suffix}`);
  }
  assert.equal(env.gate.access.length, 0);
});

test("sessions-only install (no relaygate public URL): tools listed, MCP and dashboard reach relaygate with the person's own read token", async (t) => {
  const env = await setup(t, { sessionsOnly: true });
  const listed = await env.rpc("tools/list");
  const names = (listed.body.result.tools as Array<{ name: string }>).map((tool) => tool.name);
  for (const name of SESSION_ACCESS_TOOLS) assert.ok(names.includes(name), `${name} listed`);

  const got = await env.tool("get_session_access", { session_id: SESSION });
  assert.equal(got.structuredContent.outcome, "ok");
  const route = await env.http("GET", env.route(""));
  assert.equal(route.status, 200);
  assert.equal(route.body.access.version, 1);

  assert.equal(env.gate.access.length, 2);
  const kinds = env.gate.mints.map((mint) => mint.reader_kind);
  assert.ok(kinds.includes("mcp") && kinds.includes("device"), `reader kinds ${kinds.join(",")}`);
  for (const mint of env.gate.mints) assert.equal(mint.userId, env.ownerId);
  for (const call of env.gate.access) {
    assert.match(call.bearer!, /^Bearer rth_at_read_/);
    assert.notEqual(call.bearer, `Bearer ${env.pair.accessToken}`);
  }
});
