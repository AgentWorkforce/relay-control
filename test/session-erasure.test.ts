import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { close, listen, seedTenant, startControlPlane } from "./flows-helpers.js";

const SECRET = "session-erase-secret-that-is-at-least-32-bytes";
const ORIGIN = "https://control.selfhosted.company";
const SESSION = "ses_01-abc";
const SOURCE = "codex";
/** Replaced by the fake pipeline with the request id Control last sent. */
const ECHO_REQUEST = "echo-the-request-id";

type Reply = { status: number; body: unknown };
type Call = { method: string; path: string; authorization?: string; body: any };

async function fakePipeline(t: TestContext) {
  const calls: Call[] = [];
  const state: { reply: (call: Call) => Reply } = { reply: () => ({ status: 503, body: {} }) };
  let requestId = "";
  const server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const text = Buffer.concat(chunks).toString("utf8");
      const call: Call = {
        method: request.method ?? "",
        path: request.url ?? "",
        authorization: request.headers.authorization,
        body: text ? JSON.parse(text) : undefined,
      };
      calls.push(call);
      if (call.body?.requestId) requestId = call.body.requestId;
      const reply = state.reply(call);
      const echoed = (reply.body as { requestId?: string }).requestId === ECHO_REQUEST
        ? { ...(reply.body as object), requestId }
        : reply.body;
      response.writeHead(reply.status, { "content-type": "application/json" });
      response.end(JSON.stringify(echoed));
    });
  });
  const url = await listen(server);
  t.after(() => close(server));
  return { url, calls, state };
}

function receipt(orgId: string, overrides: Record<string, unknown> = {}) {
  return {
    orgId,
    sessionId: SESSION,
    requestId: ECHO_REQUEST,
    status: "completed",
    requestedAt: "2026-01-01T00:00:00.000Z",
    completedAt: "2026-01-01T00:00:03.000Z",
    artifacts: { transcriptObjects: { count: 3, state: "done" }, briefs: { count: 0, state: "not_applicable" } },
    uploadsFenced: true,
    unreadable: true,
    unreadableAt: "2026-01-01T00:00:01.000Z",
    bytesErased: true,
    bytesErasedAt: "2026-01-01T00:00:03.000Z",
    legacyScope: "excluded",
    failure: null,
    ...overrides,
  };
}

async function setup(t: TestContext) {
  const pipeline = await fakePipeline(t);
  const app = await startControlPlane({}, undefined, { sessionErasureApi: { url: pipeline.url, secret: SECRET } });
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  const base = `/api/v1/organizations/${tenant.organizationId}/sessions/${SESSION}`;
  const query = `?workspaceId=${tenant.workspaceId}&source=${SOURCE}`;
  const path = `${base}${query}`;
  const erasure = `${base}/erasure${query}`;
  const internal = `/internal/v1/session-erase/organizations/${tenant.organizationId}/workspaces/${tenant.workspaceId}/sources/${SOURCE}/sessions`;
  const audits = async () => (await app.database.query<{ action: string; actor_id: string | null; target: string }>(
    `SELECT action, actor_id, target FROM selfhost_admin_audit_events
      WHERE organization_id = $1 AND action LIKE 'session.hard_%' ORDER BY created_at, action`,
    [tenant.organizationId],
  )).rows;
  return { app, tenant, pipeline, base, path, erasure, internal, query, audits };
}

test("session hard delete stays 501 until the pipeline erase is configured", async (t) => {
  const app = await startControlPlane();
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  const path = `/api/v1/organizations/${tenant.organizationId}/sessions/${SESSION}`;
  for (const [route, method] of [[path, "DELETE"], [`${path}/erasure`, "GET"]] as const) {
    const result = await app.api(route, { method, token: tenant.ownerToken });
    assert.equal(result.status, 501);
    assert.equal(result.body.error, "not_implemented");
  }
  const rows = await app.database.query(`SELECT 1 FROM selfhost_admin_audit_events WHERE action LIKE 'session.hard_%'`);
  assert.equal(rows.rows.length, 0);
});

test("session hard delete: owner erases, audits once, repeat is idempotent, membership kept", async (t) => {
  const { app, tenant, pipeline, path, internal, audits } = await setup(t);
  pipeline.state.reply = () => ({ status: 200, body: receipt(tenant.organizationId) });
  const members = async () => (await app.database.query(
    `SELECT 1 FROM selfhost_organization_memberships WHERE organization_id = $1`, [tenant.organizationId],
  )).rows.length;
  const before = await members();

  const first = await app.api(path, { method: "DELETE", token: tenant.ownerToken });
  assert.equal(first.status, 200);
  assert.equal(first.body.status, "completed");
  assert.equal(first.body.audit.action, "session.hard_deleted");
  assert.equal(first.headers.get("cache-control"), "no-store");

  const call = pipeline.calls[0]!;
  assert.equal(call.method, "POST");
  assert.equal(call.path, `${internal}/${SESSION}`);
  assert.equal(call.authorization, `Bearer ${SECRET}`);
  assert.equal(call.body.actor.kind, "user");

  const second = await app.api(path, { method: "DELETE", token: tenant.ownerToken });
  assert.equal(second.status, 200);
  assert.deepEqual(second.body, first.body);
  assert.equal(pipeline.calls[1]!.body.requestId, call.body.requestId);

  const events = await audits();
  assert.deepEqual(events.map((event) => event.action).sort(), [
    "session.hard_delete.requested",
    "session.hard_delete.requested",
    "session.hard_deleted",
  ]);
  for (const event of events) {
    assert.equal(event.target, `session:${SESSION} source=${SOURCE} request=${call.body.requestId}`);
    assert.ok(event.actor_id);
  }
  assert.equal(await members(), before);
});

test("session hard delete: authorization, entitlement and CSRF gates reach no pipeline", async (t) => {
  const { app, tenant, pipeline, base, path, erasure } = await setup(t);
  assert.equal((await app.api(path, { method: "DELETE" })).status, 401);
  assert.equal((await app.api(path, { method: "DELETE", token: tenant.memberToken })).status, 403);
  assert.equal((await app.api(erasure, { token: tenant.memberToken })).status, 403);

  for (const suffix of ["", `?workspaceId=${tenant.workspaceId}`, `?source=${SOURCE}`]) {
    const incomplete = await app.api(`${base}${suffix}`, { method: "DELETE", token: tenant.ownerToken });
    assert.equal(incomplete.status, 400);
    assert.equal(incomplete.body.error, "invalid_session_target");
  }
  for (const workspaceId of [randomUUID(), "not-a-uuid"]) {
    const unknown = await app.api(`${base}?workspaceId=${workspaceId}&source=${SOURCE}`, {
      method: "DELETE", token: tenant.ownerToken,
    });
    assert.equal(unknown.status, 404);
    assert.equal(unknown.body.error, "workspace_not_found");
  }
  assert.equal((await app.api(
    `/api/v1/organizations/${randomUUID()}/sessions/${SESSION}`, { method: "DELETE", token: tenant.ownerToken },
  )).status, 404);

  const previous = process.env.SELFHOST_OPERATOR_CONTROLS;
  process.env.SELFHOST_OPERATOR_CONTROLS = "off";
  t.after(() => {
    if (previous === undefined) delete process.env.SELFHOST_OPERATOR_CONTROLS;
    else process.env.SELFHOST_OPERATOR_CONTROLS = previous;
  });
  const gated = await app.api(path, { method: "DELETE", token: tenant.ownerToken });
  assert.equal(gated.status, 403);
  assert.equal(gated.body.error, "operator_controls_not_entitled");
  delete process.env.SELFHOST_OPERATOR_CONTROLS;

  for (const id of ["a\u0001b", " padded ", "x".repeat(513)]) {
    const invalid = await app.api(`/api/v1/organizations/${tenant.organizationId}/sessions/${encodeURIComponent(id)}`, {
      method: "DELETE", token: tenant.ownerToken,
    });
    assert.equal(invalid.status, 400);
    assert.equal(invalid.body.error, "invalid_session_id");
  }

  assert.equal(pipeline.calls.length, 0);
});

test("session hard delete: in-progress erase completes and is audited through the read", async (t) => {
  const { tenant, app, pipeline, path, erasure, audits } = await setup(t);
  pipeline.state.reply = () => ({
    status: 202,
    body: receipt(tenant.organizationId, { status: "in_progress", completedAt: null, bytesErased: false, bytesErasedAt: null }),
  });
  const started = await app.api(path, { method: "DELETE", token: tenant.ownerToken });
  assert.equal(started.status, 202);
  assert.equal(started.body.audit, null);
  assert.deepEqual((await audits()).map((event) => event.action), ["session.hard_delete.requested"]);

  pipeline.state.reply = () => ({ status: 200, body: receipt(tenant.organizationId) });
  const read = await app.api(erasure, { token: tenant.ownerToken });
  assert.equal(read.status, 200);
  assert.equal(read.body.status, "completed");
  assert.equal(read.body.audit.action, "session.hard_deleted");
  await app.api(erasure, { token: tenant.ownerToken });
  assert.equal((await audits()).filter((event) => event.action === "session.hard_deleted").length, 1);
});

test("session hard delete never reports success it cannot prove", async (t) => {
  const { tenant, app, pipeline, path, audits } = await setup(t);
  const org = tenant.organizationId;
  const cases: Array<[Reply, number, string]> = [
    [{ status: 200, body: receipt(org, { completedAt: null }) }, 502, "invalid_session_erasure_response"],
    [{ status: 200, body: receipt(org, { uploadsFenced: false }) }, 502, "invalid_session_erasure_response"],
    [{ status: 200, body: receipt(org, { unreadable: false }) }, 502, "invalid_session_erasure_response"],
    [{ status: 200, body: receipt(org, { bytesErased: false }) }, 502, "invalid_session_erasure_response"],
    [{ status: 200, body: receipt(org, { artifacts: { ledgerRows: { count: 1, state: "pending" } } }) }, 502, "invalid_session_erasure_response"],
    [{ status: 501, body: { error: "not_implemented" } }, 501, "not_implemented"],
    [{ status: 200, body: receipt(randomUUID()) }, 502, "invalid_session_erasure_response"],
    [{ status: 200, body: receipt(org, { sessionId: "other" }) }, 502, "invalid_session_erasure_response"],
    [{ status: 200, body: { ok: true } }, 502, "invalid_session_erasure_response"],
    [{ status: 404, body: { error: "route not found" } }, 502, "invalid_session_erasure_response"],
    [{ status: 401, body: {} }, 502, "invalid_session_erasure_response"],
    [{ status: 503, body: {} }, 503, "session_erasure_unavailable"],
  ];
  for (const [reply, status, error] of cases) {
    pipeline.state.reply = () => reply;
    const result = await app.api(path, { method: "DELETE", token: tenant.ownerToken });
    assert.equal(result.status, status, JSON.stringify(reply));
    assert.equal(result.body.error, error);
  }

  pipeline.state.reply = () => ({
    status: 200,
    body: receipt(org, { status: "failed", completedAt: null, failure: { code: "object_store_error" } }),
  });
  const failed = await app.api(path, { method: "DELETE", token: tenant.ownerToken });
  assert.equal(failed.status, 502);
  assert.equal(failed.body.error, "session_erasure_failed");
  assert.equal(failed.body.erasure.failure.code, "object_store_error");
  assert.equal(failed.body.erasure.audit, null);
  assert.equal((await audits()).filter((event) => event.action === "session.hard_deleted").length, 0);

  pipeline.state.reply = () => ({ status: 200, body: { ...receipt(org), artifacts: { note: "secret text" } } });
  const content = await app.api(path, { method: "DELETE", token: tenant.ownerToken });
  assert.equal(content.status, 502);
  assert.doesNotMatch(JSON.stringify(content.body), /secret text/);
});

test("session hard delete reaches a session id containing a slash", async (t) => {
  const { tenant, app, pipeline, query, internal } = await setup(t);
  const id = "agent/run:1";
  pipeline.state.reply = () => ({ status: 200, body: receipt(tenant.organizationId, { sessionId: id }) });
  const result = await app.api(`/api/v1/organizations/${tenant.organizationId}/sessions/${encodeURIComponent(id)}${query}`, {
    method: "DELETE", token: tenant.ownerToken,
  });
  assert.equal(result.status, 200);
  assert.equal(pipeline.calls[0]!.path, `${internal}/agent%2Frun%3A1`);
});

test("session hard delete does not audit a receipt for a different request", async (t) => {
  const { tenant, app, pipeline, path, audits } = await setup(t);
  pipeline.state.reply = () => ({ status: 200, body: receipt(tenant.organizationId, { requestId: "someone-else" }) });
  const result = await app.api(path, { method: "DELETE", token: tenant.ownerToken });
  assert.equal(result.status, 200);
  assert.equal(result.body.requestId, "someone-else");
  assert.equal(result.body.audit, null);
  assert.deepEqual((await audits()).map((event) => event.action), ["session.hard_delete.requested"]);
});

test("the same session id in another source is a separate erasure", async (t) => {
  const { tenant, app, pipeline, base, path } = await setup(t);
  pipeline.state.reply = () => ({ status: 200, body: receipt(tenant.organizationId) });
  await app.api(path, { method: "DELETE", token: tenant.ownerToken });
  await app.api(`${base}?workspaceId=${tenant.workspaceId}&source=claude`, { method: "DELETE", token: tenant.ownerToken });
  assert.notEqual(pipeline.calls[0]!.body.requestId, pipeline.calls[1]!.body.requestId);
  const rows = await app.database.query(
    `SELECT source FROM selfhost_session_erasures WHERE organization_id = $1 ORDER BY source`, [tenant.organizationId],
  );
  assert.deepEqual(rows.rows.map((row) => row.source), ["claude", "codex"]);
});

test("session hard delete: unknown session is a 404 and leaves no erasure behind", async (t) => {
  const { tenant, app, pipeline, path, erasure, audits } = await setup(t);
  pipeline.state.reply = () => ({ status: 404, body: { error: "session_not_found" } });
  const missing = await app.api(path, { method: "DELETE", token: tenant.ownerToken });
  assert.equal(missing.status, 404);
  assert.equal(missing.body.error, "session_not_found");
  const rows = await app.database.query(
    `SELECT 1 FROM selfhost_session_erasures WHERE organization_id = $1`, [tenant.organizationId],
  );
  assert.equal(rows.rows.length, 0);
  assert.deepEqual((await audits()).map((event) => event.action), ["session.hard_delete.requested"]);

  pipeline.state.reply = () => ({ status: 404, body: { error: "erasure_not_found" } });
  const read = await app.api(erasure, { token: tenant.ownerToken });
  assert.equal(read.status, 404);
  assert.equal(read.body.error, "erasure_not_found");
});

test("session hard delete is served under the cloud prefix with cookie CSRF protection", async (t) => {
  const { tenant, app, pipeline, path } = await setup(t);
  pipeline.state.reply = () => ({ status: 200, body: receipt(tenant.organizationId) });
  const cloud = await app.api(`/cloud${path}`, { method: "DELETE", token: tenant.ownerToken });
  assert.equal(cloud.status, 200);

  const cookie = `agent_relay_session=${tenant.ownerToken}`;
  const calls = pipeline.calls.length;
  const attempts: Array<Record<string, string>> = [
    { cookie, origin: "https://attacker.example" },
    { cookie },
    { cookie, origin: "null" },
  ];
  for (const headers of attempts) {
    const refused = await app.api(`/cloud${path}`, { method: "DELETE", headers });
    assert.equal(refused.status, 403);
    assert.equal(refused.body.error, "csrf_rejected");
  }
  assert.equal(pipeline.calls.length, calls);

  const allowed = await app.api(`/cloud${path}`, { method: "DELETE", headers: { cookie, origin: ORIGIN } });
  assert.equal(allowed.status, 200);
  assert.equal(pipeline.calls.length, calls + 1);
});
