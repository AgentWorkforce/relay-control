import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { BOOTSTRAP, close, listen, seedTenant, startControlPlane } from "./flows-helpers.js";

const SECRET = "session-erase-secret-that-is-at-least-32-bytes";
const ORIGIN = "https://control.selfhosted.company";
const SESSION = "ses_01-abc";
const SOURCE = "codex";
/** Replaced by the fake pipeline with the request id Control last sent. */
const ECHO_REQUEST = "echo-the-request-id";
const ARTIFACTS = Object.fromEntries([
  "transcriptObjects", "stagedObjects", "bufferedBatches", "bufferedRows", "pointerRows", "ledgerRows",
  "directoryRows", "catalogRows", "largeReadJobs", "searchDocuments", "briefDocuments", "summaries", "briefs",
  "replayPublications", "analysisPublications", "historyDerivedObjects",
].map((key) => [key, { count: 1, state: "done" }]));

/** `raw` is sent verbatim instead of the JSON-serialized `body`. */
type Reply = { status: number; body: unknown; raw?: string; headers?: Record<string, string> };
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
      if (reply.raw !== undefined) {
        response.writeHead(reply.status, { "content-type": "application/json", ...reply.headers });
        response.end(reply.raw);
        return;
      }
      const body = reply.body as Record<string, unknown>;
      const segments = call.path.split("/").map(decodeURIComponent);
      const echoed = body && typeof body === "object" && "orgId" in body
        ? {
            workspaceId: segments[7],
            source: segments[9],
            ...body,
            requestId: body.requestId === ECHO_REQUEST ? requestId : body.requestId,
          }
        : body;
      response.writeHead(reply.status, { "content-type": "application/json", ...reply.headers });
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
    artifacts: ARTIFACTS,
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
    `SELECT action, actor_id, target FROM admin_audit_events
      WHERE organization_id = $1 AND action LIKE 'session.hard_%' ORDER BY created_at, action`,
    [tenant.organizationId],
  )).rows;
  return { app, tenant, pipeline, base, path, erasure, internal, query, audits };
}

test("session hard delete stays 501 until the pipeline erase is configured", async (t) => {
  const app = await startControlPlane();
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  for (const endpoint of ["/api/v1/capabilities", "/cloud/api/v1/capabilities", "/readyz"]) {
    const read = await app.api(endpoint, { token: tenant.ownerToken });
    assert.equal(read.status, 200);
    assert.equal(read.body.capabilities.session_delete, false, endpoint);
  }
  const path = `/api/v1/organizations/${tenant.organizationId}/sessions/${SESSION}`;
  for (const [route, method] of [[path, "DELETE"], [`${path}/erasure`, "GET"]] as const) {
    const result = await app.api(route, { method, token: tenant.ownerToken });
    assert.equal(result.status, 501);
    assert.equal(result.body.error, "not_implemented");
  }
  const rows = await app.database.query(`SELECT 1 FROM admin_audit_events WHERE action LIKE 'session.hard_%'`);
  assert.equal(rows.rows.length, 0);
});

test("session_delete advertises configuration and the write gate, without probing or erasing", async (t) => {
  const previous = process.env.SELFHOST_OPERATOR_CONTROLS;
  process.env.SELFHOST_OPERATOR_CONTROLS = "always";
  t.after(() => {
    if (previous === undefined) delete process.env.SELFHOST_OPERATOR_CONTROLS;
    else process.env.SELFHOST_OPERATOR_CONTROLS = previous;
  });
  const { app, tenant, pipeline, audits } = await setup(t);
  // The pipeline defaults to 503: discovery reports wiring, not health,
  // and never contacts the upstream or creates an erase/audit record.
  for (const token of [tenant.ownerToken, tenant.memberToken]) {
    for (const endpoint of ["/api/v1/capabilities", "/readyz"]) {
      const read = await app.api(endpoint, { token });
      assert.equal(read.status, 200);
      assert.equal(read.body.capabilities.session_delete, true, endpoint);
      assert.equal(JSON.stringify(read.body).includes(SECRET), false);
      assert.equal(JSON.stringify(read.body.capabilities).includes(pipeline.url), false);
    }
  }
  const cookie = await app.api("/cloud/api/v1/capabilities", {
    headers: { cookie: `agent_relay_session=${tenant.ownerToken}` },
  });
  assert.equal(cookie.status, 200);
  assert.equal(cookie.body.capabilities.session_delete, true);
  assert.equal(cookie.headers.get("cache-control"), "no-store");
  assert.equal((await app.api("/api/v1/capabilities")).status, 401);

  for (const mode of ["off", "invalid"]) {
    process.env.SELFHOST_OPERATOR_CONTROLS = mode;
    for (const endpoint of ["/api/v1/capabilities", "/readyz"]) {
      const read = await app.api(endpoint, { token: tenant.ownerToken });
      assert.equal(read.body.capabilities.session_delete, false, mode);
    }
  }
  assert.equal(pipeline.calls.length, 0);
  assert.equal((await audits()).length, 0);
});

test("session hard delete: owner erases, audits once, repeat is idempotent, membership kept", async (t) => {
  const { app, tenant, pipeline, path, internal, audits } = await setup(t);
  pipeline.state.reply = () => ({ status: 200, body: receipt(tenant.organizationId) });
  const members = async () => (await app.database.query(
    `SELECT 1 FROM organization_memberships WHERE organization_id = $1`, [tenant.organizationId],
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

  for (const id of ["a\u0001b", " padded ", "x".repeat(513), "é".repeat(257)]) {
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
    [{ status: 200, body: receipt(org, { artifacts: { ...ARTIFACTS, ledgerRows: { count: 1, state: "pending" } } }) }, 502, "invalid_session_erasure_response"],
    [{ status: 200, body: receipt(org, { artifacts: { ledgerRows: { count: 1, state: "done" } } }) }, 502, "invalid_session_erasure_response"],
    [{ status: 200, body: receipt(org, { artifacts: { ...ARTIFACTS, invented: { count: 0, state: "done" } } }) }, 502, "invalid_session_erasure_response"],
    [{ status: 200, body: receipt(org, { workspaceId: randomUUID() }) }, 502, "invalid_session_erasure_response"],
    [{ status: 200, body: receipt(org, { source: "another-source" }) }, 502, "invalid_session_erasure_response"],
    [{ status: 400, body: { error: "invalid_request", feature: "session_erase" } }, 502, "invalid_session_erasure_response"],
    [{ status: 401, body: { error: "invalid_token", feature: "session_erase" } }, 502, "invalid_session_erasure_response"],
    [{ status: 503, body: { error: "too_many_owners", feature: "session_erase" } }, 503, "session_erasure_unavailable"],
    [{ status: 501, body: { error: "not_implemented", feature: "session_erase" } }, 501, "not_implemented"],
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
    body: receipt(org, {
      status: "failed", completedAt: null, failure: { step: "transcriptObjects", code: "object_store_error", retryable: true },
    }),
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

test("session hard delete maps only the pipeline's exact unsupported_storage refusal to a static 503", async (t) => {
  const { tenant, app, pipeline, path, erasure } = await setup(t);
  const UNSUPPORTED = { error: "unsupported_storage", feature: "session_erase" };
  const MESSAGE = "This session cannot be erased with the current storage or ingest configuration.";
  const expectUnsupported = (result: Awaited<ReturnType<typeof app.api>>, label: string) => {
    assert.equal(result.status, 503, label);
    assert.equal(result.body.error, "session_erasure_unsupported_storage", label);
    assert.equal(result.body.message, MESSAGE, label);
    assert.equal(result.headers.get("retry-after"), null, label);
    assert.doesNotMatch(result.text, /retry/i, label);
  };

  // The erase request.
  pipeline.state.reply = () => ({ status: 503, body: UNSUPPORTED, headers: { "retry-after": "60" } });
  expectUnsupported(await app.api(path, { method: "DELETE", token: tenant.ownerToken }), "DELETE");

  // The verification read of an erase that was recorded.
  pipeline.state.reply = () => ({
    status: 202,
    body: receipt(tenant.organizationId, { status: "in_progress", completedAt: null, bytesErased: false, bytesErasedAt: null }),
  });
  assert.equal((await app.api(path, { method: "DELETE", token: tenant.ownerToken })).status, 202);
  pipeline.state.reply = () => ({ status: 503, body: UNSUPPORTED, headers: { "retry-after": "60" } });
  expectUnsupported(await app.api(erasure, { token: tenant.ownerToken }), "GET");
  assert.equal(pipeline.calls.at(-1)!.method, "GET");

  // Provider text alongside the exact shape is never echoed.
  pipeline.state.reply = () => ({ status: 503, body: { ...UNSUPPORTED, detail: "secret provider text" } });
  const detailed = await app.api(path, { method: "DELETE", token: tenant.ownerToken });
  expectUnsupported(detailed, "detail");
  assert.doesNotMatch(detailed.text, /secret provider text/);

  // Anything other than the exact shape on a 503 stays the static retryable error.
  const prefix = JSON.stringify(UNSUPPORTED).slice(0, -1);
  const oversized = `${prefix},"pad":"${"x".repeat(8_192)}"}`;
  const fallbacks: Reply[] = [
    { status: 503, body: { error: "unsupported_storage", feature: "other" } },
    { status: 503, body: { error: "unsupported_storage" } },
    { status: 503, body: { error: "UNSUPPORTED_STORAGE", feature: "session_erase" } },
    { status: 503, body: { error: "too_many_owners", feature: "session_erase" } },
    { status: 503, body: [] },
    { status: 503, body: "unsupported_storage" },
    { status: 503, body: null, raw: "not json" },
    { status: 503, body: null, raw: "" },
    { status: 503, body: null, raw: oversized },
  ];
  for (const reply of fallbacks) {
    pipeline.state.reply = () => reply;
    const label = reply.raw === undefined ? JSON.stringify(reply.body) : `raw ${reply.raw.slice(0, 40)}`;
    const result = await app.api(path, { method: "DELETE", token: tenant.ownerToken });
    assert.equal(result.status, 503, label);
    assert.equal(result.body.error, "session_erasure_unavailable", label);
    assert.equal(result.headers.get("retry-after"), null, label);
  }

  // Other 5xx statuses never read the body.
  pipeline.state.reply = () => ({ status: 501, body: UNSUPPORTED });
  const notImplemented = await app.api(path, { method: "DELETE", token: tenant.ownerToken });
  assert.equal(notImplemented.status, 501);
  assert.equal(notImplemented.body.error, "not_implemented");
  pipeline.state.reply = () => ({ status: 500, body: UNSUPPORTED });
  const serverError = await app.api(path, { method: "DELETE", token: tenant.ownerToken });
  assert.equal(serverError.status, 503);
  assert.equal(serverError.body.error, "session_erasure_unavailable");
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
    `SELECT source FROM session_erasures WHERE organization_id = $1 ORDER BY source`, [tenant.organizationId],
  );
  assert.deepEqual(rows.rows.map((row) => row.source), ["claude", "codex"]);
});

test("the bootstrap bearer is sent to the pipeline with a non-empty actor id", async (t) => {
  const { tenant, app, pipeline, path } = await setup(t);
  pipeline.state.reply = () => ({ status: 200, body: receipt(tenant.organizationId) });
  const result = await app.api(path, { method: "DELETE", token: BOOTSTRAP });
  assert.equal(result.status, 200);
  assert.deepEqual(pipeline.calls[0]!.body.actor, { kind: "bootstrap", id: "bootstrap" });
});

test("a session with nothing stored is fenced with a zero-count receipt", async (t) => {
  const { tenant, app, pipeline, path } = await setup(t);
  const empty = Object.fromEntries(Object.keys(ARTIFACTS).map((key) => [key, { count: 0, state: "not_applicable" }]));
  pipeline.state.reply = () => ({ status: 200, body: receipt(tenant.organizationId, { artifacts: empty }) });
  const result = await app.api(path, { method: "DELETE", token: tenant.ownerToken });
  assert.equal(result.status, 200);
  assert.equal(result.body.artifacts.ledgerRows.count, 0);
});

test("session hard delete: a read with no recorded erase is a 404", async (t) => {
  const { tenant, app, pipeline, erasure } = await setup(t);
  pipeline.state.reply = () => ({ status: 404, body: { error: "erasure_not_found", feature: "session_erase" } });
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
