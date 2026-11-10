// Analytics collector runtime: request handling, authorization, validation,
// limits, producer isolation, the adapter end to end, and shutdown. Storage
// recovery, retention and fault injection are in analytics-collector-storage.test.ts.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { request as httpRequest } from "node:http";
import { connect } from "node:net";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { projectEvent } from "../src/analytics/events.js";
import { createCollectorSink } from "../src/analytics/sinks/collector.js";
import { ANALYTICS_BATCH_SCHEMA } from "../src/analytics/types.js";
import { COLLECTOR_REGISTRIES } from "../src/analytics-collector/registries.js";
import {
  createProducerRegistry,
  loadCollectorConfig,
  loadProducers,
} from "../src/analytics-collector/index.js";
import {
  batch,
  DEPLOYMENT_A,
  DEPLOYMENT_B,
  dirState,
  faultyFs,
  installEvent,
  post,
  readSegments,
  setup,
  tenantEvent,
  TOKEN_A,
  TOKEN_B,
  tempDir,
  workspaceEvent,
} from "./support/collector.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));

// ---------------------------------------------------------------------------
// Configuration and producer registry

test("config: defaults, required variables and bounds name the variable only", () => {
  const base = {
    ANALYTICS_COLLECTOR_PORT: "8080",
    ANALYTICS_COLLECTOR_DATA_DIR: "/data",
    ANALYTICS_COLLECTOR_PRODUCERS_FILE: "/etc/producers.json",
  };
  const config = loadCollectorConfig(base);
  assert.equal(config.host, "127.0.0.1");
  assert.equal(config.port, 8080);
  assert.equal(config.maxBatchBytes, 262_144);
  assert.equal(config.maxBatchEvents, 500);
  assert.equal(config.maxEventBytes, 4096);
  assert.equal(config.requestTimeoutMs, 10_000);
  assert.equal(config.maxInFlight, 16);
  assert.equal(config.maxSegments, 100_000);
  assert.equal(config.maxDiskBytes, 1_073_741_824);
  assert.equal(config.retention, "reject-new");
  assert.equal(config.retentionMaxAgeMs, null);
  assert.equal(config.shutdownDeadlineMs, 5000);

  for (const missing of Object.keys(base)) {
    const env: Record<string, string> = { ...base };
    delete env[missing];
    assert.throws(() => loadCollectorConfig(env), new RegExp(`^Error: ${missing} is required$`));
  }
  const bad: Array<[string, string]> = [
    ["ANALYTICS_COLLECTOR_PORT", "70000"],
    ["ANALYTICS_COLLECTOR_MAX_BATCH_BYTES", "99999999999"],
    ["ANALYTICS_COLLECTOR_MAX_BATCH_EVENTS", "-7"],
    ["ANALYTICS_COLLECTOR_MAX_EVENT_BYTES", "1e3"],
    ["ANALYTICS_COLLECTOR_REQUEST_TIMEOUT_MS", "-5"],
    ["ANALYTICS_COLLECTOR_MAX_IN_FLIGHT", "0x10"],
    ["ANALYTICS_COLLECTOR_MAX_SEGMENTS", "-3"],
    ["ANALYTICS_COLLECTOR_MAX_DISK_BYTES", "1024"],
    ["ANALYTICS_COLLECTOR_SHUTDOWN_DEADLINE_MS", "600001"],
  ];
  for (const [name, value] of bad) {
    assert.throws(
      () => loadCollectorConfig({ ...base, [name]: value }),
      (error: Error) => error.message.startsWith(`${name} must be an integer from`) && !error.message.includes(value),
      name,
    );
  }
  assert.throws(() => loadCollectorConfig({ ...base, ANALYTICS_COLLECTOR_RETENTION: "forever" }), /RETENTION must be/);
  assert.throws(
    () => loadCollectorConfig({ ...base, ANALYTICS_COLLECTOR_RETENTION_MAX_AGE_MS: "86400000" }),
    /RETENTION_MAX_AGE_MS requires ANALYTICS_COLLECTOR_RETENTION=delete-oldest-closed/,
  );
  assert.equal(
    loadCollectorConfig({
      ...base,
      ANALYTICS_COLLECTOR_RETENTION: "delete-oldest-closed",
      ANALYTICS_COLLECTOR_RETENTION_MAX_AGE_MS: "86400000",
    }).retentionMaxAgeMs,
    86_400_000,
  );
  assert.throws(
    () => loadCollectorConfig({ ...base, ANALYTICS_COLLECTOR_MAX_EVENT_BYTES: "8192", ANALYTICS_COLLECTOR_MAX_BATCH_BYTES: "4096" }),
    /MAX_EVENT_BYTES must not exceed/,
  );
  assert.throws(() => loadCollectorConfig({ ...base, ANALYTICS_COLLECTOR_HOST: "bad host" }), /HOST must be/);
});

test("producers: loaded once from token files; duplicates and bad tokens are startup errors that never echo a token", async (t) => {
  const dir = await tempDir(t);
  const tokenFile = async (name: string, value: string): Promise<string> => {
    const path = join(dir, name);
    await writeFile(path, `${value}\n`);
    return path;
  };
  const fileA = await tokenFile("a.token", TOKEN_A);
  const fileB = await tokenFile("b.token", TOKEN_B);
  const write = async (entries: unknown): Promise<string> => {
    const path = join(dir, `producers-${randomUUID()}.json`);
    await writeFile(path, JSON.stringify(entries));
    return path;
  };
  const entry = (name: string, deployment: string, tokenFilePath: string) =>
    ({ name, component: "relaycontrol", deployment_id: deployment, token_file: tokenFilePath });

  const registry = loadProducers(await write([entry("control-a", DEPLOYMENT_A, fileA), entry("control-b", DEPLOYMENT_B, fileB)]));
  assert.equal(registry.authenticate(TOKEN_A)?.name, "control-a");
  assert.equal(registry.authenticate(TOKEN_B)?.name, "control-b");
  assert.equal(registry.authenticate(`${TOKEN_A}x`), null);
  assert.equal(registry.authenticate(TOKEN_A.toUpperCase()), null, "tokens are case-sensitive");
  const described = JSON.stringify(registry.describe());
  assert.ok(!described.includes(TOKEN_A) && !described.includes(TOKEN_B));
  assert.deepEqual(registry.describe()[0], { name: "control-a", component: "relaycontrol", deployment_id: DEPLOYMENT_A });

  const failures: Array<[unknown, RegExp]> = [
    [[entry("control-a", DEPLOYMENT_A, fileA), entry("control-a", DEPLOYMENT_B, fileB)], /duplicate producer name/],
    [[entry("control-a", DEPLOYMENT_A, fileA), entry("control-b", DEPLOYMENT_A, fileB)], /duplicate component and deployment_id/],
    [[entry("control-a", DEPLOYMENT_A, fileA), entry("control-b", DEPLOYMENT_B, fileA)], /token is shared/],
    [[entry("control-a", DEPLOYMENT_A, await tokenFile("short.token", "too-short"))], /token must be 32 to 512 bytes/],
    [[entry("control-a", DEPLOYMENT_A, await tokenFile("long.token", "x".repeat(513)))], /token must be 32 to 512 bytes/],
    [[entry("control-a", DEPLOYMENT_A, join(dir, "missing.token"))], /token_file is not readable/],
    [[{ ...entry("control-a", DEPLOYMENT_A, fileA), token: TOKEN_A }], /unknown key/],
    [[entry("control-a", "bad id!", fileA)], /deployment_id is not an opaque identifier/],
    [[], /at least one producer/],
    [{ producers: [] }, /JSON array/],
  ];
  for (const [entries, pattern] of failures) {
    const path = await write(entries);
    assert.throws(
      () => loadProducers(path),
      (error: Error) => pattern.test(error.message) && !error.message.includes(TOKEN_A) && !error.message.includes(TOKEN_B),
      pattern.source,
    );
  }
  const notJson = join(dir, "broken.json");
  await writeFile(notJson, "{");
  assert.throws(() => loadProducers(notJson), /^Error: ANALYTICS_COLLECTOR_PRODUCERS_FILE must name a readable JSON file$/);
});

test("a producer whose component has no registry is a startup error", async (t) => {
  await assert.rejects(
    setup(t, {
      producers: createProducerRegistry([{ name: "other", component: "relayhistory", deploymentId: DEPLOYMENT_A, token: TOKEN_A }]),
    }),
    /producer other: component has no registered event kinds/,
  );
});

// ---------------------------------------------------------------------------
// Routing and media type

test("routing: unknown paths 404, wrong methods 405, non-JSON 415, health is GET only", async (t) => {
  const ctx = await setup(t);
  assert.equal((await fetch(`${ctx.origin}/nope`)).status, 404);
  const get = await fetch(`${ctx.origin}/v1/events`);
  assert.equal(get.status, 405);
  assert.equal(get.headers.get("allow"), "POST");
  assert.deepEqual(await get.json(), { error: "method_not_allowed" });
  const healthPost = await fetch(`${ctx.origin}/healthz`, { method: "POST" });
  assert.equal(healthPost.status, 405);
  const text = await post(ctx.origin, batch([installEvent()]), { token: TOKEN_A, contentType: "text/plain" });
  assert.equal(text.status, 415);
  assert.deepEqual(text.body, { error: "unsupported_media_type" });
  const charset = await post(ctx.origin, batch([installEvent()]), { token: TOKEN_A, contentType: "application/json; charset=utf-8" });
  assert.equal(charset.status, 204);
  const health = await fetch(`${ctx.origin}/healthz`);
  assert.equal(health.status, 200);
  const body = await health.json() as Record<string, any>;
  assert.deepEqual(Object.keys(body).sort(), [
    "accepted", "disk_bytes", "ok", "producers", "rejected", "retention_loss", "segments", "write_failures",
  ]);
  assert.equal(body.ok, true);
  assert.deepEqual(Object.keys(body.rejected).sort(), ["busy", "capacity", "forbidden", "invalid", "oversize", "timeout", "unauthorized"]);
  assert.deepEqual(body.producers["control-a"], { accepted_batches: 1, rejected: 0 });
  assert.deepEqual(body.accepted, { batches: 1, events: 1 });
});

// ---------------------------------------------------------------------------
// Authorization

/** Sends a request over a raw socket so the header lines are exactly as given. */
function rawPost(origin: string, headerLines: string[], body: string): Promise<{ status: number; headers: string; body: string }> {
  const { port } = new URL(origin);
  return new Promise((resolve, reject) => {
    const socket = connect(Number(port), "127.0.0.1");
    let data = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => data += chunk);
    socket.on("error", reject);
    socket.on("close", () => {
      const [head = "", ...rest] = data.split("\r\n\r\n");
      const status = Number(/^HTTP\/1\.1 (\d{3})/.exec(head)?.[1] ?? 0);
      resolve({ status, headers: head, body: rest.join("\r\n\r\n") });
    });
    socket.write([
      "POST /v1/events HTTP/1.1",
      "Host: 127.0.0.1",
      "Content-Type: application/json",
      `Content-Length: ${Buffer.byteLength(body)}`,
      "Connection: close",
      ...headerLines,
      "",
      body,
    ].join("\r\n"));
  });
}

test("missing, malformed, unknown and duplicate Authorization are 401 with WWW-Authenticate and write nothing", async (t) => {
  const ctx = await setup(t);
  const before = await dirState(ctx.dataDir);
  const body = JSON.stringify(batch([installEvent()]));
  const cases: Array<[string, string[]]> = [
    ["missing", []],
    ["empty", ["Authorization: "]],
    ["basic scheme", [`Authorization: Basic ${TOKEN_A}`]],
    ["no scheme", [`Authorization: ${TOKEN_A}`]],
    ["two tokens", [`Authorization: Bearer ${TOKEN_A} ${TOKEN_A}`]],
    ["unknown token", [`Authorization: Bearer ${"z".repeat(40)}`]],
    ["prefix of a token", [`Authorization: Bearer ${TOKEN_A.slice(0, -1)}`]],
    ["duplicate, same case", [`Authorization: Bearer ${TOKEN_A}`, `Authorization: Bearer ${TOKEN_A}`]],
    ["duplicate, mixed case", [`Authorization: Bearer ${TOKEN_A}`, `authorization: Bearer ${TOKEN_A}`]],
    ["duplicate, valid then bogus", [`Authorization: Bearer ${TOKEN_A}`, "AUTHORIZATION: Bearer nope"]],
    ["duplicate, two producers", [`Authorization: Bearer ${TOKEN_A}`, `Authorization: Bearer ${TOKEN_B}`]],
  ];
  for (const [label, lines] of cases) {
    const response = await rawPost(ctx.origin, lines, body);
    assert.equal(response.status, 401, label);
    assert.match(response.headers, /\r\nWWW-Authenticate: Bearer\r\n/i, label);
    assert.deepEqual(JSON.parse(response.body), { error: "unauthorized" }, label);
    assert.ok(!response.body.includes(TOKEN_A) && !response.headers.includes(TOKEN_A), label);
  }
  // The control: one header with the same token is accepted.
  assert.equal((await rawPost(ctx.origin, [`Authorization: Bearer ${TOKEN_A}`], body)).status, 204);
  const after = await dirState(ctx.dataDir);
  assert.deepEqual(after.tmp, before.tmp);
  assert.equal(after.segments.length, before.segments.length + 1);
  const health = ctx.collector.health();
  assert.equal(health.rejected.unauthorized, cases.length);
  assert.deepEqual(health.producers["control-a"], { accepted_batches: 1, rejected: 0 });
  assert.ok(!JSON.stringify(ctx.logs).includes(TOKEN_A));
});

test("a token in the query string or the body is not authentication", async (t) => {
  const ctx = await setup(t);
  const query = await fetch(`${ctx.origin}/v1/events?access_token=${TOKEN_A}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(batch([installEvent()])),
  });
  assert.equal(query.status, 401);
  const inBody = await post(ctx.origin, { ...batch([installEvent()]), token: TOKEN_A }, {});
  assert.equal(inBody.status, 401);
  assert.equal((await dirState(ctx.dataDir)).segments.length, 0);
});

// ---------------------------------------------------------------------------
// Authority and validation

test("component or deployment_id that differs from the producer registration is 403 for the whole batch", async (t) => {
  const ctx = await setup(t);
  const cases = [
    [installEvent(), installEvent({ deployment_id: DEPLOYMENT_B })],
    [installEvent({ component: "relayhistory" })],
    // Producer B's identity under producer A's token.
    [installEvent({ deployment_id: DEPLOYMENT_B })],
  ];
  for (const events of cases) {
    const response = await post(ctx.origin, batch(events), { token: TOKEN_A });
    assert.equal(response.status, 403);
    assert.deepEqual(response.body, { error: "forbidden" });
  }
  assert.deepEqual(await dirState(ctx.dataDir), { tmp: [], segments: [] });
  assert.equal(ctx.collector.health().rejected.forbidden, cases.length);
  assert.deepEqual(ctx.collector.health().producers["control-a"], { accepted_batches: 0, rejected: cases.length });
});

test("invalid batches are 400 invalid_batch (with index for an event) and write nothing", async (t) => {
  const ctx = await setup(t, { config: { maxBatchEvents: 3 } });
  const raw = (body: string | Uint8Array) => post(ctx.origin, undefined, { token: TOKEN_A, raw: body });
  const top: Array<[string, unknown]> = [
    ["wrong schema", { schema: "agent-relay.analytics.batch/v2", events: [installEvent()] }],
    ["missing schema", { events: [installEvent()] }],
    ["zero events", batch([])],
    ["events not an array", { schema: ANALYTICS_BATCH_SCHEMA, events: {} }],
    ["over MAX_BATCH_EVENTS", batch([installEvent(), installEvent(), installEvent(), installEvent()])],
    ["unknown top-level key", { ...batch([installEvent()]), extra: true }],
    ["array body", [installEvent()]],
  ];
  for (const [label, body] of top) {
    const response = await post(ctx.origin, body, { token: TOKEN_A });
    assert.equal(response.status, 400, label);
    assert.deepEqual(response.body, { error: "invalid_batch" }, label);
  }
  const malformed: Array<[string, string | Uint8Array]> = [["not JSON", "{"], ["invalid UTF-8", Buffer.from([0x7b, 0xff, 0x7d])]];
  for (const [label, body] of malformed) {
    const response = await raw(body);
    assert.equal(response.status, 400, label);
    assert.deepEqual(response.body, { error: "invalid_batch" }, label);
  }

  const { tenant_id: _tenant, ...workspaceWithoutTenant } = workspaceEvent();
  const { tenant_id: _t2, ...tenantWithoutTenant } = tenantEvent();
  const { properties: _p, ...withoutProperties } = installEvent();
  const perEvent: Array<[string, Record<string, unknown>]> = [
    ["bad event_id", installEvent({ event_id: "not-a-uuid" })],
    ["version 2", installEvent({ version: 2 })],
    ["unparsable occurred_at", installEvent({ occurred_at: "yesterday" })],
    ["impossible occurred_at", installEvent({ occurred_at: "2026-13-45T99:99:99Z" })],
    ["bad trace_id", installEvent({ trace_id: "short" })],
    ["unknown envelope key", installEvent({ user: "x" })],
    ["missing properties", withoutProperties],
    ["unregistered kind", installEvent({ event: "user.signed_up" })],
    ["installation kind with tenant_id", installEvent({ tenant_id: "org_1" })],
    ["scope substitution: workspace kind sent as tenant", workspaceWithoutTenant],
    ["scope substitution: tenant kind with workspace_id", tenantEvent({ workspace_id: "ws_1" })],
    ["missing tenant_id on a tenant kind", tenantWithoutTenant],
    ["bad tenant_id grammar", tenantEvent({ tenant_id: "org 1" })],
    ["unregistered property", installEvent({ properties: { component_version: "1.0.0", email: "a@b.c" } })],
    ["property failing its spec", installEvent({ properties: { component_version: "has space" } })],
    ["property named like an envelope field", installEvent({ properties: { deployment_id: DEPLOYMENT_A } })],
    ["property named tenant_id", workspaceEvent({ properties: { client: "dashboard", page: "overview", tenant_id: "org_2" } })],
    ["nested property value", installEvent({ properties: { component_version: { nested: true } } })],
  ];
  for (const [label, event] of perEvent) {
    const response = await post(ctx.origin, batch([installEvent(), event]), { token: TOKEN_A });
    assert.equal(response.status, 400, label);
    assert.deepEqual(response.body, { error: "invalid_batch", index: 1 }, label);
    assert.ok(!response.raw.includes("a@b.c"), label);
  }
  assert.deepEqual(await dirState(ctx.dataDir), { tmp: [], segments: [] });
  const health = ctx.collector.health();
  assert.equal(health.rejected.invalid, top.length + 2 + perEvent.length);
  assert.equal(health.accepted.batches, 0);
});

test("a streamed body over MAX_BATCH_BYTES is 413 before the upload ends; a declared one at once", async (t) => {
  const ctx = await setup(t, { config: { maxBatchBytes: 32 * 1024 } });
  // Chunked upload, no Content-Length: the cap can only be enforced on the
  // bytes read. The request is never ended, so a 413 proves the collector
  // stopped reading at the cap instead of buffering the whole body.
  const result = await new Promise<{ status: number; body: string; written: number }>((resolve, reject) => {
    let written = 0;
    let timer: NodeJS.Timeout | undefined;
    const outgoing = httpRequest(new URL("/v1/events", ctx.origin), {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN_A}`, "content-type": "application/json" },
    }, (response) => {
      clearInterval(timer);
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => body += chunk);
      response.on("end", () => {
        resolve({ status: response.statusCode ?? 0, body, written });
        outgoing.destroy();
      });
    });
    outgoing.on("error", (error) => {
      clearInterval(timer);
      reject(error);
    });
    assert.equal(outgoing.getHeader("content-length"), undefined);
    const chunk = Buffer.alloc(1024, "a");
    outgoing.write(`{"schema":"${ANALYTICS_BATCH_SCHEMA}","pad":"`);
    timer = setInterval(() => {
      if (written > 1024 * 1024) {
        clearInterval(timer);
        reject(new Error("no early 413"));
        outgoing.destroy();
        return;
      }
      outgoing.write(chunk);
      written += chunk.length;
    }, 1);
  });
  assert.equal(result.status, 413);
  assert.deepEqual(JSON.parse(result.body), { error: "payload_too_large" });
  assert.ok(result.written >= 31 * 1024, `answered after ${result.written} bytes`);
  assert.ok(result.written < 1024 * 1024);

  const declared = await post(ctx.origin, undefined, { token: TOKEN_A, raw: "x".repeat(33 * 1024) });
  assert.equal(declared.status, 413);
  assert.deepEqual(declared.body, { error: "payload_too_large" });
  assert.deepEqual(await dirState(ctx.dataDir), { tmp: [], segments: [] });
  assert.equal(ctx.collector.health().rejected.oversize, 2);
});

test("an event whose canonical line exceeds MAX_EVENT_BYTES is 413 event_too_large with its index", async (t) => {
  const ctx = await setup(t, { config: { maxEventBytes: 400 } });
  const small = installEvent();
  // A long trace_id stays within the grammar (<= 128) but pushes the line past 400 bytes.
  const big = workspaceEvent({ trace_id: "t".repeat(128), tenant_id: "o".repeat(100), workspace_id: "w".repeat(100) });
  const response = await post(ctx.origin, batch([small, small, big]), { token: TOKEN_A });
  assert.equal(response.status, 413);
  assert.deepEqual(response.body, { error: "event_too_large", index: 2 });
  assert.deepEqual(await dirState(ctx.dataDir), { tmp: [], segments: [] });
  assert.equal(ctx.collector.health().rejected.oversize, 1);
  assert.equal((await post(ctx.origin, batch([small]), { token: TOKEN_A })).status, 204);
});

test("a body not completed within REQUEST_TIMEOUT_MS is 408 timeout and writes nothing", async (t) => {
  const ctx = await setup(t, { config: { requestTimeoutMs: 200 } });
  const result = await new Promise<{ status: number; body: string }>((resolve, reject) => {
    const outgoing = httpRequest(new URL("/v1/events", ctx.origin), {
      method: "POST",
      headers: { authorization: `Bearer ${TOKEN_A}`, "content-type": "application/json" },
    }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("data", (chunk) => body += chunk);
      response.on("end", () => {
        resolve({ status: response.statusCode ?? 0, body });
        outgoing.destroy();
      });
    });
    outgoing.on("error", reject);
    outgoing.write(`{"schema":"${ANALYTICS_BATCH_SCHEMA}",`);
  });
  assert.equal(result.status, 408);
  assert.deepEqual(JSON.parse(result.body), { error: "timeout" });
  assert.deepEqual(await dirState(ctx.dataDir), { tmp: [], segments: [] });
  assert.equal(ctx.collector.health().rejected.timeout, 1);
});

// ---------------------------------------------------------------------------
// Acceptance

test("a valid batch is 204 with an empty body: exactly one new segment whose lines equal the events, tmp/ empty", async (t) => {
  const ctx = await setup(t);
  const events = [installEvent(), workspaceEvent(), tenantEvent()];
  const response = await post(ctx.origin, batch(events), { token: TOKEN_A });
  assert.equal(response.status, 204);
  assert.equal(response.raw, "");
  const state = await dirState(ctx.dataDir);
  assert.deepEqual(state.tmp, []);
  assert.equal(state.segments.length, 1);
  assert.match(state.segments[0]!, /^\d{13}-0000000001-[0-9a-f-]{36}\.ndjson$/);
  const content = await readFile(join(ctx.dataDir, "segments", state.segments[0]!), "utf8");
  assert.ok(content.endsWith("\n"));
  const lines = content.trimEnd().split("\n");
  assert.deepEqual(lines.map((line) => JSON.parse(line)), events);
  // Canonical key order is the envelope's.
  assert.deepEqual(Object.keys(JSON.parse(lines[1]!)), [
    "version", "event_id", "occurred_at", "component", "deployment_id", "event", "trace_id", "tenant_id", "workspace_id", "properties",
  ]);
  const health = ctx.collector.health();
  assert.equal(health.segments, 1);
  assert.equal(health.disk_bytes, Buffer.byteLength(content));
  assert.deepEqual(health.accepted, { batches: 1, events: 3 });
});

test("session-brief: its installation-scoped tick is accepted and the vocabulary is closed per component", async (t) => {
  const ctx = await setup(t, {
    registries: COLLECTOR_REGISTRIES,
    producers: createProducerRegistry([{ name: "brief-a", component: "session-brief", deploymentId: DEPLOYMENT_A, token: TOKEN_A }]),
  });
  const tick = (overrides: Record<string, unknown> = {}) => installEvent({
    component: "session-brief",
    event: "session_brief.tick_completed",
    properties: {
      claimed: 3, generated: 2, reused: 1, rate_limited: 0, throttled: 0, retrying: 0, failed: 0, latency_bucket: "lt_1s",
    },
    ...overrides,
  });
  assert.equal((await post(ctx.origin, batch([tick()]), { token: TOKEN_A })).status, 204);
  const scoped = await post(ctx.origin, batch([tick({ tenant_id: "org_synthetic", workspace_id: "ws_synthetic" })]), { token: TOKEN_A });
  assert.equal(scoped.status, 400);
  assert.deepEqual(scoped.body, { error: "invalid_batch", index: 0 });
  const extra = await post(ctx.origin, batch([tick({
    properties: {
      claimed: 3, generated: 2, reused: 1, rate_limited: 0, throttled: 0, retrying: 0, failed: 0, latency_bucket: "lt_1s", session_id: "abc",
    },
  })]), { token: TOKEN_A });
  assert.equal(extra.status, 400);
  assert.deepEqual(extra.body, { error: "invalid_batch", index: 0 });
  const foreign = await post(ctx.origin, batch([tick({
    event: "session_pipeline.index_tick_completed",
    properties: { collected: 1, failed: 0, requeued: 0, stale: 0, tombstoned: 0, complete: true, latency_bucket: "lt_1s" },
  })]), { token: TOKEN_A });
  assert.equal(foreign.status, 400);
  assert.deepEqual(foreign.body, { error: "invalid_batch", index: 0 });
  assert.equal((await readSegments(ctx.dataDir)).length, 1);
});

test("session-read-api: the coordination overlaps route is accepted", async (t) => {
  const ctx = await setup(t, {
    registries: COLLECTOR_REGISTRIES,
    producers: createProducerRegistry([{ name: "read-a", component: "session-read-api", deploymentId: DEPLOYMENT_A, token: TOKEN_A }]),
  });
  const event = installEvent({
    component: "session-read-api",
    event: "session_read.request_completed",
    tenant_id: "org_synthetic",
    workspace_id: "ws_synthetic",
    properties: { route: "/v1/coordination/overlaps", outcome: "served", status_class: "2xx", latency_bucket: "lt_250ms" },
  });
  assert.equal((await post(ctx.origin, batch([event]), { token: TOKEN_A })).status, 204);
});

test("busy gate: beyond MAX_IN_FLIGHT is 429 busy with Retry-After", async (t) => {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => release = resolve);
  let entered!: () => void;
  const inCommit = new Promise<void>((resolve) => entered = resolve);
  const ctx = await setup(t, {
    config: { maxInFlight: 1 },
    fsImpl: faultyFs({ sync: async (path) => {
      if (path.endsWith(".part")) {
        entered();
        await gate;
      }
    } }),
  });
  const first = post(ctx.origin, batch([installEvent()]), { token: TOKEN_A });
  await inCommit;
  const second = await post(ctx.origin, batch([installEvent({ deployment_id: DEPLOYMENT_B })]), { token: TOKEN_B });
  assert.equal(second.status, 429);
  assert.equal(second.headers.get("retry-after"), "1");
  assert.deepEqual(second.body, { error: "busy" });
  release();
  assert.equal((await first).status, 204);
  const health = ctx.collector.health();
  assert.equal(health.rejected.busy, 1);
  assert.deepEqual(health.producers["control-b"], { accepted_batches: 0, rejected: 1 });
  assert.equal(health.segments, 1);
});

test("producer isolation: producer A's 401/403/413 traffic leaves producer B's batch and counters unaffected", async (t) => {
  const ctx = await setup(t, { config: { maxBatchBytes: 4096 } });
  assert.equal((await post(ctx.origin, batch([installEvent()]), { token: `${TOKEN_A}-revoked` })).status, 401);
  assert.equal((await post(ctx.origin, batch([installEvent({ deployment_id: DEPLOYMENT_B })]), { token: TOKEN_A })).status, 403);
  assert.equal((await post(ctx.origin, undefined, { token: TOKEN_A, raw: "x".repeat(5000) })).status, 413);
  const eventB = installEvent({ deployment_id: DEPLOYMENT_B });
  assert.equal((await post(ctx.origin, batch([eventB]), { token: TOKEN_B })).status, 204);
  const health = ctx.collector.health();
  assert.deepEqual(health.producers["control-b"], { accepted_batches: 1, rejected: 0 });
  assert.deepEqual(health.producers["control-a"], { accepted_batches: 0, rejected: 2 });
  assert.equal(health.rejected.unauthorized, 1);
  assert.deepEqual(health.accepted, { batches: 1, events: 1 });
  const segments = await readSegments(ctx.dataDir);
  assert.equal(segments.length, 1);
  assert.deepEqual(segments[0]!.events, [eventB]);
});

test("end to end: the adapter's createCollectorSink delivers projected envelopes and gets accepted; the segment holds the trace", async (t) => {
  const ctx = await setup(t);
  const traceId = `trace-${randomUUID()}`;
  const context = { deploymentId: DEPLOYMENT_A, traceId, now: Date.now };
  const started = projectEvent({ event: "service_started", properties: { component_version: "0.1.0" } }, context);
  const viewed = projectEvent({
    event: "dashboard.page_viewed",
    properties: { client: "dashboard", page: "overview" },
    tenantId: "org_synthetic",
    workspaceId: "ws_synthetic",
  }, context);
  const sink = createCollectorSink({ url: `${ctx.origin}/v1/events`, token: TOKEN_A });
  assert.deepEqual(await sink.send([started, viewed], AbortSignal.timeout(5000)), { outcome: "accepted" });

  const segments = await readSegments(ctx.dataDir);
  assert.equal(segments.length, 1);
  assert.deepEqual(segments[0]!.events, [started, viewed]);
  assert.deepEqual(segments[0]!.events.map((event) => event.event_id), [started.event_id, viewed.event_id]);
  assert.ok(segments[0]!.events.every((event) => event.trace_id === traceId));

  // The adapter classifies the collector's refusals as the contract says.
  const foreign = projectEvent({ event: "service_started" }, { ...context, deploymentId: DEPLOYMENT_B });
  assert.deepEqual(await sink.send([foreign], AbortSignal.timeout(5000)), { outcome: "auth", status: 403 });
  const wrongToken = createCollectorSink({ url: `${ctx.origin}/v1/events`, token: "w".repeat(40) });
  assert.deepEqual(await wrongToken.send([started], AbortSignal.timeout(5000)), { outcome: "auth", status: 401 });
  assert.equal((await readSegments(ctx.dataDir)).length, 1);
});

// ---------------------------------------------------------------------------
// Shutdown

test("shutdown: an in-flight commit completes and is acknowledged, then the server closes within the deadline", async (t) => {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => release = resolve);
  let entered!: () => void;
  const inCommit = new Promise<void>((resolve) => entered = resolve);
  const ctx = await setup(t, {
    fsImpl: faultyFs({ sync: async (path) => {
      if (path.endsWith(".part")) {
        entered();
        await gate;
      }
    } }),
  });
  const pending = post(ctx.origin, batch([installEvent()]), { token: TOKEN_A });
  await inCommit;
  const startedAt = Date.now();
  const stopping = ctx.collector.shutdown(2000);
  setTimeout(release, 50);
  const response = await pending;
  assert.equal(response.status, 204);
  assert.deepEqual(await stopping, { completed: true });
  assert.ok(Date.now() - startedAt < 2000);
  assert.equal(ctx.collector.server.listening, false);
  assert.equal((await dirState(ctx.dataDir)).segments.length, 1);
  await assert.rejects(fetch(`${ctx.origin}/healthz`));
});

test("CLI: SIGTERM after a commit exits 0 within SHUTDOWN_DEADLINE_MS and logs no token", async (t) => {
  const dir = await tempDir(t);
  const dataDir = join(dir, "data");
  await import("node:fs/promises").then((fs) => fs.mkdir(dataDir));
  const tokenFile = join(dir, "a.token");
  await writeFile(tokenFile, TOKEN_A);
  const producersFile = join(dir, "producers.json");
  await writeFile(producersFile, JSON.stringify([
    { name: "control-a", component: "relaycontrol", deployment_id: DEPLOYMENT_A, token_file: tokenFile },
  ]));
  const child = spawn(process.execPath, ["--import", "tsx", "src/collector-cli.ts"], {
    cwd: ROOT,
    env: {
      PATH: process.env.PATH,
      ANALYTICS_COLLECTOR_HOST: "127.0.0.1",
      ANALYTICS_COLLECTOR_PORT: "0",
      ANALYTICS_COLLECTOR_DATA_DIR: dataDir,
      ANALYTICS_COLLECTOR_PRODUCERS_FILE: producersFile,
      ANALYTICS_COLLECTOR_SHUTDOWN_DEADLINE_MS: "2000",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  t.after(() => child.kill("SIGKILL"));
  let output = "";
  child.stderr.on("data", (chunk) => output += chunk);
  const exited = new Promise<number | null>((resolve) => child.on("exit", (code) => resolve(code)));
  const port = await new Promise<number>((resolve, reject) => {
    child.stdout.on("data", (chunk) => {
      output += chunk;
      const match = /listening[\s\S]*port: (\d+)/.exec(output);
      if (match) resolve(Number(match[1]));
    });
    void exited.then(() => reject(new Error(`collector exited early: ${output}`)));
  });
  const response = await post(`http://127.0.0.1:${port}`, batch([installEvent()]), { token: TOKEN_A });
  assert.equal(response.status, 204);
  const startedAt = Date.now();
  child.kill("SIGTERM");
  assert.equal(await exited, 0);
  assert.ok(Date.now() - startedAt < 3000);
  assert.match(output, /shutting down/);
  assert.ok(!output.includes(TOKEN_A));
  assert.equal((await dirState(dataDir)).segments.length, 1);
});

test("CLI: a startup error names the variable and exits non-zero", async () => {
  const child = spawn(process.execPath, ["--import", "tsx", "src/collector-cli.ts"], {
    cwd: ROOT,
    env: { PATH: process.env.PATH, ANALYTICS_COLLECTOR_PORT: "0" },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  child.stdout.on("data", (chunk) => output += chunk);
  child.stderr.on("data", (chunk) => output += chunk);
  const code = await new Promise<number | null>((resolve) => child.on("exit", resolve));
  assert.equal(code, 1);
  assert.match(output, /ANALYTICS_COLLECTOR_DATA_DIR is required/);
});

