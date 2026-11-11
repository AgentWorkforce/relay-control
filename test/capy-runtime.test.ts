import assert from "node:assert/strict";
import test from "node:test";
import { CapyRuntimeError, createCapyRuntime, DEFAULT_CAPY_MODEL } from "../src/capy/runtime.js";

const key = "capy_" + "s".repeat(32);
const thread = "jam_0123456789";
const message = { text: "hello", clientKey: "relay-message-123", delivery: "steer" as const };

test("Capy native transport uses only the provider origin, escaped ids, bearer and no redirects", async () => {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const runtime = createCapyRuntime({ fetchImpl: async (input, init = {}) => {
    calls.push({ url: String(input), init });
    return Response.json({ items: [], nextCursor: null, hasMore: false });
  } });
  assert.deepEqual(await runtime.listProjects(key, { limit: 10, cursor: "a/b?secret=value" }),
    { items: [], nextCursor: null, hasMore: false });
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.url, "https://api.capy.ai/api/v1/projects?limit=10&cursor=a%2Fb%3Fsecret%3Dvalue");
  assert.equal(calls[0]!.init.redirect, "error");
  assert.equal(calls[0]!.init.cache, "no-store");
  assert.equal(new Headers(calls[0]!.init.headers).get("authorization"), `Bearer ${key}`);
  assert.ok(calls[0]!.init.signal instanceof AbortSignal);
});

test("Capy send retries only a definitive missing-model rejection, retaining the same idempotency key", async () => {
  for (const field of ["_tag", "code"]) {
    const bodies: any[] = [];
    const runtime = createCapyRuntime({ fetchImpl: async (_input, init) => {
      bodies.push(JSON.parse(String(init!.body)));
      return bodies.length === 1 ? Response.json({ [field]: "model_not_selected" }, { status: 400 })
        : Response.json({ id: "message-1", deduped: true });
    } });
    assert.deepEqual(await runtime.sendMessage(key, thread, message), { id: "message-1", deduped: true });
    assert.equal(bodies.length, 2);
    assert.equal(bodies[0].model, undefined);
    assert.deepEqual(bodies[1], { ...bodies[0], model: { modelId: DEFAULT_CAPY_MODEL } });
    assert.equal(bodies[1].clientKey, message.clientKey);
  }
});

test("Capy thread creation preserves requestId and organization visibility", async () => {
  let body: any;
  const runtime = createCapyRuntime({ fetchImpl: async (_input, init) => {
    body = JSON.parse(String(init!.body));
    return Response.json({ id: thread, title: null, status: "active" });
  } });
  assert.equal((await runtime.createThread(key, {
    requestId: "request-1", projectId: "project-1", message: "task", model: { modelId: "my/model" },
  })).id, thread);
  assert.deepEqual(body, { requestId: "request-1", projectId: "project-1", message: "task",
    model: { modelId: "my/model" }, visibility: "org" });
});

test("Capy ambiguous writes never automatically retry or disclose upstream errors", async () => {
  for (const kind of ["network", "server", "invalid-json", "invalid-ack"]) {
    let calls = 0;
    const runtime = createCapyRuntime({ fetchImpl: async () => {
      calls++;
      if (kind === "network") throw new Error(`Authorization: Bearer ${key}`);
      if (kind === "server") return Response.json({ _tag: key, leak: key }, { status: 503 });
      if (kind === "invalid-json") return new Response(`not-json ${key}`);
      return Response.json({ id: "message-1", deduped: "false", leak: key });
    } });
    await assert.rejects(runtime.sendMessage(key, thread, message), (error: unknown) => {
      assert.ok(error instanceof CapyRuntimeError);
      assert.equal(error.outcome, "unknown");
      assert.equal(error.message.includes(key), false);
      assert.equal(JSON.stringify(error).includes(key), false);
      return true;
    });
    assert.equal(calls, 1, kind);
  }
});

test("Capy explicit model and unrelated rejection never enter missing-model fallback", async () => {
  for (const explicit of [false, true]) {
    let calls = 0;
    const runtime = createCapyRuntime({ fetchImpl: async () => {
      calls++;
      return Response.json({ _tag: explicit ? "model_not_selected" : "capy/DeviceAccessDenied", secret: key }, { status: 400 });
    } });
    await assert.rejects(runtime.sendMessage(key, thread, { ...message, ...(explicit ? { model: { modelId: "my/model" } } : {}) }),
      { outcome: "rejected", status: 400 });
    assert.equal(calls, 1);
  }
});

test("Capy rate-limit retry hint is bounded and errors do not echo provider tags", async () => {
  const runtime = createCapyRuntime({ fetchImpl: async () => Response.json({ _tag: key, retryAfterSeconds: 99_999 }, { status: 429 }) });
  await assert.rejects(runtime.sendMessage(key, thread, message), (error: unknown) => {
    assert.ok(error instanceof CapyRuntimeError);
    assert.equal(error.outcome, "rejected");
    assert.equal(error.retryAfterSeconds, 3600);
    assert.equal(error.message.includes(key), false);
    return true;
  });
});

test("Capy validates scope-free transport inputs before any external request", async () => {
  let calls = 0;
  const runtime = createCapyRuntime({ fetchImpl: async () => { calls++; return Response.json({}); } });
  for (const invoke of [
    () => runtime.getThread("bad-key", thread),
    () => runtime.getThread(key, "../../elsewhere"),
    () => runtime.listProjects(key, { limit: 0, cursor: null }),
    () => runtime.listProjects(key, { limit: 1, cursor: "x".repeat(4097) }),
    () => runtime.sendMessage(key, thread, { ...message, clientKey: "" }),
    () => runtime.sendMessage(key, thread, { ...message, text: "" }),
    () => runtime.sendMessage(key, thread, { ...message, text: "界".repeat(22_000) }),
  ]) await assert.rejects(invoke, { outcome: "rejected", code: "capy_invalid_input" });
  assert.equal(calls, 0);
});

test("Capy refuses malformed successful reads instead of returning unvalidated bodies", async () => {
  for (const body of [null, [], { items: [], hasMore: true, nextCursor: null },
    { items: [{ id: "p" }], hasMore: false, nextCursor: null }]) {
    const runtime = createCapyRuntime({ fetchImpl: async () => Response.json(body) });
    await assert.rejects(runtime.listProjects(key, { limit: 10, cursor: null }), { code: "capy_invalid_response", outcome: "rejected" });
  }
});

test("Capy has a finite decoded-body budget and cancels an oversized stream", async () => {
  let cancelled = false;
  const runtime = createCapyRuntime({ fetchImpl: async () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(2 * 1024 * 1024 + 1)); },
    cancel() { cancelled = true; return new Promise<void>(() => {}); },
  })) });
  await assert.rejects(runtime.getThread(key, thread), { code: "capy_invalid_response" });
  assert.equal(cancelled, true);
});

test("Capy uses one operation deadline through body reads and fallback", { timeout: 2000 }, async t => {
  const original = AbortSignal.timeout;
  const observed: AbortSignal[] = [];
  const deadlines: number[] = [];
  t.mock.method(AbortSignal, "timeout", (ms: number) => { deadlines.push(ms); return original(25); });
  const runtime = createCapyRuntime({ fetchImpl: async (_input, init) => {
    observed.push(init!.signal!);
    if (observed.length === 1) return Response.json({ _tag: "model_not_selected" }, { status: 400 });
    return new Response(new ReadableStream({
      start(controller) { controller.enqueue(new TextEncoder().encode('{"id":')); },
      pull() { return new Promise<void>(() => {}); },
      cancel() { return new Promise<void>(() => {}); },
    }));
  } });
  // Keep Node's loop alive: AbortSignal.timeout alone is intentionally unref'ed.
  const keeper = setTimeout(() => {}, 1000);
  try {
    await assert.rejects(runtime.sendMessage(key, thread, message), { code: "capy_deadline", outcome: "unknown" });
    assert.deepEqual(deadlines, [15_000]);
    assert.equal(observed.length, 2);
    assert.equal(observed[0], observed[1]);
  } finally { clearTimeout(keeper); }
});

test("Capy transcript page retains optional evidence fields and encodes the continuation", async () => {
  let url = "";
  const item = { id: "message-1", source: "assistant", text: "answer", model: "model",
    createdAt: "2026-11-10T00:00:00Z", calls: [{ tool: "read", durationMs: 10 }] };
  const runtime = createCapyRuntime({ fetchImpl: async input => { url = String(input); return Response.json({ items: [item], cursor: "next" }); } });
  assert.deepEqual(await runtime.listMessages(key, thread, { after: "a/b", limit: 25 }), { items: [item], cursor: "next" });
  assert.equal(url, `https://api.capy.ai/api/v1/threads/${thread}/messages?limit=25&after=a%2Fb`);
});

test("Capy ends an ignored fetch deadline and cancels its eventual response", { timeout: 2000 }, async t => {
  const original = AbortSignal.timeout;
  t.mock.method(AbortSignal, "timeout", () => original(25));
  let finish!: (response: Response) => void;
  let cancelled = false;
  const runtime = createCapyRuntime({ fetchImpl: () => new Promise(resolve => { finish = resolve; }) });
  const keeper = setTimeout(() => {}, 1000);
  try {
    await assert.rejects(runtime.sendMessage(key, thread, message), { code: "capy_deadline", outcome: "unknown" });
    finish(new Response(new ReadableStream({ cancel() { cancelled = true; } })));
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(cancelled, true);
  } finally { clearTimeout(keeper); }
});
