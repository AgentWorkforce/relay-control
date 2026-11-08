// analytics lane: queue, retry, and drop semantics with an injected clock and
// a scripted sink (no network).
import assert from "node:assert/strict";
import test from "node:test";
import type { AnalyticsLimits } from "../src/analytics/config.js";
import {
  AnalyticsProjectionError,
  EVENT_REGISTRY,
  projectEvent,
  RELAYCONTROL_IDENTITY_MODEL,
  type EventSpec,
} from "../src/analytics/events.js";
import { createAnalytics, realClock, type AnalyticsQueue } from "../src/analytics/queue.js";
import { noneSink } from "../src/analytics/sinks/none.js";
import type {
  AnalyticsClock,
  AnalyticsEnvelope,
  AnalyticsSink,
  CaptureInput,
  SinkResult,
} from "../src/analytics/types.js";

const DEFAULTS: AnalyticsLimits = {
  maxEventBytes: 4096,
  maxBatchEvents: 50,
  maxBatchBytes: 262_144,
  queueMaxEvents: 1000,
  queueMaxBytes: 1_048_576,
  requestTimeoutMs: 5000,
  deliveryDeadlineMs: 60_000,
  maxAttempts: 4,
  flushIntervalMs: 5000,
  shutdownDeadlineMs: 3000,
};

async function settle(): Promise<void> {
  for (let index = 0; index < 5; index += 1) await new Promise((resolve) => setImmediate(resolve));
}

function fakeClock(start = Date.parse("2026-11-08T00:00:00Z")) {
  let now = start;
  let sequence = 0;
  const timers = new Map<number, { at: number; callback: () => void }>();
  const clock: AnalyticsClock & { advance(ms: number): Promise<void>; pending(): number } = {
    now: () => now,
    setTimeout(callback, ms) {
      sequence += 1;
      timers.set(sequence, { at: now + ms, callback });
      return sequence;
    },
    clearTimeout(handle) {
      timers.delete(handle as number);
    },
    async advance(ms) {
      const end = now + ms;
      await settle();
      for (;;) {
        let next: [number, { at: number; callback: () => void }] | undefined;
        for (const entry of timers) {
          if (entry[1].at <= end && (!next || entry[1].at < next[1].at)) next = entry;
        }
        if (!next) break;
        timers.delete(next[0]);
        now = Math.max(now, next[1].at);
        next[1].callback();
        await settle();
      }
      now = end;
      await settle();
    },
    pending: () => timers.size,
  };
  return clock;
}

type Responder = (batch: AnalyticsEnvelope[], call: number) => SinkResult | "hang" | "throw";

function scriptedSink(respond: Responder = () => ({ outcome: "accepted" })) {
  const calls: string[][] = [];
  const sink: AnalyticsSink = {
    name: "collector",
    send(events, signal) {
      calls.push(events.map((event) => event.event_id));
      const result = respond(events, calls.length);
      if (result === "throw") throw new Error("sink exploded");
      if (result === "hang") {
        return new Promise((resolve) => {
          signal.addEventListener("abort", () => resolve({ outcome: "retry", reason: "timeout" }));
        });
      }
      return Promise.resolve(result);
    },
  };
  return { sink, calls };
}

function sequence(...results: Array<SinkResult | "hang" | "throw">): Responder {
  return (_, call) => results[call - 1] ?? { outcome: "accepted" };
}

function setup(respond?: Responder, limits: Partial<AnalyticsLimits> = {}) {
  const clock = fakeClock();
  const { sink, calls } = scriptedSink(respond);
  const logs: Array<[string, Record<string, unknown> | undefined]> = [];
  const analytics = createAnalytics({
    limits: { ...DEFAULTS, ...limits },
    sink,
    deploymentId: "dep_test_000001",
    clock,
    random: () => 0.5,
    log: (message, fields) => logs.push([message, fields]),
  });
  return { analytics, clock, calls, logs };
}

function capture(analytics: AnalyticsQueue, count = 1, input: CaptureInput = { event: "service_started" }): void {
  for (let index = 0; index < count; index += 1) analytics.capture(input);
}

function assertBalanced(analytics: AnalyticsQueue): void {
  const stats = analytics.stats();
  const dropped = Object.values(stats.dropped).reduce((sum, value) => sum + value, 0);
  assert.equal(stats.captured, stats.sent.events + dropped + stats.queueEvents);
}

const EVENT_BYTES = Buffer.byteLength(JSON.stringify(projectEvent(
  { event: "service_started" },
  { deploymentId: "dep_test_000001", traceId: "00000000-0000-4000-8000-000000000000", now: () => 0 },
)));

test("an accepted batch (204) dequeues after the flush interval", async () => {
  const { analytics, clock, calls } = setup();
  capture(analytics, 3);
  assert.equal(analytics.stats().queueEvents, 3);
  await clock.advance(4999);
  assert.equal(calls.length, 0);
  await clock.advance(1);
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.length, 3);
  const stats = analytics.stats();
  assert.deepEqual(stats.sent, { batches: 1, events: 3 });
  assert.equal(stats.queueEvents, 0);
  assert.equal(stats.queueBytes, 0);
  assert.equal(stats.lastSuccessAt, new Date(clock.now()).toISOString());
  assert.equal(clock.pending(), 0);
  assertBalanced(analytics);
});

test("503 then success retries after backoff with the same event_id", async () => {
  const { analytics, clock, calls, logs } = setup(sequence({ outcome: "retry", reason: "backpressure", status: 503 }));
  capture(analytics);
  await clock.advance(5000);
  assert.equal(calls.length, 1);
  await clock.advance(999);
  assert.equal(calls.length, 1);
  await clock.advance(1);
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1], calls[0]);
  assert.deepEqual(analytics.stats().sent, { batches: 1, events: 1 });
  assert.deepEqual(logs.map(([message]) => message), ["analytics sink failing", "analytics sink recovered"]);
  assertBalanced(analytics);
});

test("backoff is 1, 2, 4 s with ±20% jitter and ends in dropped.retryExhausted", async () => {
  const delays: number[] = [];
  for (const jitter of [0, 0.5, 0.999999]) {
    const clock = fakeClock();
    const times: number[] = [];
    const { sink } = scriptedSink(() => {
      times.push(clock.now());
      return { outcome: "retry", reason: "server", status: 500 };
    });
    const analytics = createAnalytics({ limits: DEFAULTS, sink, deploymentId: "dep_test_000001", clock, random: () => jitter });
    capture(analytics);
    await clock.advance(60_000);
    assert.equal(times.length, 4);
    delays.push(...times.slice(1).map((time, index) => time - times[index]!));
    const stats = analytics.stats();
    assert.equal(stats.dropped.retryExhausted, 1);
    assert.equal(stats.queueEvents, 0);
    assert.equal(stats.lastFailureReason, "server");
    assertBalanced(analytics);
  }
  assert.deepEqual(delays, [800, 1600, 3200, 1000, 2000, 4000, 1200, 2400, 4800]);
});

test("Retry-After is honoured and bounded", async () => {
  const { analytics, clock, calls } = setup(sequence(
    { outcome: "retry", reason: "backpressure", status: 429, retryAfterMs: 2500 },
    { outcome: "retry", reason: "backpressure", status: 503, retryAfterMs: 90_000 },
  ));
  capture(analytics);
  await clock.advance(5000);
  await clock.advance(2499);
  assert.equal(calls.length, 1);
  await clock.advance(1);
  assert.equal(calls.length, 2);
  await clock.advance(29_999);
  assert.equal(calls.length, 2);
  await clock.advance(1);
  assert.equal(calls.length, 3);
  assert.equal(analytics.stats().sent.events, 1);
});

test("507 is retried and counted in failures.storage", async () => {
  const { analytics, clock, calls } = setup(sequence(
    { outcome: "retry", reason: "storage", status: 507 },
    { outcome: "retry", reason: "storage", status: 507 },
  ));
  capture(analytics, 2);
  await clock.advance(5000 + 1000 + 2000);
  assert.equal(calls.length, 3);
  assert.deepEqual(calls[2], calls[0]);
  const stats = analytics.stats();
  assert.equal(stats.failures.storage, 2);
  assert.deepEqual(stats.sent, { batches: 1, events: 2 });
});

test("rejections, auth and redirects are terminal and never retried", async () => {
  const cases: Array<[SinkResult, (stats: ReturnType<AnalyticsQueue["stats"]>) => void]> = [
    [{ outcome: "rejected", status: 400 }, (stats) => assert.equal(stats.dropped.rejected, 2)],
    [{ outcome: "rejected", status: 422 }, (stats) => assert.equal(stats.dropped.rejected, 2)],
    [{ outcome: "auth", status: 401 }, (stats) => {
      assert.equal(stats.dropped.rejected, 2);
      assert.equal(stats.failures.auth, 1);
      assert.equal(stats.lastFailureReason, "auth");
    }],
    [{ outcome: "auth", status: 403 }, (stats) => {
      assert.equal(stats.failures.config, 1);
      assert.equal(stats.lastFailureReason, "config");
    }],
    [{ outcome: "redirect", status: 302 }, (stats) => {
      assert.equal(stats.failures.redirect, 1);
      assert.equal(stats.dropped.rejected, 2);
      assert.equal(stats.lastFailureReason, "redirect");
    }],
  ];
  for (const [result, check] of cases) {
    const { analytics, clock, calls, logs } = setup(sequence(result, result));
    capture(analytics, 2);
    await clock.advance(60_000);
    assert.equal(calls.length, 1, JSON.stringify(result));
    const stats = analytics.stats();
    assert.equal(stats.sent.events, 0);
    assert.equal(stats.queueEvents, 0);
    check(stats);
    assert.ok(logs.some(([message, fields]) => message === "analytics batch dropped" && fields?.status === (result as { status?: number }).status));
    assertBalanced(analytics);
  }
});

test("413 splits the batch down to single events, then drops the oversized one", async () => {
  let poison = "";
  const { analytics, clock, calls } = setup((batch, call) => {
    if (call === 1) poison = batch[1]!.event_id;
    return batch.some((event) => event.event_id === poison) ? { outcome: "oversize", status: 413 } : { outcome: "accepted" };
  });
  capture(analytics, 4);
  await clock.advance(5000);
  await clock.advance(30_000);
  assert.deepEqual(calls.map((batch) => batch.length), [4, 2, 1, 1, 1, 1]);
  assert.deepEqual(calls[3], [poison]);
  const stats = analytics.stats();
  assert.equal(stats.dropped.oversize, 1);
  assert.deepEqual(stats.sent, { batches: 3, events: 3 });
  assertBalanced(analytics);
  // The cap resets once the split batch is done.
  capture(analytics, 3);
  await clock.advance(5000);
  assert.equal(calls.at(-1)!.length, 3);
});

test("MAX_EVENT_BYTES drops oversized events at capture", () => {
  const { analytics } = setup(undefined, { maxEventBytes: EVENT_BYTES - 1 });
  capture(analytics, 2);
  const stats = analytics.stats();
  assert.equal(stats.dropped.oversize, 2);
  assert.equal(stats.queueEvents, 0);
  assertBalanced(analytics);
});

test("MAX_BATCH_EVENTS and MAX_BATCH_BYTES bound each request", async () => {
  {
    const { analytics, clock, calls } = setup(undefined, { maxBatchEvents: 2 });
    capture(analytics, 5);
    await clock.advance(0);
    // A full batch is sent at once; the remainder waits for the interval or flush.
    assert.deepEqual(calls.map((batch) => batch.length), [2, 2]);
    await clock.advance(5000);
    assert.deepEqual(calls.map((batch) => batch.length), [2, 2, 1]);
  }
  {
    const overhead = Buffer.byteLength('{"schema":"agent-relay.analytics.batch/v1","events":[]}');
    const { analytics, clock, calls } = setup(undefined, { maxBatchBytes: overhead + 2 * EVENT_BYTES + 1 });
    capture(analytics, 5);
    const flushed = analytics.flush(clock.now() + 1000);
    await clock.advance(0);
    assert.deepEqual(await flushed, { sent: 5, dropped: 0 });
    assert.deepEqual(calls.map((batch) => batch.length), [2, 2, 1]);
  }
});

test("QUEUE_MAX_EVENTS and QUEUE_MAX_BYTES drop the newest event", async () => {
  {
    const { analytics, clock, calls } = setup(undefined, { queueMaxEvents: 3 });
    capture(analytics, 3);
    const kept = analytics.stats().queueEvents;
    capture(analytics, 2);
    const stats = analytics.stats();
    assert.equal(kept, 3);
    assert.equal(stats.dropped.queueFull, 2);
    assert.equal(stats.queueEvents, 3);
    await clock.advance(5000);
    assert.equal(calls[0]!.length, 3);
    assertBalanced(analytics);
  }
  {
    const { analytics } = setup(undefined, { queueMaxBytes: Math.floor(EVENT_BYTES * 2.5) });
    capture(analytics, 4);
    const stats = analytics.stats();
    assert.equal(stats.queueEvents, 2);
    assert.equal(stats.dropped.queueFull, 2);
    assert.ok(stats.queueBytes <= Math.floor(EVENT_BYTES * 2.5));
  }
});

test("only one request is in flight and a hanging request times out as transport failure", async () => {
  const { analytics, clock, calls } = setup(sequence("hang"), { maxBatchEvents: 1 });
  capture(analytics, 3);
  await clock.advance(0);
  assert.equal(calls.length, 1);
  capture(analytics, 2);
  await clock.advance(4999);
  assert.equal(calls.length, 1);
  await clock.advance(1);
  const stats = analytics.stats();
  assert.equal(stats.failures.transport, 1);
  assert.equal(stats.lastFailureReason, "timeout");
  await clock.advance(1000);
  assert.deepEqual(calls[1], calls[0]);
});

test("flush with a hanging sink resolves by the deadline: the in-flight batch is aborted, the rest shutdown", async () => {
  const { analytics, clock, calls } = setup(() => "hang", { maxBatchEvents: 2 });
  capture(analytics, 3);
  const deadline = clock.now() + 1500;
  let settled = false;
  const flushed = analytics.flush(deadline).then((result) => {
    settled = true;
    return result;
  });
  await clock.advance(1499);
  assert.equal(settled, false);
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.length, 2);
  await clock.advance(1);
  assert.deepEqual(await flushed, { sent: 0, dropped: 3 });
  assert.equal(clock.now(), deadline);
  const stats = analytics.stats();
  // In flight when abandoned: the collector may have committed them.
  assert.equal(stats.dropped.aborted, 2);
  // Never attempted.
  assert.equal(stats.dropped.shutdown, 1);
  assert.equal(stats.queueEvents, 0);
  assert.equal(clock.pending(), 0);
  assertBalanced(analytics);
});

test("events captured while an abandoned request is still settling are scheduled and drain", async () => {
  const clock = fakeClock();
  const calls: number[] = [];
  let analytics: AnalyticsQueue | null = null;
  const sink: AnalyticsSink = {
    name: "collector",
    send(events, signal) {
      calls.push(events.length);
      if (calls.length > 1) return Promise.resolve({ outcome: "accepted" });
      return new Promise((resolve) => {
        signal.addEventListener("abort", () => {
          // Runs synchronously inside flush's give-up, while the abandoned
          // request still occupies the in-flight slot.
          analytics!.capture({ event: "service_stopping", properties: { reason: "SIGTERM" } });
          resolve({ outcome: "retry", reason: "timeout" });
        });
      });
    },
  };
  analytics = createAnalytics({ limits: DEFAULTS, sink, deploymentId: "dep_test_000001", clock, random: () => 0.5 });
  capture(analytics, 3);
  const flushed = analytics.flush(clock.now() + 1000);
  await clock.advance(1000);
  assert.deepEqual(await flushed, { sent: 0, dropped: 3 });
  let stats = analytics.stats();
  assert.equal(stats.dropped.aborted, 3);
  assert.equal(stats.dropped.shutdown, 0);
  assert.equal(stats.queueEvents, 1);
  // The late capture has a timer once the abandoned attempt settles.
  assert.equal(clock.pending(), 1);
  await clock.advance(DEFAULTS.flushIntervalMs);
  assert.deepEqual(calls, [3, 1]);
  stats = analytics.stats();
  assert.deepEqual(stats.sent, { batches: 1, events: 1 });
  assert.equal(stats.queueEvents, 0);
  assert.equal(clock.pending(), 0);
  assertBalanced(analytics);
  // A later flush returns at once with nothing queued.
  assert.deepEqual(await analytics.flush(clock.now()), { sent: 0, dropped: 0 });
});

test("only the flush deadline timer holds the process open", async () => {
  const kept: boolean[] = [];
  const inner = fakeClock();
  const clock: AnalyticsClock = {
    now: inner.now,
    setTimeout(callback, ms, options) {
      kept.push(options?.keepAlive === true);
      return inner.setTimeout(callback, ms, options);
    },
    clearTimeout: inner.clearTimeout,
  };
  const analytics = createAnalytics({
    limits: DEFAULTS,
    sink: scriptedSink(sequence({ outcome: "retry", reason: "server", status: 500 })).sink,
    deploymentId: "dep_test_000001",
    clock,
    random: () => 0.5,
  });
  capture(analytics, 1);
  assert.deepEqual(kept, [false]);
  const flushed = analytics.flush(inner.now() + 3000);
  await inner.advance(3000);
  assert.deepEqual(await flushed, { sent: 1, dropped: 0 });
  // Flush interval, flush deadline, request timeout, backoff, request timeout.
  assert.equal(kept.filter(Boolean).length, 1);
  assert.equal(kept[1], true);

  const background = realClock.setTimeout(() => undefined, 60_000) as NodeJS.Timeout;
  const deadline = realClock.setTimeout(() => undefined, 60_000, { keepAlive: true }) as NodeJS.Timeout;
  try {
    assert.equal(background.hasRef(), false);
    assert.equal(deadline.hasRef(), true);
  } finally {
    realClock.clearTimeout(background);
    realClock.clearTimeout(deadline);
  }
});

test("flush drains completely when the sink is healthy", async () => {
  const { analytics, clock, calls } = setup(sequence({ outcome: "retry", reason: "server", status: 500 }));
  capture(analytics, 120);
  const flushed = analytics.flush(clock.now() + 3000);
  await clock.advance(3000);
  assert.deepEqual(await flushed, { sent: 120, dropped: 0 });
  assert.deepEqual(calls.map((batch) => batch.length), [50, 50, 50, 20]);
  assert.equal(analytics.stats().queueEvents, 0);
  assert.equal(clock.pending(), 0);
  // Nothing queued: flush returns at once.
  assert.deepEqual(await analytics.flush(clock.now()), { sent: 0, dropped: 0 });
});

test("capture never throws: sink errors, unregistered kinds, reserved properties, and attribution are counted", async () => {
  const { analytics, clock } = setup(sequence("throw"));
  assert.doesNotThrow(() => {
    analytics.capture({ event: "user_signed_up" as never });
    analytics.capture({ event: "service_started", properties: { event_id: "forged" } });
    analytics.capture({ event: "service_started", properties: { deployment_id: "other" } });
    analytics.capture({ event: "service_started", tenantId: "tenant_1" });
    analytics.capture({ event: "service_started", tenantId: "tenant_1", workspaceId: "ws_1" });
    analytics.capture({ event: "service_started", traceId: "bad trace" });
    analytics.capture(null as never);
    analytics.capture({ event: "service_started" });
  });
  let stats = analytics.stats();
  assert.equal(stats.dropped.invalid, 7);
  assert.equal(stats.captured, 8);
  await clock.advance(5000);
  stats = analytics.stats();
  assert.equal(stats.failures.transport, 1);
  await clock.advance(1000);
  assert.equal(analytics.stats().sent.events, 1);
  assertBalanced(analytics);
});

test("the projector enforces the scope registry and the property allowlist", () => {
  const registry: Record<string, EventSpec> = {
    install_thing: { scope: "installation", properties: { count: { type: "integer", min: 0, max: 10 } } },
    tenant_thing: { scope: "tenant", properties: {} },
    workspace_thing: { scope: "workspace", properties: {} },
  };
  const context = { deploymentId: "dep_test_000001", traceId: "trace_test_0001", now: () => 0 };
  const project = (input: Record<string, unknown>) => projectEvent(input as never, context, registry);

  const installation = project({ event: "install_thing", properties: { count: 3, extra: "x", other: 99 } });
  assert.equal("tenant_id" in installation, false);
  assert.equal("workspace_id" in installation, false);
  assert.deepEqual(installation.properties, { count: 3 });
  assert.deepEqual(project({ event: "install_thing", properties: { count: 11 } }).properties, {});
  assert.throws(() => project({ event: "install_thing", tenantId: "t_1" }), AnalyticsProjectionError);
  assert.throws(() => project({ event: "install_thing", workspaceId: "w_1" }), AnalyticsProjectionError);

  assert.equal(project({ event: "tenant_thing", tenantId: "t_1" }).tenant_id, "t_1");
  assert.throws(() => project({ event: "tenant_thing" }), /require tenant_id/);
  assert.throws(() => project({ event: "tenant_thing", tenantId: "t_1", workspaceId: "w_1" }), AnalyticsProjectionError);

  const workspace = project({ event: "workspace_thing", tenantId: "t_1", workspaceId: "w_1" });
  assert.equal(workspace.tenant_id, "t_1");
  assert.equal(workspace.workspace_id, "w_1");
  assert.throws(() => project({ event: "workspace_thing", workspaceId: "w_1" }), /require tenant_id and workspace_id/);
  assert.throws(() => project({ event: "workspace_thing", tenantId: "t 1", workspaceId: "w_1" }), /opaque/);

  for (const reserved of ["version", "event_id", "occurred_at", "component", "deployment_id", "event", "trace_id", "tenant_id", "workspace_id"]) {
    assert.throws(() => project({ event: "install_thing", properties: { [reserved]: "x" } }), /reserved/, reserved);
  }
  assert.throws(() => project({ event: "unknown_thing" }), /unregistered event kind/);
  assert.throws(() => project({ event: "toString" }), /unregistered event kind/);
});

test("the none destination only counts captures", async () => {
  const clock = fakeClock();
  const analytics = createAnalytics({ limits: DEFAULTS, sink: noneSink, deploymentId: null, clock });
  capture(analytics, 3);
  assert.equal(clock.pending(), 0);
  const stats = analytics.stats();
  assert.equal(stats.captured, 3);
  assert.equal(stats.queueEvents, 0);
  assert.deepEqual(stats.sent, { batches: 0, events: 0 });
  assert.deepEqual(await analytics.flush(clock.now()), { sent: 0, dropped: 0 });
  assert.throws(
    () => createAnalytics({ limits: DEFAULTS, sink: scriptedSink().sink, deploymentId: null }),
    /deployment id is required/,
  );
});

test("200/202 are never acceptance: retried within the budget, then dropped.protocol", async () => {
  for (const status of [200, 202]) {
    const result: SinkResult = { outcome: "protocol", status };
    const { analytics, clock, calls, logs } = setup(() => result);
    capture(analytics, 2);
    await clock.advance(60_000);
    assert.equal(calls.length, DEFAULTS.maxAttempts, String(status));
    for (const call of calls) assert.deepEqual(call, calls[0]);
    const stats = analytics.stats();
    assert.equal(stats.sent.events, 0);
    assert.equal(stats.dropped.protocol, 2);
    assert.equal(stats.dropped.retryExhausted, 0);
    assert.equal(stats.queueEvents, 0);
    assert.equal(stats.lastFailureReason, "protocol");
    assert.ok(logs.some(([message, fields]) => message === "analytics batch dropped" && fields?.outcome === "protocol" && fields?.status === status));
    assertBalanced(analytics);
  }
  // A protocol answer does not dequeue: the same events are accepted by a later 204.
  const { analytics, clock, calls } = setup(sequence({ outcome: "protocol", status: 200 }));
  capture(analytics, 2);
  await clock.advance(5000 + 1000);
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1], calls[0]);
  assert.deepEqual(analytics.stats().sent, { batches: 1, events: 2 });
  assert.equal(analytics.stats().dropped.protocol, 0);
});

test("a zero Retry-After still consumes an attempt", async () => {
  const { analytics, clock, calls } = setup(() => ({ outcome: "retry", reason: "backpressure", status: 429, retryAfterMs: 0 }));
  capture(analytics);
  // Bounded by MAX_ATTEMPTS: a zero delay retries immediately, and each try counts.
  await clock.advance(5000 + 3 * 5000);
  assert.equal(calls.length, DEFAULTS.maxAttempts);
  for (const call of calls) assert.deepEqual(call, calls[0]);
  const stats = analytics.stats();
  assert.equal(stats.dropped.retryExhausted, 1);
  assert.equal(clock.pending(), 0);
  assertBalanced(analytics);
});

test("after a zero Retry-After the next attempt is immediate, not a flush interval past the delivery deadline", async () => {
  // Outside a flush with a short queue: the flush interval (60 s) is far longer
  // than the batch's remaining delivery budget after its first attempt (10 s).
  const { analytics, clock, calls } = setup(
    sequence({ outcome: "retry", reason: "backpressure", status: 503, retryAfterMs: 0 }),
    { flushIntervalMs: 60_000, deliveryDeadlineMs: 70_000 },
  );
  capture(analytics);
  await clock.advance(59_999);
  assert.equal(calls.length, 0);
  await clock.advance(1);
  // First attempt at the flush interval answers 503 with Retry-After: 0; the
  // retry goes out at once, well before the deadline at 70 s.
  assert.equal(calls.length, 2);
  assert.deepEqual(calls[1], calls[0]);
  const stats = analytics.stats();
  assert.equal(stats.sent.events, 1);
  assert.equal(stats.dropped.deadline, 0);
  assert.equal(stats.queueEvents, 0);
  assert.equal(clock.pending(), 0);
  assertBalanced(analytics);
});

test("Retry-After is clipped to the batch's remaining delivery deadline, then the batch is dropped without a new request", async () => {
  const { analytics, clock, calls, logs } = setup(
    () => ({ outcome: "retry", reason: "backpressure", status: 503, retryAfterMs: 30_000 }),
    { deliveryDeadlineMs: 8000 },
  );
  capture(analytics, 2);
  await clock.advance(5000);
  assert.equal(calls.length, 1);
  await clock.advance(2999);
  assert.equal(analytics.stats().queueEvents, 2);
  await clock.advance(1);
  // At the deadline: dropped, no second request and no further wait.
  assert.equal(calls.length, 1);
  const stats = analytics.stats();
  assert.equal(stats.dropped.deadline, 2);
  assert.equal(stats.dropped.retryExhausted, 0);
  assert.equal(stats.queueEvents, 0);
  assert.equal(clock.pending(), 0);
  assert.ok(logs.some(([message, fields]) => message === "analytics events dropped" && fields?.outcome === "deadline"));
  assertBalanced(analytics);
});

test("deadline exhaustion drops events before another attempt; later events keep their own deadline", async () => {
  const { analytics, clock, calls } = setup(
    sequence(
      { outcome: "retry", reason: "server", status: 500 },
      { outcome: "retry", reason: "server", status: 500 },
    ),
    { deliveryDeadlineMs: 7000, maxAttempts: 10 },
  );
  capture(analytics);
  await clock.advance(4000);
  capture(analytics);
  // Attempt at 5000, backoff 1 s, attempt at 6000, backoff 2 s clipped to the
  // batch deadline (the first event's, 7000).
  await clock.advance(2999);
  assert.equal(calls.length, 2);
  assert.equal(calls[0]!.length, 2);
  assert.equal(analytics.stats().dropped.deadline, 0);
  await clock.advance(1);
  // The expired event is dropped and never sent again; the second event
  // (deadline 11000) goes out on its own once the wait has ended.
  const stats = analytics.stats();
  assert.equal(stats.dropped.deadline, 1);
  assert.equal(calls.length, 3);
  assert.deepEqual(calls[2], [calls[0]![1]]);
  assert.deepEqual(stats.sent, { batches: 1, events: 1 });
  assert.equal(stats.queueEvents, 0);
  assertBalanced(analytics);
});

test("each attempt's timeout is clipped to the batch's remaining delivery deadline", async () => {
  const { analytics, clock, calls } = setup(() => "hang", { deliveryDeadlineMs: 7000, requestTimeoutMs: 5000 });
  capture(analytics, 3);
  await clock.advance(5000);
  assert.equal(calls.length, 1);
  // Request timeout is 5 s, but only 2 s of the delivery budget remain.
  await clock.advance(1999);
  assert.equal(analytics.stats().failures.transport, 0);
  await clock.advance(1);
  const stats = analytics.stats();
  assert.equal(stats.failures.transport, 1);
  assert.equal(stats.lastFailureReason, "timeout");
  assert.equal(stats.dropped.deadline, 3);
  assert.equal(stats.queueEvents, 0);
  assert.equal(calls.length, 1);
  assert.equal(clock.pending(), 0);
  assertBalanced(analytics);
});

test("splitting a 413 batch never resets its delivery deadline", async () => {
  const { analytics, clock, calls } = setup(
    (batch) => (batch.length > 1 ? { outcome: "oversize", status: 413 } : "hang"),
    { deliveryDeadlineMs: 12_000 },
  );
  capture(analytics, 2);
  // 413 at 5000; the first half goes out at the next interval (10000).
  await clock.advance(10_000);
  assert.deepEqual(calls.map((batch) => batch.length), [2, 1]);
  // Its timeout is the 2 s left of the original deadline, not a fresh 5 s.
  await clock.advance(1999);
  assert.equal(analytics.stats().dropped.deadline, 0);
  await clock.advance(1);
  const stats = analytics.stats();
  assert.equal(stats.dropped.deadline, 2);
  assert.equal(calls.length, 2);
  assert.equal(clock.pending(), 0);
  assertBalanced(analytics);
});

test("during a flush, Retry-After is clipped to the flush deadline", async () => {
  const { analytics, clock, calls } = setup(
    () => ({ outcome: "retry", reason: "backpressure", status: 429, retryAfterMs: 30_000 }),
  );
  capture(analytics);
  const flushed = analytics.flush(clock.now() + 2000);
  await clock.advance(2000);
  assert.deepEqual(await flushed, { sent: 0, dropped: 1 });
  assert.equal(calls.length, 1);
  const stats = analytics.stats();
  assert.equal(stats.dropped.shutdown, 1);
  assert.equal(clock.pending(), 0);
  assertBalanced(analytics);
});

test("the projector enforces the identity model: no missing ids, no extra ids, no weaker scope", () => {
  const tenantModel: Record<string, EventSpec> = {
    install_thing: { scope: "installation", properties: {} },
    tenant_thing: { scope: "tenant", properties: {} },
    workspace_thing: { scope: "workspace", properties: {} },
    native_thing: { scope: "native_workspace", properties: {} },
    bogus_thing: { scope: "organization" as never, properties: {} },
  };
  const context = { deploymentId: "dep_test_000001", traceId: "trace_test_0001", now: () => 0 };
  const project = (input: Record<string, unknown>, model?: "tenant" | "native_workspace") =>
    projectEvent(input as never, context, tenantModel, model);

  // relaycontrol: tenant model (organization = tenant) by default.
  assert.equal(RELAYCONTROL_IDENTITY_MODEL, "tenant");
  for (const spec of Object.values(EVENT_REGISTRY)) assert.equal(spec.scope, "installation");

  // Missing required ids.
  assert.throws(() => project({ event: "tenant_thing" }), /require tenant_id/);
  assert.throws(() => project({ event: "workspace_thing", tenantId: "t_1" }), /require tenant_id and workspace_id/);
  assert.throws(() => project({ event: "native_thing", workspaceId: "w_1" }), /not registered under the tenant identity model/);
  assert.throws(() => project({ event: "native_thing" }, "native_workspace"), /require workspace_id/);
  assert.throws(() => project({ event: "native_thing", workspaceId: "" }, "native_workspace"), /opaque/);
  assert.throws(() => project({ event: "tenant_thing", tenantId: null }), /opaque/);

  // Ids present for installation-only kinds.
  for (const model of ["tenant", "native_workspace"] as const) {
    assert.throws(() => project({ event: "install_thing", tenantId: "t_1" }, model), /installation events/);
    assert.throws(() => project({ event: "install_thing", workspaceId: "w_1" }, model), /installation events/);
    assert.equal("workspace_id" in project({ event: "install_thing" }, model), false);
  }

  // Weaker-scope substitution: a workspace kind with only workspace_id, a
  // tenant kind with only workspace_id, a tenant id invented for a native kind.
  assert.throws(() => project({ event: "workspace_thing", workspaceId: "w_1" }), /require tenant_id and workspace_id/);
  assert.throws(() => project({ event: "tenant_thing", workspaceId: "w_1" }), /require tenant_id/);
  assert.throws(
    () => project({ event: "native_thing", tenantId: "w_1", workspaceId: "w_1" }, "native_workspace"),
    /no tenant attribution/,
  );
  // A kind cannot be reclassified across models.
  assert.throws(() => project({ event: "tenant_thing", tenantId: "t_1" }, "native_workspace"), /not registered under the native_workspace/);
  assert.throws(
    () => project({ event: "workspace_thing", tenantId: "t_1", workspaceId: "w_1" }, "native_workspace"),
    /not registered under the native_workspace/,
  );
  assert.throws(() => project({ event: "bogus_thing" }), /not registered under the tenant identity model/);
  assert.throws(() => project({ event: "install_thing" }, "organization" as never), /unregistered identity model/);

  // Supported shapes.
  const native = project({ event: "native_thing", workspaceId: "w_1" }, "native_workspace");
  assert.equal(native.workspace_id, "w_1");
  assert.equal("tenant_id" in native, false);
  const workspace = project({ event: "workspace_thing", tenantId: "t_1", workspaceId: "w_1" });
  assert.deepEqual([workspace.tenant_id, workspace.workspace_id], ["t_1", "w_1"]);
});
