// analytics lane: the bounded queue behind the port. One request in flight,
// bounded by count and bytes, bounded retries, counted drops. Delivery is best
// effort: event_id is kept across retries, so a batch committed before a lost
// acknowledgement may arrive twice; nothing here deduplicates.
//
// Every event has a total delivery deadline (enqueue + DELIVERY_DEADLINE_MS)
// covering queue time, every attempt and every wait. A batch uses the earliest
// deadline of its events; splitting or retrying never resets it. Expired events
// are dropped (dropped.deadline) before any further attempt or wait.
import { randomUUID } from "node:crypto";
import type { AnalyticsLimits } from "./config.js";
import { projectEvent } from "./events.js";
import { boundRetryDelay, RETRY_AFTER_CAP_MS } from "./retry.js";
import {
  ANALYTICS_BATCH_OVERHEAD_BYTES,
  type AnalyticsClock,
  type AnalyticsEnvelope,
  type AnalyticsFailureReason,
  type AnalyticsGatewayCounter,
  type AnalyticsLog,
  type AnalyticsPort,
  type AnalyticsSink,
  type AnalyticsStats,
  type CaptureInput,
  type FlushResult,
  type SinkResult,
} from "./types.js";

export const realClock: AnalyticsClock = {
  now: () => Date.now(),
  setTimeout(callback, ms, options) {
    const timer = setTimeout(callback, ms);
    // Background timers never hold the process open; the flush deadline does,
    // so a flush on the way out completes or times out before exit.
    if (!options?.keepAlive) timer.unref();
    return timer;
  },
  clearTimeout(handle) {
    clearTimeout(handle as NodeJS.Timeout);
  },
};

export type AnalyticsQueueOptions = {
  limits: AnalyticsLimits;
  sink: AnalyticsSink;
  /** Required unless the sink is `none`. */
  deploymentId: string | null;
  clock?: AnalyticsClock;
  log?: AnalyticsLog;
  /** [0, 1); jitter source. */
  random?: () => number;
  /** Shared by every event of this process unless a capture names its own. */
  bootTraceId?: string;
};

export type AnalyticsQueue = AnalyticsPort & {
  readonly bootTraceId: string;
  recordGateway(counter: AnalyticsGatewayCounter, amount?: number): void;
};

/** `deadline`: epoch ms on the queue's clock; enqueue time + DELIVERY_DEADLINE_MS. */
type Queued = { envelope: AnalyticsEnvelope; bytes: number; deadline: number };

const BACKOFF_BASE_MS = 1000;

function emptyStats(): AnalyticsStats {
  return {
    captured: 0,
    sent: { batches: 0, events: 0 },
    dropped: {
      oversize: 0,
      queueFull: 0,
      rejected: 0,
      protocol: 0,
      retryExhausted: 0,
      deadline: 0,
      shutdown: 0,
      aborted: 0,
      invalid: 0,
    },
    failures: { auth: 0, config: 0, storage: 0, redirect: 0, transport: 0 },
    queueEvents: 0,
    queueBytes: 0,
    lastFailureReason: null,
    lastSuccessAt: null,
    gateway: {
      requests: 0,
      accepted: 0,
      rejected: {
        auth: 0,
        csrf: 0,
        client_mismatch: 0,
        body: 0,
        invalid: 0,
        reserved_field: 0,
        rate_limited: 0,
      },
      clock_adjusted: 0,
    },
  };
}

/** Sum of every `dropped` counter. */
export function droppedTotal(stats: AnalyticsStats): number {
  return Object.values(stats.dropped).reduce((sum, count) => sum + count, 0);
}

export function createAnalytics(options: AnalyticsQueueOptions): AnalyticsQueue {
  const { limits, sink } = options;
  const clock = options.clock ?? realClock;
  const log = options.log ?? (() => undefined);
  const random = options.random ?? Math.random;
  const bootTraceId = options.bootTraceId ?? randomUUID();
  const disabled = sink.name === "none";
  if (!disabled && !options.deploymentId) throw new Error("analytics deployment id is required");
  const deploymentId = options.deploymentId ?? "";

  const stats = emptyStats();
  const queue: Queued[] = [];
  let queueBytes = 0;

  let timer: unknown = null;
  /** While `epoch` is current, `count` events at the head of `queue` are in this request. */
  let inFlight: { controller: AbortController; done: Promise<void>; count: number; epoch: number } | null = null;
  /**
   * Bumped when flush gives up, so a late in-flight result is ignored. The
   * abandoned request still occupies `inFlight` until its abort settles.
   */
  let epoch = 0;
  let attempts = 0;
  let backoffUntil = 0;
  /** After a 413: events of the oversized batch still pending, and the reduced batch cap. */
  let splitRemaining = 0;
  let splitCap = 0;
  let healthy = true;
  const loggedStatuses = new Set<string>();
  let flushing = 0;
  /** Deadlines of the flushes in progress; the earliest bounds attempts and waits. */
  const flushDeadlines: number[] = [];
  const idleWaiters: Array<() => void> = [];

  function schedule(delay: number): void {
    if (timer !== null) clock.clearTimeout(timer);
    timer = clock.setTimeout(() => {
      timer = null;
      pump();
    }, Math.max(0, delay));
  }

  function notifyIdle(): void {
    if (inFlight || queue.length > 0) return;
    for (const resolve of idleWaiters.splice(0)) resolve();
  }

  function nextBatch(): Queued[] {
    const cap = splitRemaining > 0 ? Math.min(splitCap, limits.maxBatchEvents) : limits.maxBatchEvents;
    const batch: Queued[] = [];
    let bytes = ANALYTICS_BATCH_OVERHEAD_BYTES;
    for (const item of queue) {
      if (batch.length >= cap) break;
      const added = bytes + item.bytes + (batch.length > 0 ? 1 : 0);
      if (batch.length > 0 && added > limits.maxBatchBytes) break;
      batch.push(item);
      bytes = added;
    }
    return batch;
  }

  /** Remaining time of the earliest flush in progress; undefined when not flushing. */
  function flushRemaining(now: number): number | undefined {
    return flushDeadlines.length > 0 ? Math.min(...flushDeadlines) - now : undefined;
  }

  function batchDeadline(batch: Queued[]): number {
    return batch.reduce((earliest, item) => Math.min(earliest, item.deadline), Number.POSITIVE_INFINITY);
  }

  /**
   * Drop every queued event whose delivery deadline has passed. Only called
   * with nothing in flight. Like a dequeue, the retry state of the head batch
   * ends with it.
   */
  function expire(now: number): void {
    let removed = 0;
    let removedInSplit = 0;
    for (let index = queue.length - 1; index >= 0; index -= 1) {
      const item = queue[index]!;
      if (item.deadline > now) continue;
      if (index < splitRemaining) removedInSplit += 1;
      queue.splice(index, 1);
      queueBytes -= item.bytes;
      removed += 1;
    }
    if (removed === 0) return;
    stats.dropped.deadline += removed;
    splitRemaining = Math.max(0, splitRemaining - removedInSplit);
    attempts = 0;
    backoffUntil = 0;
    if (!loggedStatuses.has("deadline")) {
      loggedStatuses.add("deadline");
      log("analytics events dropped", { sink: sink.name, outcome: "deadline" });
    }
  }

  function dequeue(count: number): void {
    for (const item of queue.splice(0, count)) queueBytes -= item.bytes;
    attempts = 0;
    backoffUntil = 0;
    if (splitRemaining > 0) splitRemaining = Math.max(0, splitRemaining - count);
  }

  function failing(reason: AnalyticsFailureReason, status?: number): void {
    stats.lastFailureReason = reason;
    if (healthy) {
      healthy = false;
      log("analytics sink failing", { sink: sink.name, reason, status: status ?? null });
    }
  }

  function terminal(kind: string, status: number): void {
    const key = `${kind}:${status}`;
    if (loggedStatuses.has(key)) return;
    loggedStatuses.add(key);
    log("analytics batch dropped", { sink: sink.name, outcome: kind, status });
  }

  function backoff(): number {
    const base = Math.min(BACKOFF_BASE_MS * 2 ** (attempts - 1), RETRY_AFTER_CAP_MS);
    const jittered = base * (0.8 + random() * 0.4);
    return Math.min(Math.round(jittered), RETRY_AFTER_CAP_MS);
  }

  function apply(result: SinkResult, count: number, deadline: number): void {
    switch (result.outcome) {
      case "accepted":
        dequeue(count);
        stats.sent.batches += 1;
        stats.sent.events += count;
        stats.lastSuccessAt = new Date(clock.now()).toISOString();
        if (!healthy) {
          healthy = true;
          log("analytics sink recovered", { sink: sink.name });
        }
        return;
      case "rejected":
        dequeue(count);
        stats.dropped.rejected += count;
        failing("rejected", result.status);
        terminal("rejected", result.status);
        return;
      case "auth":
        dequeue(count);
        stats.dropped.rejected += count;
        if (result.status === 401) {
          stats.failures.auth += 1;
          failing("auth", 401);
        } else {
          stats.failures.config += 1;
          failing("config", 403);
        }
        terminal("auth", result.status);
        return;
      case "redirect":
        dequeue(count);
        stats.dropped.rejected += count;
        stats.failures.redirect += 1;
        failing("redirect", result.status);
        terminal("redirect", result.status);
        return;
      case "oversize":
        failing("oversize", result.status);
        if (count <= 1) {
          dequeue(count);
          stats.dropped.oversize += count;
          terminal("oversize", result.status);
        } else {
          // Bounded split: halve the cap for the events of this batch; every
          // 413 either shrinks the cap or drops a single event.
          splitRemaining = Math.max(splitRemaining, count);
          splitCap = Math.ceil(count / 2);
          attempts = 0;
          backoffUntil = 0;
        }
        return;
      // A non-204 2xx is never acceptance: it is retried like a retryable
      // failure and counted as dropped.protocol once the budget runs out.
      case "protocol":
      case "retry": {
        if (result.outcome === "protocol") {
          failing("protocol", result.status);
        } else {
          if (result.reason === "storage") stats.failures.storage += 1;
          if (result.reason === "transport" || result.reason === "timeout") stats.failures.transport += 1;
          failing(result.reason, result.status);
        }
        // Every attempt counts, whatever the delay before the next one.
        attempts += 1;
        const now = clock.now();
        // Past the batch deadline: expire() drops these events (dropped.deadline)
        // before any further attempt or wait.
        if (deadline <= now) return;
        if (attempts >= limits.maxAttempts) {
          dequeue(count);
          if (result.outcome === "protocol") {
            stats.dropped.protocol += count;
            terminal("protocol", result.status);
          } else {
            stats.dropped.retryExhausted += count;
          }
          return;
        }
        const requested = result.outcome === "retry" && result.retryAfterMs !== undefined
          ? result.retryAfterMs
          : backoff();
        backoffUntil = now + boundRetryDelay(requested, deadline - now, flushRemaining(now));
        return;
      }
    }
  }

  async function attempt(batch: Queued[], controller: AbortController, timeoutMs: number): Promise<SinkResult> {
    const timeoutResult: SinkResult = { outcome: "retry", reason: "timeout" };
    let timeout: unknown = null;
    const aborted = new Promise<SinkResult>((resolve) => {
      if (controller.signal.aborted) resolve(timeoutResult);
      controller.signal.addEventListener("abort", () => resolve(timeoutResult), { once: true });
    });
    timeout = clock.setTimeout(() => controller.abort(), timeoutMs);
    try {
      // A sink that throws (sync or async) is a transport failure, never a product failure.
      const sent = Promise.resolve()
        .then(() => sink.send(batch.map((item) => item.envelope), controller.signal))
        .catch((): SinkResult => ({ outcome: "retry", reason: "transport" }));
      return await Promise.race([sent, aborted]);
    } finally {
      clock.clearTimeout(timeout);
    }
  }

  function pump(): void {
    if (inFlight || queue.length === 0) {
      notifyIdle();
      return;
    }
    const now = clock.now();
    expire(now);
    if (queue.length === 0) {
      notifyIdle();
      return;
    }
    if (backoffUntil > now) {
      schedule(backoffUntil - now);
      return;
    }
    // At the flush deadline the flush gives up; no new request is started.
    const flushLeft = flushRemaining(now);
    if (flushLeft !== undefined && flushLeft <= 0) return;
    const batch = nextBatch();
    const deadline = batchDeadline(batch);
    // Never longer than the request timeout, the batch's remaining delivery
    // budget (positive: expired events were just dropped) or the flush budget.
    const timeoutMs = Math.min(limits.requestTimeoutMs, deadline - now, flushLeft ?? Number.POSITIVE_INFINITY);
    const controller = new AbortController();
    const started = epoch;
    const done = attempt(batch, controller, timeoutMs).then((result) => {
      inFlight = null;
      // An abandoned attempt's batch was already counted and dequeued by
      // flush; only events captured since then remain, and they are scheduled.
      if (started === epoch) apply(result, batch.length, deadline);
      afterAttempt();
    }, () => {
      inFlight = null;
      notifyIdle();
    });
    inFlight = { controller, done, count: batch.length, epoch: started };
  }

  function afterAttempt(): void {
    const now = clock.now();
    expire(now);
    if (queue.length === 0) {
      notifyIdle();
      return;
    }
    if (backoffUntil > now) schedule(backoffUntil - now);
    // A head batch mid-retry whose wait has elapsed (e.g. `Retry-After: 0`, or a
    // wait clipped to 0 by its budget) is retried now, never after the flush interval.
    else if (flushing > 0 || queue.length >= limits.maxBatchEvents || attempts > 0) schedule(0);
    else schedule(limits.flushIntervalMs);
  }

  function capture(input: CaptureInput): void {
    try {
      stats.captured += 1;
      if (disabled) return;
      const envelope = projectEvent(input, { deploymentId, traceId: bootTraceId, now: clock.now });
      const bytes = Buffer.byteLength(JSON.stringify(envelope));
      if (bytes > limits.maxEventBytes) {
        stats.dropped.oversize += 1;
        return;
      }
      if (queue.length + 1 > limits.queueMaxEvents || queueBytes + bytes > limits.queueMaxBytes) {
        stats.dropped.queueFull += 1;
        return;
      }
      queue.push({ envelope, bytes, deadline: clock.now() + limits.deliveryDeadlineMs });
      queueBytes += bytes;
      if (inFlight) return;
      if (flushing > 0 || queue.length >= limits.maxBatchEvents) {
        if (backoffUntil <= clock.now()) schedule(0);
      } else if (timer === null) {
        schedule(limits.flushIntervalMs);
      }
    } catch {
      stats.dropped.invalid += 1;
    }
  }

  async function flush(deadline: number): Promise<FlushResult> {
    const sentBefore = stats.sent.events;
    const droppedBefore = droppedTotal(stats);
    try {
      if (!disabled && (queue.length > 0 || inFlight)) {
        flushing += 1;
        flushDeadlines.push(deadline);
        try {
          let deadlineTimer: unknown = null;
          let waiter: () => void = () => undefined;
          const reachedDeadline = await new Promise<boolean>((resolve) => {
            waiter = () => resolve(false);
            idleWaiters.push(waiter);
            deadlineTimer = clock.setTimeout(
              () => resolve(true),
              Math.max(0, deadline - clock.now()),
              { keepAlive: true },
            );
            if (!inFlight && (backoffUntil <= clock.now())) schedule(0);
          });
          clock.clearTimeout(deadlineTimer);
          const index = idleWaiters.indexOf(waiter);
          if (index >= 0) idleWaiters.splice(index, 1);
          if (reachedDeadline) {
            // Give up: the request in flight is aborted and its result ignored.
            // Its events may have been committed, so they count as `aborted`;
            // the rest were never attempted and count as `shutdown`.
            const abandoned = inFlight && inFlight.epoch === epoch ? Math.min(inFlight.count, queue.length) : 0;
            epoch += 1;
            stats.dropped.aborted += abandoned;
            stats.dropped.shutdown += queue.length - abandoned;
            dequeue(queue.length);
            splitRemaining = 0;
            if (timer !== null) {
              clock.clearTimeout(timer);
              timer = null;
            }
            // Abort last: anything captured from here on is new work, scheduled
            // by the abandoned attempt's handler once the abort settles.
            inFlight?.controller.abort();
          }
        } finally {
          flushing -= 1;
          const index = flushDeadlines.indexOf(deadline);
          if (index >= 0) flushDeadlines.splice(index, 1);
        }
      }
    } catch {
      // flush never rejects.
    }
    return { sent: stats.sent.events - sentBefore, dropped: droppedTotal(stats) - droppedBefore };
  }

  function recordGateway(counter: AnalyticsGatewayCounter, amount = 1): void {
    if (!Number.isSafeInteger(amount) || amount < 0) return;
    const gateway = stats.gateway;
    if (counter.startsWith("rejected.")) {
      const reason = counter.slice("rejected.".length);
      if (Object.hasOwn(gateway.rejected, reason)) {
        gateway.rejected[reason as keyof typeof gateway.rejected] += amount;
      }
      return;
    }
    if (counter === "requests" || counter === "accepted" || counter === "clock_adjusted") gateway[counter] += amount;
  }

  return {
    bootTraceId,
    capture,
    flush,
    recordGateway,
    stats() {
      return {
        ...stats,
        sent: { ...stats.sent },
        dropped: { ...stats.dropped },
        failures: { ...stats.failures },
        queueEvents: queue.length,
        queueBytes,
        gateway: { ...stats.gateway, rejected: { ...stats.gateway.rejected } },
      };
    },
  };
}
