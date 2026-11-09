// analytics collector: the HTTP listener. Routes: POST /v1/events (internal,
// producer-authenticated batch intake) and GET /healthz. Request handling
// follows design §3 in order: route and method, content type, authorization,
// in-flight gate, bounded streamed body, validation, line size, commit. Error
// bodies are `{ "error": "<code>" }` (plus `index` for a per-event problem);
// they never carry event content, tokens or exception text.
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { CollectorLimits } from "./config.js";
import type { Producer, ProducerRegistry } from "./producers.js";
import type { SegmentStore } from "./storage.js";
import { BatchRejection, validateBatch, type CollectorRegistries } from "./validate.js";

export const EVENTS_PATH = "/v1/events";
export const HEALTH_PATH = "/healthz";

export type CollectorLog = (message: string, fields?: Record<string, unknown>) => void;

type RejectedCounter = "unauthorized" | "forbidden" | "invalid" | "oversize" | "busy" | "timeout" | "capacity";

export type CollectorHealth = {
  ok: boolean;
  segments: number;
  disk_bytes: number;
  accepted: { batches: number; events: number };
  rejected: Record<RejectedCounter, number>;
  write_failures: number;
  retention_loss: { segments: number; bytes: number };
  producers: Record<string, { accepted_batches: number; rejected: number }>;
};

export type CollectorServerOptions = {
  limits: CollectorLimits;
  producers: ProducerRegistry;
  registries: CollectorRegistries;
  storage: SegmentStore;
  log?: CollectorLog;
};

export type CollectorServer = {
  server: Server;
  health(): CollectorHealth;
  /** Stops accepting, lets in-flight requests and commits finish, then closes. Resolves by the deadline. */
  shutdown(deadlineMs: number): Promise<{ completed: boolean }>;
};

const BEARER = /^Bearer ([\x21-\x7e]{1,4096})$/i;
const STORAGE_RETRY_AFTER_SECONDS = "5";

/** Thrown inside the body reader; carries only a status and code. */
class RequestFailure extends Error {
  constructor(readonly status: 408 | 413, readonly code: "timeout" | "payload_too_large") {
    super(code);
  }
}

/** Exactly one Authorization header (node keeps only the first in `headers`, so count `rawHeaders`). */
function bearerToken(request: IncomingMessage): string | null {
  let value: string | undefined;
  let count = 0;
  for (let i = 0; i < request.rawHeaders.length; i += 2) {
    if (request.rawHeaders[i]!.toLowerCase() === "authorization") {
      count += 1;
      value = request.rawHeaders[i + 1];
    }
  }
  if (count !== 1 || value === undefined) return null;
  const match = BEARER.exec(value.trim());
  return match ? match[1]! : null;
}

function isJson(request: IncomingMessage): boolean {
  const header = request.headers["content-type"];
  if (typeof header !== "string") return false;
  const [type, ...parameters] = header.split(";").map((part) => part.trim().toLowerCase());
  if (type !== "application/json") return false;
  return parameters.every((parameter) => parameter === "" || parameter === "charset=utf-8");
}

export function createCollectorServer(options: CollectorServerOptions): CollectorServer {
  const { limits, producers, registries, storage } = options;
  const log = options.log ?? (() => {});
  const accepted = { batches: 0, events: 0 };
  const rejected: Record<RejectedCounter, number> = {
    unauthorized: 0,
    forbidden: 0,
    invalid: 0,
    oversize: 0,
    busy: 0,
    timeout: 0,
    capacity: 0,
  };
  const perProducer = new Map<string, { accepted_batches: number; rejected: number }>(
    producers.list().map((producer) => [producer.name, { accepted_batches: 0, rejected: 0 }]),
  );
  let inFlight = 0;
  let draining = false;
  const idleWaiters: Array<() => void> = [];

  function release(): void {
    inFlight -= 1;
    if (inFlight === 0) for (const resolve of idleWaiters.splice(0)) resolve();
  }

  function send(
    response: ServerResponse,
    status: number,
    body: Record<string, unknown> | null,
    headers: Record<string, string> = {},
    close = false,
  ): void {
    if (response.headersSent) return;
    const payload = body === null ? "" : JSON.stringify(body);
    response.writeHead(status, {
      ...headers,
      ...(body === null ? {} : { "content-type": "application/json", "content-length": Buffer.byteLength(payload) }),
      "cache-control": "no-store",
      ...(close || draining ? { connection: "close" } : {}),
    });
    response.end(payload);
  }

  /** Counts a refused request globally and, once authenticated, against its producer. */
  function refuse(producer: Producer | null, counter: RejectedCounter | null): void {
    if (counter) rejected[counter] += 1;
    if (producer) perProducer.get(producer.name)!.rejected += 1;
  }

  /** Streams the body under the byte cap and the read deadline. */
  function readBody(request: IncomingMessage): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const declared = Number(request.headers["content-length"]);
      if (Number.isFinite(declared) && declared > limits.maxBatchBytes) {
        reject(new RequestFailure(413, "payload_too_large"));
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      let settled = false;
      const finish = (error: Error | null): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        request.off("data", onData);
        request.off("end", onEnd);
        request.off("error", onError);
        request.off("aborted", onError);
        if (error) {
          // Stop reading; the connection is closed after the answer.
          request.pause();
          reject(error);
        } else {
          resolve(Buffer.concat(chunks, size));
        }
      };
      const onData = (chunk: Buffer): void => {
        size += chunk.length;
        if (size > limits.maxBatchBytes) finish(new RequestFailure(413, "payload_too_large"));
        else chunks.push(chunk);
      };
      const onEnd = (): void => finish(null);
      const onError = (): void => finish(new Error("request stream failed"));
      const timer = setTimeout(() => finish(new RequestFailure(408, "timeout")), limits.requestTimeoutMs);
      timer.unref();
      request.on("data", onData);
      request.on("end", onEnd);
      request.on("error", onError);
      request.on("aborted", onError);
    });
  }

  /** Answers, then drops the connection so an unread upload is not drained. */
  function sendAndDestroy(
    request: IncomingMessage,
    response: ServerResponse,
    status: number,
    body: Record<string, unknown>,
    headers: Record<string, string> = {},
  ): void {
    send(response, status, body, headers, true);
    response.once("finish", () => setImmediate(() => request.destroy()));
  }

  async function events(request: IncomingMessage, response: ServerResponse): Promise<void> {
    // 2. Authorization: nothing is read from the body before it completes.
    const token = bearerToken(request);
    const producer = token === null ? null : producers.authenticate(token);
    if (!producer) {
      refuse(null, "unauthorized");
      // An unauthenticated or refused upload is not drained.
      sendAndDestroy(request, response, 401, { error: "unauthorized" }, { "www-authenticate": "Bearer" });
      return;
    }
    // 3. In-flight gate (and drain: a request on a kept-alive socket during shutdown).
    if (draining || inFlight >= limits.maxInFlight) {
      refuse(producer, "busy");
      sendAndDestroy(request, response, draining ? 503 : 429, { error: "busy" }, { "retry-after": "1" });
      return;
    }
    inFlight += 1;
    try {
      // 4. Bounded streamed body.
      let body: Buffer;
      try {
        body = await readBody(request);
      } catch (error) {
        if (error instanceof RequestFailure) {
          refuse(producer, error.status === 413 ? "oversize" : "timeout");
          sendAndDestroy(request, response, error.status, { error: error.code });
        } else {
          refuse(producer, null);
          request.destroy();
        }
        return;
      }
      // 5-8. Whole-batch validation; nothing is written for a refused batch.
      let lines: string[];
      try {
        lines = validateBatch(body, {
          producer,
          registries,
          maxBatchEvents: limits.maxBatchEvents,
          maxEventBytes: limits.maxEventBytes,
        }).lines;
      } catch (error) {
        if (!(error instanceof BatchRejection)) throw error;
        refuse(
          producer,
          error.status === 403 ? "forbidden" : error.status === 413 ? "oversize" : "invalid",
        );
        send(response, error.status, {
          error: error.code,
          ...(error.index !== undefined ? { index: error.index } : {}),
        });
        return;
      }
      // 9. Durable commit; 204 only after file fsync, rename and directory fsync.
      const result = await storage.commit(lines);
      if (!result.ok) {
        if (result.reason === "capacity") {
          refuse(producer, "capacity");
          log("storage exhausted", { producer: producer.name, events: lines.length });
        } else {
          refuse(producer, null);
          log("write failure", { producer: producer.name, events: lines.length, ...(result.fsCode ? { code: result.fsCode } : {}) });
        }
        send(response, 507, { error: "storage_exhausted" }, { "retry-after": STORAGE_RETRY_AFTER_SECONDS });
        return;
      }
      accepted.batches += 1;
      accepted.events += lines.length;
      perProducer.get(producer.name)!.accepted_batches += 1;
      send(response, 204, null);
    } finally {
      release();
    }
  }

  function health(): CollectorHealth {
    const stored = storage.stats();
    return {
      ok: !draining,
      segments: stored.segments,
      disk_bytes: stored.diskBytes,
      accepted: { ...accepted },
      rejected: { ...rejected },
      write_failures: stored.writeFailures,
      retention_loss: stored.retentionLoss,
      producers: Object.fromEntries([...perProducer].map(([name, counters]) => [name, { ...counters }])),
    };
  }

  const server = createServer((request, response) => {
    const path = (request.url ?? "").split("?")[0];
    if (path === HEALTH_PATH) {
      if (request.method !== "GET") {
        send(response, 405, { error: "method_not_allowed" }, { allow: "GET" }, true);
        return;
      }
      send(response, 200, health());
      return;
    }
    if (path !== EVENTS_PATH) {
      send(response, 404, { error: "not_found" }, {}, true);
      return;
    }
    // 1. Method, then content type.
    if (request.method !== "POST") {
      sendAndDestroy(request, response, 405, { error: "method_not_allowed" }, { allow: "POST" });
      return;
    }
    if (!isJson(request)) {
      sendAndDestroy(request, response, 415, { error: "unsupported_media_type" });
      return;
    }
    events(request, response).catch(() => {
      // Unexpected: answer with a code only; the exception text is never logged or sent.
      log("internal error", {});
      if (!response.headersSent) send(response, 500, { error: "internal" }, {}, true);
      else response.destroy();
    });
  });
  // Backstops for slow headers; the body deadline is enforced per request above.
  server.headersTimeout = Math.min(60_000, limits.requestTimeoutMs + 1000);
  server.requestTimeout = limits.requestTimeoutMs + 5000;

  async function shutdown(deadlineMs: number): Promise<{ completed: boolean }> {
    draining = true;
    const closed = new Promise<void>((resolve) => server.close(() => resolve()));
    server.closeIdleConnections();
    let timer: NodeJS.Timeout | undefined;
    const deadline = new Promise<false>((resolve) => {
      timer = setTimeout(() => resolve(false), deadlineMs);
    });
    const drained = (async () => {
      if (inFlight > 0) await new Promise<void>((resolve) => idleWaiters.push(resolve));
      await storage.idle();
      return true as const;
    })();
    const completed = await Promise.race([drained, deadline]);
    clearTimeout(timer);
    server.closeAllConnections();
    await closed;
    return { completed };
  }

  return { server, health, shutdown };
}
