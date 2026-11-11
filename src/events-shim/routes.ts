import type { IncomingMessage, ServerResponse } from "node:http";
import {
  EVENTS_SHIM_LIMITS,
  handleEventsShimRequest,
  type EventsShimHttpOptions,
  type ShimUrls,
} from "@agent-relay/events-shim";
import type { EncryptionKeyring } from "../crypto.js";
import type { Database } from "../database.js";
import { PostgresEventsShimStore, type EventsShimCreator } from "./store.js";

/** Every events-shim route lives under this normalized (/cloud-stripped) prefix. */
export const EVENTS_SHIM_PREFIX = "/api/v1/events-shim";
/** Largest request body read: the package's webhook and MCP limit. */
const MAX_BODY_BYTES = EVENTS_SHIM_LIMITS.maxBodyBytes;

export function isEventsShimPath(path: string): boolean {
  return path === EVENTS_SHIM_PREFIX || path.startsWith(`${EVENTS_SHIM_PREFIX}/`);
}

export type EventsShimRoutesInput = {
  database: Database;
  keyring: EncryptionKeyring;
  /** The configured public origin; every MCP and webhook URL is built on it. */
  publicBaseUrl: string;
  /** Relaycast origins a wake link may name. */
  relayOrigins: readonly string[];
  fetchImpl?: typeof fetch;
  now?: () => Date;
  /**
   * Admits `POST /shims`: authenticates a signed-in person, applies the
   * per-user limit and names the creator. Throws the host's HTTP error to refuse.
   */
  authorizeCreate(request: IncomingMessage, response: ServerResponse): Promise<EventsShimCreator>;
  pollIntervalMs?: number;
};

export function eventsShimUrls(publicBaseUrl: string): ShimUrls {
  const base = `${publicBaseUrl.replace(/\/+$/, "")}${EVENTS_SHIM_PREFIX}`;
  return {
    mcpUrl: (token) => `${base}/t/${token}/mcp`,
    hookUrl: (token, mode) => `${base}/h/${token}${mode === "open" ? "" : `/${mode}`}`,
  };
}

/**
 * The events-shim routes (docs/events-shim.md), mounted by the app only
 * while the `events_shim` feature is selected. Adapts node:http to the
 * package's Web `Request` handler. Returns false for a path it does not own.
 */
export function createEventsShimRoutes(input: EventsShimRoutesInput) {
  const urls = eventsShimUrls(input.publicBaseUrl);
  const clock = input.now ?? (() => new Date());

  return async function handle(
    request: IncomingMessage,
    response: ServerResponse,
    path: string,
    method: string,
  ): Promise<boolean> {
    if (!isEventsShimPath(path)) return false;
    const relative = path.slice(EVENTS_SHIM_PREFIX.length) || "/";

    const declared = Number(request.headers["content-length"] ?? "0");
    if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
      await send(response, tooLarge());
      return true;
    }
    const body = method === "GET" || method === "HEAD" ? null : await readBounded(request, MAX_BODY_BYTES);
    if (body === undefined) {
      await send(response, tooLarge());
      return true;
    }

    // Ends a long-poll (wait_for_webhook) when the client goes away.
    const aborted = new AbortController();
    response.once("close", () => {
      if (!response.writableEnded) aborted.abort();
    });
    const headers = new Headers();
    for (const [name, value] of Object.entries(request.headers)) {
      if (value === undefined || name.startsWith(":")) continue;
      headers.set(name, Array.isArray(value) ? value.join(", ") : value);
    }
    const webRequest = new Request(new URL(request.url ?? "/", input.publicBaseUrl), {
      method,
      headers,
      ...(body !== null ? { body } : {}),
      signal: aborted.signal,
    });

    // The creator is set by beforeCreate and read by the store's insert in the same request.
    let creator: EventsShimCreator | undefined;
    const store = new PostgresEventsShimStore(input.database, input.keyring, () => creator);
    const options: EventsShimHttpOptions = {
      deps: { store, now: clock, ...(input.fetchImpl ? { fetchImpl: input.fetchImpl } : {}) },
      urls,
      relayOrigins: input.relayOrigins,
      ...(input.pollIntervalMs ? { pollIntervalMs: input.pollIntervalMs } : {}),
      beforeCreate: async () => {
        creator = await input.authorizeCreate(request, response);
        // Opportunistic cleanup: expired inboxes and stale feeds of idle ones.
        const now = clock().getTime();
        await store.prune({
          idleBefore: new Date(now - EVENTS_SHIM_LIMITS.idleExpiryMs).toISOString(),
          feedBefore: new Date(now - EVENTS_SHIM_LIMITS.feedRetentionMs).toISOString(),
        }).catch(() => undefined);
        return undefined;
      },
    };
    const answer = await handleEventsShimRequest(webRequest, relative, options);
    await send(response, answer ?? new Response(JSON.stringify({ error: "Not found" }), {
      status: 404,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    }));
    return true;
  };
}

function tooLarge(): Response {
  return new Response(JSON.stringify({
    error: "payload_too_large",
    message: `Bodies are limited to ${MAX_BODY_BYTES / 1024} KB.`,
  }), { status: 413, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

/** The body as bytes, or undefined once it passes `limit`. */
async function readBounded(request: IncomingMessage, limit: number): Promise<Uint8Array<ArrayBuffer> | undefined> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > limit) return undefined;
    chunks.push(buffer);
  }
  return new Uint8Array(Buffer.concat(chunks));
}

async function send(response: ServerResponse, answer: Response): Promise<void> {
  const headers: Record<string, string> = {};
  answer.headers.forEach((value, name) => {
    headers[name] = value;
  });
  const body = Buffer.from(await answer.arrayBuffer());
  if (response.writableEnded || response.destroyed) return;
  response.writeHead(answer.status, headers);
  response.end(body);
}
