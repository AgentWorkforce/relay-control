import type { IncomingMessage, ServerResponse } from "node:http";
import {
  EVENTS_SHIM_LIMITS,
  handleEventsShimRequest,
  sha256Hex,
  type EventsShimHttpOptions,
  type ShimUrls,
} from "@agent-relay/events-shim";
import type { EncryptionKeyring } from "../crypto.js";
import type { Database } from "../database.js";
import { agentDmFetch, type AgentLinkDeps } from "./agent-link.js";
import { PostgresEventsShimStore, type EventsShimCreator } from "./store.js";
import { inboxTempWorkspace, keepTempWorkspaceAlive, TempWorkspaceError, type TempWorkspaceDeps } from "./temp-workspace.js";

/** Every events-shim route lives under this normalized (/cloud-stripped) prefix. */
export const EVENTS_SHIM_PREFIX = "/api/v1/events-shim";
/** Largest request body read: the package's webhook and MCP limit. */
const MAX_BODY_BYTES = EVENTS_SHIM_LIMITS.maxBodyBytes;

/**
 * MCP Events (SEP-3415) receiver document, served at the origin root while the
 * feature is on: it lists the path prefix of this install's `/h/<token>/mcp`
 * webhook URLs so an MCP Events server can deliver without a challenge round trip.
 */
export const MCP_WEBHOOK_RECEIVER_DOCUMENT = "/.well-known/mcp-webhook-receiver.json";
/**
 * How often an open `events/stream` re-reads Postgres. The package default is
 * 1s; 2s halves the reads per open stream and matches hosted Cloud.
 */
export const EVENTS_SHIM_STREAM_POLL_MS = 2_000;

export function isEventsShimPath(path: string): boolean {
  return path === EVENTS_SHIM_PREFIX || path.startsWith(`${EVENTS_SHIM_PREFIX}/`)
    || path === MCP_WEBHOOK_RECEIVER_DOCUMENT;
}

/** Origin-relative prefixes of the webhook URLs, for `mcpWebhookReceivers`. */
export function eventsShimMcpWebhookReceivers(publicBaseUrl: string): string[] {
  const basePath = new URL(publicBaseUrl).pathname.replace(/\/+$/, "");
  return [`${basePath}${EVENTS_SHIM_PREFIX}/h/`];
}

export type EventsShimRoutesInput = {
  database: Database;
  keyring: EncryptionKeyring;
  /** The configured public origin; every MCP and webhook URL is built on it. */
  publicBaseUrl: string;
  /** Relaycast origins a wake link may name. */
  relayOrigins: readonly string[];
  /** Relaycast's internal origin and admin secret, for each inbox's temporary workspace. */
  relaycast?: { url: string; internalSecret: string | null };
  /**
   * Gate-only install (SELFHOST_RELAYGATE_PUBLIC_URL set): no temporary
   * workspace is minted or handed out, because a laptop holding any Relaycast
   * workspace key talks to Relaycast directly, around relaygate.
   */
  gateOnly?: boolean;
  fetchImpl?: typeof fetch;
  /** Inbox links to bound agents: when set, wake forwards to an agent link become relay DMs (agent-link.ts). */
  agentLinks?: AgentLinkDeps;
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
    const relative = path === MCP_WEBHOOK_RECEIVER_DOCUMENT
      ? path
      : path.slice(EVENTS_SHIM_PREFIX.length) || "/";
    const temp: TempWorkspaceDeps | null = input.relaycast && !input.gateOnly
      ? {
        database: input.database,
        keyring: input.keyring,
        relaycastUrl: input.relaycast.url,
        internalSecret: input.relaycast.internalSecret,
        ...(input.fetchImpl ? { fetchImpl: input.fetchImpl } : {}),
        now: clock,
      }
      : null;
    const parts = relative.split("/").filter(Boolean);
    // POST /t/<mcp token>/workspace: the inbox's temporary Agent Relay workspace.
    if (method === "POST" && parts.length === 3 && parts[0] === "t" && parts[2] === "workspace") {
      await send(response, input.gateOnly
        ? gateOnlyTempWorkspace(input.publicBaseUrl)
        : await tempWorkspaceResponse(temp, parts[1]!, input.publicBaseUrl));
      return true;
    }
    // Activity keeps that workspace alive: posts (/h/<token>…) and agent calls (/t/<token>/mcp).
    if (temp && (parts[0] === "h" || parts[0] === "t") && parts[1]) {
      const hash = await sha256Hex(parts[1]);
      void keepTempWorkspaceAlive(temp, parts[0] === "h" ? { hookTokenHash: hash } : { mcpTokenHash: hash });
    }

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
      deps: {
        store,
        now: clock,
        ...(input.agentLinks
          ? { fetchImpl: agentDmFetch(input.agentLinks, input.fetchImpl) }
          : input.fetchImpl ? { fetchImpl: input.fetchImpl } : {}),
      },
      urls,
      relayOrigins: input.relayOrigins,
      mcpWebhookReceivers: eventsShimMcpWebhookReceivers(input.publicBaseUrl),
      eventsStream: { pollMs: EVENTS_SHIM_STREAM_POLL_MS },
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

const NO_STORE = { "content-type": "application/json", "cache-control": "no-store" };

/** The 404 a control plane that issues no temporary workspaces answers, with the gate-only reason. */
function gateOnlyTempWorkspace(publicBaseUrl: string): Response {
  return new Response(JSON.stringify({
    error: "not_found",
    message: `This control plane is gate-only and issues no temporary workspaces. Sign this machine's Agent Relay in to ${publicBaseUrl}.`,
  }), { status: 404, headers: NO_STORE });
}

async function tempWorkspaceResponse(temp: TempWorkspaceDeps | null, mcpToken: string, publicBaseUrl: string): Promise<Response> {
  if (!temp) {
    return new Response(JSON.stringify({ error: "not_found", message: "This control plane issues no temporary workspaces." }), { status: 404, headers: NO_STORE });
  }
  try {
    const workspace = await inboxTempWorkspace(temp, mcpToken);
    if (!workspace) {
      return new Response(JSON.stringify({ error: "not_found", message: "No webhook inbox has that MCP URL." }), { status: 404, headers: NO_STORE });
    }
    return new Response(JSON.stringify({
      workspace_id: workspace.workspaceId,
      workspace_key: workspace.workspaceKey,
      workspace_expires_at: workspace.expiresAt,
      temporary: true,
      message: `A temporary Agent Relay workspace for this inbox. It is deleted ${workspace.expiresAt.slice(0, 10)} unless the inbox is used. To use your own workspace, sign this machine's Agent Relay in to ${publicBaseUrl}.`,
    }), { status: 200, headers: NO_STORE });
  } catch (error) {
    if (error instanceof TempWorkspaceError) {
      return error.configured
        ? new Response(JSON.stringify({ error: "unavailable", message: "Try again in a minute." }), { status: 503, headers: { ...NO_STORE, "retry-after": "60" } })
        : new Response(JSON.stringify({ error: "not_configured", message: "Temporary workspaces need RELAYCAST_INTERNAL_SECRET on this control plane." }), { status: 503, headers: NO_STORE });
    }
    throw error;
  }
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
  // `events/stream` answers Server-Sent Events: write each chunk as it comes,
  // or the client sees nothing until the stream closes minutes later.
  if (answer.body && (headers["content-type"] ?? "").startsWith("text/event-stream")) {
    if (response.writableEnded || response.destroyed) {
      await answer.body.cancel().catch(() => undefined);
      return;
    }
    response.writeHead(answer.status, headers);
    response.flushHeaders();
    const reader = answer.body.getReader();
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done || response.destroyed) break;
        response.write(value);
      }
    } finally {
      await reader.cancel().catch(() => undefined);
      if (!response.writableEnded) response.end();
    }
    return;
  }
  const body = Buffer.from(await answer.arrayBuffer());
  if (response.writableEnded || response.destroyed) return;
  response.writeHead(answer.status, headers);
  response.end(body);
}
