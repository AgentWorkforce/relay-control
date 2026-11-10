import type { IncomingMessage, ServerResponse } from "node:http";
import type { ApiTokenStore } from "../admin/api-tokens.js";

/**
 * Relay node broker (docs/relay-node-credential.md). An agent-relay-node host
 * holds a `relay-node` workspace API token instead of the workspace's
 * Relaycast key; this broker runs a fixed set of Relaycast workspace-key
 * routes for it with the stored key, which never leaves this service.
 *
 * - 401 token_invalid: no bearer, or not a live relay-node token.
 * - 403 scope_denied: any path or method outside the allowlist.
 * - 403 node_mismatch: POST nodes whose body names another node; nothing is forwarded.
 * - 502 relaycast_unavailable: no binding, Relaycast unreachable, a non-JSON
 *   answer, or Relaycast refusing the stored key (401), so a node never
 *   reads a stale workspace key as its own token being rejected. A 403 is
 *   Relaycast's decision about the request (suspended workspace, node
 *   ownership) and passes through like any other status.
 * - Otherwise Relaycast's status and JSON body pass through.
 *
 * Request headers and response bodies carry node tokens: never log them.
 */
export const RELAY_NODE_PREFIX = "/relay-node/v1";
export const RELAY_NODE_RATE_LIMIT = { limit: 600, windowMs: 60_000 };
const RELAYCAST_TIMEOUT_MS = 10_000;
const LIST_QUERY_KEYS = ["status", "limit", "cursor"] as const;
const FORWARDED_POST_HEADERS = ["idempotency-key", "x-relaycast-node-token"] as const;

export type RelayNodeDeps = {
  apiTokens: Pick<ApiTokenStore, "authenticateRelayNode">;
  relaycastUrl: string;
  relaycastBinding(workspaceId: string): Promise<{ relaycastApiKey: string } | null>;
  bearer(request: IncomingMessage): string | null;
  /** Throws (429) when `key` is over `rule`. */
  rateLimit(response: ServerResponse, key: string, rule: { limit: number; windowMs: number }): void;
  /** The raw body, refused (413) past the service's body limit. */
  bodyText(request: IncomingMessage): Promise<string>;
  json(response: ServerResponse, status: number, body: unknown, noStore: boolean): void;
  fetch?: typeof fetch;
};

type Plan =
  | { kind: "workspace" }
  | { kind: "get"; path: string; query: boolean }
  | { kind: "enroll" };

function plan(method: string, path: string): Plan | "denied" | "malformed" {
  const rest = path.slice(RELAY_NODE_PREFIX.length);
  if (method === "GET" && rest === "/workspace") return { kind: "workspace" };
  if (rest === "/nodes" && method === "POST") return { kind: "enroll" };
  if (method !== "GET") return "denied";
  if (rest === "/nodes" || rest === "/agents") return { kind: "get", path: `/v1${rest}`, query: true };
  const item = /^\/(nodes|agents)\/([^/]+)$/.exec(rest);
  if (!item) return "denied";
  let name: string;
  try {
    name = decodeURIComponent(item[2]!);
  } catch {
    return "malformed";
  }
  return { kind: "get", path: `/v1/${item[1]}/${encodeURIComponent(name)}`, query: false };
}

class Unavailable extends Error {}

export async function handleRelayNode(
  request: IncomingMessage,
  response: ServerResponse,
  method: string,
  path: string,
  deps: RelayNodeDeps,
): Promise<boolean> {
  if (path !== RELAY_NODE_PREFIX && !path.startsWith(`${RELAY_NODE_PREFIX}/`)) return false;
  const send = (status: number, body: unknown) => deps.json(response, status, body, true);
  const token = deps.bearer(request);
  const principal = token ? await deps.apiTokens.authenticateRelayNode(token) : null;
  if (!principal) {
    send(401, { error: "token_invalid", message: "A live relay-node token is required" });
    return true;
  }
  deps.rateLimit(response, `relay-node:${principal.tokenId}`, RELAY_NODE_RATE_LIMIT);
  const route = plan(method, path);
  if (route === "denied") {
    send(403, { error: "scope_denied", message: "This route is not available to relay-node tokens" });
    return true;
  }
  if (route === "malformed") {
    send(400, { error: "invalid_request", message: "Malformed path segment" });
    return true;
  }

  let forwardBody: string | undefined;
  const headers: Record<string, string> = {};
  if (route.kind === "enroll") {
    const raw = await deps.bodyText(request);
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      send(400, { error: "invalid_request", message: "Body must be valid JSON" });
      return true;
    }
    const name = parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>).name
      : undefined;
    if (typeof name !== "string" || name !== principal.nodeName) {
      send(403, { error: "node_mismatch", message: "This token may only enroll its own node" });
      return true;
    }
    forwardBody = raw;
    headers["content-type"] = request.headers["content-type"] ?? "application/json";
    for (const header of FORWARDED_POST_HEADERS) {
      const value = request.headers[header];
      if (typeof value === "string") headers[header] = value;
    }
  }

  const binding = await deps.relaycastBinding(principal.workspaceId);
  if (!binding) {
    send(502, { error: "relaycast_unavailable", message: "Relaycast is not available for this workspace" });
    return true;
  }
  headers.authorization = `Bearer ${binding.relaycastApiKey}`;

  let upstreamPath = route.kind === "workspace" ? "/v1/workspace" : route.kind === "enroll" ? "/v1/nodes" : route.path;
  if (route.kind === "get" && route.query) {
    const incoming = new URL(request.url ?? "/", "http://relay-node.invalid").searchParams;
    const query = new URLSearchParams();
    for (const key of LIST_QUERY_KEYS) {
      for (const value of incoming.getAll(key)) query.append(key, value);
    }
    const encoded = query.toString();
    if (encoded) upstreamPath += `?${encoded}`;
  }

  try {
    const answer = await relaycast(deps, upstreamPath, route.kind === "enroll" ? "POST" : "GET", headers, forwardBody);
    if (route.kind === "workspace" && answer.status === 200) {
      const envelope = answer.body as { data?: unknown };
      const data = envelope && typeof envelope.data === "object" && envelope.data !== null
        ? envelope.data as Record<string, unknown>
        : answer.body as Record<string, unknown>;
      const id = data?.id;
      const name = data?.name;
      if (typeof id !== "string" || typeof name !== "string") throw new Unavailable();
      send(200, { id, name });
      return true;
    }
    if (answer.retryAfter) response.setHeader("retry-after", answer.retryAfter);
    send(answer.status, answer.body);
  } catch (error) {
    if (!(error instanceof Unavailable)) throw error;
    send(502, { error: "relaycast_unavailable", message: "Relaycast could not complete the request" });
  }
  return true;
}

async function relaycast(
  deps: RelayNodeDeps,
  path: string,
  method: "GET" | "POST",
  headers: Record<string, string>,
  body: string | undefined,
): Promise<{ status: number; body: unknown; retryAfter: string | null }> {
  const base = deps.relaycastUrl.replace(/\/+$/, "");
  let upstream: Response;
  let text: string;
  try {
    upstream = await (deps.fetch ?? globalThis.fetch)(`${base}${path}`, {
      method,
      headers,
      body,
      redirect: "error",
      signal: AbortSignal.timeout(RELAYCAST_TIMEOUT_MS),
    });
    text = await upstream.text();
  } catch {
    throw new Unavailable();
  }
  // The stored workspace key was refused: Control's problem, not the node's token.
  if (upstream.status === 401) throw new Unavailable();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Unavailable();
  }
  return { status: upstream.status, body: parsed, retryAfter: upstream.headers.get("retry-after") };
}
