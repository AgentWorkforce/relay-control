import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { z } from "zod";
import { admitIdentity, IDENTITY_SERVER_NAME, IdentityRefusal, withIdentityBinding } from "./environments.js";
import { ReplicaIdentityError, ReplicaIdentityUnavailable, type ReplicaIdentityClaims } from "./identity.js";
import { ReplicasError, type ReplicasDeps } from "./service.js";
import { checkRelayInbox, listRelayAgents, sendRelayMessage } from "./tools.js";

/**
 * POST /api/v1/replicas/mcp: the environment-level Replicas MCP. Stateless
 * streamable HTTP (JSON responses, no sessions, no SSE). The only accepted
 * credential is `Authorization: Bearer <workspace_identity JWT>`; Control
 * cookies, API keys, MCP OAuth and capability secrets are not accepted here.
 *
 * Admission order, nothing written until all pass: (1) token verification
 * 401 replica_identity_invalid, (2) release tombstone 403 replica_released,
 * (3) enabled environment policy, refused as well when the provider
 * organization is connected in more than one workspace, 403
 * replica_environment_not_enabled, (4) a creator mapping to a current member,
 * else (no or unmapped creator) the workspace's VM principal when it is set
 * and a current member, 403 replica_creator_not_allowed,
 * (5) binding lookup (a live launch or bind of the same replica in this
 * workspace is reused while its owner is a member) or enrolment. Every tool call repeats 2-4 under the
 * workspace lock. Pull-only: nothing is pushed into the replica's chats.
 */
const BODY_MAX_BYTES = 256 * 1024;
const MAX_BEARER = 8 * 1024 + 16;

class BodyTooLarge extends Error {}

async function boundedBody(request: IncomingMessage, limit: number): Promise<string> {
  const declared = Number(request.headers["content-length"]);
  if (Number.isFinite(declared) && declared > limit) throw new BodyTooLarge();
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > limit) throw new BodyTooLarge();
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function webHeaders(request: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(request.headers)) {
    if (value === undefined || name === "authorization" || name === "cookie") continue;
    headers.set(name, Array.isArray(value) ? value.join(", ") : value);
  }
  return headers;
}

type JsonRpcId = string | number | null;
const requestId = (body: unknown): JsonRpcId => {
  const id = body && typeof body === "object" && !Array.isArray(body) ? (body as { id?: unknown }).id : null;
  return typeof id === "string" || typeof id === "number" ? id : null;
};

function rpcError(response: ServerResponse, status: number, code: number, message: string, id: JsonRpcId = null,
  headers: Record<string, string> = {}): void {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers });
  response.end(JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id }));
}

const INVALID = { "www-authenticate": 'Bearer error="invalid_token"' };

function buildServer(deps: ReplicasDeps, claims: ReplicaIdentityClaims): McpServer {
  const server = new McpServer({ name: IDENTITY_SERVER_NAME, version: "1.0.0" });
  async function run(work: () => Promise<unknown>) {
    try {
      const data = await work();
      return { content: [{ type: "text" as const, text: JSON.stringify(data) }], structuredContent: data as Record<string, unknown> };
    } catch (error) {
      const text = error instanceof IdentityRefusal ? error.code
        : error instanceof ReplicasError ? error.message : "Agent Relay could not complete this call. Retry it.";
      return { isError: true, content: [{ type: "text" as const, text }] };
    }
  }
  const annotations = { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true };
  server.registerTool("list_relay_agents", {
    description: "List the Agent Relay agents in your workspace. Your own Relay name is returned as agent.",
    inputSchema: {}, annotations: { ...annotations, readOnlyHint: true } },
  () => run(() => withIdentityBinding(deps, claims, (binding) => listRelayAgents(deps, binding))));
  server.registerTool("check_relay_inbox", {
    description: "Read Agent Relay messages sent to you. Pass delivery ids in acknowledge to mark earlier messages handled; unacknowledged messages are returned again.",
    inputSchema: { acknowledge: z.array(z.string().min(1).max(256)).max(100).optional() }, annotations },
  ({ acknowledge }) => run(() => withIdentityBinding(deps, claims, (binding) => checkRelayInbox(deps, binding, { acknowledge: acknowledge ?? [] }))));
  server.registerTool("send_relay_message", {
    description: "Send an Agent Relay message: a DM with to (name or address), or a reply with reply_to (a message id from your inbox). request_id makes a retried send one message.",
    inputSchema: {
      to: z.string().min(1).max(256).optional(),
      reply_to: z.string().regex(/^[0-9]{1,32}$/).optional(),
      text: z.string().min(1).max(20_000),
      request_id: z.string().uuid().optional(),
    }, annotations: { ...annotations, openWorldHint: true } },
  (input) => run(() => withIdentityBinding(deps, claims, (binding) =>
    sendRelayMessage(deps, binding, { ...input, request_id: input.request_id ?? randomUUID() }))));
  return server;
}

/**
 * Answers one environment-level MCP request. The caller has already answered
 * 404 when Replicas is off. `rateLimit` (per source IP) runs before any token
 * work, so an unauthenticated flood never reaches the issuer or the database.
 */
export async function handleEnvironmentMcp(deps: ReplicasDeps, request: IncomingMessage, response: ServerResponse,
  method: string, rateLimit?: () => { allowed: boolean; retryAfterSeconds: number }): Promise<void> {
  if (!deps.identity) return rpcError(response, 404, -32004, "Not found");
  if (method !== "POST") return rpcError(response, 405, -32000, "Use POST.", null, { allow: "POST" });
  const limited = rateLimit?.();
  if (limited && !limited.allowed) {
    return rpcError(response, 429, -32000, "rate_limited", null, { "retry-after": String(limited.retryAfterSeconds) });
  }
  const header = request.headers.authorization ?? "";
  // RFC 7235: the scheme is case-insensitive and followed by any whitespace.
  const match = header.length <= MAX_BEARER ? /^Bearer\s+([A-Za-z0-9._-]+)$/i.exec(header) : null;
  if (!match) return rpcError(response, 401, -32001, "replica_identity_invalid", null, INVALID);
  let claims: ReplicaIdentityClaims;
  try {
    claims = await deps.identity.verifier.verify(match[1]!);
  } catch (error) {
    // The issuer being unreachable is not the caller's fault: no invalid_token challenge.
    if (error instanceof ReplicaIdentityUnavailable) return rpcError(response, 503, -32000, "replica_identity_unavailable");
    if (error instanceof ReplicaIdentityError) return rpcError(response, 401, -32001, "replica_identity_invalid", null, INVALID);
    return rpcError(response, 503, -32000, "replica_identity_unavailable");
  }
  let body: unknown;
  try {
    const raw = await boundedBody(request, BODY_MAX_BYTES);
    body = JSON.parse(raw) as unknown;
  } catch (error) {
    if (error instanceof BodyTooLarge) {
      response.setHeader("connection", "close");
      return rpcError(response, 413, -32000, "Request is too large.");
    }
    return rpcError(response, 400, -32700, "Parse error");
  }
  const id = requestId(body);
  try {
    // Checks 2-5; enrols on the first admitted call.
    await admitIdentity(deps, claims);
  } catch (error) {
    if (error instanceof IdentityRefusal) return rpcError(response, error.status, error.status === 409 ? -32009 : -32003, error.code, id);
    if (error instanceof ReplicasError && error.status < 500) return rpcError(response, error.status, -32000, error.message, id);
    return rpcError(response, 503, -32000, "Agent Relay could not admit this replica. Retry the call.", id);
  }
  const server = buildServer(deps, claims);
  try {
    const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    await server.connect(transport);
    const url = new URL("/api/v1/replicas/mcp", deps.identity.mcpUrl);
    const webResponse = await transport.handleRequest(
      new Request(url, { method: "POST", headers: webHeaders(request), body: JSON.stringify(body) }),
      { parsedBody: body },
    );
    const out: Record<string, string> = {};
    webResponse.headers.forEach((value, name) => { out[name] = value; });
    out["cache-control"] = "no-store";
    const payload = Buffer.from(await webResponse.arrayBuffer());
    response.writeHead(webResponse.status, out);
    response.end(payload);
  } catch {
    if (!response.headersSent) rpcError(response, 500, -32603, "Internal error", id);
  } finally {
    await server.close().catch(() => undefined);
  }
}
