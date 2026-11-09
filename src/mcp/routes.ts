import type { IncomingMessage, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { JSONRPCRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { ApiTokenStore } from "../admin/api-tokens.js";
import { cookieRequestAllowed } from "../auth/device-approval.js";
import type { SelfhostConfig } from "../config.js";
import { secureEqual } from "../crypto.js";
import type { AmpDeps } from "../amp/service.js";
import { createRelaycastClient } from "../messaging/relaycast.js";
import { providerStatuses, type ProviderProbes } from "../providers/registry.js";
import type { ControlPlaneStore } from "../store.js";
import { MCP_FACADE, type McpAuthMode } from "./catalog.js";
import { historyReader, type McpContext, type McpMember } from "./context.js";
import { desktopCallContext } from "./desktop-call.js";
import { buildMcpServer } from "./server.js";

/**
 * `POST /api/v1/mcp/shared-sessions` (also `/cloud/api/v1/...`, the path
 * Agent Relay Desktop uses), ported from Cloud's
 * `app/api/v1/mcp/shared-sessions/route.ts`: a stateless Streamable HTTP MCP
 * endpoint with JSON responses. Every refusal is a JSON-RPC error envelope.
 */

const MAX_BODY_BYTES = 64 * 1024;
const MCP_SESSION_ID = /^[A-Za-z0-9_-]{1,128}$/;
const SESSION_COOKIE = "agent_relay_session";

type JsonRpcId = string | number | null;

function rpcError(response: ServerResponse, status: number, code: number, message: string,
  id: JsonRpcId = null, headers: Record<string, string> = {}): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...headers,
  });
  response.end(JSON.stringify({ jsonrpc: "2.0", error: { code, message }, id }));
}

function bearerToken(request: IncomingMessage): string | null {
  const match = /^Bearer\s+(.+)$/i.exec(request.headers.authorization ?? "");
  return match?.[1]?.trim() || null;
}

function cookieValue(request: IncomingMessage, name: string): string | null {
  for (const part of (request.headers.cookie ?? "").split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0 || part.slice(0, separator).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(separator + 1).trim());
    } catch {
      return null;
    }
  }
  return null;
}

class BodyTooLarge extends Error {}

/** Reads at most MAX_BODY_BYTES; a larger body is refused before it is buffered. */
async function boundedBody(request: IncomingMessage): Promise<string> {
  const declared = Number(request.headers["content-length"]);
  if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) throw new BodyTooLarge();
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > MAX_BODY_BYTES) throw new BodyTooLarge();
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function webHeaders(request: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(request.headers)) {
    if (value === undefined) continue;
    headers.set(name, Array.isArray(value) ? value.join(", ") : value);
  }
  return headers;
}

function isInitialize(body: unknown): boolean {
  const messages = Array.isArray(body) ? body : [body];
  return messages.some((message) =>
    message !== null && typeof message === "object" && (message as { method?: unknown }).method === "initialize");
}

export function createMcpHandler(input: {
  config: SelfhostConfig;
  store: ControlPlaneStore;
  browserOrigins: readonly string[];
  /** The site origin the request arrived on (public API or dashboard). */
  siteBaseUrl: (request: IncomingMessage) => string;
  /** Relaycast fetch; tests inject it, the server uses global fetch. */
  fetchImpl?: typeof fetch;
  /** Amp control dependencies, only when SELFHOST_AMP_ENABLED is on. */
  amp?: AmpDeps;
  /** Provider runtime probes (src/providers/registry.ts); empty when unset. */
  providerProbes?: ProviderProbes;
}) {
  const { config, store } = input;
  const apiTokens = new ApiTokenStore(store.database);
  const relaycast = createRelaycastClient({ internalOrigin: config.relaycastUrl, fetchImpl: input.fetchImpl });
  // Citations open the dashboard's session page.
  const citationOrigin = new URL(config.dashboardUrl).origin;

  /** Returns the context, or null after writing the refusal. */
  async function admit(request: IncomingMessage, response: ServerResponse, rawPath: string) {
    const origin = request.headers.origin;
    if (typeof origin === "string" && origin && !input.browserOrigins.includes(origin)) {
      rpcError(response, 403, -32003, "Cross-origin MCP requests are forbidden.");
      return null;
    }
    const headerToken = bearerToken(request);
    const cookieToken = rawPath.startsWith("/cloud/") ? cookieValue(request, SESSION_COOKIE) : null;
    const token = headerToken ?? cookieToken;
    if (!token) {
      rpcError(response, 401, -32001, "Unauthorized", null, { "www-authenticate": "Bearer" });
      return null;
    }
    const forbidden = () => rpcError(response, 403, -32003, "Forbidden");
    // Workspace agent tokens and the service token are not a person.
    if (headerToken && config.internalServiceToken && secureEqual(headerToken, config.internalServiceToken)) {
      forbidden();
      return null;
    }
    if (headerToken?.startsWith("sh_wk_") && await apiTokens.authenticate(headerToken)) {
      forbidden();
      return null;
    }
    const principal = await store.authenticateAccessToken(token);
    if (!principal) {
      rpcError(response, 401, -32001, "Unauthorized", null, {
        "www-authenticate": headerToken ? 'Bearer error="invalid_token"' : "Bearer",
      });
      return null;
    }
    if (!principal.scopes.includes("cli:auth")) {
      forbidden();
      return null;
    }
    // A browser cookie alone must come from the dashboard itself (CSRF).
    if (!headerToken && !cookieRequestAllowed(request, input.browserOrigins)) {
      rpcError(response, 403, -32003, "Cross-origin MCP requests are forbidden.");
      return null;
    }
    const workspace = await store.workspaceForUser(principal.workspaceId, principal.userId);
    if (!workspace) {
      forbidden();
      return null;
    }
    const authMode: McpAuthMode = headerToken ? "cli_login" : "session";
    // The validated access token is used only for History reads, never exposed.
    return { principal, workspace, authMode, token };
  }

  return async function handle(
    request: IncomingMessage,
    response: ServerResponse,
    path: string,
    method: string,
  ): Promise<boolean> {
    if (path !== MCP_FACADE.path) return false;
    if (method !== "POST") {
      rpcError(response, 405, -32000, "Method not allowed", null, { allow: "POST" });
      return true;
    }
    const rawPath = new URL(request.url ?? "/", "http://localhost").pathname;
    const admitted = await admit(request, response, rawPath);
    if (!admitted) return true;

    const sessionId = request.headers["mcp-session-id"];
    if (sessionId !== undefined && (typeof sessionId !== "string" || !MCP_SESSION_ID.test(sessionId))) {
      rpcError(response, 400, -32600, "Invalid Mcp-Session-Id.");
      return true;
    }
    let raw: string;
    try {
      raw = await boundedBody(request);
    } catch (error) {
      if (error instanceof BodyTooLarge) {
        response.setHeader("connection", "close");
        rpcError(response, 413, -32600, "MCP request body is too large.");
        return true;
      }
      throw error;
    }
    let body: unknown;
    try {
      body = JSON.parse(raw);
    } catch {
      rpcError(response, 400, -32700, "Parse error");
      return true;
    }
    const headers = webHeaders(request);
    let desktopCall;
    try {
      desktopCall = desktopCallContext(body, headers);
    } catch {
      const parsed = JSONRPCRequestSchema.safeParse(body);
      rpcError(response, 400, -32602, "Invalid native chat context.", parsed.success ? parsed.data.id : null);
      return true;
    }

    const { principal, workspace, authMode, token } = admitted;
    const site = input.siteBaseUrl(request);
    const context: McpContext = {
      principal,
      workspace,
      authMode,
      role: workspace.role,
      origin: citationOrigin,
      endpointUrl: `${site}${rawPath}`,
      desktopCall,
      readHistory: historyReader(config, principal, workspace, token),
      members: async () => (await store.listMemberships(workspace.organizationId)).map((row): McpMember => ({
        userId: String(row.userId),
        email: String(row.email),
        name: typeof row.name === "string" && row.name.trim() ? row.name : null,
      })),
      providers: () => providerStatuses(input.providerProbes),
      relaycast: {
        listAgents: (status) => relaycast.listAgents(workspace.relaycastApiKey, status),
        listPresence: () => relaycast.listPresence(workspace.relaycastApiKey),
      },
      relay: {
        database: store.database,
        keyring: config.encryptionKeyring,
        client: relaycast,
        sessionId: typeof sessionId === "string" ? sessionId : undefined,
      },
      ...(input.amp ? { amp: input.amp } : {}),
    };

    const server = buildMcpServer(context);
    try {
      const transport = new WebStandardStreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      await server.connect(transport);
      const url = new URL(rawPath, site);
      const webResponse = await transport.handleRequest(
        new Request(url, { method: "POST", headers, body: raw }),
        { parsedBody: body },
      );
      const out: Record<string, string> = {};
      webResponse.headers.forEach((value, name) => { out[name] = value; });
      out["cache-control"] = "no-store";
      if (isInitialize(body)) out["mcp-session-id"] = typeof sessionId === "string" ? sessionId : randomUUID();
      const payload = Buffer.from(await webResponse.arrayBuffer());
      response.writeHead(webResponse.status, out);
      response.end(payload);
    } catch (error) {
      console.error("[selfhost-mcp] Request failed", { error: error instanceof Error ? error.name : "unknown" });
      if (!response.headersSent) rpcError(response, 500, -32603, "Internal server error");
      else response.end();
    } finally {
      await server.close().catch(() => {});
    }
    return true;
  };
}
