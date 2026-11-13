import type { IncomingMessage, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { JSONRPCRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { ApiTokenStore } from "../admin/api-tokens.js";
import { cookieRequestAllowed } from "../auth/device-approval.js";
import { DesktopMcpCredentials } from "../auth/desktop-mcp-credentials.js";
import type { SelfhostConfig } from "../config.js";
import { mcpOAuthActive } from "./oauth/config.js";
import { secureEqual } from "../crypto.js";
import type { AmpDeps } from "../amp/service.js";
import type { FactoryMcpDeps } from "../factory/mcp-tools.js";
import { createRelaycastClient } from "../messaging/relaycast.js";
import { providerStatuses, type ProviderProbes } from "../providers/registry.js";
import type { ControlPlaneStore } from "../store.js";
import { MCP_FACADE, type McpAuthMode } from "./catalog.js";
import { historyReader, type McpContext, type McpMember } from "./context.js";
import { ClaudeAttestationError, claudeAttestationFor, type ClaudeAttestation } from "./claude-attestation.js";
import { CopilotAttestationError, copilotAttestationFor, postgresAttestationStore, type CopilotAttestation } from "./copilot-attestation.js";
import { desktopCallContext, DesktopCallContextError } from "./desktop-call.js";
import { auditUnhandledReadCalls } from "./read-audit.js";
import { buildMcpServer } from "./server.js";
import { admitMcpOAuthBearer, type McpOAuthConnection } from "./oauth/admission.js";
import type { McpOAuthSessions } from "./oauth/sessions.js";
import { MCP_RELAY_SCOPE, type McpOAuthResourcePath } from "./oauth/protocol.js";
import { sendCustomerSupport } from "./customer-support.js";
import { customerSupportDesktop } from "./customer-support-notice.js";

/**
 * `POST /api/v1/mcp/shared-sessions` (also `/cloud/api/v1/...`, the path
 * Agent Relay Desktop uses), ported from Cloud's
 * `app/api/v1/mcp/shared-sessions/route.ts`: a stateless Streamable HTTP MCP
 * endpoint with JSON responses. Every refusal is a JSON-RPC error envelope.
 */

const MAX_BODY_BYTES = 64 * 1024;
/** Copilot calls carry a signed proof of the exact arguments, so their cap is larger (Cloud's limit). */
const COPILOT_MAX_BODY_BYTES = 128 * 1024;
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

function withoutDesktopMarker(headers: Headers): Headers {
  const copy = new Headers(headers);
  copy.delete("x-agent-relay-desktop");
  return copy;
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

/** Reads at most `limit` bytes; a larger body is refused before it is buffered. */
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
  /** Factory tools and resolver hook, only when SELFHOST_FACTORY_ENABLED is on. */
  factory?: FactoryMcpDeps;
  /** Internal native send resolver, never supplied to OAuth or managed calls. */
  capy?: McpContext["capy"];
  /** Optional exact-grant Capy send permits, supplied only to OAuth contexts. */
  capyPermits?: McpContext["capyPermits"];
  /** Provider runtime probes (src/providers/registry.ts); empty when unset. */
  providerProbes?: ProviderProbes;
  /** SELFHOST_FEATURES launch: register the agent launch tools. */
  launch?: boolean;
  /** Own credential resolver, used only at these MCP routes when the module is enabled. */
  oauthSessions?: McpOAuthSessions;
  /** Clock for shared-session read audit records; tests inject it. */
  now?: () => Date;
}) {
  const { config, store } = input;
  const apiTokens = new ApiTokenStore(store.database);
  const desktopCredentials = new DesktopMcpCredentials(store.database);
  const attestations = postgresAttestationStore(store.database);
  const relaycast = createRelaycastClient({ internalOrigin: config.relaycastUrl, fetchImpl: input.fetchImpl });
  // Citations open the dashboard's session page.
  const citationOrigin = new URL(config.dashboardUrl).origin;
  const oauthSessions = mcpOAuthActive(config) ? input.oauthSessions : undefined;
  const oauthProtocol = oauthSessions?.options.protocol;
  function resourceFor(path: string): McpOAuthResourcePath | null {
    const clean = path.replace(/\/+$/u,"");
    if (clean === "/mcp" || clean === "/cloud/mcp") return "/mcp";
    if (clean === MCP_FACADE.path || clean === "/cloud"+MCP_FACADE.path) return "/api/v1/mcp/shared-sessions";
    return null;
  }
  function challenge(path: string, invalid: boolean, scopes?: string[]): string {
    const resource = resourceFor(path);
    if (!oauthProtocol || !resource || !oauthProtocol.mcpOAuthResourceAvailable(resource)) {
      return invalid ? 'Bearer error="invalid_token"' : "Bearer";
    }
    return oauthProtocol.mcpOAuthChallenge(oauthProtocol.mcpResourceUrl(resource),{
      ...(invalid ? { error: "invalid_token" as const } : {}),
      ...(scopes ? { error: "insufficient_scope" as const, scopes } : {}),
    });
  }

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
      rpcError(response, 401, -32001, "Unauthorized", null, { "www-authenticate": challenge(rawPath,false) });
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
    if (headerToken?.startsWith("mcp_at_") && oauthSessions) {
      const resourcePath = resourceFor(rawPath);
      const access = resourcePath ? await admitMcpOAuthBearer({sessions:oauthSessions,token:headerToken,resourcePath}) : null;
      if (!access?.ok) {
        const status = access?.status ?? 401;
        rpcError(response,status,status===403?-32003:-32001,status===403?"Forbidden":"Unauthorized",null,{
          "www-authenticate":challenge(rawPath,status!==403,status===403?[MCP_RELAY_SCOPE]:undefined),
        });
        return null;
      }
      const principal = access.connection.access.principal;
      const workspace = await store.workspaceForUser(principal.workspaceId,principal.userId);
      if (!workspace || workspace.organizationId !== principal.organizationId) {
        rpcError(response,401,-32001,"Unauthorized",null,{"www-authenticate":challenge(rawPath,true)});
        return null;
      }
      return {principal,workspace,authMode:"oauth" as McpAuthMode,token:headerToken,
        provider:undefined as string|undefined,oauth:access.connection};
    }
    const principal = await store.authenticateAccessToken(token);
    // A Desktop provider credential (mcp:desktop child token) is honoured only
    // here, only as a header bearer, and only while its verified parent and
    // the membership are live (resolve re-checks both on every request).
    const provider = !principal && headerToken ? await desktopCredentials.resolve(headerToken) : null;
    if (provider) {
      const workspace = await store.workspaceForUser(provider.principal.workspaceId, provider.principal.userId);
      if (!workspace) {
        forbidden();
        return null;
      }
      return { principal: provider.principal, workspace, authMode: "cli_login" as McpAuthMode, token: headerToken!,
        provider: provider.provider, oauth:undefined as McpOAuthConnection|undefined };
    }
    if (!principal) {
      rpcError(response, 401, -32001, "Unauthorized", null, {
        "www-authenticate": challenge(rawPath,Boolean(headerToken)),
      });
      return null;
    }
    if (!principal.scopes.includes("cli:auth") || principal.pendingHandoff || principal.handoff) {
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
    return { principal, workspace, authMode, token, provider: undefined as string | undefined,
      oauth:undefined as McpOAuthConnection|undefined };
  }

  return async function handle(
    request: IncomingMessage,
    response: ServerResponse,
    path: string,
    method: string,
  ): Promise<boolean> {
    if (path !== MCP_FACADE.path && !(oauthSessions && (path==="/mcp" || path==="/cloud/mcp"))) return false;
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
      raw = await boundedBody(request, admitted.provider === "copilot" ? COPILOT_MAX_BODY_BYTES : MAX_BODY_BYTES);
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
    const { principal, workspace, authMode, token, provider, oauth } = admitted;
    let desktopCall;
    try {
      // Always strips `_agent_relay_attestation` from the arguments; a proof
      // that does not verify refuses the call (no unattested fallback).
      // Copilot credentials carry a Copilot proof; every other call may carry
      // a Claude Code proof, which counts only on desktop-managed calls (as Cloud).
      const auth = { workspaceId: workspace.id, userId: principal.userId, desktopMcpProvider: provider };
      // An OAuth grant acts only as its approved agent: the Desktop marker
      // never makes it managed, so its proofs are stripped and ignored.
      const callHeaders = oauth ? withoutDesktopMarker(headers) : headers;
      const attested: CopilotAttestation | ClaudeAttestation | undefined = provider === "copilot"
        ? await copilotAttestationFor(body, auth, attestations)
        : await claudeAttestationFor(body, callHeaders, auth, attestations);
      desktopCall = desktopCallContext(body, callHeaders, provider, attested);
    } catch (error) {
      // Store failures are server errors, not a refused proof.
      if (!(error instanceof CopilotAttestationError) && !(error instanceof ClaudeAttestationError) &&
          !(error instanceof DesktopCallContextError)) throw error;
      const parsed = JSONRPCRequestSchema.safeParse(body);
      rpcError(response, 400, -32602, "Invalid native chat context.", parsed.success ? parsed.data.id : null);
      return true;
    }

    const site = input.siteBaseUrl(request);
    const context: McpContext = {
      principal,
      workspace,
      authMode,
      role: workspace.role,
      origin: citationOrigin,
      endpointUrl: `${site}${rawPath}`,
      desktopCall,
      ...(oauth ? { oauth } : {}),
      readHistory: historyReader(config, principal, workspace, token),
      agentTokens: config.sessionSearchAgentTokens,
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
        relaycastPublicUrl: config.relaycastPublicUrl,
      },
      ...(!oauth && input.amp ? { amp: input.amp } : {}),
      ...(!oauth && input.factory ? { factory: input.factory } : {}),
      ...(!oauth && !desktopCall.required && desktopCall.provider === undefined && input.capy ? { capy: input.capy } : {}),
      ...(oauth && input.capyPermits ? { capyPermits: input.capyPermits } : {}),
      ...(!oauth && input.launch ? { launch: true } : {}),
      readAudit: { database: store.database, handled: new Set<string>(), ...(input.now ? { now: input.now } : {}) },
    };
    if (config.customerSupport) context.customerSupport = {
      origin: new URL(config.publicBaseUrl).origin,
      send: request => sendCustomerSupport(config.customerSupport!, request),
      notifyTarget: () => customerSupportDesktop(context),
      authorize: async () => {
        const current = oauth && oauthSessions
          ? (await admitMcpOAuthBearer({ sessions: oauthSessions, token, resourcePath: resourceFor(rawPath)! }))
          : null;
        const person = oauth ? (current?.ok ? current.connection.access.principal : null)
          : provider ? (await desktopCredentials.resolve(token))?.principal : await store.authenticateAccessToken(token);
        if (!person || person.userId !== principal.userId || person.workspaceId !== workspace.id || person.organizationId !== workspace.organizationId
          || person.pendingHandoff || person.handoff) return false;
        if (!oauth && !provider && !person.scopes.includes("cli:auth")) return false;
        const member = await store.workspaceForUser(workspace.id, principal.userId);
        return member?.organizationId === workspace.organizationId;
      },
    };

    const server = buildMcpServer(context);
    const startedAt = Date.now();
    try {
      const transport = new WebStandardStreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      await server.connect(transport);
      const url = new URL(rawPath, site);
      const webResponse = await transport.handleRequest(
        // The proof is gone from `body`; the transport never sees it.
        new Request(url, { method: "POST", headers, body: JSON.stringify(body) }),
        { parsedBody: body },
      );
      const out: Record<string, string> = {};
      webResponse.headers.forEach((value, name) => { out[name] = value; });
      out["cache-control"] = "no-store";
      if (isInitialize(body)) out["mcp-session-id"] = typeof sessionId === "string" ? sessionId : randomUUID();
      const payload = Buffer.from(await webResponse.arrayBuffer());
      // Reads refused by input validation never reach the audited handler.
      await auditUnhandledReadCalls(context, body, startedAt);
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
