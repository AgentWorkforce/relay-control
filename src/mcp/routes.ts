import type { CursorCloudDeps } from "./cursor-cloud.js";
import type { IncomingMessage, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { correlateMcpResponse, instrumentMcpTransport, withMcpDiagnosticContext } from "./request-diagnostics.js";
import type { GrokRoutines } from "./grok-routines.js";
import { connectorKind, isGrokRoutineKind } from "./oauth/connector-kind.js";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { JSONRPCRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { AGENT_IDENTITY_SCOPE, ApiTokenStore } from "../admin/api-tokens.js";
import { STAFF_READ_GRANT_PREFIX, StaffReadGrants } from "../admin/staff-read-grants.js";
import { cookieRequestAllowed } from "../auth/device-approval.js";
import { DesktopMcpCredentials } from "../auth/desktop-mcp-credentials.js";
import type { SelfhostConfig } from "../config.js";
import { mcpOAuthActive } from "./oauth/config.js";
import { secureEqual } from "../crypto.js";
import type { AmpDeps } from "../amp/service.js";
import type { ReplicasDeps } from "../replicas/service.js";
import type { AgentLinkDeps } from "../events-shim/agent-link.js";
import type { FactoryMcpDeps } from "../factory/mcp-tools.js";
import { createRelaycastClient } from "../messaging/relaycast.js";
import { relayLaunchCheck } from "./relay-launch-check.js";
import { providerStatuses, type ProviderProbes } from "../providers/registry.js";
import type { ControlPlaneStore, Principal } from "../store.js";
import { AGENT_IDENTITY_TOOLS, MCP_FACADE, STAFF_READ_GRANT_TOOLS, type McpAuthMode } from "./catalog.js";
import { historyReader, sessionAccessDeps, type McpContext, type McpMember, type McpWorkspace } from "./context.js";
import { sessionAccessConfigured } from "../sessions/access.js";
import { ClaudeAttestationError, claudeAttestationFor, type ClaudeAttestation } from "./claude-attestation.js";
import { CopilotAttestationError, copilotAttestationFor, postgresAttestationStore, type CopilotAttestation } from "./copilot-attestation.js";
import { desktopCallContext, DesktopCallContextError } from "./desktop-call.js";
import { nativeContextRefusalReason, responseCorrelationId, type NativeContextStage } from "./native-context-refusal.js";
import { auditUnhandledReadCalls } from "./read-audit.js";
import { buildMcpServer } from "./server.js";
import { admitMcpOAuthBearer, type McpOAuthConnection } from "./oauth/admission.js";
import type { McpOAuthSessions } from "./oauth/sessions.js";
import { MCP_RELAY_SCOPE, type McpOAuthResourcePath } from "./oauth/protocol.js";
import { sendCustomerSupport } from "./customer-support.js";
import { customerSupportDesktop } from "./customer-support-notice.js";
import { ownerLockFetch } from "./owner-lock-deadline.js";
import { controlSessionToken } from "../auth/session-cookie.js";

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
const SAFE_ERROR_NAMES = new Set([
  "Error", "TypeError", "RangeError", "ReferenceError", "SyntaxError", "URIError", "EvalError", "AggregateError",
  "AbortError", "TimeoutError", "DatabaseError", "PostgresError", "McpError", "UpstreamError", "SessionReadError",
]);

type JsonRpcId = string | number | null;

function rpcError(response: ServerResponse, status: number, code: number, message: string,
  id: JsonRpcId = null, headers: Record<string, string> = {}): void {
  const correlationId = response.getHeader("x-correlation-id") as string;
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...headers,
  });
  console.error("[mcp] request failed", { endpoint: "shared-sessions", status, correlationId });
  response.end(JSON.stringify({ jsonrpc: "2.0", error: { code,
    message, data: { correlation_id: correlationId } }, id }));
}

/**
 * A staff read grant may send only initialize, ping, tools/list,
 * notifications and tools/call of an allowlisted tool. Every message of a
 * batch must qualify, so an allowed call cannot hide a forbidden one. A
 * message without an id counts as a notification only under `notifications/`.
 */
export function staffReadGrantAllows(body: unknown): boolean {
  return allowlistAllows(body, STAFF_READ_GRANT_TOOLS);
}

/**
 * A workspace agent identity token is fenced the same way as a staff read
 * grant, to the Relay messaging tools and describe_capabilities
 * (AGENT_IDENTITY_TOOLS). Every other tools/call is refused before a server
 * is built, so no unlisted handler runs.
 */
export function agentIdentityAllows(body: unknown): boolean {
  return allowlistAllows(body, AGENT_IDENTITY_TOOLS);
}

function allowlistAllows(body: unknown, tools: readonly string[]): boolean {
  const messages = Array.isArray(body) ? body : [body];
  if (messages.length === 0) return false;
  return messages.every((message) => {
    if (!message || typeof message !== "object" || Array.isArray(message)) return false;
    const { method, params, id } = message as { method?: unknown; params?: unknown; id?: unknown };
    if (typeof method !== "string") return false;
    if (id === undefined) return method.startsWith("notifications/");
    if (method === "initialize" || method === "ping" || method === "tools/list") return true;
    if (method !== "tools/call" || !params || typeof params !== "object") return false;
    const name = (params as { name?: unknown }).name;
    return typeof name === "string" && tools.includes(name);
  });
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
  /** Replicas dependencies, only when SELFHOST_REPLICAS_ENABLED is on. */
  replicas?: ReplicasDeps;
  /** Webhook inbox links to bound agents, only when the events_shim feature is selected. */
  webhookInbox?: AgentLinkDeps;
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
  grokRoutines?: GrokRoutines;
  cursorCloud?: CursorCloudDeps;
  /** Clock for shared-session read audit records; tests inject it. */
  now?: () => Date;
  /** Observe handled unexpected failures without changing their MCP response. */
  onError?: (error: unknown, context: { path: string; status: number }) => void;
}) {
  const { config, store } = input;
  const apiTokens = new ApiTokenStore(store.database);
  const desktopCredentials = new DesktopMcpCredentials(store.database);
  const staffReadGrants = new StaffReadGrants(store.database, store.tenancy);
  const attestations = postgresAttestationStore(store.database);
  // Calls made under the hosted-MCP owner lock share one time budget; all others are unchanged.
  const relayFetch = ownerLockFetch(input.fetchImpl);
  const relaycast = createRelaycastClient({ internalOrigin: config.relaycastUrl, fetchImpl: relayFetch });
  function reportUnexpected(error: unknown, request: IncomingMessage, response: ServerResponse, path: string): void {
    let errorPath = path;
    try { errorPath = new URL(request.url ?? path, config.publicBaseUrl).pathname; } catch { /* Use the matched route. */ }
    try { input.onError?.(error, { path: errorPath, status: 500 }); } catch { /* Telemetry cannot change the response. */ }
    // Error.name is writable too. Keep only fixed class names, never a message.
    const name = error instanceof Error && SAFE_ERROR_NAMES.has(error.name) ? error.name : error instanceof Error ? "Error" : "unknown";
    console.error("[selfhost-mcp] Request failed", { error: name, correlationId: response.getHeader("x-correlation-id") });
  }
  // Gate-only installs only: desktop identities hold rg_ tokens that only relaygate accepts.
  const gateClient = config.relaygatePublicUrl
    ? createRelaycastClient({ internalOrigin: config.relaygatePublicUrl, fetchImpl: relayFetch })
    : undefined;
  // Gate-only installs only: relaygate checks every agent launch before it is reserved or sent.
  const launchCheck = config.relaygatePublicUrl
    ? relayLaunchCheck({ relaygatePublicUrl: config.relaygatePublicUrl, store, database: store.database,
      ...(input.fetchImpl ? { fetchImpl: input.fetchImpl } : {}) })
    : undefined;
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
    const cookieToken = rawPath.startsWith("/cloud/") ? controlSessionToken(request.headers.cookie) : null;
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
    // A workspace agent identity token: header bearer only, only on the
    // shared-sessions facade, live with a non-null expiry, purpose
    // agent-identity and exactly relay:agent. The workspace, organization and
    // agent come only from the token row; it is never a person and holds no
    // membership. Every other sh_wk_ token, and this one on any other path,
    // keeps the 403 below.
    if (headerToken?.startsWith("sh_wk_") && resourceFor(rawPath) === "/api/v1/mcp/shared-sessions") {
      const agent = await apiTokens.authenticateAgentIdentity(headerToken);
      if (agent) {
        const binding = await store.relaycastBinding(agent.workspaceId);
        if (!binding) {
          forbidden();
          return null;
        }
        const principal: Principal = {
          sessionId: agent.tokenId,
          tokenFamilyId: agent.agentIdentityId,
          userId: agent.agentIdentityId,
          email: "",
          name: agent.agentName,
          organizationId: agent.organizationId,
          organizationName: agent.organizationName,
          workspaceId: agent.workspaceId,
          workspaceName: agent.workspaceName,
          // Not a membership: the least role, never read for authorization on this path.
          role: "member",
          scopes: [AGENT_IDENTITY_SCOPE],
        };
        const workspace: McpWorkspace = {
          id: agent.workspaceId,
          organizationId: agent.organizationId,
          name: agent.workspaceName,
          relaycastWorkspaceId: binding.relaycastWorkspaceId,
          relaycastApiKey: binding.relaycastApiKey,
          role: "member",
        };
        return { principal, workspace, authMode: "agent_identity" as McpAuthMode, token: headerToken,
          provider: undefined as string | undefined, oauth: undefined as McpOAuthConnection | undefined,
          agentIdentity: { id: agent.agentIdentityId, name: agent.agentName } };
      }
    }
    if (headerToken?.startsWith("sh_wk_") && await apiTokens.authenticate(headerToken)) {
      forbidden();
      return null;
    }
    // A staff read grant: header bearer only, only on the shared-sessions
    // facade, fenced (revocation, expiry, live staff rule) on every request.
    // The holder and the pinned workspace come only from the grant row; it
    // never falls back to a membership or a person session.
    if (token.startsWith(STAFF_READ_GRANT_PREFIX)) {
      const admission = headerToken && resourceFor(rawPath) === "/api/v1/mcp/shared-sessions"
        ? await staffReadGrants.use(headerToken)
        : null;
      if (!admission) {
        rpcError(response, 401, -32001, "Unauthorized", null, { "www-authenticate": challenge(rawPath, true) });
        return null;
      }
      return { principal: admission.principal, workspace: admission.workspace, authMode: "staff_read_grant" as McpAuthMode,
        token: headerToken!, provider: undefined as string | undefined, oauth: undefined as McpOAuthConnection | undefined };
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
    // A Desktop provider credential (cld_at_ mcp:desktop child token) is
    // honoured only here, only as a header bearer on the shared-sessions
    // facade, and only while its verified parent and the membership are live
    // (resolve re-checks both on every request).
    const provider = !principal && headerToken && resourceFor(rawPath) === "/api/v1/mcp/shared-sessions"
      ? await desktopCredentials.resolve(headerToken) : null;
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

  async function handleRequest(
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
      // Copilot and Cursor proofs sign the call's arguments, so their requests
      // may be larger. A Cursor proof may also arrive on the app bearer with
      // the Desktop marker, which binds no provider (never an OAuth or staff grant).
      const desktopMarked = admitted.provider === undefined && !admitted.oauth &&
        admitted.authMode !== "staff_read_grant" && admitted.authMode !== "agent_identity" &&
        request.headers["x-agent-relay-desktop"] === "1";
      raw = await boundedBody(request, admitted.provider === "copilot" || admitted.provider === "cursor" || desktopMarked
        ? COPILOT_MAX_BODY_BYTES : MAX_BODY_BYTES);
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
    const { principal, workspace, authMode, token, provider, oauth } = admitted;
    const agentIdentity = "agentIdentity" in admitted ? admitted.agentIdentity : undefined;
    // Before any server is built: a staff read grant reaches only its allowlist.
    const staffGrant = authMode === "staff_read_grant";
    if (staffGrant && !staffReadGrantAllows(body)) {
      const parsed = JSONRPCRequestSchema.safeParse(body);
      rpcError(response, 403, -32003, "Forbidden: a staff read grant reaches only the shared-session read tools.",
        parsed.success ? parsed.data.id : null);
      return true;
    }
    // Likewise, a workspace agent identity token reaches only its allowlist.
    const agentToken = authMode === "agent_identity";
    if (agentToken && !agentIdentityAllows(body)) {
      const parsed = JSONRPCRequestSchema.safeParse(body);
      rpcError(response, 403, -32003, "Forbidden: a workspace agent identity token reaches only the Relay messaging tools.",
        parsed.success ? parsed.data.id : null);
      return true;
    }
    // Features a person's connection may reach and a grant or an agent identity never does.
    const personOnly = !staffGrant && !agentToken;
    const headers = webHeaders(request);
    let desktopCall;
    let stage: NativeContextStage = provider === "copilot" ? "copilot_attestation" : "claude_attestation";
    try {
      // Always strips `_agent_relay_attestation` from the arguments; a proof
      // that does not verify refuses the call (no unattested fallback).
      // Copilot credentials carry a Copilot proof; every other call may carry
      // a Claude Code or Cursor proof, which counts only on desktop-managed calls (as Cloud).
      const auth = { workspaceId: workspace.id, userId: principal.userId, desktopMcpProvider: provider };
      // An OAuth grant acts only as its approved agent: the Desktop marker
      // never makes it managed, so its proofs are stripped and ignored.
      const callHeaders = oauth || staffGrant || agentToken ? withoutDesktopMarker(headers) : headers;
      const attested: CopilotAttestation | ClaudeAttestation | undefined = provider === "copilot"
        ? await copilotAttestationFor(body, auth, attestations)
        : await claudeAttestationFor(body, callHeaders, auth, attestations);
      stage = "desktop_context";
      desktopCall = desktopCallContext(body, callHeaders, provider, attested);
    } catch (error) {
      // Store failures are server errors, not a refused proof.
      if (!(error instanceof CopilotAttestationError) && !(error instanceof ClaudeAttestationError) &&
          !(error instanceof DesktopCallContextError)) throw error;
      const parsed = JSONRPCRequestSchema.safeParse(body);
      // The response stays generic; the operator log joins it by correlation
      // id and names the stage and a fixed reason code (never the verifier's
      // message, the proof, the token or the arguments).
      const call = body as { method?: unknown; params?: { name?: unknown } } | null;
      console.warn("[selfhost-mcp] native chat context refused", {
        correlation_id: responseCorrelationId(response),
        stage,
        reason: nativeContextRefusalReason(stage, error),
        method: typeof call?.method === "string" ? call.method : null,
        tool: typeof call?.params?.name === "string" ? call.params.name : null,
        provider: provider ?? null,
        auth_mode: authMode,
        workspace_id: workspace.id,
        user_id: principal.userId,
      });
      rpcError(response, 400, -32602, "Invalid native chat context.", parsed.success ? parsed.data.id : null);
      return true;
    }

    const site = input.siteBaseUrl(request);
    const members = async () => (await store.listMemberships(workspace.organizationId)).map((row): McpMember => ({
      userId: String(row.userId),
      email: String(row.email),
      name: typeof row.name === "string" && row.name.trim() ? row.name : null,
    }));
    // Session access management: a person's own exchanged session only (never
    // OAuth, a Desktop provider credential, a staff grant or an agent
    // identity), on a relaygate read path.
    const sessionAccess = !oauth && personOnly && provider === undefined && sessionAccessConfigured(config) &&
      token.startsWith("sh_at_") && principal.scopes.includes("rth:read") && !principal.pendingHandoff
      ? sessionAccessDeps(config, principal, workspace, token, members) : undefined;
    const context: McpContext = {
      principal,
      workspace,
      authMode,
      // A grant or an agent identity holds no membership in the workspace.
      role: personOnly ? workspace.role : "none",
      origin: citationOrigin,
      endpointUrl: `${site}${rawPath}`,
      desktopCall,
      ...(oauth ? { oauth } : {}),
      ...(agentIdentity ? { agentIdentity } : {}),
      readHistory: historyReader(config, principal, workspace, token),
      agentTokens: config.sessionSearchAgentTokens,
      members,
      providers: async () => (await providerStatuses(input.providerProbes)).map(provider => provider.id === "grok-bot"
        ? { ...provider, mcpGroupsRegistered: Boolean(context.grokRoutines) } : provider),
      relaycast: {
        listAgents: (status, options) => relaycast.listAgents(workspace.relaycastApiKey, status, { signal: options?.signal }),
        listPresence: (options) => relaycast.listPresence(workspace.relaycastApiKey, { signal: options?.signal }),
      },
      relay: {
        database: store.database,
        keyring: config.encryptionKeyring,
        client: relaycast,
        sessionId: typeof sessionId === "string" ? sessionId : undefined,
        relaycastPublicUrl: config.relaycastPublicUrl,
        ...(config.relaygatePublicUrl ? { relaygatePublicUrl: config.relaygatePublicUrl } : {}),
        ...(launchCheck ? { launchCheck } : {}),
        ...(gateClient ? { gateClient } : {}),
        ...(config.spawnMemoryPolicy ? { spawnMemoryPolicy: config.spawnMemoryPolicy } : {}),
      },
      ...(!oauth && personOnly && input.amp ? { amp: input.amp } : {}),
      ...(!oauth && personOnly && input.replicas ? { replicas: input.replicas } : {}),
      ...(!oauth && personOnly && input.webhookInbox ? { webhookInbox: input.webhookInbox } : {}),
      ...(!oauth && personOnly && input.factory ? { factory: input.factory } : {}),
      ...(!oauth && personOnly && !desktopCall.required && desktopCall.provider === undefined && input.capy ? { capy: input.capy } : {}),
      ...(oauth && input.capyPermits ? { capyPermits: input.capyPermits } : {}),
      ...(input.launch && personOnly ? { launch: true } : {}),
      ...(sessionAccess ? { sessionAccess } : {}),
      readAudit: { database: store.database, handled: new Set<string>(), ...(input.now ? { now: input.now } : {}) },
    };
    if (oauth && input.cursorCloud) context.cursorCloud = input.cursorCloud;
    if (oauth && input.grokRoutines) {
      const client = (await store.database.query<{ client_name: string | null; redirect_uris: string[] }>(
        "SELECT client_name,redirect_uris FROM mcp_oauth_clients WHERE client_id=$1", [oauth.access.clientId])).rows[0];
      if (client && isGrokRoutineKind(connectorKind({ clientName: client.client_name, redirectUris: client.redirect_uris }))) {
        context.grokRoutines = input.grokRoutines;
      }
    }
    if (config.customerSupport && personOnly) context.customerSupport = {
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
      instrumentMcpTransport(transport, "shared-sessions");
      await server.connect(transport);
      const url = new URL(rawPath, site);
      const webResponse = await correlateMcpResponse(await transport.handleRequest(
        // The proof is gone from `body`; the transport never sees it.
        new Request(url, { method: "POST", headers, body: JSON.stringify(body) }),
        { parsedBody: body },
      ), "shared-sessions");
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
      reportUnexpected(error, request, response, path);
      if (!response.headersSent) rpcError(response, 500, -32603, "Internal server error");
      else response.end();
    } finally {
      await server.close().catch(() => {});
    }
    return true;
  }

  return async function handle(request: IncomingMessage, response: ServerResponse, path: string, method: string): Promise<boolean> {
    if (path !== MCP_FACADE.path && !(oauthSessions && (path === "/mcp" || path === "/cloud/mcp"))) return false;
    response.setHeader("x-correlation-id", randomUUID());
    try {
      return await withMcpDiagnosticContext(response.getHeader("x-correlation-id") as string,
        () => handleRequest(request, response, path, method));
    } catch (error) {
      // Admission, membership and server construction failures used to escape
      // to the generic HTTP handler, losing the MCP error and its correlation.
      reportUnexpected(error, request, response, path);
      if (!response.headersSent) rpcError(response, 500, -32603, "The MCP service is temporarily unavailable. Please try again.");
      else response.end();
      return true;
    }
  };
}
