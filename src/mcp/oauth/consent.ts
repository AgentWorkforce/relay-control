/**
 * Unmounted port of Cloud 1776499a api/oauth/authorize and agent-name routes.
 * The intentional tenancy adaptation: a browser account session consents only
 * for its issue-time workspace; selecting another workspace requires a switch.
 */
import { createHash } from "node:crypto";
import { agentNameError } from "./agent-name.js";
import { connectorKind } from "./connector-kind.js";
import { APP_BASE_PATH, MCP_EVENTS_SCOPE, type AuthorizationRequest, type createMcpOAuthProtocol } from "./protocol.js";

export type McpConsentPrincipal = {
  userId: string; organizationId: string; workspaceId: string;
  scopes: readonly string[]; pendingHandoff?: boolean; handoff?: boolean;
};
export type McpConsentSession = { transport: "cookie" | "bearer"; principal: McpConsentPrincipal };
type ConsentClient = { clientId: string; clientName: string | null; redirectUris: string[] };
import { McpOAuthContinuationError, McpOAuthAgentNameTakenError } from "./errors.js";
export { McpOAuthContinuationError } from "./errors.js";
export type AgentNameAvailability = "available" | "yours" | "taken" | "unknown";
type TenantOwner = Pick<McpConsentPrincipal, "userId" | "organizationId" | "workspaceId">;

export interface McpOAuthConsentStore {
  getMcpOAuthClient(clientId: string | undefined): Promise<ConsentClient | null>;
  createMcpOAuthAuthorizationCode(request: AuthorizationRequest, principal: TenantOwner & { agentName: string }, continuationGrantId?: string): Promise<string>;
  listConnectedAgentNames(owner: TenantOwner): Promise<Array<{ workspaceId: string; agentName: string }>>;
}

const AUTHORIZATION_PARAMS = ["response_type", "client_id", "redirect_uri", "code_challenge", "code_challenge_method",
  "state", "scope", "nonce", "resource"] as const;
const GROK_NAME_COOKIE = "relay_grok_name_hint";
const GROK_NAME_MAX_AGE_MS = 10 * 60 * 1_000;

function oauthJson(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store", Pragma: "no-cache" } });
}

/** Source grok-name-handoff validation: correlation only, never a principal. */
function readNameHint(request: Request, now: number): { id: string } | null {
  const raw = (request.headers.get("cookie") ?? "").split(";")
    .map(part => part.trim()).find(part => part.startsWith(`${GROK_NAME_COOKIE}=`))?.slice(GROK_NAME_COOKIE.length + 1);
  if (!raw || raw.length > 3 * 1024) return null;
  try {
    const decoded = decodeURIComponent(raw);
    if (decoded.length > 1024) return null;
    const hint = JSON.parse(decoded);
    if (!hint || typeof hint.id !== "string" || !/^[a-f0-9-]{36}$/u.test(hint.id) ||
        typeof hint.agentName !== "string" || hint.agentName !== hint.agentName.trim() || agentNameError(hint.agentName) ||
        !Number.isFinite(hint.expiresAt) || hint.expiresAt <= now || hint.expiresAt > now + GROK_NAME_MAX_AGE_MS) return null;
    return { id: hint.id };
  } catch { return null; }
}

export function mcpOAuthSetupHandoff(code: string): string {
  return `mcpos_${createHash("sha256").update(code).digest("hex")}`;
}

/** Shared account admission for the consent API and its server-rendered page. */
export async function resolveMcpConsentAccount(request:Request,
  resolveSession:(request:Request)=>Promise<McpConsentSession|null>):Promise<McpConsentPrincipal|Response> {
  const session=await resolveSession(request);
  if(!session || session.transport!=="cookie") return oauthJson({error:"unauthorized"},401);
  if(!session.principal.scopes.includes("account") || session.principal.pendingHandoff || session.principal.handoff) {
    return oauthJson({error:"reauthentication_required"},403);
  }
  if(!new URL(request.url).pathname.startsWith(`${APP_BASE_PATH}/`)) return oauthJson({error:"unauthorized"},401);
  return session.principal;
}

export function createMcpOAuthConsentHandlers(deps: {
  protocol: ReturnType<typeof createMcpOAuthProtocol>;
  store: McpOAuthConsentStore;
  /** Trusted application authentication, not a value parsed from request JSON. */
  resolveSession(request: Request): Promise<McpConsentSession | null>;
  /** Live org membership plus workspace->org/session binding; store rechecks in its transaction. */
  workspaceAccess(principal: TenantOwner): Promise<boolean>;
  checkAgentNameAvailability(principal: TenantOwner, name: string): Promise<AgentNameAvailability>;
  /** Only if the matching relay-app setup route exists; default false. */
  grokSetupEnabled?: boolean;
  now?: () => number;
}) {
  const origin = deps.protocol.mcpOAuthOrigin();
  const grokSetupEnabled = deps.grokSetupEnabled === true;
  const now = deps.now ?? Date.now;

  const accountSession = (request:Request) => resolveMcpConsentAccount(request,deps.resolveSession);

  async function authorize(request: Request): Promise<Response> {
    const principal = await accountSession(request);
    if (principal instanceof Response) return principal;
    // Configured public origin, never the potentially untrusted request host.
    if (request.headers.get("origin") !== origin) return oauthJson({ error: "forbidden" }, 403);
    let body: Record<string, unknown>;
    try {
      const value: unknown = await request.json();
      if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("not an object");
      body = value as Record<string, unknown>;
    } catch { return oauthJson({ error: "invalid_request", error_description: "Body must be a JSON object." }, 400); }
    const rawParams = body.params && typeof body.params === "object" ? body.params as Record<string, unknown> : {};
    const params: Record<string, string | undefined> = {};
    for (const key of AUTHORIZATION_PARAMS) if (typeof rawParams[key] === "string") params[key] = rawParams[key];
    const client = await deps.store.getMcpOAuthClient(params.client_id);
    const validated = deps.protocol.validateAuthorizationRequest(params, client);
    if (!validated.ok && !validated.redirect) return oauthJson(validated.error, 400);
    if (!validated.ok) return oauthJson({ redirect_to: deps.protocol.authorizationResponseUrl(validated.redirectUri,
      { ...validated.error, state: validated.state }) });
    const authorization = validated.value;
    const grok = authorization.resourcePath === "/api/v1/mcp/relay-events" && authorization.scopes.includes(MCP_EVENTS_SCOPE) &&
      connectorKind({ clientName: client!.clientName, redirectUris: [authorization.redirectUri] }) === "grok-bot";
    function finish(payload: unknown): Response {
      const response = oauthJson(payload);
      const hint = readNameHint(request, now());
      if (grok && hint && hint.id === body.name_handoff_id) {
        response.headers.append("set-cookie", `${GROK_NAME_COOKIE}=; Max-Age=0; Path=${APP_BASE_PATH}; HttpOnly; SameSite=Lax${origin.startsWith("https:") ? "; Secure" : ""}`);
      }
      return response;
    }
    if (body.decision !== "approve") return finish({ redirect_to: deps.protocol.authorizationResponseUrl(authorization.redirectUri,
      { error: "access_denied", error_description: "The user denied access.", state: authorization.state }) });
    if (body.workspace_id !== principal.workspaceId || !await deps.workspaceAccess(principal)) {
      return oauthJson({ error: "invalid_workspace", error_description: "Switch to an accessible workspace before granting consent." }, 400);
    }
    const agentName = typeof body.agent_name === "string" ? body.agent_name.trim() : "";
    const invalidName = agentNameError(agentName);
    if (invalidName) return oauthJson({ error: "invalid_agent_name", error_description: invalidName }, 400);
    if (body.continue_grant_id !== undefined && typeof body.continue_grant_id !== "string") {
      return oauthJson({ error: "invalid_request", error_description: "Select an existing connection." }, 400);
    }
    if (body.attach_existing !== undefined && typeof body.attach_existing !== "boolean") {
      return oauthJson({ error: "invalid_request", error_description: "attach_existing must be a boolean." }, 400);
    }
    if (!body.continue_grant_id) {
      // A new connection never lands on an existing agent by accident: another
      // member's (or a retiring) agent is refused, and this user's own agent
      // needs an explicit confirmation, since attaching shares its identity and inbox.
      const availability = await deps.checkAgentNameAvailability(principal, agentName).catch((): AgentNameAvailability => "unknown");
      if (availability === "unknown") {
        return oauthJson({ error: "temporarily_unavailable", error_description: "The agent name could not be checked. Try again." }, 503);
      }
      if (availability === "taken") {
        return oauthJson({ error: "agent_name_taken", error_description: "That name is already in use. Choose another name." }, 409);
      }
      if (availability === "yours" && body.attach_existing !== true) {
        return oauthJson({ error: "agent_name_in_use", error_description:
          "That name belongs to one of your existing agents. Confirm that this app should attach to it, or choose another name." }, 409);
      }
    }
    if (grok && !body.continue_grant_id) {
      const connected = await deps.store.listConnectedAgentNames(principal);
      if (connected.some(agent => agent.workspaceId === principal.workspaceId && agent.agentName === agentName)) {
        return oauthJson({ error: "agent_name_taken", error_description: "That name is already in use. Choose another name." }, 409);
      }
    }
    let code: string;
    try {
      code = await deps.store.createMcpOAuthAuthorizationCode(authorization, {
        userId: principal.userId, organizationId: principal.organizationId, workspaceId: principal.workspaceId, agentName,
      }, body.continue_grant_id ? body.continue_grant_id as string : undefined);
    } catch (error) {
      if (error instanceof McpOAuthAgentNameTakenError) return oauthJson({ error: error.code, error_description: error.message }, error.status);
      if (error instanceof McpOAuthContinuationError) return oauthJson({ error: "invalid_request", error_description: error.message }, 400);
      throw error;
    }
    const setupUrl = grok && grokSetupEnabled ? `${APP_BASE_PATH}/connect/grok/webhook?${new URLSearchParams({
      workspace: principal.workspaceId, handoff: mcpOAuthSetupHandoff(code),
    })}` : undefined;
    return finish({ redirect_to: deps.protocol.authorizationResponseUrl(authorization.redirectUri, { code, state: authorization.state }),
      ...(setupUrl ? { setup_url: setupUrl } : {}) });
  }

  async function agentName(request: Request): Promise<Response> {
    const principal = await accountSession(request);
    if (principal instanceof Response) return principal;
    const url = new URL(request.url);
    if (url.searchParams.get("workspace_id") !== principal.workspaceId || !await deps.workspaceAccess(principal)) {
      return oauthJson({ error: "invalid_workspace", error_description: "Switch to an accessible workspace first." }, 400);
    }
    const name = (url.searchParams.get("name") ?? "").trim();
    const invalid = agentNameError(name);
    if (invalid) return oauthJson({ error: "invalid_agent_name", error_description: invalid }, 400);
    return oauthJson({ name, status: await deps.checkAgentNameAvailability(principal, name) });
  }

  return { authorize, agentName };
}
