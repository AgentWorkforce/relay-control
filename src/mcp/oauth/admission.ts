import { hashSecret } from "../../crypto.js";
import type { SqlExecutor } from "../../database.js";
import { lockOrganization, lockUser, type TenancyMode } from "../../tenancy.js";
import { MCP_EVENTS_SCOPE, MCP_RELAY_SCOPE, type McpOAuthResourcePath } from "./protocol.js";
import type { McpOAuthAccess, McpOAuthSessions } from "./sessions.js";

export class McpOAuthAccessRefused extends Error {
  constructor() { super("This connection no longer has access to this workspace. Reconnect the app."); }
}
export class McpOAuthActorRefused extends Error {
  constructor() { super("This connection can only act as the agent approved when it was connected."); }
}

export type McpOAuthAgent = { agentName: string; agentRemoteId: string };

/**
 * Cloud's grant-bound actor and pin contract, adapted to the tenant locks.
 * Every tool checks its credential at entry. Participant registration,
 * recovery, pin updates and release also hold this fence, matching the
 * source's actor lock without holding a SQL transaction over a whole send.
 */
export class McpOAuthConnection {
  readonly access: McpOAuthAccess;
  private readonly tokenHash: string;
  private readonly locked = new WeakSet<SqlExecutor>();

  constructor(access: McpOAuthAccess, token: string, readonly options: {
    tenancyMode: TenancyMode;
    requiredScope: typeof MCP_RELAY_SCOPE | typeof MCP_EVENTS_SCOPE;
    now?: () => Date;
  }) {
    this.access = { ...access, principal: { ...access.principal, scopes: [...access.principal.scopes] } };
    this.tokenHash = hashSecret(token);
  }

  /** Never infer a tenant from a user or accept a refreshed credential by session id alone. */
  async lock(tx: SqlExecutor): Promise<void> {
    const { principal, grantId, resource, clientId } = this.access;
    await lockUser(tx, principal.userId);
    await lockOrganization(tx, principal.organizationId);
    const row = (await tx.query<{
      agent_name: string; agent_remote_id: string | null;
      scopes: string[]; grant_scopes: string[]; role: typeof principal.role;
    }>(`SELECT g.agent_name,g.agent_remote_id,s.scopes,g.scopes AS grant_scopes,m.role
      FROM selfhost_mcp_oauth_grants g
      JOIN selfhost_mcp_oauth_sessions s ON s.grant_id=g.id AND s.token_family_id=g.token_family_id
        AND s.user_id=g.user_id AND s.organization_id=g.organization_id AND s.workspace_id=g.workspace_id
      JOIN selfhost_organization_memberships m ON m.organization_id=g.organization_id AND m.user_id=g.user_id
      JOIN selfhost_workspaces w ON w.id=g.workspace_id AND w.organization_id=g.organization_id
      WHERE g.id=$1 AND g.client_id=$2 AND g.resource=$3 AND g.revoked_at IS NULL
        AND s.id=$4 AND s.access_token_hash=$5 AND s.revoked_at IS NULL AND s.access_token_expires_at>$6
        AND g.user_id=$7 AND g.organization_id=$8 AND g.workspace_id=$9
        AND ($10::text='multi' OR NOT EXISTS (SELECT 1 FROM selfhost_organizations other WHERE other.id<>g.organization_id))
      FOR UPDATE OF g FOR KEY SHARE OF s,m,w`,
    [grantId,clientId,resource,principal.sessionId,this.tokenHash,this.options.now?.() ?? new Date(),
      principal.userId,principal.organizationId,principal.workspaceId,this.options.tenancyMode])).rows[0];
    if (!row) throw new McpOAuthAccessRefused();
    const scopes = principal.scopes.filter(scope => row.scopes.includes(scope) && row.grant_scopes.includes(scope));
    if (!scopes.includes(this.options.requiredScope) || principal.pendingHandoff || principal.handoff) {
      throw new McpOAuthAccessRefused();
    }
    principal.scopes = scopes;
    principal.role = row.role;
    this.access.agentName = row.agent_name;
    this.access.agentRemoteId = row.agent_remote_id;
    this.locked.add(tx);
  }

  assertActor(requested: string | undefined, currentName?: string): void {
    if (requested && requested !== this.access.agentName && requested !== currentName) {
      throw new McpOAuthActorRefused();
    }
  }

  /** First use pins an immutable id; later calls may learn only that same agent's new name. */
  async pin(tx: SqlExecutor, participant: McpOAuthAgent & { workspaceId: string; userId: string }): Promise<void> {
    const { principal, grantId, agentRemoteId } = this.access;
    if (!this.locked.has(tx) || participant.workspaceId !== principal.workspaceId ||
        participant.userId !== principal.userId || (agentRemoteId && agentRemoteId !== participant.agentRemoteId)) {
      throw new McpOAuthAccessRefused();
    }
    // Like Cloud, every live grant already pinned to this same id learns its rename.
    const updated = await tx.query<{ id: string }>(`UPDATE selfhost_mcp_oauth_grants
      SET agent_remote_id=$5,agent_name=$6
      WHERE organization_id=$1 AND workspace_id=$2 AND user_id=$3 AND revoked_at IS NULL
        AND (id=$4 OR agent_remote_id=$5) AND (agent_remote_id IS NULL OR agent_remote_id=$5)
      RETURNING id`,
    [principal.organizationId,principal.workspaceId,principal.userId,grantId,participant.agentRemoteId,participant.agentName]);
    if (!updated.rows.some(row => row.id === grantId)) throw new McpOAuthAccessRefused();
    this.access.agentName = participant.agentName;
    this.access.agentRemoteId = participant.agentRemoteId;
  }

  /** A successor connection or another live grant must never lose its inbox during cleanup. */
  async claimedByOther(tx: SqlExecutor, agent: McpOAuthAgent): Promise<boolean> {
    const { principal, grantId } = this.access;
    const result = await tx.query(`SELECT id FROM selfhost_mcp_oauth_grants
      WHERE organization_id=$1 AND workspace_id=$2 AND user_id=$3 AND revoked_at IS NULL AND id<>$4
        AND (agent_remote_id=$5 OR agent_name=$6) LIMIT 1`,
    [principal.organizationId,principal.workspaceId,principal.userId,grantId,agent.agentRemoteId,agent.agentName]);
    return result.rows.length > 0;
  }
}

/** Mounted only by the MCP handler; the general session middleware never calls this resolver. */
export async function admitMcpOAuthBearer(input: {
  sessions: McpOAuthSessions;
  token: string;
  resourcePath: McpOAuthResourcePath;
}): Promise<{ ok: true; connection: McpOAuthConnection } | { ok: false; status: 401 | 403 }> {
  const protocol = input.sessions.options.protocol;
  if (!protocol.mcpOAuthResourceAvailable(input.resourcePath)) return { ok: false, status: 401 };
  const access = await input.sessions.resolveAccessToken(input.token, protocol.mcpResourceUrl(input.resourcePath));
  if (!access) return { ok: false, status: 401 };
  const requiredScope = input.resourcePath === "/api/v1/mcp/relay-events" ? MCP_EVENTS_SCOPE : MCP_RELAY_SCOPE;
  if (!access.principal.scopes.includes(requiredScope) || access.principal.pendingHandoff || access.principal.handoff) {
    return { ok: false, status: 403 };
  }
  return { ok: true, connection: new McpOAuthConnection(access,input.token,{
    tenancyMode: input.sessions.options.tenancyMode,requiredScope,now: input.sessions.options.now,
  }) };
}
