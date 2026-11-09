/**
 * OAuth-only adapter for Cloud's createApiTokenSession/refreshApiTokenSession.
 * Own table and prefixes: never calls ControlPlaneStore session issuance and
 * never participates in general API auth/refresh. No routes are mounted here.
 */
import { randomUUID } from "node:crypto";
import type { Database, SqlExecutor } from "../../database.js";
import { hashSecret, opaqueToken } from "../../crypto.js";
import type { Principal } from "../../store.js";
import type { TenancyMode } from "../../tenancy.js";
import type { createMcpOAuthProtocol } from "./protocol.js";

export const MCP_OAUTH_ACCESS_PREFIX = "mcp_at_";
export const MCP_OAUTH_REFRESH_PREFIX = "mcp_rt_";
const ACCESS_TTL_MS = 60 * 60 * 1_000;
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1_000;
const ACCESS_PATTERN = /^mcp_at_[A-Za-z0-9_-]{43}$/;
const REFRESH_PATTERN = /^mcp_rt_[A-Za-z0-9_-]{43}$/;

export type McpOAuthSessionOwner = {
  grantId: string; tokenFamilyId: string; userId: string; organizationId: string; workspaceId: string;
};
export type McpOAuthIssuedPair = {
  sessionId: string; tokenFamilyId: string; accessToken: string; refreshToken: string;
  accessTokenExpiresAt: string; refreshTokenExpiresAt: string; scopes: string[];
};
export type McpOAuthSessionRecord = McpOAuthSessionOwner & {
  sessionId: string; scopes: string[]; grantScopes: string[]; resource: string; clientId: string;
  revokedAt: Date | null; grantRevokedAt: Date | null;
  accessTokenExpiresAt: Date; refreshTokenExpiresAt: Date;
};
export type McpOAuthAccess = {
  principal: Principal;
  grantId: string; clientId: string; resource: string; agentName: string; agentRemoteId: string | null;
};

type SessionRow = {
  id: string; grant_id: string; token_family_id: string; user_id: string; organization_id: string; workspace_id: string;
  scopes: string[]; grant_scopes: string[]; resource: string; client_id: string;
  revoked_at: Date | string | null; grant_revoked_at: Date | string | null;
  access_token_expires_at: Date | string; refresh_token_expires_at: Date | string;
};

function record(row: SessionRow): McpOAuthSessionRecord {
  return { sessionId: row.id, grantId: row.grant_id, tokenFamilyId: row.token_family_id, userId: row.user_id,
    organizationId: row.organization_id, workspaceId: row.workspace_id, scopes: row.scopes, grantScopes: row.grant_scopes,
    resource: row.resource, clientId: row.client_id, revokedAt: row.revoked_at ? new Date(row.revoked_at) : null,
    grantRevokedAt: row.grant_revoked_at ? new Date(row.grant_revoked_at) : null,
    accessTokenExpiresAt: new Date(row.access_token_expires_at), refreshTokenExpiresAt: new Date(row.refresh_token_expires_at) };
}

export class McpOAuthSessions {
  constructor(readonly database: Database, readonly options: {
    protocol: ReturnType<typeof createMcpOAuthProtocol>; tenancyMode: TenancyMode; now?: () => Date;
  }) {}

  private now(): Date { return (this.options.now ?? (() => new Date()))(); }

  /** Caller owns the consent/redemption transaction and its user->org locks. */
  async issue(tx: SqlExecutor, input: McpOAuthSessionOwner & { scopes: readonly string[] }): Promise<McpOAuthIssuedPair> {
    const context = await tx.query<{ scopes: string[] }>(`SELECT g.scopes FROM selfhost_mcp_oauth_grants g
      JOIN selfhost_organization_memberships m ON m.organization_id=g.organization_id AND m.user_id=g.user_id
      JOIN selfhost_workspaces w ON w.id=g.workspace_id AND w.organization_id=g.organization_id
      WHERE g.id=$1 AND g.token_family_id=$2 AND g.user_id=$3 AND g.organization_id=$4 AND g.workspace_id=$5
        AND g.revoked_at IS NULL AND ($6::text='multi' OR NOT EXISTS
          (SELECT 1 FROM selfhost_organizations other WHERE other.id<>g.organization_id))`,
    [input.grantId,input.tokenFamilyId,input.userId,input.organizationId,input.workspaceId,this.options.tenancyMode]);
    const scopes = [...new Set(input.scopes)];
    if (!context.rows[0] || !scopes.length || !scopes.every(scope => context.rows[0]!.scopes.includes(scope))) {
      throw new Error("OAuth session does not match an active consented grant");
    }
    const createdAt = this.now();
    const sessionId = randomUUID();
    const accessToken = opaqueToken(MCP_OAUTH_ACCESS_PREFIX), refreshToken = opaqueToken(MCP_OAUTH_REFRESH_PREFIX);
    const accessExpires = new Date(createdAt.getTime()+ACCESS_TTL_MS), refreshExpires = new Date(createdAt.getTime()+REFRESH_TTL_MS);
    await tx.query(`INSERT INTO selfhost_mcp_oauth_sessions
      (id,grant_id,token_family_id,user_id,organization_id,workspace_id,scopes,access_token_hash,refresh_token_hash,
       access_token_expires_at,refresh_token_expires_at,created_at,updated_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)`,
    [sessionId,input.grantId,input.tokenFamilyId,input.userId,input.organizationId,input.workspaceId,scopes,
      hashSecret(accessToken),hashSecret(refreshToken),accessExpires,refreshExpires,createdAt]);
    return { sessionId,tokenFamilyId:input.tokenFamilyId,accessToken,refreshToken,
      accessTokenExpiresAt:accessExpires.toISOString(),refreshTokenExpiresAt:refreshExpires.toISOString(),scopes };
  }

  /** Internal lookup for OAuth code/token routes only; grant/client checks remain mandatory. */
  async find(tx: SqlExecutor, kind: "access" | "refresh", token: string): Promise<McpOAuthSessionRecord | null> {
    if (!(kind === "access" ? ACCESS_PATTERN : REFRESH_PATTERN).test(token)) return null;
    const column = kind === "access" ? "access_token_hash" : "refresh_token_hash";
    const result = await tx.query<SessionRow>(`SELECT s.*,g.scopes AS grant_scopes,g.resource,g.client_id,g.revoked_at AS grant_revoked_at
      FROM selfhost_mcp_oauth_sessions s JOIN selfhost_mcp_oauth_grants g ON g.id=s.grant_id
      WHERE s.${column}=$1`,[hashSecret(token)]);
    return result.rows[0] ? record(result.rows[0]) : null;
  }

  /** Source refresh CAS; the retired hash is committed atomically with rotation. */
  async rotate(tx: SqlExecutor, refreshToken: string, expected: McpOAuthSessionOwner): Promise<McpOAuthIssuedPair | null> {
    if (!REFRESH_PATTERN.test(refreshToken)) return null;
    const now = this.now();
    const accessToken = opaqueToken(MCP_OAUTH_ACCESS_PREFIX), nextRefresh = opaqueToken(MCP_OAUTH_REFRESH_PREFIX);
    const accessExpires = new Date(now.getTime()+ACCESS_TTL_MS), refreshExpires = new Date(now.getTime()+REFRESH_TTL_MS);
    const result = await tx.query<{ id: string; scopes: string[] }>(`UPDATE selfhost_mcp_oauth_sessions s
      SET access_token_hash=$2,refresh_token_hash=$3,access_token_expires_at=$4,refresh_token_expires_at=$5,
          last_refreshed_at=$6,updated_at=$6
      FROM selfhost_mcp_oauth_grants g,selfhost_organization_memberships m,selfhost_workspaces w
      WHERE s.refresh_token_hash=$1 AND s.revoked_at IS NULL AND s.refresh_token_expires_at>$6
        AND s.grant_id=$7 AND s.token_family_id=$8 AND s.user_id=$9 AND s.organization_id=$10 AND s.workspace_id=$11
        AND g.id=s.grant_id AND g.revoked_at IS NULL
        AND m.organization_id=s.organization_id AND m.user_id=s.user_id
        AND w.id=s.workspace_id AND w.organization_id=s.organization_id
        AND ($12::text='multi' OR NOT EXISTS (SELECT 1 FROM selfhost_organizations other WHERE other.id<>s.organization_id))
      RETURNING s.id,s.scopes`,[hashSecret(refreshToken),hashSecret(accessToken),hashSecret(nextRefresh),accessExpires,refreshExpires,now,
      expected.grantId,expected.tokenFamilyId,expected.userId,expected.organizationId,expected.workspaceId,this.options.tenancyMode]);
    const row = result.rows[0];
    if (!row) return null;
    await tx.query(`INSERT INTO selfhost_mcp_oauth_retired_refresh_tokens
      (token_hash,grant_id,user_id,organization_id,workspace_id,retired_at) VALUES ($1,$2,$3,$4,$5,$6)
      ON CONFLICT (token_hash) DO NOTHING`,[hashSecret(refreshToken),expected.grantId,expected.userId,
      expected.organizationId,expected.workspaceId,now]);
    return { sessionId:row.id,tokenFamilyId:expected.tokenFamilyId,accessToken,refreshToken:nextRefresh,
      accessTokenExpiresAt:accessExpires.toISOString(),refreshTokenExpiresAt:refreshExpires.toISOString(),scopes:row.scopes };
  }

  async revokeFamily(tx: SqlExecutor, owner: McpOAuthSessionOwner, reason: string): Promise<void> {
    await revokeMcpOAuthSessionFamily(tx, owner, reason, this.now());
  }

  async revokeSession(tx: SqlExecutor, sessionId: string, owner: McpOAuthSessionOwner, reason: string): Promise<void> {
    await tx.query(`UPDATE selfhost_mcp_oauth_sessions SET revoked_at=$7,revoked_reason=$8,updated_at=$7
      WHERE id=$1 AND grant_id=$2 AND token_family_id=$3 AND user_id=$4 AND organization_id=$5 AND workspace_id=$6 AND revoked_at IS NULL`,
    [sessionId,owner.grantId,owner.tokenFamilyId,owner.userId,owner.organizationId,owner.workspaceId,this.now(),reason]);
  }

  /** MCP-only resolver: canonical resource, live grant/role and issue-time scopes. */
  async resolveAccessToken(token: string, requestUrl: string): Promise<McpOAuthAccess | null> {
    if (!ACCESS_PATTERN.test(token)) return null;
    if (requestUrl.trim()!==requestUrl || /[\u0000-\u001f\u007f]/u.test(requestUrl)) return null;
    let url: URL;
    try { url = new URL(requestUrl,this.options.protocol.mcpOAuthOrigin()); } catch { return null; }
    const resourcePath = this.options.protocol.parseMcpResource(url.toString());
    if (!resourcePath) return null;
    const resource = this.options.protocol.mcpResourceUrl(resourcePath);
    const result = await this.database.query<SessionRow & {
      email: string; user_name: string; organization_name: string; workspace_name: string; role: Principal["role"];
      agent_name: string; agent_remote_id: string | null;
    }>(`SELECT s.*,g.scopes AS grant_scopes,g.resource,g.client_id,g.revoked_at AS grant_revoked_at,
        g.agent_name,g.agent_remote_id,u.email,u.name AS user_name,o.name AS organization_name,w.name AS workspace_name,m.role
      FROM selfhost_mcp_oauth_sessions s JOIN selfhost_mcp_oauth_grants g ON g.id=s.grant_id
      JOIN selfhost_users u ON u.id=s.user_id JOIN selfhost_organizations o ON o.id=s.organization_id
      JOIN selfhost_workspaces w ON w.id=s.workspace_id AND w.organization_id=s.organization_id
      JOIN selfhost_organization_memberships m ON m.organization_id=s.organization_id AND m.user_id=s.user_id
      WHERE s.access_token_hash=$1 AND s.revoked_at IS NULL AND s.access_token_expires_at>$2
        AND g.revoked_at IS NULL AND g.resource=$3
        AND ($4::text='multi' OR NOT EXISTS (SELECT 1 FROM selfhost_organizations other WHERE other.id<>s.organization_id))`,
    [hashSecret(token),this.now(),resource,this.options.tenancyMode]);
    const row = result.rows[0];
    if (!row) return null;
    const scopes=row.scopes.filter(scope=>row.grant_scopes.includes(scope));
    if(scopes.length===0) return null;
    return { principal: {
      sessionId:row.id,tokenFamilyId:row.token_family_id,userId:row.user_id,email:row.email,name:row.user_name,
      organizationId:row.organization_id,organizationName:row.organization_name,workspaceId:row.workspace_id,
      workspaceName:row.workspace_name,role:row.role,scopes,
      pendingHandoff:false,handoff:false,
    },grantId:row.grant_id,clientId:row.client_id,resource:row.resource,agentName:row.agent_name,agentRemoteId:row.agent_remote_id };
  }
}

/** Ends every live session of one grant's token family; shared by the class and out-of-store revokers. */
export async function revokeMcpOAuthSessionFamily(tx: SqlExecutor, owner: McpOAuthSessionOwner, reason: string, now: Date): Promise<void> {
  await tx.query(`UPDATE selfhost_mcp_oauth_sessions SET revoked_at=$6,revoked_reason=$7,updated_at=$6
    WHERE grant_id=$1 AND token_family_id=$2 AND user_id=$3 AND organization_id=$4 AND workspace_id=$5 AND revoked_at IS NULL`,
  [owner.grantId,owner.tokenFamilyId,owner.userId,owner.organizationId,owner.workspaceId,now,reason]);
}
