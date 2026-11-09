/**
 * Cloud 1776499a mcp-oauth-store.ts: SQL/tenant-lock/token-class adaptation.
 * Uses only OAuth session tables; mounts no routes and grants no general
 * control-plane or History child credential authority.
 */
import { randomBytes, randomUUID } from "node:crypto";
import type { Database, SqlExecutor } from "../../database.js";
import { hashSecret } from "../../crypto.js";
import { lockOrganization, lockUser, type TenancyMode } from "../../tenancy.js";
import { isValidCodeVerifier, pkceS256, oidcSectorIdentifierForRedirectUri,
  type AuthorizationRequest, type ClientRegistrationInput, type McpAuthorizationScope,
  type OAuthErrorBody, type createMcpOAuthProtocol } from "./protocol.js";
import { McpOAuthSessions, MCP_OAUTH_REFRESH_PREFIX, revokeMcpOAuthSessionFamily, type McpOAuthIssuedPair, type McpOAuthSessionOwner } from "./sessions.js";

const CODE_TTL_SECONDS = 120;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type McpOAuthOwner = { userId: string; organizationId: string; workspaceId: string };
export type McpOAuthConsentPrincipal = McpOAuthOwner & { agentName: string };
export type McpOAuthClient = { clientId: string; clientName: string | null; redirectUris: string[]; createdAt: Date };
export type McpOAuthGrant = McpOAuthOwner & { id:string;clientId:string;clientName:string|null;agentName:string;
  agentRemoteId:string|null;scopes:string[];resource:string;setupHandoffId:string|null;tokenFamilyId:string;
  createdAt:Date;revokedAt:Date|null;revokedReason:string|null };

export class McpOAuthContinuationError extends Error {}
export class McpOAuthAgentNameTakenError extends Error {
  readonly status = 409;
  readonly code = "agent_name_taken";
  constructor() { super("That name is already in use. Choose another name."); }
}

type ClientRow = { client_id: string; client_name: string | null; redirect_uris: string[]; created_at: Date | string };
type ConnectionRow = { id: string; scopes: string[] };
type GrantRow = {
  id: string; client_id: string; client_name: string | null; user_id: string; organization_id: string; workspace_id: string;
  agent_name: string; agent_remote_id: string | null; scopes: string[]; resource: string; token_family_id: string;
  setup_handoff_id: string | null; continued_at: Date | string | null; created_at: Date | string;
  revoked_at: Date | string | null; revoked_reason: string | null;
};
type CodeRow = {
  code_hash: string; client_id: string; user_id: string; organization_id: string; workspace_id: string;
  agent_name: string; redirect_uri: string; redirect_uri_required: boolean; code_challenge: string; scopes: string[]; resource: string;
  oidc_nonce: string | null; grant_id: string | null; issued_session_id: string | null;
  expires_at: Date | string; consumed_at: Date | string | null;
};
export type McpOAuthTokenResponse = { access_token: string; token_type: "Bearer"; expires_in: number;
  refresh_token: string; scope: string; id_token?: string };
export type McpOAuthTokenResult = { ok: true; body: McpOAuthTokenResponse }
  | { ok: false; status: number; error: OAuthErrorBody };

function invalidGrant(description = "The token or authorization code is invalid, expired, or revoked."): McpOAuthTokenResult {
  return { ok:false,status:400,error:{ error:"invalid_grant",error_description:description } };
}
function invalidTarget(): McpOAuthTokenResult {
  return { ok:false,status:400,error:{ error:"invalid_target",error_description:"resource does not match the grant or authorization request." } };
}
function ownerOf(row: GrantRow): McpOAuthSessionOwner {
  return { grantId:row.id,tokenFamilyId:row.token_family_id,userId:row.user_id,organizationId:row.organization_id,workspaceId:row.workspace_id };
}
function setupHandoff(code: string): string { return `mcpos_${hashSecret(code)}`; }
function mapGrant(row:GrantRow):McpOAuthGrant {
  return { id:row.id,clientId:row.client_id,clientName:row.client_name,userId:row.user_id,
    organizationId:row.organization_id,workspaceId:row.workspace_id,agentName:row.agent_name,agentRemoteId:row.agent_remote_id,
    scopes:[...row.scopes],resource:row.resource,setupHandoffId:row.setup_handoff_id,tokenFamilyId:row.token_family_id,
    createdAt:new Date(row.created_at),revokedAt:row.revoked_at?new Date(row.revoked_at):null,revokedReason:row.revoked_reason };
}

function clientFromRow(row: ClientRow): McpOAuthClient {
  return { clientId: row.client_id, clientName: row.client_name, redirectUris: row.redirect_uris, createdAt: new Date(row.created_at) };
}

export class McpOAuthStore {
  readonly sessions: McpOAuthSessions;
  constructor(readonly database: Database, readonly options: {
    protocol: ReturnType<typeof createMcpOAuthProtocol>;
    tenancyMode: TenancyMode;
    /** Cloud connectorKind classifier supplied by composition; never display-name authority. */
    isGrokRoutine(request: AuthorizationRequest, client: McpOAuthClient): boolean;
    /** Pure signer from the OIDC port; required only for a consented openid code. */
    issueIdToken?(input: { issuer:string; clientId:string; sectorIdentifier:string; userId:string;
      accessToken:string; nonce:string|null; now:Date }): string;
    now?: () => Date;
  }) { this.sessions=new McpOAuthSessions(database,options); }

  async registerMcpOAuthClient(input: ClientRegistrationInput): Promise<McpOAuthClient> {
    const client = { clientId: `mcpc_${randomBytes(18).toString("base64url")}`, clientName: input.clientName,
      redirectUris: [...input.redirectUris], createdAt: this.now() };
    await this.database.query(`INSERT INTO selfhost_mcp_oauth_clients (client_id,client_name,redirect_uris,created_at)
      VALUES ($1,$2,$3,$4)`, [client.clientId, client.clientName, client.redirectUris, client.createdAt]);
    return client;
  }

  async getMcpOAuthClient(clientId: string | null | undefined): Promise<McpOAuthClient | null> {
    if (!clientId || clientId.length > 128) return null;
    const result = await this.database.query<ClientRow>("SELECT * FROM selfhost_mcp_oauth_clients WHERE client_id=$1", [clientId]);
    return result.rows[0] ? clientFromRow(result.rows[0]) : null;
  }

  private now(): Date { return (this.options.now ?? (() => new Date()))(); }

  /** Same lock order as every design-G membership writer; tenant is explicit. */
  private async lockWorkspaceAccess(tx: SqlExecutor, owner: McpOAuthOwner): Promise<boolean> {
    await lockUser(tx, owner.userId);
    await lockOrganization(tx, owner.organizationId);
    const result = await tx.query(`SELECT w.id FROM selfhost_workspaces w
      JOIN selfhost_organization_memberships m ON m.organization_id=w.organization_id AND m.user_id=$1
      WHERE w.id=$2 AND w.organization_id=$3
        AND ($4::text='multi' OR NOT EXISTS (SELECT 1 FROM selfhost_organizations other WHERE other.id<>$3)) FOR KEY SHARE OF m,w`,
    [owner.userId, owner.workspaceId, owner.organizationId, this.options.tenancyMode]);
    return result.rows.length === 1;
  }

  private async connections(tx: SqlExecutor, request: AuthorizationRequest, principal: McpOAuthConsentPrincipal): Promise<ConnectionRow[]> {
    const result = await tx.query<ConnectionRow>(`SELECT id,scopes FROM selfhost_mcp_oauth_grants
      WHERE client_id=$1 AND resource=$2 AND user_id=$3 AND organization_id=$4 AND workspace_id=$5
        AND agent_name=$6 AND revoked_at IS NULL FOR UPDATE`,
    [request.clientId, request.resource, principal.userId, principal.organizationId, principal.workspaceId, principal.agentName]);
    return result.rows;
  }

  /** Source continuation behavior, with live membership and name check under the same locks. */
  async createMcpOAuthAuthorizationCode(request: AuthorizationRequest, principal: McpOAuthConsentPrincipal,
    continuationGrantId?: string): Promise<string> {
    const stepUp = this.options.protocol.canContinueEventsConsent(request);
    if (continuationGrantId && (!stepUp || !UUID.test(continuationGrantId))) {
      throw new McpOAuthContinuationError("Select an active existing connection for this client, workspace and agent.");
    }
    continuationGrantId = continuationGrantId?.toLowerCase();
    const code = `mcpac_${randomBytes(32).toString("base64url")}`;
    await this.database.transaction(async tx => {
      if (!await this.lockWorkspaceAccess(tx, principal)) {
        throw new McpOAuthContinuationError("Workspace access changed. Repeat consent after rejoining.");
      }
      const clientResult = await tx.query<ClientRow>("SELECT * FROM selfhost_mcp_oauth_clients WHERE client_id=$1", [request.clientId]);
      if (!clientResult.rows[0]) throw new McpOAuthContinuationError("The OAuth client is no longer available.");
      const client = clientFromRow(clientResult.rows[0]);
      const matches = stepUp ? await this.connections(tx, request, principal) : [];
      if (stepUp) {
        const selected = matches.find(grant => grant.id === continuationGrantId);
        if (continuationGrantId && (!selected || !selected.scopes.every(scope => request.scopes.some(allowed => allowed === scope)))) {
          throw new McpOAuthContinuationError("Select an active existing connection with all its existing permissions.");
        }
      }
      if (this.options.isGrokRoutine(request, client)) {
        // Both code issuance and the forthcoming redemption path must take
        // these same owner locks. Never rely on the advisory UI name lookup.
        const collision = await tx.query(`SELECT id FROM selfhost_mcp_oauth_grants
          WHERE user_id=$1 AND organization_id=$2 AND workspace_id=$3 AND agent_name=$4
            AND revoked_at IS NULL AND ($5::uuid IS NULL OR id<>$5::uuid) LIMIT 1`,
        [principal.userId, principal.organizationId, principal.workspaceId, principal.agentName, continuationGrantId ?? null]);
        if (collision.rows.length) throw new McpOAuthAgentNameTakenError();
      }
      if (stepUp && !continuationGrantId && matches.length) {
        throw new McpOAuthContinuationError("Select the existing connection to retain its wake subscriptions and settings.");
      }
      const createdAt = this.now();
      await tx.query(`INSERT INTO selfhost_mcp_oauth_authorization_codes
        (code_hash,client_id,user_id,organization_id,workspace_id,agent_name,redirect_uri,code_challenge,
         scopes,resource,oidc_nonce,grant_id,expires_at,created_at,redirect_uri_required)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
      [hashSecret(code), request.clientId, principal.userId, principal.organizationId, principal.workspaceId,
        principal.agentName, request.redirectUri, request.codeChallenge, request.scopes, request.resource,
        request.oidcNonce, continuationGrantId ?? null, new Date(createdAt.getTime() + CODE_TTL_SECONDS * 1000), createdAt, request.redirectUriRequired ?? true]);
    });
    return code;
  }

  async listConnectedAgentNames(owner: McpOAuthOwner): Promise<Array<{ workspaceId: string; agentName: string }>> {
    return this.database.transaction(async tx => {
      if (!await this.lockWorkspaceAccess(tx, owner)) return [];
      const result = await tx.query<{ workspace_id: string; agent_name: string }>(`SELECT DISTINCT workspace_id,agent_name
        FROM selfhost_mcp_oauth_grants WHERE user_id=$1 AND organization_id=$2 AND workspace_id=$3 AND revoked_at IS NULL`,
      [owner.userId, owner.organizationId, owner.workspaceId]);
      return result.rows.map(row => ({ workspaceId: row.workspace_id, agentName: row.agent_name }));
    });
  }

  private async grant(tx: SqlExecutor,id: string): Promise<GrantRow|null> {
    return (await tx.query<GrantRow>("SELECT * FROM selfhost_mcp_oauth_grants WHERE id=$1 FOR UPDATE",[id])).rows[0]??null;
  }

  private tokenResult(tokens:McpOAuthIssuedPair,idToken?:string):McpOAuthTokenResult {
    return { ok:true,body:{ access_token:tokens.accessToken,token_type:"Bearer",
      expires_in:Math.max(0,Math.round((Date.parse(tokens.accessTokenExpiresAt)-this.now().getTime())/1000)),
      refresh_token:tokens.refreshToken,scope:tokens.scopes.join(" "),...(idToken?{ id_token:idToken }:{}) } };
  }

  /** Caller holds user->org locks. Authority and durable teardown commit together. */
  private async revokeRows(tx:SqlExecutor,id:string,reason:string):Promise<boolean> {
    return revokeMcpOAuthGrantRows(tx,id,reason,this.now());
  }

  /** Port of Cloud code redemption: verify bindings before consume/replay action. */
  async exchangeMcpOAuthAuthorizationCode(input:{ code:string; clientId:string; redirectUri:string|undefined;
    codeVerifier:string; resource:string|undefined }):Promise<McpOAuthTokenResult> {
    if(!isValidCodeVerifier(input.codeVerifier)) return { ok:false,status:400,error:{ error:"invalid_request",error_description:"code_verifier is malformed." } };
    const codeHash=hashSecret(input.code);
    return this.database.transaction(async tx=>{
      const candidate=(await tx.query<CodeRow>("SELECT * FROM selfhost_mcp_oauth_authorization_codes WHERE code_hash=$1",[codeHash])).rows[0];
      if(!candidate || !await this.lockWorkspaceAccess(tx,{ userId:candidate.user_id,organizationId:candidate.organization_id,workspaceId:candidate.workspace_id })) return invalidGrant();
      const row=(await tx.query<CodeRow>("SELECT * FROM selfhost_mcp_oauth_authorization_codes WHERE code_hash=$1 FOR UPDATE",[codeHash])).rows[0];
      const now=this.now();
      if(!row || row.user_id!==candidate.user_id || row.organization_id!==candidate.organization_id || row.workspace_id!==candidate.workspace_id ||
        new Date(row.expires_at).getTime()<=now.getTime()) return invalidGrant();
      if(row.client_id!==input.clientId || (row.redirect_uri_required && input.redirectUri===undefined) ||
        (input.redirectUri!==undefined && input.redirectUri!==row.redirect_uri)) return invalidGrant();
      if(input.resource!==undefined && this.options.protocol.canonicalMcpResourceParam(input.resource)!==row.resource) return invalidTarget();
      if(pkceS256(input.codeVerifier)!==row.code_challenge) return invalidGrant("PKCE verification failed.");
      const resourcePath=this.options.protocol.parseMcpResource(row.resource);
      if(!resourcePath) return invalidTarget();
      const context={ userId:row.user_id,organizationId:row.organization_id,workspaceId:row.workspace_id,agentName:row.agent_name };
      if(row.consumed_at) {
        const grant=row.grant_id?await this.grant(tx,row.grant_id):null;
        if(grant && (grant.user_id!==row.user_id || grant.organization_id!==row.organization_id || grant.workspace_id!==row.workspace_id ||
          grant.client_id!==row.client_id || grant.resource!==row.resource)) return invalidGrant();
        const previousSessions=grant && !grant.continued_at && resourcePath==="/api/v1/mcp/relay-events"
          ? (await tx.query(`SELECT id FROM selfhost_mcp_oauth_sessions WHERE grant_id=$1 AND token_family_id=$2
              AND user_id=$3 AND organization_id=$4 AND workspace_id=$5 LIMIT 2`,
            [grant.id,grant.token_family_id,grant.user_id,grant.organization_id,grant.workspace_id])).rows:[];
        if(grant && (grant.continued_at || previousSessions.length===2)) {
          if(!grant.continued_at) await tx.query("UPDATE selfhost_mcp_oauth_grants SET continued_at=$2 WHERE id=$1",[grant.id,now]);
          if(row.issued_session_id) await this.sessions.revokeSession(tx,row.issued_session_id,ownerOf(grant),"authorization_code_replayed");
        } else if(grant) await this.revokeRows(tx,grant.id,"authorization_code_replayed");
        return invalidGrant("The authorization code was already used.");
      }
      const authorization:AuthorizationRequest={ clientId:row.client_id,redirectUri:row.redirect_uri,codeChallenge:row.code_challenge,
        scopes:row.scopes as McpAuthorizationScope[],resource:row.resource,resourcePath,state:null,oidcNonce:row.oidc_nonce,requestedAgentName:null };
      const continuation=this.options.protocol.canContinueEventsConsent(authorization);
      const matches=continuation?await this.connections(tx,authorization,context):[];
      const selected=row.grant_id?matches.find(grant=>grant.id===row.grant_id):undefined;
      if(row.grant_id && (!continuation || !selected || !selected.scopes.every(scope=>row.scopes.includes(scope)))) return invalidGrant("The selected existing connection changed or was revoked. Repeat consent.");
      const clientRow=(await tx.query<ClientRow>("SELECT * FROM selfhost_mcp_oauth_clients WHERE client_id=$1",[row.client_id])).rows[0];
      if(!clientRow) return invalidGrant();
      const client=clientFromRow(clientRow);
      if(this.options.isGrokRoutine(authorization,client)) {
        const collision=await tx.query(`SELECT id FROM selfhost_mcp_oauth_grants WHERE user_id=$1 AND organization_id=$2
          AND workspace_id=$3 AND agent_name=$4 AND revoked_at IS NULL AND ($5::uuid IS NULL OR id<>$5::uuid) LIMIT 1`,
        [row.user_id,row.organization_id,row.workspace_id,row.agent_name,row.grant_id]);
        if(collision.rows.length) return { ok:false,status:409,error:{ error:"agent_name_taken",error_description:"That name is already in use. Choose another name." } };
      }
      if(!row.grant_id && continuation && matches.length) return invalidGrant("An existing connection appeared. Repeat consent and select it to retain its wake subscriptions and settings.");
      if(row.scopes.includes("openid") && !this.options.issueIdToken) throw new Error("MCP OIDC signing is not configured");
      const previous=row.grant_id?await this.grant(tx,row.grant_id):null;
      const grantId=previous?.id??randomUUID(),tokenFamilyId=previous?.token_family_id??randomUUID();
      if(previous) {
        await tx.query(`UPDATE selfhost_mcp_oauth_grants SET scopes=$2,setup_handoff_id=$3,continued_at=COALESCE(continued_at,$4) WHERE id=$1`,
          [grantId,row.scopes,setupHandoff(input.code),now]);
      } else {
        await tx.query(`INSERT INTO selfhost_mcp_oauth_grants
          (id,client_id,client_name,user_id,organization_id,workspace_id,agent_name,scopes,resource,setup_handoff_id,token_family_id,created_at)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
        [grantId,row.client_id,client.clientName,row.user_id,row.organization_id,row.workspace_id,row.agent_name,row.scopes,row.resource,
          setupHandoff(input.code),tokenFamilyId,now]);
      }
      const tokens=await this.sessions.issue(tx,{ ...context,grantId,tokenFamilyId,scopes:row.scopes });
      await tx.query(`UPDATE selfhost_mcp_oauth_authorization_codes SET consumed_at=$2,grant_id=$3,issued_session_id=$4 WHERE code_hash=$1`,
        [codeHash,now,grantId,tokens.sessionId]);
      const idToken=row.scopes.includes("openid")?this.options.issueIdToken!({ issuer:this.options.protocol.mcpOAuthIssuer(),
        clientId:row.client_id,sectorIdentifier:oidcSectorIdentifierForRedirectUri(row.redirect_uri),userId:row.user_id,
        accessToken:tokens.accessToken,nonce:row.oidc_nonce,now }):undefined;
      return this.tokenResult(tokens,idToken);
    });
  }

  /** Cloud refresh bindings, rotation and 30-second lost-race/reuse grace. */
  async refreshMcpOAuthToken(input:{ refreshToken:string; clientId:string; resource:string|undefined }):Promise<McpOAuthTokenResult> {
    if(!input.refreshToken.startsWith(MCP_OAUTH_REFRESH_PREFIX) || input.refreshToken.length>128) return invalidGrant();
    return this.database.transaction(async tx=>{
      const session=await this.sessions.find(tx,"refresh",input.refreshToken);
      if(!session) {
        const retired=(await tx.query<{ grant_id:string; retired_at:Date|string }>(
          "SELECT grant_id,retired_at FROM selfhost_mcp_oauth_retired_refresh_tokens WHERE token_hash=$1",[hashSecret(input.refreshToken)])).rows[0];
        if(!retired) return invalidGrant();
        const candidate=(await tx.query<GrantRow>("SELECT * FROM selfhost_mcp_oauth_grants WHERE id=$1",[retired.grant_id])).rows[0];
        if(!candidate || !await this.lockWorkspaceAccess(tx,{ userId:candidate.user_id,organizationId:candidate.organization_id,workspaceId:candidate.workspace_id })) return invalidGrant();
        const grant=await this.grant(tx,candidate.id);
        if(!grant || grant.revoked_at || grant.client_id!==input.clientId) return invalidGrant();
        if(input.resource!==undefined && this.options.protocol.canonicalMcpResourceParam(input.resource)!==grant.resource) return invalidTarget();
        if(this.now().getTime()-new Date(retired.retired_at).getTime()>=30_000) await this.revokeRows(tx,grant.id,"refresh_token_reused");
        return invalidGrant();
      }
      if(!await this.lockWorkspaceAccess(tx,session)) return invalidGrant();
      const grant=await this.grant(tx,session.grantId);
      if(!grant || grant.revoked_at || session.revokedAt || grant.client_id!==input.clientId) return invalidGrant();
      if(input.resource!==undefined && this.options.protocol.canonicalMcpResourceParam(input.resource)!==grant.resource) return invalidTarget();
      const tokens=await this.sessions.rotate(tx,input.refreshToken,session);
      return tokens?this.tokenResult(tokens):invalidGrant();
    });
  }

  /** Internal cleanup entry; user-facing callers must authorize the grant owner. */
  async revokeMcpOAuthGrant(grantId:string,reason:string):Promise<boolean> {
    return this.database.transaction(async tx=>{
      const candidate=(await tx.query<GrantRow>("SELECT * FROM selfhost_mcp_oauth_grants WHERE id=$1",[grantId])).rows[0];
      if(!candidate) return false;
      await lockUser(tx,candidate.user_id); await lockOrganization(tx,candidate.organization_id);
      return this.revokeRows(tx,grantId,reason);
    });
  }

  /** RFC7009: unknown or client-mismatched tokens reveal no grant and do nothing. */
  async revokeMcpOAuthToken(input:{ token:string; clientId:string|undefined }):Promise<void> {
    await this.database.transaction(async tx=>{
      const session=await this.sessions.find(tx,"access",input.token)??await this.sessions.find(tx,"refresh",input.token);
      if(!session || (input.clientId!==undefined && input.clientId!==session.clientId)) return;
      await lockUser(tx,session.userId); await lockOrganization(tx,session.organizationId);
      await this.revokeRows(tx,session.grantId,"client_revoked");
    });
  }

  /** Membership-departure hook; caller already holds user->org locks. */
  async revokeWorkspaceMcpOAuthGrants(tx:SqlExecutor,owner:McpOAuthOwner):Promise<void> {
    await tx.query(`UPDATE selfhost_mcp_oauth_authorization_codes SET expires_at=$4
      WHERE user_id=$1 AND organization_id=$2 AND workspace_id=$3 AND expires_at>$4`,
    [owner.userId,owner.organizationId,owner.workspaceId,this.now()]);
    const grants=await tx.query<{ id:string }>(`SELECT id FROM selfhost_mcp_oauth_grants
      WHERE user_id=$1 AND organization_id=$2 AND workspace_id=$3 ORDER BY id`,[owner.userId,owner.organizationId,owner.workspaceId]);
    for(const { id } of grants.rows) await this.revokeRows(tx,id,"workspace_left");
  }

  /** Organization departure spans every workspace; caller holds user->org locks. */
  async revokeOrganizationMcpOAuthGrants(tx:SqlExecutor,owner:Pick<McpOAuthOwner,"userId"|"organizationId">):Promise<void> {
    await tx.query(`UPDATE selfhost_mcp_oauth_authorization_codes SET expires_at=$3
      WHERE user_id=$1 AND organization_id=$2 AND expires_at>$3`,[owner.userId,owner.organizationId,this.now()]);
    const grants=await tx.query<{ id:string }>(`SELECT id FROM selfhost_mcp_oauth_grants
      WHERE user_id=$1 AND organization_id=$2 ORDER BY id`,[owner.userId,owner.organizationId]);
    for(const { id } of grants.rows) await this.revokeRows(tx,id,"organization_left");
  }

  async getOAuthGrant(grantId:string,owner:McpOAuthOwner):Promise<McpOAuthGrant|null> {
    if(!UUID.test(grantId)) return null;
    return this.database.transaction(async tx=>{
      if(!await this.lockWorkspaceAccess(tx,owner)) return null;
      const row=(await tx.query<GrantRow>(`SELECT * FROM selfhost_mcp_oauth_grants
        WHERE id=$1 AND user_id=$2 AND organization_id=$3 AND workspace_id=$4`,
      [grantId,owner.userId,owner.organizationId,owner.workspaceId])).rows[0];
      return row?mapGrant(row):null;
    });
  }

  async getOAuthGrantForSetupHandoff(owner:McpOAuthOwner,handoff:string):Promise<McpOAuthGrant|null> {
    if(!/^mcpos_[a-f0-9]{64}$/.test(handoff)) return null;
    return this.database.transaction(async tx=>{
      if(!await this.lockWorkspaceAccess(tx,owner)) return null;
      const row=(await tx.query<GrantRow>(`SELECT * FROM selfhost_mcp_oauth_grants WHERE setup_handoff_id=$1
        AND user_id=$2 AND organization_id=$3 AND workspace_id=$4 AND revoked_at IS NULL`,
      [handoff,owner.userId,owner.organizationId,owner.workspaceId])).rows[0];
      return row?mapGrant(row):null;
    });
  }

  async isOAuthSetupHandoffPending(owner:McpOAuthOwner,handoff:string):Promise<boolean> {
    if(!/^mcpos_[a-f0-9]{64}$/.test(handoff)) return false;
    return this.database.transaction(async tx=>{
      if(!await this.lockWorkspaceAccess(tx,owner)) return false;
      return (await tx.query(`SELECT code_hash FROM selfhost_mcp_oauth_authorization_codes WHERE code_hash=$1
        AND user_id=$2 AND organization_id=$3 AND workspace_id=$4 AND consumed_at IS NULL AND expires_at>$5`,
      [handoff.slice(6),owner.userId,owner.organizationId,owner.workspaceId,this.now()])).rows.length===1;
    });
  }

  async isOAuthGrantActive(grantId:string,owner:McpOAuthOwner):Promise<boolean> {
    const grant=await this.getOAuthGrant(grantId,owner);
    return grant!==null && grant.revokedAt===null;
  }

  async hasMcpOAuthGrantForWorkspace(owner:McpOAuthOwner,resource:string):Promise<boolean> {
    if(!this.options.protocol.parseMcpResource(resource)) return false;
    return this.database.transaction(async tx=>{
      if(!await this.lockWorkspaceAccess(tx,owner)) return false;
      return (await tx.query(`SELECT g.id FROM selfhost_mcp_oauth_grants g JOIN selfhost_mcp_oauth_sessions s ON s.grant_id=g.id
        WHERE g.user_id=$1 AND g.organization_id=$2 AND g.workspace_id=$3 AND g.resource=$4 AND g.revoked_at IS NULL
          AND s.revoked_at IS NULL AND s.refresh_token_expires_at>$5 LIMIT 1`,
      [owner.userId,owner.organizationId,owner.workspaceId,this.options.protocol.canonicalMcpResourceParam(resource),this.now()])).rows.length===1;
    });
  }

  async listMcpOAuthGrantsForUser(owner:McpOAuthOwner,connection?:{ clientId:string;resource:string }):Promise<McpOAuthGrant[]> {
    if(connection && !this.options.protocol.parseMcpResource(connection.resource)) return [];
    const resource=connection?this.options.protocol.canonicalMcpResourceParam(connection.resource):undefined;
    return this.database.transaction(async tx=>{
      if(!await this.lockWorkspaceAccess(tx,owner)) return [];
      const result=await tx.query<GrantRow>(`SELECT * FROM selfhost_mcp_oauth_grants WHERE user_id=$1 AND organization_id=$2
        AND workspace_id=$3 AND revoked_at IS NULL ${connection?"AND client_id=$4 AND resource=$5":""}
        ORDER BY created_at DESC,id ${connection?"":"LIMIT 200"}`,
      [owner.userId,owner.organizationId,owner.workspaceId,...(connection?[connection.clientId,resource]:[])]);
      return result.rows.map(mapGrant);
    });
  }
}

/**
 * Revokes one grant, ends its session family and writes the durable
 * revocation tombstone that drives Relaycast teardown, all on the caller's
 * transaction. Caller holds user->org locks. Returns whether the grant was
 * live before this call.
 */
export async function revokeMcpOAuthGrantRows(tx:SqlExecutor,id:string,reason:string,now:Date):Promise<boolean> {
  const grant=(await tx.query<GrantRow>("SELECT * FROM selfhost_mcp_oauth_grants WHERE id=$1 FOR UPDATE",[id])).rows[0];
  if(!grant) return false;
  const changed=grant.revoked_at===null;
  await tx.query(`UPDATE selfhost_mcp_oauth_grants SET revoked_at=$2,revoked_reason=$3 WHERE id=$1 AND revoked_at IS NULL`,[id,now,reason]);
  await revokeMcpOAuthSessionFamily(tx,ownerOf(grant),`oauth_grant_${grant.revoked_reason??reason}`,now);
  await tx.query(`INSERT INTO selfhost_mcp_oauth_revocations
    (id,grant_id,token_family_id,user_id,organization_id,workspace_id,client_id,agent_name,agent_remote_id,reason,created_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (grant_id) DO NOTHING`,
  [randomUUID(),id,grant.token_family_id,grant.user_id,grant.organization_id,grant.workspace_id,grant.client_id,
    grant.agent_name,grant.agent_remote_id,grant.revoked_reason??reason,now]);
  return changed;
}
