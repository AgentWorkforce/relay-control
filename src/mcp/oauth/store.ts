/**
 * Cloud 1776499a mcp-oauth-store.ts: client and authorization-code portion.
 * SQL/tenant-lock adaptation only. This module does not mint token sessions,
 * mount routes or admit OAuth credentials to any control-plane API.
 */
import { randomBytes } from "node:crypto";
import type { Database, SqlExecutor } from "../../database.js";
import { hashSecret } from "../../crypto.js";
import { lockOrganization, lockUser, type TenancyMode } from "../../tenancy.js";
import { type AuthorizationRequest, type ClientRegistrationInput, type createMcpOAuthProtocol } from "./protocol.js";

const CODE_TTL_SECONDS = 120;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type McpOAuthOwner = { userId: string; organizationId: string; workspaceId: string };
export type McpOAuthConsentPrincipal = McpOAuthOwner & { agentName: string };
export type McpOAuthClient = { clientId: string; clientName: string | null; redirectUris: string[]; createdAt: Date };

export class McpOAuthContinuationError extends Error {}
export class McpOAuthAgentNameTakenError extends Error {
  readonly status = 409;
  readonly code = "agent_name_taken";
  constructor() { super("That name is already in use. Choose another name."); }
}

type ClientRow = { client_id: string; client_name: string | null; redirect_uris: string[]; created_at: Date | string };
type ConnectionRow = { id: string; scopes: string[] };

function clientFromRow(row: ClientRow): McpOAuthClient {
  return { clientId: row.client_id, clientName: row.client_name, redirectUris: row.redirect_uris, createdAt: new Date(row.created_at) };
}

export class McpOAuthStore {
  constructor(readonly database: Database, readonly options: {
    protocol: ReturnType<typeof createMcpOAuthProtocol>;
    tenancyMode: TenancyMode;
    /** Cloud connectorKind classifier supplied by composition; never display-name authority. */
    isGrokRoutine(request: AuthorizationRequest, client: McpOAuthClient): boolean;
    now?: () => Date;
  }) {}

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
        AND ($4::text='multi' OR NOT EXISTS (SELECT 1 FROM selfhost_organizations other WHERE other.id<>$3))`,
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
         scopes,resource,oidc_nonce,grant_id,expires_at,created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
      [hashSecret(code), request.clientId, principal.userId, principal.organizationId, principal.workspaceId,
        principal.agentName, request.redirectUri, request.codeChallenge, request.scopes, request.resource,
        request.oidcNonce, continuationGrantId ?? null, new Date(createdAt.getTime() + CODE_TTL_SECONDS * 1000), createdAt]);
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
}
