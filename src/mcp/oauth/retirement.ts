import type { SqlExecutor } from "../../database.js";

export const MCP_OAUTH_RETIRING_MESSAGE =
  "This agent is being retired after a disconnect. Choose another name or retry shortly.";

/** A binding to an identity whose remote release may be in flight. */
export class McpOAuthAgentRetiring extends Error {
  constructor() { super(MCP_OAUTH_RETIRING_MESSAGE); this.name = "McpOAuthAgentRetiring"; }
}

export type RetiringIdentityQuery = {
  organizationId: string; workspaceId: string; userId: string;
  agentRemoteId: string | null; agentName: string;
};

/**
 * The retirement fence. The revocation row is written in the revocation
 * transaction, so it predates any teardown claim. While it is pending, or
 * after the operator abandoned it (a release may still be in flight), its
 * agent must not gain a new binding: the release that follows would leave the
 * binding pointing at a released agent. Abandoned rows fence by immutable id
 * only; the name match for never-pinned rows applies only while pending.
 * Identities teardown keeps anyway (another live grant pinned to the id, or
 * a native MCP session bound to its participant row) are not fenced.
 * Call under the owner lock, in the transaction that would write the binding,
 * before any Relaycast call.
 */
export async function retiringIdentity(tx: SqlExecutor, query: RetiringIdentityQuery): Promise<boolean> {
  const result = await tx.query(`SELECT 1 FROM mcp_oauth_revocations r
    WHERE r.organization_id=$1 AND r.workspace_id=$2 AND r.user_id=$3
      AND (($4::text IS NOT NULL AND r.agent_remote_id=$4::text
            AND (r.completed_at IS NULL OR r.outcome='operator_abandoned'))
        OR (r.completed_at IS NULL AND r.agent_remote_id IS NULL AND r.agent_name=$5))
      AND NOT ($4::text IS NOT NULL AND (
        EXISTS (SELECT 1 FROM mcp_oauth_grants g
          WHERE g.organization_id=$1 AND g.workspace_id=$2 AND g.user_id=$3
            AND g.revoked_at IS NULL AND g.agent_remote_id=$4::text)
        OR EXISTS (SELECT 1 FROM hosted_relay_participants p
          WHERE p.workspace_id=$2 AND p.user_id=$3 AND p.agent_remote_id=$4::text AND p.session_hash IS NOT NULL)))
    LIMIT 1`,
  [query.organizationId, query.workspaceId, query.userId, query.agentRemoteId, query.agentName]);
  return result.rows.length > 0;
}
