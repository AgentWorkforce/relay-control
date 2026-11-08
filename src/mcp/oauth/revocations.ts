import { randomUUID } from "node:crypto";
import type { SqlExecutor } from "../../database.js";

type Grant = { id:string; token_family_id:string; user_id:string; organization_id:string; workspace_id:string;
  client_id:string; agent_name:string; agent_remote_id:string|null; revoked_at:Date|string|null; revoked_reason:string|null };

/** Caller holds user->organization locks. Authority and teardown intent commit together. */
export async function revokeMcpOAuthGrantRows(tx:SqlExecutor,id:string,reason:string,now:Date):Promise<boolean> {
  const grant=(await tx.query<Grant>("SELECT * FROM selfhost_mcp_oauth_grants WHERE id=$1 FOR UPDATE",[id])).rows[0];
  if(!grant) return false;
  await tx.query(`UPDATE selfhost_mcp_oauth_grants SET revoked_at=$2,revoked_reason=$3 WHERE id=$1 AND revoked_at IS NULL`,[id,now,reason]);
  await tx.query(`UPDATE selfhost_mcp_oauth_sessions SET revoked_at=$6,revoked_reason=$7,updated_at=$6
    WHERE grant_id=$1 AND token_family_id=$2 AND user_id=$3 AND organization_id=$4 AND workspace_id=$5 AND revoked_at IS NULL`,
  [id,grant.token_family_id,grant.user_id,grant.organization_id,grant.workspace_id,now,`oauth_grant_${grant.revoked_reason??reason}`]);
  await tx.query(`INSERT INTO selfhost_mcp_oauth_revocations
    (id,grant_id,token_family_id,user_id,organization_id,workspace_id,client_id,agent_name,agent_remote_id,reason,created_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (grant_id) DO NOTHING`,
  [randomUUID(),id,grant.token_family_id,grant.user_id,grant.organization_id,grant.workspace_id,grant.client_id,
    grant.agent_name,grant.agent_remote_id,grant.revoked_reason??reason,now]);
  return grant.revoked_at===null;
}

/** Explicit organization departure, all workspaces; caller already holds user->org locks. */
export async function revokeOrganizationMcpOAuthGrants(tx:SqlExecutor,owner:{userId:string;organizationId:string},now=new Date()):Promise<void> {
  await tx.query(`UPDATE selfhost_mcp_oauth_authorization_codes SET expires_at=$3
    WHERE user_id=$1 AND organization_id=$2 AND expires_at>$3`,[owner.userId,owner.organizationId,now]);
  const grants=await tx.query<{id:string}>(`SELECT id FROM selfhost_mcp_oauth_grants
    WHERE user_id=$1 AND organization_id=$2 ORDER BY id`,[owner.userId,owner.organizationId]);
  for(const {id} of grants.rows) await revokeMcpOAuthGrantRows(tx,id,"organization_left",now);
}
