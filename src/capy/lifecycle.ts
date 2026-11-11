import type { SqlExecutor } from "../database.js";

type Scope = { organizationId: string; workspaceId: string; userId?: never }
  | { organizationId: string; userId: string; workspaceId?: never };
type Reason = "capy_connection_replaced" | "capy_disconnected" | "capy_member_removed" | "capy_member_demoted";

/** Transaction-local revocation, after the caller's tenancy/connection locks.
 * No external calls: commit it atomically with the owning key/member change.
 * Remote identities remain durable cleanup obligations, including unknown writes.
 */
export async function retireCapyBindingsInTx(tx: SqlExecutor, scope: Scope, reason: Reason): Promise<void> {
  const column=scope.workspaceId !== undefined ? "workspace_id" : "user_id";
  const id=scope.workspaceId ?? scope.userId;
  await tx.query(`UPDATE capy_bindings SET state='retired',generation=generation+1,
    token_ciphertext=NULL,lease_owner=NULL,lease_until=NULL,cleanup_pending=true,
    last_error=$3,updated_at=now()
    WHERE organization_id=$1 AND ${column}=$2 AND state<>'retired'`,[scope.organizationId,id,reason]);
}

/** Called with the workspace row locked. Never discard active/unknown custody.
 * The live workspace key must survive until exact-id remote cleanup completes.
 */
export async function removeCompletedWorkspaceCapyInTx(tx: SqlExecutor, organizationId: string, workspaceId: string): Promise<boolean> {
  const pending=await tx.query(`SELECT 1 FROM capy_bindings WHERE organization_id=$1 AND workspace_id=$2
    AND (state<>'retired' OR cleanup_pending OR agent_remote_id IS NOT NULL) LIMIT 1`,[organizationId,workspaceId]);
  if (pending.rows.length) return false;
  await tx.query(`DELETE FROM capy_bindings WHERE organization_id=$1 AND workspace_id=$2
    AND state='retired' AND NOT cleanup_pending AND agent_remote_id IS NULL`,[organizationId,workspaceId]);
  return true;
}
