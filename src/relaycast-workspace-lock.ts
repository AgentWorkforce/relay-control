import type { SqlExecutor } from "./database.js";

/** Advisory-lock namespace for one Relaycast workspace's credential group ("RCK"). */
const RELAYCAST_WORKSPACE_LOCK_NAMESPACE = 0x52434b;

/**
 * Serializes every database write that can create, rotate or restore a
 * Relaycast workspace-key binding. Callers must hold the transaction open
 * until their binding rows are committed.
 */
export async function lockRelaycastWorkspace(
  tx: SqlExecutor,
  relaycastWorkspaceId: string,
): Promise<void> {
  await tx.query("SELECT pg_advisory_xact_lock($1::int, hashtext($2))", [
    RELAYCAST_WORKSPACE_LOCK_NAMESPACE,
    relaycastWorkspaceId,
  ]);
}
