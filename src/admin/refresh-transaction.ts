import type { SqlExecutor } from "../database.js";

export const REFRESH_TX_IDLE_TIMEOUT = "60s";
export const REFRESH_TX_LOCK_TIMEOUT = "30s";

/**
 * Credential-refresh transactions hold a per-credential lock across a provider
 * token exchange (15 s fetch timeout). SET LOCAL keeps the transaction alive
 * longer than the exchange even when the server default is shorter, bounds how
 * long a second refresher waits for the lock, and is scoped to this
 * transaction only so pooled sessions keep their defaults.
 */
export async function applyRefreshTransactionTimeouts(tx: SqlExecutor): Promise<void> {
  await tx.exec(`SET LOCAL idle_in_transaction_session_timeout = '${REFRESH_TX_IDLE_TIMEOUT}'`);
  await tx.exec(`SET LOCAL lock_timeout = '${REFRESH_TX_LOCK_TIMEOUT}'`);
}
