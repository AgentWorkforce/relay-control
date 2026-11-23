import type { Database } from "../database.js";
import { flushRelaycastRedactions, recordDelegationAudit, redactExpiredQuotes, type RelaycastQuoteRedactor } from "./service.js";

/** How often the delegation retention sweep runs. */
export const DELEGATION_SWEEP_INTERVAL_MS = 60 * 60 * 1000;

/**
 * The delegation retention sweep, independent of delegation traffic:
 * quotes older than their org's `quote_retention_days` are redacted to their
 * keyed digest (and queued for redaction in Relaycast, retried here), and lapsed active grants are marked `expired` with one `grant.expired`
 * event each (as Cloud's sweep does). Attestation and audit reads also redact,
 * so the sweep only bounds how long a quiet workspace keeps quote text.
 */
export function createDelegationRetention(input: {
  database: Database;
  /** Redacts queued quotes in Relaycast; null or absent: they stay queued. */
  relaycastRedact?: RelaycastQuoteRedactor;
  relaycastBinding?: (workspaceId: string) => Promise<{ relaycastWorkspaceId: string } | null>;
  log?: (message: string, fields: Record<string, unknown>) => void;
}) {
  let timer: NodeJS.Timeout | null = null;
  const log = input.log ?? ((message, fields) => console.warn(`[delegation] ${message}`, fields));

  async function sweep(): Promise<{ expired: number; relaycastPending: number }> {
    await redactExpiredQuotes(input.database);
    const relaycast = await flushRelaycastRedactions(input.database, { redact: input.relaycastRedact ?? null,
      relaycastBinding: input.relaycastBinding ?? (async () => null) });
    const expired = await input.database.transaction(async (tx) => {
      const rows = (await tx.query<{ id: string; workspace_id: string; owner_user_id: string; delegate_agent_id: string }>(
        `UPDATE delegation_grants SET status = 'expired', updated_at = now()
          WHERE status = 'active' AND expires_at <= now()
          RETURNING id, workspace_id, owner_user_id, delegate_agent_id`,
      )).rows;
      for (const row of rows) {
        await recordDelegationAudit(tx, { workspaceId: row.workspace_id, event: "grant.expired",
          ownerUserId: row.owner_user_id, grantId: row.id, actorAgentId: row.delegate_agent_id, reason: "expired" });
      }
      return rows.length;
    });
    return { expired, relaycastPending: relaycast.pending };
  }

  return {
    sweep,
    /** Starts the hourly sweep (runs once now); stop() ends it. */
    start() {
      if (timer) return;
      const run = () => {
        void sweep().catch((error: unknown) => {
          log("retention sweep failed", { error: error instanceof Error ? error.message : String(error) });
        });
      };
      run();
      timer = setInterval(run, DELEGATION_SWEEP_INTERVAL_MS);
      timer.unref();
    },
    stop() {
      if (timer) clearInterval(timer);
      timer = null;
    },
  };
}
