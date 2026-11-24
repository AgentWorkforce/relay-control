import type { Database } from "../database.js";
import { logRedactionBacklog, logUnavailable } from "./observe.js";
import {
  flushRelaycastRedactions,
  recordDelegationAudit,
  redactExpiredQuotes,
  relaycastRedactionBacklog,
  type RelaycastQuoteRedactor,
} from "./service.js";

/** How often the delegation retention sweep runs. */
export const DELEGATION_SWEEP_INTERVAL_MS = 60 * 60 * 1000;

/** At most this many grants and this many quotes per sweep, so one run never holds them all in one transaction (as Cloud). */
export const DELEGATION_SWEEP_LIMIT = 500;

export type DelegationSweepResult = {
  expired: number;
  redacted: number;
  relaycastRedacted: number;
  relaycastAbsent: number;
  relaycastRejected: number;
  /** Unfinished Relaycast redactions, any state. */
  relaycastPending: number;
  /** Parked for an operator (rejected). */
  relaycastRejectedTotal: number;
  /** Unfinished and older than REDACTION_STALE_HOURS. */
  relaycastStale: number;
  relaycastOldestPendingSeconds: number | null;
};

/**
 * The delegation retention sweep, independent of delegation traffic, as
 * Cloud's retention route: up to `limit` lapsed grants are marked `expired`
 * (one `grant.expired` event each), up to `limit` quotes older than their
 * org's `quote_retention_days` are redacted to their keyed digest and queued
 * for redaction in Relaycast (one statement), the due Relaycast redactions
 * are tried, and the queue's backlog is reported and logged
 * (`delegation.redaction_backlog`, warn while any is rejected or stale).
 * Audit reads also redact. See docs/delegation-quote-redaction-runbook.md.
 */
export function createDelegationRetention(input: {
  database: Database;
  /** Redacts queued quotes in Relaycast; null or absent: they stay queued. */
  relaycastRedact?: RelaycastQuoteRedactor;
  relaycastBinding?: (workspaceId: string) => Promise<{ relaycastWorkspaceId: string } | null>;
  limit?: number;
}) {
  let timer: NodeJS.Timeout | null = null;
  const limit = input.limit ?? DELEGATION_SWEEP_LIMIT;

  async function sweep(): Promise<DelegationSweepResult> {
    const expired = await input.database.transaction(async (tx) => {
      const rows = (await tx.query<{ id: string; workspace_id: string; owner_user_id: string; delegate_agent_id: string }>(
        `UPDATE delegation_grants SET status = 'expired', updated_at = now()
          WHERE id IN (SELECT id FROM delegation_grants WHERE status = 'active' AND expires_at <= now() LIMIT $1)
            AND status = 'active' AND expires_at <= now()
          RETURNING id, workspace_id, owner_user_id, delegate_agent_id`,
        [limit],
      )).rows;
      for (const row of rows) {
        await recordDelegationAudit(tx, { workspaceId: row.workspace_id, event: "grant.expired",
          ownerUserId: row.owner_user_id, grantId: row.id, actorAgentId: row.delegate_agent_id, reason: "expired" });
      }
      return rows.length;
    });
    const redacted = await redactExpiredQuotes(input.database, limit);
    const relaycast = await flushRelaycastRedactions(input.database, { redact: input.relaycastRedact ?? null,
      relaycastBinding: input.relaycastBinding ?? (async () => null) });
    const backlog = await relaycastRedactionBacklog(input.database);
    if (backlog.unfinished > 0) {
      logRedactionBacklog(backlog.rejected > 0 || backlog.stale > 0 ? "warn" : "info", { unfinished: backlog.unfinished,
        rejected: backlog.rejected, stale: backlog.stale, oldest_age_seconds: backlog.oldestAgeSeconds });
    }
    return { expired, redacted, relaycastRedacted: relaycast.redacted, relaycastAbsent: relaycast.absent,
      relaycastRejected: relaycast.rejected, relaycastPending: relaycast.pending, relaycastRejectedTotal: backlog.rejected,
      relaycastStale: backlog.stale, relaycastOldestPendingSeconds: backlog.oldestAgeSeconds };
  }

  return {
    sweep,
    /** Starts the hourly sweep (runs once now); stop() ends it. */
    start() {
      if (timer) return;
      const run = () => {
        // Class and SQLSTATE only, never the error's message.
        void sweep().catch((error: unknown) => logUnavailable("retention", error));
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
