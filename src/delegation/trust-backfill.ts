import type { Database } from "../database.js";
import { retiringIdentity } from "../mcp/oauth/retirement.js";
import { recordDelegationAudit } from "./service.js";
import { launcherName } from "./trust.js";

/**
 * The existing-connections backfill for the trust rule, as Cloud's
 * lib/delegation/trust-backfill.ts (#owner-decisions 251242695516778496:
 * "Build a backfill for existing connections (prod run needs my OK)").
 *
 * A connector grant becomes a trust-rule root only once it is pinned to its
 * agent's immutable id (`mcp_oauth_grants.agent_remote_id`). A grant
 * consented before its participant was ever resolved is still unpinned; the
 * connector pins it on its next call (src/mcp/oauth/admission.ts pin). This
 * pins it now the same way, from stored rows only: the grant is live, exactly
 * one hosted participant of the same owner in the same workspace holds the
 * agent name the owner consented to, the agent id has no other Control
 * binding, and no retirement of that identity is in flight. Everything else
 * is skipped and counted (fail closed). It creates no rule and no grant,
 * writes only the pin (one audited `trust_root.backfilled` event per grant,
 * actor system, reason backfill), and is idempotent: a pinned grant is never
 * touched again. It pages by grant id (`after`, `next_cursor`).
 */
export type TrustBackfillSkip = "no_participant" | "ambiguous_participant" | "launcher" | "other_binding" | "retiring" | "raced";
export type TrustBackfillReport = {
  dry_run: boolean;
  scanned: number;
  provable: number;
  pinned: number;
  skipped: Record<TrustBackfillSkip, number>;
  /** What was (or, in a dry run, would be) pinned: ids only, never tokens. */
  pins: Array<{ workspace_id: string; owner_id: string; oauth_grant_id: string; agent_id: string }>;
  /** Pass as `after` to scan the next page; null once every unpinned grant was scanned. */
  next_cursor: string | null;
};

export async function backfillConnectorRoots(database: Database, input: { apply: boolean; limit?: number; after?: string }):
  Promise<TrustBackfillReport> {
  const limit = Math.min(Math.max(input.limit ?? 500, 1), 2000);
  const report: TrustBackfillReport = { dry_run: !input.apply, scanned: 0, provable: 0, pinned: 0,
    skipped: { no_participant: 0, ambiguous_participant: 0, launcher: 0, other_binding: 0, retiring: 0, raced: 0 }, pins: [],
    next_cursor: null };
  // Paged by id: skipped rows stay unpinned, so a rerun without the cursor
  // would see them again first; the cursor moves past them.
  const unpinned = (await database.query<{ id: string; organization_id: string; workspace_id: string; user_id: string;
    agent_name: string }>(
    `SELECT id::text, organization_id::text, workspace_id::text, user_id::text, agent_name FROM mcp_oauth_grants
      WHERE agent_remote_id IS NULL AND revoked_at IS NULL AND ($1::uuid IS NULL OR id > $1::uuid)
      ORDER BY id LIMIT $2`,
    [input.after ?? null, limit],
  )).rows;
  if (unpinned.length === limit) report.next_cursor = unpinned[unpinned.length - 1]!.id;
  for (const grant of unpinned) {
    report.scanned += 1;
    if (grant.agent_name === launcherName(grant.user_id)) {
      report.skipped.launcher += 1;
      continue;
    }
    const participants = (await database.query<{ agent_remote_id: string; relaycast_workspace_id: string }>(
      `SELECT agent_remote_id, relaycast_workspace_id FROM hosted_relay_participants
        WHERE workspace_id = $1 AND user_id = $2 AND agent_name = $3 LIMIT 2`,
      [grant.workspace_id, grant.user_id, grant.agent_name],
    )).rows;
    if (!participants.length) {
      report.skipped.no_participant += 1;
      continue;
    }
    if (participants.length > 1) {
      report.skipped.ambiguous_participant += 1;
      continue;
    }
    const participant = participants[0]!;
    // The agent id must have no other Control binding (desktop, person identity,
    // claim, launch, another participant), as the rule's chain requires.
    const others = (await database.query(
      `SELECT 1 FROM desktop_relay_identities WHERE relaycast_workspace_id = $1 AND agent_remote_id = $2
       UNION ALL SELECT 1 FROM person_identities WHERE relaycast_workspace_id = $1 AND agent_remote_id = $2
       UNION ALL SELECT 1 FROM delegation_agent_bindings WHERE relaycast_workspace_id = $1 AND agent_id = $2
       UNION ALL SELECT 1 FROM relay_spawns WHERE relaycast_workspace_id = $1 AND worker_id = $2
       UNION ALL SELECT 1 FROM hosted_relay_participants WHERE relaycast_workspace_id = $1 AND agent_remote_id = $2
       LIMIT 2`,
      [participant.relaycast_workspace_id, participant.agent_remote_id],
    )).rows.length;
    if (others !== 1) {
      report.skipped.other_binding += 1;
      continue;
    }
    if (await retiringIdentity(database, { organizationId: grant.organization_id, workspaceId: grant.workspace_id,
      userId: grant.user_id, agentRemoteId: participant.agent_remote_id, agentName: grant.agent_name })) {
      report.skipped.retiring += 1;
      continue;
    }
    report.provable += 1;
    const pin = { workspace_id: grant.workspace_id, owner_id: grant.user_id, oauth_grant_id: grant.id,
      agent_id: participant.agent_remote_id };
    if (!input.apply) {
      report.pins.push(pin);
      continue;
    }
    const pinned = await database.transaction(async (tx) => {
      // Re-checked in the write: still unpinned, unrevoked and consenting to the same name.
      const rows = (await tx.query(
        `UPDATE mcp_oauth_grants SET agent_remote_id = $2
          WHERE id = $1 AND agent_remote_id IS NULL AND revoked_at IS NULL AND agent_name = $3 RETURNING id`,
        [grant.id, participant.agent_remote_id, grant.agent_name],
      )).rows;
      if (!rows.length) return false;
      await recordDelegationAudit(tx, { workspaceId: grant.workspace_id, event: "trust_root.backfilled", actorUserId: null,
        authMethod: "system", ownerUserId: grant.user_id, reason: "backfill",
        data: { oauth_grant_id: grant.id, agent_id: participant.agent_remote_id } });
      return true;
    });
    if (pinned) {
      report.pinned += 1;
      report.pins.push(pin);
    } else {
      report.skipped.raced += 1;
    }
  }
  return report;
}
