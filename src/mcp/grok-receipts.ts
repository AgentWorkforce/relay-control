import type { SqlExecutor } from "../database.js";

export type RoutineWakeReceipt = {
  state: "queued" | "wake_sent" | "backoff" | "failed" | "replied";
  wake_sent_at: string | null;
  replied_at: string | null;
  next_attempt_at: string | null;
  attempts: number;
  hint: string;
};

type WakeRow = {
  event_id: string | null;
  notified_at: Date | string | null;
  wake_sent_at: Date | string | null;
  wake_attempts: number;
  answered_at: Date | string | null;
  failures: number;
  last_error: string | null;
  next_attempt_at: Date | string;
};

const iso = (value: Date | string | null) => value === null ? null : new Date(value).toISOString();
const latest = (values: Array<Date | string | null>): string | null => {
  const dates = values.flatMap(value => value === null ? [] : [new Date(value)]);
  return dates.length ? new Date(Math.max(...dates.map(value => value.getTime()))).toISOString() : null;
};

/**
 * Report Control's routine progress after Relaycast either proved that the
 * caller owns the outgoing message or the just-completed send supplied its
 * exact recipient. Organization, workspace and recipient agent remain bound
 * into the lookup.
 */
export async function routineWakeStatus(executor: SqlExecutor, input: {
  organizationId: string;
  workspaceId: string;
  messageId: string;
  recipientAgentIds: string[];
}): Promise<RoutineWakeReceipt | null> {
  const recipientIds = [...new Set(input.recipientAgentIds)];
  if (!recipientIds.length) return null;
  const rows = (await executor.query<WakeRow>(`SELECT e.event_id,e.notified_at,e.wake_sent_at,e.wake_attempts,e.answered_at,
        r.failures,r.last_error,r.next_attempt_at
      FROM mcp_oauth_grants g JOIN grok_bot_routines r ON r.grant_id=g.id
      LEFT JOIN grok_bot_events e ON e.grant_id=r.grant_id AND e.message_id=$3
      WHERE g.organization_id=$1 AND g.workspace_id=$2 AND g.agent_remote_id=ANY($4::text[])
        AND g.revoked_at IS NULL AND r.cloud_copy AND r.delivery_mode='webhook'`,
  [input.organizationId, input.workspaceId, input.messageId, recipientIds])).rows;
  if (!rows.length) return null;

  // A from-filtered or otherwise non-waking event is retained for polling but
  // must not look like a wake that is still queued.
  const eligible = rows.filter(row => row.event_id === null || row.notified_at === null
    || row.wake_sent_at !== null || row.answered_at !== null);
  if (!eligible.length) return null;
  const repliedAt = latest(eligible.map(row => row.answered_at));
  const wakeSentAt = latest(eligible.map(row => row.wake_sent_at));
  const retrying = eligible.filter(row => row.event_id !== null && row.notified_at === null && row.last_error !== null);
  const state: RoutineWakeReceipt["state"] = repliedAt ? "replied"
    : wakeSentAt ? "wake_sent"
      : retrying.length ? "backoff"
        : "queued";
  const nextAttemptAt = state === "backoff"
    ? retrying.map(row => iso(row.next_attempt_at)).filter((value): value is string => value !== null).sort()[0] ?? null
    : null;
  return {
    state,
    wake_sent_at: wakeSentAt,
    replied_at: repliedAt,
    next_attempt_at: nextAttemptAt,
    attempts: Math.max(wakeSentAt ? 1 : 0, ...eligible.map(row => Math.max(row.wake_attempts, row.failures))),
    hint: "wake_sent means the routine endpoint accepted the trigger; it does not prove the client woke. Allow time for a reply.",
  };
}

/**
 * A successful reply through this Control instance is the durable dedupe
 * signal returned by get_event. The reply already succeeded upstream, so a
 * bookkeeping outage is deliberately best-effort at the call site.
 */
export async function markRoutineMessageAnswered(executor: SqlExecutor, input: {
  organizationId: string;
  workspaceId: string;
  agentRemoteId: string;
  messageId: string;
  replyMessageId: string;
}): Promise<void> {
  await executor.query(`WITH matching AS (
      SELECT g.id AS grant_id FROM mcp_oauth_grants g JOIN grok_bot_routines r ON r.grant_id=g.id
      WHERE g.organization_id=$1 AND g.workspace_id=$2 AND g.agent_remote_id=$3 AND g.revoked_at IS NULL AND r.cloud_copy
    ), answered AS (
      INSERT INTO grok_bot_answered_messages(grant_id,message_id,reply_message_id)
      SELECT grant_id,$4,$5 FROM matching
      ON CONFLICT (grant_id,message_id) DO UPDATE SET
        answered_at=LEAST(grok_bot_answered_messages.answered_at,EXCLUDED.answered_at),
        reply_message_id=COALESCE(grok_bot_answered_messages.reply_message_id,EXCLUDED.reply_message_id)
      RETURNING grant_id,message_id,answered_at,reply_message_id
    )
    UPDATE grok_bot_events e SET answered_at=a.answered_at,reply_message_id=a.reply_message_id
      FROM answered a WHERE e.grant_id=a.grant_id AND e.message_id=a.message_id`,
  [input.organizationId, input.workspaceId, input.agentRemoteId, input.messageId, input.replyMessageId]);
}
