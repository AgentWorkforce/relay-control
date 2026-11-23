import { decryptSecret, encryptSecret, hashSecret, type EncryptionKeyring } from "../crypto.js";
import type { SqlExecutor } from "../database.js";
import type { HostedDelivery } from "../messaging/relaycast.js";
import { isChannelDelivery } from "./relay-participants.js";
import {
  RELAY_CHANNEL_MESSAGE_EVENT, RELAY_MESSAGE_EVENT, UNTRUSTED, eventSteps, grantEventsSettings, replyCall,
  type ReplyMode, type SenderTrust,
} from "./grok-events-policy.js";
import { GrokRoutineError, perBotConnectionRequired } from "./grok-routine.js";
import { CHANNEL_WAKE_WINDOW_MS, type ChannelAddress, type ChannelSenderKind } from "./channel-wake.js";

/**
 * Cloud's durable event log, reduced to one Grok grant
 * (docs/specs/grok-bot-dynamic-prompt.md, Phase 1). The copied routine prompt
 * reads events with get_event / get_recent_events and never acknowledges
 * Relaycast deliveries itself, so the worker ingests each delivery here and
 * acknowledges it only after this table has committed it.
 */

export const GROK_EVENT_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
/** Wakes per routine per scan; the rest follow on the next scan. */
export const GROK_WAKES_PER_SCAN = 10;
const SUMMARY_CHARS = 200;

/** Copied from Cloud service.ts `summarize`. */
export function summarize(text: string): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length <= SUMMARY_CHARS ? flat : `${flat.slice(0, SUMMARY_CHARS - 1)}…`;
}

/** One stable id per (grant, delivery), in Cloud's `evt_<32 hex>` shape, so a retried wake keeps it. */
export function grokEventId(grantId: string, deliveryId: string): string {
  return `evt_${hashSecret(JSON.stringify(["grok-event:v1", grantId, deliveryId])).slice(0, 32)}`;
}

type Payload = { data: Record<string, unknown>; detail: Record<string, unknown> };
type EventRow = { event_id: string; grant_seq: string | number; name: string; sender: string | null; occurred_at: Date | string;
  trusted_reason: string | null; payload_ciphertext: string };
const COLUMNS = "event_id,grant_seq,name,sender,occurred_at,trusted_reason,payload_ciphertext";

const iso = (value: Date | string) => new Date(value).toISOString();

/**
 * Which senders are the grant owner's own, judged only from rows this service writes: the person's hosted
 * participants, Desktop identities and bound Amp and Capy bindings in this workspace's Relaycast workspace. Agent
 * metadata is never consulted: an agent holding its own token can merge metadata into its own card. `people`
 * holds senders that are a workspace person's own person identity (their sender kind, not trust).
 */
export async function ownedSenders(tx: SqlExecutor, owner: { userId: string; workspaceId: string; relaycastWorkspaceId: string },
  agentIds: string[]): Promise<{ owned: Set<string>; people: Set<string> }> {
  const ids = [...new Set(agentIds)];
  if (!ids.length) return { owned: new Set(), people: new Set() };
  const owned = (await tx.query<{ agent_remote_id: string }>(`SELECT agent_remote_id FROM (
      SELECT agent_remote_id FROM hosted_relay_participants WHERE workspace_id=$1 AND user_id=$2 AND relaycast_workspace_id=$3
      UNION SELECT agent_remote_id FROM desktop_relay_identities WHERE workspace_id=$1 AND user_id=$2 AND relaycast_workspace_id=$3
      UNION SELECT agent_remote_id FROM amp_bindings WHERE workspace_id=$1 AND user_id=$2 AND relaycast_workspace_id=$3 AND state='bound'
      UNION SELECT agent_remote_id FROM capy_bindings WHERE workspace_id=$1 AND user_id=$2 AND relaycast_workspace_id=$3 AND state='bound'
    ) mine WHERE agent_remote_id=ANY($4::text[])`, [owner.workspaceId, owner.userId, owner.relaycastWorkspaceId, ids])).rows;
  const people = (await tx.query<{ agent_remote_id: string }>(
    "SELECT agent_remote_id FROM person_identities WHERE workspace_id=$1 AND agent_remote_id=ANY($2::text[])",
    [owner.workspaceId, ids])).rows;
  return { owned: new Set(owned.map(row => row.agent_remote_id)), people: new Set(people.map(row => row.agent_remote_id)) };
}

/**
 * Cloud's channel sender kinds, from rows this service owns: `human` for a workspace person's own person identity,
 * `agent` for any agent this service recorded in this Relaycast workspace (a hosted participant, Desktop identity or
 * bound Amp or Capy binding, whoever owns it), absent (unknown) otherwise. An unknown kind counts as an agent.
 */
export async function senderKinds(tx: SqlExecutor, owner: { workspaceId: string; relaycastWorkspaceId: string },
  agentIds: string[]): Promise<Map<string, "human" | "agent">> {
  const ids = [...new Set(agentIds)];
  const kinds = new Map<string, "human" | "agent">();
  if (!ids.length) return kinds;
  const agents = (await tx.query<{ agent_remote_id: string }>(`SELECT agent_remote_id FROM hosted_relay_participants
      WHERE workspace_id=$1 AND relaycast_workspace_id=$2 AND agent_remote_id=ANY($3::text[])
    UNION SELECT agent_remote_id FROM desktop_relay_identities WHERE workspace_id=$1 AND relaycast_workspace_id=$2 AND agent_remote_id=ANY($3::text[])
    UNION SELECT agent_remote_id FROM amp_bindings WHERE workspace_id=$1 AND relaycast_workspace_id=$2 AND state='bound' AND agent_remote_id=ANY($3::text[])
    UNION SELECT agent_remote_id FROM capy_bindings WHERE workspace_id=$1 AND relaycast_workspace_id=$2 AND state='bound' AND agent_remote_id=ANY($3::text[])`,
  [owner.workspaceId, owner.relaycastWorkspaceId, ids])).rows;
  for (const row of agents) kinds.set(row.agent_remote_id, "agent");
  const people = (await tx.query<{ agent_remote_id: string }>(
    "SELECT agent_remote_id FROM person_identities WHERE workspace_id=$1 AND relaycast_workspace_id=$2 AND agent_remote_id=ANY($3::text[])",
    [owner.workspaceId, owner.relaycastWorkspaceId, ids])).rows;
  for (const row of people) kinds.set(row.agent_remote_id, "human");
  return kinds;
}

/**
 * `addressed` and a Cloud sender kind are passed for channel posts (Cloud's relay.channel_message data); without
 * them a channel post keeps the earlier boolean.
 */
export function eventFromDelivery(input: { grantId: string; agent: string; message: HostedDelivery; channel: string | null;
  senderKind: "agent" | "person" | ChannelSenderKind; now: Date; addressed?: ChannelAddress }) {
  const { message, agent } = input;
  const channelPost = isChannelDelivery(message);
  const occurredAt = message.created_at && !Number.isNaN(new Date(message.created_at).getTime()) ? new Date(message.created_at) : input.now;
  const payload: Payload = channelPost
    ? {
      data: { messageId: message.message_id, channel: input.channel, channelId: message.channel_id, threadId: message.thread_id,
        replyThreadId: message.thread_id ?? message.message_id, from: message.sender, senderKind: input.senderKind,
        addressed: input.addressed ?? (message.reason === "mention" || message.reason === "thread-reply"), agent, summary: summarize(message.text) },
      detail: { text: message.text, sender: message.sender, senderAgentId: message.sender_id ?? null, senderKind: input.senderKind,
        channel: input.channel, channelId: message.channel_id, threadId: message.thread_id, reason: message.reason ?? null,
        createdAt: message.created_at, deliveryId: message.delivery_id },
    }
    : {
      data: { messageId: message.message_id, from: message.sender, conversationId: message.conversation_id,
        threadId: message.thread_id, agent, summary: summarize(message.text) },
      detail: { text: message.text, sender: message.sender, senderAgentId: message.sender_id ?? null, threadId: message.thread_id,
        conversationId: message.conversation_id, createdAt: message.created_at, deliveryId: message.delivery_id },
    };
  return { eventId: grokEventId(input.grantId, message.delivery_id), name: channelPost ? RELAY_CHANNEL_MESSAGE_EVENT : RELAY_MESSAGE_EVENT,
    occurredAt, payload };
}

/**
 * `channel` holds a channel post's clear columns (the wake guards count them); `notifiedAt` set means the event
 * wakes nobody (no webhook routine, or a channel post that reserved no wake-up).
 */
export async function insertEvent(tx: SqlExecutor, keyring: EncryptionKeyring, grantId: string,
  event: ReturnType<typeof eventFromDelivery>, trust: SenderTrust, options: { notifiedAt?: Date | null;
    channel?: { channelId: string | null; replyThreadId: string; senderKind: ChannelSenderKind; addressed: ChannelAddress;
      wakeReservedAt: Date | null } } = {}): Promise<void> {
  // grant_seq is this grant's own cursor (the grant row is locked FOR UPDATE by every writer, so it cannot race).
  const channel = options.channel;
  await tx.query(`INSERT INTO grok_bot_events(grant_id,event_id,grant_seq,name,sender,occurred_at,trusted_reason,payload_ciphertext,
      notified_at,channel_id,reply_thread_id,sender_kind,addressed,wake_reserved_at)
    SELECT $1,$2,COALESCE((SELECT MAX(grant_seq) FROM grok_bot_events WHERE grant_id=$1),0)+1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13
    ON CONFLICT (grant_id,event_id) DO NOTHING`,
  [grantId, event.eventId, event.name, typeof event.payload.data.from === "string" ? event.payload.data.from : null,
    event.occurredAt, trust.trusted ? trust.reason : null, encryptSecret(JSON.stringify(event.payload), keyring.active),
    options.notifiedAt ?? null, channel?.channelId ?? null, channel?.replyThreadId ?? null, channel?.senderKind ?? null,
    channel?.addressed ?? null, channel?.wakeReservedAt ?? null]);
}

/** Whether an event for this delivery is already stored for the grant (a re-read page after a failed acknowledgement). */
export async function eventStored(tx: SqlExecutor, grantId: string, eventId: string): Promise<boolean> {
  return (await tx.query("SELECT 1 FROM grok_bot_events WHERE grant_id=$1 AND event_id=$2", [grantId, eventId])).rows.length > 0;
}

/**
 * Bot-thread rule (1): an addressed relay.channel_message for this Relaycast agent is already stored with this
 * replyThreadId, under any of its connections in this workspace. Only retained events count (seven days); past
 * that, only the thread root's sender decides.
 */
export async function addressedInThread(tx: SqlExecutor, agent: { workspaceId: string; agentRemoteId: string },
  replyThreadId: string, retainedSince: Date): Promise<boolean> {
  return (await tx.query(`SELECT 1 FROM grok_bot_events e JOIN mcp_oauth_grants g ON g.id=e.grant_id
    WHERE g.workspace_id=$1 AND g.agent_remote_id=$2 AND e.name=$3 AND e.reply_thread_id=$4
      AND e.addressed IN ('mention','bot-thread') AND e.created_at>=$5 LIMIT 1`,
  [agent.workspaceId, agent.agentRemoteId, RELAY_CHANNEL_MESSAGE_EVENT, replyThreadId, retainedSince])).rows.length > 0;
}

/**
 * This window's reserved wake-ups for one Relaycast agent in one channel, across its connections in this
 * workspace (Cloud counts per inbox). The caller holds lockChannelWakes, so concurrent scans cannot both pass a cap.
 */
export async function channelWakeCounts(tx: SqlExecutor, agent: { workspaceId: string; agentRemoteId: string },
  channelId: string, replyThreadId: string, now: Date) {
  const row = (await tx.query<{ channel: number; thread: number; agent_thread: number }>(`SELECT count(*)::int AS channel,
      count(*) FILTER (WHERE e.reply_thread_id=$4)::int AS thread,
      count(*) FILTER (WHERE e.reply_thread_id=$4 AND e.sender_kind IS DISTINCT FROM 'human')::int AS agent_thread
    FROM grok_bot_events e JOIN mcp_oauth_grants g ON g.id=e.grant_id
    WHERE g.workspace_id=$1 AND g.agent_remote_id=$2 AND e.name=$5 AND e.channel_id=$3 AND e.wake_reserved_at>$6`,
  [agent.workspaceId, agent.agentRemoteId, channelId, replyThreadId, RELAY_CHANNEL_MESSAGE_EVENT,
    new Date(now.getTime() - CHANNEL_WAKE_WINDOW_MS)])).rows[0];
  return { channel: row?.channel ?? 0, thread: row?.thread ?? 0, agentThread: row?.agent_thread ?? 0 };
}

/** Serializes channel wake reservations for one Relaycast agent, whichever connection's scan reserves them. */
export async function lockChannelWakes(tx: SqlExecutor, agentRemoteId: string): Promise<void> {
  await tx.query("SELECT pg_advisory_xact_lock(hashtext('grok-channel-wake:' || $1::text))", [agentRemoteId]);
}

/** Null when the payload cannot be decrypted (a retired key): such an event is skipped, never fatal. */
function view(row: EventRow, keyring: EncryptionKeyring, agent: string) {
  let payload: Payload;
  try { payload = JSON.parse(decryptSecret(row.payload_ciphertext, keyring)) as Payload; } catch { return null; }
  // Like Cloud's routedEventData: instructions name the inbox that owns the event now, including after a rename.
  const data = typeof payload.data.agent === "string" ? { ...payload.data, agent } : payload.data;
  return { eventId: row.event_id, name: row.name, timestamp: iso(row.occurred_at), cursor: String(row.grant_seq), data, detail: payload.detail };
}

/** The thin body a webhook wake carries (Cloud's eventView, without detail). */
export function wakeBody(row: EventRow, keyring: EncryptionKeyring, agent: string) {
  const event = view(row, keyring, agent);
  if (!event) return null;
  const { detail: _detail, ...body } = event;
  return body;
}

export async function pendingWakes(tx: SqlExecutor, grantId: string, limit = GROK_WAKES_PER_SCAN): Promise<EventRow[]> {
  return (await tx.query<EventRow>(`SELECT ${COLUMNS} FROM grok_bot_events
    WHERE grant_id=$1 AND notified_at IS NULL ORDER BY grant_seq LIMIT $2`, [grantId, limit])).rows;
}

export function assertOwnIdentity(approved: string, declared: string | undefined): void {
  if (declared !== undefined && declared !== approved) throw new GrokRoutineError(perBotConnectionRequired(declared, approved));
}

/** Cloud's getEvent for a relay.message / relay.channel_message, from this grant's retained log. */
export async function getEvent(tx: SqlExecutor, keyring: EncryptionKeyring, grant: { id: string; agent_name: string },
  replyMode: ReplyMode, eventId: string, retainedSince: Date) {
  const row = (await tx.query<EventRow>(`SELECT ${COLUMNS} FROM grok_bot_events WHERE grant_id=$1 AND event_id=$2 AND created_at>=$3`,
    [grant.id, eventId, retainedSince])).rows[0];
  const event = row ? view(row, keyring, grant.agent_name) : null;
  if (!row || !event) return null;
  const settings = grantEventsSettings(replyMode);
  const trust: SenderTrust = row.trusted_reason === "your agent" ? { trusted: true, reason: "your agent" } : UNTRUSTED;
  // Earlier messages of the same DM conversation, or earlier posts of the same channel thread that reached this
  // connection (Cloud keeps five, 500 characters each).
  const conversationId = typeof event.data.conversationId === "string" ? event.data.conversationId : null;
  const replyThreadId = event.name === RELAY_CHANNEL_MESSAGE_EVENT && typeof event.data.replyThreadId === "string" ? event.data.replyThreadId : null;
  const earlier = replyThreadId ? (await tx.query<EventRow>(`SELECT ${COLUMNS} FROM grok_bot_events
    WHERE grant_id=$1 AND name=$2 AND reply_thread_id=$3 AND grant_seq<$4 AND created_at>=$5 ORDER BY grant_seq DESC LIMIT 5`,
  [grant.id, RELAY_CHANNEL_MESSAGE_EVENT, replyThreadId, row.grant_seq, retainedSince])).rows.flatMap(item => {
    const earlierEvent = view(item, keyring, grant.agent_name);
    return earlierEvent ? [earlierEvent] : [];
  }).reverse().map(item => ({ from: String(item.data.from ?? ""), at: item.timestamp, text: String(item.detail.text ?? item.data.summary ?? "").slice(0, 500) }))
    : conversationId ? (await tx.query<EventRow>(`SELECT ${COLUMNS} FROM grok_bot_events
    WHERE grant_id=$1 AND name=$2 AND grant_seq<$3 AND created_at>=$4 ORDER BY grant_seq DESC LIMIT 20`,
  [grant.id, RELAY_MESSAGE_EVENT, row.grant_seq, retainedSince])).rows.flatMap(item => {
    const earlierEvent = view(item, keyring, grant.agent_name);
    return earlierEvent ? [earlierEvent] : [];
  }).filter(item => item.data.conversationId === conversationId).slice(0, 5).reverse()
    .map(item => ({ from: String(item.data.from ?? ""), at: item.timestamp, text: String(item.detail.text ?? item.data.summary ?? "").slice(0, 500) })) : [];
  return { ...event, earlierMessages: earlier, noteToUser: settings.noteEveryMessage, replyMode: settings.replyMode,
    trustedSender: trust.trusted, trustedSenderReason: trust.reason,
    nextSteps: eventSteps(settings, { fetched: true, trust, channel: event.name === RELAY_CHANNEL_MESSAGE_EVENT }),
    ...replyCall(event, settings, trust) };
}

/** Cloud's getRecentEvents contract: since is this grant's cursor or an ISO timestamp; oldest first; retained events only. */
export async function recentEvents(tx: SqlExecutor, keyring: EncryptionKeyring, grant: { id: string; agent_name: string },
  routine: { delivery_mode: string; from_filter: string | null } | null,
  input: { since?: string; limit: number; scheduled?: boolean }, retainedSince: Date) {
  if (input.scheduled === true && routine?.delivery_mode !== "polling") {
    // A schedule that was replaced (by a webhook, or disconnected) stops.
    return { events: [], cursor: input.since ?? null, polling_active: false, delivery_paused: false };
  }
  const from = input.scheduled === true ? routine?.from_filter ?? null : null;
  // A schedule picks up only the channel posts that reserved its wake-up (Cloud's pollingWake): a post over a wake
  // cap, or from before the schedule, stays readable by hand.
  const pickup = input.scheduled === true ? `AND (name<>'${RELAY_CHANNEL_MESSAGE_EVENT}' OR wake_reserved_at IS NOT NULL)` : "";
  let rows: EventRow[];
  if (input.since !== undefined) {
    const numeric = /^\d{1,15}$/.test(input.since);
    const at = numeric ? null : new Date(input.since);
    if (at && Number.isNaN(at.getTime())) throw new GrokRoutineError("since must be a cursor or an ISO timestamp.");
    rows = (await tx.query<EventRow>(`SELECT ${COLUMNS} FROM grok_bot_events WHERE grant_id=$1 AND created_at>=$5
      AND ${numeric ? "grant_seq>$2::bigint" : "occurred_at>$2::timestamptz"} AND ($4::text IS NULL OR sender=$4) ${pickup} ORDER BY grant_seq LIMIT $3`,
    [grant.id, numeric ? input.since : at, input.limit, from, retainedSince])).rows;
  } else {
    rows = (await tx.query<EventRow>(`SELECT ${COLUMNS} FROM grok_bot_events WHERE grant_id=$1 AND created_at>=$4
      AND ($3::text IS NULL OR sender=$3) ${pickup} ORDER BY grant_seq DESC LIMIT $2`, [grant.id, input.limit, from, retainedSince])).rows.reverse();
  }
  // An unreadable event still advances the cursor past it.
  const events = rows.flatMap(row => {
    const event = view(row, keyring, grant.agent_name);
    if (!event) return [];
    const { detail, ...rest } = event;
    return [{ ...rest, text: typeof detail.text === "string" ? detail.text : null }];
  });
  const last = rows.at(-1);
  return { events, cursor: last ? String(last.grant_seq) : input.since ?? null, polling_active: true, delivery_paused: false };
}
