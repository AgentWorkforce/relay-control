import { decryptSecret, encryptSecret, hashSecret, type EncryptionKeyring } from "../crypto.js";
import type { SqlExecutor } from "../database.js";
import type { HostedDelivery } from "../messaging/relaycast.js";
import { isChannelDelivery } from "./relay-participants.js";
import {
  RELAY_CHANNEL_MESSAGE_EVENT, RELAY_MESSAGE_EVENT, UNTRUSTED, eventSteps, grantEventsSettings, replyCall,
  type ReplyMode, type SenderTrust,
} from "./grok-events-policy.js";
import { GrokRoutineError, perBotConnectionRequired } from "./grok-routine.js";

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
  payload_ciphertext: string };
const COLUMNS = "event_id,grant_seq,name,sender,occurred_at,payload_ciphertext";

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

export function eventFromDelivery(input: { grantId: string; agent: string; message: HostedDelivery; channel: string | null;
  senderKind: "agent" | "person"; now: Date }) {
  const { message, agent } = input;
  const channelPost = isChannelDelivery(message);
  const occurredAt = message.created_at && !Number.isNaN(new Date(message.created_at).getTime()) ? new Date(message.created_at) : input.now;
  const payload: Payload = channelPost
    ? {
      data: { messageId: message.message_id, channel: input.channel, channelId: message.channel_id, threadId: message.thread_id,
        replyThreadId: message.thread_id ?? message.message_id, from: message.sender, senderKind: input.senderKind,
        // Cloud's shape ("mention" | "bot-thread" | "post"). Relaycast gives thread-reply to every member for every
        // thread, so only a mention counts as addressed here; the bot-thread rule needs channel-event tracking.
        addressed: message.reason === "mention" ? "mention" : "post", agent, summary: summarize(message.text) },
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
 * Stores one event if it is new. Its sequence comes from the routine row's counter (locked FOR UPDATE by the scan),
 * so a value is never reused, even after retention deletes older rows. `wake` false stores it as already notified:
 * readable through get_recent_events but never a webhook wake.
 */
export async function insertEvent(tx: SqlExecutor, keyring: EncryptionKeyring, grantId: string,
  event: ReturnType<typeof eventFromDelivery>, wake: boolean, now: Date): Promise<void> {
  if ((await tx.query("SELECT 1 FROM grok_bot_events WHERE grant_id=$1 AND event_id=$2", [grantId, event.eventId])).rows.length) return;
  const seq = (await tx.query<{ event_seq: string | number }>(
    "UPDATE grok_bot_routines SET event_seq=event_seq+1 WHERE grant_id=$1 RETURNING event_seq", [grantId])).rows[0];
  if (!seq) throw new Error("routine_unavailable");
  // created_at uses the same clock as the retention sweep and the read filter.
  await tx.query(`INSERT INTO grok_bot_events(grant_id,event_id,grant_seq,name,sender,occurred_at,payload_ciphertext,notified_at,created_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
  [grantId, event.eventId, seq.event_seq, event.name, typeof event.payload.data.from === "string" ? event.payload.data.from : null,
    event.occurredAt, encryptSecret(JSON.stringify(event.payload), keyring.active), wake ? null : now, now]);
}

/** Until a channel-wake policy exists here, a routine wakes for direct messages and channel mentions only. */
export function wakesRoutine(event: ReturnType<typeof eventFromDelivery>): boolean {
  return event.name === RELAY_MESSAGE_EVENT || event.payload.data.addressed === "mention";
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
  replyMode: ReplyMode, eventId: string, retainedSince: Date,
  owner: { userId: string; workspaceId: string; relaycastWorkspaceId: string }) {
  const row = (await tx.query<EventRow>(`SELECT ${COLUMNS} FROM grok_bot_events WHERE grant_id=$1 AND event_id=$2 AND created_at>=$3`,
    [grant.id, eventId, retainedSince])).rows[0];
  const event = row ? view(row, keyring, grant.agent_name) : null;
  if (!row || !event) return null;
  const settings = grantEventsSettings(replyMode);
  // Trust is decided now, from current rows: a retired binding or a removed participant is no longer "your agent".
  const senderAgentId = typeof event.detail.senderAgentId === "string" ? event.detail.senderAgentId : null;
  const trust: SenderTrust = senderAgentId && (await ownedSenders(tx, owner, [senderAgentId])).owned.has(senderAgentId)
    ? { trusted: true, reason: "your agent" } : UNTRUSTED;
  // Earlier messages of the same DM conversation (Cloud keeps five, 500 characters each).
  const conversationId = typeof event.data.conversationId === "string" ? event.data.conversationId : null;
  const earlier = conversationId ? (await tx.query<EventRow>(`SELECT ${COLUMNS} FROM grok_bot_events
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
  let rows: EventRow[];
  if (input.since !== undefined) {
    const numeric = /^\d{1,15}$/.test(input.since);
    const at = numeric ? null : new Date(input.since);
    if (at && Number.isNaN(at.getTime())) throw new GrokRoutineError("since must be a cursor or an ISO timestamp.");
    rows = (await tx.query<EventRow>(`SELECT ${COLUMNS} FROM grok_bot_events WHERE grant_id=$1 AND created_at>=$5
      AND ${numeric ? "grant_seq>$2::bigint" : "occurred_at>$2::timestamptz"} AND ($4::text IS NULL OR sender=$4) ORDER BY grant_seq LIMIT $3`,
    [grant.id, numeric ? input.since : at, input.limit, from, retainedSince])).rows;
  } else {
    rows = (await tx.query<EventRow>(`SELECT ${COLUMNS} FROM grok_bot_events WHERE grant_id=$1 AND created_at>=$4
      AND ($3::text IS NULL OR sender=$3) ORDER BY grant_seq DESC LIMIT $2`, [grant.id, input.limit, from, retainedSince])).rows.reverse();
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
