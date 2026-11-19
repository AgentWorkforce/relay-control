import { decryptSecret, encryptSecret, hashSecret, type EncryptionKeyring } from "../crypto.js";
import type { SqlExecutor } from "../database.js";
import type { HostedDelivery, RelaycastClient, RosterAgent } from "../messaging/relaycast.js";
import { isChannelDelivery, ownerHash } from "./relay-participants.js";
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
type EventRow = { event_id: string; seq: string | number; name: string; sender: string | null; occurred_at: Date | string;
  trusted_reason: string | null; payload_ciphertext: string };

const iso = (value: Date | string) => new Date(value).toISOString();

/**
 * Sender trust, judged for the grant's owner: Cloud's "your agent" check (the
 * sender's immutable agent id is a roster agent this person owns). Workspace
 * members and trusted groups are not trusted in this copy (Cloud's
 * trustWorkspaceMembers=false, no trustedAgents).
 */
export function senderTrust(sender: { name: string | null; agentId: string | null }, roster: RosterAgent[], userId: string): SenderTrust {
  if (!sender.name || !sender.agentId) return UNTRUSTED;
  const agent = roster.find(row => row.name === sender.name && row.id === sender.agentId);
  if (!agent || agent.status === "released" || agent.metadata.owner_hash !== ownerHash(userId)) return UNTRUSTED;
  return { trusted: true, reason: "your agent" };
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
        addressed: message.reason === "mention" || message.reason === "thread-reply", agent, summary: summarize(message.text) },
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

export async function insertEvent(tx: SqlExecutor, keyring: EncryptionKeyring, grantId: string,
  event: ReturnType<typeof eventFromDelivery>, trust: SenderTrust): Promise<void> {
  await tx.query(`INSERT INTO grok_bot_events(grant_id,event_id,name,sender,occurred_at,trusted_reason,payload_ciphertext)
    VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (grant_id,event_id) DO NOTHING`,
  [grantId, event.eventId, event.name, typeof event.payload.data.from === "string" ? event.payload.data.from : null,
    event.occurredAt, trust.trusted ? trust.reason : null, encryptSecret(JSON.stringify(event.payload), keyring.active)]);
}

function view(row: EventRow, keyring: EncryptionKeyring, agent: string) {
  const payload = JSON.parse(decryptSecret(row.payload_ciphertext, keyring)) as Payload;
  // Like Cloud's routedEventData: instructions name the inbox that owns the event now, including after a rename.
  const data = typeof payload.data.agent === "string" ? { ...payload.data, agent } : payload.data;
  return { eventId: row.event_id, name: row.name, timestamp: iso(row.occurred_at), cursor: String(row.seq), data, detail: payload.detail };
}

/** The thin body a webhook wake carries (Cloud's eventView, without detail). */
export function wakeBody(row: EventRow, keyring: EncryptionKeyring, agent: string) {
  const { detail: _detail, ...body } = view(row, keyring, agent);
  return body;
}

export async function pendingWakes(tx: SqlExecutor, grantId: string, limit = GROK_WAKES_PER_SCAN): Promise<EventRow[]> {
  return (await tx.query<EventRow>(`SELECT event_id,seq,name,sender,occurred_at,trusted_reason,payload_ciphertext FROM grok_bot_events
    WHERE grant_id=$1 AND notified_at IS NULL ORDER BY seq LIMIT $2`, [grantId, limit])).rows;
}

export function assertOwnIdentity(approved: string, declared: string | undefined): void {
  if (declared !== undefined && declared !== approved) throw new GrokRoutineError(perBotConnectionRequired(declared, approved));
}

/** Cloud's getEvent for a relay.message / relay.channel_message, from this grant's log. */
export async function getEvent(tx: SqlExecutor, keyring: EncryptionKeyring, grant: { id: string; agent_name: string },
  replyMode: ReplyMode, eventId: string) {
  const row = (await tx.query<EventRow>(`SELECT event_id,seq,name,sender,occurred_at,trusted_reason,payload_ciphertext
    FROM grok_bot_events WHERE grant_id=$1 AND event_id=$2`, [grant.id, eventId])).rows[0];
  if (!row) return null;
  const event = view(row, keyring, grant.agent_name);
  const settings = grantEventsSettings(replyMode);
  const trust: SenderTrust = row.trusted_reason === "your agent" ? { trusted: true, reason: "your agent" } : UNTRUSTED;
  // Earlier messages of the same DM conversation (Cloud keeps five, 500 characters each).
  const conversationId = typeof event.data.conversationId === "string" ? event.data.conversationId : null;
  const earlier = conversationId ? (await tx.query<EventRow>(`SELECT event_id,seq,name,sender,occurred_at,trusted_reason,payload_ciphertext
    FROM grok_bot_events WHERE grant_id=$1 AND name=$2 AND seq<$3 ORDER BY seq DESC LIMIT 20`,
  [grant.id, RELAY_MESSAGE_EVENT, row.seq])).rows.map(item => view(item, keyring, grant.agent_name))
    .filter(item => item.data.conversationId === conversationId).slice(0, 5).reverse()
    .map(item => ({ from: String(item.data.from ?? ""), at: item.timestamp, text: String(item.detail.text ?? item.data.summary ?? "").slice(0, 500) })) : [];
  return { ...event, earlierMessages: earlier, noteToUser: settings.noteEveryMessage, replyMode: settings.replyMode,
    trustedSender: trust.trusted, trustedSenderReason: trust.reason,
    nextSteps: eventSteps(settings, { fetched: true, trust, channel: event.name === RELAY_CHANNEL_MESSAGE_EVENT }),
    ...replyCall(event, settings, trust) };
}

/** Cloud's getRecentEvents contract: since is a cursor (seq) or an ISO timestamp; oldest first. */
export async function recentEvents(tx: SqlExecutor, keyring: EncryptionKeyring, grant: { id: string; agent_name: string },
  routine: { delivery_mode: string; from_filter: string | null } | null,
  input: { since?: string; limit: number; scheduled?: boolean }) {
  if (input.scheduled === true && routine?.delivery_mode !== "polling") {
    // A schedule that was replaced (by a webhook, or disconnected) stops.
    return { events: [], cursor: input.since ?? null, polling_active: false, delivery_paused: false };
  }
  const from = input.scheduled === true ? routine?.from_filter ?? null : null;
  let rows: EventRow[];
  const columns = "event_id,seq,name,sender,occurred_at,trusted_reason,payload_ciphertext";
  if (input.since !== undefined) {
    const numeric = /^\d{1,15}$/.test(input.since);
    const at = numeric ? null : new Date(input.since);
    if (at && Number.isNaN(at.getTime())) throw new GrokRoutineError("since must be a cursor or an ISO timestamp.");
    rows = (await tx.query<EventRow>(`SELECT ${columns} FROM grok_bot_events WHERE grant_id=$1
      AND ${numeric ? "seq>$2::bigint" : "occurred_at>$2::timestamptz"} AND ($4::text IS NULL OR sender=$4) ORDER BY seq LIMIT $3`,
    [grant.id, numeric ? input.since : at, input.limit, from])).rows;
  } else {
    rows = (await tx.query<EventRow>(`SELECT ${columns} FROM grok_bot_events WHERE grant_id=$1 AND ($3::text IS NULL OR sender=$3)
      ORDER BY seq DESC LIMIT $2`, [grant.id, input.limit, from])).rows.reverse();
  }
  const events = rows.map(row => {
    const { detail, ...event } = view(row, keyring, grant.agent_name);
    return { ...event, text: typeof detail.text === "string" ? detail.text : null };
  });
  return { events, cursor: events.at(-1)?.cursor ?? input.since ?? null, polling_active: true, delivery_paused: false };
}
