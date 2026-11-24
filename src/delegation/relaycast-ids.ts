/**
 * Relaycast message ids are snowflakes (relaycast
 * `packages/engine/src/engine/snowflake.ts`): a decimal 64-bit integer whose
 * top 42 bits are milliseconds since 2025-01-01T00:00:00Z, followed by a
 * 10-bit worker id and a 12-bit sequence. Relaycast mints a message's id when
 * it stores the message, so the id carries its send time. As Cloud's
 * lib/delegation/relaycast-ids.ts.
 */
const RELAYCAST_EPOCH_MS = Date.UTC(2025, 0, 1);
const TIMESTAMP_SHIFT = 22n;
/** Clock skew tolerated between Relaycast and Control when judging an id from the future. */
const FUTURE_SKEW_MS = 5 * 60 * 1000;

/** The send time a Relaycast message id encodes, or null when it is not a plausible snowflake. */
export function relaycastMessageTime(messageId: string, now: Date): Date | null {
  if (!/^[1-9][0-9]{0,19}$/u.test(messageId)) return null;
  const value = BigInt(messageId);
  if (value >= 1n << 63n) return null;
  const at = Number(value >> TIMESTAMP_SHIFT) + RELAYCAST_EPOCH_MS;
  if (at <= RELAYCAST_EPOCH_MS || at > now.getTime() + FUTURE_SKEW_MS) return null;
  return new Date(at);
}

/**
 * When a delivered message was sent: Relaycast's `created_at` when it reports
 * one, else the time encoded in its snowflake id. Null when neither is known.
 */
export function messageSentAt(messageId: string, createdAt: string | null | undefined, now: Date): Date | null {
  if (createdAt && !Number.isNaN(Date.parse(createdAt))) return new Date(createdAt);
  return relaycastMessageTime(messageId, now);
}
