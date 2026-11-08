// analytics lane: retry timing shared by the queue and both sinks. Contract:
// infra docs/analytics-collector-interface.md, infra #84 @62599fb as amended by
// infra #85 @ca91118 (merged 91c9b79).

/** Longest honoured Retry-After and longest local backoff step. */
export const RETRY_AFTER_CAP_MS = 30_000;

/**
 * Retry-After as unsigned decimal delta-seconds only, capped at 30 s.
 * HTTP-date, signed, fractional and otherwise malformed values return
 * undefined so the caller uses its bounded local backoff. Zero is a valid
 * delay; it still consumes an attempt in the queue.
 */
export function parseRetryAfter(value: string | null | undefined): number | undefined {
  const raw = value?.trim();
  if (!raw || !/^\d+$/.test(raw)) return undefined;
  return Math.min(Number(raw) * 1000, RETRY_AFTER_CAP_MS);
}

/**
 * Bound a retry wait: at most RETRY_AFTER_CAP_MS, the remaining total delivery
 * deadline of the batch, and the remaining flush deadline when one applies.
 * Never negative.
 */
export function boundRetryDelay(requestedMs: number, remainingDeliveryMs: number, remainingFlushMs?: number): number {
  const bound = Math.min(requestedMs, RETRY_AFTER_CAP_MS, remainingDeliveryMs, remainingFlushMs ?? Number.POSITIVE_INFINITY);
  return Math.max(0, bound);
}
