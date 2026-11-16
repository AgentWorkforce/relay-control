import type { IntrospectedToken } from "../store.js";

/** Upper bound on remembered verdicts per process. */
export const INTROSPECTION_HOLD_MAX_ENTRIES = 10_000;

/**
 * Held answers stop this long before the hold or the token would run out:
 * `exp` is whole seconds, so a verifier never reads a held `exp` as passed.
 */
export const HOLD_TAIL_MS = 1_000;

type HeldAudience = { checkedAt: number };
type HeldEntry = {
  session: IntrospectedToken;
  audiences: Map<string, HeldAudience>;
};

export type HeldAudienceVerdict = {
  /** When the database last confirmed this token and audience (ms since epoch). */
  checkedAt: number;
  /** min(token expiry, checkedAt + holdMs), in ms since epoch. */
  validUntil: number;
};

export type HeldVerdict = {
  session: IntrospectedToken;
  /** Every still-current authoritative audience confirmation for this token. */
  audiences: ReadonlyMap<string, HeldAudienceVerdict>;
};

/**
 * The last authoritative ACTIVE verdict for each `sh_at_` access token, kept
 * only so introspection can keep answering through a database outage
 * (docs/identity.md, "Database outage hold"). It is never consulted while the
 * database answers: every introspection still runs the SQL and then records
 * the result here.
 *
 * Keyed by the access token hash (never the raw token). Inactive verdicts
 * remove the entry. Bounded LRU: touching an entry moves it to the newest
 * position, and inserting at capacity first prunes stale or expired entries
 * and then evicts the oldest.
 */
export class IntrospectionHold {
  readonly holdMs: number;
  readonly #maxEntries: number;
  readonly #now: () => number;
  readonly #entries = new Map<string, HeldEntry>();

  constructor(holdMs: number, options: { maxEntries?: number; now?: () => number } = {}) {
    if (!Number.isSafeInteger(holdMs) || holdMs <= 0) {
      throw new Error("IntrospectionHold requires a positive integer holdMs");
    }
    const maxEntries = options.maxEntries ?? INTROSPECTION_HOLD_MAX_ENTRIES;
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
      throw new Error("IntrospectionHold requires a positive integer maxEntries");
    }
    this.holdMs = holdMs;
    this.#maxEntries = maxEntries;
    this.#now = options.now ?? Date.now;
  }

  get size(): number {
    return this.#entries.size;
  }

  /**
   * Record one authoritative answer. Active: add or refresh its audience and
   * make the token the newest entry. Unknown (null, with the hash), revoked or
   * expired: forget the token and all of its audiences.
   */
  observe(
    session: IntrospectedToken | null,
    options: { hash?: string; audience?: string } = {},
  ): void {
    if (!session) {
      if (options.hash !== undefined) this.forget(options.hash);
      return;
    }
    const key = session.accessTokenHash;
    if (session.revoked || session.expired) {
      this.forget(key);
      if (options.hash !== undefined && options.hash !== key) this.forget(options.hash);
      return;
    }
    if (!options.audience) throw new Error("IntrospectionHold requires an audience for an active verdict");
    const now = this.#now();
    const existing = this.#entries.get(key);
    const audiences = existing?.audiences ?? new Map<string, HeldAudience>();
    if (existing) this.#pruneAudiences(existing, now);
    audiences.set(options.audience, { checkedAt: now });
    this.#entries.delete(key);
    if (!existing && this.#entries.size >= this.#maxEntries) this.#makeRoom(now);
    this.#entries.set(key, { session, audiences });
  }

  forget(hash: string): void {
    this.#entries.delete(hash);
  }

  /**
   * The held verdict for this hash, or null. Returned only while at least
   * one audience has at least one second (HOLD_TAIL_MS) left before the
   * earlier of token expiry and its own checkedAt + holdMs. Stale audience
   * confirmations are pruned independently; an entry with none is deleted.
   */
  lookup(hash: string): HeldVerdict | null {
    const entry = this.#entries.get(hash);
    if (!entry) return null;
    const now = this.#now();
    if (!this.#pruneAudiences(entry, now)) {
      this.#entries.delete(hash);
      return null;
    }
    this.#entries.delete(hash);
    this.#entries.set(hash, entry);
    const audiences = new Map<string, HeldAudienceVerdict>();
    for (const [audience, confirmation] of entry.audiences) {
      audiences.set(audience, {
        checkedAt: confirmation.checkedAt,
        validUntil: this.#validUntil(entry.session, confirmation.checkedAt),
      });
    }
    return { session: entry.session, audiences };
  }

  /** Drop stale audience confirmations; true while the token retains one. */
  #pruneAudiences(entry: HeldEntry, now: number): boolean {
    for (const [audience, confirmation] of entry.audiences) {
      if (this.#validUntil(entry.session, confirmation.checkedAt) - now < HOLD_TAIL_MS) {
        entry.audiences.delete(audience);
      }
    }
    return entry.audiences.size > 0;
  }

  #validUntil(session: IntrospectedToken, checkedAt: number): number {
    return Math.min(session.expiresAt.getTime(), checkedAt + this.holdMs);
  }

  #makeRoom(now: number): void {
    for (const [key, entry] of this.#entries) {
      if (!this.#pruneAudiences(entry, now)) this.#entries.delete(key);
    }
    while (this.#entries.size >= this.#maxEntries) {
      const oldest = this.#entries.keys().next();
      if (oldest.done) break;
      this.#entries.delete(oldest.value);
    }
  }
}
