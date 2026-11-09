import type { IntrospectedToken } from "../store.js";

/** Upper bound on remembered verdicts per process. */
export const INTROSPECTION_HOLD_MAX_ENTRIES = 10_000;

/**
 * Held answers stop this long before the hold or the token would run out:
 * `exp` is whole seconds, so a verifier never reads a held `exp` as passed.
 */
export const HOLD_TAIL_MS = 1_000;

type HeldEntry = { session: IntrospectedToken; checkedAt: number };

export type HeldVerdict = {
  session: IntrospectedToken;
  /** When the database last confirmed the token active (ms since epoch). */
  checkedAt: number;
  /** min(token expiry, checkedAt + holdMs), in ms since epoch. */
  validUntil: number;
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
   * Record one authoritative SQL answer. Active: remember it (as the newest
   * entry). Unknown (null, with the hash), revoked or expired: forget it.
   */
  observe(session: IntrospectedToken | null, hash?: string): void {
    if (!session) {
      if (hash !== undefined) this.forget(hash);
      return;
    }
    const key = session.accessTokenHash;
    if (session.revoked || session.expired) {
      this.forget(key);
      if (hash !== undefined && hash !== key) this.forget(hash);
      return;
    }
    const now = this.#now();
    this.#entries.delete(key);
    if (this.#entries.size >= this.#maxEntries) this.#makeRoom(now);
    this.#entries.set(key, { session, checkedAt: now });
  }

  forget(hash: string): void {
    this.#entries.delete(hash);
  }

  /**
   * The held verdict for this hash, or null. Returned only while at least
   * one second (HOLD_TAIL_MS) remains before the earlier of the token's
   * expiry and checkedAt + holdMs; anything else is deleted. Held answers
   * stop one second before the hold or the token would run out, so a
   * verifier never reads a held `exp` (whole seconds) as already passed.
   */
  lookup(hash: string): HeldVerdict | null {
    const entry = this.#entries.get(hash);
    if (!entry) return null;
    const now = this.#now();
    if (!this.#usable(entry, now)) {
      this.#entries.delete(hash);
      return null;
    }
    this.#entries.delete(hash);
    this.#entries.set(hash, entry);
    return {
      session: entry.session,
      checkedAt: entry.checkedAt,
      validUntil: this.#validUntil(entry),
    };
  }

  /** At least HOLD_TAIL_MS before the earlier of token expiry and the end of the hold. */
  #usable(entry: HeldEntry, now: number): boolean {
    return this.#validUntil(entry) - now >= HOLD_TAIL_MS;
  }

  #validUntil(entry: HeldEntry): number {
    return Math.min(entry.session.expiresAt.getTime(), entry.checkedAt + this.holdMs);
  }

  #makeRoom(now: number): void {
    for (const [key, entry] of this.#entries) {
      if (!this.#usable(entry, now)) this.#entries.delete(key);
    }
    while (this.#entries.size >= this.#maxEntries) {
      const oldest = this.#entries.keys().next();
      if (oldest.done) break;
      this.#entries.delete(oldest.value);
    }
  }
}
