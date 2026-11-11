import { createHmac, randomBytes } from "node:crypto";
import type { Database } from "../database.js";

/**
 * Usage page counters (docs/usage.md): daily aggregates per organization,
 * written only while SELFHOST_FEATURES includes `usage`.
 *
 * Active users are stored as HMAC-SHA256(user id) under a per-install secret
 * kept in `usage_state`. The secret and the hashes never leave this module:
 * reads return counts only.
 */
export type UsageCounterMetric = "searches";

export type UsageDay = { date: string; activeUsers: number; searches: number };

const DEDUPE_LIMIT = 10_000;

function day(at: Date): string {
  return at.toISOString().slice(0, 10);
}

export class UsageStore {
  #salt: Promise<string> | null = null;
  /** `${org}|${day}|${hash}` already written by this process; saves a write per request. */
  readonly #seen = new Set<string>();

  constructor(
    private readonly database: Database,
    private readonly now: () => Date = () => new Date(),
  ) {}

  private salt(): Promise<string> {
    this.#salt ??= (async () => {
      await this.database.query(
        "INSERT INTO usage_state (id, salt) VALUES (1, $1) ON CONFLICT (id) DO NOTHING",
        [randomBytes(32).toString("base64url")],
      );
      const result = await this.database.query<{ salt: string }>("SELECT salt FROM usage_state WHERE id = 1");
      return result.rows[0]!.salt;
    })().catch((error: unknown) => {
      this.#salt = null;
      throw error;
    });
    return this.#salt;
  }

  async recordActiveUser(organizationId: string, userId: string): Promise<void> {
    const today = day(this.now());
    const hash = createHmac("sha256", await this.salt()).update(userId).digest("base64url");
    const key = `${organizationId}|${today}|${hash}`;
    if (this.#seen.has(key)) return;
    await this.database.query(
      `INSERT INTO usage_daily_users (organization_id, day, user_hash) VALUES ($1, $2, $3)
       ON CONFLICT DO NOTHING`,
      [organizationId, today, hash],
    );
    if (this.#seen.size >= DEDUPE_LIMIT) this.#seen.clear();
    this.#seen.add(key);
  }

  async increment(organizationId: string, metric: UsageCounterMetric, amount = 1): Promise<void> {
    await this.database.query(
      `INSERT INTO usage_daily_counters (organization_id, day, metric, value) VALUES ($1, $2, $3, $4)
       ON CONFLICT (organization_id, day, metric)
       DO UPDATE SET value = usage_daily_counters.value + EXCLUDED.value`,
      [organizationId, day(this.now()), metric, amount],
    );
  }

  /** Per-day counts for the inclusive UTC days `dates` (oldest first), plus distinct active users over them. */
  async read(organizationId: string, dates: readonly string[]): Promise<{ days: UsageDay[]; activeUsers: number }> {
    const first = dates[0]!;
    const last = dates[dates.length - 1]!;
    const [users, counters, distinct] = await Promise.all([
      this.database.query<{ day: string; n: number }>(
        `SELECT to_char(day, 'YYYY-MM-DD') AS day, count(*)::int AS n FROM usage_daily_users
          WHERE organization_id = $1 AND day BETWEEN $2 AND $3 GROUP BY day`,
        [organizationId, first, last],
      ),
      this.database.query<{ day: string; metric: string; n: string | number }>(
        `SELECT to_char(day, 'YYYY-MM-DD') AS day, metric, value AS n FROM usage_daily_counters
          WHERE organization_id = $1 AND day BETWEEN $2 AND $3`,
        [organizationId, first, last],
      ),
      this.database.query<{ n: number }>(
        `SELECT count(DISTINCT user_hash)::int AS n FROM usage_daily_users
          WHERE organization_id = $1 AND day BETWEEN $2 AND $3`,
        [organizationId, first, last],
      ),
    ]);
    const byDay = new Map<string, UsageDay>(dates.map((date) => [date, { date, activeUsers: 0, searches: 0 }]));
    for (const row of users.rows) {
      const entry = byDay.get(row.day);
      if (entry) entry.activeUsers = Number(row.n);
    }
    for (const row of counters.rows) {
      const entry = byDay.get(row.day);
      if (entry && row.metric === "searches") entry.searches = Number(row.n);
    }
    return { days: [...byDay.values()], activeUsers: Number(distinct.rows[0]?.n ?? 0) };
  }
}
