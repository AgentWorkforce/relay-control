// telemetry lane: Postgres persistence (counters, errors, salt, outbox).
import { randomBytes, randomUUID } from "node:crypto";
import type { Database, SqlExecutor } from "../database.js";

export type CounterDelta = { area: string; metric: string; value: number };
export type ErrorDelta = {
  fingerprint: string;
  component: string;
  route: string;
  status: number;
  errorClass: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
};
export type ErrorAggregate = ErrorDelta & { firstSeenEver: string };
export type OutboxKind = "digest" | "error_burst" | "issue_report";
export type OutboxStatus = "pending" | "sent" | "exported" | "dead";
export type OutboxRow = {
  id: string;
  kind: OutboxKind;
  body: string;
  status: OutboxStatus;
  attempts: number;
  nextAttemptAt: string;
  lastError: string | null;
  createdAt: string;
  sentAt: string | null;
};

const MAX_PENDING = 500;

function iso(value: unknown): string {
  return value instanceof Date ? value.toISOString() : new Date(String(value)).toISOString();
}

function outboxRow(row: Record<string, unknown>): OutboxRow {
  return {
    id: String(row.id),
    kind: row.kind as OutboxKind,
    body: String(row.body),
    status: row.status as OutboxStatus,
    attempts: Number(row.attempts),
    nextAttemptAt: iso(row.next_attempt_at),
    lastError: (row.last_error as string | null) ?? null,
    createdAt: iso(row.created_at),
    sentAt: row.sent_at ? iso(row.sent_at) : null,
  };
}

export class TelemetryStore {
  #salt: string | null = null;

  constructor(readonly database: Database) {}

  async state(): Promise<{ salt: string; windowStartedAt: string; lastDigestAt: string | null }> {
    await this.database.query(
      `INSERT INTO telemetry_state (id, salt) VALUES (1, $1)
       ON CONFLICT (id) DO NOTHING`,
      [randomBytes(32).toString("base64url")],
    );
    const result = await this.database.query<{
      salt: string;
      window_started_at: Date | string;
      last_digest_at: Date | string | null;
    }>("SELECT salt, window_started_at, last_digest_at FROM telemetry_state WHERE id = 1");
    const row = result.rows[0]!;
    this.#salt = row.salt;
    return {
      salt: row.salt,
      windowStartedAt: iso(row.window_started_at),
      lastDigestAt: row.last_digest_at ? iso(row.last_digest_at) : null,
    };
  }

  async salt(): Promise<string> {
    return this.#salt ?? (await this.state()).salt;
  }

  async flush(counters: CounterDelta[], errors: ErrorDelta[]): Promise<void> {
    if (!counters.length && !errors.length) return;
    await this.database.transaction(async (tx) => {
      for (const counter of counters) {
        await tx.query(
          `INSERT INTO telemetry_counters (area, metric, value) VALUES ($1, $2, $3)
           ON CONFLICT (area, metric)
           DO UPDATE SET value = telemetry_counters.value + EXCLUDED.value`,
          [counter.area, counter.metric, counter.value],
        );
      }
      for (const error of errors) {
        await tx.query(
          `INSERT INTO telemetry_errors
             (fingerprint, component, route, status, error_class, count, first_seen, last_seen)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           ON CONFLICT (fingerprint, component, route, status, error_class)
           DO UPDATE SET count = telemetry_errors.count + EXCLUDED.count,
                         first_seen = LEAST(telemetry_errors.first_seen, EXCLUDED.first_seen),
                         last_seen = GREATEST(telemetry_errors.last_seen, EXCLUDED.last_seen)`,
          [
            error.fingerprint, error.component, error.route, error.status,
            error.errorClass, error.count, error.firstSeen, error.lastSeen,
          ],
        );
        await tx.query(
          `INSERT INTO telemetry_error_index (fingerprint, component, first_seen, last_seen)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (fingerprint, component)
           DO UPDATE SET last_seen = GREATEST(telemetry_error_index.last_seen, EXCLUDED.last_seen)`,
          [error.fingerprint, error.component, error.firstSeen, error.lastSeen],
        );
      }
    });
  }

  /** Current window without consuming it (preview). */
  async peekWindow(executor: SqlExecutor = this.database): Promise<{
    counters: CounterDelta[];
    errors: ErrorAggregate[];
  }> {
    const counters = await executor.query<{ area: string; metric: string; value: string | number }>(
      "SELECT area, metric, value FROM telemetry_counters ORDER BY area, metric",
    );
    const errors = await executor.query<Record<string, unknown>>(
      `SELECT e.fingerprint, e.component, e.route, e.status, e.error_class, e.count,
              e.first_seen, e.last_seen, COALESCE(i.first_seen, e.first_seen) AS first_seen_ever
         FROM telemetry_errors e
         LEFT JOIN telemetry_error_index i
           ON i.fingerprint = e.fingerprint AND i.component = e.component
        ORDER BY e.count DESC, e.last_seen DESC
        LIMIT 200`,
    );
    return {
      counters: counters.rows.map((row) => ({
        area: row.area,
        metric: row.metric,
        value: Number(row.value),
      })),
      errors: errors.rows.map((row) => ({
        fingerprint: String(row.fingerprint),
        component: String(row.component),
        route: String(row.route),
        status: Number(row.status),
        errorClass: String(row.error_class),
        count: Number(row.count),
        firstSeen: iso(row.first_seen),
        lastSeen: iso(row.last_seen),
        firstSeenEver: iso(row.first_seen_ever),
      })),
    };
  }

  /**
   * Take the current window (short transaction), build the payload outside
   * any transaction (it makes HTTP probes and gauge queries), then enqueue it.
   * If building fails, the taken window is added back so nothing is lost.
   */
  async closeWindow(
    build: (window: { counters: CounterDelta[]; errors: ErrorAggregate[]; windowStartedAt: string }) =>
      Promise<{ id: string; body: string } | null>,
  ): Promise<string | null> {
    const taken = await this.database.transaction(async (tx) => {
      const state = await tx.query<{ window_started_at: Date | string }>(
        "SELECT window_started_at FROM telemetry_state WHERE id = 1 FOR UPDATE",
      );
      const windowStartedAt = state.rows[0] ? iso(state.rows[0].window_started_at) : new Date().toISOString();
      const window = await this.peekWindow(tx);
      await tx.query("DELETE FROM telemetry_counters");
      await tx.query("DELETE FROM telemetry_errors");
      await tx.query(
        "UPDATE telemetry_state SET window_started_at = now(), last_digest_at = now() WHERE id = 1",
      );
      return { ...window, windowStartedAt };
    });
    let built: { id: string; body: string } | null;
    try {
      built = await build(taken);
      if (built) await this.enqueue(this.database, "digest", built.id, built.body);
    } catch (error) {
      await this.flush(taken.counters, taken.errors);
      throw error;
    }
    return built?.id ?? null;
  }

  async enqueue(
    executor: SqlExecutor,
    kind: OutboxKind,
    id: string,
    body: string,
    organizationId: string | null = null,
  ): Promise<void> {
    await executor.query(
      "INSERT INTO telemetry_outbox (id, kind, body, organization_id) VALUES ($1, $2, $3, $4)",
      [id, kind, body, organizationId],
    );
  }

  /** organizationId: the organisation an issue report was filed in (null: installation-wide). */
  async enqueueStandalone(
    kind: OutboxKind,
    body: string,
    id: string = randomUUID(),
    organizationId: string | null = null,
  ): Promise<string> {
    await this.enqueue(this.database, kind, id, body, organizationId);
    return id;
  }

  /** True when this fingerprint has not had a burst report in `quietSeconds`. */
  async claimBurst(fingerprint: string, component: string, quietSeconds: number): Promise<boolean> {
    const result = await this.database.query<{ fingerprint: string }>(
      `INSERT INTO telemetry_error_index (fingerprint, component, last_burst_reported_at)
       VALUES ($1, $2, now())
       ON CONFLICT (fingerprint, component) DO UPDATE
         SET last_burst_reported_at = now()
       WHERE telemetry_error_index.last_burst_reported_at IS NULL
          OR telemetry_error_index.last_burst_reported_at
             < now() - make_interval(secs => $3)
       RETURNING fingerprint`,
      [fingerprint, component, quietSeconds],
    );
    return result.rows.length === 1;
  }

  async due(limit = 10): Promise<OutboxRow[]> {
    const result = await this.database.query<Record<string, unknown>>(
      `SELECT * FROM telemetry_outbox
        WHERE status = 'pending' AND next_attempt_at <= now()
        ORDER BY created_at
        LIMIT $1`,
      [limit],
    );
    return result.rows.map(outboxRow);
  }

  async list(statuses: OutboxStatus[] = ["pending"], limit = 50): Promise<OutboxRow[]> {
    const result = await this.database.query<Record<string, unknown>>(
      `SELECT * FROM telemetry_outbox
        WHERE status = ANY($1::text[])
        ORDER BY created_at DESC
        LIMIT $2`,
      [statuses, Math.max(1, Math.min(500, limit))],
    );
    return result.rows.map(outboxRow);
  }

  /** Multi mode, an organisation admin: only the reports filed in that organisation. */
  async listForOrganization(organizationId: string, statuses: OutboxStatus[] = ["pending"], limit = 50): Promise<OutboxRow[]> {
    const result = await this.database.query<Record<string, unknown>>(
      `SELECT * FROM telemetry_outbox
        WHERE organization_id = $1 AND status = ANY($2::text[])
        ORDER BY created_at DESC
        LIMIT $3`,
      [organizationId, statuses, Math.max(1, Math.min(500, limit))],
    );
    return result.rows.map(outboxRow);
  }

  async statsForOrganization(organizationId: string): Promise<Record<string, number>> {
    const counts = await this.database.query<{ status: string; count: string }>(
      `SELECT status, count(*)::text AS count FROM telemetry_outbox
        WHERE organization_id = $1 GROUP BY status`,
      [organizationId],
    );
    return Object.fromEntries(counts.rows.map((row) => [row.status, Number(row.count)]));
  }

  async markSent(id: string): Promise<void> {
    await this.database.query(
      `UPDATE telemetry_outbox
          SET status = 'sent', sent_at = now(), attempts = attempts + 1, last_error = NULL
        WHERE id = $1`,
      [id],
    );
  }

  async markExported(ids: string[]): Promise<void> {
    if (!ids.length) return;
    await this.database.query(
      `UPDATE telemetry_outbox SET status = 'exported', sent_at = now()
        WHERE id = ANY($1::uuid[]) AND status = 'pending'`,
      [ids],
    );
  }

  async markRetry(id: string, delaySeconds: number, error: string, dead: boolean): Promise<void> {
    await this.database.query(
      `UPDATE telemetry_outbox
          SET attempts = attempts + 1,
              last_error = $2,
              next_attempt_at = now() + make_interval(secs => $3),
              status = CASE WHEN $4::boolean THEN 'dead' ELSE status END
        WHERE id = $1`,
      [id, error.slice(0, 200), delaySeconds, dead],
    );
  }

  async stats(): Promise<Record<string, unknown>> {
    const counts = await this.database.query<{ status: string; count: string }>(
      "SELECT status, count(*)::text AS count FROM telemetry_outbox GROUP BY status",
    );
    const last = await this.database.query<{ sent_at: Date | string | null; last_error: string | null }>(
      `SELECT max(sent_at) FILTER (WHERE status = 'sent') AS sent_at,
              (SELECT last_error FROM telemetry_outbox
                WHERE last_error IS NOT NULL AND status = 'pending'
                ORDER BY next_attempt_at DESC LIMIT 1) AS last_error
         FROM telemetry_outbox`,
    );
    const state = await this.state();
    return {
      outbox: Object.fromEntries(counts.rows.map((row) => [row.status, Number(row.count)])),
      lastSentAt: last.rows[0]?.sent_at ? iso(last.rows[0].sent_at) : null,
      lastError: last.rows[0]?.last_error ?? null,
      windowStartedAt: state.windowStartedAt,
      lastDigestAt: state.lastDigestAt,
    };
  }

  /** Retention: drop delivered rows after 14 days and cap the pending backlog. */
  async prune(): Promise<void> {
    await this.database.query(
      `DELETE FROM telemetry_outbox
        WHERE status IN ('sent', 'exported', 'dead') AND created_at < now() - interval '14 days'`,
    );
    await this.database.query(
      `UPDATE telemetry_outbox SET status = 'dead', last_error = 'backlog_cap'
        WHERE id IN (
          SELECT id FROM telemetry_outbox
           WHERE status = 'pending' AND kind = 'digest'
           ORDER BY created_at DESC OFFSET $1
        )`,
      [MAX_PENDING],
    );
  }

  /** Opportunistic gauges: tables owned by other lanes are read only if present. */
  async tableExists(name: string): Promise<boolean> {
    const result = await this.database.query<{ present: boolean }>(
      "SELECT to_regclass($1) IS NOT NULL AS present",
      [`public.${name}`],
    );
    return result.rows[0]?.present === true;
  }
}
