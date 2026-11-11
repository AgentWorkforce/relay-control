import type {
  DeliveryState,
  EventsShimStore,
  NewShimEvent,
  SecretMode,
  ShimEvent,
  ShimRecord,
  VerificationMode,
  WakeTarget,
} from "@agent-relay/events-shim";
import { decryptSecret, encryptSecret, type EncryptionKeyring } from "../crypto.js";
import type { Database, SqlExecutor } from "../database.js";

/** The signed-in person a new inbox is recorded against. */
export type EventsShimCreator = { workspaceId: string; userId: string };

type ShimRow = {
  id: string;
  hook_token_ciphertext: string;
  secrets_ciphertext: string | null;
  wake_url: string | null;
  wake_secret_ciphertext: string | null;
  wake_linked_at: Date | string | null;
  wake_broken_at: Date | string | null;
  wake_broken_reason: string | null;
  created_at: Date | string;
  last_used_at: Date | string;
  agent_seen_at: Date | string | null;
};

type EventRow = {
  id: string;
  shim_id: string;
  seq: number;
  received_at: Date | string;
  mode: string;
  event_type: string | null;
  idempotency_key: string | null;
  content_type: string;
  body: string;
  headers: Record<string, string> | string | null;
  delivery: string;
  delivered_at: Date | string | null;
  wake_error: string | null;
};

const SHIM_COLUMNS = `id, hook_token_ciphertext, secrets_ciphertext, wake_url, wake_secret_ciphertext,
  wake_linked_at, wake_broken_at, wake_broken_reason, created_at, last_used_at, agent_seen_at`;
const EVENT_COLUMNS = `id, shim_id, seq, received_at, mode, event_type, idempotency_key, content_type,
  body, headers, delivery, delivered_at, wake_error`;
const DAY_MS = 24 * 60 * 60 * 1000;

function iso(value: Date | string): string {
  return (value instanceof Date ? value : new Date(value)).toISOString();
}

function isoOrUndefined(value: Date | string | null): string | undefined {
  return value === null ? undefined : iso(value);
}

/**
 * `EventsShimStore` on the control-plane database (migration 0047). Token
 * lookups use sha256 hashes; the hook token, signing secrets and the wake
 * bearer are kept with the encryption keyring. `creator` names the
 * signed-in person a new inbox belongs to (deleted with them).
 */
export class PostgresEventsShimStore implements EventsShimStore {
  constructor(
    private readonly database: Database,
    private readonly keyring: EncryptionKeyring,
    private readonly creator: () => EventsShimCreator | undefined = () => undefined,
  ) {}

  private encrypt(value: string): string {
    return encryptSecret(value, this.keyring.active);
  }

  private decrypt(value: string): string {
    return decryptSecret(value, this.keyring);
  }

  private record(row: ShimRow): ShimRecord {
    const secrets = row.secrets_ciphertext
      ? JSON.parse(this.decrypt(row.secrets_ciphertext)) as Partial<Record<SecretMode, string>>
      : {};
    const shim: ShimRecord = {
      id: row.id,
      createdAt: iso(row.created_at),
      lastUsedAt: iso(row.last_used_at),
      hookToken: this.decrypt(row.hook_token_ciphertext),
      secrets,
    };
    if (row.wake_url && row.wake_secret_ciphertext) {
      const wake: WakeTarget = {
        url: row.wake_url,
        secret: this.decrypt(row.wake_secret_ciphertext),
        linkedAt: iso(row.wake_linked_at ?? row.created_at),
      };
      if (row.wake_broken_at) wake.brokenAt = iso(row.wake_broken_at);
      if (row.wake_broken_reason) wake.brokenReason = row.wake_broken_reason;
      shim.wake = wake;
    }
    if (row.agent_seen_at) shim.agentSeenAt = iso(row.agent_seen_at);
    return shim;
  }

  async createShim(input: {
    id: string;
    mcpTokenHash: string;
    hookToken: string;
    hookTokenHash: string;
    manageTokenHash: string;
    now: string;
  }): Promise<ShimRecord> {
    const creator = this.creator();
    const result = await this.database.query<ShimRow>(
      `INSERT INTO events_shims
         (id, mcp_token_hash, hook_token_hash, manage_token_hash, hook_token_ciphertext,
          created_at, last_used_at, workspace_id, user_id)
       VALUES ($1, $2, $3, $4, $5, $6, $6, $7, $8)
       RETURNING ${SHIM_COLUMNS}`,
      [
        input.id, input.mcpTokenHash, input.hookTokenHash, input.manageTokenHash,
        this.encrypt(input.hookToken), input.now, creator?.workspaceId ?? null, creator?.userId ?? null,
      ],
    );
    return this.record(result.rows[0]!);
  }

  private async findBy(column: "mcp_token_hash" | "hook_token_hash" | "manage_token_hash", hash: string) {
    const result = await this.database.query<ShimRow>(
      `SELECT ${SHIM_COLUMNS} FROM events_shims WHERE ${column} = $1`,
      [hash],
    );
    return result.rows[0] ? this.record(result.rows[0]) : null;
  }

  findByMcpTokenHash(hash: string) {
    return this.findBy("mcp_token_hash", hash);
  }

  findByHookTokenHash(hash: string) {
    return this.findBy("hook_token_hash", hash);
  }

  findByManageTokenHash(hash: string) {
    return this.findBy("manage_token_hash", hash);
  }

  async rotateHookToken(shimId: string, hookToken: string, hookTokenHash: string): Promise<void> {
    await this.database.query(
      "UPDATE events_shims SET hook_token_hash = $2, hook_token_ciphertext = $3 WHERE id = $1",
      [shimId, hookTokenHash, this.encrypt(hookToken)],
    );
  }

  async setSecret(shimId: string, mode: SecretMode, secret: string | null): Promise<void> {
    // Read-modify-write of one encrypted map, serialized on the shim row.
    await this.database.transaction(async (tx) => {
      const current = await tx.query<{ secrets_ciphertext: string | null }>(
        "SELECT secrets_ciphertext FROM events_shims WHERE id = $1 FOR UPDATE",
        [shimId],
      );
      const row = current.rows[0];
      if (!row) return;
      const secrets = row.secrets_ciphertext
        ? JSON.parse(this.decrypt(row.secrets_ciphertext)) as Partial<Record<SecretMode, string>>
        : {};
      if (secret === null) delete secrets[mode];
      else secrets[mode] = secret;
      await tx.query("UPDATE events_shims SET secrets_ciphertext = $2 WHERE id = $1", [
        shimId,
        Object.keys(secrets).length > 0 ? this.encrypt(JSON.stringify(secrets)) : null,
      ]);
    });
  }

  async setWakeTarget(shimId: string, target: WakeTarget | null): Promise<void> {
    await this.database.query(
      `UPDATE events_shims
          SET wake_url = $2, wake_secret_ciphertext = $3, wake_linked_at = $4,
              wake_broken_at = $5, wake_broken_reason = $6
        WHERE id = $1`,
      target
        ? [shimId, target.url, this.encrypt(target.secret), target.linkedAt, target.brokenAt ?? null, target.brokenReason ?? null]
        : [shimId, null, null, null, null, null],
    );
  }

  async touch(shimId: string, now: string, agent: boolean): Promise<void> {
    await this.database.query(
      agent
        ? "UPDATE events_shims SET last_used_at = $2, agent_seen_at = $2 WHERE id = $1"
        : "UPDATE events_shims SET last_used_at = $2 WHERE id = $1",
      [shimId, now],
    );
  }

  async countPostsSince(shimId: string, since: string): Promise<number> {
    const result = await this.database.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM events_shim_posts WHERE shim_id = $1 AND at >= $2",
      [shimId, since],
    );
    return result.rows[0]?.n ?? 0;
  }

  async recordPost(shimId: string, at: string): Promise<void> {
    await this.database.query("INSERT INTO events_shim_posts (shim_id, at) VALUES ($1, $2)", [shimId, at]);
    // Nothing older than a day is ever counted.
    await this.database.query("DELETE FROM events_shim_posts WHERE shim_id = $1 AND at < $2", [
      shimId,
      new Date(Date.parse(at) - DAY_MS).toISOString(),
    ]);
  }

  async appendEvent(
    shimId: string,
    input: NewShimEvent,
    feedSize: number,
  ): Promise<{ event: ShimEvent; duplicate: boolean }> {
    return this.database.transaction(async (tx) => {
      // The row lock serializes appends per shim, so the duplicate check
      // below sees any concurrent post with the same key that committed first.
      const locked = await tx.query("SELECT 1 FROM events_shims WHERE id = $1 FOR UPDATE", [shimId]);
      if (locked.rows.length === 0) throw new Error(`unknown shim ${shimId}`);
      if (input.idempotencyKey) {
        const existing = await this.byKey(tx, shimId, input.idempotencyKey);
        if (existing) return { event: existing, duplicate: true };
      }
      const seq = await tx.query<{ seq: number }>(
        "UPDATE events_shims SET next_seq = next_seq + 1 WHERE id = $1 RETURNING next_seq - 1 AS seq",
        [shimId],
      );
      const inserted = await tx.query<EventRow>(
        `INSERT INTO events_shim_events
           (id, shim_id, seq, received_at, mode, event_type, idempotency_key, content_type, body, headers)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
         ON CONFLICT (shim_id, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
         RETURNING ${EVENT_COLUMNS}`,
        [
          crypto.randomUUID(), shimId, seq.rows[0]!.seq, input.receivedAt, input.mode,
          input.eventType ?? null, input.idempotencyKey ?? null, input.contentType, input.body,
          JSON.stringify(input.headers),
        ],
      );
      if (inserted.rows.length === 0) {
        // Unreachable under the row lock; kept so a conflict can never surface as an error.
        const existing = await this.byKey(tx, shimId, input.idempotencyKey!);
        return { event: existing!, duplicate: true };
      }
      const event = eventFrom(inserted.rows[0]!);
      await tx.query("DELETE FROM events_shim_events WHERE shim_id = $1 AND seq <= $2", [shimId, event.seq - feedSize]);
      return { event, duplicate: false };
    });
  }

  private async byKey(tx: SqlExecutor, shimId: string, key: string): Promise<ShimEvent | null> {
    const result = await tx.query<EventRow>(
      `SELECT ${EVENT_COLUMNS} FROM events_shim_events WHERE shim_id = $1 AND idempotency_key = $2`,
      [shimId, key],
    );
    return result.rows[0] ? eventFrom(result.rows[0]) : null;
  }

  async listRecent(shimId: string, limit: number): Promise<ShimEvent[]> {
    const result = await this.database.query<EventRow>(
      `SELECT ${EVENT_COLUMNS} FROM events_shim_events WHERE shim_id = $1 ORDER BY seq DESC LIMIT $2`,
      [shimId, limit],
    );
    return result.rows.map(eventFrom);
  }

  async listUndelivered(shimId: string, limit: number, includeWoken: boolean): Promise<ShimEvent[]> {
    const result = await this.database.query<EventRow>(
      `SELECT ${EVENT_COLUMNS} FROM events_shim_events
        WHERE shim_id = $1 AND delivery = ANY($2::text[])
        ORDER BY seq ASC LIMIT $3`,
      [shimId, includeWoken ? ["pending", "woken"] : ["pending"], limit],
    );
    return result.rows.map(eventFrom);
  }

  async markDelivery(
    shimId: string,
    eventIds: string[],
    state: DeliveryState,
    at: string,
    wakeError?: string,
  ): Promise<void> {
    if (eventIds.length === 0) return;
    // A post the agent already read stays read when a late wake result lands.
    if (state === "pending") {
      await this.database.query(
        `UPDATE events_shim_events SET delivery = 'pending', wake_error = COALESCE($3, wake_error)
          WHERE shim_id = $1 AND id = ANY($2::uuid[]) AND delivery <> 'read'`,
        [shimId, eventIds, wakeError ?? null],
      );
      return;
    }
    await this.database.query(
      `UPDATE events_shim_events SET delivery = $3, delivered_at = $4, wake_error = NULL
        WHERE shim_id = $1 AND id = ANY($2::uuid[]) AND ($3 = 'read' OR delivery <> 'read')`,
      [shimId, eventIds, state, at],
    );
  }

  async prune(input: { idleBefore: string; feedBefore: string }): Promise<void> {
    await this.database.query("DELETE FROM events_shims WHERE last_used_at < $1", [input.idleBefore]);
    await this.database.query(
      `DELETE FROM events_shim_events e USING events_shims s
        WHERE e.shim_id = s.id AND s.last_used_at < $1`,
      [input.feedBefore],
    );
  }
}

function eventFrom(row: EventRow): ShimEvent {
  const headers = typeof row.headers === "string" ? JSON.parse(row.headers) as Record<string, string> : row.headers ?? {};
  const event: ShimEvent = {
    id: row.id,
    shimId: row.shim_id,
    seq: Number(row.seq),
    receivedAt: iso(row.received_at),
    mode: row.mode as VerificationMode,
    contentType: row.content_type,
    body: row.body,
    headers,
    delivery: row.delivery as DeliveryState,
  };
  if (row.event_type) event.eventType = row.event_type;
  if (row.idempotency_key) event.idempotencyKey = row.idempotency_key;
  const deliveredAt = isoOrUndefined(row.delivered_at);
  if (deliveredAt) event.deliveredAt = deliveredAt;
  if (row.wake_error) event.wakeError = row.wake_error;
  return event;
}
