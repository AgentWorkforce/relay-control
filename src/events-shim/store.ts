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
import type { Database } from "../database.js";
import { AGENT_NAME_PATTERN } from "../mcp/oauth/agent-name.js";

/** The signed-in person a new inbox is recorded against. */
export type EventsShimCreator = { workspaceId: string; userId: string };

type ShimRow = {
  id: string;
  hook_token_ciphertext: string;
  secrets_ciphertext: string | null;
  wake_url: string | null;
  wake_secret_ciphertext: string | null;
  wake_linked_at: Date | string | null;
  wake_agent: string | null;
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
  claim_token: string | null;
  wake_error: string | null;
};

const SHIM_COLUMNS = `id, hook_token_ciphertext, secrets_ciphertext, wake_url, wake_secret_ciphertext,
  wake_linked_at, wake_agent, wake_broken_at, wake_broken_reason, created_at, last_used_at, agent_seen_at`;
const EVENT_COLUMNS = `id, shim_id, seq, received_at, mode, event_type, idempotency_key, content_type,
  body, headers, delivery, delivered_at, claim_token, wake_error`;
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * Posts not yet handed over (`alias.`-qualified): `pending` or `sending` with
 * no claim, or a claim (`delivered_at`) older than `$<staleBefore>`. A newer
 * claim is a lease: a relay wake forward in flight (`sending`) or a
 * `wait_for_webhook` lease (`pending`, `claim_token`). Mirrors the package's
 * `MemoryEventsShimStore`.
 */
function claimable(alias: string, staleBefore: string): string {
  return `(${alias}delivery IN ('pending', 'sending')
    AND (${alias}delivered_at IS NULL OR ${alias}delivered_at < ${staleBefore}::timestamptz))`;
}

/** Event ids are uuids; anything else (client-supplied `ack_ids`) matches no post, as in the memory store. */
const EVENT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** `ids` that can name a post, or none when there is no token to match. */
function leaseIds(ids: string[], claimToken: string): string[] {
  return claimToken ? [...new Set(ids.filter((id) => EVENT_ID.test(id)))] : [];
}

/**
 * The posts in `$2` (uuid[]) of shim `$1` still leased to `$3` by a
 * `wait_for_webhook` claim: `pending` with a claim time, whose stored token
 * matches (or, for a lease stored without one, whose claim time does, as its
 * millisecond ISO string). Unclaimed posts and relay wake forwards
 * (`sending`) never match, so confirmWake/releaseWake still settle theirs.
 */
const LEASED_TO = `shim_id = $1 AND id = ANY($2::uuid[]) AND delivery = 'pending' AND delivered_at IS NOT NULL
  AND coalesce(claim_token, to_char(delivered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')) = $3`;

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
 * signed-in person a new inbox belongs to (deleted with them). It implements
 * the optional `ackPending`/`releasePending`, so `wait_for_webhook` with
 * `auto_ack: false` leases posts (`claim_token`, migration 0078) instead of
 * marking them read.
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
      if (row.wake_agent) wake.agent = row.wake_agent;
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
    // An inbox lives only while its creator is still a member of the
    // organization that owns its workspace: removing the member turns off
    // every URL at once (the rows themselves go when the user or workspace does).
    const result = await this.database.query<ShimRow>(
      `SELECT ${SHIM_COLUMNS} FROM events_shims s
        WHERE s.${column} = $1
          AND (s.user_id IS NULL OR EXISTS (
            SELECT 1 FROM workspaces w
              JOIN organization_memberships m
                ON m.organization_id = w.organization_id AND m.user_id = s.user_id
             WHERE w.id = s.workspace_id))`,
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

  /**
   * The wake agent's name as kept: a valid Agent Relay agent name (a leading @ dropped), else null.
   * watch_webhooks repeats it into other sessions' guidance, so free text is never kept.
   */
  async setWakeTarget(shimId: string, target: WakeTarget | null): Promise<void> {
    await this.database.query(
      `UPDATE events_shims
          SET wake_url = $2, wake_secret_ciphertext = $3, wake_linked_at = $4,
              wake_broken_at = $5, wake_broken_reason = $6, wake_agent = $7
        WHERE id = $1`,
      target
        ? [shimId, target.url, this.encrypt(target.secret), target.linkedAt, target.brokenAt ?? null, target.brokenReason ?? null,
          wakeAgentName(target.agent)]
        : [shimId, null, null, null, null, null, null],
    );
  }

  async markWakeBroken(shimId: string, linkedAt: string, reason: string, at: string): Promise<void> {
    // Only the link that failed: a late result never touches a newer or removed link.
    await this.database.query(
      `UPDATE events_shims SET wake_broken_at = $3, wake_broken_reason = $4
        WHERE id = $1 AND wake_url IS NOT NULL AND wake_linked_at = $2::timestamptz`,
      [shimId, linkedAt, at, reason],
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

  async reservePost(
    shimId: string,
    at: string,
    windows: { since: string; limit: number; name: "hour" | "day" }[],
  ): Promise<{ ok: true } | { ok: false; window: "hour" | "day" }> {
    return this.database.transaction(async (tx) => {
      // The row lock serializes reservations per shim, so concurrent posts
      // cannot all pass the count before any of them inserts.
      const locked = await tx.query("SELECT 1 FROM events_shims WHERE id = $1 FOR UPDATE", [shimId]);
      if (locked.rows.length === 0) throw new Error(`unknown shim ${shimId}`);
      for (const window of windows) {
        const counted = await tx.query<{ n: number }>(
          "SELECT count(*)::int AS n FROM events_shim_posts WHERE shim_id = $1 AND at >= $2",
          [shimId, window.since],
        );
        if ((counted.rows[0]?.n ?? 0) >= window.limit) return { ok: false as const, window: window.name };
      }
      await tx.query("INSERT INTO events_shim_posts (shim_id, at) VALUES ($1, $2)", [shimId, at]);
      // Nothing older than a day is ever counted.
      await tx.query("DELETE FROM events_shim_posts WHERE shim_id = $1 AND at < $2", [
        shimId,
        new Date(Date.parse(at) - DAY_MS).toISOString(),
      ]);
      return { ok: true as const };
    });
  }

  async appendEvent(
    shimId: string,
    input: NewShimEvent,
    options: { feedSize: number; dedupeSince: string },
  ): Promise<{ duplicate: false; event: ShimEvent } | { duplicate: true; eventId: string; seq: number }> {
    return this.database.transaction(async (tx) => {
      // The row lock serializes appends per shim, so the ledger check below
      // sees any concurrent post with the same key that committed first.
      const locked = await tx.query("SELECT 1 FROM events_shims WHERE id = $1 FOR UPDATE", [shimId]);
      if (locked.rows.length === 0) throw new Error(`unknown shim ${shimId}`);
      // Keys older than the dedupe window no longer count.
      await tx.query("DELETE FROM events_shim_idempotency_keys WHERE shim_id = $1 AND created_at < $2", [
        shimId,
        options.dedupeSince,
      ]);
      if (input.idempotencyKey) {
        const seen = await tx.query<{ event_id: string; seq: number }>(
          "SELECT event_id, seq FROM events_shim_idempotency_keys WHERE shim_id = $1 AND key = $2",
          [shimId, input.idempotencyKey],
        );
        if (seen.rows[0]) return { duplicate: true as const, eventId: seen.rows[0].event_id, seq: Number(seen.rows[0].seq) };
      }
      const seq = await tx.query<{ seq: number }>(
        "UPDATE events_shims SET next_seq = next_seq + 1 WHERE id = $1 RETURNING next_seq - 1 AS seq",
        [shimId],
      );
      const inserted = await tx.query<EventRow>(
        `INSERT INTO events_shim_events
           (id, shim_id, seq, received_at, mode, event_type, idempotency_key, content_type, body, headers)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb)
         RETURNING ${EVENT_COLUMNS}`,
        [
          crypto.randomUUID(), shimId, seq.rows[0]!.seq, input.receivedAt, input.mode,
          input.eventType ?? null, input.idempotencyKey ?? null, input.contentType, input.body,
          JSON.stringify(input.headers),
        ],
      );
      const event = eventFrom(inserted.rows[0]!);
      if (input.idempotencyKey) {
        await tx.query(
          `INSERT INTO events_shim_idempotency_keys (shim_id, key, event_id, seq, created_at)
           VALUES ($1, $2, $3, $4, $5)`,
          [shimId, input.idempotencyKey, event.id, event.seq, input.receivedAt],
        );
      }
      await tx.query("DELETE FROM events_shim_events WHERE shim_id = $1 AND seq <= $2", [
        shimId,
        event.seq - options.feedSize,
      ]);
      return { duplicate: false as const, event };
    });
  }

  async listRecent(shimId: string, limit: number): Promise<ShimEvent[]> {
    const result = await this.database.query<EventRow>(
      `SELECT ${EVENT_COLUMNS} FROM events_shim_events WHERE shim_id = $1 ORDER BY seq DESC LIMIT $2`,
      [shimId, limit],
    );
    return result.rows.map(eventFrom);
  }

  async listStalledWakes(input: {
    staleBefore: string;
    receivedBefore: string;
    activeSince: string;
    limit: number;
  }): Promise<ShimRecord[]> {
    if (input.limit <= 0) return [];
    // Live inboxes with a working wake link and a claimable post old enough
    // that its own delivery pass is over, whose creator (like every lookup)
    // is still in the workspace's organization. Random order, so inboxes whose
    // relay keeps failing cannot hold every slot run after run.
    const result = await this.database.query<ShimRow>(
      `SELECT ${SHIM_COLUMNS} FROM events_shims s
        WHERE s.wake_url IS NOT NULL AND s.wake_broken_at IS NULL
          AND s.last_used_at >= $3
          AND EXISTS (
            SELECT 1 FROM events_shim_events e
             WHERE e.shim_id = s.id
               AND ${claimable("e.", "$1")}
               AND e.received_at < $2)
          AND (s.user_id IS NULL OR EXISTS (
            SELECT 1 FROM workspaces w
              JOIN organization_memberships m
                ON m.organization_id = w.organization_id AND m.user_id = s.user_id
             WHERE w.id = s.workspace_id))
        ORDER BY random()
        LIMIT $4`,
      [input.staleBefore, input.receivedBefore, input.activeSince, input.limit],
    );
    return result.rows.map((row) => this.record(row));
  }

  async countPending(shimId: string, staleBefore: string): Promise<number> {
    const result = await this.database.query<{ n: number }>(
      `SELECT count(*)::int AS n FROM events_shim_events
        WHERE shim_id = $1
          AND ${claimable("", "$2")}`,
      [shimId, staleBefore],
    );
    return result.rows[0]?.n ?? 0;
  }

  async claimPending(
    shimId: string,
    options: { limit: number; ids?: string[]; staleBefore: string; linkedAt?: string },
    state: "sending" | "read" | "pending",
    at: string,
    claimToken?: string,
  ): Promise<ShimEvent[]> {
    // One statement, the pick materialized once: rows another caller holds are
    // skipped and rows it already moved no longer match, so two callers never
    // get the same event. Claimable: pending or sending with no claim or an
    // expired one. A 'pending' claim (wait_for_webhook, auto_ack: false) is a
    // lease held by claimToken; any other claim clears the token.
    // With linkedAt (a wake send), nothing is claimed unless that link is still
    // current and unbroken and the creator is still in the workspace's
    // organization, checked in the same statement: a member removed after a
    // pass or sweep picked the inbox gets nothing more forwarded.
    const result = await this.database.query<EventRow>(
      `WITH picked AS MATERIALIZED (
         SELECT id FROM events_shim_events
          WHERE shim_id = $1
            AND ${claimable("", "$6")}
            AND ($5::uuid[] IS NULL OR id = ANY($5::uuid[]))
            AND ($7::timestamptz IS NULL OR EXISTS (
              SELECT 1 FROM events_shims s
               WHERE s.id = $1 AND s.wake_url IS NOT NULL
                 AND s.wake_linked_at = $7::timestamptz AND s.wake_broken_at IS NULL
                 AND (s.user_id IS NULL OR EXISTS (
                   SELECT 1 FROM workspaces w
                     JOIN organization_memberships m
                       ON m.organization_id = w.organization_id AND m.user_id = s.user_id
                    WHERE w.id = s.workspace_id))))
          ORDER BY seq ASC
          LIMIT $4::int
          FOR UPDATE SKIP LOCKED)
       UPDATE events_shim_events e SET delivery = $2, delivered_at = $3, claim_token = $8, wake_error = NULL
         FROM picked
        WHERE e.id = picked.id
          AND ${claimable("e.", "$6")}
        RETURNING ${EVENT_COLUMNS.split(",").map((column) => `e.${column.trim()}`).join(", ")}`,
      [
        shimId, state, at, options.limit, options.ids ?? null, options.staleBefore, options.linkedAt ?? null,
        claimToken || null,
      ],
    );
    return result.rows.map(eventFrom).sort((a, b) => a.seq - b.seq);
  }

  // Optional EventsShimStore methods: with both, wait_for_webhook (auto_ack:
  // false) leases posts instead of marking them read. Each is one statement, so
  // a concurrent re-claim of an expired lease either commits first (new token,
  // no match) or waits for the row lock and skips the row.
  async ackPending(shimId: string, ids: string[], at: string, claimToken: string): Promise<string[]> {
    const named = leaseIds(ids, claimToken);
    if (named.length === 0) return [];
    const result = await this.database.query<{ id: string; seq: number }>(
      `UPDATE events_shim_events SET delivery = 'read', delivered_at = $4, claim_token = NULL
        WHERE ${LEASED_TO}
        RETURNING id, seq`,
      [shimId, named, claimToken, at],
    );
    return result.rows.sort((a, b) => Number(a.seq) - Number(b.seq)).map((row) => row.id);
  }

  async releasePending(shimId: string, ids: string[], claimToken: string): Promise<string[]> {
    const named = leaseIds(ids, claimToken);
    if (named.length === 0) return [];
    const result = await this.database.query<{ id: string; seq: number }>(
      `UPDATE events_shim_events SET delivered_at = NULL, claim_token = NULL
        WHERE ${LEASED_TO}
        RETURNING id, seq`,
      [shimId, named, claimToken],
    );
    return result.rows.sort((a, b) => Number(a.seq) - Number(b.seq)).map((row) => row.id);
  }

  // Both apply only to this sender's own claim: once its lease expires and
  // another caller re-claims the post, delivered_at no longer matches.
  // claimedAt is the deliveredAt claimPending returned (ISO, millisecond
  // precision, written from the same JS string), so the comparison is exact.
  async confirmWake(shimId: string, eventId: string, claimedAt: string, at: string): Promise<void> {
    await this.database.query(
      `UPDATE events_shim_events SET delivery = 'woken', delivered_at = $4
        WHERE shim_id = $1 AND id = $2 AND delivery = 'sending' AND delivered_at = $3::timestamptz`,
      [shimId, eventId, claimedAt, at],
    );
  }

  async releaseWake(shimId: string, eventId: string, claimedAt: string, wakeError: string): Promise<void> {
    await this.database.query(
      `UPDATE events_shim_events SET delivery = 'pending', delivered_at = NULL, wake_error = $4
        WHERE shim_id = $1 AND id = $2 AND delivery = 'sending' AND delivered_at = $3::timestamptz`,
      [shimId, eventId, claimedAt, wakeError],
    );
  }

  async prune(input: { idleBefore: string; feedBefore: string }): Promise<void> {
    await this.database.query("DELETE FROM events_shims WHERE last_used_at < $1", [input.idleBefore]);
    await this.database.query(
      `DELETE FROM events_shim_events e USING events_shims s
        WHERE e.shim_id = s.id AND s.last_used_at < $1`,
      [input.feedBefore],
    );
    await this.database.query("DELETE FROM events_shim_idempotency_keys WHERE created_at < $1", [input.feedBefore]);
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
  if (row.claim_token) event.claimToken = row.claim_token;
  if (row.wake_error) event.wakeError = row.wake_error;
  return event;
}

/** `link_relay_wake`'s `agent`, kept only when it is a valid agent name; anything else is stored as null. */
export function wakeAgentName(agent: string | undefined): string | null {
  const name = agent?.trim().replace(/^@/u, "") ?? "";
  return AGENT_NAME_PATTERN.test(name) ? name : null;
}
