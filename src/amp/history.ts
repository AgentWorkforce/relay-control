import { createHash, randomUUID } from "node:crypto";
import type { SqlExecutor } from "../database.js";
import { ampExport, type AmpEvidence } from "./provider.js";
import { decrypt, encrypt, withAmpLock, type AmpDeps } from "./service.js";

/**
 * Amp thread history sync, ported from the hosted control plane's history sync
 * and history schedule up to the RelayHistory push-session boundary.
 *
 * Everything before the upload runs here: Amp export through deps.run, the
 * RelayHistory-owned parser (provider.ts ampExport), per-version diffing,
 * an encrypted pending page, the receipt check and the watermark. The one
 * thing relaycontrol cannot do is obtain the session the upload is sent with.
 *
 * Why the push session is injected and null in production (module.ts):
 * Cloud mints it per job with createRelayhistorySandboxPushSession, a RelayAuth
 * `/v1/tokens/relayhistory-assertion` call with scopes ["rth:sync"] and purpose
 * "amp-session-sync", exchanged at RelayHistory `POST /v1/cli/login`. This
 * control plane has no equivalent:
 * - src/relayhistory.ts issueRelayhistorySession only exchanges the caller's own
 *   sh_at_ person token (callerAccessToken). A background job has no caller.
 * - RelayHistory verifies that exchange through relaycontrol
 *   `POST /internal/v1/auth/introspect` (src/auth/introspect.ts), which answers
 *   only sh_at_ person access tokens and returns wrong-kind for every other
 *   token, so there is no control-issued, workspace-scoped push credential.
 * - The optional relayauthAssertion path requests read+sync scopes with fixed
 *   "relayhistory-login" metadata for a person; it is not a push-only,
 *   binding-scoped job grant and is deliberately not wired here.
 * No mint, trust or fallback path is invented. History stays inactive until a
 * workspace-scoped, push-only (rth:sync) session can be issued without a
 * caller token and supplied as AmpDeps.pushSession.
 */

/** Hosted history schedule: a bound thread is polled at most this often. */
export const AMP_HISTORY_INTERVAL_MS = 5 * 60_000;
/** Cloud's queue lease. Here it is both the run lease and the retry delay after a failure. */
export const AMP_HISTORY_QUEUE_LEASE_MS = 15 * 60_000;
/** Runs per worker pass; each run can export a whole thread. */
export const AMP_HISTORY_PER_TICK = 2;
const PAGE_RECORDS = 100;
const UPLOAD_TIMEOUT_MS = 30_000;
export const HISTORY_PUSH_UNAVAILABLE = "push_session_unavailable";

export type PushSession = { baseUrl: string; accessToken: string };
export type PushSessionScope = { userId: string; organizationId: string; workspaceId: string; bindingId: string };
/** Issues a workspace-scoped, push-only RelayHistory session; null means not configured. */
export type PushSessionFactory = (scope: PushSessionScope) => Promise<PushSession | null>;
/** Sends one prepared ingest body. The receipt is checked by the caller, never trusted here. */
export type HistoryUploader = (
  session: PushSession,
  body: string,
) => Promise<{ ok: boolean; status: number; receipt: unknown }>;

type AmpVersion = { version: number | null; digest: string; sourceDigest?: string; deliveryRevision?: number };
type AmpVersions = Record<string, AmpVersion>;
type PendingHistory = { v: 1; protocol: "ingest"; batchId: string; body: string; versions: AmpVersions; records: number };

class HistoryError extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "HistoryError";
  }
}
/** The binding, connection or lease changed under this run: stop without writing anything. */
class StaleHistory extends Error {}

export const hash = (value: string) => createHash("sha256").update(value).digest("hex");
export function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, item]) => `${JSON.stringify(key)}:${stableJson(item)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

const setVersion = (versions: AmpVersions, key: string, value: AmpVersion) =>
  Object.defineProperty(versions, key, { value, enumerable: true, configurable: true, writable: true });
// A native message can produce separate human and tool evidence events.
const versionKey = (record: AmpEvidence) => record.eventId;
function priorVersion(versions: AmpVersions, record: AmpEvidence): AmpVersion | undefined {
  if (Object.hasOwn(versions, versionKey(record))) return versions[versionKey(record)];
  return record.eventId === `amp:${record.sessionId}:${record.record.messageId}` && Object.hasOwn(versions, record.record.messageId)
    ? versions[record.record.messageId] : undefined;
}
const sourceDigest = (record: AmpEvidence) => hash(stableJson({ raw: record.record.raw, timestamp: record.ts }));

/** Default uploader: Cloud's ingest protocol, `POST {baseUrl}/v1/ingest`. */
export function ingestUploader(fetchImpl: typeof fetch = fetch): HistoryUploader {
  return async (session, body) => {
    const response = await fetchImpl(`${session.baseUrl.replace(/\/+$/, "")}/v1/ingest`, {
      method: "POST",
      redirect: "manual",
      cache: "no-store",
      signal: AbortSignal.timeout(UPLOAD_TIMEOUT_MS),
      headers: { authorization: `Bearer ${session.accessToken}`, "content-type": "application/json" },
      body,
    });
    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      return { ok: false, status: response.status, receipt: null };
    }
    return { ok: true, status: response.status, receipt: await response.json().catch(() => null) };
  };
}

function preparePage(row: Claimed, page: AmpEvidence[], versions: AmpVersions): PendingHistory {
  const next: AmpVersions = {};
  const revisions = new Map<string, number>();
  for (const record of page) {
    const revision = (priorVersion(versions, record)?.deliveryRevision ?? 0) + 1;
    revisions.set(record.eventId, revision);
    setVersion(next, versionKey(record), {
      version: record.record.messageVersion,
      digest: hash(stableJson(record)),
      sourceDigest: sourceDigest(record),
      deliveryRevision: revision,
    });
  }
  const batchId = `amp:${hash(stableJson([row.workspace_id, row.thread_id, page, [...revisions]])).slice(0, 48)}`;
  const body = { machine: { id: `amp:${row.workspace_id}`, label: "Amp" }, batchId, records: page };
  return { v: 1, protocol: "ingest", batchId, body: JSON.stringify(body), versions: next, records: page.length };
}

function changedRecords(records: AmpEvidence[], versions: AmpVersions) {
  let backfilled = false;
  const changed = records.filter((record) => {
    const prior = priorVersion(versions, record);
    if (!prior) return true;
    const version = record.record.messageVersion;
    if (version === null && prior.version !== null) throw new HistoryError("amp_message_version_missing");
    if (version !== null && prior.version !== null && version < prior.version) return false;
    const digest = hash(stableJson(record));
    if (version !== null && version === prior.version && digest !== prior.digest) {
      // Cloud also accepts a legacy-parser digest here; self-host never wrote
      // pre-sourceDigest checkpoints, so a missing sourceDigest is a change.
      if (!prior.sourceDigest || prior.sourceDigest !== sourceDigest(record)) {
        throw new HistoryError("amp_same_version_changed");
      }
    }
    if (digest === prior.digest && !prior.sourceDigest) {
      backfilled = true;
      setVersion(versions, versionKey(record), { ...prior, sourceDigest: sourceDigest(record) });
    }
    return digest !== prior.digest;
  });
  return { changed, backfilled };
}

function readPending(deps: AmpDeps, ciphertext: string): PendingHistory {
  let pending: PendingHistory | null = null;
  try {
    pending = JSON.parse(decrypt(deps, ciphertext)) as PendingHistory;
  } catch {
    pending = null;
  }
  if (!pending || pending.v !== 1 || pending.protocol !== "ingest" || typeof pending.body !== "string"
    || typeof pending.batchId !== "string" || !Number.isSafeInteger(pending.records)
    || !pending.versions || typeof pending.versions !== "object") {
    throw new HistoryError("amp_history_pending_invalid");
  }
  return pending;
}

/** Stored redactions are exact capability strings only; nothing in self-host writes them yet. */
function readRedactions(deps: AmpDeps, ciphertext: string | null): string[] {
  if (!ciphertext) return [];
  let list: unknown;
  try {
    list = JSON.parse(decrypt(deps, ciphertext));
  } catch {
    throw new HistoryError("amp_history_redactions_invalid");
  }
  if (!Array.isArray(list) || !list.every((item) => typeof item === "string" && /^[A-Za-z0-9_-]{16,512}$/.test(item))) {
    throw new HistoryError("amp_history_redactions_invalid");
  }
  return list as string[];
}

const at = (deps: AmpDeps, offsetMs = 0) => new Date(deps.now().getTime() + offsetMs);

/**
 * Marks due bound threads queued (the hosted history schedule). Coalesced: a
 * thread already queued keeps its original history_queued_at. Retired
 * bindings and bindings whose connection is gone or changed owner never queue.
 */
export async function scheduleHistory(deps: AmpDeps): Promise<number> {
  const result = await deps.database.query(
    `UPDATE amp_bindings b
        SET history_queued_at = $1
      WHERE b.state = 'bound'
        AND b.history_queued_at IS NULL
        AND (b.last_synced_at IS NULL OR b.last_synced_at <= $2)
        AND EXISTS (SELECT 1 FROM amp_connections c
                     WHERE c.workspace_id = b.workspace_id AND c.user_id = b.user_id)
      RETURNING b.id`,
    [at(deps), at(deps, -AMP_HISTORY_INTERVAL_MS)],
  );
  return result.rows.length;
}

/**
 * Queues one binding now (the internal history job). Coalesced with any
 * existing queue entry. With scheduledAt, a poll already completed at or after
 * that time satisfies the request (Cloud's skip rule).
 */
export async function queueHistory(deps: AmpDeps, bindingId: string, scheduledAt?: string): Promise<boolean> {
  const result = await deps.database.query(
    `UPDATE amp_bindings b
        SET history_queued_at = COALESCE(b.history_queued_at, $2)
      WHERE b.id = $1 AND b.state = 'bound'
        AND ($3::timestamptz IS NULL OR b.last_synced_at IS NULL OR b.last_synced_at < $3::timestamptz)
        AND EXISTS (SELECT 1 FROM amp_connections c
                     WHERE c.workspace_id = b.workspace_id AND c.user_id = b.user_id)
      RETURNING b.id`,
    [bindingId, at(deps), scheduledAt ?? null],
  );
  return result.rows.length > 0;
}

type Claimed = {
  id: string;
  workspace_id: string;
  organization_id: string;
  user_id: string;
  thread_id: string;
  generation: number;
  last_synced_at: Date | string | null;
  history_queued_at: Date | string;
  owner: string;
};

/**
 * Claims up to `limit` queued bindings with a run lease. FOR UPDATE SKIP
 * LOCKED keeps concurrent replicas off the same rows; a live lease (or the
 * retry delay after a failure) keeps a row unclaimable until it expires.
 */
export async function claimHistory(deps: AmpDeps, limit = AMP_HISTORY_PER_TICK): Promise<Claimed[]> {
  const owner = randomUUID();
  return deps.database.transaction(async (tx) => {
    const now = at(deps);
    const due = await tx.query<{ id: string }>(
      `SELECT b.id FROM amp_bindings b
        WHERE b.state = 'bound'
          AND b.history_queued_at IS NOT NULL
          AND (b.history_lease_until IS NULL OR b.history_lease_until <= $1)
          AND EXISTS (SELECT 1 FROM amp_connections c
                       WHERE c.workspace_id = b.workspace_id AND c.user_id = b.user_id)
        ORDER BY b.history_queued_at, b.id
        LIMIT $2
        FOR UPDATE OF b SKIP LOCKED`,
      [now, limit],
    );
    if (!due.rows.length) return [];
    const claimed = await tx.query<Omit<Claimed, "owner">>(
      `UPDATE amp_bindings
          SET history_lease_owner = $2, history_lease_until = $3
        WHERE id = ANY($1::uuid[])
        RETURNING id, workspace_id, organization_id, user_id, thread_id, generation, last_synced_at, history_queued_at`,
      [due.rows.map((row) => row.id), owner, at(deps, AMP_HISTORY_QUEUE_LEASE_MS)],
    );
    return claimed.rows.map((row) => ({ ...row, owner }));
  });
}

type Ledger = { versions: AmpVersions; pending_ciphertext: string | null; redactions_ciphertext: string | null };

/**
 * One fenced history run for a claimed binding. Every database step re-checks,
 * under the workspace Amp lock, that the binding is still bound at the claimed
 * generation and person, that the connection key is unchanged, and that this
 * run still holds the lease (renewing it). Remote calls start inside that
 * fence and are awaited after it releases, as Cloud's startAmpOperation does.
 */
export async function runHistory(
  deps: AmpDeps,
  row: Claimed,
): Promise<{ records: number; skipped?: boolean; error?: string }> {
  const scope = { workspaceId: row.workspace_id, organizationId: row.organization_id };
  let keyCiphertext: string | null = null;
  const guard = <T>(work: (tx: SqlExecutor) => Promise<T>) =>
    withAmpLock(deps, scope, async (tx) => {
      const current = await tx.query<{ state: string; generation: number; user_id: string; history_lease_owner: string | null }>(
        "SELECT state, generation, user_id, history_lease_owner FROM amp_bindings WHERE id = $1 FOR UPDATE",
        [row.id],
      );
      const binding = current.rows[0];
      if (!binding || binding.state !== "bound" || binding.generation !== row.generation
        || binding.user_id !== row.user_id || binding.history_lease_owner !== row.owner) {
        throw new StaleHistory();
      }
      const connection = await tx.query<{ user_id: string; key_ciphertext: string }>(
        "SELECT user_id, key_ciphertext FROM amp_connections WHERE workspace_id = $1 FOR SHARE",
        [row.workspace_id],
      );
      const conn = connection.rows[0];
      if (!conn || conn.user_id !== row.user_id || (keyCiphertext !== null && conn.key_ciphertext !== keyCiphertext)) {
        throw new StaleHistory();
      }
      keyCiphertext = conn.key_ciphertext;
      await tx.query(
        "UPDATE amp_bindings SET history_lease_until = $2 WHERE id = $1",
        [row.id, at(deps, AMP_HISTORY_QUEUE_LEASE_MS)],
      );
      return work(tx);
    });
  /** Starts a remote call inside the fence; the lock is released before it is awaited. */
  const remote = async <T>(start: () => Promise<T>): Promise<T> => {
    const started = await guard(async () => {
      const promise = start();
      promise.catch(() => undefined);
      return { promise };
    });
    return started.promise;
  };
  const queuedAt = new Date(row.history_queued_at);
  try {
    if (row.last_synced_at && new Date(row.last_synced_at).getTime() >= queuedAt.getTime()) {
      // A poll that finished after this request was queued already covers it.
      await guard(async (tx) => {
        await tx.query(
          `UPDATE amp_bindings
              SET history_lease_owner = NULL, history_lease_until = NULL,
                  history_queued_at = CASE WHEN history_queued_at = $2 THEN NULL ELSE history_queued_at END
            WHERE id = $1`,
          [row.id, queuedAt],
        );
      });
      return { records: 0, skipped: true };
    }
    const startedAt = at(deps);
    const ledger = await guard(async (tx) => {
      await tx.query(
        `INSERT INTO amp_history_syncs (workspace_id, thread_id) VALUES ($1, $2)
         ON CONFLICT (workspace_id, thread_id) DO NOTHING`,
        [row.workspace_id, row.thread_id],
      );
      const found = await tx.query<Ledger>(
        `SELECT versions, pending_ciphertext, redactions_ciphertext FROM amp_history_syncs
          WHERE workspace_id = $1 AND thread_id = $2`,
        [row.workspace_id, row.thread_id],
      );
      return found.rows[0]!;
    });
    const key = decrypt(deps, keyCiphertext!);
    const redactions = readRedactions(deps, ledger.redactions_ciphertext);
    const versions: AmpVersions = {};
    for (const [id, value] of Object.entries(ledger.versions ?? {})) setVersion(versions, id, value);
    const uploader = deps.historyUpload ?? ingestUploader();
    let session: PushSession | null = null;
    const upload = async (pending: PendingHistory): Promise<number> => {
      if (!session) {
        // Minted lazily: an unchanged thread never asks for a push session.
        const factory = deps.pushSession;
        if (!factory) throw new HistoryError("history_not_configured");
        session = await remote(() => factory({
          userId: row.user_id,
          organizationId: row.organization_id,
          workspaceId: row.workspace_id,
          bindingId: row.id,
        }));
        if (!session) throw new HistoryError("history_not_configured");
      }
      const pushed = session;
      const response = await remote(() => uploader(pushed, pending.body));
      if (!response.ok) throw new HistoryError(`history_http_${response.status}`);
      const receipt = response.receipt as { batchId?: unknown; received?: unknown; accepted?: unknown } | null;
      if (receipt?.batchId !== pending.batchId || receipt.received !== pending.records || receipt.accepted !== pending.records) {
        throw new HistoryError("history_partial_accept");
      }
      for (const [id, version] of Object.entries(pending.versions)) setVersion(versions, id, version);
      // Acknowledge the page and retire its outbox entry in one durable mutation.
      await guard(async (tx) => {
        await tx.query(
          `UPDATE amp_history_syncs SET versions = $3::jsonb, pending_ciphertext = NULL
            WHERE workspace_id = $1 AND thread_id = $2`,
          [row.workspace_id, row.thread_id, JSON.stringify(versions)],
        );
      });
      return pending.records;
    };
    // Finish the exact older upload before observing newer provider bytes.
    let count = ledger.pending_ciphertext ? await upload(readPending(deps, ledger.pending_ciphertext)) : 0;
    let raw: unknown = await remote(() => deps.run(key, { kind: "export", threadId: row.thread_id }));
    // Reply capabilities injected into the thread never leave this host.
    let scrubbed = JSON.stringify(raw)
      .replace(/amp_reply_[A-Za-z0-9_-]{43}/g, "[REDACTED]")
      .replace(/Authorization: Bearer [A-Za-z0-9_-]{43}/g, "Authorization: Bearer [REDACTED]");
    for (const capability of redactions) scrubbed = scrubbed.replaceAll(capability, "[REDACTED]");
    raw = JSON.parse(scrubbed);
    let records: AmpEvidence[];
    try {
      records = ampExport(row.thread_id, raw);
    } catch {
      throw new HistoryError("amp_history_unparseable");
    }
    const { changed, backfilled } = changedRecords(records, versions);
    for (let offset = 0; offset < changed.length; offset += PAGE_RECORDS) {
      const pending = preparePage(row, changed.slice(offset, offset + PAGE_RECORDS), versions);
      await guard(async (tx) => {
        await tx.query(
          `UPDATE amp_history_syncs SET pending_ciphertext = $3
            WHERE workspace_id = $1 AND thread_id = $2`,
          [row.workspace_id, row.thread_id, encrypt(deps, JSON.stringify(pending))],
        );
      });
      count += await upload(pending);
    }
    await guard(async (tx) => {
      // Persist metadata-only backfills too; uploaded pages already committed theirs.
      if (backfilled && changed.length === 0) {
        await tx.query(
          "UPDATE amp_history_syncs SET versions = $3::jsonb WHERE workspace_id = $1 AND thread_id = $2",
          [row.workspace_id, row.thread_id, JSON.stringify(versions)],
        );
      }
      // The watermark moves only here, after every page was fully accepted.
      // Empty exports are successful polls.
      await tx.query(
        `UPDATE amp_bindings
            SET last_synced_at = $2, history_error = NULL,
                history_lease_owner = NULL, history_lease_until = NULL,
                history_queued_at = CASE WHEN history_queued_at = $3 THEN NULL ELSE history_queued_at END
          WHERE id = $1`,
        [row.id, startedAt, queuedAt],
      );
    });
    return { records: count };
  } catch (error) {
    if (error instanceof StaleHistory) {
      // Give back only this run's own lease (a key change, say); a newer
      // claim or a retired row is left untouched.
      await deps.database.query(
        `UPDATE amp_bindings SET history_lease_owner = NULL, history_lease_until = NULL
          WHERE id = $1 AND history_lease_owner = $2`,
        [row.id, row.owner],
      ).catch(() => undefined);
      return { records: 0, skipped: true };
    }
    const code = error instanceof HistoryError ? error.code : "amp_history_failed";
    // Fenced on the lease: a stale run never overwrites a newer run or a retired row.
    // The lease becomes the retry delay; history_queued_at stays so the thread is retried.
    await deps.database.query(
      `UPDATE amp_bindings
          SET history_error = $3, history_lease_owner = NULL, history_lease_until = $4
        WHERE id = $1 AND history_lease_owner = $2 AND state = 'bound'`,
      [row.id, row.owner, code, at(deps, AMP_HISTORY_QUEUE_LEASE_MS)],
    ).catch(() => undefined);
    // Binding id and a fixed code only: never the key, session, thread text or provider detail.
    console.warn("[amp] history_sync_failed", { bindingId: row.id, error: code });
    return { records: 0, error: code };
  }
}

/** Without a push session nothing is exported or polled; only the reason is recorded. */
export async function recordHistoryBlocked(deps: AmpDeps): Promise<void> {
  await deps.database.query(
    `UPDATE amp_bindings SET history_error = $1
      WHERE state = 'bound' AND history_error IS DISTINCT FROM $1`,
    [HISTORY_PUSH_UNAVAILABLE],
  );
}

/** One worker step: schedule due threads, then run a small number of claimed ones. */
export async function historyPass(deps: AmpDeps, stopped: () => boolean = () => false): Promise<void> {
  if (!deps.pushSession) {
    await recordHistoryBlocked(deps);
    return;
  }
  await scheduleHistory(deps);
  if (stopped()) return;
  for (const claim of await claimHistory(deps)) {
    if (stopped()) break;
    await runHistory(deps, claim);
  }
}

export type HistoryRowState = {
  last_synced_at: Date | string | null;
  history_queued_at: Date | string | null;
  history_lease_owner: string | null;
  history_lease_until: Date | string | null;
  history_error: string | null;
};

/** Per-binding history state for the workspace summary. */
export function historyState(deps: AmpDeps, row: HistoryRowState & { state: string }) {
  const iso = (value: Date | string | null) => (value === null ? null : new Date(value).toISOString());
  const base = { lastSyncedAt: iso(row.last_synced_at), queuedAt: iso(row.history_queued_at) };
  if (!deps.pushSession) {
    return { state: "unavailable" as const, reason: HISTORY_PUSH_UNAVAILABLE, lastError: null, ...base };
  }
  const leased = row.history_lease_owner !== null && row.history_lease_until !== null
    && new Date(row.history_lease_until).getTime() > deps.now().getTime();
  const state = row.state !== "bound"
    ? "idle" as const
    : leased
      ? "running" as const
      : row.history_error
        ? "error" as const
        : row.history_queued_at
          ? "queued" as const
          : row.last_synced_at
            ? "synced" as const
            : "idle" as const;
  return { state, lastError: row.history_error, ...base };
}
