// Relaycast re-key (README, "Re-keying Relaycast credentials"). Before a
// self-hosted Relaycast moves from the Postgres runtime to durable actors,
// every Relaycast credential this service stores must be an ar_ one: the
// actor gateway routes only ar_ credentials. While Relaycast still runs on
// Postgres with credentials.format=ar (legacy credentials verify during a
// grace window), this rotates each workspace key through Relaycast's internal
// admin API and upgrades each agent/webhook token through
// POST /v1/credentials/upgrade, keeping the old ciphertext in
// relaycast_rekey_backups first so `--undo <run-id>` can put it back.
//
// Nothing secret is logged or returned: items carry table, column, row id,
// kind, outcome and an error code only.
import { randomUUID } from "node:crypto";
import { decryptSecret, EncryptedSecretError, encryptSecret, type EncryptionKeyring } from "./crypto.js";
import type { Database, SqlExecutor } from "./database.js";
import { loadDatabaseUrl, loadEncryptionKeyring, readSecret, serviceUrl, type Env } from "./config.js";

export type RekeyKind = "workspace" | "agent" | "webhook";
export type RekeyOutcome =
  | "upgraded"
  | "already_ar"
  | "would_upgrade"
  | "foreign"
  | "failed"
  | "restored";

export type RekeyItem = {
  table: string;
  column: string;
  rowId: string;
  kind: RekeyKind;
  outcome: RekeyOutcome;
  /** A fixed error identifier (never a message, value or body). */
  code?: string;
};

export type RekeyReport = {
  runId: string | null;
  mode: "rekey" | "dry-run" | "undo";
  items: RekeyItem[];
  /** `${table}.${column}` -> outcome -> count. */
  summary: Record<string, Partial<Record<RekeyOutcome, number>>>;
  failed: number;
};

/** Only non-secret scalars ever reach the log. */
export type RekeyLogger = (event: string, fields: Record<string, string | number | boolean | null>) => void;

export type RekeyFetch = (input: string, init: RequestInit) => Promise<Response>;

export type RekeyDeps = {
  database: Database;
  keyring: EncryptionKeyring;
  /** Relaycast's in-cluster URL (RELAYCAST_URL). */
  relaycastUrl: string;
  /**
   * Origins that are this install's Relaycast (RELAYCAST_URL and
   * RELAYCAST_PUBLIC_URL). An events-shim wake link on any other origin
   * belongs to another Relaycast and is left alone.
   */
  relaycastOrigins: string[];
  /** RELAYCAST_INTERNAL_SECRET; required to rotate (or undo) workspace keys. */
  internalSecret: string | null;
  fetch?: RekeyFetch;
  log?: RekeyLogger;
};

/** Relaycast's maximum workspace key grace (engine WORKSPACE_KEY_MAX_GRACE_MS). */
export const WORKSPACE_KEY_MAX_GRACE_MS = 3_600_000;

type TokenSource = {
  table: string;
  column: string;
  kind: Exclude<RekeyKind, "workspace">;
  hasUpdatedAt: boolean;
  /** Column holding the URL the credential is presented to, when it may be another Relaycast. */
  originColumn?: string;
};

/**
 * Every column outside `workspaces` that holds a Relaycast credential. The
 * workspace key (workspaces.relaycast_api_key_ciphertext) is handled apart.
 */
export const TOKEN_SOURCES: readonly TokenSource[] = [
  // Person messaging human agent (0010).
  { table: "person_identities", column: "token_ciphertext", kind: "agent", hasUpdatedAt: false },
  // Hosted MCP relay participants (0012).
  { table: "hosted_relay_participants", column: "token_ciphertext", kind: "agent", hasUpdatedAt: true },
  // Desktop relay identities synced by Agent Relay Desktop (0020).
  { table: "desktop_relay_identities", column: "token_ciphertext", kind: "agent", hasUpdatedAt: true },
  // Amp thread agents (0017).
  { table: "amp_bindings", column: "token_ciphertext", kind: "agent", hasUpdatedAt: true },
  // Factory session hosted agents (0016).
  { table: "factory_bindings", column: "hosted_token_envelope", kind: "agent", hasUpdatedAt: true },
  // Capy thread agents (0045).
  { table: "capy_bindings", column: "token_ciphertext", kind: "agent", hasUpdatedAt: true },
  // Events-shim wake link: a Relaycast inbound webhook wh_live_ token (0047).
  { table: "events_shims", column: "wake_secret_ciphertext", kind: "webhook", hasUpdatedAt: false, originColumn: "wake_url" },
];

const WORKSPACE_SOURCE = { table: "workspaces", column: "relaycast_api_key_ciphertext" } as const;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ERROR_CODE = /^[a-z][a-z0-9_]{0,63}$/;
const REQUEST_TIMEOUT_MS = 30_000;

class RekeyFailure extends Error {
  constructor(readonly code: string) {
    super(code);
  }
}

export function isArCredential(value: string): boolean {
  return value.startsWith("ar_");
}

function decryptCode(error: unknown): string {
  return error instanceof EncryptedSecretError ? `ciphertext_${error.code}` : "ciphertext_unreadable";
}

function failureCode(error: unknown): string {
  return error instanceof RekeyFailure ? error.code : "internal_error";
}

/** `{ ok:false, error:{ code } }` -> code, only when it is a plain identifier. */
async function relaycastError(response: Response): Promise<string> {
  const body = await response.json().catch(() => null) as { error?: { code?: unknown } } | null;
  const code = body?.error?.code;
  return typeof code === "string" && ERROR_CODE.test(code) ? code : `http_${response.status}`;
}

async function relaycastPost(
  deps: RekeyDeps,
  path: string,
  bearer: string,
  body: Record<string, unknown>,
): Promise<{ status: number; response: Response }> {
  const fetchImpl = deps.fetch ?? ((input, init) => globalThis.fetch(input, init));
  try {
    const response = await fetchImpl(`${deps.relaycastUrl.replace(/\/+$/, "")}${path}`, {
      method: "POST",
      headers: { authorization: `Bearer ${bearer}`, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    return { status: response.status, response };
  } catch {
    throw new RekeyFailure("relaycast_unreachable");
  }
}

type Rotation = { apiKey: string; generation: number };

async function rotateWorkspaceKey(deps: RekeyDeps, relaycastWorkspaceId: string, graceMs: number): Promise<Rotation> {
  if (!deps.internalSecret) throw new RekeyFailure("internal_secret_missing");
  const { status, response } = await relaycastPost(
    deps,
    `/internal/workspaces/${encodeURIComponent(relaycastWorkspaceId)}/api-key`,
    deps.internalSecret,
    // No api_key: Relaycast mints the replacement (ar_ws_ under
    // credentials.format=ar) and fences it at its stored generation + 1.
    { grace_ms: graceMs },
  );
  if (status !== 200 && status !== 201) throw new RekeyFailure(await relaycastError(response));
  const body = await response.json().catch(() => null) as { data?: { api_key?: unknown; api_key_generation?: unknown } } | null;
  const apiKey = body?.data?.api_key;
  const generation = body?.data?.api_key_generation;
  if (typeof apiKey !== "string" || typeof generation !== "number" || !Number.isSafeInteger(generation)) {
    throw new RekeyFailure("relaycast_invalid_response");
  }
  // A Relaycast still minting legacy keys has not been switched to
  // credentials.format=ar; storing its key would gain nothing.
  if (!apiKey.startsWith("ar_ws_")) throw new RekeyFailure("relaycast_minted_legacy_key");
  return { apiKey, generation };
}

async function pushWorkspaceKey(
  deps: RekeyDeps,
  relaycastWorkspaceId: string,
  apiKey: string,
  generation: number,
  graceMs: number,
): Promise<void> {
  if (!deps.internalSecret) throw new RekeyFailure("internal_secret_missing");
  const { status, response } = await relaycastPost(
    deps,
    `/internal/workspaces/${encodeURIComponent(relaycastWorkspaceId)}/api-key`,
    deps.internalSecret,
    { api_key: apiKey, key_generation: generation, grace_ms: graceMs },
  );
  if (status !== 200 && status !== 201) throw new RekeyFailure(await relaycastError(response));
}

type Upgrade = { credential: string } | { alreadyAr: true };

async function upgradeCredential(deps: RekeyDeps, legacy: string): Promise<Upgrade> {
  const { status, response } = await relaycastPost(deps, "/v1/credentials/upgrade", legacy, {});
  if (status === 409) {
    const code = await relaycastError(response);
    if (code === "credential_not_legacy") return { alreadyAr: true };
    throw new RekeyFailure(code);
  }
  if (status !== 200) throw new RekeyFailure(await relaycastError(response));
  const body = await response.json().catch(() => null) as { data?: { credential?: unknown } } | null;
  const credential = body?.data?.credential;
  if (typeof credential !== "string" || !isArCredential(credential)) throw new RekeyFailure("relaycast_invalid_response");
  return { credential };
}

function originOf(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

class Reporter {
  readonly items: RekeyItem[] = [];
  constructor(private readonly log: RekeyLogger | undefined) {}

  add(item: RekeyItem): void {
    this.items.push(item);
    this.log?.("relaycast_rekey.item", {
      table: item.table,
      column: item.column,
      row_id: item.rowId,
      kind: item.kind,
      outcome: item.outcome,
      code: item.code ?? null,
    });
  }

  report(runId: string | null, mode: RekeyReport["mode"]): RekeyReport {
    const summary: RekeyReport["summary"] = {};
    for (const item of this.items) {
      const key = `${item.table}.${item.column}`;
      const counts = summary[key] ??= {};
      counts[item.outcome] = (counts[item.outcome] ?? 0) + 1;
    }
    return { runId, mode, items: this.items, summary, failed: this.items.filter((item) => item.outcome === "failed").length };
  }
}

async function insertBackup(
  tx: SqlExecutor,
  runId: string,
  row: {
    table: string;
    column: string;
    rowId: string;
    kind: RekeyKind;
    relaycastWorkspaceId: string | null;
    oldCiphertext: string;
    newCiphertext: string;
    keyGeneration: number | null;
  },
): Promise<void> {
  await tx.query(
    `INSERT INTO relaycast_rekey_backups
       (id, run_id, table_name, row_id, column_name, kind, relaycast_workspace_id,
        old_ciphertext, new_ciphertext, key_generation)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    [
      randomUUID(), runId, row.table, row.rowId, row.column, row.kind, row.relaycastWorkspaceId,
      row.oldCiphertext, row.newCiphertext, row.keyGeneration,
    ],
  );
}

/**
 * Compare-and-swap one ciphertext: the row is written only while it still
 * holds `expected`, so a concurrent writer (a re-registration, a Desktop
 * re-sync) is never overwritten. Table and column names come only from the
 * fixed lists above.
 */
async function swapCiphertext(
  tx: SqlExecutor,
  table: string,
  column: string,
  hasUpdatedAt: boolean,
  rowId: string,
  expected: string,
  next: string,
): Promise<void> {
  const result = await tx.query(
    `UPDATE ${table} SET ${column} = $3${hasUpdatedAt ? ", updated_at = now()" : ""}
      WHERE id = $1::uuid AND ${column} = $2
      RETURNING id`,
    [rowId, expected, next],
  );
  if (result.rows.length !== 1) throw new RekeyFailure("concurrent_change");
}

function sourceFor(table: string, column: string): { hasUpdatedAt: boolean } | null {
  if (table === WORKSPACE_SOURCE.table && column === WORKSPACE_SOURCE.column) return { hasUpdatedAt: true };
  return TOKEN_SOURCES.find((source) => source.table === table && source.column === column) ?? null;
}

export type RekeyOptions = {
  /** relay-control workspace id (workspaces.id); all workspaces when absent. */
  workspaceId?: string;
  dryRun?: boolean;
  /** Grace for each rotated workspace key; Relaycast caps it at one hour. */
  workspaceKeyGraceMs?: number;
  runId?: string;
};

export async function rekeyRelaycastCredentials(deps: RekeyDeps, options: RekeyOptions = {}): Promise<RekeyReport> {
  const dryRun = options.dryRun === true;
  if (options.workspaceId !== undefined && !UUID.test(options.workspaceId)) {
    throw new Error("--workspace must be a workspace id (uuid)");
  }
  const graceMs = options.workspaceKeyGraceMs ?? WORKSPACE_KEY_MAX_GRACE_MS;
  if (!Number.isSafeInteger(graceMs) || graceMs < 0 || graceMs > WORKSPACE_KEY_MAX_GRACE_MS) {
    throw new Error(`--grace-ms must be an integer from 0 to ${WORKSPACE_KEY_MAX_GRACE_MS}`);
  }
  const runId = dryRun ? null : options.runId ?? randomUUID();
  const reporter = new Reporter(deps.log);
  deps.log?.("relaycast_rekey.start", {
    run_id: runId,
    dry_run: dryRun,
    workspace_id: options.workspaceId ?? null,
  });

  await rekeyWorkspaceKeys(deps, reporter, runId, options.workspaceId, graceMs);
  for (const source of TOKEN_SOURCES) {
    await rekeyTokens(deps, reporter, runId, source, options.workspaceId);
  }

  const report = reporter.report(runId, dryRun ? "dry-run" : "rekey");
  deps.log?.("relaycast_rekey.done", { run_id: runId, dry_run: dryRun, failed: report.failed });
  return report;
}

async function rekeyWorkspaceKeys(
  deps: RekeyDeps,
  reporter: Reporter,
  runId: string | null,
  workspaceId: string | undefined,
  graceMs: number,
): Promise<void> {
  // Every row bound to a selected Relaycast workspace, even in another
  // organization: one rotation replaces the key they all hold.
  const { rows } = await deps.database.query<{ id: string; relaycast_workspace_id: string; ciphertext: string }>(
    `SELECT id::text AS id, relaycast_workspace_id, relaycast_api_key_ciphertext AS ciphertext
       FROM workspaces
      ${workspaceId === undefined ? "" : "WHERE relaycast_workspace_id IN (SELECT relaycast_workspace_id FROM workspaces WHERE id = $1)"}
      ORDER BY relaycast_workspace_id, id`,
    workspaceId === undefined ? [] : [workspaceId],
  );
  const groups = new Map<string, typeof rows>();
  for (const row of rows) {
    const group = groups.get(row.relaycast_workspace_id) ?? [];
    group.push(row);
    groups.set(row.relaycast_workspace_id, group);
  }

  for (const [relaycastWorkspaceId, group] of groups) {
    const item = (rowId: string, outcome: RekeyOutcome, code?: string): void =>
      reporter.add({ ...WORKSPACE_SOURCE, rowId, kind: "workspace", outcome, ...(code ? { code } : {}) });

    const keys: { row: (typeof rows)[number]; key: string }[] = [];
    let unreadable: string | null = null;
    for (const row of group) {
      try {
        keys.push({ row, key: decryptSecret(row.ciphertext, deps.keyring) });
      } catch (error) {
        unreadable ??= decryptCode(error);
      }
    }
    // Rotating would strand a row this keyring cannot read (for example one
    // under a previous key that is no longer configured): leave the group.
    if (unreadable) {
      for (const row of group) item(row.id, "failed", unreadable);
      continue;
    }
    if (keys.every(({ key }) => isArCredential(key))) {
      for (const row of group) item(row.id, "already_ar");
      continue;
    }
    if (runId === null) {
      // A rotation rewrites every row of the group, ar_ ones included.
      for (const row of group) item(row.id, "would_upgrade");
      continue;
    }

    try {
      const rotation = await rotateWorkspaceKey(deps, relaycastWorkspaceId, graceMs);
      const next = encryptSecret(rotation.apiKey, deps.keyring.active);
      await deps.database.transaction(async (tx) => {
        for (const { row } of keys) {
          await insertBackup(tx, runId, {
            ...WORKSPACE_SOURCE,
            rowId: row.id,
            kind: "workspace",
            relaycastWorkspaceId,
            oldCiphertext: row.ciphertext,
            newCiphertext: next,
            keyGeneration: rotation.generation,
          });
          await swapCiphertext(tx, WORKSPACE_SOURCE.table, WORKSPACE_SOURCE.column, true, row.id, row.ciphertext, next);
        }
      });
      for (const row of group) item(row.id, "upgraded");
    } catch (error) {
      // A rotation whose key could not be stored is recovered by rerunning:
      // the internal secret rotates again regardless of the lost key.
      const code = failureCode(error);
      for (const row of group) item(row.id, "failed", code);
    }
  }
}

async function rekeyTokens(
  deps: RekeyDeps,
  reporter: Reporter,
  runId: string | null,
  source: TokenSource,
  workspaceId: string | undefined,
): Promise<void> {
  const origin = source.originColumn ? `, ${source.originColumn} AS origin_url` : "";
  const { rows } = await deps.database.query<{ id: string; ciphertext: string; origin_url?: string | null }>(
    `SELECT id::text AS id, ${source.column} AS ciphertext${origin}
       FROM ${source.table}
      WHERE ${source.column} IS NOT NULL${workspaceId === undefined ? "" : " AND workspace_id = $1"}
      ORDER BY id`,
    workspaceId === undefined ? [] : [workspaceId],
  );
  const ours = new Set(deps.relaycastOrigins.map(originOf).filter((value): value is string => value !== null));

  for (const row of rows) {
    const item = (outcome: RekeyOutcome, code?: string): void =>
      reporter.add({ table: source.table, column: source.column, rowId: row.id, kind: source.kind, outcome, ...(code ? { code } : {}) });

    if (source.originColumn) {
      const rowOrigin = row.origin_url ? originOf(row.origin_url) : null;
      if (!rowOrigin || !ours.has(rowOrigin)) {
        item("foreign");
        continue;
      }
    }
    let legacy: string;
    try {
      legacy = decryptSecret(row.ciphertext, deps.keyring);
    } catch (error) {
      item("failed", decryptCode(error));
      continue;
    }
    if (isArCredential(legacy)) {
      item("already_ar");
      continue;
    }
    if (runId === null) {
      item("would_upgrade");
      continue;
    }
    try {
      const upgraded = await upgradeCredential(deps, legacy);
      if ("alreadyAr" in upgraded) {
        item("already_ar", "credential_not_legacy");
        continue;
      }
      const next = encryptSecret(upgraded.credential, deps.keyring.active);
      await deps.database.transaction(async (tx) => {
        await insertBackup(tx, runId, {
          table: source.table,
          column: source.column,
          rowId: row.id,
          kind: source.kind,
          relaycastWorkspaceId: null,
          oldCiphertext: row.ciphertext,
          newCiphertext: next,
          keyGeneration: null,
        });
        await swapCiphertext(tx, source.table, source.column, source.hasUpdatedAt, row.id, row.ciphertext, next);
      });
      item("upgraded");
    } catch (error) {
      item("failed", failureCode(error));
    }
  }
}

type BackupRow = {
  id: string;
  table_name: string;
  row_id: string;
  column_name: string;
  kind: RekeyKind;
  relaycast_workspace_id: string | null;
  old_ciphertext: string;
  new_ciphertext: string;
  key_generation: string | number | null;
};

/**
 * Puts back every ciphertext a run replaced. An agent or webhook token goes
 * back as stored: its legacy credential keeps verifying for Relaycast's
 * legacy grace. A workspace key is first pushed back to Relaycast above the
 * generation the rotation produced, because the rotated-out key verified for
 * at most an hour. A row changed since the run is reported, not overwritten.
 */
export async function undoRelaycastRekey(
  deps: RekeyDeps,
  runId: string,
  options: { workspaceKeyGraceMs?: number } = {},
): Promise<RekeyReport> {
  if (!UUID.test(runId)) throw new Error("--undo must be a run id (uuid)");
  const graceMs = options.workspaceKeyGraceMs ?? WORKSPACE_KEY_MAX_GRACE_MS;
  const reporter = new Reporter(deps.log);
  deps.log?.("relaycast_rekey.undo_start", { run_id: runId });

  const { rows: all } = await deps.database.query<BackupRow & { restored: boolean }>(
    `SELECT id::text AS id, table_name, row_id, column_name, kind, relaycast_workspace_id,
            old_ciphertext, new_ciphertext, key_generation, restored_at IS NOT NULL AS restored
       FROM relaycast_rekey_backups
      WHERE run_id = $1
      ORDER BY created_at, id`,
    [runId],
  );
  if (all.length === 0) throw new Error("No relaycast rekey backups for that run id");
  const rows = all.filter((row) => !row.restored);

  const restore = async (row: BackupRow): Promise<void> => {
    const source = sourceFor(row.table_name, row.column_name);
    if (!source) throw new RekeyFailure("unknown_source");
    await deps.database.transaction(async (tx) => {
      await swapCiphertext(tx, row.table_name, row.column_name, source.hasUpdatedAt, row.row_id, row.new_ciphertext, row.old_ciphertext);
      await tx.query("UPDATE relaycast_rekey_backups SET restored_at = now() WHERE id = $1", [row.id]);
    });
  };
  const item = (row: BackupRow, outcome: RekeyOutcome, code?: string): void =>
    reporter.add({ table: row.table_name, column: row.column_name, rowId: row.row_id, kind: row.kind, outcome, ...(code ? { code } : {}) });

  const workspaceGroups = new Map<string, BackupRow[]>();
  for (const row of rows) {
    if (row.kind !== "workspace") continue;
    const key = row.relaycast_workspace_id ?? "";
    workspaceGroups.set(key, [...(workspaceGroups.get(key) ?? []), row]);
  }
  for (const [relaycastWorkspaceId, group] of workspaceGroups) {
    try {
      const generation = Number(group[0]!.key_generation);
      if (!relaycastWorkspaceId || !Number.isSafeInteger(generation)) throw new RekeyFailure("backup_incomplete");
      const oldKeys = new Set<string>();
      for (const row of group) {
        try {
          oldKeys.add(decryptSecret(row.old_ciphertext, deps.keyring));
        } catch (error) {
          throw new RekeyFailure(decryptCode(error));
        }
      }
      // Rows that held different keys cannot all be made current again.
      if (oldKeys.size !== 1) throw new RekeyFailure("ambiguous_old_key");
      await pushWorkspaceKey(deps, relaycastWorkspaceId, [...oldKeys][0]!, generation + 1, graceMs);
    } catch (error) {
      for (const row of group) item(row, "failed", failureCode(error));
      continue;
    }
    for (const row of group) {
      try {
        await restore(row);
        item(row, "restored");
      } catch (error) {
        item(row, "failed", failureCode(error));
      }
    }
  }

  for (const row of rows) {
    if (row.kind === "workspace") continue;
    try {
      await restore(row);
      item(row, "restored");
    } catch (error) {
      item(row, "failed", failureCode(error));
    }
  }

  const report = reporter.report(runId, "undo");
  deps.log?.("relaycast_rekey.undo_done", { run_id: runId, failed: report.failed, already_restored: all.length - rows.length });
  return report;
}

export type PurgeReport = {
  runId: string;
  confirmed: boolean;
  /** Backups of the run, by state of the row they came from. */
  backups: number;
  /** The row still holds the run's new value: undo could still restore it. */
  live: number;
  /** The row was rewritten since the run; undo would refuse it anyway. */
  changed: number;
  /** The row no longer exists. */
  gone: number;
  /** Already put back by --undo. */
  restored: number;
  purged: number;
};

/**
 * Deletes a run's backups once the cutover is done and they are no longer
 * wanted: they hold old Relaycast credential ciphertexts, and after the purge
 * `--undo` for that run is impossible. Without `confirm` it only reports what
 * it would delete. Counts only; nothing secret is read into the log.
 */
export async function purgeRelaycastRekey(
  deps: Pick<RekeyDeps, "database" | "log">,
  runId: string,
  options: { confirm?: boolean } = {},
): Promise<PurgeReport> {
  if (!UUID.test(runId)) throw new Error("--purge must be a run id (uuid)");
  const confirmed = options.confirm === true;
  return deps.database.transaction(async (tx) => {
    const { rows } = await tx.query<BackupRow & { restored: boolean }>(
      `SELECT id::text AS id, table_name, row_id, column_name, kind, new_ciphertext,
              restored_at IS NOT NULL AS restored
         FROM relaycast_rekey_backups
        WHERE run_id = $1
        FOR UPDATE`,
      [runId],
    );
    if (rows.length === 0) throw new Error("No relaycast rekey backups for that run id");
    const report: PurgeReport = { runId, confirmed, backups: rows.length, live: 0, changed: 0, gone: 0, restored: 0, purged: 0 };
    for (const row of rows) {
      if (row.restored) {
        report.restored += 1;
        continue;
      }
      if (!sourceFor(row.table_name, row.column_name)) throw new Error("Backup names an unknown table or column");
      const current = await tx.query<{ value: string | null }>(
        `SELECT ${row.column_name} AS value FROM ${row.table_name} WHERE id = $1::uuid`,
        [row.row_id],
      );
      if (current.rows.length === 0) report.gone += 1;
      else if (current.rows[0]!.value === row.new_ciphertext) report.live += 1;
      else report.changed += 1;
    }
    if (confirmed) {
      const deleted = await tx.query("DELETE FROM relaycast_rekey_backups WHERE run_id = $1 RETURNING id", [runId]);
      report.purged = deleted.rows.length;
    }
    deps.log?.("relaycast_rekey.purge", {
      run_id: runId,
      confirmed,
      backups: report.backups,
      live: report.live,
      changed: report.changed,
      gone: report.gone,
      restored: report.restored,
      purged: report.purged,
    });
    return report;
  });
}

export type RekeyArgs =
  | { mode: "rekey"; workspaceId?: string; dryRun: boolean; graceMs?: number }
  | { mode: "undo"; runId: string; graceMs?: number }
  | { mode: "purge"; runId: string; confirm: boolean }
  | { mode: "help" };

export const REKEY_USAGE = `usage: relaycast-rekey [--workspace <id>] [--dry-run] [--grace-ms <n>]
       relaycast-rekey --undo <run-id> [--grace-ms <n>]
       relaycast-rekey --purge <run-id> [--confirm]

Reads DATABASE_URL, RELAYCAST_URL, RELAYCAST_PUBLIC_URL (optional),
RELAYCAST_INTERNAL_SECRET and SELFHOST_ENCRYPTION_KEY* (each secret also as
<NAME>_FILE). No secret is accepted on the command line.`;

export function parseRekeyArgs(argv: readonly string[]): RekeyArgs {
  let workspaceId: string | undefined;
  let runId: string | undefined;
  let graceMs: number | undefined;
  let purgeRunId: string | undefined;
  let dryRun = false;
  let confirm = false;
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]!;
    const value = (): string => {
      const next = argv[index + 1];
      if (next === undefined || next.startsWith("--")) throw new Error(`${arg} needs a value`);
      index += 1;
      return next;
    };
    if (arg === "--help" || arg === "-h") return { mode: "help" };
    else if (arg === "--dry-run") dryRun = true;
    else if (arg === "--workspace") workspaceId = value();
    else if (arg === "--undo") runId = value();
    else if (arg === "--purge") purgeRunId = value();
    else if (arg === "--confirm") confirm = true;
    else if (arg === "--grace-ms") {
      const raw = value();
      if (!/^\d+$/.test(raw)) throw new Error("--grace-ms must be a non-negative integer");
      graceMs = Number(raw);
    } else {
      // Echo only a flag-shaped name: a stray positional could be a secret.
      throw new Error(/^--[a-z-]{1,32}$/.test(arg) ? `unknown argument ${arg}` : "unexpected positional argument");
    }
  }
  if (purgeRunId !== undefined) {
    if (runId !== undefined || workspaceId !== undefined || dryRun || graceMs !== undefined) {
      throw new Error("--purge takes only --confirm");
    }
    return { mode: "purge", runId: purgeRunId, confirm };
  }
  if (confirm) throw new Error("--confirm applies only to --purge");
  if (runId !== undefined) {
    if (workspaceId !== undefined || dryRun) throw new Error("--undo takes no --workspace or --dry-run");
    return { mode: "undo", runId, ...(graceMs === undefined ? {} : { graceMs }) };
  }
  return {
    mode: "rekey",
    dryRun,
    ...(workspaceId === undefined ? {} : { workspaceId }),
    ...(graceMs === undefined ? {} : { graceMs }),
  };
}

export function loadRekeyEnv(env: Env, needsInternalSecret: boolean): Omit<RekeyDeps, "database" | "fetch" | "log"> & { databaseUrl: string } {
  const relaycastUrl = serviceUrl(env, "RELAYCAST_URL");
  const internalSecret = readSecret(env, "RELAYCAST_INTERNAL_SECRET") ?? null;
  if (needsInternalSecret && internalSecret === null) {
    throw new Error("RELAYCAST_INTERNAL_SECRET is required to rotate workspace keys (use --dry-run to inspect without it)");
  }
  const publicUrl = env.RELAYCAST_PUBLIC_URL?.trim();
  return {
    databaseUrl: loadDatabaseUrl(env),
    keyring: loadEncryptionKeyring(env),
    relaycastUrl,
    relaycastOrigins: publicUrl ? [relaycastUrl, publicUrl] : [relaycastUrl],
    internalSecret,
  };
}
