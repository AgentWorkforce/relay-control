// Cloud -> relay-control identity importer. See ./README.md and ./mapping.ts.
//
// Safety properties:
// - The source is read in one REPEATABLE READ, READ ONLY transaction.
// - Compared values travel as server-rendered jsonb text and are rebuilt on
//   the target with jsonb_populate_record, so timestamps and JSON numbers are
//   never round-tripped through JavaScript.
// - Secrets are decrypted (Cloud envelope) or read (plaintext Relaycast key)
//   only to be re-encrypted with Control's active key. Plaintext, ciphertext,
//   keys, emails and SQL error messages are never logged or reported.
// - Idempotent: every write is an upsert on the target primary key. Ids are
//   the Cloud ids. A re-run converges; invite token hashes are insert-only.
import { createDecipheriv, randomBytes } from "node:crypto";
import { recordAudit } from "../../src/admin/audit.js";
import { canonicalRelayhistoryOrigin } from "../../src/relayhistory-origin.js";
import { decryptSecret, encryptSecret, hashSecret, opaqueToken, type EncryptionKeyring } from "../../src/crypto.js";
import type { Database, SqlExecutor } from "../../src/database.js";
import {
  MAPPING_REVISION,
  IMPORT_LEDGER_TABLE,
  UNBOUND_WORKSPACE_MARKER,
  SECRET_MARKER,
  ORG_TABLES,
  RECONCILED_TABLES,
  REQUIRED_MIGRATION,
  SOURCE_TABLES,
  TARGETS,
  assertScope,
  sourceQuery,
  type ImportScope,
  type ImportTable,
} from "./mapping.js";

export type ImportMode = "plan" | "dry-run" | "apply";

export type ImportLogger = (event: string, fields: Record<string, unknown>) => void;

export type ImportDeps = {
  source: Database;
  /** Not used (and may be omitted) in plan mode. */
  target?: Database;
  keyring: EncryptionKeyring;
  /**
   * Cloud CREDENTIAL_ENCRYPTION_KEY, 64 hex characters. Optional in plan
   * mode only: without it envelopes are not opened and the ledger carries a
   * `secrets_not_checked` warning instead of decrypt skips.
   */
  cloudKeyHex?: string;
  log?: ImportLogger;
  now?: () => Date;
  /** Rows per insert statement. */
  batchSize?: number;
  /**
   * Canonical relayhistory_origin for a Cloud value, or null when it cannot
   * be one. Defaults to Control's canonicalRelayhistoryOrigin (#163), the
   * same contract 0062's CHECK enforces.
   */
  canonicalOrigin?: (raw: string) => string | null;
};

/**
 * The pre-#163 stand-in, kept for callers that pinned it (the verifier's
 * older default). The importer uses canonicalRelayhistoryOrigin.
 */
export function interimCanonicalOrigin(raw: string): string | null {
  const value = raw.trim().toLowerCase().replace(/\/$/, "");
  return /^https:\/\/([a-z0-9.-]+|\[[0-9a-f:.]+\])(:[0-9]{1,5})?$/.test(value) ? value : null;
}

export type TableLedger = {
  candidates: number;
  imported: number;
  skipped: Record<string, number>;
  /**
   * Row keys skipped by the importer itself (not by the mapping's SQL), so a
   * verifier can reconcile them: ids are Cloud UUIDs, never emails or values.
   */
  importerSkips: Record<string, string[]>;
  /**
   * Logical removals: keys the target ledger held for this table that this
   * run no longer imports. Each is absent afterwards, removed by the
   * reconcile DELETE or by an FK cascade earlier in the same transaction.
   */
  deleted: number;
};

export type OrgLedger = {
  status: "ok" | "failed" | "planned";
  /** SQLSTATE and constraint name only; never the driver message. */
  error?: { code: string; constraint?: string; table?: string };
  imported: Partial<Record<ImportTable, number>>;
  /**
   * Keys written for this organization (Cloud UUIDs; memberships org:user).
   * The next run's reconcile reads them from this report.
   */
  keys: Partial<Record<ImportTable, string[]>>;
  deleted: Partial<Record<ImportTable, number>>;
};

export type ImportReport = {
  version: 1;
  mappingRevision: string;
  mode: ImportMode;
  scope: { orgIds: string[] | null };
  startedAt: string;
  finishedAt: string;
  ok: boolean;
  /** Fatal reason when the import refused to write anything. */
  refused?: string;
  tables: Record<ImportTable, TableLedger>;
  orgs: Record<string, OrgLedger>;
  /** Columns written beyond the 0051 baseline, as found on the target. */
  optionalColumns: string[];
  warnings: Record<string, number>;
  /** Distinct canonical History origins imported (customer hosts; keep local). */
  relayhistoryOrigins: string[];
};

type SourceRow = {
  key: string;
  skip: string | null;
  org: string | null;
  email: string | null;
  /** Plaintext Relaycast key, or the Cloud envelope as JSON text. */
  secret: string | null;
  /** jsonb text of the non-secret fields. */
  row: string;
  /** Row facts the importer acts on without parsing `row`. */
  flags: string[] | null;
  /** workspaces: Cloud's raw relayhistory_origin. */
  origin: string | null;
};

type PreparedRow = { override?: string; key: string; org: string | null; email: string | null; row: string; secret: string | null; flags: string[] | null };

type EncryptedEnvelope = { v: number; iv: string; tag: string; ciphertext: string };

/** Cloud's packages/core/src/auth/credential-encryption.ts decryptCredential. */
export function decryptCloudEnvelope(envelope: EncryptedEnvelope, hexKey: string): string {
  if (envelope.v !== 1) throw new Error("unsupported envelope version");
  const key = Buffer.from(hexKey, "hex");
  if (key.length !== 32) throw new Error("Cloud key must be 32 bytes of hex");
  const iv = Buffer.from(envelope.iv, "hex");
  const tag = Buffer.from(envelope.tag, "hex");
  if (iv.length !== 12 || tag.length !== 16) throw new Error("malformed envelope");
  const decipher = createDecipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, "base64")), decipher.final()]).toString("utf8");
}

const quote = (name: string) => {
  if (!/^[a-z_][a-z0-9_]*$/.test(name)) throw new Error("unexpected identifier");
  return `"${name}"`;
};

async function readSource(tx: SqlExecutor, table: ImportTable, scope: ImportScope): Promise<SourceRow[]> {
  const secret = TARGETS[table].secret?.source;
  const email = table === "users" ? "q.email" : "NULL::text";
  const result = await tx.query<SourceRow>(
    `SELECT ${table === "organization_memberships" ? "q.organization_id::text || ':' || q.user_id::text" : `q.${TARGETS[table].key ?? "id"}::text`} AS key,
            q.skip_reason AS skip,
            ${table === "users" ? "NULL::text" : "q.organization_id::text"} AS org,
            ${email} AS email,
            ${secret === "secret_plaintext" ? "q.secret_plaintext" : secret === "secret_envelope" ? "q.secret_envelope::text" : "NULL::text"} AS secret,
            ${ROW_FLAGS[table] ?? "NULL::text[]"} AS flags,
            ${table === "workspaces" ? "q.relayhistory_origin_raw" : "NULL::text"} AS origin,
            (to_jsonb(q) - 'skip_reason' - 'secret_plaintext' - 'secret_envelope' - 'cloud_user_id' - 'relayhistory_origin_raw')::text AS row
       FROM (${sourceQuery(table, scope)}) q`,
  );
  return result.rows;
}

const ROW_FLAGS: Partial<Record<ImportTable, string>> = {
  workspaces: `array_remove(ARRAY[
      CASE WHEN q.cloud_relay_workspace_id IS NULL AND q.unbound_reason IS DISTINCT FROM 'no_relay_workspace'
           THEN 'workspace_rw_id_not_rw_8hex' END,
      CASE WHEN q.unbound_reason IS NOT NULL THEN 'unbound:' || q.unbound_reason END,
      CASE WHEN q.has_dashboard_url THEN 'relayhistory_dashboard_url_dropped' END,
      CASE WHEN q.relayhistory_origin_raw IS NOT NULL THEN 'relayhistory_origin_set' END
    ], NULL)`,
  desktop_relay_identities: `CASE WHEN NOT q.source_id_is_uuid THEN ARRAY['source_id_not_uuid'] END`,
  coding_agent_credentials: `CASE WHEN q.active_demoted THEN ARRAY['coding_agent_active_demoted'] END`,
};

type ColumnInfo = { udt: string; nullable: boolean };
type TargetColumns = Map<string, Map<string, ColumnInfo>>;

async function targetColumns(target: SqlExecutor): Promise<TargetColumns> {
  const tables = SOURCE_TABLES.map((table) => TARGETS[table].table);
  const result = await target.query<{ table_name: string; column_name: string; udt_name: string; is_nullable: string }>(
    `SELECT table_name, column_name, udt_name, is_nullable FROM information_schema.columns
      WHERE table_schema = 'public' AND table_name = ANY($1::text[])`,
    [tables],
  );
  const columns: TargetColumns = new Map();
  for (const row of result.rows) {
    if (!columns.has(row.table_name)) columns.set(row.table_name, new Map());
    columns.get(row.table_name)!.set(row.column_name, { udt: row.udt_name, nullable: row.is_nullable === "YES" });
  }
  return columns;
}

function writeColumns(table: ImportTable, columns: TargetColumns): string[] | null {
  const spec = TARGETS[table];
  const present = columns.get(spec.table) ?? new Map<string, ColumnInfo>();
  const list = [...spec.columns, ...(spec.optional ?? []).filter((column) => present.has(column))];
  if (spec.secret) list.push(spec.secret.target);
  if (spec.inviteTokenHash) list.push(spec.inviteTokenHash);
  if (spec.freshTokenHash) list.push(spec.freshTokenHash);
  const missing = list.filter((column) => !present.has(column));
  if (missing.length) {
    if (spec.gate) return null;
    throw new ImportRefused(`target_missing_columns:${spec.table}`);
  }
  return list;
}

function upsertSql(table: ImportTable, columns: string[], fill = "'{}'::jsonb"): string {
  const spec = TARGETS[table];
  const secretColumn = spec.secret?.target ?? spec.inviteTokenHash ?? spec.freshTokenHash;
  const relation = `public.${quote(spec.table)}`;
  const keep = spec.keepTargetBinding;
  const keepWhen = keep
    ? `__t.${quote(keep.when)} IS NOT NULL AND (EXCLUDED.${quote(keep.when)} IS NULL OR EXCLUDED.${quote(keep.when)} <> __t.${quote(keep.when)}${
      keep.generation && columns.includes(keep.generation) ? ` OR EXCLUDED.${quote(keep.generation)} < __t.${quote(keep.generation)}` : ""})`
    : "";
  // Control rotated the secret since the import last wrote it (SECRET_MARKER):
  // keep Control's secret and the columns it rewrites with it.
  const secret = spec.secret?.target;
  const keepSecret = secret
    ? `(__t.${quote(secret)} IS NOT NULL AND NOT EXISTS (SELECT 1 FROM public.${IMPORT_LEDGER_TABLE} __l
         WHERE __l.organization_id = $4::uuid AND __l.table_name = '${SECRET_MARKER}'
           AND __l.row_key = '${spec.table}:' || __t.id::text || ':' || encode(sha256(convert_to(__t.${quote(secret)}, 'UTF8')), 'hex')))`
    : "";
  const secretOwned = secret ? [secret, ...(spec.secretGroup ?? [])] : [];
  const assigned = columns
    .filter((column) => !spec.primaryKey.includes(column) && !(spec.insertOnly ?? []).includes(column))
    .map((column) => {
      const incoming = keep?.columns.includes(column)
        ? `CASE WHEN ${keepWhen} THEN __t.${quote(column)} ELSE EXCLUDED.${quote(column)} END`
        : (spec.monotonic ?? []).includes(column)
          ? `GREATEST(__t.${quote(column)}, EXCLUDED.${quote(column)})`
          : `EXCLUDED.${quote(column)}`;
      return [column, secretOwned.includes(column) ? `CASE WHEN ${keepSecret} THEN __t.${quote(column)} ELSE ${incoming} END` : incoming] as const;
    });
  const updates = assigned.map(([column, value]) => `${quote(column)} = ${value}`);
  // No same-value UPDATE: a re-run rewrites a row only when a value differs,
  // so unchanged rows keep their versions (xmin) and convergence checkpoints
  // can prove it. A re-encrypted secret column (fresh IV every run, e.g.
  // workspaces.relaycast_api_key_ciphertext) always differs and is rewritten.
  const changed = assigned.length
    ? ` WHERE ROW(${assigned.map(([column]) => `__t.${quote(column)}`).join(", ")}) IS DISTINCT FROM ROW(${assigned.map(([, value]) => value).join(", ")})`
    : "";
  return `INSERT INTO ${relation} AS __t (${columns.map(quote).join(", ")})
SELECT ${columns.map((column) => `p.${quote(column)}`).join(", ")}
  FROM unnest($1::text[], $2::text[], $3::text[]) AS u(r, s, o)
 CROSS JOIN LATERAL jsonb_populate_record(
   NULL::${relation},
   u.r::jsonb || COALESCE(u.o::jsonb, '{}'::jsonb) || ${fill} || ${secretColumn ? `CASE WHEN u.s IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('${secretColumn}', u.s) END` : "'{}'::jsonb"}
 ) AS p
ON CONFLICT (${spec.primaryKey.map(quote).join(", ")}) DO ${updates.length ? `UPDATE SET ${updates.join(", ")}${changed}` : "NOTHING"}`;
}

/** Keys of `rows` not yet present on the target (first import). */
async function newKeys(tx: SqlExecutor, table: ImportTable, rows: PreparedRow[]): Promise<Set<string>> {
  const existing = await tx.query<{ id: string }>(
    `SELECT id::text AS id FROM public.${quote(TARGETS[table].table)} WHERE id::text = ANY($1::text[])`,
    [rows.map((row) => row.key)],
  );
  const present = new Set(existing.rows.map((row) => row.id));
  return new Set(rows.map((row) => row.key).filter((key) => !present.has(key)));
}

const USERS_LAST_SQL = `
UPDATE public.users u
   SET last_organization_id = CASE WHEN EXISTS (
         SELECT 1 FROM public.organization_memberships m
          WHERE m.user_id = u.id AND m.organization_id = p.last_organization_id
       ) THEN p.last_organization_id END,
       last_workspace_id = CASE WHEN EXISTS (
         SELECT 1 FROM public.workspaces w
           JOIN public.organization_memberships m ON m.organization_id = w.organization_id AND m.user_id = u.id
          WHERE w.id = p.last_workspace_id
       ) THEN p.last_workspace_id END
  FROM unnest($1::text[]) AS x(r)
 CROSS JOIN LATERAL jsonb_populate_record(NULL::public.users, x.r::jsonb) AS p
 WHERE u.id = p.id`;

class ImportRefused extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = "ImportRefused";
  }
}

class DryRunRollback extends Error {}

function errorFields(error: unknown): { code: string; constraint?: string; table?: string } {
  const { code, constraint, table } = (error ?? {}) as { code?: unknown; constraint?: unknown; table?: unknown };
  return {
    code: typeof code === "string" ? code : error instanceof Error ? error.name : "unknown",
    ...(typeof constraint === "string" ? { constraint } : {}),
    ...(typeof table === "string" ? { table } : {}),
  };
}

function chunks<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let index = 0; index < items.length; index += size) out.push(items.slice(index, index + size));
  return out;
}

/** Tables whose rows carry workspace_id and follow their workspace's skip. */
const WORKSPACE_DEPENDENT_TABLES: readonly ImportTable[] = [
  "person_identities",
  "hosted_relay_participants",
  "desktop_relay_identities",
  "fleet_node_owners",
  "github_app_connections",
  "coding_agent_credentials",
  "staff_read_grants",
];

/** A per-organization refusal: recorded as that org's failure, others go on. */
class OrgRefused extends Error {
  constructor(readonly code: string) {
    super(code);
    this.name = "OrgRefused";
  }
}

const KEY_FORMAT: Partial<Record<ImportTable, RegExp>> = {
  organization_memberships: /^[0-9a-f-]{36}:[0-9a-f-]{36}$/,
  github_app_installations: /^[1-9][0-9]{0,19}$/,
};
const UUID_KEY = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function deleteSql(table: ImportTable): string {
  switch (table) {
    case "organization_memberships":
      return `DELETE FROM public.organization_memberships
               WHERE organization_id = $2 AND (organization_id::text || ':' || user_id::text) = ANY($1::text[])`;
    case "person_identities":
    case "hosted_relay_participants":
      return `DELETE FROM public.${table} x USING public.workspaces w
               WHERE w.id = x.workspace_id AND w.organization_id = $2 AND x.id::text = ANY($1::text[])`;
    case "github_app_connections":
      return `DELETE FROM public.integration_connections
               WHERE auth_mode = 'github_app' AND github_app_organization_id = $2 AND id::text = ANY($1::text[])`;
    case "coding_agent_credentials":
      // Only the main run's relay_managed rows; copier rows have Control ids.
      return `DELETE FROM public.coding_agent_credentials
               WHERE auth_type = 'relay_managed' AND organization_id = $2 AND id::text = ANY($1::text[])`;
    default:
      return `DELETE FROM public.${quote(TARGETS[table].table)} WHERE organization_id = $2 AND id::text = ANY($1::text[])`;
  }
}

export async function runImport(deps: ImportDeps, scope: ImportScope, mode: ImportMode): Promise<ImportReport> {
  assertScope(scope);
  const now = deps.now ?? (() => new Date());
  const log: ImportLogger = deps.log ?? (() => {});
  const batchSize = deps.batchSize ?? 250;
  if (mode !== "plan" && !deps.cloudKeyHex) throw new Error("the Cloud credential key is required outside plan mode");
  const startedAt = now().toISOString();
  const report: ImportReport = {
    version: 1,
    mappingRevision: MAPPING_REVISION,
    mode,
    scope: { orgIds: scope.orgIds === null ? null : [...scope.orgIds] },
    startedAt,
    finishedAt: startedAt,
    ok: false,
    tables: Object.fromEntries(SOURCE_TABLES.map((table) => [table, { candidates: 0, imported: 0, skipped: {}, importerSkips: {}, deleted: 0 }])) as Record<ImportTable, TableLedger>,
    orgs: {},
    optionalColumns: [],
    warnings: {},
    relayhistoryOrigins: [],
  };
  const skip = (table: ImportTable, reason: string, key?: string) => {
    const ledger = report.tables[table];
    ledger.skipped[reason] = (ledger.skipped[reason] ?? 0) + 1;
    if (key !== undefined) (ledger.importerSkips[reason] ??= []).push(key);
  };
  const warn = (name: string) => {
    report.warnings[name] = (report.warnings[name] ?? 0) + 1;
  };

  const canonicalOrigin = deps.canonicalOrigin ?? canonicalRelayhistoryOrigin;
  const origins = new Set<string>();
  // 1. Read and transform. Nothing is written before every row is prepared.
  const prepared = {} as Record<ImportTable, PreparedRow[]>;
  await deps.source.transaction(async (tx) => {
    await tx.exec("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
    // Deterministic transforms: interval arithmetic (the 90-day grant clamp)
    // and rendered timestamps must not depend on the session's time zone.
    await tx.exec("SET LOCAL TIME ZONE 'UTC'");
    for (const table of SOURCE_TABLES) {
      const relation = TARGETS[table].sourceRelation;
      if (relation) {
        const present = await tx.query<{ present: boolean }>(
          "SELECT to_regclass(format('public.%I', $1::text)) IS NOT NULL AS present",
          [relation],
        );
        if (present.rows[0]?.present !== true) {
          // An older Cloud branch: nothing to import, said out loud.
          warn(`source_lacks_${relation}`);
          prepared[table] = [];
          continue;
        }
      }
      const rows = await readSource(tx, table, scope);
      report.tables[table].candidates = rows.length;
      const kept: PreparedRow[] = [];
      for (const row of rows) {
        if (row.skip !== null) {
          skip(table, row.skip);
          continue;
        }
        let secret: string | null = null;
        const spec = TARGETS[table];
        try {
          if (spec.secretConstant !== undefined) {
            secret = encryptSecret(spec.secretConstant, deps.keyring.active);
          } else if (spec.secret?.source === "secret_plaintext") {
            // NULL for an unbound workspace: its Relaycast pair stays NULL (0064).
            secret = row.secret === null ? null : encryptSecret(row.secret, deps.keyring.active);
          } else if (spec.secret?.source === "secret_envelope" && !deps.cloudKeyHex) {
            warn("secrets_not_checked");
          } else if (spec.secret?.source === "secret_envelope") {
            const plaintext = decryptCloudEnvelope(JSON.parse(row.secret ?? "null") as EncryptedEnvelope, deps.cloudKeyHex!);
            secret = encryptSecret(plaintext, deps.keyring.active);
          } else if (spec.freshTokenHash) {
            // A random value nobody holds: imported grants never authenticate.
            secret = hashSecret(randomBytes(32).toString("base64url"));
          } else if (spec.inviteTokenHash) {
            // Same mint as IdentityStore.createInvitation: an sh_inv_ opaque
            // token stored as its sha256. The token itself is discarded; an
            // admin issues a usable link with "Copy link"/"Resend"
            // (rotateInvitation), and sign-in auto-accepts by email anyway.
            secret = hashSecret(opaqueToken("sh_inv_"));
          }
        } catch {
          skip(table, "cloud_decrypt_failed", row.key);
          continue;
        }
        for (const flag of row.flags ?? []) if (flag !== "source_id_not_uuid" && !flag.startsWith("unbound:")) warn(flag);
        let override: string | undefined;
        if (table === "workspaces") {
          const canonical = row.origin === null ? null : canonicalOrigin(row.origin);
          if (row.origin !== null && canonical === null) warn("relayhistory_origin_invalid_dropped");
          if (canonical !== null) origins.add(canonical);
          override = JSON.stringify({ relayhistory_origin: canonical });
        }
        kept.push({ ...(override ? { override } : {}), key: row.key, org: row.org, email: row.email, row: row.row, secret, flags: row.flags });
      }
      prepared[table] = kept;
    }
  });

  // Operators list these in SELFHOST_RELAYHISTORY_AUDIENCES (#163).
  report.relayhistoryOrigins = [...origins].sort();
  const orgIds = [...new Set(prepared.organizations.map((row) => row.org!))].sort();
  // Keys are (re)computed from `prepared` after every filter has run, so the
  // ledger lists exactly the rows this run writes.
  const recordKeys = () => {
    for (const org of orgIds) {
      const keys: Partial<Record<ImportTable, string[]>> = {};
      for (const table of ORG_TABLES) keys[table] = prepared[table].filter((row) => row.org === org).map((row) => row.key).sort();
      report.orgs[org]!.keys = keys;
    }
  };
  for (const org of orgIds) report.orgs[org] = { status: "planned", imported: {}, keys: {}, deleted: {} };
  recordKeys();
  // Every key is checked before anything is written: a malformed key fails
  // the run cleanly instead of reaching SQL or the ledger.
  for (const table of SOURCE_TABLES) {
    const format = KEY_FORMAT[table] ?? UUID_KEY;
    if (prepared[table].some((row) => !format.test(row.key))) {
      report.refused = `invalid_row_key:${table}`;
      report.finishedAt = now().toISOString();
      return report;
    }
  }

  if (mode === "plan") {
    for (const table of SOURCE_TABLES) {
      report.tables[table].imported = prepared[table].length;
      for (const row of prepared[table]) {
        if (row.org && report.orgs[row.org]) {
          const ledger = report.orgs[row.org]!.imported;
          ledger[table] = (ledger[table] ?? 0) + 1;
        }
      }
    }
    report.ok = true;
    report.finishedAt = now().toISOString();
    log("cloud_import.plan", { tables: summary(report) });
    return report;
  }

  const target = deps.target;
  if (!target) throw new Error("target database is required outside plan mode");

  // 2. Preflight on the target.
  try {
    const ledger = await target.query<{ name: string }>(
      "SELECT name FROM control_schema_migrations WHERE name = $1",
      [REQUIRED_MIGRATION],
    );
    if (!ledger.rows[0]) throw new ImportRefused("target_schema_too_old");
    const columns = await targetColumns(target);
    const writable = Object.fromEntries(SOURCE_TABLES.map((table) => [table, writeColumns(table, columns)])) as Record<ImportTable, string[] | null>;
    // Tables from later migrations the target lacks: skip their rows by gate.
    for (const table of SOURCE_TABLES) {
      if (writable[table] !== null) continue;
      for (const row of prepared[table]) skip(table, TARGETS[table].gate!, row.key);
      prepared[table] = [];
    }
    const write = writable as Record<ImportTable, string[]>;
    const finishFilters = () => recordKeys();
    // Before 0057 the target source_id is uuid: a Cloud text id cannot land.
    if (columns.get("desktop_relay_identities")?.get("source_id")?.udt === "uuid") {
      prepared.desktop_relay_identities = prepared.desktop_relay_identities.filter((row) => {
        if (!row.flags?.includes("source_id_not_uuid")) return true;
        skip("desktop_relay_identities", "source_id_not_uuid", row.key);
        return false;
      });
    }
    // Before 0064 a Control workspace needs a Relaycast binding: an unbound
    // Cloud workspace is skipped under its unbound reason, and so is every
    // row that would reference it. From 0064 it imports with the pair NULL.
    const workspaceColumns = columns.get("workspaces");
    const unboundAllowed = workspaceColumns?.get("relaycast_workspace_id")?.nullable === true
      && workspaceColumns?.get("relaycast_api_key_ciphertext")?.nullable === true;
    const unboundReason = (row: PreparedRow) => row.flags?.find((flag) => flag.startsWith("unbound:"))?.slice("unbound:".length);
    if (!unboundAllowed) {
      const dropped = new Set<string>();
      prepared.workspaces = prepared.workspaces.filter((row) => {
        const reason = unboundReason(row);
        if (!reason) return true;
        skip("workspaces", reason, row.key);
        dropped.add(row.key);
        return false;
      });
      if (dropped.size > 0) {
        for (const table of WORKSPACE_DEPENDENT_TABLES) {
          prepared[table] = prepared[table].filter((row) => {
            const { workspace_id: workspaceId } = JSON.parse(row.row) as { workspace_id?: string };
            if (!workspaceId || !dropped.has(workspaceId)) return true;
            skip(table, "workspace_unbound_pre_0064", row.key);
            return false;
          });
        }
      }
    } else {
      for (const row of prepared.workspaces) if (unboundReason(row)) warn("workspace_imported_unbound");
    }
    // Before 0058 Control cannot hold a relay_managed credential.
    const relayManaged = await target.query<{ ok: boolean }>(
      `SELECT EXISTS (
         SELECT 1 FROM pg_constraint c
          WHERE c.conrelid = 'public.coding_agent_credentials'::regclass AND c.contype = 'c'
            AND pg_get_constraintdef(c.oid) LIKE '%auth_type%' AND pg_get_constraintdef(c.oid) LIKE '%relay_managed%'
       ) AS ok`,
    );
    if (relayManaged.rows[0]?.ok !== true) {
      prepared.coding_agent_credentials = prepared.coding_agent_credentials.filter((row) => {
        skip("coding_agent_credentials", "target_lacks_relay_managed", row.key);
        return false;
      });
    }
    // Before 0057 node_name is NOT NULL: the node id stands in.
    const fills: Partial<Record<ImportTable, string>> = {};
    // staff_read_grants.staff_organization_id is the target's operator org.
    if (prepared.staff_read_grants.length > 0) {
      const operator = await target.query<{ organization_id: string }>(
        "SELECT organization_id::text AS organization_id FROM public.installation_bootstrap WHERE organization_id IS NOT NULL LIMIT 1",
      );
      const operatorOrg = operator.rows[0]?.organization_id;
      if (operatorOrg && UUID_KEY.test(operatorOrg)) {
        fills.staff_read_grants = `jsonb_build_object('staff_organization_id', '${operatorOrg}'::text)`;
      } else {
        prepared.staff_read_grants = prepared.staff_read_grants.filter((row) => {
          skip("staff_read_grants", "no_operator_organization", row.key);
          return false;
        });
      }
    }
    if (columns.get("fleet_node_owners")?.get("node_name")?.nullable === false) {
      fills.fleet_node_owners = "jsonb_build_object('node_name', u.r::jsonb ->> 'node_id')";
      warn("fleet_node_name_filled_with_node_id");
    }
    report.optionalColumns = SOURCE_TABLES.flatMap((table) =>
      (TARGETS[table].optional ?? []).filter((column) => write[table]?.includes(column)).map((column) => `${TARGETS[table].table}.${column}`));

    // A Control user that already owns an imported email under another id
    // would make the upsert fail mid-way; refuse up front instead.
    const conflicts = await target.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM public.users t
         JOIN unnest($1::text[]) AS x(r) ON (x.r::jsonb ->> 'email') = t.email
        WHERE t.id::text <> (x.r::jsonb ->> 'id')`,
      [prepared.users.map((row) => row.row)],
    );
    const ledgerTable = await target.query<{ present: boolean }>(
      "SELECT to_regclass('public.cloud_import_ledger') IS NOT NULL AS present",
    );
    if (ledgerTable.rows[0]?.present !== true) throw new ImportRefused("target_lacks_import_ledger");
    if (Number(conflicts.rows[0]?.n ?? 0) > 0) {
      report.tables.users.skipped.target_email_conflict = Number(conflicts.rows[0]!.n);
      throw new ImportRefused("target_email_conflict");
    }

    finishFilters();

    // 3. Write. apply: users in batches, then one transaction per org.
    //    dry-run: the same units as savepoints inside one transaction that is
    //    rolled back at the end.
    const writeRows = async (tx: SqlExecutor, table: ImportTable, rows: PreparedRow[]) => {
      if (rows.length === 0) return;
      const keep = TARGETS[table].keepTargetBinding;
      if (keep) await countKeptBindings(tx, table, keep, rows);
      if (table === "coding_agent_credentials") rows = await keepActiveCredential(tx, rows);
      const sql = upsertSql(table, write[table], fills[table]);
      const secret = TARGETS[table].secret?.target;
      const org = rows[0]!.org;
      for (const batch of chunks(rows, batchSize)) {
        const params: unknown[] = [batch.map((row) => row.row), batch.map((row) => row.secret), batch.map((row) => row.override ?? null)];
        if (secret) params.push(org);
        if (secret && org) {
          const settled = await settleSecrets(tx, table, secret, org, batch);
          params[1] = batch.map((row) => settled.get(row.key) ?? row.secret);
          await tx.query(sql, params);
          await recordSecrets(tx, table, secret, org, batch, settled);
        } else {
          await tx.query(sql, params);
        }
      }
    };
    // After the upsert: a row now holding the ciphertext this run sent was
    // written by the import, so its marker moves to that ciphertext; a row
    // holding anything else kept Control's secret (counted).
    // Before the upsert, per row whose target already holds a secret T:
    // - T is the import's own (its marker) and decrypts to Cloud's plaintext:
    //   send T back unchanged, so nothing is rewritten and the marker stays
    //   (no fresh-IV churn on a converged re-run);
    // - no marker at all (imported before .28, or pre-seeded): when T decrypts
    //   to Cloud's plaintext, adopt it (record the marker, no write) so later
    //   Cloud rotations flow; otherwise it is Control's and the upsert keeps it;
    // - a marker for another value: Control rotated it; the upsert keeps it.
    // Returns the ciphertext to send for rows whose target value is reused.
    const settleSecrets = async (tx: SqlExecutor, table: ImportTable, secret: string, org: string, rows: PreparedRow[]) => {
      const relation = TARGETS[table].table;
      const current = (await tx.query<{ id: string; value: string; digest: string; marker: string | null }>(
        `SELECT t.id::text AS id, t.${quote(secret)} AS value,
                encode(sha256(convert_to(t.${quote(secret)}, 'UTF8')), 'hex') AS digest,
                (SELECT l.row_key FROM public.${IMPORT_LEDGER_TABLE} l WHERE l.organization_id = $2::uuid AND l.table_name = $3
                   AND starts_with(l.row_key, $4 || ':' || t.id::text || ':') LIMIT 1) AS marker
           FROM public.${quote(relation)} t
          WHERE t.id::text = ANY($1::text[]) AND t.${quote(secret)} IS NOT NULL`,
        [rows.map((row) => row.key), org, SECRET_MARKER, relation])).rows;
      const incoming = new Map(rows.map((row) => [row.key, row]));
      const plain = (ciphertext: string | null) => {
        if (ciphertext === null) return null;
        try { return decryptSecret(ciphertext, deps.keyring); } catch { return null; }
      };
      const reuse = new Map<string, string>();
      const adopt: string[] = [];
      for (const target of current) {
        const row = incoming.get(target.id);
        const cloud = plain(row?.secret ?? null);
        if (!row || cloud === null) continue;
        const ownMarker = `${relation}:${target.id}:${target.digest}`;
        if (target.marker === ownMarker) {
          if (plain(target.value) === cloud) reuse.set(target.id, target.value);
        } else if (target.marker === null && plain(target.value) === cloud) {
          reuse.set(target.id, target.value);
          adopt.push(ownMarker);
        }
      }
      if (adopt.length) {
        await tx.query(
          `INSERT INTO public.${IMPORT_LEDGER_TABLE} (organization_id, table_name, row_key, mapping_revision)
           SELECT $1::uuid, $2, k, $4 FROM unnest($3::text[]) AS u(k) ON CONFLICT DO NOTHING`,
          [org, SECRET_MARKER, adopt, MAPPING_REVISION]);
        report.warnings[`${table}_secret_adopted`] = (report.warnings[`${table}_secret_adopted`] ?? 0) + adopt.length;
      }
      return reuse;
    };
    // After the upsert: a row now holding the ciphertext this run sent carries
    // the import's value, so its marker names that ciphertext (written only
    // when it changed); a row holding anything else kept Control's secret.
    const recordSecrets = async (tx: SqlExecutor, table: ImportTable, secret: string, org: string, rows: PreparedRow[], sent: Map<string, string>) => {
      const relation = TARGETS[table].table;
      const stored = new Map((await tx.query<{ id: string; value: string | null; digest: string | null; markers: string[] }>(
        `SELECT t.id::text AS id, t.${quote(secret)} AS value, encode(sha256(convert_to(t.${quote(secret)}, 'UTF8')), 'hex') AS digest,
                ARRAY(SELECT l.row_key FROM public.${IMPORT_LEDGER_TABLE} l WHERE l.organization_id = $2::uuid AND l.table_name = $3
                        AND starts_with(l.row_key, $4 || ':' || t.id::text || ':')) AS markers
           FROM public.${quote(relation)} t WHERE t.id::text = ANY($1::text[])`,
        [rows.map((row) => row.key), org, SECRET_MARKER, relation])).rows.map((row) => [row.id, row]));
      const moved: Array<[string, string]> = [];
      for (const row of rows) {
        const now = stored.get(row.key);
        const value = sent.get(row.key) ?? row.secret;
        if (!now?.value) continue;
        if (value !== null && now.value === value) {
          const key = `${relation}:${row.key}:${now.digest}`;
          if (now.markers.length !== 1 || now.markers[0] !== key) moved.push([row.key, key]);
        } else {
          report.warnings[`${table}_secret_kept`] = (report.warnings[`${table}_secret_kept`] ?? 0) + 1;
        }
      }
      if (!moved.length) return;
      await tx.query(
        `DELETE FROM public.${IMPORT_LEDGER_TABLE} l USING unnest($3::text[], $4::text[]) AS u(id, k)
          WHERE l.organization_id = $1::uuid AND l.table_name = $2
            AND starts_with(l.row_key, $5 || ':' || u.id || ':') AND l.row_key <> u.k`,
        [org, SECRET_MARKER, moved.map(([id]) => id), moved.map(([, key]) => key), relation],
      );
      await tx.query(
        `INSERT INTO public.${IMPORT_LEDGER_TABLE} (organization_id, table_name, row_key, mapping_revision)
         SELECT $1::uuid, $2, k, $4 FROM unnest($3::text[]) AS u(k)
         ON CONFLICT (organization_id, table_name, row_key) DO NOTHING`,
        [org, SECRET_MARKER, moved.map(([, key]) => key), MAPPING_REVISION],
      );
    };
    // A credential new to Control enters inactive when its (workspace,
    // provider) already has an active row on the target (a copied or native
    // key Control selected): one LLM credential per group
    // (coding_agent_one_llm), and Control's selection stands. Counted.
    const keepActiveCredential = async (tx: SqlExecutor, rows: PreparedRow[]): Promise<PreparedRow[]> => {
      const incoming = rows.map((row) => ({ row, value: JSON.parse(row.row) as { workspace_id?: string; model_provider?: string; is_active?: boolean } }));
      const candidates = incoming.filter(({ value }) => value.is_active === true);
      if (!candidates.length) return rows;
      const existing = new Set((await tx.query<{ id: string }>(
        "SELECT id::text AS id FROM public.coding_agent_credentials WHERE id::text = ANY($1::text[])",
        [candidates.map(({ row }) => row.key)])).rows.map((row) => row.id));
      const fresh = candidates.filter(({ row }) => !existing.has(row.key));
      if (!fresh.length) return rows;
      const active = new Set((await tx.query<{ g: string }>(
        `SELECT workspace_id::text || '|' || model_provider AS g FROM public.coding_agent_credentials
          WHERE is_active AND workspace_id::text = ANY($1::text[])`,
        [[...new Set(fresh.map(({ value }) => String(value.workspace_id)))]])).rows.map((row) => row.g));
      const demote = new Set(fresh.filter(({ value }) => active.has(`${value.workspace_id}|${value.model_provider}`)).map(({ row }) => row));
      if (!demote.size) return rows;
      report.warnings.coding_agent_credentials_control_active_kept = (report.warnings.coding_agent_credentials_control_active_kept ?? 0) + demote.size;
      return rows.map((row) => demote.has(row)
        ? { ...row, override: JSON.stringify({ ...(row.override ? JSON.parse(row.override) as object : {}), is_active: false }) }
        : row);
    };
    // Target rows a re-run leaves bound as they are (keepTargetBinding),
    // counted so an operator sees them: a binding Cloud made after Control's
    // (binding_conflict), or Control's newer key generation (generation_kept).
    const countKeptBindings = async (
      tx: SqlExecutor, table: ImportTable, keep: { when: string; generation?: string }, rows: PreparedRow[],
    ) => {
      const generation = keep.generation && write[table]!.includes(keep.generation) ? keep.generation : null;
      const current = new Map((await tx.query<{ key: string; bound: string | null; generation: number | null }>(
        `SELECT id::text AS key, ${quote(keep.when)}::text AS bound, ${generation ? `${quote(generation)}::int` : "NULL::int"} AS generation
           FROM public.${quote(TARGETS[table].table)} WHERE id::text = ANY($1::text[])`,
        [rows.map((row) => row.key)],
      )).rows.map((row) => [row.key, row]));
      for (const row of rows) {
        const target = current.get(row.key);
        if (!target?.bound) continue;
        const incoming = JSON.parse(row.row) as Record<string, unknown>;
        const bound = incoming[keep.when];
        if (bound !== null && bound !== undefined && String(bound) !== target.bound) {
          report.warnings[`${table}_binding_conflict`] = (report.warnings[`${table}_binding_conflict`] ?? 0) + 1;
        } else if (bound !== null && bound !== undefined && generation && target.generation !== null
          && Number(incoming[generation]) < target.generation) {
          report.warnings[`${table}_generation_kept`] = (report.warnings[`${table}_generation_kept`] ?? 0) + 1;
        }
      }
    };
    const runOrg = async (tx: SqlExecutor, org: string) => {
      // The target ledger is the only record of what earlier runs wrote.
      const ledger = await tx.query<{ table_name: string; row_key: string }>(
        // Only the importer's own tables: the credential copier keeps its
        // markers here too (copier_login), and they must not make an org
        // look imported.
        `SELECT table_name, row_key FROM public.${IMPORT_LEDGER_TABLE}
          WHERE organization_id = $1 AND table_name = ANY($2::text[]) FOR UPDATE`,
        [org, [...ORG_TABLES]],
      );
      if (ledger.rows.length === 0) {
        // Never imported. An existing org with this id is Control's own:
        // refuse it rather than merging into it.
        const existing = await tx.query("SELECT 1 FROM public.organizations WHERE id = $1", [org]);
        if (existing.rows[0]) throw new OrgRefused("org_exists_without_ledger");
      }
      const before = new Map<string, string[]>();
      for (const row of ledger.rows) {
        if (!before.has(row.table_name)) before.set(row.table_name, []);
        before.get(row.table_name)!.push(row.row_key);
      }
      const keys = report.orgs[org]!.keys;
      // Deletes first: a replacement row (an invite re-sent to the same
      // email) must not collide with the row it replaces.
      for (const table of ORG_TABLES) {
        const now = new Set(keys[table] ?? []);
        const gone = (before.get(table) ?? []).filter((key) => !now.has(key));
        if (gone.length === 0) continue;
        if (!RECONCILED_TABLES.includes(table)) {
          // Kept in Control and in the ledger; an operator decides.
          report.warnings[`${table}_absent_in_source`] = (report.warnings[`${table}_absent_in_source`] ?? 0) + gone.length;
          continue;
        }
        // `deleted` counts logical removals: ledger keys reconciled away,
        // whether this DELETE or an earlier FK cascade in this transaction
        // (a removed membership takes its Desktop/fleet rows) removed them.
        await tx.query(deleteSql(table), [gone, org]);
        report.orgs[org]!.deleted[table] = gone.length;
        await tx.query(
          `DELETE FROM public.${IMPORT_LEDGER_TABLE} WHERE organization_id = $1 AND table_name = $2 AND row_key = ANY($3::text[])`,
          [org, table, gone],
        );
      }
      for (const table of ORG_TABLES) {
        const rows = prepared[table].filter((row) => row.org === org);
        const fresh = table === "staff_read_grants" && rows.length > 0
          ? await newKeys(tx, table, rows)
          : null;
        await writeRows(tx, table, rows);
        report.orgs[org]!.imported[table] = rows.length;
        // 0061: one audit row per grant, on its first import only.
        for (const row of rows) {
          if (!fresh?.has(row.key)) continue;
          const { workspace_id: workspaceId } = JSON.parse(row.row) as { workspace_id: string };
          await recordAudit(tx, {
            organizationId: org,
            workspaceId,
            actor: { kind: "service", subject: "cloud-import" },
            action: "staff_read_grant.imported",
            target: `${row.key} workspace ${workspaceId}`,
          });
        }
      }
      const tables = ORG_TABLES.flatMap((table) => (keys[table] ?? []).map(() => table));
      const rowKeys = ORG_TABLES.flatMap((table) => keys[table] ?? []);
      for (const batch of chunks(tables.map((table, index) => [table, rowKeys[index]!] as const), 1000)) {
        await tx.query(
          `INSERT INTO public.${IMPORT_LEDGER_TABLE} (organization_id, table_name, row_key, mapping_revision)
           SELECT $1, t, k, $4 FROM unnest($2::text[], $3::text[]) AS u(t, k)
           ON CONFLICT (organization_id, table_name, row_key)
           DO UPDATE SET mapping_revision = EXCLUDED.mapping_revision, imported_at = now()`,
          [org, batch.map(([table]) => table), batch.map(([, key]) => key), MAPPING_REVISION],
        );
      }
      // Which of this org's workspaces this run wrote unbound (see
      // UNBOUND_WORKSPACE_MARKER): exactly the current set, every run.
      const written = new Set(keys.workspaces ?? []);
      const unbound = prepared.workspaces
        .filter((row) => row.org === org && written.has(row.key) && (JSON.parse(row.row) as { relaycast_workspace_id?: unknown }).relaycast_workspace_id == null)
        .map((row) => row.key);
      await tx.query(
        `DELETE FROM public.${IMPORT_LEDGER_TABLE} WHERE organization_id = $1 AND table_name = $2 AND NOT (row_key = ANY($3::text[]))`,
        [org, UNBOUND_WORKSPACE_MARKER, unbound],
      );
      await tx.query(
        `INSERT INTO public.${IMPORT_LEDGER_TABLE} (organization_id, table_name, row_key, mapping_revision)
         SELECT $1, $2, k, $4 FROM unnest($3::text[]) AS u(k)
         ON CONFLICT (organization_id, table_name, row_key) DO UPDATE SET mapping_revision = EXCLUDED.mapping_revision`,
        [org, UNBOUND_WORKSPACE_MARKER, unbound, MAPPING_REVISION],
      );
    };
    const body = async (unit: (run: (tx: SqlExecutor) => Promise<void>) => Promise<void>) => {
      for (const batch of chunks(prepared.users, batchSize)) {
        await unit((tx) => writeRows(tx, "users", batch));
      }
      report.tables.users.imported = prepared.users.length;
      for (const org of orgIds) {
        try {
          await unit((tx) => runOrg(tx, org));
          report.orgs[org]!.status = "ok";
          for (const table of ORG_TABLES) {
            report.tables[table].imported += report.orgs[org]!.imported[table] ?? 0;
            report.tables[table].deleted += report.orgs[org]!.deleted[table] ?? 0;
          }
          log("cloud_import.org", { org, status: "ok" });
        } catch (error) {
          report.orgs[org] = { status: "failed", error: errorFields(error), imported: {}, keys: {}, deleted: {} };
          log("cloud_import.org", { org, status: "failed", ...errorFields(error) });
        }
      }
      await unit(async (tx) => {
        for (const batch of chunks(prepared.users, batchSize)) {
          await tx.query(USERS_LAST_SQL, [batch.map((row) => row.row)]);
        }
      });
    };

    if (mode === "apply") {
      await body((run) => target.transaction(run));
    } else {
      try {
        await target.transaction(async (outer) => {
          let savepoint = 0;
          await body(async (run) => {
            const name = `cloud_import_${++savepoint}`;
            await outer.exec(`SAVEPOINT ${name}`);
            try {
              await run(outer);
              await outer.exec(`RELEASE SAVEPOINT ${name}`);
            } catch (error) {
              await outer.exec(`ROLLBACK TO SAVEPOINT ${name}`);
              throw error;
            }
          });
          throw new DryRunRollback();
        });
      } catch (error) {
        if (!(error instanceof DryRunRollback)) throw error;
      }
    }
    report.ok = Object.values(report.orgs).every((org) => org.status === "ok");
  } catch (error) {
    if (!(error instanceof ImportRefused)) throw error;
    report.refused = error.reason;
    report.ok = false;
  }
  report.finishedAt = now().toISOString();
  log("cloud_import.done", { mode, ok: report.ok, refused: report.refused, tables: summary(report) });
  return report;
}

function summary(report: ImportReport): Record<string, unknown> {
  return Object.fromEntries(Object.entries(report.tables).map(([table, ledger]) => [table, {
    candidates: ledger.candidates,
    imported: ledger.imported,
    skipped: ledger.skipped,
  }]));
}
