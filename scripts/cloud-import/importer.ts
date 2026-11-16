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
import { createDecipheriv } from "node:crypto";
import { encryptSecret, hashSecret, opaqueToken, type EncryptionKeyring } from "../../src/crypto.js";
import type { Database, SqlExecutor } from "../../src/database.js";
import {
  MAPPING_REVISION,
  ORG_TABLES,
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
  /** Cloud CREDENTIAL_ENCRYPTION_KEY, 64 hex characters. */
  cloudKeyHex: string;
  log?: ImportLogger;
  now?: () => Date;
  /** Rows per insert statement. */
  batchSize?: number;
};

export type TableLedger = {
  candidates: number;
  imported: number;
  skipped: Record<string, number>;
  /**
   * Row keys skipped by the importer itself (not by the mapping's SQL), so a
   * verifier can reconcile them: ids are Cloud UUIDs, never emails or values.
   */
  importerSkips: Record<string, string[]>;
};

export type OrgLedger = {
  status: "ok" | "failed" | "planned";
  /** SQLSTATE and constraint name only; never the driver message. */
  error?: { code: string; constraint?: string; table?: string };
  imported: Partial<Record<ImportTable, number>>;
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
};

type PreparedRow = { key: string; org: string | null; email: string | null; row: string; secret: string | null; flags: string[] | null };

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
    `SELECT ${table === "organization_memberships" ? "q.organization_id::text || ':' || q.user_id::text" : "q.id::text"} AS key,
            q.skip_reason AS skip,
            ${table === "users" ? "NULL::text" : "q.organization_id::text"} AS org,
            ${email} AS email,
            ${secret === "secret_plaintext" ? "q.secret_plaintext" : secret === "secret_envelope" ? "q.secret_envelope::text" : "NULL::text"} AS secret,
            ${ROW_FLAGS[table] ?? "NULL::text[]"} AS flags,
            (to_jsonb(q) - 'skip_reason' - 'secret_plaintext' - 'secret_envelope' - 'cloud_user_id')::text AS row
       FROM (${sourceQuery(table, scope)}) q`,
  );
  return result.rows;
}

const ROW_FLAGS: Partial<Record<ImportTable, string>> = {
  workspaces: `array_remove(ARRAY[
      CASE WHEN q.cloud_relay_workspace_id IS NULL THEN 'workspace_rw_id_not_rw_8hex' END,
      CASE WHEN q.has_dashboard_url THEN 'relayhistory_dashboard_url_dropped' END,
      CASE WHEN q.relayhistory_origin IS NOT NULL THEN 'relayhistory_origin_set' END,
      CASE WHEN q.origin_invalid THEN 'relayhistory_origin_invalid_dropped' END
    ], NULL)`,
  desktop_relay_identities: `CASE WHEN NOT q.source_id_is_uuid THEN ARRAY['source_id_not_uuid'] END`,
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

function writeColumns(table: ImportTable, columns: TargetColumns): string[] {
  const spec = TARGETS[table];
  const present = columns.get(spec.table) ?? new Map<string, ColumnInfo>();
  const list = [...spec.columns, ...(spec.optional ?? []).filter((column) => present.has(column))];
  if (spec.secret) list.push(spec.secret.target);
  if (spec.inviteTokenHash) list.push(spec.inviteTokenHash);
  const missing = list.filter((column) => !present.has(column));
  if (missing.length) throw new ImportRefused(`target_missing_columns:${spec.table}`);
  return list;
}

function upsertSql(table: ImportTable, columns: string[], fill = "'{}'::jsonb"): string {
  const spec = TARGETS[table];
  const secretColumn = spec.secret?.target ?? spec.inviteTokenHash;
  const relation = `public.${quote(spec.table)}`;
  const updates = columns
    .filter((column) => !spec.primaryKey.includes(column) && !(spec.insertOnly ?? []).includes(column))
    .map((column) => `${quote(column)} = EXCLUDED.${quote(column)}`);
  return `INSERT INTO ${relation} (${columns.map(quote).join(", ")})
SELECT ${columns.map((column) => `p.${quote(column)}`).join(", ")}
  FROM unnest($1::text[], $2::text[]) AS u(r, s)
 CROSS JOIN LATERAL jsonb_populate_record(
   NULL::${relation},
   u.r::jsonb || ${fill} || ${secretColumn ? `CASE WHEN u.s IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('${secretColumn}', u.s) END` : "'{}'::jsonb"}
 ) AS p
ON CONFLICT (${spec.primaryKey.map(quote).join(", ")}) DO ${updates.length ? `UPDATE SET ${updates.join(", ")}` : "NOTHING"}`;
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

export async function runImport(deps: ImportDeps, scope: ImportScope, mode: ImportMode): Promise<ImportReport> {
  assertScope(scope);
  const now = deps.now ?? (() => new Date());
  const log: ImportLogger = deps.log ?? (() => {});
  const batchSize = deps.batchSize ?? 250;
  const startedAt = now().toISOString();
  const report: ImportReport = {
    version: 1,
    mappingRevision: MAPPING_REVISION,
    mode,
    scope: { orgIds: scope.orgIds === null ? null : [...scope.orgIds] },
    startedAt,
    finishedAt: startedAt,
    ok: false,
    tables: Object.fromEntries(SOURCE_TABLES.map((table) => [table, { candidates: 0, imported: 0, skipped: {}, importerSkips: {} }])) as Record<ImportTable, TableLedger>,
    orgs: {},
    optionalColumns: [],
    warnings: {},
  };
  const skip = (table: ImportTable, reason: string, key?: string) => {
    const ledger = report.tables[table];
    ledger.skipped[reason] = (ledger.skipped[reason] ?? 0) + 1;
    if (key !== undefined) (ledger.importerSkips[reason] ??= []).push(key);
  };
  const warn = (name: string) => {
    report.warnings[name] = (report.warnings[name] ?? 0) + 1;
  };

  // 1. Read and transform. Nothing is written before every row is prepared.
  const prepared = {} as Record<ImportTable, PreparedRow[]>;
  await deps.source.transaction(async (tx) => {
    await tx.exec("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY");
    for (const table of SOURCE_TABLES) {
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
          if (spec.secret?.source === "secret_plaintext") {
            secret = encryptSecret(row.secret ?? "", deps.keyring.active);
          } else if (spec.secret?.source === "secret_envelope") {
            const plaintext = decryptCloudEnvelope(JSON.parse(row.secret ?? "null") as EncryptedEnvelope, deps.cloudKeyHex);
            secret = encryptSecret(plaintext, deps.keyring.active);
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
        for (const flag of row.flags ?? []) if (flag !== "source_id_not_uuid") warn(flag);
        kept.push({ key: row.key, org: row.org, email: row.email, row: row.row, secret, flags: row.flags });
      }
      prepared[table] = kept;
    }
  });

  const orgIds = [...new Set(prepared.organizations.map((row) => row.org!))].sort();
  for (const org of orgIds) report.orgs[org] = { status: "planned", imported: {} };

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
    const write = Object.fromEntries(SOURCE_TABLES.map((table) => [table, writeColumns(table, columns)])) as Record<ImportTable, string[]>;
    // Before 0057 the target source_id is uuid: a Cloud text id cannot land.
    if (columns.get("desktop_relay_identities")?.get("source_id")?.udt === "uuid") {
      prepared.desktop_relay_identities = prepared.desktop_relay_identities.filter((row) => {
        if (!row.flags?.includes("source_id_not_uuid")) return true;
        skip("desktop_relay_identities", "source_id_not_uuid", row.key);
        return false;
      });
    }
    // Before 0057 node_name is NOT NULL: the node id stands in.
    const fills: Partial<Record<ImportTable, string>> = {};
    if (columns.get("fleet_node_owners")?.get("node_name")?.nullable === false) {
      fills.fleet_node_owners = "jsonb_build_object('node_name', u.r::jsonb ->> 'node_id')";
      warn("fleet_node_name_filled_with_node_id");
    }
    report.optionalColumns = SOURCE_TABLES.flatMap((table) =>
      (TARGETS[table].optional ?? []).filter((column) => write[table].includes(column)).map((column) => `${TARGETS[table].table}.${column}`));

    // A Control user that already owns an imported email under another id
    // would make the upsert fail mid-way; refuse up front instead.
    const conflicts = await target.query<{ n: string }>(
      `SELECT count(*)::text AS n FROM public.users t
         JOIN unnest($1::text[]) AS x(r) ON (x.r::jsonb ->> 'email') = t.email
        WHERE t.id::text <> (x.r::jsonb ->> 'id')`,
      [prepared.users.map((row) => row.row)],
    );
    if (Number(conflicts.rows[0]?.n ?? 0) > 0) {
      report.tables.users.skipped.target_email_conflict = Number(conflicts.rows[0]!.n);
      throw new ImportRefused("target_email_conflict");
    }

    // 3. Write. apply: users in batches, then one transaction per org.
    //    dry-run: the same units as savepoints inside one transaction that is
    //    rolled back at the end.
    const writeRows = async (tx: SqlExecutor, table: ImportTable, rows: PreparedRow[]) => {
      const sql = upsertSql(table, write[table], fills[table]);
      for (const batch of chunks(rows, batchSize)) {
        await tx.query(sql, [batch.map((row) => row.row), batch.map((row) => row.secret)]);
      }
    };
    const runOrg = async (tx: SqlExecutor, org: string) => {
      for (const table of ORG_TABLES) {
        const rows = prepared[table].filter((row) => row.org === org);
        await writeRows(tx, table, rows);
        report.orgs[org]!.imported[table] = rows.length;
      }
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
          for (const table of ORG_TABLES) report.tables[table].imported += report.orgs[org]!.imported[table] ?? 0;
          log("cloud_import.org", { org, status: "ok" });
        } catch (error) {
          report.orgs[org] = { status: "failed", error: errorFields(error), imported: {} };
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
