import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { CONTROL_SEQUENCES, CONTROL_TABLES } from "./control-tables.js";
import type { Database, SqlExecutor } from "./database.js";

const LEGACY_MIGRATION_LEDGER = "selfhost_schema_migrations";
const MIGRATION_LEDGER = "control_schema_migrations";

type AppliedMigration = {
  name: string;
  checksum: string;
};

export function defaultMigrationsDirectory(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), "../migrations");
}

function quoteIdentifier(value: string): string {
  if (
    !/^[A-Za-z_][A-Za-z0-9_$]{0,62}$/.test(value) ||
    value.toLowerCase() === "public"
  ) {
    throw new Error("Invalid runtime PostgreSQL role name");
  }
  return `"${value.replaceAll('"', '""')}"`;
}

export async function grantRuntimeDatabaseRole(
  database: Database,
  runtimeRole: string,
): Promise<void> {
  const role = quoteIdentifier(runtimeRole);
  await database.transaction(async (transaction) => {
    const current = await transaction.query<{ current_user: string }>(
      "SELECT current_user AS current_user",
    );
    if (current.rows[0]?.current_user === runtimeRole) {
      throw new Error("Migration and runtime database roles must be distinct");
    }

    const schemaPrivileges = await transaction.query<{ can_create: boolean }>(
      "SELECT has_schema_privilege($1, 'public', 'CREATE') AS can_create",
      [runtimeRole],
    );
    if (schemaPrivileges.rows[0]?.can_create === true) {
      throw new Error("Runtime database role must not have schema CREATE privilege");
    }

    await transaction.exec(`GRANT USAGE ON SCHEMA public TO ${role}`);
    await transaction.exec(
      `REVOKE ALL PRIVILEGES ON TABLE public.control_schema_migrations FROM ${role}`,
    );
    const migrationPrivileges = await transaction.query<{ can_migrate: boolean }>(
      `SELECT
         has_table_privilege($1, 'public.control_schema_migrations', 'SELECT')
         OR has_table_privilege($1, 'public.control_schema_migrations', 'INSERT')
         OR has_table_privilege($1, 'public.control_schema_migrations', 'UPDATE')
         OR has_table_privilege($1, 'public.control_schema_migrations', 'DELETE')
         OR has_table_privilege($1, 'public.control_schema_migrations', 'TRUNCATE')
         OR has_table_privilege($1, 'public.control_schema_migrations', 'REFERENCES')
         OR has_table_privilege($1, 'public.control_schema_migrations', 'TRIGGER')
         AS can_migrate`,
      [runtimeRole],
    );
    if (migrationPrivileges.rows[0]?.can_migrate === true) {
      throw new Error("Runtime database role must not inherit migration table privileges");
    }

    const tables = await transaction.query<{ tablename: string }>(
      `SELECT tablename
         FROM pg_tables
        WHERE schemaname = 'public'
          AND tablename = ANY($1::text[])`,
      [CONTROL_TABLES],
    );
    for (const { tablename } of tables.rows) {
      await transaction.exec(
        `GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.${quoteIdentifier(tablename)} TO ${role}`,
      );
    }
    const sequences = await transaction.query<{ sequencename: string }>(
      `SELECT sequencename
         FROM pg_sequences
        WHERE schemaname = 'public'
          AND sequencename = ANY($1::text[])`,
      [CONTROL_SEQUENCES],
    );
    for (const { sequencename } of sequences.rows) {
      await transaction.exec(
        `GRANT USAGE, SELECT, UPDATE ON SEQUENCE public.${quoteIdentifier(sequencename)} TO ${role}`,
      );
    }
  });
}

// An install from before migration 0033 records its history under the old
// ledger name. The ledger must move first because the runner reads it to decide
// what to apply. This runs in the migration transaction, so it rolls back too.
async function adoptLegacyMigrationLedger(transaction: SqlExecutor): Promise<void> {
  const ledgers = await transaction.query<{ legacy: boolean; current: boolean }>(
    `SELECT
       to_regclass(format('%I.%I', current_schema(), $1::text)) IS NOT NULL AS legacy,
       to_regclass(format('%I.%I', current_schema(), $2::text)) IS NOT NULL AS current`,
    [LEGACY_MIGRATION_LEDGER, MIGRATION_LEDGER],
  );
  if (ledgers.rows[0]?.legacy !== true) {
    return;
  }
  if (ledgers.rows[0]?.current === true) {
    throw new Error(
      `Both ${LEGACY_MIGRATION_LEDGER} and ${MIGRATION_LEDGER} exist; an older image probably ran migrations against this database`,
    );
  }
  await transaction.exec(`ALTER TABLE ${LEGACY_MIGRATION_LEDGER} RENAME TO ${MIGRATION_LEDGER}`);
  await transaction.exec(
    `ALTER TABLE ${MIGRATION_LEDGER} RENAME CONSTRAINT ${LEGACY_MIGRATION_LEDGER}_pkey TO ${MIGRATION_LEDGER}_pkey`,
  );
}

export async function migrate(
  database: Database,
  directory = defaultMigrationsDirectory(),
): Promise<string[]> {
  const files = (await readdir(directory))
    .filter((name) => /^\d+.*\.sql$/.test(name))
    .sort();
  const migrations = await Promise.all(files.map(async (name) => {
    const sql = await readFile(join(directory, name), "utf8");
    return {
      name,
      sql,
      checksum: createHash("sha256").update(sql).digest("hex"),
    };
  }));
  const applied: string[] = [];

  await database.transaction(async (transaction) => {
    // Serializes startup jobs without requiring an extension or an external lock.
    await transaction.query("SELECT pg_advisory_xact_lock(1947182641)");
    await adoptLegacyMigrationLedger(transaction);
    await transaction.query(`
      CREATE TABLE IF NOT EXISTS control_schema_migrations (
        name text PRIMARY KEY,
        checksum text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);

    for (const migration of migrations) {
      const existing = await transaction.query<AppliedMigration>(
        "SELECT name, checksum FROM control_schema_migrations WHERE name = $1",
        [migration.name],
      );
      if (existing.rows[0]) {
        if (existing.rows[0].checksum !== migration.checksum) {
          throw new Error(`Applied migration ${migration.name} has changed`);
        }
        continue;
      }

      await transaction.exec(migration.sql);
      await transaction.query(
        "INSERT INTO control_schema_migrations (name, checksum) VALUES ($1, $2)",
        [migration.name, migration.checksum],
      );
      applied.push(migration.name);
    }
  });

  return applied;
}
