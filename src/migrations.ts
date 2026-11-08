import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import type { Database } from "./database.js";

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
      `REVOKE ALL PRIVILEGES ON TABLE public.selfhost_schema_migrations FROM ${role}`,
    );
    const migrationPrivileges = await transaction.query<{ can_migrate: boolean }>(
      `SELECT
         has_table_privilege($1, 'public.selfhost_schema_migrations', 'SELECT')
         OR has_table_privilege($1, 'public.selfhost_schema_migrations', 'INSERT')
         OR has_table_privilege($1, 'public.selfhost_schema_migrations', 'UPDATE')
         OR has_table_privilege($1, 'public.selfhost_schema_migrations', 'DELETE')
         OR has_table_privilege($1, 'public.selfhost_schema_migrations', 'TRUNCATE')
         OR has_table_privilege($1, 'public.selfhost_schema_migrations', 'REFERENCES')
         OR has_table_privilege($1, 'public.selfhost_schema_migrations', 'TRIGGER')
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
          AND tablename LIKE 'selfhost\\_%' ESCAPE '\\'
          AND tablename <> 'selfhost_schema_migrations'`,
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
          AND sequencename LIKE 'selfhost\\_%' ESCAPE '\\'`,
    );
    for (const { sequencename } of sequences.rows) {
      await transaction.exec(
        `GRANT USAGE, SELECT, UPDATE ON SEQUENCE public.${quoteIdentifier(sequencename)} TO ${role}`,
      );
    }
  });
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
    await transaction.query(`
      CREATE TABLE IF NOT EXISTS selfhost_schema_migrations (
        name text PRIMARY KEY,
        checksum text NOT NULL,
        applied_at timestamptz NOT NULL DEFAULT now()
      )
    `);

    for (const migration of migrations) {
      const existing = await transaction.query<AppliedMigration>(
        "SELECT name, checksum FROM selfhost_schema_migrations WHERE name = $1",
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
        "INSERT INTO selfhost_schema_migrations (name, checksum) VALUES ($1, $2)",
        [migration.name, migration.checksum],
      );
      applied.push(migration.name);
    }
  });

  return applied;
}
