import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { CONTROL_SEQUENCES, CONTROL_TABLES } from "../src/control-tables.js";
import type { Database, SqlExecutor, SqlResult } from "../src/database.js";
import { defaultMigrationsDirectory, grantRuntimeDatabaseRole, migrate } from "../src/migrations.js";
import { PGliteDatabase } from "./support/harness.js";

class RecordingDatabase implements Database {
  readonly statements: string[] = [];
  transactions = 0;

  constructor(
    readonly currentUser = "selfhost_migrations",
    readonly canCreateSchema = false,
    readonly canMigrate = false,
  ) {}

  async query<T extends Record<string, unknown>>(
    sql: string,
    _params: unknown[] = [],
  ): Promise<SqlResult<T>> {
    this.statements.push(sql);
    if (sql.includes("current_user")) {
      return { rows: [{ current_user: this.currentUser }] as unknown as T[] };
    }
    if (sql.includes("has_schema_privilege")) {
      return { rows: [{ can_create: this.canCreateSchema }] as unknown as T[] };
    }
    if (sql.includes("has_table_privilege")) {
      return { rows: [{ can_migrate: this.canMigrate }] as unknown as T[] };
    }
    if (sql.includes("FROM pg_tables")) {
      return {
        rows: [
          { tablename: "users" },
          { tablename: "token_sessions" },
        ] as unknown as T[],
      };
    }
    if (sql.includes("FROM pg_sequences")) {
      return {
        rows: [{ sequencename: "example_seq" }] as unknown as T[],
      };
    }
    return { rows: [] };
  }

  async exec(sql: string): Promise<void> {
    this.statements.push(sql);
  }

  async transaction<T>(run: (transaction: SqlExecutor) => Promise<T>): Promise<T> {
    this.transactions += 1;
    return run(this);
  }

  async close(): Promise<void> {}
}

test("runtime role grants exclude migration metadata and schema creation", async () => {
  const database = new RecordingDatabase();
  await grantRuntimeDatabaseRole(database, "selfhost_runtime");

  assert.equal(database.transactions, 1);
  assert(database.statements.some((sql) =>
    sql === 'GRANT USAGE ON SCHEMA public TO "selfhost_runtime"'
  ));
  assert(database.statements.some((sql) =>
    sql ===
      'REVOKE ALL PRIVILEGES ON TABLE public.control_schema_migrations FROM "selfhost_runtime"'
  ));
  assert(database.statements.some((sql) =>
    sql.includes(
      'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public."users" TO "selfhost_runtime"',
    )
  ));
  assert(database.statements.some((sql) =>
    sql.includes(
      'GRANT USAGE, SELECT, UPDATE ON SEQUENCE public."example_seq" TO "selfhost_runtime"',
    )
  ));
  assert(!database.statements.some((sql) => /GRANT CREATE/i.test(sql)));
  assert(!database.statements.some((sql) =>
    /GRANT .*control_schema_migrations/i.test(sql)
  ));
});

test("migration owner cannot also be the runtime role", async () => {
  const database = new RecordingDatabase("selfhost_runtime");
  await assert.rejects(
    grantRuntimeDatabaseRole(database, "selfhost_runtime"),
    /must be distinct/,
  );
  assert.equal(
    database.statements.filter((sql) => /^(?:GRANT|REVOKE)/.test(sql)).length,
    0,
  );
});

test("runtime role cannot inherit schema creation or migration privileges", async () => {
  await assert.rejects(
    grantRuntimeDatabaseRole(
      new RecordingDatabase("selfhost_migrations", true),
      "selfhost_runtime",
    ),
    /schema CREATE privilege/,
  );
  await assert.rejects(
    grantRuntimeDatabaseRole(
      new RecordingDatabase("selfhost_migrations", false, true),
      "selfhost_runtime",
    ),
    /inherit migration table privileges/,
  );
});

test("runtime role identifiers are rejected before database access", async () => {
  const database = new RecordingDatabase();
  for (const role of ["PUBLIC", "runtime-role", 'runtime"; DROP ROLE owner; --']) {
    await assert.rejects(
      grantRuntimeDatabaseRole(database, role),
      /Invalid runtime PostgreSQL role name/,
    );
  }
  assert.equal(database.transactions, 0);
});

const RENAME_MIGRATION = "0033_drop_selfhost_table_prefix.sql";
const PRIOR_LEDGER = "selfhost_schema_migrations";
const LEDGER = "control_schema_migrations";

async function schemaObjects(database: PGliteDatabase): Promise<{ tables: string[]; other: string[] }> {
  const tables = await database.query<{ name: string }>(
    "SELECT tablename AS name FROM pg_tables WHERE schemaname = 'public' ORDER BY 1",
  );
  const other = await database.query<{ name: string }>(
    `SELECT relname AS name FROM pg_class
      WHERE relnamespace = 'public'::regnamespace AND relkind IN ('i', 'S')
     UNION ALL
     SELECT conname FROM pg_constraint WHERE connamespace = 'public'::regnamespace
     ORDER BY 1`,
  );
  return { tables: tables.rows.map((row) => row.name), other: other.rows.map((row) => row.name) };
}

/** Builds the schema exactly as the runner shipped before migration 0033 left it. */
async function databaseAtPriorSchema(): Promise<PGliteDatabase> {
  const database = new PGliteDatabase();
  const directory = defaultMigrationsDirectory();
  await database.exec(`CREATE TABLE ${PRIOR_LEDGER} (
    name text PRIMARY KEY,
    checksum text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
  )`);
  const names = (await readdir(directory)).filter((name) => /^\d+.*\.sql$/.test(name)).sort();
  for (const name of names.filter((candidate) => candidate < RENAME_MIGRATION)) {
    const sql = await readFile(join(directory, name), "utf8");
    await database.exec(sql);
    await database.query(`INSERT INTO ${PRIOR_LEDGER} (name, checksum) VALUES ($1, $2)`, [
      name,
      createHash("sha256").update(sql).digest("hex"),
    ]);
  }
  return database;
}

/** The migrations shipped after the rename, in the order the runner applies them. */
async function migrationsAfterRename(): Promise<Array<{ name: string; sql: string }>> {
  const directory = defaultMigrationsDirectory();
  const names = (await readdir(directory))
    .filter((name) => /^\d+.*\.sql$/.test(name) && name > RENAME_MIGRATION)
    .sort();
  return Promise.all(names.map(async (name) => ({ name, sql: await readFile(join(directory, name), "utf8") })));
}

/** Inserts one type-derived row per table, skipping tables whose CHECKs reject it. */
async function seedPriorSchema(database: PGliteDatabase): Promise<number> {
  await database.exec("SET session_replication_role = replica");
  const { tables } = await schemaObjects(database);
  let seeded = 0;
  for (const table of tables.filter((name) => name !== PRIOR_LEDGER)) {
    const columns = await database.query<{ column_name: string; data_type: string; is_nullable: string; column_default: string | null }>(
      `SELECT column_name, data_type, is_nullable, column_default
         FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = $1 ORDER BY ordinal_position`,
      [table],
    );
    const required = columns.rows.filter((column) => column.is_nullable === "NO" && column.column_default === null);
    const value = (type: string): string => {
      if (type === "uuid") return "gen_random_uuid()";
      if (type.includes("timestamp")) return "now()";
      if (type === "boolean") return "true";
      if (type.includes("int") || type === "numeric") return "1";
      if (type === "jsonb" || type === "json") return "'{}'";
      if (type === "bytea") return "'\\x00'";
      if (type === "ARRAY") return "'{}'";
      return "'a'";
    };
    const statement = required.length === 0
      ? `INSERT INTO ${table} DEFAULT VALUES`
      : `INSERT INTO ${table} (${required.map((column) => `"${column.column_name}"`).join(", ")})
         VALUES (${required.map((column) => value(column.data_type)).join(", ")})`;
    try {
      await database.exec(statement);
      seeded += 1;
    } catch {
      // A CHECK constraint rejected the generic value; the table stays empty.
    }
  }
  await database.exec("SET session_replication_role = origin");
  return seeded;
}

async function rowCounts(database: PGliteDatabase, tables: string[]): Promise<Map<string, number>> {
  const counts = new Map<string, number>();
  for (const table of tables) {
    const result = await database.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${table}`);
    counts.set(table, result.rows[0]!.n);
  }
  return counts;
}

function renamedTable(table: string): string {
  return table === PRIOR_LEDGER ? LEDGER : table.replace(/^selfhost_/, "");
}

test("an install at the previous schema upgrades in place with row counts unchanged", async (t) => {
  const database = await databaseAtPriorSchema();
  t.after(() => database.close());
  const seeded = await seedPriorSchema(database);
  assert.ok(seeded >= 40, `expected a broad sample, seeded ${seeded} tables`);
  await database.query("SELECT nextval('selfhost_desktop_feed_publish_seq')");
  await database.query("SELECT nextval('selfhost_desktop_feed_publish_seq')");

  const before = await schemaObjects(database);
  const beforeCounts = await rowCounts(database, before.tables);

  // The rename runs first; later migrations apply after it in the same pass.
  const later = await migrationsAfterRename();
  assert.deepEqual(await migrate(database), [RENAME_MIGRATION, ...later.map((migration) => migration.name)]);
  assert.deepEqual(await migrate(database), []);

  const after = await schemaObjects(database);
  const renamed = before.tables.map(renamedTable).sort();
  assert.deepEqual(after.tables.filter((table) => renamed.includes(table)), renamed);
  // Any other table is one a migration after the rename creates.
  for (const table of after.tables.filter((name) => !renamed.includes(name))) {
    assert.ok(
      later.some((migration) => new RegExp(`CREATE TABLE (IF NOT EXISTS )?${table}\\b`).test(migration.sql)),
      `${table} appeared without a later migration creating it`,
    );
  }
  assert.deepEqual([...after.tables, ...after.other].filter((name) => name.startsWith("selfhost_")), []);
  const afterCounts = await rowCounts(database, after.tables);
  for (const [table, count] of beforeCounts) {
    // The ledger gains exactly the rows that record the migrations just applied.
    const expected = table === PRIOR_LEDGER ? count + 1 + later.length : count;
    assert.equal(afterCounts.get(renamedTable(table)), expected, `row count changed for ${table}`);
  }
  const sequence = await database.query<{ value: string }>("SELECT nextval('desktop_feed_publish_seq')::text AS value");
  assert.equal(sequence.rows[0]!.value, "3");
});

test("the upgraded and freshly migrated schemas have identical object names", async (t) => {
  const upgraded = await databaseAtPriorSchema();
  t.after(() => upgraded.close());
  await migrate(upgraded);
  const fresh = new PGliteDatabase();
  t.after(() => fresh.close());
  await migrate(fresh);
  assert.deepEqual(await schemaObjects(fresh), await schemaObjects(upgraded));
});

test("a table already using a target name aborts the rename without a partial move", async (t) => {
  const database = await databaseAtPriorSchema();
  t.after(() => database.close());
  await database.exec("CREATE TABLE users (id integer)");
  const before = await schemaObjects(database);
  await assert.rejects(migrate(database), /already exists/);
  assert.deepEqual(await schemaObjects(database), before);
});

test("migrate refuses a database holding both migration ledgers", async (t) => {
  const database = await databaseAtPriorSchema();
  t.after(() => database.close());
  await database.exec(`CREATE TABLE ${LEDGER} (name text PRIMARY KEY)`);
  await assert.rejects(migrate(database), /Both selfhost_schema_migrations and control_schema_migrations exist/);
});

test("runtime grant lists cover every table and sequence the migrations create", async (t) => {
  const database = new PGliteDatabase();
  t.after(() => database.close());
  await migrate(database);
  const { tables } = await schemaObjects(database);
  assert.deepEqual([...CONTROL_TABLES].sort(), tables.filter((name) => name !== LEDGER).sort());
  const sequences = await database.query<{ name: string }>(
    "SELECT sequencename AS name FROM pg_sequences WHERE schemaname = 'public' ORDER BY 1",
  );
  assert.deepEqual([...CONTROL_SEQUENCES].sort(), sequences.rows.map((row) => row.name));
});
