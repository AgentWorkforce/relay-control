import assert from "node:assert/strict";
import test from "node:test";
import type { Database, SqlExecutor, SqlResult } from "../src/database.js";
import { grantRuntimeDatabaseRole } from "../src/migrations.js";

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
          { tablename: "selfhost_users" },
          { tablename: "selfhost_token_sessions" },
        ] as unknown as T[],
      };
    }
    if (sql.includes("FROM pg_sequences")) {
      return {
        rows: [{ sequencename: "selfhost_example_seq" }] as unknown as T[],
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
      'REVOKE ALL PRIVILEGES ON TABLE public.selfhost_schema_migrations FROM "selfhost_runtime"'
  ));
  assert(database.statements.some((sql) =>
    sql.includes(
      'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public."selfhost_users" TO "selfhost_runtime"',
    )
  ));
  assert(database.statements.some((sql) =>
    sql.includes(
      'GRANT USAGE, SELECT, UPDATE ON SEQUENCE public."selfhost_example_seq" TO "selfhost_runtime"',
    )
  ));
  assert(!database.statements.some((sql) => /GRANT CREATE/i.test(sql)));
  assert(!database.statements.some((sql) =>
    /GRANT .*selfhost_schema_migrations/i.test(sql)
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
