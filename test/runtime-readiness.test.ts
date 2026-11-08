import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { PGlite } from "@electric-sql/pglite";
import type { Database, SqlExecutor, SqlResult } from "../src/database.js";
import { grantRuntimeDatabaseRole, migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";

class RoleDatabase implements Database {
  readonly client = new PGlite();

  async query<T extends Record<string, unknown>>(sql: string, params: unknown[] = []): Promise<SqlResult<T>> {
    const result = await this.client.query<T>(sql, params);
    return { rows: result.rows };
  }

  async transaction<T>(run: (transaction: SqlExecutor) => Promise<T>): Promise<T> {
    return this.client.transaction(async (transaction) => run({
      query: async <R extends Record<string, unknown>>(sql: string, params: unknown[] = []) => {
        const result = await transaction.query<R>(sql, params);
        return { rows: result.rows };
      },
      exec: async (sql: string) => { await transaction.exec(sql); },
    }));
  }

  async close(): Promise<void> { await this.client.close(); }
  async exec(sql: string): Promise<void> { await this.client.exec(sql); }
}

const keyring = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const role = "readiness_runtime";

async function runtime(t: TestContext, options: { missingColumn?: boolean; organizations?: number } = {}) {
  const database = new RoleDatabase();
  t.after(async () => {
    try { await database.exec("RESET ROLE"); } finally { await database.close(); }
  });
  await migrate(database);
  if (options.missingColumn) {
    await database.exec("ALTER TABLE selfhost_users DROP COLUMN last_workspace_id");
  }
  for (let n = 0; n < (options.organizations ?? 0); n += 1) {
    await database.query(
      "INSERT INTO selfhost_organizations(id,name) VALUES($1,$2)",
      [`00000000-0000-4000-8000-${String(n + 1).padStart(12, "0")}`, `Fixture ${n + 1}`],
    );
  }
  await database.exec(`CREATE ROLE ${role} LOGIN NOINHERIT`);
  await grantRuntimeDatabaseRole(database, role);
  await database.exec(`SET ROLE ${role}`);
  return database;
}

test("a runtime role is ready without permission to read migration metadata", async (t) => {
  const database = await runtime(t);
  assert.equal((await database.query<{ current_user: string }>("SELECT current_user")).rows[0]?.current_user, role);
  await assert.rejects(database.query("SELECT name FROM selfhost_schema_migrations"),
    (error: unknown) => error instanceof Error && "code" in error && error.code === "42501");
  assert.deepEqual(await new ControlPlaneStore(database, keyring).readiness(), { ready: true });
});

test("readiness refuses an incomplete multi-tenant schema for the runtime role", async (t) => {
  const database = await runtime(t, { missingColumn: true });
  assert.deepEqual(await new ControlPlaneStore(database, keyring).readiness(), {
    ready: false, reason: "schema", message: "Database migrations are not applied",
  });
});

test("runtime readiness keeps single versus multi organization checks", async (t) => {
  const database = await runtime(t, { organizations: 2 });
  const single = new ControlPlaneStore(database, keyring, 0, { tenancy: "single" });
  const multi = new ControlPlaneStore(database, keyring, 0, { tenancy: "multi" });
  const refused = await single.readiness();
  assert.equal(refused.ready, false);
  assert.equal(!refused.ready && refused.reason, "tenancy_mismatch");
  assert.deepEqual(await multi.readiness(), { ready: true });
});
