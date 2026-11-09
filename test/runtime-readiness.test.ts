import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { grantRuntimeDatabaseRole, migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { PGliteDatabase } from "./support/harness.js";

const keyring = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const role = "readiness_runtime";

async function runtime(t: TestContext, options: { missingColumn?: boolean; organizations?: number } = {}) {
  const database = new PGliteDatabase();
  t.after(async () => {
    try { await database.exec("RESET ROLE"); } finally { await database.close(); }
  });
  await migrate(database);
  if (options.missingColumn) {
    await database.exec("ALTER TABLE users DROP COLUMN last_workspace_id");
  }
  for (let n = 0; n < (options.organizations ?? 0); n += 1) {
    await database.query(
      "INSERT INTO organizations(id,name) VALUES($1,$2)",
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
  await assert.rejects(database.query("SELECT name FROM control_schema_migrations"),
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
