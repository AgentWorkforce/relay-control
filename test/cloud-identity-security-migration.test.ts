import assert from "node:assert/strict";
import test from "node:test";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { defaultMigrationsDirectory } from "../src/migrations.js";
import { PGliteDatabase } from "./support/harness.js";

const MIGRATION = "0062_cloud_identity_security.sql";

async function databaseBefore0062(): Promise<PGliteDatabase> {
  const database = new PGliteDatabase();
  const directory = defaultMigrationsDirectory();
  const names = (await readdir(directory))
    .filter((name) => /^\d+.*\.sql$/.test(name) && name < MIGRATION)
    .sort();
  for (const name of names) await database.exec(await readFile(join(directory, name), "utf8"));
  return database;
}

async function migration0062(): Promise<string> {
  return readFile(join(defaultMigrationsDirectory(), MIGRATION), "utf8");
}

async function seedWorkspace(
  database: PGliteDatabase,
  organizationId: string,
  workspaceId: string,
  suffix: string,
): Promise<void> {
  await database.query("INSERT INTO organizations (id, name) VALUES ($1, $2)", [organizationId, `Org ${suffix}`]);
  await database.query(
    `INSERT INTO workspaces
       (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
     VALUES ($1, $2, $3, $4, 'ciphertext')`,
    [workspaceId, organizationId, `Workspace ${suffix}`, `relay-ws-${suffix}`],
  );
}

function hasActionableError(error: unknown, id: string, remediation: RegExp): boolean {
  assert(error instanceof Error);
  assert.match(error.message, /0062 preflight/);
  assert.match(error.message, new RegExp(id));
  const hint = String((error as Error & { hint?: string }).hint ?? error.message);
  assert.match(hint, remediation);
  return true;
}

test("0062 preflight names a workspace with a non-canonical History origin", async (t) => {
  const database = await databaseBefore0062();
  t.after(() => database.close());
  const workspaceId = "00000000-0000-4000-8000-000000000621";
  await seedWorkspace(
    database,
    "00000000-0000-4000-8000-000000000620",
    workspaceId,
    "preflight-origin",
  );
  await database.query("UPDATE workspaces SET relayhistory_origin = 'http://evil.example' WHERE id = $1", [workspaceId]);
  await assert.rejects(
    database.exec(await migration0062()),
    (error) => hasActionableError(error, workspaceId, /canonical HTTPS origin/),
  );
});

test("0062 preflight names workspaces sharing one History origin", async (t) => {
  const database = await databaseBefore0062();
  t.after(() => database.close());
  const first = "00000000-0000-4000-8000-000000000623";
  const second = "00000000-0000-4000-8000-000000000625";
  await seedWorkspace(database, "00000000-0000-4000-8000-000000000622", first, "duplicate-a");
  await seedWorkspace(database, "00000000-0000-4000-8000-000000000624", second, "duplicate-b");
  await database.query(
    "UPDATE workspaces SET relayhistory_origin = 'https://history.duplicate.example' WHERE id = ANY($1::uuid[])",
    [[first, second]],
  );
  await assert.rejects(
    database.exec(await migration0062()),
    (error) => hasActionableError(error, first, /Assign each canonical History origin to one workspace/),
  );
});

test("0062 preflight names organizations with case-colliding slugs", async (t) => {
  const database = await databaseBefore0062();
  t.after(() => database.close());
  const firstOrg = "00000000-0000-4000-8000-000000000626";
  const secondOrg = "00000000-0000-4000-8000-000000000628";
  await seedWorkspace(database, firstOrg, "00000000-0000-4000-8000-000000000627", "slug-a");
  await seedWorkspace(database, secondOrg, "00000000-0000-4000-8000-000000000629", "slug-b");
  await database.query("UPDATE organizations SET slug = CASE WHEN id = $1 THEN 'Acme' ELSE 'acme' END", [firstOrg]);
  await assert.rejects(
    database.exec(await migration0062()),
    (error) => hasActionableError(error, firstOrg, /Rename or NULL colliding organization slugs/),
  );
});
