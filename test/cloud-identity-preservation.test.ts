import assert from "node:assert/strict";
import test from "node:test";
import { migrate } from "../src/migrations.js";
import { PGliteDatabase } from "./support/harness.js";

test("Cloud identity preservation columns match the import contract", async (t) => {
  const database = new PGliteDatabase();
  t.after(() => database.close());
  await migrate(database);

  const columns = await database.query<{
    table_name: string;
    column_name: string;
    data_type: string;
    is_nullable: "YES" | "NO";
    column_default: string | null;
  }>(`
    SELECT table_name, column_name, data_type, is_nullable, column_default
      FROM information_schema.columns
     WHERE (table_name, column_name) IN (
       ('organizations', 'slug'),
       ('workspaces', 'slug'),
       ('workspaces', 'relayhistory_origin'),
       ('workspaces', 'relaycast_api_key_generation')
     )
     ORDER BY table_name, column_name
  `);
  const byColumn = new Map(columns.rows.map((row) => [`${row.table_name}.${row.column_name}`, row]));
  const expected = [
    "organizations.slug",
    "workspaces.slug",
    "workspaces.relayhistory_origin",
    "workspaces.relaycast_api_key_generation",
  ];
  assert.deepEqual([...byColumn.keys()].sort(), [...expected].sort());
  for (const key of ["organizations.slug", "workspaces.slug", "workspaces.relayhistory_origin"]) {
    assert.equal(byColumn.get(key)!.is_nullable, "YES", key);
  }
  const generation = byColumn.get("workspaces.relaycast_api_key_generation")!;
  assert.equal(generation.data_type, "integer");
  assert.equal(generation.is_nullable, "NO");
  assert.equal(generation.column_default, "1");

  const indexes = await database.query<{ indexname: string }>(`
    SELECT indexname FROM pg_indexes
     WHERE indexname IN ('organizations_slug_unique', 'workspaces_org_slug_unique')
     ORDER BY indexname
  `);
  assert.deepEqual(indexes.rows.map((row) => row.indexname), ["organizations_slug_unique", "workspaces_org_slug_unique"]);
});
