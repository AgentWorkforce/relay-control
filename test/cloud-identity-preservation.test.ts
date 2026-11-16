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

  const organizationId = "00000000-0000-4000-8000-000000000056";
  const workspaceId = "00000000-0000-4000-8000-000000000057";
  await database.query("INSERT INTO organizations (id, name) VALUES ($1, 'Imported org')", [organizationId]);
  await database.query(
    `INSERT INTO workspaces
       (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
     VALUES ($1, $2, 'Imported workspace', 'relay-ws-0056', 'ciphertext')`,
    [workspaceId, organizationId],
  );
  for (const origin of [
    "https://history.customer.example",
    "http://localhost:3000",
    "https://[2001:db8::1]:8443",
  ]) {
    await database.query("UPDATE workspaces SET relayhistory_origin = $2 WHERE id = $1", [workspaceId, origin]);
    const stored = await database.query<{ relayhistory_origin: string }>(
      "SELECT relayhistory_origin FROM workspaces WHERE id = $1",
      [workspaceId],
    );
    assert.equal(stored.rows[0]!.relayhistory_origin, origin);
  }
  for (const invalid of [
    "history.customer.example",
    "ftp://history.customer.example",
    "https://history.customer.example/",
    "https://history.customer.example/path",
    "https://history.customer.example?tenant=1",
    "https://user@history.customer.example",
  ]) {
    await assert.rejects(
      database.query("UPDATE workspaces SET relayhistory_origin = $2 WHERE id = $1", [workspaceId, invalid]),
      /workspaces_relayhistory_origin_format/,
      invalid,
    );
  }
});
