import assert from "node:assert/strict";
import test from "node:test";
import { migrate } from "../src/migrations.js";
import { PGliteDatabase } from "./support/harness.js";

test("Cloud Desktop and fleet import columns accept the source shapes", async (t) => {
  const database = new PGliteDatabase();
  t.after(() => database.close());
  await migrate(database);

  const columns = await database.query<{
    table_name: string;
    column_name: string;
    data_type: string;
    is_nullable: "YES" | "NO";
  }>(`
    SELECT table_name, column_name, data_type, is_nullable
      FROM information_schema.columns
     WHERE (table_name, column_name) IN (
       ('desktop_relay_identities', 'source_id'),
       ('desktop_attestation_keys', 'source_id'),
       ('fleet_node_owners', 'node_name')
     )
     ORDER BY table_name, column_name
  `);
  const byColumn = new Map(columns.rows.map((row) => [`${row.table_name}.${row.column_name}`, row]));
  assert.deepEqual([...byColumn.keys()].sort(), [
    "desktop_attestation_keys.source_id",
    "desktop_relay_identities.source_id",
    "fleet_node_owners.node_name",
  ]);
  assert.equal(byColumn.get("desktop_relay_identities.source_id")!.data_type, "text");
  assert.equal(byColumn.get("desktop_attestation_keys.source_id")!.data_type, "text");
  assert.equal(byColumn.get("fleet_node_owners.node_name")!.is_nullable, "YES");
});
