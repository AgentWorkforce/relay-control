import assert from "node:assert/strict";
import test from "node:test";
import { migrate } from "../src/migrations.js";
import { canonicalRelayhistoryOrigin } from "../src/relayhistory-origin.js";
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

  const indexes = await database.query<{ indexname: string; indexdef: string }>(`
    SELECT indexname, indexdef FROM pg_indexes
     WHERE indexname IN (
       'organizations_slug_unique',
       'workspaces_org_slug_unique',
       'workspaces_relayhistory_origin_unique'
     )
     ORDER BY indexname
  `);
  assert.deepEqual(indexes.rows.map((row) => row.indexname), [
    "organizations_slug_unique",
    "workspaces_org_slug_unique",
    "workspaces_relayhistory_origin_unique",
  ]);
  assert.match(indexes.rows[0]!.indexdef, /lower\(slug\)/);
  assert.match(indexes.rows[1]!.indexdef, /organization_id, lower\(slug\)/);
  assert.match(indexes.rows[2]!.indexdef, /\(relayhistory_origin\)/);
  assert.doesNotMatch(indexes.rows[2]!.indexdef, /lower\(relayhistory_origin\)/);

  const organizationId = "00000000-0000-4000-8000-000000000056";
  const otherOrganizationId = "00000000-0000-4000-8000-000000000058";
  const workspaceId = "00000000-0000-4000-8000-000000000057";
  const siblingWorkspaceId = "00000000-0000-4000-8000-000000000059";
  const otherWorkspaceId = "00000000-0000-4000-8000-000000000060";
  await database.query("INSERT INTO organizations (id, name) VALUES ($1, 'Imported org')", [organizationId]);
  await database.query("INSERT INTO organizations (id, name) VALUES ($1, 'Other imported org')", [otherOrganizationId]);
  await database.query(
    `INSERT INTO workspaces
       (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
     VALUES ($1, $2, 'Imported workspace', 'relay-ws-0056', 'ciphertext')`,
    [workspaceId, organizationId],
  );
  await database.query(
    `INSERT INTO workspaces
       (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
     VALUES
       ($1, $3, 'Sibling workspace', 'relay-ws-0056-sibling', 'ciphertext'),
       ($2, $4, 'Other workspace', 'relay-ws-0056-other', 'ciphertext')`,
    [siblingWorkspaceId, otherWorkspaceId, organizationId, otherOrganizationId],
  );
  for (const origin of [
    "https://history.customer.example",
    "https://xn--bcher-kva.example",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://[::1]:3000",
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
    "http://history.customer.example",
    "https://HISTORY.customer.example",
    "https://history.customer.example:443",
    "https://history.customer.example:0443",
    "https://history.customer.example.",
    "https://bücher.example",
    "https://0x7f.1",
    "https://0x7f000001",
    "https://[::ffff:127.0.0.1]",
    "https://[::ffff:7f00:1]",
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

  for (const input of [
    "https://history.customer.example",
    "https://history.customer.example:8443",
    "https://xn--bcher-kva.example",
    "https://127.0.0.1",
    "https://0x7f.1",
    "https://0x7f000001",
    "https://[2001:db8::1]",
    "https://[::ffff:127.0.0.1]",
    "https://[::ffff:7f00:1]",
  ]) {
    const pg = await database.query<{ accepted: boolean }>(
      "SELECT relayhistory_origin_is_canonical($1) AS accepted",
      [input],
    );
    assert.equal(pg.rows[0]!.accepted, canonicalRelayhistoryOrigin(input) === input, input);
  }

  await database.query("UPDATE organizations SET slug = 'Acme' WHERE id = $1", [organizationId]);
  await assert.rejects(
    database.query("UPDATE organizations SET slug = 'acme' WHERE id = $1", [otherOrganizationId]),
    /organizations_slug_unique/,
  );
  await database.query("UPDATE workspaces SET slug = 'Primary' WHERE id = $1", [workspaceId]);
  await assert.rejects(
    database.query("UPDATE workspaces SET slug = 'primary' WHERE id = $1", [siblingWorkspaceId]),
    /workspaces_org_slug_unique/,
  );
  await database.query("UPDATE workspaces SET slug = 'primary' WHERE id = $1", [otherWorkspaceId]);

  await database.query(
    "UPDATE workspaces SET relayhistory_origin = 'https://history.unique.example' WHERE id = $1",
    [workspaceId],
  );
  await assert.rejects(
    database.query(
      "UPDATE workspaces SET relayhistory_origin = 'https://history.unique.example' WHERE id = $1",
      [otherWorkspaceId],
    ),
    /workspaces_relayhistory_origin_unique/,
  );
});
