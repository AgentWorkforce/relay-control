import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import pg from "pg";
import { PostgresDatabase } from "../src/database.js";
import { listAuditPage, recordDelegationAudit } from "../src/delegation/service.js";
import { migrate } from "../src/migrations.js";
import { isolatedPostgresPool } from "./support/postgres.js";

const postgresUrl = process.env.TEST_DATABASE_URL;
const options = { skip: postgresUrl ? false : "TEST_DATABASE_URL is not set (audit paging multi-connection proof)", timeout: 60_000 };

test("audit pages never skip an event committed out of id order", options, async (t) => {
  const admin = new pg.Pool({ connectionString: postgresUrl, max: 1 });
  const schema = `delegation_audit_${randomUUID().replaceAll("-", "")}`;
  await admin.query(`CREATE SCHEMA "${schema}"`);
  let database: PostgresDatabase | null = null;
  t.after(async () => {
    try { await database?.close(); } finally {
      try { await admin.query(`DROP SCHEMA "${schema}" CASCADE`); } finally { await admin.end(); }
    }
  });
  const pool = await isolatedPostgresPool(postgresUrl!, schema, 3);
  database = new PostgresDatabase(pool);
  await migrate(database);
  const organizationId = randomUUID();
  const workspaceId = randomUUID();
  await database.query("INSERT INTO organizations (id, name) VALUES ($1, 'Org')", [organizationId]);
  await database.query(`INSERT INTO workspaces (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
    VALUES ($1, $2, 'Workspace', $3, 'envelope')`, [workspaceId, organizationId, `rw-${workspaceId}`]);
  const viewer = randomUUID();
  const page = (afterId: string | null) => listAuditPage(database!, {
    workspaceId, all: true, viewerUserId: viewer, since: null, grantId: null, limit: 100, afterId,
  });
  const ids = (rows: Record<string, unknown>[]) => rows.map(row => String(row.id));

  await recordDelegationAudit(database, { workspaceId, event: "first" });
  const settled = ids(await page(null));
  assert.equal(settled.length, 1);

  // A transaction takes the next id and stays open; a later one commits a higher id.
  const slow = await pool.connect();
  try {
    await slow.query("BEGIN");
    const pending = (await slow.query<{ id: string }>(
      "INSERT INTO delegation_audit_events (workspace_id, event) VALUES ($1, 'slow') RETURNING id::text", [workspaceId],
    )).rows[0]!.id;
    await recordDelegationAudit(database, { workspaceId, event: "fast" });
    const fast = (await database.query<{ id: string }>(
      "SELECT id::text FROM delegation_audit_events WHERE event = 'fast'")).rows[0]!.id;
    assert.ok(BigInt(fast) > BigInt(pending));
    // The committed higher id is held back while the lower one is in flight.
    assert.deepEqual(ids(await page(settled.at(-1)!)), []);
    assert.deepEqual(ids(await page(null)), settled);
    await slow.query("COMMIT");
    // Past Cloud's 30-second paging hold-back.
    await database.query("UPDATE delegation_audit_events SET created_at = created_at - interval '1 minute'");
    // Resuming from the last id returns both, in id order: nothing was skipped.
    assert.deepEqual(ids(await page(settled.at(-1)!)), [pending, fast]);
  } finally {
    slow.release();
  }

  // A rolled-back transaction leaves a gap that does not hold the log back.
  const aborted = await pool.connect();
  try {
    await aborted.query("BEGIN");
    await aborted.query("INSERT INTO delegation_audit_events (workspace_id, event) VALUES ($1, 'aborted')", [workspaceId]);
    await aborted.query("ROLLBACK");
  } finally {
    aborted.release();
  }
  await recordDelegationAudit(database, { workspaceId, event: "after-gap" });
  assert.deepEqual((await page(null)).map(row => row.event), ["first", "slow", "fast", "after-gap"]);
});
