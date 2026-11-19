import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { defaultMigrationsDirectory } from "../src/migrations.js";
import { PGliteDatabase } from "./support/harness.js";

/**
 * Migration 0080 widens staff_read_grant_lifetime (0061) from 90 to 365
 * days, matching Cloud (cloud#6414). Existing grants survive it, it can be
 * re-run, and the ceiling still holds at 366 days.
 */
const MIGRATION = "0080_staff_read_grants_year_cap.sql";

async function databaseBefore0080(): Promise<PGliteDatabase> {
  const database = new PGliteDatabase();
  const directory = defaultMigrationsDirectory();
  const names = (await readdir(directory))
    .filter((name) => /^\d+.*\.sql$/.test(name) && name < MIGRATION)
    .sort();
  for (const name of names) await database.exec(await readFile(join(directory, name), "utf8"));
  return database;
}

async function migration0080(): Promise<string> {
  return readFile(join(defaultMigrationsDirectory(), MIGRATION), "utf8");
}

type Seed = { organizationId: string; workspaceId: string; userId: string };

async function seed(database: PGliteDatabase): Promise<Seed> {
  const organizationId = randomUUID();
  const workspaceId = randomUUID();
  const userId = randomUUID();
  await database.query("INSERT INTO organizations (id, name) VALUES ($1, 'Customer')", [organizationId]);
  await database.query(
    `INSERT INTO workspaces
       (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
     VALUES ($1, $2, 'Customer workspace', $3, 'ciphertext')`,
    [workspaceId, organizationId, `relay-ws-${workspaceId}`],
  );
  await database.query("INSERT INTO users (id, email, name) VALUES ($1, $2, 'Staff')", [userId, `${userId}@example.test`]);
  return { organizationId, workspaceId, userId };
}

function insertGrant(database: PGliteDatabase, ids: Seed, lifetime: string): Promise<unknown> {
  const id = randomUUID();
  return database.query(
    `INSERT INTO staff_read_grants
       (id, workspace_id, organization_id, staff_user_id, staff_organization_id, reason, token_hash, expires_at)
     VALUES ($1, $2, $3, $4, $3, 'review', $5, now() + $6::interval)`,
    [id, ids.workspaceId, ids.organizationId, ids.userId, id.replaceAll("-", ""), lifetime],
  );
}

async function lifetimeCheck(database: PGliteDatabase): Promise<string[]> {
  const rows = await database.query<{ definition: string }>(
    `SELECT pg_get_constraintdef(oid) AS definition FROM pg_constraint
      WHERE conrelid = 'staff_read_grants'::regclass AND conname = 'staff_read_grant_lifetime'`,
  );
  return rows.rows.map((row) => row.definition);
}

test("0080 widens the staff read grant lifetime to 365 days and keeps existing grants", async (t) => {
  const database = await databaseBefore0080();
  t.after(() => database.close());
  const ids = await seed(database);
  await insertGrant(database, ids, "90 days");
  await assert.rejects(insertGrant(database, ids, "365 days"), /staff_read_grant_lifetime/);

  await database.exec(await migration0080());

  const definitions = await lifetimeCheck(database);
  assert.equal(definitions.length, 1);
  assert.match(definitions[0]!, /365 days/);
  assert.equal(
    (await database.query<{ n: number }>("SELECT count(*)::int AS n FROM staff_read_grants")).rows[0]!.n,
    1,
    "the existing 90-day grant survives",
  );
  await insertGrant(database, ids, "365 days");
  await assert.rejects(insertGrant(database, ids, "366 days"), /staff_read_grant_lifetime/);
  await assert.rejects(insertGrant(database, ids, "0 seconds"), /staff_read_grant_lifetime/);
});

test("0080 is idempotent: re-running leaves one 365-day constraint", async (t) => {
  const database = await databaseBefore0080();
  t.after(() => database.close());
  const sql = await migration0080();
  await database.exec(sql);
  await database.exec(sql);
  const definitions = await lifetimeCheck(database);
  assert.equal(definitions.length, 1);
  assert.match(definitions[0]!, /365 days/);
});
