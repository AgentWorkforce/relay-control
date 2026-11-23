import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { copyFile, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultMigrationsDirectory, migrate } from "../src/migrations.js";
import { PGliteDatabase } from "./support/harness.js";

// Migration 0089 moves grok_bot_events' foreign key from the routine row to the OAuth grant. Every existing event's
// grant_id is a routine's grant_id, which already references mcp_oauth_grants(id), so the new key validates without
// a backfill and leaves no orphan; existing rows keep every column and stay readable.
test("0089 keeps events stored under a routine, re-keyed to their grant, with no backfill", async t => {
  const directory = await mkdtemp(join(tmpdir(), "channel-events-migration-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const source = defaultMigrationsDirectory();
  const files = (await readdir(source)).filter(name => /^\d+.*\.sql$/.test(name)).sort();
  for (const name of files.filter(name => name < "0089")) await copyFile(join(source, name), join(directory, name));
  const database = new PGliteDatabase(); t.after(() => database.close());
  await migrate(database, directory);

  const user = randomUUID(), org = randomUUID(), workspace = randomUUID(), grant = randomUUID(), client = "mcpc_" + randomUUID();
  await database.query("INSERT INTO users(id,email,name) VALUES ($1,'fake@example.test','Fake')", [user]);
  await database.query("INSERT INTO organizations(id,name) VALUES ($1,'Fake Org')", [org]);
  await database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')", [org, user]);
  await database.query("INSERT INTO workspaces(id,organization_id,name) VALUES ($1,$2,'Fake')", [workspace, org]);
  await database.query("INSERT INTO mcp_oauth_clients(client_id,redirect_uris) VALUES ($1,$2)", [client, ["https://x.ai/callback"]]);
  await database.query(`INSERT INTO mcp_oauth_grants(id,client_id,user_id,organization_id,workspace_id,agent_name,scopes,resource,token_family_id)
    VALUES ($1,$2,$3,$4,$5,'fake-grok',$6,'https://relay.example.test/mcp',$7)`, [grant, client, user, org, workspace, ["relay:mcp"], randomUUID()]);
  await database.query("INSERT INTO grok_bot_routines(grant_id,delivery_mode,cloud_copy) VALUES ($1,'polling',true)", [grant]);
  await database.query(`INSERT INTO grok_bot_events(grant_id,event_id,grant_seq,name,sender,occurred_at,payload_ciphertext)
    VALUES ($1,$2,1,'relay.channel_message','someone',now(),'v1:k:AAAA'),($1,$3,2,'relay.message','someone',now(),'v1:k:BBBB')`,
  [grant, "evt_" + "a".repeat(32), "evt_" + "b".repeat(32)]);

  for (const name of files.filter(name => name >= "0089")) await copyFile(join(source, name), join(directory, name));
  await migrate(database, directory);

  const rows = (await database.query<{ event_id: string; payload_ciphertext: string; channel_id: string | null; wake_reserved_at: Date | null }>(
    "SELECT event_id,payload_ciphertext,channel_id,wake_reserved_at FROM grok_bot_events ORDER BY grant_seq")).rows;
  assert.deepEqual(rows.map(row => [row.event_id.slice(0, 5), row.payload_ciphertext, row.channel_id, row.wake_reserved_at]),
    [["evt_a", "v1:k:AAAA", null, null], ["evt_b", "v1:k:BBBB", null, null]]);
  const orphans = (await database.query<{ n: number }>(`SELECT count(*)::int AS n FROM grok_bot_events e
    LEFT JOIN mcp_oauth_grants g ON g.id=e.grant_id WHERE g.id IS NULL`)).rows[0]!.n;
  assert.equal(orphans, 0);
  // The events now belong to the grant: removing the routine row alone keeps them; deleting the grant removes them.
  await database.query("DELETE FROM grok_bot_routines WHERE grant_id=$1", [grant]);
  assert.equal((await database.query("SELECT 1 FROM grok_bot_events")).rows.length, 2);
  await database.query("DELETE FROM mcp_oauth_grants WHERE id=$1", [grant]);
  assert.equal((await database.query("SELECT 1 FROM grok_bot_events")).rows.length, 0);
});
