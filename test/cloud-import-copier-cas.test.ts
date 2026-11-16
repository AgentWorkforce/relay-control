import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { CodingAgentStore } from "../src/admin/coding-agents.js";
import { CredentialBlobStore, PostgresObjectBackend } from "../src/admin/credential-blobs.js";
import { SubscriptionLoginStore } from "../src/admin/subscription-logins.js";
import type { EncryptionKeyring } from "../src/crypto.js";
import type { Database, SqlExecutor } from "../src/database.js";
import { migrate } from "../src/migrations.js";
import { CLOUD_FIXTURE_DDL, cloudEnvelope, cloudFixtureSeed, id, ORG_A } from "../scripts/cloud-import/cloud-fixture.js";
import { copyCodingAgentCredentials } from "../scripts/cloud-import/credentials.js";
import { runImport } from "../scripts/cloud-import/importer.js";
import { PGliteDatabase } from "./support/harness.js";

/*
 * The copier decides "Cloud is newer" without locks; storeLogin re-checks
 * that decision under the per-credential lock (expectedVersion). These tests
 * force the interleavings PGlite cannot produce on its own.
 */
const CLOUD_KEY = randomBytes(32).toString("hex");
const KEYRING: EncryptionKeyring = { active: { id: "copier-cas", key: randomBytes(32) } };
const jwt = (payload: Record<string, unknown>) => `e30.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.sig`;
const auth = (refresh: string) => JSON.stringify({
  auth_mode: "chatgpt",
  tokens: { access_token: jwt({ exp: Math.floor(Date.now() / 1000) + 3600 }), id_token: jwt({ email: "alice@example.test" }), refresh_token: refresh, account_id: "acct-synthetic-1" },
});
const KEY_806 = `${id(1)}/accounts/${id(0x806)}/credentials.json.enc`;
const actor = { kind: "user" as const, userId: id(1) };

async function setup(t: { after(fn: () => Promise<void>): void }) {
  const source = new PGliteDatabase();
  const target = new PGliteDatabase();
  t.after(async () => {
    await source.close();
    await target.close();
  });
  await source.exec(CLOUD_FIXTURE_DDL);
  await source.exec(cloudFixtureSeed(CLOUD_KEY));
  await migrate(target);
  assert.equal((await runImport({ source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "apply")).ok, true);
  const objects = new Map([[KEY_806, JSON.stringify(cloudEnvelope(auth("rt-cloud-0"), CLOUD_KEY))]]);
  const blobs = new CredentialBlobStore(new PostgresObjectBackend(target), KEYRING);
  const logins = new SubscriptionLoginStore(target, KEYRING, blobs);
  const deps = {
    source, target, reader: { get: async (key: string) => objects.get(key) ?? null }, cloudKeyHex: CLOUD_KEY, keyring: KEYRING,
    codingAgents: new CodingAgentStore(target, KEYRING, undefined, blobs), logins, blobs,
  };
  return { source, target, objects, blobs, logins, deps };
}

const loginRow = async (target: Database) => (await target.query<{ id: string; v: number }>(
  "SELECT id::text AS id, blob_version AS v FROM coding_agent_credentials WHERE workspace_id = $1 AND auth_type = 'provider_oauth' AND provider_account_id = 'acct-synthetic-1'",
  [id(0x201)])).rows;
const markers = async (target: Database) => (await target.query<{ row_key: string }>(
  "SELECT row_key FROM cloud_import_ledger WHERE table_name = 'copier_login' ORDER BY row_key")).rows.map((row) => row.row_key);

test("copier: a Control refresh between the copier's check and its write is never replaced", async (t) => {
  const { target, objects, logins, deps } = await setup(t);
  const first = await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  assert.equal(first.rows[id(0x806)], "copied");
  const [{ id: loginId, v: imported }] = await loginRow(target) as [{ id: string; v: number }];
  const markersBefore = await markers(target);

  // Cloud's copy changes, so the copier decides to replace (marker == version).
  objects.set(KEY_806, JSON.stringify(cloudEnvelope(auth("rt-cloud-1"), CLOUD_KEY)));
  // Control rotates the login after that decision, just before the write.
  const racing = Object.create(logins) as SubscriptionLoginStore;
  racing.storeLogin = async (input) => {
    await logins.storeLogin({ provider: "openai", workspaceId: id(0x201), organizationId: ORG_A, actor, authFile: auth("rt-control-rotated") });
    return logins.storeLogin(input);
  };
  const report = await copyCodingAgentCredentials({ ...deps, logins: racing }, { orgIds: null }, "apply");
  assert.equal(report.rows[id(0x806)], "control_newer");
  assert.equal(report.writes.blobWrites, 0);
  assert.equal(report.writes.metadataWrites, 0, "Cloud's state is not written over Control's either");
  assert.deepEqual(await loginRow(target), [{ id: loginId, v: imported + 1 }], "only Control's rotation landed");
  assert.match((await logins.freshAuthFile(id(0x201), loginId))!, /rt-control-rotated/);
  assert.deepEqual(await markers(target), markersBefore, "the marker still names the import's own write");
  const status = (await target.query<{ status: string; last_error: string | null }>(
    "SELECT status, last_error FROM coding_agent_credentials WHERE id = $1", [loginId])).rows[0]!;
  assert.deepEqual(status, { status: "connected", last_error: null }, "Control's state after its rotation");
});

test("copier: a first login Control creates between the check and the write is never replaced", async (t) => {
  const { target, logins, deps } = await setup(t);
  // No Control login yet; Control's user signs in after the copier looked.
  const racing = Object.create(logins) as SubscriptionLoginStore;
  racing.storeLogin = async (input) => {
    if (input.workspaceId === id(0x201) && input.provider === "openai") {
      await logins.storeLogin({ provider: "openai", workspaceId: id(0x201), organizationId: ORG_A, actor, authFile: auth("rt-control-first") });
    }
    return logins.storeLogin(input);
  };
  const report = await copyCodingAgentCredentials({ ...deps, logins: racing }, { orgIds: null }, "apply");
  assert.equal(report.rows[id(0x806)], "control_newer");
  const rows = await loginRow(target);
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.v, 1);
  assert.match((await logins.freshAuthFile(id(0x201), rows[0]!.id))!, /rt-control-first/);
});

test("copier: several Cloud rows for one Control login pick one winner and converge", async (t) => {
  const { source, target, objects, deps } = await setup(t);
  // A second, unselected, newer Cloud row for the same workspace, provider and account.
  await source.exec(`
    INSERT INTO provider_credentials (id, organization_id, workspace_id, user_id, harness, model_provider, auth_type, display_name, is_active, harness_active, status, created_at, updated_at, provider_account_id)
    VALUES ('${id(0x8f0)}', '${ORG_A}', '${id(0x201)}', '${id(1)}', 'codex', 'openai', 'provider_oauth', 'ChatGPT again', false, false, 'connected', '2026-03-01T00:00:00Z', '2026-03-01T00:00:00Z', 'acct-synthetic-1');`);
  objects.set(`${id(1)}/accounts/${id(0x8f0)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(auth("rt-cloud-dup"), CLOUD_KEY)));

  const first = await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  assert.equal(first.rows[id(0x8f0)], "copied", "the freshest token wins, not the older selected row");
  assert.equal(first.rows[id(0x806)], "duplicate_login");
  const loginId = (await loginRow(target))[0]!.id;
  assert.match((await deps.logins.freshAuthFile(id(0x201), loginId))!, /rt-cloud-dup/);
  const flags = (await target.query<{ harness_active: boolean }>(
    "SELECT harness_active FROM coding_agent_credentials WHERE id = $1", [loginId])).rows[0]!;
  assert.equal(flags.harness_active, true, "the winner carries the older row's Cloud selection");

  const again = await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  assert.equal(again.rows[id(0x8f0)], "already_present");
  assert.equal(again.rows[id(0x806)], "duplicate_login");
  assert.deepEqual(again.writes, { inserted: 0, updated: 0, blobWrites: 0, metadataWrites: 0, selectionWrites: 0 }, "a re-run converges");
  assert.equal((await loginRow(target))[0]!.v, 1);
});

test("storeLogin: a login created after the unlocked lookup is retried with the advisory lock first", async (t) => {
  const target = new PGliteDatabase();
  t.after(() => target.close());
  await migrate(target);
  await target.query("INSERT INTO organizations (id, name) VALUES ($1, 'Org')", [ORG_A]);
  await target.query("INSERT INTO users (id, email, name) VALUES ($1, 'alice@example.test', 'Alice')", [id(1)]);
  await target.query("INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, 'owner')", [ORG_A, id(1)]);
  await target.query("INSERT INTO workspaces (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext) VALUES ($1, $2, 'W', 'rw_cas', 'x')", [id(0x201), ORG_A]);
  const blobs = new CredentialBlobStore(new PostgresObjectBackend(target), KEYRING);
  const existingId = await new SubscriptionLoginStore(target, KEYRING, blobs).storeLogin({ provider: "openai", workspaceId: id(0x201), organizationId: ORG_A, actor, authFile: auth("rt-a") });

  // The first attempt's unlocked lookup misses the row (as if it were created
  // just after); every statement is recorded per attempt.
  const attempts: string[][] = [];
  const hidden: Database = Object.create(target);
  hidden.transaction = (run) => target.transaction((tx) => {
    const seen: string[] = [];
    attempts.push(seen);
    const wrapped: SqlExecutor = {
      exec: (sql) => tx.exec(sql),
      query: (async (sql: string, params?: unknown[]) => {
        seen.push(sql.replace(/\s+/g, " ").trim().slice(0, 60));
        if (attempts.length === 1 && /^SELECT id FROM coding_agent_credentials/.test(sql.trim()) && !/FOR UPDATE/.test(sql)) return { rows: [] };
        return tx.query(sql, params);
      }) as SqlExecutor["query"],
    };
    return run(wrapped);
  });
  const id2 = await new SubscriptionLoginStore(hidden, KEYRING, blobs).storeLogin({ provider: "openai", workspaceId: id(0x201), organizationId: ORG_A, actor, authFile: auth("rt-b") });
  assert.equal(id2, existingId);
  assert.equal(attempts.length, 2, "retried once");
  assert.ok(!attempts[0]!.some((sql) => sql.includes("pg_advisory_xact_lock")), "attempt 1 had no advisory lock");
  const second = attempts[1]!;
  const advisory = second.findIndex((sql) => sql.includes("pg_advisory_xact_lock"));
  const workspaceLock = second.findIndex((sql) => sql.startsWith("SELECT id FROM workspaces"));
  assert.ok(advisory >= 0 && advisory < workspaceLock, "attempt 2 takes the advisory lock before the workspace lock");
  const version = (await target.query<{ v: number }>("SELECT blob_version AS v FROM coding_agent_credentials WHERE id = $1", [existingId])).rows[0]!.v;
  assert.equal(version, 2, "the abandoned attempt wrote nothing");
});

test("copier: duplicate winner tie-breaks are newest updated_at, then lowest id", async (t) => {
  const { source, target, objects, deps } = await setup(t);
  // Neither row is Cloud-selected: the newer one wins.
  await source.exec(`
    UPDATE provider_credentials SET is_active = false, harness_active = false WHERE id = '${id(0x806)}';
    INSERT INTO provider_credentials (id, organization_id, workspace_id, user_id, harness, model_provider, auth_type, display_name, is_active, harness_active, status, created_at, updated_at, provider_account_id)
    VALUES ('${id(0x8f0)}', '${ORG_A}', '${id(0x201)}', '${id(1)}', 'codex', 'openai', 'provider_oauth', 'ChatGPT again', false, false, 'connected', '2030-01-01T00:00:00Z', '2030-01-01T00:00:00Z', 'acct-synthetic-1');`);
  objects.set(`${id(1)}/accounts/${id(0x8f0)}/credentials.json.enc`, JSON.stringify(cloudEnvelope(auth("rt-cloud-newer"), CLOUD_KEY)));
  const newer = await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  assert.equal(newer.rows[id(0x8f0)], "copied", "the newer row wins");
  assert.equal(newer.rows[id(0x806)], "duplicate_login");
  const loginId = (await loginRow(target))[0]!.id;
  assert.match((await deps.logins.freshAuthFile(id(0x201), loginId))!, /rt-cloud-newer/);

  // Same updated_at: the lowest id wins (0x806 < 0x8f0); it replaces the import's own write.
  await source.exec(`UPDATE provider_credentials SET updated_at = (SELECT updated_at FROM provider_credentials WHERE id = '${id(0x806)}') WHERE id = '${id(0x8f0)}';`);
  const tie = await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  assert.equal(tie.rows[id(0x806)], "updated", "the lowest id wins a tie");
  assert.equal(tie.rows[id(0x8f0)], "duplicate_login");
  assert.match((await deps.logins.freshAuthFile(id(0x201), loginId))!, /rt-cloud-0/);
});

test("storeLogin: an onStored failure rolls back the whole store", async (t) => {
  const { target, logins, blobs, deps } = await setup(t);
  await copyCodingAgentCredentials(deps, { orgIds: null }, "apply");
  const [{ id: loginId, v: before }] = (await loginRow(target)) as Array<{ id: string; v: number }> as [{ id: string; v: number }];
  const state = async () => (await target.query<{ v: number; loc: string; status: string; ra: number; audits: number; markers: number }>(
    `SELECT c.blob_version AS v, c.blob_location AS loc, c.status, c.refresh_attempts AS ra,
            (SELECT count(*)::int FROM admin_audit_events WHERE target LIKE '%' || c.id::text) AS audits,
            (SELECT count(*)::int FROM cloud_import_ledger WHERE table_name = 'copier_login') AS markers
       FROM coding_agent_credentials c WHERE c.id = $1`, [loginId])).rows[0]!;
  const snapshot = await state();
  await assert.rejects(logins.storeLogin({
    provider: "openai", workspaceId: id(0x201), organizationId: ORG_A, actor, authFile: auth("rt-rolled-back"),
    expectedVersion: before,
    onStored: async () => { throw new Error("marker write failed"); },
  }), /marker write failed/);
  assert.deepEqual(await state(), snapshot, "row, audit and markers unchanged");
  assert.doesNotMatch(await blobs.read(snapshot.loc, loginId, snapshot.v), /rt-rolled-back/);
  await assert.rejects(blobs.read(`workspaces/${id(0x201)}/accounts/${loginId}/v${before + 1}.json.enc`, loginId, before + 1), "no blob at the next version");
});
