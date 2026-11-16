import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { CodingAgentStore } from "../src/admin/coding-agents.js";
import { CredentialBlobStore, PostgresObjectBackend } from "../src/admin/credential-blobs.js";
import { SubscriptionLoginStore } from "../src/admin/subscription-logins.js";
import type { EncryptionKeyring } from "../src/crypto.js";
import { PostgresDatabase } from "../src/database.js";
import { migrate } from "../src/migrations.js";
import { CLOUD_FIXTURE_DDL, cloudEnvelope, cloudFixtureSeed, id, ORG_A, ORG_B } from "../scripts/cloud-import/cloud-fixture.js";
import { copyCodingAgentCredentials } from "../scripts/cloud-import/credentials.js";
import { runImport } from "../scripts/cloud-import/importer.js";
import { PGliteDatabase } from "./support/harness.js";

/*
 * Real two-connection race for the Cloud credential copier's login marker
 * (scripts/cloud-import/credentials.ts writeLoginMarker, inside storeLogin's
 * transaction) against a concurrent Control rotation. PGlite serialises
 * transactions, so the in-process suite proves only the logic; this proves
 * it against a real server. Runs only when TEST_DATABASE_URL names a
 * THROWAWAY database: it migrates it and refuses to run if any organization
 * other than this file's fixtures exists. Skipped (visibly) otherwise.
 */
const url = process.env.TEST_DATABASE_URL;
const skip = url ? false : "TEST_DATABASE_URL is not set (two-connection copier race needs a throwaway Postgres)";
const CLOUD_KEY = randomBytes(32).toString("hex");
const KEYRING: EncryptionKeyring = { active: { id: "copier-race", key: Buffer.alloc(32, 7) } };
const jwt = (payload: Record<string, unknown>) => `e30.${Buffer.from(JSON.stringify(payload)).toString("base64url")}.sig`;
const auth = (refresh: string) => JSON.stringify({
  auth_mode: "chatgpt",
  tokens: {
    access_token: jwt({ exp: Math.floor(Date.now() / 1000) + 3600 }),
    id_token: jwt({ email: "alice@example.test" }),
    refresh_token: refresh,
    account_id: "acct-synthetic-1",
  },
});

test("copier marker vs a concurrent Control rotation on two real connections", { skip, timeout: 120_000 }, async (t) => {
  const first = new PostgresDatabase(url!);
  const second = new PostgresDatabase(url!);
  const source = new PGliteDatabase();
  t.after(async () => {
    await first.close();
    await second.close();
    await source.close();
  });
  await migrate(first);
  const foreign = await first.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM organizations WHERE id::text <> ALL($1::text[])", [[ORG_A, ORG_B]]);
  assert.equal(foreign.rows[0]!.n, 0, "TEST_DATABASE_URL must be an empty throwaway database");
  // A previous run may have left its fixtures: start clean.
  await first.query("DELETE FROM organizations WHERE id::text = ANY($1::text[])", [[ORG_A, ORG_B]]);
  await first.query("DELETE FROM users WHERE email LIKE '%@example.test'");

  await source.exec(CLOUD_FIXTURE_DDL);
  await source.exec(cloudFixtureSeed(CLOUD_KEY));
  assert.equal((await runImport({ source, target: first, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: [ORG_A] }, "apply")).ok, true);

  const objects = new Map<string, string>();
  const key = `${id(1)}/accounts/${id(0x806)}/credentials.json.enc`;
  const firstBlobs = new CredentialBlobStore(new PostgresObjectBackend(first), KEYRING);
  const secondBlobs = new CredentialBlobStore(new PostgresObjectBackend(second), KEYRING);
  const copier = {
    source, target: first, reader: { get: async (k: string) => objects.get(k) ?? null }, cloudKeyHex: CLOUD_KEY, keyring: KEYRING,
    codingAgents: new CodingAgentStore(first, KEYRING, undefined, firstBlobs),
    logins: new SubscriptionLoginStore(first, KEYRING, firstBlobs), blobs: firstBlobs,
  };
  const control = new SubscriptionLoginStore(second, KEYRING, secondBlobs);

  for (let round = 0; round < 12; round += 1) {
    objects.set(key, JSON.stringify(cloudEnvelope(auth(`rt-cloud-${round}`), CLOUD_KEY)));
    // The copier (pool one) and a Control rotation (pool two) race for the same login.
    await Promise.all([
      copyCodingAgentCredentials(copier, { orgIds: [ORG_A] }, "apply"),
      control.storeLogin({ provider: "openai", workspaceId: id(0x201), organizationId: ORG_A, actor: { kind: "user", userId: id(1) }, authFile: auth(`rt-control-${round}`) }),
    ]);
    // Blob versions never collide, and any marker names the import's own write.
    const rows = (await first.query<{ id: string; blob_version: number; blob_location: string }>(
      "SELECT id::text AS id, blob_version, blob_location FROM coding_agent_credentials WHERE auth_type = 'provider_oauth' AND workspace_id = $1 AND provider_account_id = 'acct-synthetic-1'",
      [id(0x201)])).rows;
    assert.equal(rows.length, 1);
    const markers = (await first.query<{ row_key: string }>(
      "SELECT row_key FROM cloud_import_ledger WHERE table_name = 'copier_login' AND row_key LIKE $1", [`${rows[0]!.id}:%`])).rows;
    assert.ok(markers.length <= 1);
    for (const { row_key } of markers) {
      const marked = Number(row_key.split(":")[1]);
      const content = await firstBlobs.read(`workspaces/${id(0x201)}/accounts/${rows[0]!.id}/v${marked}.json.enc`, rows[0]!.id, marked).catch(() => null);
      if (content !== null) assert.match(content, /rt-cloud-/, `round ${round}: marker ${row_key} names the import's write`);
    }
  }
});

test("storeLogin vs a write-back on two real connections: no lock-order deadlock", { skip, timeout: 60_000 }, async (t) => {
  const first = new PostgresDatabase(url!);
  t.after(() => first.close());
  await migrate(first);
  const foreign = await first.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM organizations WHERE id::text <> ALL($1::text[])", [[ORG_A, ORG_B]]);
  assert.equal(foreign.rows[0]!.n, 0, "TEST_DATABASE_URL must be an empty throwaway database");
  const blobs = new CredentialBlobStore(new PostgresObjectBackend(first), KEYRING);
  const logins = new SubscriptionLoginStore(first, KEYRING, blobs);
  // The first test left ORG_A imported with Alice's login; make sure it exists.
  const loginId = await logins.storeLogin({ provider: "openai", workspaceId: id(0x201), organizationId: ORG_A, actor: { kind: "user", userId: id(1) }, authFile: auth("rt-seed") });

  // Session B has write-back's lock shape: the per-credential advisory lock,
  // then an audit INSERT (FK KEY SHARE on the workspaces row).
  const { default: pg } = await import("pg");
  const writeBack = new pg.Client({ connectionString: url! });
  await writeBack.connect();
  t.after(() => writeBack.end());
  await writeBack.query("BEGIN");
  await writeBack.query("SELECT pg_advisory_xact_lock(hashtext('selfhost-cli-credential-refresh'), hashtext($1))", [loginId]);

  // storeLogin replaces the same login while B holds the advisory lock.
  const replacing = logins.storeLogin({ provider: "openai", workspaceId: id(0x201), organizationId: ORG_A, actor: { kind: "user", userId: id(1) }, authFile: auth("rt-replaced") });
  await new Promise((resolve) => setTimeout(resolve, 500));
  // With the old order (workspaces FOR UPDATE, then advisory), this INSERT
  // waits for storeLogin and PostgreSQL aborts one side with 40P01.
  await writeBack.query(
    "INSERT INTO admin_audit_events (id, organization_id, workspace_id, actor_kind, actor_id, action, target) VALUES (gen_random_uuid(), $1, $2, 'service', 'race', 'coding_agent.write_back', 'race')",
    [ORG_A, id(0x201)],
  );
  await writeBack.query("COMMIT");
  assert.equal(await replacing, loginId, "storeLogin completes after the write-back commits");
});
