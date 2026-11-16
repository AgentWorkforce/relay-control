import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { decryptSecret, type EncryptionKeyring } from "../src/crypto.js";
import { migrate } from "../src/migrations.js";
import {
  CLOUD_FIXTURE_DDL,
  EXPECTED_FULL,
  ORG_A,
  ORG_B,
  cloudFixtureSeed,
  id,
} from "../scripts/cloud-import/cloud-fixture.js";
import { runImport, type ImportReport } from "../scripts/cloud-import/importer.js";
import { SOURCE_TABLES, verifierComparisons } from "../scripts/cloud-import/mapping.js";
import { PGliteDatabase } from "./support/harness.js";

const CLOUD_KEY = randomBytes(32).toString("hex");
const KEYRING: EncryptionKeyring = { active: { id: "import-test", key: randomBytes(32) } };

// Control migrations 0053/0056/0057 as proposed in #149/#151/#152, applied
// only by the "post-0057" test so the importer is exercised on both shapes.
const POST_0057_DDL = `
ALTER TABLE workspaces
  ADD COLUMN cloud_relay_workspace_id text,
  ADD CONSTRAINT workspaces_cloud_relay_workspace_id_format
    CHECK (cloud_relay_workspace_id IS NULL OR cloud_relay_workspace_id ~ '^rw_[0-9a-f]{8}$'),
  ADD CONSTRAINT workspaces_cloud_relay_workspace_id_unique UNIQUE (cloud_relay_workspace_id);
ALTER TABLE organizations ADD COLUMN slug text;
CREATE UNIQUE INDEX organizations_slug_unique ON organizations (slug);
ALTER TABLE workspaces
  ADD COLUMN slug text,
  ADD COLUMN relayhistory_origin text,
  ADD COLUMN relaycast_api_key_generation integer NOT NULL DEFAULT 1;
CREATE UNIQUE INDEX workspaces_org_slug_unique ON workspaces (organization_id, slug);
ALTER TABLE desktop_relay_identities ALTER COLUMN source_id TYPE text USING source_id::text;
ALTER TABLE desktop_attestation_keys ALTER COLUMN source_id TYPE text USING source_id::text;
ALTER TABLE fleet_node_owners ALTER COLUMN node_name DROP NOT NULL;
`;

async function cloudSource(): Promise<PGliteDatabase> {
  const source = new PGliteDatabase();
  await source.exec(CLOUD_FIXTURE_DDL);
  await source.exec(cloudFixtureSeed(CLOUD_KEY));
  return source;
}

async function controlTarget(post0057 = false): Promise<PGliteDatabase> {
  const target = new PGliteDatabase();
  await migrate(target);
  if (post0057) await target.exec(POST_0057_DDL);
  return target;
}

function ledger(report: ImportReport) {
  return Object.fromEntries(SOURCE_TABLES.map((table) => [table, {
    imported: report.tables[table].imported,
    skipped: report.tables[table].skipped,
  }]));
}

async function count(database: PGliteDatabase, table: string): Promise<number> {
  const result = await database.query<{ n: number }>(`SELECT count(*)::int AS n FROM ${table}`);
  return result.rows[0]!.n;
}

test("cloud import: plan, dry-run, apply, re-run and verifier projections (0051 target)", async (t) => {
  const source = await cloudSource();
  const target = await controlTarget();
  t.after(async () => {
    await source.close();
    await target.close();
  });
  const deps = { source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY };
  const scope = { orgIds: null };

  // plan: no target access. The uuid-only source_id rule needs the target, so
  // the non-UUID Desktop row still counts as importable here.
  const plan = await runImport({ ...deps, target: undefined }, scope, "plan");
  assert.equal(plan.ok, true);
  const expectedPlan = structuredClone(EXPECTED_FULL);
  expectedPlan.desktop_relay_identities = { imported: 2, skipped: { not_a_member: 1 } };
  assert.deepEqual(ledger(plan), expectedPlan);

  // dry-run: writes inside a transaction that is rolled back.
  const dry = await runImport(deps, scope, "dry-run");
  assert.equal(dry.ok, true, JSON.stringify(dry.orgs));
  assert.deepEqual(ledger(dry), EXPECTED_FULL);
  assert.equal(await count(target, "users"), 0);
  assert.equal(await count(target, "organizations"), 0);

  const applied = await runImport(deps, scope, "apply");
  assert.equal(applied.ok, true, JSON.stringify(applied.orgs));
  assert.deepEqual(ledger(applied), EXPECTED_FULL);
  assert.deepEqual(Object.keys(applied.orgs).sort(), [ORG_A, ORG_B].sort());
  assert.equal(applied.warnings.fleet_node_name_filled_with_node_id, 1);
  assert.equal(applied.warnings.workspace_rw_id_not_rw_8hex, 1);
  assert.deepEqual(applied.optionalColumns, []);

  // Emails are normalized, ids are the Cloud ids, last_* survive the FK pass.
  const alice = (await target.query<{ email: string; last_organization_id: string; last_workspace_id: string }>(
    "SELECT email, last_organization_id, last_workspace_id FROM users WHERE id = $1", [id(1)])).rows[0]!;
  assert.deepEqual(alice, { email: "alice@example.test", last_organization_id: ORG_A, last_workspace_id: id(0x201) });
  const bob = (await target.query<{ name: string }>("SELECT name FROM users WHERE id = $1", [id(2)])).rows[0]!;
  assert.equal(bob.name, "bob@example.test");
  // The merged duplicate's admin role lands on the survivor.
  const merged = (await target.query<{ role: string }>(
    "SELECT role FROM organization_memberships WHERE organization_id = $1 AND user_id = $2", [ORG_B, id(1)])).rows[0]!;
  assert.equal(merged.role, "admin");

  // Secrets are Control keyring ciphertext that decrypts to the Cloud value.
  const workspace = (await target.query<{ relaycast_api_key_ciphertext: string; runtime_config: unknown }>(
    "SELECT relaycast_api_key_ciphertext, runtime_config FROM workspaces WHERE id = $1", [id(0x201)])).rows[0]!;
  assert.match(workspace.relaycast_api_key_ciphertext, /^v2\.import-test\./);
  assert.equal(decryptSecret(workspace.relaycast_api_key_ciphertext, KEYRING), "rk_live_synthetic_a1");
  assert.deepEqual(workspace.runtime_config, { id: "sandbox", config: { size: 2 } });
  const person = (await target.query<{ token_ciphertext: string }>(
    "SELECT token_ciphertext FROM person_identities WHERE id = $1", [id(0x401)])).rows[0]!;
  assert.equal(decryptSecret(person.token_ciphertext, KEYRING), "tok_person_alice");

  // Invites: a fresh sha256 token hash, not the Cloud token; inviter remapped.
  const invite = (await target.query<{ token_hash: string; invited_by_user_id: string; email: string; role: string }>(
    "SELECT token_hash, invited_by_user_id, email, role FROM organization_invitations WHERE id = $1", [id(0x302)])).rows[0]!;
  assert.match(invite.token_hash, /^[0-9a-f]{64}$/);
  assert.deepEqual({ ...invite, token_hash: undefined }, { token_hash: undefined, invited_by_user_id: id(1), email: "new@example.test", role: "admin" });

  // Re-run converges: same counts, invite hash kept, nothing duplicated.
  const counts = async () => Object.fromEntries(await Promise.all(SOURCE_TABLES.map(async (table) => [table, await count(target, table)] as const)));
  const before = await counts();
  const rerun = await runImport(deps, scope, "apply");
  assert.equal(rerun.ok, true);
  assert.deepEqual(await counts(), before);
  const inviteAfter = (await target.query<{ token_hash: string }>(
    "SELECT token_hash FROM organization_invitations WHERE id = $1", [id(0x302)])).rows[0]!;
  assert.equal(inviteAfter.token_hash, invite.token_hash);

  // The verifier projections agree row for row with what was imported.
  for (const comparison of verifierComparisons(scope, new Set())) {
    const excluded = new Set(Object.values(applied.tables[comparison.name as keyof typeof applied.tables].importerSkips).flat());
    const sourceRows = (await source.query<{ __key: string }>(comparison.sourceSql)).rows
      .filter((row) => !excluded.has(row.__key)).map((row) => JSON.stringify(row)).sort();
    const targetRows = (await target.query(comparison.targetSql)).rows.map((row) => JSON.stringify(row)).sort();
    assert.deepEqual(targetRows, sourceRows, comparison.name);
    assert.equal(sourceRows.length, EXPECTED_FULL[comparison.name]!.imported, `${comparison.name} projection count`);
  }
});

test("cloud import: post-0057 target keeps rw_, slugs, History origin and text source ids", async (t) => {
  const source = await cloudSource();
  const target = await controlTarget(true);
  t.after(async () => {
    await source.close();
    await target.close();
  });
  const report = await runImport({ source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "apply");
  assert.equal(report.ok, true, JSON.stringify(report.orgs));
  assert.deepEqual(report.optionalColumns.sort(), [
    "organizations.slug",
    "workspaces.cloud_relay_workspace_id",
    "workspaces.relaycast_api_key_generation",
    "workspaces.relayhistory_origin",
    "workspaces.slug",
  ]);
  assert.equal(report.tables.desktop_relay_identities.imported, 2);
  assert.equal(report.warnings.fleet_node_name_filled_with_node_id, undefined);

  const workspaces = (await target.query<{ id: string; cloud_relay_workspace_id: string | null; slug: string; relayhistory_origin: string | null }>(
    "SELECT id, cloud_relay_workspace_id, slug, relayhistory_origin FROM workspaces ORDER BY id")).rows;
  assert.deepEqual(workspaces, [
    { id: id(0x201), cloud_relay_workspace_id: "rw_0000a201", slug: "a1", relayhistory_origin: "https://history.example.test" },
    { id: id(0x205), cloud_relay_workspace_id: "rw_0000b201", slug: "b1", relayhistory_origin: null },
    { id: id(0x206), cloud_relay_workspace_id: null, slug: "b2", relayhistory_origin: null },
  ]);
  const desktop = (await target.query<{ source_id: string }>(
    "SELECT source_id FROM desktop_relay_identities WHERE id = $1", [id(0x602)])).rows[0]!;
  assert.equal(desktop.source_id, "not-a-uuid");
  const uuidSource = (await target.query<{ source_id: string }>(
    "SELECT source_id FROM desktop_relay_identities WHERE id = $1", [id(0x601)])).rows[0]!;
  assert.equal(uuidSource.source_id, id(0x9001));
  const fleet = (await target.query<{ node_name: string | null }>("SELECT node_name FROM fleet_node_owners")).rows;
  assert.deepEqual(fleet, [{ node_name: null }]);

  const optional = new Set(report.optionalColumns);
  for (const comparison of verifierComparisons({ orgIds: null }, optional)) {
    const excluded = new Set(Object.values(report.tables[comparison.name as keyof typeof report.tables].importerSkips).flat());
    const sourceRows = (await source.query<{ __key: string }>(comparison.sourceSql)).rows
      .filter((row) => !excluded.has(row.__key)).map((row) => JSON.stringify(row)).sort();
    const targetRows = (await target.query(comparison.targetSql)).rows.map((row) => JSON.stringify(row)).sort();
    assert.deepEqual(targetRows, sourceRows, comparison.name);
  }
});

test("cloud import: org scope imports one organization and its members only", async (t) => {
  const source = await cloudSource();
  t.after(() => source.close());
  const report = await runImport({ source, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: [ORG_B] }, "plan");
  assert.deepEqual(Object.keys(report.orgs), [ORG_B]);
  assert.equal(report.tables.organizations.imported, 1);
  // Members of B: user 2 (owner) and user 1 (admin via merged user 5).
  assert.equal(report.tables.users.imported, 2);
  assert.equal(report.tables.users.skipped.outside_org_scope, 2);
  assert.equal(report.tables.workspaces.imported, 2);
  assert.throws(() => verifierComparisons({ orgIds: ["not-a-uuid"] }), /UUID/);
});

test("cloud import: an existing Control user with an imported email under another id refuses the run", async (t) => {
  const source = await cloudSource();
  const target = await controlTarget();
  t.after(async () => {
    await source.close();
    await target.close();
  });
  await target.query("INSERT INTO users (id, email, name) VALUES ($1, 'bob@example.test', 'Existing Bob')", [id(0xfff)]);
  const report = await runImport({ source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "apply");
  assert.equal(report.ok, false);
  assert.equal(report.refused, "target_email_conflict");
  assert.equal(await count(target, "organizations"), 0);
  // The ledger never carries emails or secrets.
  const text = JSON.stringify(report);
  assert.doesNotMatch(text, /@example\.test|rk_live|tok_/);
});

test("cloud import: importer-side skips carry ids only", async (t) => {
  const source = await cloudSource();
  t.after(() => source.close());
  const report = await runImport({ source, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "plan");
  assert.deepEqual(report.tables.person_identities.importerSkips, { cloud_decrypt_failed: [id(0x403)] });
  // Without the Cloud key, plan still runs and says the envelopes were not opened.
  const keyless = await runImport({ source, keyring: KEYRING }, { orgIds: null }, "plan");
  assert.equal(keyless.ok, true);
  assert.deepEqual(keyless.tables.person_identities.importerSkips, {});
  assert.ok((keyless.warnings.secrets_not_checked ?? 0) > 0);
  await assert.rejects(runImport({ source, keyring: KEYRING }, { orgIds: null }, "dry-run"), /Cloud credential key/);
});
