import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import test from "node:test";
import { decryptSecret, type EncryptionKeyring } from "../src/crypto.js";
import { copyFile, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultMigrationsDirectory, migrate } from "../src/migrations.js";
import {
  CLOUD_FIXTURE_DDL,
  EXPECTED_FULL,
  ORG_A,
  ORG_B,
  cloudFixtureSeed,
  id,
} from "../scripts/cloud-import/cloud-fixture.js";
import { runImport, type ImportReport } from "../scripts/cloud-import/importer.js";
import { SOURCE_TABLES, TARGETS, verifierComparisons } from "../scripts/cloud-import/mapping.js";
import { PGliteDatabase } from "./support/harness.js";

const CLOUD_KEY = randomBytes(32).toString("hex");
const KEYRING: EncryptionKeyring = { active: { id: "import-test", key: randomBytes(32) } };

// 0058 (relay_managed coding agents, control-relay-managed) is not on main
// yet; the "current" target approximates it on top of the real migrations.
const POST_0058_DDL = `
-- 0058 (control-relay-managed), approximated: relay_managed rows carry no secret.
ALTER TABLE coding_agent_credentials
  ALTER COLUMN secret_preview DROP NOT NULL,
  ALTER COLUMN key_fingerprint DROP NOT NULL,
  DROP CONSTRAINT IF EXISTS selfhost_coding_agent_auth_type,
  DROP CONSTRAINT IF EXISTS coding_agent_auth_type,
  DROP CONSTRAINT IF EXISTS selfhost_coding_agent_secret_storage,
  DROP CONSTRAINT IF EXISTS coding_agent_secret_storage,
  ADD CONSTRAINT coding_agent_auth_type
    CHECK (auth_type IN ('byo_api_key', 'oauth_token', 'provider_oauth', 'relay_managed')),
  ADD CONSTRAINT coding_agent_secret_storage CHECK (
    (auth_type = 'relay_managed' AND secret_ciphertext IS NULL AND NOT harness_active)
    OR (auth_type = 'provider_oauth' AND secret_ciphertext IS NULL AND blob_location IS NOT NULL)
    OR (auth_type IN ('byo_api_key', 'oauth_token') AND secret_ciphertext IS NOT NULL)
  );
`;

async function cloudSource(): Promise<PGliteDatabase> {
  const source = new PGliteDatabase();
  await source.exec(CLOUD_FIXTURE_DDL);
  await source.exec(cloudFixtureSeed(CLOUD_KEY));
  return source;
}

/**
 * "0051": the baseline the importer gates down to (migrations <= 0051 only).
 * "current": every migration on this branch plus the 0058 approximation.
 */
async function controlTarget(kind: "0051" | "current"): Promise<PGliteDatabase> {
  const target = new PGliteDatabase();
  if (kind === "current") {
    await migrate(target);
    await target.exec(POST_0058_DDL);
    return target;
  }
  const directory = await mkdtemp(join(tmpdir(), "cloud-import-0051-"));
  try {
    for (const name of await readdir(defaultMigrationsDirectory())) {
      if (/^\d+/.test(name) && Number(name.slice(0, 4)) <= 51) {
        await copyFile(join(defaultMigrationsDirectory(), name), join(directory, name));
      }
    }
    await migrate(target, directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
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
  const target = await controlTarget("0051");
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
  expectedPlan.coding_agent_credentials = { imported: 2, skipped: { workspace_not_imported: 1, secret_in_cloud_credential_store: 5 } };
  expectedPlan.github_app_installations = { imported: 1, skipped: {} };
  expectedPlan.github_app_connections = {
    imported: 1,
    skipped: { named_connection_needs_policy: 1, installation_claimed_by_other_org: 1, invalid_installation_id: 1 },
  };
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
  // The ledger lists only rows actually written: target-side filters
  // (pre-0057 source_id, pre-0058 relay_managed, pre-0054 GitHub) apply first.
  assert.deepEqual(applied.orgs[ORG_A]!.keys.desktop_relay_identities, [id(0x601)]);
  assert.deepEqual(applied.orgs[ORG_A]!.keys.coding_agent_credentials, []);
  assert.deepEqual(applied.orgs[ORG_A]!.keys.github_app_connections, []);
  for (const table of SOURCE_TABLES.filter((t) => t !== "users")) {
    const keys = Object.values(applied.orgs).flatMap((org) => org.keys[table] ?? []);
    assert.equal(keys.length, applied.tables[table].imported, `${table} ledger keys match imported`);
  }

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
  const counts = async () => Object.fromEntries(await Promise.all(SOURCE_TABLES
    .filter((table) => !TARGETS[table].gate)
    .map(async (table) => [table, await count(target, TARGETS[table].table)] as const)));
  const before = await counts();
  // A re-run without the previous ledger is refused: it could not reconcile.
  const blind = await runImport(deps, scope, "apply");
  assert.equal(blind.refused, "rerun_requires_previous_report");
  assert.deepEqual(await counts(), before);
  const rerun = await runImport(deps, scope, "apply", { previous: applied });
  assert.equal(rerun.ok, true);
  assert.deepEqual(await counts(), before);
  assert.equal(Object.values(rerun.tables).reduce((n, ledger) => n + ledger.deleted, 0), 0);
  const inviteAfter = (await target.query<{ token_hash: string }>(
    "SELECT token_hash FROM organization_invitations WHERE id = $1", [id(0x302)])).rows[0]!;
  assert.equal(inviteAfter.token_hash, invite.token_hash);

  // Delta after removals in Cloud: the reconcile deletes exactly the rows this
  // tool imported earlier that the source no longer yields.
  await source.exec(`
    DELETE FROM organization_memberships WHERE organization_id = '${ORG_A}' AND user_id = '${id(3)}';
    UPDATE organization_invites SET canceled_at = now() WHERE id = '${id(0x302)}';
    DELETE FROM workspace_person_identities WHERE id = '${id(0x401)}';
  `);
  // A Control-side row the import never wrote must survive the reconcile.
  await target.query("INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, 'member')", [ORG_B, id(6)]);
  const delta = await runImport(deps, scope, "apply", { previous: rerun });
  assert.equal(delta.ok, true, JSON.stringify(delta.orgs));
  assert.equal(delta.tables.organization_memberships.deleted, 1);
  assert.equal(delta.tables.organization_invitations.deleted, 1);
  assert.equal(delta.tables.person_identities.deleted, 1);
  // Carol (user 3) lost her membership, so her fleet node claim goes too (the
  // membership FK cascades before the explicit reconcile reaches it).
  assert.equal(delta.tables.fleet_node_owners.imported, 0);
  assert.equal(await count(target, "fleet_node_owners"), 0);
  assert.equal((await target.query("SELECT 1 FROM organization_memberships WHERE organization_id = $1 AND user_id = $2", [ORG_A, id(3)])).rows.length, 0);
  assert.equal((await target.query("SELECT 1 FROM organization_memberships WHERE organization_id = $1 AND user_id = $2", [ORG_B, id(6)])).rows.length, 1);
  // Canceling the newer invite un-supersedes the older one for the same
  // email; deleting first keeps the open-invite unique index satisfied.
  assert.deepEqual((await target.query<{ id: string }>("SELECT id FROM organization_invitations ORDER BY id")).rows.map((row) => row.id), [id(0x301), id(0x305)]);
  await target.query("DELETE FROM organization_memberships WHERE organization_id = $1 AND user_id = $2", [ORG_B, id(6)]);
  const finalReport = delta;

  // The verifier projections agree row for row with what was imported.
  for (const comparison of verifierComparisons(scope, new Set(), new Set())) {
    const excluded = new Set(Object.values(finalReport.tables[comparison.name as keyof typeof finalReport.tables].importerSkips).flat());
    const sourceRows = (await source.query<{ __key: string }>(comparison.sourceSql)).rows
      .filter((row) => !excluded.has(row.__key)).map((row) => JSON.stringify(row)).sort();
    const targetRows = (await target.query(comparison.targetSql)).rows.map((row) => JSON.stringify(row)).sort();
    assert.deepEqual(targetRows, sourceRows, comparison.name);
    assert.equal(sourceRows.length, finalReport.tables[comparison.name as keyof typeof finalReport.tables].imported, `${comparison.name} projection count`);
  }
});

test("cloud import: current target (0053-0057 + 0058) keeps rw_, slugs, History origin and text source ids", async (t) => {
  const source = await cloudSource();
  const target = await controlTarget("current");
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
  const agents = (await target.query<{ id: string; is_active: boolean; harness_active: boolean; secret_ciphertext: string | null }>(
    "SELECT id, is_active, harness_active, secret_ciphertext FROM coding_agent_credentials ORDER BY id")).rows;
  assert.deepEqual(agents, [
    { id: id(0x801), is_active: true, harness_active: false, secret_ciphertext: null },
    { id: id(0x802), is_active: false, harness_active: false, secret_ciphertext: null },
  ]);
  assert.equal(report.warnings.coding_agent_active_demoted, 1);
  const github = (await target.query<{ id: string; installation_id: string; github_app_organization_id: string; credentials_ciphertext: string; created_by_user_id: string }>(
    "SELECT id, installation_id, github_app_organization_id, credentials_ciphertext, created_by_user_id FROM integration_connections WHERE auth_mode = 'github_app'")).rows;
  assert.equal(github.length, 1);
  assert.deepEqual({ ...github[0], credentials_ciphertext: undefined }, {
    id: id(0x901), installation_id: "12345", github_app_organization_id: ORG_A, credentials_ciphertext: undefined, created_by_user_id: id(1),
  });
  assert.equal(decryptSecret(github[0]!.credentials_ciphertext, KEYRING), "{}");
  assert.deepEqual((await target.query("SELECT installation_id, organization_id FROM github_app_installations")).rows,
    [{ installation_id: "12345", organization_id: ORG_A }]);
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
  const target = await controlTarget("0051");
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
