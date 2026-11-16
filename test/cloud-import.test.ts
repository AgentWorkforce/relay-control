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
import { IMPORT_LEDGER_DDL, SOURCE_TABLES, TARGETS, verifierComparisons } from "../scripts/cloud-import/mapping.js";
import { PGliteDatabase } from "./support/harness.js";

const CLOUD_KEY = randomBytes(32).toString("hex");
const KEYRING: EncryptionKeyring = { active: { id: "import-test", key: randomBytes(32) } };

// 0061 (staff read grants, #165) is a checked-in migration now; this copy
// matches it and IF NOT EXISTS keeps it a no-op on the real migrations.
const POST_0058_DDL = `
-- 0061 (#165, staff read grants), same as the checked-in migration.
CREATE TABLE IF NOT EXISTS staff_read_grants (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  staff_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  staff_organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  reason text NOT NULL CONSTRAINT staff_read_grant_reason CHECK (length(btrim(reason)) > 0 AND length(reason) <= 500),
  token_hash text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  revoked_by uuid,
  last_used_at timestamptz,
  CONSTRAINT staff_read_grant_workspace FOREIGN KEY (workspace_id, organization_id)
    REFERENCES workspaces(id, organization_id) ON DELETE CASCADE,
  CONSTRAINT staff_read_grant_lifetime CHECK (expires_at > created_at AND expires_at <= created_at + interval '90 days')
);
-- 0064 (#169, lazy Relaycast binding), as proposed.
ALTER TABLE workspaces
  ALTER COLUMN relaycast_workspace_id DROP NOT NULL,
  ALTER COLUMN relaycast_api_key_ciphertext DROP NOT NULL,
  ADD CONSTRAINT workspaces_relaycast_binding_pair
    CHECK (
      (relaycast_workspace_id IS NULL AND relaycast_api_key_ciphertext IS NULL)
      OR (relaycast_workspace_id IS NOT NULL AND relaycast_api_key_ciphertext IS NOT NULL)
    );
-- 0058 (relay_managed coding agents) is a real migration now.
`;

async function cloudSource(): Promise<PGliteDatabase> {
  const source = new PGliteDatabase();
  await source.exec(CLOUD_FIXTURE_DDL);
  await source.exec(cloudFixtureSeed(CLOUD_KEY));
  return source;
}

/**
 * "0051": the baseline the importer gates down to (migrations <= 0051 only).
 * "current": every migration on this branch plus the proposed 0061.
 */
async function controlTarget(kind: "0051" | "current", ledger = true): Promise<PGliteDatabase> {
  const target = new PGliteDatabase();
  if (kind === "current") {
    await migrate(target);
    await target.exec(POST_0058_DDL);
    // 0063 already created the ledger; ledger=false drops it to test refusal.
    if (!ledger) await target.exec("DROP TABLE cloud_import_ledger");
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
    if (ledger) await target.exec(IMPORT_LEDGER_DDL);
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
  // Plan has no target, so the pre-0064 unbound-workspace gate cannot apply:
  // unbound workspaces (a2 no key, a3 no rw_) count as importable.
  expectedPlan.workspaces = { imported: 5, skipped: { workspace_being_deleted: 1 } };
  expectedPlan.coding_agent_credentials = { imported: 4, skipped: { secret_in_cloud_credential_store: 18 } };
  expectedPlan.github_app_installations = { imported: 1, skipped: {} };
  expectedPlan.staff_read_grants = { imported: 2, skipped: {} };
  expectedPlan.github_app_connections = {
    imported: 1,
    skipped: { named_connection_needs_policy: 1, installation_claimed_by_other_org: 1, invalid_installation_id: 1, duplicate_default_connection: 1 },
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
  // The target ledger holds every written key, per org, beside the rows.
  const ledgerRows = (await target.query<{ n: number }>("SELECT count(*)::int AS n FROM cloud_import_ledger")).rows[0]!.n;
  assert.equal(ledgerRows, SOURCE_TABLES.filter((t) => t !== "users").reduce((n, t) => n + applied.tables[t].imported, 0));
  const rerun = await runImport(deps, scope, "apply");
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
  const delta = await runImport(deps, scope, "apply");
  assert.equal(delta.ok, true, JSON.stringify(delta.orgs));
  assert.equal(delta.tables.organization_memberships.deleted, 1);
  assert.equal(delta.tables.organization_invitations.deleted, 1);
  assert.equal(delta.tables.person_identities.deleted, 1);
  // Carol (user 3) lost her membership, so her fleet node claim goes too (the
  // membership FK cascades before the explicit reconcile reaches it).
  assert.equal(delta.tables.fleet_node_owners.imported, 0);
  assert.equal(delta.tables.fleet_node_owners.deleted, 1, "logical removal, even though the cascade got there first");
  assert.equal(await count(target, "fleet_node_owners"), 0);
  assert.equal((await target.query("SELECT 1 FROM organization_memberships WHERE organization_id = $1 AND user_id = $2", [ORG_A, id(3)])).rows.length, 0);
  assert.equal((await target.query("SELECT 1 FROM organization_memberships WHERE organization_id = $1 AND user_id = $2", [ORG_B, id(6)])).rows.length, 1);
  // Canceling the newer invite un-supersedes the older one for the same
  // email; deleting first keeps the open-invite unique index satisfied.
  assert.deepEqual((await target.query<{ id: string }>("SELECT id FROM organization_invitations ORDER BY id")).rows.map((row) => row.id), [id(0x301), id(0x305)]);
  await target.query("DELETE FROM organization_memberships WHERE organization_id = $1 AND user_id = $2", [ORG_B, id(6)]);
  const finalReport = delta;
  // The ledger shrank by exactly the reconciled rows.
  assert.equal((await target.query<{ n: number }>("SELECT count(*)::int AS n FROM cloud_import_ledger")).rows[0]!.n,
    SOURCE_TABLES.filter((t) => t !== "users").reduce((n, t) => n + delta.tables[t].imported, 0));

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

test("cloud import: current target (main + proposed 0061) keeps rw_, slugs, History origin and text source ids", async (t) => {
  const source = await cloudSource();
  const target = await controlTarget("current");
  t.after(async () => {
    await source.close();
    await target.close();
  });
  // The operator organization of this Control install (staff grants record it).
  const OPS = id(0xc0ffee);
  await target.query("INSERT INTO organizations (id, name) VALUES ($1, 'Operator')", [OPS]);
  await target.query("INSERT INTO installation_bootstrap (installation_slot, organization_id) VALUES (1, $1) ON CONFLICT (installation_slot) DO UPDATE SET organization_id = EXCLUDED.organization_id", [OPS]);
  const report = await runImport({ source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "apply");
  assert.equal(report.ok, true, JSON.stringify(report.orgs));
  // Staff grants: revoked history with a fresh hash, lifetime clamped, audited once.
  const grant = (await target.query<{ staff_user_id: string; staff_organization_id: string; reason: string; token_hash: string; revoked_at: Date | null; lifetime: string }>(
    "SELECT staff_user_id, staff_organization_id, reason, token_hash, revoked_at, (expires_at - created_at)::text AS lifetime FROM staff_read_grants WHERE id = $1", [id(0xa01)])).rows[0]!;
  assert.equal(grant.staff_user_id, id(1), "merged staff user maps to the survivor");
  assert.equal(grant.staff_organization_id, OPS);
  assert.equal(grant.reason, "Investigating a support ticket");
  assert.match(grant.token_hash, /^[0-9a-f]{64}$/);
  assert.ok(grant.revoked_at);
  assert.equal(grant.lifetime, "90 days");
  const audits = async () => (await target.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM admin_audit_events WHERE action = 'staff_read_grant.imported' AND target = $1",
    [`${id(0xa01)} workspace ${id(0x201)}`])).rows[0]!.n;
  assert.equal(await audits(), 1);
  const again = await runImport({ source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "apply");
  assert.equal(again.ok, true);
  assert.equal(await audits(), 1, "re-runs do not re-audit");
  assert.equal((await target.query<{ token_hash: string }>("SELECT token_hash FROM staff_read_grants WHERE id = $1", [id(0xa01)])).rows[0]!.token_hash, grant.token_hash);
  assert.deepEqual(report.optionalColumns.sort(), [
    "organizations.slug",
    "workspaces.cloud_relay_workspace_id",
    "workspaces.relaycast_api_key_generation",
    "workspaces.relayhistory_origin",
    "workspaces.slug",
  ]);
  assert.equal(report.tables.desktop_relay_identities.imported, 2);
  // Canonical History origins are listed for SELFHOST_RELAYHISTORY_AUDIENCES.
  assert.deepEqual(report.relayhistoryOrigins, ["https://history.example.test"]);
  // A pluggable canonicaliser (Control's, once #163 merges) decides the value.
  const strict = await runImport({ source, keyring: KEYRING, cloudKeyHex: CLOUD_KEY, canonicalOrigin: () => null }, { orgIds: null }, "plan");
  assert.deepEqual(strict.relayhistoryOrigins, []);
  assert.equal(strict.warnings.relayhistory_origin_invalid_dropped, 1);
  assert.equal(report.warnings.fleet_node_name_filled_with_node_id, undefined);

  // R4 (0064): unbound Cloud workspaces arrive with the Relaycast pair NULL.
  const unbound = (await target.query<{ id: string; relaycast_workspace_id: string | null; relaycast_api_key_ciphertext: string | null; cloud_relay_workspace_id: string | null }>(
    "SELECT id, relaycast_workspace_id, relaycast_api_key_ciphertext, cloud_relay_workspace_id FROM workspaces WHERE relaycast_workspace_id IS NULL ORDER BY id")).rows;
  assert.deepEqual(unbound, [
    // a2: a Cloud rw_ whose Relaycast key is empty keeps its hosted rw_ identity.
    { id: id(0x202), relaycast_workspace_id: null, relaycast_api_key_ciphertext: null, cloud_relay_workspace_id: "rw_0000a202" },
    // a3: never had a relay workspace.
    { id: id(0x203), relaycast_workspace_id: null, relaycast_api_key_ciphertext: null, cloud_relay_workspace_id: null },
  ]);
  assert.equal(report.warnings.workspace_imported_unbound, 2);
  assert.equal(report.tables.person_identities.skipped.workspace_unbound, 1);
  assert.equal(report.tables.fleet_node_owners.skipped.workspace_unbound, 1);
  assert.equal(report.tables.coding_agent_credentials.imported, 4, "relay_managed rows on unbound workspaces import");
  const workspaces = (await target.query<{ id: string; cloud_relay_workspace_id: string | null; slug: string; relayhistory_origin: string | null }>(
    "SELECT id, cloud_relay_workspace_id, slug, relayhistory_origin FROM workspaces WHERE relaycast_workspace_id IS NOT NULL ORDER BY id")).rows;
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
    // On a2, which now imports unbound (0064); Cloud had it unselected.
    { id: id(0x804), is_active: false, harness_active: false, secret_ciphertext: null },
    // Stored as the alias "claude"; imported as anthropic, the only one in b1.
    { id: id(0x816), is_active: true, harness_active: false, secret_ciphertext: null },
  ]);
  const alias = (await target.query<{ model_provider: string }>(
    "SELECT model_provider FROM coding_agent_credentials WHERE id = $1", [id(0x816)])).rows[0]!;
  assert.equal(alias.model_provider, "anthropic");
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

test("cloud import: signup_source is carried normalised, unknown values as NULL, set on insert only (0068)", async (t) => {
  const source = await cloudSource();
  const target = await controlTarget("current");
  t.after(async () => {
    await source.close();
    await target.close();
  });
  // 0068 (#177, users.signup_source), as proposed.
  await target.exec(`ALTER TABLE users
    ADD COLUMN IF NOT EXISTS signup_source text,
    ADD CONSTRAINT users_signup_source_known
      CHECK (signup_source IS NULL OR signup_source IN ('teams', 'flows', 'desktop', 'mcp'));`);
  // Cloud's column has no CHECK: case, padding and unknown values all occur.
  await source.exec(`
    UPDATE users SET signup_source = ' Teams ' WHERE id = '${id(1)}';
    UPDATE users SET signup_source = 'desktop' WHERE id = '${id(5)}';
    UPDATE users SET signup_source = 'bogus' WHERE id = '${id(2)}';
    UPDATE users SET signup_source = 'MCP' WHERE id = '${id(6)}';`);
  const sources = async () => Object.fromEntries((await target.query<{ id: string; signup_source: string | null }>(
    "SELECT id::text AS id, signup_source FROM users ORDER BY id")).rows.map((row) => [row.id, row.signup_source]));
  const report = await runImport({ source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "apply");
  assert.equal(report.ok, true, JSON.stringify(report.orgs));
  assert.ok(report.optionalColumns.includes("users.signup_source"));
  assert.deepEqual(await sources(), {
    [id(1)]: "teams", // the survivor keeps its own value, not the merged duplicate's
    [id(2)]: null, // unknown Cloud value
    [id(3)]: null, // never set in Cloud
    [id(6)]: "mcp",
  });
  // A re-run never overwrites what the target holds, whatever Cloud says now.
  await target.query("UPDATE users SET signup_source = 'flows' WHERE id = $1", [id(1)]);
  await source.exec(`UPDATE users SET signup_source = 'desktop' WHERE id IN ('${id(1)}', '${id(2)}');`);
  const again = await runImport({ source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "apply");
  assert.equal(again.ok, true);
  assert.deepEqual(await sources(), { [id(1)]: "flows", [id(2)]: null, [id(3)]: null, [id(6)]: "mcp" });
});

test("cloud import: a re-run keeps a binding Control made lazily on an unbound import (0064)", async (t) => {
  const source = await cloudSource();
  const target = await controlTarget("current");
  t.after(async () => {
    await source.close();
    await target.close();
  });
  const deps = { source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY };
  assert.equal((await runImport(deps, { orgIds: null }, "apply")).ok, true);
  const pair = async (workspace: string) => (await target.query<{ rc: string | null; key: string | null; generation: number }>(
    "SELECT relaycast_workspace_id AS rc, relaycast_api_key_ciphertext AS key, relaycast_api_key_generation AS generation FROM workspaces WHERE id = $1",
    [workspace])).rows[0]!;
  assert.deepEqual(await pair(id(0x202)), { rc: null, key: null, generation: 1 });
  const bound = await pair(id(0x201));

  // Control binds a2 on first use (lazy binding), after the import.
  await target.query(
    "UPDATE workspaces SET relaycast_workspace_id = 'rc_lazy_a202', relaycast_api_key_ciphertext = 'control-ciphertext', relaycast_api_key_generation = 2 WHERE id = $1",
    [id(0x202)]);
  const again = await runImport(deps, { orgIds: null }, "apply");
  assert.equal(again.ok, true, JSON.stringify(again.orgs));
  assert.deepEqual(await pair(id(0x202)), { rc: "rc_lazy_a202", key: "control-ciphertext", generation: 2 }, "the lazy binding survives as one unit");
  assert.deepEqual(await pair(id(0x203)), { rc: null, key: null, generation: 1 }, "a still-unbound import stays unbound");
  assert.equal((await pair(id(0x201))).rc, bound.rc, "a bound import still takes Cloud's binding");

  // The verifier treats a2's lazy binding as expected: its projections agree.
  const columns = new Set(["workspaces.cloud_relay_workspace_id", "workspaces.slug", "workspaces.relaycast_api_key_generation"]);
  const workspaces = verifierComparisons({ orgIds: null }, columns, new Set()).find((comparison) => comparison.name === "workspaces")!;
  const excluded = new Set(Object.values(again.tables.workspaces.importerSkips).flat());
  const sourceRows = (await source.query<{ __key: string }>(workspaces.sourceSql)).rows
    .filter((row) => !excluded.has(row.__key)).map((row) => JSON.stringify(row)).sort();
  const targetRows = (await target.query(workspaces.targetSql)).rows.map((row) => JSON.stringify(row)).sort();
  assert.deepEqual(targetRows, sourceRows);
  // Bound imports are still compared for real.
  await target.query("UPDATE workspaces SET relaycast_workspace_id = 'rc_drifted' WHERE id = $1", [id(0x201)]);
  const drifted = (await target.query(workspaces.targetSql)).rows.map((row) => JSON.stringify(row)).sort();
  assert.notDeepEqual(drifted, sourceRows);
});

test("cloud import: a binding Control holds wins over a later Cloud binding and an older key generation", async (t) => {
  const source = await cloudSource();
  const target = await controlTarget("current");
  t.after(async () => {
    await source.close();
    await target.close();
  });
  const deps = { source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY };
  assert.equal((await runImport(deps, { orgIds: null }, "apply")).ok, true);
  const pair = async (workspace: string) => (await target.query<{ rc: string | null; key: string | null; generation: number }>(
    "SELECT relaycast_workspace_id AS rc, relaycast_api_key_ciphertext AS key, relaycast_api_key_generation AS generation FROM workspaces WHERE id = $1",
    [workspace])).rows[0]!;
  // Control binds a2 lazily, and rotates a1's key (generation 1 -> 5).
  await target.query(
    "UPDATE workspaces SET relaycast_workspace_id = 'rc_lazy_a202', relaycast_api_key_ciphertext = 'control-ciphertext', relaycast_api_key_generation = 2 WHERE id = $1",
    [id(0x202)]);
  await target.query("UPDATE workspaces SET relaycast_api_key_ciphertext = 'control-rotated', relaycast_api_key_generation = 5 WHERE id = $1", [id(0x201)]);
  const a1 = await pair(id(0x201));
  // Then Cloud binds a2 too, to a different Relaycast workspace.
  await source.exec("UPDATE relay_workspaces SET relaycast_api_key = 'rk_cloud_late', relaycast_workspace_id = 'rc-ws-a2-cloud', relaycast_api_key_generation = 3 WHERE id = 'rw_0000a202'");

  const again = await runImport(deps, { orgIds: null }, "apply");
  assert.equal(again.ok, true, JSON.stringify(again.orgs));
  assert.deepEqual(await pair(id(0x202)), { rc: "rc_lazy_a202", key: "control-ciphertext", generation: 2 }, "Control's binding is kept");
  assert.deepEqual(await pair(id(0x201)), a1, "a generation never goes backwards");
  assert.equal(again.warnings.workspaces_binding_conflict, 1);
  assert.equal(again.warnings.workspaces_generation_kept, 1);
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

test("cloud import: a source branch without staff_read_grants imports the rest", async (t) => {
  const source = await cloudSource();
  t.after(() => source.close());
  await source.exec("DROP TABLE staff_read_grants");
  const report = await runImport({ source, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "plan");
  assert.equal(report.ok, true);
  assert.equal(report.warnings.source_lacks_staff_read_grants, 1);
  assert.equal(report.tables.staff_read_grants.candidates, 0);
  assert.equal(report.tables.users.imported, 4);
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

test("cloud import: ledger guards: no ledger table refuses; a Control-native org is refused alone", async (t) => {
  const source = await cloudSource();
  const bare = await controlTarget("0051", false);
  const target = await controlTarget("0051");
  t.after(async () => {
    await source.close();
    await bare.close();
    await target.close();
  });
  const refused = await runImport({ source, target: bare, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "apply");
  assert.equal(refused.refused, "target_lacks_import_ledger");
  assert.equal(await count(bare, "organizations"), 0);

  // Org B already exists in Control without a ledger entry: it was not
  // imported, so it is refused (never merged into); org A still imports.
  await target.query("INSERT INTO organizations (id, name) VALUES ($1, 'Native B')", [ORG_B]);
  // A credential-copier marker must not make a native org look imported.
  await target.query(
    "INSERT INTO cloud_import_ledger (organization_id, table_name, row_key, mapping_revision) VALUES ($1, 'copier_login', 'x:1', 'test')",
    [ORG_B],
  );
  await target.query("INSERT INTO users (id, email, name) VALUES ($1, 'native@example.test', 'Native')", [id(0xeee)]);
  await target.query("INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, 'owner')", [ORG_B, id(0xeee)]);
  const report = await runImport({ source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "apply");
  assert.equal(report.ok, false);
  assert.equal(report.orgs[ORG_A]!.status, "ok");
  assert.deepEqual(report.orgs[ORG_B]!.error, { code: "org_exists_without_ledger" });
  assert.equal((await target.query<{ name: string }>("SELECT name FROM organizations WHERE id = $1", [ORG_B])).rows[0]!.name, "Native B");
  // Re-running never deletes the native membership: it is not in the ledger.
  await runImport({ source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "apply");
  assert.equal((await target.query("SELECT 1 FROM organization_memberships WHERE organization_id = $1 AND user_id = $2", [ORG_B, id(0xeee)])).rows.length, 1);
});

test("cloud import: transforms are time-zone independent (90-day clamp across DST)", async (t) => {
  const source = await cloudSource();
  const target = await controlTarget("current");
  t.after(async () => {
    await source.close();
    await target.close();
  });
  // A session zone with a DST change inside the 90-day window (late March).
  await source.exec("SET TIME ZONE 'Europe/Oslo'");
  const OPS = id(0xc0ffee);
  await target.query("INSERT INTO organizations (id, name) VALUES ($1, 'Operator')", [OPS]);
  await target.query("INSERT INTO installation_bootstrap (installation_slot, organization_id) VALUES (1, $1) ON CONFLICT (installation_slot) DO UPDATE SET organization_id = EXCLUDED.organization_id", [OPS]);
  const report = await runImport({ source, target, keyring: KEYRING, cloudKeyHex: CLOUD_KEY }, { orgIds: null }, "apply");
  assert.equal(report.ok, true, JSON.stringify(report.orgs));
  const grant = (await target.query<{ expires_at: string }>(
    "SELECT to_char(expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US') AS expires_at FROM staff_read_grants WHERE id = $1", [id(0xa01)])).rows[0]!;
  assert.equal(grant.expires_at, "2026-04-01T00:00:00.123456", "created_at + 90 days in UTC, not in the session zone");
});
