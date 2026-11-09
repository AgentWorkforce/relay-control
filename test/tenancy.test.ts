import assert from "node:assert/strict";
import test from "node:test";
import { copyFile, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defaultMigrationsDirectory, migrate } from "../src/migrations.js";
import { ControlPlaneStore, OrganizationConflictError } from "../src/store.js";
import { loadIdentityConfig } from "../src/identity/config.js";
import { IdentityStore } from "../src/identity/store.js";
import { bootstrapOnce, type RelaycastProvisioner } from "../src/identity/bootstrap.js";
import { DEFAULT_PERSONAL_ORG_ON_SIGNIN, DEFAULT_SELF_SERVE_ORGANIZATIONS, loadTenancyConfig } from "../src/tenancy.js";
import { PGliteDatabase } from "./support/harness.js";

const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const BOOTSTRAP_ENV = {
  SELFHOST_BOOTSTRAP_ORG_NAME: "Acme",
  SELFHOST_BOOTSTRAP_ADMIN_EMAIL: "admin@acme.test",
};

test("SELFHOST_TENANCY: single by default, multi validated", () => {
  assert.deepEqual(loadTenancyConfig({}), { mode: "single", personalOrgOnSignIn: false, selfServeOrganizations: false });
  // Single mode ignores the multi-mode flags, even malformed ones.
  assert.equal(loadTenancyConfig({ SELFHOST_PERSONAL_ORG_ON_SIGNIN: "maybe" }).mode, "single");
  assert.deepEqual(loadTenancyConfig({ SELFHOST_TENANCY: "multi" }), {
    mode: "multi",
    personalOrgOnSignIn: DEFAULT_PERSONAL_ORG_ON_SIGNIN,
    selfServeOrganizations: DEFAULT_SELF_SERVE_ORGANIZATIONS,
  });
  assert.deepEqual(loadTenancyConfig({
    SELFHOST_TENANCY: "MULTI",
    SELFHOST_PERSONAL_ORG_ON_SIGNIN: "false",
    SELFHOST_SELF_SERVE_ORGANIZATIONS: "0",
  }), { mode: "multi", personalOrgOnSignIn: false, selfServeOrganizations: false });
  assert.throws(() => loadTenancyConfig({ SELFHOST_TENANCY: "many" }), /SELFHOST_TENANCY must be single or multi/);
  assert.throws(
    () => loadTenancyConfig({ SELFHOST_TENANCY: "multi", SELFHOST_SELF_SERVE_ORGANIZATIONS: "maybe" }),
    /SELFHOST_SELF_SERVE_ORGANIZATIONS must be true or false/,
  );

  assert.equal(loadIdentityConfig({}).tenancy.mode, "single");
  assert.throws(
    () => loadIdentityConfig({ SELFHOST_TENANCY: "multi" }),
    /requires SELFHOST_BOOTSTRAP_ORG_NAME and SELFHOST_BOOTSTRAP_ADMIN_EMAIL/,
  );
  assert.throws(
    () => loadIdentityConfig({ SELFHOST_TENANCY: "multi", ...BOOTSTRAP_ENV, SELFHOST_AUTO_JOIN_DOMAINS: "acme.test" }),
    /SELFHOST_AUTO_JOIN_DOMAINS is not supported with SELFHOST_TENANCY=multi/,
  );
  assert.equal(loadIdentityConfig({ SELFHOST_TENANCY: "multi", ...BOOTSTRAP_ENV }).tenancy.mode, "multi");
});

async function freshDatabase(t: test.TestContext) {
  const database = new PGliteDatabase();
  t.after(() => database.close());
  await migrate(database);
  return database;
}

async function organizationCount(database: PGliteDatabase): Promise<number> {
  const result = await database.query<{ count: number }>("SELECT count(*)::int AS count FROM organizations");
  return result.rows[0]!.count;
}

// PGlite runs every transaction on one connection, so these prove the outcome
// under concurrent callers, not real lock contention; on PostgreSQL the
// advisory lock 1947182642 is what serialises them.
test("single mode: parallel organization creators yield one organization and one 409", async (t) => {
  const database = await freshDatabase(t);
  const store = new ControlPlaneStore(database, KEYRING, 0);
  assert.equal(store.tenancy, "single");
  assert.equal(await store.ready(), true);
  const results = await Promise.allSettled([
    store.createOrganization({ name: "One", ownerEmail: "one@acme.test", ownerName: "One" }),
    store.createOrganization({ name: "Two", ownerEmail: "two@acme.test", ownerName: "Two" }),
  ]);
  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  const rejected = results.filter((result) => result.status === "rejected");
  assert.equal(rejected.length, 1);
  assert(rejected[0]!.reason instanceof OrganizationConflictError);
  assert.equal(await organizationCount(database), 1);
});

test("single mode: parallel bootstrap passes yield one organization and one workspace", async (t) => {
  const database = await freshDatabase(t);
  const control = new ControlPlaneStore(database, KEYRING, 0);
  const identityStore = new IdentityStore(database, KEYRING, {
    inviteTtlMs: 60_000,
    autoJoinDomains: [],
    issueSession: (tx, session) => control.issueBrowserSession(tx, session),
  });
  const created: string[] = [];
  const removed: string[] = [];
  const provisioner: RelaycastProvisioner = {
    async create() {
      const id = `rc-${created.length + 1}`;
      created.push(id);
      return { id, apiKey: `rk_live_${id}` };
    },
    async remove(id) {
      removed.push(id);
    },
  };
  const bootstrap = loadIdentityConfig(BOOTSTRAP_ENV).bootstrap!;
  const passes = await Promise.all([
    bootstrapOnce({ bootstrap, store: identityStore, provisioner, log: () => undefined }),
    bootstrapOnce({ bootstrap, store: identityStore, provisioner, log: () => undefined }),
  ]);
  assert.deepEqual(passes, ["done", "done"]);
  assert.equal(await organizationCount(database), 1);
  const workspaces = await database.query<{ relaycast_workspace_id: string }>(
    "SELECT relaycast_workspace_id FROM workspaces",
  );
  assert.equal(workspaces.rows.length, 1);
  // Any Relaycast workspace the losing pass provisioned is released again.
  assert.deepEqual(
    [...removed, workspaces.rows[0]!.relaycast_workspace_id].sort(),
    [...created].sort(),
  );

  // The bootstrap organization is the only one: the API creator gets the 409.
  await assert.rejects(
    control.createOrganization({ name: "Other", ownerEmail: "other@acme.test", ownerName: "Other" }),
    OrganizationConflictError,
  );
  assert.equal(await organizationCount(database), 1);
});

test("DG-004: an upgraded single installation keeps its SELFHOST_AUTO_JOIN_DOMAINS policy", async (t) => {
  // Seed a pre-0014 database (every migration before 0014) with a bootstrapped
  // organization, then apply 0014 and run a bootstrap pass with the env set.
  const legacy = await mkdtemp(join(tmpdir(), "relaycontrol-pre-0014-"));
  t.after(() => rm(legacy, { recursive: true, force: true }));
  const directory = defaultMigrationsDirectory();
  for (const name of await readdir(directory)) {
    if (/^\d+.*\.sql$/.test(name) && name < "0014") await copyFile(join(directory, name), join(legacy, name));
  }
  const database = new PGliteDatabase();
  t.after(() => database.close());
  const before = await migrate(database, legacy);
  const later = (await readdir(directory)).filter((name) => /^\d+.*\.sql$/.test(name) && name >= "0014").sort();
  assert.equal(before.length, (await readdir(directory)).filter((name) => /^\d+.*\.sql$/.test(name)).length - later.length);
  assert(!before.includes("0014_multi_tenant.sql"));
  const organizationId = "00000000-0000-4000-8000-0000000000aa";
  await database.query("INSERT INTO selfhost_organizations (id, name) VALUES ($1, 'Acme')", [organizationId]);
  await database.query(
    "INSERT INTO selfhost_installation_bootstrap (installation_slot, organization_id, admin_email) VALUES (1, $1, 'admin@acme.test')",
    [organizationId],
  );

  assert.deepEqual(await migrate(database), later);
  assert.equal(later[0], "0014_multi_tenant.sql");
  const control = new ControlPlaneStore(database, KEYRING, 0);
  const env = { ...BOOTSTRAP_ENV, SELFHOST_AUTO_JOIN_DOMAINS: "Acme.test, @Bücher.example" };
  const identityConfig = loadIdentityConfig(env);
  const identityStore = new IdentityStore(database, KEYRING, {
    inviteTtlMs: 60_000,
    autoJoinDomains: identityConfig.autoJoinDomains,
    issueSession: (tx, session) => control.issueBrowserSession(tx, session),
  });
  const pass = await identityStore.ensureOrganization(identityConfig.bootstrap!);
  assert.equal(pass.organizationId, organizationId);
  assert.equal(pass.created, false);
  assert.deepEqual(await identityStore.listDomains(organizationId), ["acme.test", "xn--bcher-kva.example"]);

  // SELFHOST_AUTO_JOIN_DOMAINS is the single-mode authority even when absent
  // or empty: each restart's bootstrap pass makes the rows equal it.
  const restart = async (domains: string | undefined) => {
    const env: Record<string, string | undefined> = { ...BOOTSTRAP_ENV };
    if (domains !== undefined) env.SELFHOST_AUTO_JOIN_DOMAINS = domains;
    const config = loadIdentityConfig(env);
    await new IdentityStore(database, KEYRING, {
      inviteTtlMs: 60_000,
      autoJoinDomains: config.autoJoinDomains,
      issueSession: (tx, session) => control.issueBrowserSession(tx, session),
    }).ensureOrganization(config.bootstrap!);
    return identityStore.listDomains(organizationId);
  };
  assert.deepEqual(await restart("acme.test beta.test"), ["acme.test", "beta.test"], "value change");
  assert.deepEqual(await restart(""), [], "explicit empty clears the rows");
  assert.deepEqual(await restart("acme.test"), ["acme.test"]);
  assert.deepEqual(await restart(undefined), [], "removal clears the rows");
  const audit = await database.query<{ target: string }>(
    "SELECT target FROM admin_audit_events WHERE action = 'organization.domains_env_sync'",
  );
  assert.equal(audit.rows.length, 5);
  assert.equal(await control.ready(), true);
});

test("DG-005: single tenancy over a multi-organization database fails readiness and deletes nothing", async (t) => {
  const database = await freshDatabase(t);
  await database.query("INSERT INTO organizations (id, name) VALUES (gen_random_uuid(), 'One'), (gen_random_uuid(), 'Two')");
  const single = new ControlPlaneStore(database, KEYRING, 0);
  assert.deepEqual(await single.readiness(), {
    ready: false,
    reason: "tenancy_mismatch",
    message: "SELFHOST_TENANCY=single but 2 organisations exist",
  });
  assert.equal(await organizationCount(database), 2);
  // The bootstrap pass changes nothing while mismatched (no admin grant, no
  // domain sync), even with SELFHOST_AUTO_JOIN_DOMAINS set.
  const config = loadIdentityConfig({ ...BOOTSTRAP_ENV, SELFHOST_AUTO_JOIN_DOMAINS: "acme.test" });
  const identityStore = new IdentityStore(database, KEYRING, {
    inviteTtlMs: 60_000,
    autoJoinDomains: config.autoJoinDomains,
    issueSession: (tx, session) => single.issueBrowserSession(tx, session),
  });
  assert.deepEqual(await identityStore.ensureOrganization(config.bootstrap!), {
    organizationId: null,
    skipped: "tenancy_mismatch",
    organizations: 2,
  });
  const logged: string[] = [];
  assert.equal(await bootstrapOnce({ bootstrap: config.bootstrap!, store: identityStore, provisioner: null, log: (message) => logged.push(message) }), "done");
  assert.match(logged.join("\n"), /bootstrap skipped/);
  const untouched = await database.query<{ users: number; domains: number; memberships: number }>(
    `SELECT (SELECT count(*)::int FROM users) AS users,
            (SELECT count(*)::int FROM organization_domains) AS domains,
            (SELECT count(*)::int FROM organization_memberships) AS memberships`,
  );
  assert.deepEqual(untouched.rows[0], { users: 0, domains: 0, memberships: 0 });
  assert.equal(await organizationCount(database), 2);
  assert.deepEqual(await new ControlPlaneStore(database, KEYRING, 0, { tenancy: "multi" }).readiness(), { ready: true });
});

test("DG-005: concurrent first sign-ins of one person create one personal organization", async (t) => {
  const database = await freshDatabase(t);
  const control = new ControlPlaneStore(database, KEYRING, 0, { tenancy: "multi" });
  const created: string[] = [];
  const removed: string[] = [];
  const provisioner: RelaycastProvisioner = {
    async create() {
      const id = `rc-${created.length + 1}`;
      created.push(id);
      return { id, apiKey: `rk_live_${id}` };
    },
    async remove(id) {
      removed.push(id);
    },
  };
  const identityStore = new IdentityStore(database, KEYRING, {
    inviteTtlMs: 60_000,
    autoJoinDomains: [],
    tenancy: loadTenancyConfig({ SELFHOST_TENANCY: "multi" }),
    provisioner,
    issueSession: (tx, session) => control.issueBrowserSession(tx, session),
  });
  const signIn = () => identityStore.signIn({ email: "Ada@Example.test", name: "Ada", inviteTokenHash: null, method: "oidc", emailVerified: true });
  const [first, second] = await Promise.all([signIn(), signIn()]);
  assert.equal(first.organizationId, second.organizationId);
  assert.equal(first.workspaceId, second.workspaceId);
  assert.equal(await organizationCount(database), 1);
  const org = await database.query<{ name: string }>("SELECT name FROM organizations");
  assert.equal(org.rows[0]!.name, "Ada's Workspace");
  const workspaces = await database.query<{ relaycast_workspace_id: string }>("SELECT relaycast_workspace_id FROM workspaces");
  assert.equal(workspaces.rows.length, 1);
  assert.deepEqual([...removed, workspaces.rows[0]!.relaycast_workspace_id].sort(), [...created].sort());
  const owners = await database.query<{ role: string }>("SELECT role FROM organization_memberships");
  assert.deepEqual(owners.rows.map((row) => row.role), ["owner"]);
  assert.equal([first, second].filter((result) => result.joined?.via === "personal").length, 1);
});
