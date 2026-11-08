import assert from "node:assert/strict";
import test from "node:test";
import { PostgresDatabase } from "../src/database.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore, OrganizationConflictError } from "../src/store.js";
import { loadIdentityConfig } from "../src/identity/config.js";
import { IdentityError, IdentityStore } from "../src/identity/store.js";
import { loadTenancyConfig } from "../src/tenancy.js";
import { bootstrapOnce, type RelaycastProvisioner } from "../src/identity/bootstrap.js";

/*
 * Two-connection race skeleton for the advisory lock order (src/tenancy.ts).
 * PGlite has one connection and serialises transactions, so the in-process
 * suites prove the logic only; this file proves the ordering against a real
 * server. It runs only when TEST_DATABASE_URL names a THROWAWAY database: it
 * migrates it and refuses to run if any organization other than this file's
 * own fixtures exists (so it can be re-run on the same database).
 * Skipped (visibly) otherwise; CI evidence stays the PGlite suites.
 */
const url = process.env.TEST_DATABASE_URL;
const skip = url ? false : "TEST_DATABASE_URL is not set (two-connection lock-order race needs a throwaway Postgres)";
const KEYRING = { active: { id: "race-key", key: Buffer.alloc(32, 9) } };
const EMAIL = "ada@race.test";
// "Ada's Workspace" is the personal organization a sign-in that wins the race creates.
const FIXTURE_ORGS = ["Race", "Ada Co", "Ada's Workspace", "Solo", "Other"];

test("lock order: one identity racing first sign-in, create-organization and bootstrap on two connections", { skip, timeout: 60_000 }, async (t) => {
  // Two pools, so the three writers run on different server connections.
  const first = new PostgresDatabase(url!);
  const second = new PostgresDatabase(url!);
  t.after(async () => {
    await first.close();
    await second.close();
  });
  await migrate(first);
  const foreign = await first.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM selfhost_organizations WHERE name <> ALL($1::text[])",
    [FIXTURE_ORGS],
  );
  assert.equal(foreign.rows[0]!.n, 0, "TEST_DATABASE_URL must be an empty throwaway database");
  // A previous run (this test and the single-mode one) may have left its
  // fixtures behind: start from a first sign-in again.
  await first.query("DELETE FROM selfhost_organizations WHERE name = ANY($1::text[])", [FIXTURE_ORGS]);
  await first.query("DELETE FROM selfhost_installation_bootstrap");
  await first.query("DELETE FROM selfhost_users WHERE email = $1", [EMAIL]);

  const tenancy = loadTenancyConfig({ SELFHOST_TENANCY: "multi" });
  const provisioner: RelaycastProvisioner = {
    async create(name) {
      return { id: `rc-${name.length}-${Math.random().toString(36).slice(2)}`, apiKey: "rk_live_race" };
    },
    async remove() {},
  };
  const identity = (database: PostgresDatabase) => {
    const control = new ControlPlaneStore(database, KEYRING, 0, { tenancy: "multi" });
    return {
      control,
      store: new IdentityStore(database, KEYRING, {
        inviteTtlMs: 60_000,
        autoJoinDomains: [],
        tenancy,
        provisioner,
        issueSession: (tx, session) => control.issueBrowserSession(tx, session),
      }),
    };
  };
  const a = identity(first);
  const b = identity(second);
  const config = loadIdentityConfig({ SELFHOST_TENANCY: "multi", SELFHOST_BOOTSTRAP_ORG_NAME: "Race", SELFHOST_BOOTSTRAP_ADMIN_EMAIL: EMAIL });

  const signInInput = { email: EMAIL, name: "Ada", inviteTokenHash: null, method: "oidc" as const, emailVerified: true };
  const [signedIn, created, ensured] = await Promise.allSettled([
    a.store.signIn(signInInput),
    b.control.createOrganization({ name: "Ada Co", ownerEmail: EMAIL, ownerName: "Ada" }),
    b.store.ensureOrganization(config.bootstrap!),
  ]);
  for (const result of [signedIn, created, ensured]) {
    if (result.status === "rejected") assert(!/deadlock/i.test(String(result.reason)), `deadlock: ${String(result.reason)}`);
  }
  // not_ready is the retryable window that predates design G (main 1f08cb6,
  // identity/store.ts ensureOrganization then bootstrapOnce): the owner
  // membership commits before its workspace is provisioned.
  if (signedIn.status === "rejected") {
    assert(signedIn.reason instanceof IdentityError && signedIn.reason.code === "not_ready", String(signedIn.reason));
  }
  assert.equal(created.status, "fulfilled", String((created as PromiseRejectedResult).reason ?? ""));
  assert.equal(ensured.status, "fulfilled", String((ensured as PromiseRejectedResult).reason ?? ""));

  // Convergence: finish provisioning the way the server does (the bootstrap
  // pass), give "Ada Co" (created by the bootstrap-bearer form, which makes
  // no workspace) one through the store, then the same sign-in succeeds.
  assert.equal(await bootstrapOnce({ bootstrap: config.bootstrap!, store: b.store, provisioner, log: () => {} }), "done");
  if (created.status === "fulfilled") {
    await b.control.createWorkspace({ organizationId: created.value.id, name: "Default", relaycastApiKey: "rk_live_race" });
  }
  const again = await a.store.signIn(signInInput);
  const member = await first.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM selfhost_organization_memberships m
       JOIN selfhost_users u ON u.id = m.user_id
      WHERE u.email = $1 AND m.organization_id = $2`,
    [EMAIL, again.organizationId],
  );
  assert.equal(member.rows[0]!.n, 1, "the session's organization is one the user belongs to");
  const users = await first.query<{ n: number }>("SELECT count(*)::int AS n FROM selfhost_users WHERE email = $1", [EMAIL]);
  assert.equal(users.rows[0]!.n, 1);
  const bootstrapOrgs = await first.query<{ n: number }>("SELECT count(*)::int AS n FROM selfhost_organizations WHERE name = 'Race'");
  assert.equal(bootstrapOrgs.rows[0]!.n, 1);
});

test("lock order: single-mode bootstrap and create-organization race to one organization on two connections", { skip, timeout: 60_000 }, async (t) => {
  const first = new PostgresDatabase(url!);
  const second = new PostgresDatabase(url!);
  t.after(async () => {
    await first.close();
    await second.close();
  });
  await migrate(first);
  // Runs after the multi test in the same throwaway database: start clean.
  await first.query("DELETE FROM selfhost_organizations");
  await first.query("DELETE FROM selfhost_installation_bootstrap");
  const control = new ControlPlaneStore(second, KEYRING, 0);
  const store = new IdentityStore(first, KEYRING, {
    inviteTtlMs: 60_000,
    autoJoinDomains: [],
    issueSession: (tx, session) => control.issueBrowserSession(tx, session),
  });
  const config = loadIdentityConfig({ SELFHOST_BOOTSTRAP_ORG_NAME: "Solo", SELFHOST_BOOTSTRAP_ADMIN_EMAIL: EMAIL });
  const [bootstrap, created] = await Promise.allSettled([
    store.ensureOrganization(config.bootstrap!),
    control.createOrganization({ name: "Other", ownerEmail: EMAIL, ownerName: "Ada" }),
  ]);
  assert.equal(bootstrap.status, "fulfilled", String((bootstrap as PromiseRejectedResult).reason ?? ""));
  if (created.status === "rejected") assert(created.reason instanceof OrganizationConflictError, String(created.reason));
  const orgs = await first.query<{ n: number }>("SELECT count(*)::int AS n FROM selfhost_organizations");
  assert.equal(orgs.rows[0]!.n, 1);
});
