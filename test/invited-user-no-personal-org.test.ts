import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { hashSecret } from "../src/crypto.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import type { RelaycastProvisioner } from "../src/identity/bootstrap.js";
import { IdentityError, IdentityStore, type SignInMethod } from "../src/identity/store.js";
import { loadTenancyConfig } from "../src/tenancy.js";
import { PGliteDatabase } from "./support/harness.js";
import { API, call, PASSWORD, registerVerified, session, sessionCookie, setup as passwordSetup } from "./support/password.js";

// SELFHOST_TENANCY=multi with personal organizations on (the default): a
// person with an open invite joins the inviting organization and never gets
// a personal one; only people with no open invite do.

const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const INVITE_TTL_MS = 60_000;
const BOOTSTRAP_ACTOR = { kind: "bootstrap" } as const;

async function harness(t: test.TestContext) {
  const database = new PGliteDatabase();
  t.after(() => database.close());
  await migrate(database);
  const control = new ControlPlaneStore(database, KEYRING, 0, { tenancy: "multi" });
  const clock = { now: Date.now() };
  const created: string[] = [];
  const removed: string[] = [];
  // Runs inside create(), between the two sign-in transactions.
  let duringCreate: (() => Promise<void>) | null = null;
  const provisioner: RelaycastProvisioner = {
    async create() {
      const id = `rc-${created.length + 1}`;
      created.push(id);
      const hook = duringCreate;
      duringCreate = null;
      if (hook) await hook();
      return { id, apiKey: `rk_live_${id}` };
    },
    async remove(id) {
      removed.push(id);
    },
  };
  const identityStore = new IdentityStore(database, KEYRING, {
    inviteTtlMs: INVITE_TTL_MS,
    autoJoinDomains: [],
    tenancy: loadTenancyConfig({ SELFHOST_TENANCY: "multi" }),
    provisioner,
    now: () => clock.now,
    issueSession: (tx, issued) => control.issueBrowserSession(tx, issued),
  });
  const acme = await control.createOrganization({ name: "Acme", ownerEmail: "admin@acme.test", ownerName: "Admin" });
  await control.createWorkspace({ organizationId: acme.id, name: "Default", relaycastWorkspaceId: "rc-acme", relaycastApiKey: "rk_live_acme" });

  const organizations = async () =>
    (await database.query<{ count: number }>("SELECT count(*)::int AS count FROM organizations")).rows[0]!.count;
  const ctx = {
    database,
    identityStore,
    clock,
    created,
    removed,
    acmeId: acme.id,
    organizations,
    onCreate(hook: () => Promise<void>) {
      duringCreate = hook;
    },
    async invite(email: string, role: "admin" | "member" = "member") {
      return identityStore.createInvitation({ organizationId: acme.id, email, role, actor: BOOTSTRAP_ACTOR });
    },
    async snapshot() {
      return { organizations: await organizations(), creates: created.length };
    },
    async roleIn(organizationId: string, email: string): Promise<string | null> {
      const result = await database.query<{ role: string }>(
        `SELECT m.role FROM organization_memberships m JOIN users u ON u.id = m.user_id
          WHERE m.organization_id = $1 AND u.email = $2`,
        [organizationId, email],
      );
      return result.rows[0]?.role ?? null;
    },
    async membershipCount(email: string): Promise<number> {
      const result = await database.query<{ count: number }>(
        `SELECT count(*)::int AS count FROM organization_memberships m JOIN users u ON u.id = m.user_id WHERE u.email = $1`,
        [email],
      );
      return result.rows[0]!.count;
    },
    signIn(email: string, options: { token?: string; method?: SignInMethod; emailVerified?: boolean; name?: string } = {}) {
      return identityStore.signIn({
        email,
        name: options.name ?? null,
        inviteTokenHash: options.token ? hashSecret(options.token) : null,
        method: options.method ?? "oidc",
        ...(options.emailVerified === undefined ? {} : { emailVerified: options.emailVerified }),
      });
    },
  };
  return ctx;
}

type Ctx = Awaited<ReturnType<typeof harness>>;

/** The person is in the inviting organization only, and nothing was provisioned. */
async function assertJoinedInvitingOrg(ctx: Ctx, email: string, before: { organizations: number; creates: number }, role = "member") {
  assert.equal(await ctx.roleIn(ctx.acmeId, email), role);
  assert.equal(await ctx.membershipCount(email), 1, `${email} has no other membership`);
  assert.equal(await ctx.organizations(), before.organizations, "no organization was created");
  assert.equal(ctx.created.length, before.creates, "no Relaycast workspace was provisioned");
}

async function rejectsWith(promise: Promise<unknown>, status: number, code: string) {
  await assert.rejects(promise, (error: unknown) => {
    assert(error instanceof IdentityError, String(error));
    assert.equal(error.status, status);
    assert.equal(error.code, code);
    return true;
  });
}

test("multi invited: every sign-in method joins the inviting organization, with and without the invite token", async (t) => {
  const ctx = await harness(t);
  for (const method of ["password", "oidc", "microsoft", "email"] as const) {
    for (const withToken of [true, false]) {
      const email = `${method}-${withToken ? "token" : "plain"}@elsewhere.test`;
      const { token } = await ctx.invite(email);
      const before = await ctx.snapshot();
      const signedIn = await ctx.signIn(email, { method, ...(withToken ? { token } : {}) });
      assert.equal(signedIn.organizationId, ctx.acmeId, `${method} ${withToken}`);
      assert.deepEqual(signedIn.joined, { role: "member", via: "invite" });
      await assertJoinedInvitingOrg(ctx, email, before);
      // The next sign-in stays in the inviting organization.
      const again = await ctx.signIn(email, { method });
      assert.equal(again.organizationId, ctx.acmeId);
      await assertJoinedInvitingOrg(ctx, email, before);
    }
  }
  assert.deepEqual(ctx.removed, []);
});

test("multi invited: an invite created while a personal workspace is being provisioned wins and the workspace is released", async (t) => {
  const ctx = await harness(t);
  const email = "late-invite@elsewhere.test";
  const before = await ctx.snapshot();
  ctx.onCreate(async () => {
    await ctx.invite(email);
  });
  const signedIn = await ctx.signIn(email, { name: "Late" });
  assert.equal(signedIn.organizationId, ctx.acmeId);
  assert.deepEqual(signedIn.joined, { role: "member", via: "invite" });
  // The race forces one create; its workspace is released, none is kept.
  assert.equal(ctx.created.length, before.creates + 1);
  assert.deepEqual(ctx.removed, ctx.created.slice(before.creates));
  const kept = await ctx.database.query("SELECT 1 FROM workspaces WHERE relaycast_workspace_id = ANY($1)", [ctx.created]);
  assert.equal(kept.rows.length, 0);
  assert.equal(await ctx.roleIn(ctx.acmeId, email), "member");
  assert.equal(await ctx.membershipCount(email), 1);
  assert.equal(await ctx.organizations(), before.organizations);
});

test("multi invited: someone who already has a personal organization joins the inviting one on the next sign-in", async (t) => {
  const ctx = await harness(t);
  const email = "early@elsewhere.test";
  const first = await ctx.signIn(email, { name: "Early" });
  assert.deepEqual(first.joined, { role: "owner", via: "personal" });
  assert.notEqual(first.organizationId, ctx.acmeId);

  const { token } = await ctx.invite(email, "admin");
  const before = await ctx.snapshot();
  const second = await ctx.signIn(email, { token });
  assert.equal(second.organizationId, ctx.acmeId);
  assert.deepEqual(second.joined, { role: "admin", via: "invite" });
  assert.equal(await ctx.roleIn(ctx.acmeId, email), "admin");
  // The earlier personal organization is kept; nothing new was created.
  assert.equal(await ctx.roleIn(first.organizationId, email), "owner");
  assert.equal(await ctx.membershipCount(email), 2);
  assert.equal(await ctx.organizations(), before.organizations);
  assert.equal(ctx.created.length, before.creates);

  // Without the token the open invite is accepted all the same.
  const other = "early-plain@elsewhere.test";
  const personal = await ctx.signIn(other);
  await ctx.invite(other);
  const beforePlain = await ctx.snapshot();
  const joined = await ctx.signIn(other);
  assert.equal(joined.organizationId, ctx.acmeId);
  assert.equal(await ctx.roleIn(ctx.acmeId, other), "member");
  assert.equal(await ctx.roleIn(personal.organizationId, other), "owner");
  assert.deepEqual(await ctx.snapshot(), beforePlain);
  // The last organization joined is where later sign-ins land.
  assert.equal((await ctx.signIn(other)).organizationId, ctx.acmeId);
});

test("multi invited: an expired or revoked invite without its token falls back to a personal organization", async (t) => {
  const ctx = await harness(t);
  const expired = "expired@elsewhere.test";
  await ctx.invite(expired);
  ctx.clock.now += INVITE_TTL_MS + 1;
  const revoked = "revoked@elsewhere.test";
  const { invitation } = await ctx.invite(revoked);
  await ctx.identityStore.revokeInvitation({ organizationId: ctx.acmeId, id: invitation.id, actor: BOOTSTRAP_ACTOR });

  for (const email of [expired, revoked]) {
    const before = await ctx.snapshot();
    const signedIn = await ctx.signIn(email);
    assert.deepEqual(signedIn.joined, { role: "owner", via: "personal" });
    assert.notEqual(signedIn.organizationId, ctx.acmeId);
    assert.equal(await ctx.roleIn(ctx.acmeId, email), null);
    assert.deepEqual(await ctx.snapshot(), { organizations: before.organizations + 1, creates: before.creates + 1 });
  }

  // With personal organizations switched off the same person is refused.
  await ctx.identityStore.updateInstallationSettings({ personalOrgSignupEnabled: false });
  const off = "expired-off@elsewhere.test";
  await ctx.invite(off);
  ctx.clock.now += INVITE_TTL_MS + 1;
  const before = await ctx.snapshot();
  await rejectsWith(ctx.signIn(off), 403, "no_organization");
  assert.deepEqual(await ctx.snapshot(), before);
  const user = await ctx.database.query("SELECT 1 FROM users WHERE email = $1", [off]);
  assert.equal(user.rows.length, 0);
});

test("multi invited: an expired, revoked or replaced invite token keeps its typed error and creates nothing", async (t) => {
  const ctx = await harness(t);
  const expired = "expired-token@elsewhere.test";
  const expiredInvite = await ctx.invite(expired);
  ctx.clock.now += INVITE_TTL_MS + 1;
  const revoked = "revoked-token@elsewhere.test";
  const revokedInvite = await ctx.invite(revoked);
  await ctx.identityStore.revokeInvitation({ organizationId: ctx.acmeId, id: revokedInvite.invitation.id, actor: BOOTSTRAP_ACTOR });
  // Re-inviting replaces the link: the old token is revoked even though a
  // newer open invite exists for the same address.
  const replaced = "replaced-token@elsewhere.test";
  const oldInvite = await ctx.invite(replaced);
  await ctx.invite(replaced);
  const rotated = "rotated-token@elsewhere.test";
  const rotatedInvite = await ctx.invite(rotated);
  await ctx.identityStore.rotateInvitation({ organizationId: ctx.acmeId, id: rotatedInvite.invitation.id, actor: BOOTSTRAP_ACTOR });

  const cases: Array<[string, string, number, string]> = [
    [expired, expiredInvite.token, 410, "invite_expired"],
    [revoked, revokedInvite.token, 410, "invite_revoked"],
    [replaced, oldInvite.token, 410, "invite_revoked"],
    [rotated, rotatedInvite.token, 404, "invite_invalid"],
  ];
  for (const [email, token, status, code] of cases) {
    const before = await ctx.snapshot();
    await rejectsWith(ctx.signIn(email, { token }), status, code);
    assert.deepEqual(await ctx.snapshot(), before, email);
    const user = await ctx.database.query("SELECT 1 FROM users WHERE email = $1", [email]);
    assert.equal(user.rows.length, 0, `${email}: a refused sign-in leaves no user row`);
  }

  // Without a token the replacing and rotated invites are still honoured.
  for (const email of [replaced, rotated]) {
    const before = await ctx.snapshot();
    assert.equal((await ctx.signIn(email)).organizationId, ctx.acmeId);
    await assertJoinedInvitingOrg(ctx, email, before);
  }
});

test("multi invited: email case and surrounding spaces never split an invite from its person", async (t) => {
  const ctx = await harness(t);
  const { invitation, token } = await ctx.invite("  Grace.Hopper@Example.TEST ");
  assert.equal(invitation.email, "grace.hopper@example.test");
  const stored = await ctx.database.query<{ email: string }>("SELECT email FROM organization_invitations WHERE id = $1", [invitation.id]);
  assert.equal(stored.rows[0]!.email, "grace.hopper@example.test");

  let before = await ctx.snapshot();
  const withToken = await ctx.signIn(" GRACE.HOPPER@example.test", { token });
  assert.equal(withToken.organizationId, ctx.acmeId);
  assert.equal(withToken.email, "grace.hopper@example.test");
  await assertJoinedInvitingOrg(ctx, "grace.hopper@example.test", before);

  await ctx.invite("Alan@Example.test");
  before = await ctx.snapshot();
  const withoutToken = await ctx.signIn("ALAN@EXAMPLE.TEST ");
  assert.equal(withoutToken.organizationId, ctx.acmeId);
  await assertJoinedInvitingOrg(ctx, "alan@example.test", before);

  // A row written outside the API is matched the same way (the column is
  // lower-case by constraint, so a mixed-case row cannot exist).
  const direct = "direct@example.test";
  const directToken = "sh_inv_direct-row-for-the-normalization-test";
  await ctx.database.query(
    `INSERT INTO organization_invitations (id, organization_id, email, role, token_hash, expires_at)
     VALUES ($1, $2, $3, 'member', $4, $5)`,
    [randomUUID(), ctx.acmeId, direct, hashSecret(directToken), new Date(ctx.clock.now + INVITE_TTL_MS)],
  );
  before = await ctx.snapshot();
  assert.equal((await ctx.signIn("Direct@Example.Test", { token: directToken })).organizationId, ctx.acmeId);
  await assertJoinedInvitingOrg(ctx, direct, before);
  await assert.rejects(ctx.database.query(
    `INSERT INTO organization_invitations (id, organization_id, email, role, token_hash, expires_at)
     VALUES ($1, $2, 'Mixed@Example.test', 'member', $3, $4)`,
    [randomUUID(), ctx.acmeId, hashSecret("sh_inv_mixed-case-row"), new Date(ctx.clock.now + INVITE_TTL_MS)],
  ));
});

test("multi invited: an unverified address joins only its own invite; another address cannot use the token", async (t) => {
  const ctx = await harness(t);
  // An id_token without email_verified still joins the org that invited
  // that exact address (the same account could already sign in to it).
  const email = "unverified@elsewhere.test";
  await ctx.invite(email);
  let before = await ctx.snapshot();
  assert.equal((await ctx.signIn(email, { emailVerified: false })).organizationId, ctx.acmeId);
  await assertJoinedInvitingOrg(ctx, email, before);

  // A token sent to one address is refused for any other, verified or not.
  const { token } = await ctx.invite("intended@elsewhere.test");
  before = await ctx.snapshot();
  for (const emailVerified of [false, true]) {
    await rejectsWith(ctx.signIn("intruder@elsewhere.test", { token, emailVerified }), 403, "invite_email_mismatch");
  }
  assert.deepEqual(await ctx.snapshot(), before);
  assert.equal(await ctx.roleIn(ctx.acmeId, "intruder@elsewhere.test"), null);
  const intruder = await ctx.database.query("SELECT 1 FROM users WHERE email = 'intruder@elsewhere.test'");
  assert.equal(intruder.rows.length, 0);
  // The invite is still open for the person it was sent to.
  const intended = await ctx.signIn("intended@elsewhere.test", { token });
  assert.equal(intended.organizationId, ctx.acmeId);
  await assertJoinedInvitingOrg(ctx, "intended@elsewhere.test", before);
});

// ---- password registration end to end -----------------------------------------------

async function passwordHarness(t: test.TestContext) {
  const created: string[] = [];
  const provisioner: RelaycastProvisioner = {
    async create() {
      const id = `rc-password-${created.length + 1}`;
      created.push(id);
      return { id, apiKey: `rk_live_${id}` };
    },
    async remove() {},
  };
  // Multi mode refuses SELFHOST_AUTO_JOIN_DOMAINS, which the shared harness sets.
  const ctx = await passwordSetup(t, { env: { SELFHOST_TENANCY: "multi", SELFHOST_AUTO_JOIN_DOMAINS: "" }, provisioner });
  const acmeId = (await ctx.database.query<{ id: string }>("SELECT id FROM organizations WHERE name = 'Acme'")).rows[0]!.id;
  const organizations = async () =>
    (await ctx.database.query<{ count: number }>("SELECT count(*)::int AS count FROM organizations")).rows[0]!.count;
  return { ...ctx, created, acmeId, organizations };
}

test("multi invited: password registration with or without the invite link joins the inviting organization", async (t) => {
  const ctx = await passwordHarness(t);
  for (const withLink of [true, false]) {
    const email = withLink ? "Link.Invitee@Elsewhere.test" : "plain.invitee@elsewhere.test";
    const { token } = await ctx.identityStore.createInvitation({ organizationId: ctx.acmeId, email, role: "member", actor: BOOTSTRAP_ACTOR });
    const organizations = await ctx.organizations();
    const creates = ctx.created.length;
    const signedIn = await registerVerified(ctx, email, PASSWORD, withLink ? token : undefined);
    const current = await session(ctx, sessionCookie(signedIn));
    assert.equal(current.status, 200, current.text);
    assert.equal(current.body.currentOrganization.id, ctx.acmeId);
    assert.equal(current.body.currentOrganization.role, "member");
    const memberships = await ctx.database.query<{ organization_id: string }>(
      `SELECT m.organization_id FROM organization_memberships m JOIN users u ON u.id = m.user_id WHERE u.email = $1`,
      [email.toLowerCase()],
    );
    assert.deepEqual(memberships.rows.map((row) => row.organization_id), [ctx.acmeId]);
    assert.equal(await ctx.organizations(), organizations);
    assert.equal(ctx.created.length, creates);
  }
});

test("multi invited: password registration with only an expired or revoked invite is not offered", async (t) => {
  const ctx = await passwordHarness(t);
  const expired = "expired.pw@elsewhere.test";
  await ctx.identityStore.createInvitation({ organizationId: ctx.acmeId, email: expired, role: "member", actor: BOOTSTRAP_ACTOR });
  const revoked = "revoked.pw@elsewhere.test";
  const revokedInvite = await ctx.identityStore.createInvitation({ organizationId: ctx.acmeId, email: revoked, role: "member", actor: BOOTSTRAP_ACTOR });
  await ctx.identityStore.revokeInvitation({ organizationId: ctx.acmeId, id: revokedInvite.invitation.id, actor: BOOTSTRAP_ACTOR });
  await ctx.database.query("UPDATE organization_invitations SET expires_at = now() - interval '1 minute' WHERE email = $1", [expired]);
  const organizations = await ctx.organizations();
  for (const email of [expired, revoked]) {
    const before = ctx.mailer.sent.length;
    const asked = await call(ctx.origin, `${API}/register`, { json: { email } });
    assert.equal(asked.status, 202, asked.text);
    await ctx.identity.idle();
    assert.equal(ctx.mailer.sent.length, before, `${email}: no verification email`);
  }
  assert.equal(await ctx.organizations(), organizations);
  assert.equal(ctx.created.length, 0);
});
