import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test, { type TestContext } from "node:test";
import pg from "pg";
import { PostgresDatabase } from "../src/database.js";
import { bindingFields, type BindingFields } from "../src/delegation/roles.js";
import {
  BindingExists, OWNER_EXCLUDED, SUPERSEDED_BY_RULE, actingAuthorityLocked, bindingState, createBinding, decideUnderLocks,
  decideWithLegacyExclusion, revokeAllGrants, quiesceRoleBindings, createGroup, excludeFromRule, grantCovers, listBindings,
  listGroups, liveTrustRule, materializeRuleGrant, putTrustRule, revokeBinding, revokeGroup, seedTrustedBindings, updateBinding,
  updateGroup, type DelegationWorkspace, type GrantRow,
} from "../src/delegation/service.js";
import type { TrustPath } from "../src/delegation/trust.js";
import { migrate } from "../src/migrations.js";
import { isolatedPostgresPool } from "./support/postgres.js";

// Role bindings on real PostgreSQL, the self-hosted twin of Cloud's
// store.role-bindings.postgres.test.ts (cloud#6665). Covers precedence,
// eager re-resolution, exclusion with no fall-through, no inheritance down
// the spawn tree, the pr_ops op filter, the role seed, review B1 and a binding
// write racing a materialization.

const postgresUrl = process.env.TEST_DATABASE_URL;
const options = { skip: postgresUrl ? false : "TEST_DATABASE_URL is not set (role binding multi-connection proofs)", timeout: 120_000 };

const grokPath = (agentId: string): TrustPath => ({ root: { kind: "connector", oauth_grant_id: `oauth-${agentId}`, connector: "grok-bot",
  agent_id: agentId, created_at: "2026-11-20T00:00:00.000Z" }, hops: [] });
const claimPath = (agentId: string): TrustPath => ({ root: { kind: "claim", claim_id: `clm_${agentId}`, agent_id: agentId,
  created_at: "2026-11-20T00:00:00.000Z" }, hops: [] });
const workerPath = (agentId: string, spawner = "grok-1"): TrustPath => ({ ...grokPath(spawner), hops: [{ spawn_id: `spawn-${agentId}`,
  actor_id: spawner, worker_id: agentId, created_at: "2026-11-21T00:00:00.000Z" }] });
const comment = { class: "pr_ops" as const, target: "acme/web#7:comment" };
const close = { class: "pr_ops" as const, target: "acme/web#7:close" };
const merge = { class: "merge" as const, target: "acme/web#7" };

async function fixture(t: TestContext) {
  const admin = new pg.Pool({ connectionString: postgresUrl, max: 1 });
  const schema = `role_bind_${randomUUID().replaceAll("-", "")}`;
  await admin.query(`CREATE SCHEMA "${schema}"`);
  let database: PostgresDatabase | null = null;
  t.after(async () => {
    try { await database?.close(); } finally {
      try { await admin.query(`DROP SCHEMA "${schema}" CASCADE`); } finally { await admin.end(); }
    }
  });
  const pool = await isolatedPostgresPool(postgresUrl!, schema, 8);
  database = new PostgresDatabase(pool);
  await migrate(database);
  const organizationId = randomUUID();
  const workspaceId = randomUUID();
  const ownerId = randomUUID();
  await database.query("INSERT INTO users (id, email, name) VALUES ($1, $2, 'Owner')", [ownerId, `owner-${ownerId}@example.test`]);
  await database.query("INSERT INTO organizations (id, name) VALUES ($1, 'Org')", [organizationId]);
  await database.query("INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, 'owner')",
    [organizationId, ownerId]);
  await database.query(`INSERT INTO workspaces (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
    VALUES ($1, $2, 'Workspace', 'rw_pg', 'envelope')`, [workspaceId, organizationId]);
  await database.query("INSERT INTO delegation_policies (workspace_id, delegation_enabled) VALUES ($1, true)", [workspaceId]);
  const workspace: DelegationWorkspace = { id: workspaceId, organizationId, relaycastWorkspaceId: "rw_pg", relaycastApiKey: "rk" };
  const db = database;
  const fields = (role: "trusted" | "standard" | "read_only" | "excluded", extra: Record<string, unknown> = {}) =>
    bindingFields({ role, ...extra }, role === "excluded" ? "agent" : "relay_agents", null, new Date()) as BindingFields;
  const actor = { actorUserId: ownerId, authMethod: "session" };
  const bind = (principalKind: "relay_agents" | "connector_kind" | "group" | "agent", principalRef: string | null,
    role: "trusted" | "standard" | "read_only" | "excluded", extra: Record<string, unknown> = {}) =>
    createBinding(db, { workspaceId, ownerUserId: ownerId, ...actor, principalKind, principalRef, fields: fields(role, extra) });
  const materialize = (agentId: string, trustPath: TrustPath, extra: Partial<Parameters<typeof materializeRuleGrant>[1]> = {}) =>
    materializeRuleGrant(db, { workspace, ownerUserId: ownerId, delegateAgentId: agentId, delegateAgentName: agentId, trustPath,
      provenAt: new Date("2026-11-20T00:00:00Z"), ...extra });
  const grant = async (id: string) => (await db.query<GrantRow>("SELECT * FROM delegation_grants WHERE id = $1", [id])).rows[0]!;
  const events = async (event: string) => (await db.query<{ reason: string | null; data: Record<string, any> }>(
    "SELECT reason, data FROM delegation_audit_events WHERE event = $1 ORDER BY id", [event])).rows;
  const group = (name: string, agentIds: string[]) => createGroup(db, { workspaceId, ownerUserId: ownerId, ...actor, name, agentIds });
  return { database: db, pool, admin, workspace, workspaceId, ownerId, fields, actor, bind, materialize, grant, events, group };
}

async function untilBlocked(admin: pg.Pool) {
  for (let attempt = 0; attempt < 150; attempt += 1) {
    const { rows } = await admin.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND datname = current_database()");
    if (rows[0]!.n > 0) return;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error("nothing waited on the lock");
}

test("the most specific binding decides, a new binding re-resolves at once, and Read-only is PR comments only", options, async (t) => {
  const f = await fixture(t);
  const relay = await f.bind("relay_agents", null, "trusted");
  const grok = await f.bind("connector_kind", "grok-bot", "standard");
  const grokGrant = (await f.materialize("grok-1", grokPath("grok-1")))!;
  assert.equal(grokGrant.trust_rule_id, grok.id);
  assert.equal(grantCovers(grokGrant, merge), true);
  assert.equal(grantCovers(grokGrant, { class: "external_comms", target: "slack:#general" }), false);
  const relayGrant = (await f.materialize("relay-1", claimPath("relay-1")))!;
  assert.equal(relayGrant.trust_rule_id, relay.id);
  assert.deepEqual(relayGrant.scopes.find(scope => scope.class === "merge"),
    { class: "merge", targets: [], conditions: [{ type: "ci_green" }, { type: "mergeable" }] });
  const readOnly = await f.bind("agent", "grok-1", "read_only");
  const retired = await f.grant(grokGrant.id);
  assert.equal(retired.status, "revoked");
  assert.equal(retired.revoked_reason, SUPERSEDED_BY_RULE);
  const second = (await f.materialize("grok-1", grokPath("grok-1")))!;
  assert.equal(second.trust_rule_id, readOnly.id);
  assert.equal(grantCovers(second, comment), true);
  assert.equal(grantCovers(second, close), false);
  assert.equal(grantCovers(second, merge), false);
  // New authority is never retroactive.
  assert.ok(new Date(second.created_at).getTime() >= new Date(retired.revoked_at!).getTime());
  // An unchanged binding keeps its grant.
  await updateBinding(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, bindingId: readOnly.id, ...f.actor,
    resolve: () => f.fields("read_only") });
  assert.equal((await f.grant(second.id)).status, "active");
});

test("an exclusion gives nothing and never falls through to a group, until the agent gets a direct setting", options, async (t) => {
  const f = await fixture(t);
  await f.bind("relay_agents", null, "trusted");
  const group = await f.group("bots", ["grok-1"]);
  await f.bind("group", group.id, "standard");
  const grouped = (await f.materialize("grok-1", grokPath("grok-1")))!;
  assert.equal(await f.database.transaction(tx => excludeFromRule(tx, { workspaceId: f.workspaceId, grant: grouped,
    actorUserId: f.ownerId, authMethod: "session" })), true);
  const revoked = await f.grant(grouped.id);
  assert.equal(revoked.revoked_reason, OWNER_EXCLUDED);
  assert.equal(await f.materialize("grok-1", grokPath("grok-1")), null);
  const excluded = (await listBindings(f.database, f.workspaceId, f.ownerId)).find(row => row.principal_kind === "agent")!;
  assert.equal(excluded.role, "excluded");
  await updateBinding(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, bindingId: excluded.id, ...f.actor,
    resolve: () => f.fields("read_only") });
  assert.equal((await f.materialize("grok-1", grokPath("grok-1")))?.trust_rule_id, excluded.id);
});

test("a launched agent does not inherit its spawner's role: Read-only by default, its own group's role when it has one", options, async (t) => {
  const f = await fixture(t);
  const relay = await f.bind("relay_agents", null, "trusted");
  const worker = (await f.materialize("worker-1", workerPath("worker-1")))!;
  assert.equal(worker.trust_rule_id, relay.id);
  assert.equal(grantCovers(worker, comment), true);
  assert.equal(grantCovers(worker, merge), false);
  assert.equal((await f.events("grant.created"))[0]!.data.source, "spawn_default");
  const group = await f.group("workers", []);
  const groupBinding = await f.bind("group", group.id, "standard");
  await updateGroup(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, groupId: group.id, ...f.actor, add: ["worker-1"] });
  assert.equal((await f.grant(worker.id)).revoked_reason, SUPERSEDED_BY_RULE);
  const promoted = (await f.materialize("worker-1", workerPath("worker-1")))!;
  assert.equal(promoted.trust_rule_id, groupBinding.id);
  assert.equal(grantCovers(promoted, merge), true);
  await updateGroup(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, groupId: group.id, ...f.actor, remove: ["worker-1"] });
  assert.equal((await f.grant(promoted.id)).status, "revoked");
  assert.equal((await f.materialize("worker-1", workerPath("worker-1")))?.trust_rule_id, relay.id);
});

test("review B1: an agent in two Trusted groups with acme/* and other/* is covered by nothing, never every repo", options, async (t) => {
  const f = await fixture(t);
  await f.bind("relay_agents", null, "trusted");
  const relayGrant = (await f.materialize("grok-1", grokPath("grok-1")))!;
  const acme = await f.group("acme", ["grok-1"]);
  const other = await f.group("other", ["grok-1"]);
  await f.bind("group", acme.id, "trusted", { targets: ["acme/*"] });
  await f.bind("group", other.id, "trusted", { targets: ["other/*"] });
  assert.equal((await f.grant(relayGrant.id)).revoked_reason, SUPERSEDED_BY_RULE);
  assert.equal(await f.materialize("grok-1", grokPath("grok-1")), null);
});

test("the legacy rule keeps the spawn tree until a role binding exists; removing a binding falls through", options, async (t) => {
  const f = await fixture(t);
  const rule = (await putTrustRule(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, requireTierO: [],
    authMethod: "session" })).rule;
  const legacyWorker = (await f.materialize("worker-1", workerPath("worker-1")))!;
  assert.equal(legacyWorker.trust_rule_id, rule.id);
  assert.deepEqual(legacyWorker.scopes, []);
  assert.equal(grantCovers(legacyWorker, { class: "deploy", target: "acme/web:prod" }), true);
  // While the legacy rule is live it is the Relay agents binding: a second one is refused with its id.
  await assert.rejects(f.bind("relay_agents", null, "standard"), (error: unknown) => error instanceof BindingExists &&
    error.bindingId === rule.id);
  // Any role binding takes precedence over the legacy rule: the worker falls to the spawn default.
  const grok = await f.bind("connector_kind", "grok-bot", "trusted");
  assert.equal((await f.grant(legacyWorker.id)).revoked_reason, SUPERSEDED_BY_RULE);
  // Converting the legacy rule makes it the Relay agents binding; a new legacy rule is then refused.
  const relay = (await updateBinding(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, bindingId: rule.id, ...f.actor,
    resolve: () => f.fields("standard") }))!;
  assert.equal(typeof relay === "string" ? null : relay.principal_kind, "relay_agents");
  await assert.rejects(putTrustRule(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, requireTierO: [],
    authMethod: "session" }), (error: unknown) => error instanceof BindingExists && error.bindingId === rule.id);
  assert.equal((await f.materialize("grok-1", grokPath("grok-1")))?.trust_rule_id, grok.id);
  const removed = await revokeBinding(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, bindingId: grok.id, ...f.actor,
    reason: "owner_revoked" });
  assert.equal(removed?.revokedGrants.length, 1);
  assert.equal((await f.materialize("grok-1", grokPath("grok-1")))?.trust_rule_id, (relay as { id: string }).id);
  assert.equal((await f.events("binding.revoked"))[0]!.data.binding_id, grok.id);
});

test("one live binding per principal: a concurrent duplicate is refused with the winner's id", options, async (t) => {
  const f = await fixture(t);
  const results = await Promise.allSettled(Array.from({ length: 5 }, () => f.bind("relay_agents", null, "trusted")));
  const made = results.filter(result => result.status === "fulfilled") as PromiseFulfilledResult<{ id: string }>[];
  assert.equal(made.length, 1);
  for (const result of results.filter(item => item.status === "rejected") as PromiseRejectedResult[]) {
    assert.ok(result.reason instanceof BindingExists);
    assert.equal((result.reason as BindingExists).bindingId, made[0]!.value.id);
  }
});

test("a binding write racing a materialization never leaves a stale grant, in either order", options, async (t) => {
  const f = await fixture(t);
  await f.bind("relay_agents", null, "trusted");
  // Order 1: the materialization holds the owner's binding lock; the write waits, then re-resolves its grant.
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  const materializing = f.materialize("grok-1", grokPath("grok-1"), { onLocked: () => held });
  await new Promise(resolve => setTimeout(resolve, 50));
  const writing = f.bind("agent", "grok-1", "read_only");
  await untilBlocked(f.admin);
  release();
  const made = (await materializing)!;
  const readOnly = await writing;
  assert.equal((await f.grant(made.id)).revoked_reason, SUPERSEDED_BY_RULE);
  assert.equal((await f.materialize("grok-1", grokPath("grok-1")))?.trust_rule_id, readOnly.id);

  // Order 2: a write holds the lock; the materialization waits, then decides on the new binding.
  const client = await f.pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`delegation-bindings:${f.workspaceId}:${f.ownerId}`]);
    await client.query("UPDATE delegation_trust_rules SET role = 'excluded', classes = '{}' WHERE id = $1", [readOnly.id]);
    await client.query("UPDATE delegation_grants SET status = 'revoked', revoked_at = now(), revoked_reason = 'owner_excluded' WHERE delegate_agent_id = 'grok-1' AND status = 'active'");
    const waiting = f.materialize("grok-1", grokPath("grok-1"));
    await untilBlocked(f.admin);
    await client.query("COMMIT");
    assert.equal(await waiting, null);
  } finally {
    client.release();
  }
});

test("the role seed: dry run first, converts legacy rules to Trusted for Relay agents, idempotent, skips an owner who chose", options, async (t) => {
  const f = await fixture(t);
  const rule = (await putTrustRule(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, requireTierO: [],
    authMethod: "session" })).rule;
  const legacyGrant = (await f.materialize("grok-1", grokPath("grok-1")))!;
  const trusted = f.fields("trusted");
  const dry = await seedTrustedBindings(f.database, { apply: false, limit: 10, trusted });
  assert.deepEqual([dry.dry_run, dry.scanned, dry.converted, dry.rules.map(item => item.trust_rule_id)], [true, 1, 0, [rule.id]]);
  assert.equal((await liveTrustRule(f.database, f.workspaceId, f.ownerId))?.id, rule.id);
  assert.equal((await f.grant(legacyGrant.id)).status, "active");
  const applied = await seedTrustedBindings(f.database, { apply: true, limit: 10, trusted });
  assert.deepEqual([applied.dry_run, applied.converted], [false, 1]);
  assert.equal(await liveTrustRule(f.database, f.workspaceId, f.ownerId), null);
  const [binding] = await listBindings(f.database, f.workspaceId, f.ownerId);
  assert.deepEqual([binding!.id, binding!.principal_kind, binding!.role], [rule.id, "relay_agents", "trusted"]);
  assert.equal((await f.grant(legacyGrant.id)).revoked_reason, SUPERSEDED_BY_RULE);
  const reissued = (await f.materialize("grok-1", grokPath("grok-1")))!;
  assert.equal(grantCovers(reissued, { class: "config_change", target: "grok-1:model=x" }), false);
  assert.equal((await f.events("binding.updated"))[0]!.reason, "role_seed");
  assert.equal((await seedTrustedBindings(f.database, { apply: true, limit: 10, trusted })).scanned, 0);
  // A legacy rule next to an existing Relay agents binding (rows from before the guard) is left for a person to decide.
  await f.database.query("INSERT INTO delegation_trust_rules (id, workspace_id, owner_user_id) VALUES ($1, $2, $3)",
    [`dtr_${randomUUID().replaceAll("-", "")}`, f.workspaceId, f.ownerId]);
  const skipped = await seedTrustedBindings(f.database, { apply: true, limit: 10, trusted });
  assert.deepEqual([skipped.converted, skipped.skipped.has_relay_agents], [0, 1]);
});

test("revoking a group revokes its bindings and their grants", options, async (t) => {
  const f = await fixture(t);
  const group = await f.group("bots", ["grok-1"]);
  await f.bind("group", group.id, "trusted");
  await f.materialize("grok-1", grokPath("grok-1"));
  assert.deepEqual(await revokeGroup(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, groupId: group.id, ...f.actor }),
    { revokedBindings: 1, revokedGrants: 1 });
  assert.deepEqual(await listGroups(f.database, f.workspaceId, f.ownerId), []);
  assert.equal(await f.materialize("grok-1", grokPath("grok-1")), null);
});

test("parity c1de4d1f1: converting a legacy rule carries its exclusions; a second Relay agents binding is refused", options, async (t) => {
  const f = await fixture(t);
  const rule = (await putTrustRule(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, requireTierO: [],
    authMethod: "session" })).rule;
  // A pre-roles exclusion: a system grant of the legacy rule revoked as owner_excluded, with no agent binding.
  const excludedGrant = (await f.materialize("grok-1", grokPath("grok-1")))!;
  await f.database.query("UPDATE delegation_grants SET status = 'revoked', revoked_at = now(), revoked_reason = $2 WHERE id = $1",
    [excludedGrant.id, OWNER_EXCLUDED]);
  assert.equal(await f.materialize("grok-1", grokPath("grok-1")), null);
  await seedTrustedBindings(f.database, { apply: true, limit: 10, trusted: f.fields("trusted") });
  const carried = (await listBindings(f.database, f.workspaceId, f.ownerId)).find(row => row.principal_kind === "agent");
  assert.deepEqual([carried?.principal_ref, carried?.role], ["grok-1", "excluded"]);
  assert.equal(await f.materialize("grok-1", grokPath("grok-1")), null);
  assert.equal((await f.materialize("grok-2", grokPath("grok-2")))?.trust_rule_id, rule.id);

  // A legacy rule PATCHed while a Relay agents binding exists (rows from before the guard): refused with that binding's id.
  const legacy = (await f.database.query<{ id: string }>(
    "INSERT INTO delegation_trust_rules (id, workspace_id, owner_user_id) VALUES ($1, $2, $3) RETURNING id",
    [`dtr_${randomUUID().replaceAll("-", "")}`, f.workspaceId, f.ownerId])).rows[0]!;
  await assert.rejects(updateBinding(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, bindingId: legacy.id, ...f.actor,
    resolve: () => f.fields("standard") }), (error: unknown) => error instanceof BindingExists && error.bindingId === rule.id);
  // PATCH resolves from the locked row: a refusal from resolve is returned, not written.
  assert.equal(await updateBinding(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, bindingId: rule.id, ...f.actor,
    resolve: () => "nope" }), "nope");
});

test("parity c1de4d1f1: a group grant is dated no earlier than the agent joined the group", options, async (t) => {
  const f = await fixture(t);
  const group = await f.group("bots", []);
  await f.bind("group", group.id, "trusted");
  await new Promise(resolve => setTimeout(resolve, 30));
  await updateGroup(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, groupId: group.id, ...f.actor, add: ["grok-1"] });
  const [member] = (await f.database.query<{ added_at: Date }>("SELECT added_at FROM delegation_group_members WHERE agent_id = 'grok-1'")).rows;
  const made = (await f.materialize("grok-1", grokPath("grok-1")))!;
  assert.ok(new Date(made.created_at).getTime() >= new Date(member!.added_at).getTime());
});

test("parity c1de4d1f1: the acting agent's authority is read under its owner's binding lock and its own grants' share lock", options, async (t) => {
  const f = await fixture(t);
  await f.bind("relay_agents", null, "standard");
  const read = await f.database.transaction(tx => actingAuthorityLocked(tx, { workspaceId: f.workspaceId, ownerUserId: f.ownerId,
    agentId: "relay-1", now: new Date() }));
  assert.equal(read.own, null);
  assert.equal(read.state.bindings[0]?.role, "standard");
  // A binding write waits for a decision that holds the lock.
  const client = await f.pool.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))", [`delegation-bindings:${f.workspaceId}:${f.ownerId}`]);
    const writing = f.bind("connector_kind", "grok-bot", "trusted");
    await untilBlocked(f.admin);
    await client.query("COMMIT");
    await writing;
  } finally {
    client.release();
  }
});

test("review: removing or outliving a restrictive binding never covers an approval sent while it decided", options, async (t) => {
  const f = await fixture(t);
  await f.bind("relay_agents", null, "trusted");
  // An override on an agent that has no grant yet, then removed before its first use.
  const override = await f.bind("agent", "grok-1", "read_only");
  await new Promise(resolve => setTimeout(resolve, 30));
  await revokeBinding(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, bindingId: override.id, ...f.actor,
    reason: "owner_revoked" });
  const [removed] = (await f.database.query<{ revoked_at: Date }>("SELECT revoked_at FROM delegation_trust_rules WHERE id = $1",
    [override.id])).rows;
  const fallback = (await f.materialize("grok-1", grokPath("grok-1")))!;
  assert.ok(new Date(fallback.created_at).getTime() >= new Date(removed!.revoked_at).getTime());
  // An override that expires unused: the fallback grant starts no earlier than its expiry.
  const until = new Date(Date.now() + 300);
  await f.bind("agent", "grok-2", "read_only", { expires_at: until.toISOString() });
  await new Promise(resolve => setTimeout(resolve, 400));
  const afterExpiry = (await f.materialize("grok-2", grokPath("grok-2")))!;
  assert.ok(new Date(afterExpiry.created_at).getTime() >= until.getTime());
  // A member removed from a Read-only group: the fallback grant starts no earlier than the removal.
  const group = await f.group("ro", ["grok-3"]);
  await f.bind("group", group.id, "read_only");
  await updateGroup(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, groupId: group.id, ...f.actor, remove: ["grok-3"] });
  const [member] = (await f.database.query<{ removed_at: Date }>(
    "SELECT removed_at FROM delegation_group_members WHERE agent_id = 'grok-3'")).rows;
  const afterRemoval = (await f.materialize("grok-3", grokPath("grok-3")))!;
  assert.ok(new Date(afterRemoval.created_at).getTime() >= new Date(member!.removed_at).getTime());
});

test("review: a deleted exclusion stops blocking the agent under a legacy rule, and a conversion does not bring it back", options, async (t) => {
  const f = await fixture(t);
  const rule = (await putTrustRule(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, requireTierO: [],
    authMethod: "session" })).rule;
  const grant = (await f.materialize("grok-1", grokPath("grok-1")))!;
  await f.database.transaction(tx => excludeFromRule(tx, { workspaceId: f.workspaceId, grant, actorUserId: f.ownerId,
    authMethod: "session" }));
  assert.equal(await f.materialize("grok-1", grokPath("grok-1")), null);
  const exclusion = (await listBindings(f.database, f.workspaceId, f.ownerId)).find(row => row.principal_kind === "agent")!;
  await revokeBinding(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, bindingId: exclusion.id, ...f.actor,
    reason: "owner_revoked" });
  assert.equal((await f.materialize("grok-1", grokPath("grok-1")))?.trust_rule_id, rule.id);
  await seedTrustedBindings(f.database, { apply: true, limit: 10, trusted: f.fields("trusted") });
  assert.equal((await listBindings(f.database, f.workspaceId, f.ownerId)).some(row => row.principal_kind === "agent"), false);
});

test("review: the rollback quiesce ends every role binding with its grants, keeps a plain legacy rule, dry run first", options, async (t) => {
  const f = await fixture(t);
  await f.bind("connector_kind", "grok-bot", "trusted");
  const excluded = await f.bind("agent", "grok-2", "excluded");
  const group = await f.group("bots", ["relay-1"]);
  const groupBinding = await f.bind("group", group.id, "read_only");
  const grokGrant = (await f.materialize("grok-1", grokPath("grok-1")))!;
  const dry = await quiesceRoleBindings(f.database, { apply: false, limit: 100 });
  assert.equal(dry.dry_run, true);
  assert.equal(dry.bindings.length, 3);
  assert.equal((await f.grant(grokGrant.id)).status, "active");
  const applied = await quiesceRoleBindings(f.database, { apply: true, limit: 100 });
  assert.deepEqual([applied.dry_run, applied.bindings.length, applied.revoked_grants], [false, 3, 1]);
  assert.equal((await f.grant(grokGrant.id)).revoked_reason, "trust_rule_revoked");
  assert.deepEqual(await listBindings(f.database, f.workspaceId, f.ownerId), []);
  const reasons = (await f.database.query<{ revoked_reason: string }>(
    "SELECT revoked_reason FROM delegation_trust_rules WHERE id = ANY($1::text[])", [[excluded.id, groupBinding.id]])).rows;
  assert.ok(reasons.every(row => row.revoked_reason === "role_bindings_quiesced"));
  assert.equal((await quiesceRoleBindings(f.database, { apply: true, limit: 100 })).bindings.length, 0);
  // A plain legacy rule is what the old build understands: left alone.
  await putTrustRule(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, requireTierO: [], authMethod: "session" });
  assert.equal((await quiesceRoleBindings(f.database, { apply: false, limit: 100 })).bindings.length, 0);
});

test("review: the quiesce ends a legacy rule that sits under role bindings; another owner's plain legacy rule stays", options, async (t) => {
  const f = await fixture(t);
  const legacy = (await putTrustRule(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, requireTierO: [],
    authMethod: "session" })).rule;
  await f.bind("connector_kind", "grok-bot", "read_only");
  await f.bind("agent", "relay-1", "excluded");
  const readOnly = (await f.materialize("grok-1", grokPath("grok-1")))!;
  const worker = (await f.materialize("worker-1", workerPath("worker-1")))!;
  // Another owner in the same workspace with only a plain legacy rule.
  const otherId = randomUUID();
  await f.database.query("INSERT INTO users (id, email, name) VALUES ($1, $2, 'Other')", [otherId, `other-${otherId}@example.test`]);
  await f.database.query(`INSERT INTO organization_memberships (organization_id, user_id, role)
    SELECT organization_id, $2, 'member' FROM workspaces WHERE id = $1`, [f.workspaceId, otherId]);
  const otherRule = (await putTrustRule(f.database, { workspaceId: f.workspaceId, ownerUserId: otherId, requireTierO: [],
    authMethod: "session" })).rule;

  const dry = await quiesceRoleBindings(f.database, { apply: false, limit: 100 });
  assert.equal(dry.bindings.length, 3);
  assert.ok(dry.bindings.some(row => row.binding_id === legacy.id));
  assert.equal(dry.bindings.some(row => row.binding_id === otherRule.id), false);
  const applied = await quiesceRoleBindings(f.database, { apply: true, limit: 100 });
  assert.deepEqual([applied.bindings.length, applied.revoked_grants], [3, 2]);
  assert.deepEqual(await listBindings(f.database, f.workspaceId, f.ownerId), []);
  assert.equal((await f.database.query(
    "SELECT 1 FROM delegation_grants WHERE owner_user_id = $1 AND status = 'active'", [f.ownerId])).rows.length, 0);
  assert.deepEqual([(await f.grant(readOnly.id)).status, (await f.grant(worker.id)).status], ["revoked", "revoked"]);
  // Nothing left to fall through to.
  for (const [agent, path] of [["grok-1", grokPath("grok-1")], ["relay-1", claimPath("relay-1")], ["worker-1", workerPath("worker-1")]] as const) {
    assert.equal(await f.materialize(agent, path), null, agent);
  }
  assert.equal((await liveTrustRule(f.database, f.workspaceId, otherId))?.id, otherRule.id);
  assert.equal((await quiesceRoleBindings(f.database, { apply: false, limit: 100 })).bindings.length, 0);
});

test("review of cloud#6672: a cross-owner redeem's acting check and a workspace revoke-all never deadlock, whichever grant sorts first", options, async (t) => {
  const f = await fixture(t);
  const minterOwner = randomUUID();
  await f.database.query("INSERT INTO users (id, email, name) VALUES ($1, $2, 'Minter')", [minterOwner, `minter-${minterOwner}@example.test`]);
  await f.database.query(`INSERT INTO organization_memberships (organization_id, user_id, role)
    SELECT organization_id, $2, 'member' FROM workspaces WHERE id = $1`, [f.workspaceId, minterOwner]);
  const insertGrant = (id: string, ownerUserId: string, agentId: string) => f.database.query(
    `INSERT INTO delegation_grants (id, workspace_id, organization_id, owner_user_id, delegate_agent_id, delegate_agent_name,
       scopes, require_tier_o, expires_at, created_auth_method)
     SELECT $2, $1, w.organization_id, $3, $4, $4, '[{"class":"merge","targets":["acme/web"]}]'::jsonb, ARRAY['merge'],
       now() + interval '1 day', 'session' FROM workspaces w WHERE w.id = $1`, [f.workspaceId, id, ownerUserId, agentId]);
  for (const [actingId, minterId] of [["grt_0acting", "grt_9minter"], ["grt_9acting", "grt_0minter"]] as const) {
    await f.database.query("DELETE FROM delegation_grants");
    await insertGrant(actingId, f.ownerId, "acting-bot");
    await insertGrant(minterId, minterOwner, "minter-bot");
    let entered!: () => void;
    let release!: () => void;
    const inDecision = new Promise<void>(resolve => { entered = resolve; });
    const held = new Promise<void>(resolve => { release = resolve; });
    // The redeem's shape: the minter's grant (another owner's) and the acting agent's own grants, then the acting check.
    const decision = decideUnderLocks(f.database, { workspaceId: f.workspaceId, memberUserIds: [f.ownerId], grantId: minterId,
      approvalId: "apr_none", grantOwnerUserId: minterOwner, actingGrants: { ownerUserId: f.ownerId, agentId: "acting-bot" } },
    async (state, tx) => {
      assert.equal(state.grant?.id, minterId);
      entered();
      await held;
      return actingAuthorityLocked(tx, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, agentId: "acting-bot", now: new Date() });
    });
    await inDecision;
    const revoke = f.database.transaction(tx => revokeAllGrants(tx, { workspaceId: f.workspaceId, ownerUserId: null,
      actorUserId: f.ownerId, reason: "admin_revoke_all", authMethod: "session" }));
    await untilBlocked(f.admin);
    release();
    const [decided, revoked] = await Promise.allSettled([decision, revoke]);
    assert.equal(decided.status, "fulfilled", `${actingId}: ${decided.status === "rejected" ? String(decided.reason?.code ?? decided.reason) : ""}`);
    assert.equal(revoked.status, "fulfilled", `${actingId}: ${revoked.status === "rejected" ? String(revoked.reason?.code ?? revoked.reason) : ""}`);
    assert.deepEqual((decided as PromiseFulfilledResult<{ own: string[] | null }>).value.own, ["merge"], actingId);
    assert.deepEqual([...(revoked as PromiseFulfilledResult<string[]>).value].sort(), [actingId, minterId].sort(), actingId);
  }
});

test("review of cloud#6672: an agent a legacy rule excluded before roles never inherits the rule's ask-first list", options, async (t) => {
  const f = await fixture(t);
  const rule = (await putTrustRule(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, requireTierO: ["merge"], ...f.actor })).rule;
  const grant = (await f.materialize("grok-1", grokPath("grok-1")))!;
  // A pre-roles exclusion: only the revoked grant row records it, with no agent binding.
  await f.database.query("UPDATE delegation_grants SET status = 'revoked', revoked_at = now(), revoked_reason = $1 WHERE id = $2",
    [OWNER_EXCLUDED, grant.id]);
  const decideNow = async (agentId: string) => decideWithLegacyExclusion(f.database, await bindingState(f.database, f.workspaceId, f.ownerId),
    { workspaceId: f.workspaceId, ownerUserId: f.ownerId, agentId, path: grokPath(agentId), now: new Date() });
  const excluded = await decideNow("grok-1");
  assert.equal(excluded.kind, "excluded");
  const other = await decideNow("grok-2");
  assert.ok(other.kind === "covered" && other.source === "legacy");
  assert.deepEqual(other.authority.requireTierO, ["merge"]);
  // A direct binding since roles supersedes the old marker, even once removed.
  const own = await f.bind("agent", "grok-1", "excluded");
  await revokeBinding(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, bindingId: own.id, ...f.actor, reason: "owner_revoked" });
  const lifted = await decideNow("grok-1");
  assert.ok(lifted.kind === "covered" && lifted.source === "legacy");
  assert.equal(rule.id, lifted.binding.id);
});

test("review of cloud#6674: an acting grant created after the lock pass is locked by the acting read; a held one fails closed", options, async (t) => {
  const f = await fixture(t);
  const minterOwner = randomUUID();
  await f.database.query("INSERT INTO users (id, email, name) VALUES ($1, $2, 'Minter')", [minterOwner, `minter-${minterOwner}@example.test`]);
  await f.database.query(`INSERT INTO organization_memberships (organization_id, user_id, role)
    SELECT organization_id, $2, 'member' FROM workspaces WHERE id = $1`, [f.workspaceId, minterOwner]);
  const insertGrant = (id: string, ownerUserId: string, agentId: string) => f.database.query(
    `INSERT INTO delegation_grants (id, workspace_id, organization_id, owner_user_id, delegate_agent_id, delegate_agent_name,
       scopes, require_tier_o, expires_at, created_auth_method)
     SELECT $2, $1, w.organization_id, $3, $4, $4, '[{"class":"merge","targets":["acme/web"]}]'::jsonb, '{}',
       now() + interval '1 day', 'session' FROM workspaces w WHERE w.id = $1`, [f.workspaceId, id, ownerUserId, agentId]);
  await insertGrant("grt_minter0001", minterOwner, "minter-bot");
  const decideWith = (between: () => Promise<void>, after: () => Promise<void> = async () => {}) => decideUnderLocks(f.database, {
    workspaceId: f.workspaceId, memberUserIds: [f.ownerId], grantId: "grt_minter0001", approvalId: "apr_none",
    grantOwnerUserId: minterOwner, actingGrants: { ownerUserId: f.ownerId, agentId: "acting-bot" } }, async (_state, tx) => {
    await between();
    const read = await actingAuthorityLocked(tx, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, agentId: "acting-bot", now: new Date() });
    await after();
    return read;
  });
  // Created after the pass: the read locks it, so a Tier O change waits for the decision.
  let tierChange: Promise<unknown> | null = null;
  const read = await decideWith(async () => { await insertGrant("grt_acting0001", f.ownerId, "acting-bot"); }, async () => {
    tierChange = f.database.query("UPDATE delegation_grants SET require_tier_o = '{merge}' WHERE id = 'grt_acting0001'");
    await untilBlocked(f.admin);
  });
  assert.deepEqual(read.own, []);
  await tierChange;
  // Held by a writer when the read runs: 55P03 at once, never a stale read or a wait.
  await f.database.query("DELETE FROM delegation_grants WHERE id = 'grt_acting0001'");
  const writer = await f.pool.connect();
  try {
    const failure = await decideWith(async () => {
      await insertGrant("grt_acting0002", f.ownerId, "acting-bot");
      await writer.query("BEGIN");
      await writer.query("SELECT 1 FROM delegation_grants WHERE id = 'grt_acting0002' FOR UPDATE");
    }).then(() => null, (error: unknown) => error as { code?: string });
    assert.equal(failure?.code, "55P03");
  } finally {
    await writer.query("ROLLBACK").catch(() => {});
    writer.release();
  }
});

test("review of cloud#6674: a worker grant made under an older resolution is superseded when re-resolved, never reused", options, async (t) => {
  const f = await fixture(t);
  const relay = await f.bind("relay_agents", null, "trusted");
  const stale = (await f.materialize("worker-1", workerPath("worker-1")))!;
  // As made before the spawn default took the root's ask-first list: the binding now asks first for pr_ops,
  // written without the eager re-resolution a binding write does.
  await f.database.query("UPDATE delegation_trust_rules SET require_tier_o = array_append(require_tier_o, 'pr_ops') WHERE id = $1", [relay.id]);
  const current = (await f.materialize("worker-1", workerPath("worker-1")))!;
  assert.notEqual(current.id, stale.id);
  assert.deepEqual(current.require_tier_o, ["pr_ops"]);
  const retired = await f.grant(stale.id);
  assert.equal(retired.status, "revoked");
  assert.equal(retired.revoked_reason, SUPERSEDED_BY_RULE);
});
