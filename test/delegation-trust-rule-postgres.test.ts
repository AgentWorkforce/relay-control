import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test, { type TestContext } from "node:test";
import pg from "pg";
import { PostgresDatabase, type SqlExecutor } from "../src/database.js";
import {
  decideUnderLocks, freshRefusal, materializeRuleGrant, putTrustRule, revokeAllGrants, revokeGrants, revokeTrustRule,
  revokeTrustRulesTx, type DelegationWorkspace, type GrantRow,
} from "../src/delegation/service.js";
import type { TrustPath } from "../src/delegation/trust.js";
import { migrate } from "../src/migrations.js";
import { isolatedPostgresPool } from "./support/postgres.js";

const postgresUrl = process.env.TEST_DATABASE_URL;
const options = { skip: postgresUrl ? false : "TEST_DATABASE_URL is not set (trust rule multi-connection proofs)", timeout: 120_000 };

async function fixture(t: TestContext) {
  const admin = new pg.Pool({ connectionString: postgresUrl, max: 1 });
  const schema = `trust_pg_${randomUUID().replaceAll("-", "")}`;
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
  /** A claimed agent of the owner (the claim root). */
  async function claimed(agentId = "ag_bot") {
    const claimId = `clm_${randomUUID().replaceAll("-", "")}`;
    await database!.query(`INSERT INTO delegation_claims (id, workspace_id, user_id, code_hash, expires_at, consumed_at, agent_id)
      VALUES ($1, $2, $3, $4, now() + interval '10 minutes', now(), $5)`, [claimId, workspaceId, ownerId, randomUUID(), agentId]);
    await database!.query(`INSERT INTO delegation_agent_bindings (workspace_id, relaycast_workspace_id, agent_id, agent_name, user_id, claim_id)
      VALUES ($1, 'rw_pg', $2, 'assistant', $3, $4)`, [workspaceId, agentId, ownerId, claimId]);
    return claimId;
  }
  const path = (agentId: string, claimId: string): TrustPath => ({ root: { kind: "claim", claim_id: claimId, agent_id: agentId,
    created_at: new Date(Date.now() - 60_000).toISOString() }, hops: [] });
  const rule = async () => (await putTrustRule(database!, { workspaceId, ownerUserId: ownerId, requireTierO: [], authMethod: "session" })).rule;
  const materialize = (ruleId: string, agentId: string, claimId: string, onLocked?: () => Promise<void>) =>
    materializeRuleGrant(database!, { workspace, ruleId, ownerUserId: ownerId, delegateAgentId: agentId, delegateAgentName: "assistant",
      trustPath: path(agentId, claimId), provenAt: new Date(Date.now() - 60_000), claimId, ...(onLocked ? { onLocked } : {}) });
  const grants = async (agentId = "ag_bot") => (await database!.query<GrantRow>(
    "SELECT * FROM delegation_grants WHERE delegate_agent_id = $1 ORDER BY created_at, id", [agentId])).rows;
  async function ownerGrant(agentId: string, expiresIn = "1 day") {
    const id = `grt_${randomUUID().replaceAll("-", "")}`;
    await database!.query(`INSERT INTO delegation_grants (id, workspace_id, organization_id, owner_user_id, delegate_agent_id,
        delegate_agent_name, scopes, expires_at, created_auth_method)
      VALUES ($1, $2, $3, $4, $5, 'assistant', '[{"class":"merge","targets":["a/*"]}]'::jsonb, now() + $6::interval, 'session')`,
      [id, workspaceId, organizationId, ownerId, agentId, expiresIn]);
    return id;
  }
  return { pool, database, workspace, workspaceId, organizationId, ownerId, claimed, rule, materialize, grants, ownerGrant };
}

test("concurrent first PUTs converge on one live rule", options, async (t) => {
  const f = await fixture(t);
  const results = await Promise.all(Array.from({ length: 6 }, () =>
    putTrustRule(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, requireTierO: [], authMethod: "session" })));
  assert.equal(new Set(results.map(result => result.rule.id)).size, 1);
  assert.equal(results.filter(result => result.created).length, 1);
  assert.equal((await f.database.query("SELECT 1 FROM delegation_trust_rules")).rows.length, 1);
});

test("concurrent first materializes converge on one system grant", options, async (t) => {
  const f = await fixture(t);
  const claimId = await f.claimed();
  const rule = await f.rule();
  const made = await Promise.all(Array.from({ length: 6 }, () => f.materialize(rule.id, "ag_bot", claimId)));
  assert.equal(new Set(made.map(grant => grant?.id)).size, 1);
  assert.equal((await f.grants()).length, 1);
  assert.equal((await f.database.query("SELECT 1 FROM delegation_audit_events WHERE event = 'grant.created'")).rows.length, 1);
});

test("materialize vs rule revoke, in both orders, leaves no live system grant", options, async (t) => {
  const f = await fixture(t);
  const claimId = await f.claimed();
  // Materialize first: it holds the rule's share lock; the revoke waits, then revokes the new grant.
  const first = await f.rule();
  let revoking: Promise<unknown> | null = null;
  const made = await f.materialize(first.id, "ag_bot", claimId, async () => {
    revoking = revokeTrustRule(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, actorUserId: f.ownerId,
      authMethod: "session", reason: "owner_revoked" });
    await new Promise(resolve => setTimeout(resolve, 200));
  });
  assert.ok(made);
  const revoked = await revoking! as { revokedGrants: string[] };
  assert.deepEqual(revoked.revokedGrants, [made!.id]);
  assert.equal((await f.grants()).filter(row => row.status === "active").length, 0);

  // Revoke first: it holds the rule FOR UPDATE; the materialize waits, then sees it revoked and creates nothing.
  const second = await f.rule();
  const client = await f.pool.connect();
  try {
    await client.query("BEGIN");
    await revokeTrustRulesTx(client as unknown as SqlExecutor, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, actorUserId: f.ownerId,
      authMethod: "session", reason: "owner_revoked" });
    const waiting = f.materialize(second.id, "ag_bot", claimId);
    await new Promise(resolve => setTimeout(resolve, 200));
    await client.query("COMMIT");
    assert.equal(await waiting, null);
  } finally {
    client.release();
  }
  assert.equal((await f.grants()).filter(row => row.status === "active").length, 0);
});

test("concurrent decisions and rule revokes never deadlock; decisions after the revoke see it revoked", options, async (t) => {
  const f = await fixture(t);
  for (let round = 0; round < 8; round += 1) {
    const agentId = `ag_bot_${round}`;
    const claimId = await f.claimed(agentId);
    const rule = await f.rule();
    const grant = (await f.materialize(rule.id, agentId, claimId))!;
    const approvalId = `apv_${randomUUID().replaceAll("-", "")}`;
    await f.database.query(`INSERT INTO delegation_approvals (id, workspace_id, owner_user_id, tier, grant_id, message_id, actions,
        single_use, expires_at) VALUES ($1, $2, $3, 'D', $4, 'm', '[{"class":"merge","target":"a/b#1"}]'::jsonb, false, now() + interval '1 hour')`,
      [approvalId, f.workspaceId, f.ownerId, grant.id]);
    const decide = (consuming: boolean) => decideUnderLocks(f.database, { workspaceId: f.workspaceId, memberUserIds: [f.ownerId],
      grantId: grant.id, approvalId, consuming, trustRuleId: rule.id }, async (state) => {
      await new Promise(resolve => setTimeout(resolve, 5));
      return freshRefusal(state, { actions: [{ class: "merge", target: "a/b#1" }], tier: "D", recipientAgentId: "r",
        nowMs: Date.now(), policy: state.policy });
    });
    const settled = await Promise.allSettled([decide(false), decide(true),
      revokeTrustRule(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, actorUserId: f.ownerId, authMethod: "session",
        reason: "owner_revoked" }), decide(false), decide(true)]);
    for (const result of settled) {
      if (result.status === "rejected") assert.fail(`round ${round}: ${(result.reason as { code?: string }).code ?? result.reason}`);
    }
    assert.equal(await decide(false), "revoked");
  }
});

test("precedence, R1 lapsed grant, exclusion, Tier O propagation and revoke-all on real Postgres", options, async (t) => {
  const f = await fixture(t);
  const claimId = await f.claimed();
  const rule = await f.rule();
  // A live owner-made grant wins: it is returned, no system grant is created.
  const own = await f.ownerGrant("ag_bot");
  assert.equal((await f.materialize(rule.id, "ag_bot", claimId))!.id, own);
  // R1: once it lapses it is expired first and the rule covers the agent.
  await f.database.query("UPDATE delegation_grants SET expires_at = now() - interval '1 second' WHERE id = $1", [own]);
  const system = (await f.materialize(rule.id, "ag_bot", claimId))!;
  assert.equal(system.trust_rule_id, rule.id);
  assert.equal((await f.grants()).find(row => row.id === own)!.status, "expired");
  // Tier O propagation: a PUT changing the list updates the rule's system grants in the same transaction.
  await putTrustRule(f.database, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, requireTierO: ["deploy"], authMethod: "session" });
  assert.deepEqual((await f.grants()).find(row => row.id === system.id)!.require_tier_o, ["deploy"]);
  // Exclusion: revoked by hand, never re-covered by the same rule.
  await f.database.transaction(tx => revokeGrants(tx, { workspaceId: f.workspaceId, grantIds: [system.id], actorUserId: f.ownerId,
    reason: "owner_excluded", authMethod: "session" }));
  assert.equal(await f.materialize(rule.id, "ag_bot", claimId), null);
  // Revoke-all: the scope's rules first, then grants.
  const other = await f.claimed("ag_other");
  const otherGrant = (await f.materialize(rule.id, "ag_other", other))!;
  const revoked = await f.database.transaction(tx => revokeAllGrants(tx, { workspaceId: f.workspaceId, ownerUserId: f.ownerId,
    actorUserId: f.ownerId, reason: "owner_revoke_all", authMethod: "session" }));
  assert.deepEqual(revoked, [otherGrant.id]);
  assert.equal((await f.database.query("SELECT 1 FROM delegation_trust_rules WHERE revoked_at IS NULL")).rows.length, 0);
  assert.equal((await f.grants("ag_other"))[0]!.revoked_reason, "trust_rule_revoked");
});

test("the expiry CHECK refuses an owner-made grant past the cap and admits a rule-backed one", options, async (t) => {
  const f = await fixture(t);
  const rule = await f.rule();
  await assert.rejects(f.ownerGrant("ag_bot", "91 days"), /delegation_grants_expiry_cap/);
  await f.ownerGrant("ag_bot", "90 days");
  await f.database.query(`INSERT INTO delegation_grants (id, workspace_id, organization_id, owner_user_id, delegate_agent_id,
      delegate_agent_name, scopes, expires_at, created_auth_method, trust_rule_id)
    VALUES ('grt_rulebacked1', $1, $2, $3, 'ag_x', 'x', '[]'::jsonb, '9999-12-31', 'system', $4)`,
  [f.workspaceId, f.organizationId, f.ownerId, rule.id]);
  const validated = (await f.database.query<{ convalidated: boolean }>(
    "SELECT convalidated FROM pg_constraint WHERE conname = 'delegation_grants_expiry_cap'")).rows[0]!;
  assert.equal(validated.convalidated, true);
});
