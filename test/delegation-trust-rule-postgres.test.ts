import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test, { type TestContext } from "node:test";
import pg from "pg";
import { PostgresDatabase, type SqlExecutor } from "../src/database.js";
import {
  chainUnderLock, decideUnderLocks, freshRefusal, materializeRuleGrant, putTrustRule, releaseClaim, revokeAllGrants, revokeGrants,
  revokeTrustRule, revokeTrustRulesTx, type DelegationWorkspace, type GrantRow,
} from "../src/delegation/service.js";
import { resolveTrustPath, sqlTrustReader, trustPathProvenAt, type TrustPath } from "../src/delegation/trust.js";
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
  assert.equal((await f.grants("ag_other"))[0]!.revoked_reason, "owner_revoke_all");
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

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
const deadlock = (error: unknown) => (error as { code?: string })?.code === "40P01";

/** A rule-backed grant on the real chain of `agentId` (walked now), and a tier D approval under it. */
async function ruled(f: Awaited<ReturnType<typeof fixture>>, ruleId: string, agentId: string) {
  const proof = (await resolveTrustPath(sqlTrustReader(f.database), { workspaceId: f.workspaceId, relaycastWorkspaceId: "rw_pg",
    ownerUserId: f.ownerId, agentId }))!;
  assert.ok(proof, `${agentId} proves out`);
  const grant = (await materializeRuleGrant(f.database, { workspace: f.workspace, ruleId, ownerUserId: f.ownerId,
    delegateAgentId: agentId, delegateAgentName: proof.name, trustPath: proof.path, provenAt: trustPathProvenAt(proof.path) }))!;
  const approvalId = `apv_${randomUUID().replaceAll("-", "")}`;
  await f.database.query(`INSERT INTO delegation_approvals (id, workspace_id, owner_user_id, tier, grant_id, message_id, actions,
      single_use, expires_at) VALUES ($1, $2, $3, 'D', $4, 'm', '[{"class":"merge","target":"a/b#1"}]'::jsonb, false, now() + interval '1 hour')`,
  [approvalId, f.workspaceId, f.ownerId, grant.id]);
  return { grant, approvalId };
}

async function spawnRow(f: Awaited<ReturnType<typeof fixture>>, actorId: string, workerId: string) {
  const id = randomUUID();
  await f.database.query(`INSERT INTO relay_spawns (id, workspace_id, user_id, authority_hash, relaycast_workspace_id, actor_id,
      idempotency_hash, request_hash, agent_name, cli, node_id, state, worker_id, worker_address, audit)
    VALUES ($1, $2, $3, $4, 'rw_pg', $5, $6, $7, 'worker', 'claude', 'node-1', 'ready', $8, 'worker@node-1', '[]'::jsonb)`,
  [id, f.workspaceId, f.ownerId, `a${id}`, actorId, `i${id}`, `r${id}`, workerId]);
  return id;
}

/** A connected assistant of the owner: a live OAuth grant and session pinned to `agentId`, and the owner's participant. */
async function connectorRow(f: Awaited<ReturnType<typeof fixture>>, agentId: string) {
  const clientId = `client-${randomUUID()}`;
  const grantId = randomUUID();
  const family = randomUUID();
  await f.database.query("INSERT INTO mcp_oauth_clients (client_id, client_name, redirect_uris) VALUES ($1, 'ChatGPT', $2)",
    [clientId, ["https://chatgpt.com/cb"]]);
  await f.database.query(`INSERT INTO mcp_oauth_grants (id, client_id, client_name, user_id, organization_id, workspace_id, agent_name,
      agent_remote_id, scopes, resource, token_family_id) VALUES ($1, $2, 'ChatGPT', $3, $4, $5, $6, $6, ARRAY['relay:mcp'], 'r', $7)`,
  [grantId, clientId, f.ownerId, f.organizationId, f.workspaceId, agentId, family]);
  await f.database.query(`INSERT INTO mcp_oauth_sessions (id, grant_id, token_family_id, user_id, organization_id, workspace_id, scopes,
      access_token_hash, refresh_token_hash, access_token_expires_at, refresh_token_expires_at, created_at, updated_at)
    VALUES ($1, $2, $3, $4, $5, $6, ARRAY['relay:mcp'], $7, $8, now() + interval '1 hour', now() + interval '30 days', now(), now())`,
  [randomUUID(), grantId, family, f.ownerId, f.organizationId, f.workspaceId, randomUUID().replaceAll("-", "").padEnd(64, "0"),
    randomUUID().replaceAll("-", "").padEnd(64, "1")]);
  await f.database.query(`INSERT INTO hosted_relay_participants (id, workspace_id, user_id, relaycast_workspace_id, agent_name,
      agent_remote_id, token_ciphertext) VALUES ($1, $2, $3, 'rw_pg', $4, $4, 'envelope')`,
  [randomUUID(), f.workspaceId, f.ownerId, agentId]);
  return grantId;
}

test("round 3 (3): a claim release blocks on a decision holding the chain's share locks; the next decision is revoked", options, async (t) => {
  const f = await fixture(t);
  const claimId = await f.claimed("ag_bot");
  await spawnRow(f, "ag_bot", "ag_worker");
  const rule = await f.rule();
  const { grant, approvalId } = await ruled(f, rule.id, "ag_worker");
  const decide = (hold = 0) => decideUnderLocks(f.database, { workspaceId: f.workspaceId, memberUserIds: [f.ownerId],
    grantOwnerUserId: f.ownerId, grantId: grant.id, approvalId, trustRuleId: rule.id,
    chain: chainUnderLock(f.workspace, grant, null) }, async (state) => {
    await sleep(hold);
    return freshRefusal(state, { actions: [{ class: "merge", target: "a/b#1" }], tier: "D", recipientAgentId: "r", nowMs: Date.now(),
      policy: state.policy });
  });
  const deciding = decide(600);
  await sleep(150);
  let released = false;
  const releasing = releaseClaim(f.database, { workspaceId: f.workspaceId, claimId, actorUserId: f.ownerId, admin: false,
    authMethod: "session" }).then(result => { released = true; return result; });
  await sleep(250);
  assert.equal(released, false, "the release waits for the decision holding the claim's share lock");
  assert.equal(await deciding, null);
  assert.ok(await releasing);
  // The worker's chain stood on the released claim: the next decision refuses under its locks.
  assert.equal(await decide(), "revoked");
});

test("round 3 (4): revoke-all locks every grant before any approval: no deadlock with a decision on an owner-made grant", options, async (t) => {
  const f = await fixture(t);
  for (let round = 0; round < 4; round += 1) {
    const claimId = await f.claimed(`ag_sys_${round}`);
    void claimId;
    const rule = await f.rule();
    const { grant: system } = await ruled(f, rule.id, `ag_sys_${round}`);
    const owned = await f.ownerGrant(`ag_own_${round}`);
    // One Tier O approval attested under both grants (a shared approval).
    const approvalId = `apv_${randomUUID().replaceAll("-", "")}`;
    await f.database.query(`INSERT INTO delegation_approvals (id, workspace_id, owner_user_id, tier, actions, single_use, expires_at)
      VALUES ($1, $2, $3, 'O', '[{"class":"merge","target":"a/b#1"}]'::jsonb, false, now() + interval '1 hour')`,
    [approvalId, f.workspaceId, f.ownerId]);
    for (const grantId of [system.id, owned]) {
      await f.database.query(`INSERT INTO delegation_attestations (jti, workspace_id, approval_id, grant_id, message_id, recipient_agent_id,
          delegate_agent_id, kid, accept, standing, issued_at, expires_at)
        VALUES ($1, $2, $3, $4, 'm', 'r', 'd', 'k', 'code_owners', 'own_owner', now(), now() + interval '5 minutes')`,
      [randomUUID(), f.workspaceId, approvalId, grantId]);
    }
    // A decision on the owner-made grant: grant share-locked, then (after a pause) the approval, as decideUnderLocks takes them.
    const client = await f.pool.connect();
    const decision = (async () => {
      try {
        await client.query("BEGIN");
        await client.query("SELECT 1 FROM delegation_grants WHERE id = $1 FOR SHARE", [owned]);
        await sleep(400);
        await client.query("SELECT 1 FROM delegation_approvals WHERE id = $1 FOR NO KEY UPDATE", [approvalId]);
        await client.query("COMMIT");
      } catch (error) {
        await client.query("ROLLBACK").catch(() => undefined);
        throw error;
      } finally {
        client.release();
      }
    })();
    // Concurrent real decisions on the owner-made grant too.
    const decisions = Array.from({ length: 3 }, () => decideUnderLocks(f.database, { workspaceId: f.workspaceId,
      memberUserIds: [f.ownerId], grantOwnerUserId: f.ownerId, grantId: owned, approvalId, consuming: true }, async () => null));
    await sleep(150);
    const revoking = f.database.transaction(tx => revokeAllGrants(tx, { workspaceId: f.workspaceId, ownerUserId: f.ownerId,
      actorUserId: f.ownerId, reason: "owner_revoke_all", authMethod: "session" }));
    const settled = await Promise.allSettled([decision, revoking, ...decisions]);
    for (const result of settled) {
      if (result.status === "rejected") assert.fail(`round ${round}: ${deadlock(result.reason) ? "40P01 deadlock" : String(result.reason)}`);
    }
    const revoked = (settled[1] as PromiseFulfilledResult<string[]>).value;
    assert.deepEqual([...revoked].sort(), [system.id, owned].sort());
    const [ruleEvent] = (await f.database.query<{ data: { revoked_grants: string[]; count: number } }>(
      "SELECT data FROM delegation_audit_events WHERE event = 'trust_rule.revoked' AND data->>'trust_rule_id' = $1", [rule.id])).rows;
    assert.deepEqual([ruleEvent!.data.revoked_grants, ruleEvent!.data.count], [[system.id], 1]);
  }
});

test("round 3 (5): a rule grant starts no earlier than the end of any earlier grant of the pair, owner-made included", options, async (t) => {
  const f = await fixture(t);
  const rule = await f.rule();
  await f.database.query("UPDATE delegation_trust_rules SET created_at = now() - interval '2 days'");
  const old = new Date(Date.now() - 86_400_000);
  // A lapsed owner-made grant: the rule takes over from its expiry, not from the older proof.
  const lapsedClaim = await f.claimed("ag_lapsed");
  const lapsed = await f.ownerGrant("ag_lapsed");
  await f.database.query("UPDATE delegation_grants SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour' WHERE id = $1",
    [lapsed]);
  const fromLapse = (await materializeRuleGrant(f.database, { workspace: f.workspace, ruleId: rule.id, ownerUserId: f.ownerId,
    delegateAgentId: "ag_lapsed", delegateAgentName: "assistant", trustPath: { root: { kind: "claim", claim_id: lapsedClaim,
      agent_id: "ag_lapsed", created_at: old.toISOString() }, hops: [] }, provenAt: old, claimId: lapsedClaim }))!;
  const lapsedRow = (await f.grants("ag_lapsed")).find(row => row.id === lapsed)!;
  assert.equal(lapsedRow.status, "expired");
  assert.equal(new Date(fromLapse.created_at).getTime(), new Date(lapsedRow.expires_at).getTime());
  // A revoked owner-made grant: from its revocation. An owner-made row revoked as `owner_excluded` never excludes the rule.
  const revokedClaim = await f.claimed("ag_revoked");
  const revoked = await f.ownerGrant("ag_revoked");
  await f.database.query(`UPDATE delegation_grants SET status = 'revoked', revoked_at = now() - interval '10 minutes',
      revoked_reason = 'owner_excluded' WHERE id = $1`, [revoked]);
  const fromRevoke = (await materializeRuleGrant(f.database, { workspace: f.workspace, ruleId: rule.id, ownerUserId: f.ownerId,
    delegateAgentId: "ag_revoked", delegateAgentName: "assistant", trustPath: { root: { kind: "claim", claim_id: revokedClaim,
      agent_id: "ag_revoked", created_at: old.toISOString() }, hops: [] }, provenAt: old, claimId: revokedClaim }));
  assert.ok(fromRevoke, "an owner-made revocation does not exclude the agent from the rule");
  const revokedRow = (await f.grants("ag_revoked")).find(row => row.id === revoked)!;
  assert.equal(new Date(fromRevoke!.created_at).getTime(), new Date(revokedRow.revoked_at!).getTime());
});

test("round 3 (8): the expiry cap counts hours, so an exactly-2160-hour grant across the March DST change is admitted", options, async (t) => {
  const f = await fixture(t);
  const client = await f.pool.connect();
  try {
    await client.query("SET TIME ZONE 'America/Los_Angeles'");
    // 2027-02-15 00:00 PST, then 2160 elapsed hours later (across the 2027-03-14 spring-forward).
    const created = new Date("2027-02-15T08:00:00Z");
    const insert = (id: string, hours: number) => client.query(`INSERT INTO delegation_grants (id, workspace_id, organization_id,
        owner_user_id, delegate_agent_id, delegate_agent_name, scopes, expires_at, created_auth_method, created_at)
      VALUES ($1, $2, $3, $4, $5, 'x', '[]'::jsonb, $6, 'session', $7)`,
    [id, f.workspaceId, f.organizationId, f.ownerId, `ag_${id}`, new Date(created.getTime() + hours * 3_600_000), created]);
    // 90 calendar days in Los Angeles is 2159 elapsed hours here; the cap admits the full 2160.
    const days = (await client.query<{ ends: Date }>("SELECT $1::timestamptz + interval '90 days' AS ends", [created])).rows[0]!;
    assert.equal(new Date(created.getTime() + 2160 * 3_600_000).getTime() - new Date(days.ends).getTime(), 3_600_000);
    await insert("grt_dst2160h", 2160);
    await assert.rejects(insert("grt_dst2161h", 2161), /delegation_grants_expiry_cap/);
  } finally {
    await client.query("RESET TIME ZONE").catch(() => undefined);
    client.release();
  }
});

test("D1: an owner's departure racing a decision by another member under a connector chain: no deadlock, either order", options, async (t) => {
  const f = await fixture(t);
  const bob = randomUUID();
  await f.database.query("INSERT INTO users (id, email, name) VALUES ($1, $2, 'Bob')", [bob, `bob-${bob}@example.test`]);
  await f.database.query("INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, 'member')",
    [f.organizationId, bob]);

  /** The departure: the owner's membership FOR UPDATE, their OAuth grants revoked, then their rules and grants, then the membership. */
  async function departure(client: pg.PoolClient, oauthGrantId: string, between?: () => Promise<void>) {
    await client.query("SELECT 1 FROM organization_memberships WHERE organization_id = $1 AND user_id = $2 FOR UPDATE",
      [f.organizationId, f.ownerId]);
    await between?.();
    await client.query("UPDATE mcp_oauth_grants SET revoked_at = now(), revoked_reason = 'member_removed' WHERE id = $1", [oauthGrantId]);
    await revokeTrustRulesTx(client as unknown as SqlExecutor, { workspaceId: f.workspaceId, ownerUserId: f.ownerId, actorUserId: null,
      authMethod: "system", reason: "owner_left" });
    await client.query("DELETE FROM organization_memberships WHERE organization_id = $1 AND user_id = $2", [f.organizationId, f.ownerId]);
  }
  const decideAs = (grant: GrantRow, approvalId: string, ruleId: string, pause = 0) => decideUnderLocks(f.database, {
    workspaceId: f.workspaceId, memberUserIds: [bob], grantOwnerUserId: f.ownerId, grantId: grant.id, approvalId, trustRuleId: ruleId,
    chain: async tx => { await sleep(pause); return chainUnderLock(f.workspace, grant, null)!(tx); } }, async (state) =>
    freshRefusal(state, { actions: [{ class: "merge", target: "a/b#1" }], tier: "D", recipientAgentId: "r", nowMs: Date.now(),
      policy: state.policy }));

  // Decision first: it holds the owner's membership share lock, the rule and the grant, then reads the chain;
  // the departure queues at its first lock instead of holding the OAuth grant the chain needs.
  {
    const oauth = await connectorRow(f, "ag_gpt_1");
    const rule = await f.rule();
    const { grant, approvalId } = await ruled(f, rule.id, "ag_gpt_1");
    const deciding = decideAs(grant, approvalId, rule.id, 400);
    await sleep(150);
    const client = await f.pool.connect();
    try {
      await client.query("BEGIN");
      const leaving = departure(client, oauth).then(() => client.query("COMMIT"));
      const settled = await Promise.allSettled([deciding, leaving]);
      for (const result of settled) {
        if (result.status === "rejected") {
          await client.query("ROLLBACK").catch(() => undefined);
          assert.fail(deadlock(result.reason) ? "40P01 deadlock" : String(result.reason));
        }
      }
      assert.equal((settled[0] as PromiseFulfilledResult<unknown>).value, null);
    } finally {
      client.release();
    }
  }
  // Departure first (committing while the decision waits): the decision answers revoked.
  await f.database.query("INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, 'owner')",
    [f.organizationId, f.ownerId]);
  {
    const oauth = await connectorRow(f, "ag_gpt_2");
    const rule = await f.rule();
    const { grant, approvalId } = await ruled(f, rule.id, "ag_gpt_2");
    const client = await f.pool.connect();
    try {
      await client.query("BEGIN");
      let deciding: Promise<unknown> | null = null;
      await departure(client, oauth, async () => {
        deciding = decideAs(grant, approvalId, rule.id);
        await sleep(200);
      });
      await client.query("COMMIT");
      assert.equal(await deciding!, "revoked");
    } finally {
      client.release();
    }
  }
});
