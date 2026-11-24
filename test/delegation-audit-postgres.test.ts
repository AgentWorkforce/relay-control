import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test, { type TestContext } from "node:test";
import pg from "pg";
import { PostgresDatabase } from "../src/database.js";
import { consumeAction, decideUnderLocks, listAuditPage, recordDelegationAudit, redactExpiredQuotes, releaseClaim, revokeAllGrants } from "../src/delegation/service.js";
import { createDelegationRetention } from "../src/delegation/retention.js";
import { migrate } from "../src/migrations.js";
import { isolatedPostgresPool } from "./support/postgres.js";

const postgresUrl = process.env.TEST_DATABASE_URL;
const options = { skip: postgresUrl ? false : "TEST_DATABASE_URL is not set (delegation multi-connection proofs)", timeout: 60_000 };

async function fixture(t: TestContext) {
  const admin = new pg.Pool({ connectionString: postgresUrl, max: 1 });
  const schema = `delegation_pg_${randomUUID().replaceAll("-", "")}`;
  await admin.query(`CREATE SCHEMA "${schema}"`);
  let database: PostgresDatabase | null = null;
  t.after(async () => {
    try { await database?.close(); } finally {
      try { await admin.query(`DROP SCHEMA "${schema}" CASCADE`); } finally { await admin.end(); }
    }
  });
  const pool = await isolatedPostgresPool(postgresUrl!, schema, 4);
  database = new PostgresDatabase(pool);
  await migrate(database);
  const organizationId = randomUUID();
  const workspaceId = randomUUID();
  const ownerId = randomUUID();
  await database.query("INSERT INTO users (id, email, name) VALUES ($1, $2, 'Owner')", [ownerId, `owner-${ownerId}@example.test`]);
  await database.query("INSERT INTO organizations (id, name) VALUES ($1, 'Org')", [organizationId]);
  await database.query(`INSERT INTO workspaces (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
    VALUES ($1, $2, 'Workspace', $3, 'envelope')`, [workspaceId, organizationId, `rw-${workspaceId}`]);
  return { pool, database, workspaceId, ownerId };
}

test("audit pages: the first page lists every committed event; cursor pages never skip one committed out of id order", options,
  async (t) => {
    const { pool, database, workspaceId } = await fixture(t);
    const viewer = randomUUID();
    const page = (afterId: string | null) => listAuditPage(database, {
      workspaceId, all: true, viewerUserId: viewer, since: null, grantId: null, limit: 100, afterId,
    });
    const ids = (rows: Record<string, unknown>[]) => rows.map(row => String(row.id));

    await recordDelegationAudit(database, { workspaceId, event: "first" });
    const start = await page(null);
    assert.equal(start.events.length, 1);
    assert.equal(start.complete, true);
    const first = start.nextAfterId!;
    assert.equal(first, ids(start.events)[0]);

    // A transaction takes the next id and stays open; a later one commits a higher id.
    const slow = await pool.connect();
    try {
      await slow.query("BEGIN");
      const pending = (await slow.query<{ id: string }>(
        "INSERT INTO delegation_audit_events (workspace_id, event) VALUES ($1, 'slow') RETURNING id::text", [workspaceId],
      )).rows[0]!.id;
      await recordDelegationAudit(database, { workspaceId, event: "fast" });
      const fast = (await database.query<{ id: string }>(
        "SELECT id::text FROM delegation_audit_events WHERE event = 'fast'")).rows[0]!.id;
      assert.ok(BigInt(fast) > BigInt(pending));
      // The first page is not fenced: it lists the committed higher id, but its
      // safe cursor stays before it, and it is not complete.
      const unfenced = await page(null);
      assert.deepEqual(ids(unfenced.events), [first, fast]);
      assert.equal(unfenced.nextAfterId, first);
      assert.equal(unfenced.complete, false);
      // A cursor page holds the committed higher id back while the lower one is in flight.
      const held = await page(first);
      assert.deepEqual(ids(held.events), []);
      assert.equal(held.heldBack, 1);
      assert.equal(held.nextAfterId, first);
      assert.equal(held.complete, false);
      await slow.query("COMMIT");
      // Resuming from the cursor returns both, in commit-safe order: nothing was skipped.
      const resumed = await page(first);
      assert.deepEqual(ids(resumed.events), [pending, fast]);
      assert.equal(resumed.nextAfterId, fast);
      assert.equal(resumed.complete, true);
    } finally {
      slow.release();
    }

    // A transaction that took its id early but writes its event late is ordered
    // by its transaction, ahead of an event a younger transaction committed first.
    const before = (await page(null)).nextAfterId!;
    const early = await pool.connect();
    let late: string;
    try {
      await early.query("BEGIN");
      await early.query("SELECT pg_current_xact_id()");
      await recordDelegationAudit(database, { workspaceId, event: "younger" });
      assert.deepEqual(ids((await page(before)).events), []);
      late = (await early.query<{ id: string }>(
        "INSERT INTO delegation_audit_events (workspace_id, event) VALUES ($1, 'older') RETURNING id::text", [workspaceId],
      )).rows[0]!.id;
      await early.query("COMMIT");
    } finally {
      early.release();
    }
    const resumed = (await page(before)).events;
    assert.deepEqual(resumed.map(row => row.event), ["older", "younger"]);
    assert.ok(BigInt(String(resumed[0]!.id)) > BigInt(String(resumed[1]!.id)));
    assert.equal(String(resumed[0]!.id), late);

    // A rolled-back transaction leaves a gap that does not hold the log back.
    const aborted = await pool.connect();
    try {
      await aborted.query("BEGIN");
      await aborted.query("INSERT INTO delegation_audit_events (workspace_id, event) VALUES ($1, 'aborted')", [workspaceId]);
      await aborted.query("ROLLBACK");
    } finally {
      aborted.release();
    }
    await recordDelegationAudit(database, { workspaceId, event: "after-gap" });
    const all = await page(null);
    assert.deepEqual(all.events.map(row => row.event), ["first", "slow", "fast", "older", "younger", "after-gap"]);
    assert.equal(all.complete, true);
  });

test("consuming redeems of one approval serialize (FOR NO KEY UPDATE); share locks deadlock", options, async (t) => {
  const { database, workspaceId, ownerId } = await fixture(t);
  await database.query("INSERT INTO delegation_policies (workspace_id, delegation_enabled) VALUES ($1, true)", [workspaceId]);
  const action = { class: "deploy" as const, target: "web:prod" };
  const mint = async () => {
    const id = `apv_${randomUUID().replaceAll("-", "")}`;
    await database.query(
      `INSERT INTO delegation_approvals (id, workspace_id, owner_user_id, tier, actions, single_use, expires_at)
       VALUES ($1, $2, $3, 'O', $4::jsonb, true, now() + interval '1 hour')`,
      [id, workspaceId, ownerId, JSON.stringify([action])],
    );
    return id;
  };
  const consumer = (approvalId: string, consuming: boolean, afterLock: () => Promise<void>) =>
    decideUnderLocks(database, { workspaceId, memberUserIds: [], grantId: null, approvalId, consuming }, async (_state, tx) => {
      await afterLock();
      return consumeAction(tx, { approvalId, workspaceId, action, consumedBy: "recipient" });
    });
  const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

  // Share locks: both hold the approval, A's consumed_at stamp waits on B's
  // share lock while B's insert of the same action waits on A: a deadlock.
  const shared = await mint();
  let locked = 0;
  const bothLocked = async () => {
    locked += 1;
    while (locked < 2) await sleep(10);
  };
  const results = await Promise.allSettled([
    consumer(shared, false, bothLocked),
    consumer(shared, false, async () => { await bothLocked(); await sleep(200); }),
  ]);
  const rejected = results.filter(result => result.status === "rejected") as PromiseRejectedResult[];
  assert.equal(rejected.length, 1, JSON.stringify(results));
  assert.equal((rejected[0]!.reason as { code?: string }).code, "40P01");

  // FOR NO KEY UPDATE: the second consumer waits for the first to commit, then
  // sees its consumption; the approval is stamped consumed_at.
  const serialized = await mint();
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  const firstRun = consumer(serialized, true, () => held);
  await sleep(100);
  const secondRun = consumer(serialized, true, async () => undefined);
  await sleep(200);
  release();
  assert.deepEqual(await Promise.all([firstRun, secondRun]), [true, false]);
  const row = (await database.query<{ consumed_at: Date | null }>(
    "SELECT consumed_at FROM delegation_approvals WHERE id = $1", [serialized])).rows[0]!;
  assert.ok(row.consumed_at);
});

test("the retention sweep skips a row another transaction holds, and never expires a grant revoked meanwhile", options, async (t) => {
  const { pool, database, workspaceId, ownerId } = await fixture(t);
  // Two expired quotes; another transaction (an owner's redaction, say) holds one of them.
  const quoteRow = async (messageId: string) => (await database.query<{ id: string }>(
    `INSERT INTO delegation_audit_events (workspace_id, event, owner_user_id, message_id, quote, quote_hash, created_at)
     VALUES ($1, 'approval.attested', $2, $3, 'old words', 'h', now() - interval '91 days') RETURNING id::text`,
    [workspaceId, ownerId, messageId])).rows[0]!.id;
  const held = await quoteRow("m-held");
  const free = await quoteRow("m-free");
  const holder = await pool.connect();
  try {
    await holder.query("BEGIN");
    await holder.query("SELECT 1 FROM delegation_audit_events WHERE id = $1 FOR UPDATE", [held]);
    // The sweep neither waits on nor fails for the held row: it redacts the other.
    const started = Date.now();
    assert.equal(await redactExpiredQuotes(database, 100), 1);
    assert.ok(Date.now() - started < 5_000);
    await holder.query("ROLLBACK");
  } finally {
    holder.release();
  }
  const quotes = (await database.query<{ id: string; quote: string | null }>(
    "SELECT id::text, quote FROM delegation_audit_events WHERE id IN ($1, $2) ORDER BY id", [held, free])).rows;
  assert.equal(quotes.find(row => row.id === free)!.quote, null);
  assert.equal(quotes.find(row => row.id === held)!.quote, "old words");
  // The next sweep redacts the row that was held.
  assert.equal(await redactExpiredQuotes(database, 100), 1);

  // A lapsed grant revoked by a concurrent transaction is never overwritten as expired.
  await database.query("INSERT INTO delegation_policies (workspace_id, delegation_enabled) VALUES ($1, true)", [workspaceId]);
  await database.query(
    `INSERT INTO delegation_grants (id, workspace_id, organization_id, owner_user_id, delegate_agent_id, delegate_agent_name,
       scopes, expires_at, created_auth_method)
     SELECT 'grt_lapsedrevoked1', $1, w.organization_id, $2, 'ag_x', 'x', '[]'::jsonb, now() - interval '1 minute', 'session'
       FROM workspaces w WHERE w.id = $1`, [workspaceId, ownerId]);
  const revoker = await pool.connect();
  try {
    await revoker.query("BEGIN");
    await revoker.query("UPDATE delegation_grants SET status = 'revoked', revoked_at = now() WHERE id = 'grt_lapsedrevoked1'");
    const sweep = createDelegationRetention({ database }).sweep();
    await new Promise(resolve => setTimeout(resolve, 300));
    await revoker.query("COMMIT");
    assert.equal((await sweep).expired, 0);
  } finally {
    revoker.release();
  }
  const grant = (await database.query<{ status: string }>("SELECT status FROM delegation_grants WHERE id = 'grt_lapsedrevoked1'")).rows[0]!;
  assert.equal(grant.status, "revoked");
});

test("standalone consumers of one approval serialize: 4 over 2 actions, exactly 2 win, consumed_at set", options, async (t) => {
  const { database, workspaceId, ownerId } = await fixture(t);
  const actions = [{ class: "deploy" as const, target: "web:prod" }, { class: "deploy" as const, target: "api:prod" }];
  const id = `apv_${randomUUID().replaceAll("-", "")}`;
  await database.query(
    `INSERT INTO delegation_approvals (id, workspace_id, owner_user_id, tier, actions, single_use, expires_at)
     VALUES ($1, $2, $3, 'O', $4::jsonb, true, now() + interval '1 hour')`, [id, workspaceId, ownerId, JSON.stringify(actions)]);
  const results = await Promise.all([0, 1, 2, 3].map(index =>
    consumeAction(database, { approvalId: id, workspaceId, action: actions[index % 2]!, consumedBy: `r-${index}` })));
  assert.equal(results.filter(Boolean).length, 2);
  const row = (await database.query<{ consumed_at: Date | null }>("SELECT consumed_at FROM delegation_approvals WHERE id = $1", [id])).rows[0]!;
  assert.ok(row.consumed_at);
});

test("releasing a claim and revoking grants concurrently never deadlock (grants, then the claim)", options, async (t) => {
  const { database, workspaceId, ownerId } = await fixture(t);
  await database.query(
    `INSERT INTO delegation_claims (id, workspace_id, user_id, code_hash, expires_at, consumed_at, agent_id)
     VALUES ('clm_concurrent0001', $1, $2, 'h1', now() + interval '10 minutes', now(), 'ag_bot')`, [workspaceId, ownerId]);
  await database.query(
    `INSERT INTO delegation_agent_bindings (workspace_id, relaycast_workspace_id, agent_id, agent_name, user_id, claim_id)
     VALUES ($1, 'rw', 'ag_bot', 'bot', $2, 'clm_concurrent0001')`, [workspaceId, ownerId]);
  await database.query(
    `INSERT INTO delegation_grants (id, workspace_id, organization_id, owner_user_id, delegate_agent_id, delegate_agent_name,
       scopes, expires_at, created_auth_method)
     SELECT 'grt_concurrent00001', $1, w.organization_id, $2, 'ag_bot', 'bot', '[]'::jsonb, now() + interval '1 day', 'session'
       FROM workspaces w WHERE w.id = $1`, [workspaceId, ownerId]);
  for (let round = 0; round < 5; round += 1) {
    await database.query("UPDATE delegation_claims SET released_at = NULL WHERE id = 'clm_concurrent0001'");
    await database.query("UPDATE delegation_grants SET status = 'active', revoked_at = NULL WHERE id = 'grt_concurrent00001'");
    const results = await Promise.allSettled([
      releaseClaim(database, { workspaceId, claimId: "clm_concurrent0001", actorUserId: ownerId, admin: true, authMethod: "session" }),
      database.transaction(tx => revokeAllGrants(tx, { workspaceId, ownerUserId: ownerId, actorUserId: ownerId, reason: "owner_revoked",
        authMethod: "session" })),
      releaseClaim(database, { workspaceId, claimId: "clm_concurrent0001", actorUserId: ownerId, admin: true, authMethod: "session" }),
    ]);
    for (const result of results) assert.equal(result.status, "fulfilled", JSON.stringify(result));
    const winners = results.slice(0, 1).concat(results.slice(2)).filter(result => result.status === "fulfilled" && result.value);
    assert.equal(winners.length, 1);
    const grant = (await database.query<{ status: string }>("SELECT status FROM delegation_grants WHERE id = 'grt_concurrent00001'")).rows[0]!;
    assert.equal(grant.status, "revoked");
  }
});

test("the retention sweep takes the oldest due quotes across workspaces, so one backlog cannot starve the rest", options, async (t) => {
  const { database, workspaceId: busy, ownerId } = await fixture(t);
  // A second workspace, created after the busy one, holding the oldest due quote.
  const quiet = randomUUID();
  await database.query(`INSERT INTO workspaces (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
    SELECT $1, organization_id, 'Quiet', $2, 'envelope' FROM workspaces WHERE id = $3`, [quiet, `rw-${quiet}`, busy]);
  const quoteRow = async (workspaceId: string, messageId: string, days: number) => (await database.query<{ id: string }>(
    `INSERT INTO delegation_audit_events (workspace_id, event, owner_user_id, message_id, quote, quote_hash, created_at)
     VALUES ($1, 'approval.attested', $2, $3, 'old words', 'h', now() - make_interval(days => $4)) RETURNING id::text`,
    [workspaceId, ownerId, messageId, days])).rows[0]!.id;
  const busyRows = [];
  for (let index = 0; index < 5; index += 1) busyRows.push(await quoteRow(busy, `m-busy-${index}`, 100 - index));
  const oldest = await quoteRow(quiet, "m-quiet", 200);
  const quoted = async (id: string) => (await database.query<{ quote: string | null }>(
    "SELECT quote FROM delegation_audit_events WHERE id = $1", [id])).rows[0]!.quote;
  // A batch of one takes the quiet workspace's older quote, not the busy one's.
  assert.equal(await redactExpiredQuotes(database, 1), 1);
  assert.equal(await quoted(oldest), null);
  for (const id of busyRows) assert.equal(await quoted(id), "old words");
  // The next batch of two takes the busy workspace's two oldest (100 and 99 days).
  assert.equal(await redactExpiredQuotes(database, 2), 2);
  assert.deepEqual(await Promise.all(busyRows.map(quoted)), [null, null, "old words", "old words", "old words"]);
});
