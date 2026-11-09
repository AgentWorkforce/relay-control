/**
 * Factory outbox on real PostgreSQL with two workers on two connection pools:
 * SKIP LOCKED contention under a barrier, and lease/generation-fenced
 * completion. PGlite is single-connection, so none of this is provable there.
 *
 * Opt-in: set FACTORY_PG_TEST_URL to a PostgreSQL 16 server URL whose role
 * may CREATE DATABASE. The test creates a dedicated `factory_race_<random>`
 * database, migrates it, and drops it at the end.
 */
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import test from "node:test";
import pg from "pg";
import { encryptSecret, type EncryptionKeyring } from "../src/crypto.js";
import { PostgresDatabase } from "../src/database.js";
import type { RelaycastClient } from "../src/messaging/relaycast.js";
import type { FactoryRuntime } from "../src/factory/runtime.js";
import { retireBindingsInTx } from "../src/factory/store.js";
import { createFactoryWorker, type FactoryWorkerDeps } from "../src/factory/worker.js";
import { migrate } from "../src/migrations.js";

const baseUrl = process.env.FACTORY_PG_TEST_URL;
const skip = baseUrl ? false : "FACTORY_PG_TEST_URL is unset (opt-in real-PostgreSQL outbox test)";

const keyring: EncryptionKeyring = { active: { id: "pg-race", key: Buffer.alloc(32, 9) } };
const FACTORY_KEY = "fk_live_pg_race_key_0001";

/** A two-party barrier that fails instead of hanging. */
function barrier(parties: number, timeoutMs = 10_000) {
  let arrived = 0;
  let open!: () => void;
  const opened = new Promise<void>((resolve) => { open = resolve; });
  return async () => {
    if (++arrived === parties) open();
    let timer!: NodeJS.Timeout;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`barrier timed out with ${arrived}/${parties} inside the claim`)), timeoutMs);
    });
    try {
      await Promise.race([opened, timeout]);
    } finally {
      clearTimeout(timer);
    }
  };
}

test("factory outbox on real PostgreSQL: two workers, SKIP LOCKED claim and lease/generation-fenced completion", { skip }, async (t) => {
  const admin = new pg.Client({ connectionString: baseUrl });
  await admin.connect();
  const dbName = `factory_race_${randomBytes(6).toString("hex")}`;
  await admin.query(`CREATE DATABASE ${dbName}`);
  const url = new URL(baseUrl!);
  url.pathname = `/${dbName}`;
  const databases: PostgresDatabase[] = [];
  t.after(async () => {
    for (const database of databases) await database.close().catch(() => undefined);
    await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
    await admin.end();
  });
  const open = () => {
    const database = new PostgresDatabase(url.toString());
    databases.push(database);
    return database;
  };

  const setup = open();
  await migrate(setup);
  const serverVersion = (await setup.query<{ server_version: string }>("SHOW server_version")).rows[0]!.server_version;
  t.diagnostic(`PostgreSQL ${serverVersion}`);

  // ----------------------------------------------------------------- seed
  const orgId = randomUUID();
  const userId = randomUUID();
  const workspaceId = randomUUID();
  await setup.query("INSERT INTO users (id, email, name) VALUES ($1, 'owner@race.test', 'Owner')", [userId]);
  await setup.query("INSERT INTO organizations (id, name) VALUES ($1, 'Race')", [orgId]);
  await setup.query("INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, 'owner')", [orgId, userId]);
  await setup.query(
    `INSERT INTO workspaces (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
     VALUES ($1, $2, 'race', 'rc-race', $3)`,
    [workspaceId, orgId, encryptSecret("rk_live_race", keyring.active)],
  );
  await setup.query(
    `INSERT INTO factory_connections (workspace_id, organization_id, user_id, key_envelope, key_hint, validated_at)
     VALUES ($1, $2, $3, $4, '…0001', now())`,
    [workspaceId, orgId, userId, encryptSecret(FACTORY_KEY, keyring.active)],
  );
  const bind = async (sessionId: string) => {
    const id = randomUUID();
    await setup.query(
      `INSERT INTO factory_bindings
         (id, workspace_id, organization_id, user_id, session_id, computer_id, state, generation,
          relay_agent_name, relay_agent_id, hosted_token_envelope)
       VALUES ($1, $2, $3, $4, $5, 'cmp-1', 'bound', 1, $6, $7, $8)`,
      [id, workspaceId, orgId, userId, sessionId, `factory-${sessionId}`, `ag-${sessionId}`, encryptSecret(`at_${sessionId}`, keyring.active)],
    );
    return id;
  };
  const enqueue = async (bindingId: string, messageId: string) => {
    await setup.query(
      `INSERT INTO factory_deliveries
         (binding_id, message_id, workspace_id, organization_id, relay_delivery_id, sender_agent_name, payload_envelope, state)
       VALUES ($1, $2, $3, $4, $5, 'lead', $6, 'pending')`,
      [bindingId, messageId, workspaceId, orgId, `dl-${messageId}`,
        encryptSecret(JSON.stringify({ sender: "lead", text: `body ${messageId}` }), keyring.active)],
    );
  };
  const row = async (bindingId: string, messageId: string) =>
    (await setup.query<Record<string, any>>(
      "SELECT state, code, lease_owner, claim_generation::text AS claim_generation, factory_message_id, attempts FROM factory_deliveries WHERE binding_id = $1 AND message_id = $2",
      [bindingId, messageId],
    )).rows[0]!;
  const expireLease = (bindingId: string, messageId: string) => setup.query(
    "UPDATE factory_deliveries SET lease_until = now() - interval '1 second' WHERE binding_id = $1 AND message_id = $2",
    [bindingId, messageId],
  );

  // -------------------------------------------------------------- workers
  const relaycast = { replyToMessage: async () => ({ id: "rm", conversation_id: "c" }) } as unknown as RelaycastClient;
  let injected = 0;
  const runtime = {
    // Runs the real pre-POST fence on the worker's own connection, then acks.
    async inject(_key: string, _target: unknown, beforeWrite: () => Promise<void>) {
      await beforeWrite();
      return { messageId: `fm-${++injected}` };
    },
  } as unknown as FactoryRuntime;
  let claimHook: FactoryWorkerDeps["afterClaimSelect"];
  const worker = (name: string) => {
    const database = open();
    return {
      name,
      database,
      worker: createFactoryWorker({
        database,
        keyring,
        runtime,
        relaycast,
        log: () => undefined,
        publicBaseUrl: "https://control.race.test",
        historyIntervalMs: 300_000,
        releasePending: async () => 0,
        afterClaimSelect: (tx, rows) => claimHook?.(tx, rows) ?? Promise.resolve(),
      }),
    };
  };
  const a = worker("A");
  const b = worker("B");

  // ---------------------------------- (a) SKIP LOCKED under a two-worker barrier
  await t.test("(a) N due rows are each claimed by exactly one of two concurrent workers", async () => {
    const N = 20;
    const LIMIT = 15;
    const bindingId = await bind("sess-skip");
    for (let i = 0; i < N; i++) await enqueue(bindingId, `m-${String(i).padStart(2, "0")}`);
    const wait = barrier(2);
    const inside: Array<{ pid: number; rows: number }> = [];
    claimHook = async (tx, rows) => {
      const pid = (await tx.query<{ pid: number }>("SELECT pg_backend_pid() AS pid")).rows[0]!.pid;
      inside.push({ pid, rows: rows.length });
      // Both claim transactions hold their row locks here at the same time. A
      // blocking FOR UPDATE (no SKIP LOCKED) would wait on the other worker
      // and time this barrier out.
      await wait();
    };
    const [claimsA, claimsB] = await Promise.all([a.worker.claim(LIMIT), b.worker.claim(LIMIT)]);
    claimHook = undefined;
    assert.equal(inside.length, 2);
    assert.notEqual(inside[0]!.pid, inside[1]!.pid, "two separate backend connections");
    const keys = [...claimsA, ...claimsB].map((claim) => claim.message_id);
    assert.equal(keys.length, N, "every due row claimed");
    assert.equal(new Set(keys).size, N, "no row claimed twice");
    assert.deepEqual([claimsA.length, claimsB.length].sort((x, y) => x - y), [N - LIMIT, LIMIT], "the second select skipped the first's locked rows");
    const owners = new Set([...claimsA, ...claimsB].map((claim) => claim.lease_owner));
    assert.equal(owners.size, N, "one lease owner per claim");
    const states = await setup.query<{ state: string; n: number }>(
      "SELECT state, count(*)::int AS n FROM factory_deliveries WHERE binding_id = $1 GROUP BY state",
      [bindingId],
    );
    assert.deepEqual(states.rows, [{ state: "sending", n: N }]);
    // Each row's stored lease owner is the claiming worker's.
    for (const claim of [...claimsA, ...claimsB]) assert.equal((await row(bindingId, claim.message_id)).lease_owner, claim.lease_owner);
    // Nothing is left to claim; sending rows are never reclaimed.
    assert.deepEqual([(await a.worker.claim(N)).length, (await b.worker.claim(N)).length], [0, 0]);
    t.diagnostic(`(a) A claimed ${claimsA.length}, B claimed ${claimsB.length}, backends ${inside.map((entry) => entry.pid).join("/")}`);
  });

  // ------------------- (b) a swept-expired lease: own owner + same generation only
  await t.test("(b) an expired, swept claim finalizes delivered only under its own lease owner and generation", async () => {
    const bindingId = await bind("sess-lease");
    await enqueue(bindingId, "m-ok");
    const [claim] = await a.worker.claim(1);
    assert.ok(claim);
    await expireLease(bindingId, "m-ok");
    assert.equal(await b.worker.sweepLeases(), 1);
    assert.deepEqual([(await row(bindingId, "m-ok")).state, (await row(bindingId, "m-ok")).code], ["unknown", "lease_expired"]);
    // Another lease owner cannot confirm it, from either connection.
    const forged = { ...claim, lease_owner: randomUUID() };
    assert.equal(await b.worker.finalize(forged, { state: "delivered", factoryMessageId: "fm-forged" }), false);
    assert.equal(await a.worker.finalize(forged, { state: "delivered", factoryMessageId: "fm-forged" }), false);
    // The owner's late non-delivered outcomes never overwrite unknown.
    assert.equal(await a.worker.finalize(claim, { state: "rejected", code: "factory_http_409" }), false);
    assert.equal(await a.worker.finalize(claim, { state: "pending", code: "factory_http_429" }), false);
    assert.equal((await row(bindingId, "m-ok")).state, "unknown");
    // Its own positive ack, same generation: confirmed.
    assert.equal(await a.worker.finalize(claim, { state: "delivered", factoryMessageId: "fm-own" }), true);
    assert.deepEqual([(await row(bindingId, "m-ok")).state, (await row(bindingId, "m-ok")).factory_message_id], ["delivered", "fm-own"]);

    // Same, but the binding is retired (generation bumped) before the late ack.
    const retiredId = await bind("sess-retire");
    await enqueue(retiredId, "m-late");
    const [lateClaim] = await a.worker.claim(1);
    assert.ok(lateClaim);
    assert.equal(lateClaim.binding_id, retiredId);
    await expireLease(retiredId, "m-late");
    assert.equal(await b.worker.sweepLeases(), 1);
    await b.database.transaction((tx) => retireBindingsInTx(tx, { bindingIds: [retiredId] }));
    const generation = (await setup.query<{ g: string }>("SELECT generation::text AS g FROM factory_bindings WHERE id = $1", [retiredId])).rows[0]!.g;
    assert.notEqual(generation, lateClaim.claim_generation);
    const before = await row(retiredId, "m-late");
    assert.equal(await a.worker.finalize(lateClaim, { state: "delivered", factoryMessageId: "fm-too-late" }), false);
    assert.deepEqual(await row(retiredId, "m-late"), before);
    assert.deepEqual([before.state, before.code, before.factory_message_id], ["unknown", "lease_expired", null]);
  });

  // ------------------- (c) re-claim after expiry: new owner, old late outcome ignored
  await t.test("(c) after lease expiry a second worker re-claims with a new lease owner and the first worker's late rejected is ignored", async () => {
    const bindingId = await bind("sess-reclaim");
    await enqueue(bindingId, "m-re");
    const [first] = await a.worker.claim(1);
    assert.ok(first);
    // A's lease expires before its POST: the fence refuses, the row returns to pending.
    await expireLease(bindingId, "m-re");
    await a.worker.process(first);
    assert.deepEqual([(await row(bindingId, "m-re")).state, (await row(bindingId, "m-re")).code], ["pending", "fence_refused"]);
    assert.equal(injected, 0, "nothing was sent under the expired lease");
    await setup.query("UPDATE factory_deliveries SET next_attempt_at = now() WHERE binding_id = $1", [bindingId]);

    const [second] = await b.worker.claim(1);
    assert.ok(second);
    assert.equal(second.message_id, "m-re");
    assert.notEqual(second.lease_owner, first.lease_owner);
    assert.equal(second.claim_generation, first.claim_generation);
    assert.equal(second.attempts, 2);
    assert.equal((await row(bindingId, "m-re")).lease_owner, second.lease_owner);

    // A's late outcomes are all stale.
    assert.equal(await a.worker.finalize(first, { state: "rejected", code: "factory_http_409" }), false);
    assert.equal(await a.worker.finalize(first, { state: "delivered", factoryMessageId: "fm-stale" }), false);
    assert.deepEqual([(await row(bindingId, "m-re")).state, (await row(bindingId, "m-re")).lease_owner], ["sending", second.lease_owner]);
    // B completes under its own lease.
    await b.worker.process(second);
    assert.deepEqual([(await row(bindingId, "m-re")).state, (await row(bindingId, "m-re")).factory_message_id], ["delivered", "fm-1"]);
    assert.equal(injected, 1);
  });
});
