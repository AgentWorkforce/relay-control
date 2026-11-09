/**
 * Factory setup concurrency on real PostgreSQL: first-connect admission and
 * the org -> workspace -> connection -> bindings lock order. PGlite is
 * single-connection (its transactions never overlap), so neither is provable
 * there.
 *
 * Opt-in: set FACTORY_PG_TEST_URL to a PostgreSQL 16 server URL whose role
 * may CREATE DATABASE (same convention as test/factory-worker-pg.test.ts).
 * Each test creates a dedicated `factory_race_<random>` database, migrates
 * it, and drops it at the end.
 */
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import test, { type TestContext } from "node:test";
import pg from "pg";
import { decryptSecret, encryptSecret, type EncryptionKeyring } from "../src/crypto.js";
import { PostgresDatabase } from "../src/database.js";
import type { RelaycastClient } from "../src/messaging/relaycast.js";
import type { FactoryRuntime } from "../src/factory/runtime.js";
import { createFactoryService, type FactoryAccess, type FactoryServiceDeps } from "../src/factory/service.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";

const baseUrl = process.env.FACTORY_PG_TEST_URL;
const skip = baseUrl ? false : "FACTORY_PG_TEST_URL is unset (opt-in real-PostgreSQL setup concurrency test)";

const keyring: EncryptionKeyring = { active: { id: "pg-setup", key: Buffer.alloc(32, 7) } };

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

async function within<T>(promise: Promise<T>, label: string, ms = 10_000): Promise<T> {
  let timer!: NodeJS.Timeout;
  try {
    return await Promise.race([promise, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`timed out: ${label}`)), ms);
    })]);
  } finally {
    clearTimeout(timer);
  }
}

async function raceDatabase(t: TestContext) {
  const admin = new pg.Client({ connectionString: baseUrl });
  await admin.connect();
  const dbName = `factory_race_${randomBytes(6).toString("hex")}`;
  await admin.query(`CREATE DATABASE ${dbName}`);
  const url = new URL(baseUrl!);
  url.pathname = `/${dbName}`;
  const databases: PostgresDatabase[] = [];
  t.after(async () => {
    for (const database of databases) await database.close().catch(() => undefined);
    // pg-pool's end() resolves before the server-side backends exit; dropping
    // WITH (FORCE) while they close terminates a socket nothing listens on.
    for (let attempt = 0; attempt < 100; attempt++) {
      const open = await admin.query<{ n: string }>(
        "SELECT count(*)::text AS n FROM pg_stat_activity WHERE datname = $1", [dbName]);
      if (open.rows[0]!.n === "0") break;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
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

  const orgId = randomUUID();
  const ownerId = randomUUID();
  const adminId = randomUUID();
  const workspaceId = randomUUID();
  await setup.query("INSERT INTO organizations (id, name) VALUES ($1, 'Race')", [orgId]);
  for (const [id, role] of [[ownerId, "owner"], [adminId, "admin"]] as const) {
    await setup.query("INSERT INTO users (id, email, name) VALUES ($1, $2, $3)", [id, `${role}@race.test`, role]);
    await setup.query("INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, $3)", [orgId, id, role]);
  }
  await setup.query(
    `INSERT INTO workspaces (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
     VALUES ($1, $2, 'race', 'rc-race', $3)`,
    [workspaceId, orgId, encryptSecret("rk_live_race", keyring.active)],
  );

  /** Backends of this database currently waiting on a heavyweight lock. */
  const lockWaiters = async () => Number((await admin.query<{ n: string }>(
    "SELECT count(*)::text AS n FROM pg_stat_activity WHERE datname = $1 AND wait_event_type = 'Lock'",
    [dbName],
  )).rows[0]!.n);

  const runtime = {
    listComputers: async () => [{ id: "cmp-1", name: "c1" }],
    getSession: async () => ({}),
  } as unknown as FactoryRuntime;
  const relaycast = { releaseHosted: async () => undefined } as unknown as RelaycastClient;
  const service = (hooks: Pick<FactoryServiceDeps, "afterLock"> = {}) => createFactoryService({
    database: open(), keyring, runtime, relaycast, log: () => undefined, ...hooks,
  });
  const access = (userId: string): FactoryAccess => ({
    principal: { userId },
    workspace: { id: workspaceId, organizationId: orgId, relaycastApiKey: "rk_live_race" },
  });
  return { setup, open, orgId, ownerId, adminId, workspaceId, lockWaiters, service, access };
}

/** Waits until some backend waits on a lock, or `settled` resolves first. */
async function untilBlockedOrSettled(lockWaiters: () => Promise<number>, settled: Promise<unknown>) {
  let done = false;
  void settled.finally(() => { done = true; }).catch(() => undefined);
  await within((async () => {
    while (!done && await lockWaiters() === 0) await new Promise((resolve) => setTimeout(resolve, 20));
  })(), "waiting for the second transaction to block on a lock");
}

test("factory connect on real PostgreSQL: two first connects on an absent row are serialized; exactly one wins", { skip }, async (t) => {
  const env = await raceDatabase(t);
  const held = deferred();
  const arrived = deferred();
  const first = env.service({
    afterLock: async (operation) => {
      if (operation !== "connect") return;
      arrived.resolve();
      await held.promise;
    },
  });
  const second = env.service();

  const a = first.connect(env.access(env.ownerId), "fk_live_owner_first_k001").then(() => 200, (error) => error);
  await within(arrived.promise, "first connect reaching its write");
  const b = second.connect(env.access(env.adminId), "fk_live_admin_second_k02").then(() => 200, (error) => error);
  // With admission serialized, the second connect waits on the workspace
  // lock while the first holds it; without it the second commits here.
  await untilBlockedOrSettled(env.lockWaiters, b);
  held.resolve();
  const outcomes = await within(Promise.all([a, b]), "both connects settling");

  assert.equal(outcomes[0], 200, `first connect: ${String(outcomes[0])}`);
  const refused = outcomes[1] as { status?: number; code?: string; message?: string };
  assert.equal(refused.status, 409, `second connect must be refused, got ${String(outcomes[1])}`);
  assert.equal(refused.code, "factory_bindings_changed");
  assert.equal(refused.message, "Factory changed while verification was running. Retry from current Settings.");
  const rows = (await env.setup.query<{ user_id: string; key_envelope: string }>(
    "SELECT user_id, key_envelope FROM factory_connections WHERE workspace_id = $1",
    [env.workspaceId],
  )).rows;
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.user_id, env.ownerId, "the winner's connection is kept");
  assert.equal(decryptSecret(rows[0]!.key_envelope, keyring), "fk_live_owner_first_k001");
});

test("factory lock order on real PostgreSQL: a disconnect racing the member's removal does not deadlock", { skip }, async (t) => {
  const env = await raceDatabase(t);
  // The admin owns the connection and a bound session.
  await env.setup.query(
    `INSERT INTO factory_connections (workspace_id, organization_id, user_id, key_envelope, key_hint, validated_at)
     VALUES ($1, $2, $3, $4, '…k001', now())`,
    [env.workspaceId, env.orgId, env.adminId, encryptSecret("fk_live_admin_owned_k001", keyring.active)],
  );
  await env.setup.query(
    `INSERT INTO factory_bindings
       (id, workspace_id, organization_id, user_id, session_id, computer_id, state, generation,
        relay_agent_name, relay_agent_id, hosted_token_envelope)
     VALUES ($1, $2, $3, $4, 'sess-a', 'cmp-1', 'bound', 1, 'factory-sess-a', 'ag-sess-a', $5)`,
    [randomUUID(), env.workspaceId, env.orgId, env.adminId, encryptSecret("at_sess_a", keyring.active)],
  );
  const held = deferred();
  const arrived = deferred();
  const disconnecting = env.service({
    afterLock: async (operation) => {
      if (operation !== "disconnect") return;
      arrived.resolve();
      await held.promise;
    },
  });
  const remover = env.service();
  const store = new ControlPlaneStore(env.open(), keyring);

  const a = disconnecting.disconnect(env.access(env.adminId)).then(() => "ok", (error) => error);
  await within(arrived.promise, "disconnect holding its locks");
  const b = store.deleteMembership(env.orgId, env.adminId, (tx) => remover.purgeMemberInTx(tx, env.orgId, env.adminId))
    .then((deleted) => deleted ? "ok" : "not deleted", (error) => error);
  await untilBlockedOrSettled(env.lockWaiters, b);
  held.resolve();
  const outcomes = await within(Promise.all([a, b]), "disconnect and removal settling");

  for (const [label, outcome] of [["disconnect", outcomes[0]], ["removal", outcomes[1]]] as const) {
    assert.equal(outcome, "ok", `${label}: ${(outcome as { code?: string }).code ?? ""} ${String(outcome)}`);
  }
  const left = await env.setup.query<{ n: string }>(
    "SELECT count(*)::text AS n FROM factory_connections WHERE workspace_id = $1", [env.workspaceId]);
  assert.equal(left.rows[0]!.n, "0");
  const live = await env.setup.query<{ n: string }>(
    "SELECT count(*)::text AS n FROM factory_bindings WHERE state <> 'retired'");
  assert.equal(live.rows[0]!.n, "0");
});
