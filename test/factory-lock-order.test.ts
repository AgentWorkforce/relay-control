/**
 * §6.0 lock order: every Factory transaction locks the organization (or the
 * workspace advisory lock beneath it) first, then the workspace connection,
 * then binding rows. Recorded from the statements each path issues inside
 * its transaction; the real-PostgreSQL deadlock is in factory-setup-pg.
 */
import assert from "node:assert/strict";
import test from "node:test";
import type { SqlExecutor } from "../src/database.js";
import { liveDeliveryTargetInTx } from "../src/factory/store.js";
import {
  bindingRow, connectAndBind, FACTORY_KEY_2, factoryPath, removeMember, startFactoryEnv, type FactoryEnv,
} from "./factory-helpers.js";

type Level = "organization" | "workspace" | "connection" | "bindings";
const RANK: Record<Level, number> = { organization: 0, workspace: 1, connection: 2, bindings: 3 };
const TABLE: Record<string, Level> = {
  organizations: "organization",
  factory_connections: "connection",
  factory_bindings: "bindings",
};

/** The lock level a statement takes, if any (row locks and writes only). */
function lockLevel(sql: string): Level | null {
  const text = sql.replace(/\s+/g, " ");
  if (/pg_advisory_xact_lock\(hashtext\('factory-workspace'\)/.test(text)) return "workspace";
  const write = /^\s*(?:UPDATE|DELETE FROM|INSERT INTO) (\w+)/i.exec(text);
  if (write) return TABLE[write[1]!] ?? null;
  if (/\bFOR (?:UPDATE|SHARE)\b/i.test(text)) {
    const from = /\bFROM (\w+)/i.exec(text);
    return from ? TABLE[from[1]!] ?? null : null;
  }
  return null;
}

/** Records, per transaction, the order in which it first takes each lock level. */
function recordLocks(env: FactoryEnv) {
  const transactions: Level[][] = [];
  const database = env.database;
  const original = database.transaction.bind(database);
  database.transaction = (async <T>(run: (tx: SqlExecutor) => Promise<T>) => original(async (tx) => {
    const levels: Level[] = [];
    transactions.push(levels);
    return run({
      ...tx,
      query: async (sql: string, params?: unknown[]) => {
        const level = lockLevel(sql);
        // Only a level's first acquisition matters: a later write to a row
        // the transaction already locked takes no new lock.
        if (level && !levels.includes(level)) levels.push(level);
        return tx.query(sql, params);
      },
    } as SqlExecutor);
  })) as typeof database.transaction;
  return {
    reset: () => { transactions.length = 0; },
    /** Each factory transaction's lock levels never step back to a lower rank. */
    assertOrdered(label: string) {
      const relevant = transactions.filter((levels) => levels.some((level) => level !== "organization"));
      assert.ok(relevant.length > 0, `${label}: no factory lock recorded`);
      for (const levels of relevant) {
        for (let i = 1; i < levels.length; i++) {
          assert.ok(RANK[levels[i]!] >= RANK[levels[i - 1]!],
            `${label}: lock order ${levels.join(" -> ")} takes ${levels[i]} after ${levels[i - 1]}`);
        }
      }
    },
  };
}

test("factory lock order: disconnect locks organization, then connection, then bindings", async (t) => {
  const env = await startFactoryEnv(t);
  await connectAndBind(env);
  const locks = recordLocks(env);
  assert.equal((await env.api(factoryPath(env.workspaceId, "/connection"), { method: "DELETE", token: env.ownerToken })).status, 204);
  locks.assertOrdered("disconnect");
});

test("factory lock order: member removal locks organization, then connections, then bindings", async (t) => {
  const env = await startFactoryEnv(t);
  await connectAndBind(env, { token: env.adminToken });
  const locks = recordLocks(env);
  assert.equal((await removeMember(env, env.adminId)).status, 204);
  locks.assertOrdered("removal");
});

test("factory lock order: connect, replacement, bind and unbind keep the same order", async (t) => {
  const env = await startFactoryEnv(t);
  const locks = recordLocks(env);
  const bound = await connectAndBind(env);
  locks.assertOrdered("connect + bind");
  locks.reset();
  assert.equal((await env.api(factoryPath(env.workspaceId, "/connection"), { method: "PUT", token: env.ownerToken, body: { key: FACTORY_KEY_2 } })).status, 200);
  locks.assertOrdered("key replacement");
  locks.reset();
  assert.equal((await env.api(factoryPath(env.workspaceId, `/bindings/${bound.binding_id}`), { method: "DELETE", token: env.ownerToken })).status, 204);
  locks.assertOrdered("unbind");
});

test("factory lock order: the delivery fence locks organization, then connection, then binding", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await connectAndBind(env);
  const row = await bindingRow(env, bound.binding_id);
  const locks = recordLocks(env);
  const live = await env.database.transaction((tx) => liveDeliveryTargetInTx(tx, {
    id: row.id, organization_id: row.organization_id, workspace_id: row.workspace_id, user_id: row.user_id, generation: row.generation,
  }));
  assert.equal(live, true);
  locks.assertOrdered("delivery fence");
});
