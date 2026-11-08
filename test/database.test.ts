import assert from "node:assert/strict";
import test from "node:test";
import type pg from "pg";
import { PostgresDatabase } from "../src/database.js";

// A pool whose single client records statements and fails the ones named.
function stubPool(fail: Record<string, Error>) {
  const statements: string[] = [];
  let released = 0;
  const client = {
    async query(sql: string) {
      statements.push(sql);
      const error = fail[sql];
      if (error) throw error;
      return { rows: [] };
    },
    release() {
      released += 1;
    },
  };
  const pool = { connect: async () => client } as unknown as pg.Pool;
  return { pool, statements, released: () => released };
}

test("transaction: a failed ROLLBACK does not mask the original error", async () => {
  const rollbackError = new Error("Connection terminated");
  const stub = stubPool({ ROLLBACK: rollbackError });
  const database = new PostgresDatabase(stub.pool);
  const original = new Error("body failed");

  await assert.rejects(database.transaction(async () => { throw original; }), (error) => {
    assert.equal(error, original);
    assert.equal((error as { rollbackError?: unknown }).rollbackError, rollbackError);
    return true;
  });
  assert.deepEqual(stub.statements, ["BEGIN", "ROLLBACK"]);
  assert.equal(stub.released(), 1);
});

test("transaction: a COMMIT error survives a failed ROLLBACK with its SQLSTATE", async () => {
  const commitError = Object.assign(new Error("terminating connection due to administrator command"), { code: "57P01" });
  const stub = stubPool({ COMMIT: commitError, ROLLBACK: new Error("Client has encountered a connection error") });
  const database = new PostgresDatabase(stub.pool);

  await assert.rejects(database.transaction(async () => "done"), (error) => {
    assert.equal(error, commitError);
    assert.equal((error as { code?: string }).code, "57P01");
    return true;
  });
  assert.deepEqual(stub.statements, ["BEGIN", "COMMIT", "ROLLBACK"]);
  assert.equal(stub.released(), 1);
});

test("transaction: a successful ROLLBACK rethrows the original error unchanged", async () => {
  const stub = stubPool({});
  const database = new PostgresDatabase(stub.pool);
  const original = new Error("body failed");

  await assert.rejects(database.transaction(async () => { throw original; }), (error) => {
    assert.equal(error, original);
    assert.equal(Object.hasOwn(error as object, "rollbackError"), false);
    return true;
  });
  assert.deepEqual(stub.statements, ["BEGIN", "ROLLBACK"]);
});
