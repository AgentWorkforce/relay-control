import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { encryptSecret } from "../src/crypto.js";
import type { SqlExecutor, SqlResult } from "../src/database.js";
import { sweepDeviceRevocations } from "../src/messaging/device-credentials.js";
import { PGliteDatabase } from "./support/harness.js";

test("busy or aborted cleanup stays pending; retry revokes the current replacement binding", async (t) => {
  const database = new PGliteDatabase();
  t.after(() => database.close());
  const workspaceId = randomUUID(), userId = randomUUID(), rowId = randomUUID();
  const keyring = { active: { id: "cleanup-test", key: Buffer.alloc(32, 9) } };
  await database.exec(`
    CREATE TABLE workspaces (id uuid PRIMARY KEY, organization_id uuid,
      relaycast_workspace_id text, relaycast_api_key_ciphertext text);
    CREATE TABLE person_device_credentials (id uuid PRIMARY KEY, workspace_id uuid,
      user_id uuid, device_id text, agent_name text, relaycast_workspace_id text,
      revoked_at timestamptz, upstream_revoked_at timestamptz, updated_at timestamptz);
  `);
  await database.query("INSERT INTO workspaces VALUES ($1, $2, 'relay-workspace', $3)",
    [workspaceId, randomUUID(), encryptSecret("workspace-key", keyring.active)]);
  await database.query(`INSERT INTO person_device_credentials
    VALUES ($1, $2, $3, 'web', 'person', 'relay-workspace', now(), NULL, now())`,
  [rowId, workspaceId, userId]);

  let lockAvailable = false, abortOnLock: AbortController | null = null;
  let replaceOnLock = false;
  let lockAttempts = 0, revocations = 0;
  const transaction = database.transaction.bind(database);
  database.transaction = <T>(run: (tx: SqlExecutor) => Promise<T>) => transaction((tx) => run({
    exec: (sql) => tx.exec(sql),
    query: async <R extends Record<string, unknown>>(sql: string, params?: unknown[]): Promise<SqlResult<R>> => {
      assert.equal(/(?<!try_)pg_advisory_xact_lock/.test(sql), false, "cleanup must never take a blocking lock");
      if (sql.includes("pg_try_advisory_xact_lock")) {
        lockAttempts += 1;
        abortOnLock?.abort();
        if (replaceOnLock) {
          await tx.query(`UPDATE person_device_credentials SET agent_name = 'replacement-person',
            device_id = 'replacement-device', relaycast_workspace_id = 'replacement-workspace' WHERE id = $1`, [rowId]);
          await tx.query(`UPDATE workspaces SET relaycast_workspace_id = 'replacement-workspace',
            relaycast_api_key_ciphertext = $2 WHERE id = $1`,
          [workspaceId, encryptSecret("replacement-key", keyring.active)]);
        }
        return { rows: [{ acquired: lockAvailable } as unknown as R] };
      }
      return tx.query<R>(sql, params);
    },
  }));
  const deps = {
    database, keyring, relaycastUrl: "https://relay.invalid",
    fetchImpl: async (url: string | URL | Request, init?: RequestInit) => {
      revocations += 1;
      assert.equal(init?.method, "DELETE");
      assert.equal(String(url), "https://relay.invalid/v1/agents/replacement-person/device-tokens/replacement-device");
      assert.equal(new Headers(init?.headers).get("authorization"), "Bearer replacement-key");
      return new Response(null, { status: 204 });
    },
  };
  const pending = async () => (await database.query<{ pending: boolean }>(
    "SELECT upstream_revoked_at IS NULL AS pending FROM person_device_credentials WHERE id = $1", [rowId],
  )).rows[0]!.pending;

  await sweepDeviceRevocations(deps);
  assert.equal(lockAttempts, 1);
  assert.equal(revocations, 0);
  assert.equal(await pending(), true);

  const alreadyAborted = new AbortController();
  alreadyAborted.abort();
  await sweepDeviceRevocations(deps, undefined, { signal: alreadyAborted.signal });
  assert.equal(lockAttempts, 1);
  assert.equal(await pending(), true);

  lockAvailable = true;
  abortOnLock = new AbortController();
  await sweepDeviceRevocations(deps, undefined, { signal: abortOnLock.signal });
  assert.equal(lockAttempts, 2);
  assert.equal(revocations, 0);
  assert.equal(await pending(), true);

  abortOnLock = null;
  replaceOnLock = true;
  await sweepDeviceRevocations(deps);
  assert.equal(lockAttempts, 3);
  assert.equal(revocations, 1);
  assert.equal(await pending(), false);
});
