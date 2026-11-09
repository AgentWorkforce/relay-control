/**
 * Setup snapshot fence (Cloud 9f813ff `requireSetupIdentity`): a connect or
 * bind whose provider call is held while the setup changes underneath it
 * must refuse its stale final write, never overwrite or resurrect.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { decryptSecret } from "../src/crypto.js";
import {
  bindingRow, connectAndBind, FACTORY_KEY, FACTORY_KEY_2, factoryPath, providerHold, startFactoryEnv, type FactoryEnv,
} from "./factory-helpers.js";

const FACTORY_KEY_3 = "fk_live_third_rotation_k03";

const put = (env: FactoryEnv, key: string, token = env.ownerToken) =>
  env.api(factoryPath(env.workspaceId, "/connection"), { method: "PUT", token, body: { key } });

async function storedKey(env: FactoryEnv): Promise<string | null> {
  const rows = await env.database.query<{ key_envelope: string }>(
    "SELECT key_envelope FROM factory_connections WHERE workspace_id = $1",
    [env.workspaceId],
  );
  return rows.rows[0] ? decryptSecret(rows.rows[0].key_envelope, env.config.encryptionKeyring) : null;
}

const CHANGED = { error: "factory_bindings_changed", message: "Factory changed while verification was running. Retry from current Settings." };

test("factory connect: a disconnect during the held session re-verification is not resurrected by the stale connect", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await connectAndBind(env);
  const held = providerHold();
  env.factory.holdSessionGet = held.hold;
  // Key replacement re-verifies the bound session; that provider call is held.
  const stale = put(env, FACTORY_KEY_2);
  await held.arrived;
  assert.equal((await env.api(factoryPath(env.workspaceId, "/connection"), { method: "DELETE", token: env.ownerToken })).status, 204);
  held.release();
  const refused = await stale;
  assert.equal(refused.status, 409, JSON.stringify(refused.body));
  assert.deepEqual(refused.body, CHANGED);
  assert.equal(await storedKey(env), null, "the disconnected connection stays deleted");
  assert.equal((await bindingRow(env, bound.binding_id)).state, "retired");
});

test("factory connect: a same-user key replacement during the held computers call is not overwritten by the stale connect", async (t) => {
  const env = await startFactoryEnv(t);
  await connectAndBind(env);
  const held = providerHold();
  env.factory.holdComputers = held.hold;
  // A same-key PUT (no re-verification) holds in its key check.
  const stale = put(env, FACTORY_KEY);
  await held.arrived;
  const replaced = await put(env, FACTORY_KEY_2);
  assert.equal(replaced.status, 200, JSON.stringify(replaced.body));
  held.release();
  const refused = await stale;
  assert.equal(refused.status, 409, JSON.stringify(refused.body));
  assert.deepEqual(refused.body, CHANGED);
  assert.equal(await storedKey(env), FACTORY_KEY_2, "the newer key is kept");
});

test("factory connect: a same-user key replacement during the held re-verification is not overwritten by the stale replacement", async (t) => {
  const env = await startFactoryEnv(t);
  env.factory.keys.add(FACTORY_KEY_3);
  await connectAndBind(env);
  const held = providerHold();
  env.factory.holdSessionGet = held.hold;
  const stale = put(env, FACTORY_KEY_2);
  await held.arrived;
  const replaced = await put(env, FACTORY_KEY_3);
  assert.equal(replaced.status, 200, JSON.stringify(replaced.body));
  held.release();
  const refused = await stale;
  assert.equal(refused.status, 409, JSON.stringify(refused.body));
  assert.deepEqual(refused.body, CHANGED);
  assert.equal(await storedKey(env), FACTORY_KEY_3, "the newer key is kept");
});

const bind = (env: FactoryEnv, sessionId = "sess-a") =>
  env.api(factoryPath(env.workspaceId, "/bindings"), { method: "POST", token: env.ownerToken, body: { session_id: sessionId, computer_id: "cmp-1" } });

test("factory bind: a key rotation during the held session check refuses the bind in its preparing transaction", async (t) => {
  const env = await startFactoryEnv(t);
  assert.equal((await put(env, FACTORY_KEY)).status, 200);
  const held = providerHold();
  env.factory.holdSessionGet = held.hold;
  const stale = bind(env);
  await held.arrived;
  assert.equal((await put(env, FACTORY_KEY_2)).status, 200);
  held.release();
  const refused = await stale;
  assert.equal(refused.status, 409, JSON.stringify(refused.body));
  assert.deepEqual(refused.body, CHANGED);
  const rows = await env.database.query("SELECT id FROM factory_bindings");
  assert.equal(rows.rows.length, 0, "no binding row is created");
  assert.equal(env.relay.registered, 0, "no Relay agent is registered");
});

test("factory bind: a key rotation between the preparing and the final transaction refuses the bind and releases its agent", async (t) => {
  let env!: FactoryEnv;
  let rotate = true;
  env = await startFactoryEnv(t, {
    hooks: {
      beforeFinalWrite: async (operation) => {
        if (operation !== "bind" || !rotate) return;
        rotate = false;
        assert.equal((await put(env, FACTORY_KEY_2)).status, 200);
      },
    },
  });
  assert.equal((await put(env, FACTORY_KEY)).status, 200);
  const refused = await bind(env);
  assert.equal(refused.status, 409, JSON.stringify(refused.body));
  assert.deepEqual(refused.body, CHANGED);
  const rows = await env.database.query<{ state: string }>("SELECT state FROM factory_bindings");
  assert.deepEqual(rows.rows.map((row) => row.state), ["retired"], "the preparing row is retired, never bound");
  assert.equal(env.relay.registered, 1);
  assert.equal(env.relay.released.length, 1, "the registered agent is released");
  assert.equal(await storedKey(env), FACTORY_KEY_2);
});
