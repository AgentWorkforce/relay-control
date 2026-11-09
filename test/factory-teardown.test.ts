import assert from "node:assert/strict";
import test from "node:test";
import { cleanupWorkspaceFactory } from "../src/factory/routes.js";
import { ControlPlaneStore } from "../src/store.js";
import { BOOTSTRAP } from "./flows-helpers.js";
import {
  bindingRow,
  connectAndBind,
  deliveryRows,
  FACTORY_KEY,
  FACTORY_KEY_2,
  factoryPath,
  replyPath,
  seedDelivery,
  startFactoryEnv,
  type FactoryEnv,
} from "./factory-helpers.js";

const removeMember = (env: FactoryEnv, userId: string) =>
  env.api(`/api/v1/organizations/${env.organizationId}/memberships/${userId}`, { method: "DELETE", token: env.ownerToken });

async function assertSecretFree(env: FactoryEnv, bindingId: string) {
  const row = await bindingRow(env, bindingId);
  assert.equal(row.state, "retired");
  assert.equal(row.hosted_token_envelope, null);
  assert.equal(row.hook_secret_envelope, null);
  assert.equal(row.helper_secret_envelope, null);
  for (const delivery of await deliveryRows(env, bindingId)) {
    assert.equal(delivery.payload_envelope, null, `payload of ${delivery.message_id}`);
    assert.equal(delivery.reply_hash, null, `reply hash of ${delivery.message_id}`);
    assert.equal(delivery.reply_expires_at, null);
  }
}

test("factory local unbind and disconnect clear payload ciphertext and reply bearers, and settle the outbox (6168 req 4)", async (t) => {
  const env = await startFactoryEnv(t);
  const first = await connectAndBind(env);
  const second = await env.api(factoryPath(env.workspaceId, "/bindings"), {
    method: "POST", token: env.ownerToken, body: { session_id: "sess-b", computer_id: "cmp-1" },
  });
  const seeded = [];
  for (const id of [first.binding_id, second.body.binding_id]) {
    for (const state of ["pending", "sending", "delivered"] as const) seeded.push({ id, state, ...(await seedDelivery(env, id, { state })) });
  }
  assert.equal((await env.api(factoryPath(env.workspaceId, `/bindings/${first.binding_id}`), { method: "DELETE", token: env.ownerToken })).status, 204);
  await assertSecretFree(env, first.binding_id);
  // The sibling binding is untouched until disconnect.
  assert.ok((await deliveryRows(env, second.body.binding_id)).every((row) => row.payload_envelope && row.reply_hash));
  assert.equal((await env.api(factoryPath(env.workspaceId, "/connection"), { method: "DELETE", token: env.ownerToken })).status, 204);
  await assertSecretFree(env, second.body.binding_id);

  const states = Object.fromEntries((await deliveryRows(env, first.binding_id)).map((row) => [row.state, row.code]));
  assert.deepEqual(states, { rejected: "binding_retired", unknown: "binding_retired", delivered: null });
  // Every previously valid bearer is now dead.
  for (const row of seeded) {
    const refused = await env.api(replyPath(row.id), { method: "POST", token: row.bearer, body: { text: "late" } });
    assert.equal(refused.status, 409);
  }
  assert.equal(env.relay.replies.length, 0);
});

test("factory member removal purges bindings, key and bearers inside the removal transaction", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await connectAndBind(env, { token: env.adminToken });
  const { bearer } = await seedDelivery(env, bound.binding_id, { state: "sending" });

  // A purge failure aborts the removal: both live in one transaction.
  const store = new ControlPlaneStore(env.database, env.config.encryptionKeyring, 0);
  await assert.rejects(store.deleteMembership(env.organizationId, env.adminId, async (tx) => {
    await env.module.purgeMemberInTx(tx, env.organizationId, env.adminId);
    throw new Error("abort after purge");
  }), /abort after purge/);
  assert.equal((await bindingRow(env, bound.binding_id)).state, "bound");
  assert.equal((await env.database.query("SELECT 1 FROM factory_connections")).rows.length, 1);
  assert.equal((await env.database.query("SELECT 1 FROM organization_memberships WHERE user_id = $1", [env.adminId])).rows.length, 1);

  // Authorized acceptance: the org owner removes the admin.
  const removed = await removeMember(env, env.adminId);
  assert.equal(removed.status, 204);
  await assertSecretFree(env, bound.binding_id);
  assert.equal((await env.database.query("SELECT 1 FROM factory_connections")).rows.length, 0);
  // Removal deletes the departed member's outbox rows outright (Cloud a749e46c).
  assert.deepEqual(await deliveryRows(env, bound.binding_id), []);
  assert.deepEqual(env.relay.released, [bound.agent.id]);
  assert.equal((await bindingRow(env, bound.binding_id)).relay_agent_id, null);
  assert.equal((await env.api(replyPath(bound.binding_id), { method: "POST", token: bearer, body: { text: "x" } })).status, 409);
  const audit = await env.database.query<{ action: string; target: string }>(
    "SELECT action, target FROM admin_audit_events WHERE action = 'factory.member.purge'",
  );
  assert.deepEqual(audit.rows, [{ action: "factory.member.purge", target: "bindings:1;connections:1" }]);
});

test("factory successor connects and rebinds the same session after the former owner retired (6168 req 1)", async (t) => {
  const env = await startFactoryEnv(t);
  // Former owner: bound, then removed from the org (rows retired, not deleted).
  const former = await connectAndBind(env, { token: env.adminToken });
  assert.equal((await removeMember(env, env.adminId)).status, 204);
  assert.equal((await bindingRow(env, former.binding_id)).state, "retired");

  // The successor (org owner) connects with a different key and binds the same session.
  const successor = await connectAndBind(env, { key: FACTORY_KEY_2, sessionId: "sess-a" });
  assert.notEqual(successor.binding_id, former.binding_id);
  assert.equal((await bindingRow(env, successor.binding_id)).state, "bound");
  assert.equal((await bindingRow(env, former.binding_id)).state, "retired");

  // Same after a plain unbind + disconnect by an owner who is still a member.
  assert.equal((await env.api(factoryPath(env.workspaceId, "/connection"), { method: "DELETE", token: env.ownerToken })).status, 204);
  const admin2 = await env.api(`/api/v1/organizations/${env.organizationId}/memberships`, {
    method: "POST", token: BOOTSTRAP, body: { email: "admin2@acme.test", name: "admin2", role: "admin" },
  });
  const admin2Token = await env.login(admin2.body.userId, env.workspaceId);
  const third = await connectAndBind(env, { token: admin2Token, sessionId: "sess-a" });
  assert.equal((await bindingRow(env, third.binding_id)).state, "bound");
  const retired = await env.database.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM factory_bindings WHERE session_id = 'sess-a' AND state = 'retired'",
  );
  assert.equal(retired.rows[0]!.n, 2);
});

test("factory membership removal racing a final bind write wins and leaves no live binding (6168 req 3)", async (t) => {
  let race: (() => Promise<void>) | null = null;
  const env = await startFactoryEnv(t, {
    hooks: { beforeFinalWrite: async (operation) => { if (operation === "bind" && race) await race(); } },
  });
  await env.api(factoryPath(env.workspaceId, "/connection"), { method: "PUT", token: env.adminToken, body: { key: FACTORY_KEY } });
  race = async () => {
    race = null;
    assert.equal((await removeMember(env, env.adminId)).status, 204);
  };
  const late = await env.api(factoryPath(env.workspaceId, "/bindings"), {
    method: "POST", token: env.adminToken, body: { session_id: "sess-a", computer_id: "cmp-1" },
  });
  assert.equal(late.status, 403);
  assert.equal(late.body.error, "factory_access_revoked");
  const rows = await env.database.query<{ id: string; state: string; relay_agent_id: string | null }>(
    "SELECT id, state, relay_agent_id FROM factory_bindings",
  );
  assert.deepEqual(rows.rows.map((row) => [row.state, row.relay_agent_id]), [["retired", null]]);
  await assertSecretFree(env, rows.rows[0]!.id);
  assert.equal(env.relay.agents.size, 0, "the late registration is released");
  assert.equal(env.relay.released.length, 1);
});

test("factory membership removal racing a final connect write wins and stores no key (6168 req 3)", async (t) => {
  let race: (() => Promise<void>) | null = null;
  const env = await startFactoryEnv(t, {
    hooks: { beforeFinalWrite: async (operation) => { if (operation === "connect" && race) await race(); } },
  });
  race = async () => {
    race = null;
    assert.equal((await removeMember(env, env.adminId)).status, 204);
  };
  const late = await env.api(factoryPath(env.workspaceId, "/connection"), { method: "PUT", token: env.adminToken, body: { key: FACTORY_KEY } });
  assert.equal(late.status, 403);
  assert.equal(late.body.error, "factory_access_revoked");
  assert.equal((await env.database.query("SELECT 1 FROM factory_connections")).rows.length, 0);
});

test("factory workspace cleanup removes every local row and releases remote agents with the captured key", async (t) => {
  const env = await startFactoryEnv(t);
  const here = await connectAndBind(env);
  await seedDelivery(env, here.binding_id);
  await env.api(factoryPath(env.workspaceId, `/bindings/${here.binding_id}/history/schedule`), { method: "POST", token: env.ownerToken });
  const elsewhere = await connectAndBind(env, { token: env.ownerOtherToken, workspaceId: env.otherWorkspaceId, sessionId: "sess-b" });

  const { releases } = await env.database.transaction((tx) => cleanupWorkspaceFactory(tx, env.workspaceId));
  assert.deepEqual(releases.map((row) => row.relay_agent_id), [here.agent.id]);
  for (const table of ["connections", "bindings", "deliveries", "history_syncs"]) {
    const rows = await env.database.query(`SELECT 1 FROM factory_${table} WHERE workspace_id = $1`, [env.workspaceId]);
    assert.equal(rows.rows.length, 0, table);
  }
  // The RESTRICT foreign keys no longer block deleting the workspace.
  await env.database.query("DELETE FROM workspaces WHERE id = $1", [env.workspaceId]);
  assert.equal(await env.module.afterWorkspaceDeleted("rk_live_primary", releases), 0);
  assert.deepEqual(env.relay.released, [here.agent.id]);
  // The other workspace is untouched.
  assert.equal((await bindingRow(env, elsewhere.binding_id)).state, "bound");
  assert.ok(env.relay.agents.has(elsewhere.agent.name));
});

test("factory workspace cleanup is required: Factory rows block a bare workspace delete", async (t) => {
  const env = await startFactoryEnv(t);
  await connectAndBind(env);
  await assert.rejects(env.database.query("DELETE FROM workspaces WHERE id = $1", [env.workspaceId]), /foreign key/);
});

const addAdmin = async (env: FactoryEnv, email: string, role: "admin" | "member" = "admin") => {
  const member = await env.api(`/api/v1/organizations/${env.organizationId}/memberships`, {
    method: "POST", token: BOOTSTRAP, body: { email, name: email, role },
  });
  assert.equal(member.status, 200);
  return { userId: member.body.userId as string, token: await env.login(member.body.userId, env.workspaceId) };
};

/** Alice (admin) binds sess-a and is removed with cleanup pending; Bob (owner) connects and binds sess-b; Alice rejoins. */
async function rejoinedFormerOwner(env: FactoryEnv, role: "admin" | "member" = "admin") {
  env.relay.failRelease = true; // Keep Alice's retired row holding its remote agent (cleanup pending).
  const alice = await connectAndBind(env, { token: env.adminToken, sessionId: "sess-a" });
  assert.equal((await removeMember(env, env.adminId)).status, 204);
  const aliceRow = await bindingRow(env, alice.binding_id);
  assert.deepEqual([aliceRow.state, aliceRow.relay_agent_id], ["retired", alice.agent.id]);
  // Alice's retired row reserves only sess-a; it does not block Bob's fresh connection.
  const bob = await connectAndBind(env, { key: FACTORY_KEY, sessionId: "sess-b" });
  const rejoined = await addAdmin(env, "admin@acme.test", role);
  assert.equal(rejoined.userId, env.adminId);
  return { alice, aliceRow, bob, aliceToken: rejoined.token };
}

const connectionRow = async (env: FactoryEnv) =>
  (await env.database.query<Record<string, unknown>>("SELECT * FROM factory_connections")).rows;

test("factory current owner manages own connection after a removed member rejoins; rejoined member gains no authority over the old session (Cloud 9f813ff)", async (t) => {
  const env = await startFactoryEnv(t);
  const { alice, aliceRow, bob, aliceToken } = await rejoinedFormerOwner(env);
  const connection = factoryPath(env.workspaceId, "/connection");
  const unbind = (token: string, id: string) => env.api(factoryPath(env.workspaceId, `/bindings/${id}`), { method: "DELETE", token });

  // The rejoined former owner cannot borrow admission or manage anything.
  assert.equal((await env.api(connection, { method: "PUT", token: aliceToken, body: { key: FACTORY_KEY } })).status, 409);
  assert.equal((await unbind(aliceToken, alice.binding_id)).body.error, "factory_not_owner");
  assert.equal((await unbind(aliceToken, bob.binding_id)).status, 403);
  assert.equal((await env.api(connection, { method: "DELETE", token: aliceToken })).status, 403);
  assert.equal((await env.api(factoryPath(env.workspaceId, "/computers"), { token: aliceToken })).status, 403);
  const rebind = await env.api(factoryPath(env.workspaceId, "/bindings"), {
    method: "POST", token: aliceToken, body: { session_id: "sess-a", computer_id: "cmp-1" },
  });
  assert.equal(rebind.status, 403);
  assert.equal((await env.api(factoryPath(env.workspaceId, `/bindings/${alice.binding_id}/history/schedule`), { method: "POST", token: aliceToken })).status, 409);
  // The current owner cannot take Alice's old row either.
  assert.equal((await unbind(env.ownerToken, alice.binding_id)).status, 403);

  // The admitted owner replaces their own key despite the foreign retired row.
  const rotated = await env.api(connection, { method: "PUT", token: env.ownerToken, body: { key: FACTORY_KEY_2 } });
  assert.equal(rotated.status, 200, JSON.stringify(rotated.body));
  assert.equal(rotated.body.user_is_owner, true);
  const [owned] = await connectionRow(env);
  assert.deepEqual([owned!.user_id, owned!.key_hint], [env.ownerId, `…${FACTORY_KEY_2.slice(-4)}`]);
  // The old session id stays cleanup-only, even for the current owner.
  const early = await env.api(factoryPath(env.workspaceId, "/bindings"), {
    method: "POST", token: env.ownerToken, body: { session_id: "sess-a", computer_id: "cmp-1" },
  });
  assert.deepEqual([early.status, early.body.error], [409, "factory_cleanup_pending"]);

  // A current connection protects its owner even with no live bindings.
  assert.equal((await unbind(env.ownerToken, bob.binding_id)).status, 204);
  const charlie = await addAdmin(env, "charlie@acme.test");
  assert.equal((await env.api(connection, { method: "PUT", token: charlie.token, body: { key: FACTORY_KEY } })).status, 409);
  assert.equal((await env.api(connection, { method: "DELETE", token: charlie.token })).status, 403);
  assert.deepEqual(await connectionRow(env), [owned]);

  // The owner's disconnect retires only their own rows; Alice's cleanup row is untouched.
  assert.equal((await env.api(connection, { method: "DELETE", token: env.ownerToken })).status, 204);
  assert.deepEqual(await connectionRow(env), []);
  const untouched = await bindingRow(env, alice.binding_id);
  assert.deepEqual(
    [untouched.state, untouched.generation, untouched.relay_agent_id, untouched.user_id],
    ["retired", aliceRow.generation, alice.agent.id, env.adminId],
  );
  assert.ok(env.relay.agents.has(alice.agent.name), "the old remote agent was not released by anyone's manage action");
  assert.equal((await env.database.query("SELECT 1 FROM factory_history_syncs")).rows.length, 0);

  // Verified cleanup then frees the old session id.
  env.relay.failRelease = false;
  assert.equal(await env.module.worker.cleanup(), 0);
  assert.ok(env.relay.released.includes(alice.agent.id));
  const after = await connectAndBind(env, { sessionId: "sess-a" });
  assert.equal((await bindingRow(env, after.binding_id)).state, "bound");
});

for (const state of ["bound", "preparing"] as const) {
  test(`factory foreign ${state} binding still blocks the current connection owner after a rejoin, and a fresh connect without a connection (Cloud 9f813ff)`, async (t) => {
    const env = await startFactoryEnv(t);
    const { alice, bob } = await rejoinedFormerOwner(env);
    await env.database.query("UPDATE factory_bindings SET state = $2 WHERE id = $1", [alice.binding_id, state]);
    const before = await connectionRow(env);
    const connection = factoryPath(env.workspaceId, "/connection");
    assert.equal((await env.api(connection, { method: "PUT", token: env.ownerToken, body: { key: FACTORY_KEY_2 } })).status, 409);
    assert.equal((await env.api(factoryPath(env.workspaceId, `/bindings/${bob.binding_id}`), { method: "DELETE", token: env.ownerToken })).status, 403);
    assert.equal((await env.api(connection, { method: "DELETE", token: env.ownerToken })).status, 403);
    assert.deepEqual(await connectionRow(env), before);
    assert.equal((await bindingRow(env, bob.binding_id)).state, "bound");
    const row = await bindingRow(env, alice.binding_id);
    assert.deepEqual([row.state, row.user_id, row.relay_agent_id], [state, env.adminId, alice.agent.id]);

    // With no connection at all, the foreign live row alone still refuses a fresh connect.
    await env.database.query("DELETE FROM factory_connections");
    const fresh = await env.api(connection, { method: "PUT", token: env.ownerToken, body: { key: FACTORY_KEY_2 } });
    assert.deepEqual([fresh.status, fresh.body.error], [409, "factory_other_member_bindings"]);
    assert.deepEqual(await connectionRow(env), []);
  });
}

test("factory current personal connection with zero binding rows still refuses a different admin (Cloud 9f813ff)", async (t) => {
  const env = await startFactoryEnv(t);
  const connection = factoryPath(env.workspaceId, "/connection");
  assert.equal((await env.api(connection, { method: "PUT", token: env.ownerToken, body: { key: FACTORY_KEY } })).status, 200);
  assert.equal((await env.database.query("SELECT 1 FROM factory_bindings")).rows.length, 0);
  const before = await connectionRow(env);

  const takeover = await env.api(connection, { method: "PUT", token: env.adminToken, body: { key: FACTORY_KEY_2 } });
  assert.deepEqual([takeover.status, takeover.body.error], [409, "factory_other_member_bindings"]);
  const bound = await env.api(factoryPath(env.workspaceId, "/bindings"), {
    method: "POST", token: env.adminToken, body: { session_id: "sess-a", computer_id: "cmp-1" },
  });
  assert.deepEqual([bound.status, bound.body.error], [403, "factory_not_owner"]);
  assert.deepEqual([(await env.api(connection, { method: "DELETE", token: env.adminToken })).body.error], ["factory_not_owner"]);
  assert.deepEqual(await connectionRow(env), before);
  assert.equal((await env.database.query("SELECT 1 FROM factory_bindings")).rows.length, 0);
});

test("factory A removed, B connects, A rejoins as member, B disconnects and reconnects without touching A's cleanup rows (Cloud 9f813ff)", async (t) => {
  const env = await startFactoryEnv(t);
  const { alice, aliceRow, bob, aliceToken } = await rejoinedFormerOwner(env, "member");
  const connection = factoryPath(env.workspaceId, "/connection");
  const bindings = factoryPath(env.workspaceId, "/bindings");

  assert.equal((await env.api(connection, { method: "DELETE", token: env.ownerToken })).status, 204);
  assert.deepEqual(await connectionRow(env), []);
  assert.equal((await bindingRow(env, bob.binding_id)).state, "retired");

  const reconnected = await env.api(connection, { method: "PUT", token: env.ownerToken, body: { key: FACTORY_KEY_2 } });
  assert.equal(reconnected.status, 200, JSON.stringify(reconnected.body));
  assert.equal(reconnected.body.user_is_owner, true);
  // A's old session id stays reserved; A's row is neither B's to unbind nor A's (now a plain member).
  const early = await env.api(bindings, { method: "POST", token: env.ownerToken, body: { session_id: "sess-a", computer_id: "cmp-1" } });
  assert.deepEqual([early.status, early.body.error], [409, "factory_cleanup_pending"]);
  assert.equal((await env.api(`${bindings}/${alice.binding_id}`, { method: "DELETE", token: env.ownerToken })).status, 403);
  assert.equal((await env.api(`${bindings}/${alice.binding_id}`, { method: "DELETE", token: aliceToken })).status, 403);
  const own = await env.api(bindings, { method: "POST", token: env.ownerToken, body: { session_id: "sess-c", computer_id: "cmp-2" } });
  assert.equal(own.status, 201, JSON.stringify(own.body));
  assert.equal((await env.api(connection, { method: "DELETE", token: env.ownerToken })).status, 204);

  const untouched = await bindingRow(env, alice.binding_id);
  assert.deepEqual(
    [untouched.state, untouched.generation, untouched.relay_agent_id, untouched.user_id, untouched.remote_cleanup_code],
    ["retired", aliceRow.generation, alice.agent.id, env.adminId, aliceRow.remote_cleanup_code],
  );
  assert.ok(env.relay.agents.has(alice.agent.name), "A's old remote agent was not released by B's actions");
  assert.ok(!env.relay.released.includes(alice.agent.id));
});

test("factory retired cleanup-pending row of a current member reserves only its session id, never a fresh connection (Cloud 9f813ff)", async (t) => {
  const env = await startFactoryEnv(t);
  const connection = factoryPath(env.workspaceId, "/connection");
  const bindings = factoryPath(env.workspaceId, "/bindings");
  // The admin (still a member) binds sess-a, then disconnects with the remote release failing.
  const old = await connectAndBind(env, { token: env.adminToken, sessionId: "sess-a" });
  env.relay.failRelease = true;
  assert.equal((await env.api(connection, { method: "DELETE", token: env.adminToken })).status, 204);
  const oldRow = await bindingRow(env, old.binding_id);
  assert.deepEqual([oldRow.state, oldRow.relay_agent_id, oldRow.user_id], ["retired", old.agent.id, env.adminId]);
  assert.deepEqual(await connectionRow(env), []);

  // Another admin connects fresh and binds an unrelated session.
  const fresh = await env.api(connection, { method: "PUT", token: env.ownerToken, body: { key: FACTORY_KEY_2 } });
  assert.equal(fresh.status, 200, JSON.stringify(fresh.body));
  const unrelated = await env.api(bindings, { method: "POST", token: env.ownerToken, body: { session_id: "sess-b", computer_id: "cmp-1" } });
  assert.equal(unrelated.status, 201, JSON.stringify(unrelated.body));
  // The old session id stays reserved until cleanup releases it.
  const reserved = await env.api(bindings, { method: "POST", token: env.ownerToken, body: { session_id: "sess-a", computer_id: "cmp-1" } });
  assert.deepEqual([reserved.status, reserved.body.error], [409, "factory_cleanup_pending"]);
  assert.equal((await env.api(`${bindings}/${old.binding_id}`, { method: "DELETE", token: env.ownerToken })).status, 403);
  // The former connection owner cannot take the connection back.
  assert.equal((await env.api(connection, { method: "PUT", token: env.adminToken, body: { key: FACTORY_KEY } })).status, 409);

  env.relay.failRelease = false;
  assert.equal(await env.module.worker.cleanup(), 0);
  assert.ok(env.relay.released.includes(old.agent.id));
  const freed = await env.api(bindings, { method: "POST", token: env.ownerToken, body: { session_id: "sess-a", computer_id: "cmp-1" } });
  assert.equal(freed.status, 201, JSON.stringify(freed.body));
});

test("factory role demotion racing a final bind write is fenced inside the commit transaction (a749e46c fix 3)", async (t) => {
  let race: (() => Promise<void>) | null = null;
  const env = await startFactoryEnv(t, {
    hooks: { beforeFinalWrite: async (operation) => { if (operation === "bind" && race) await race(); } },
  });
  assert.equal((await env.api(factoryPath(env.workspaceId, "/connection"), { method: "PUT", token: env.adminToken, body: { key: FACTORY_KEY } })).status, 200);
  race = async () => {
    race = null;
    const demoted = await env.api(`/api/v1/organizations/${env.organizationId}/memberships`, {
      method: "POST", token: BOOTSTRAP, body: { email: "admin@acme.test", name: "admin", role: "member" },
    });
    assert.equal(demoted.status, 200);
  };
  const late = await env.api(factoryPath(env.workspaceId, "/bindings"), {
    method: "POST", token: env.adminToken, body: { session_id: "sess-a", computer_id: "cmp-1" },
  });
  assert.equal(late.status, 403);
  assert.equal(late.body.error, "factory_access_revoked");
  const rows = await env.database.query<{ state: string }>("SELECT state FROM factory_bindings");
  assert.deepEqual(rows.rows.map((row) => row.state), ["retired"]);
  assert.equal(env.relay.agents.size, 0, "the late registration is released");
});
