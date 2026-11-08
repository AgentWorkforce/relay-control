import assert from "node:assert/strict";
import test from "node:test";
import { backoffMs, MAX_ATTEMPTS } from "../src/factory/worker.js";
import {
  assertNoSecrets,
  bearerFrom,
  bindingRow,
  connectAndBind,
  deliveryRows,
  factoryPath,
  FACTORY_KEY,
  queueRelayMessage,
  removeMember,
  replyPath,
  startFactoryEnv,
  type FactoryEnv,
} from "./factory-helpers.js";

/** Binds sess-a as the owner and records one inbound Relay message as `pending`. */
async function boundWithPending(env: FactoryEnv, messageId = "m-1", text = "please run the tests") {
  const bound = await connectAndBind(env);
  queueRelayMessage(env.relay, bound.agent.name, { id: messageId, from: "lead", text });
  assert.equal(await env.module.worker.pollInbox(), 1);
  return bound;
}

const makeDue = (env: FactoryEnv) =>
  env.database.query("UPDATE selfhost_factory_deliveries SET next_attempt_at = now() WHERE state = 'pending'");

const notices = (env: FactoryEnv) => env.relay.replies.filter((reply) => reply.idempotencyKey.startsWith("factory-notice-"));

/** Holds the next Factory POST open until the returned release is called. */
function holdNextPost(env: FactoryEnv) {
  let release!: () => void;
  env.factory.holdInject = new Promise<void>((resolve) => { release = resolve; });
  const arrived = new Promise<void>((resolve) => { env.factory.onInjectArrived = resolve; });
  return { arrived, release: () => { env.factory.holdInject = null; release(); } };
}

test("factory worker round trip: inbox commit before ack, one pinned inject, reply bearer answers, no secrets logged", async (t) => {
  const acksAtInsert: string[][] = [];
  const env = await startFactoryEnv(t, { hooks: { beforeInboxInsert: async () => { acksAtInsert.push([...env.relay.acked]); } } });
  const bound = await boundWithPending(env, "m-1", "please run the tests");
  // The Relay delivery is acknowledged only after the row committed.
  assert.deepEqual(acksAtInsert, [[]]);
  assert.deepEqual(env.relay.acked, ["dl-m-1"]);
  let [row] = await deliveryRows(env, bound.binding_id);
  assert.equal(row!.state, "pending");
  assert.ok(row!.payload_envelope);
  assert.ok(!String(row!.payload_envelope).includes("please run the tests"), "payload is encrypted at rest");

  assert.equal(await env.module.worker.injectBatch(), 1);
  assert.equal(env.factory.injected.length, 1);
  const injected = env.factory.injected[0]!;
  assert.deepEqual([injected.sessionId, injected.computerId, injected.key], ["sess-a", "cmp-1", FACTORY_KEY]);
  assert.match(injected.text, /please run the tests/);
  [row] = await deliveryRows(env, bound.binding_id);
  assert.deepEqual([row!.state, row!.factory_message_id, row!.payload_envelope, row!.attempts], ["delivered", "fm-1", null, 1]);
  assert.ok(row!.reply_hash);

  // The bearer delivered to the session is the reply capability; only its hash is stored.
  const bearer = bearerFrom(injected.text);
  assert.notEqual(row!.reply_hash, bearer);
  const reply = await env.api(replyPath(bound.binding_id), { method: "POST", token: bearer, body: { text: "tests pass" } });
  assert.equal(reply.status, 200, JSON.stringify(reply.body));
  assert.deepEqual(env.relay.replies.map((entry) => [entry.parentId, entry.text]), [["m-1", "tests pass"]]);

  // Nothing further is claimable; the delivered row is never resent.
  assert.equal(await env.module.worker.injectBatch(), 0);
  assert.equal(env.factory.posts, 1);
  assertNoSecrets(env, env.logs);
  assertNoSecrets(env, reply.body);
});

test("factory worker inbox acks self-sent messages and records empty, oversized and senderless ones as rejected", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await connectAndBind(env);
  queueRelayMessage(env.relay, bound.agent.name, { id: "self", from: bound.agent.name, text: "echo" });
  queueRelayMessage(env.relay, bound.agent.name, { id: "empty", text: "" });
  queueRelayMessage(env.relay, bound.agent.name, { id: "huge", text: "x".repeat(20_001) });
  assert.equal(await env.module.worker.pollInbox(), 2);
  const rows = Object.fromEntries((await deliveryRows(env, bound.binding_id)).map((row) => [row.message_id, [row.state, row.code, row.payload_envelope]]));
  assert.deepEqual(rows, { empty: ["rejected", "message_empty", null], huge: ["rejected", "message_too_large", null] });
  assert.deepEqual(env.relay.acked.sort(), ["dl-empty", "dl-huge", "dl-self"]);
  assert.equal(notices(env).length, 2);
  assert.equal(await env.module.worker.injectBatch(), 0);
  assert.equal(env.factory.posts, 0);
});

test("factory worker re-poll after a lost ack records no duplicate and resends nothing", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await boundWithPending(env);
  await env.module.worker.injectBatch();
  env.relay.acked.length = 0; // Relay redelivers: the ack was lost.
  assert.equal(await env.module.worker.pollInbox(), 0);
  assert.equal((await deliveryRows(env, bound.binding_id)).length, 1);
  assert.deepEqual(env.relay.acked, ["dl-m-1"]);
  assert.equal(await env.module.worker.injectBatch(), 0);
  assert.equal(env.factory.posts, 1);
});

test("factory worker retries a 429 with backoff, then rejects attempts_exhausted with one notice", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await boundWithPending(env);
  env.factory.injectMode = "429";
  const before = Date.now();
  assert.equal(await env.module.worker.injectBatch(), 1);
  let [row] = await deliveryRows(env, bound.binding_id);
  assert.deepEqual([row!.state, row!.code, row!.attempts, row!.reply_hash], ["pending", "factory_http_429", 1, null]);
  assert.ok(row!.payload_envelope, "a retryable row keeps its payload");
  const wait = new Date(row!.next_attempt_at).getTime() - before;
  assert.ok(wait >= backoffMs(1) - 1000 && wait <= backoffMs(1) + 5000, `backoff ${wait}`);
  // Not due yet: nothing is claimed.
  assert.equal(await env.module.worker.injectBatch(), 0);
  for (let attempt = 2; attempt <= MAX_ATTEMPTS; attempt++) {
    await makeDue(env);
    assert.equal(await env.module.worker.injectBatch(), 1);
  }
  [row] = await deliveryRows(env, bound.binding_id);
  assert.deepEqual([row!.state, row!.code, row!.attempts, row!.payload_envelope, row!.reply_hash], ["rejected", "attempts_exhausted", MAX_ATTEMPTS, null, null]);
  assert.equal(env.factory.posts, MAX_ATTEMPTS);
  await makeDue(env);
  assert.equal(await env.module.worker.injectBatch(), 0);
  assert.equal(notices(env).length, 1);
  assert.equal(notices(env)[0]!.parentId, "m-1");
  assert.match(notices(env)[0]!.text, /attempts_exhausted/);
});

test("factory worker pre-write failure (session lookup) returns the row to pending without a POST", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await boundWithPending(env);
  env.factory.sessionGetStatus = 503;
  assert.equal(await env.module.worker.injectBatch(), 1);
  const [row] = await deliveryRows(env, bound.binding_id);
  assert.deepEqual([row!.state, row!.code], ["pending", "factory_http_503"]);
  assert.equal(env.factory.posts, 0);
  assert.equal(notices(env).length, 0);
});

test("factory worker terminal rejection is sticky: no reclaim, no new bearer, generation unchanged (6168 req 2)", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await boundWithPending(env);
  const generation = (await bindingRow(env, bound.binding_id)).generation;
  env.factory.injectMode = "409";
  assert.equal(await env.module.worker.injectBatch(), 1);
  const [rejected] = await deliveryRows(env, bound.binding_id);
  assert.deepEqual([rejected!.state, rejected!.code, rejected!.reply_hash, rejected!.payload_envelope], ["rejected", "factory_http_409", null, null]);
  assert.equal(notices(env).length, 1);

  env.factory.injectMode = "ok";
  await env.database.query("UPDATE selfhost_factory_deliveries SET next_attempt_at = now() - interval '1 hour'");
  assert.equal(await env.module.worker.injectBatch(), 0);
  assert.deepEqual(await env.module.worker.kickDelivery(bound.binding_id, "m-1"), { state: "rejected" });
  // A later poll of the same Relay message does not mint a replacement row.
  env.relay.acked.length = 0;
  assert.equal(await env.module.worker.pollInbox(), 0);
  const [after] = await deliveryRows(env, bound.binding_id);
  assert.deepEqual(
    [after!.state, after!.attempts, after!.reply_hash, after!.lease_owner],
    ["rejected", rejected!.attempts, null, rejected!.lease_owner],
  );
  assert.equal((await bindingRow(env, bound.binding_id)).generation, generation);
  assert.equal(env.factory.posts, 1);
  assert.equal(notices(env).length, 1, "the notice is not repeated");
});

test("factory worker ambiguous 500 becomes unknown and is never resent", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await boundWithPending(env);
  env.factory.injectMode = "500";
  await env.module.worker.injectBatch();
  const [row] = await deliveryRows(env, bound.binding_id);
  assert.deepEqual([row!.state, row!.code, row!.payload_envelope], ["unknown", "factory_http_500", null]);
  assert.ok(row!.reply_hash, "an unknown delivery keeps its reply bearer: the session may have received it");
  env.factory.injectMode = "ok";
  await env.database.query("UPDATE selfhost_factory_deliveries SET next_attempt_at = now() - interval '1 hour'");
  assert.equal(await env.module.worker.injectBatch(), 0);
  assert.equal(env.factory.posts, 1);
  assert.match(notices(env)[0]!.text, /unconfirmed/);
});

test("factory worker never double-sends a claimed row while its POST is in flight", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await boundWithPending(env);
  const hold = holdNextPost(env);
  const first = env.module.worker.injectBatch();
  await hold.arrived;
  // A second tick and a manual kick both see the row as leased.
  assert.equal(await env.module.worker.injectBatch(), 0);
  assert.deepEqual(await env.module.worker.kickDelivery(bound.binding_id, "m-1"), { state: "sending" });
  hold.release();
  assert.equal(await first, 1);
  assert.equal(env.factory.posts, 1);
  assert.equal((await deliveryRows(env, bound.binding_id))[0]!.state, "delivered");
});

test("factory worker expired lease becomes unknown without resend; the same claim's late ack still confirms delivery", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await boundWithPending(env);
  const hold = holdNextPost(env);
  const first = env.module.worker.injectBatch();
  await hold.arrived;
  await env.database.query("UPDATE selfhost_factory_deliveries SET lease_until = now() - interval '1 second'");
  assert.equal(await env.module.worker.sweepLeases(), 1);
  let [row] = await deliveryRows(env, bound.binding_id);
  assert.deepEqual([row!.state, row!.code, row!.payload_envelope], ["unknown", "lease_expired", null]);
  assert.equal(await env.module.worker.injectBatch(), 0);
  hold.release();
  await first;
  [row] = await deliveryRows(env, bound.binding_id);
  assert.deepEqual([row!.state, row!.factory_message_id], ["delivered", "fm-1"]);
  assert.equal(env.factory.posts, 1);
});

test("factory worker late completion after unbind is a stale_completion and leaves the binding retired", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await boundWithPending(env);
  const hold = holdNextPost(env);
  const first = env.module.worker.injectBatch();
  await hold.arrived;
  assert.equal((await env.api(factoryPath(env.workspaceId, `/bindings/${bound.binding_id}`), { method: "DELETE", token: env.ownerToken })).status, 204);
  hold.release();
  await first;
  assert.ok(env.logs.some((entry) => entry.event === "factory.inject" && entry.code === "stale_completion"));
  const [row] = await deliveryRows(env, bound.binding_id);
  assert.deepEqual([row!.state, row!.code, row!.reply_hash], ["unknown", "binding_retired", null]);
  assert.equal((await bindingRow(env, bound.binding_id)).state, "retired");
});

test("factory worker fence: a retire or a lost lease between claim and POST sends nothing", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await boundWithPending(env, "m-1");
  // Lease lost (expired, not yet swept): no POST, the row returns to pending.
  let [claimed] = await env.module.worker.claim(1);
  await env.database.query("UPDATE selfhost_factory_deliveries SET lease_until = now() - interval '1 second'");
  await env.module.worker.process(claimed!);
  assert.equal(env.factory.posts, 0);
  let [row] = await deliveryRows(env, bound.binding_id);
  assert.deepEqual([row!.state, row!.code, row!.reply_hash], ["pending", "fence_refused", null]);
  assert.ok(row!.payload_envelope);

  // Binding retired between claim and process: no POST.
  await makeDue(env);
  [claimed] = await env.module.worker.claim(1);
  assert.ok(claimed);
  assert.equal((await env.api(factoryPath(env.workspaceId, `/bindings/${bound.binding_id}`), { method: "DELETE", token: env.ownerToken })).status, 204);
  await env.module.worker.process(claimed!);
  assert.equal(env.factory.posts, 0);
  [row] = await deliveryRows(env, bound.binding_id);
  assert.equal(row!.code, "binding_retired");
  assert.equal(row!.payload_envelope, null);
});

test("factory worker inbox insert is fenced against a membership removal that commits first (a749e46c fix 4)", async (t) => {
  let race: (() => Promise<void>) | null = null;
  const env = await startFactoryEnv(t, { hooks: { beforeInboxInsert: async () => { if (race) await race(); } } });
  const bound = await connectAndBind(env, { token: env.adminToken });
  queueRelayMessage(env.relay, bound.agent.name, { id: "m-race", text: "late message" });
  race = async () => {
    race = null;
    assert.equal((await removeMember(env, env.adminId)).status, 204);
  };
  assert.equal(await env.module.worker.pollInbox(), 0);
  assert.deepEqual(await deliveryRows(env, bound.binding_id), []);
  assert.ok(env.logs.some((entry) => entry.event === "factory.inbox" && entry.code === "binding_not_live"));
  assert.equal((await env.database.query("SELECT 1 FROM selfhost_factory_deliveries")).rows.length, 0);
  assert.equal(env.factory.posts, 0);
});

test("factory worker cleanup loop retries a failed remote release", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await connectAndBind(env);
  env.relay.failRelease = true;
  assert.equal((await env.api(factoryPath(env.workspaceId, `/bindings/${bound.binding_id}`), { method: "DELETE", token: env.ownerToken })).status, 204);
  assert.equal((await bindingRow(env, bound.binding_id)).relay_agent_id, bound.agent.id);
  assert.equal(await env.module.worker.cleanup(), 1);
  env.relay.failRelease = false;
  assert.equal(await env.module.worker.cleanup(), 0);
  assert.deepEqual(env.relay.released, [bound.agent.id]);
  assert.equal((await bindingRow(env, bound.binding_id)).relay_agent_id, null);
});

test("factory worker starts only when SELFHOST_FACTORY_ENABLED is on", async (t) => {
  const off = await startFactoryEnv(t, { enabled: false });
  off.module.start();
  assert.equal(off.module.worker.started, false);
  const on = await startFactoryEnv(t);
  on.module.start();
  assert.equal(on.module.worker.started, true);
  await on.module.stop();
  assert.equal(on.module.worker.started, false);
});
