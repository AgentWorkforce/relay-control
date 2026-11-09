import assert from "node:assert/strict";
import test from "node:test";
import { replyIdempotencyKey } from "../src/factory/reply-capability.js";
import {
  assertNoSecrets,
  connectAndBind,
  factoryPath,
  replyPath,
  seedDelivery,
  startFactoryEnv,
} from "./factory-helpers.js";

const reply = (env: Awaited<ReturnType<typeof startFactoryEnv>>, bindingId: string, bearer: string, body: unknown) =>
  env.api(replyPath(bindingId), { method: "POST", token: bearer, body });

test("factory reply capability: malformed, unknown, wrong-binding and bad-body requests are refused before Relay", async (t) => {
  const env = await startFactoryEnv(t);
  const { binding_id } = await connectAndBind(env);
  const second = await env.api(factoryPath(env.workspaceId, "/bindings"), {
    method: "POST", token: env.ownerToken, body: { session_id: "sess-b", computer_id: "cmp-1" },
  });
  const { bearer } = await seedDelivery(env, binding_id);

  assert.equal((await env.api(replyPath(binding_id), { method: "POST", body: { text: "x" } })).status, 401);
  assert.deepEqual((await reply(env, binding_id, "factory_reply_short", { text: "x" })).body, { error: "unauthorized", message: "Unauthorized" });
  assert.equal((await reply(env, binding_id, env.ownerToken, { text: "x" })).status, 401);
  assert.equal((await reply(env, binding_id, `factory_reply_${"A".repeat(43)}`, { text: "x" })).status, 401);
  // A valid bearer is pinned to its binding.
  assert.equal((await reply(env, second.body.binding_id, bearer, { text: "x" })).status, 401);
  assert.equal((await env.api(replyPath(binding_id), { method: "GET", token: bearer })).status, 405);
  for (const body of [{}, { text: "" }, { text: "x", extra: 1 }, { text: 5 }, { text: "x".repeat(20_001) }, []]) {
    const refused = await reply(env, binding_id, bearer, body);
    assert.equal(refused.status, 400, JSON.stringify(body).slice(0, 40));
    assert.equal(refused.body.error, "invalid_request");
  }
  const malformed = await env.api(replyPath(binding_id), { method: "POST", token: bearer, headers: { "content-type": "application/json" }, raw: "{not json" });
  assert.equal(malformed.status, 400);
  const huge = await env.api(replyPath(binding_id), {
    method: "POST", token: bearer, headers: { "content-type": "application/json" }, raw: JSON.stringify({ text: "y".repeat(70_000) }),
  });
  assert.equal(huge.status, 413);
  assert.deepEqual(huge.body, { error: "payload_too_large", message: "Too large" });
  assert.equal(env.relay.replies.length, 0);
});

test("factory reply round trip posts once to the pinned parent with the binding's hosted token and is idempotent", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await connectAndBind(env);
  const { bearer, messageId } = await seedDelivery(env, bound.binding_id, { messageId: "relay-msg-1" });
  const first = await reply(env, bound.binding_id, bearer, { text: "done: 3 files changed" });
  assert.equal(first.status, 200, JSON.stringify(first.body));
  assert.equal(first.body.ok, true);
  assert.equal(typeof first.body.message_id, "string");
  assertNoSecrets(env, first.body);
  assert.equal(env.relay.replies.length, 1);
  assert.deepEqual(env.relay.replies[0], {
    token: env.relay.agents.get(bound.agent.name)!.token,
    parentId: messageId,
    text: "done: 3 files changed",
    idempotencyKey: replyIdempotencyKey(bound.binding_id, messageId),
  });
  // Same body: the stored result, no second Relay call.
  const repeat = await reply(env, bound.binding_id, bearer, { text: "done: 3 files changed" });
  assert.deepEqual(repeat.body, first.body);
  assert.equal(env.relay.replies.length, 1);
  // Different body on the same bearer: refused.
  const other = await reply(env, bound.binding_id, bearer, { text: "something else" });
  assert.deepEqual(other.body, { error: "reply_already_recorded", message: "Reply already recorded" });
  assert.equal(env.relay.replies.length, 1);
  assertNoSecrets(env, env.logs);
  assert.ok(!JSON.stringify(env.logs).includes(bearer));
});

test("factory reply accepts sending and unknown deliveries but not pending, rejected, expired or failed relay", async (t) => {
  const env = await startFactoryEnv(t);
  const { binding_id } = await connectAndBind(env);
  for (const state of ["sending", "unknown"] as const) {
    const { bearer } = await seedDelivery(env, binding_id, { state });
    assert.equal((await reply(env, binding_id, bearer, { text: `from ${state}` })).status, 200, state);
  }
  for (const state of ["pending", "rejected"] as const) {
    const { bearer } = await seedDelivery(env, binding_id, { state });
    assert.equal((await reply(env, binding_id, bearer, { text: "no" })).status, 401, state);
  }
  const expired = await seedDelivery(env, binding_id, { expiresInMs: -1000 });
  assert.equal((await reply(env, binding_id, expired.bearer, { text: "late" })).status, 401);

  env.relay.failReply = true;
  const failing = await seedDelivery(env, binding_id);
  const failed = await reply(env, binding_id, failing.bearer, { text: "relay down" });
  assert.deepEqual(failed.body, { error: "factory_reply_failed", message: "Factory reply failed." });
  // A failed relay call records nothing, so the retry with the same body goes through.
  env.relay.failReply = false;
  assert.equal((await reply(env, binding_id, failing.bearer, { text: "relay down" })).status, 200);
});

test("factory reply on a retired binding is 409 and the bearer hash is gone", async (t) => {
  const env = await startFactoryEnv(t);
  const { binding_id } = await connectAndBind(env);
  const { bearer, hash } = await seedDelivery(env, binding_id);
  assert.equal((await env.api(factoryPath(env.workspaceId, `/bindings/${binding_id}`), { method: "DELETE", token: env.ownerToken })).status, 204);
  const refused = await reply(env, binding_id, bearer, { text: "after unbind" });
  assert.deepEqual(refused.body, { error: "binding_retired", message: "Binding is retired" });
  const rows = await env.database.query("SELECT 1 FROM factory_deliveries WHERE reply_hash = $1", [hash]);
  assert.equal(rows.rows.length, 0);
  assert.equal(env.relay.replies.length, 0);
});

test("factory reply is refused once the binding's member leaves the organization", async (t) => {
  const env = await startFactoryEnv(t);
  // The admin is the binding owner here so the org owner can remove them.
  const { binding_id } = await connectAndBind(env, { token: env.adminToken });
  const { bearer } = await seedDelivery(env, binding_id);
  // Simulate the bearer outliving membership without the purge (purge clears the hash; tested in teardown).
  await env.database.query("DELETE FROM organization_memberships WHERE user_id = $1", [env.adminId]);
  assert.equal((await reply(env, binding_id, bearer, { text: "ghost" })).status, 401);
  assert.equal(env.relay.replies.length, 0);
});
