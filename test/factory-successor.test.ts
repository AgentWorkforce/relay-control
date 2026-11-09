/**
 * A late, old-generation release or finalization never touches a successor
 * binding of the same Factory session (same derived agent name, new Relay
 * agent id, new binding row).
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  bindingRow,
  connectAndBind,
  deliveryRows,
  FACTORY_KEY_2,
  factoryPath,
  queueRelayMessage,
  startFactoryEnv,
  type FactoryEnv,
} from "./factory-helpers.js";

/** Holds the next release-exact request open (before its lookup) until released. */
function holdNextRelease(env: FactoryEnv) {
  let release!: () => void;
  env.relay.holdRelease = new Promise<void>((resolve) => { release = resolve; });
  const arrived = new Promise<void>((resolve) => { env.relay.onReleaseArrived = resolve; });
  return { arrived, release };
}

/**
 * Admin A binds sess-a, then disconnects with the remote release failing:
 * A's retired row keeps its relay_agent_id with release_failed.
 */
async function retiredWithPendingRelease(env: FactoryEnv) {
  const old = await connectAndBind(env, { token: env.adminToken, sessionId: "sess-a" });
  env.relay.failRelease = true;
  assert.equal((await env.api(factoryPath(env.workspaceId, "/connection"), { method: "DELETE", token: env.adminToken })).status, 204);
  env.relay.failRelease = false;
  const row = await bindingRow(env, old.binding_id);
  assert.deepEqual([row.state, row.relay_agent_id, row.remote_cleanup_code], ["retired", old.agent.id, "release_failed"]);
  assert.ok(env.relay.agents.has(old.agent.name), "the old agent is still live remotely");
  return old;
}

async function assertSuccessorIntact(env: FactoryEnv, successor: { binding_id: string; agent: { name: string; id: string } }) {
  const live = env.relay.agents.get(successor.agent.name);
  assert.equal(live?.id, successor.agent.id, "the successor's Relay agent still holds the name");
  assert.ok(!env.relay.released.includes(successor.agent.id), "the successor agent was never released");
  assert.ok(
    env.relay.releaseRequests.every((request) => request.expectedAgentId !== successor.agent.id),
    "no release request ever targeted the successor's agent id",
  );
  const row = await bindingRow(env, successor.binding_id);
  assert.deepEqual([row.state, row.relay_agent_id], ["bound", successor.agent.id]);
  assert.ok(row.hosted_token_envelope);
}

async function assertTombstone(env: FactoryEnv, bindingId: string) {
  const row = await bindingRow(env, bindingId);
  assert.deepEqual(
    [row.state, row.relay_agent_id, row.remote_cleanup_code, row.hosted_token_envelope, row.hook_secret_envelope, row.helper_secret_envelope],
    ["retired", null, null, null, null, null],
  );
}

for (const absent of ["completed", "404"] as const) {
  test(`factory late cleanup-loop release held across a successor bind only targets the old agent id (release of a missing id answers ${absent})`, async (t) => {
    const env = await startFactoryEnv(t);
    env.relay.releaseAbsentAs404 = absent === "404";
    const old = await retiredWithPendingRelease(env);

    // The cleanup loop read A's row (old agent id) and its release is in flight.
    const hold = holdNextRelease(env);
    const late = env.module.worker.cleanup();
    await hold.arrived;

    // Meanwhile the owner connects and binds the same session: bind's own
    // releasePending({sessionId}) frees the old agent, then a new agent is
    // registered under the same derived name.
    const successor = await connectAndBind(env, { key: FACTORY_KEY_2, sessionId: "sess-a" });
    assert.equal(successor.agent.name, old.agent.name, "same derived agent name");
    assert.notEqual(successor.agent.id, old.agent.id);
    assert.notEqual(successor.binding_id, old.binding_id);

    // The late request now lands while the successor holds the name.
    hold.release();
    assert.equal(await late, 0);
    assert.deepEqual(
      env.relay.releaseRequests.map((request) => request.expectedAgentId),
      [old.agent.id, old.agent.id, old.agent.id],
      "the failed disconnect release, the late loop and bind's cleanup all targeted only the old row's own agent id",
    );
    assert.deepEqual(env.relay.released, [old.agent.id]);
    await assertSuccessorIntact(env, successor);
    await assertTombstone(env, old.binding_id);
  });

  test(`factory old retired row still holding its agent id beside a live successor is tombstoned by cleanup without touching the successor (missing id answers ${absent})`, async (t) => {
    const env = await startFactoryEnv(t);
    env.relay.releaseAbsentAs404 = absent === "404";
    const old = await retiredWithPendingRelease(env);
    const successor = await connectAndBind(env, { key: FACTORY_KEY_2, sessionId: "sess-a" });
    assert.deepEqual(env.relay.released, [old.agent.id]);

    // Worst case: A's row still names its (now gone) agent id while the
    // successor is live, e.g. a lost markReleased write.
    await env.database.query(
      "UPDATE factory_bindings SET relay_agent_id = $2, remote_cleanup_code = 'release_failed' WHERE id = $1",
      [old.binding_id, old.agent.id],
    );
    const requestsBefore = env.relay.releaseRequests.length;
    // Both late release drivers: the worker cleanup loop and the service's releasePending.
    assert.equal(await env.module.worker.cleanup(), 0);
    await env.database.query(
      "UPDATE factory_bindings SET relay_agent_id = $2, remote_cleanup_code = 'release_failed' WHERE id = $1",
      [old.binding_id, old.agent.id],
    );
    assert.equal(await env.module.service.releasePending({ sessionId: "sess-a" }), 0);
    assert.deepEqual(
      env.relay.releaseRequests.slice(requestsBefore).map((request) => request.expectedAgentId),
      [old.agent.id, old.agent.id],
    );
    assert.deepEqual(env.relay.released, [old.agent.id]);
    await assertSuccessorIntact(env, successor);
    await assertTombstone(env, old.binding_id);

    // The successor keeps working: a rebind of the same session is idempotent.
    const again = await env.api(factoryPath(env.workspaceId, "/bindings"), {
      method: "POST", token: env.ownerToken, body: { session_id: "sess-a", computer_id: "cmp-1" },
    });
    assert.equal(again.status, 201, JSON.stringify(again.body));
    assert.deepEqual([again.body.binding_id, again.body.agent.id], [successor.binding_id, successor.agent.id]);
  });
}

test("factory old-generation finalization cannot write into a successor binding's deliveries", async (t) => {
  const env = await startFactoryEnv(t);
  // A binds sess-a and the worker claims a delivery under that generation.
  const old = await connectAndBind(env, { token: env.adminToken, sessionId: "sess-a" });
  queueRelayMessage(env.relay, old.agent.name, { id: "m-shared", from: "lead", text: "old generation" });
  assert.equal(await env.module.worker.pollInbox(), 1);
  const [claim] = await env.module.worker.claim(1);
  assert.ok(claim);
  const oldGeneration = String((await bindingRow(env, old.binding_id)).generation);
  assert.equal(claim.claim_generation, oldGeneration);

  // A disconnects (generation bumped, outbox settled), the owner rebinds the same session.
  assert.equal((await env.api(factoryPath(env.workspaceId, "/connection"), { method: "DELETE", token: env.adminToken })).status, 204);
  assert.notEqual(String((await bindingRow(env, old.binding_id)).generation), oldGeneration);
  const successor = await connectAndBind(env, { key: FACTORY_KEY_2, sessionId: "sess-a" });
  assert.equal(successor.agent.name, old.agent.name);
  // Adversarial: the successor receives a delivery with the very same message id, and claims it.
  // Same derived name, so the fake inbox is shared: replace it with a fresh delivery id.
  env.relay.inbox.set(successor.agent.name, [{
    id: "dl-successor", message: { id: "m-shared", agent_name: "lead", agent_id: "ag-lead", text: "successor generation" },
  }]);
  assert.equal(await env.module.worker.pollInbox(), 1);
  const [successorClaim] = await env.module.worker.claim(1);
  assert.ok(successorClaim);
  assert.equal(successorClaim.binding_id, successor.binding_id);
  const successorBefore = await deliveryRows(env, successor.binding_id);
  const oldBefore = await deliveryRows(env, old.binding_id);
  assert.deepEqual(oldBefore.map((row) => [row.state, row.code]), [["unknown", "binding_retired"]]);

  // The old-generation worker finishes late, with every outcome.
  for (const outcome of [
    { state: "delivered" as const, factoryMessageId: "fm-late" },
    { state: "rejected" as const, code: "factory_http_409" },
    { state: "unknown" as const, code: "factory_http_500" },
    { state: "pending" as const, code: "factory_http_429" },
  ]) {
    assert.equal(await env.module.worker.finalize(claim, outcome), false, `old claim ${outcome.state}`);
    // Even pointed at the successor's binding id, the old lease owner and generation match nothing.
    assert.equal(await env.module.worker.finalize({ ...claim, binding_id: successor.binding_id }, outcome), false, `redirected ${outcome.state}`);
  }
  assert.deepEqual(await deliveryRows(env, successor.binding_id), successorBefore);
  assert.deepEqual(await deliveryRows(env, old.binding_id), oldBefore);
  assert.ok(env.logs.filter((entry) => entry.code === "stale_completion").length >= 8);
  assert.equal((await bindingRow(env, successor.binding_id)).state, "bound");

  // The successor's own claim still completes normally.
  await env.module.worker.process(successorClaim);
  const [done] = await deliveryRows(env, successor.binding_id);
  assert.equal(done!.state, "delivered");
  assert.equal(env.factory.posts, 1);
  assert.match(env.factory.injected[0]!.text, /successor generation/);
});
