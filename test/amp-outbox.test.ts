import assert from "node:assert/strict";
import test from "node:test";
import { claimNext, finalize, processClaim, recoverInbox, sweep } from "../src/amp/delivery.js";
import { cleanupWorkspaceAmp, purgeMemberAmp, retireLocally } from "../src/amp/service.js";
import { startAmpWorker } from "../src/amp/worker.js";
import { ampPath, connectAndBind, dmEvent, lastReplyCapability, postEvent, startAmp, THREAD_2, AMP_KEY } from "./amp-helpers.js";
import { BOOTSTRAP } from "./flows-helpers.js";

async function deliveryState(h: Awaited<ReturnType<typeof startAmp>>, messageId: string) {
  const row = await h.database.query<{ state: string; code: string | null; attempts: number }>(
    "SELECT state, code, attempts FROM selfhost_amp_deliveries WHERE message_id = $1", [messageId]);
  return row.rows[0];
}

test("amp outbox: an expired lease becomes unknown and is never resent (req 4)", async (t) => {
  const h = await startAmp(t);
  const deps = h.amp!.deps;
  const binding = await connectAndBind(h);
  await postEvent(h, binding.binding_id, dmEvent(binding.agent, "m-1"));
  await postEvent(h, binding.binding_id, dmEvent(binding.agent, "m-2"));

  // The worker crashes (or stalls) mid-send: the transport sees the prompt,
  // the lease runs out, and a sweep runs before the completion arrives.
  let stall = true;
  h.transport.hooks.inject = async () => {
    if (!stall) return;
    h.clock.now = new Date(h.clock.now.getTime() + deps.leaseMs + 1);
    const swept = await sweep(deps);
    assert.equal(swept.expired, 1);
  };
  const claim = (await claimNext(deps))!;
  assert.equal(claim.messageId, "m-1");
  // One delivery per binding in flight: m-2 waits behind m-1's live lease.
  assert.equal(await claimNext(deps), null);
  const result = await processClaim(deps, claim);
  assert.deepEqual(result.body, { ok: true, skipped: true }, "the stale completion is dropped");
  assert.deepEqual(await deliveryState(h, "m-1"), { state: "unknown", code: "lease_expired", attempts: 1 });
  const held = await h.api(ampPath(h), { token: h.ownerToken });
  assert.match(held.body.bindings[0].lastError ?? "", /^amp_send_unknown/);
  stall = false;

  // Later passes deliver m-2 but never m-1 again.
  const worker = startAmpWorker(deps, 600_000);
  t.after(() => worker.stop());
  await worker.tick();
  await worker.tick();
  const injected = h.transport.injects().map((call) => call.operation.kind === "inject" && /message (m-\d)\]/.exec(call.operation.text)?.[1]);
  assert.deepEqual(injected, ["m-1", "m-2"]);
  assert.deepEqual(await deliveryState(h, "m-1"), { state: "unknown", code: "lease_expired", attempts: 1 });
  assert.equal((await deliveryState(h, "m-2"))!.state, "delivered");
});

test("amp outbox: finalize is conditional on lease owner and generation (req 4)", async (t) => {
  const h = await startAmp(t);
  const deps = h.amp!.deps;
  const binding = await connectAndBind(h);
  await postEvent(h, binding.binding_id, dmEvent(binding.agent, "m-1"));

  const claim = (await claimNext(deps))!;
  // Another owner's finalize (a different lease) changes nothing.
  assert.equal(await finalize(deps, { ...claim, leaseOwner: "00000000-0000-4000-8000-000000000000" }, "delivered", null), false);
  assert.equal((await deliveryState(h, "m-1"))!.state, "sending");
  // A generation bump (as any revocation does) fences the claim.
  await h.database.query("UPDATE selfhost_amp_bindings SET generation = generation + 1 WHERE id = $1", [binding.binding_id]);
  assert.equal(await finalize(deps, claim, "delivered", null), false);
  assert.equal((await deliveryState(h, "m-1"))!.state, "sending");
  await h.database.query("UPDATE selfhost_amp_bindings SET generation = generation - 1 WHERE id = $1", [binding.binding_id]);
  // Control: the matching claim finalizes exactly once.
  assert.equal(await finalize(deps, claim, "delivered", null), true);
  assert.equal(await finalize(deps, claim, "delivered", null), false);
  assert.equal((await deliveryState(h, "m-1"))!.state, "delivered");

  // Unbinding mid-send: the in-flight row becomes unknown and the late completion is stale.
  await postEvent(h, binding.binding_id, dmEvent(binding.agent, "m-2"));
  const second = (await claimNext(deps))!;
  await h.api(ampPath(h, `/bindings/${binding.binding_id}`), { method: "DELETE", token: h.ownerToken });
  assert.equal(await finalize(deps, second, "delivered", null), false);
  const rows = await h.database.query("SELECT 1 FROM selfhost_amp_deliveries");
  assert.equal(rows.rows.length, 0, "the released binding takes its outbox with it");
});

test("amp member removal purges grants inside the membership transaction (req 5)", async (t) => {
  const h = await startAmp(t);
  h.world.addAgent("alice");
  const binding = await connectAndBind(h, h.adminToken);
  await postEvent(h, binding.binding_id, dmEvent(binding.agent, "m-1"));
  const deps = h.amp!.deps;
  await processClaim(deps, (await claimNext(deps))!);
  const capability = lastReplyCapability(h.transport);

  // Atomicity: a failure later in the same transaction rolls the purge back with the membership.
  await assert.rejects(h.store.deleteMembership(h.organizationId, h.adminId, async (tx, member) => {
    await purgeMemberAmp(tx, member);
    const inside = await tx.query<{ state: string }>("SELECT state FROM selfhost_amp_bindings");
    assert.equal(inside.rows[0]!.state, "retired");
    throw new Error("abort");
  }), /abort/);
  const kept = await h.database.query<{ state: string }>("SELECT state FROM selfhost_amp_bindings");
  assert.equal(kept.rows[0]!.state, "bound");
  assert.equal((await h.database.query("SELECT 1 FROM selfhost_amp_connections")).rows.length, 1);

  // The route: revoked in the transaction, released from Relaycast after commit.
  const removed = await h.api(`/api/v1/organizations/${h.organizationId}/memberships/${h.adminId}`, { method: "DELETE", token: BOOTSTRAP });
  assert.equal(removed.status, 204);
  assert.equal((await h.database.query("SELECT 1 FROM selfhost_amp_bindings")).rows.length, 0);
  assert.equal((await h.database.query("SELECT 1 FROM selfhost_amp_connections")).rows.length, 0);
  assert.equal(h.world.agents.has(binding.agent), false);
  assert.equal(h.world.subscriptions.size, 0, "its Relaycast subscriptions are deleted");
  const reply = await h.api(new URL(capability.url).pathname, { method: "POST", token: capability.bearer, body: capability.request });
  assert.equal(reply.status, 401);
});

test("amp member removal with the feature off still revokes grants locally (req 5, 8)", async (t) => {
  // Grants left from a time the feature was on must not outlive the member.
  const h = await startAmp(t, { amp: null });
  await h.database.query(
    `INSERT INTO selfhost_amp_connections (workspace_id, organization_id, user_id, key_ciphertext, key_hint, validated_at)
     VALUES ($1, $2, $3, 'ciphertext', 'sgamp_…mnop', now())`, [h.workspaceId, h.organizationId, h.adminId]);
  await h.database.query(
    `INSERT INTO selfhost_amp_bindings (id, workspace_id, organization_id, user_id, thread_id, relaycast_workspace_id,
       agent_name, state, token_ciphertext, hook_ciphertext)
     VALUES (gen_random_uuid(), $1, $2, $3, 'T-0123456789abcdef', 'rc-primary', 'amp-0123456789abcdef', 'bound', 'tok', 'hook')`,
    [h.workspaceId, h.organizationId, h.adminId]);
  const removed = await h.api(`/api/v1/organizations/${h.organizationId}/memberships/${h.adminId}`, { method: "DELETE", token: BOOTSTRAP });
  assert.equal(removed.status, 204);
  const row = await h.database.query<{ state: string; token_ciphertext: string | null; hook_ciphertext: string | null; generation: number }>(
    "SELECT state, token_ciphertext, hook_ciphertext, generation FROM selfhost_amp_bindings");
  assert.deepEqual(row.rows[0], { state: "retired", token_ciphertext: null, hook_ciphertext: null, generation: 2 });
  assert.equal((await h.database.query("SELECT 1 FROM selfhost_amp_connections")).rows.length, 0);
});

test("amp cleanupWorkspaceAmp retires and releases every binding (req 5)", async (t) => {
  const h = await startAmp(t);
  const deps = h.amp!.deps;
  const first = await connectAndBind(h);
  h.transport.addThread(THREAD_2, AMP_KEY);
  const second = await connectAndBind(h, h.ownerToken, THREAD_2);
  // A failing release leaves the row for the worker rather than losing it.
  h.world.failNext("POST", "/v1/agents/release-exact", 503);
  assert.deepEqual(await cleanupWorkspaceAmp(deps, h.workspaceId), { released: 1, pending: 1 });
  const left = await h.database.query<{ state: string }>("SELECT state FROM selfhost_amp_bindings");
  assert.deepEqual(left.rows.map((row) => row.state), ["retired"]);
  assert.equal((await h.database.query("SELECT 1 FROM selfhost_amp_connections")).rows.length, 0);
  assert.deepEqual(await cleanupWorkspaceAmp(deps, h.workspaceId), { released: 1, pending: 0 });
  assert.equal(h.world.agents.has(first.agent), false);
  assert.equal(h.world.agents.has(second.agent), false);
  assert.equal(h.world.subscriptions.size, 0);
  assert.equal((await h.database.query("SELECT 1 FROM selfhost_amp_bindings")).rows.length, 0);
  assert.deepEqual(await cleanupWorkspaceAmp(deps, "00000000-0000-4000-8000-000000000000"), { released: 0, pending: 0 });
});

type Harness = Awaited<ReturnType<typeof startAmp>>;

const injectedIds = (h: Harness) => h.transport.injects()
  .map((call) => call.operation.kind === "inject" ? /; message ([^\]]+)\]/.exec(call.operation.text)?.[1] : undefined);
const acks = (h: Harness, from = 0) => h.world.bodies.slice(from)
  .filter((call) => call.method === "POST" && /^\/v1\/deliveries\/[^/]+\/ack$/.test(call.path)).length;
const inboxReads = (h: Harness, from = 0) => h.world.bodies.slice(from)
  .filter((call) => call.method === "GET" && call.path === "/v1/deliveries").length;
async function lastError(h: Harness, bindingId: string) {
  return (await h.database.query<{ last_error: string | null }>(
    "SELECT last_error FROM selfhost_amp_bindings WHERE id = $1", [bindingId])).rows[0]?.last_error ?? null;
}

test("amp inbox recovery: a message the webhook missed is queued, injected once and acknowledged", async (t) => {
  const h = await startAmp(t);
  const binding = await connectAndBind(h);
  h.world.addAgent("alice");
  // No webhook arrives (lost upstream); the message sits in the agent's hosted inbox.
  const sent = h.world.sendAs("alice", binding.agent, "please review the diff");
  const worker = startAmpWorker(h.amp!.deps, 600_000);
  t.after(() => worker.stop());
  await worker.tick();
  assert.deepEqual(injectedIds(h), [sent.message.id]);
  const inject = h.transport.injects()[0]!.operation;
  assert(inject.kind === "inject");
  assert.match(inject.text, /^\[via Agent Relay — from "alice" to @/);
  assert.match(inject.text, /please review the diff$/);
  assert.equal((await deliveryState(h, sent.message.id))!.state, "delivered");
  assert.deepEqual(h.world.pending(binding.agent), [], "acknowledged once the outbox row is committed");

  // The payload is stored encrypted, never as the plain text.
  const stored = await h.database.query<{ payload_ciphertext: string }>("SELECT payload_ciphertext FROM selfhost_amp_deliveries");
  assert.doesNotMatch(stored.rows[0]!.payload_ciphertext, /alice|please review/);

  // A later pass reads an empty inbox and injects nothing more.
  await worker.tick();
  assert.equal(h.transport.injects().length, 1);
});

test("amp inbox recovery: own messages and untargeted channel posts are acknowledged and never queued", async (t) => {
  const h = await startAmp(t);
  const deps = h.amp!.deps;
  const binding = await connectAndBind(h);
  h.world.addAgent("alice");
  // The agent's own message echoed into its inbox.
  const own = h.world.sendAs(binding.agent, "alice", `@${binding.agent} note to self`);
  h.world.deliveries.push({ id: "dl_own", agent: binding.agent, message: h.world.messages.get(own.message.id)!, reason: "dm", acked: false });
  // A channel post that does not mention the agent, then one that does.
  h.world.channelAs("alice", "general");
  h.world.channels.get("general")!.members.add(binding.agent);
  h.world.channelAs("alice", "general", "status update for everyone");
  const mention = h.world.channelAs("alice", "general", `@${binding.agent} can you look?`)!;

  const result = await recoverInbox(deps, { after: null });
  assert.deepEqual(result, { polled: 1, queued: 1, failed: 0 });
  const rows = await h.database.query<{ message_id: string }>("SELECT message_id FROM selfhost_amp_deliveries");
  assert.deepEqual(rows.rows.map((row) => row.message_id), [mention.id]);
  assert.deepEqual(h.world.pending(binding.agent), [], "dropped messages are acknowledged as the webhook drops them");
});

test("amp inbox recovery and the webhook dedupe on (binding, message): one delivery, one injection", async (t) => {
  const h = await startAmp(t);
  const deps = h.amp!.deps;
  const binding = await connectAndBind(h);
  h.world.addAgent("alice");

  // Webhook first, then the inbox sees the same message.
  const first = h.world.sendAs("alice", binding.agent, "first");
  assert.deepEqual((await postEvent(h, binding.binding_id, dmEvent(binding.agent, first.message.id, "first"))).body,
    { ok: true, queued: true });
  assert.deepEqual(await recoverInbox(deps, { after: null }), { polled: 1, queued: 0, failed: 0 });
  assert.deepEqual(h.world.pending(binding.agent), [], "the already-present row is confirmed, so it is acknowledged");

  // Inbox first, then the webhook arrives late.
  const second = h.world.sendAs("alice", binding.agent, "second");
  assert.deepEqual(await recoverInbox(deps, { after: null }), { polled: 1, queued: 1, failed: 0 });
  assert.deepEqual((await postEvent(h, binding.binding_id, dmEvent(binding.agent, second.message.id, "second"))).body,
    { ok: true, duplicate: true });

  const worker = startAmpWorker(deps, 600_000);
  t.after(() => worker.stop());
  await worker.tick();
  await worker.tick();
  assert.deepEqual(injectedIds(h), [first.message.id, second.message.id]);
  const rows = await h.database.query<{ count: number }>("SELECT count(*)::int AS count FROM selfhost_amp_deliveries");
  assert.equal(rows.rows[0]!.count, 2);
});

test("amp inbox recovery acknowledges only after the outbox commit; a failed commit is recovered next pass", async (t) => {
  const h = await startAmp(t);
  const deps = h.amp!.deps;
  const binding = await connectAndBind(h);
  h.world.addAgent("alice");
  const sent = h.world.sendAs("alice", binding.agent, "please review");
  // The insert succeeds but the transaction fails at COMMIT.
  await h.database.query(`CREATE FUNCTION amp_test_fail_commit() RETURNS trigger LANGUAGE plpgsql AS
    $$ BEGIN RAISE EXCEPTION 'commit refused'; END $$`);
  await h.database.query(`CREATE CONSTRAINT TRIGGER amp_test_fail_commit AFTER INSERT ON selfhost_amp_deliveries
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION amp_test_fail_commit()`);
  const from = h.world.bodies.length;
  assert.deepEqual(await recoverInbox(deps, { after: null }), { polled: 1, queued: 0, failed: 1 });
  assert.equal(acks(h, from), 0, "nothing is acknowledged when the commit fails");
  assert.equal(h.world.pending(binding.agent).length, 1);
  assert.equal(await deliveryState(h, sent.message.id), undefined);
  assert.equal(await lastError(h, binding.binding_id), "inbox_poll_failed");

  await h.database.query("DROP TRIGGER amp_test_fail_commit ON selfhost_amp_deliveries");
  assert.deepEqual(await recoverInbox(deps, { after: null }), { polled: 1, queued: 1, failed: 0 });
  assert.deepEqual(h.world.pending(binding.agent), []);
  assert.equal((await deliveryState(h, sent.message.id))!.state, "pending");
  assert.equal(await lastError(h, binding.binding_id), null);
  await processClaim(deps, (await claimNext(deps))!);
  assert.deepEqual(injectedIds(h), [sent.message.id]);

  // A lost acknowledgement re-reads the message; the existing row dedupes it.
  const again = h.world.sendAs("alice", binding.agent, "again");
  h.world.failNext("POST", `/v1/deliveries/${h.world.pending(binding.agent)[0]!.id}/ack`, 503);
  assert.deepEqual(await recoverInbox(deps, { after: null }), { polled: 1, queued: 1, failed: 1 });
  assert.deepEqual(await recoverInbox(deps, { after: null }), { polled: 1, queued: 0, failed: 0 });
  assert.deepEqual(h.world.pending(binding.agent), []);
  const rows = await h.database.query("SELECT 1 FROM selfhost_amp_deliveries WHERE message_id = $1", [again.message.id]);
  assert.equal(rows.rows.length, 1);
});

test("amp inbox recovery never polls or queues for a retired binding, even one retired after the read", async (t) => {
  const h = await startAmp(t);
  const deps = h.amp!.deps;
  const binding = await connectAndBind(h);
  h.world.addAgent("alice");
  const sent = h.world.sendAs("alice", binding.agent, "please review");

  // Retired between the inbox read and the insert.
  const read = deps.relaycast.readHostedInbox;
  deps.relaycast.readHostedInbox = async (token) => {
    const rows = await read(token);
    await h.database.transaction((tx) => retireLocally(tx, "id = $1", [binding.binding_id]));
    return rows;
  };
  const from = h.world.bodies.length;
  assert.deepEqual(await recoverInbox(deps, { after: null }), { polled: 1, queued: 0, failed: 0 });
  deps.relaycast.readHostedInbox = read;
  assert.equal(await deliveryState(h, sent.message.id), undefined, "nothing is queued for the retired generation");
  assert.equal(acks(h, from), 0, "and nothing is acknowledged");
  assert.equal(h.world.pending(binding.agent).length, 1);

  // Once retired, the binding is not polled at all.
  const later = h.world.bodies.length;
  assert.deepEqual(await recoverInbox(deps, { after: null }), { polled: 0, queued: 0, failed: 0 });
  assert.equal(inboxReads(h, later), 0);

  // A generation bump alone (a rebind) also fences the insert, and a moved workspace relay skips the poll.
  h.transport.addThread(THREAD_2, AMP_KEY);
  const second = await connectAndBind(h, h.ownerToken, THREAD_2);
  h.world.sendAs("alice", second.agent, "to the new binding");
  deps.relaycast.readHostedInbox = async (token) => {
    const rows = await read(token);
    await h.database.query("UPDATE selfhost_amp_bindings SET generation = generation + 1 WHERE id = $1", [second.binding_id]);
    return rows;
  };
  assert.deepEqual(await recoverInbox(deps, { after: null }), { polled: 1, queued: 0, failed: 0 });
  deps.relaycast.readHostedInbox = read;
  assert.equal(h.world.pending(second.agent).length, 1);
  await h.database.query("UPDATE selfhost_workspaces SET relaycast_workspace_id = 'rc-moved' WHERE id = $1", [h.workspaceId]);
  const moved = h.world.bodies.length;
  assert.deepEqual(await recoverInbox(deps, { after: null }), { polled: 0, queued: 0, failed: 0 });
  assert.equal(inboxReads(h, moved), 0);
  assert.equal((await h.database.query("SELECT 1 FROM selfhost_amp_deliveries")).rows.length, 0);
});

test("amp inbox recovery: one binding's failure does not block another, and passes are capped and fair", async (t) => {
  const h = await startAmp(t);
  const deps = h.amp!.deps;
  const one = await connectAndBind(h);
  h.transport.addThread(THREAD_2, AMP_KEY);
  const two = await connectAndBind(h, h.ownerToken, THREAD_2);
  const [first, second] = [one, two].sort((a, b) => a.binding_id.localeCompare(b.binding_id));
  h.world.addAgent("alice");
  h.world.sendAs("alice", first!.agent, "for the first");
  h.world.sendAs("alice", second!.agent, "for the second");

  const warnings: unknown[][] = [];
  const warn = console.warn;
  console.warn = (...args: unknown[]) => void warnings.push(args);
  t.after(() => { console.warn = warn; });
  h.world.failNext("GET", "/v1/deliveries", 503, { code: "relay_unavailable" });
  assert.deepEqual(await recoverInbox(deps, { after: null }), { polled: 2, queued: 1, failed: 1 });
  console.warn = warn;
  assert.equal(h.world.pending(first!.agent).length, 1);
  assert.equal(h.world.pending(second!.agent).length, 0);
  assert.equal(await lastError(h, first!.binding_id), "inbox_poll_failed");
  assert.deepEqual(warnings, [["[amp] inbox_poll_failed", { bindingId: first!.binding_id, error: "relay_unavailable" }]],
    "only the error code is logged");
  // An outstanding send outcome is never overwritten by a poll failure.
  await h.database.query("UPDATE selfhost_amp_bindings SET last_error = 'amp_send_unknown' WHERE id = $1", [second!.binding_id]);

  // One binding per pass: round-robin, oldest-polled first.
  const cursor = { after: null as string | null };
  const limits = { bindings: 1, messages: 50 };
  const order: Array<string | null> = [];
  for (let index = 0; index < 3; index += 1) {
    await recoverInbox(deps, cursor, limits);
    order.push(cursor.after);
  }
  assert.deepEqual(order, [first!.binding_id, second!.binding_id, first!.binding_id]);
  assert.equal(h.world.pending(first!.agent).length, 0, "the failed binding recovers on its next turn");
  assert.equal(await lastError(h, first!.binding_id), null);
  assert.equal(await lastError(h, second!.binding_id), "amp_send_unknown");

  // A message cap leaves the rest unacknowledged for the next pass.
  for (const text of ["a", "b", "c"]) h.world.sendAs("alice", first!.agent, text);
  assert.deepEqual(await recoverInbox(deps, { after: null }, { bindings: 10, messages: 2 }), { polled: 1, queued: 2, failed: 0 });
  assert.equal(h.world.pending(first!.agent).length, 1);
  assert.deepEqual(await recoverInbox(deps, { after: null }, { bindings: 10, messages: 2 }), { polled: 2, queued: 1, failed: 0 });
  assert.equal(h.world.pending(first!.agent).length, 0);
});
