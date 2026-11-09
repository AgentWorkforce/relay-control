import assert from "node:assert/strict";
import test from "node:test";
import { registerAmpTools } from "../src/amp/mcp-tools.js";
import { claimNext, RELAY_EVENT_MAX_BYTES } from "../src/amp/delivery.js";
import { decrypt } from "../src/amp/service.js";
import { startAmpWorker } from "../src/amp/worker.js";
import { planToolGroups } from "../src/mcp/catalog.js";
import type { McpContext } from "../src/mcp/context.js";
import {
  AMP_KEY, OTHER_KEY, THREAD, THREAD_2, INTERNAL_SECRET, SERVICE_TOKEN,
  ampConfig, ampPath, connectAndBind, dmEvent, hookSecret, internalJob, lastReplyCapability, postEvent, startAmp,
  subscriptionsFor,
} from "./amp-helpers.js";
import { BOOTSTRAP } from "./flows-helpers.js";

const NOT_FOUND = { error: "Not found" };

test("amp gating: off answers 404 before auth on every route and starts no worker (req 8)", async (t) => {
  for (const variant of [{ amp: null }, { amp: ampConfig({ enabled: false }) }]) {
    const h = await startAmp(t, variant);
    const routes: Array<[string, string]> = [
      ["GET", ampPath(h)],
      ["POST", ampPath(h, "/connection")],
      ["GET", ampPath(h, "/threads")],
      ["POST", `/cloud${ampPath(h, "/bindings")}`],
      ["POST", "/api/v1/amp/agents/00000000-0000-4000-8000-000000000000/messages"],
      ["POST", "/api/v1/amp/relay-events/00000000-0000-4000-8000-000000000000"],
      ["POST", "/api/v1/internal/amp/job"],
    ];
    for (const [method, path] of routes) {
      // No credential at all: an enabled route would answer 401; off answers 404 first.
      const anonymous = await h.api(path, { method, ...(method === "POST" ? { body: {} } : {}) });
      assert.equal(anonymous.status, 404, `${method} ${path}`);
      assert.deepEqual(anonymous.body, NOT_FOUND);
      const owner = await h.api(path, { method, token: h.ownerToken, ...(method === "POST" ? { body: {} } : {}) });
      assert.equal(owner.status, 404);
      assert.deepEqual(owner.body, NOT_FOUND);
    }
    if (h.amp) assert.equal(h.amp.start(), null);
    assert.equal(h.transport.calls.length, 0);
  }
  // Control: the same anonymous call reaches auth when the feature is on.
  const on = await startAmp(t);
  assert.equal((await on.api(ampPath(on))).status, 401);
});

test("amp refuses non-admins, missing cli:auth, service and cross-workspace callers before Amp (req 1)", async (t) => {
  const h = await startAmp(t);
  h.transport.addThread(THREAD, AMP_KEY);
  const connect = (token: string, path = ampPath(h, "/connection")) =>
    h.api(path, { method: "POST", token, body: { key: AMP_KEY } });

  const member = await connect(h.memberToken);
  assert.equal(member.status, 403);
  assert.equal(member.body.error, "forbidden");
  const service = await connect(SERVICE_TOKEN);
  assert.equal(service.status, 403);
  assert.equal(service.body.error, "forbidden");
  // A token for another workspace is not this workspace's admin.
  assert.equal((await connect(h.otherOwnerToken)).status, 404);
  assert.equal((await h.api(ampPath(h))).status, 401);

  // The owner's own session, stripped of cli:auth, is refused; restored, accepted.
  await h.database.query("UPDATE token_sessions SET scopes = ARRAY['rth:read']::text[] WHERE user_id = $1", [h.ownerId]);
  const scoped = await connect(h.ownerToken);
  assert.equal(scoped.status, 403);
  assert.match(scoped.body.message, /cli:auth/);
  assert.equal(h.transport.calls.length, 0, "no refused caller reaches the Amp transport");
  await h.database.query("UPDATE token_sessions SET scopes = ARRAY['rth:read','cli:auth']::text[] WHERE user_id = $1", [h.ownerId]);
  const ok = await connect(h.ownerToken);
  assert.equal(ok.status, 200, ok.text);
  assert.equal(ok.body.connection.keyHint, `sgamp_…${AMP_KEY.slice(-4)}`);
  assert.doesNotMatch(ok.text, new RegExp(AMP_KEY));

  // Demoted to member mid-session: the role is re-read from Postgres.
  await h.database.query("UPDATE organization_memberships SET role = 'member' WHERE user_id = $1", [h.adminId]);
  assert.equal((await h.api(ampPath(h), { token: h.adminToken })).status, 403);
  assert.equal((await h.api(ampPath(h), { token: h.ownerToken })).status, 200);
});

test("amp connect, discover, bind, unbind and disconnect keep the key-owner and chosen-thread fences (req 1, 5)", async (t) => {
  const h = await startAmp(t);
  h.transport.addThread(THREAD, AMP_KEY);
  h.transport.addThread(THREAD_2, OTHER_KEY);

  const badKey = await h.api(ampPath(h, "/connection"), { method: "POST", token: h.ownerToken, body: { key: "nope" } });
  assert.equal(badKey.status, 400);
  assert.equal(badKey.body.error, "invalid_key");
  assert.equal(h.transport.calls.length, 0);

  const connected = await h.api(ampPath(h, "/connection"), { method: "POST", token: h.ownerToken, body: { key: AMP_KEY } });
  assert.equal(connected.status, 200);
  assert.deepEqual(connected.body.threads, [{ id: THREAD, title: `Thread ${THREAD}` }]);
  assert.deepEqual(connected.body.history, { available: false, reason: "push_session_unavailable" });
  const stored = await h.database.query<{ key_ciphertext: string }>("SELECT key_ciphertext FROM amp_connections");
  assert.equal(stored.rows.length, 1);
  assert.doesNotMatch(stored.rows[0]!.key_ciphertext, /sgamp_/, "the key is encrypted at rest");

  // API-key-owner fence: another admin may not browse or bind with the owner's key.
  const adminThreads = await h.api(ampPath(h, "/threads"), { token: h.adminToken });
  assert.equal(adminThreads.status, 403);
  assert.equal(adminThreads.body.error, "not_connection_owner");
  const adminBind = await h.api(ampPath(h, "/bindings"), { method: "POST", token: h.adminToken, body: { threadId: THREAD } });
  assert.equal(adminBind.status, 403);
  const threads = await h.api(ampPath(h, "/threads"), { token: h.ownerToken });
  assert.deepEqual(threads.body, { threads: [{ id: THREAD, title: `Thread ${THREAD}` }] });

  // Explicit chosen-thread fence: no thread, or one the key cannot export, binds nothing.
  const none = await h.api(ampPath(h, "/bindings"), { method: "POST", token: h.ownerToken, body: {} });
  assert.equal(none.status, 400);
  assert.equal(none.body.error, "invalid_thread");
  const unreadable = await h.api(ampPath(h, "/bindings"), { method: "POST", token: h.ownerToken, body: { threadId: THREAD_2 } });
  assert.equal(unreadable.status, 409);
  assert.equal(unreadable.body.error, "amp_thread_unreadable");
  assert.equal((await h.database.query("SELECT 1 FROM amp_bindings")).rows.length, 0);

  const bound = await h.api(ampPath(h, "/bindings"), {
    method: "POST", token: h.ownerToken, body: { thread_id: `https://ampcode.com/threads/${THREAD}` },
  });
  assert.equal(bound.status, 201, bound.text);
  assert.equal(bound.body.thread_id, THREAD);
  const agent = h.world.agents.get(bound.body.agent)!;
  assert.equal(agent.metadata.amp_binding_id, bound.body.binding_id);
  assert.equal(agent.metadata.session_kind, "amp");

  // A different key cannot replace the owner's while a bound thread depends on it.
  const swap = await h.api(ampPath(h, "/connection"), { method: "POST", token: h.ownerToken, body: { key: OTHER_KEY } });
  assert.equal(swap.status, 409);
  assert.equal(swap.body.error, "key_cannot_read_threads");
  // Nor can another admin take the connection over.
  const takeover = await h.api(ampPath(h, "/connection"), { method: "POST", token: h.adminToken, body: { key: AMP_KEY } });
  assert.equal(takeover.status, 409);
  assert.equal(takeover.body.error, "connection_owner_locked");

  const summary = await h.api(ampPath(h), { token: h.adminToken });
  assert.equal(summary.status, 200);
  assert.equal(summary.body.bindings[0].state, "bound");
  assert.equal(summary.body.bindings[0].relaySubscription, "configured");

  const unbound = await h.api(ampPath(h, `/bindings/${bound.body.binding_id}`), { method: "DELETE", token: h.adminToken });
  assert.deepEqual(unbound.body, { disconnected: true });
  assert.equal(h.world.agents.has(bound.body.agent), false, "the Relaycast identity is released");
  assert.equal(h.world.subscriptions.size, 0, "its Relaycast subscriptions are deleted");
  assert.equal((await h.database.query("SELECT 1 FROM amp_bindings")).rows.length, 0);

  await connectAndBind(h, h.ownerToken, THREAD);
  const gone = await h.api(`/cloud${ampPath(h, "/connection")}`, { method: "DELETE", token: h.ownerToken });
  assert.deepEqual(gone.body, { disconnected: true });
  assert.equal((await h.database.query("SELECT 1 FROM amp_connections")).rows.length, 0);
  assert.equal([...h.world.agents.keys()].some((name) => name.startsWith("amp-")), false);
  assert.equal(h.world.subscriptions.size, 0);
  for (const call of h.transport.calls) assert.notEqual(call.operation.kind, "inject", "no lifecycle step prompts Amp");
});

test("amp relay-events verify the stored secret, timestamp and body bound (req 3)", async (t) => {
  const h = await startAmp(t);
  const binding = await connectAndBind(h);
  const body = dmEvent(binding.agent, "m-1");

  // No secret stored: nothing is accepted.
  const [stored] = (await h.database.query<{ hook_ciphertext: string }>("SELECT hook_ciphertext FROM amp_bindings")).rows;
  await h.database.query("UPDATE amp_bindings SET hook_ciphertext = NULL");
  const unset = await postEvent(h, binding.binding_id, body);
  assert.equal(unset.status, 401);
  assert.equal(unset.body.error, "unauthorized");
  await h.database.query("UPDATE amp_bindings SET hook_ciphertext = $1", [stored!.hook_ciphertext]);
  assert.doesNotMatch(stored!.hook_ciphertext, /whsec_/, "the minted secret is encrypted at rest");

  const badSignature = await postEvent(h, binding.binding_id, body, { secret: `whsec_${Buffer.alloc(32, 1).toString("base64")}` });
  assert.equal(badSignature.status, 401);
  const nowSeconds = Math.floor(h.clock.now.getTime() / 1000);
  const stale = await postEvent(h, binding.binding_id, body, { timestamp: nowSeconds - 301 });
  assert.equal(stale.status, 401);
  const oversized = JSON.stringify({ type: "dm.received", data: { pad: "x".repeat(RELAY_EVENT_MAX_BYTES) } });
  const tooLarge = await postEvent(h, binding.binding_id, oversized);
  assert.equal(tooLarge.status, 413);
  assert.equal(tooLarge.body.error, "payload_too_large");
  assert.equal((await h.database.query("SELECT 1 FROM amp_deliveries")).rows.length, 0);

  // Control: the identical body, correctly signed and fresh, queues one delivery.
  const accepted = await postEvent(h, binding.binding_id, body, { timestamp: nowSeconds - 299 });
  assert.deepEqual(accepted.body, { ok: true, queued: true });
  const duplicate = await postEvent(h, binding.binding_id, body);
  assert.deepEqual(duplicate.body, { ok: true, duplicate: true });
  const elsewhere = await postEvent(h, binding.binding_id, dmEvent("someone-else", "m-2"));
  assert.deepEqual(elsewhere.body, { ok: true, delivered: false });
  const self = await postEvent(h, binding.binding_id, dmEvent(binding.agent, "m-3", "echo", binding.agent));
  assert.deepEqual(self.body, { ok: true });
  const unknown = await postEvent(h, "00000000-0000-4000-8000-000000000000", body, { secret: hookSecret(h, binding.binding_id) });
  assert.equal(unknown.status, 410);
  const rows = await h.database.query<{ message_id: string; state: string; payload_ciphertext: string }>(
    "SELECT message_id, state, payload_ciphertext FROM amp_deliveries");
  assert.deepEqual(rows.rows.map((row) => [row.message_id, row.state]), [["m-1", "pending"]]);
  assert.doesNotMatch(rows.rows[0]!.payload_ciphertext, /please review/, "the queued payload is encrypted");
  assert.equal(h.transport.injects().length, 0, "the event route only writes the outbox");
});

test("amp internal job: own secret, inject once, history unavailable without a push session, not on /cloud (req 4, 6)", async (t) => {
  const h = await startAmp(t);
  const binding = await connectAndBind(h);
  await postEvent(h, binding.binding_id, dmEvent(binding.agent, "m-1"));
  const inject = { v: 1, kind: "inject", bindingId: binding.binding_id, messageId: "m-1" };

  assert.equal((await internalJob(h, inject, null)).status, 401);
  assert.equal((await internalJob(h, inject, SERVICE_TOKEN)).status, 403);
  assert.equal((await internalJob(h, inject, BOOTSTRAP)).status, 403);
  const aliased = await internalJob(h, inject, INTERNAL_SECRET, "/cloud/api/v1/internal/amp/job");
  assert.notEqual(aliased.status, 200);
  assert.equal(h.transport.injects().length, 0);
  assert.equal((await internalJob(h, { v: 1, kind: "nope" })).status, 400);

  const done = await internalJob(h, inject);
  assert.deepEqual(done.body, { ok: true, delivered: true });
  assert.equal(h.transport.injects().length, 1);
  const prompt = h.transport.injects()[0]!.operation;
  assert(prompt.kind === "inject");
  assert.equal(prompt.threadId, THREAD);
  assert.match(prompt.text, /^\[via Agent Relay — from "alice" to @amp-[0-9a-f]{16}; message m-1\]/);
  assert.match(prompt.text, /please review$/);
  const again = await internalJob(h, inject);
  assert.deepEqual(again.body, { ok: true, duplicate: true, state: "delivered" });
  assert.equal(h.transport.injects().length, 1, "a delivered message is never injected twice");

  const sweep = await internalJob(h, { v: 1, kind: "sweep" });
  assert.equal(sweep.status, 200);
  assert.equal(sweep.body.deferred, true);
  // No push session in production: the history job names the missing capability.
  const history = await internalJob(h, { v: 1, kind: "history", bindingId: binding.binding_id });
  assert.equal(history.status, 501);
  assert.equal(history.body.error, "history_push_unavailable");
  assert.equal(typeof history.body.message, "string");
  const after = (await h.api(ampPath(h), { token: h.ownerToken })).body;
  assert.deepEqual(after.history, { available: false, reason: "push_session_unavailable" });
  assert.equal(after.bindings[0].history.state, "unavailable");
  assert.equal(after.bindings[0].history.reason, "push_session_unavailable");
  assert.equal(h.transport.calls.filter((call) => call.operation.kind === "export").length, 1,
    "history reads no thread (the only export is bind's proof)");

  // Unset secret: the job surface does not exist.
  const noSecret = await startAmp(t, { amp: ampConfig({ internalSecret: null }) });
  const absent = await internalJob(noSecret, { v: 1, kind: "sweep" });
  assert.equal(absent.status, 404);
  assert.deepEqual(absent.body, NOT_FOUND);
});

test("amp reply bearer: one idempotent reply, refused for wrong binding, revoked, expired and non-member (req 2)", async (t) => {
  const h = await startAmp(t);
  h.world.addAgent("alice");
  const binding = await connectAndBind(h, h.adminToken);
  await postEvent(h, binding.binding_id, dmEvent(binding.agent, "m-1"));
  await internalJob(h, { v: 1, kind: "inject", bindingId: binding.binding_id, messageId: "m-1" });
  const capability = lastReplyCapability(h.transport);
  assert.equal(capability.url, `https://control.selfhosted.company/api/v1/amp/agents/${binding.binding_id}/messages`);
  const stored = await h.database.query<{ reply_hash: string }>("SELECT reply_hash FROM amp_deliveries");
  assert.notEqual(stored.rows[0]!.reply_hash, capability.bearer, "only the bearer hash is stored");
  const path = `/api/v1/amp/agents/${binding.binding_id}/messages`;
  const reply = (body: unknown, bearer = capability.bearer, to = path) =>
    h.api(to, { method: "POST", token: bearer, body });
  const body = { ...capability.request, text: "looks good" };

  assert.equal((await reply(body, `amp_reply_${"A".repeat(43)}`)).status, 401);
  assert.equal((await reply(body, h.ownerToken)).status, 401, "a person token is not a reply capability");
  const otherBinding = await reply(body, capability.bearer, "/api/v1/amp/agents/00000000-0000-4000-8000-000000000000/messages");
  assert.equal(otherBinding.status, 401);
  assert.equal(otherBinding.body.error, "unauthorized");
  const wrongRecipient = await reply({ ...body, to: "mallory" });
  assert.equal(wrongRecipient.status, 403);
  const wrongMessage = await reply({ ...body, message_id: "m-9" });
  assert.equal(wrongMessage.status, 403);

  // Membership is checked on every use: removed (directly, bypassing the
  // purge hook) the bearer is refused; restored, it works again.
  await h.database.exec(`CREATE TEMP TABLE saved_membership AS SELECT * FROM organization_memberships WHERE user_id = '${h.adminId}'`);
  await h.database.query("DELETE FROM organization_memberships WHERE user_id = $1", [h.adminId]);
  const nonMember = await reply(body);
  assert.equal(nonMember.status, 401);
  await h.database.exec("INSERT INTO organization_memberships SELECT * FROM saved_membership");
  const sent = await reply(body);
  assert.equal(sent.status, 200, sent.text);
  assert.equal(sent.body.ok, true);
  const dm = h.world.messages.get(sent.body.message_id)!;
  assert.equal(dm.agent_name, binding.agent);
  assert.equal(dm.text, "looks good");
  assert.deepEqual((await reply(body)).body, { ok: true, duplicate: true, message_id: sent.body.message_id });
  assert.equal((await reply({ ...body, text: "changed my mind" })).body.error, "reply_already_sent");
  assert.equal([...h.world.messages.values()].filter((row) => row.agent_name === binding.agent).length, 1);

  // Expiry: 24 hours after the claim the capability is dead.
  h.clock.now = new Date(h.clock.now.getTime() + 24 * 60 * 60 * 1000 + 1);
  assert.equal((await reply(body)).status, 401);
  h.clock.now = new Date(h.clock.now.getTime() - 24 * 60 * 60 * 1000 - 1);
  assert.equal((await reply(body)).status, 200);

  // Revocation: unbinding clears every reply capability.
  await h.api(ampPath(h, `/bindings/${binding.binding_id}`), { method: "DELETE", token: h.ownerToken });
  const revoked = await reply(body);
  assert.equal(revoked.status, 401);
  assert.equal(revoked.body.message, "Invalid or revoked reply capability.");
});

test("amp check_delivery settles unknown only from the thread's own marker (req 1, 4)", async (t) => {
  const h = await startAmp(t);
  const binding = await connectAndBind(h);
  // The transport accepts the prompt but the response is lost.
  let lose = true;
  h.transport.hooks.inject = async (call) => {
    if (!lose) return;
    const thread = h.transport.threads.get(THREAD)!;
    if (call.operation.kind === "inject") {
      thread.messages.push({ messageID: "msg-x", role: "user", content: call.operation.text, createdAt: "2026-11-08T00:00:01.000Z" });
    }
    return { ok: false, outcome: "unknown" };
  };
  await postEvent(h, binding.binding_id, dmEvent(binding.agent, "m-1"));
  const job = await internalJob(h, { v: 1, kind: "inject", bindingId: binding.binding_id, messageId: "m-1" });
  assert.deepEqual(job.body, { ok: true, delivered: false, outcome: "unknown" });
  // Unknown is held: a redelivered event and another job never resend it.
  assert.deepEqual((await postEvent(h, binding.binding_id, dmEvent(binding.agent, "m-1"))).body, { ok: true, duplicate: true });
  await internalJob(h, { v: 1, kind: "inject", bindingId: binding.binding_id, messageId: "m-1" });
  await internalJob(h, { v: 1, kind: "sweep" });
  assert.equal(h.transport.injects().length, 1);
  lose = false;

  const check = (messageId: string, token = h.ownerToken) =>
    h.api(ampPath(h, `/bindings/${binding.binding_id}/deliveries/${messageId}/check`), { method: "POST", token });
  assert.equal((await check("m-1", h.memberToken)).status, 403);
  assert.equal((await check("m-404")).body.error, "delivery_not_found");

  // A queued message with no marker in the thread stays unconfirmed.
  await postEvent(h, binding.binding_id, dmEvent(binding.agent, "m-2"));
  await h.database.query("UPDATE amp_deliveries SET state = 'unknown' WHERE message_id = 'm-2'");
  assert.deepEqual((await check("m-2")).body, { confirmed: false, state: "unknown" });
  const confirmed = await check("m-1");
  assert.deepEqual(confirmed.body, { confirmed: true, state: "delivered" });
  assert.equal(h.transport.injects().length, 1, "check_delivery is read-only");
});

test("amp reconcileDelivery settles every outcome from the marker alone and never re-sends", async (t) => {
  const h = await startAmp(t);
  const deps = h.amp!.deps;
  const binding = await connectAndBind(h);
  const check = (messageId: string) =>
    h.api(ampPath(h, `/bindings/${binding.binding_id}/deliveries/${messageId}/check`), { method: "POST", token: h.ownerToken });
  const row = async (messageId: string) => (await h.database.query<{
    state: string; code: string | null; lease_owner: string | null; payload_ciphertext: string | null;
  }>("SELECT state, code, lease_owner, payload_ciphertext FROM amp_deliveries WHERE message_id = $1", [messageId])).rows[0]!;
  const setState = (messageId: string, state: string, extra = "") => h.database.query(
    `UPDATE amp_deliveries SET state = $2, code = 'test'${extra} WHERE message_id = $1`, [messageId, state]);

  // m-1 reaches the thread (its marker is in the export); m-2 is queued but never sent.
  await postEvent(h, binding.binding_id, dmEvent(binding.agent, "m-1", "secret body"));
  await internalJob(h, { v: 1, kind: "inject", bindingId: binding.binding_id, messageId: "m-1" });
  await postEvent(h, binding.binding_id, dmEvent(binding.agent, "m-2"));
  assert.equal(h.transport.injects().length, 1);

  // delivered stays delivered.
  assert.deepEqual((await check("m-1")).body, { confirmed: true, state: "delivered" });
  // rejected or unknown with the marker: settled delivered, the text dropped (sender only).
  for (const state of ["rejected", "unknown"]) {
    await setState("m-1", state);
    assert.deepEqual((await check("m-1")).body, { confirmed: true, state: "delivered" });
    const settled = await row("m-1");
    assert.equal(settled.code, null);
    assert.deepEqual(JSON.parse(decrypt(deps, settled.payload_ciphertext!)), { sender: "alice" });
  }
  // pending with the marker (a requeued row that had in fact landed): settled, so the drain cannot resend it.
  await setState("m-1", "pending");
  assert.deepEqual((await check("m-1")).body, { confirmed: true, state: "delivered" });
  assert.equal((await claimNext(deps, { bindingId: binding.binding_id, messageId: "m-1" })), null);
  // A live lease is left to the worker's own finalize.
  await setState("m-1", "sending", ", lease_owner = gen_random_uuid(), lease_until = now() + interval '1 hour'");
  assert.deepEqual((await check("m-1")).body, { confirmed: true, state: "sending" });
  assert.notEqual((await row("m-1")).lease_owner, null);
  await setState("m-1", "delivered", ", lease_owner = NULL, lease_until = NULL");

  // No marker: unconfirmed, the state unchanged, nothing sent.
  for (const state of ["pending", "unknown", "rejected"]) {
    await setState("m-2", state);
    assert.deepEqual((await check("m-2")).body, { confirmed: false, state });
  }
  assert.equal(h.transport.injects().length, 1, "reconciliation is read-only: absence never re-sends");

  // The binding retired or rebound while the export ran: nothing is written.
  await setState("m-1", "unknown");
  h.transport.hooks.export = async () => {
    await h.database.query("UPDATE amp_bindings SET generation = generation + 1 WHERE id = $1", [binding.binding_id]);
  };
  const raced = await check("m-1");
  assert.equal(raced.status, 404);
  assert.deepEqual(raced.body, { error: "binding_not_found", message: "Binding not found." });
  assert.equal((await row("m-1")).state, "unknown");
  delete h.transport.hooks.export;

  // A workspace whose relay moved refuses before any export.
  const exports = h.transport.calls.filter((call) => call.operation.kind === "export").length;
  await h.database.query("UPDATE workspaces SET relaycast_workspace_id = 'rc-moved' WHERE id = $1", [h.workspaceId]);
  const moved = await check("m-1");
  assert.equal(moved.status, 409);
  assert.deepEqual(moved.body, { error: "relay_changed", message: "The bound relay is unavailable." });
  assert.equal(h.transport.calls.filter((call) => call.operation.kind === "export").length, exports);
  assert.deepEqual((await check("not a valid id!")).body.error, "invalid_request");
});

test("amp MCP tools exist only when enabled and authorize the connection's person (req 7)", async (t) => {
  assert.equal(planToolGroups().some((entry) => entry.group === "amp"), false);
  assert.deepEqual(planToolGroups({ amp: true }).find((entry) => entry.group === "amp")?.tools,
    ["list_amp_threads", "bind_amp_thread", "unbind_amp_thread"]);

  const h = await startAmp(t);
  await connectAndBind(h);
  type Tool = { schema: { inputSchema: Record<string, unknown> }; handler: (args: any) => Promise<any> };
  const toolsFor = (userId: string) => {
    const tools = new Map<string, Tool>();
    const server = { registerTool: (name: string, schema: Tool["schema"], handler: Tool["handler"]) => tools.set(name, { schema, handler }) };
    const context = {
      principal: { userId, workspaceId: h.workspaceId, organizationId: h.organizationId, role: "owner", scopes: ["cli:auth"] },
      workspace: { id: h.workspaceId, organizationId: h.organizationId },
    } as unknown as McpContext;
    registerAmpTools(server as never, context, h.amp!.deps);
    return tools;
  };
  const memberTools = toolsFor(h.memberId);
  for (const tool of memberTools.values()) {
    assert.equal(Object.keys(tool.schema.inputSchema).some((key) => /user|role|workspace|org/i.test(key)), false,
      "no tool accepts an identity argument");
  }
  // The member's MCP context claims role "owner"; the database role decides.
  const refused = await memberTools.get("list_amp_threads")!.handler({});
  assert.equal(refused.isError, true);
  assert.equal(refused.content[0].text, "Only current owners and admins using a person connection can manage Amp.");
  const listed = await toolsFor(h.ownerId).get("list_amp_threads")!.handler({});
  assert.equal(listed.isError, undefined);
  assert.deepEqual(JSON.parse(listed.content[0].text), [{ id: THREAD, title: `Thread ${THREAD}` }]);
  const adminBind = await toolsFor(h.adminId).get("bind_amp_thread")!.handler({ thread_id: THREAD });
  assert.equal(adminBind.isError, true, "an admin who did not connect the key cannot bind with it");
});

test("amp never returns stored secrets in summaries or errors (req 9)", async (t) => {
  const h = await startAmp(t);
  const binding = await connectAndBind(h);
  const summary = await h.api(ampPath(h), { token: h.ownerToken });
  assert.equal(summary.body.bindings[0].relaySubscription, "configured");
  for (const secret of [AMP_KEY, hookSecret(h, binding.binding_id), "whsec_", "rk_live_primary", "at_amp-"]) {
    assert.equal(summary.text.includes(secret), false);
  }
  const failure = await h.api(ampPath(h, "/nope"), { token: h.ownerToken });
  assert.deepEqual(Object.keys(failure.body).sort(), ["error", "message"]);
});

const WHSEC = /^whsec_[A-Za-z0-9+/]{43}=$/;

test("amp bind creates both Relaycast subscriptions with the workspace key and stores their ids", async (t) => {
  const h = await startAmp(t);
  h.transport.addThread(THREAD, AMP_KEY);
  await h.api(ampPath(h, "/connection"), { method: "POST", token: h.ownerToken, body: { key: AMP_KEY } });
  const bound = await h.api(ampPath(h, "/bindings"), { method: "POST", token: h.ownerToken, body: { threadId: THREAD } });
  assert.equal(bound.status, 201, bound.text);
  const { binding_id: id, agent } = bound.body as { binding_id: string; agent: string };

  const subscriptions = subscriptionsFor(h, id);
  assert.equal(subscriptions.length, 2);
  const [direct, mention] = subscriptions;
  const url = `https://control.selfhosted.company/api/v1/amp/relay-events/${id}`;
  assert.deepEqual(direct!.events, ["dm.received", "thread.reply"]);
  assert.equal(direct!.filter, null);
  assert.deepEqual(mention!.events, ["message.created"]);
  assert.deepEqual(mention!.filter, { mentions: agent });
  for (const subscription of subscriptions) {
    assert.equal(subscription.url, url);
    assert.equal(subscription.signature_scheme, "standard-webhooks");
    assert.equal(subscription.workspaceKey, "rk_live_primary", "created with the workspace key, not an agent token");
  }
  const secret = hookSecret(h, id);
  assert.match(secret, WHSEC);
  assert.equal(Buffer.from(secret.slice("whsec_".length), "base64").byteLength, 32);

  const row = (await h.database.query<{ subscription_id: string; mention_subscription_id: string; hook_ciphertext: string; state: string }>(
    "SELECT subscription_id, mention_subscription_id, hook_ciphertext, state FROM amp_bindings")).rows[0]!;
  assert.deepEqual([row.subscription_id, row.mention_subscription_id, row.state], [direct!.id, mention!.id, "bound"]);
  assert.doesNotMatch(row.hook_ciphertext, /whsec_/, "the minted secret is encrypted at rest");

  const summary = await h.api(ampPath(h), { token: h.ownerToken });
  assert.equal(summary.body.bindings[0].relaySubscription, "configured");
  for (const text of [bound.text, summary.text]) assert.doesNotMatch(text, /whsec_/);

  // An event signed with the minted secret is accepted.
  assert.deepEqual((await postEvent(h, id, dmEvent(agent, "m-1"))).body, { ok: true, queued: true });

  // Re-binding the bound thread creates nothing new.
  const again = await h.api(ampPath(h, "/bindings"), { method: "POST", token: h.ownerToken, body: { threadId: THREAD } });
  assert.equal(again.status, 201);
  assert.equal(h.world.subscriptions.size, 2);

  // Manual subscription entry no longer exists.
  for (const method of ["PUT", "POST", "GET"]) {
    const manual = await h.api(ampPath(h, `/bindings/${id}/relay-subscription`), {
      method, token: h.ownerToken, ...(method === "GET" ? {} : { body: { secret } }),
    });
    assert.equal(manual.status, 404, method);
    assert.equal(manual.body.error, "not_found");
  }
  assert.equal(hookSecret(h, id), secret, "the secret is unchanged");
});

test("amp bind: a failed subscription create fails the bind, deletes what it created, and a retry succeeds", async (t) => {
  const h = await startAmp(t);
  h.transport.addThread(THREAD, AMP_KEY);
  await h.api(ampPath(h, "/connection"), { method: "POST", token: h.ownerToken, body: { key: AMP_KEY } });
  const bind = () => h.api(ampPath(h, "/bindings"), { method: "POST", token: h.ownerToken, body: { threadId: THREAD } });
  const row = async () => (await h.database.query<{
    id: string; state: string; token_ciphertext: string | null; subscription_id: string | null; mention_subscription_id: string | null;
  }>("SELECT id, state, token_ciphertext, subscription_id, mention_subscription_id FROM amp_bindings")).rows[0]!;
  const creates = () => h.world.bodies.filter((call) => call.method === "POST" && call.path === "/v1/subscriptions");
  const registrations = () => h.world.bodies.filter((call) => call.method === "POST" && call.path === "/v1/agents");
  const assertFailed = (response: Awaited<ReturnType<typeof bind>>) => {
    assert.equal(response.status, 502, response.text);
    assert.deepEqual(Object.keys(response.body).sort(), ["error", "message"]);
    assert.equal(response.body.error, "relay_subscription_failed");
    assert.doesNotMatch(response.text, /whsec_|rk_live/);
  };

  // The first create fails.
  h.world.failNext("POST", "/v1/subscriptions", 503);
  assertFailed(await bind());
  let current = await row();
  assert.equal(current.state, "preparing");
  assert.notEqual(current.token_ciphertext, null, "the registered agent is kept for the retry");
  assert.deepEqual([current.subscription_id, current.mention_subscription_id], [null, null]);
  assert.equal(h.world.subscriptions.size, 0);
  assert.equal((await h.api(ampPath(h), { token: h.ownerToken })).body.bindings[0].relaySubscription, "not_configured");
  assert.equal((await postEvent(h, current.id, dmEvent(`amp-x`, "m-0"), {
    secret: creates()[0]!.body!.secret,
  })).status, 410, "a preparing binding accepts no events");

  // The second create fails: the first one, already created upstream, is deleted.
  const handle = h.world.handle;
  let seen = 0;
  h.world.handle = async (method, path, ...rest) => {
    if (method === "POST" && path === "/v1/subscriptions" && ++seen === 2) {
      return { status: 503, body: { ok: false, error: { code: "unavailable" } } };
    }
    return handle(method, path, ...rest);
  };
  assertFailed(await bind());
  h.world.handle = handle;
  current = await row();
  assert.equal(current.state, "preparing");
  assert.deepEqual([current.subscription_id, current.mention_subscription_id], [null, null]);
  assert.equal(h.world.subscriptions.size, 0, "the first subscription was deleted");
  const deletes = h.world.bodies.filter((call) => call.method === "DELETE" && call.path.startsWith("/v1/subscriptions/"));
  assert.equal(deletes.length, 1);

  // The retry reuses the agent and the minted secret and finishes the bind.
  const retried = await bind();
  assert.equal(retried.status, 201, retried.text);
  current = await row();
  assert.equal(current.state, "bound");
  const subscriptions = subscriptionsFor(h, current.id);
  assert.deepEqual([current.subscription_id, current.mention_subscription_id], subscriptions.map((sub) => sub.id));
  assert.equal(registrations().length, 1, "one Relaycast agent across all attempts");
  assert.equal(new Set(creates().map((call) => call.body!.secret)).size, 1, "every attempt sent the same minted secret");
  assert.equal((await h.api(ampPath(h), { token: h.ownerToken })).body.bindings[0].relaySubscription, "configured");
});

test("amp bind: a failed update after creating subscriptions deletes them and the row stays retryable", async (t) => {
  const h = await startAmp(t);
  h.transport.addThread(THREAD, AMP_KEY);
  await h.api(ampPath(h, "/connection"), { method: "POST", token: h.ownerToken, body: { key: AMP_KEY } });
  await h.database.exec(`
    CREATE FUNCTION amp_test_refuse_mention() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      IF NEW.mention_subscription_id IS NOT NULL THEN RAISE EXCEPTION 'refused'; END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER amp_test_refuse_mention BEFORE UPDATE ON amp_bindings
      FOR EACH ROW EXECUTE FUNCTION amp_test_refuse_mention();`);
  const bind = () => h.api(ampPath(h, "/bindings"), { method: "POST", token: h.ownerToken, body: { threadId: THREAD } });
  const failed = await bind();
  assert.ok(failed.status >= 500, failed.text);
  assert.doesNotMatch(failed.text, /whsec_/);
  assert.equal(h.world.bodies.filter((call) => call.method === "POST" && call.path === "/v1/subscriptions").length, 2);
  assert.equal(h.world.subscriptions.size, 0, "both created subscriptions were deleted");
  const row = (await h.database.query<{ state: string; subscription_id: string | null }>(
    "SELECT state, subscription_id FROM amp_bindings")).rows[0]!;
  assert.deepEqual(row, { state: "preparing", subscription_id: null });

  await h.database.exec("DROP TRIGGER amp_test_refuse_mention ON amp_bindings");
  assert.equal((await bind()).status, 201);
  assert.equal(h.world.subscriptions.size, 2);
});

test("amp unbind deletes both subscriptions before releasing the agent; a failed delete keeps locators for the worker", async (t) => {
  const h = await startAmp(t);
  const binding = await connectAndBind(h);
  const [direct, mention] = subscriptionsFor(h, binding.binding_id);
  const from = h.world.bodies.length;
  h.world.failNext("DELETE", `/v1/subscriptions/${mention!.id}`, 503);
  const unbound = await h.api(ampPath(h, `/bindings/${binding.binding_id}`), { method: "DELETE", token: h.ownerToken });
  assert.deepEqual(unbound.body, { disconnected: true, cleanup: "pending" });
  const row = (await h.database.query<{
    state: string; agent_remote_id: string | null; subscription_id: string | null; mention_subscription_id: string | null;
    hook_ciphertext: string | null; last_error: string | null;
  }>("SELECT state, agent_remote_id, subscription_id, mention_subscription_id, hook_ciphertext, last_error FROM amp_bindings")).rows[0]!;
  assert.equal(row.state, "retired");
  assert.equal(row.subscription_id, null, "the deleted subscription's id is cleared");
  assert.equal(row.mention_subscription_id, mention!.id, "the undeleted subscription's id is kept for the retry");
  assert.notEqual(row.agent_remote_id, null);
  assert.equal(row.hook_ciphertext, null, "the relay-events secret is revoked at once");
  assert.match(row.last_error ?? "", /^release_pending/);
  assert.equal(h.world.subscriptions.has(direct!.id), false);
  assert.equal(h.world.agents.has(binding.agent), true, "the agent is not released while a subscription remains");
  assert.equal(h.world.bodies.slice(from).some((call) => call.path === "/v1/agents/release-exact"), false);

  // The worker's retired-row retry finishes the cleanup, subscriptions first.
  const worker = startAmpWorker(h.amp!.deps, 600_000);
  t.after(() => worker.stop());
  await worker.tick();
  assert.equal(h.world.subscriptions.size, 0);
  assert.equal(h.world.agents.has(binding.agent), false);
  assert.equal((await h.database.query("SELECT 1 FROM amp_bindings")).rows.length, 0);
  const calls = h.world.bodies.slice(from).map((call) => `${call.method} ${call.path}`);
  const release = calls.indexOf("POST /v1/agents/release-exact");
  assert.ok(release > 0);
  assert.deepEqual(calls.slice(0, release).filter((call) => call.startsWith("DELETE /v1/subscriptions/")), [
    `DELETE /v1/subscriptions/${direct!.id}`,
    `DELETE /v1/subscriptions/${mention!.id}`,
    `DELETE /v1/subscriptions/${mention!.id}`,
  ]);
  assert.equal(calls.slice(release).some((call) => call.startsWith("DELETE /v1/subscriptions/")), false);

  // Subscriptions already gone upstream (404) do not block cleanup.
  const second = await connectAndBind(h);
  h.world.subscriptions.clear();
  const tolerated = await h.api(ampPath(h, `/bindings/${second.binding_id}`), { method: "DELETE", token: h.ownerToken });
  assert.deepEqual(tolerated.body, { disconnected: true });
  assert.equal(h.world.agents.has(second.agent), false);
  assert.equal((await h.database.query("SELECT 1 FROM amp_bindings")).rows.length, 0);
});
