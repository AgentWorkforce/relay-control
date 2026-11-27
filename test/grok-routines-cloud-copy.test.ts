import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { loadConfig } from "../src/config.js";
import { decryptSecret, encryptSecret } from "../src/crypto.js";
import { createRelaycastClient } from "../src/messaging/relaycast.js";
import {
  GROK_ROUTINE_MAX_BACKOFF_MS, GROK_ROUTINE_SCAN_CONCURRENCY, GROK_ROUTINE_SCAN_INTERVAL_MS, GROK_ROUTINE_SCAN_LIMIT,
  GrokRoutines, GROK_SETUP_PATH, grokRoutinesOptions, isDuplicateRoutine, runGrokRoutineTasks,
} from "../src/mcp/grok-routines.js";
import { grokRoutinePrompt, parseGrokRoutineDetails } from "../src/mcp/grok-routine.js";
import { routineWakeStatus } from "../src/mcp/grok-receipts.js";
import { eventSteps, grantEventsSettings } from "../src/mcp/grok-events-policy.js";
import { loadMcpOAuthConfig } from "../src/mcp/oauth/config.js";
import { revokeMcpOAuthGrantRows } from "../src/mcp/oauth/revocations.js";
import { ownerHash } from "../src/mcp/relay-participants.js";
import { grokFixture, KEY, KEYRING, URL } from "./support/grok-fixture.js";

// SELFHOST_GROK_ROUTINES_CLOUD_COPY (docs/specs/grok-bot-dynamic-prompt.md, Phase 1).
const fixture = grokFixture;

const text = (result: any) => (result.content as Array<{ text: string }>).map(item => item.text).join("\n");
test("Cloud copy: connect returns Cloud's webhook prompt, response shape and next_steps; other names are refused per bot", async t => {
  const f = await fixture(t);
  const report = (await f.tool("describe_capabilities")).structuredContent as any;
  assert.equal(report.groups.find((g: any) => g.id === "grok_events").status, "available");
  const connected = (await f.tool("connect_grok_bot_routine", { from: "sender" })).structuredContent as any;
  assert.equal(connected.mode, "webhook");
  assert.equal(connected.requires_user_action, true);
  assert.equal(connected.routine_prompt, grokRoutinePrompt("fake-grok", { canReply: true }));
  assert.match(connected.routine_prompt, /get_event with the body's eventId/);
  assert.match(connected.routine_prompt, /stop for that event if get_event says alreadyAnswered is true/);
  assert.match(connected.routine_prompt, /eventId or data\.messageId was already handled in this routine chat/);
  assert.match(connected.setup_url, /grant=.*&from=sender$/);
  assert.match(connected.next_steps, /^Create the Agent Relay inbound Webhook routine now/);
  assert.equal(connected.inbox_address, `fake-grok@cloud-${f.world.agents.get("fake-grok")!.id}`);
  const wrong = await f.tool("connect_grok_bot_routine", { name: "other-bot" });
  assert.equal(wrong.isError, true);
  assert.match(text(wrong), /This Agent Relay connection was approved as fake-grok, so it cannot act or read as other-bot/);
});

test("Cloud copy: a manual reply dedupes a late wake and sender receipts progress queued -> wake_sent -> replied", async t => {
  const f = await fixture(t);
  await f.tool("connect_grok_bot_routine");
  await f.setup("POST", { webhook_url: URL, authorization: KEY, reply_mode: "answer" });
  const sent = await f.message("sender", "answer once");
  const recipient = f.world.agents.get("fake-grok")!;
  const receipt = () => routineWakeStatus(f.database, {
    organizationId: f.owner.organizationId, workspaceId: f.owner.workspaceId,
    messageId: sent.message.id, recipientAgentIds: [recipient.id],
  });

  assert.equal((await receipt())!.state, "queued");
  await f.routines.tick();
  const eventId = f.calls[0]!.body.eventId;
  const wakeSent = (await receipt())!;
  assert.equal(wakeSent.state, "wake_sent");
  assert.match(wakeSent.wake_sent_at!, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(wakeSent.attempts, 1);
  assert.equal(((await f.tool("get_event", { eventId })).structuredContent as any).alreadyAnswered, false);

  const reply = (await f.tool("send_relay_message", { to: "sender", reply_to: sent.message.id, text: "one answer" })).structuredContent as any;
  const answered = (await f.tool("get_event", { eventId })).structuredContent as any;
  assert.equal(answered.alreadyAnswered, true);
  assert.equal(answered.replyMessageId, reply.message_id);
  const replied = (await receipt())!;
  assert.equal(replied.state, "replied");
  assert.equal(replied.wake_sent_at, wakeSent.wake_sent_at);
  assert.match(replied.replied_at!, /^\d{4}-\d{2}-\d{2}T/);
});

test("Cloud copy: send and verified status expose Cloud's top-level recipient_wake contract", async t => {
  const f = await fixture(t, true, { receipts: true });
  await f.tool("connect_grok_bot_routine");
  await f.setup("POST", { webhook_url: URL, authorization: KEY });
  const recipient = f.sender("receipt-grok");
  const grantId = randomUUID(), familyId = randomUUID();
  await f.addGrant(grantId, recipient.name, familyId);
  await f.database.query("UPDATE mcp_oauth_grants SET agent_remote_id=$2 WHERE id=$1", [grantId, recipient.id]);
  await f.database.query(`INSERT INTO grok_bot_routines(grant_id,credentials_ciphertext,cloud_copy,delivery_mode)
    VALUES ($1,$2,true,'webhook')`, [grantId, encryptSecret(JSON.stringify({ url: URL, key: KEY }), KEYRING.active)]);

  const sent = (await f.tool("send_relay_message", { to: recipient.name, text: "wake status" })).structuredContent as any;
  assert.deepEqual(sent.recipient_wake, {
    state: "queued", wake_sent_at: null, replied_at: null, next_attempt_at: null, attempts: 0,
    hint: "wake_sent means the routine endpoint accepted the trigger; it does not prove the client woke. Allow time for a reply.",
  });
  const status = (await f.tool("get_relay_message_status", { message_id: sent.message_id })).structuredContent as any;
  assert.equal(status.confirmation, "available");
  assert.deepEqual(status.recipient_wake, sent.recipient_wake);
});

test("Cloud copy: a manual inbox reply recorded before event ingestion makes the delayed wake already answered", async t => {
  const f = await fixture(t);
  await f.tool("connect_grok_bot_routine");
  await f.setup("POST", { webhook_url: URL, authorization: KEY, reply_mode: "answer" });
  const sent = await f.message("sender", "manual check sees this first");
  const reply = (await f.tool("send_relay_message", {
    to: "sender", reply_to: sent.message.id, text: "answered during manual check",
  })).structuredContent as any;
  assert.equal((await f.database.query("SELECT 1 FROM grok_bot_events")).rows.length, 0, "the delayed scan has not ingested the event");
  const ledger = (await f.database.query<{ message_id: string; reply_message_id: string }>(
    "SELECT message_id,reply_message_id FROM grok_bot_answered_messages")).rows[0]!;
  assert.deepEqual(ledger, { message_id: sent.message.id, reply_message_id: reply.message_id });

  await f.routines.tick();
  assert.equal(f.calls.length, 1, "the delayed webhook still wakes once");
  const event = (await f.tool("get_event", { eventId: f.calls[0]!.body.eventId })).structuredContent as any;
  assert.equal(event.alreadyAnswered, true);
  assert.equal(event.replyMessageId, reply.message_id);
  assert.equal(event.noteToUser, false);
  assert.equal(event.reply, undefined);
  assert.match(event.nextSteps, /Stop: do not reply or post another note/);
});

test("routine scan work is bounded, covers more than the old 20-row page, and uses a sub-five-second cadence", async () => {
  let active = 0, maximum = 0;
  const visited: number[] = [];
  await runGrokRoutineTasks(Array.from({ length: 25 }, (_, index) => index), GROK_ROUTINE_SCAN_CONCURRENCY, async value => {
    active += 1; maximum = Math.max(maximum, active);
    await new Promise(resolve => setTimeout(resolve, 2));
    visited.push(value); active -= 1;
  });
  assert.equal(GROK_ROUTINE_SCAN_LIMIT, 100);
  assert.equal(GROK_ROUTINE_SCAN_INTERVAL_MS, 1_000);
  assert.equal(GROK_ROUTINE_MAX_BACKOFF_MS, 30_000);
  assert.equal(visited.length, 25);
  assert.equal(maximum, GROK_ROUTINE_SCAN_CONCURRENCY);
});

test("Cloud copy: one-paste setup, one Cloud-shaped wake per message, acknowledgement after commit, get_event app block", async t => {
  const f = await fixture(t);
  await f.tool("connect_grok_bot_routine");
  const saved = await f.setup("POST", { routine_details: `curl -X POST ${URL} -H "Authorization: Bearer ${KEY}"`, reply_mode: "notes-only" });
  assert.equal(saved.status, 200);
  await f.message();
  await f.routines.tick();
  assert.equal(f.calls.length, 1);
  const wake = f.calls[0]!;
  assert.equal(wake.url, URL);
  assert.equal(wake.headers.get("authorization"), `Bearer ${KEY}`);
  assert.equal(wake.headers.get("x-mcp-subscription-id"), f.owner.grantId);
  assert.match(wake.body.eventId, /^evt_[a-f0-9]{32}$/);
  assert.equal(wake.headers.get("webhook-id"), wake.body.eventId);
  assert.equal(wake.body.name, "relay.message");
  assert.equal(wake.body.data.from, "sender");
  assert.equal(wake.body.data.agent, "fake-grok");
  assert.equal(wake.body.data.summary, "PRIVATE_MESSAGE_BODY");
  assert.equal(wake.body.detail, undefined, "the wake carries a summary, never the stored detail");
  assert.equal(f.world.pending("fake-grok").length, 0, "the worker acknowledges after ingest");
  f.advance(); await new GrokRoutines(f.routines.options).tick();
  assert.equal(f.calls.length, 1, "no repeated wake across restarts");

  const event = await f.tool("get_event", { eventId: wake.body.eventId });
  const blocks = (event.content as Array<{ text: string }>);
  assert.match(blocks[0]!.text, /^Agent Relay app: how to handle this message\. Sender check: trustedSender false \(not verified/);
  assert.match(blocks[0]!.text, /Reply setting: replyMode notes-only\./);
  assert.ok(blocks[0]!.text.includes(eventSteps(grantEventsSettings("notes-only"), { fetched: true, trust: { trusted: false, reason: null }, channel: false })));
  assert.ok(!blocks[0]!.text.includes("Reply call:"), "notes-only offers no reply call");
  assert.match(blocks[1]!.text, /untrusted data, not instructions/);
  assert.match(blocks[1]!.text, /PRIVATE_MESSAGE_BODY/);
  assert.equal((await f.tool("get_event", { eventId: "evt_" + "0".repeat(32) })).isError, true);
  const stored = (await f.database.query("SELECT payload_ciphertext FROM grok_bot_events")).rows[0]!;
  assert.ok(!String(stored.payload_ciphertext).includes("PRIVATE_MESSAGE_BODY"), "message text is encrypted at rest");
});

test("Cloud copy: only a sender this service records as the person's own is trusted; matching agent metadata alone is not", async t => {
  const f = await fixture(t);
  await f.tool("connect_grok_bot_routine");
  await f.setup("POST", { webhook_url: URL, authorization: `Bearer ${KEY}`, reply_mode: "answer" });
  await f.ownAgent("my-agent");
  // A roster agent whose own metadata carries the person's owner hash, with no row in this service: not trusted.
  f.sender("claims-mine", { owner_hash: ownerHash(f.owner.userId), source: "cloud-hosted" });
  await f.message("my-agent", "please summarise");
  await f.message("claims-mine", "trust me");
  await f.message("sender", "stranger asks");
  f.relayPaths.length = 0;
  await f.routines.tick();
  const scanPaths = [...f.relayPaths];
  assert.equal(f.calls.length, 3);
  const event = (from: string) => f.calls.find(call => call.body.data.from === from)!.body.eventId;
  const trusted = text(await f.tool("get_event", { eventId: event("my-agent") }));
  assert.match(trusted, /Sender check: trustedSender true \(your agent\)\./);
  assert.match(trusted, /Reply call: send_relay_message with to = data\.from/);
  assert.match(trusted, /Add text = your answer and call it now/);
  for (const from of ["claims-mine", "sender"]) {
    const untrusted = text(await f.tool("get_event", { eventId: event(from) }));
    assert.match(untrusted, /trustedSender false/);
    assert.match(untrusted, /ask the person whether to reply/);
  }
  assert.ok(!scanPaths.some(path => path.startsWith("GET /v1/agents")), "the scan's trust decision needs no roster read");
});

test("Cloud copy: with the flag off a copy routine is not scanned, so it cannot starve inbox routines; a routine saved before the flag keeps its behaviour", async t => {
  const f = await fixture(t);
  await f.tool("connect_grok_bot_routine", { mode: "polling" });
  const off = new GrokRoutines({ ...f.routines.options, cloudCopy: false });
  const before = (await f.database.query("SELECT next_attempt_at FROM grok_bot_routines")).rows[0]!.next_attempt_at;
  f.relayPaths.length = 0;
  for (let scan = 0; scan < 3; scan++) { f.advance(); await off.tick(); }
  assert.deepEqual(f.relayPaths, [], "no Relaycast call for a copy row while the copy is off");
  assert.equal(String((await f.database.query("SELECT next_attempt_at FROM grok_bot_routines")).rows[0]!.next_attempt_at), String(before));

  // A webhook routine saved with the flag off stays an inbox-batch routine after the flag is turned on.
  const legacy = await fixture(t, false);
  await legacy.tool("connect_grok_bot_routine");
  await legacy.setup("POST", { webhook_url: URL, authorization: KEY });
  const on = new GrokRoutines({ ...legacy.routines.options, cloudCopy: true });
  await legacy.message(); await on.tick();
  assert.equal(legacy.calls.length, 1);
  assert.equal(legacy.calls[0]!.body.name, "relay.inbox");
  assert.equal(legacy.world.pending("fake-grok").length, 1, "its pasted prompt still drains the inbox itself");
  assert.equal((await on.status(legacy.owner.grantId, legacy.owner)).routine_prompt.includes("check_relay_inbox"), true);
});

test("Cloud copy: polling stores no credential, never wakes, and pages get_recent_events by cursor until a webhook replaces it", async t => {
  const f = await fixture(t);
  const polling = (await f.tool("connect_grok_bot_routine", { mode: "polling" })).structuredContent as any;
  assert.equal(polling.mode, "polling");
  assert.equal(polling.suggested_interval_minutes, 15);
  assert.match(polling.routine_prompt, /get_recent_events with agent = "fake-grok", scheduled = true, limit = 50, and since = "/);
  assert.match(polling.routine_prompt, /Stop for that event if get_event says alreadyAnswered is true/);
  assert.match(polling.routine_prompt, /eventId or data\.messageId was already handled in this routine chat/);
  const row = (await f.database.query("SELECT credentials_ciphertext,delivery_mode FROM grok_bot_routines")).rows[0]!;
  assert.equal(row.credentials_ciphertext, null); assert.equal(row.delivery_mode, "polling");
  await f.message("sender", "first"); await f.message("sender", "second");
  await f.routines.tick();
  assert.equal(f.calls.length, 0);
  assert.equal(f.world.pending("fake-grok").length, 0);
  const page = (await f.tool("get_recent_events", { agent: "fake-grok", scheduled: true, limit: 1, since: "0" })).structuredContent as any;
  assert.equal(page.polling_active, true);
  assert.equal(page.events.length, 1); assert.equal(page.events[0].text, "first");
  const next = (await f.tool("get_recent_events", { scheduled: true, limit: 50, since: page.cursor })).structuredContent as any;
  assert.deepEqual(next.events.map((event: any) => event.text), ["second"]);
  assert.equal((await f.tool("get_recent_events", { agent: "someone-else" })).isError, true);
  await f.setup("POST", { webhook_url: URL, authorization: KEY });
  const stopped = (await f.tool("get_recent_events", { scheduled: true, since: next.cursor })).structuredContent as any;
  assert.equal(stopped.polling_active, false);
  assert.equal(((await f.tool("get_recent_events", {})).structuredContent as any).events.length, 2, "manual reads still work");
});

test("Cloud copy: a routine URL is saved under one grant only; disconnect narrows by mode; revocation deletes the event log", async t => {
  const f = await fixture(t);
  await f.tool("connect_grok_bot_routine");
  assert.equal((await f.setup("POST", { webhook_url: URL, authorization: KEY })).status, 200);
  const other = randomUUID();
  const family = randomUUID();
  await f.addGrant(other, "other-grok", family);
  await f.database.query("UPDATE mcp_oauth_grants SET agent_remote_id=$2 WHERE id=$1", [other, "ag_other"]);
  await f.issue(other, family);
  const duplicate = await f.setup("POST", { webhook_url: URL, authorization: KEY }, other);
  assert.equal(duplicate.status, 400);
  assert.match((await duplicate.json() as any).error_description, /already connected to another Agent Relay connection/);
  assert.equal((await f.database.query("SELECT * FROM grok_bot_routines")).rows.length, 1);

  assert.deepEqual((await f.tool("disconnect_grok_bot_routine", { mode: "polling" })).structuredContent, { removed: 0 });
  await f.message(); await f.routines.tick();
  assert.equal((await f.database.query("SELECT * FROM grok_bot_events")).rows.length, 1);
  await f.database.transaction(tx => revokeMcpOAuthGrantRows(tx, f.owner.grantId, "test", new Date()));
  assert.equal((await f.database.query("SELECT * FROM grok_bot_events")).rows.length, 0);
  assert.equal((await f.database.query("SELECT * FROM grok_bot_routines")).rows.length, 0);
});

test("Cloud copy: a failed wake keeps its event pending with the same id and backs off; the message is still acknowledged once ingested", async t => {
  const f = await fixture(t);
  await f.tool("connect_grok_bot_routine");
  await f.setup("POST", { webhook_url: URL, authorization: KEY });
  await f.message(); f.fail(503);
  await f.routines.tick();
  assert.equal(f.calls.length, 1);
  assert.equal(f.world.pending("fake-grok").length, 0);
  const state = (await f.tool("grok_bot_routine_status")).structuredContent as any;
  assert.equal(state.last_error, "delivery_unavailable"); assert.equal(state.reply_mode, "notes-only");
  assert.ok(!JSON.stringify(state).includes("PROVIDER_SECRET"));
  await f.routines.tick(); assert.equal(f.calls.length, 1, "backoff holds");
  f.fail(202); f.advance(); await f.routines.tick();
  assert.equal(f.calls.length, 2);
  assert.equal(f.calls[0]!.body.eventId, f.calls[1]!.body.eventId);
});

test("Cloud copy: a failed wake is visible to the sender and retry backoff never exceeds 30 seconds", async t => {
  const f = await fixture(t);
  await f.tool("connect_grok_bot_routine");
  await f.setup("POST", { webhook_url: URL, authorization: KEY });
  const sent = await f.message();
  const recipient = f.world.agents.get("fake-grok")!;
  f.fail(503);
  for (let attempt = 0; attempt < 6; attempt++) {
    await f.routines.tick();
    const row = (await f.database.query<{ next_attempt_at: Date | string; updated_at: Date | string }>(
      "SELECT next_attempt_at,updated_at FROM grok_bot_routines")).rows[0]!;
    assert.ok(new Date(row.next_attempt_at).getTime() - new Date(row.updated_at).getTime() <= GROK_ROUTINE_MAX_BACKOFF_MS);
    f.advance();
  }
  const status = await routineWakeStatus(f.database, {
    organizationId: f.owner.organizationId, workspaceId: f.owner.workspaceId, messageId: sent.message.id,
    recipientAgentIds: [recipient.id],
  });
  assert.equal(status!.state, "backoff");
  assert.match(status!.next_attempt_at!, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(status!.attempts, 6);
});

test("Cloud copy is off by default: no event tools, the #136 inbox prompt, and a typo in the flag fails start-up", async t => {
  const f = await fixture(t, false);
  const tools = (await (async () => (await f.tool("describe_capabilities")).structuredContent as any)()).groups;
  assert.equal(tools.find((g: any) => g.id === "grok_events").status, "unavailable");
  assert.equal((await f.tool("get_event", { eventId: "evt_" + "0".repeat(32) })).isError, true);
  const connected = (await f.tool("connect_grok_bot_routine")).structuredContent as any;
  assert.match(connected.routine_prompt, /check_relay_inbox without as/);
  assert.equal(loadMcpOAuthConfig({}, () => undefined).grokCloudCopy, false);
  assert.equal(loadMcpOAuthConfig({ SELFHOST_GROK_ROUTINES_CLOUD_COPY: "on" }, () => undefined).grokCloudCopy, true);
  assert.throws(() => loadMcpOAuthConfig({ SELFHOST_GROK_ROUTINES_CLOUD_COPY: "yes" }, () => undefined), /must be on or off/);
  assert.deepEqual(parseGrokRoutineDetails(`POST to ${URL}\nAuthorization: Bearer ${KEY}`), { webhookUrl: URL, apiKey: KEY });
});

test("Cloud copy: retention deletes week-old events whatever the flag says, and disconnecting deletes a routine's events", async t => {
  const f = await fixture(t);
  await f.tool("connect_grok_bot_routine");
  await f.setup("POST", { webhook_url: URL, authorization: KEY });
  await f.message(); await f.routines.tick();
  const event = f.calls[0]!.body.eventId;
  assert.equal(((await f.tool("get_event", { eventId: event })).isError), undefined);
  assert.equal(f.calls[0]!.body.cursor, "1", "the cursor is this grant's own sequence");
  f.advance(8 * 24 * 3_600_000);
  assert.equal((await f.tool("get_event", { eventId: event })).isError, true, "reads never return expired events");
  await new GrokRoutines({ ...f.routines.options, cloudCopy: false }).tick();
  assert.equal((await f.database.query("SELECT * FROM grok_bot_events")).rows.length, 0);
  await f.message(); f.advance(); await f.routines.tick();
  assert.equal((await f.database.query("SELECT * FROM grok_bot_events")).rows.length, 1);
  await f.tool("disconnect_grok_bot_routine");
  assert.equal((await f.database.query("SELECT * FROM grok_bot_events")).rows.length, 0);
});

test("Cloud copy: an event that can no longer be decrypted is skipped instead of blocking later wakes", async t => {
  const f = await fixture(t);
  await f.tool("connect_grok_bot_routine");
  await f.setup("POST", { webhook_url: URL, authorization: KEY });
  f.fail(503); await f.message("sender", "first"); await f.routines.tick();
  assert.equal(f.calls.length, 1);
  await f.database.query("UPDATE grok_bot_events SET payload_ciphertext='v1:retired-key:AAAA'");
  f.fail(202); await f.message("sender", "second"); f.advance(); await f.routines.tick();
  assert.equal(f.calls.length, 2);
  assert.equal(f.calls[1]!.body.data.summary, "second");
});

test("Cloud copy: a concurrent save of the same routine URL maps the unique-index refusal to the duplicate answer", async t => {
  const f = await fixture(t);
  await f.tool("connect_grok_bot_routine");
  await f.setup("POST", { webhook_url: URL, authorization: KEY });
  const other = randomUUID(), family = randomUUID();
  await f.addGrant(other, "other-grok", family);
  await f.database.query(`INSERT INTO grok_bot_routines(grant_id,credentials_ciphertext,routine_url_hash)
    SELECT $1,credentials_ciphertext,'race-hash' FROM grok_bot_routines LIMIT 1`, [other]);
  const error = await f.database.query("UPDATE grok_bot_routines SET routine_url_hash='race-hash' WHERE grant_id=$1", [f.owner.grantId])
    .then(() => null, (failure: unknown) => failure);
  assert.ok(error, "the unique index refuses a second grant with the same routine URL");
  assert.equal(isDuplicateRoutine(error), true);
  assert.equal(isDuplicateRoutine(new Error("other")), false);
});

test("Cloud copy, gate-only: ingest and acknowledgement go through relaygate with the participant's own token, never Relaycast", async t => {
  const f = await fixture(t);
  await f.tool("connect_grok_bot_routine");
  await f.setup("POST", { webhook_url: URL, authorization: KEY });
  const agent = f.world.agents.get("fake-grok")!;
  const tokens = new Map<string, string>([["rg_current", agent.token]]);
  await f.database.query(`UPDATE hosted_relay_participants SET relaygate_agent_id='rga_fake', token_ciphertext=$1, admitted_clients='{grok-bot,cursor-cloud}'
    WHERE agent_remote_id=$2`, [encryptSecret("rg_current", KEYRING.active), agent.id]);
  const gatePaths: string[] = [];
  const gate = createRelaycastClient({ internalOrigin: "https://gate.example.test", fetchImpl: async (input, init) => {
    const url = new globalThis.URL(input instanceof Request ? input.url : String(input));
    const bearer = (new Headers(init?.headers).get("authorization") ?? "").replace(/^Bearer /, "");
    const upstream = tokens.get(bearer);
    if (!upstream) return Response.json({ error: "relaygate_unauthenticated" }, { status: 401 });
    gatePaths.push(`${init?.method ?? "GET"} ${url.pathname}`);
    const result = await f.world.handle(init?.method ?? "GET", url.pathname, url.searchParams, upstream, init?.body ? JSON.parse(String(init.body)) : null, null);
    if (url.pathname === "/v1/agent" && result?.status === 200) (result.body as any).data.workspace_id = "fake-workspace";
    return Response.json(result?.body ?? { ok: false }, { status: result?.status ?? 404 });
  } });
  const routines = new GrokRoutines({ ...f.routines.options, gate });
  await f.message();
  f.relayPaths.length = 0;
  await routines.tick();
  assert.equal(f.calls.length, 1, "the gated inbox was ingested and woke the routine");
  assert.ok(gatePaths.includes("GET /v1/deliveries"));
  assert.ok(gatePaths.some(path => /^POST \/v1\/deliveries\/[^/]+\/ack$/.test(path)), "acknowledged through relaygate");
  assert.equal(f.world.pending("fake-grok").length, 0);
  assert.deepEqual(f.relayPaths.filter(path => /deliveries|\/v1\/agent$/.test(path)), [], "no direct Relaycast read or ack");
});

/**
 * A gated participant whose rg_ token is due for renewal, read through a relaygate fake that revokes the presented
 * token when it issues a new one. `failInbox` answers inbox reads with 500.
 */
async function staleGatedParticipant(f: Awaited<ReturnType<typeof fixture>>) {
  await f.tool("connect_grok_bot_routine");
  assert.equal((await f.setup("POST", { webhook_url: URL, authorization: KEY })).status, 200);
  const agent = f.world.agents.get("fake-grok")!;
  const tokens = new Map<string, string>([["rg_current", agent.token]]);
  await f.database.query(`UPDATE hosted_relay_participants SET relaygate_agent_id='rga_fake', token_ciphertext=$1, admitted_clients='{grok-bot,cursor-cloud}',
    updated_at='2000-01-01' WHERE agent_remote_id=$2`, [encryptSecret("rg_current", KEYRING.active), agent.id]);
  const state = { renewals: 0, rejected: 0, failInbox: false };
  const gate = createRelaycastClient({ internalOrigin: "https://gate.example.test", fetchImpl: async (input, init) => {
    const url = new globalThis.URL(input instanceof Request ? input.url : String(input));
    const method = init?.method ?? "GET";
    const bearer = (new Headers(init?.headers).get("authorization") ?? "").replace(/^Bearer /, "");
    const upstream = tokens.get(bearer);
    if (!upstream) { state.rejected++; return Response.json({ error: "relaygate_unauthenticated" }, { status: 401 }); }
    if (url.pathname === "/v1/token/refresh") {
      tokens.delete(bearer);
      const next = `rg_renewed_${++state.renewals}`;
      tokens.set(next, upstream);
      return Response.json({ token: next, expires_at: new Date().toISOString() });
    }
    if (state.failInbox && method === "GET" && url.pathname === "/v1/deliveries") return Response.json({ ok: false }, { status: 500 });
    const result = await f.world.handle(method, url.pathname, url.searchParams, upstream, init?.body ? JSON.parse(String(init.body)) : null, null);
    if (url.pathname === "/v1/agent" && result?.status === 200) (result.body as any).data.workspace_id = "fake-workspace";
    return Response.json(result?.body ?? { ok: false }, { status: result?.status ?? 404 });
  } });
  const participant = async () => (await f.database.query<{ token_ciphertext: string; admitted_clients: string[] }>(
    "SELECT token_ciphertext,admitted_clients FROM hosted_relay_participants WHERE agent_remote_id=$1", [agent.id])).rows[0]!;
  return { routines: new GrokRoutines({ ...f.routines.options, gate }), state,
    accepted: async () => tokens.has(decryptSecret((await participant()).token_ciphertext, KEYRING)),
    admittedClients: async () => (await participant()).admitted_clients };
}

test("Gate-only, inbox batch: a token renewed in a scan whose wake fails stays stored, so the next scan needs no recovery", async t => {
  const f = await fixture(t, false);
  const gated = await staleGatedParticipant(f);
  await f.message(); f.fail(500);
  await gated.routines.tick();
  assert.equal(gated.state.renewals, 1);
  assert.equal(f.calls.length, 1, "the wake was tried and failed");
  assert.equal((await f.database.query("SELECT last_error FROM grok_bot_routines")).rows[0]!.last_error, "delivery_unavailable");
  assert.equal(await gated.accepted(), true, "the stored token is the renewed one relaygate accepts");
  f.fail(202); f.advance(); await gated.routines.tick();
  assert.equal(f.calls.length, 2, "the next scan wakes the routine");
  assert.equal(gated.state.rejected, 0, "no 401, so no recovery");
  assert.equal(gated.state.renewals, 1);
  assert.deepEqual(await gated.admittedClients(), ["grok-bot", "cursor-cloud"], "admitted clients are not reset by a recovery");
});

test("Gate-only, Cloud copy: a token renewed in a scan whose inbox read fails stays stored, so the next scan needs no recovery", async t => {
  const f = await fixture(t);
  const gated = await staleGatedParticipant(f);
  await f.message(); gated.state.failInbox = true;
  await gated.routines.tick();
  assert.equal(gated.state.renewals, 1);
  assert.equal(f.calls.length, 0);
  assert.equal((await f.database.query("SELECT * FROM grok_bot_events")).rows.length, 0, "the rest of the scan was rolled back");
  assert.equal((await f.database.query("SELECT last_error FROM grok_bot_routines")).rows[0]!.last_error, "delivery_unavailable");
  assert.equal(await gated.accepted(), true, "the stored token is the renewed one relaygate accepts");
  gated.state.failInbox = false; f.advance(); await gated.routines.tick();
  assert.equal(f.calls.length, 1, "the next scan ingests and wakes the routine");
  assert.equal(f.world.pending("fake-grok").length, 0, "and acknowledges through relaygate");
  assert.equal(gated.state.rejected, 0, "no 401, so no recovery");
  assert.equal(gated.state.renewals, 1);
  assert.deepEqual(await gated.admittedClients(), ["grok-bot", "cursor-cloud"], "admitted clients are not reset by a recovery");
});

test("Cloud copy: trust is decided at read time from this person's own rows in this workspace", async t => {
  const f = await fixture(t);
  await f.tool("connect_grok_bot_routine");
  await f.setup("POST", { webhook_url: URL, authorization: KEY });
  const other = randomUUID();
  await f.database.query("INSERT INTO users(id,email,name) VALUES ($1,'teammate@example.test','Teammate')", [other]);
  await f.database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')", [f.owner.organizationId, other]);
  const insertDesktop = async (name: string, userId: string, workspaceId: string) => {
    const agent = f.sender(name);
    await f.database.query(`INSERT INTO desktop_relay_identities(id,workspace_id,organization_id,user_id,relaycast_workspace_id,source_id,agent_name,
      agent_remote_id,address,token_ciphertext) VALUES ($1,$2,$3,$4,'fake-workspace',$5,$6,$7,$8,$9)`,
    [randomUUID(), workspaceId, f.owner.organizationId, userId, randomUUID(), name, agent.id, `${name}@laptop`, encryptSecret(agent.token, KEYRING.active)]);
  };
  // A teammate's own agent in the same workspace is not this person's agent.
  await insertDesktop("teammate-agent", other, f.owner.workspaceId);
  // The person's agent in another workspace of the organization does not count here.
  const elsewhere = randomUUID();
  await f.database.query(`INSERT INTO workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
    VALUES ($1,$2,'Other Workspace','other-relay',$3)`, [elsewhere, f.owner.organizationId, encryptSecret("rk_other", KEYRING.active)]);
  await insertDesktop("elsewhere-agent", f.owner.userId, elsewhere);
  await f.ownAgent("mine-for-now");
  for (const from of ["teammate-agent", "elsewhere-agent", "mine-for-now"]) await f.message(from, `from ${from}`);
  await f.routines.tick();
  const event = (from: string) => f.calls.find(call => call.body.data.from === from)!.body.eventId;
  assert.match(text(await f.tool("get_event", { eventId: event("teammate-agent") })), /trustedSender false/);
  assert.match(text(await f.tool("get_event", { eventId: event("elsewhere-agent") })), /trustedSender false/);
  assert.match(text(await f.tool("get_event", { eventId: event("mine-for-now") })), /trustedSender true/);
  // The identity is removed after the message was stored: the next read no longer trusts it.
  await f.database.query("DELETE FROM desktop_relay_identities WHERE agent_name='mine-for-now'");
  assert.match(text(await f.tool("get_event", { eventId: event("mine-for-now") })), /trustedSender false/);
  // A retired Capy binding never counts; a bound one does.
  const capy = f.sender("capy-agent");
  await f.database.query(`INSERT INTO capy_bindings(id,workspace_id,organization_id,user_id,thread_id,state,connection_digest,relaycast_workspace_id,agent_name,agent_remote_id)
    VALUES ($1,$2,$3,$4,'thread-1','retired','digest','fake-workspace','capy-agent',$5)`, [randomUUID(), f.owner.workspaceId, f.owner.organizationId, f.owner.userId, capy.id]);
  await f.message("capy-agent", "from capy"); f.advance(); await f.routines.tick();
  assert.match(text(await f.tool("get_event", { eventId: event("capy-agent") })), /trustedSender false/);
});

test("Cloud copy: the cursor never restarts after retention deletes events", async t => {
  const f = await fixture(t);
  await f.tool("connect_grok_bot_routine", { mode: "polling" });
  await f.message("sender", "one"); await f.message("sender", "two"); await f.routines.tick();
  const first = (await f.tool("get_recent_events", { scheduled: true, since: "0" })).structuredContent as any;
  assert.deepEqual(first.events.map((event: any) => event.cursor), ["1", "2"]);
  f.advance(8 * 24 * 3_600_000); await f.routines.tick();
  assert.equal((await f.database.query("SELECT * FROM grok_bot_events")).rows.length, 0);
  await f.message("sender", "three"); f.advance(); await f.routines.tick();
  const later = (await f.tool("get_recent_events", { scheduled: true, since: first.cursor })).structuredContent as any;
  assert.deepEqual(later.events.map((event: any) => [event.cursor, event.text]), [["3", "three"]]);
});

test("Cloud copy: a channel post wakes the routine only when it mentions the bot; addressed has Cloud's shape", async t => {
  const f = await fixture(t);
  await f.tool("connect_grok_bot_routine");
  await f.setup("POST", { webhook_url: URL, authorization: KEY });
  f.sender("peer");
  f.world.channelAs("fake-grok", "ops");
  f.world.channelAs("peer", "ops", "general chatter");
  f.world.channelAs("peer", "ops", "@fake-grok please look", { mention: "fake-grok" });
  await f.routines.tick();
  assert.equal(f.calls.length, 1, "only the mention woke the routine");
  assert.equal(f.calls[0]!.body.name, "relay.channel_message");
  assert.equal(f.calls[0]!.body.data.addressed, "mention");
  const all = (await f.tool("get_recent_events", {})).structuredContent as any;
  assert.deepEqual(all.events.map((event: any) => [event.data.addressed, event.text]),
    [["post", "general chatter"], ["mention", "@fake-grok please look"]]);
  assert.equal(f.world.pending("fake-grok").length, 0, "both were ingested and acknowledged");
});

test("Cloud copy: a racing duplicate save is refused through the route's unique-index catch; a save before join_relay is refused", async t => {
  const f = await fixture(t);
  // Before the bot joins Relay there is no pinned identity to wake.
  const early = await f.setup("POST", { webhook_url: URL, authorization: KEY });
  assert.equal(early.status, 400);
  assert.match((await early.json() as any).error_description, /join_relay/);
  await f.tool("connect_grok_bot_routine");
  // Another grant holds the URL, and the pre-check is made to miss it, as when two saves race.
  const other = randomUUID();
  await f.addGrant(other, "other-grok", randomUUID());
  const hash = (await import("../src/crypto.js")).hashSecret(URL);
  await f.database.query("INSERT INTO grok_bot_routines(grant_id,credentials_ciphertext,routine_url_hash) VALUES ($1,'x',$2)", [other, hash]);
  const database = f.routines.options.database;
  const racing = { ...database, transaction: (fn: (tx: any) => Promise<unknown>) => database.transaction(tx => fn({
    query: (sql: string, params?: unknown[]) => sql.startsWith("SELECT 1 FROM grok_bot_routines WHERE routine_url_hash")
      ? Promise.resolve({ rows: [] }) : tx.query(sql, params) })) } as typeof database;
  const routines = new GrokRoutines({ ...f.routines.options, database: racing });
  const response = await routines.handle(new Request(`https://relay.example.test${GROK_SETUP_PATH}?grant=${f.owner.grantId}`, {
    method: "POST", headers: { origin: "https://relay.example.test", "content-type": "application/json" },
    body: JSON.stringify({ webhook_url: URL, authorization: KEY }) }), f.owner);
  assert.equal(response.status, 400);
  assert.match((await response.json() as any).error_description, /already connected to another Agent Relay connection/);
});

test("Cloud copy: the server's wiring reads SELFHOST_GROK_ROUTINES_CLOUD_COPY from config", () => {
  const env = { DATABASE_URL: "postgres://unused", SELFHOST_BOOTSTRAP_TOKEN: "fake-bootstrap-token-at-least-32-bytes",
    SELFHOST_PUBLIC_URL: "https://relay.example.test", RELAYCAST_URL: "http://relaycast.test",
    RELAYCAST_PUBLIC_URL: "https://relaycast.selfhosted.company", SESSION_READ_API_URL: "http://history.test",
    SESSION_READ_API_SECRET: "fake-read-api-secret-at-least-32-bytes", RELAYCONTROL_INTROSPECT_SECRET: "fake-introspect-secret-at-least-32-bytes",
    SESSION_READ_API_PUBLIC_URL: "https://history.selfhosted.company", SELFHOST_ENCRYPTION_KEY_ID: "fake-key",
    SELFHOST_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString("base64") };
  const deps = { database: undefined as never, tenancyMode: "single" as const, client: undefined as never };
  assert.equal(new GrokRoutines(grokRoutinesOptions(loadConfig(env), deps)).cloudCopy, false);
  assert.equal(new GrokRoutines(grokRoutinesOptions(loadConfig({ ...env, SELFHOST_GROK_ROUTINES_CLOUD_COPY: "on" }), deps)).cloudCopy, true);
});

test("webhook prompt keeps keyed links out of chat notes", () => {
  const prompt = grokRoutinePrompt("fake-grok", { canReply: true });
  assert.doesNotMatch(prompt, /observerUrl/);
  assert.match(prompt, /Never paste links containing keys/);
});
