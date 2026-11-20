import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { encryptSecret } from "../src/crypto.js";
import { createRelaycastClient } from "../src/messaging/relaycast.js";
import { GrokRoutines, isDuplicateRoutine } from "../src/mcp/grok-routines.js";
import { grokRoutinePrompt, parseGrokRoutineDetails } from "../src/mcp/grok-routine.js";
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
  assert.match(connected.setup_url, /grant=.*&from=sender$/);
  assert.match(connected.next_steps, /^Create the Agent Relay inbound Webhook routine now/);
  assert.equal(connected.inbox_address, `fake-grok@cloud-${f.world.agents.get("fake-grok")!.id}`);
  const wrong = await f.tool("connect_grok_bot_routine", { name: "other-bot" });
  assert.equal(wrong.isError, true);
  assert.match(text(wrong), /This Agent Relay connection was approved as fake-grok, so it cannot act or read as other-bot/);
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
