import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { encryptSecret } from "../src/crypto.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { createRelaycastClient } from "../src/messaging/relaycast.js";
import { GrokRoutines, GROK_SETUP_PATH } from "../src/mcp/grok-routines.js";
import { grokRoutinePrompt, parseGrokRoutineDetails } from "../src/mcp/grok-routine.js";
import { eventSteps, grantEventsSettings } from "../src/mcp/grok-events-policy.js";
import { loadMcpOAuthConfig } from "../src/mcp/oauth/config.js";
import { createMcpOAuthProtocol } from "../src/mcp/oauth/protocol.js";
import { McpOAuthSessions } from "../src/mcp/oauth/sessions.js";
import { revokeMcpOAuthGrantRows } from "../src/mcp/oauth/revocations.js";
import { ownerHash } from "../src/mcp/relay-participants.js";
import { PGliteDatabase, listen, close } from "./support/harness.js";
import { createRelaycastWorld } from "./support/relaycast-world.js";

// SELFHOST_GROK_ROUTINES_CLOUD_COPY (docs/specs/grok-bot-dynamic-prompt.md, Phase 1).
const ORIGIN = "https://relay.example.test", SHARED = "/api/v1/mcp/shared-sessions";
const KEYRING = { active: { id: "fake-key", key: Buffer.alloc(32, 7) } };
const URL = "https://api2.cursor.sh/automations/webhook/rt_fake";
const KEY = "crsr_" + "fake_routine_key_".repeat(3);

async function fixture(t: test.TestContext, cloudCopy = true) {
  const database = new PGliteDatabase(); t.after(() => database.close()); await migrate(database);
  const owner = { userId: randomUUID(), organizationId: randomUUID(), workspaceId: randomUUID(), grantId: randomUUID(), tokenFamilyId: randomUUID() };
  const clientId = "mcpc_" + randomUUID();
  await database.query("INSERT INTO users(id,email,name) VALUES ($1,'fake@example.test','Fake User')", [owner.userId]);
  await database.query("INSERT INTO organizations(id,name) VALUES ($1,'Fake Org')", [owner.organizationId]);
  await database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')", [owner.organizationId, owner.userId]);
  await database.query(`INSERT INTO workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
    VALUES ($1,$2,'Fake Workspace','fake-workspace',$3)`, [owner.workspaceId, owner.organizationId, encryptSecret("rk_fake", KEYRING.active)]);
  await database.query("INSERT INTO mcp_oauth_clients(client_id,redirect_uris) VALUES ($1,$2)", [clientId, ["https://www.cursor.com/agents/fake/callback"]]);
  const protocol = createMcpOAuthProtocol({ publicOrigin: ORIGIN, enabledResources: [SHARED, "/mcp"] });
  const addGrant = async (id: string, agent: string, family: string) => database.query(`INSERT INTO mcp_oauth_grants(id,client_id,user_id,organization_id,workspace_id,agent_name,scopes,resource,token_family_id)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [id, clientId, owner.userId, owner.organizationId, owner.workspaceId, agent,
    ["relay:mcp"], protocol.mcpResourceUrl(SHARED), family]);
  await addGrant(owner.grantId, "fake-grok", owner.tokenFamilyId);
  let now = new Date();
  const sessions = new McpOAuthSessions(database, { protocol, tenancyMode: "multi", now: () => now });
  const pair = await database.transaction(tx => sessions.issue(tx, { ...owner, scopes: ["relay:mcp"] }));
  const world = createRelaycastWorld([]);
  const relayFetch: typeof fetch = async (input, init) => {
    const url = new globalThis.URL(input instanceof Request ? input.url : String(input)), headers = new Headers(init?.headers);
    if (url.pathname === "/v1/agents" && (init?.method ?? "GET") === "GET") return Response.json({ ok: true,
      data: [...world.agents.values()].map(agent => ({ ...agent, address: `${agent.name}@cloud-${agent.id}`, last_seen: new Date().toISOString() })) });
    const result = await world.handle(init?.method ?? "GET", url.pathname, url.searchParams,
      (headers.get("authorization") ?? "").replace(/^Bearer /, ""), init?.body ? JSON.parse(String(init.body)) : null, headers.get("idempotency-key"));
    if (url.pathname === "/v1/agent" && result?.status === 200) (result.body as any).data.workspace_id = "fake-workspace";
    return Response.json(result?.body ?? { ok: false, error: { code: "not_found" } }, { status: result?.status ?? 404 });
  };
  const cast = createRelaycastClient({ internalOrigin: "http://fake-relay.test", fetchImpl: relayFetch });
  const calls: Array<{ url: string; headers: Headers; body: any }> = [];
  let webhookStatus = 202;
  const routines = new GrokRoutines({ database, keyring: KEYRING, client: cast, publicOrigin: ORIGIN, tenancyMode: "multi", now: () => now,
    cloudCopy, fetchImpl: async (input, init) => {
      calls.push({ url: String(input), headers: new Headers(init?.headers), body: JSON.parse(String(init?.body)) });
      return new Response("PROVIDER_SECRET_MUST_NOT_LEAK", { status: webhookStatus });
    } });
  const config: SelfhostConfig = { databaseUrl: "unused", publicBaseUrl: ORIGIN, dashboardUrl: ORIGIN,
    relaycastUrl: "http://fake-relay.test", relaycastPublicUrl: "https://cast.example.test",
    relayhistoryUrl: "http://unused-history.test", relayhistoryPublicUrl: "https://history.example.test",
    sessionReadApi: { url: "http://unused-history.test", publicUrl: "https://history.example.test", secret: "session-read-secret-".repeat(2) },
    internalServiceToken: null, bootstrapToken: "fake-bootstrap-token-at-least-thirty-two-bytes", encryptionKeyring: KEYRING,
    oauthRedirectUrl: ORIGIN + "/unused", host: "127.0.0.1", port: 3000,
    mcpOAuth: { enabled: true, unavailable: null, eventsEnabled: false, pumpEnabled: false, grokCloudCopy: cloudCopy, oidc: null } };
  const store = new ControlPlaneStore(database, KEYRING, 0, { tenancy: "multi" });
  const browser = await database.transaction(tx => store.issueBrowserSession(tx, { ...owner, label: "grok-test" }));
  const server = createServer(createApp({ config, store, messagingFetch: relayFetch, grokRoutines: routines }));
  const base = await listen(server); t.after(() => close(server));
  const client = new Client({ name: "grok-test", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new globalThis.URL(base + SHARED), { requestInit: { headers: { authorization: `Bearer ${pair.accessToken}` } } }));
  t.after(() => client.close());
  const tool = async (name: string, args = {}) => client.callTool({ name, arguments: args });
  const setup = async (method = "GET", body?: unknown, grant = owner.grantId) => fetch(base + GROK_SETUP_PATH + "?grant=" + grant, {
    method, redirect: "manual", headers: { cookie: `agent_relay_session=${browser.accessToken}`, origin: ORIGIN, "content-type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const sender = (name = "sender", metadata: Record<string, unknown> = {}) => world.agents.get(name) ?? world.addAgent(name, metadata);
  const message = async (from = "sender", text = "PRIVATE_MESSAGE_BODY") =>
    cast.sendDirectMessage({ token: sender(from).token, to: "fake-grok", text, idempotencyKey: randomUUID() });
  const issue = (grantId: string, tokenFamilyId: string) =>
    database.transaction(tx => sessions.issue(tx, { ...owner, grantId, tokenFamilyId, scopes: ["relay:mcp"] }));
  return { database, owner, addGrant, issue, pair, routines, world, calls, tool, setup, message, sender,
    advance: () => { now = new Date(now.getTime() + 301_000); }, fail: (status: number) => { webhookStatus = status; } };
}

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

test("Cloud copy: a sender the person owns is trusted, and answer mode offers the reply call", async t => {
  const f = await fixture(t);
  await f.tool("connect_grok_bot_routine");
  await f.setup("POST", { webhook_url: URL, authorization: `Bearer ${KEY}`, reply_mode: "answer" });
  f.sender("my-agent", { owner_hash: ownerHash(f.owner.userId) });
  await f.message("my-agent", "please summarise");
  await f.message("sender", "stranger asks");
  await f.routines.tick();
  assert.equal(f.calls.length, 2);
  const mine = f.calls.find(call => call.body.data.from === "my-agent")!;
  const theirs = f.calls.find(call => call.body.data.from === "sender")!;
  const trusted = text(await f.tool("get_event", { eventId: mine.body.eventId }));
  assert.match(trusted, /Sender check: trustedSender true \(your agent\)\./);
  assert.match(trusted, /Reply call: send_relay_message with to = data\.from/);
  assert.match(trusted, /Add text = your answer and call it now/);
  const untrusted = text(await f.tool("get_event", { eventId: theirs.body.eventId }));
  assert.match(untrusted, /trustedSender false/);
  assert.match(untrusted, /ask the person whether to reply/);
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
