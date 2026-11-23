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
import { createRelaycastClient, type RelaycastClient } from "../src/messaging/relaycast.js";
import { GrokRoutines, GROK_SETUP_PATH } from "../src/mcp/grok-routines.js";
import { CHANNEL_RETRY_WINDOW_MS, CHANNEL_WAKE_WINDOW_MS, MAX_AGENT_THREAD_WAKES, MAX_CHANNEL_WAKES, MAX_THREAD_WAKES } from "../src/mcp/channel-wake.js";
import { createMcpOAuthProtocol } from "../src/mcp/oauth/protocol.js";
import { loadMcpOAuthConfig } from "../src/mcp/oauth/config.js";
import { McpOAuthSessions } from "../src/mcp/oauth/sessions.js";
import { PGliteDatabase, listen, close } from "./support/harness.js";
import { createRelaycastWorld } from "./support/relaycast-world.js";

// Addressed relay channel posts as relay.channel_message (SELFHOST_GROK_ROUTINES_CLOUD_COPY; docs/grok-bot.md,
// "Channel posts"): which posts are kept, which wake a routine, the bot-thread rule and the loop caps.
const ORIGIN = "https://relay.example.test", SHARED = "/api/v1/mcp/shared-sessions";
const KEYRING = { active: { id: "fake-key", key: Buffer.alloc(32, 7) } };
const URL = "https://api2.cursor.sh/automations/webhook/rt_fake";
const KEY = "crsr_" + "fake_routine_key_".repeat(3);
const CHANNEL = "family";

async function fixture(t: test.TestContext, options: { cloudCopy?: boolean; gate?: boolean; memberTrust?: boolean } = {}) {
  const cloudCopy = options.cloudCopy ?? true;
  const database = new PGliteDatabase(); t.after(() => database.close()); await migrate(database);
  const owner = { userId: randomUUID(), organizationId: randomUUID(), workspaceId: randomUUID(), grantId: randomUUID(), tokenFamilyId: randomUUID() };
  const grokClient = "mcpc_" + randomUUID(), chatClient = "mcpc_" + randomUUID();
  await database.query("INSERT INTO users(id,email,name) VALUES ($1,'fake@example.test','Fake User')", [owner.userId]);
  await database.query("INSERT INTO organizations(id,name) VALUES ($1,'Fake Org')", [owner.organizationId]);
  await database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')", [owner.organizationId, owner.userId]);
  await database.query(`INSERT INTO workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
    VALUES ($1,$2,'Fake Workspace','fake-workspace',$3)`, [owner.workspaceId, owner.organizationId, encryptSecret("rk_fake", KEYRING.active)]);
  await database.query("INSERT INTO mcp_oauth_clients(client_id,redirect_uris) VALUES ($1,$2),($3,$4)",
    [grokClient, ["https://www.cursor.com/agents/fake/callback"], chatClient, ["https://chatgpt.com/connector_platform_oauth_redirect"]]);
  const protocol = createMcpOAuthProtocol({ publicOrigin: ORIGIN, enabledResources: [SHARED, "/mcp"] });
  const addGrant = (id: string, clientId: string, agent: string, family: string) => database.query(`INSERT INTO mcp_oauth_grants(id,client_id,user_id,organization_id,workspace_id,agent_name,scopes,resource,token_family_id)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [id, clientId, owner.userId, owner.organizationId, owner.workspaceId, agent,
    ["relay:mcp"], protocol.mcpResourceUrl(SHARED), family]);
  await addGrant(owner.grantId, grokClient, "fake-grok", owner.tokenFamilyId);
  let now = new Date();
  const clock = () => now;
  const sessions = new McpOAuthSessions(database, { protocol, tenancyMode: "multi", now: clock });
  const world = createRelaycastWorld([], { mentions: true, now: clock });
  const relayPaths: string[] = [];
  const relayFetch: typeof fetch = async (input, init) => {
    const url = new globalThis.URL(input instanceof Request ? input.url : String(input)), headers = new Headers(init?.headers);
    relayPaths.push(`${init?.method ?? "GET"} ${url.pathname}`);
    if (url.pathname === "/v1/agents" && (init?.method ?? "GET") === "GET") return Response.json({ ok: true,
      data: [...world.agents.values()].map(agent => ({ ...agent, address: `${agent.name}@cloud-${agent.id}`, last_seen: now.toISOString() })) });
    const result = await world.handle(init?.method ?? "GET", url.pathname, url.searchParams,
      (headers.get("authorization") ?? "").replace(/^Bearer /, ""), init?.body ? JSON.parse(String(init.body)) : null, headers.get("idempotency-key"));
    if (url.pathname === "/v1/agent" && result?.status === 200) (result.body as any).data.workspace_id = "fake-workspace";
    return Response.json(result?.body ?? { ok: false, error: { code: "not_found" } }, { status: result?.status ?? 404 });
  };
  const cast = createRelaycastClient({ internalOrigin: "http://fake-relay.test", fetchImpl: relayFetch });
  // A gate-only install: participants read through relaygate with their rg_ token, which maps to the agent's own.
  const gatePaths: string[] = [];
  const gateTokens = new Map<string, string>();
  const gate: RelaycastClient | undefined = options.gate ? createRelaycastClient({ internalOrigin: "https://gate.example.test", fetchImpl: async (input, init) => {
    const url = new globalThis.URL(input instanceof Request ? input.url : String(input));
    const upstream = gateTokens.get((new Headers(init?.headers).get("authorization") ?? "").replace(/^Bearer /, ""));
    if (!upstream) return Response.json({ error: "relaygate_unauthenticated" }, { status: 401 });
    gatePaths.push(`${init?.method ?? "GET"} ${url.pathname}`);
    const result = await world.handle(init?.method ?? "GET", url.pathname, url.searchParams, upstream, init?.body ? JSON.parse(String(init.body)) : null, null);
    if (url.pathname === "/v1/agent" && result?.status === 200) (result.body as any).data.workspace_id = "fake-workspace";
    return Response.json(result?.body ?? { ok: false }, { status: result?.status ?? 404 });
  } }) : undefined;
  const calls: Array<{ body: any }> = [];
  const routines = new GrokRoutines({ database, keyring: KEYRING, client: cast, publicOrigin: ORIGIN, tenancyMode: "multi", now: clock,
    cloudCopy, ...(gate ? { gate } : {}), fetchImpl: async (_input, init) => {
      calls.push({ body: JSON.parse(String(init?.body)) });
      return new Response(null, { status: 202 });
    } });
  const config: SelfhostConfig = { databaseUrl: "unused", publicBaseUrl: ORIGIN, dashboardUrl: ORIGIN,
    relaycastUrl: "http://fake-relay.test", relaycastPublicUrl: "https://cast.example.test",
    relayhistoryUrl: "http://unused-history.test", relayhistoryPublicUrl: "https://history.example.test",
    sessionReadApi: { url: "http://unused-history.test", publicUrl: "https://history.example.test", secret: "session-read-secret-".repeat(2) },
    internalServiceToken: null, bootstrapToken: "fake-bootstrap-token-at-least-thirty-two-bytes", encryptionKeyring: KEYRING,
    oauthRedirectUrl: ORIGIN + "/unused", host: "127.0.0.1", port: 3000,
    mcpOAuth: { enabled: true, unavailable: null, eventsEnabled: false, pumpEnabled: false, grokCloudCopy: cloudCopy,
      ...(options.memberTrust === undefined ? {} : { channelMemberTrust: options.memberTrust }), oidc: null } };
  const store = new ControlPlaneStore(database, KEYRING, 0, { tenancy: "multi" });
  const browser = await database.transaction(tx => store.issueBrowserSession(tx, { ...owner, label: "channel-test" }));
  const server = createServer(createApp({ config, store, messagingFetch: relayFetch, grokRoutines: routines }));
  const base = await listen(server); t.after(() => close(server));
  const connect = async (grantId: string, family: string) => {
    const pair = await database.transaction(tx => sessions.issue(tx, { ...owner, grantId, tokenFamilyId: family, scopes: ["relay:mcp"] }));
    const client = new Client({ name: "channel-test", version: "1" });
    await client.connect(new StreamableHTTPClientTransport(new globalThis.URL(base + SHARED), { requestInit: { headers: { authorization: `Bearer ${pair.accessToken}` } } }));
    t.after(() => client.close());
    return (name: string, args = {}) => client.callTool({ name, arguments: args });
  };
  const tool = await connect(owner.grantId, owner.tokenFamilyId);
  const setup = (body: unknown) => fetch(base + GROK_SETUP_PATH + "?grant=" + owner.grantId, { method: "POST", redirect: "manual",
    headers: { cookie: `agent_relay_session=${browser.accessToken}`, origin: ORIGIN, "content-type": "application/json" }, body: JSON.stringify(body) });
  /** A person (a workspace member's person identity, sender kind `human`). */
  const person = async (name: string, userId = owner.userId) => {
    const agent = world.agents.get(name) ?? world.addAgent(name);
    await database.query(`INSERT INTO person_identities(id,workspace_id,user_id,agent_name,agent_remote_id,token_ciphertext,relaycast_workspace_id)
      VALUES ($1,$2,$3,$4,$5,$6,'fake-workspace')`, [randomUUID(), owner.workspaceId, userId, name, agent.id, encryptSecret(agent.token, KEYRING.active)]);
    return agent;
  };
  /** An agent this service records (a Desktop identity of `userId`): sender kind `agent`. */
  const recordedAgent = async (name: string, userId = owner.userId) => {
    const agent = world.agents.get(name) ?? world.addAgent(name);
    await database.query(`INSERT INTO desktop_relay_identities(id,workspace_id,organization_id,user_id,relaycast_workspace_id,source_id,agent_name,
      agent_remote_id,address,token_ciphertext) VALUES ($1,$2,$3,$4,'fake-workspace',$5,$6,$7,$8,$9)`,
    [randomUUID(), owner.workspaceId, owner.organizationId, userId, randomUUID(), name, agent.id, `${name}@laptop`, encryptSecret(agent.token, KEYRING.active)]);
    return agent;
  };
  const member = async () => {
    const userId = randomUUID();
    await database.query("INSERT INTO users(id,email,name) VALUES ($1,$2,'Member')", [userId, `${userId}@example.test`]);
    await database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')", [owner.organizationId, userId]);
    return userId;
  };
  /** A hosted participant of `userId` (null: an agent identity's, which no person owns). */
  const participant = async (name: string, userId: string | null) => {
    const agent = world.agents.get(name) ?? world.addAgent(name);
    let identity: string | null = null;
    if (!userId) {
      identity = randomUUID();
      await database.query("INSERT INTO agent_identities(id,workspace_id,organization_id,agent_name) VALUES ($1,$2,$3,$4)",
        [identity, owner.workspaceId, owner.organizationId, name]);
    }
    await database.query(`INSERT INTO hosted_relay_participants(id,workspace_id,user_id,agent_identity_id,relaycast_workspace_id,agent_name,agent_remote_id,token_ciphertext)
      VALUES ($1,$2,$3,$4,'fake-workspace',$5,$6,$7)`, [randomUUID(), owner.workspaceId, userId, identity, name, agent.id, encryptSecret(agent.token, KEYRING.active)]);
    return agent;
  };
  /** A user who belongs to another organization only. */
  const outsider = async () => {
    const userId = randomUUID(), org = randomUUID();
    await database.query("INSERT INTO users(id,email,name) VALUES ($1,$2,'Outsider')", [userId, `${userId}@example.test`]);
    await database.query("INSERT INTO organizations(id,name) VALUES ($1,'Other Org')", [org]);
    await database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')", [org, userId]);
    return userId;
  };
  /** The channel with the bot (and `others`) as members. */
  const channel = (...others: string[]) => {
    for (const name of others) world.channelAs(name, CHANNEL);
    world.channels.get(CHANNEL)!.members.add("fake-grok");
  };
  const post = (from: string, text: string) => world.channelAs(from, CHANNEL, text)!;
  const reply = async (from: string, rootId: string, text: string) => {
    const result = await world.handle("POST", `/v1/messages/${rootId}/replies`, new URLSearchParams(), world.agents.get(from)!.token, { text }, null);
    return (result!.body as any).data as { id: string };
  };
  const channelEvents = async () => (await database.query<{ addressed: string; sender_kind: string | null; wake_reserved_at: Date | null; sender: string }>(
    "SELECT addressed,sender_kind,wake_reserved_at,sender FROM grok_bot_events WHERE name='relay.channel_message' ORDER BY grant_seq")).rows;
  /** Ticks until no wake is pending (each scan wakes at most ten). */
  const drain = async () => {
    for (let scan = 0; scan < 6; scan++) { now = new Date(now.getTime() + 6_000); await routines.tick(); }
  };
  return { database, owner, world, routines, calls, tool, setup, person, recordedAgent, member, participant, outsider, channel, post, reply, channelEvents, drain,
    relayPaths, gatePaths, gateTokens, connect, addGrant, chatClient, grokClient,
    advance: (ms: number) => { now = new Date(now.getTime() + ms); } };
}

type Fixture = Awaited<ReturnType<typeof fixture>>;
const webhook = async (f: Fixture, replyMode = "notes-only") => {
  await f.tool("connect_grok_bot_routine");
  assert.equal((await f.setup({ webhook_url: URL, authorization: KEY, reply_mode: replyMode })).status, 200);
};
const woke = (f: Fixture) => f.calls.filter(call => call.body.name === "relay.channel_message").map(call => call.body.data);

test("channel posts: a mention is saved with Cloud's data shape and wakes; plain posts and agents' unmentioned posts are acknowledged and never saved", async t => {
  const f = await fixture(t);
  await webhook(f, "answer");
  await f.person("parent");
  await f.recordedAgent("ci-bot");
  f.channel("parent", "ci-bot");
  f.post("parent", "lunch?");
  f.post("ci-bot", "deploy finished");
  const mention = f.post("parent", "@fake-grok seating chart?");
  f.post("fake-grok", "@fake-grok note to self");
  await f.drain();
  assert.equal(f.world.pending("fake-grok").length, 0, "every delivery is acknowledged");
  const data = woke(f);
  assert.equal(data.length, 1);
  const channelId = f.world.channels.get(CHANNEL)!.id;
  assert.deepEqual(data[0], { messageId: mention.id, channel: CHANNEL, channelId, threadId: null, replyThreadId: mention.id,
    from: "parent", senderKind: "human", addressed: "mention", agent: "fake-grok", summary: "@fake-grok seating chart?" });
  assert.deepEqual(Object.keys(data[0]), ["messageId", "channel", "channelId", "threadId", "replyThreadId", "from", "senderKind", "addressed", "agent", "summary"]);
  assert.equal((await f.channelEvents()).length, 1, "nothing else is saved");
  const event = await f.tool("get_event", { eventId: f.calls.at(-1)!.body.eventId });
  assert.match((event.content as any)[0].text, /post_relay_channel/);
});

test("bot-thread: a person's reply wakes in the bot's own thread and in a thread it was mentioned in, never in another agent's thread", async t => {
  const f = await fixture(t);
  await webhook(f);
  await f.person("parent");
  await f.recordedAgent("ci-bot");
  f.channel("parent", "ci-bot");
  const ownRoot = f.post("fake-grok", "I booked the table");
  const otherRoot = f.post("ci-bot", "build 42 is green");
  const mentioned = f.post("parent", "@fake-grok can you check the flights?");
  await f.drain();
  assert.equal(woke(f).length, 1);
  await f.reply("parent", otherRoot.id, "nice");
  await f.reply("parent", ownRoot.id, "thanks!");
  f.relayPaths.length = 0;
  await f.reply("parent", mentioned.id, "and the hotel too");
  await f.drain();
  assert.deepEqual(woke(f).map(data => [data.addressed, data.threadId]), [["mention", null], ["bot-thread", ownRoot.id], ["bot-thread", mentioned.id]]);
  assert.ok(!f.relayPaths.includes(`GET /v1/messages/${mentioned.id}`), "the store check answers first; the root is not read");
  assert.equal(f.world.pending("fake-grok").length, 0);
  // An agent's unmentioned reply in the bot's own thread is never saved; with an @mention it is.
  await f.reply("ci-bot", ownRoot.id, "noted");
  await f.reply("ci-bot", ownRoot.id, "@fake-grok want the receipt?");
  await f.drain();
  assert.deepEqual((await f.channelEvents()).map(row => [row.sender, row.addressed]),
    [["parent", "mention"], ["parent", "bot-thread"], ["parent", "bot-thread"], ["ci-bot", "mention"]]);
});

test("bot-thread compares the root's Relaycast agent id, never its name; a missing root is an ordinary reply, acknowledged", async t => {
  const f = await fixture(t);
  await webhook(f);
  await f.person("parent");
  f.channel("parent");
  const root = f.post("parent", "who is driving?");
  // A root whose name matches the bot but whose agent id is another agent's (a released and re-registered name).
  f.world.messages.get(root.id)!.agent_name = "fake-grok";
  await f.reply("parent", root.id, "me");
  const gone = f.post("parent", "old thread");
  await f.drain();
  f.world.failNext("GET", `/v1/messages/${gone.id}`, 404, { code: "not_found" });
  await f.reply("parent", gone.id, "still on?");
  await f.drain();
  assert.deepEqual(woke(f), []);
  assert.deepEqual(await f.channelEvents(), []);
  assert.equal(f.world.pending("fake-grok").length, 0, "both replies are acknowledged");
});

test("bot-thread: a failed root read leaves only that delivery unacknowledged, never wakes, and gives up after ten minutes", async t => {
  const f = await fixture(t);
  await webhook(f);
  await f.person("parent");
  f.channel("parent");
  const ownRoot = f.post("fake-grok", "I'll check");
  await f.drain();
  // Every read of the root fails, across retries.
  for (let attempt = 0; attempt < 30; attempt++) f.world.failNext("GET", `/v1/messages/${ownRoot.id}`, 503);
  const stuck = await f.reply("parent", ownRoot.id, "any news?");
  f.world.sendAs("parent", "fake-grok", "a direct message on the same page");
  await f.drain();
  const pending = () => f.world.pending("fake-grok").map(row => row.message.id);
  assert.deepEqual(pending(), [stuck.id], "the DM on the same page was stored and acknowledged");
  assert.deepEqual(f.calls.map(call => call.body.name), ["relay.message"]);
  f.advance(CHANNEL_RETRY_WINDOW_MS + 1_000);
  await f.drain();
  assert.deepEqual(pending(), [], "past the window it is an ordinary reply and acknowledged");
  assert.deepEqual(woke(f), [], "an unverified thread never wakes");
  assert.deepEqual(await f.channelEvents(), []);
});

test("bot-thread: a successful retry within the window wakes once", async t => {
  const f = await fixture(t);
  await webhook(f);
  await f.person("parent");
  f.channel("parent");
  const ownRoot = f.post("fake-grok", "I'll check");
  f.world.failNext("GET", `/v1/messages/${ownRoot.id}`, 503);
  await f.reply("parent", ownRoot.id, "any news?");
  await f.drain();
  assert.deepEqual(woke(f).map(data => data.addressed), ["bot-thread"]);
});

test("loop caps: six wakes per thread, two agent hops per thread, twenty per channel, per ten minutes; over-cap posts are saved and wake nobody", async t => {
  const f = await fixture(t);
  await webhook(f);
  await f.person("parent");
  await f.recordedAgent("ci-bot");
  f.channel("parent", "ci-bot");
  // Thread cap.
  const root = f.post("parent", "@fake-grok plan the trip");
  for (let i = 1; i < MAX_THREAD_WAKES + 1; i++) await f.reply("parent", root.id, `@fake-grok detail ${i}`);
  await f.drain();
  assert.equal(woke(f).length, MAX_THREAD_WAKES);
  assert.equal((await f.channelEvents()).length, MAX_THREAD_WAKES + 1, "the over-cap post is still saved");
  const recent = (await f.tool("get_recent_events", { limit: 50 })).structuredContent as any;
  assert.equal(recent.events.filter((event: any) => event.name === "relay.channel_message").length, MAX_THREAD_WAKES + 1);

  // Agent hop cap, in a fresh thread.
  const hops = f.post("parent", "@fake-grok ask ci-bot");
  for (let i = 0; i < MAX_AGENT_THREAD_WAKES + 1; i++) await f.reply("ci-bot", hops.id, `@fake-grok hop ${i}`);
  await f.drain();
  assert.equal(woke(f).filter(data => data.from === "ci-bot").length, MAX_AGENT_THREAD_WAKES);

  // Channel cap: top-level mentions, each its own thread.
  const before = woke(f).length;
  for (let i = 0; i < MAX_CHANNEL_WAKES; i++) f.post("parent", `@fake-grok item ${i}`);
  await f.drain(); await f.drain();
  assert.equal(woke(f).length, MAX_CHANNEL_WAKES, "the channel's 20 wakes in the window are spent");
  assert.ok(woke(f).length - before < MAX_CHANNEL_WAKES);

  // The window passes: the thread wakes again.
  f.advance(CHANNEL_WAKE_WINDOW_MS + 1_000);
  await f.reply("parent", root.id, "@fake-grok one more");
  await f.drain();
  assert.equal(woke(f).length, MAX_CHANNEL_WAKES + 1);
  // Counted in the database: a fresh scanner (a restart) sees the same counts.
  const reserved = (await f.database.query("SELECT count(*)::int AS n FROM grok_bot_events WHERE wake_reserved_at IS NOT NULL")).rows[0]!.n;
  assert.equal(reserved, MAX_CHANNEL_WAKES + 1);
});

test("an unknown sender (no record here) counts as an agent: its thread reply is not saved, its mentions hit the hop cap", async t => {
  const f = await fixture(t);
  await webhook(f);
  f.world.addAgent("stranger");
  f.channel("stranger");
  const ownRoot = f.post("fake-grok", "anyone?");
  await f.reply("stranger", ownRoot.id, "me");
  for (let i = 0; i < MAX_AGENT_THREAD_WAKES + 1; i++) await f.reply("stranger", ownRoot.id, `@fake-grok ping ${i}`);
  await f.drain();
  const rows = await f.channelEvents();
  assert.deepEqual(rows.map(row => [row.addressed, row.sender_kind]), Array(MAX_AGENT_THREAD_WAKES + 1).fill(["mention", null]));
  assert.equal(woke(f).length, MAX_AGENT_THREAD_WAKES);
  assert.equal(woke(f)[0].senderKind, null);
});

test("pull-only: any OAuth connection reads addressed channel posts with get_recent_events, which refreshes its inbox first", async t => {
  const f = await fixture(t);
  const grant = randomUUID(), family = randomUUID();
  await f.addGrant(grant, f.chatClient, "family-chat", family);
  const chat = await f.connect(grant, family);
  const report = (await chat("describe_capabilities")).structuredContent as any;
  assert.equal(report.groups.find((g: any) => g.id === "grok_events").status, "available");
  assert.equal(report.groups.find((g: any) => g.id === "grok_routines").status, "unavailable");
  assert.equal((await chat("join_relay", {})).isError, undefined);
  await f.person("parent");
  f.world.channelAs("parent", CHANNEL);
  f.world.channels.get(CHANNEL)!.members.add("family-chat");
  f.world.channelAs("parent", CHANNEL, "chatter");
  const mention = f.world.channelAs("parent", CHANNEL, "@family-chat what time is dinner?")!;
  const recent = (await chat("get_recent_events", { limit: 10 })).structuredContent as any;
  assert.deepEqual(recent.events.map((event: any) => [event.name, event.data.messageId, event.data.addressed]),
    [["relay.channel_message", mention.id, "mention"]]);
  assert.equal(f.world.pending("family-chat").length, 0, "acknowledged after the read committed");
  const event = await chat("get_event", { eventId: recent.events[0].eventId });
  assert.equal(event.isError, undefined);
  assert.equal((await f.database.query("SELECT notified_at FROM grok_bot_events WHERE grant_id=$1", [grant])).rows[0]!.notified_at !== null, true,
    "with no routine nothing is pending a wake");
});

test("flag off: no event tools for any OAuth connection and nothing is ingested", async t => {
  const f = await fixture(t, { cloudCopy: false });
  const grant = randomUUID(), family = randomUUID();
  await f.addGrant(grant, f.chatClient, "family-chat", family);
  const chat = await f.connect(grant, family);
  const report = (await chat("describe_capabilities")).structuredContent as any;
  assert.equal(report.groups.find((g: any) => g.id === "grok_events").status, "unavailable");
  assert.equal((await chat("get_recent_events", {})).isError, true);
  await chat("join_relay", {});
  f.world.addAgent("parent-agent");
  f.world.channelAs("parent-agent", CHANNEL);
  f.world.channels.get(CHANNEL)!.members.add("family-chat");
  f.world.channelAs("parent-agent", CHANNEL, "@family-chat hello");
  await f.routines.tick();
  assert.equal(f.world.pending("family-chat").length, 1, "the inbox is left as it was");
  assert.equal((await f.database.query("SELECT count(*)::int AS n FROM grok_bot_events")).rows[0]!.n, 0);
});

test("polling: a scheduled read picks up only channel posts that reserved its wake; over-cap posts stay readable by hand", async t => {
  const f = await fixture(t);
  await f.tool("connect_grok_bot_routine", { mode: "polling" });
  await f.recordedAgent("ci-bot");
  f.channel("ci-bot");
  const root = f.post("ci-bot", "@fake-grok status?");
  for (let i = 0; i < MAX_AGENT_THREAD_WAKES; i++) await f.reply("ci-bot", root.id, `@fake-grok again ${i}`);
  await f.drain();
  const scheduled = (await f.tool("get_recent_events", { scheduled: true, limit: 50, since: "0" })).structuredContent as any;
  assert.equal(scheduled.events.length, MAX_AGENT_THREAD_WAKES);
  const manual = (await f.tool("get_recent_events", { limit: 50, since: "0" })).structuredContent as any;
  assert.equal(manual.events.length, MAX_AGENT_THREAD_WAKES + 1);
  assert.equal(f.calls.length, 0, "polling never posts a wake");
});

test("gate-only: the thread root is read through relaygate with the participant's own token, never Relaycast", async t => {
  const f = await fixture(t, { gate: true });
  await webhook(f);
  await f.person("parent");
  f.channel("parent");
  const agent = f.world.agents.get("fake-grok")!;
  f.gateTokens.set("rg_current", agent.token);
  await f.database.query(`UPDATE hosted_relay_participants SET relaygate_agent_id='rga_fake', token_ciphertext=$1, admitted_clients='{grok-bot,cursor-cloud}'
    WHERE agent_remote_id=$2`, [encryptSecret("rg_current", KEYRING.active), agent.id]);
  const ownRoot = f.post("fake-grok", "booked");
  await f.drain();
  f.relayPaths.length = 0;
  await f.reply("parent", ownRoot.id, "great");
  await f.drain();
  assert.deepEqual(woke(f).map(data => data.addressed), ["bot-thread"]);
  assert.ok(f.gatePaths.includes(`GET /v1/messages/${ownRoot.id}`), "the root lookup went through relaygate");
  assert.deepEqual(f.relayPaths.filter(path => path.startsWith("GET /v1/messages/") || /deliveries/.test(path)), [], "no direct Relaycast read");
});

// Workspace members' agents in channel posts (trustWorkspaceMembersInChannels): computed per event by get_event.
const trustOf = async (f: Fixture, eventId: string) => {
  const event = await f.tool("get_event", { eventId });
  const structured = event.structuredContent as any;
  return { trusted: structured.trustedSender, reason: structured.trustedSenderReason, text: (event.content as any)[0].text as string };
};
const mentionEvent = async (f: Fixture, from: string) => {
  f.post(from, `@fake-grok from ${from}`);
  await f.drain();
  return f.calls.filter(call => call.body.name === "relay.channel_message" && call.body.data.from === from).at(-1)!.body.eventId as string;
};

test("member trust: a current member's agent is trusted in a channel post, computed at get_event time; the opt-out and removal take effect at once", async t => {
  const f = await fixture(t);
  await webhook(f, "answer");
  const userId = await f.member();
  await f.participant("member-bot2", userId);
  f.channel("member-bot2");
  const eventId = await mentionEvent(f, "member-bot2");
  let trust = await trustOf(f, eventId);
  assert.deepEqual([trust.trusted, trust.reason], [true, "workspace member's agent"]);
  assert.match(trust.text, /Sender check: trustedSender true \(workspace member's agent\)\./);
  assert.match(trust.text, /Add text = your answer and call it now/);
  assert.equal((await f.database.query("SELECT trusted_reason FROM grok_bot_events")).rows[0]!.trusted_reason, null, "never stored");

  // Opt-out (the connection's setting), then back on: the same event follows the setting.
  assert.deepEqual((await f.tool("settings.read")).structuredContent, { trustWorkspaceMembersInChannels: true });
  assert.deepEqual((await f.tool("settings.update", { trustWorkspaceMembersInChannels: false })).structuredContent, { trustWorkspaceMembersInChannels: false });
  trust = await trustOf(f, eventId);
  assert.deepEqual([trust.trusted, trust.reason], [false, null]);
  assert.match(trust.text, /ask the person whether to reply/);
  await f.tool("settings.update", { trustWorkspaceMembersInChannels: true });
  assert.equal((await trustOf(f, eventId)).trusted, true);

  // Former member: the same event is no longer trusted.
  await f.database.query("DELETE FROM organization_memberships WHERE user_id=$1", [userId]);
  trust = await trustOf(f, eventId);
  assert.deepEqual([trust.trusted, trust.reason], [false, null]);
});

test("member trust never covers: another organization's person, an agent identity, an agent with no record (a Connect guest), or a DM", async t => {
  const f = await fixture(t, { memberTrust: true });
  await webhook(f, "answer");
  const outsiderId = await f.outsider();
  await f.participant("outsider-bot", outsiderId);
  await f.participant("identity-bot", null);
  // A Connect guest or anonymous agent: on the Relaycast roster, claiming a member's ownership in its own metadata.
  const memberId = await f.member();
  f.world.addAgent("guest-bot", { source: "cloud-hosted", owner_hash: "claimed", user_id: memberId });
  f.channel("outsider-bot", "identity-bot", "guest-bot");
  for (const from of ["outsider-bot", "identity-bot", "guest-bot"]) {
    const trust = await trustOf(f, await mentionEvent(f, from));
    assert.deepEqual([from, trust.trusted, trust.reason], [from, false, null]);
  }
  await f.participant("member-bot", memberId);
  f.world.sendAs("member-bot", "fake-grok", "a DM from a member's agent");
  await f.drain();
  const dm = f.calls.find(call => call.body.name === "relay.message")!.body.eventId;
  assert.equal((await trustOf(f, dm)).trusted, false, "DMs are unchanged");
});

test("member trust: the installation off switch wins over the connection's setting and hides the settings tools", async t => {
  const f = await fixture(t, { memberTrust: false });
  await webhook(f, "answer");
  const userId = await f.member();
  await f.participant("member-bot2", userId);
  f.channel("member-bot2");
  const trust = await trustOf(f, await mentionEvent(f, "member-bot2"));
  assert.deepEqual([trust.trusted, trust.reason], [false, null]);
  assert.equal((await f.tool("settings.read")).isError, true);
  const report = (await f.tool("describe_capabilities")).structuredContent as any;
  assert.equal(report.groups.find((g: any) => g.id === "events_settings").status, "unavailable");
});

test("member trust: flag off offers no settings tools and no events", async t => {
  const f = await fixture(t, { cloudCopy: false });
  assert.equal((await f.tool("settings.update", { trustWorkspaceMembersInChannels: false })).isError, true);
  assert.equal((await f.tool("get_event", { eventId: "evt_" + "0".repeat(32) })).isError, true);
  const report = (await f.tool("describe_capabilities")).structuredContent as any;
  assert.equal(report.groups.find((g: any) => g.id === "events_settings").status, "unavailable");
});

test("member trust: the switch parses on and off and defaults on", () => {
  assert.equal(loadMcpOAuthConfig({}, () => undefined).channelMemberTrust, true);
  assert.equal(loadMcpOAuthConfig({ SELFHOST_TRUST_WORKSPACE_MEMBERS_IN_CHANNELS: "off" }, () => undefined).channelMemberTrust, false);
  assert.throws(() => loadMcpOAuthConfig({ SELFHOST_TRUST_WORKSPACE_MEMBERS_IN_CHANNELS: "maybe" }, () => undefined), /must be on or off/);
});
