import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { encryptSecret, decryptSecret } from "../src/crypto.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { createRelaycastClient } from "../src/messaging/relaycast.js";
import { GrokRoutines, GROK_SETUP_PATH } from "../src/mcp/grok-routines.js";
import { parseGrokRoutineCredentials } from "../src/mcp/grok-routine.js";
import { createMcpOAuthProtocol } from "../src/mcp/oauth/protocol.js";
import { McpOAuthSessions } from "../src/mcp/oauth/sessions.js";
import { revokeMcpOAuthGrantRows } from "../src/mcp/oauth/revocations.js";
import { PGliteDatabase, listen, close } from "./support/harness.js";
import { createRelaycastWorld } from "./support/relaycast-world.js";

const ORIGIN = "https://relay.example.test", SHARED = "/api/v1/mcp/shared-sessions";
const KEYRING = { active: { id: "fake-key", key: Buffer.alloc(32, 7) } };
const URL = "https://api2.cursor.sh/automations/webhook/rt_fake";
const KEY = "crsr_" + "fake_routine_key_".repeat(3);

async function fixture(t: test.TestContext, resourcePath: typeof SHARED | "/mcp" = SHARED) {
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
  await database.query(`INSERT INTO mcp_oauth_grants(id,client_id,user_id,organization_id,workspace_id,agent_name,scopes,resource,token_family_id)
    VALUES ($1,$2,$3,$4,$5,'fake-grok',$6,$7,$8)`, [owner.grantId, clientId, owner.userId, owner.organizationId, owner.workspaceId,
    ["relay:mcp"], protocol.mcpResourceUrl(resourcePath), owner.tokenFamilyId]);
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
    // The real GET /v1/agent returns workspace_id; the generic world predates that field.
    if (url.pathname === "/v1/agent" && result?.status === 200) (result.body as any).data.workspace_id = "fake-workspace";
    return Response.json(result?.body ?? { ok: false, error: { code: "not_found" } }, { status: result?.status ?? 404 });
  };
  const cast = createRelaycastClient({ internalOrigin: "http://fake-relay.test", fetchImpl: relayFetch });
  const calls: Array<{ url: string; headers: Headers; body: any; redirect?: RequestRedirect }> = [];
  let webhookStatus = 202;
  const routines = new GrokRoutines({ database, keyring: KEYRING, client: cast, publicOrigin: ORIGIN, tenancyMode: "multi", now: () => now,
    fetchImpl: async (input, init) => {
      calls.push({ url: String(input), headers: new Headers(init?.headers), body: JSON.parse(String(init?.body)), redirect: init?.redirect });
      return new Response("PROVIDER_SECRET_MUST_NOT_LEAK", { status: webhookStatus });
    } });
  const config: SelfhostConfig = { databaseUrl: "unused", publicBaseUrl: ORIGIN, dashboardUrl: ORIGIN,
    relaycastUrl: "http://fake-relay.test", relaycastPublicUrl: "https://cast.example.test",
    relayhistoryUrl: "http://unused-history.test", relayhistoryPublicUrl: "https://history.example.test",
    sessionReadApi: { url: "http://unused-history.test", publicUrl: "https://history.example.test", secret: "session-read-secret-".repeat(2) },
    internalServiceToken: null, bootstrapToken: "fake-bootstrap-token-at-least-thirty-two-bytes", encryptionKeyring: KEYRING,
    oauthRedirectUrl: ORIGIN + "/unused", host: "127.0.0.1", port: 3000,
    mcpOAuth: { enabled: true, unavailable: null, eventsEnabled: false, pumpEnabled: false, oidc: null } };
  const store = new ControlPlaneStore(database, KEYRING, 0, { tenancy: "multi" });
  const browser = await database.transaction(tx => store.issueBrowserSession(tx, { ...owner, label: "grok-test" }));
  const server = createServer(createApp({ config, store, messagingFetch: relayFetch, grokRoutines: routines }));
  const base = await listen(server); t.after(() => close(server));
  const client = new Client({ name: "grok-test", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new globalThis.URL(base + resourcePath), { requestInit: { headers: { authorization: `Bearer ${pair.accessToken}` } } }));
  t.after(() => client.close());
  const tool = async (name: string, args = {}) => client.callTool({ name, arguments: args });
  const setup = async (method = "GET", body?: unknown, headers: Record<string, string> = {}) => fetch(base + GROK_SETUP_PATH + "?grant=" + owner.grantId, {
    method, redirect: "manual", headers: { cookie: `agent_relay_session=${browser.accessToken}`, origin: ORIGIN, "content-type": "application/json", ...headers },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const save = () => setup("POST", { webhook_url: URL, authorization: `Authorization: Bearer ${KEY}` });
  const message = async () => {
    const sender = world.agents.get("sender") ?? world.addAgent("sender");
    await cast.sendDirectMessage({ token: sender.token, to: "fake-grok", text: "PRIVATE_MESSAGE_BODY", idempotencyKey: randomUUID() });
  };
  return { database, owner, clientId, pair, routines, world, calls, tool, setup, save, message, base,
    advance: () => { now = new Date(now.getTime() + 301_000); }, fail: (status: number) => { webhookStatus = status; } };
}

test("self-hosted Grok OAuth discovers wake-ups, creates its pinned participant and stores browser-only encrypted credentials", async t => {
  const f = await fixture(t);
  assert.ok((await f.tool("describe_capabilities")).structuredContent);
  const connected = (await f.tool("connect_grok_bot_routine")).structuredContent as any;
  assert.match(connected.setup_url, /^https:\/\/relay.example.test\/cloud\/api\/v1\/grok-bot\/routine\?grant=/);
  assert.equal(connected.configured, false);
  assert.match(connected.routine_prompt, /check_relay_inbox/);
  assert.equal(connected.inbox_address, `fake-grok@cloud-${f.world.agents.get("fake-grok")!.id}`);
  const report = (await f.tool("describe_capabilities")).structuredContent as any;
  assert.equal(report.groups.find((g: any) => g.id === "grok_routines").status, "available");
  assert.equal(report.providers.find((p: any) => p.id === "grok-bot").mcpGroupsRegistered, true);
  const wrong = await f.tool("connect_grok_bot_routine", { name: "someone-else" });
  assert.equal(wrong.isError, true);
  assert.equal((await f.save()).status, 200);
  const saved = (await f.database.query("SELECT * FROM grok_bot_routines")).rows[0]!;
  assert.ok(!JSON.stringify(saved).includes(KEY)); assert.ok(!JSON.stringify(saved).includes(URL));
  assert.deepEqual(JSON.parse(decryptSecret(String(saved.credentials_ciphertext), KEYRING)), { url: URL, key: KEY });
  const page = await f.setup(); assert.equal(page.status, 200);
  assert.match(page.headers.get("content-security-policy")!, /script-src 'nonce-/);
  assert.ok(!(await page.text()).includes(KEY));
});

test("worker wakes pending inbox once across restarts, includes no message text and leaves acknowledgement to the bot", async t => {
  const f = await fixture(t, "/mcp");
  await f.tool("connect_grok_bot_routine"); await f.save(); await f.message();
  await f.routines.tick();
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0]!.url, URL); assert.equal(f.calls[0]!.headers.get("authorization"), `Bearer ${KEY}`);
  assert.equal(f.calls[0]!.redirect, "error");
  assert.equal(f.calls[0]!.body.name, "relay.inbox");
  assert.ok(!JSON.stringify(f.calls[0]!.body).includes("PRIVATE_MESSAGE_BODY"));
  assert.equal(f.world.pending("fake-grok").length, 1);
  f.advance();
  const restarted = new GrokRoutines(f.routines.options); await restarted.tick(); assert.equal(f.calls.length, 1);
  const inbox = (await f.tool("check_relay_inbox")).structuredContent as any;
  assert.equal(inbox.messages[0].text, "PRIVATE_MESSAGE_BODY");
  await f.tool("check_relay_inbox", { acknowledge: [inbox.messages[0].delivery_id] });
  f.advance(); await restarted.tick(); assert.equal(f.world.pending("fake-grok").length, 0);
  await f.message(); f.advance(); await restarted.tick(); assert.equal(f.calls.length, 2);
  assert.equal(((await f.tool("grok_bot_routine_status")).structuredContent as any).webhook_accepted, true);
});

test("failed webhooks persist a retry, keep the same event id, redact errors and disconnect deletes the credential", async t => {
  const f = await fixture(t); await f.tool("connect_grok_bot_routine"); await f.save(); await f.message(); f.fail(503);
  await f.routines.tick(); assert.equal(f.calls.length, 1);
  const state = (await f.tool("grok_bot_routine_status")).structuredContent as any;
  assert.equal(state.webhook_accepted, false); assert.equal(state.last_error, "delivery_unavailable");
  assert.ok(!JSON.stringify(state).includes("PROVIDER_SECRET"));
  await f.routines.tick(); assert.equal(f.calls.length, 1, "backoff survives a new scan");
  f.fail(202); f.advance(); await f.routines.tick(); assert.equal(f.calls.length, 2);
  assert.equal(f.calls[0]!.headers.get("webhook-id"), f.calls[1]!.headers.get("webhook-id"));
  assert.deepEqual((await f.tool("disconnect_grok_bot_routine")).structuredContent, { removed: 1 });
  assert.equal((await f.database.query("SELECT * FROM grok_bot_routines")).rows.length, 0);
  await f.message(); f.advance(); await f.routines.tick(); assert.equal(f.calls.length, 2);
});

test("browser setup refuses anonymous, bearer, cross-origin and cross-owner callers; other connector kinds get no wake-up tools", async t => {
  const f = await fixture(t); await f.tool("connect_grok_bot_routine");
  assert.equal((await f.setup("GET", undefined, { cookie: "" })).status, 302);
  assert.equal((await f.setup("POST", { webhook_url: URL, authorization: KEY }, { origin: "https://evil.test" })).status, 403);
  assert.equal((await f.setup("POST", { webhook_url: URL, authorization: KEY }, { authorization: `Bearer ${f.pair.accessToken}` })).status, 401);
  const before = await f.routines.status(f.owner.grantId, f.owner); assert.equal(before.configured, false);
  await assert.rejects(f.routines.status(f.owner.grantId, { ...f.owner, userId: randomUUID() }));
  await assert.rejects(f.routines.status(f.owner.grantId, { ...f.owner, workspaceId: randomUUID() }));
  await f.database.query("UPDATE mcp_oauth_clients SET redirect_uris=$2 WHERE client_id=$1", [f.clientId, ["https://chatgpt.com/callback"]]);
  assert.ok(!(await f.tool("describe_capabilities")).isError);
  const report = (await f.tool("describe_capabilities")).structuredContent as any;
  assert.equal(report.groups.find((g: any) => g.id === "grok_routines").status, "unavailable");
  const tools = await f.tool("connect_grok_bot_routine"); assert.equal(tools.isError, true);
  assert.equal((await f.save()).status, 400);
});

test("revocation deletes the encrypted routine atomically; expired sessions stop the worker", async t => {
  const f = await fixture(t); await f.tool("connect_grok_bot_routine"); await f.save(); await f.message();
  await assert.rejects(f.database.transaction(async tx => {
    await revokeMcpOAuthGrantRows(tx, f.owner.grantId, "test", new Date()); throw new Error("rollback");
  }), /rollback/);
  assert.equal((await f.database.query("SELECT * FROM grok_bot_routines")).rows.length, 1);
  await f.database.query("UPDATE mcp_oauth_sessions SET refresh_token_expires_at=now()-interval '1 day'");
  await f.routines.tick(); assert.equal(f.calls.length, 0);
  assert.equal((await f.database.query("SELECT * FROM grok_bot_routines")).rows.length, 0);
  await f.database.query("UPDATE mcp_oauth_sessions SET refresh_token_expires_at=now()+interval '1 day'");
  await f.save();
  await f.database.transaction(tx => revokeMcpOAuthGrantRows(tx, f.owner.grantId, "test", new Date()));
  assert.equal((await f.database.query("SELECT * FROM grok_bot_routines")).rows.length, 0);
  f.advance(); await f.routines.tick(); assert.equal(f.calls.length, 0);
});

test("worker refuses a changed remote owner or a token for another immutable agent", async t => {
  const f = await fixture(t); await f.tool("connect_grok_bot_routine"); await f.save(); await f.message();
  const remote = f.world.agents.get("fake-grok")!, metadata = { ...remote.metadata };
  remote.metadata.owner_hash = "someone-else";
  await f.routines.tick(); assert.equal(f.calls.length, 0);
  remote.metadata = metadata;
  const other = f.world.addAgent("different-agent", metadata);
  await f.database.query("UPDATE hosted_relay_participants SET token_ciphertext=$1 WHERE agent_remote_id=$2",
    [encryptSecret(other.token, KEYRING.active), remote.id]);
  f.advance(); await f.routines.tick(); assert.equal(f.calls.length, 0);
  await f.database.query("UPDATE hosted_relay_participants SET token_ciphertext=$1 WHERE agent_remote_id=$2",
    [encryptSecret(remote.token, KEYRING.active), remote.id]);
  f.advance(); await f.routines.tick(); assert.equal(f.calls.length, 1);
  await f.message(); f.fail(503); f.advance(); await f.routines.tick();
  const page = await f.setup(); assert.match(await page.text(), /Delivery failed/);
});

test("routine credentials refuse alternate origins, redirects, URL credentials, queries and malformed keys without echoing input", () => {
  for (const value of ["http://api2.cursor.sh/automations/webhook/a", "https://evil.test/automations/webhook/a", URL + "?key=secret",
    URL + "#secret", "https://u:p@api2.cursor.sh/automations/webhook/a", "https://api2.cursor.sh:444/automations/webhook/a"]) {
    assert.throws(() => parseGrokRoutineCredentials(value, KEY));
  }
  assert.throws(() => parseGrokRoutineCredentials(URL, "secret-invalid"), error => error instanceof Error && !error.message.includes("secret-invalid"));
  assert.deepEqual(parseGrokRoutineCredentials(URL, `Authorization: Bearer ${KEY}`), { url: URL, key: KEY });
});
