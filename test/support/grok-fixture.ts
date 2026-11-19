// Shared fixture for the Grok Bot Cloud-copy and agent-rules tests.
import type test from "node:test";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createApp } from "../../src/app.js";
import type { SelfhostConfig } from "../../src/config.js";
import { encryptSecret } from "../../src/crypto.js";
import { migrate } from "../../src/migrations.js";
import { ControlPlaneStore } from "../../src/store.js";
import { createRelaycastClient } from "../../src/messaging/relaycast.js";
import { GrokRoutines, GROK_SETUP_PATH } from "../../src/mcp/grok-routines.js";
import { createMcpOAuthProtocol } from "../../src/mcp/oauth/protocol.js";
import { McpOAuthSessions } from "../../src/mcp/oauth/sessions.js";
import { PGliteDatabase, listen, close } from "./harness.js";
import { createRelaycastWorld } from "./relaycast-world.js";

import type { AgentRules } from "../../src/agent-rules/service.js";

// SELFHOST_GROK_ROUTINES_CLOUD_COPY (docs/specs/grok-bot-dynamic-prompt.md, Phase 1).
const ORIGIN = "https://relay.example.test", SHARED = "/api/v1/mcp/shared-sessions";
export const KEYRING = { active: { id: "fake-key", key: Buffer.alloc(32, 7) } };
export const URL = "https://api2.cursor.sh/automations/webhook/rt_fake";
export const KEY = "crsr_" + "fake_routine_key_".repeat(3);

export const ORIGIN_FOR_TESTS = "https://relay.example.test";

/** A Grok Bot OAuth connection on a self-hosted app, with the Cloud copy on unless cloudCopy is false. */
export async function grokFixture(t: test.TestContext, cloudCopy = true, extra: { dynamicPrompt?: { bootstrapVersion: number }; agentRules?: AgentRules } = {}) {
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
    cloudCopy, ...(extra.dynamicPrompt ? { dynamicPrompt: extra.dynamicPrompt } : {}), fetchImpl: async (input, init) => {
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
  const server = createServer(createApp({ config, store, messagingFetch: relayFetch, grokRoutines: routines, ...(extra.agentRules ? { agentRules: extra.agentRules } : {}) }));
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
  return { database, owner, addGrant, issue, pair, store, base, browser, routines, world, calls, tool, setup, message, sender,
    advance: () => { now = new Date(now.getTime() + 301_000); }, fail: (status: number) => { webhookStatus = status; } };
}

