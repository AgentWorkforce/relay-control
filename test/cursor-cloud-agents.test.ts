import assert from "node:assert/strict";
import test from "node:test";
import { generateKeyPairSync, randomUUID, sign } from "node:crypto";
import { createServer } from "node:http";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { encryptSecret } from "../src/crypto.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { createRelaycastClient } from "../src/messaging/relaycast.js";
import { cursorCloudParticipantName, cursorJwks } from "../src/mcp/cursor-oidc.js";
import { loadCursorCloudConfig, type CursorCloudConfig } from "../src/mcp/cursor-cloud.js";
import { createMcpOAuthProtocol } from "../src/mcp/oauth/protocol.js";
import { McpOAuthSessions } from "../src/mcp/oauth/sessions.js";
import { McpOAuthTeardown } from "../src/mcp/oauth/teardown.js";
import { revokeMcpOAuthGrantRows } from "../src/mcp/oauth/revocations.js";
import { PGliteDatabase, listen, close } from "./support/harness.js";
import { createRelaycastWorld } from "./support/relaycast-world.js";

// Cursor cloud agents (docs/cursor-cloud-agents.md): a Cursor cloud agent
// connects with the person's OAuth grant from cursor.com/agents and joins as
// its own run's participant with a Cursor-signed OIDC token, once the Cursor
// account is linked to the person. A local RSA key stands in for
// api.cursor.com's signing key.

const ORIGIN = "https://relay.example.test";
const AUDIENCE = `${ORIGIN}/mcp#cursor-cloud`;
const KEYRING = { active: { id: "fake-key", key: Buffer.alloc(32, 7) } };

function cursorIssuer() {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const kid = "cursor-test-key";
  const jwks = cursorJwks({ fetchImpl: (async () => Response.json({ keys: [{ ...publicKey.export({ format: "jwk" }), kid, alg: "RS256", use: "sig" }] })) as typeof fetch });
  const mint = (nonce: string, claims: Record<string, unknown> = {}) => {
    const now = Math.floor(Date.now() / 1000);
    const head = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT", kid })).toString("base64url");
    const body = Buffer.from(JSON.stringify({ iss: "https://api.cursor.com", aud: AUDIENCE, sub: "user:4242", iat: now, nbf: now - 5,
      exp: now + 300, jti: randomUUID(), cloud_agent_id: "bc-run-1", agent_runtime: "managed", owner_user_id: "4242",
      owner_email: "dev@example.test", team_id: "77", repo_url: "github.com/example/widgets", nonce, ...claims })).toString("base64url");
    return `${head}.${body}.${sign("sha256", Buffer.from(`${head}.${body}`), privateKey).toString("base64url")}`;
  };
  return { jwks, mint };
}

const GATE = "https://gate.example.test";
const INTROSPECT_SECRET = "cursor-gate-introspection-secret-".repeat(2);

/**
 * A fake relaygate in front of the Relaycast world (as in
 * gate-only-hosted-participants.test.ts): POST /v1/register introspects the
 * hosted credential with Control's real endpoint; rg_ tokens act as their
 * upstream agent; self-administration and directory reads use the workspace
 * key, as relaygate does.
 */
function fakeRelaygate(relaycast: typeof fetch, world: ReturnType<typeof createRelaycastWorld>, control: () => string) {
  const tokens = new Map<string, string>(), agents = new Map<string, { agentId: string; userId: string }>();
  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const upstream = (path: string, token: string, init: RequestInit) =>
    relaycast(`http://example-relay.test${path}`, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json" } });
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new globalThis.URL(String(input instanceof Request ? input.url : input));
    if (url.origin !== GATE) return relaycast(input, init);
    const method = init?.method ?? "GET";
    const bearer = (new Headers(init?.headers).get("authorization") ?? "").replace(/^Bearer /, "");
    if (method === "POST" && url.pathname === "/v1/register") {
      const answer = await (await fetch(`${control()}/internal/v1/auth/introspect`, { method: "POST",
        headers: { authorization: `Bearer ${INTROSPECT_SECRET}`, "content-type": "application/json" },
        body: JSON.stringify({ token: bearer, aud: "https://history.example.test" }) })).json() as Record<string, any>;
      if (answer.active !== true || answer.principal_type !== "relay_hosted") return json(401, { error: "relaygate_unauthenticated" });
      const { name } = JSON.parse(String(init!.body)) as { name: string };
      let agent = agents.get(name);
      if (agent && agent.userId !== answer.sub) return json(409, { error: "relaygate_name_taken" });
      if (!agent) { agent = { agentId: `rga_${randomUUID()}`, userId: answer.sub }; agents.set(name, agent); }
      const existing = world.agents.get(name);
      if (existing) existing.metadata = { ...existing.metadata, relaygate: { agent_id: agent.agentId } };
      else world.addAgent(name, { relaygate: { agent_id: agent.agentId } });
      for (const [token, owner] of tokens) if (owner === name) tokens.delete(token);
      const token = `rg_${randomUUID()}`;
      tokens.set(token, name);
      return json(200, { agent_id: agent.agentId, gid: 55, token, user_id: answer.sub });
    }
    const name = tokens.get(bearer);
    if (!name) return json(401, { error: "relaygate_unauthenticated" });
    if (method === "GET" && url.pathname === "/v1/whoami") return json(200, { agent_id: agents.get(name)!.agentId, name, user_id: agents.get(name)!.userId });
    if (method === "PATCH" && url.pathname === "/v1/agent") return upstream(`/v1/agents/${encodeURIComponent(name)}`, "rk_example", { method: "PATCH", body: init!.body });
    if (method === "DELETE" && url.pathname === "/v1/agent") {
      const own = world.agents.get(name);
      for (const [token, owner] of tokens) if (owner === name) tokens.delete(token);
      if (!own) return json(404, { ok: false, error: { code: "agent_not_found" } });
      return upstream("/v1/agents/release-exact", "rk_example", { method: "POST",
        body: JSON.stringify({ name, expected_agent_id: own.id, delete_agent: true }) });
    }
    if (method === "GET" && (url.pathname.startsWith("/v1/agents") || url.pathname.startsWith("/v1/channels"))) {
      return upstream(`${url.pathname}${url.search}`, "rk_example", { method });
    }
    const own = world.agents.get(name);
    if (!own) return json(401, { error: "relaygate_unauthenticated" });
    return upstream(`${url.pathname}${url.search}`, own.token, { method, ...(init?.body ? { body: init.body } : {}) });
  }) as typeof fetch;
}

async function fixture(t: test.TestContext, options: { redirect?: string; cursorCloud?: Partial<CursorCloudConfig>; gate?: boolean } = {}) {
  const database = new PGliteDatabase(); t.after(() => database.close()); await migrate(database);
  const owner = { userId: randomUUID(), organizationId: randomUUID(), workspaceId: randomUUID(), grantId: randomUUID(), tokenFamilyId: randomUUID() };
  const clientId = "mcpc_" + randomUUID();
  await database.query("INSERT INTO users(id,email,name) VALUES ($1,'dev@example.test','Dev Person')", [owner.userId]);
  await database.query("INSERT INTO organizations(id,name) VALUES ($1,'Example Org')", [owner.organizationId]);
  await database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')", [owner.organizationId, owner.userId]);
  await database.query(`INSERT INTO workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
    VALUES ($1,$2,'Example Workspace','example-workspace',$3)`, [owner.workspaceId, owner.organizationId, encryptSecret("rk_example", KEYRING.active)]);
  await database.query("INSERT INTO mcp_oauth_clients(client_id,redirect_uris) VALUES ($1,$2)",
    [clientId, [options.redirect ?? "https://www.cursor.com/agents/oauth/callback"]]);
  const protocol = createMcpOAuthProtocol({ publicOrigin: ORIGIN, enabledResources: ["/api/v1/mcp/shared-sessions", "/mcp"] });
  await database.query(`INSERT INTO mcp_oauth_grants(id,client_id,user_id,organization_id,workspace_id,agent_name,scopes,resource,token_family_id)
    VALUES ($1,$2,$3,$4,$5,'dev-cursor',$6,$7,$8)`, [owner.grantId, clientId, owner.userId, owner.organizationId, owner.workspaceId,
    ["relay:mcp"], protocol.mcpResourceUrl("/mcp"), owner.tokenFamilyId]);
  const sessions = new McpOAuthSessions(database, { protocol, tenancyMode: "multi" });
  const pair = await database.transaction(tx => sessions.issue(tx, { ...owner, scopes: ["relay:mcp"] }));
  /** Another connection of the same person and Cursor client: a new grant and its session. */
  const grant = async () => {
    const grantId = randomUUID(), tokenFamilyId = randomUUID();
    await database.query(`INSERT INTO mcp_oauth_grants(id,client_id,user_id,organization_id,workspace_id,agent_name,scopes,resource,token_family_id)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, [grantId, clientId, owner.userId, owner.organizationId, owner.workspaceId, `dev-cursor-${grantId.slice(0, 6)}`,
      ["relay:mcp"], protocol.mcpResourceUrl("/mcp"), tokenFamilyId]);
    return { grantId, pair: await database.transaction(tx => sessions.issue(tx, { ...owner, grantId, tokenFamilyId, scopes: ["relay:mcp"] })) };
  };
  const world = createRelaycastWorld([]);
  /** When set, upstream releases wait for it (a release in flight). */
  let releaseGate: Promise<void> | null = null;
  const releaseStarted: Array<() => void> = [];
  const relayFetch: typeof fetch = async (input, init) => {
    const url = new globalThis.URL(input instanceof Request ? input.url : String(input)), headers = new Headers(init?.headers);
    if (url.pathname === "/v1/agents/release-exact" && releaseGate) {
      releaseStarted.splice(0).forEach(started => started());
      await releaseGate;
    }
    if (url.pathname === "/v1/agents" && (init?.method ?? "GET") === "GET") return Response.json({ ok: true,
      data: [...world.agents.values()].map(agent => ({ ...agent, address: `${agent.name}@cloud-${agent.id}`, last_seen: new Date().toISOString() })) });
    const result = await world.handle(init?.method ?? "GET", url.pathname, url.searchParams,
      (headers.get("authorization") ?? "").replace(/^Bearer /, ""), init?.body ? JSON.parse(String(init.body)) : null, headers.get("idempotency-key"));
    return Response.json(result?.body ?? { ok: false, error: { code: "not_found" } }, { status: result?.status ?? 404 });
  };
  const issuer = cursorIssuer();
  const config: SelfhostConfig = { databaseUrl: "unused", publicBaseUrl: ORIGIN, dashboardUrl: ORIGIN,
    relaycastUrl: "http://example-relay.test", relaycastPublicUrl: "https://cast.example.test",
    relayhistoryUrl: "http://unused-history.test", relayhistoryPublicUrl: "https://history.example.test",
    sessionReadApi: { url: "http://unused-history.test", publicUrl: "https://history.example.test", secret: "session-read-secret-".repeat(2) },
    internalServiceToken: null, bootstrapToken: "example-bootstrap-token-at-least-thirty-two-bytes", encryptionKeyring: KEYRING,
    oauthRedirectUrl: ORIGIN + "/unused", host: "127.0.0.1", port: 3000,
    mcpOAuth: { enabled: true, unavailable: null, eventsEnabled: false, pumpEnabled: false, oidc: null },
    cursorCloud: { ...loadCursorCloudConfig({}), ...options.cursorCloud },
    ...(options.gate ? { relaygatePublicUrl: GATE, introspectSecret: INTROSPECT_SECRET } : {}) };
  const store = new ControlPlaneStore(database, KEYRING, 0, { tenancy: "multi" });
  const browser = await database.transaction(tx => store.issueBrowserSession(tx, { ...owner, label: "cursor-test" }));
  let base = "";
  const messagingFetch = options.gate ? fakeRelaygate(relayFetch, world, () => base) : relayFetch;
  const teardown = new McpOAuthTeardown({ database, keyring: KEYRING,
    client: createRelaycastClient({ internalOrigin: "http://example-relay.test", fetchImpl: relayFetch }),
    ...(options.gate ? { gate: createRelaycastClient({ internalOrigin: GATE, fetchImpl: messagingFetch }) } : {}) });
  const server = createServer(createApp({ config, store, messagingFetch, cursorJwks: issuer.jwks, mcpOAuthTeardown: teardown }));
  base = await listen(server); t.after(() => close(server));
  const connect = async (accessToken: string) => {
    const client = new Client({ name: "cursor-cloud-test", version: "1" });
    await client.connect(new StreamableHTTPClientTransport(new globalThis.URL(base + "/mcp"), { requestInit: { headers: { authorization: `Bearer ${accessToken}` } } }));
    t.after(() => client.close());
    return async (name: string, args: Record<string, unknown> = {}) => client.callTool({ name, arguments: args });
  };
  const call = await connect(pair.accessToken);
  const ok = (result: Awaited<ReturnType<typeof call>>) => {
    assert.notEqual(result.isError, true, JSON.stringify(result.content));
    return result.structuredContent as Record<string, any>;
  };
  const failed = (result: Awaited<ReturnType<typeof call>>) => {
    assert.equal(result.isError, true, JSON.stringify(result.structuredContent));
    return (result.content as Array<{ text: string }>)[0]!.text;
  };
  /** The nonce relay_status hands this connection, as the agent would read it. */
  const nonce = async () => ok(await call("relay_status")).cursor_identity.nonce as string;
  /** Follows a confirmation URL in the person's signed-in browser. */
  const confirm = async (url: string) => {
    const path = new URL(url);
    const headers = { cookie: `agent_relay_session=${browser.accessToken}`, origin: ORIGIN };
    const page = await fetch(base + path.pathname + path.search, { headers, redirect: "manual" });
    assert.equal(page.status, 200);
    assert.match(await page.text(), /user:4242/);
    const done = await fetch(base + path.pathname + path.search, { method: "POST", headers, redirect: "manual" });
    assert.equal(done.status, 200, await done.clone().text());
  };
  /** A same-origin POST from the person's signed-in browser; returns the status. */
  const post = async (pathAndQuery: string) => (await fetch(base + pathAndQuery, { method: "POST", redirect: "manual",
    headers: { cookie: `agent_relay_session=${browser.accessToken}`, origin: ORIGIN } })).status;
  /** Holds upstream releases until resume(); started resolves once one is waiting. */
  const pauseReleases = () => {
    let resume!: () => void;
    releaseGate = new Promise<void>(resolve => { resume = () => { releaseGate = null; resolve(); }; });
    const started = new Promise<void>(resolve => releaseStarted.push(resolve));
    return { started, resume: () => resume() };
  };
  return { database, owner, world, issuer, call, ok, failed, nonce, confirm, teardown, grant, connect, post, pauseReleases };
}

test("a Cursor cloud agent run links its Cursor account, joins as its own participant and messages as it", async t => {
  const f = await fixture(t);
  f.world.addAgent("peer");
  const status = f.ok(await f.call("relay_status"));
  assert.equal(status.cursor_identity.audience, AUDIENCE);
  assert.match(status.cursor_identity.mint_command, /CURSOR_AGENT_SOCKET.*\/v1\/tokens\/oidc/);
  assert.ok(status.cursor_identity.mint_command.includes(status.cursor_identity.nonce));

  // Not linked yet: a one-time confirmation link for the signed-in person.
  const pending = f.failed(await f.call("join_relay", { cursor_identity_token: f.issuer.mint(await f.nonce()) }));
  const url = /(https:\/\/relay\.example\.test\/cloud\/api\/v1\/cursor-cloud\/link\?code=[A-Za-z0-9_-]+)/.exec(pending)?.[1];
  assert.ok(url, pending);
  // The confirmation page answers on the server under test, not the public origin.
  await f.confirm(url!);

  const joined = f.ok(await f.call("join_relay", { cursor_identity_token: f.issuer.mint(await f.nonce()) }));
  const name = cursorCloudParticipantName("bc-run-1");
  assert.equal(joined.name, name);
  assert.equal(joined.cursor_cloud_run, true);
  assert.match(joined.reply_guidance, new RegExp(`as="${name}"`));
  // The run is its own participant: the grant's approved agent is never pinned to it.
  const grant = (await f.database.query("SELECT agent_remote_id FROM mcp_oauth_grants WHERE id=$1", [f.owner.grantId])).rows[0]!;
  assert.equal(grant.agent_remote_id, null);
  assert.deepEqual((await f.database.query("SELECT agent_name FROM cursor_cloud_runs")).rows, [{ agent_name: name }]);
  assert.equal(f.world.agents.get(name)!.metadata.created_by, "mcp-oauth");

  const sent = f.ok(await f.call("send_relay_message", { to: "peer", text: "hello from a cloud run", as: name }));
  assert.equal(sent.from, name);
  f.world.sendAs("peer", name, "hello back");
  const inbox = f.ok(await f.call("check_relay_inbox", { as: name }));
  assert.deepEqual(inbox.messages.map((m: any) => m.text), ["hello back"]);

  // A second run under the same connection is a different participant.
  const second = f.ok(await f.call("join_relay", { cursor_identity_token: f.issuer.mint(await f.nonce(), { cloud_agent_id: "bc-run-2" }) }));
  assert.equal(second.name, cursorCloudParticipantName("bc-run-2"));
  assert.notEqual(second.name, name);
});

test("tokens that are replayed, for another audience or another connection, or from an unlinked account are refused", async t => {
  const f = await fixture(t, { cursorCloud: { trustedTeams: ["77"] } });
  const token = f.issuer.mint(await f.nonce());
  // The operator trusts team 77 and the token's email is the person's own: linked without a click.
  assert.equal(f.ok(await f.call("join_relay", { cursor_identity_token: token })).name, cursorCloudParticipantName("bc-run-1"));
  assert.match(f.failed(await f.call("join_relay", { cursor_identity_token: token })), /refused \(replayed\)/);
  assert.match(f.failed(await f.call("join_relay", { cursor_identity_token: f.issuer.mint(await f.nonce(), { aud: "sts.amazonaws.com" }) })), /refused \(audience\)/);
  assert.match(f.failed(await f.call("join_relay", { cursor_identity_token: f.issuer.mint("a-nonce-for-some-other-connection") })), /refused \(nonce\)/);
  // A trusted team with someone else's email still needs the person to confirm.
  const other = f.failed(await f.call("join_relay", { cursor_identity_token: f.issuer.mint(await f.nonce(),
    { sub: "user:9999", owner_email: "someone@example.test", cloud_agent_id: "bc-run-9" }) }));
  assert.match(other, /cursor-cloud\/link\?code=/);
  // A run name can't be chosen, and it can't be combined with name.
  assert.match(f.failed(await f.call("join_relay", { name: "my-own-name", cursor_identity_token: f.issuer.mint(await f.nonce()) })), /cannot be combined/);
});

test("required run identity refuses the connector's shared agent and points at the mint command", async t => {
  const f = await fixture(t, { cursorCloud: { runIdentity: "required", trustedTeams: ["77"] } });
  f.world.addAgent("peer");
  const status = f.ok(await f.call("relay_status"));
  assert.equal(status.joined, false);
  assert.match(status.guidance, /join_relay with cursor_identity_token/);
  assert.match(f.failed(await f.call("send_relay_message", { to: "peer", text: "x" })), /acts only as a verified cloud agent run.*tokens\/oidc/s);
  const joined = f.ok(await f.call("join_relay", { cursor_identity_token: f.issuer.mint(await f.nonce()) }));
  assert.equal(f.ok(await f.call("send_relay_message", { to: "peer", text: "x", as: joined.name })).from, joined.name);
});

test("only Cursor cloud agent connections take identity tokens", async t => {
  const f = await fixture(t, { redirect: "https://chatgpt.com/connector/oauth/callback" });
  const status = f.ok(await f.call("relay_status"));
  assert.equal(status.cursor_identity, undefined);
  assert.match(f.failed(await f.call("join_relay", { cursor_identity_token: "x".repeat(40) })), /only for Cursor cloud agents/);
});

test("leaving releases a run, and revoking the connection releases its remaining runs", async t => {
  const f = await fixture(t, { cursorCloud: { trustedTeams: ["77"] } });
  const one = f.ok(await f.call("join_relay", { cursor_identity_token: f.issuer.mint(await f.nonce()) })).name as string;
  const two = f.ok(await f.call("join_relay", { cursor_identity_token: f.issuer.mint(await f.nonce(), { cloud_agent_id: "bc-run-2" }) })).name as string;
  f.ok(await f.call("leave_relay", { as: one }));
  assert.equal(f.world.agents.has(one), false);
  assert.deepEqual((await f.database.query("SELECT agent_name FROM cursor_cloud_runs")).rows, [{ agent_name: two }]);
  await f.database.transaction(tx => revokeMcpOAuthGrantRows(tx, f.owner.grantId, "user_revoked", new Date()));
  await f.teardown.drain();
  assert.equal(f.world.agents.has(two), false);
  assert.deepEqual((await f.database.query("SELECT agent_name FROM cursor_cloud_runs")).rows, []);
  assert.deepEqual((await f.database.query("SELECT agent_name FROM hosted_relay_participants")).rows, []);
});

test("a revoked connection's run stays while something live still uses it, and is fenced from reattachment until released", async t => {
  const f = await fixture(t, { cursorCloud: { trustedTeams: ["77"] } });
  const name = f.ok(await f.call("join_relay", { cursor_identity_token: f.issuer.mint(await f.nonce()) })).name as string;
  const second = await f.grant();
  const call2 = await f.connect(second.pair.accessToken);
  const nonce2 = async () => f.ok(await call2("relay_status")).cursor_identity.nonce as string;
  await f.database.transaction(tx => revokeMcpOAuthGrantRows(tx, f.owner.grantId, "user_revoked", new Date()));
  // Until the teardown worker has released it, no other connection may take the run over.
  assert.match(f.failed(await call2("join_relay", { cursor_identity_token: f.issuer.mint(await nonce2()) })), /being released/);
  await f.teardown.drain();
  assert.equal(f.world.agents.has(name), false);
  // After the release the run joins afresh under the new connection.
  assert.equal(f.ok(await call2("join_relay", { cursor_identity_token: f.issuer.mint(await nonce2()) })).name, name);

  // A run a native MCP session is bound to, or a live grant is pinned to, is kept; only the revoked run is forgotten.
  await f.database.query("UPDATE hosted_relay_participants SET session_hash='bound-native-session' WHERE agent_name=$1", [name]);
  await f.database.transaction(tx => revokeMcpOAuthGrantRows(tx, second.grantId, "user_revoked", new Date()));
  await f.teardown.drain();
  assert.equal(f.world.agents.has(name), true);
  assert.deepEqual((await f.database.query("SELECT agent_name FROM hosted_relay_participants")).rows, [{ agent_name: name }]);
  assert.deepEqual((await f.database.query("SELECT agent_name FROM cursor_cloud_runs")).rows, []);
});

test("a run shared by two connections survives one leaving; the last one releases it", async t => {
  const f = await fixture(t, { cursorCloud: { trustedTeams: ["77"] } });
  f.world.addAgent("peer");
  const name = f.ok(await f.call("join_relay", { cursor_identity_token: f.issuer.mint(await f.nonce()) })).name as string;
  const second = await f.grant();
  const call2 = await f.connect(second.pair.accessToken);
  const nonce2 = async () => f.ok(await call2("relay_status")).cursor_identity.nonce as string;
  assert.equal(f.ok(await call2("join_relay", { cursor_identity_token: f.issuer.mint(await nonce2()) })).name, name);
  assert.equal(f.ok(await f.call("leave_relay", { as: name })).kept_for_other_connections, true);
  assert.equal(f.world.agents.has(name), true);
  assert.equal(f.ok(await call2("send_relay_message", { to: "peer", text: "still here", as: name })).from, name);
  assert.match(f.failed(await f.call("send_relay_message", { to: "peer", text: "x", as: name })), /./);
  f.ok(await call2("leave_relay", { as: name }));
  assert.equal(f.world.agents.has(name), false);
});

test("required run identity: cards and directory reads take the run's name", async t => {
  const f = await fixture(t, { cursorCloud: { runIdentity: "required", trustedTeams: ["77"] } });
  f.world.addAgent("peer");
  const name = f.ok(await f.call("join_relay", { cursor_identity_token: f.issuer.mint(await f.nonce()) })).name as string;
  const card = f.ok(await f.call("set_relay_agent_card", { description: "Builds widgets in the cloud", skills: [], as: name }));
  assert.equal(card.name, name);
  assert.equal(card.card.description, "Builds widgets in the cloud");
  assert.match(JSON.stringify(f.world.agents.get(name)!.metadata), /Builds widgets in the cloud/);
  assert.ok(f.ok(await f.call("list_relay_agents", { status: "all", as: name })).agents.some((agent: any) => agent.name === "peer"));
  assert.equal(f.ok(await f.call("get_relay_agent_card", { agent: name, as: name })).description, "Builds widgets in the cloud");
});

test("a run whose release keeps failing does not hold up other runs' cleanup", async t => {
  const f = await fixture(t, { cursorCloud: { trustedTeams: ["77"] } });
  const one = f.ok(await f.call("join_relay", { cursor_identity_token: f.issuer.mint(await f.nonce()) })).name as string;
  const two = f.ok(await f.call("join_relay", { cursor_identity_token: f.issuer.mint(await f.nonce(), { cloud_agent_id: "bc-run-2" }) })).name as string;
  await f.database.transaction(tx => revokeMcpOAuthGrantRows(tx, f.owner.grantId, "user_revoked", new Date()));
  // The first run's release fails; the second is still released in the same pass.
  f.world.failNext("POST", "/v1/agents/release-exact", 503);
  await f.teardown.drain();
  assert.deepEqual([f.world.agents.has(one), f.world.agents.has(two)], [true, false]);
  await f.teardown.drain();
  assert.equal(f.world.agents.has(one), false);
  assert.deepEqual((await f.database.query("SELECT agent_name FROM cursor_cloud_runs")).rows, []);
});

test("a confirmation link redeems once even when confirmed twice at the same time", async t => {
  const f = await fixture(t);
  const pending = f.failed(await f.call("join_relay", { cursor_identity_token: f.issuer.mint(await f.nonce()) }));
  const url = new URL(/(https:\/\/\S+cursor-cloud\/link\?code=[A-Za-z0-9_-]+)/.exec(pending)![1]!);
  const statuses = await Promise.all([1, 2].map(() => f.post(url.pathname + url.search)));
  assert.deepEqual(statuses.sort(), [200, 404]);
  assert.equal((await f.database.query("SELECT count(*)::int AS n FROM admin_audit_events WHERE action='cursor_cloud.link.confirmed'")).rows[0]!.n, 1);
});

test("required run identity: leaving a run twice is idempotent, and Grok routines are refused with the setting to change", async t => {
  const f = await fixture(t, { cursorCloud: { runIdentity: "required", trustedTeams: ["77"] } });
  const name = f.ok(await f.call("join_relay", { cursor_identity_token: f.issuer.mint(await f.nonce()) })).name as string;
  assert.equal(f.ok(await f.call("leave_relay", { as: name })).already_left, false);
  assert.equal(f.ok(await f.call("leave_relay", { as: name })).already_left, true);
  assert.match(f.failed(await f.call("connect_grok_bot_routine", { mode: "webhook" })), /SELFHOST_CURSOR_CLOUD_RUN_IDENTITY=optional/);
});

for (const gate of [false, true]) test(`a run cannot be rejoined while its release is in flight${gate ? " (gate-only install)" : ""}`, async t => {
  const f = await fixture(t, { cursorCloud: { trustedTeams: ["77"] }, gate });
  const name = f.ok(await f.call("join_relay", { cursor_identity_token: f.issuer.mint(await f.nonce()) })).name as string;
  const second = await f.grant();
  const call2 = await f.connect(second.pair.accessToken);
  const nonce2 = async () => f.ok(await call2("relay_status")).cursor_identity.nonce as string;
  await f.database.transaction(tx => revokeMcpOAuthGrantRows(tx, f.owner.grantId, "user_revoked", new Date()));
  const paused = f.pauseReleases();
  const draining = f.teardown.drain();
  await paused.started;
  // The upstream release is in flight: the run can't be re-recorded for the live connection.
  assert.match(f.failed(await call2("join_relay", { cursor_identity_token: f.issuer.mint(await nonce2()) })), /being released/);
  paused.resume();
  await draining;
  assert.equal(f.world.agents.has(name), false);
  assert.deepEqual((await f.database.query("SELECT agent_name FROM cursor_cloud_runs")).rows, []);
  assert.deepEqual((await f.database.query("SELECT agent_name FROM hosted_relay_participants")).rows, []);
  const rejoined = f.ok(await call2("join_relay", { cursor_identity_token: f.issuer.mint(await nonce2()) }));
  assert.equal(rejoined.name, name);
  if (gate) {
    // Through relaygate: the participant holds only an rg_ token.
    const row = (await f.database.query<{ relaygate_agent_id: string | null }>("SELECT relaygate_agent_id FROM hosted_relay_participants")).rows[0]!;
    assert.ok(row.relaygate_agent_id);
  }
});

test("required run identity: an existing Grok routine can still be read and disconnected; saving a new one is refused", async t => {
  const f = await fixture(t, { cursorCloud: { runIdentity: "required" } });
  // A routine saved while run identity was optional.
  await f.database.query(`INSERT INTO grok_bot_routines(grant_id,credentials_ciphertext,next_attempt_at,updated_at)
    VALUES ($1,'sealed',now(),now())`, [f.owner.grantId]);
  assert.equal(f.ok(await f.call("grok_bot_routine_status")).configured, true);
  assert.match(f.failed(await f.call("connect_grok_bot_routine", { mode: "webhook" })), /SELFHOST_CURSOR_CLOUD_RUN_IDENTITY=optional/);
  assert.equal(f.ok(await f.call("disconnect_grok_bot_routine")).removed, 1);
});
