import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createAdminModule } from "../src/admin/routes.js";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { encryptSecret } from "../src/crypto.js";
import { AGENT_IDENTITY_TOOLS } from "../src/mcp/catalog.js";
import { pkceS256 } from "../src/mcp/oauth/protocol.js";
import { HOSTED_SOURCE, ownerHash } from "../src/mcp/relay-participants.js";
import { agentIdentityAllows } from "../src/mcp/routes.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";
import { createRelaycastWorld } from "./support/relaycast-world.js";

/**
 * Workspace agent identity tokens (docs/identity.md, "Workspace agent
 * identity tokens"): an owner or admin mints an expiring `sh_wk_` token of
 * purpose agent-identity (scope relay:agent) naming one agent of the
 * workspace. Over the shared-sessions MCP facade it reaches only the Relay
 * messaging tools and describe_capabilities, acting as that named agent and
 * never as a person. Every other sh_wk_ gate keeps refusing it.
 */

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const SERVICE = "internal-service-token-that-is-at-least-32-bytes";
const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const HISTORY = "https://history.selfhosted.test";
const MCP_PATH = "/api/v1/mcp/shared-sessions";
const DAY_MS = 86_400_000;

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");

type Minted = { id: string; accessToken: string } & Record<string, any>;

async function setup(t: TestContext, options: { mcpOAuth?: boolean } = {}) {
  const database = new PGliteDatabase();
  await migrate(database);
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: origin,
    relaycastUrl: "http://relaycast.invalid",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: HISTORY,
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: HISTORY, secret: "r".repeat(32) },
    introspectSecret: INTROSPECT_SECRET,
    introspectAudiences: [],
    relayhistoryAudiences: [HISTORY],
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: SERVICE,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${origin}/dashboard/`,
    port: 0,
    host: "127.0.0.1",
    ...(options.mcpOAuth ? { mcpOAuth: { enabled: true, unavailable: null, eventsEnabled: false, pumpEnabled: false, oidc: null } } : {}),
  };

  // One Relaycast for the whole install; every upstream bearer is recorded.
  const world = createRelaycastWorld([]);
  const bearers: string[] = [];
  const messagingFetch: typeof fetch = async (input, init) => {
    const url = new globalThis.URL(input instanceof Request ? input.url : String(input));
    const headers = new Headers(init?.headers);
    const bearer = (headers.get("authorization") ?? "").replace(/^Bearer /, "");
    bearers.push(bearer);
    if (url.pathname === "/v1/agents" && (init?.method ?? "GET") === "GET") {
      return Response.json({ ok: true, data: [...world.agents.values()].map(agent => ({
        ...agent, address: `${agent.name}@cloud-${agent.id}`, last_seen: new Date().toISOString() })) });
    }
    const result = await world.handle(init?.method ?? "GET", url.pathname, url.searchParams, bearer,
      init?.body ? JSON.parse(String(init.body)) : null, headers.get("idempotency-key"));
    return Response.json(result?.body ?? { ok: false, error: { code: "not_found" } }, { status: result?.status ?? 404 });
  };

  const store = new ControlPlaneStore(database, KEYRING, 0, { tenancy: "multi" });
  const admin = createAdminModule({ config, database, keyring: KEYRING });
  control.on("request", createApp({ config, store, admin, messagingFetch }));
  t.after(async () => {
    control.closeAllConnections();
    await close(control);
    await database.close();
  });

  const created = await request(origin, "/api/v1/organizations", {
    method: "POST", token: BOOTSTRAP, body: { name: "Acme", ownerEmail: "owner@acme.test", ownerName: "Owner" },
  });
  assert.equal(created.status, 201);
  const organizationId = created.body.id as string;
  const ownerId = created.body.owner.id as string;
  const newWorkspace = async (name: string, orgId = organizationId) => {
    const answer = await request(origin, `/api/v1/organizations/${orgId}/workspaces`, {
      method: "POST", token: BOOTSTRAP, body: { name, relaycastApiKey: `rk_${name}` },
    });
    assert.equal(answer.status, 201);
    return answer.body.id as string;
  };
  const addMember = async (email: string, role: "member" | "admin" | "owner" = "member", orgId = organizationId) => {
    const added = await request(origin, `/api/v1/organizations/${orgId}/memberships`, {
      method: "POST", token: BOOTSTRAP, body: { email, name: email, role },
    });
    assert.equal(added.status, 200);
    return added.body.userId as string;
  };
  const deviceToken = async (userId: string, workspaceId: string) => {
    const started = await request(origin, "/api/v1/auth/device/start", { method: "POST", body: {} });
    assert.equal(started.status, 201);
    const approved = await request(origin, "/api/v1/auth/device/approve", {
      method: "POST", token: BOOTSTRAP,
      body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: workspaceId },
    });
    assert.equal(approved.status, 200);
    const issued = await request(origin, "/api/v1/auth/device/token", {
      method: "POST", body: { device_code: started.body.device_code },
    });
    assert.equal(issued.status, 200);
    return issued.body.access_token as string;
  };

  const workspaceId = await newWorkspace("primary");
  const otherWorkspaceId = await newWorkspace("secondary");
  // A device token is bound to one workspace; the admin routes answer 404
  // workspace_not_found for any other path workspace. One per workspace.
  const owner = await deviceToken(ownerId, workspaceId);
  const otherOwner = await deviceToken(ownerId, otherWorkspaceId);
  const ownerFor = (workspace: string) => workspace === otherWorkspaceId ? otherOwner : owner;
  const tokensPath = (workspace = workspaceId) => `/api/v1/workspaces/${workspace}/deployment-api-tokens`;
  const mint = (body: Record<string, unknown>, token?: string, workspace = workspaceId) =>
    request(origin, tokensPath(workspace), { method: "POST", token: token ?? ownerFor(workspace), body: { purpose: "agent-identity", ...body } });
  const mintAgent = async (agentName: string, extra: Record<string, unknown> = {}, workspace = workspaceId, token?: string) => {
    const answer = await mint({ agentName, ...extra }, token, workspace);
    assert.equal(answer.status, 201, `mint ${agentName}: ${answer.status} ${JSON.stringify(answer.body)}`);
    return answer.body as Minted;
  };
  const identityOf = async (tokenId: string) => (await database.query<{ agent_identity_id: string }>(
    "SELECT agent_identity_id FROM workspace_api_tokens WHERE id = $1", [tokenId])).rows[0]!.agent_identity_id;

  const rpc = async (token: string, body: unknown, path = MCP_PATH, headers: Record<string, string> = {}) => {
    const response = await fetch(`${origin}${path}`, {
      method: "POST",
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        ...headers,
      },
      body: JSON.stringify(body),
    });
    const text = await response.text();
    let parsed: any = null;
    try { parsed = text ? JSON.parse(text) : null; } catch { parsed = text; }
    return { status: response.status, body: parsed };
  };
  const list = (token: string, path?: string, headers?: Record<string, string>) =>
    rpc(token, { jsonrpc: "2.0", id: 1, method: "tools/list" }, path, headers);
  const call = (token: string, name: string, args: Record<string, unknown> = {}, headers?: Record<string, string>) =>
    rpc(token, { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }, MCP_PATH, headers);
  const connect = async (token: string) => {
    const client = new Client({ name: "agent-identity-test", version: "1.0.0" });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${origin}${MCP_PATH}`),
      { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
    t.after(() => client.close());
    return client;
  };
  const introspect = (body: Record<string, unknown>) =>
    request(origin, "/internal/v1/auth/introspect", { method: "POST", token: INTROSPECT_SECRET, body });

  return {
    database, store, origin, world, bearers, organizationId, ownerId, workspaceId, otherWorkspaceId, owner, otherOwner,
    newWorkspace, addMember, deviceToken, tokensPath, mint, mintAgent, identityOf, rpc, list, call, connect, introspect,
  };
}

type Env = Awaited<ReturnType<typeof setup>>;

const relaycastWorkspaceOf = async (env: Env, workspaceId: string) => (await env.database.query<{ relaycast_workspace_id: string }>(
  "SELECT relaycast_workspace_id FROM workspaces WHERE id = $1", [workspaceId])).rows[0]!.relaycast_workspace_id;

/**
 * A person's hosted Relay participant under `name` in the workspace. With
 * `onRoster: false` its agent is left off the (install-wide) fake roster, so a
 * mint is refused by Control's own rows rather than by the roster check.
 */
async function personParticipant(env: Env, name: string, userId = env.ownerId, workspaceId = env.workspaceId,
  options: { onRoster?: boolean } = {}) {
  const remote = options.onRoster === false
    ? { id: `ag_off_roster_${randomUUID()}`, token: `at_${name}_off_roster` }
    : env.world.addAgent(name);
  await env.database.query(
    `INSERT INTO hosted_relay_participants (id, workspace_id, user_id, relaycast_workspace_id, session_hash, agent_name, agent_remote_id, token_ciphertext)
     VALUES ($1, $2, $3, $4, NULL, $5, $6, $7)`,
    [randomUUID(), workspaceId, userId, await relaycastWorkspaceOf(env, workspaceId), name, remote.id, encryptSecret(remote.token, KEYRING.active)],
  );
}

test("an owner mints an expiring sh_wk_ agent-identity token with exactly relay:agent", async (t) => {
  const env = await setup(t);
  const minted = await env.mintAgent("  release-bot  ");
  assert.match(minted.accessToken, /^sh_wk_/);
  assert.equal(minted.purpose, "agent-identity");
  assert.deepEqual(minted.scopes, ["relay:agent"]);
  assert.equal(minted.agent_name, "release-bot");
  assert.equal(minted.nodeName, null);
  assert.equal(minted.aud, null);
  // The label defaults to the trimmed name.
  assert.equal(minted.label, "release-bot");
  // 90 days by default.
  const days = (Date.parse(minted.accessTokenExpiresAt) - Date.now()) / DAY_MS;
  assert.ok(Math.abs(days - 90) < 0.01, `expires after ${days} days`);

  const labelled = await env.mintAgent("ci-bot", { label: "CI pipeline", expiryDays: 1 });
  assert.equal(labelled.label, "CI pipeline");
  assert.ok(Math.abs((Date.parse(labelled.accessTokenExpiresAt) - Date.now()) / DAY_MS - 1) < 0.01);
  const longest = await env.mintAgent("year-bot", { expiryDays: 365 });
  assert.ok(Math.abs((Date.parse(longest.accessTokenExpiresAt) - Date.now()) / DAY_MS - 365) < 0.01);

  // An admin (not only the owner) may mint.
  const adminId = await env.addMember("admin@acme.test", "admin");
  const adminToken = await env.deviceToken(adminId, env.workspaceId);
  await env.mintAgent("admin-bot", {}, env.workspaceId, adminToken);

  // The mint is audited with the identity it names.
  const audit = (await env.database.query<{ target: string }>(
    "SELECT target FROM admin_audit_events WHERE action = 'api_token.create' AND target LIKE $1", [`${minted.id}%`])).rows;
  assert.equal(audit.length, 1);
  assert.match(audit[0]!.target, /agent-identity: release-bot identity [0-9a-f-]{36}/);
});

test("mint validation: name rules, reserved names, expiry bounds, never-expiring, callers", async (t) => {
  const env = await setup(t);
  const refused: Array<[string, Record<string, unknown>, RegExp]> = [
    ["missing name", {}, /agentName is required/],
    ["blank name", { agentName: "   " }, /agentName is required/],
    ["non-string name", { agentName: 42 }, /agentName is required/],
    ["too long", { agentName: "a".repeat(65) }, /at most 64 characters/],
    ["bad characters", { agentName: "release bot" }, /Invalid agentName/],
    ["leading punctuation", { agentName: "-release" }, /Invalid agentName/],
    ["reserved", { agentName: "cloud-github" }, /reserved/],
    ["reserved, other case", { agentName: "Cloud-GitHub" }, /reserved/],
    ["reserved client name", { agentName: "Relay-Control" }, /reserved/],
    ["reserved brand prefix", { agentName: "AgentRelay-bot" }, /reserved/],
    ["reserved prefix", { agentName: "launcher-abc" }, /reserved/],
    ["reserved prefix, other case", { agentName: "Cursor-Cloud-run" }, /reserved/],
    ["expiry zero", { agentName: "ok-bot", expiryDays: 0 }, /expiryDays must be an integer from 1 to 365/],
    ["expiry above a year", { agentName: "ok-bot", expiryDays: 366 }, /expiryDays must be an integer from 1 to 365/],
    ["expiry fraction", { agentName: "ok-bot", expiryDays: 1.5 }, /expiryDays must be an integer from 1 to 365/],
    ["expiry string", { agentName: "ok-bot", expiryDays: "30" }, /expiryDays must be an integer from 1 to 365/],
    ["never expiring", { agentName: "ok-bot", neverExpires: true }, /always expire/],
    ["caller scopes", { agentName: "ok-bot", scopes: ["relay:agent", "runtime:env"] }, /scopes are fixed by purpose/],
  ];
  for (const [label, body, message] of refused) {
    const answer = await env.mint(body);
    assert.equal(answer.status, 400, `${label}: ${answer.status}`);
    assert.equal(answer.body.error, "invalid_request", label);
    assert.match(String(answer.body.message), message, label);
  }
  // 64 characters is the limit, inclusive.
  await env.mintAgent("a".repeat(64));
  // Nothing was written for a refused mint.
  assert.equal((await env.database.query("SELECT 1 FROM agent_identities")).rows.length, 1);

  // A member who is not an owner or admin is refused.
  const memberId = await env.addMember("member@acme.test");
  const member = await env.deviceToken(memberId, env.workspaceId);
  const byMember = await env.mint({ agentName: "member-bot" }, member);
  assert.equal(byMember.status, 403);

  // An enrollment-operator token manages only desktop-enrollment keys.
  const operator = await request(env.origin, env.tokensPath(), {
    method: "POST", token: env.owner, body: { label: "mdm", purpose: "enrollment-operator" },
  });
  assert.equal(operator.status, 201);
  const byOperator = await env.mint({ agentName: "operator-bot" }, operator.body.accessToken);
  assert.equal(byOperator.status, 403);
  assert.equal(byOperator.body.error, "enrollment_operator_scope");

  // An agent token cannot mint tokens of any purpose.
  const agent = await env.mintAgent("minting-bot");
  for (const body of [{ agentName: "child-bot" }, { purpose: "agent-runtime", label: "x" }]) {
    const answer = await env.mint(body, agent.accessToken);
    assert.equal(answer.status, 401, JSON.stringify(body));
  }
  // No bearer at all.
  assert.equal((await request(env.origin, env.tokensPath(), { method: "POST", body: { purpose: "agent-identity", agentName: "anon-bot" } })).status, 401);
  assert.equal((await env.database.query("SELECT 1 FROM agent_identities WHERE lower(agent_name) IN ('member-bot', 'operator-bot', 'child-bot', 'anon-bot')")).rows.length, 0);
});

test("a name a person's participant or a linked Desktop identity uses is 409 name_taken", async (t) => {
  const env = await setup(t);
  // Off the roster: this refusal comes from Control's own participant rows.
  await personParticipant(env, "person-bot", env.ownerId, env.workspaceId, { onRoster: false });
  const taken = await env.mint({ agentName: "Person-Bot" });
  assert.equal(taken.status, 409);
  assert.equal(taken.body.error, "name_taken");

  await env.database.query(
    `INSERT INTO desktop_relay_identities
       (id, workspace_id, organization_id, user_id, relaycast_workspace_id, source_id, agent_name,
        agent_remote_id, address, token_ciphertext)
     VALUES ($1, $2, $3, $4, $5, $6, 'desk-chat', 'remote-desk-chat', 'desk-chat@cloud-remote', 'encrypted-test-token')`,
    [randomUUID(), env.workspaceId, env.organizationId, env.ownerId, await relaycastWorkspaceOf(env, env.workspaceId), randomUUID()],
  );
  const desktop = await env.mint({ agentName: "DESK-CHAT" });
  assert.equal(desktop.status, 409);
  assert.equal(desktop.body.error, "name_taken");

  // The same names are free in another workspace.
  await env.mintAgent("person-bot", {}, env.otherWorkspaceId);
  await env.mintAgent("desk-chat", {}, env.otherWorkspaceId);

  // Rotation is refused once a person's participant has taken the name.
  await env.mintAgent("late-bot");
  await personParticipant(env, "late-bot", env.ownerId, env.workspaceId, { onRoster: false });
  const rotated = await env.mint({ agentName: "late-bot" });
  assert.equal(rotated.status, 409);
  assert.equal(rotated.body.error, "name_taken");
});

test("re-minting rotates: one identity, one Relay participant, older tokens stay live", async (t) => {
  const env = await setup(t);
  const first = await env.mintAgent("release-bot");
  const joined = await env.call(first.accessToken, "join_relay", {});
  assert.equal(joined.status, 200);
  assert.notEqual(joined.body.result.isError, true, JSON.stringify(joined.body));
  assert.equal(joined.body.result.structuredContent.name, "release-bot");
  const registrations = () => env.world.bodies.filter(entry => entry.method === "POST" && entry.path === "/v1/agents").length;
  assert.equal(registrations(), 1);

  const participants = async () => (await env.database.query<{ user_id: string | null; agent_identity_id: string | null; agent_name: string; agent_remote_id: string }>(
    "SELECT user_id, agent_identity_id, agent_name, agent_remote_id FROM hosted_relay_participants WHERE workspace_id = $1", [env.workspaceId])).rows;
  const before = await participants();
  assert.equal(before.length, 1);
  const identityId = await env.identityOf(first.id);
  // Never a person's: the participant is owned by the identity, not a user.
  assert.equal(before[0]!.user_id, null);
  assert.equal(before[0]!.agent_identity_id, identityId);
  assert.equal(before[0]!.agent_name, "release-bot");
  const remoteId = before[0]!.agent_remote_id;
  assert.equal(env.world.agents.get("release-bot")!.id, remoteId);

  // A second mint for the same name in another letter case reuses the identity.
  // Its roster check finds the identity's own agent (looked up by the
  // first-mint letter case), which does not hold the name against it.
  const lookups = () => env.world.bodies.filter(entry => entry.method === "GET" && entry.path === "/v1/agents/release-bot").length;
  const lookupsBefore = lookups();
  const second = await env.mintAgent("Release-Bot");
  assert.equal(lookups(), lookupsBefore + 1);
  assert.equal(second.agent_name, "release-bot");
  assert.equal(await env.identityOf(second.id), identityId);
  assert.equal((await env.database.query("SELECT 1 FROM agent_identities WHERE workspace_id = $1", [env.workspaceId])).rows.length, 1);

  // The new token reaches the same Relay agent: no second registration.
  const again = await env.call(second.accessToken, "join_relay", {});
  assert.notEqual(again.body.result.isError, true, JSON.stringify(again.body));
  assert.equal(again.body.result.structuredContent.name, "release-bot");
  const status = await env.call(second.accessToken, "relay_status", {});
  assert.notEqual(status.body.result.isError, true, JSON.stringify(status.body));
  const after = await participants();
  assert.equal(after.length, 1);
  assert.equal(after[0]!.agent_remote_id, remoteId);
  assert.equal(registrations(), 1);

  // Both tokens stay live.
  assert.equal((await env.list(first.accessToken)).status, 200);
  assert.equal((await env.list(second.accessToken)).status, 200);

  // A send acts as the named agent.
  env.world.addAgent("peer-bot");
  const sent = await env.call(first.accessToken, "send_relay_message", { to: "peer-bot", text: "build is green" });
  assert.equal(sent.status, 200);
  assert.notEqual(sent.body.result.isError, true, JSON.stringify(sent.body));
  assert.ok([...env.world.messages.values()].some(message => message.agent_name === "release-bot" && message.text === "build is green"));
});

const agentTokenRows = async (env: Env) => (await env.database.query(
  "SELECT 1 FROM workspace_api_tokens WHERE purpose = 'agent-identity'")).rows.length;
const identityRows = async (env: Env, ...names: string[]) => {
  let count = 0;
  for (const name of names) {
    count += (await env.database.query("SELECT 1 FROM agent_identities WHERE lower(agent_name) = lower($1)", [name])).rows.length;
  }
  return count;
};

test("a name another agent holds on the workspace's Relaycast roster is 409 name_taken", async (t) => {
  const env = await setup(t);
  // A plain agent, a person's hosted agent, a binding's agent and a released
  // agent all hold their names: only the identity's own agent does not.
  env.world.addAgent("roster-bot");
  env.world.addAgent("person-held", { source: HOSTED_SOURCE, cloud_workspace_id: env.workspaceId, owner_hash: ownerHash(env.ownerId) });
  env.world.addAgent("capy-held", { capy_binding_id: randomUUID() });
  env.world.addAgent("gone-bot").status = "released";
  for (const name of ["roster-bot", "person-held", "capy-held", "gone-bot"]) {
    const answer = await env.mint({ agentName: name });
    assert.equal(answer.status, 409, `${name}: ${answer.status} ${JSON.stringify(answer.body)}`);
    assert.equal(answer.body.error, "name_taken", name);
    assert.ok(env.world.bodies.some(entry => entry.method === "GET" && entry.path === `/v1/agents/${name}`), name);
  }
  // Nothing was written for a refused mint, and nothing was registered.
  assert.equal(await identityRows(env, "roster-bot", "person-held", "capy-held", "gone-bot"), 0);
  assert.equal(await agentTokenRows(env), 0);
  assert.equal(env.world.bodies.filter(entry => entry.method === "POST" && entry.path === "/v1/agents").length, 0);

  // A name free on the roster mints.
  await env.mintAgent("fresh-bot");
});

test("an unreadable roster is 503 relay_unavailable with Retry-After and writes nothing", async (t) => {
  const env = await setup(t);
  for (const status of [503, 500, 401]) {
    env.world.failNext("GET", "/v1/agents/flaky-bot", status);
    const answer = await env.mint({ agentName: "flaky-bot" });
    assert.equal(answer.status, 503, `upstream ${status}: ${answer.status} ${JSON.stringify(answer.body)}`);
    assert.equal(answer.body.error, "relay_unavailable", `upstream ${status}`);
    assert.equal(answer.headers.get("retry-after"), "5", `upstream ${status}`);
    assert.equal(await identityRows(env, "flaky-bot"), 0, `upstream ${status}`);
    assert.equal(await agentTokenRows(env), 0, `upstream ${status}`);
  }
  // The same rotation of an existing identity is refused the same way and
  // leaves its tokens as they were.
  const first = await env.mintAgent("steady-bot");
  env.world.failNext("GET", "/v1/agents/steady-bot", 503);
  const rotated = await env.mint({ agentName: "steady-bot" });
  assert.equal(rotated.status, 503);
  assert.equal(rotated.headers.get("retry-after"), "5");
  assert.equal(await agentTokenRows(env), 1);
  assert.equal((await env.list(first.accessToken)).status, 200);

  // Once the roster answers, the mint goes through.
  await env.mintAgent("flaky-bot");
  assert.equal(await identityRows(env, "flaky-bot"), 1);
});

test("a workspace with no Relaycast binding is bound by the route's access check first; unbindable is 503 relaycast_not_ready", async (t) => {
  // The mint route's owner/admin access check binds an unbound workspace, as
  // every owner/admin route does. This install has no Relaycast provisioner, so
  // the binding cannot be made: the route answers 503 relaycast_not_ready with
  // Retry-After, mints nothing, and leaves the workspace unbound.
  const env = await setup(t);
  await env.database.query(
    "UPDATE workspaces SET relaycast_workspace_id = NULL, relaycast_api_key_ciphertext = NULL WHERE id = $1", [env.otherWorkspaceId]);
  const tokensBefore = await agentTokenRows(env);
  const upstreamBefore = env.bearers.length;
  const bodiesBefore = env.world.bodies.length;
  const answer = await env.mint({ agentName: "unbound-bot" }, undefined, env.otherWorkspaceId);
  assert.equal(answer.status, 503, JSON.stringify(answer.body));
  assert.equal(answer.body.error, "relaycast_not_ready");
  assert.equal(answer.headers.get("retry-after"), "5");
  assert.equal(await agentTokenRows(env), tokensBefore);
  assert.equal(await identityRows(env, "unbound-bot"), 0);
  assert.equal(env.bearers.length, upstreamBefore, "no Relaycast call");
  assert.equal(env.world.bodies.length, bodiesBefore, "no Relaycast call");
  const binding = (await env.database.query<{ relaycast_workspace_id: string | null; relaycast_api_key_ciphertext: string | null }>(
    "SELECT relaycast_workspace_id, relaycast_api_key_ciphertext FROM workspaces WHERE id = $1", [env.otherWorkspaceId])).rows[0]!;
  assert.deepEqual(binding, { relaycast_workspace_id: null, relaycast_api_key_ciphertext: null });
});

test("a person cannot join_relay under an agent identity's name, whatever case the identity was minted in", async (t) => {
  const env = await setup(t);
  // Identity names may carry capitals; a person's relay name is lower case
  // only, so the collision to refuse is the lower-cased spelling.
  await env.mintAgent("Ops-Bot");
  await env.mintAgent("audit-bot");
  const bodiesAfterMint = env.world.bodies.length;
  for (const name of ["ops-bot", "audit-bot"]) {
    const answer = await env.call(env.owner, "join_relay", { name });
    assert.equal(answer.status, 200, name);
    assert.equal(answer.body.result.isError, true, `${name}: ${JSON.stringify(answer.body)}`);
    assert.match(answer.body.result.content[0].text, /That relay name is already taken/, name);
  }
  // Refused before any Relaycast lookup or registration under that name.
  assert.ok(!env.world.bodies.slice(bodiesAfterMint).some(entry =>
    entry.path.toLowerCase().includes("ops-bot") || entry.path.toLowerCase().includes("audit-bot")
      || (entry.method === "POST" && entry.path === "/v1/agents")));
  assert.equal(env.world.agents.has("Ops-Bot") || env.world.agents.has("ops-bot") || env.world.agents.has("audit-bot"), false);
  assert.equal((await env.database.query("SELECT 1 FROM hosted_relay_participants")).rows.length, 0);

  // A mixed-case person name never reaches the identity check: the tool's input
  // schema refuses it.
  const mixed = await env.call(env.owner, "join_relay", { name: "Ops-Bot" });
  assert.equal(mixed.status, 200);
  assert.equal(mixed.body.result?.isError ?? Boolean(mixed.body.error), true, JSON.stringify(mixed.body));
  assert.match(JSON.stringify(mixed.body), /-32602|Input validation error/);

  // A free name joins as the person's own participant.
  const joined = await env.call(env.owner, "join_relay", { name: "owner-chat" });
  assert.notEqual(joined.body.result.isError, true, JSON.stringify(joined.body));
  const rows = (await env.database.query<{ user_id: string; agent_name: string }>(
    "SELECT user_id, agent_name FROM hosted_relay_participants")).rows;
  assert.deepEqual(rows, [{ user_id: env.ownerId, agent_name: "owner-chat" }]);
});

test("OAuth consent reports an agent identity's name as taken, in any letter case", async (t) => {
  const env = await setup(t, { mcpOAuth: true });
  await env.mintAgent("Consent-Bot");
  const browser = await env.database.transaction(tx => env.store.issueBrowserSession(tx, {
    userId: env.ownerId, organizationId: env.organizationId, workspaceId: env.workspaceId, label: "consent-test" }));
  const cookie = `agent_relay_session=${browser.accessToken}`;
  const post = (path: string, body: unknown, headers: Record<string, string> = {}) => fetch(`${env.origin}${path}`, {
    method: "POST", headers: { "content-type": "application/json", accept: "application/json", ...headers }, body: JSON.stringify(body) });
  const registered = await (await post("/cloud/api/oauth/register", {
    client_name: "Consent client", redirect_uris: ["https://client.example.test/cb"] })).json();
  const params = {
    client_id: registered.client_id, response_type: "code", redirect_uri: "https://client.example.test/cb",
    code_challenge: pkceS256("v".repeat(43)), code_challenge_method: "S256", resource: `${env.origin}/cloud${MCP_PATH}`,
  };
  const page = await fetch(`${env.origin}/cloud/oauth/authorize?${new URLSearchParams(params)}`, { headers: { cookie }, redirect: "manual" });
  assert.equal(page.status, 200);
  const approve = (agentName: string) => post("/cloud/api/oauth/authorize",
    { params, decision: "approve", workspace_id: env.workspaceId, agent_name: agentName }, { cookie, origin: env.origin });
  for (const name of ["consent-bot", "CONSENT-BOT", "Consent-Bot"]) {
    const answer = await approve(name);
    assert.equal(answer.status, 409, name);
    assert.equal((await answer.json()).error, "agent_name_taken", name);
  }
  assert.equal((await env.database.query("SELECT 1 FROM mcp_oauth_authorization_codes")).rows.length, 0);

  // A free name is approved.
  const free = await approve("consent-app");
  assert.equal(free.status, 200, JSON.stringify(await free.clone().json()));
  assert.ok(new URL((await free.json()).redirect_to).searchParams.get("code"));
});

test("admission: header bearer on the shared-sessions facade only, live, unexpired, exact purpose and scope", async (t) => {
  const env = await setup(t);
  const agent = await env.mintAgent("gate-bot");
  const token = agent.accessToken;
  assert.equal((await env.list(token)).status, 200);
  assert.equal((await env.list(token, `/cloud${MCP_PATH}`)).status, 200);
  const used = (await env.database.query<{ last_used_at: Date | null }>(
    "SELECT last_used_at FROM workspace_api_tokens WHERE id = $1", [agent.id])).rows[0]!;
  assert.notEqual(used.last_used_at, null);

  // Never as a cookie.
  const cookie = await fetch(`${env.origin}/cloud${MCP_PATH}`, {
    method: "POST",
    headers: { cookie: `agent_relay_session=${token}`, "content-type": "application/json", accept: "application/json, text/event-stream", origin: env.origin },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  assert.ok(cookie.status === 401 || cookie.status === 403, `cookie: ${cookie.status}`);
  await cookie.body?.cancel();
  // Never on another MCP path.
  assert.notEqual((await env.list(token, "/mcp")).status, 200);
  assert.notEqual((await env.list(token, "/cloud/mcp")).status, 200);
  // A forged or altered token is not a token.
  assert.equal((await env.list(`${token}x`)).status, 401);
  assert.equal((await env.list(`sh_wk_${randomUUID().replaceAll("-", "")}`)).status, 401);

  // Every other sh_wk_ purpose keeps its existing answer on the facade: a
  // workspace token is 403; an enrollment-operator token is not a workspace
  // token to the facade (as on every route but the token routes) and is 401.
  for (const [body, status] of [
    [{ label: "runtime", purpose: "agent-runtime" }, 403],
    [{ label: "workflow", purpose: "workflow" }, 403],
    [{ label: "deployment", purpose: "deployment" }, 403],
    [{ label: "mdm", purpose: "enrollment-operator" }, 401],
  ] as const) {
    const other = await request(env.origin, env.tokensPath(), { method: "POST", token: env.owner, body });
    assert.equal(other.status, 201, body.purpose);
    const answer = await env.list(other.body.accessToken);
    assert.equal(answer.status, status, body.purpose);
    if (status === 403) assert.equal(answer.body.error.code, -32003, body.purpose);
  }

  // Scopes other than exactly relay:agent are refused (403: still a live workspace token).
  const scoped = await env.mintAgent("scope-bot");
  for (const scopes of [["relay:agent", "runtime:env"], ["runtime:env"], []]) {
    await env.database.query("UPDATE workspace_api_tokens SET scopes = $2 WHERE id = $1", [scoped.id, scopes]);
    assert.notEqual((await env.list(scoped.accessToken)).status, 200, JSON.stringify(scopes));
  }
  await env.database.query("UPDATE workspace_api_tokens SET scopes = ARRAY['relay:agent'] WHERE id = $1", [scoped.id]);
  assert.equal((await env.list(scoped.accessToken)).status, 200);

  // Expired.
  const expiring = await env.mintAgent("expired-bot");
  await env.database.query("UPDATE workspace_api_tokens SET expires_at = now() - interval '1 minute' WHERE id = $1", [expiring.id]);
  assert.equal((await env.list(expiring.accessToken)).status, 401);

  // Revoked through the existing route.
  const revoked = await env.mintAgent("revoked-bot");
  const deleted = await request(env.origin, `${env.tokensPath()}/${revoked.id}`, { method: "DELETE", token: env.owner });
  assert.equal(deleted.status, 204);
  assert.equal((await env.list(revoked.accessToken)).status, 401);

  // A token row cannot change purpose while bound to an identity (the CHECK
  // pins agent_identity_id to purpose agent-identity).
  await assert.rejects(env.database.query(
    "UPDATE workspace_api_tokens SET purpose = 'agent-runtime', agent_name = NULL WHERE id = $1", [agent.id]));
});

test("the fence: tools/list is the allowlist and an unlisted call is refused before dispatch", async (t) => {
  const env = await setup(t);
  const { accessToken: token } = await env.mintAgent("fence-bot");

  const client = await env.connect(token);
  const tools = (await client.listTools()).tools.map(tool => tool.name).sort();
  assert.deepEqual(tools, [...AGENT_IDENTITY_TOOLS].sort());

  const report = (await client.callTool({ name: "describe_capabilities", arguments: {} })).structuredContent as Record<string, any>;
  assert.equal(report.connection.auth_mode, "agent_identity");
  assert.deepEqual(report.connection.scopes, ["relay:agent"]);
  assert.equal(report.workspace.workspace_id, env.workspaceId);
  assert.equal(report.workspace.can_launch, false);
  const available = report.groups.filter((group: any) => group.status === "available").map((group: any) => group.id).sort();
  assert.deepEqual(available, ["capability_discovery", "relay_messaging"]);
  const reads = report.groups.find((group: any) => group.id === "shared_session_reads");
  assert.equal(reads.status, "unavailable");
  assert.match(reads.reason, /agent identity token/);

  const forbidden: unknown[] = [
    ...["list_team_activity", "search_shared_sessions", "get_shared_session", "list_session_summaries", "get_session_summary",
      "list_session_timings", "spawn_relay_agent", "release_relay_agent", "list_relay_spawn_targets", "link_webhook_inbox",
      "unlink_webhook_inbox", "ask_customer_support", "bind_replica", "spawn_replica", "bind_amp_thread", "spawn_capy_thread",
      "show_ui", "show_ui_guide", "create_connect", "not_a_tool"]
      .map(name => ({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: {} } })),
    { jsonrpc: "2.0", id: 1, method: "resources/read", params: { uri: "ui://relay/inbox" } },
    { jsonrpc: "2.0", id: 1, method: "resources/list" },
    { jsonrpc: "2.0", id: 1, method: "prompts/list" },
    // A tools/call without an id is not a notification.
    { jsonrpc: "2.0", method: "tools/call", params: { name: "send_relay_message", arguments: {} } },
    // An allowed call cannot hide a forbidden one in a batch.
    [
      { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "describe_capabilities", arguments: {} } },
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "list_team_activity", arguments: {} } },
    ],
    [],
  ];
  const upstreamBefore = env.bearers.length;
  for (const body of forbidden) {
    const answer = await env.rpc(token, body);
    assert.equal(answer.status, 403, JSON.stringify(body));
    assert.equal(answer.body.error.code, -32003, JSON.stringify(body));
    assert.match(answer.body.error.message, /agent identity token reaches only the Relay messaging tools/);
  }
  // A refused call reached no Relaycast.
  assert.equal(env.bearers.length, upstreamBefore);

  assert.equal(agentIdentityAllows({ jsonrpc: "2.0", method: "notifications/initialized" }), true);
  assert.equal(agentIdentityAllows({ jsonrpc: "2.0", id: 1, method: "ping" }), true);
  assert.equal(agentIdentityAllows({ jsonrpc: "2.0", id: 1, method: "tools/list" }), true);
  assert.equal(agentIdentityAllows({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "send_relay_message", arguments: {} } }), true);
  assert.equal(agentIdentityAllows({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "spawn_relay_agent", arguments: {} } }), false);
  assert.equal(agentIdentityAllows({ jsonrpc: "2.0", id: 1, method: "tools/call" }), false);
  assert.equal(agentIdentityAllows([]), false);
  assert.equal(agentIdentityAllows(null), false);

  // A person on the same facade keeps the full plan.
  const personTools = (await (await env.connect(env.owner)).listTools()).tools.map(tool => tool.name);
  assert.ok(personTools.includes("list_team_activity"));
  assert.ok(personTools.length > AGENT_IDENTITY_TOOLS.length);
});

test("join_relay and `as` act only as the token's own agent", async (t) => {
  const env = await setup(t);
  const { accessToken: token } = await env.mintAgent("Join-Bot");
  // The mint's roster check is the only upstream call so far.
  const upstreamAfterMint = env.world.bodies.length;
  const joinRefused = /joins only as Join-Bot/;
  for (const args of [
    { desktop_address: "someone@build-01" },
    { name: "other-bot" },
    { cursor_identity_token: "x".repeat(32) },
    { name: "join-bot", desktop_address: "join-bot@build-01" },
  ]) {
    const answer = await env.call(token, "join_relay", args);
    assert.equal(answer.status, 200, JSON.stringify(args));
    assert.equal(answer.body.result.isError, true, JSON.stringify(args));
    assert.match(answer.body.result.content[0].text, joinRefused, JSON.stringify(args));
  }
  assert.equal(env.world.bodies.length, upstreamAfterMint, "a refused join reaches no Relaycast");
  assert.equal((await env.database.query("SELECT 1 FROM hosted_relay_participants")).rows.length, 0);

  // Its own name, in any case the zod schema accepts, joins.
  const joined = await env.call(token, "join_relay", { name: "join-bot" });
  assert.notEqual(joined.body.result.isError, true, JSON.stringify(joined.body));
  assert.equal(joined.body.result.structuredContent.name, "Join-Bot");

  // `as` may only name itself.
  env.world.addAgent("peer-bot");
  const other = await env.call(token, "send_relay_message", { to: "peer-bot", text: "hi", as: "someone-else" });
  assert.equal(other.body.result.isError, true);
  assert.match(other.body.result.content[0].text, /acts only as the relay agent Join-Bot/);
  const self = await env.call(token, "send_relay_message", { to: "peer-bot", text: "hi", as: "join-bot" });
  assert.notEqual(self.body.result.isError, true, JSON.stringify(self.body));

  // A person's participant of the same workspace is never reachable by `as`.
  await personParticipant(env, "owner-chat");
  const person = await env.call(token, "check_relay_inbox", { as: "owner-chat" });
  assert.equal(person.body.result.isError, true);
  assert.match(person.body.result.content[0].text, /acts only as the relay agent Join-Bot/);
});

test("the workspace comes only from the token row", async (t) => {
  const env = await setup(t);
  const primary = await env.mintAgent("cross-bot");
  // Spoofed workspace or Desktop headers change nothing.
  const spoofed = await env.call(primary.accessToken, "describe_capabilities", {},
    { "x-workspace-id": env.otherWorkspaceId, "x-agent-relay-desktop": "1" });
  assert.equal(spoofed.status, 200);
  assert.equal(spoofed.body.result.structuredContent.workspace.workspace_id, env.workspaceId);
  assert.equal(spoofed.body.result.structuredContent.connection.auth_mode, "agent_identity");

  // The same name in another workspace is a distinct identity.
  const secondary = await env.mintAgent("cross-bot", {}, env.otherWorkspaceId);
  assert.notEqual(await env.identityOf(secondary.id), await env.identityOf(primary.id));
  const rows = (await env.database.query<{ workspace_id: string }>(
    "SELECT workspace_id FROM agent_identities WHERE lower(agent_name) = 'cross-bot' ORDER BY workspace_id")).rows;
  assert.equal(rows.length, 2);

  // Relay work for the primary token uses only the primary workspace's key
  // (the secondary mint's own roster check used the secondary key).
  const relayFrom = env.bearers.length;
  const joined = await env.call(primary.accessToken, "join_relay", {}, { "x-workspace-id": env.otherWorkspaceId });
  assert.notEqual(joined.body.result.isError, true, JSON.stringify(joined.body));
  const listed = await env.call(primary.accessToken, "list_relay_agents", { status: "all" });
  assert.notEqual(listed.body.result.isError, true, JSON.stringify(listed.body));
  assert.ok(env.bearers.length > relayFrom);
  assert.ok(!env.bearers.slice(relayFrom).includes("rk_secondary"), "never the other workspace's key");
  const participant = (await env.database.query<{ workspace_id: string }>(
    "SELECT workspace_id FROM hosted_relay_participants WHERE agent_identity_id = $1", [await env.identityOf(primary.id)])).rows;
  assert.deepEqual(participant, [{ workspace_id: env.workspaceId }]);

  // A token of another organization's workspace is still its own workspace.
  const otherOrg = await request(env.origin, "/api/v1/organizations", {
    method: "POST", token: BOOTSTRAP, body: { name: "Other", ownerEmail: "owner@other.test", ownerName: "Other" },
  });
  assert.equal(otherOrg.status, 201);
  const foreignWorkspace = await env.newWorkspace("foreign", otherOrg.body.id);
  const foreignOwner = await env.deviceToken(otherOrg.body.owner.id, foreignWorkspace);
  // An owner cannot mint into a workspace of another organization.
  assert.notEqual((await env.mint({ agentName: "intruder-bot" }, env.owner, foreignWorkspace)).status, 201);
  const foreign = await env.mintAgent("foreign-bot", {}, foreignWorkspace, foreignOwner);
  const foreignReport = await env.call(foreign.accessToken, "describe_capabilities", {}, { "x-workspace-id": env.workspaceId });
  assert.equal(foreignReport.body.result.structuredContent.workspace.workspace_id, foreignWorkspace);
});

test("the token passes no other sh_wk_ gate and introspects inactive", async (t) => {
  const env = await setup(t);
  const { id, accessToken: token } = await env.mintAgent("gates-bot");

  // Token management.
  assert.equal((await request(env.origin, env.tokensPath(), { token })).status, 401);
  assert.equal((await request(env.origin, `${env.tokensPath()}?purpose=agent-identity`, { token })).status, 401);
  assert.equal((await request(env.origin, `${env.tokensPath()}/${id}`, { method: "DELETE", token })).status, 401);
  // Runtime environment: relay:agent is no runtime scope.
  const environment = await request(env.origin, `/internal/v1/workspaces/${env.workspaceId}/environment`, { token });
  assert.equal(environment.status, 403);
  assert.equal(environment.body.error, "insufficient_scope");
  // The workspace's Relaycast key never goes to a workspace token.
  assert.equal((await request(env.origin, `/api/v1/workspaces/${env.workspaceId}/resolve`, { token })).status, 403);
  // No membership falls back from it.
  assert.equal((await request(env.origin, `/api/v1/workspaces/${env.workspaceId}/admin/audit`, { token })).status, 401);
  assert.equal((await request(env.origin, `/api/v1/organizations/${env.organizationId}/workspaces`, {
    method: "POST", token, body: { name: "sneaky", relaycastApiKey: "rk_sneaky" } })).status, 401);
  // Introspection authorizes no service scope with it.
  for (const body of [{ token, aud: HISTORY }, { token, aud: HISTORY, workspace: env.workspaceId }]) {
    const answer = await env.introspect(body);
    assert.equal(answer.status, 200, JSON.stringify(body));
    assert.equal(answer.body.active, false, JSON.stringify(body));
  }
  // A body without an audience is malformed, whatever the token.
  const unaudienced = await env.introspect({ token });
  assert.equal(unaudienced.status, 400);
  assert.equal(unaudienced.body.error, "invalid_request");
  // The token is still live after all of these.
  assert.equal((await env.list(token)).status, 200);
});

test("list and revoke through the existing routes; revoking one token leaves the others live", async (t) => {
  const env = await setup(t);
  const first = await env.mintAgent("list-bot");
  const second = await env.mintAgent("list-bot", { label: "rotation" });
  await request(env.origin, env.tokensPath(), { method: "POST", token: env.owner, body: { label: "runtime", purpose: "agent-runtime" } });

  const listed = await request(env.origin, `${env.tokensPath()}?purpose=agent-identity`, { token: env.owner });
  assert.equal(listed.status, 200);
  const items = listed.body.tokens as Array<Record<string, any>>;
  assert.deepEqual(items.map(item => item.id).sort(), [first.id, second.id].sort());
  for (const item of items) {
    assert.equal(item.purpose, "agent-identity");
    assert.equal(item.agent_name, "list-bot");
    assert.deepEqual(item.scopes, ["relay:agent"]);
    assert.equal(item.accessToken, undefined, "no token material in the list");
    assert.equal(item.nodeName, null);
  }
  // The unfiltered list shows them too, other purposes unchanged.
  const all = await request(env.origin, env.tokensPath(), { token: env.owner });
  const runtime = (all.body.tokens as Array<Record<string, any>>).find(item => item.purpose === "agent-runtime")!;
  assert.equal(runtime.agent_name, null);
  assert.equal(runtime.nodeName, null);

  // A member cannot list.
  const memberId = await env.addMember("member@acme.test");
  const member = await env.deviceToken(memberId, env.workspaceId);
  assert.equal((await request(env.origin, `${env.tokensPath()}?purpose=agent-identity`, { token: member })).status, 403);

  const deleted = await request(env.origin, `${env.tokensPath()}/${first.id}`, { method: "DELETE", token: env.owner });
  assert.equal(deleted.status, 204);
  assert.equal((await env.list(first.accessToken)).status, 401);
  assert.equal((await env.list(second.accessToken)).status, 200);
  const revokedItem = ((await request(env.origin, `${env.tokensPath()}?purpose=agent-identity`, { token: env.owner }))
    .body.tokens as Array<Record<string, any>>).find(item => item.id === first.id)!;
  assert.notEqual(revokedItem.revokedAt ?? revokedItem.revoked_at ?? null, null);
  // The identity stays for the live token.
  assert.equal((await env.database.query("SELECT 1 FROM agent_identities WHERE workspace_id = $1", [env.workspaceId])).rows.length, 1);
  // Revoke audit.
  const audit = (await env.database.query("SELECT 1 FROM admin_audit_events WHERE action = 'api_token.revoke' AND target LIKE $1", [`${first.id}%`])).rows;
  assert.equal(audit.length, 1);
});

test("schema: an agent token always expires, binds one identity, and a participant has one owner", async (t) => {
  const env = await setup(t);
  const minted = await env.mintAgent("schema-bot");
  const identityId = await env.identityOf(minted.id);
  const insert = (purpose: string, agentName: string | null, identity: string | null, expires: string | null) =>
    env.database.query(
      `INSERT INTO workspace_api_tokens (id, workspace_id, label, purpose, scopes, token_hash, token_prefix, agent_name, agent_identity_id, expires_at)
       VALUES ($1, $2, 'raw', $3, ARRAY['relay:agent'], $4, 'sh_wk_raw', $5, $6, $7)`,
      [randomUUID(), env.workspaceId, purpose, sha256(randomUUID()), agentName, identity, expires],
    );
  const tomorrow = new Date(Date.now() + DAY_MS).toISOString();
  await assert.rejects(insert("agent-identity", "schema-bot", identityId, null), "never-expiring agent token");
  await assert.rejects(insert("agent-identity", "schema-bot", null, tomorrow), "agent token without an identity");
  await assert.rejects(insert("agent-identity", null, identityId, tomorrow), "agent token without a name");
  await assert.rejects(insert("agent-runtime", null, identityId, tomorrow), "identity on another purpose");
  await insert("agent-identity", "schema-bot", identityId, tomorrow);

  const relaycastWorkspace = await relaycastWorkspaceOf(env, env.workspaceId);
  const participant = (userId: string | null, identity: string | null) => env.database.query(
    `INSERT INTO hosted_relay_participants (id, workspace_id, user_id, agent_identity_id, relaycast_workspace_id, agent_name, agent_remote_id, token_ciphertext)
     VALUES ($1, $2, $3, $4, $5, 'schema-bot', $6, 'ciphertext')`,
    [randomUUID(), env.workspaceId, userId, identity, relaycastWorkspace, randomUUID()],
  );
  await assert.rejects(participant(env.ownerId, identityId), "two owners");
  await assert.rejects(participant(null, null), "no owner");
  await participant(null, identityId);
  await assert.rejects(participant(null, identityId), "one participant per identity");

  // Case-blind uniqueness per workspace.
  await assert.rejects(env.database.query(
    "INSERT INTO agent_identities (id, workspace_id, organization_id, agent_name) VALUES ($1, $2, $3, 'SCHEMA-BOT')",
    [randomUUID(), env.workspaceId, env.organizationId]));
});
