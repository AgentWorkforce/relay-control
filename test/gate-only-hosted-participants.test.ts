import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import test, { type TestContext } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { decryptSecret, encryptSecret } from "../src/crypto.js";
import { launcherName } from "../src/mcp/relay-participants.js";
/** The keyring test/support/copilot-desktop.ts configures. */
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
import { copilotDesktopSetup, MCP_PATH, type DesktopGate } from "./support/copilot-desktop.js";

// Gate-only installs (relaygatePublicUrl set): every hosted MCP participant
// enrols at relaygate with a one-time hosted credential (sh_ht_) that
// relaygate introspects with relay-control, holds only an rg_ token, and
// makes every call, reads included, through relaygate. relay-control never
// talks to Relaycast for a hosted participant's traffic, neither with its
// own Relaycast token nor with the workspace key.

const GATE = "https://gate.selfhosted.test";
const INTROSPECT_SECRET = "gate-introspection-secret-".repeat(2);
const AUD = "https://history.selfhosted.test";
const WORKSPACE_KEY = "rk_primary";
const ownerHash = (userId: string) => createHash("sha256").update(userId).digest("hex");

type CallResult = Awaited<ReturnType<Client["callTool"]>>;
function structured(result: CallResult): Record<string, any> {
  assert.notEqual(result.isError, true, JSON.stringify(result.content));
  return result.structuredContent as Record<string, any>;
}
function toolError(result: CallResult): string {
  assert.equal(result.isError, true, JSON.stringify(result.content));
  return (result.content as Array<{ text: string }>)[0]!.text;
}

/**
 * A fake relaygate in front of the Relaycast world. POST /v1/register takes a
 * hosted credential and introspects it with relay-control (the real
 * endpoint), refusing clients its policy has no rule for; every other call is
 * authorized by an rg_ token and forwarded upstream as that agent (or, for the
 * directory and self-administration routes relaygate answers itself, with the
 * workspace key). Requests that bypass relaygate are recorded.
 */
const plain = (headers: Headers) => {
  const out: Record<string, string> = {};
  headers.forEach((value, name) => { out[name] = value; });
  return out;
};

function relaygate(control: { origin: () => string }) {
  const state = {
    /** Hosted clients the policy has a rule for. */
    allowed: new Set<string>(["mcp"]),
    tokens: new Map<string, string>(),
    agents: new Map<string, { agentId: string; userId: string }>(),
    /** `METHOD path` of every request relaygate received. */
    seen: [] as string[],
    /** Introspection answers relaygate got. */
    introspected: [] as Array<Record<string, unknown>>,
    /** Hosted credentials presented to /v1/register. */
    credentials: [] as string[],
    /** `METHOD path bearer-kind` of every call that went to Relaycast without relaygate. */
    direct: [] as string[],
  };
  const revoke = (name: string) => {
    for (const [token, owner] of state.tokens) if (owner === name) state.tokens.delete(token);
  };
  const issue = (name: string) => {
    revoke(name);
    const token = `rg_${randomBytes(24).toString("base64url")}`;
    state.tokens.set(token, name);
    return token;
  };
  const gate: DesktopGate = {
    url: GATE,
    fetch: (relaycast, world) => (async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(String(input instanceof Request ? input.url : input));
      const method = init?.method ?? "GET";
      const headers = new Headers(init?.headers);
      const bearer = (headers.get("authorization") ?? "").replace(/^Bearer /, "");
      if (url.origin !== GATE) {
        const kind = bearer === WORKSPACE_KEY ? "workspace-key" : bearer.startsWith("rg_") ? "rg" : "agent-token";
        state.direct.push(`${method} ${url.pathname} ${kind}`);
        return relaycast(input, init);
      }
      const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
      state.seen.push(`${method} ${url.pathname}`);
      const upstream = (path: string, token: string, override?: { method?: string; body?: unknown }) =>
        relaycast(`http://relaycast.internal${path}`, {
          ...init, method: override?.method ?? method,
          headers: { ...plain(headers), authorization: `Bearer ${token}`, "content-type": "application/json" },
          ...(override?.body !== undefined ? { body: JSON.stringify(override.body) } : {}),
        });
      if (method === "POST" && url.pathname === "/v1/register") {
        if (!bearer.startsWith("sh_ht_")) return json(401, { error: "relaygate_unauthenticated" });
        state.credentials.push(bearer);
        const answer = await (await fetch(`${control.origin()}/internal/v1/auth/introspect`, {
          method: "POST", headers: { authorization: `Bearer ${INTROSPECT_SECRET}`, "content-type": "application/json" },
          body: JSON.stringify({ token: bearer, aud: AUD }),
        })).json() as Record<string, any>;
        state.introspected.push(answer);
        if (answer.active !== true || answer.principal_type !== "relay_hosted") return json(401, { error: "relaygate_unauthenticated" });
        if (!state.allowed.has(answer.client)) {
          return json(403, { error: "relaygate_denied", detail: `no controlPrincipals rule allows hosted ${answer.client} participants` });
        }
        const { name } = JSON.parse(String(init!.body)) as { name: string };
        if (name !== answer.agent_name) return json(403, { error: "relaygate_name_scope" });
        let agent = state.agents.get(name);
        if (agent && agent.userId !== answer.sub) return json(409, { error: "relaygate_name_taken" });
        if (!agent) {
          agent = { agentId: `rga_${randomUUID()}`, userId: answer.sub };
          state.agents.set(name, agent);
        }
        // relaygate registers the agent upstream with its own workspace key, stamped with its agent id, or takes an
        // existing upstream agent of that name over, leaving its metadata as it was.
        if (!world.agents.has(name)) world.addAgent(name, { relaygate: { agent_id: agent.agentId } });
        return json(200, { agent_id: agent.agentId, gid: 22, token: issue(name), expires_at: new Date(Date.now() + 86_400_000).toISOString(), user_id: answer.sub });
      }
      const name = state.tokens.get(bearer);
      if (!name) return json(401, { error: "relaygate_unauthenticated" });
      const enrolled = state.agents.get(name)!;
      if (method === "GET" && url.pathname === "/v1/whoami") return json(200, { agent_id: enrolled.agentId, name, user_id: enrolled.userId });
      if (method === "PATCH" && url.pathname === "/v1/agent") {
        return upstream(`/v1/agents/${encodeURIComponent(name)}`, WORKSPACE_KEY, { method: "PATCH" });
      }
      if (method === "DELETE" && url.pathname === "/v1/agent") {
        const own = world.agents.get(name);
        revoke(name);
        if (!own) return json(404, { ok: false, error: { code: "agent_not_found" } });
        return upstream("/v1/agents/release-exact", WORKSPACE_KEY, { method: "POST", body: { name, expected_agent_id: own.id, delete_agent: true } });
      }
      // Directory reads relaygate answers with the workspace key (filtered by policy in the real gate).
      if (method === "GET" && (url.pathname === "/v1/agents" || url.pathname.startsWith("/v1/agents/") || url.pathname === "/v1/channels" ||
          /^\/v1\/channels\/[^/]+\/messages$/.test(url.pathname))) {
        return upstream(`${url.pathname}${url.search}`, WORKSPACE_KEY);
      }
      const own = world.agents.get(name);
      if (!own) return json(401, { error: "relaygate_unauthenticated" });
      return upstream(`${url.pathname}${url.search}`, own.token);
    }) as typeof fetch,
  };
  return { gate, state, issue };
}

async function gateHosted(t: TestContext) {
  let origin = "";
  const { gate, state, issue } = relaygate({ origin: () => origin });
  const env = await copilotDesktopSetup(t, {}, gate);
  origin = env.origin;
  // relaygate introspects hosted credentials here.
  env.config.introspectSecret = INTROSPECT_SECRET;
  const peer = env.world.addAgent("peer");
  const accessToken = await env.deviceLogin();
  const connect = async () => {
    const client = new Client({ name: "gate-hosted-test", version: "1.0.0" });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${env.origin}${MCP_PATH}`),
      { requestInit: { headers: { authorization: `Bearer ${accessToken}` } } }));
    t.after(() => client.close());
    return client;
  };
  const rows = async () => (await env.database.query<{ agent_name: string; agent_remote_id: string; token_ciphertext: string; relaygate_agent_id: string | null;
    admitted_clients: string[] }>(
    "SELECT agent_name, agent_remote_id, token_ciphertext, relaygate_agent_id, admitted_clients FROM hosted_relay_participants ORDER BY agent_name")).rows
    .map(row => ({ ...row, token: decryptSecret(row.token_ciphertext, KEYRING) }));
  /** Direct Relaycast calls made since `mark`. */
  const directSince = (mark: number) => state.direct.slice(mark);
  return { env, state, issue, peer, connect, rows, directSince };
}

test("on a gate-only install a hosted participant enrols at relaygate and every call it makes goes through relaygate", async (t) => {
  const { env, state, peer, connect, rows, directSince } = await gateHosted(t);
  const client = await connect();
  const mark = state.direct.length;

  const joined = structured(await client.callTool({ name: "join_relay", arguments: { name: "notes-agent" } }));
  assert.equal(joined.name, "notes-agent");
  // One single-use hosted credential, introspected as relay_hosted for the owner, the exact name and the client.
  assert.equal(state.credentials.length, 1);
  assert.match(state.credentials[0]!, /^sh_ht_/);
  assert.deepEqual({ ...state.introspected[0], iat: 0, exp: 0, token_id: "" }, {
    active: true, sub: env.ownerId, email: null, principal_type: "relay_hosted", agent_name: "notes-agent", client: "mcp",
    machine_id: null, org: env.orgId, workspace: env.workspaceId, scopes: ["relay:hosted:enrol"], aud: AUD, iat: 0, exp: 0, token_id: "",
  });
  // Burned: presenting it again is inactive.
  const again = await (await fetch(`${env.origin}/internal/v1/auth/introspect`, {
    method: "POST", headers: { authorization: `Bearer ${INTROSPECT_SECRET}`, "content-type": "application/json" },
    body: JSON.stringify({ token: state.credentials[0], aud: AUD }),
  })).json() as Record<string, unknown>;
  assert.deepEqual(again, { active: false, reason: "revoked" });

  const [row] = await rows();
  assert.match(row!.token, /^rg_/, "the participant holds only a relaygate token");
  assert.equal(row!.relaygate_agent_id, state.agents.get("notes-agent")!.agentId);
  assert.equal(row!.agent_remote_id, env.world.agents.get("notes-agent")!.id, "agent_remote_id stays the upstream Relaycast id");
  // Owner metadata was merged upstream through relaygate (OAuth teardown and the roster read it).
  assert.deepEqual(
    (({ source, owner_hash, cloud_workspace_id, kind, hosted_client }) => ({ source, owner_hash, cloud_workspace_id, kind, hosted_client }))(
      env.world.agents.get("notes-agent")!.metadata as Record<string, unknown>),
    { source: "cloud-hosted-mcp", owner_hash: ownerHash(env.ownerId), cloud_workspace_id: env.workspaceId, kind: "hosted", hosted_client: "mcp" });

  const sent = structured(await client.callTool({ name: "send_relay_message", arguments: { to: "peer", text: "hello through the gate" } }));
  assert.equal(sent.from, "notes-agent");
  env.world.sendAs("peer", "notes-agent", "hello back");
  const inbox = structured(await client.callTool({ name: "check_relay_inbox", arguments: {} }));
  assert.deepEqual(inbox.messages.map((message: any) => message.text), ["hello back"]);
  const read = structured(await client.callTool({ name: "read_relay_conversation", arguments: { agent: "peer" } }));
  assert.deepEqual(read.messages.map((message: any) => message.text).sort(), ["hello back", "hello through the gate"]);
  const listed = structured(await client.callTool({ name: "list_relay_agents", arguments: { status: "all" } }));
  assert.ok(listed.agents.some((agent: any) => agent.name === peer.name));
  structured(await client.callTool({ name: "subscribe_relay_channel", arguments: { channel: "team", create: true } }));
  structured(await client.callTool({ name: "post_relay_channel", arguments: { channel: "team", text: "posted through the gate" } }));
  const history = structured(await client.callTool({ name: "read_relay_channel", arguments: { channel: "team" } }));
  assert.deepEqual(history.messages.map((message: any) => message.text), ["posted through the gate"]);
  structured(await client.callTool({ name: "list_relay_channels", arguments: {} }));
  structured(await client.callTool({ name: "relay_status", arguments: {} }));
  structured(await client.callTool({ name: "set_relay_agent_card", arguments: { description: "Takes notes", skills: [] } }));

  assert.deepEqual((await rows())[0]!.admitted_clients, ["mcp"]);
  // Nothing above reached Relaycast without relaygate: no participant token, and the workspace key only for the
  // one control-plane check that the name is free before enrolling.
  assert.deepEqual(directSince(mark), ["GET /v1/agents/notes-agent workspace-key"]);
  for (const expected of ["POST /v1/register", "GET /v1/whoami", "POST /v1/dm", "GET /v1/deliveries", "GET /v1/agents", "POST /v1/channels",
    "GET /v1/channels", "PATCH /v1/agent"]) {
    assert.ok(state.seen.includes(expected), `${expected} went through relaygate: ${JSON.stringify(state.seen)}`);
  }
});

test("on a gate-only install relaygate fails closed: without a hosted rule nothing joins, and the error names the rule to add", async (t) => {
  const { env, state, connect, rows, directSince } = await gateHosted(t);
  state.allowed.clear();
  const client = await connect();
  const mark = state.direct.length;
  const refused = toolError(await client.callTool({ name: "join_relay", arguments: { name: "notes-agent" } }));
  assert.match(refused, /does not allow hosted mcp participants/);
  assert.match(refused, /"kinds": \["hosted"\]/);
  assert.match(refused, /"clients": \["mcp"\]/);
  assert.deepEqual(await rows(), []);
  // Sending auto-joins, and is refused the same way; no agent was registered in Relaycast directly.
  assert.match(toolError(await client.callTool({ name: "send_relay_message", arguments: { to: "peer", text: "x" } })), /does not allow hosted mcp/);
  assert.equal(env.world.agents.has("notes-agent"), false);
  // Only the control-plane name checks used the workspace key; no agent was registered with it.
  assert.ok(directSince(mark).length > 0);
  for (const call of directSince(mark)) assert.match(call, /^GET \/v1\/agents\/[^/]+ workspace-key$/);
});

test("on a gate-only install a hosted participant can no longer reach Relaycast directly, and a pre-gate participant is re-enrolled through relaygate", async (t) => {
  const { env, state, connect, rows, directSince } = await gateHosted(t);
  // A participant registered in Relaycast directly, before this install enforced relaygate for hosted participants.
  const legacy = env.world.addAgent("old-notes", {
    source: "cloud-hosted-mcp", cloud_workspace_id: env.workspaceId, owner_hash: ownerHash(env.ownerId), kind: "hosted" });
  const relayWorkspace = (await env.database.query<{ relaycast_workspace_id: string }>(
    "SELECT relaycast_workspace_id FROM workspaces WHERE id = $1", [env.workspaceId])).rows[0]!.relaycast_workspace_id;
  await env.database.query(
    `INSERT INTO hosted_relay_participants (id, workspace_id, user_id, relaycast_workspace_id, session_hash, agent_name, agent_remote_id, token_ciphertext)
     VALUES ($1, $2, $3, $4, NULL, $5, $6, $7)`,
    [randomUUID(), env.workspaceId, env.ownerId, relayWorkspace, legacy.name, legacy.id, encryptSecret(legacy.token, KEYRING.active)]);
  const client = await connect();

  const mark = state.direct.length;
  const sent = structured(await client.callTool({ name: "send_relay_message", arguments: { to: "peer", text: "migrated", as: "old-notes" } }));
  assert.equal(sent.from, "old-notes");
  const [row] = await rows();
  assert.match(row!.token, /^rg_/, "the Relaycast token was replaced by a relaygate token");
  assert.equal(row!.agent_remote_id, legacy.id, "the same upstream agent: pins and launches keep working");
  assert.equal(row!.relaygate_agent_id, state.agents.get("old-notes")!.agentId);
  // The only direct call was the one-time ownership check of the legacy agent, with the workspace key; the
  // participant's own Relaycast token was never used.
  assert.deepEqual(directSince(mark), ["GET /v1/agents/old-notes workspace-key"]);

  // The old Relaycast token is useless to relay-control from now on: everything goes through relaygate.
  const before = state.direct.length;
  structured(await client.callTool({ name: "relay_status", arguments: { as: "old-notes" } }));
  structured(await client.callTool({ name: "check_relay_inbox", arguments: { as: "old-notes" } }));
  assert.deepEqual(directSince(before), []);
});

test("on a gate-only install a rejected relaygate token is renewed by enrolling again, and leave releases through relaygate", async (t) => {
  const { env, state, issue, connect, rows } = await gateHosted(t);
  const client = await connect();
  structured(await client.callTool({ name: "join_relay", arguments: { name: "notes-agent" } }));
  const first = (await rows())[0]!;
  // relaygate tokens expire after 24 hours: the stored one stops working.
  issue("notes-agent");
  const status = structured(await client.callTool({ name: "relay_status", arguments: {} }));
  assert.equal(status.name, "notes-agent");
  const renewed = (await rows())[0]!;
  assert.notEqual(renewed.token, first.token);
  assert.equal(renewed.relaygate_agent_id, first.relaygate_agent_id, "the same relaygate agent");
  assert.equal(state.credentials.length, 2);

  const mark = state.direct.length;
  const left = structured(await client.callTool({ name: "leave_relay", arguments: {} }));
  assert.equal(left.already_left, false);
  assert.deepEqual(await rows(), []);
  assert.equal(env.world.agents.has("notes-agent"), false, "released upstream");
  assert.ok(state.seen.includes("DELETE /v1/agent"));
  assert.deepEqual(state.direct.slice(mark), [], "released through relaygate, not with the workspace key");
});

test("on a gate-only install directory reads need a relay identity first, and the launcher name is not a messaging participant", async (t) => {
  const { env, connect, rows } = await gateHosted(t);
  const client = await connect();
  assert.match(toolError(await client.callTool({ name: "list_relay_agents", arguments: { status: "all" } })), /Call join_relay first/);
  assert.match(toolError(await client.callTool({ name: "list_relay_channels", arguments: {} })), /Call join_relay first/);
  assert.match(toolError(await client.callTool({ name: "join_relay", arguments: { name: launcherName(env.ownerId) } })), /reserved/);
  assert.deepEqual(await rows(), []);
});

test("on a gate-only install a name another owner holds is refused before any hosted credential is minted", async (t) => {
  const { env, state, connect, rows } = await gateHosted(t);
  const foreign = env.world.addAgent("notes-agent", {
    source: "cloud-hosted-mcp", cloud_workspace_id: env.workspaceId, owner_hash: ownerHash("another-user"), kind: "hosted" });
  const client = await connect();
  assert.match(toolError(await client.callTool({ name: "join_relay", arguments: { name: "notes-agent" } })), /already taken/);
  assert.equal(state.credentials.length, 0, "relaygate never saw an enrolment, so it never took the name over");
  assert.deepEqual(await rows(), []);
  assert.equal(env.world.agents.get("notes-agent"), foreign, "the other owner's agent is untouched");
});

test("on a gate-only install a binding-owned agent's name is refused before any hosted credential is minted", async (t) => {
  const { env, state, connect, rows } = await gateHosted(t);
  env.world.addAgent("notes-agent", { capy_binding_id: "binding-1" });
  const client = await connect();
  assert.match(toolError(await client.callTool({ name: "join_relay", arguments: { name: "notes-agent" } })), /already taken/);
  assert.equal(state.credentials.length, 0);
  assert.deepEqual(await rows(), []);
  assert.ok(env.world.agents.has("notes-agent"));
});

test("on a gate-only install an interrupted join of the owner's own agent enrols that same agent through relaygate", async (t) => {
  const { env, state, connect, rows } = await gateHosted(t);
  const own = env.world.addAgent("notes-agent", {
    source: "cloud-hosted-mcp", cloud_workspace_id: env.workspaceId, owner_hash: ownerHash(env.ownerId), kind: "hosted" });
  const client = await connect();
  structured(await client.callTool({ name: "join_relay", arguments: { name: "notes-agent" } }));
  const [row] = await rows();
  assert.equal(row!.agent_remote_id, own.id);
  assert.equal(row!.relaygate_agent_id, state.agents.get("notes-agent")!.agentId);
  assert.match(row!.token, /^rg_/);
});

test("on a gate-only install a participant relaygate admitted for another hosted client is refused when the policy has no rule for this one", async (t) => {
  const { env, state, connect, rows } = await gateHosted(t);
  const client = await connect();
  structured(await client.callTool({ name: "join_relay", arguments: { name: "notes-agent" } }));
  // Enrolled as another hosted client; this install's policy now allows only that one.
  await env.database.query("UPDATE hosted_relay_participants SET admitted_clients = '{chatgpt}'");
  state.allowed = new Set(["chatgpt"]);
  const before = (await rows())[0]!;
  const credentials = state.credentials.length;
  assert.match(toolError(await client.callTool({ name: "relay_status", arguments: {} })), /does not allow hosted mcp participants/);
  assert.equal(state.credentials.length, credentials + 1, "relaygate's policy decided, with a fresh enrolment");
  const after = (await rows())[0]!;
  assert.equal(after.token, before.token, "a refusal leaves the row and its token as they were");
  assert.deepEqual(after.admitted_clients, ["chatgpt"]);
  assert.equal(state.tokens.get(after.token), "notes-agent", "the stored token still works for the client it was admitted for");
});

test("on a gate-only install a second hosted client enrols once at relaygate and is then admitted beside the first", async (t) => {
  const { env, state, connect, rows } = await gateHosted(t);
  const client = await connect();
  structured(await client.callTool({ name: "join_relay", arguments: { name: "notes-agent" } }));
  await env.database.query("UPDATE hosted_relay_participants SET admitted_clients = '{chatgpt}'");
  state.allowed = new Set(["mcp", "chatgpt"]);
  const before = (await rows())[0]!;
  const credentials = state.credentials.length;
  structured(await client.callTool({ name: "relay_status", arguments: {} }));
  assert.equal(state.credentials.length, credentials + 1);
  const after = (await rows())[0]!;
  assert.deepEqual([...after.admitted_clients].sort(), ["chatgpt", "mcp"]);
  assert.notEqual(after.token, before.token, "relaygate revoked the earlier token and issued one for the current rule");
  assert.equal(after.relaygate_agent_id, before.relaygate_agent_id);
  structured(await client.callTool({ name: "relay_status", arguments: {} }));
  assert.equal(state.credentials.length, credentials + 1, "an admitted client does not enrol again");
});

test("on a gate-only install a renewed participant adopts the new relaygate agent relaygate answers for the same upstream agent", async (t) => {
  const { env, state, issue, connect, rows } = await gateHosted(t);
  const client = await connect();
  structured(await client.callTool({ name: "join_relay", arguments: { name: "notes-agent" } }));
  const before = (await rows())[0]!;
  // relaygate re-created its record for the name (a new relaygate agent id), and the stored token stopped working.
  state.agents.set("notes-agent", { agentId: `rga_${randomUUID()}`, userId: env.ownerId });
  issue("notes-agent");
  const status = structured(await client.callTool({ name: "relay_status", arguments: {} }));
  assert.equal(status.name, "notes-agent");
  const after = (await rows())[0]!;
  assert.equal(after.relaygate_agent_id, state.agents.get("notes-agent")!.agentId);
  assert.notEqual(after.relaygate_agent_id, before.relaygate_agent_id);
  assert.equal(after.agent_remote_id, before.agent_remote_id, "the same upstream agent");
  assert.ok(env.world.agents.has("notes-agent"), "the upstream agent was not released");
});
