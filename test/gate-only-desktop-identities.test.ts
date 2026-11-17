import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import test, { type TestContext } from "node:test";
import { request } from "./support/harness.js";
import {
  copilotDesktopSetup, desktopSecret, identitiesPath, installationId, MCP_PATH, tokensPath, type DesktopGate,
} from "./support/copilot-desktop.js";
import { claudeSigner } from "./support/claude-signer.js";

// Gate-only installs (relaygatePublicUrl set): Agent Relay Desktop enrols each
// chat at relaygate and holds an rg_ token that only relaygate accepts, and
// agent_id is relaygate's agent id. Identity sync and every MCP call made with
// that token are verified through relaygate's GET /v1/whoami plus the upstream
// Relaycast agent card (metadata.relaygate.agent_id), and the chat's own
// messaging goes through relaygate.

const GATE = "https://gate.selfhosted.test";
const PROOF = "_agent_relay_attestation";

type GateAgent = { agent_id: string; name: string; user_id?: string };

/**
 * A fake relaygate in front of the Relaycast world: whoami for its rg_ tokens,
 * 404 relaygate_route_not_proxied for heartbeats and deliveries, and every
 * other /v1 call proxied upstream with the enrolled agent's Relaycast token.
 */
function relaygate() {
  const state = {
    tokens: new Map<string, GateAgent>(),
    mode: "ok" as "ok" | "unavailable" | "throw",
    /** `METHOD path` of every request relaygate received. */
    seen: [] as string[],
    /** rg_ bearers sent straight to Relaycast (always a bug). */
    leaked: [] as string[],
  };
  const gate: DesktopGate = {
    url: GATE,
    fetch: (relaycast, world) => (async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(String(input instanceof Request ? input.url : input));
      const method = init?.method ?? "GET";
      const headers = new Headers(init?.headers);
      const bearer = (headers.get("authorization") ?? "").replace(/^Bearer /, "");
      if (url.origin !== GATE) {
        if (bearer.startsWith("rg_")) state.leaked.push(`${method} ${url.pathname}`);
        return relaycast(input, init);
      }
      const json = (status: number, body: unknown) => new Response(JSON.stringify(body), {
        status, headers: { "content-type": "application/json" },
      });
      state.seen.push(`${method} ${url.pathname}`);
      if (state.mode === "throw") throw new TypeError("fetch failed");
      if (state.mode === "unavailable") return json(503, { error: "relaygate_unavailable" });
      const agent = state.tokens.get(bearer);
      if (!agent) return json(401, { error: "relaygate_unauthorized" });
      if (method === "GET" && url.pathname === "/v1/whoami") return json(200, agent);
      if (url.pathname.endsWith("/deliveries") || url.pathname === "/v1/agents/heartbeat") {
        return json(404, { error: "relaygate_route_not_proxied" });
      }
      const upstream = world.agents.get(agent.name);
      if (!upstream) return json(401, { error: "relaygate_unauthorized" });
      headers.set("authorization", `Bearer ${upstream.token}`);
      return relaycast(`http://relaycast.internal${url.pathname}${url.search}`, { ...init, headers });
    }) as typeof fetch,
  };
  return { gate, state };
}

async function rpc(origin: string, token: string, body: unknown) {
  const response = await fetch(`${origin}${MCP_PATH}`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, accept: "application/json, text/event-stream", "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) as Record<string, any> : {} };
}

/** A gate-only self-host with a verified Desktop parent, a peer agent and a fake relaygate. */
async function gateDesktop(t: TestContext) {
  const { gate, state } = relaygate();
  const env = await copilotDesktopSetup(t, {}, gate);
  const parent = await env.desktopSignIn({ hostName: "sf-mini" });
  const signer = await claudeSigner();
  const sourceId = "desktop-source-gate";
  env.world.addAgent("peer");
  /**
   * Enrols a chat at relaygate: an rg_ token whose whoami names relaygate's
   * agent id (and the owner unless `userId` says otherwise; null omits it),
   * and the upstream Relaycast agent whose card carries that id.
   */
  const enrol = (name: string, options: { userId?: string | null; card?: Record<string, unknown> } = {}) => {
    const agentId = `rga_${randomUUID()}`;
    const token = `rg_${randomBytes(24).toString("base64url")}`;
    env.world.addAgent(name, options.card ?? { relaygate: { agent_id: agentId } });
    state.tokens.set(token, { agent_id: agentId, name,
      ...(options.userId === null ? {} : { user_id: options.userId ?? env.ownerId }) });
    return { name, address: `${name}@sf-mini`, agent_id: agentId, token, native_session: { kind: "cursor" as const, id: randomUUID() } };
  };
  const sync = (identities: Array<ReturnType<typeof enrol>>) => request(env.origin, identitiesPath(env.workspaceId), {
    method: "PUT", token: parent.accessToken,
    body: { source_id: sourceId, identities, attestation_key: { kid: signer.kid, alg: "Ed25519", public_key: signer.publicKey } },
  });
  const stored = async () => (await env.database.query<{ agent_name: string; agent_remote_id: string; address: string }>(
    "SELECT agent_name, agent_remote_id, address FROM desktop_relay_identities ORDER BY agent_name")).rows;
  const keys = async () => (await env.database.query<{ kid: string }>("SELECT kid FROM desktop_attestation_keys")).rows;
  return { env, parent, signer, sourceId, state, enrol, sync, stored, keys };
}

test("gate-only sync verifies rg_ identities through relaygate whoami and the upstream card, storing relaygate's agent id and the attestation key", async (t) => {
  const { state, enrol, sync, stored, keys, signer } = await gateDesktop(t);
  const cursor = enrol("cursor-chat");
  // relaygate may not report the enrolling user yet; the identity still verifies.
  const codex = enrol("codex-chat", { userId: null });
  const synced = await sync([cursor, codex]);
  assert.equal(synced.status, 200, synced.raw);
  assert.equal(synced.body.synced, 2);
  assert.equal(synced.body.skipped, undefined);
  assert.deepEqual(await stored(), [
    { agent_name: "codex-chat", agent_remote_id: codex.agent_id, address: "codex-chat@sf-mini" },
    { agent_name: "cursor-chat", agent_remote_id: cursor.agent_id, address: "cursor-chat@sf-mini" },
  ]);
  assert.deepEqual(await keys(), [{ kid: signer.kid }]);
  assert.equal(state.seen.filter((row) => row === "GET /v1/whoami").length, 2);
  assert.deepEqual(state.leaked, [], "no rg_ token was sent to Relaycast");
});

test("gate-only sync skips an identity relaygate refuses, or whose whoami or upstream card does not match, as unverified and keeps no attestation key", async (t) => {
  const { state, enrol, sync, stored, keys } = await gateDesktop(t);
  const refused = enrol("refused-chat");
  state.tokens.delete(refused.token);
  const renamed = enrol("renamed-chat");
  state.tokens.set(renamed.token, { ...state.tokens.get(renamed.token)!, name: "someone-else" });
  const otherId = enrol("other-id-chat");
  state.tokens.set(otherId.token, { ...state.tokens.get(otherId.token)!, agent_id: "rga_other" });
  const uncarded = enrol("uncarded-chat", { card: { source: "relay-desktop" } });
  const miscarded = enrol("miscarded-chat", { card: { relaygate: { agent_id: "rga_someone_else" } } });
  const all = [refused, renamed, otherId, uncarded, miscarded];
  const synced = await sync(all);
  assert.equal(synced.status, 200, synced.raw);
  assert.equal(synced.body.synced, 0);
  assert.deepEqual(
    [...synced.body.skipped].sort((a: any, b: any) => a.agent_id.localeCompare(b.agent_id)),
    all.map((item) => ({ agent_id: item.agent_id, reason: "unverified" })).sort((a, b) => a.agent_id.localeCompare(b.agent_id)),
  );
  assert.deepEqual(await stored(), []);
  assert.deepEqual(await keys(), [], "no verified identity, so no attestation key");
  assert.deepEqual(state.leaked, []);
});

test("gate-only sync skips an identity relaygate enrolled for another user as not_owned and keeps the caller's own", async (t) => {
  const { enrol, sync, stored, keys, signer } = await gateDesktop(t);
  const theirs = enrol("their-chat", { userId: randomUUID() });
  const mine = enrol("my-chat");
  const synced = await sync([theirs, mine]);
  assert.equal(synced.status, 200, synced.raw);
  assert.equal(synced.body.synced, 1);
  assert.deepEqual(synced.body.skipped, [{ agent_id: theirs.agent_id, reason: "not_owned" }]);
  assert.deepEqual((await stored()).map((row) => row.agent_remote_id), [mine.agent_id]);
  assert.deepEqual(await keys(), [{ kid: signer.kid }]);
});

test("gate-only sync answers 503 upstream_unavailable when relaygate fails or is unreachable, and keeps what was synced", async (t) => {
  const { state, enrol, sync, stored, keys } = await gateDesktop(t);
  const chat = enrol("cursor-chat");
  assert.equal((await sync([chat])).status, 200);
  for (const mode of ["unavailable", "throw"] as const) {
    state.mode = mode;
    const failed = await sync([chat]);
    assert.equal(failed.status, 503, `${mode}: ${failed.raw}`);
    assert.equal(failed.body.error, "upstream_unavailable", mode);
    assert.equal((await stored()).length, 1, mode);
    assert.equal((await keys()).length, 1, mode);
  }
});

test("a signed Cursor call on a gate-only install sends, reads and reports status as the chat's own identity through relaygate", async (t) => {
  const { env, parent, signer, sourceId, state, enrol, sync } = await gateDesktop(t);
  const chat = enrol("cursor-chat");
  assert.equal((await sync([chat])).status, 200);
  const secret = desktopSecret();
  const registered = await request(env.origin, tokensPath(env.workspaceId), {
    method: "POST", token: parent.accessToken, body: { provider: "cursor", installationId: installationId(), accessToken: secret },
  });
  assert.equal(registered.status, 201, registered.raw);
  const call = async (tool: string, args: Record<string, unknown>) => ({
    jsonrpc: "2.0", id: 7, method: "tools/call",
    params: { name: tool, arguments: { ...args, [PROOF]: await signer.sign({ tool, src: sourceId, sid: chat.native_session.id,
      tuid: randomUUID(), kind: "cursor", extra: { args } }) } },
  });

  const sent = await rpc(env.origin, secret, await call("send_relay_message", { to: "peer", text: "hello through the gate" }));
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  assert.notEqual(sent.body.result.isError, true, JSON.stringify(sent.body.result));
  assert.equal(sent.body.result.structuredContent.from, "cursor-chat");
  const conversation = env.world.conversations.find((row) => row.participants.includes("peer"));
  assert.deepEqual(conversation?.participants.slice().sort(), ["cursor-chat", "peer"]);
  assert.ok(state.seen.includes("POST /v1/dm"), JSON.stringify(state.seen));

  const read = await rpc(env.origin, secret, await call("read_relay_conversation", { agent: "peer" }));
  assert.equal(read.status, 200, JSON.stringify(read.body));
  assert.notEqual(read.body.result.isError, true, JSON.stringify(read.body.result));
  assert.deepEqual(read.body.result.structuredContent.messages.map((row: any) => row.text), ["hello through the gate"]);

  // relaygate does not proxy deliveries, so confirmation is unavailable rather than an error.
  const receipt = await rpc(env.origin, secret, await call("get_relay_message_status",
    { message_id: sent.body.result.structuredContent.message_id }));
  assert.equal(receipt.status, 200, JSON.stringify(receipt.body));
  assert.notEqual(receipt.body.result.isError, true, JSON.stringify(receipt.body.result));
  assert.equal(receipt.body.result.structuredContent.confirmation, "unavailable");

  const status = await rpc(env.origin, secret, await call("relay_status", {}));
  assert.equal(status.status, 200, JSON.stringify(status.body));
  assert.notEqual(status.body.result.isError, true, JSON.stringify(status.body.result));

  assert.deepEqual(state.leaked, [], "no rg_ token was sent to Relaycast");
  const hosted = await env.database.query("SELECT 1 FROM hosted_relay_participants");
  assert.equal(hosted.rows.length, 0, "no hosted participant was created");
});

test("a gate-only desktop identity whose rg_ token relaygate no longer accepts fails as gone and sends nothing", async (t) => {
  const { env, parent, signer, sourceId, state, enrol, sync } = await gateDesktop(t);
  const chat = enrol("cursor-chat");
  assert.equal((await sync([chat])).status, 200);
  const secret = desktopSecret();
  const registered = await request(env.origin, tokensPath(env.workspaceId), {
    method: "POST", token: parent.accessToken, body: { provider: "cursor", installationId: installationId(), accessToken: secret },
  });
  assert.equal(registered.status, 201, registered.raw);
  state.tokens.delete(chat.token);
  const args = { to: "peer", text: "after revoke" };
  const sent = await rpc(env.origin, secret, {
    jsonrpc: "2.0", id: 7, method: "tools/call",
    params: { name: "send_relay_message", arguments: { ...args, [PROOF]: await signer.sign({ tool: "send_relay_message", src: sourceId,
      sid: chat.native_session.id, tuid: randomUUID(), kind: "cursor", extra: { args } }) } },
  });
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  assert.equal(sent.body.result.isError, true);
  assert.match(sent.body.result.content[0].text as string, /no longer available\. Open Agent Relay Desktop to re-sync it/);
  assert.equal(env.world.bodies.some((row) => row.method === "POST" && row.path === "/v1/dm"), false, "nothing was sent");
  assert.deepEqual(state.leaked, []);
});
