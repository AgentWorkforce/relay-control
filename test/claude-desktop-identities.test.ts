import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import test, { type TestContext } from "node:test";
import { request } from "./support/harness.js";
import { copilotDesktopSetup, identitiesPath, MCP_PATH } from "./support/copilot-desktop.js";
import { claudeSigner, toolUseId } from "./support/claude-signer.js";

// Claude Code chat identity end to end: Desktop syncs a Claude chat and its
// attestation key, the site advertises claude_session_attestation, and each
// hosted tool call (app bearer + X-Agent-Relay-Desktop) carries a hook proof.

const ownerHash = (userId: string) => createHash("sha256").update(userId).digest("hex");
const PROOF = "_agent_relay_attestation";

async function rpc(origin: string, token: string, body: unknown, options: { desktop?: boolean; path?: string } = {}) {
  const response = await fetch(`${origin}${options.path ?? MCP_PATH}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`, accept: "application/json, text/event-stream", "content-type": "application/json",
      ...(options.desktop === false ? {} : { "x-agent-relay-desktop": "1" }),
    },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) as Record<string, any> : {} };
}

/** A verified Desktop with one synced Claude Code chat identity and its signing key. */
async function claudeDesktop(t: TestContext) {
  const env = await copilotDesktopSetup(t);
  const parent = await env.desktopSignIn({ hostName: "sf-mini" });
  const signer = await claudeSigner();
  const sourceId = randomUUID();
  const sid = randomUUID();
  const chat = env.world.addAgent("claude-chat", { source: "relay-desktop", owner_hash: ownerHash(env.ownerId) });
  env.world.addAgent("peer");
  const identity = {
    name: "claude-chat", address: `claude-chat@cloud-${chat.id}`, agent_id: chat.id, token: chat.token,
    native_session: { kind: "claude", id: sid },
  };
  const attestationKey = { kid: signer.kid, alg: "Ed25519", public_key: signer.publicKey };
  const synced = await request(env.origin, identitiesPath(env.workspaceId), {
    method: "PUT", token: parent.accessToken, body: { source_id: sourceId, identities: [identity], attestation_key: attestationKey },
  });
  assert.equal(synced.status, 200, synced.raw);
  /** A tools/call carrying Claude Code's tool-use id in _meta and a hook proof over it. */
  const call = async (tool: string, args: Record<string, unknown>, overrides: Partial<Parameters<typeof signer.sign>[0]>
    & { signWith?: typeof signer; meta?: string } = {}) => {
    const { signWith, meta, ...claims } = overrides;
    const tuid = claims.tuid ?? toolUseId();
    const proof = await (signWith ?? signer).sign({ tool, src: sourceId, sid, ...claims, tuid });
    return {
      jsonrpc: "2.0", id: 7, method: "tools/call",
      params: { name: tool, arguments: { ...args, [PROOF]: proof }, _meta: { "claudecode/toolUseId": meta ?? tuid } },
    };
  };
  return { env, parent, signer, sourceId, sid, chat, identity, attestationKey, synced, call };
}

test("desktop identities advertise claude_session_attestation and MCP initialize advertises the capability", async (t) => {
  const { env, parent, sourceId, chat, synced } = await claudeDesktop(t);
  assert.deepEqual(synced.body, { synced: 1, identities: [{ agent_id: chat.id, linked_mcp: null, linked_at: null }] });
  const listed = await request(env.origin, `/cloud${identitiesPath(env.workspaceId)}?source_id=${sourceId}`, { token: parent.accessToken });
  assert.equal(listed.status, 200);
  assert.deepEqual(listed.body.capabilities, { native_session_identity: 1, claude_session_attestation: 1, copilot_session_attestation: 1 });
  const stored = await env.database.query<{ native_session_kind: string }>(
    "SELECT native_session_kind FROM desktop_relay_identities WHERE agent_remote_id = $1", [chat.id]);
  assert.equal(stored.rows[0]!.native_session_kind, "claude");
  const keys = await env.database.query("SELECT 1 FROM desktop_attestation_keys");
  assert.equal(keys.rows.length, 1);
  const initialized = await rpc(env.origin, parent.accessToken, {
    jsonrpc: "2.0", id: 1, method: "initialize",
    params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "claude-code", version: "1" } },
  });
  assert.deepEqual(initialized.body.result.capabilities.experimental["com.agentrelay/claude-session-attestation"], { version: 1 });
});

test("a signed Claude call joins and sends as the verified desktop identity; the proof never reaches dispatch", async (t) => {
  const { env, parent, chat, call } = await claudeDesktop(t);
  const joined = await rpc(env.origin, parent.accessToken, await call("join_relay", {}));
  assert.equal(joined.status, 200, JSON.stringify(joined.body));
  assert.notEqual(joined.body.result.isError, true, JSON.stringify(joined.body.result));
  assert.equal(joined.body.result.structuredContent.linked, "desktop");
  assert.equal(joined.body.result.structuredContent.address, `claude-chat@cloud-${chat.id}`);

  const sent = await rpc(env.origin, parent.accessToken, await call("send_relay_message", { to: "peer", text: "hello from claude" }),
    { path: `/cloud${MCP_PATH}` });
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  assert.notEqual(sent.body.result.isError, true, JSON.stringify(sent.body.result));
  const conversation = env.world.conversations.find((row) => row.participants.includes("peer"));
  assert.deepEqual(conversation?.participants.slice().sort(), ["claude-chat", "peer"]);
  const dm = env.world.bodies.find((row) => row.method === "POST" && row.path === "/v1/dm");
  assert.deepEqual(dm?.body, { to: "peer", text: "hello from claude" });
  assert.equal(JSON.stringify(env.world.bodies).includes(PROOF), false);
  const hosted = await env.database.query("SELECT 1 FROM hosted_relay_participants");
  assert.equal(hosted.rows.length, 0, "no hosted participant was created");

  const as = await rpc(env.origin, parent.accessToken, await call("send_relay_message", { to: "peer", text: "x", as: "someone" }));
  assert.equal(as.body.result.isError, true, "managed calls cannot choose another actor");
});

test("a desktop Claude call without a proof fails closed, with no hosted fallback", async (t) => {
  const { env, parent } = await claudeDesktop(t);
  const before = env.world.bodies.length;
  const sent = await rpc(env.origin, parent.accessToken, {
    jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "send_relay_message", arguments: { to: "peer", text: "unproven" } },
  });
  assert.equal(sent.status, 200);
  assert.equal(sent.body.result.isError, true);
  assert.match(sent.body.result.content[0].text, /cannot verify this chat's desktop identity/);
  assert.equal(env.world.bodies.slice(before).some((row) => row.method === "POST"), false, "nothing was sent or registered");
});

test("bad Claude proofs are refused: replay, wrong key, wrong tool use, stale, other source, other provider", async (t) => {
  const { env, parent, signer, call } = await claudeDesktop(t);
  const invalid = (response: { status: number; body: Record<string, any> }, label: string) => {
    assert.equal(response.status, 400, label);
    assert.equal(response.body.error.code, -32602, label);
    assert.equal(response.body.error.message, "Invalid native chat context.", label);
  };
  const once = await call("relay_status", {});
  assert.equal((await rpc(env.origin, parent.accessToken, once)).status, 200);
  invalid(await rpc(env.origin, parent.accessToken, once), "replayed tool use");

  invalid(await rpc(env.origin, parent.accessToken, await call("relay_status", {}, { signWith: await claudeSigner() })), "wrong key");
  invalid(await rpc(env.origin, parent.accessToken,
    await call("relay_status", {}, { signWith: await claudeSigner(), kid: signer.kid })), "forged kid");
  invalid(await rpc(env.origin, parent.accessToken, await call("relay_status", {}, { meta: toolUseId() })), "other tool use");
  const renamed = await call("relay_status", {});
  renamed.params.name = "send_relay_message";
  invalid(await rpc(env.origin, parent.accessToken, renamed), "other tool");
  const now = Math.floor(Date.now() / 1000);
  invalid(await rpc(env.origin, parent.accessToken, await call("relay_status", {}, { iat: now - 120, exp: now - 60 })), "expired");
  invalid(await rpc(env.origin, parent.accessToken, await call("relay_status", {}, { src: randomUUID() })), "other source");
  const withThread = await call("relay_status", {});
  (withThread.params._meta as Record<string, unknown>).threadId = randomUUID();
  invalid(await rpc(env.origin, parent.accessToken, withThread), "conflicting native context");
  assert.equal(env.world.bodies.some((row) => row.method === "POST" && row.path === "/v1/dm"), false);
});

test("a proof for an unsynced chat or another account does not act", async (t) => {
  const { env, call } = await claudeDesktop(t);
  // A signed chat id this Desktop never synced resolves to no identity.
  const unsynced = await rpc(env.origin, (await env.desktopSignIn({ hostName: "sf-mini" })).accessToken,
    await call("send_relay_message", { to: "peer", text: "x" }, { sid: randomUUID() }));
  assert.equal(unsynced.status, 200);
  assert.equal(unsynced.body.result.isError, true);
  assert.match(unsynced.body.result.content[0].text, /not synced/);
  // Another member's login cannot use this owner's registered key.
  const memberId = await env.addMember("member@acme.test");
  const member = await env.desktopSignIn({ hostName: "sf-mini", userId: memberId });
  const foreign = await rpc(env.origin, member.accessToken, await call("send_relay_message", { to: "peer", text: "x" }));
  assert.equal(foreign.status, 400);
  assert.equal(foreign.body.error.message, "Invalid native chat context.");
  assert.equal(env.world.bodies.some((row) => row.method === "POST" && row.path === "/v1/dm"), false);
});

test("outside desktop management a Claude proof is stripped and ignored", async (t) => {
  const { env, parent, call } = await claudeDesktop(t);
  const plain = await rpc(env.origin, parent.accessToken, await call("relay_status", {}), { desktop: false });
  assert.equal(plain.status, 200, JSON.stringify(plain.body));
  const spent = await env.database.query("SELECT 1 FROM mcp_attestation_tool_uses");
  assert.equal(spent.rows.length, 0);
});
