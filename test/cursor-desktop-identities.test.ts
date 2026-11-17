import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import test, { type TestContext } from "node:test";
import { request } from "./support/harness.js";
import { copilotDesktopSetup, desktopSecret, identitiesPath, installationId, MCP_PATH, tokensPath } from "./support/copilot-desktop.js";
import { claudeSigner } from "./support/claude-signer.js";

// Cursor chat identity end to end. Cursor's beforeMCPExecution hook can only
// allow or deny, so Agent Relay Desktop points Cursor's agent-relay MCP entry
// at its stdio helper (agent-relay-probe cursor-mcp), which forwards each call
// here with a Desktop provider credential bound to "cursor" (cld_at_, #205)
// and a Claude-shaped proof of kind "cursor": sid is Cursor's conversation_id,
// tuid Cursor's per-call tool_use_id, args the exact forwarded arguments (required).

const ownerHash = (userId: string) => createHash("sha256").update(userId).digest("hex");
const PROOF = "_agent_relay_attestation";
// Cursor's per-call tool_use_id (a UUID in Cursor 3.30).
const ticket = () => randomUUID();

async function rpc(origin: string, token: string, body: unknown, options: { desktop?: boolean; path?: string } = {}) {
  const response = await fetch(`${origin}${options.path ?? MCP_PATH}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`, accept: "application/json, text/event-stream", "content-type": "application/json",
      ...(options.desktop ? { "x-agent-relay-desktop": "1" } : {}),
    },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) as Record<string, any> : {} };
}

/** A verified Desktop with one synced Cursor chat, its signing key and a cursor-bound provider credential. */
async function cursorDesktop(t: TestContext) {
  const env = await copilotDesktopSetup(t);
  const parent = await env.desktopSignIn({ hostName: "sf-mini" });
  const signer = await claudeSigner();
  const sourceId = "desktop-source-cursor";
  // Cursor's conversation_id is a lowercase UUID (captured from Cursor 3.30).
  const sid = randomUUID();
  const chat = env.world.addAgent("cursor-chat", { source: "relay-desktop", owner_hash: ownerHash(env.ownerId) });
  env.world.addAgent("peer");
  const identity = {
    name: "cursor-chat", address: `cursor-chat@cloud-${chat.id}`, agent_id: chat.id, token: chat.token,
    native_session: { kind: "cursor", id: sid.toUpperCase() },
  };
  const attestationKey = { kid: signer.kid, alg: "Ed25519", public_key: signer.publicKey };
  const synced = await request(env.origin, identitiesPath(env.workspaceId), {
    method: "PUT", token: parent.accessToken, body: { source_id: sourceId, identities: [identity], attestation_key: attestationKey },
  });
  assert.equal(synced.status, 200, synced.raw);
  const secret = desktopSecret();
  const registered = await request(env.origin, tokensPath(env.workspaceId), {
    method: "POST", token: parent.accessToken, body: { provider: "cursor", installationId: installationId(), accessToken: secret },
  });
  assert.equal(registered.status, 201, registered.raw);
  /** A tools/call as the Cursor helper forwards it: arguments plus a proof over exactly them. */
  const call = async (tool: string, args: Record<string, unknown>, overrides: Partial<Parameters<typeof signer.sign>[0]>
    & { signWith?: typeof signer; signedArgs?: Record<string, unknown> | null } = {}) => {
    const { signWith, signedArgs, ...claims } = overrides;
    const extra = signedArgs === null ? {} : { args: signedArgs ?? args };
    const proof = await (signWith ?? signer).sign({ tool, src: sourceId, sid, tuid: ticket(), kind: "cursor", ...claims,
      extra: { ...extra, ...claims.extra } });
    return {
      jsonrpc: "2.0", id: 7, method: "tools/call",
      params: { name: tool, arguments: { ...args, [PROOF]: proof }, _meta: { progressToken: 2 } },
    };
  };
  return { env, parent, signer, sourceId, sid, chat, secret, call };
}

const invalid = (response: { status: number; body: Record<string, any> }, label: string) => {
  assert.equal(response.status, 400, `${label}: ${JSON.stringify(response.body)}`);
  assert.equal(response.body.error.code, -32602, label);
  assert.equal(response.body.error.message, "Invalid native chat context.", label);
};

test("identity sync advertises cursor_session_attestation, stores kind cursor, and MCP initialize advertises it", async (t) => {
  const { env, parent, sourceId, chat, sid } = await cursorDesktop(t);
  const listed = await request(env.origin, `/cloud${identitiesPath(env.workspaceId)}?source_id=${sourceId}`, { token: parent.accessToken });
  assert.equal(listed.status, 200);
  assert.equal(listed.body.capabilities.cursor_session_attestation, 1);
  const stored = await env.database.query<{ native_session_kind: string; native_session_id: string }>(
    "SELECT native_session_kind, native_session_id FROM desktop_relay_identities WHERE agent_remote_id = $1", [chat.id]);
  assert.deepEqual(stored.rows[0], { native_session_kind: "cursor", native_session_id: sid });
  const initialized = await rpc(env.origin, parent.accessToken, {
    jsonrpc: "2.0", id: 1, method: "initialize",
    params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "cursor-vscode", version: "1.0.0" } },
  }, { desktop: true });
  assert.deepEqual(initialized.body.result.capabilities.experimental["com.agentrelay/cursor-session-attestation"], { version: 1 });
});

test("a signed Cursor call on a cursor credential joins, sends and reads as the chat's own desktop identity", async (t) => {
  const { env, secret, chat, call } = await cursorDesktop(t);
  const joined = await rpc(env.origin, secret, await call("join_relay", {}));
  assert.equal(joined.status, 200, JSON.stringify(joined.body));
  assert.notEqual(joined.body.result.isError, true, JSON.stringify(joined.body.result));
  assert.equal(joined.body.result.structuredContent.linked, "desktop");
  assert.equal(joined.body.result.structuredContent.address, `cursor-chat@cloud-${chat.id}`);

  const sent = await rpc(env.origin, secret, await call("send_relay_message", { to: "peer", text: "hello from cursor" }),
    { path: `/cloud${MCP_PATH}` });
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  assert.notEqual(sent.body.result.isError, true, JSON.stringify(sent.body.result));
  const conversation = env.world.conversations.find((row) => row.participants.includes("peer"));
  assert.deepEqual(conversation?.participants.slice().sort(), ["cursor-chat", "peer"]);
  const dm = env.world.bodies.find((row) => row.method === "POST" && row.path === "/v1/dm");
  assert.deepEqual(dm?.body, { to: "peer", text: "hello from cursor" });
  assert.equal(JSON.stringify(env.world.bodies).includes(PROOF), false, "the proof never reaches dispatch");

  const status = await rpc(env.origin, secret, await call("relay_status", {}));
  assert.equal(status.status, 200, JSON.stringify(status.body));
  assert.notEqual(status.body.result.isError, true, JSON.stringify(status.body.result));
  const inbox = await rpc(env.origin, secret, await call("check_relay_inbox", {}));
  assert.equal(inbox.status, 200, JSON.stringify(inbox.body));
  assert.notEqual(inbox.body.result.isError, true, JSON.stringify(inbox.body.result));

  const hosted = await env.database.query("SELECT 1 FROM hosted_relay_participants");
  assert.equal(hosted.rows.length, 0, "no hosted participant was created");
  const spent = await env.database.query<{ tool_use_id: string }>("SELECT tool_use_id FROM mcp_attestation_tool_uses");
  assert.ok(spent.rows.every((row) => row.tool_use_id.startsWith("cursor:desktop-source-cursor:")), JSON.stringify(spent.rows));
});

test("an unsigned Cursor call is refused with what to do, not to wait, and sends nothing", async (t) => {
  const { env, secret } = await cursorDesktop(t);
  const before = env.world.bodies.length;
  const sent = await rpc(env.origin, secret, {
    jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "send_relay_message", arguments: { to: "peer", text: "unproven" } },
  });
  assert.equal(sent.status, 200);
  assert.equal(sent.body.result.isError, true);
  const text = sent.body.result.content[0].text as string;
  assert.match(text, /cannot verify this chat's desktop identity/);
  assert.match(text, /Cursor integration in Agent Relay Desktop/);
  assert.doesNotMatch(text, /keep the app open/i);
  assert.equal(env.world.bodies.slice(before).some((row) => row.method === "POST"), false, "nothing was sent or registered");
});

test("bad Cursor proofs are refused: replay, wrong key, changed or unsigned args, other tool, expired, other source, wrong kind", async (t) => {
  const { env, secret, signer, call } = await cursorDesktop(t);
  const once = await call("relay_status", {});
  assert.equal((await rpc(env.origin, secret, once)).status, 200);
  invalid(await rpc(env.origin, secret, once), "replayed ticket");

  invalid(await rpc(env.origin, secret, await call("relay_status", {}, { signWith: await claudeSigner() })), "other installation key");
  invalid(await rpc(env.origin, secret, await call("relay_status", {}, { signWith: await claudeSigner(), kid: signer.kid })), "forged kid");
  invalid(await rpc(env.origin, secret, await call("send_relay_message", { to: "peer", text: "changed" },
    { signedArgs: { to: "peer", text: "approved" } })), "arguments mismatch");
  const renamed = await call("relay_status", {});
  renamed.params.name = "send_relay_message";
  invalid(await rpc(env.origin, secret, renamed), "other tool");
  const now = Math.floor(Date.now() / 1000);
  invalid(await rpc(env.origin, secret, await call("relay_status", {}, { iat: now - 120, exp: now - 60 })), "expired");
  invalid(await rpc(env.origin, secret, await call("relay_status", {}, { src: "another-source" })), "other source");
  invalid(await rpc(env.origin, secret, await call("relay_status", {}, { kind: "claude", signedArgs: null })), "claude proof on cursor credential");
  invalid(await rpc(env.origin, secret, await call("relay_status", {}, { tuid: "has space" })), "malformed ticket");
  invalid(await rpc(env.origin, secret, await call("relay_status", {}, { signedArgs: null })), "no signed arguments");
  assert.equal(env.world.bodies.some((row) => row.method === "POST" && row.path === "/v1/dm"), false);
});

test("a Cursor proof acts only as a synced cursor chat of the same person", async (t) => {
  const { env, secret, parent, call } = await cursorDesktop(t);
  // A conversation this Desktop never synced resolves to no identity.
  const unsynced = await rpc(env.origin, secret, await call("send_relay_message", { to: "peer", text: "x" }, { sid: randomUUID() }));
  assert.equal(unsynced.status, 200);
  assert.equal(unsynced.body.result.isError, true);
  assert.match(unsynced.body.result.content[0].text, /not synced/);
  // A chat synced as another kind (Claude) is not a Cursor chat, even with the same id.
  const claudeOnly = randomUUID();
  const other = env.world.addAgent("claude-chat", { source: "relay-desktop", owner_hash: ownerHash(env.ownerId) });
  const signer2 = await claudeSigner();
  const resync = await request(env.origin, identitiesPath(env.workspaceId), {
    method: "PUT", token: parent.accessToken, body: { source_id: "desktop-source-other", identities: [{
      name: "claude-chat", address: `claude-chat@cloud-${other.id}`, agent_id: other.id, token: other.token,
      native_session: { kind: "claude", id: claudeOnly } }], attestation_key: { kid: signer2.kid, alg: "Ed25519", public_key: signer2.publicKey } },
  });
  assert.equal(resync.status, 200, resync.raw);
  const wrongKind = await rpc(env.origin, secret, await call("send_relay_message", { to: "peer", text: "x" },
    { sid: claudeOnly, src: "desktop-source-other", signWith: signer2 }));
  assert.equal(wrongKind.body.result?.isError, true, JSON.stringify(wrongKind.body));
  assert.match(wrongKind.body.result.content[0].text, /not synced/);
  // Another member's credential cannot use this owner's registered key or chat.
  const memberId = await env.addMember("member@acme.test");
  const member = await env.desktopSignIn({ hostName: "sf-mini", userId: memberId });
  const memberSecret = desktopSecret();
  const minted = await request(env.origin, tokensPath(env.workspaceId), {
    method: "POST", token: member.accessToken, body: { provider: "cursor", installationId: installationId(), accessToken: memberSecret },
  });
  assert.equal(minted.status, 201, minted.raw);
  invalid(await rpc(env.origin, memberSecret, await call("send_relay_message", { to: "peer", text: "x" })), "other person");
  assert.equal(env.world.bodies.some((row) => row.method === "POST" && row.path === "/v1/dm"), false);
});

test("the app bearer with the desktop marker also accepts a Cursor proof; without the marker it is stripped and ignored", async (t) => {
  const { env, parent, call } = await cursorDesktop(t);
  const managed = await rpc(env.origin, parent.accessToken, await call("join_relay", {}), { desktop: true });
  assert.equal(managed.status, 200, JSON.stringify(managed.body));
  assert.equal(managed.body.result.structuredContent?.linked, "desktop", JSON.stringify(managed.body.result));
  await env.database.query("DELETE FROM mcp_attestation_tool_uses");
  const plain = await rpc(env.origin, parent.accessToken, await call("relay_status", {}));
  assert.equal(plain.status, 200, JSON.stringify(plain.body));
  const spent = await env.database.query("SELECT 1 FROM mcp_attestation_tool_uses");
  assert.equal(spent.rows.length, 0);
});
