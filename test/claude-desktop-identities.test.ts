import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import test, { type TestContext } from "node:test";
import { request } from "./support/harness.js";
import { copilotDesktopSetup, desktopSecret, identitiesPath, installationId, MCP_PATH, tokensPath } from "./support/copilot-desktop.js";
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
  const sourceId = "desktop-source-claude";
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
  assert.deepEqual(listed.body.capabilities, {
    native_session_identity: 1, claude_session_attestation: 1, copilot_session_attestation: 1, cursor_session_attestation: 1,
    claude_attestation_handoff: 1,
  });
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

test("a sync without attestation_key keeps the registered key; null removes it; a new key replaces it", async (t) => {
  const { env, parent, signer, sourceId, identity, call } = await claudeDesktop(t);
  const keys = async () => (await env.database.query<{ kid: string }>("SELECT kid FROM desktop_attestation_keys")).rows;
  const sync = (body: Record<string, unknown>) => request(env.origin, identitiesPath(env.workspaceId), {
    method: "PUT", token: parent.accessToken, body: { source_id: sourceId, identities: [identity], ...body },
  });
  // The Desktop syncs its chats on launch before its key slot is loaded: the
  // key registered earlier must survive, and signed calls keep verifying.
  const keyless = await sync({});
  assert.equal(keyless.status, 200, keyless.raw);
  assert.deepEqual(await keys(), [{ kid: signer.kid }]);
  const status = await rpc(env.origin, parent.accessToken, await call("relay_status", {}));
  assert.equal(status.status, 200, JSON.stringify(status.body));
  assert.notEqual(status.body.result.isError, true, JSON.stringify(status.body.result));
  assert.equal((await sync({})).status, 200);
  assert.deepEqual(await keys(), [{ kid: signer.kid }]);

  const rotated = await claudeSigner();
  const replaced = await sync({ attestation_key: { kid: rotated.kid, alg: "Ed25519", public_key: rotated.publicKey } });
  assert.equal(replaced.status, 200, replaced.raw);
  assert.deepEqual(await keys(), [{ kid: rotated.kid }]);
  const oldKey = await rpc(env.origin, parent.accessToken, await call("relay_status", {}));
  assert.equal(oldKey.status, 400, "the replaced key no longer verifies");
  const newKey = await rpc(env.origin, parent.accessToken, await call("relay_status", {}, { signWith: rotated, kid: rotated.kid }));
  assert.equal(newKey.status, 200, JSON.stringify(newKey.body));

  const removed = await sync({ attestation_key: null });
  assert.equal(removed.status, 200, removed.raw);
  assert.deepEqual(await keys(), []);
  const unverifiable = await rpc(env.origin, parent.accessToken, await call("relay_status", {}, { signWith: rotated, kid: rotated.kid }));
  assert.equal(unverifiable.status, 400, "no key is registered any more");

  // An empty identity list still clears the source, key included.
  assert.equal((await sync({ attestation_key: { kid: rotated.kid, alg: "Ed25519", public_key: rotated.publicKey } })).status, 200);
  assert.deepEqual(await keys(), [{ kid: rotated.kid }]);
  const cleared = await request(env.origin, identitiesPath(env.workspaceId), {
    method: "PUT", token: parent.accessToken, body: { source_id: sourceId, identities: [] },
  });
  assert.equal(cleared.status, 200, cleared.raw);
  assert.deepEqual(await keys(), []);
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

// The handoff: Claude Code's auto mode refuses a call whose input a hook
// rewrote, so Desktop posts the proof first and the call goes out unchanged.

const handoffPath = (workspaceId: string) => `${identitiesPath(workspaceId)}/attestations`;

/** A Claude Desktop that hands proofs off: `hand` posts one, `plain` is the unchanged call. */
async function handoffDesktop(t: TestContext) {
  const desktop = await claudeDesktop(t);
  const { env, parent, signer, sourceId, sid } = desktop;
  const sign = (tool: string, tuid: string, overrides: Partial<Parameters<typeof signer.sign>[0]> & { signWith?: typeof signer } = {}) => {
    const { signWith, ...claims } = overrides;
    return (signWith ?? signer).sign({ tool, src: sourceId, sid, tuid, ...claims });
  };
  const hand = (body: unknown, token = parent.accessToken, path = handoffPath(env.workspaceId)) =>
    request(env.origin, path, { method: "POST", token, body });
  const plain = (tool: string, args: Record<string, unknown>, tuid: string) => ({
    jsonrpc: "2.0", id: 9, method: "tools/call", params: { name: tool, arguments: args, _meta: { "claudecode/toolUseId": tuid } },
  });
  return { ...desktop, sign, hand, plain };
}

test("a handed-off proof makes the unchanged call act as the verified desktop identity", async (t) => {
  const { env, parent, chat, sign, hand, plain } = await handoffDesktop(t);
  const tuid = toolUseId();
  const handed = await hand({ attestation: await sign("send_relay_message", tuid) });
  assert.equal(handed.status, 204, handed.raw);
  assert.equal(handed.raw, "");
  const rows = await env.database.query("SELECT 1 FROM mcp_attestation_handoffs");
  assert.equal(rows.rows.length, 1);
  const sent = await rpc(env.origin, parent.accessToken, plain("send_relay_message", { to: "peer", text: "handed off" }, tuid));
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  assert.notEqual(sent.body.result.isError, true, JSON.stringify(sent.body.result));
  const dm = env.world.bodies.find((row) => row.method === "POST" && row.path === "/v1/dm");
  assert.deepEqual(dm?.body, { to: "peer", text: "handed off" });
  assert.deepEqual(env.world.conversations.find((row) => row.participants.includes("peer"))?.participants.slice().sort(),
    ["claude-chat", "peer"]);
  assert.equal((await env.database.query("SELECT 1 FROM mcp_attestation_handoffs")).rows.length, 0, "taken");
  assert.equal((await env.database.query("SELECT 1 FROM mcp_attestation_tool_uses WHERE tool_use_id = $1", [tuid])).rows.length, 1, "spent");

  // Under /cloud too, and an in-argument proof still works next to it.
  const cloudTuid = toolUseId();
  assert.equal((await hand({ attestation: await sign("relay_status", cloudTuid) }, parent.accessToken,
    `/cloud${handoffPath(env.workspaceId)}`)).status, 204);
  const status = await rpc(env.origin, parent.accessToken, plain("relay_status", {}, cloudTuid), { path: `/cloud${MCP_PATH}` });
  assert.equal(status.status, 200, JSON.stringify(status.body));
  assert.equal(status.body.result.structuredContent.address, `claude-chat@cloud-${chat.id}`, JSON.stringify(status.body.result));
});

test("a handoff is used once, binds its tool, and a call with nothing handed off gets today's guidance", async (t) => {
  const { env, parent, sign, hand, plain } = await handoffDesktop(t);
  const tuid = toolUseId();
  const proof = await sign("relay_status", tuid);
  assert.equal((await hand({ attestation: proof })).status, 204);
  assert.equal((await rpc(env.origin, parent.accessToken, plain("relay_status", {}, tuid))).status, 200);
  // The same call again: nothing is handed off any more, so it carries no identity.
  const again = await rpc(env.origin, parent.accessToken, plain("send_relay_message", { to: "peer", text: "x" }, tuid));
  assert.equal(again.status, 200);
  assert.equal(again.body.result.isError, true);
  assert.match(again.body.result.content[0].text, /cannot verify this chat's desktop identity/);
  // Handing the spent proof off again is accepted, but the call is a replay.
  assert.equal((await hand({ attestation: proof })).status, 204);
  const replay = await rpc(env.origin, parent.accessToken, plain("relay_status", {}, tuid));
  assert.equal(replay.status, 400);
  assert.equal(replay.body.error.message, "Invalid native chat context.");

  const other = toolUseId();
  assert.equal((await hand({ attestation: await sign("relay_status", other) })).status, 204);
  const wrongTool = await rpc(env.origin, parent.accessToken, plain("send_relay_message", { to: "peer", text: "x" }, other));
  assert.equal(wrongTool.status, 400, "a proof for another tool is refused");
  assert.equal(wrongTool.body.error.message, "Invalid native chat context.");
  assert.equal(env.world.bodies.some((row) => row.method === "POST" && row.path === "/v1/dm"), false);
});

test("a handoff is idempotent for the same proof and 409 for another one", async (t) => {
  const { sign, hand } = await handoffDesktop(t);
  const tuid = toolUseId();
  const proof = await sign("relay_status", tuid);
  assert.equal((await hand({ attestation: proof })).status, 204);
  assert.equal((await hand({ attestation: proof })).status, 204);
  const conflict = await hand({ attestation: await sign("send_relay_message", tuid) });
  assert.equal(conflict.status, 409, conflict.raw);
  assert.equal(conflict.body.error, "conflict");
  assert.equal(conflict.raw.includes(proof.split(".")[2]!), false);
});

test("a malformed, unknown-key, forged, expired or Cursor handoff is refused and nothing is stored", async (t) => {
  const { env, parent, sign, hand } = await handoffDesktop(t);
  const rejected = async (body: unknown, status: number, code: string, label: string) => {
    const response = await hand(body);
    assert.equal(response.status, status, `${label}: ${response.raw}`);
    assert.equal(response.body.error, code, label);
  };
  const tuid = toolUseId();
  const good = await sign("relay_status", tuid);
  await rejected({ attestation: await sign("relay_status", tuid, { signWith: await claudeSigner() }) }, 403, "attestation_rejected", "unknown key");
  const [head, payload] = good.split(".");
  await rejected({ attestation: `${head}.${payload}.${Buffer.alloc(64, 1).toString("base64url")}` }, 403, "attestation_rejected", "bad signature");
  const now = Math.floor(Date.now() / 1000);
  await rejected({ attestation: await sign("relay_status", tuid, { iat: now - 120, exp: now - 60 }) }, 403, "attestation_rejected", "expired");
  await rejected({ attestation: "not-a-proof" }, 400, "invalid_attestation", "malformed");
  await rejected({ attestation: good, extra: true }, 400, "invalid_attestation", "unknown field");
  await rejected({}, 400, "invalid_attestation", "missing");
  await rejected({ attestation: "a".repeat(4097) }, 400, "invalid_attestation", "too large");
  await rejected({ attestation: await sign("relay_status", tuid, { kind: "cursor", extra: { args: {} } }) }, 400, "invalid_attestation", "cursor kind");
  assert.equal((await env.database.query("SELECT 1 FROM mcp_attestation_handoffs")).rows.length, 0);
  // Only POST, and only with the identity sync's auth.
  const get = await request(env.origin, handoffPath(env.workspaceId), { token: parent.accessToken });
  assert.equal(get.status, 405);
  const anonymous = await request(env.origin, handoffPath(env.workspaceId), { method: "POST", body: { attestation: good } });
  assert.equal(anonymous.status, 401);
});

test("a Cursor credential never takes a handed-off Claude proof", async (t) => {
  const { env, parent, sign, hand, plain } = await handoffDesktop(t);
  const secret = desktopSecret();
  const registered = await request(env.origin, tokensPath(env.workspaceId), {
    method: "POST", token: parent.accessToken, body: { provider: "cursor", installationId: installationId(), accessToken: secret },
  });
  assert.equal(registered.status, 201, registered.raw);
  const tuid = toolUseId();
  assert.equal((await hand({ attestation: await sign("send_relay_message", tuid) })).status, 204);
  const sent = await rpc(env.origin, secret, plain("send_relay_message", { to: "peer", text: "x" }, tuid), { desktop: false });
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  assert.equal(sent.body.result.isError, true, "no verified chat on a Cursor credential");
  assert.equal((await env.database.query("SELECT 1 FROM mcp_attestation_handoffs")).rows.length, 1, "not taken");
  assert.equal(env.world.bodies.some((row) => row.method === "POST" && row.path === "/v1/dm"), false);
});

test("a native join keeps its name: the verified identity's own name joins, another name or address is refused", async (t) => {
  const { env, parent, chat, sign, hand, plain, call } = await handoffDesktop(t);
  const join = async (args: Record<string, unknown>) => {
    const tuid = toolUseId();
    assert.equal((await hand({ attestation: await sign("join_relay", tuid) })).status, 204);
    return rpc(env.origin, parent.accessToken, plain("join_relay", args, tuid));
  };
  for (const args of [{ name: "claude-chat" }, { name: "  claude-chat " }, { name: "claude-chat", description: "ignored" }, { description: "ignored" }]) {
    const joined = await join(args);
    assert.equal(joined.status, 200, JSON.stringify(joined.body));
    assert.notEqual(joined.body.result.isError, true, `${JSON.stringify(args)}: ${JSON.stringify(joined.body.result)}`);
    assert.equal(joined.body.result.structuredContent.linked, "desktop");
    assert.equal(joined.body.result.structuredContent.address, `claude-chat@cloud-${chat.id}`);
  }
  for (const args of [{ name: "someone-else" }, { desktop_address: "other@cloud-x" }]) {
    const refusedJoin = await join(args);
    assert.equal(refusedJoin.status, 200);
    assert.equal(refusedJoin.body.result.isError, true, JSON.stringify(args));
    assert.match(refusedJoin.body.result.content[0].text, /can only use its verified desktop identity/);
  }
  // The in-argument path follows the same rule.
  const inArgument = await rpc(env.origin, parent.accessToken, await call("join_relay", { name: "claude-chat" }));
  assert.notEqual(inArgument.body.result.isError, true, JSON.stringify(inArgument.body.result));
  assert.equal(env.world.bodies.some((row) => row.method === "PATCH" || (row.method === "POST" && row.path.includes("card"))), false);
});
