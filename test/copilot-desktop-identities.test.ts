import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import test, { type TestContext } from "node:test";
import { request } from "./support/harness.js";
import { copilotDesktopSetup, desktopSecret, identitiesPath, installationId, MCP_PATH, tokensPath } from "./support/copilot-desktop.js";
import { copilotSigner } from "./support/copilot-signer.js";

// Requirements (2) desktop identities and (3) the Copilot MCP endpoint.

const ownerHash = (userId: string) => createHash("sha256").update(userId).digest("hex");
const PROOF = "_agent_relay_attestation";

async function rpc(origin: string, token: string, body: unknown, path = MCP_PATH) {
  const response = await fetch(`${origin}${path}`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, accept: "application/json, text/event-stream", "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) as Record<string, any> : {} };
}

/** A verified Desktop with one synced Copilot chat identity, its signing key and a Copilot provider credential. */
async function copilotDesktop(t: TestContext) {
  const env = await copilotDesktopSetup(t);
  const parent = await env.desktopSignIn({ hostName: "sf-mini" });
  const signer = await copilotSigner();
  const sourceId = randomUUID();
  const sid = randomUUID();
  const chat = env.world.addAgent("copilot-chat", { source: "relay-desktop", owner_hash: ownerHash(env.ownerId) });
  env.world.addAgent("peer");
  const identity = {
    name: "copilot-chat", address: `copilot-chat@cloud-${chat.id}`, agent_id: chat.id, token: chat.token,
    native_session: { kind: "copilot", id: sid },
  };
  const attestationKey = { kid: signer.kid, alg: "Ed25519", public_key: signer.publicKey };
  const synced = await request(env.origin, identitiesPath(env.workspaceId), {
    method: "PUT", token: parent.accessToken, body: { source_id: sourceId, identities: [identity], attestation_key: attestationKey },
  });
  assert.equal(synced.status, 200, synced.raw);
  const secret = desktopSecret();
  const registered = await request(env.origin, tokensPath(env.workspaceId), {
    method: "POST", token: parent.accessToken, body: { provider: "copilot", installationId: installationId(), accessToken: secret },
  });
  assert.equal(registered.status, 201, registered.raw);
  /** A tools/call whose arguments carry a Desktop hook proof over exactly `args`. */
  const call = async (tool: string, args: Record<string, unknown>, overrides: Parameters<typeof signer.sign>[0] extends infer P
    ? Partial<P> & { signWith?: typeof signer } : never = {}) => {
    const { signWith, ...claims } = overrides;
    const proof = await (signWith ?? signer).sign({
      tool, args, user: env.ownerId, workspace: env.workspaceId, src: sourceId, sid, ...claims,
    });
    return { jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: tool, arguments: { ...args, [PROOF]: proof } } };
  };
  return { env, parent, signer, sourceId, sid, chat, identity, attestationKey, synced, secret, call };
}

test("desktop identities round-trip and advertise copilot_session_attestation", async (t) => {
  const { env, parent, sourceId, chat, identity, attestationKey, synced } = await copilotDesktop(t);
  assert.deepEqual(synced.body, { synced: 1, identities: [{ agent_id: chat.id, linked_mcp: null, linked_at: null }] });
  assert.equal(synced.raw.includes(chat.token), false, "the agent token is never returned");
  const stored = await env.database.query<{ token_ciphertext: string }>(
    "SELECT token_ciphertext FROM selfhost_desktop_relay_identities WHERE agent_remote_id = $1", [chat.id]);
  assert.equal(stored.rows[0]!.token_ciphertext.includes(chat.token), false, "encrypted at rest");

  for (const prefix of ["", "/cloud"]) {
    const listed = await request(env.origin, `${prefix}${identitiesPath(env.workspaceId)}?source_id=${sourceId}`, { token: parent.accessToken });
    assert.equal(listed.status, 200);
    assert.deepEqual(listed.body, {
      identities: [{ agent_id: chat.id, linked_mcp: null, linked_at: null }],
      capabilities: { native_session_identity: 1, copilot_session_attestation: 1 },
    });
  }
  const initialized = await rpc(env.origin, parent.accessToken, {
    jsonrpc: "2.0", id: 1, method: "initialize",
    params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "desktop", version: "1" } },
  });
  assert.deepEqual(initialized.body.result.capabilities.experimental["com.agentrelay/copilot-session-attestation"], { version: 1 });

  // Unverified and foreign identities are skipped, not stored.
  const stranger = env.world.addAgent("stranger-chat", { source: "relay-desktop", owner_hash: ownerHash("someone-else") });
  const resync = await request(env.origin, identitiesPath(env.workspaceId), {
    method: "PUT", token: parent.accessToken, body: {
      source_id: sourceId, attestation_key: attestationKey, identities: [
        identity,
        { name: "stranger-chat", address: `stranger-chat@cloud-${stranger.id}`, agent_id: stranger.id, token: stranger.token },
        { name: "forged", address: "forged@cloud-x", agent_id: "ag_forged", token: "at_forged_not_a_token" },
      ],
    },
  });
  assert.equal(resync.status, 200, resync.raw);
  assert.equal(resync.body.synced, 1);
  assert.deepEqual(resync.body.skipped, [
    { agent_id: stranger.id, reason: "not_owned" },
    { agent_id: "ag_forged", reason: "unverified" },
  ]);

  // A key that does not match its kid, and a missing source_id, are invalid.
  const badKey = await request(env.origin, identitiesPath(env.workspaceId), {
    method: "PUT", token: parent.accessToken,
    body: { source_id: sourceId, identities: [identity], attestation_key: { ...attestationKey, kid: "A".repeat(22) } },
  });
  assert.equal(badKey.status, 400);
  assert.deepEqual(badKey.body, { error: "invalid_request", message: "Invalid desktop identity sync" });
  assert.equal((await request(env.origin, identitiesPath(env.workspaceId), { token: parent.accessToken })).status, 400);

  // An empty list clears the source (and its key).
  const cleared = await request(env.origin, identitiesPath(env.workspaceId), {
    method: "PUT", token: parent.accessToken, body: { source_id: sourceId, identities: [] },
  });
  assert.deepEqual(cleared.body, { synced: 0, identities: [] });
  const keys = await env.database.query("SELECT 1 FROM selfhost_desktop_attestation_keys");
  assert.equal(keys.rows.length, 0);
});

test("a signed Copilot call joins and sends as the verified desktop identity; the proof never reaches dispatch", async (t) => {
  const { env, secret, chat, call } = await copilotDesktop(t);
  const joined = await rpc(env.origin, secret, await call("join_relay", {}));
  assert.equal(joined.status, 200, JSON.stringify(joined.body));
  assert.notEqual(joined.body.result.isError, true, JSON.stringify(joined.body.result));
  assert.equal(joined.body.result.structuredContent.linked, "desktop");
  assert.equal(joined.body.result.structuredContent.name, "copilot-chat");
  assert.equal(joined.body.result.structuredContent.address, `copilot-chat@cloud-${chat.id}`);

  const sent = await rpc(env.origin, secret, await call("send_relay_message", { to: "peer", text: "hello from copilot" }), `/cloud${MCP_PATH}`);
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  assert.notEqual(sent.body.result.isError, true, JSON.stringify(sent.body.result));
  assert.equal(sent.body.result.structuredContent.reply_guidance, "replies will be injected into your session by Agent Relay Desktop");
  const conversation = env.world.conversations.find((row) => row.participants.includes("peer"));
  assert.deepEqual(conversation?.participants.slice().sort(), ["copilot-chat", "peer"]);
  const dm = env.world.bodies.find((row) => row.method === "POST" && row.path === "/v1/dm");
  assert.deepEqual(dm?.body, { to: "peer", text: "hello from copilot" });
  assert.equal(JSON.stringify(env.world.bodies).includes(PROOF), false);
  // No hosted participant was created for the chat.
  const hosted = await env.database.query("SELECT 1 FROM selfhost_hosted_relay_participants");
  assert.equal(hosted.rows.length, 0);

  // Managed calls cannot choose another actor.
  const as = await rpc(env.origin, secret, await call("send_relay_message", { to: "peer", text: "x", as: "someone" }));
  assert.equal(as.body.result.isError, true);
});

test("a Copilot call without proof is unavailable, with no hosted fallback", async (t) => {
  const { env, secret } = await copilotDesktop(t);
  const before = env.world.bodies.length;
  const sent = await rpc(env.origin, secret, {
    jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "send_relay_message", arguments: { to: "peer", text: "unproven" } },
  });
  assert.equal(sent.status, 200);
  assert.equal(sent.body.result.isError, true);
  assert.match(sent.body.result.content[0].text, /cannot verify this chat's desktop identity/);
  // An MCP session id is not proof of a chat.
  const withSession = await fetch(`${env.origin}${MCP_PATH}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${secret}`, "mcp-session-id": randomUUID(),
      accept: "application/json, text/event-stream", "content-type": "application/json",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "join_relay", arguments: {} } }),
  });
  const joined = await withSession.json() as Record<string, any>;
  assert.equal(joined.result.isError, true);
  assert.equal(env.world.bodies.slice(before).some((row) => row.method === "POST"), false, "nothing was sent or registered");
});

test("bad proofs are refused: replay, wrong key, stale, mismatched args, other workspace, other provider", async (t) => {
  const { env, parent, secret, signer, call } = await copilotDesktop(t);
  const invalid = (response: { status: number; body: Record<string, any> }, label: string) => {
    assert.equal(response.status, 400, label);
    assert.equal(response.body.error.code, -32602, label);
    assert.equal(response.body.error.message, "Invalid native chat context.", label);
  };
  const once = await call("relay_status", {});
  assert.equal((await rpc(env.origin, secret, once)).status, 200);
  invalid(await rpc(env.origin, secret, once), "replayed nonce");

  // Signed by a key Desktop never registered (under its own kid).
  invalid(await rpc(env.origin, secret, await call("relay_status", {}, { signWith: await copilotSigner() })), "wrong key");
  // Signed by an unregistered key that claims the registered kid.
  const impostor = await copilotSigner();
  invalid(await rpc(env.origin, secret, await call("relay_status", {}, { signWith: impostor, kid: signer.kid })), "forged kid");

  const now = Math.floor(Date.now() / 1000);
  invalid(await rpc(env.origin, secret, await call("relay_status", {}, { iat: now - 120, exp: now - 60 })), "stale");

  const tampered = await call("send_relay_message", { to: "peer", text: "approved text" });
  (tampered.params.arguments as Record<string, unknown>).text = "different text";
  invalid(await rpc(env.origin, secret, tampered), "mismatched args");

  invalid(await rpc(env.origin, secret, await call("relay_status", {}, { workspace: env.otherWorkspaceId })), "other workspace");
  invalid(await rpc(env.origin, secret, await call("relay_status", {}, { src: randomUUID() })), "other source");

  // A proof on a connection that is not a Copilot credential.
  invalid(await rpc(env.origin, parent.accessToken, await call("relay_status", {})), "not copilot");
  assert.equal(env.world.bodies.some((row) => row.method === "POST" && row.path === "/v1/dm"), false);
});

test("Copilot requests may be up to 128 KiB; everyone else stays at 64 KiB", async (t) => {
  const { env, parent, secret } = await copilotDesktop(t);
  const sized = (bytes: number) => {
    const base = { jsonrpc: "2.0", id: 1, method: "ping", params: { padding: "" } };
    const padding = "x".repeat(bytes - JSON.stringify(base).length);
    return JSON.stringify({ ...base, params: { padding } });
  };
  const hundred = sized(100 * 1024);
  assert.notEqual((await rpc(env.origin, secret, hundred)).status, 413);
  assert.equal((await rpc(env.origin, parent.accessToken, hundred)).status, 413);
  assert.notEqual((await rpc(env.origin, secret, sized(128 * 1024))).status, 413);
  assert.equal((await rpc(env.origin, secret, sized(128 * 1024 + 1))).status, 413);
});
