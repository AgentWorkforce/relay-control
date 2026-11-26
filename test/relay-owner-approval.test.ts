import assert from "node:assert/strict";
import test from "node:test";
import { createRelaycastClient, RelaycastCallError } from "../src/messaging/relaycast.js";
import { checkOwnerApproval, relayFailure } from "../src/mcp/relay-participants.js";

// A delegate's owner_approval rides beside the text exactly as given (relay
// client::send_with_owner_approval; Cloud's hosted MCP twin, cloud#6689).
const approval = { v: 1, owner_id: "user-1", actions: [{ class: "merge", target: "acme/web#7", conditions: [{ type: "ci_green" }] }],
  quote: "merge it once green" };

function fixture() {
  const bodies: unknown[] = [];
  const fetchImpl = (async (url, init) => {
    bodies.push(JSON.parse(String(init?.body)));
    return String(url).endsWith("/v1/dm")
      ? Response.json({ ok: true, data: { conversation_id: "c1", message: { id: "m1", agent_name: "a", text: "hi" } } }, { status: 201 })
      : Response.json({ ok: true, data: { id: "500" } }, { status: 201 });
  }) as typeof fetch;
  return { bodies, client: createRelaycastClient({ internalOrigin: "http://cast.internal.example", fetchImpl }) };
}

test("a DM and a channel post carry owner_approval exactly as given; without one the body is unchanged", async () => {
  const f = fixture();
  await f.client.sendDirectMessage({ token: "t", to: "bot", text: "hi", idempotencyKey: "k-dm", ownerApproval: approval });
  await f.client.sendDirectMessage({ token: "t", to: "bot", address: "bot@m", text: "hi", idempotencyKey: "k-addr", ownerApproval: approval });
  await f.client.postChannelMessage({ token: "t", channel: "swarm", text: "hi", idempotencyKey: "k-post", ownerApproval: approval });
  await f.client.postChannelMessage({ token: "t", channel: "swarm", text: "plain", idempotencyKey: "k-plain" });
  assert.deepEqual(f.bodies, [
    { to: "bot", text: "hi", owner_approval: approval },
    { address: "bot@m", text: "hi", owner_approval: approval },
    { text: "hi", owner_approval: approval },
    { text: "plain" },
  ]);
});

test("owner_approval is refused on a reply or thread reply, and above 192 KiB, before anything is sent", () => {
  assert.doesNotThrow(() => checkOwnerApproval(undefined, "reply_to"));
  assert.doesNotThrow(() => checkOwnerApproval(approval, null));
  assert.throws(() => checkOwnerApproval(approval, "reply_to"), /owner_approval goes on a new message, never with reply_to/);
  assert.throws(() => checkOwnerApproval(approval, "thread_id"), /owner_approval goes on a new post, never with thread_id/);
  assert.throws(() => checkOwnerApproval({ ...approval, quote: "x".repeat(192 * 1024) }, null), /larger than 192 KiB/);
});

test("Relaycast's invalid_owner_approval reads as nothing sent, not an unknown outcome", (t) => {
  t.mock.method(console, "error", () => {});
  const error = new RelaycastCallError(400, JSON.stringify({ ok: false, error: { code: "invalid_owner_approval", message: "bad" } }));
  const text = relayFailure(error, "send").content[0]!.text;
  assert.match(text, /Relay refused owner_approval as invalid, so nothing was sent/);
  assert.doesNotMatch(text, /outcome may be unknown/);
});
