import assert from "node:assert/strict";
import test from "node:test";
import { createRelaycastClient, RelaycastCallError } from "../src/messaging/relaycast.js";
import type { McpContext } from "../src/mcp/context.js";
import { prepareOwnerApproval, relayFailure, relayService, RelayToolError } from "../src/mcp/relay-participants.js";
import { connectAndBind, startFactoryEnv } from "./factory-helpers.js";

// A delegate's owner_approval rides beside the text exactly as given (relay
// client::send_with_owner_approval; Cloud's hosted MCP twin, cloud#6689).
const approval = { v: 1, owner_id: "0b6f3c1e-8f9a-4d2b-9c71-2e5a4f3d1b08", actions: [{ class: "merge", target: "acme/web#7", conditions: [{ type: "ci_green" }] }],
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

const OWNER = "0b6f3c1e-8f9a-4d2b-9c71-2e5a4f3d1b08";

test("owner_approval is refused on a reply or thread reply, and above 192 KiB, before anything is sent", () => {
  assert.equal(prepareOwnerApproval(undefined, "reply_to", OWNER), undefined);
  assert.equal(JSON.stringify(prepareOwnerApproval(approval, null, OWNER)), JSON.stringify(approval));
  assert.throws(() => prepareOwnerApproval(approval, "reply_to", OWNER), /owner_approval goes on a new message, never with reply_to/);
  assert.throws(() => prepareOwnerApproval(approval, "thread_id", OWNER), /owner_approval goes on a new post, never with thread_id/);
  assert.throws(() => prepareOwnerApproval({ ...approval, quote: "x".repeat(192 * 1024) }, null, OWNER), /larger than 192 KiB/);
});

test("owner_approval fills v and the caller's own owner_id, and passes a hand-stated one on byte for byte (cloud#6699)", () => {
  const actions = [{ class: "merge", target: "acme/web#7", conditions: [{ type: "ci_green" }, { type: "mergeable" }] }];
  assert.deepEqual(prepareOwnerApproval({ actions, quote: "go" }, null, OWNER), { v: 1, actions, quote: "go", owner_id: OWNER });
  const stated = { v: 1, owner_id: OWNER, actions };
  assert.equal(JSON.stringify(prepareOwnerApproval(stated, null, OWNER)), JSON.stringify(stated));
  // The schema canonicalizes a UUID's case, so an upper-case spelling of the same owner is that owner, sent as given.
  const upper = { v: 1, owner_id: OWNER.toUpperCase(), actions };
  assert.equal(JSON.stringify(prepareOwnerApproval(upper, null, OWNER)), JSON.stringify(upper));
  // An agent identity token has no owner: any owner_approval is refused, stated owner_id or not.
  for (const given of [{ actions }, { owner_id: OWNER, actions }]) {
    assert.throws(() => prepareOwnerApproval(given, null, null), /invalid_owner_approval: a workspace agent identity token has no owner/);
  }
  assert.equal(prepareOwnerApproval(undefined, null, null), undefined);
});

test("owner_approval for another owner, or with a bad field, is refused naming the field, before sending", () => {
  const merge = { class: "merge", target: "acme/web#7" };
  const refused: Array<[Record<string, unknown>, RegExp]> = [
    [{ owner_id: "mallory", actions: [merge] }, /^invalid_owner_approval: owner_id must be your owner's user id/],
    [{ actions: [] }, /^invalid_owner_approval: owner_approval\.actions:/],
    [{ actions: [{ class: "merge", target: "acme/web" }] }, /owner_approval\.actions\[0\] is not a valid merge action/],
    [{ actions: [merge, { class: "pr_ops", target: "acme/web#7:force_push" }] }, /owner_approval\.actions\[1\] is not a valid pr_ops action/],
    [{ actions: [{ class: "release", target: "acme/web:*" }] }, /owner_approval\.actions\[0\] is not a valid release action/],
    [{ actions: [{ class: "approve_everything", target: "acme/web#7" }] }, /owner_approval\.actions\[0\]\.class:/],
    [{ actions: [{ ...merge, conditions: [{ type: "head_sha", sha: "abc" }] }] }, /owner_approval\.actions\[0\]\.conditions\[0\]\.sha:/],
    [{ actions: [{ class: "deploy", target: "production", conditions: [{ type: "ci_green" }] }] }, /owner_approval\.actions\[0\] is not a valid deploy action/],
    [{ actions: [merge, merge] }, /owner_approval\.actions: one entry per class and target/],
    [{ actions: [merge], scope: "all" }, /owner_approval has unknown field scope/],
    [{ v: 2, actions: [merge] }, /^invalid_owner_approval: owner_approval\.v:/],
    [{ actions: [merge], expires_at: "tomorrow" }, /^invalid_owner_approval: owner_approval\.expires_at:/],
  ];
  for (const [ownerApproval, message] of refused) {
    assert.throws(() => prepareOwnerApproval(ownerApproval, null, OWNER), (error: unknown) =>
      error instanceof RelayToolError && message.test(error.message) && error.message.endsWith("Nothing was sent."), JSON.stringify(ownerApproval));
  }
  // The tool error reaches the agent as is.
  const failure = relayFailure(new RelayToolError("invalid_owner_approval: owner_approval.actions[0] is not a valid merge action"));
  assert.match(failure.content[0]!.text, /owner_approval\.actions\[0\]/);
});

test("send fills the signed-in owner into owner_approval and refuses a bad one without sending", async (t) => {
  const env = await startFactoryEnv(t);
  const binding = await connectAndBind(env);
  const name = binding.agent.name;
  const peer = { id: "ag-peer", name: "peer-agent", address: null, kind: "agent", persona: null, status: "online", lastSeen: null, metadata: {} };
  const sent: unknown[] = [];
  const client = {
    listAgents: async () => [peer],
    findAgentsByNames: async (_key: string, names: string[]) => [peer].filter(agent => names.includes(agent.name)),
    findAgentByName: async (_key: string, agentName: string) => agentName === peer.name ? peer : null,
    getRosterAgent: async () => peer,
    heartbeat: async () => undefined,
    sendDirectMessage: async (input: { ownerApproval?: unknown }) => {
      sent.push(input.ownerApproval);
      return { message: { id: String(sent.length) }, conversationId: "conv-1" };
    },
  };
  const context = {
    principal: { userId: env.ownerId, workspaceId: env.workspaceId, organizationId: env.organizationId, role: "owner", scopes: ["cli:auth"] },
    workspace: { id: env.workspaceId, organizationId: env.organizationId, name: "primary", relaycastWorkspaceId: "rc-primary",
      relaycastApiKey: "rk_live_primary", role: "owner" },
    desktopCall: {}, members: async () => [], factory: env.module.mcp,
    relay: { database: env.database, keyring: env.config.encryptionKeyring, client, sessionId: undefined },
  } as unknown as McpContext;
  const actions = [{ class: "pr_ops", target: "acme/web#7:comment" }];
  await relayService(context).send({ to: "peer-agent", text: "ok to comment", as: name, owner_approval: { actions } });
  assert.deepEqual(sent, [{ v: 1, actions, owner_id: env.ownerId }]);
  await assert.rejects(relayService(context).send({ to: "peer-agent", text: "x", as: name,
    owner_approval: { owner_id: env.memberId, actions } }), /owner_id must be your owner's user id/);
  await assert.rejects(relayService(context).send({ to: "peer-agent", text: "x", as: name,
    owner_approval: { actions: [{ class: "merge", target: "acme/web" }] } }), /actions\[0\] is not a valid merge action/);
  assert.equal(sent.length, 1);
});

test("Relaycast's invalid_owner_approval reads as nothing sent, not an unknown outcome", (t) => {
  t.mock.method(console, "error", () => {});
  const error = new RelaycastCallError(400, JSON.stringify({ ok: false, error: { code: "invalid_owner_approval", message: "bad" } }));
  const text = relayFailure(error, "send").content[0]!.text;
  assert.match(text, /Relay refused owner_approval as invalid, so nothing was sent/);
  assert.doesNotMatch(text, /outcome may be unknown/);
});
