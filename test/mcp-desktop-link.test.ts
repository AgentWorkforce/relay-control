import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import test, { type TestContext } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { McpContext } from "../src/mcp/context.js";
import { desktopCallContext } from "../src/mcp/desktop-call.js";
import { relayService } from "../src/mcp/relay-participants.js";
import { createRelaycastClient } from "../src/messaging/relaycast.js";
import { copilotDesktopSetup, identitiesPath, MCP_PATH } from "./support/copilot-desktop.js";
import { request } from "./support/harness.js";

// join_relay desktop_address: a native MCP session links to one of the
// owner's synced Desktop identities and then acts as it (ported from Cloud).

const ownerHash = (userId: string) => createHash("sha256").update(userId).digest("hex");
const NOT_SYNCED = "That desktop identity is not synced to your account in this workspace. Is Agent Relay Desktop running and signed in?";
const LINKED = { linked_mcp: "agent-relay-sessions" };
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;

type CallResult = Awaited<ReturnType<Client["callTool"]>>;
function structured(result: CallResult): Record<string, any> {
  assert.notEqual(result.isError, true, JSON.stringify(result.content));
  return result.structuredContent as Record<string, any>;
}
function toolError(result: CallResult): string {
  assert.equal(result.isError, true, JSON.stringify(result.content));
  return (result.content as Array<{ text: string }>)[0]!.text;
}

/** A signed-in Desktop that synced one relay identity, a peer, and a native MCP client for the owner. */
async function linkedDesktop(t: TestContext) {
  const env = await copilotDesktopSetup(t);
  const parent = await env.desktopSignIn();
  const sourceId = randomUUID();
  const chat = env.world.addAgent("desk-chat", { source: "relay-desktop", owner_hash: ownerHash(env.ownerId) });
  const peer = env.world.addAgent("peer");
  const identity = (agent: typeof chat) => ({ name: agent.name, address: `${agent.name}@cloud-${agent.id}`, agent_id: agent.id, token: agent.token });
  const sync = (identities: Array<ReturnType<typeof identity>>) => request(env.origin, identitiesPath(env.workspaceId), {
    method: "PUT", token: parent.accessToken, body: { source_id: sourceId, identities },
  });
  const synced = await sync([identity(chat)]);
  assert.equal(synced.status, 200, synced.raw);
  const accessToken = await env.deviceLogin();
  const connect = async () => {
    const client = new Client({ name: "desktop-link-test", version: "1.0.0" });
    await client.connect(new StreamableHTTPClientTransport(new URL(`${env.origin}${MCP_PATH}`),
      { requestInit: { headers: { authorization: `Bearer ${accessToken}` } } }));
    t.after(() => client.close());
    return client;
  };
  const client = await connect();
  const address = `desk-chat@cloud-${chat.id}`;
  const bindings = async () => (await env.database.query<{ session_hash: string; desktop_identity_id: string }>(
    "SELECT session_hash, desktop_identity_id FROM desktop_relay_session_bindings")).rows;
  const listed = () => request(env.origin, `${identitiesPath(env.workspaceId)}?source_id=${sourceId}`, { token: parent.accessToken });
  return { env, parent, sourceId, chat, peer, identity, sync, connect, client, address, bindings, listed };
}

test("join by desktop_address links the session; send, status and inbox act as the desktop identity", async (t) => {
  const f = await linkedDesktop(t);
  const joined = structured(await f.client.callTool({ name: "join_relay", arguments: { desktop_address: ` ${f.address} ` } }));
  assert.deepEqual(joined, {
    joined: true, linked: "desktop", name: "desk-chat", address: f.address, already_joined: false,
    reply_guidance: "replies will be injected into your session by Agent Relay Desktop",
  });
  assert.equal((await f.bindings()).length, 1);
  assert.equal(JSON.stringify(joined).includes(f.chat.token), false);

  const sent = structured(await f.client.callTool({ name: "send_relay_message", arguments: { to: "peer", text: "from the desk" } }));
  assert.equal(sent.from, "desk-chat");
  assert.equal(sent.reply_guidance, "replies will be injected into your session by Agent Relay Desktop");
  assert.equal(sent.desktop_relay_guidance, undefined);
  const delivered = f.env.world.deliveries.find(row => row.agent === "peer")!;
  assert.equal(delivered.message.agent_name, "desk-chat");
  assert.equal(delivered.message.text, "from the desk");
  // No hosted participant was created along the way.
  assert.equal((await f.env.database.query("SELECT 1 FROM hosted_relay_participants")).rows.length, 0);

  const status = structured(await f.client.callTool({ name: "relay_status", arguments: {} }));
  assert.deepEqual({ joined: status.joined, linked: status.linked, name: status.name, address: status.address, unread: status.unread_count },
    { joined: true, linked: "desktop", name: "desk-chat", address: f.address, unread: null });
  const inbox = structured(await f.client.callTool({ name: "check_relay_inbox", arguments: {} }));
  assert.equal(inbox.linked, "desktop");
  assert.equal(inbox.name, "desk-chat");
  assert.deepEqual(inbox.messages, []);
  assert.equal(inbox.polling_needed, false);

  // A repeat join is already_joined and keeps one binding.
  const again = structured(await f.client.callTool({ name: "join_relay", arguments: { desktop_address: f.address } }));
  assert.equal(again.already_joined, true);
  assert.equal((await f.bindings()).length, 1);

  // Another MCP session of the same owner is not linked by the first one's join.
  const second = await f.connect();
  assert.equal(structured(await second.callTool({ name: "relay_status", arguments: {} })).joined, false);
});

test("the sync responses report linked_mcp and an ISO linked_at once a session links", async (t) => {
  const f = await linkedDesktop(t);
  const before = await f.listed();
  assert.deepEqual(before.body.identities, [{ agent_id: f.chat.id, linked_mcp: null, linked_at: null }]);
  structured(await f.client.callTool({ name: "join_relay", arguments: { desktop_address: f.address } }));

  const listed = await f.listed();
  assert.equal(listed.status, 200);
  assert.equal(listed.body.identities.length, 1);
  const [entry] = listed.body.identities;
  assert.equal(entry.agent_id, f.chat.id);
  assert.equal(entry.linked_mcp, LINKED.linked_mcp);
  assert.match(entry.linked_at, ISO);
  assert.ok(listed.body.capabilities);

  // The full re-PUT keeps the identities array and the link.
  const resynced = await f.sync([f.identity(f.chat)]);
  assert.equal(resynced.status, 200, resynced.raw);
  assert.equal(resynced.body.synced, 1);
  assert.equal(resynced.body.identities[0].agent_id, f.chat.id);
  assert.equal(resynced.body.identities[0].linked_mcp, LINKED.linked_mcp);
  assert.match(resynced.body.identities[0].linked_at, ISO);
});

test("unknown, unsynced, other-workspace and another owner's addresses are refused", async (t) => {
  const f = await linkedDesktop(t);
  const refused = async (address: string) =>
    toolError(await f.client.callTool({ name: "join_relay", arguments: { desktop_address: address } }));
  assert.equal(await refused("nobody@nowhere"), NOT_SYNCED);
  // Address matching is exact: no case folding.
  assert.equal(await refused(f.address.toUpperCase()), NOT_SYNCED);
  // An alias address of a synced agent names the direct address Desktop synced.
  assert.equal(await refused("desk-chat@alias-host"),
    `That address is not the synced one. desktop_address is the direct name@machine address Agent Relay Desktop syncs, not an alias; use desktop_address "${f.address}".`);
  // An owned Desktop agent that was never synced.
  const unsynced = f.env.world.addAgent("never-synced", { source: "relay-desktop", owner_hash: ownerHash(f.env.ownerId) });
  assert.equal(await refused(`never-synced@cloud-${unsynced.id}`), NOT_SYNCED);
  // Synced to the owner's other workspace only.
  const elsewhere = f.env.world.addAgent("elsewhere-chat", { source: "relay-desktop", owner_hash: ownerHash(f.env.ownerId) });
  await f.env.database.query(
    `INSERT INTO desktop_relay_identities (id, workspace_id, organization_id, user_id, source_id, relaycast_workspace_id,
       agent_name, agent_remote_id, address, token_ciphertext)
     SELECT $1, $2, organization_id, user_id, source_id, relaycast_workspace_id, $3, $4, $5, token_ciphertext
       FROM desktop_relay_identities WHERE agent_remote_id = $6`,
    [randomUUID(), f.env.otherWorkspaceId, "elsewhere-chat", elsewhere.id, `elsewhere-chat@cloud-${elsewhere.id}`, f.chat.id]);
  assert.equal(await refused(`elsewhere-chat@cloud-${elsewhere.id}`), NOT_SYNCED);

  // Another member's synced identity in the same workspace.
  const memberId = await f.env.addMember("member@acme.test");
  const member = await f.env.desktopSignIn({ userId: memberId });
  const theirs = f.env.world.addAgent("their-chat", { source: "relay-desktop", owner_hash: ownerHash(memberId) });
  const theirAddress = `their-chat@cloud-${theirs.id}`;
  const synced = await request(f.env.origin, identitiesPath(f.env.workspaceId), {
    method: "PUT", token: member.accessToken,
    body: { source_id: randomUUID(), identities: [{ name: "their-chat", address: theirAddress, agent_id: theirs.id, token: theirs.token }] },
  });
  assert.equal(synced.status, 200, synced.raw);
  assert.equal(synced.body.synced, 1);
  assert.equal(await refused(theirAddress), NOT_SYNCED);

  assert.equal((await f.bindings()).length, 0);
  assert.equal((await f.env.database.query("SELECT 1 FROM hosted_relay_participants")).rows.length, 0);
});

test("desktop_address cannot be combined with name or description", async (t) => {
  const f = await linkedDesktop(t);
  for (const extra of [{ name: "owner-hosted" }, { description: "Reviews" }]) {
    assert.equal(toolError(await f.client.callTool({ name: "join_relay", arguments: { desktop_address: f.address, ...extra } })),
      "desktop_address cannot be combined with name or description.");
  }
  assert.equal((await f.bindings()).length, 0);
});

test("linking releases the session's hosted participant; a later hosted join unlinks", async (t) => {
  const f = await linkedDesktop(t);
  const hosted = structured(await f.client.callTool({ name: "join_relay", arguments: { name: "owner-hosted" } }));
  assert.equal(hosted.linked, "hosted");
  const hostedId = f.env.world.agents.get("owner-hosted")!.id;

  const linked = structured(await f.client.callTool({ name: "join_relay", arguments: { desktop_address: f.address } }));
  assert.equal(linked.linked, "desktop");
  assert.equal(linked.already_joined, false);
  assert.equal(f.env.world.agents.has("owner-hosted"), false);
  const release = f.env.world.bodies.find(call => call.path === "/v1/agents/release-exact")!;
  assert.equal(release.body!.name, "owner-hosted");
  assert.equal(release.body!.expected_agent_id, hostedId);
  assert.equal((await f.env.database.query("SELECT 1 FROM hosted_relay_participants")).rows.length, 0);
  assert.equal((await f.bindings()).length, 1);

  // Joining a hosted participant by name replaces the link.
  const back = structured(await f.client.callTool({ name: "join_relay", arguments: { name: "after-link" } }));
  assert.equal(back.linked, "hosted");
  assert.equal(back.name, "after-link");
  assert.equal((await f.bindings()).length, 0);
  const status = structured(await f.client.callTool({ name: "relay_status", arguments: {} }));
  assert.deepEqual({ linked: status.linked, name: status.name }, { linked: "hosted", name: "after-link" });
  const sent = structured(await f.client.callTool({ name: "send_relay_message", arguments: { to: "peer", text: "hosted again" } }));
  assert.equal(sent.from, "after-link");
  // The Desktop's agent was never touched.
  assert.equal(f.env.world.agents.has("desk-chat"), true);
});

test("leave_relay with no as removes the link and leaves the Desktop agent running", async (t) => {
  const f = await linkedDesktop(t);
  structured(await f.client.callTool({ name: "join_relay", arguments: { desktop_address: f.address } }));
  const left = structured(await f.client.callTool({ name: "leave_relay", arguments: {} }));
  assert.deepEqual(left, { joined: false, linked: null, already_left: false, desktop_agent_unchanged: true });
  assert.equal((await f.bindings()).length, 0);
  assert.equal(f.env.world.agents.has("desk-chat"), true);
  assert.equal(f.env.world.bodies.some(call => call.path === "/v1/agents/release-exact"), false);
  assert.equal(structured(await f.client.callTool({ name: "relay_status", arguments: {} })).joined, false);
  assert.deepEqual(structured(await f.client.callTool({ name: "leave_relay", arguments: {} })), { joined: false, already_left: true });
  const listed = await f.listed();
  assert.deepEqual(listed.body.identities, [{ agent_id: f.chat.id, linked_mcp: null, linked_at: null }]);
});

test("a re-sync that drops the linked identity cascades the binding away", async (t) => {
  const f = await linkedDesktop(t);
  structured(await f.client.callTool({ name: "join_relay", arguments: { desktop_address: f.address } }));
  assert.equal((await f.bindings()).length, 1);

  // Desktop re-PUTs its full set without the linked identity (replace-all).
  const other = f.env.world.addAgent("desk-other", { source: "relay-desktop", owner_hash: ownerHash(f.env.ownerId) });
  const resynced = await f.sync([f.identity(other)]);
  assert.equal(resynced.status, 200, resynced.raw);
  assert.deepEqual(resynced.body.identities, [{ agent_id: other.id, linked_mcp: null, linked_at: null }]);
  assert.equal((await f.bindings()).length, 0);

  // The session falls back: nothing joined, and a send auto-joins a hosted participant.
  assert.equal(structured(await f.client.callTool({ name: "relay_status", arguments: {} })).joined, false);
  const sent = structured(await f.client.callTool({ name: "send_relay_message", arguments: { to: "peer", text: "fallback" } }));
  assert.notEqual(sent.from, "desk-chat");
  assert.equal(sent.reply_guidance, "replies arrive in check_relay_inbox; poll it");
  assert.equal(toolError(await f.client.callTool({ name: "join_relay", arguments: { desktop_address: f.address } })), NOT_SYNCED);
});

test("an OAuth connection cannot link a desktop identity", async (t) => {
  const f = await linkedDesktop(t);
  const workspace = (await f.env.database.query<{ organization_id: string }>(
    "SELECT organization_id FROM workspaces WHERE id = $1", [f.env.workspaceId])).rows[0]!;
  const context = {
    principal: { userId: f.env.ownerId, email: "owner@acme.test", name: "Owner" },
    workspace: { id: f.env.workspaceId, organizationId: workspace.organization_id, name: "Primary",
      relaycastWorkspaceId: "rw_primary", relaycastApiKey: "rk_primary", role: "owner" },
    authMode: "oauth", role: "owner", origin: f.env.origin, endpointUrl: `${f.env.origin}${MCP_PATH}`,
    desktopCall: desktopCallContext({}, new Headers()),
    relay: {
      database: f.env.database, keyring: f.env.config.encryptionKeyring, sessionId: "an-oauth-session",
      client: createRelaycastClient({ internalOrigin: "http://relaycast.invalid", fetchImpl: (async () => {
        throw new Error("no Relaycast call is expected");
      }) as typeof fetch }),
    },
    // The live-bearer fence passes; the refusal comes before the connection is otherwise consulted.
    oauth: { lock: async () => undefined },
  } as unknown as McpContext;
  await assert.rejects(relayService(context).join({ desktop_address: f.address }),
    /cannot link a desktop identity/);
  assert.equal((await f.bindings()).length, 0);
});

test("set_relay_agent_card on a linked session writes the Desktop identity's card and keeps its metadata", async (t) => {
  const f = await linkedDesktop(t);
  const card = { description: "Desk chat that triages relay bugs.",
    skills: [{ id: "triage-bugs", name: "Triage bugs", description: "Reproduce and label a bug report.", examples: ["Triage issue 7"] }] };
  // A hosted participant of the same session is replaced by the link, so the card goes to the Desktop identity.
  structured(await f.client.callTool({ name: "join_relay", arguments: { desktop_address: f.address } }));
  f.chat.metadata.session_id = "codex-thread-1";
  f.chat.metadata.renamed_from = "older-name";
  const before = { ...f.chat.metadata };
  const set = structured(await f.client.callTool({ name: "set_relay_agent_card", arguments: card }));
  assert.equal(set.linked, "desktop");
  assert.equal(set.name, "desk-chat");
  assert.equal(JSON.stringify(set).includes(f.chat.token), false);
  const { card: stored, skills, ...rest } = f.chat.metadata as Record<string, any>;
  assert.deepEqual(rest, before);
  assert.deepEqual(skills, [{ ...card.skills[0], tags: [] }]);
  assert.equal(stored.description, card.description);
  // The peer is untouched, and the card reads back for any workspace member.
  assert.equal(f.peer.metadata.card, undefined);
  const read = structured(await f.client.callTool({ name: "get_relay_agent_card", arguments: { agent: f.address } }));
  assert.equal(read.description, card.description);
  assert.equal(read["x-agent-relay"].hasCard, true);
  assert.equal(read.url, "https://relaycast.selfhosted.test/a2a/rpc");

  // After leaving the link, the session has no identity to write.
  structured(await f.client.callTool({ name: "leave_relay", arguments: {} }));
  assert.match(toolError(await f.client.callTool({ name: "set_relay_agent_card", arguments: card })), /no relay identity/);
});
