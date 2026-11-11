import assert from "node:assert/strict";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { registerFactoryTools } from "../src/factory/mcp-tools.js";
import { planToolGroups } from "../src/mcp/catalog.js";
import type { McpContext } from "../src/mcp/context.js";
import { createRelaycastClient } from "../src/messaging/relaycast.js";
import { FACTORY_REPLY_GUIDANCE, relayService } from "../src/mcp/relay-participants.js";
import { buildMcpServer } from "../src/mcp/server.js";
import { assertNoSecrets, bindingRow, connectAndBind, removeMember, startFactoryEnv, type FactoryEnv } from "./factory-helpers.js";

const FACTORY_TOOL_NAMES = ["list_factory_sessions", "bind_factory_session", "unbind_factory_session"];
const NO_PARTICIPANT = "No hosted participant with that name is owned by you in this workspace.";
const NOT_MANAGER = "Only current owners and admins using a person connection can manage Factory.";

type Tool = { schema: { inputSchema: Record<string, unknown> }; handler: (args: any) => Promise<any> };

function mcpContext(env: FactoryEnv, userId: string, extra: Partial<McpContext> = {}): McpContext {
  return {
    principal: { userId, workspaceId: env.workspaceId, organizationId: env.organizationId, role: "owner", scopes: ["cli:auth"] },
    workspace: { id: env.workspaceId, organizationId: env.organizationId, name: "primary", relaycastWorkspaceId: "rc-primary",
      relaycastApiKey: "rk_live_primary", role: "owner" },
    desktopCall: {},
    members: async () => [],
    factory: env.module.mcp,
    ...extra,
  } as unknown as McpContext;
}

function toolsFor(env: FactoryEnv, userId: string) {
  const tools = new Map<string, Tool>();
  const server = { registerTool: (name: string, schema: Tool["schema"], handler: Tool["handler"]) => tools.set(name, { schema, handler }) };
  registerFactoryTools(server as never, mcpContext(env, userId), env.module.mcp);
  return tools;
}

const json = (result: any) => {
  assert.equal(result.isError, undefined, result.content?.[0]?.text);
  return JSON.parse(result.content[0].text);
};

async function listedToolNames(context: McpContext): Promise<string[]> {
  const server = buildMcpServer(context);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "factory-mcp-test", version: "1.0.0" });
  await client.connect(clientTransport);
  try {
    return (await client.listTools()).tools.map((tool) => tool.name);
  } finally {
    await client.close();
    await server.close();
  }
}

test("the factory group is planned only when enabled, right after amp", () => {
  assert.equal(planToolGroups().some((entry) => entry.group === "factory"), false);
  assert.equal(planToolGroups({ amp: true }).some((entry) => entry.group === "factory"), false);
  assert.deepEqual(planToolGroups({ factory: true }).find((entry) => entry.group === "factory")?.tools, FACTORY_TOOL_NAMES);
  const groups = planToolGroups({ amp: true, factory: true }).map((entry) => entry.group);
  assert.equal(groups.indexOf("factory"), groups.indexOf("amp") + 1);
  assert.ok(groups.indexOf("factory") < groups.indexOf("capability_discovery"));
  const alone = planToolGroups({ factory: true }).map((entry) => entry.group);
  assert.ok(alone.indexOf("factory") < alone.indexOf("capability_discovery"));
});

test("tools/list carries the factory tools only when the module is present", async (t) => {
  const env = await startFactoryEnv(t);
  const base = { ...mcpContext(env, env.ownerId), relay: { database: env.database, keyring: env.config.encryptionKeyring, client: {}, sessionId: undefined } } as unknown as McpContext;
  const off = await listedToolNames({ ...base, factory: undefined });
  for (const name of FACTORY_TOOL_NAMES) assert.equal(off.includes(name), false, `${name} listed while disabled`);
  assert.ok(off.includes("send_relay_message"));
  const on = await listedToolNames(base);
  for (const name of FACTORY_TOOL_NAMES) assert.ok(on.includes(name), `${name} missing while enabled`);
});

test("factory MCP tools refuse members and let the connecting owner list, bind and unbind", async (t) => {
  const env = await startFactoryEnv(t);
  const connected = await env.api(`/api/v1/workspaces/${env.workspaceId}/factory/connection`,
    { method: "PUT", token: env.ownerToken, body: { key: "fk_live_primary_key_0001" } });
  assert.equal(connected.status, 200, JSON.stringify(connected.body));

  const memberTools = toolsFor(env, env.memberId);
  for (const tool of memberTools.values()) {
    assert.equal(Object.keys(tool.schema.inputSchema).some((key) => /user|role|workspace|org/i.test(key)), false,
      "no tool accepts an identity argument");
  }
  // The member's MCP context claims role "owner"; the database role decides.
  for (const [name, args] of [["list_factory_sessions", {}], ["bind_factory_session", { session_id: "sess-a", computer_id: "cmp-1" }],
    ["unbind_factory_session", { binding_id: "00000000-0000-4000-8000-000000000000" }]] as const) {
    const refused = await memberTools.get(name)!.handler(args);
    assert.equal(refused.isError, true, name);
    assert.equal(refused.content[0].text, NOT_MANAGER, name);
  }

  const owner = toolsFor(env, env.ownerId);
  // Two active computers: no automatic selection.
  const ambiguous = json(await owner.get("list_factory_sessions")!.handler({}));
  assert.deepEqual(ambiguous.computers.map((computer: { id: string }) => computer.id).sort(), ["cmp-1", "cmp-2"]);
  assert.equal(ambiguous.selected_computer, null);
  assert.deepEqual(ambiguous.sessions, []);
  assert.equal(typeof ambiguous.note, "string");
  const listed = json(await owner.get("list_factory_sessions")!.handler({ computer_id: "cmp-1" }));
  assert.deepEqual(listed.sessions.map((session: { id: string }) => session.id).sort(), ["sess-a", "sess-b"]);
  assert.deepEqual(listed.bindings, []);

  const unresolved = await owner.get("bind_factory_session")!.handler({ session_id: "sess-a" });
  assert.equal(unresolved.isError, true);
  assert.equal(unresolved.content[0].text, "Several Factory computers are available. Provide computer_id.");

  const bound = json(await owner.get("bind_factory_session")!.handler({ session_id: "sess-a", computer_id: "cmp-1" }));
  assert.equal((await bindingRow(env, bound.binding_id)).state, "bound");
  const afterBind = json(await owner.get("list_factory_sessions")!.handler({ computer_id: "cmp-1" }));
  assert.deepEqual(afterBind.bindings.map((binding: { id: string }) => binding.id), [bound.binding_id]);

  const unbound = json(await owner.get("unbind_factory_session")!.handler({ binding_id: bound.binding_id }));
  assert.deepEqual(unbound, { binding_id: bound.binding_id, unbound: true });
  assert.notEqual((await bindingRow(env, bound.binding_id)).state, "bound");
  const afterUnbind = json(await owner.get("list_factory_sessions")!.handler({ computer_id: "cmp-1" }));
  assert.deepEqual(afterUnbind.bindings, []);

  // An admin who did not connect the key cannot use it.
  const adminList = await toolsFor(env, env.adminId).get("list_factory_sessions")!.handler({});
  assert.equal(adminList.isError, true);
  assertNoSecrets(env, [ambiguous, listed, afterBind, unbound, adminList]);
});

test("agentFor resolves only the caller's own bound agent of a current member", async (t) => {
  const env = await startFactoryEnv(t);
  const binding = await connectAndBind(env);
  const name = binding.agent.name;
  const hosted = env.relay.agents.get(name);
  assert.ok(hosted, "the binding registered its hosted agent");
  assert.deepEqual(await env.module.mcp.agentFor(env.workspaceId, env.ownerId, name), { name, token: hosted.token });
  assert.equal(await env.module.mcp.agentFor(env.workspaceId, env.memberId, name), null, "another user");
  assert.equal(await env.module.mcp.agentFor(env.workspaceId, env.ownerId, "factory-0000000000000000"), null, "unknown name");
  assert.equal(await env.module.mcp.agentFor(env.workspaceId, env.ownerId, "not-a-factory-agent"), null, "non-factory name");

  const unbound = await env.api(`/api/v1/workspaces/${env.workspaceId}/factory/bindings/${binding.binding_id}`,
    { method: "DELETE", token: env.ownerToken });
  assert.equal(unbound.status, 204, JSON.stringify(unbound.body));
  assert.equal(await env.module.mcp.agentFor(env.workspaceId, env.ownerId, name), null, "retired binding");

  // A removed membership resolves to nothing even while the row still reads bound
  // (the membership row is deleted directly, so no retirement sweep runs).
  const second = await connectAndBind(env, { sessionId: "sess-b" });
  assert.ok(await env.module.mcp.agentFor(env.workspaceId, env.ownerId, second.agent.name));
  await env.database.query("DELETE FROM organization_memberships WHERE organization_id = $1 AND user_id = $2",
    [env.organizationId, env.ownerId]);
  assert.equal((await bindingRow(env, second.binding_id)).state, "bound");
  assert.equal(await env.module.mcp.agentFor(env.workspaceId, env.ownerId, second.agent.name), null, "removed member");
});

test("agentFor returns null after the binding owner is removed through the API", async (t) => {
  const env = await startFactoryEnv(t);
  const binding = await connectAndBind(env, { token: env.adminToken });
  assert.ok(await env.module.mcp.agentFor(env.workspaceId, env.adminId, binding.agent.name));
  const removed = await removeMember(env, env.adminId);
  assert.ok(removed.status < 300, JSON.stringify(removed.body));
  assert.equal(await env.module.mcp.agentFor(env.workspaceId, env.adminId, binding.agent.name), null);
});

test("send and read accept as=<own bound factory agent>; inbox, leave and channel subscribe do not", async (t) => {
  const env = await startFactoryEnv(t);
  const binding = await connectAndBind(env);
  const name = binding.agent.name;
  const token = env.relay.agents.get(name)!.token;
  const peer = { id: "ag-peer", name: "peer-agent", address: null, kind: "agent", persona: null, status: "online", lastSeen: null, metadata: {} };
  const sent: Array<{ token: string; to: string; text: string }> = [];
  const read: string[] = [];
  const client = {
    listAgents: async () => [peer],
    getRosterAgent: async () => peer,
    heartbeat: async () => undefined,
    sendDirectMessage: async (input: { token: string; to: string; text: string }) => {
      sent.push({ token: input.token, to: input.to, text: input.text });
      return { message: { id: "1" }, conversationId: "conv-1" };
    },
    listConversations: async (used: string) => { read.push(used); return []; },
  };
  const context = (factory = true) => mcpContext(env, env.ownerId, {
    relay: { database: env.database, keyring: env.config.encryptionKeyring, client, sessionId: undefined },
    ...(factory ? {} : { factory: undefined }),
  } as unknown as Partial<McpContext>);

  const result = await relayService(context()).send({ to: "peer-agent", text: "hello", as: name });
  assert.equal(result.from, name);
  assert.equal(result.reply_guidance, FACTORY_REPLY_GUIDANCE);
  assert.ok(!("desktop_relay_guidance" in result));
  assert.deepEqual(sent, [{ token, to: "peer-agent", text: "hello" }]);
  const conversation = await relayService(context()).read({ agent: "peer-agent", as: name, limit: 10 });
  assert.equal(conversation.you, name);
  assert.deepEqual(read, [token]);

  await assert.rejects(relayService(context()).inbox(name, []), { message: NO_PARTICIPANT });
  await assert.rejects(relayService(context()).leave(name), { message: NO_PARTICIPANT });
  await assert.rejects(relayService(context()).subscribeChannel({ channel: "ops", as: name }), { message: NO_PARTICIPANT });
  // Another user and a disabled module get the original error.
  await assert.rejects(relayService(mcpContext(env, env.memberId, { relay: context().relay } as Partial<McpContext>))
    .send({ to: "peer-agent", text: "x", as: name }), { message: NO_PARTICIPANT });
  await assert.rejects(relayService(context(false)).send({ to: "peer-agent", text: "x", as: name }), { message: NO_PARTICIPANT });
  assert.equal(sent.length, 1);
});


for (const retired of [false,true]) test(`generic join refuses ${retired?"retired cleanup-pending":"live"} Factory binding custody`,async t=>{
  const env=await startFactoryEnv(t),bound=await connectAndBind(env),name=bound.agent.name;
  const originalToken=env.relay.agents.get(name)!.token;
  if(retired) {
    env.relay.failRelease=true;
    const disconnected=await env.api(`/api/v1/workspaces/${env.workspaceId}/factory/connection`,{method:"DELETE",token:env.ownerToken});
    assert.equal(disconnected.status,204);
    assert.equal((await bindingRow(env,bound.binding_id)).state,"retired");
    assert.equal(await env.module.mcp.agentFor(env.workspaceId,env.ownerId,name),null);
    assert.ok(env.relay.agents.has(name),"failed cleanup preserves the original remote obligation");
  }
  const before={registered:env.relay.registered,recovered:env.relay.recovered};
  const base=mcpContext(env,env.ownerId);
  const context=mcpContext(env,env.ownerId,{principal:{...base.principal,name:"Owner",email:"owner@acme.test"},
    relay:{database:env.database,keyring:env.config.encryptionKeyring,
      client:createRelaycastClient({internalOrigin:env.config.relaycastUrl}),sessionId:undefined}});
  await assert.rejects(relayService(context).join({name}),/name is already taken/);
  assert.deepEqual({registered:env.relay.registered,recovered:env.relay.recovered},before);
  assert.equal(env.relay.agents.get(name)!.token,originalToken,"generic recovery cannot rotate the provider token");
  assert.equal((await env.database.query("SELECT id FROM hosted_relay_participants")).rows.length,0);
  if(!retired) {
    assert.deepEqual(await env.module.mcp.agentFor(env.workspaceId,env.ownerId,name),{name,token:originalToken});
    const ordinary=await relayService(context).join({name:"factory-support"});
    assert.equal(ordinary.name,"factory-support","provider prefixes alone are not reserved");
  }
});
