import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { randomUUID } from "node:crypto";
import { CapyBindings, CapyBindingError } from "../src/capy/bindings.js";
import { RemoteAgentConnections } from "../src/remote-agents/connections.js";
import type { McpContext } from "../src/mcp/context.js";
import { McpOAuthActorRefused } from "../src/mcp/oauth/admission.js";
import { HOSTED_SOURCE, ownerHash, relayService } from "../src/mcp/relay-participants.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { copilotDesktopSetup, MCP_PATH } from "./support/copilot-desktop.js";
import { seedTenant, startControlPlane } from "./flows-helpers.js";

const MISSING = "No hosted participant with that name is owned by you in this workspace.";
async function setup(t: TestContext) {
  const c = await startControlPlane(); t.after(() => c.stop());
  const tenant = await seedTenant(c.api);
  const rows = (await c.database.query<{ user_id: string; role: string }>(
    "SELECT user_id,role FROM organization_memberships WHERE organization_id=$1", [tenant.organizationId])).rows;
  const owner = rows.find(r => r.role === "owner")!.user_id;
  const member = rows.find(r => r.role === "member")!.user_id;
  const actor = { userId: owner, organizationId: tenant.organizationId, workspaceId: tenant.workspaceId };
  await new RemoteAgentConnections(c.database,c.config.encryptionKeyring,async () => Response.json({ items: [] }))
    .connect(actor,"capy",{ key: "capy_"+"s".repeat(32) });
  const agents = new Map<string,{ id: string; name: string; token: string; metadata: Record<string,unknown> }>();
  const roster = (a: { id: string; name: string; metadata: Record<string,unknown> }) =>
    ({ ...a,address:null,kind:"agent",persona:null,status:"active",lastSeen:null });
  const peer = roster({ id:"ag_peer",name:"peer",metadata:{} });
  const writes: any[] = [];
  let recoveries = 0, registrations = 0, lookups = 0;
  let onAddress: (() => Promise<void>) | undefined;
  const client = {
    getRosterAgent: async (_key:string,name:string) => { const a=agents.get(name);return a?roster(a):null; },
    getAgent: async (_key:string,name:string) => { const a=agents.get(name);return a?roster(a):null; },
    registerHosted: async (_key:string,name:string,metadata:Record<string,unknown>) => {
      registrations++;const a={id:`ag_${randomUUID()}`,name,token:`native-${randomUUID()}`,metadata};agents.set(name,a);return a;
    },
    recoverHosted: async (_key:string,name:string,id:string) => {
      recoveries++;const a=agents.get(name)!;assert.equal(a.id,id);return a;
    },
    authenticatedAgent: async (token:string) => {
      const a=[...agents.values()].find(a=>a.token===token);assert.ok(a);
      return { ...roster(a),workspaceId:"rc-primary",channels:[] };
    },
    releaseHosted: async () => undefined,
    listAgents: async () => { await onAddress?.();return [peer,...[...agents.values()].map(roster)]; },
    heartbeat: async () => undefined,
    sendDirectMessage: async (input:any) => { writes.push(input);return { message:{id:"12"},conversationId:"dm" }; },
    replyToMessage: async (input:any) => { writes.push(input);return { message:{id:"13"},conversationId:"dm" }; },
    listConversations: async () => [{ id:"dm",participants:[binding.agent,"peer"] }],
    listMessages: async () => ({ messages:[{id:"10"}] }),
  };
  const bindings = new CapyBindings({ database:c.database,keyring:c.config.encryptionKeyring,relaycast:client,
    runtime:{getThread:async (_key,id)=>({id,title:null,status:"active"})} });
  const binding = await bindings.bind(actor,"jam_owned000");
  const counts = () => ({ registrations,recoveries,lookups });
  const context = (extra: Partial<McpContext> = {}): McpContext => ({
    principal:{ ...actor,role:"owner",name:"Owner",email:"owner@acme.test",scopes:["cli:auth"] },
    workspace:{id:actor.workspaceId,organizationId:actor.organizationId,name:"Primary",role:"owner",
      relaycastWorkspaceId:"rc-primary",relaycastApiKey:"rk_live_primary"},
    desktopCall:{},members:async()=>[],
    relay:{database:c.database,keyring:c.config.encryptionKeyring,client,sessionId:undefined},
    capy:{agentFor:async (ws:string,user:string,name:string)=>{lookups++;return bindings.agentFor(ws,user,name);}},
    ...extra,
  } as unknown as McpContext);
  const participantCount = async () => (await c.database.query("SELECT id FROM hosted_relay_participants")).rows.length;
  return { c,tenant,actor,owner,member,agents,client,bindings,binding,context,writes,counts,participantCount,
    setOnAddress:(fn:typeof onAddress)=>{onAddress=fn;} };
}

test("native Capy sends/replies use only the owned binding and preserve idempotency without participant aliases",async t=>{
  const e=await setup(t), name=e.binding.agent;
  const before=e.counts();
  const sent=await relayService(e.context({factory:{agentFor:async()=>{assert.fail("Factory cannot resolve a selected Capy identity");}}} as any)).send({to:"peer",text:"hello",as:name,idempotency_key:"stable"});
  assert.equal(sent.from,name);assert.equal(sent.idempotency_key,"stable");
  assert.equal(sent.reply_guidance,"Replies are addressed to the bound Capy thread. This receipt does not confirm delivery or reading.");
  assert.equal("desktop_relay_guidance" in sent,false);
  assert.equal(e.writes[0].token,e.agents.get(name)!.token);
  assert.match(e.writes[0].idempotencyKey,/:stable$/);
  await relayService(e.context()).send({to:"peer",text:"reply",as:name,reply_to:"10",idempotency_key:"reply"});
  assert.equal(e.writes[1].parentId,"10");
  await assert.rejects(relayService(e.context()).send({to:"peer",text:"bad parent",as:name,reply_to:"9"}),/reply_to must belong/);
  assert.equal(e.writes.length,2);assert.equal(await e.participantCount(),0);
  assert.equal(e.counts().registrations,before.registrations);
  assert.equal(e.counts().recoveries,before.recoveries);
  assert.equal(e.counts().lookups,5,"one resolution and a fresh pre-write fence; invalid parent never sends");
});

test("native Capy lookup refuses other owners/workspaces, disabled hook and retired or demoted bindings",async t=>{
  const e=await setup(t), name=e.binding.agent, base=e.context();
  for(const ctx of [e.context({capy:undefined} as any),e.context({principal:{...base.principal,userId:e.member}}),
    e.context({workspace:{...base.workspace,id:e.tenant.otherWorkspaceId}}),
    e.context({workspace:{...base.workspace,relaycastWorkspaceId:"old-route"}}),
    e.context({workspace:{...base.workspace,relaycastApiKey:"old-key"}})]) {
    await assert.rejects(relayService(ctx).send({to:"peer",text:"no",as:name}),{message:MISSING});
  }
  await e.c.database.query("UPDATE organization_memberships SET role='member' WHERE user_id=$1 AND organization_id=$2",[e.owner,e.actor.organizationId]);
  await assert.rejects(relayService(e.context()).send({to:"peer",text:"no",as:name}),{message:MISSING});
  await e.c.database.query("UPDATE organization_memberships SET role='owner' WHERE user_id=$1 AND organization_id=$2",[e.owner,e.actor.organizationId]);
  await e.bindings.retire(e.actor,e.binding.id);
  await assert.rejects(relayService(e.context()).send({to:"peer",text:"no",as:name}),{message:MISSING});
  assert.equal(e.writes.length,0);assert.equal(await e.participantCount(),0);
});

test("Capy authority is rechecked after pre-send reads and resolver outages are preserved",async t=>{
  const e=await setup(t),name=e.binding.agent;
  // Recipient lookup is first; only mutate during the later sender-address read.
  let reads=0;e.setOnAddress(async()=>{if(++reads===2) await e.bindings.retire(e.actor,e.binding.id);});
  await assert.rejects(relayService(e.context()).send({to:"peer",text:"revoked",as:name}),{message:MISSING});
  assert.equal(e.writes.length,0);
  const unavailable=new CapyBindingError(503,"capy_relay_unavailable");
  await assert.rejects(relayService(e.context({capy:{agentFor:async()=>{throw unavailable;}}} as any))
    .send({to:"peer",text:"no",as:name}),error=>error===unavailable);
  let calls=0;
  await assert.rejects(relayService(e.context({capy:{agentFor:async()=>({name,token:++calls===1?"old":"new"})}} as any))
    .send({to:"peer",text:"changed",as:name}),{message:MISSING});
  for(const result of [{name:"different",token:"secret"},{name,token:""}]) {
    await assert.rejects(relayService(e.context({capy:{agentFor:async()=>result}} as any))
      .send({to:"peer",text:"bad",as:name}),{message:MISSING});
  }
  assert.equal(e.writes.length,0);
});

test("managed and OAuth calls cannot use an injected Capy resolver; Capy hook grants no read or channel rights",async t=>{
  const e=await setup(t),name=e.binding.agent;
  const trap={agentFor:async()=>{assert.fail("Capy resolver must not run");}};
  await assert.rejects(relayService(e.context({desktopCall:{required:true},capy:trap} as any))
    .send({to:"peer",text:"no",as:name}),/managed chat|verify this chat/);
  for(const approved of ["approved-agent",name]) {
    const oauth={access:{agentName:approved,agentRemoteId:null},lock:async()=>{},
      assertActor:(requested:string)=>{if(requested && requested!==approved) throw new McpOAuthActorRefused();}};
    await assert.rejects(relayService(e.context({oauth,capy:trap} as any)).send({to:"peer",text:"no",as:name}),
      approved===name?/name is already taken/:/approved when/);
  }
  const service=relayService(e.context({capy:trap} as any));
  await assert.rejects(service.read({agent:"peer",as:name,limit:10}),{message:MISSING});
  await assert.rejects(service.inbox(name,[]),{message:MISSING});
  await assert.rejects(service.leave(name),{message:MISSING});
  await assert.rejects(service.subscribeChannel({channel:"ops",as:name}),{message:MISSING});
  await assert.rejects(service.send({to:"peer",text:"no",as:"ordinary-agent"}),{message:MISSING});
  assert.equal(e.writes.length,0);
});

test("generic join cannot recover Capy metadata into a participant, including OAuth and malformed markers",async t=>{
  const e=await setup(t),name=e.binding.agent,before=e.counts();
  const oauth={access:{agentName:name,agentRemoteId:null},lock:async()=>{},assertActor:()=>{},pin:async()=>{}};
  for(const ctx of [e.context(),e.context({oauth} as any)]) {
    await assert.rejects(relayService(ctx).join({name}),/name is already taken/);
  }
  const agent=e.agents.get(name)!;
  for(const metadata of [
    {source:HOSTED_SOURCE,cloud_workspace_id:e.actor.workspaceId,owner_hash:ownerHash(e.owner),capy_binding_id:null},
    {source:HOSTED_SOURCE,cloud_workspace_id:e.actor.workspaceId,owner_hash:ownerHash(e.owner),created_by:"capy-binding"},
  ]) {
    agent.metadata=metadata;
    await assert.rejects(relayService(e.context()).join({name}),/name is already taken/);
  }
  assert.equal(e.counts().recoveries,before.recoveries);assert.equal(await e.participantCount(),0);
  // The provider domain is metadata-based, not a blanket name-prefix ban.
  const joined=await relayService(e.context()).join({name:"capy-support"});
  assert.equal(joined.name,"capy-support");assert.equal(await e.participantCount(),1);
  await relayService(e.context()).send({to:"peer",text:"ordinary participant",as:"capy-support"});
  assert.equal(e.writes.length,1);
  e.agents.get("capy-support")!.metadata.capy_binding_id=e.binding.id;
  await assert.rejects(relayService(e.context()).send({to:"peer",text:"cannot adopt",as:"capy-support"}),/identity changed/);
  assert.equal(e.writes.length,1,"even an existing generic row cannot act as a Capy identity");
});


test("normal HTTP MCP admission passes its authenticated scope to the dormant native Capy hook",async t=>{
  let expectedWorkspace="",expectedOwner="",actor:{name:string;token:string}|undefined;
  const lookups:unknown[][]=[];
  const e=await copilotDesktopSetup(t,{capy:{agentFor:async (workspace,user,name)=>{
    lookups.push([workspace,user,name]);
    return workspace===expectedWorkspace && user===expectedOwner && name===actor?.name?actor:null;
  }}});
  expectedWorkspace=e.workspaceId;expectedOwner=e.ownerId;
  const bound=e.world.addAgent("capy-bound",{source:HOSTED_SOURCE,cloud_workspace_id:e.workspaceId,
    owner_hash:ownerHash(e.ownerId),capy_binding_id:randomUUID(),created_by:"capy-binding"});
  actor={name:bound.name,token:bound.token};
  e.world.addAgent("peer");
  const token=await e.deviceLogin();
  const connect=async(headers:Record<string,string>={})=>{
    const client=new Client({name:"capy-native-test",version:"1"});
    await client.connect(new StreamableHTTPClientTransport(new URL(e.origin+MCP_PATH),{
      requestInit:{headers:{authorization:`Bearer ${token}`,...headers}}}));
    t.after(()=>client.close());return client;
  };
  const client=await connect();
  const result=await client.callTool({name:"send_relay_message",arguments:{to:"peer",text:"native",as:bound.name,idempotency_key:"http-native"}});
  assert.notEqual(result.isError,true,JSON.stringify(result.content));
  assert.equal((result.structuredContent as any).from,bound.name);
  assert.deepEqual(lookups,[[e.workspaceId,e.ownerId,bound.name],[e.workspaceId,e.ownerId,bound.name]]);
  assert.equal(JSON.stringify(result).includes(bound.token),false,"tool output never exposes the agent token");
  assert.equal(e.world.deliveries.find(row=>row.agent==="peer")!.message.agent_name,bound.name);
  const refused=await client.callTool({name:"join_relay",arguments:{name:bound.name}});
  assert.equal(refused.isError,true);
  assert.equal((await e.database.query("SELECT id FROM hosted_relay_participants")).rows.length,0);
  const managed=await connect({"x-agent-relay-desktop":"1"});
  const rejected=await managed.callTool({name:"send_relay_message",arguments:{to:"peer",text:"must refuse",as:bound.name}});
  assert.equal(rejected.isError,true);
  assert.equal(lookups.length,2,"managed calls never receive Capy authority");
});
