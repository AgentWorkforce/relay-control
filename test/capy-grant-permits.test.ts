import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { randomUUID } from "node:crypto";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CapyBindings, CapyBindingError } from "../src/capy/bindings.js";
import { removeCompletedWorkspaceCapyInTx } from "../src/capy/lifecycle.js";
import { RemoteAgentConnections } from "../src/remote-agents/connections.js";
import { encryptSecret } from "../src/crypto.js";
import { migrate } from "../src/migrations.js";
import { McpOAuthSessions } from "../src/mcp/oauth/sessions.js";
import { McpOAuthConnection, McpOAuthAccessRefused } from "../src/mcp/oauth/admission.js";
import { createMcpOAuthProtocol } from "../src/mcp/oauth/protocol.js";
import { revokeMcpOAuthGrantRows } from "../src/mcp/oauth/revocations.js";
import { relayService } from "../src/mcp/relay-participants.js";
import { buildMcpServer } from "../src/mcp/server.js";
import type { McpContext } from "../src/mcp/context.js";
import { PGliteDatabase } from "./support/harness.js";

const ORIGIN="https://relay.example.test", SHARED="/api/v1/mcp/shared-sessions", RESOURCE=ORIGIN+"/cloud"+SHARED;
const MISSING="No hosted participant with that name is owned by you in this workspace.";
async function fixture(t:TestContext) {
  const database=new PGliteDatabase();t.after(()=>database.close());await migrate(database);
  const keyring={active:{id:"fake",key:Buffer.alloc(32,7)}};
  const actor={userId:randomUUID(),organizationId:randomUUID(),workspaceId:randomUUID()};
  const member=randomUUID(),otherWorkspace=randomUUID();
  await database.query("INSERT INTO organizations(id,name) VALUES ($1,'Org')",[actor.organizationId]);
  for(const [id,role] of [[actor.userId,"owner"],[member,"member"]]) {
    await database.query("INSERT INTO users(id,email,name) VALUES ($1,$2,'Fake User')",[id,`${id}@example.test`]);
    await database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,$3)",[actor.organizationId,id,role]);
  }
  for(const id of [actor.workspaceId,otherWorkspace]) await database.query(`INSERT INTO workspaces
    (id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext) VALUES($1,$2,'Workspace',$3,$4)`,
  [id,actor.organizationId,id===actor.workspaceId?"rc-primary":"rc-other",encryptSecret("rk-primary",keyring.active)]);
  await new RemoteAgentConnections(database,keyring,async()=>Response.json({items:[]})).connect(actor,"capy",{key:"capy_"+"s".repeat(32)});
  const agents=new Map<string,any>(),writes:any[]=[];let registrations=0,reads=0,remoteChecks=0;
  let onAddress:(()=>Promise<void>)|undefined,onAuthenticated:(()=>Promise<void>)|undefined;
  let unavailable=false;
  const roster=(a:any)=>({...a,address:null,kind:"agent",persona:null,status:"active",lastSeen:null});
  const client={
    getRosterAgent:async(_key:string,name:string)=>agents.has(name)?roster(agents.get(name)):null,
    getAgent:async(_key:string,name:string)=>agents.has(name)?roster(agents.get(name)):null,
    registerHosted:async(_key:string,name:string,metadata:Record<string,unknown>)=>{
      registrations++;const a={id:`ag_${randomUUID()}`,name,metadata,token:`native-${randomUUID()}`};agents.set(name,a);return a;
    },
    recoverHosted:async()=>{assert.fail("permit must never recover a remote");},
    authenticatedAgent:async(token:string)=>{remoteChecks++;if(unavailable)throw new Error("private provider secret");
      const a=[...agents.values()].find(a=>a.token===token);assert.ok(a);await onAuthenticated?.();return {...roster(a),workspaceId:"rc-primary",channels:[]};},
    releaseHosted:async()=>undefined,
    listAgents:async()=>{await onAddress?.();return [roster({id:"ag_peer",name:"peer",metadata:{}}),...[...agents.values()].map(roster)];},
    heartbeat:async()=>undefined,
    sendDirectMessage:async(input:any)=>{writes.push(input);return {message:{id:"12"},conversationId:"dm"};},
    replyToMessage:async(input:any)=>{writes.push(input);return {message:{id:"13"},conversationId:"dm"};},
    listConversations:async()=>[{id:"dm",participants:[binding.agent,"peer"]}],
    listMessages:async()=>({messages:[{id:"10"}]}),
  };
  const bindings=new CapyBindings({database,keyring,relaycast:client,runtime:{getThread:async(_key,id)=>{reads++;return {id,title:null,status:"active"};}}});
  const binding=await bindings.bind(actor,"jam_owned000");
  const protocol=createMcpOAuthProtocol({publicOrigin:ORIGIN,enabledResources:[SHARED]});
  const sessions=new McpOAuthSessions(database,{protocol,tenancyMode:"multi"});
  const clientId=`mcpc_${randomUUID()}`;
  await database.query("INSERT INTO mcp_oauth_clients(client_id,redirect_uris) VALUES ($1,$2)",[clientId,[ORIGIN+"/cb"]]);
  const grant=async(owner=actor)=>{
    const grantId=randomUUID(),tokenFamilyId=randomUUID();
    await database.query(`INSERT INTO mcp_oauth_grants
      (id,client_id,user_id,organization_id,workspace_id,agent_name,agent_remote_id,scopes,resource,token_family_id)
      VALUES($1,$2,$3,$4,$5,'approved-persona','ag_persona',$6,$7,$8)`,
    [grantId,clientId,owner.userId,owner.organizationId,owner.workspaceId,["relay:mcp"],RESOURCE,tokenFamilyId]);
    const pair=await database.transaction(tx=>sessions.issue(tx,{...owner,grantId,tokenFamilyId,scopes:["relay:mcp"]}));
    const access=await sessions.resolveAccessToken(pair.accessToken,RESOURCE);assert.ok(access);
    const connection=new McpOAuthConnection(access,pair.accessToken,{tenancyMode:"multi",requiredScope:"relay:mcp"});
    return {connection,pair,grantId,owner,tokenFamilyId};
  };
  const context=(connection:McpOAuthConnection,extra:Partial<McpContext>={}):McpContext=>({
    principal:connection.access.principal,oauth:connection,authMode:"oauth",role:"owner",origin:ORIGIN,endpointUrl:RESOURCE,
    workspace:{id:actor.workspaceId,organizationId:actor.organizationId,name:"Workspace",role:"owner",relaycastWorkspaceId:"rc-primary",relaycastApiKey:"rk-primary"},
    desktopCall:{},members:async()=>[],providers:async()=>[],readHistory:async()=>{assert.fail("no history");},
    relaycast:{listAgents:async()=>[],listPresence:async()=>[]},
    relay:{database,keyring,client,sessionId:undefined},capyPermits:bindings,...extra,
  } as McpContext);
  const permits=()=>database.query<any>("SELECT * FROM capy_grant_permits ORDER BY created_at,id");
  const revoke=(id:string)=>database.transaction(tx=>revokeMcpOAuthGrantRows(tx,id,"user_revoked",new Date()));
  const mcp=async(ctx:McpContext)=>{
    const server=buildMcpServer(ctx),[a,b]=InMemoryTransport.createLinkedPair();await server.connect(b);
    const sdk=new Client({name:"capy-permit-test",version:"1"});await sdk.connect(a);
    t.after(async()=>{await sdk.close();await server.close();});return sdk;
  };
  return {database,keyring,actor,member,otherWorkspace,bindings,binding,agents,writes,grant,context,permits,revoke,sessions,mcp,
    counts:()=>({registrations,reads,remoteChecks}),onAddress:(fn:typeof onAddress)=>{onAddress=fn;},
    onAuthenticated:(fn:typeof onAuthenticated)=>{onAuthenticated=fn;},unavailable:(value:boolean)=>{unavailable=value;}};
}

test("Capy explicit grant permits preserve binding custody and the OAuth persona",async t=>{
  const e=await fixture(t),g=await e.grant(),second=await e.grant(),name=e.binding.agent;
  await t.test("same person alone grants no send authority; self-bind is explicit, existing-only and idempotent",async()=>{
    await assert.rejects(relayService(e.context(g.connection)).send({to:"peer",text:"no",as:name}),/approved/);
    const before=e.counts();
    await assert.rejects(e.bindings.bindGrant(g.connection,"jam_absent00"),{code:"capy_binding_not_found"});
    assert.equal((await e.permits()).rows.length,0);
    const first=await e.bindings.bindGrant(g.connection,"jam_owned000");
    assert.deepEqual(first,{...e.binding,already_bound:true});
    assert.deepEqual(await e.bindings.bindGrant(g.connection,"jam_owned000"),first);
    assert.equal((await e.permits()).rows.length,1);
    assert.deepEqual(e.counts(),before,"bind permit performs no provider/Relay reads or writes");
    assert.equal(JSON.stringify(first).includes(e.agents.get(name).token),false);
  });
  await t.test("only the exact grant sends and replies; no pin, participant or other identity rights",async()=>{
    await assert.rejects(relayService(e.context(second.connection)).send({to:"peer",text:"no",as:name}),/approved/);
    const result=await relayService(e.context(g.connection)).send({to:"peer",text:"yes",as:name,idempotency_key:"same-key"});
    assert.equal(result.from,name);assert.equal(e.writes[0].token,e.agents.get(name).token);
    assert.equal(JSON.stringify(result).includes(e.agents.get(name).token),false);
    await relayService(e.context(g.connection)).send({to:"peer",text:"reply",as:name,reply_to:"10"});
    const service=relayService(e.context(g.connection));
    await assert.rejects(service.read({agent:"peer",as:name,limit:10}),/approved/);
    await assert.rejects(service.inbox(name,[]),/approved/);
    await assert.rejects(service.subscribeChannel({channel:"ops",as:name}),/approved/);
    await assert.rejects(service.join({name}),/approved/);
    assert.equal((await e.database.query("SELECT * FROM hosted_relay_participants")).rows.length,0);
    const grant=(await e.database.query<any>("SELECT agent_name,agent_remote_id FROM mcp_oauth_grants WHERE id=$1",[g.grantId])).rows[0];
    assert.deepEqual(grant,{agent_name:"approved-persona",agent_remote_id:"ag_persona"});
    assert.equal(g.connection.access.agentName,"approved-persona");assert.equal(e.writes.length,2);
  });
  await t.test("explicit unbind only revokes its own permit, never native injection or another grant",async()=>{
    await e.bindings.bindGrant(second.connection,"jam_owned000");
    assert.deepEqual(await e.bindings.unbindGrant(g.connection,"jam_owned000"),{revoked:true});
    assert.deepEqual(await e.bindings.unbindGrant(g.connection,"jam_owned000"),{revoked:false});
    assert.equal(await e.bindings.agentForGrant(g.connection,name),null);
    assert.ok(await e.bindings.agentForGrant(second.connection,name));
    assert.ok(await e.bindings.agentFor(e.actor.workspaceId,e.actor.userId,name));
    assert.equal((await e.database.query<any>("SELECT state,generation FROM capy_bindings WHERE id=$1",[e.binding.id])).rows[0]?.state,"bound");
    await e.bindings.bindGrant(g.connection,"jam_owned000");
    assert.equal((await e.permits()).rows.filter(p=>p.grant_id===g.grantId&&p.revoked_at===null).length,1);
  });
  await t.test("grant revocation and its permit revoke atomically, including rollback",async()=>{
    await assert.rejects(e.database.transaction(async tx=>{await revokeMcpOAuthGrantRows(tx,g.grantId,"test",new Date());throw new Error("rollback");}),/rollback/);
    assert.ok(await e.bindings.agentForGrant(g.connection,name));
    await e.revoke(g.grantId);
    assert.equal((await e.permits()).rows.some(p=>p.grant_id===g.grantId&&p.revoked_at===null),false);
    await assert.rejects(e.bindings.agentForGrant(g.connection,name),McpOAuthAccessRefused);
    assert.ok(await e.bindings.agentForGrant(second.connection,name));
    assert.ok(await e.bindings.agentFor(e.actor.workspaceId,e.actor.userId,name));
  });
});

test("Capy permits fail closed across actor, credential and binding changes",async t=>{
  const e=await fixture(t),name=e.binding.agent;
  await t.test("foreign tenants/context swaps, member role and key owner cannot create or use a permit",async()=>{
    const g=await e.grant();await e.bindings.bindGrant(g.connection,"jam_owned000");
    const member=await e.grant({...e.actor,userId:e.member});
    await assert.rejects(e.bindings.bindGrant(member.connection,"jam_owned000"),{code:"capy_binding_not_found"});
    const other=await e.grant({...e.actor,workspaceId:e.otherWorkspace});
    await assert.rejects(e.bindings.bindGrant(other.connection,"jam_owned000"),{code:"capy_binding_not_found"});
    const base=e.context(g.connection);
    for(const ctx of [e.context(g.connection,{principal:{...base.principal,userId:e.member}}),
      e.context(g.connection,{workspace:{...base.workspace,id:e.otherWorkspace}}),
      e.context(g.connection,{workspace:{...base.workspace,organizationId:randomUUID()}}),
      e.context(g.connection,{workspace:{...base.workspace,relaycastWorkspaceId:"moved"}}),
      e.context(g.connection,{workspace:{...base.workspace,relaycastApiKey:"rotated"}})]) {
      await assert.rejects(relayService(ctx).send({to:"peer",text:"no",as:name}),{message:MISSING});
    }
    await e.database.query("UPDATE organization_memberships SET role='member' WHERE user_id=$1",[e.actor.userId]);
    assert.equal(await e.bindings.agentForGrant(g.connection,name),null);
    await assert.rejects(e.bindings.bindGrant(g.connection,"jam_owned000"),{code:"capy_forbidden"});
    await e.database.query("UPDATE organization_memberships SET role='owner' WHERE user_id=$1",[e.actor.userId]);
    await e.database.query("UPDATE remote_agent_connections SET created_by_user_id=$1 WHERE workspace_id=$2",[e.member,e.actor.workspaceId]);
    assert.equal(await e.bindings.agentForGrant(g.connection,name),null);
    await e.database.query("UPDATE remote_agent_connections SET created_by_user_id=$1 WHERE workspace_id=$2",[e.actor.userId,e.actor.workspaceId]);
    assert.equal(e.writes.length,0);
  });
  await t.test("expired/rotated bearers cannot use a retained connection object",async()=>{
    for(const mode of ["expired","rotated"]){
      const g=await e.grant();await e.bindings.bindGrant(g.connection,"jam_owned000");
      if(mode==="expired") await e.database.query("UPDATE mcp_oauth_sessions SET access_token_expires_at=now()-interval '1 second' WHERE id=$1",[g.pair.sessionId]);
      else {
        const fresh=await e.database.transaction(tx=>e.sessions.rotate(tx,g.pair.refreshToken,{...g.owner,grantId:g.grantId,tokenFamilyId:g.tokenFamilyId}));
        assert.ok(fresh);
        const access=await e.sessions.resolveAccessToken(fresh.accessToken,RESOURCE);assert.ok(access);
        const renewed=new McpOAuthConnection(access,fresh.accessToken,{tenancyMode:"multi",requiredScope:"relay:mcp"});
        assert.ok(await e.bindings.agentForGrant(renewed,name),"refresh retains this grant's explicit permit");
      }
      await assert.rejects(e.bindings.agentForGrant(g.connection,name),McpOAuthAccessRefused);
      await assert.rejects(e.bindings.bindGrant(g.connection,"jam_owned000"),McpOAuthAccessRefused);
    }
  });
  await t.test("remote verification outage stays an error; revocation during external verification refuses",async()=>{
    const g=await e.grant();await e.bindings.bindGrant(g.connection,"jam_owned000");
    e.unavailable(true);await assert.rejects(e.bindings.agentForGrant(g.connection,name),{code:"capy_relay_unavailable"});e.unavailable(false);
    e.onAuthenticated(async()=>{e.onAuthenticated(undefined);await e.revoke(g.grantId);});
    await assert.rejects(e.bindings.agentForGrant(g.connection,name),McpOAuthAccessRefused);
  });
  await t.test("pre-send metadata reads cannot cross permit revocation",async()=>{
    const g=await e.grant();await e.bindings.bindGrant(g.connection,"jam_owned000");
    let calls=0;e.onAddress(async()=>{if(++calls===2)await e.bindings.unbindGrant(g.connection,"jam_owned000");});
    await assert.rejects(relayService(e.context(g.connection)).send({to:"peer",text:"no",as:name}),{message:MISSING});
    e.onAddress(undefined);assert.equal(e.writes.length,0);
  });
  await t.test("generation and immutable identity snapshots never follow successors",async()=>{
    const g=await e.grant();await e.bindings.bindGrant(g.connection,"jam_owned000");
    const old=(await e.database.query<any>("SELECT * FROM capy_bindings WHERE id=$1",[e.binding.id])).rows[0]!;
    const permit=(await e.permits()).rows.find(p=>p.grant_id===g.grantId&&p.revoked_at===null)!;
    for(const [column,value] of [["binding_generation",permit.binding_generation+1],["agent_remote_id","ag_successor"]] as const){
      await e.database.query(`UPDATE capy_grant_permits SET ${column}=$2 WHERE id=$1`,[permit.id,value]);
      assert.equal(await e.bindings.agentForGrant(g.connection,name),null,`permit ${column}`);
      await e.database.query(`UPDATE capy_grant_permits SET ${column}=$2 WHERE id=$1`,[permit.id,permit[column]]);
    }
    for(const [column,value] of [["generation",old.generation+1],["agent_remote_id","ag_successor"],["agent_name","capy-successor"]] as const){
      await e.database.query(`UPDATE capy_bindings SET ${column}=$2 WHERE id=$1`,[e.binding.id,value]);
      assert.equal(await e.bindings.agentForGrant(g.connection,name),null,column);
      await e.database.query(`UPDATE capy_bindings SET ${column}=$2 WHERE id=$1`,[e.binding.id,old[column]]);
    }
    await e.bindings.retire(e.actor,e.binding.id);assert.equal(await e.bindings.agentForGrant(g.connection,name),null);
    await assert.rejects(e.bindings.bindGrant(g.connection,"jam_owned000"),{code:"capy_binding_not_found"});
  });
});

test("permit tenant integrity and uniqueness are enforced by SQL; completed custody cleanup remains possible",async t=>{
  const e=await fixture(t),g=await e.grant();await e.bindings.bindGrant(g.connection,"jam_owned000");
  const p=(await e.permits()).rows[0]!;
  await assert.rejects(e.database.query(`INSERT INTO capy_grant_permits
    (id,organization_id,workspace_id,user_id,grant_id,binding_id,binding_generation,agent_remote_id,agent_name)
    SELECT $1,organization_id,workspace_id,user_id,grant_id,binding_id,binding_generation,agent_remote_id,agent_name
    FROM capy_grant_permits WHERE id=$2`,[randomUUID(),p.id]),/unique constraint/);
  const other=await e.grant({...e.actor,workspaceId:e.otherWorkspace});
  // Matching a different grant's tenant cannot point at this workspace's binding.
  await assert.rejects(e.database.query(`INSERT INTO capy_grant_permits
    (id,organization_id,workspace_id,user_id,grant_id,binding_id,binding_generation,agent_remote_id,agent_name)
    VALUES($1,$2,$3,$4,$5,$6,1,'ag_fake','capy-fake')`,
  [randomUUID(),e.actor.organizationId,e.otherWorkspace,e.actor.userId,other.grantId,e.binding.id]),/foreign key/);
  assert.equal(await e.database.transaction(tx=>removeCompletedWorkspaceCapyInTx(tx,e.actor.organizationId,e.actor.workspaceId)),false);
  await e.bindings.retire(e.actor,e.binding.id);
  assert.equal(await e.database.transaction(tx=>removeCompletedWorkspaceCapyInTx(tx,e.actor.organizationId,e.actor.workspaceId)),true);
  assert.equal((await e.permits()).rows.length,0,"no orphan permits after completed native cleanup");
});

test("optional MCP permit tools advertise only explicit OAuth send authority and no secrets",async t=>{
  const e=await fixture(t),g=await e.grant(),ctx=e.context(g.connection),sdk=await e.mcp(ctx);
  const tools=(await sdk.listTools()).tools.map(tool=>tool.name);
  assert.ok(tools.includes("bind_capy_thread"));assert.ok(tools.includes("unbind_capy_thread"));assert.ok(!tools.includes("spawn_capy_thread"));
  const capabilities:any=await sdk.callTool({name:"describe_capabilities",arguments:{}});
  assert.equal(capabilities.structuredContent.groups.find((group:any)=>group.id==="capy_binding").status,"available");
  const result:any=await sdk.callTool({name:"bind_capy_thread",arguments:{thread_id:"jam_owned000"}});
  assert.equal(result.isError,undefined);assert.equal(JSON.parse(result.content[0].text).already_bound,true);
  assert.equal(JSON.stringify(result).includes(e.agents.get(e.binding.agent).token),false);
  const sent:any=await sdk.callTool({name:"send_relay_message",arguments:{to:"peer",text:"mcp reply",as:e.binding.agent,idempotency_key:"stable-001"}});
  assert.equal(sent.isError,undefined);assert.equal(e.writes.length,1);
  const removed:any=await sdk.callTool({name:"unbind_capy_thread",arguments:{thread_id:"jam_owned000"}});
  assert.equal(removed.isError,undefined);assert.equal(JSON.parse(removed.content[0].text).revoked,true);
  const denied:any=await sdk.callTool({name:"send_relay_message",arguments:{to:"peer",text:"no",as:e.binding.agent}});
  assert.equal(denied.isError,true);assert.equal(e.writes.length,1);
  const bad:any=await sdk.callTool({name:"bind_capy_thread",arguments:{thread_id:"jam_absent00"}});assert.equal(bad.isError,true);
  const off=await e.mcp({...ctx,capyPermits:undefined});
  assert.ok(!(await off.listTools()).tools.some(tool=>tool.name==="bind_capy_thread"));
  const native=await e.mcp({...ctx,oauth:undefined,authMode:"cli_login"});
  assert.ok(!(await native.listTools()).tools.some(tool=>tool.name==="bind_capy_thread"));
  const swapped=await e.mcp({...ctx,workspace:{...ctx.workspace,id:e.otherWorkspace}});
  const refusal:any=await swapped.callTool({name:"bind_capy_thread",arguments:{thread_id:"jam_owned000"}});assert.equal(refusal.isError,true);
});
