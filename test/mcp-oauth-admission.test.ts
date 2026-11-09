import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { migrate } from "../src/migrations.js";
import { createMcpOAuthProtocol } from "../src/mcp/oauth/protocol.js";
import { McpOAuthSessions } from "../src/mcp/oauth/sessions.js";
import { admitMcpOAuthBearer, McpOAuthAccessRefused, McpOAuthActorRefused } from "../src/mcp/oauth/admission.js";
import { PGliteDatabase } from "./support/harness.js";
import { encryptSecret } from "../src/crypto.js";
import { createRelaycastClient } from "../src/messaging/relaycast.js";
import type { McpContext } from "../src/mcp/context.js";
import { desktopCallContext } from "../src/mcp/desktop-call.js";
import { HOSTED_SOURCE, ownerHash, relayService } from "../src/mcp/relay-participants.js";
import { createRelaycastWorld } from "./support/relaycast-world.js";
import { createServer } from "node:http";
import { createApp } from "../src/app.js";
import { ControlPlaneStore } from "../src/store.js";
import type { SelfhostConfig } from "../src/config.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { close,listen } from "./support/harness.js";
import { pkceS256 } from "../src/mcp/oauth/protocol.js";
import { McpOAuthStore } from "../src/mcp/oauth/store.js";
import { McpOAuthTeardown,mcpOAuthTeardownFetch } from "../src/mcp/oauth/teardown.js";

const ORIGIN="https://relay.example.test",SHARED="/api/v1/mcp/shared-sessions";
const RESOURCE=ORIGIN+"/cloud"+SHARED;
const KEYRING={active:{id:"fake-key",key:Buffer.alloc(32,7)}};
function appConfig(enabled=true):SelfhostConfig {
  return {
    databaseUrl:"unused",publicBaseUrl:ORIGIN,dashboardUrl:ORIGIN,
    relaycastUrl:"http://fake-relay.test",relaycastPublicUrl:"https://cast.example.test",
    relayhistoryUrl:"http://unused-history.test",relayhistoryPublicUrl:"https://history.example.test",
    relayauthUrl:null,relayauthApiKey:null,internalServiceToken:null,
    bootstrapToken:"fake-bootstrap-token-at-least-thirty-two-bytes",encryptionKeyring:KEYRING,
    oauthRedirectUrl:ORIGIN+"/unused",host:"127.0.0.1",port:3000,
    mcpOAuth:{enabled,eventsEnabled:false,pumpEnabled:false,oidc:null},
  };
}
const INITIALIZE={jsonrpc:"2.0",id:1,method:"initialize",params:{
  protocolVersion:"2025-06-18",capabilities:{},clientInfo:{name:"fake-client",version:"1"},
}};

async function fixture(t:test.TestContext) {
  const database=new PGliteDatabase();t.after(()=>database.close());await migrate(database);
  const userId=randomUUID(),organizationId=randomUUID(),workspaceId=randomUUID();
  const grantId=randomUUID(),tokenFamilyId=randomUUID(),clientId="mcpc_fake_"+randomUUID();
  await database.query("INSERT INTO selfhost_users(id,email,name) VALUES ($1,'fake@example.test','Fake User')",[userId]);
  await database.query("INSERT INTO selfhost_organizations(id,name) VALUES ($1,'Fake Org')",[organizationId]);
  await database.query("INSERT INTO selfhost_organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')",[organizationId,userId]);
  await database.query(`INSERT INTO selfhost_workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
    VALUES ($1,$2,'Fake Workspace','fake-workspace',$3)`,[workspaceId,organizationId,encryptSecret("rk_fake",KEYRING.active)]);
  await database.query("INSERT INTO selfhost_mcp_oauth_clients(client_id,redirect_uris) VALUES ($1,$2)",[clientId,["https://client.example.test/cb"]]);
  await database.query(`INSERT INTO selfhost_mcp_oauth_grants
    (id,client_id,user_id,organization_id,workspace_id,agent_name,scopes,resource,token_family_id)
    VALUES ($1,$2,$3,$4,$5,'approved-agent',$6,$7,$8)`,
    [grantId,clientId,userId,organizationId,workspaceId,["relay:mcp","openid"],RESOURCE,tokenFamilyId]);
  const protocol=createMcpOAuthProtocol({publicOrigin:ORIGIN,enabledResources:[SHARED,"/mcp"]});
  const sessions=new McpOAuthSessions(database,{protocol,tenancyMode:"multi"});
  const owner={userId,organizationId,workspaceId,grantId,tokenFamilyId};
  const issue=(scopes=["relay:mcp"])=>database.transaction(tx=>sessions.issue(tx,{...owner,scopes}));
  const pair=await issue();
  const admitted=await admitMcpOAuthBearer({sessions,token:pair.accessToken,resourcePath:SHARED});
  assert.ok(admitted.ok);
  return {database,owner,clientId,sessions,pair,connection:admitted.connection,issue};
}

async function relayFixture(t:test.TestContext) {
  const f=await fixture(t),world=createRelaycastWorld([]);
  const keyring=KEYRING;
  const fetchImpl:typeof fetch=async(input,init)=>{
    const url=new URL(input instanceof Request?input.url:String(input));
    const headers=new Headers(init?.headers);
    const token=(headers.get("authorization")??"").replace(/^Bearer /,"");
    const body=init?.body?JSON.parse(String(init.body)):null;
    if(url.pathname==="/v1/agents" && (init?.method??"GET")==="GET") {
      return Response.json({ok:true,data:[...world.agents.values()].map(agent=>({...agent,
        address:agent.name+"@cloud-"+agent.id,last_seen:new Date().toISOString()}))});
    }
    const result=await world.handle(init?.method??"GET",url.pathname,url.searchParams,token,body,headers.get("idempotency-key"));
    return Response.json(result?.body??{ok:false,error:{code:"not_found"}},{status:result?.status??404});
  };
  const client=createRelaycastClient({internalOrigin:"http://fake-relay.test",fetchImpl});
  const context:McpContext={
    principal:f.connection.access.principal,
    workspace:{id:f.owner.workspaceId,organizationId:f.owner.organizationId,name:"Fake Workspace",
      relaycastWorkspaceId:"fake-workspace",relaycastApiKey:"rk_fake",role:"member"},
    authMode:"oauth",role:"member",origin:ORIGIN,endpointUrl:RESOURCE,
    desktopCall:desktopCallContext({},new Headers()),
    readHistory:async()=>{throw new Error("No History authority");},
    members:async()=>[{userId:f.owner.userId,email:"fake@example.test",name:"Fake User"}],
    providers:async()=>[],
    relaycast:{listAgents:status=>client.listAgents("rk_fake",status),listPresence:()=>client.listPresence("rk_fake")},
    relay:{database:f.database,keyring,client,sessionId:"fake-chat-session"},oauth:f.connection,
  };
  const service=relayService(context);
  const oauth=new McpOAuthStore(f.database,{protocol:f.sessions.options.protocol,tenancyMode:"multi",isGrokRoutine:()=>false});
  const teardown=new McpOAuthTeardown({database:f.database,keyring,client});
  t.after(()=>teardown.stop());
  return {...f,world,keyring,context,service,fetchImpl,oauth,teardown};
}

test("MCP-only admission checks the audience, own token class and resource permission",async t=>{
  const f=await fixture(t);
  for(const token of [f.pair.refreshToken,"sh_at_fake","cld_at_fake","mcp_at_bad"]) {
    assert.deepEqual(await admitMcpOAuthBearer({sessions:f.sessions,token,resourcePath:SHARED}),{ok:false,status:401});
  }
  assert.deepEqual(await admitMcpOAuthBearer({sessions:f.sessions,token:f.pair.accessToken,resourcePath:"/mcp"}),{ok:false,status:401});
  const oidcOnly=await f.issue(["openid"]);
  assert.deepEqual(await admitMcpOAuthBearer({sessions:f.sessions,token:oidcOnly.accessToken,resourcePath:SHARED}),{ok:false,status:403});
  assert.equal((await f.database.query("SELECT id FROM selfhost_token_sessions")).rows.length,0);
});

test("the relay fence rechecks exact credential after rotation and live grant scopes after admission",async t=>{
  const f=await fixture(t);
  await f.database.transaction(tx=>f.connection.lock(tx));
  await f.database.query("UPDATE selfhost_organization_memberships SET role='admin' WHERE organization_id=$1 AND user_id=$2",
    [f.owner.organizationId,f.owner.userId]);
  await f.database.transaction(tx=>f.connection.lock(tx));
  assert.equal(f.connection.access.principal.role,"admin");
  await f.database.query("UPDATE selfhost_mcp_oauth_grants SET scopes=$2 WHERE id=$1",[f.owner.grantId,["openid"]]);
  await assert.rejects(f.database.transaction(tx=>f.connection.lock(tx)),McpOAuthAccessRefused);
  await f.database.query("UPDATE selfhost_mcp_oauth_grants SET scopes=$2 WHERE id=$1",[f.owner.grantId,["relay:mcp","openid"]]);
  assert.ok(await f.database.transaction(tx=>f.sessions.rotate(tx,f.pair.refreshToken,f.owner)));
  await assert.rejects(f.database.transaction(tx=>f.connection.lock(tx)),McpOAuthAccessRefused);
});

test("a pin accepts only its owner's participant and never switches immutable ids, including after a rename",async t=>{
  const f=await fixture(t),agent={userId:f.owner.userId,workspaceId:f.owner.workspaceId,agentName:"approved-agent",agentRemoteId:"fake-original-id"};
  await assert.rejects(f.database.transaction(tx=>f.connection.pin(tx,agent)),McpOAuthAccessRefused);
  await f.database.transaction(async tx=>{
    await f.connection.lock(tx);
    await assert.rejects(f.connection.pin(tx,{...agent,userId:randomUUID()}),McpOAuthAccessRefused);
    await f.connection.pin(tx,agent);
  });
  assert.equal(f.connection.access.agentRemoteId,agent.agentRemoteId);
  assert.throws(()=>f.connection.assertActor("another-owned-agent"),McpOAuthActorRefused);
  const secondId=randomUUID();
  await f.database.query(`INSERT INTO selfhost_mcp_oauth_grants
    (id,client_id,user_id,organization_id,workspace_id,agent_name,agent_remote_id,scopes,resource,token_family_id)
    SELECT $2,client_id,user_id,organization_id,workspace_id,agent_name,agent_remote_id,scopes,resource,$3
    FROM selfhost_mcp_oauth_grants WHERE id=$1`,[f.owner.grantId,secondId,randomUUID()]);
  await f.database.transaction(async tx=>{
    await f.connection.lock(tx);
    assert.equal(await f.connection.claimedByOther(tx,agent),true);
    await assert.rejects(f.connection.pin(tx,{...agent,agentRemoteId:"fake-successor-id"}),McpOAuthAccessRefused);
    await f.connection.pin(tx,{...agent,agentName:"renamed-agent"});
  });
  const rows=(await f.database.query("SELECT agent_name,agent_remote_id FROM selfhost_mcp_oauth_grants ORDER BY id")).rows;
  assert.equal(rows.length,2);
  for(const row of rows) assert.deepEqual(row,{agent_name:"renamed-agent",agent_remote_id:"fake-original-id"});
  f.connection.assertActor("renamed-agent");
  const different=randomUUID();
  await f.database.query(`INSERT INTO selfhost_mcp_oauth_grants
    (id,client_id,user_id,organization_id,workspace_id,agent_name,agent_remote_id,scopes,resource,token_family_id)
    SELECT $2,client_id,user_id,organization_id,workspace_id,agent_name,'fake-different-id',scopes,resource,$3
    FROM selfhost_mcp_oauth_grants WHERE id=$1`,[f.owner.grantId,different,randomUUID()]);
  await f.database.transaction(async tx=>{
    await f.connection.lock(tx);await f.connection.pin(tx,{...agent,agentName:"renamed-again"});
  });
  assert.deepEqual((await f.database.query("SELECT agent_name,agent_remote_id FROM selfhost_mcp_oauth_grants WHERE id=$1",[different])).rows[0],
    {agent_name:"renamed-agent",agent_remote_id:"fake-different-id"});
  await f.database.query("UPDATE selfhost_mcp_oauth_grants SET revoked_at=now() WHERE id=$1",[secondId]);
  await f.database.transaction(async tx=>{
    await f.connection.lock(tx);
    assert.equal(await f.connection.claimedByOther(tx,{...agent,agentName:"renamed-agent"}),false);
  });
});

test("membership departure and grant revocation refuse an admitted connection before a relay action",async t=>{
  const f=await fixture(t);
  await f.database.query("DELETE FROM selfhost_organization_memberships WHERE organization_id=$1 AND user_id=$2",
    [f.owner.organizationId,f.owner.userId]);
  await assert.rejects(f.database.transaction(tx=>f.connection.lock(tx)),McpOAuthAccessRefused);
  await f.database.query("INSERT INTO selfhost_organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')",
    [f.owner.organizationId,f.owner.userId]);
  await f.database.query("UPDATE selfhost_mcp_oauth_grants SET revoked_at=now() WHERE id=$1",[f.owner.grantId]);
  await assert.rejects(f.database.transaction(tx=>f.connection.lock(tx)),McpOAuthAccessRefused);
});

test("OAuth relay actor pins once, follows the same immutable agent through a rename, and rejects an owned successor",async t=>{
  const f=await relayFixture(t);
  f.world.addAgent("peer");
  const sent=await f.service.send({to:"peer",text:"first"});
  assert.equal(sent.from,"approved-agent");
  const first=f.world.agents.get("approved-agent")!;
  assert.equal(first.metadata.created_by,"mcp-oauth");
  const participant=(await f.database.query("SELECT session_hash,agent_remote_id FROM selfhost_hosted_relay_participants")).rows[0]!;
  assert.equal(participant.session_hash,null);
  assert.equal(participant.agent_remote_id,first.id);
  assert.equal(f.connection.access.agentRemoteId,first.id);

  const other=f.world.addAgent("other-owned",{source:HOSTED_SOURCE,cloud_workspace_id:f.owner.workspaceId,owner_hash:ownerHash(f.owner.userId)});
  await f.database.query(`INSERT INTO selfhost_hosted_relay_participants
    (id,workspace_id,user_id,relaycast_workspace_id,agent_name,agent_remote_id,token_ciphertext)
    VALUES ($1,$2,$3,'fake-workspace',$4,$5,$6)`,
    [randomUUID(),f.owner.workspaceId,f.owner.userId,other.name,other.id,encryptSecret(other.token,f.keyring.active)]);
  const before=f.world.messages.size;
  await assert.rejects(f.service.send({to:"peer",text:"forbidden",as:other.name}),/only act as/);
  await assert.rejects(f.service.send({to:"peer",text:"forbidden",as_person:true}),/as_person/);
  assert.equal(f.world.messages.size,before);

  f.world.agents.delete(first.name);first.name="renamed-approved";f.world.agents.set(first.name,first);
  assert.equal((await f.service.status()).name,"renamed-approved");
  assert.equal(f.connection.access.agentRemoteId,first.id);
  assert.equal(f.connection.access.agentName,"renamed-approved");
  f.world.agents.delete(first.name);
  const successor=f.world.addAgent(first.name,{source:HOSTED_SOURCE,cloud_workspace_id:f.owner.workspaceId,owner_hash:ownerHash(f.owner.userId)});
  await assert.rejects(f.service.join({}),/identity changed/);
  assert.equal(f.world.agents.get(first.name)!.id,successor.id);
  assert.equal(f.connection.access.agentRemoteId,first.id);
});

test("revocation after admission prevents any relay request and a pinned leave never releases another live connection",async t=>{
  const f=await relayFixture(t);
  await f.service.join({});
  const agent=f.world.agents.get("approved-agent")!,otherGrant=randomUUID();
  await f.database.query(`INSERT INTO selfhost_mcp_oauth_grants
    (id,client_id,user_id,organization_id,workspace_id,agent_name,agent_remote_id,scopes,resource,token_family_id)
    SELECT $2,client_id,user_id,organization_id,workspace_id,agent_name,agent_remote_id,scopes,resource,$3
    FROM selfhost_mcp_oauth_grants WHERE id=$1`,[f.owner.grantId,otherGrant,randomUUID()]);
  await assert.rejects(f.service.leave(),/Another active connection/);
  assert.equal(f.world.agents.get(agent.name)!.id,agent.id);
  await f.database.query("UPDATE selfhost_mcp_oauth_grants SET revoked_at=now() WHERE id=$1",[otherGrant]);
  await f.service.leave();
  assert.equal(f.world.agents.has(agent.name),false);
  await assert.rejects(f.service.join({}),/approved agent is no longer available/);
  const requests=f.world.bodies.length;
  await f.database.query("UPDATE selfhost_mcp_oauth_grants SET revoked_at=now() WHERE id=$1",[f.owner.grantId]);
  await assert.rejects(f.service.status(),/no longer has access/);
  assert.equal(f.world.bodies.length,requests);
});

test("OAuth recovers the pinned immutable agent after both a rename and external token rotation",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  const original=f.world.agents.get("approved-agent")!;
  f.world.agents.delete(original.name);original.name="renamed-original";f.world.agents.set(original.name,original);
  f.world.rotateToken(original.name);
  const successor=f.world.addAgent("approved-agent",{source:HOSTED_SOURCE,cloud_workspace_id:f.owner.workspaceId,
    owner_hash:ownerHash(f.owner.userId),created_by:"mcp-oauth"});
  const joined=await f.service.join({});
  assert.equal(joined.name,original.name);
  assert.equal(f.connection.access.agentRemoteId,original.id);
  assert.equal(f.world.agents.get(successor.name)!.id,successor.id);
  assert.equal((await f.service.status()).name,original.name);
});

test("a lost relay send response retains the new pin for idempotent retry and later teardown",async t=>{
  const f=await relayFixture(t);f.world.addAgent("peer");
  f.world.failNext("POST","/v1/dm",503,{after:true});
  const input={to:"peer",text:"accepted before response loss",idempotency_key:"fake-stable-retry"};
  await assert.rejects(f.service.send(input),/Relaycast answered 503/);
  const remote=f.world.agents.get("approved-agent")!;
  const grant=(await f.database.query("SELECT agent_remote_id FROM selfhost_mcp_oauth_grants WHERE id=$1",[f.owner.grantId])).rows[0]!;
  assert.equal(grant.agent_remote_id,remote.id);
  assert.equal((await f.database.query("SELECT id FROM selfhost_hosted_relay_participants")).rows.length,1);
  assert.equal(f.world.messages.size,1);
  await f.service.send(input);
  assert.equal(f.world.messages.size,1);
});

test("durable remote teardown retries failure, serializes workers and follows only the original id after rename",async t=>{
  const f=await relayFixture(t);
  await f.service.join({});
  const original=f.world.agents.get("approved-agent")!;
  f.world.agents.delete(original.name);original.name="renamed-original";f.world.agents.set(original.name,original);
  f.world.rotateToken(original.name);
  const successor=f.world.addAgent("approved-agent",{source:HOSTED_SOURCE,cloud_workspace_id:f.owner.workspaceId,
    owner_hash:ownerHash(f.owner.userId),created_by:"mcp-oauth"});
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  f.world.failNext("POST","/v1/agents/release-exact",503);
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:0,pending:1});
  assert.ok(f.world.agents.has(original.name));
  const second=new McpOAuthTeardown(f.teardown.deps);
  const results=await Promise.all([f.teardown.drain(),second.drain()]);
  assert.equal(results.reduce((sum,result)=>sum+result.completed,0),1);
  assert.equal(f.world.agents.has(original.name),false);
  assert.equal(f.world.agents.get(successor.name)!.id,successor.id);
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:0,pending:0});
  const completed=(await f.database.query("SELECT completed_at FROM selfhost_mcp_oauth_revocations")).rows[0]!;
  assert.ok(completed.completed_at);
});

test("first pin covers an unused same-name grant, whose final disconnect releases the agent before workspace deletion",async t=>{
  const f=await relayFixture(t);
  const other=randomUUID();
  await f.database.query(`INSERT INTO selfhost_mcp_oauth_grants
    (id,client_id,user_id,organization_id,workspace_id,agent_name,agent_remote_id,scopes,resource,token_family_id)
    SELECT $2,client_id,user_id,organization_id,workspace_id,agent_name,NULL,scopes,resource,$3
    FROM selfhost_mcp_oauth_grants WHERE id=$1`,[f.owner.grantId,other,randomUUID()]);
  await f.service.join({});
  const original=f.world.agents.get("approved-agent")!;
  assert.equal((await f.database.query("SELECT agent_remote_id FROM selfhost_mcp_oauth_grants WHERE id=$1",[other])).rows[0]!.agent_remote_id,original.id);
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:1,pending:0});
  assert.ok(f.world.agents.has("approved-agent"));
  const store=new ControlPlaneStore(f.database,KEYRING,0,{tenancy:"multi"});
  const remove=()=>store.deleteWorkspace({...f.owner,allowLast:true,actor:{kind:"bootstrap"}});
  assert.equal(await remove(),"in_use");
  await f.oauth.revokeMcpOAuthGrant(other,"fake-last-disconnect");
  assert.equal(await remove(),"in_use");
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
  assert.equal(f.world.agents.has("approved-agent"),false);
  assert.equal(await remove(),"deleted");
});

test("teardown transfers the verified pin to a later unused same-name grant before keeping its agent",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  const original=f.world.agents.get("approved-agent")!,other=randomUUID();
  await f.database.query(`INSERT INTO selfhost_mcp_oauth_grants
    (id,client_id,user_id,organization_id,workspace_id,agent_name,scopes,resource,token_family_id)
    SELECT $2,client_id,user_id,organization_id,workspace_id,agent_name,scopes,resource,$3
    FROM selfhost_mcp_oauth_grants WHERE id=$1`,[f.owner.grantId,other,randomUUID()]);
  assert.equal((await f.database.query("SELECT agent_remote_id FROM selfhost_mcp_oauth_grants WHERE id=$1",[other])).rows[0]!.agent_remote_id,null);
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:1,pending:0});
  assert.equal((await f.database.query("SELECT agent_remote_id FROM selfhost_mcp_oauth_grants WHERE id=$1",[other])).rows[0]!.agent_remote_id,original.id);
  await f.oauth.revokeMcpOAuthGrant(other,"fake-last-disconnect");
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
  assert.equal(f.world.agents.has(original.name),false);
});

test("OAuth leave preserves an approved agent and inbox already bound to a native chat",async t=>{
  const f=await relayFixture(t);
  const native=relayService({...f.context,oauth:undefined,authMode:"cli_login",
    relay:{...f.context.relay,sessionId:"fake-native-chat"}});
  await native.join({name:"approved-agent"});
  const original=f.world.agents.get("approved-agent")!;
  const row=(await f.database.query("SELECT session_hash FROM selfhost_hosted_relay_participants")).rows[0]!;
  assert.ok(row.session_hash);
  await f.service.join({});
  const releases=f.world.bodies.filter(row=>row.path==="/v1/agents/release-exact").length;
  await assert.rejects(f.service.leave(),/native MCP session still uses/);
  assert.equal(f.world.bodies.filter(row=>row.path==="/v1/agents/release-exact").length,releases);
  assert.equal(f.world.agents.get(original.name)!.id,original.id);
  assert.equal((await f.database.query("SELECT session_hash FROM selfhost_hosted_relay_participants")).rows[0]!.session_hash,row.session_hash);
  assert.equal((await native.status()).name,original.name);
});

test("a stalled teardown request aborts and releases local locks with durable work still retryable",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  const stalled:typeof fetch=(input,init)=>{
    if(!String(input).endsWith("/v1/agents/release-exact")) return f.fetchImpl(input,init);
    return new Promise((_resolve,reject)=>{
      const signal=init!.signal!;
      const network=setTimeout(()=>reject(new Error("missing abort")),1000);
      const aborted=()=>{clearTimeout(network);reject(signal.reason);};
      if(signal.aborted)aborted();
      else signal.addEventListener("abort",aborted,{once:true});
    });
  };
  const client=createRelaycastClient({internalOrigin:"http://fake-relay.test",fetchImpl:mcpOAuthTeardownFetch(stalled,10)});
  const worker=new McpOAuthTeardown({...f.teardown.deps,client});
  assert.deepEqual(await worker.drain(),{completed:0,kept:0,pending:1});
  assert.equal((await f.database.query("SELECT completed_at FROM selfhost_mcp_oauth_revocations")).rows[0]!.completed_at,null);
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
});

test("disconnect preserves an OAuth participant a native MCP session has since bound",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  await f.database.query("UPDATE selfhost_hosted_relay_participants SET session_hash=$1",["f".repeat(64)]);
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:1,pending:0});
  assert.ok(f.world.agents.has("approved-agent"));
});

test("a rejected token and an already-released roster entry complete cleanup without another release",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  f.world.rotateToken("approved-agent");f.world.agents.get("approved-agent")!.status="released";
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  const requests=f.world.bodies.filter(row=>row.path==="/v1/agents/release-exact").length;
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
  assert.equal(f.world.bodies.filter(row=>row.path==="/v1/agents/release-exact").length,requests);
  assert.equal((await f.database.query("SELECT id FROM selfhost_hosted_relay_participants")).rows.length,0);
});

test("teardown intent survives deletion of the user and participant rows",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-user-removal");
  await f.database.query("DELETE FROM selfhost_users WHERE id=$1",[f.owner.userId]);
  assert.equal((await f.database.query("SELECT id FROM selfhost_hosted_relay_participants")).rows.length,0);
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
  assert.equal(f.world.agents.has("approved-agent"),false);
});

test("workspace HTTP deletion preserves credentials through live grants and failed remote cleanup",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  const config=appConfig(),store=new ControlPlaneStore(f.database,KEYRING,0,{tenancy:"multi"});
  const server=createServer(createApp({config,store,messagingFetch:f.fetchImpl,mcpOAuthTeardown:f.teardown}));
  const base=await listen(server);t.after(()=>close(server));
  const remove=()=>fetch(`${base}/api/v1/organizations/${f.owner.organizationId}/workspaces/${f.owner.workspaceId}`,{
    method:"DELETE",headers:{authorization:`Bearer ${config.bootstrapToken}`},
  });
  let response=await remove();assert.equal(response.status,409);
  assert.equal((await response.json()).error,"workspace_in_use");
  assert.ok(await f.sessions.resolveAccessToken(f.pair.accessToken,RESOURCE));
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  f.world.failNext("POST","/v1/agents/release-exact",503);
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:0,pending:1});
  response=await remove();assert.equal(response.status,409);
  assert.equal((await response.json()).error,"workspace_in_use");
  assert.equal((await f.database.query("SELECT id FROM selfhost_workspaces WHERE id=$1",[f.owner.workspaceId])).rows.length,1);
  assert.ok(f.world.agents.has("approved-agent"));
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
  response=await remove();assert.equal(response.status,204);
  assert.equal(f.world.agents.has("approved-agent"),false);
  assert.equal((await f.database.query("SELECT id FROM selfhost_workspaces WHERE id=$1",[f.owner.workspaceId])).rows.length,0);
});

test("a missing workspace keeps teardown pending instead of substituting another tenant credential",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-workspace-removal");
  await f.database.query("DELETE FROM selfhost_workspaces WHERE id=$1",[f.owner.workspaceId]);
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:0,pending:1});
  assert.ok(f.world.agents.has("approved-agent"));
  assert.equal((await f.database.query("SELECT completed_at FROM selfhost_mcp_oauth_revocations")).rows[0]!.completed_at,null);
});

test("blocked old teardown records cannot starve later releasable work",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  for(let index=0;index<20;index++) await f.database.query(`INSERT INTO selfhost_mcp_oauth_revocations
    (id,grant_id,token_family_id,user_id,organization_id,workspace_id,client_id,agent_name,agent_remote_id,reason,created_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,'fake-missing','fake-missing-id','fake-old-intent','2020-01-01T00:00:00Z')`,
    [randomUUID(),randomUUID(),randomUUID(),f.owner.userId,f.owner.organizationId,randomUUID(),f.clientId]);
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:0,pending:20});
  assert.ok(f.world.agents.has("approved-agent"));
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
  assert.equal(f.world.agents.has("approved-agent"),false);
});

test("disabled module exposes no issuer, root facade or grant API and cannot admit its stored tokens",async t=>{
  const f=await relayFixture(t),config=appConfig(false);
  const store=new ControlPlaneStore(f.database,KEYRING,0,{tenancy:"multi"});
  const server=createServer(createApp({config,store,messagingFetch:f.fetchImpl}));
  const base=await listen(server);t.after(()=>close(server));
  for(const path of ["/cloud/.well-known/oauth-authorization-server","/mcp","/cloud/mcp","/cloud/api/v1/oauth/grants"]) {
    assert.equal((await fetch(base+path)).status,404);
  }
  assert.equal((await fetch(base+"/cloud/api/oauth/register",{method:"POST",
    headers:{"content-type":"application/json"},body:"{}"})).status,404);
  const rejected=await fetch(base+"/cloud"+SHARED,{method:"POST",headers:{
    authorization:"Bearer "+f.pair.accessToken,"content-type":"application/json",accept:"application/json, text/event-stream",
  },body:JSON.stringify(INITIALIZE)});
  assert.equal(rejected.status,401);
  assert.ok(!rejected.headers.get("www-authenticate")!.includes("resource_metadata"));
});

test("native pending and exchanged handoff artifacts cannot gain MCP capability",async t=>{
  const f=await relayFixture(t),config=appConfig(false);
  const store=new ControlPlaneStore(f.database,KEYRING,0,{tenancy:"multi"});
  const server=createServer(createApp({config,store,messagingFetch:f.fetchImpl}));
  const base=await listen(server);t.after(()=>close(server));
  const verifier="h".repeat(43);
  const handoff=await store.issueDesktopHandoff({...f.owner,codeChallenge:pkceS256(verifier)});
  const initialize=(token:string)=>fetch(base+"/cloud"+SHARED,{method:"POST",headers:{
    authorization:"Bearer "+token,"content-type":"application/json",accept:"application/json, text/event-stream",
  },body:JSON.stringify(INITIALIZE)});
  assert.equal((await initialize(handoff.accessToken)).status,403);
  const exchanged=await store.exchangeDesktopHandoff(handoff.accessToken,challenge=>challenge===pkceS256(verifier));
  assert.ok(exchanged);
  assert.ok([401,403].includes((await initialize(handoff.accessToken)).status));
  assert.equal((await initialize(exchanged.accessToken)).status,200);
});

for(const endpoint of ["/mcp","/cloud/mcp","/cloud"+SHARED]) test("mounted app OAuth round trip is MCP-only and chat-independent at "+endpoint,async t=>{
  const f=await relayFixture(t);
  f.world.addAgent("peer");
  const config=appConfig();
  const store=new ControlPlaneStore(f.database,KEYRING,0,{tenancy:"multi"});
  const account=await f.database.transaction(tx=>store.issueBrowserSession(tx,{...f.owner,label:"fake-browser"}));
  const server=createServer(createApp({config,store,messagingFetch:f.fetchImpl,mcpOAuthTeardown:f.teardown}));
  const base=await listen(server);t.after(()=>close(server));
  const init=INITIALIZE;
  const call=(path:string,body:unknown,headers:Record<string,string>={})=>fetch(base+path,{method:"POST",
    headers:{"content-type":"application/json",accept:"application/json, text/event-stream",...headers},
    body:JSON.stringify(body)});
  const unauthorized=await call(endpoint,init);
  assert.equal(unauthorized.status,401);
  assert.match(unauthorized.headers.get("www-authenticate")!,/resource_metadata=/);
  const discovery=await (await fetch(base+"/cloud/.well-known/oauth-authorization-server")).json();
  assert.equal(discovery.issuer,ORIGIN+"/cloud");
  const registered=await (await call("/cloud/api/oauth/register",{
    client_name:"Fake connector",redirect_uris:["https://client.example.test/cb"],
  })).json();
  const verifier="v".repeat(43),resource=ORIGIN+(endpoint==="/cloud/mcp"?"/mcp":endpoint);
  const params={client_id:registered.client_id,response_type:"code",redirect_uri:"https://client.example.test/cb",
    code_challenge:pkceS256(verifier),code_challenge_method:"S256",resource,state:""};
  const cookie="agent_relay_session="+account.accessToken;
  const page=await fetch(base+"/cloud/oauth/authorize?"+new URLSearchParams(params),{headers:{cookie},redirect:"manual"});
  assert.equal(page.status,200);
  assert.match(await page.text(),/Fake connector/);
  const approved=await call("/cloud/api/oauth/authorize",{params,decision:"approve",
    workspace_id:f.owner.workspaceId,agent_name:"connected-agent"},{cookie,origin:ORIGIN});
  assert.equal(approved.status,200);
  const redirect=new URL((await approved.json()).redirect_to);
  assert.equal(redirect.searchParams.get("state"),"");
  const exchanged=await call("/cloud/api/oauth/token",{grant_type:"authorization_code",
    client_id:registered.client_id,code:redirect.searchParams.get("code"),code_verifier:verifier,
    redirect_uri:params.redirect_uri,resource});
  assert.equal(exchanged.status,200);
  const pair=await exchanged.json();
  assert.match(pair.access_token,/^mcp_at_/);
  const nativeBefore=(await f.database.query("SELECT id FROM selfhost_token_sessions")).rows.length;
  assert.equal(nativeBefore,1);

  const first=new Client({name:"fake-chat-one",version:"1"});
  const second=new Client({name:"fake-chat-two",version:"1"});
  t.after(()=>Promise.all([first.close(),second.close()]));
  await first.connect(new StreamableHTTPClientTransport(new URL(base+endpoint),{
    requestInit:{headers:{authorization:"Bearer "+pair.access_token}}}));
  await second.connect(new StreamableHTTPClientTransport(new URL(base+endpoint),{
    requestInit:{headers:{authorization:"Bearer "+pair.access_token}}}));
  const tools=(await first.listTools()).tools.map(tool=>tool.name);
  assert.ok(tools.includes("send_relay_message"));
  assert.equal(first.getServerCapabilities()?.experimental?.["com.agentrelay/desktop-provider-credentials"],undefined);
  const capabilities=await first.callTool({name:"describe_capabilities",arguments:{}});
  const report=capabilities.structuredContent as {connection:{auth_mode:string};groups:Array<{id:string;status:string}>};
  assert.equal(report.connection.auth_mode,"oauth");
  assert.equal(report.groups.find(group=>group.id==="shared_session_reads")!.status,"restricted");
  const sent=await first.callTool({name:"send_relay_message",arguments:{to:"peer",text:"first chat"}});
  assert.notEqual(sent.isError,true);
  const pinned=f.world.agents.get("connected-agent")!.id;
  const status=await second.callTool({name:"relay_status",arguments:{}});
  assert.notEqual(status.isError,true);
  assert.equal(f.world.agents.get("connected-agent")!.id,pinned);
  assert.equal(f.world.bodies.filter(call=>call.method==="POST" && call.path==="/v1/agents" && call.body?.name==="connected-agent").length,1);
  const deniedRead=await first.callTool({name:"search_shared_sessions",arguments:{query:"anything"}});
  assert.equal(deniedRead.isError,true);
  const otherEndpoint=endpoint==="/mcp" || endpoint==="/cloud/mcp"?"/cloud"+SHARED:"/mcp";
  assert.equal((await call(otherEndpoint,init,{authorization:"Bearer "+pair.access_token})).status,401);
  assert.equal((await call(endpoint,init,{cookie:"agent_relay_session="+pair.access_token,origin:ORIGIN})).status,401);
  const general=await fetch(base+"/api/v1/organizations/"+f.owner.organizationId+"/memberships",
    {headers:{authorization:"Bearer "+pair.access_token}});
  assert.equal(general.status,401);
  assert.equal((await call("/api/v1/auth/token/refresh",{refreshToken:pair.refresh_token})).status,403);
  assert.equal((await f.database.query("SELECT id FROM selfhost_token_sessions")).rows.length,nativeBefore);

  const grantsPath="/cloud/api/v1/oauth/grants";
  const secondWorkspace=randomUUID(),foreignGrant=randomUUID();
  await f.database.query(`INSERT INTO selfhost_workspaces
    (id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
    VALUES ($1,$2,'Other Workspace',$3,$4)`,[secondWorkspace,f.owner.organizationId,
    "fake-relay-"+secondWorkspace,encryptSecret("rk_other",KEYRING.active)]);
  await f.database.query(`INSERT INTO selfhost_mcp_oauth_grants
    (id,client_id,user_id,organization_id,workspace_id,agent_name,scopes,resource,token_family_id)
    VALUES ($1,$2,$3,$4,$5,'foreign-workspace-agent',$6,$7,$8)`,
    [foreignGrant,registered.client_id,f.owner.userId,f.owner.organizationId,secondWorkspace,["relay:mcp"],resource,randomUUID()]);
  const listed=await fetch(base+grantsPath+"?workspace_id="+secondWorkspace,{headers:{cookie}});
  assert.equal(listed.status,200);
  const grants=(await listed.json()).grants;
  assert.ok(grants.some((grant:{agent_name:string})=>grant.agent_name==="connected-agent"));
  assert.ok(grants.every((grant:{workspace_id:string})=>grant.workspace_id===f.owner.workspaceId));
  assert.equal((await fetch(base+grantsPath,{headers:{authorization:"Bearer "+pair.access_token}})).status,401);
  assert.equal((await fetch(base+grantsPath+"/"+f.owner.grantId,{method:"DELETE",headers:{cookie}})).status,403);
  assert.equal((await fetch(base+grantsPath+"/"+foreignGrant,{method:"DELETE",headers:{cookie,origin:ORIGIN}})).status,404);
  assert.equal((await fetch(base+grantsPath+"/"+f.owner.grantId,{method:"DELETE",headers:{cookie,origin:ORIGIN}})).status,204);
  assert.ok((await f.database.query("SELECT revoked_at FROM selfhost_mcp_oauth_grants WHERE id=$1",[f.owner.grantId])).rows[0]!.revoked_at);

  const removed=await fetch(base+"/api/v1/organizations/"+f.owner.organizationId+"/memberships/"+f.owner.userId,
    {method:"DELETE",headers:{authorization:"Bearer "+config.bootstrapToken}});
  assert.equal(removed.status,204);
  await f.teardown.drain();
  await f.database.query("INSERT INTO selfhost_organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')",
    [f.owner.organizationId,f.owner.userId]);
  assert.equal((await call(endpoint,init,{authorization:"Bearer "+pair.access_token})).status,401);
  assert.equal((await f.database.query("SELECT agent_remote_id FROM selfhost_mcp_oauth_revocations WHERE agent_remote_id=$1",[pinned])).rows.length,1);
});
