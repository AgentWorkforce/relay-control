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
import { MCP_OAUTH_TEARDOWN_DECRYPT_MAX_ATTEMPTS,McpOAuthTeardown,mcpOAuthTeardownBackoffMs,mcpOAuthTeardownFetch } from "../src/mcp/oauth/teardown.js";
import { lockOrganization,lockUser } from "../src/tenancy.js";
import type { RelaycastClient } from "../src/messaging/relaycast.js";

const ORIGIN="https://relay.example.test",SHARED="/api/v1/mcp/shared-sessions";
const RESOURCE=ORIGIN+"/cloud"+SHARED;
const KEYRING={active:{id:"fake-key",key:Buffer.alloc(32,7)}};
function appConfig(enabled=true,unavailable:{reason:"public_url"|"oidc_signing_key";detail:string}|null=null):SelfhostConfig {
  return {
    databaseUrl:"unused",publicBaseUrl:ORIGIN,dashboardUrl:ORIGIN,
    relaycastUrl:"http://fake-relay.test",relaycastPublicUrl:"https://cast.example.test",
    relayhistoryUrl:"http://unused-history.test",relayhistoryPublicUrl:"https://history.example.test",
    sessionReadApi:{url:"http://unused-history.test",publicUrl:"https://history.example.test",secret:"session-read-secret-".repeat(2)},
    internalServiceToken:null,
    bootstrapToken:"fake-bootstrap-token-at-least-thirty-two-bytes",encryptionKeyring:KEYRING,
    oauthRedirectUrl:ORIGIN+"/unused",host:"127.0.0.1",port:3000,
    mcpOAuth:{enabled,unavailable,eventsEnabled:false,pumpEnabled:false,oidc:null},
  };
}
const INITIALIZE={jsonrpc:"2.0",id:1,method:"initialize",params:{
  protocolVersion:"2025-06-18",capabilities:{},clientInfo:{name:"fake-client",version:"1"},
}};

test("OAuth support checks its exact live grant again before returning a private answer", async t => {
  const f = await fixture(t);
  let revoke = false;
  const support = createServer(async (request, response) => {
    assert.equal(request.headers.authorization, "Bearer " + "support-credential-".repeat(2));
    if (revoke) await f.database.query("UPDATE mcp_oauth_grants SET revoked_at = now() WHERE id = $1", [f.owner.grantId]);
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ kind: "reply", replies: ["PRIVATE_OAUTH_SUPPORT"] }));
  });
  const supportUrl = await listen(support); t.after(() => close(support));
  const config = appConfig();
  config.customerSupport = { url: supportUrl, token: "support-credential-".repeat(2) };
  const store = new ControlPlaneStore(f.database, KEYRING, 0, { tenancy: "multi" });
  const server = createServer(createApp({ config, store }));
  const base = await listen(server); t.after(() => close(server));
  const client = new Client({ name: "support-oauth-test", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(base + SHARED), {
    requestInit: { headers: { authorization: "Bearer " + f.pair.accessToken } },
  }));
  t.after(() => client.close());
  const args = { message: "Help with setup", request_id: "oauth-support-001" };
  assert.equal(((await client.callTool({ name: "ask_customer_support", arguments: args })).structuredContent as any).status, "reply");
  revoke = true;
  assert.deepEqual((await client.callTool({ name: "ask_customer_support", arguments: { ...args, request_id: "oauth-support-002" } })).structuredContent,
    { status: "not_authorized" });
});

async function fixture(t:test.TestContext) {
  const database=new PGliteDatabase();t.after(()=>database.close());await migrate(database);
  const userId=randomUUID(),organizationId=randomUUID(),workspaceId=randomUUID();
  const grantId=randomUUID(),tokenFamilyId=randomUUID(),clientId="mcpc_fake_"+randomUUID();
  await database.query("INSERT INTO users(id,email,name) VALUES ($1,'fake@example.test','Fake User')",[userId]);
  await database.query("INSERT INTO organizations(id,name) VALUES ($1,'Fake Org')",[organizationId]);
  await database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')",[organizationId,userId]);
  await database.query(`INSERT INTO workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
    VALUES ($1,$2,'Fake Workspace','fake-workspace',$3)`,[workspaceId,organizationId,encryptSecret("rk_fake",KEYRING.active)]);
  await database.query("INSERT INTO mcp_oauth_clients(client_id,redirect_uris) VALUES ($1,$2)",[clientId,["https://client.example.test/cb"]]);
  await database.query(`INSERT INTO mcp_oauth_grants
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
    relay:{database:f.database,keyring,client,sessionId:"fake-chat-session",relaycastPublicUrl:"https://cast.example.test"},oauth:f.connection,
  };
  const service=relayService(context);
  const oauth=new McpOAuthStore(f.database,{protocol:f.sessions.options.protocol,tenancyMode:"multi",isGrokRoutine:()=>false});
  // Teardown backoff runs on this clock; advance() makes every retry due.
  const clock={at:Date.now()},advance=(ms=3_600_000)=>{clock.at+=ms;};
  const teardown=new McpOAuthTeardown({database:f.database,keyring,client,now:()=>new Date(clock.at)});
  t.after(()=>teardown.stop());
  return {...f,world,keyring,context,service,fetchImpl,oauth,teardown,clock,advance};
}

test("MCP-only admission checks the audience, own token class and resource permission",async t=>{
  const f=await fixture(t);
  for(const token of [f.pair.refreshToken,"sh_at_fake","cld_at_fake","mcp_at_bad"]) {
    assert.deepEqual(await admitMcpOAuthBearer({sessions:f.sessions,token,resourcePath:SHARED}),{ok:false,status:401});
  }
  assert.deepEqual(await admitMcpOAuthBearer({sessions:f.sessions,token:f.pair.accessToken,resourcePath:"/mcp"}),{ok:false,status:401});
  const oidcOnly=await f.issue(["openid"]);
  assert.deepEqual(await admitMcpOAuthBearer({sessions:f.sessions,token:oidcOnly.accessToken,resourcePath:SHARED}),{ok:false,status:403});
  assert.equal((await f.database.query("SELECT id FROM token_sessions")).rows.length,0);
});

test("the relay fence rechecks exact credential after rotation and live grant scopes after admission",async t=>{
  const f=await fixture(t);
  await f.database.transaction(tx=>f.connection.lock(tx));
  await f.database.query("UPDATE organization_memberships SET role='admin' WHERE organization_id=$1 AND user_id=$2",
    [f.owner.organizationId,f.owner.userId]);
  await f.database.transaction(tx=>f.connection.lock(tx));
  assert.equal(f.connection.access.principal.role,"admin");
  await f.database.query("UPDATE mcp_oauth_grants SET scopes=$2 WHERE id=$1",[f.owner.grantId,["openid"]]);
  await assert.rejects(f.database.transaction(tx=>f.connection.lock(tx)),McpOAuthAccessRefused);
  await f.database.query("UPDATE mcp_oauth_grants SET scopes=$2 WHERE id=$1",[f.owner.grantId,["relay:mcp","openid"]]);
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
  await f.database.query(`INSERT INTO mcp_oauth_grants
    (id,client_id,user_id,organization_id,workspace_id,agent_name,agent_remote_id,scopes,resource,token_family_id)
    SELECT $2,client_id,user_id,organization_id,workspace_id,agent_name,agent_remote_id,scopes,resource,$3
    FROM mcp_oauth_grants WHERE id=$1`,[f.owner.grantId,secondId,randomUUID()]);
  await f.database.transaction(async tx=>{
    await f.connection.lock(tx);
    assert.equal(await f.connection.claimedByOther(tx,agent),true);
    await assert.rejects(f.connection.pin(tx,{...agent,agentRemoteId:"fake-successor-id"}),McpOAuthAccessRefused);
    await f.connection.pin(tx,{...agent,agentName:"renamed-agent"});
  });
  const rows=(await f.database.query("SELECT agent_name,agent_remote_id FROM mcp_oauth_grants ORDER BY id")).rows;
  assert.equal(rows.length,2);
  for(const row of rows) assert.deepEqual(row,{agent_name:"renamed-agent",agent_remote_id:"fake-original-id"});
  f.connection.assertActor("renamed-agent");
  const different=randomUUID();
  await f.database.query(`INSERT INTO mcp_oauth_grants
    (id,client_id,user_id,organization_id,workspace_id,agent_name,agent_remote_id,scopes,resource,token_family_id)
    SELECT $2,client_id,user_id,organization_id,workspace_id,agent_name,'fake-different-id',scopes,resource,$3
    FROM mcp_oauth_grants WHERE id=$1`,[f.owner.grantId,different,randomUUID()]);
  await f.database.transaction(async tx=>{
    await f.connection.lock(tx);await f.connection.pin(tx,{...agent,agentName:"renamed-again"});
  });
  assert.deepEqual((await f.database.query("SELECT agent_name,agent_remote_id FROM mcp_oauth_grants WHERE id=$1",[different])).rows[0],
    {agent_name:"renamed-agent",agent_remote_id:"fake-different-id"});
  await f.database.query("UPDATE mcp_oauth_grants SET revoked_at=now() WHERE id=$1",[secondId]);
  await f.database.transaction(async tx=>{
    await f.connection.lock(tx);
    assert.equal(await f.connection.claimedByOther(tx,{...agent,agentName:"renamed-agent"}),false);
  });
});

test("membership departure and grant revocation refuse an admitted connection before a relay action",async t=>{
  const f=await fixture(t);
  await f.database.query("DELETE FROM organization_memberships WHERE organization_id=$1 AND user_id=$2",
    [f.owner.organizationId,f.owner.userId]);
  await assert.rejects(f.database.transaction(tx=>f.connection.lock(tx)),McpOAuthAccessRefused);
  await f.database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')",
    [f.owner.organizationId,f.owner.userId]);
  await f.database.query("UPDATE mcp_oauth_grants SET revoked_at=now() WHERE id=$1",[f.owner.grantId]);
  await assert.rejects(f.database.transaction(tx=>f.connection.lock(tx)),McpOAuthAccessRefused);
});

test("OAuth relay actor pins once, follows the same immutable agent through a rename, and rejects an owned successor",async t=>{
  const f=await relayFixture(t);
  f.world.addAgent("peer");
  const sent=await f.service.send({to:"peer",text:"first"});
  assert.equal(sent.from,"approved-agent");
  const first=f.world.agents.get("approved-agent")!;
  assert.equal(first.metadata.created_by,"mcp-oauth");
  const participant=(await f.database.query("SELECT session_hash,agent_remote_id FROM hosted_relay_participants")).rows[0]!;
  assert.equal(participant.session_hash,null);
  assert.equal(participant.agent_remote_id,first.id);
  assert.equal(f.connection.access.agentRemoteId,first.id);

  const other=f.world.addAgent("other-owned",{source:HOSTED_SOURCE,cloud_workspace_id:f.owner.workspaceId,owner_hash:ownerHash(f.owner.userId)});
  await f.database.query(`INSERT INTO hosted_relay_participants
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
  await f.database.query(`INSERT INTO mcp_oauth_grants
    (id,client_id,user_id,organization_id,workspace_id,agent_name,agent_remote_id,scopes,resource,token_family_id)
    SELECT $2,client_id,user_id,organization_id,workspace_id,agent_name,agent_remote_id,scopes,resource,$3
    FROM mcp_oauth_grants WHERE id=$1`,[f.owner.grantId,otherGrant,randomUUID()]);
  await assert.rejects(f.service.leave(),/Another active connection/);
  assert.equal(f.world.agents.get(agent.name)!.id,agent.id);
  await f.database.query("UPDATE mcp_oauth_grants SET revoked_at=now() WHERE id=$1",[otherGrant]);
  await f.service.leave();
  assert.equal(f.world.agents.has(agent.name),false);
  await assert.rejects(f.service.join({}),/approved agent is no longer available/);
  const requests=f.world.bodies.length;
  await f.database.query("UPDATE mcp_oauth_grants SET revoked_at=now() WHERE id=$1",[f.owner.grantId]);
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
  const grant=(await f.database.query("SELECT agent_remote_id FROM mcp_oauth_grants WHERE id=$1",[f.owner.grantId])).rows[0]!;
  assert.equal(grant.agent_remote_id,remote.id);
  assert.equal((await f.database.query("SELECT id FROM hosted_relay_participants")).rows.length,1);
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
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:0,pending:0});
  f.advance();
  const second=new McpOAuthTeardown(f.teardown.deps);
  const results=await Promise.all([f.teardown.drain(),second.drain()]);
  assert.equal(results.reduce((sum,result)=>sum+result.completed,0),1);
  assert.equal(f.world.agents.has(original.name),false);
  assert.equal(f.world.agents.get(successor.name)!.id,successor.id);
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:0,pending:0});
  const completed=(await f.database.query("SELECT completed_at FROM mcp_oauth_revocations")).rows[0]!;
  assert.ok(completed.completed_at);
});

test("first pin covers an unused same-name grant, whose final disconnect releases the agent before workspace deletion",async t=>{
  const f=await relayFixture(t);
  const other=randomUUID();
  await f.database.query(`INSERT INTO mcp_oauth_grants
    (id,client_id,user_id,organization_id,workspace_id,agent_name,agent_remote_id,scopes,resource,token_family_id)
    SELECT $2,client_id,user_id,organization_id,workspace_id,agent_name,NULL,scopes,resource,$3
    FROM mcp_oauth_grants WHERE id=$1`,[f.owner.grantId,other,randomUUID()]);
  await f.service.join({});
  const original=f.world.agents.get("approved-agent")!;
  assert.equal((await f.database.query("SELECT agent_remote_id FROM mcp_oauth_grants WHERE id=$1",[other])).rows[0]!.agent_remote_id,original.id);
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
  await f.database.query(`INSERT INTO mcp_oauth_grants
    (id,client_id,user_id,organization_id,workspace_id,agent_name,scopes,resource,token_family_id)
    SELECT $2,client_id,user_id,organization_id,workspace_id,agent_name,scopes,resource,$3
    FROM mcp_oauth_grants WHERE id=$1`,[f.owner.grantId,other,randomUUID()]);
  assert.equal((await f.database.query("SELECT agent_remote_id FROM mcp_oauth_grants WHERE id=$1",[other])).rows[0]!.agent_remote_id,null);
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:1,pending:0});
  assert.equal((await f.database.query("SELECT agent_remote_id FROM mcp_oauth_grants WHERE id=$1",[other])).rows[0]!.agent_remote_id,original.id);
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
  const row=(await f.database.query("SELECT session_hash FROM hosted_relay_participants")).rows[0]!;
  assert.ok(row.session_hash);
  await f.service.join({});
  const releases=f.world.bodies.filter(row=>row.path==="/v1/agents/release-exact").length;
  await assert.rejects(f.service.leave(),/native MCP session still uses/);
  assert.equal(f.world.bodies.filter(row=>row.path==="/v1/agents/release-exact").length,releases);
  assert.equal(f.world.agents.get(original.name)!.id,original.id);
  assert.equal((await f.database.query("SELECT session_hash FROM hosted_relay_participants")).rows[0]!.session_hash,row.session_hash);
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
  assert.equal((await f.database.query("SELECT completed_at FROM mcp_oauth_revocations")).rows[0]!.completed_at,null);
  f.advance();
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
});

test("disconnect preserves an OAuth participant a native MCP session has since bound",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  await f.database.query("UPDATE hosted_relay_participants SET session_hash=$1",["f".repeat(64)]);
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
  assert.equal((await f.database.query("SELECT id FROM hosted_relay_participants")).rows.length,0);
});

test("teardown intent survives deletion of the user and participant rows",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-user-removal");
  await f.database.query("DELETE FROM users WHERE id=$1",[f.owner.userId]);
  assert.equal((await f.database.query("SELECT id FROM hosted_relay_participants")).rows.length,0);
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
  assert.equal((await f.database.query("SELECT id FROM workspaces WHERE id=$1",[f.owner.workspaceId])).rows.length,1);
  assert.ok(f.world.agents.has("approved-agent"));
  f.advance();
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
  response=await remove();assert.equal(response.status,204);
  assert.equal(f.world.agents.has("approved-agent"),false);
  assert.equal((await f.database.query("SELECT id FROM workspaces WHERE id=$1",[f.owner.workspaceId])).rows.length,0);
});

test("a missing workspace ends teardown as workspace_mismatch instead of substituting another tenant credential",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-workspace-removal");
  await f.database.query("DELETE FROM workspaces WHERE id=$1",[f.owner.workspaceId]);
  const releases=f.world.bodies.filter(row=>row.path==="/v1/agents/release-exact").length;
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
  assert.ok(f.world.agents.has("approved-agent"));
  assert.equal(f.world.bodies.filter(row=>row.path==="/v1/agents/release-exact").length,releases);
  const row=(await f.database.query("SELECT completed_at,outcome FROM mcp_oauth_revocations")).rows[0]!;
  assert.ok(row.completed_at);assert.equal(row.outcome,"workspace_mismatch");
});

test("blocked old teardown records cannot starve later releasable work",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  for(let index=0;index<20;index++) await f.database.query(`INSERT INTO mcp_oauth_revocations
    (id,grant_id,token_family_id,user_id,organization_id,workspace_id,client_id,agent_name,agent_remote_id,reason,created_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,'fake-missing','fake-missing-id','fake-old-intent','2020-01-01T00:00:00Z')`,
    [randomUUID(),randomUUID(),randomUUID(),f.owner.userId,f.owner.organizationId,randomUUID(),f.clientId]);
  // Their workspace is gone: terminal, so they cannot block a later pass.
  assert.deepEqual(await f.teardown.drain(),{completed:20,kept:0,pending:0});
  assert.equal((await f.database.query("SELECT id FROM mcp_oauth_revocations WHERE outcome='workspace_mismatch'")).rows.length,20);
  assert.ok(f.world.agents.has("approved-agent"));
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
  assert.equal(f.world.agents.has("approved-agent"),false);
});

/** A teardown client whose `method` waits at a gate the test opens. */
function gated(f:Awaited<ReturnType<typeof relayFixture>>,method:"authenticatedAgent"|"releaseHosted") {
  const base=f.teardown.deps.client;
  let entered!:()=>void,resume!:()=>void;
  const reached=new Promise<void>(resolve=>{entered=resolve;}),gate=new Promise<void>(resolve=>{resume=resolve;});
  const wrapped=async(...args:unknown[])=>{entered();await gate;return (base[method] as (...rest:unknown[])=>unknown)(...args);};
  const client={...base,[method]:wrapped} as RelaycastClient;
  return {worker:new McpOAuthTeardown({...f.teardown.deps,client}),reached,resume};
}
const revocation=async(f:Awaited<ReturnType<typeof relayFixture>>)=>(await f.database.query<{attempts:number;
  next_attempt_at:Date|null;claimed_at:Date|null;completed_at:Date|null;outcome:string|null}>(
  "SELECT attempts,next_attempt_at,claimed_at,completed_at,outcome FROM mcp_oauth_revocations")).rows[0]!;
const releaseCount=(f:Awaited<ReturnType<typeof relayFixture>>)=>f.world.bodies.filter(row=>row.path==="/v1/agents/release-exact").length;
const within=<T,>(promise:Promise<T>,ms=2000)=>Promise.race([promise,
  new Promise<never>((_resolve,reject)=>setTimeout(()=>reject(new Error("still blocked")),ms))]);

test("teardown commits its claim and holds no lifecycle lock while Relaycast answers",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  const {worker,reached,resume}=gated(f,"authenticatedAgent");
  const running=worker.drain();
  await reached;
  const claimed=await revocation(f);
  assert.equal(claimed.attempts,1);assert.ok(claimed.claimed_at);assert.equal(claimed.completed_at,null);
  assert.equal(new Date(claimed.next_attempt_at!).getTime(),f.clock.at+60_000);
  // A login, membership change or MCP join of the same owner proceeds meanwhile.
  await within(f.database.transaction(async tx=>{
    await lockUser(tx,f.owner.userId);await lockOrganization(tx,f.owner.organizationId);
    await tx.query("SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))",["selfhost-hosted-mcp",f.owner.workspaceId+":"+f.owner.userId]);
  }));
  resume();
  assert.deepEqual(await running,{completed:1,kept:0,pending:0});
  assert.equal((await revocation(f)).outcome,"released");
  assert.equal(f.world.agents.has("approved-agent"),false);
});

test("a retryable failure backs off exponentially and retries only once due",async t=>{
  assert.deepEqual([1,2,3,6,7,40].map(mcpOAuthTeardownBackoffMs),[60_000,120_000,240_000,1_920_000,3_600_000,3_600_000]);
  const f=await relayFixture(t);await f.service.join({});
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  f.world.failNext("POST","/v1/agents/release-exact",503);
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:0,pending:1});
  let row=await revocation(f);
  assert.equal(row.attempts,1);assert.equal(new Date(row.next_attempt_at!).getTime(),f.clock.at+60_000);
  f.advance(59_999);
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:0,pending:0});
  assert.equal((await revocation(f)).attempts,1);
  f.advance(1);f.world.failNext("POST","/v1/agents/release-exact",429);
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:0,pending:1});
  row=await revocation(f);
  assert.equal(row.attempts,2);assert.equal(new Date(row.next_attempt_at!).getTime(),f.clock.at+120_000);
  assert.ok(f.world.agents.has("approved-agent"));
  f.advance(120_000);
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
  row=await revocation(f);
  assert.equal(row.attempts,3);assert.equal(row.outcome,"released");
  assert.equal(f.world.agents.has("approved-agent"),false);
});

test("a pass stops at its wall-clock budget and an immediate rerun finishes the rest",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  await f.database.query(`INSERT INTO mcp_oauth_revocations
    (id,grant_id,token_family_id,user_id,organization_id,workspace_id,client_id,agent_name,agent_remote_id,reason,created_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,'fake-unused',NULL,'fake-later-intent',now()+interval '1 second')`,
  [randomUUID(),randomUUID(),randomUUID(),f.owner.userId,f.owner.organizationId,f.owner.workspaceId,f.clientId]);
  const worker=new McpOAuthTeardown({...f.teardown.deps,passBudgetMs:0});
  t.after(()=>worker.stop());
  assert.deepEqual(await worker.drain(),{completed:1,kept:0,pending:0});
  // drain() now joins the rerun the budget stop scheduled.
  assert.deepEqual(await worker.drain(),{completed:1,kept:0,pending:0});
  const outcomes=(await f.database.query<{outcome:string}>("SELECT outcome FROM mcp_oauth_revocations ORDER BY created_at")).rows;
  assert.deepEqual(outcomes.map(row=>row.outcome),["released","no_remote"]);
});

test("a native bind between claim and release keeps the intent pending without releasing",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  const {worker,reached,resume}=gated(f,"authenticatedAgent");
  const running=worker.drain();
  await reached;
  await f.database.query("UPDATE hosted_relay_participants SET session_hash=$1",["f".repeat(64)]);
  resume();
  assert.deepEqual(await running,{completed:0,kept:0,pending:1});
  assert.equal(releaseCount(f),0);
  assert.ok(f.world.agents.has("approved-agent"));
  assert.equal((await revocation(f)).completed_at,null);
  f.advance();
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:1,pending:0});
  assert.equal((await revocation(f)).outcome,"kept");
  assert.equal((await f.database.query("SELECT id FROM hosted_relay_participants")).rows.length,1);
});

test("a grant re-pinned during the remote release makes the commit inconclusive and keeps the participant",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  const original=f.world.agents.get("approved-agent")!;
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  const {worker,reached,resume}=gated(f,"releaseHosted");
  const running=worker.drain();
  await reached;
  await f.database.query(`INSERT INTO mcp_oauth_grants
    (id,client_id,user_id,organization_id,workspace_id,agent_name,agent_remote_id,scopes,resource,token_family_id)
    SELECT $2,client_id,user_id,organization_id,workspace_id,agent_name,$3,scopes,resource,$4
    FROM mcp_oauth_grants WHERE id=$1`,[f.owner.grantId,randomUUID(),original.id,randomUUID()]);
  resume();
  assert.deepEqual(await running,{completed:0,kept:0,pending:1});
  assert.equal((await revocation(f)).completed_at,null);
  assert.equal((await f.database.query("SELECT id FROM hosted_relay_participants")).rows.length,1);
});

/** A second live grant of the fixture owner, unpinned unless `pinned` is given. */
async function laterConnection(f:Awaited<ReturnType<typeof relayFixture>>,pinned:string|null=null,createdAfterRevocation=false) {
  const grantId=randomUUID(),tokenFamilyId=randomUUID();
  await f.database.query(`INSERT INTO mcp_oauth_grants
    (id,client_id,user_id,organization_id,workspace_id,agent_name,agent_remote_id,scopes,resource,token_family_id,created_at)
    SELECT $2,client_id,user_id,organization_id,workspace_id,agent_name,$4,scopes,resource,$3,
      CASE WHEN $5::boolean THEN (SELECT max(created_at) FROM mcp_oauth_revocations)+interval '1 second' ELSE now() END
    FROM mcp_oauth_grants WHERE id=$1`,[f.owner.grantId,grantId,tokenFamilyId,pinned,createdAfterRevocation]);
  const pair=await f.database.transaction(tx=>f.sessions.issue(tx,{...f.owner,grantId,tokenFamilyId,scopes:["relay:mcp"]}));
  const admitted=await admitMcpOAuthBearer({sessions:f.sessions,token:pair.accessToken,resourcePath:SHARED});
  assert.ok(admitted.ok);
  const service=relayService({...f.context,principal:admitted.connection.access.principal,oauth:admitted.connection});
  return {grantId,connection:admitted.connection,service};
}
const nativeService=(f:Awaited<ReturnType<typeof relayFixture>>,sessionId:string)=>
  relayService({...f.context,oauth:undefined,authMode:"cli_login",relay:{...f.context.relay,sessionId}});

test("the retirement fence lifts once teardown completes and a rejoin gets a fresh identity",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  const original=f.world.agents.get("approved-agent")!;
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  const later=await laterConnection(f,null,true);
  await assert.rejects(later.service.join({}),/being retired after a disconnect/);
  await assert.rejects(nativeService(f,"fake-native-early").join({name:original.name}),/being retired after a disconnect/);
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
  assert.equal((await revocation(f)).outcome,"released");
  const joined=await later.service.join({});
  assert.equal(joined.name,original.name);
  const fresh=f.world.agents.get(original.name)!;
  assert.notEqual(fresh.id,original.id);
  assert.equal(later.connection.access.agentRemoteId,fresh.id);
  const native=await nativeService(f,"fake-native-after").join({name:"fake-native-fresh"});
  assert.equal(native.name,"fake-native-fresh");
});

test("the retirement fence does not block an identity another live grant or a native session already holds",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  const original=f.world.agents.get("approved-agent")!;
  const pinned=await laterConnection(f,original.id);
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  assert.equal((await pinned.service.join({})).name,original.name);
  assert.equal(pinned.connection.access.agentRemoteId,original.id);
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:1,pending:0});

  const g=await relayFixture(t);
  await nativeService(g,"fake-native-chat").join({name:"approved-agent"});
  await g.service.join({});
  const held=g.world.agents.get("approved-agent")!;
  await g.oauth.revokeMcpOAuthGrant(g.owner.grantId,"fake-disconnect");
  const unpinned=await laterConnection(g);
  assert.equal((await unpinned.service.join({})).name,held.name);
  assert.equal(unpinned.connection.access.agentRemoteId,held.id);
  assert.equal((await nativeService(g,"fake-native-chat").join({name:held.name})).name,held.name);
});

test("operator abandonment keeps the retirement fence while an older release is still in flight",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  const original=f.world.agents.get("approved-agent")!;
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  const {worker,reached,resume}=gated(f,"releaseHosted");
  const running=worker.drain();
  await reached;
  const store=new ControlPlaneStore(f.database,KEYRING,0,{tenancy:"multi"});
  try {
    assert.deepEqual(await store.abandonMcpOAuthCleanup({organizationId:f.owner.organizationId,
      workspaceId:f.owner.workspaceId,actor:{kind:"bootstrap"}}),{abandoned:1,revoked:0});
    assert.equal((await revocation(f)).outcome,"operator_abandoned");
    const later=await laterConnection(f);
    await assert.rejects(later.service.join({}),/being retired after a disconnect/);
    await assert.rejects(nativeService(f,"fake-native-reconnect").join({name:original.name}),/being retired after a disconnect/);
  } finally { resume(); }
  assert.deepEqual(await running,{completed:0,kept:0,pending:0});
  assert.equal(f.world.agents.has(original.name),false);
  // The abandoned row fences its immutable id permanently.
  await assert.rejects(nativeService(f,"fake-native-reconnect").join({name:original.name}),/being retired after a disconnect/);
  assert.equal((await f.database.query("SELECT id FROM mcp_oauth_grants WHERE agent_remote_id=$1",
    [original.id])).rows.length,1);
  assert.equal((await f.database.query("SELECT session_hash FROM hosted_relay_participants")).rows[0]!.session_hash,null);
});

test("a same-name grant issued after retirement began never inherits the agent and teardown releases it",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  const original=f.world.agents.get("approved-agent")!;
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  const later=await laterConnection(f,null,true);
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
  assert.equal((await revocation(f)).outcome,"released");
  assert.equal(f.world.agents.has(original.name),false);
  assert.equal((await f.database.query("SELECT agent_remote_id FROM mcp_oauth_grants WHERE id=$1",
    [later.grantId])).rows[0]!.agent_remote_id,null);
  await later.service.join({});
  assert.notEqual(later.connection.access.agentRemoteId,original.id);
});

test("terminal teardown outcomes complete the row once, log only the outcome and never release a foreign agent",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  const warn=t.mock.method(console,"warn",()=>undefined);
  f.world.agents.get("approved-agent")!.metadata.owner_hash="fake-other-owner";
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
  const row=await revocation(f);
  assert.equal(row.outcome,"metadata_mismatch");assert.ok(row.completed_at);
  assert.equal(releaseCount(f),0);assert.ok(f.world.agents.has("approved-agent"));
  f.advance();
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:0,pending:0});
  assert.equal(warn.mock.callCount(),1);
  const id=(await f.database.query<{id:string}>("SELECT id FROM mcp_oauth_revocations")).rows[0]!.id;
  assert.deepEqual(warn.mock.calls[0]!.arguments,["[mcp-oauth] teardown abandoned",{outcome:"metadata_mismatch",revocationId:id}]);
});

test("a workspace key sealed under a retired encryption key keeps teardown pending until it decrypts again",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  const warn=t.mock.method(console,"warn",()=>undefined);
  const retired={id:"fake-retired-key",key:Buffer.alloc(32,9)};
  await f.database.query("UPDATE workspaces SET relaycast_api_key_ciphertext=$2 WHERE id=$1",
    [f.owner.workspaceId,encryptSecret("rk_fake",retired)]);
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:0,pending:1});
  const row=await revocation(f);
  assert.equal(row.completed_at,null);assert.equal(row.outcome,null);assert.equal(row.attempts,1);
  assert.equal(new Date(row.next_attempt_at!).getTime(),f.clock.at+60_000);
  const id=(await f.database.query<{id:string}>("SELECT id FROM mcp_oauth_revocations")).rows[0]!.id;
  assert.deepEqual(warn.mock.calls.map(call=>call.arguments),[["[mcp-oauth] teardown key unavailable",{revocationId:id,attempts:1}]]);
  assert.equal(releaseCount(f),0);assert.ok(f.world.agents.has("approved-agent"));
  // The key is back (the replica got its keyring): the next due attempt releases.
  await f.database.query("UPDATE workspaces SET relaycast_api_key_ciphertext=$2 WHERE id=$1",
    [f.owner.workspaceId,encryptSecret("rk_fake",KEYRING.active)]);
  f.advance();
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
  assert.equal((await revocation(f)).outcome,"released");
  assert.equal(f.world.agents.has("approved-agent"),false);
});

test("an undecryptable workspace key ends teardown as decrypt_failed after the attempt limit",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  const warn=t.mock.method(console,"warn",()=>undefined);
  await f.database.query("UPDATE workspaces SET relaycast_api_key_ciphertext=$2 WHERE id=$1",
    [f.owner.workspaceId,encryptSecret("rk_fake",{id:"fake-retired-key",key:Buffer.alloc(32,9)})]);
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  for(let attempt=1;attempt<MCP_OAUTH_TEARDOWN_DECRYPT_MAX_ATTEMPTS;attempt++) {
    assert.deepEqual(await f.teardown.drain(),{completed:0,kept:0,pending:1});
    assert.equal((await revocation(f)).attempts,attempt);
    f.advance();
  }
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
  const row=await revocation(f);
  assert.equal(row.outcome,"decrypt_failed");assert.equal(row.attempts,MCP_OAUTH_TEARDOWN_DECRYPT_MAX_ATTEMPTS);
  const id=(await f.database.query<{id:string}>("SELECT id FROM mcp_oauth_revocations")).rows[0]!.id;
  const logged=warn.mock.calls.map(call=>call.arguments[0]);
  assert.equal(logged.filter(line=>line==="[mcp-oauth] teardown key unavailable").length,MCP_OAUTH_TEARDOWN_DECRYPT_MAX_ATTEMPTS-1);
  assert.deepEqual(warn.mock.calls.at(-1)!.arguments,["[mcp-oauth] teardown abandoned",{outcome:"decrypt_failed",revocationId:id}]);
  assert.equal(releaseCount(f),0);assert.ok(f.world.agents.has("approved-agent"));
});

test("a relocated relay workspace ends teardown as workspace_mismatch and a never-pinned grant as no_remote",async t=>{
  const f=await relayFixture(t);
  t.mock.method(console,"warn",()=>undefined);
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-unused-disconnect");
  assert.deepEqual(await f.teardown.drain(),{completed:1,kept:0,pending:0});
  assert.equal((await revocation(f)).outcome,"no_remote");
  const g=await relayFixture(t);await g.service.join({});
  await g.oauth.revokeMcpOAuthGrant(g.owner.grantId,"fake-disconnect");
  await g.database.query("UPDATE workspaces SET relaycast_workspace_id='fake-moved-workspace' WHERE id=$1",[g.owner.workspaceId]);
  assert.deepEqual(await g.teardown.drain(),{completed:1,kept:0,pending:0});
  assert.equal((await revocation(g)).outcome,"workspace_mismatch");
  assert.equal(releaseCount(g),0);assert.ok(g.world.agents.has("approved-agent"));
});

test("only the operator can abandon pending connector cleanup, which unblocks deletion but not live grants",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  const config=appConfig(),store=new ControlPlaneStore(f.database,KEYRING,0,{tenancy:"multi"});
  const server=createServer(createApp({config,store,messagingFetch:f.fetchImpl,mcpOAuthTeardown:f.teardown}));
  const base=await listen(server);t.after(()=>close(server));
  const item=`${base}/api/v1/organizations/${f.owner.organizationId}/workspaces/${f.owner.workspaceId}`;
  const operator={authorization:`Bearer ${config.bootstrapToken}`};
  const abandon=(headers:Record<string,string>,workspace=item)=>fetch(workspace+"/mcp-oauth/abandon-cleanup",{method:"POST",headers});
  const remove=()=>fetch(item,{method:"DELETE",headers:operator});
  for(const role of ["owner","admin"]) {
    await f.database.query("UPDATE organization_memberships SET role=$3 WHERE organization_id=$1 AND user_id=$2",
      [f.owner.organizationId,f.owner.userId,role]);
    const account=await f.database.transaction(tx=>store.issueBrowserSession(tx,{...f.owner,label:"fake-"+role}));
    const refused=await abandon({authorization:`Bearer ${account.accessToken}`});
    assert.equal(refused.status,403);assert.equal((await refused.json()).error,"operator_only");
  }
  // Nothing pending yet: a live grant still blocks deletion after an override.
  let response=await abandon(operator);
  assert.equal(response.status,200);assert.deepEqual(await response.json(),{abandoned:0});
  response=await remove();assert.equal(response.status,409);assert.equal((await response.json()).error,"workspace_in_use");
  response=await abandon(operator,`${base}/api/v1/organizations/${f.owner.organizationId}/workspaces/${randomUUID()}`);
  assert.equal(response.status,404);
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  f.world.failNext("POST","/v1/agents/release-exact",503);
  assert.deepEqual(await f.teardown.drain(),{completed:0,kept:0,pending:1});
  response=await remove();assert.equal(response.status,409);
  response=await abandon(operator);
  assert.equal(response.status,200);assert.deepEqual(await response.json(),{abandoned:1});
  assert.equal((await revocation(f)).outcome,"operator_abandoned");
  const audit=(await f.database.query<{target:string;actor_kind:string}>(
    "SELECT target,actor_kind FROM admin_audit_events WHERE action='mcp_oauth.cleanup_abandoned' ORDER BY target")).rows;
  assert.deepEqual(audit.map(row=>row.target),[`${f.owner.workspaceId} (0 pending)`,`${f.owner.workspaceId} (1 pending)`]);
  assert.ok(audit.every(row=>row.actor_kind==="bootstrap"));
  response=await remove();assert.equal(response.status,204);
});

test("with the module off the operator can revoke live grants and complete their cleanup so deletion proceeds",async t=>{
  const f=await relayFixture(t);await f.service.join({});
  const config=appConfig(false),store=new ControlPlaneStore(f.database,KEYRING,0,{tenancy:"multi"});
  const server=createServer(createApp({config,store,messagingFetch:f.fetchImpl}));
  const base=await listen(server);t.after(()=>close(server));
  const item=`${base}/api/v1/organizations/${f.owner.organizationId}/workspaces/${f.owner.workspaceId}`;
  const operator={authorization:`Bearer ${config.bootstrapToken}`};
  const abandon=(query="")=>fetch(item+"/mcp-oauth/abandon-cleanup"+query,{method:"POST",headers:operator});
  const remove=()=>fetch(item,{method:"DELETE",headers:operator});
  let response=await remove();assert.equal(response.status,409);assert.equal((await response.json()).error,"workspace_in_use");
  response=await abandon("?revoke_live=maybe");assert.equal(response.status,400);
  // Without the flag a live grant is untouched.
  response=await abandon("?revoke_live=false");
  assert.equal(response.status,200);assert.deepEqual(await response.json(),{abandoned:0});
  assert.equal((await f.database.query("SELECT revoked_at FROM mcp_oauth_grants WHERE id=$1",[f.owner.grantId])).rows[0]!.revoked_at,null);
  response=await abandon("?revoke_live=true");
  assert.equal(response.status,200);assert.deepEqual(await response.json(),{abandoned:1,revoked:1});
  const grant=(await f.database.query<{revoked_at:Date|null;revoked_reason:string|null}>(
    "SELECT revoked_at,revoked_reason FROM mcp_oauth_grants WHERE id=$1",[f.owner.grantId])).rows[0]!;
  assert.ok(grant.revoked_at);assert.equal(grant.revoked_reason,"operator_abandoned");
  const row=await revocation(f);
  assert.equal(row.outcome,"operator_abandoned");assert.ok(row.completed_at);
  const sessions=await f.database.query("SELECT 1 FROM mcp_oauth_sessions WHERE grant_id=$1 AND revoked_at IS NULL",[f.owner.grantId]);
  assert.equal(sessions.rows.length,0);
  const audit=(await f.database.query<{target:string}>(
    "SELECT target FROM admin_audit_events WHERE action='mcp_oauth.cleanup_abandoned' ORDER BY target")).rows;
  assert.deepEqual(audit.map(r=>r.target),[`${f.owner.workspaceId} (0 pending)`,`${f.owner.workspaceId} (1 pending, 1 live revoked)`]);
  response=await remove();assert.equal(response.status,204);
});

test("registration follows configured proxy trust without sharing an ingress bucket or trusting spoofed hops",async t=>{
  const f=await relayFixture(t),config=appConfig();
  const before=process.env.SELFHOST_TRUSTED_PROXIES;
  t.after(()=>{
    if(before===undefined)delete process.env.SELFHOST_TRUSTED_PROXIES;
    else process.env.SELFHOST_TRUSTED_PROXIES=before;
  });
  process.env.SELFHOST_TRUSTED_PROXIES="0";
  const store=new ControlPlaneStore(f.database,KEYRING,0,{tenancy:"multi"});
  const server=createServer(createApp({config,store,messagingFetch:f.fetchImpl,mcpOAuthTeardown:f.teardown}));
  const base=await listen(server);t.after(()=>close(server));
  const register=(forwarded:string)=>fetch(base+"/cloud/api/oauth/register",{method:"POST",
    headers:{"content-type":"application/json","x-forwarded-for":forwarded},
    body:JSON.stringify({redirect_uris:["https://client.example.test/cb"]}),
  });
  for(let index=0;index<20;index++)assert.equal((await register(`192.0.2.${index+1}`)).status,201);
  assert.equal((await register("198.51.100.100")).status,429,"untrusted forwarded addresses cannot evade the socket bucket");
  process.env.SELFHOST_TRUSTED_PROXIES="1";
  for(let index=0;index<20;index++)assert.equal((await register(`203.0.113.${index+1}, 198.51.100.7`)).status,201);
  assert.equal((await register("192.0.2.200, 198.51.100.7")).status,429,"spoofed leftmost hops cannot evade the trusted client bucket");
  assert.equal((await register("198.51.100.8")).status,201,"a different trusted client behind the same socket has its own budget");
  for(let index=0;index<20;index++)assert.equal((await register(`2001:db8:abcd:1::${index+1}`)).status,201);
  assert.equal((await register("2001:db8:abcd:1::ffff")).status,429,"IPv6 addresses in one /64 share a budget");
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

test("unavailable module answers 501 on OAuth paths, starts no worker and refuses stored bearers with 401",async t=>{
  for(const [reason,config] of [["oidc_signing_key",appConfig(true,{reason:"oidc_signing_key",detail:"fake detail"})],
    ["public_url",{...appConfig(),publicBaseUrl:"http://relay.example.test"}]] as const) {
    const f=await relayFixture(t);
    const store=new ControlPlaneStore(f.database,KEYRING,0,{tenancy:"multi"});
    const server=createServer(createApp({config,store,messagingFetch:f.fetchImpl}));
    const base=await listen(server);t.after(()=>close(server));
    for(const [path,init] of [["/cloud/.well-known/oauth-authorization-server",{}],["/.well-known/oauth-protected-resource/cloud"+SHARED,{}],
      ["/cloud/api/v1/oauth/grants",{}],["/cloud/api/oauth/token",{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body:"grant_type=x"}]] as const) {
      const response=await fetch(base+path,init);
      assert.equal(response.status,501,path);
      assert.equal(response.headers.get("cache-control"),"no-store");
      assert.deepEqual(await response.json(),{error:"mcp_oauth_unavailable",reason});
    }
    assert.equal((await fetch(base+"/mcp")).status,404);
    const rejected=await fetch(base+"/cloud"+SHARED,{method:"POST",headers:{
      authorization:"Bearer "+f.pair.accessToken,"content-type":"application/json",accept:"application/json, text/event-stream",
    },body:JSON.stringify(INITIALIZE)});
    assert.equal(rejected.status,401,reason);
    assert.ok(!rejected.headers.get("www-authenticate")!.includes("resource_metadata"));
  }
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
  const nativeBefore=(await f.database.query("SELECT id FROM token_sessions")).rows.length;
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
  assert.equal((await f.database.query("SELECT id FROM token_sessions")).rows.length,nativeBefore);

  const grantsPath="/cloud/api/v1/oauth/grants";
  const secondWorkspace=randomUUID(),foreignGrant=randomUUID();
  await f.database.query(`INSERT INTO workspaces
    (id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
    VALUES ($1,$2,'Other Workspace',$3,$4)`,[secondWorkspace,f.owner.organizationId,
    "fake-relay-"+secondWorkspace,encryptSecret("rk_other",KEYRING.active)]);
  await f.database.query(`INSERT INTO mcp_oauth_grants
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
  assert.ok((await f.database.query("SELECT revoked_at FROM mcp_oauth_grants WHERE id=$1",[f.owner.grantId])).rows[0]!.revoked_at);

  const removed=await fetch(base+"/api/v1/organizations/"+f.owner.organizationId+"/memberships/"+f.owner.userId,
    {method:"DELETE",headers:{authorization:"Bearer "+config.bootstrapToken}});
  assert.equal(removed.status,204);
  await f.teardown.drain();
  await f.database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')",
    [f.owner.organizationId,f.owner.userId]);
  assert.equal((await call(endpoint,init,{authorization:"Bearer "+pair.access_token})).status,401);
  assert.equal((await f.database.query("SELECT agent_remote_id FROM mcp_oauth_revocations WHERE agent_remote_id=$1",[pinned])).rows.length,1);
});

for (const actor of ["oauth", "native", "abandon-oauth"] as const) test("review repro: cleanup must retain an identity rejoined by " + actor + " during remote release", async t => {
  const f=await relayFixture(t);await f.service.join({});
  const original=f.world.agents.get("approved-agent")!;
  await f.oauth.revokeMcpOAuthGrant(f.owner.grantId,"fake-disconnect");
  let notify!:()=>void,release!:()=>void;
  const started=new Promise<void>(resolve=>{notify=resolve;});
  const held=new Promise<void>(resolve=>{release=resolve;});
  const originalClient=f.teardown.deps.client;
  const delayed:RelaycastClient={...originalClient,releaseHosted:async(key,name,id)=>{
    notify();await held;await originalClient.releaseHosted(key,name,id);
  }};
  const worker=new McpOAuthTeardown({...f.teardown.deps,client:delayed});
  const finished=worker.drain().then(value=>({value}),error=>({error}));
  await Promise.race([started,finished.then(result=>{if("error" in result)throw result.error;throw new Error("release not reached");})]);
  let connected=false, refused=false;
  let beforeJoin=0;
  try {
    if(actor==="abandon-oauth") {
      const store=new ControlPlaneStore(f.database,KEYRING,0,{tenancy:"multi"});
      try {
        const count=await store.abandonMcpOAuthCleanup({...f.owner,actor:{kind:"bootstrap"}});
        assert.ok(count!==null,"the operator target exists");
      } catch(error) {
        // Refusing abandonment while remote work is in flight is also safe.
        assert.match(String(error),/retir|teardown|cleanup|disconnect|connect|releas|pending|busy|in.?progress/i);
      }
    }
    if(actor!=="native") {
      const grantId=randomUUID(),tokenFamilyId=randomUUID();
      await f.database.query(`INSERT INTO mcp_oauth_grants
        (id,client_id,user_id,organization_id,workspace_id,agent_name,scopes,resource,token_family_id)
        SELECT $2,client_id,user_id,organization_id,workspace_id,agent_name,scopes,resource,$3
        FROM mcp_oauth_grants WHERE id=$1`,[f.owner.grantId,grantId,tokenFamilyId]);
      const pair=await f.database.transaction(tx=>f.sessions.issue(tx,{...f.owner,grantId,tokenFamilyId,scopes:["relay:mcp"]}));
      const admission=await admitMcpOAuthBearer({sessions:f.sessions,token:pair.accessToken,resourcePath:SHARED});
      assert.ok(admission.ok);
      const service=relayService({...f.context,principal:admission.connection.access.principal,oauth:admission.connection});
      beforeJoin=f.world.bodies.length;
      try {
        assert.equal((await service.join({})).name,original.name);
        connected=true;
        assert.equal(admission.connection.access.agentRemoteId,original.id);
      } catch(error) {
        assert.match(String(error),/retir|teardown|cleanup|disconnect|connect|releas|pending|busy|in.?progress/i);
        refused=true;
        assert.equal(f.world.bodies.length,beforeJoin,"retiring identity must be refused before Relaycast I/O");
        assert.equal((await f.database.query("SELECT agent_remote_id FROM mcp_oauth_grants WHERE id=$1",[grantId])).rows[0]!.agent_remote_id,null);
      }
    } else {
      const service=relayService({...f.context,oauth:undefined,authMode:"cli_login",
        relay:{...f.context.relay,sessionId:"fake-native-reconnect"}});
      beforeJoin=f.world.bodies.length;
      try {
        assert.equal((await service.join({name:original.name})).name,original.name);
        connected=true;
        assert.ok((await f.database.query("SELECT session_hash FROM hosted_relay_participants")).rows[0]!.session_hash);
      } catch(error) {
        assert.match(String(error),/retir|teardown|cleanup|disconnect|connect|releas|pending|busy|in.?progress/i);
        refused=true;
        assert.equal(f.world.bodies.length,beforeJoin,"retiring native identity must be refused before Relaycast I/O");
        assert.equal((await f.database.query("SELECT session_hash FROM hosted_relay_participants")).rows[0]!.session_hash,null);
      }
    }
    assert.equal(f.world.agents.get(original.name)!.id,original.id,"join succeeded against the live original identity");
  } finally {release();}
  const result=await finished;if("error" in result)throw result.error;
  if(connected) assert.equal(f.world.agents.get(original.name)?.id,original.id,"cleanup deleted an identity after a successful reconnect");
  else assert.ok(refused,"reconnect must either be refused or retain its identity");
});

test("an OAuth grant stays on its approved agent even with a Desktop marker and a native chat id",async t=>{
  const f=await relayFixture(t);
  f.world.addAgent("peer");
  const marked=desktopCallContext(
    {method:"tools/call",params:{name:"send_relay_message",arguments:{},_meta:{threadId:randomUUID()}}},
    new Headers({"x-agent-relay-desktop":"1"}));
  assert.equal(marked.required,true);
  const service=relayService({...f.context,desktopCall:marked});
  const sent=await service.send({to:"peer",text:"from the grant"});
  assert.equal(sent.from,"approved-agent");
});

test("OAuth consent and live actor admission never adopt provider binding identities",async t=>{
  const f=await relayFixture(t),config=appConfig();
  const store=new ControlPlaneStore(f.database,KEYRING,0,{tenancy:"multi"});
  const account=await f.database.transaction(tx=>store.issueBrowserSession(tx,{...f.owner,label:"capy-domain-test"}));
  const trap={agentFor:async()=>{assert.fail("OAuth must never invoke native Capy authority");}};
  const server=createServer(createApp({config,store,messagingFetch:f.fetchImpl,mcpOAuthTeardown:f.teardown,capy:trap}));
  const base=await listen(server);t.after(()=>close(server));
  const metadata={source:HOSTED_SOURCE,cloud_workspace_id:f.owner.workspaceId,owner_hash:ownerHash(f.owner.userId)};
  const remote=f.world.addAgent("approved-agent",metadata);
  const check=async(name:string)=>{
    const response=await fetch(base+"/cloud/api/oauth/authorize/agent-name?"+new URLSearchParams({workspace_id:f.owner.workspaceId,name}),
      {headers:{cookie:"agent_relay_session="+account.accessToken}});
    assert.equal(response.status,200);return (await response.json()).status;
  };
  assert.equal(await check(remote.name),"yours");
  for(const marker of [{capy_binding_id:randomUUID()},{capy_binding_id:null},{created_by:"capy-binding"},
    {factory_binding_id:randomUUID()},{factory_binding_id:null},{created_by:"factory-binding"},
    {amp_binding_id:randomUUID()},{amp_binding_id:null},{created_by:"amp-binding"}]) {
    remote.metadata={...metadata,...marker};
    assert.equal(await check(remote.name),"taken");
    await assert.rejects(relayService({...f.context,capy:trap}).join({name:remote.name}),/name is already taken/);
  }
  assert.equal((await f.database.query("SELECT id FROM hosted_relay_participants")).rows.length,0);
  assert.equal((await f.database.query("SELECT agent_remote_id FROM mcp_oauth_grants WHERE id=$1",[f.owner.grantId])).rows[0]!.agent_remote_id,null);
  assert.equal(f.world.bodies.some(call=>call.path.includes("takeover")),false);
  f.world.addAgent("capy-support",metadata);
  assert.equal(await check("capy-support"),"yours","name prefix alone does not reserve provider custody");
});

test("set_relay_agent_card on an OAuth grant writes its approved agent with the connector kind",async t=>{
  const f=await relayFixture(t);
  await f.service.join({});
  const card={description:"Answers in ChatGPT.",skills:[]};
  const set=await f.service.setCard(card) as Record<string,any>;
  assert.equal(set.name,"approved-agent");
  assert.equal(f.world.agents.get("approved-agent")!.metadata.kind,"hosted");
  await f.database.query("UPDATE mcp_oauth_clients SET redirect_uris=$2 WHERE client_id=$1",[f.clientId,["https://chatgpt.com/connector/oauth/cb"]]);
  await f.service.setCard(card);
  const metadata=f.world.agents.get("approved-agent")!.metadata;
  assert.equal(metadata.kind,"chatgpt");
  assert.equal(metadata.owner_name,"Fake User");
  assert.equal(metadata.source,HOSTED_SOURCE);
  assert.equal(metadata.owner_hash,ownerHash(f.owner.userId));
});
