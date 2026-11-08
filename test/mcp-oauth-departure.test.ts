import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { McpOAuthStore } from "../src/mcp/oauth/store.js";
import { createMcpOAuthProtocol,pkceS256 } from "../src/mcp/oauth/protocol.js";
import { revokeOrganizationMcpOAuthGrants } from "../src/mcp/oauth/revocations.js";
import { PGliteDatabase,listen,close } from "./support/harness.js";

const ORIGIN="https://relay.example.test",RESOURCE=`${ORIGIN}/cloud/api/v1/mcp/shared-sessions`,VERIFIER="a".repeat(43);
const KEYRING={ active:{ id:"fake-key",key:Buffer.alloc(32,7) } };

async function fixture(t:test.TestContext) {
  const database=new PGliteDatabase();t.after(()=>database.close());await migrate(database);
  const organizationId=randomUUID(),ownerId=randomUUID(),userId=randomUUID();
  await database.query("INSERT INTO selfhost_organizations(id,name) VALUES ($1,'Fake Org')",[organizationId]);
  for(const [id,role] of [[ownerId,"owner"],[userId,"member"]]) {
    await database.query("INSERT INTO selfhost_users(id,email,name) VALUES ($1,$2,'Fake User')",[id,`fake-${id}@example.test`]);
    await database.query("INSERT INTO selfhost_organization_memberships(organization_id,user_id,role) VALUES ($1,$2,$3)",[organizationId,id,role]);
  }
  const store=new ControlPlaneStore(database,KEYRING,0,{tenancy:"multi"});
  const protocol=createMcpOAuthProtocol({publicOrigin:ORIGIN,enabledResources:["/api/v1/mcp/shared-sessions"]});
  const oauth=new McpOAuthStore(database,{protocol,tenancyMode:"multi",isGrokRoutine:()=>false});
  const client=await oauth.registerMcpOAuthClient({clientName:"fake-client",redirectUris:["https://client.example.test/cb"]});
  const result=protocol.validateAuthorizationRequest({client_id:client.clientId,response_type:"code",redirect_uri:client.redirectUris[0],
    code_challenge:pkceS256(VERIFIER),code_challenge_method:"S256",resource:RESOURCE},client);
  assert.ok(result.ok);
  const pairs=[];
  for(let i=0;i<2;i++) {
    const workspaceId=randomUUID();
    await database.query(`INSERT INTO selfhost_workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
      VALUES ($1,$2,'Fake Workspace',$3,'fake-envelope')`,[workspaceId,organizationId,`fake-${workspaceId}`]);
    const consent={userId,organizationId,workspaceId,agentName:"fake-agent"};
    const code=await oauth.createMcpOAuthAuthorizationCode(result.value,consent);
    const issued=await oauth.exchangeMcpOAuthAuthorizationCode({code,clientId:client.clientId,redirectUri:client.redirectUris[0],codeVerifier:VERIFIER,resource:undefined});
    assert.ok(issued.ok);
    const pending=await oauth.createMcpOAuthAuthorizationCode(result.value,consent);
    pairs.push({...issued.body,pending});
  }
  const config:SelfhostConfig={databaseUrl:"unused",publicBaseUrl:ORIGIN,relaycastUrl:"http://unused.test",
    relaycastPublicUrl:"https://relay.example.test",relayauthUrl:null,relayauthApiKey:null,
    relayhistoryUrl:"http://unused.test",relayhistoryPublicUrl:"https://history.example.test",bootstrapToken:"fake-bootstrap-at-least-thirty-two-bytes",
    encryptionKeyring:KEYRING,internalServiceToken:null,oauthRedirectUrl:`${ORIGIN}/unused`,dashboardUrl:ORIGIN,host:"127.0.0.1",port:3000};
  const count=async(table:"sessions"|"revocations")=>(await database.query<{n:number}>(`SELECT count(*)::int AS n FROM selfhost_mcp_oauth_${table}`)).rows[0]!.n;
  return {database,store,oauth,organizationId,ownerId,userId,client,pairs,config,count};
}

test("membership HTTP removal consumes the real OAuth departure hook; rejoin cannot revive either workspace",async t=>{
  const f=await fixture(t),server=createServer(createApp({config:f.config,store:f.store}));
  const base=await listen(server);t.after(()=>close(server));
  const response=await fetch(`${base}/api/v1/organizations/${f.organizationId}/memberships/${f.userId}`,{
    method:"DELETE",headers:{authorization:`Bearer ${f.config.bootstrapToken}`}});
  assert.equal(response.status,204);
  assert.equal(await f.store.memberRole(f.organizationId,f.userId),null);
  assert.equal(await f.count("revocations"),2);assert.equal(await f.count("sessions"),2);
  await f.database.query("INSERT INTO selfhost_organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')",[f.organizationId,f.userId]);
  for(const pair of f.pairs) {
    assert.equal(await f.oauth.sessions.resolveAccessToken(pair.access_token,RESOURCE),null);
    assert.equal((await f.oauth.refreshMcpOAuthToken({refreshToken:pair.refresh_token,clientId:f.client.clientId,resource:undefined})).ok,false);
    assert.equal((await f.oauth.exchangeMcpOAuthAuthorizationCode({code:pair.pending,clientId:f.client.clientId,
      redirectUri:f.client.redirectUris[0],codeVerifier:VERIFIER,resource:undefined})).ok,false);
  }
});

test("departure callback failure rolls back membership, family revocation and durable intent together",async t=>{
  const f=await fixture(t);
  await assert.rejects(f.store.deleteMembership(f.organizationId,f.userId,async(tx)=>{
    await revokeOrganizationMcpOAuthGrants(tx,{organizationId:f.organizationId,userId:f.userId});throw new Error("fake departure failure");
  }),/fake departure failure/);
  assert.equal(await f.store.memberRole(f.organizationId,f.userId),"member");
  assert.equal(await f.count("revocations"),0);
  for(const pair of f.pairs) assert.ok(await f.oauth.sessions.resolveAccessToken(pair.access_token,RESOURCE));
});

test("last-owner refusal does not invoke departure; retry of an absent member can repair stale credentials",async t=>{
  const f=await fixture(t);let called=false;
  assert.equal(await f.store.deleteMembership(f.organizationId,f.ownerId,async()=>{called=true;}),false);
  assert.equal(called,false);assert.equal(await f.store.memberRole(f.organizationId,f.ownerId),"owner");
  await f.database.query("DELETE FROM selfhost_organization_memberships WHERE organization_id=$1 AND user_id=$2",[f.organizationId,f.userId]);
  assert.equal(await f.store.deleteMembership(f.organizationId,f.userId,(tx)=>revokeOrganizationMcpOAuthGrants(tx,{organizationId:f.organizationId,userId:f.userId})),false);
  assert.equal(await f.count("revocations"),2);
});

test("Factory and OAuth departure cleanup commit or roll back together after main integration",async t=>{
  const {startFactoryEnv,connectAndBind,bindingRow,removeMember}=await import("./factory-helpers.js");
  const env=await startFactoryEnv(t),bound=await connectAndBind(env,{token:env.adminToken});
  const origin=new URL(env.config.publicBaseUrl).origin;
  const resource=`${origin}/cloud/api/v1/mcp/shared-sessions`;
  const protocol=createMcpOAuthProtocol({publicOrigin:origin,enabledResources:["/api/v1/mcp/shared-sessions"]});
  const oauth=new McpOAuthStore(env.database,{protocol,tenancyMode:"single",isGrokRoutine:()=>false});
  const client=await oauth.registerMcpOAuthClient({clientName:"fake-client",redirectUris:["https://client.example.test/cb"]});
  const request=protocol.validateAuthorizationRequest({client_id:client.clientId,response_type:"code",redirect_uri:client.redirectUris[0],
    code_challenge:pkceS256(VERIFIER),code_challenge_method:"S256",resource},client);
  assert.ok(request.ok);
  const owner={userId:env.adminId,organizationId:env.organizationId,workspaceId:env.workspaceId,agentName:"fake-oauth-agent"};
  const code=await oauth.createMcpOAuthAuthorizationCode(request.value,owner);
  const issued=await oauth.exchangeMcpOAuthAuthorizationCode({code,clientId:client.clientId,
    redirectUri:client.redirectUris[0],codeVerifier:VERIFIER,resource:undefined});
  assert.ok(issued.ok);
  const store=new ControlPlaneStore(env.database,env.config.encryptionKeyring,0);
  await assert.rejects(store.deleteMembership(env.organizationId,env.adminId,async tx=>{
    await env.module.purgeMemberInTx(tx,env.organizationId,env.adminId);
    await revokeOrganizationMcpOAuthGrants(tx,owner);
    throw new Error("fake combined cleanup abort");
  }),/fake combined cleanup abort/);
  assert.equal((await bindingRow(env,bound.binding_id)).state,"bound");
  assert.ok(await oauth.sessions.resolveAccessToken(issued.body.access_token,resource));
  assert.equal(await store.memberRole(env.organizationId,env.adminId),"admin");
  assert.equal((await env.database.query("SELECT id FROM selfhost_mcp_oauth_revocations")).rows.length,0);
  assert.equal((await removeMember(env,env.adminId)).status,204);
  const retired=await bindingRow(env,bound.binding_id);
  assert.equal(retired.state,"retired");assert.equal(retired.hosted_token_envelope,null);
  assert.ok(env.relay.released.includes(bound.agent.id));
  assert.equal((await env.database.query("SELECT id FROM selfhost_mcp_oauth_revocations")).rows.length,1);
  await env.database.query("INSERT INTO selfhost_organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'admin')",[env.organizationId,env.adminId]);
  assert.equal(await oauth.sessions.resolveAccessToken(issued.body.access_token,resource),null);
});
