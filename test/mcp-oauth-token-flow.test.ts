import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { ControlPlaneStore } from "../src/store.js";
import { migrate } from "../src/migrations.js";
import { hashSecret } from "../src/crypto.js";
import { lockUser,lockOrganization } from "../src/tenancy.js";
import { createMcpOAuthProtocol,pkceS256 } from "../src/mcp/oauth/protocol.js";
import { McpOAuthStore,type McpOAuthTokenResult } from "../src/mcp/oauth/store.js";
import { PGliteDatabase } from "./support/harness.js";

const ORIGIN="https://relay.example.test",SHARED="/api/v1/mcp/shared-sessions",EVENTS="/api/v1/mcp/relay-events";
const VERIFIER="a".repeat(43);
const KEYRING={ active:{ id:"fake-key",key:Buffer.alloc(32,7) } };

function issued(result:McpOAuthTokenResult) {
  assert.ok(result.ok,JSON.stringify(result));
  return result.body;
}

async function fixture(t:test.TestContext) {
  const database=new PGliteDatabase(); t.after(()=>database.close()); await migrate(database);
  const owner={ userId:randomUUID(),organizationId:randomUUID(),workspaceId:randomUUID(),agentName:"fake-agent" };
  await database.query("INSERT INTO selfhost_users(id,email,name) VALUES ($1,'fake@example.test','Fake User')",[owner.userId]);
  await database.query("INSERT INTO selfhost_organizations(id,name) VALUES ($1,'Fake Org')",[owner.organizationId]);
  await database.query("INSERT INTO selfhost_organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'owner')",[owner.organizationId,owner.userId]);
  await database.query(`INSERT INTO selfhost_workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
    VALUES ($1,$2,'Fake Workspace','fake-relay','fake-envelope')`,[owner.workspaceId,owner.organizationId]);
  let now=new Date(),signerFails=false;
  const signed:Array<Record<string,unknown>>=[];
  const protocol=createMcpOAuthProtocol({ publicOrigin:ORIGIN,enabledResources:[SHARED,EVENTS,"/mcp"],
    mountedEndpoints:["authorization","token","jwks"],oidcEnabled:true });
  const store=new McpOAuthStore(database,{ protocol,tenancyMode:"multi",now:()=>new Date(now),
    isGrokRoutine:request=>request.resourcePath===EVENTS && new URL(request.redirectUri).hostname==="x.ai",
    issueIdToken:input=>{ if(signerFails) throw new Error("fake signer failure"); signed.push(input); return "fake-id-token"; },
  });
  const client=await store.registerMcpOAuthClient({ clientName:"fake-client",redirectUris:["https://x.ai/callback"] });
  function authorization(overrides:Record<string,string>={}) {
    const result=protocol.validateAuthorizationRequest({ client_id:client.clientId,redirect_uri:client.redirectUris[0]!,
      response_type:"code",code_challenge:pkceS256(VERIFIER),code_challenge_method:"S256",resource:`${ORIGIN}/cloud${SHARED}`,...overrides },client);
    assert.ok(result.ok); return result.value;
  }
  const exchange=(code:string,overrides:Record<string,string>={})=>store.exchangeMcpOAuthAuthorizationCode({ code,
    clientId:client.clientId,codeVerifier:VERIFIER,redirectUri:client.redirectUris[0],resource:undefined,...overrides });
  const create=(overrides:Record<string,string>={},continuation?:string,agentName=owner.agentName)=>
    store.createMcpOAuthAuthorizationCode(authorization(overrides),{ ...owner,agentName },continuation);
  async function grantId(code:string) {
    return (await database.query<{ grant_id:string }>("SELECT grant_id FROM selfhost_mcp_oauth_authorization_codes WHERE code_hash=$1",[hashSecret(code)])).rows[0]!.grant_id;
  }
  const count=(table:"grants"|"sessions"|"revocations")=>database.query<{ n:number }>(`SELECT count(*)::int AS n FROM selfhost_mcp_oauth_${table}`).then(r=>r.rows[0]!.n);
  return { database,owner,store,client,create,exchange,grantId,count,signed,authorization,
    advance:(ms:number)=>{ now=new Date(now.getTime()+ms); },signerFailure:(value:boolean)=>{ signerFails=value; } };
}

test("code exchange creates only an OAuth pair with source TTL/scope and exact consumed-session receipt",async t=>{
  const f=await fixture(t),code=await f.create(),body=issued(await f.exchange(code));
  assert.match(body.access_token,/^mcp_at_/); assert.match(body.refresh_token,/^mcp_rt_/);
  assert.equal(body.expires_in,3600); assert.equal(body.scope,"relay:mcp");
  const access=await f.store.sessions.resolveAccessToken(body.access_token,`${ORIGIN}/cloud${SHARED}`);
  assert.ok(access); assert.equal(access.principal.organizationId,f.owner.organizationId);
  const row=(await f.database.query("SELECT * FROM selfhost_mcp_oauth_authorization_codes")).rows[0]!;
  assert.equal(row.issued_session_id,access.principal.sessionId); assert.ok(row.consumed_at);
  assert.equal(row.grant_id,access.grantId);
  const general=new ControlPlaneStore(f.database,KEYRING,0,{ tenancy:"multi" });
  assert.equal(await general.authenticateAccessToken(body.access_token),null);
  assert.equal(await general.refresh(body.refresh_token),null);
  assert.equal((await f.database.query("SELECT id FROM selfhost_token_sessions")).rows.length,0);
});

test("client/redirect/resource/PKCE errors cannot burn a code or revoke the legitimate pair",async t=>{
  const f=await fixture(t),code=await f.create();
  const invalid:Array<Record<string,string>>=[{ clientId:"mcpc_fake_other" },{ redirectUri:"https://evil.example.test/cb" },
    { resource:`${ORIGIN}/mcp` },{ codeVerifier:"b".repeat(43) },{ codeVerifier:"bad" }];
  for(const override of invalid) {
    const response=await f.exchange(code,override); assert.equal(response.ok,false);
    assert.equal((await f.database.query("SELECT consumed_at FROM selfhost_mcp_oauth_authorization_codes")).rows[0]!.consumed_at,null);
  }
  const body=issued(await f.exchange(code));
  assert.equal((await f.exchange(code,{ codeVerifier:"b".repeat(43) })).ok,false);
  assert.ok(await f.store.sessions.resolveAccessToken(body.access_token,`${ORIGIN}/cloud${SHARED}`));
  assert.equal(await f.count("revocations"),0);
});

test("verified basic code replay revokes its family and persists one durable teardown intent",async t=>{
  const f=await fixture(t),code=await f.create(),body=issued(await f.exchange(code));
  assert.equal((await f.exchange(code)).ok,false);
  assert.equal(await f.store.sessions.resolveAccessToken(body.access_token,`${ORIGIN}/cloud${SHARED}`),null);
  const event=(await f.database.query("SELECT * FROM selfhost_mcp_oauth_revocations")).rows[0]!;
  assert.equal(event.reason,"authorization_code_replayed"); assert.equal(event.completed_at,null);
  await f.exchange(code); assert.equal(await f.count("revocations"),1);
});

test("Events continuation retains grant/family; old-code replay retires only its own receipt",async t=>{
  const f=await fixture(t),request={ resource:`${ORIGIN}/cloud${EVENTS}`,scope:"relay:events" };
  const oldCode=await f.create(request),old=issued(await f.exchange(oldCode)),id=await f.grantId(oldCode);
  const oldAccess=await f.store.sessions.resolveAccessToken(old.access_token,request.resource);
  const nextCode=await f.create({ ...request,scope:"relay:events relay:mcp relay:agents" },id.toUpperCase()),next=issued(await f.exchange(nextCode));
  const nextAccess=await f.store.sessions.resolveAccessToken(next.access_token,request.resource);
  assert.equal(nextAccess!.grantId,id); assert.equal(nextAccess!.principal.tokenFamilyId,oldAccess!.principal.tokenFamilyId);
  assert.equal(await f.count("grants"),1);
  assert.deepEqual((await f.store.sessions.resolveAccessToken(old.access_token,request.resource))!.principal.scopes,["relay:events"]);
  assert.equal((await f.exchange(oldCode)).ok,false);
  assert.equal(await f.store.sessions.resolveAccessToken(old.access_token,request.resource),null);
  assert.ok(await f.store.sessions.resolveAccessToken(next.access_token,request.resource));
  assert.equal(await f.count("revocations"),0);
  assert.equal((await f.store.refreshMcpOAuthToken({ refreshToken:old.refresh_token,clientId:f.client.clientId,resource:undefined })).ok,false);
  assert.ok(await f.store.sessions.resolveAccessToken(next.access_token,request.resource));
});

test("legacy continued grant without marker/receipt never revokes unrelated continued pairs",async t=>{
  const f=await fixture(t),request={ resource:`${ORIGIN}/cloud${EVENTS}`,scope:"relay:events" };
  const code=await f.create(request); issued(await f.exchange(code)); const id=await f.grantId(code);
  const nextCode=await f.create(request,id),next=issued(await f.exchange(nextCode));
  await f.database.query("UPDATE selfhost_mcp_oauth_grants SET continued_at=NULL WHERE id=$1",[id]);
  await f.database.query("UPDATE selfhost_mcp_oauth_authorization_codes SET issued_session_id=NULL WHERE grant_id=$1",[id]);
  assert.equal((await f.exchange(code)).ok,false);
  assert.ok(await f.store.sessions.resolveAccessToken(next.access_token,request.resource));
  assert.ok((await f.database.query("SELECT continued_at FROM selfhost_mcp_oauth_grants WHERE id=$1",[id])).rows[0]!.continued_at);
  assert.equal(await f.count("revocations"),0);
});

test("two pending Grok codes cannot establish duplicate connections at redemption",async t=>{
  const f=await fixture(t),request={ resource:`${ORIGIN}/cloud${EVENTS}`,scope:"relay:events" };
  const first=await f.create(request),second=await f.create(request);
  issued(await f.exchange(first));
  const collision=await f.exchange(second); assert.ok(!collision.ok); assert.equal(collision.status,409);
  assert.equal(collision.error.error,"agent_name_taken"); assert.equal(await f.count("grants"),1); assert.equal(await f.count("sessions"),1);
});

test("refresh client/resource bindings precede rotation; old-token grace refuses then revokes only its grant",async t=>{
  const f=await fixture(t),code=await f.create(),body=issued(await f.exchange(code));
  const unrelated=issued(await f.exchange(await f.create({},undefined,"fake-other-agent")));
  const refresh=(clientId=f.client.clientId,resource:string|undefined=undefined)=>f.store.refreshMcpOAuthToken({ refreshToken:body.refresh_token,clientId,resource });
  assert.equal((await refresh("mcpc_fake_other")).ok,false);
  assert.equal((await refresh(f.client.clientId,`${ORIGIN}/mcp`)).ok,false);
  const next=issued(await refresh());
  assert.equal((await refresh()).ok,false);
  assert.ok(await f.store.sessions.resolveAccessToken(next.access_token,`${ORIGIN}/cloud${SHARED}`));
  f.advance(31_000);
  assert.equal((await refresh("mcpc_fake_other")).ok,false);
  assert.equal((await refresh(f.client.clientId,`${ORIGIN}/mcp`)).ok,false);
  assert.equal(await f.count("revocations"),0);
  assert.equal((await refresh()).ok,false);
  assert.equal(await f.store.sessions.resolveAccessToken(next.access_token,`${ORIGIN}/cloud${SHARED}`),null);
  assert.ok(await f.store.sessions.resolveAccessToken(unrelated.access_token,`${ORIGIN}/cloud${SHARED}`));
  assert.equal((await f.database.query("SELECT reason FROM selfhost_mcp_oauth_revocations")).rows[0]!.reason,"refresh_token_reused");
});

test("OIDC failure rolls back code/grant/session; nonce and signer inputs are source-bound on retry",async t=>{
  const f=await fixture(t),code=await f.create({ scope:"openid relay:mcp",nonce:"fake-nonce" });
  f.signerFailure(true); await assert.rejects(f.exchange(code),/fake signer failure/);
  assert.equal(await f.count("grants"),0); assert.equal(await f.count("sessions"),0);
  assert.equal((await f.database.query("SELECT consumed_at FROM selfhost_mcp_oauth_authorization_codes")).rows[0]!.consumed_at,null);
  f.signerFailure(false); const body=issued(await f.exchange(code)); assert.equal(body.id_token,"fake-id-token");
  assert.equal(f.signed[0]!.nonce,"fake-nonce"); assert.equal(f.signed[0]!.issuer,`${ORIGIN}/cloud`);
  assert.equal(f.signed[0]!.sectorIdentifier,"x.ai"); assert.equal(f.signed[0]!.userId,f.owner.userId);
  assert.equal(f.signed[0]!.accessToken,body.access_token);
});

test("revocation conceals unknown/mismatched clients, kills its family and queues teardown idempotently",async t=>{
  const f=await fixture(t),body=issued(await f.exchange(await f.create()));
  await f.store.revokeMcpOAuthToken({ token:"fake-unknown",clientId:f.client.clientId });
  await f.store.revokeMcpOAuthToken({ token:body.access_token,clientId:"mcpc_fake_other" });
  assert.ok(await f.store.sessions.resolveAccessToken(body.access_token,`${ORIGIN}/cloud${SHARED}`));
  await f.store.revokeMcpOAuthToken({ token:body.refresh_token,clientId:f.client.clientId });
  await f.store.revokeMcpOAuthToken({ token:body.access_token,clientId:f.client.clientId });
  assert.equal(await f.store.sessions.resolveAccessToken(body.access_token,`${ORIGIN}/cloud${SHARED}`),null);
  assert.equal(await f.count("revocations"),1);
  assert.equal((await f.database.query("SELECT reason FROM selfhost_mcp_oauth_revocations")).rows[0]!.reason,"client_revoked");
});

test("departure hook expires outstanding codes and revokes families before a later rejoin",async t=>{
  const f=await fixture(t),pending=await f.create(),body=issued(await f.exchange(await f.create()));
  await f.database.transaction(async tx=>{
    await lockUser(tx,f.owner.userId); await lockOrganization(tx,f.owner.organizationId);
    await f.store.revokeWorkspaceMcpOAuthGrants(tx,f.owner);
    await tx.query("DELETE FROM selfhost_organization_memberships WHERE organization_id=$1 AND user_id=$2",[f.owner.organizationId,f.owner.userId]);
  });
  await f.database.query("INSERT INTO selfhost_organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')",[f.owner.organizationId,f.owner.userId]);
  assert.equal((await f.exchange(pending)).ok,false);
  assert.equal(await f.store.sessions.resolveAccessToken(body.access_token,`${ORIGIN}/cloud${SHARED}`),null);
  assert.equal((await f.store.refreshMcpOAuthToken({ refreshToken:body.refresh_token,clientId:f.client.clientId,resource:undefined })).ok,false);
  assert.equal(await f.count("revocations"),1);
});

test("expired authorization code creates no grant or session",async t=>{
  const f=await fixture(t),code=await f.create(); f.advance(121_000);
  assert.equal((await f.exchange(code)).ok,false); assert.equal(await f.count("grants"),0); assert.equal(await f.count("sessions"),0);
});

test("setup correlation and connection management remain live and explicitly tenant-bound",async t=>{
  const f=await fixture(t),code=await f.create(),handoff=`mcpos_${hashSecret(code)}`,resource=`${ORIGIN}/cloud${SHARED}`;
  assert.equal(await f.store.isOAuthSetupHandoffPending(f.owner,handoff),true);
  assert.equal(await f.store.getOAuthGrantForSetupHandoff(f.owner,handoff),null);
  issued(await f.exchange(code)); const id=await f.grantId(code);
  assert.equal(await f.store.isOAuthSetupHandoffPending(f.owner,handoff),false);
  assert.equal((await f.store.getOAuthGrantForSetupHandoff(f.owner,handoff))!.id,id);
  assert.equal(await f.store.isOAuthGrantActive(id,f.owner),true);
  assert.equal(await f.store.hasMcpOAuthGrantForWorkspace(f.owner,resource),true);
  assert.equal((await f.store.listMcpOAuthGrantsForUser(f.owner,{ clientId:f.client.clientId,resource })).length,1);
  const wrong={ ...f.owner,workspaceId:randomUUID() };
  assert.equal(await f.store.getOAuthGrant(id,wrong),null);
  assert.equal(await f.store.getOAuthGrantForSetupHandoff(wrong,handoff),null);
  assert.deepEqual(await f.store.listMcpOAuthGrantsForUser(wrong),[]);
  await f.store.revokeMcpOAuthGrant(id,"fake-management-revoke");
  assert.equal(await f.store.isOAuthGrantActive(id,f.owner),false);
  assert.equal(await f.store.hasMcpOAuthGrantForWorkspace(f.owner,resource),false);
  assert.deepEqual(await f.store.listMcpOAuthGrantsForUser(f.owner),[]);
});


test("redemption requires redirect_uri iff authorization supplied it, without burning rejected codes",async t=>{
  const f=await fixture(t),code=await f.create();
  const exchange=(value:string,redirectUri?:string)=>f.store.exchangeMcpOAuthAuthorizationCode({
    code:value,clientId:f.client.clientId,codeVerifier:VERIFIER,redirectUri,resource:undefined });
  assert.equal((await exchange(code)).ok,false);
  issued(await f.exchange(code));
  const request=f.authorization();
  // Presence is derived by protocol parsing, never from a public internal flag.
  const omitted=f.store.options.protocol.validateAuthorizationRequest({ client_id:f.client.clientId,response_type:"code",
    code_challenge:pkceS256(VERIFIER),code_challenge_method:"S256",resource:request.resource },f.client);
  assert.ok(omitted.ok); assert.equal(omitted.value.redirectUriRequired,false);
  const implicit=await f.store.createMcpOAuthAuthorizationCode(omitted.value,f.owner);
  assert.equal((await exchange(implicit,"https://evil.example.test/cb")).ok,false);
  issued(await exchange(implicit));
});

test("receipt FK accepts only the code's OAuth session, grant and tenant tuple",async t=>{
  const f=await fixture(t),first=await f.create(); issued(await f.exchange(first));
  const second=await f.create({},undefined,"fake-other-agent"); issued(await f.exchange(second));
  const row=(await f.database.query<{ issued_session_id:string }>(
    "SELECT issued_session_id FROM selfhost_mcp_oauth_authorization_codes WHERE code_hash=$1",[hashSecret(second)])).rows[0]!;
  for(const id of [randomUUID(),row.issued_session_id]) {
    await assert.rejects(f.database.query("UPDATE selfhost_mcp_oauth_authorization_codes SET issued_session_id=$2 WHERE code_hash=$1",
      [hashSecret(first),id]),/foreign key/);
  }
  await assert.rejects(f.database.query("UPDATE selfhost_mcp_oauth_authorization_codes SET grant_id=NULL WHERE code_hash=$1",[hashSecret(first)]),/check constraint/);
});

test("connection filters canonicalize hints and trailing slash but reject foreign origins",async t=>{
  const f=await fixture(t);
  const resource=`${ORIGIN}/cloud${EVENTS}`;
  issued(await f.exchange(await f.create({ resource,scope:"relay:events" })));
  for(const value of [resource,`${resource}/`,`${resource}?agent_name=fake-agent`]) {
    assert.equal((await f.store.listMcpOAuthGrantsForUser(f.owner,{ clientId:f.client.clientId,resource:value })).length,1,value);
  }
  assert.deepEqual(await f.store.listMcpOAuthGrantsForUser(f.owner,{ clientId:f.client.clientId,resource:`https://evil.example.test/cloud${SHARED}` }),[]);
});

test("organization departure revokes every workspace while preserving session receipts and durable intents",async t=>{
  const f=await fixture(t),first=issued(await f.exchange(await f.create())),pending=await f.create();
  const secondWorkspace=randomUUID();
  await f.database.query(`INSERT INTO selfhost_workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
    VALUES ($1,$2,'Fake Second Workspace','fake-second-relay','fake-envelope')`,[secondWorkspace,f.owner.organizationId]);
  const secondCode=await f.store.createMcpOAuthAuthorizationCode(f.authorization(),{ ...f.owner,workspaceId:secondWorkspace });
  const second=issued(await f.exchange(secondCode));
  const otherOrg=randomUUID(),otherWorkspace=randomUUID();
  await f.database.query("INSERT INTO selfhost_organizations(id,name) VALUES ($1,'Fake Other Org')",[otherOrg]);
  await f.database.query("INSERT INTO selfhost_organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'owner')",[otherOrg,f.owner.userId]);
  await f.database.query(`INSERT INTO selfhost_workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
    VALUES ($1,$2,'Fake Other Workspace','fake-other-relay','fake-envelope')`,[otherWorkspace,otherOrg]);
  const otherCode=await f.store.createMcpOAuthAuthorizationCode(f.authorization(),{ ...f.owner,organizationId:otherOrg,workspaceId:otherWorkspace });
  const other=issued(await f.exchange(otherCode));
  await f.database.transaction(async tx=>{
    await lockUser(tx,f.owner.userId); await lockOrganization(tx,f.owner.organizationId);
    await f.store.revokeOrganizationMcpOAuthGrants(tx,f.owner);
    await tx.query("DELETE FROM selfhost_organization_memberships WHERE organization_id=$1 AND user_id=$2",[f.owner.organizationId,f.owner.userId]);
  });
  await f.database.query("INSERT INTO selfhost_organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')",[f.owner.organizationId,f.owner.userId]);
  assert.equal((await f.exchange(pending)).ok,false);
  assert.equal(await f.store.sessions.resolveAccessToken(first.access_token,`${ORIGIN}/cloud${SHARED}`),null);
  assert.equal(await f.store.sessions.resolveAccessToken(second.access_token,`${ORIGIN}/cloud${SHARED}`),null);
  assert.ok(await f.store.sessions.resolveAccessToken(other.access_token,`${ORIGIN}/cloud${SHARED}`));
  assert.equal(await f.count("sessions"),3); assert.equal(await f.count("revocations"),2);
  assert.equal((await f.store.refreshMcpOAuthToken({ refreshToken:first.refresh_token,clientId:f.client.clientId,resource:undefined })).ok,false);
});
