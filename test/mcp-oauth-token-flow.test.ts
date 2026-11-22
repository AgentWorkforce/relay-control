import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { ControlPlaneStore } from "../src/store.js";
import { migrate } from "../src/migrations.js";
import { hashSecret } from "../src/crypto.js";
import { lockUser,lockOrganization } from "../src/tenancy.js";
import { createMcpOAuthProtocol,pkceS256 } from "../src/mcp/oauth/protocol.js";
import { McpOAuthStore,MCP_OAUTH_UNDELIVERED_REFRESH_RECOVERY_SECONDS,type McpOAuthRefreshLog,type McpOAuthTokenResult } from "../src/mcp/oauth/store.js";
import type { Database } from "../src/database.js";
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
  await database.query("INSERT INTO users(id,email,name) VALUES ($1,'fake@example.test','Fake User')",[owner.userId]);
  await database.query("INSERT INTO organizations(id,name) VALUES ($1,'Fake Org')",[owner.organizationId]);
  await database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'owner')",[owner.organizationId,owner.userId]);
  await database.query(`INSERT INTO workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
    VALUES ($1,$2,'Fake Workspace','fake-relay','fake-envelope')`,[owner.workspaceId,owner.organizationId]);
  let now=new Date(),signerFails=false;
  const signed:Array<Record<string,unknown>>=[],refreshLogs:McpOAuthRefreshLog[]=[];
  const protocol=createMcpOAuthProtocol({ publicOrigin:ORIGIN,enabledResources:[SHARED,EVENTS,"/mcp"],
    mountedEndpoints:["authorization","token","jwks"],oidcEnabled:true });
  const store=new McpOAuthStore(database,{ protocol,tenancyMode:"multi",now:()=>new Date(now),
    isGrokRoutine:request=>request.resourcePath===EVENTS && new URL(request.redirectUri).hostname==="x.ai",
    issueIdToken:input=>{ if(signerFails) throw new Error("fake signer failure"); signed.push(input); return "fake-id-token"; },
    logRefresh:entry=>{ refreshLogs.push(entry); },
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
    return (await database.query<{ grant_id:string }>("SELECT grant_id FROM mcp_oauth_authorization_codes WHERE code_hash=$1",[hashSecret(code)])).rows[0]!.grant_id;
  }
  const count=(table:"grants"|"sessions"|"revocations")=>database.query<{ n:number }>(`SELECT count(*)::int AS n FROM mcp_oauth_${table}`).then(r=>r.rows[0]!.n);
  return { database,owner,store,client,create,exchange,grantId,count,signed,authorization,refreshLogs,
    advance:(ms:number)=>{ now=new Date(now.getTime()+ms); },signerFailure:(value:boolean)=>{ signerFails=value; } };
}

test("code exchange creates only an OAuth pair with source TTL/scope and exact consumed-session receipt",async t=>{
  const f=await fixture(t),code=await f.create(),body=issued(await f.exchange(code));
  assert.match(body.access_token,/^mcp_at_/); assert.match(body.refresh_token,/^mcp_rt_/);
  assert.equal(body.expires_in,3600); assert.equal(body.scope,"relay:mcp");
  const access=await f.store.sessions.resolveAccessToken(body.access_token,`${ORIGIN}/cloud${SHARED}`);
  assert.ok(access); assert.equal(access.principal.organizationId,f.owner.organizationId);
  const row=(await f.database.query("SELECT * FROM mcp_oauth_authorization_codes")).rows[0]!;
  assert.equal(row.issued_session_id,access.principal.sessionId); assert.ok(row.consumed_at);
  assert.equal(row.grant_id,access.grantId);
  const general=new ControlPlaneStore(f.database,KEYRING,0,{ tenancy:"multi" });
  assert.equal(await general.authenticateAccessToken(body.access_token),null);
  assert.equal(await general.refresh(body.refresh_token),null);
  assert.equal((await f.database.query("SELECT id FROM token_sessions")).rows.length,0);
});

test("client/redirect/resource/PKCE errors cannot burn a code or revoke the legitimate pair",async t=>{
  const f=await fixture(t),code=await f.create();
  const invalid:Array<Record<string,string>>=[{ clientId:"mcpc_fake_other" },{ redirectUri:"https://evil.example.test/cb" },
    { resource:`${ORIGIN}/mcp` },{ codeVerifier:"b".repeat(43) },{ codeVerifier:"bad" }];
  for(const override of invalid) {
    const response=await f.exchange(code,override); assert.equal(response.ok,false);
    assert.equal((await f.database.query("SELECT consumed_at FROM mcp_oauth_authorization_codes")).rows[0]!.consumed_at,null);
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
  const event=(await f.database.query("SELECT * FROM mcp_oauth_revocations")).rows[0]!;
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
  await f.database.query("UPDATE mcp_oauth_grants SET continued_at=NULL WHERE id=$1",[id]);
  await f.database.query("UPDATE mcp_oauth_authorization_codes SET issued_session_id=NULL WHERE grant_id=$1",[id]);
  assert.equal((await f.exchange(code)).ok,false);
  assert.ok(await f.store.sessions.resolveAccessToken(next.access_token,request.resource));
  assert.ok((await f.database.query("SELECT continued_at FROM mcp_oauth_grants WHERE id=$1",[id])).rows[0]!.continued_at);
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
  assert.equal((await f.database.query("SELECT reason FROM mcp_oauth_revocations")).rows[0]!.reason,"refresh_token_reused");
  assert.deepEqual(f.refreshLogs.at(-1),{ outcome:"revoked",grantId:await f.grantId(code),reason:"refresh_token_reused",retiredForSeconds:31 });
});

/** One delivered pair, then a rotation whose response the client never received. */
async function lostRefresh(t:test.TestContext) {
  const f=await fixture(t),code=await f.create(),first=issued(await f.exchange(code)),id=await f.grantId(code);
  await f.database.query("UPDATE mcp_oauth_grants SET agent_remote_id='fake-immutable-id' WHERE id=$1",[id]);
  const resource=`${ORIGIN}/cloud${SHARED}`;
  assert.ok(await f.store.sessions.resolveAccessToken(first.access_token,resource));
  const refresh=(token:string,clientId=f.client.clientId)=>f.store.refreshMcpOAuthToken({ refreshToken:token,clientId,resource:undefined });
  const resolve=(token:string)=>f.store.sessions.resolveAccessToken(token,resource);
  const lost=issued(await refresh(first.refresh_token));
  const sessionId=(await f.database.query<{ id:string }>("SELECT id FROM mcp_oauth_sessions")).rows[0]!.id;
  const reused=async()=>(await f.database.query<{ reason:string }>("SELECT reason FROM mcp_oauth_revocations")).rows.map(row=>row.reason);
  const stored=async()=>(await f.database.query<{ refresh_token_hash:string; access_token_expires_at:Date; refresh_token_expires_at:Date }>(
    "SELECT refresh_token_hash,access_token_expires_at,refresh_token_expires_at FROM mcp_oauth_sessions WHERE id=$1",[sessionId])).rows[0]!;
  return { ...f,first,lost,id,sessionId,refresh,resolve,reused,stored };
}

test("re-issues a rotation whose response never reached the client instead of revoking the grant",async t=>{
  const f=await lostRefresh(t);
  f.advance(31_000);
  const again=issued(await f.refresh(f.first.refresh_token));
  assert.deepEqual(await f.reused(),[]); assert.equal(await f.count("sessions"),1); assert.equal(await f.count("grants"),1);
  const grant=(await f.database.query("SELECT * FROM mcp_oauth_grants WHERE id=$1",[f.id])).rows[0]!;
  assert.equal(grant.revoked_at,null); assert.equal(grant.agent_name,"fake-agent"); assert.equal(grant.agent_remote_id,"fake-immutable-id");
  assert.equal(await f.resolve(f.lost.access_token),null);
  const access=await f.resolve(again.access_token);
  assert.equal(access!.grantId,f.id); assert.equal(access!.principal.sessionId,f.sessionId);
  assert.equal(again.expires_in,3600); assert.equal(again.scope,"relay:mcp");
  const retired=(await f.database.query("SELECT token_hash,successor_token_hash FROM mcp_oauth_retired_refresh_tokens ORDER BY retired_at")).rows;
  assert.deepEqual(retired,[{ token_hash:hashSecret(f.first.refresh_token),successor_token_hash:hashSecret(again.refresh_token) },
    { token_hash:hashSecret(f.lost.refresh_token),successor_token_hash:hashSecret(again.refresh_token) }]);
  assert.deepEqual(f.refreshLogs.at(-1),{ outcome:"reissued_undelivered",grantId:f.id,retiredForSeconds:31 });
  const logged=JSON.stringify(f.refreshLogs);
  for(const secret of [f.first.refresh_token,f.lost.refresh_token,again.refresh_token,hashSecret(f.first.refresh_token),f.owner.userId,"fake-agent"]) {
    assert.ok(!logged.includes(secret));
  }
});

test("recovers again when the re-issued response is lost too",async t=>{
  const f=await lostRefresh(t);
  f.advance(31_000); const second=issued(await f.refresh(f.first.refresh_token));
  f.advance(31_000);
  const third=issued(await f.refresh(f.first.refresh_token));
  assert.equal(await f.resolve(second.access_token),null);
  assert.ok(await f.resolve(third.access_token));
  assert.deepEqual(await f.reused(),[]);
  // A re-issue restarts only the race window; the recovery window runs from the first retirement.
  assert.deepEqual(f.refreshLogs.slice(-2),[{ outcome:"reissued_undelivered",grantId:f.id,retiredForSeconds:31 },
    { outcome:"reissued_undelivered",grantId:f.id,retiredForSeconds:62 }]);
});

test("refuses a retry that races a recovery without replacing or revoking the recovered pair",async t=>{
  const f=await lostRefresh(t);
  f.advance(31_000);
  const recovered=issued(await f.refresh(f.first.refresh_token));
  const presented=(await f.database.query<{ token_hash:string; reissued_at:Date|null }>(
    "SELECT token_hash,reissued_at FROM mcp_oauth_retired_refresh_tokens ORDER BY retired_at")).rows;
  assert.equal(presented[0]!.token_hash,hashSecret(f.first.refresh_token)); assert.ok(presented[0]!.reissued_at);
  assert.equal(presented[1]!.token_hash,hashSecret(f.lost.refresh_token)); assert.equal(presented[1]!.reissued_at,null);
  f.advance(5_000);
  const duplicate=await f.refresh(f.first.refresh_token);
  assert.ok(!duplicate.ok); assert.equal(duplicate.error.error,"invalid_grant");
  assert.deepEqual(await f.reused(),[]);
  assert.equal((await f.stored()).refresh_token_hash,hashSecret(recovered.refresh_token));
  assert.deepEqual(f.refreshLogs.at(-1),{ outcome:"refused",grantId:f.id,reason:"refresh_race",retiredForSeconds:36 });
  assert.ok(await f.resolve(recovered.access_token));
  const next=issued(await f.refresh(recovered.refresh_token));
  assert.ok(await f.resolve(next.access_token)); assert.deepEqual(await f.reused(),[]);
});

test("a duplicate retry is refused when the recovered pair was used before it arrived",async t=>{
  const f=await lostRefresh(t);
  f.advance(31_000);
  const recovered=issued(await f.refresh(f.first.refresh_token));
  f.advance(2_000);
  assert.ok(await f.resolve(recovered.access_token));
  f.advance(2_000);
  const duplicate=await f.refresh(f.first.refresh_token);
  assert.ok(!duplicate.ok); assert.equal(duplicate.error.error,"invalid_grant");
  assert.deepEqual(await f.reused(),[]);
  assert.deepEqual(f.refreshLogs.at(-1),{ outcome:"refused",grantId:f.id,reason:"refresh_race",retiredForSeconds:35 });
  assert.ok(await f.resolve(recovered.access_token));
  assert.ok(await f.resolve(issued(await f.refresh(recovered.refresh_token)).access_token));
});

test("still revokes when the successor pair has been used",async t=>{
  const f=await lostRefresh(t);
  assert.ok(await f.resolve(f.lost.access_token));
  f.advance(31_000);
  assert.equal((await f.refresh(f.first.refresh_token)).ok,false);
  assert.deepEqual(await f.reused(),["refresh_token_reused"]);
  assert.equal(await f.resolve(f.lost.access_token),null);
  assert.deepEqual(f.refreshLogs.at(-1),{ outcome:"revoked",grantId:f.id,reason:"refresh_token_reused",retiredForSeconds:31 });
});

test("refuses recovery when the successor authenticates first, even late in the window",async t=>{
  const f=await lostRefresh(t);
  f.advance(20_000);
  assert.ok(await f.resolve(f.lost.access_token));
  f.advance(11_000);
  assert.equal((await f.refresh(f.first.refresh_token)).ok,false);
  assert.deepEqual(await f.reused(),["refresh_token_reused"]);
});

test("still revokes a token retired before the latest rotation",async t=>{
  const f=await lostRefresh(t);
  f.advance(1_000);
  const second=issued(await f.refresh(f.lost.refresh_token));
  f.advance(31_000);
  assert.equal((await f.refresh(f.first.refresh_token)).ok,false);
  assert.deepEqual(await f.reused(),["refresh_token_reused"]);
  assert.equal(await f.resolve(second.access_token),null);
});

test("revokes when the other holder presents its successor after the re-issued pair was used",async t=>{
  const f=await lostRefresh(t);
  f.advance(31_000);
  const reissued=issued(await f.refresh(f.first.refresh_token));
  assert.ok(await f.resolve(reissued.access_token));
  f.advance(31_000);
  assert.equal((await f.refresh(f.lost.refresh_token)).ok,false);
  assert.deepEqual(await f.reused(),["refresh_token_reused"]);
  assert.equal(await f.resolve(reissued.access_token),null);
});

test("does not re-issue to another client id",async t=>{
  const f=await lostRefresh(t);
  f.advance(31_000);
  const other=await f.refresh(f.first.refresh_token,"mcpc_fake_other");
  assert.ok(!other.ok); assert.equal(other.error.error,"invalid_grant");
  assert.deepEqual(await f.reused(),[]);
  assert.equal((await f.database.query("SELECT refresh_token_hash FROM mcp_oauth_sessions")).rows[0]!.refresh_token_hash,hashSecret(f.lost.refresh_token));
  assert.deepEqual(f.refreshLogs.at(-1),{ outcome:"refused",grantId:f.id,reason:"client_mismatch" });
  assert.ok(await f.resolve(f.lost.access_token));
});

test("a retry inside the 30-second window is refused without revoking or re-issuing",async t=>{
  const f=await lostRefresh(t);
  f.advance(29_000);
  assert.equal((await f.refresh(f.first.refresh_token)).ok,false);
  assert.deepEqual(await f.reused(),[]);
  assert.equal((await f.database.query("SELECT refresh_token_hash FROM mcp_oauth_sessions")).rows[0]!.refresh_token_hash,hashSecret(f.lost.refresh_token));
  assert.deepEqual(f.refreshLogs.at(-1),{ outcome:"refused",grantId:f.id,reason:"refresh_race",retiredForSeconds:29 });
  assert.ok(await f.resolve(f.lost.access_token));
});

test("a retired row without a successor (rotated before the upgrade) is not recovered",async t=>{
  const f=await lostRefresh(t);
  await f.database.query("UPDATE mcp_oauth_retired_refresh_tokens SET successor_token_hash=NULL,refresh_token_expires_at=NULL");
  f.advance(31_000);
  assert.equal((await f.refresh(f.first.refresh_token)).ok,false);
  assert.deepEqual(await f.reused(),["refresh_token_reused"]);
});

test("the old access token, used just before the rotation, does not block recovery",async t=>{
  const f=await lostRefresh(t);
  assert.equal(await f.resolve(f.first.access_token),null);
  assert.equal((await f.database.query("SELECT current_pair_used_at FROM mcp_oauth_sessions")).rows[0]!.current_pair_used_at,null);
  f.advance(31_000);
  assert.ok(await f.resolve(issued(await f.refresh(f.first.refresh_token)).access_token));
  assert.deepEqual(await f.reused(),[]);
});

test("of two concurrent recoveries of one token only the first wins, without revoking",async t=>{
  // PGlite runs one transaction at a time, so the competing winner is simulated: after this request's unlocked
  // read, the successor moves as a concurrent recovery would leave it.
  const f=await lostRefresh(t);
  const moved=`fake-moved-successor-${randomUUID()}`;
  let first=true;
  const racing:Database={ query:<T extends Record<string,unknown>>(sql:string,params?:unknown[])=>f.database.query<T>(sql,params),
    exec:sql=>f.database.exec(sql),close:async()=>{},
    transaction:run=>f.database.transaction(tx=>run({ exec:sql=>tx.exec(sql),query:async <T extends Record<string,unknown>>(sql:string,params?:unknown[])=>{
      const result=await tx.query<T>(sql,params);
      if(first && sql.includes("FROM mcp_oauth_retired_refresh_tokens WHERE token_hash=$1") && !sql.includes("FOR UPDATE")) {
        first=false; await tx.query("UPDATE mcp_oauth_retired_refresh_tokens SET successor_token_hash=$1 WHERE token_hash=$2",[moved,hashSecret(f.first.refresh_token)]);
      }
      return result;
    } })) };
  const store=new McpOAuthStore(racing,f.store.options);
  f.advance(31_000);
  const lostRace=await store.refreshMcpOAuthToken({ refreshToken:f.first.refresh_token,clientId:f.client.clientId,resource:undefined });
  assert.ok(!lostRace.ok); assert.equal(lostRace.error.error,"invalid_grant");
  assert.deepEqual(await f.reused(),[]);
  assert.equal((await f.stored()).refresh_token_hash,hashSecret(f.lost.refresh_token));
  assert.deepEqual(f.refreshLogs.at(-1),{ outcome:"refused",grantId:f.id,reason:"reissue_lost_race",retiredForSeconds:31 });
});

test("a re-issue recorded between the unlocked read and the lock is refused without revoking",async t=>{
  // Simulated: only reissued_at moves after the unlocked read. A real competing re-issue also moves the successor;
  // this pins the locked reissued_at check on its own.
  const f=await lostRefresh(t);
  let first=true;
  const racing:Database={ query:<T extends Record<string,unknown>>(sql:string,params?:unknown[])=>f.database.query<T>(sql,params),
    exec:sql=>f.database.exec(sql),close:async()=>{},
    transaction:run=>f.database.transaction(tx=>run({ exec:sql=>tx.exec(sql),query:async <T extends Record<string,unknown>>(sql:string,params?:unknown[])=>{
      const result=await tx.query<T>(sql,params);
      if(first && sql.includes("FROM mcp_oauth_retired_refresh_tokens WHERE token_hash=$1") && !sql.includes("FOR UPDATE")) {
        first=false; await tx.query("UPDATE mcp_oauth_retired_refresh_tokens SET reissued_at=$1 WHERE token_hash=$2",[f.store.options.now!(),hashSecret(f.first.refresh_token)]);
      }
      return result;
    } })) };
  const store=new McpOAuthStore(racing,f.store.options);
  f.advance(31_000);
  const lostRace=await store.refreshMcpOAuthToken({ refreshToken:f.first.refresh_token,clientId:f.client.clientId,resource:undefined });
  assert.ok(!lostRace.ok); assert.equal(lostRace.error.error,"invalid_grant");
  assert.deepEqual(await f.reused(),[]);
  assert.equal((await f.stored()).refresh_token_hash,hashSecret(f.lost.refresh_token));
  assert.deepEqual(f.refreshLogs.at(-1),{ outcome:"refused",grantId:f.id,reason:"reissue_lost_race",retiredForSeconds:31 });
});

test("on a grant with more than one session only the exact successor session is re-issued",async t=>{
  const f=await fixture(t),request={ resource:`${ORIGIN}/cloud${EVENTS}`,scope:"relay:events" };
  const oldCode=await f.create(request),old=issued(await f.exchange(oldCode)),id=await f.grantId(oldCode);
  const next=issued(await f.exchange(await f.create({ ...request,scope:"relay:events relay:mcp relay:agents" },id)));
  const refresh=(token:string)=>f.store.refreshMcpOAuthToken({ refreshToken:token,clientId:f.client.clientId,resource:undefined });
  const lost=issued(await refresh(next.refresh_token));
  f.advance(31_000);
  const again=issued(await refresh(next.refresh_token));
  assert.equal(await f.count("sessions"),2); assert.equal(await f.count("revocations"),0);
  const sessions=(await f.database.query<{ refresh_token_hash:string }>("SELECT refresh_token_hash FROM mcp_oauth_sessions ORDER BY created_at,id")).rows.map(row=>row.refresh_token_hash);
  assert.ok(sessions.includes(hashSecret(old.refresh_token))); assert.ok(sessions.includes(hashSecret(again.refresh_token)));
  assert.ok(!sessions.includes(hashSecret(lost.refresh_token)));
  assert.ok(await f.store.sessions.resolveAccessToken(old.access_token,request.resource));
  assert.ok(await f.store.sessions.resolveAccessToken(again.access_token,request.resource));
});

test("re-issue keeps the session's refresh expiry and caps the access expiry by it",async t=>{
  const f=await lostRefresh(t);
  const until=new Date((await f.stored()).access_token_expires_at.getTime()-20*60*1000);
  await f.database.query("UPDATE mcp_oauth_sessions SET refresh_token_expires_at=$1",[until]);
  f.advance(31_000);
  const again=issued(await f.refresh(f.first.refresh_token)),row=await f.stored();
  assert.equal(row.refresh_token_expires_at.getTime(),until.getTime());
  assert.equal(row.access_token_expires_at.getTime(),until.getTime());
  assert.ok(again.expires_in<3600-20*60+1);
  assert.equal((await f.database.query<{ refresh_token_expires_at:Date }>("SELECT refresh_token_expires_at FROM mcp_oauth_retired_refresh_tokens WHERE token_hash=$1",
    [hashSecret(f.lost.refresh_token)])).rows[0]!.refresh_token_expires_at.getTime(),until.getTime());
});

test("refuses recovery once the presented token's own expiry has passed",async t=>{
  const f=await lostRefresh(t);
  await f.database.query(`UPDATE mcp_oauth_retired_refresh_tokens
    SET refresh_token_expires_at=retired_at+interval '30 seconds' WHERE token_hash=$1`,[hashSecret(f.first.refresh_token)]);
  f.advance(31_000);
  assert.equal((await f.refresh(f.first.refresh_token)).ok,false);
  assert.deepEqual(await f.reused(),["refresh_token_reused"]);
});

test("refuses recovery after the 36-hour window",async t=>{
  const f=await lostRefresh(t);
  f.advance(MCP_OAUTH_UNDELIVERED_REFRESH_RECOVERY_SECONDS*1000+1_000);
  assert.equal((await f.refresh(f.first.refresh_token)).ok,false);
  assert.deepEqual(await f.reused(),["refresh_token_reused"]);
});

test("revoking a retired refresh token ends its grant; another client id is ignored",async t=>{
  const f=await lostRefresh(t);
  await f.store.revokeMcpOAuthToken({ token:f.first.refresh_token,clientId:"mcpc_fake_other" });
  assert.deepEqual(await f.reused(),[]);
  assert.ok(await f.resolve(f.lost.access_token));
  await f.store.revokeMcpOAuthToken({ token:f.first.refresh_token,clientId:f.client.clientId });
  assert.deepEqual(await f.reused(),["client_revoked"]);
  assert.equal(await f.resolve(f.lost.access_token),null);
  assert.ok((await f.database.query("SELECT revoked_at FROM mcp_oauth_grants WHERE id=$1",[f.id])).rows[0]!.revoked_at);
});

test("unknown refresh tokens are refused and logged without a grant id",async t=>{
  const f=await fixture(t);
  assert.equal((await f.store.refreshMcpOAuthToken({ refreshToken:`mcp_rt_${"a".repeat(43)}`,clientId:f.client.clientId,resource:undefined })).ok,false);
  assert.deepEqual(f.refreshLogs,[{ outcome:"refused",reason:"unknown_token" }]);
  assert.equal((await f.store.refreshMcpOAuthToken({ refreshToken:"fake-malformed",clientId:f.client.clientId,resource:undefined })).ok,false);
  assert.equal(f.refreshLogs.length,1);
});

test("OIDC failure rolls back code/grant/session; nonce and signer inputs are source-bound on retry",async t=>{
  const f=await fixture(t),code=await f.create({ scope:"openid relay:mcp",nonce:"fake-nonce" });
  f.signerFailure(true); await assert.rejects(f.exchange(code),/fake signer failure/);
  assert.equal(await f.count("grants"),0); assert.equal(await f.count("sessions"),0);
  assert.equal((await f.database.query("SELECT consumed_at FROM mcp_oauth_authorization_codes")).rows[0]!.consumed_at,null);
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
  assert.equal((await f.database.query("SELECT reason FROM mcp_oauth_revocations")).rows[0]!.reason,"client_revoked");
});

test("departure hook expires outstanding codes and revokes families before a later rejoin",async t=>{
  const f=await fixture(t),pending=await f.create(),body=issued(await f.exchange(await f.create()));
  await f.database.transaction(async tx=>{
    await lockUser(tx,f.owner.userId); await lockOrganization(tx,f.owner.organizationId);
    await f.store.revokeWorkspaceMcpOAuthGrants(tx,f.owner);
    await tx.query("DELETE FROM organization_memberships WHERE organization_id=$1 AND user_id=$2",[f.owner.organizationId,f.owner.userId]);
  });
  await f.database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')",[f.owner.organizationId,f.owner.userId]);
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
    "SELECT issued_session_id FROM mcp_oauth_authorization_codes WHERE code_hash=$1",[hashSecret(second)])).rows[0]!;
  for(const id of [randomUUID(),row.issued_session_id]) {
    await assert.rejects(f.database.query("UPDATE mcp_oauth_authorization_codes SET issued_session_id=$2 WHERE code_hash=$1",
      [hashSecret(first),id]),/foreign key/);
  }
  await assert.rejects(f.database.query("UPDATE mcp_oauth_authorization_codes SET grant_id=NULL WHERE code_hash=$1",[hashSecret(first)]),/check constraint/);
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
  await f.database.query(`INSERT INTO workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
    VALUES ($1,$2,'Fake Second Workspace','fake-second-relay','fake-envelope')`,[secondWorkspace,f.owner.organizationId]);
  const secondCode=await f.store.createMcpOAuthAuthorizationCode(f.authorization(),{ ...f.owner,workspaceId:secondWorkspace });
  const second=issued(await f.exchange(secondCode));
  const otherOrg=randomUUID(),otherWorkspace=randomUUID();
  await f.database.query("INSERT INTO organizations(id,name) VALUES ($1,'Fake Other Org')",[otherOrg]);
  await f.database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'owner')",[otherOrg,f.owner.userId]);
  await f.database.query(`INSERT INTO workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
    VALUES ($1,$2,'Fake Other Workspace','fake-other-relay','fake-envelope')`,[otherWorkspace,otherOrg]);
  const otherCode=await f.store.createMcpOAuthAuthorizationCode(f.authorization(),{ ...f.owner,organizationId:otherOrg,workspaceId:otherWorkspace });
  const other=issued(await f.exchange(otherCode));
  await f.database.transaction(async tx=>{
    await lockUser(tx,f.owner.userId); await lockOrganization(tx,f.owner.organizationId);
    await f.store.revokeOrganizationMcpOAuthGrants(tx,f.owner);
    await tx.query("DELETE FROM organization_memberships WHERE organization_id=$1 AND user_id=$2",[f.owner.organizationId,f.owner.userId]);
  });
  await f.database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')",[f.owner.organizationId,f.owner.userId]);
  assert.equal((await f.exchange(pending)).ok,false);
  assert.equal(await f.store.sessions.resolveAccessToken(first.access_token,`${ORIGIN}/cloud${SHARED}`),null);
  assert.equal(await f.store.sessions.resolveAccessToken(second.access_token,`${ORIGIN}/cloud${SHARED}`),null);
  assert.ok(await f.store.sessions.resolveAccessToken(other.access_token,`${ORIGIN}/cloud${SHARED}`));
  assert.equal(await f.count("sessions"),3); assert.equal(await f.count("revocations"),2);
  assert.equal((await f.store.refreshMcpOAuthToken({ refreshToken:first.refresh_token,clientId:f.client.clientId,resource:undefined })).ok,false);
});
