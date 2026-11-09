import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import pg from "pg";
import { PostgresDatabase,type Database,type SqlExecutor } from "../src/database.js";
import { migrate } from "../src/migrations.js";
import { createMcpOAuthProtocol,pkceS256 } from "../src/mcp/oauth/protocol.js";
import { McpOAuthStore } from "../src/mcp/oauth/store.js";

const postgresUrl=process.env.TEST_DATABASE_URL;
const options={ skip:postgresUrl?false:"TEST_DATABASE_URL is not set (OAuth multi-connection proof)",timeout:60_000 };
const ORIGIN="https://relay.example.test",SHARED="/api/v1/mcp/shared-sessions",VERIFIER="a".repeat(43);

async function fixture(t:test.TestContext) {
  const admin=new pg.Pool({ connectionString:postgresUrl,max:1 });
  const schema=`mcp_flow_${randomUUID().replaceAll("-","")}`;
  await admin.query(`CREATE SCHEMA "${schema}"`);
  const pool=new pg.Pool({ connectionString:postgresUrl,max:4,options:`-c search_path=${schema},public` });
  const database=new PostgresDatabase(pool);
  t.after(async()=>{
    try { await database.close(); } finally {
      try { await admin.query(`DROP SCHEMA "${schema}" CASCADE`); } finally { await admin.end(); }
    }
  });
  await migrate(database);
  const owner={ userId:randomUUID(),organizationId:randomUUID(),workspaceId:randomUUID(),agentName:"fake-agent" };
  await database.query("INSERT INTO selfhost_users(id,email,name) VALUES ($1,$2,'Fake User')",[owner.userId,`fake-${owner.userId}@example.test`]);
  await database.query("INSERT INTO selfhost_organizations(id,name) VALUES ($1,'Fake Org')",[owner.organizationId]);
  await database.query("INSERT INTO selfhost_organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'owner')",[owner.organizationId,owner.userId]);
  await database.query(`INSERT INTO selfhost_workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
    VALUES ($1,$2,'Fake Workspace',$3,'fake-envelope')`,[owner.workspaceId,owner.organizationId,`fake-${owner.workspaceId}`]);
  const protocol=createMcpOAuthProtocol({ publicOrigin:ORIGIN,enabledResources:[SHARED] });
  const storeOptions={ protocol,tenancyMode:"multi" as const,isGrokRoutine:()=>false };
  const store=new McpOAuthStore(database,storeOptions);
  const client=await store.registerMcpOAuthClient({ clientName:"fake-client",redirectUris:["https://client.example.test/cb"] });
  const request=protocol.validateAuthorizationRequest({ client_id:client.clientId,redirect_uri:client.redirectUris[0],
    response_type:"code",code_challenge:pkceS256(VERIFIER),code_challenge_method:"S256",resource:`${ORIGIN}/cloud${SHARED}` },client);
  assert.ok(request.ok);
  const exchange=(code:string)=>store.exchangeMcpOAuthAuthorizationCode({ code,clientId:client.clientId,
    redirectUri:client.redirectUris[0],codeVerifier:VERIFIER,resource:undefined });
  return { pool,database,owner,store,storeOptions,client,request:request.value,exchange };
}

test("real Postgres: full refresh flow serializes competing refreshes and preserves the winning family",options,async t=>{
  const f=await fixture(t),code=await f.store.createMcpOAuthAuthorizationCode(f.request,f.owner);
  const issued=await f.exchange(code); assert.ok(issued.ok);
  const results=await Promise.all([0,1].map(()=>f.store.refreshMcpOAuthToken({ refreshToken:issued.body.refresh_token,
    clientId:f.client.clientId,resource:undefined })));
  const winners=results.filter(value=>value.ok);
  assert.equal(winners.length,1); assert.ok(winners[0]!.ok);
  assert.ok(await f.store.sessions.resolveAccessToken(winners[0]!.body.access_token,f.request.resource));
  assert.equal((await f.database.query("SELECT token_hash FROM selfhost_mcp_oauth_retired_refresh_tokens")).rows.length,1);
  assert.equal((await f.database.query("SELECT id FROM selfhost_mcp_oauth_revocations")).rows.length,0);
});

test("real Postgres: code issuance fences native membership deletion with a row lock",options,async t=>{
  const f=await fixture(t);
  let notifyLocked!:()=>void,release!:()=>void;
  const locked=new Promise<void>(resolve=>{ notifyLocked=resolve; });
  const released=new Promise<void>(resolve=>{ release=resolve; });
  const intercepted:Database={
    query:f.database.query.bind(f.database),exec:f.database.exec.bind(f.database),close:async()=>{},
    transaction:run=>f.database.transaction(tx=>{
      const wrapped:SqlExecutor={ exec:tx.exec.bind(tx),query:async <T extends Record<string,unknown>>(sql:string,params?:unknown[])=>{
        const result=await tx.query<T>(sql,params);
        if(sql.includes("SELECT w.id FROM selfhost_workspaces w")) { notifyLocked(); await released; }
        return result;
      } };
      return run(wrapped);
    }),
  };
  const store=new McpOAuthStore(intercepted,f.storeOptions);
  const issuing=store.createMcpOAuthAuthorizationCode(f.request,f.owner);
  // Attach rejection immediately, so a setup failure cannot leave a dangling rejection.
  const outcome=issuing.then(code=>({ code }),error=>({ error }));
  const deleter=await f.pool.connect();
  try {
    await Promise.race([locked,outcome.then(value=>{ if("error" in value) throw value.error; throw new Error("missing membership fence"); })]);
    await deleter.query("BEGIN"); await deleter.query("SET LOCAL lock_timeout='150ms'");
    await assert.rejects(deleter.query("DELETE FROM selfhost_organization_memberships WHERE organization_id=$1 AND user_id=$2",
      [f.owner.organizationId,f.owner.userId]),(error:unknown)=>typeof error==="object" && error!==null && "code" in error && error.code==="55P03");
    await deleter.query("ROLLBACK");
  } finally { release(); deleter.release(); }
  const result=await outcome; if("error" in result) throw result.error;
  await f.database.query("DELETE FROM selfhost_organization_memberships WHERE organization_id=$1 AND user_id=$2",[f.owner.organizationId,f.owner.userId]);
  assert.equal((await f.exchange(result.code)).ok,false);
});
