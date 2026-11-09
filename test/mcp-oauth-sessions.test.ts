import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import pg from "pg";
import type { Database } from "../src/database.js";
import { PostgresDatabase } from "../src/database.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { hashSecret } from "../src/crypto.js";
import { createMcpOAuthProtocol } from "../src/mcp/oauth/protocol.js";
import { McpOAuthSessions } from "../src/mcp/oauth/sessions.js";
import { PGliteDatabase } from "./support/harness.js";

const ORIGIN = "https://relay.example.test";
const SHARED = "/api/v1/mcp/shared-sessions";
const EVENTS = "/api/v1/mcp/relay-events";
const RESOURCE = `${ORIGIN}/cloud${SHARED}`;
const KEYRING = { active: { id: "fake-key", key: Buffer.alloc(32,7) } };

async function seed(database: Database) {
  await migrate(database);
  const userId=randomUUID(), organizationId=randomUUID(), workspaceId=randomUUID(), grantId=randomUUID(), tokenFamilyId=randomUUID();
  const clientId=`mcpc_fake_${randomUUID()}`;
  await database.query("INSERT INTO users(id,email,name) VALUES ($1,$2,'Fake User')",[userId,`fake-${userId}@example.test`]);
  await database.query("INSERT INTO organizations(id,name) VALUES ($1,'Fake Org')",[organizationId]);
  await database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'owner')",[organizationId,userId]);
  await database.query(`INSERT INTO workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext)
    VALUES ($1,$2,'Fake Workspace',$3,'fake-envelope')`,[workspaceId,organizationId,`fake-relay-${workspaceId}`]);
  await database.query("INSERT INTO mcp_oauth_clients(client_id,redirect_uris) VALUES ($1,$2)",[clientId,["https://client.example.test/cb"]]);
  await database.query(`INSERT INTO mcp_oauth_grants
    (id,client_id,user_id,organization_id,workspace_id,agent_name,agent_remote_id,scopes,resource,token_family_id)
    VALUES ($1,$2,$3,$4,$5,'fake-agent','fake-immutable-id',$6,$7,$8)`,
  [grantId,clientId,userId,organizationId,workspaceId,["relay:mcp"],RESOURCE,tokenFamilyId]);
  return { grantId,tokenFamilyId,userId,organizationId,workspaceId };
}

async function fixture(t: test.TestContext) {
  const database = new PGliteDatabase();
  t.after(()=>database.close());
  const owner = await seed(database);
  let now = new Date();
  const protocol = createMcpOAuthProtocol({ publicOrigin:ORIGIN,enabledResources:[SHARED,EVENTS,"/mcp"] });
  const sessions = new McpOAuthSessions(database,{ protocol,tenancyMode:"multi",now:()=>new Date(now) });
  const issue = (scopes=["relay:mcp"]) => database.transaction(tx=>sessions.issue(tx,{ ...owner,scopes }));
  return { database,owner,sessions,issue,protocol,advance:(ms:number)=>{ now=new Date(now.getTime()+ms); } };
}

test("OAuth tokens have own prefixes/hash-only table and never pass general session auth/refresh/introspection", async t=>{
  const f=await fixture(t), pair=await f.issue();
  assert.match(pair.accessToken,/^mcp_at_[A-Za-z0-9_-]{43}$/);
  assert.match(pair.refreshToken,/^mcp_rt_[A-Za-z0-9_-]{43}$/);
  const row=(await f.database.query("SELECT * FROM mcp_oauth_sessions")).rows[0]!;
  assert.equal(row.access_token_hash,hashSecret(pair.accessToken));
  assert.equal(row.refresh_token_hash,hashSecret(pair.refreshToken));
  assert.ok(!JSON.stringify(row).includes(pair.accessToken));
  assert.ok(!JSON.stringify(row).includes(pair.refreshToken));
  assert.equal(Date.parse(pair.refreshTokenExpiresAt)-Date.parse(pair.accessTokenExpiresAt),29*24*60*60*1000+23*60*60*1000);
  const general=new ControlPlaneStore(f.database,KEYRING,0,{ tenancy:"multi" });
  assert.equal(await general.authenticateAccessToken(pair.accessToken),null);
  assert.equal(await general.refresh(pair.refreshToken),null);
  assert.equal(await general.introspectAccessToken(pair.accessToken),null);
  assert.equal((await f.database.query("SELECT id FROM token_sessions")).rows.length,0);
});

test("MCP resolver binds resource/origin/tenant and returns only approved participant plus issued scopes", async t=>{
  const f=await fixture(t), pair=await f.issue();
  const access=await f.sessions.resolveAccessToken(pair.accessToken,RESOURCE);
  assert.ok(access);
  assert.equal(access.principal.userId,f.owner.userId);
  assert.equal(access.principal.organizationId,f.owner.organizationId);
  assert.equal(access.principal.workspaceId,f.owner.workspaceId);
  assert.equal(access.principal.tokenFamilyId,f.owner.tokenFamilyId);
  assert.deepEqual(access.principal.scopes,["relay:mcp"]);
  assert.equal(access.principal.pendingHandoff,false);
  assert.equal(access.principal.handoff,false);
  assert.equal(access.agentRemoteId,"fake-immutable-id");
  for(const url of [`${ORIGIN}/mcp`,`${ORIGIN}/cloud${EVENTS}`,`https://evil.example.test/cloud${SHARED}`,
    `${ORIGIN}/api/v1/workspaces`,`${ORIGIN}/api/v1/mcp/shared-sessions`,"http://[bad",` ${RESOURCE}`,`${RESOURCE}\n`]) {
    assert.equal(await f.sessions.resolveAccessToken(pair.accessToken,url),null,url);
  }
  assert.equal(await f.sessions.resolveAccessToken(pair.refreshToken,RESOURCE),null);
  assert.equal(await f.sessions.resolveAccessToken("sh_at_fake",RESOURCE),null);
});

test("grant expansion never widens older sessions; resolver intersects current grant and reads live role", async t=>{
  const f=await fixture(t), pair=await f.issue();
  await f.database.query("UPDATE mcp_oauth_grants SET scopes=$2 WHERE id=$1",[f.owner.grantId,["relay:mcp","relay:agents"]]);
  await f.database.query("UPDATE organization_memberships SET role='member' WHERE user_id=$1 AND organization_id=$2",
    [f.owner.userId,f.owner.organizationId]);
  const access=await f.sessions.resolveAccessToken(pair.accessToken,RESOURCE);
  assert.deepEqual(access!.principal.scopes,["relay:mcp"]);
  assert.equal(access!.principal.role,"member");
  const rotated=await f.database.transaction(tx=>f.sessions.rotate(tx,pair.refreshToken,f.owner));
  assert.deepEqual(rotated!.scopes,["relay:mcp"]);
  await f.database.query("UPDATE mcp_oauth_grants SET scopes=$2 WHERE id=$1",[f.owner.grantId,["openid"]]);
  assert.equal(await f.sessions.resolveAccessToken(rotated!.accessToken,RESOURCE),null);
});

test("refresh CAS has one winner, persists retired hash atomically, and preserves session/family", async t=>{
  const f=await fixture(t), pair=await f.issue();
  const results=await Promise.all([0,1].map(()=>f.database.transaction(tx=>f.sessions.rotate(tx,pair.refreshToken,f.owner))));
  const winners=results.filter(value=>value!==null);
  assert.equal(winners.length,1);
  const next=winners[0]!;
  assert.equal(next.sessionId,pair.sessionId);
  assert.equal(next.tokenFamilyId,pair.tokenFamilyId);
  assert.equal(await f.sessions.resolveAccessToken(pair.accessToken,RESOURCE),null);
  assert.ok(await f.sessions.resolveAccessToken(next.accessToken,RESOURCE));
  const receipt=(await f.database.query("SELECT * FROM mcp_oauth_retired_refresh_tokens")).rows[0]!;
  assert.equal(receipt.token_hash,hashSecret(pair.refreshToken));
  assert.equal(receipt.grant_id,f.owner.grantId);
  assert.equal(receipt.organization_id,f.owner.organizationId);
});

test("rotation rollback keeps the old pair and no retired receipt", async t=>{
  const f=await fixture(t), pair=await f.issue();
  await assert.rejects(f.database.transaction(async tx=>{
    assert.ok(await f.sessions.rotate(tx,pair.refreshToken,f.owner));
    throw new Error("fake transaction failure");
  }),/fake transaction failure/);
  assert.ok(await f.sessions.resolveAccessToken(pair.accessToken,RESOURCE));
  assert.equal((await f.database.query("SELECT token_hash FROM mcp_oauth_retired_refresh_tokens")).rows.length,0);
});

test("revoked grant, expired pair and missing membership cannot resolve/rotate; deletion retains receipts", async t=>{
  const f=await fixture(t), pair=await f.issue();
  await f.database.query("UPDATE mcp_oauth_grants SET revoked_at=now() WHERE id=$1",[f.owner.grantId]);
  assert.equal(await f.sessions.resolveAccessToken(pair.accessToken,RESOURCE),null);
  assert.equal(await f.database.transaction(tx=>f.sessions.rotate(tx,pair.refreshToken,f.owner)),null);
  await f.database.query("UPDATE mcp_oauth_grants SET revoked_at=NULL WHERE id=$1",[f.owner.grantId]);
  f.advance(31*24*60*60*1000);
  assert.equal(await f.sessions.resolveAccessToken(pair.accessToken,RESOURCE),null);
  assert.equal(await f.database.transaction(tx=>f.sessions.rotate(tx,pair.refreshToken,f.owner)),null);
  f.advance(-31*24*60*60*1000);
  await f.database.query("DELETE FROM organization_memberships WHERE user_id=$1 AND organization_id=$2",[f.owner.userId,f.owner.organizationId]);
  assert.equal((await f.database.query("SELECT id FROM mcp_oauth_sessions WHERE id=$1",[pair.sessionId])).rows.length,1);
  assert.equal(await f.sessions.resolveAccessToken(pair.accessToken,RESOURCE),null);
  assert.equal(await f.database.transaction(tx=>f.sessions.rotate(tx,pair.refreshToken,f.owner)),null);
});

test("session receipt revocation is exact, family revocation covers continued pairs, and cross-owner issuance fails", async t=>{
  const f=await fixture(t), first=await f.issue(), second=await f.issue();
  await assert.rejects(f.database.transaction(tx=>f.sessions.issue(tx,{ ...f.owner,tokenFamilyId:randomUUID(),scopes:["relay:mcp"] })),/consented grant/);
  await assert.rejects(f.issue(["account"]),/consented grant/);
  await assert.rejects(f.database.query("UPDATE mcp_oauth_sessions SET scopes=$2 WHERE id=$1",[first.sessionId,["rth:acquire"]]),/check constraint/);
  const otherGrant=randomUUID(),otherFamily=randomUUID();
  await f.database.query(`INSERT INTO mcp_oauth_grants
    (id,client_id,user_id,organization_id,workspace_id,agent_name,scopes,resource,token_family_id)
    SELECT $2,client_id,user_id,organization_id,workspace_id,'fake-other-agent',scopes,resource,$3
    FROM mcp_oauth_grants WHERE id=$1`,[f.owner.grantId,otherGrant,otherFamily]);
  await assert.rejects(f.database.query("UPDATE mcp_oauth_sessions SET grant_id=$2 WHERE id=$1",[first.sessionId,otherGrant]),/foreign key/);
  assert.equal(await f.database.transaction(tx=>f.sessions.rotate(tx,second.refreshToken,{ ...f.owner,workspaceId:randomUUID() })),null);
  await f.database.transaction(tx=>f.sessions.revokeSession(tx,first.sessionId,f.owner,"fake-code-replay"));
  assert.equal(await f.sessions.resolveAccessToken(first.accessToken,RESOURCE),null);
  assert.ok(await f.sessions.resolveAccessToken(second.accessToken,RESOURCE));
  await f.database.transaction(tx=>f.sessions.revokeFamily(tx,f.owner,"fake-grant-revoke"));
  assert.equal(await f.sessions.resolveAccessToken(second.accessToken,RESOURCE),null);
  assert.equal(await f.database.transaction(tx=>f.sessions.rotate(tx,second.refreshToken,f.owner)),null);
});

test("single-mode gate over multi-org state and disabled resources fail closed", async t=>{
  const f=await fixture(t), pair=await f.issue();
  await f.database.query("INSERT INTO organizations(id,name) VALUES ($1,'Fake Other Org')",[randomUUID()]);
  const single=new McpOAuthSessions(f.database,{ protocol:f.protocol,tenancyMode:"single" });
  assert.equal(await single.resolveAccessToken(pair.accessToken,RESOURCE),null);
  assert.equal(await f.database.transaction(tx=>single.rotate(tx,pair.refreshToken,f.owner)),null);
  const off=new McpOAuthSessions(f.database,{ protocol:createMcpOAuthProtocol({ publicOrigin:ORIGIN }),tenancyMode:"multi" });
  assert.equal(await off.resolveAccessToken(pair.accessToken,RESOURCE),null);
});

const postgresUrl=process.env.TEST_DATABASE_URL;
test("real Postgres: concurrent OAuth refresh has one winner across independent connections",{
  skip:postgresUrl?false:"TEST_DATABASE_URL is not set (OAuth refresh race needs a throwaway Postgres)",timeout:60_000,
},async t=>{
  // Isolate this test's schema; never migrate or delete another suite's tables.
  const admin=new pg.Pool({ connectionString:postgresUrl,max:1 });
  const schema=`mcp_oauth_${randomUUID().replaceAll("-","")}`;
  await admin.query(`CREATE SCHEMA "${schema}"`);
  const pool=new pg.Pool({ connectionString:postgresUrl,max:4,options:`-c search_path=${schema},public` });
  const database=new PostgresDatabase(pool);
  t.after(async()=>{
    try { await database.close(); } finally {
      try { await admin.query(`DROP SCHEMA "${schema}" CASCADE`); } finally { await admin.end(); }
    }
  });
  const owner=await seed(database);
  const protocol=createMcpOAuthProtocol({ publicOrigin:ORIGIN,enabledResources:[SHARED] });
  const sessions=new McpOAuthSessions(database,{ protocol,tenancyMode:"multi" });
  const pair=await database.transaction(tx=>sessions.issue(tx,{ ...owner,scopes:["relay:mcp"] }));
  const results=await Promise.all([0,1].map(()=>database.transaction(tx=>sessions.rotate(tx,pair.refreshToken,owner))));
  const winners=results.filter(value=>value!==null);
  assert.equal(winners.length,1);
  assert.ok(await sessions.resolveAccessToken(winners[0]!.accessToken,RESOURCE));
  assert.equal((await database.query("SELECT token_hash FROM mcp_oauth_retired_refresh_tokens")).rows.length,1);
});
