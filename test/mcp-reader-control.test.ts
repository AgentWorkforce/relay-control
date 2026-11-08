import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { hashSecret } from "../src/crypto.js";
import { migrate } from "../src/migrations.js";
import { historyReader } from "../src/mcp/context.js";
import { ControlPlaneStore } from "../src/store.js";
import { close,listen,PGliteDatabase } from "./support/harness.js";

test("MCP obtains and refreshes through real Control HTTP admission, and parent revocation stops renewal",async t=>{
  const secret="fake-reader-issuer-secret-".repeat(2);
  const calls:Array<{path:string;bearer:string|undefined;body:Record<string,unknown>}> = [];
  let serial=0,currentAccess="",currentRefresh="",workspaceId="";
  const reader=createServer(async(req,res)=>{
    const url=new URL(req.url??"/","http://localhost");
    const chunks:Buffer[]=[];for await(const chunk of req) chunks.push(Buffer.from(chunk));
    const raw=Buffer.concat(chunks).toString("utf8"),body=raw?JSON.parse(raw) as Record<string,unknown>:{};
    calls.push({path:url.pathname,bearer:req.headers.authorization,body});
    res.setHeader("content-type","application/json");
    if(url.pathname.startsWith("/internal/v1/session-read/sessions")) {
      assert.equal(req.headers.authorization,`Bearer ${secret}`);
      if(url.pathname.endsWith("/refresh")) assert.equal(body.refreshToken,currentRefresh);
      serial++;workspaceId=String(body.workspaceId);
      currentAccess=`rth_at_read_${String(serial).padEnd(43,"a")}`;
      currentRefresh=`rth_rt_read_${String(serial).padEnd(43,"r")}`;
      res.end(JSON.stringify({sessionId:"fake-reader-session",userId:body.userId,orgId:body.orgId,workspaceId,
        audience:body.audience,scopes:["rth:read"],accessToken:currentAccess,refreshToken:currentRefresh,
        accessTokenExpiresAt:new Date(Date.now()+10_000).toISOString(),
        refreshTokenExpiresAt:new Date(Date.now()+86_400_000).toISOString(),tokenType:"Bearer"}));
      return;
    }
    assert.equal(url.pathname,"/v1/sessions");
    assert.equal(req.headers.authorization,`Bearer ${currentAccess}`);
    assert.equal(url.searchParams.get("workspace"),workspaceId);
    res.setHeader("x-relayhistory-workspace-id",workspaceId);res.end(JSON.stringify({sessions:[]}));
  });
  const readerUrl=await listen(reader);t.after(()=>close(reader));
  const database=new PGliteDatabase();await migrate(database);
  const keyring={active:{id:"fake-key",key:Buffer.alloc(32,7)}};
  const store=new ControlPlaneStore(database,keyring,0,{tenancy:"multi"});
  const org=await store.createOrganization({name:"Fake Org",ownerEmail:"fake@example.test",ownerName:"Fake User"});
  const workspace=await store.createWorkspace({organizationId:org.id,name:"Fake Workspace",relaycastApiKey:"fake-relay-key"});
  const pair=await database.transaction(tx=>store.issueBrowserSession(tx,{userId:org.owner.id,organizationId:org.id,workspaceId:workspace.id,label:"fake-mcp"}));
  const principal=await store.authenticateAccessToken(pair.accessToken);assert.ok(principal);
  const control=createServer(),controlUrl=await listen(control);
  const config:SelfhostConfig={databaseUrl:"unused",publicBaseUrl:controlUrl,relaycastUrl:"http://unused.test",
    relaycastPublicUrl:"https://relay.selfhosted.company",relayhistoryUrl:"http://unused.test",
    relayhistoryPublicUrl:"https://history.selfhosted.company",relayauthUrl:null,relayauthApiKey:null,
    bootstrapToken:"fake-bootstrap-token-".repeat(3),encryptionKeyring:keyring,internalServiceToken:null,
    oauthRedirectUrl:`${controlUrl}/unused`,dashboardUrl:controlUrl,host:"127.0.0.1",port:3000,
    sessionReadApi:{url:readerUrl,publicUrl:readerUrl,secret},sessionReadMcpReads:true};
  control.on("request",createApp({config,store}));
  t.after(async()=>{await close(control);await database.close();});
  const authorized=await store.workspaceForUser(workspace.id,principal.userId);assert.ok(authorized);
  const read=historyReader(config,principal,authorized,pair.accessToken);
  assert.deepEqual(await read("/v1/sessions?workspace=other"),{sessions:[]});
  assert.deepEqual(await read("/v1/sessions"),{sessions:[]});
  assert.deepEqual(calls.map(call=>call.path),["/internal/v1/session-read/sessions","/v1/sessions",
    "/internal/v1/session-read/sessions/refresh","/v1/sessions"]);
  for(const call of calls.filter(call=>call.path==="/v1/sessions")) {
    assert.match(call.bearer!,/^Bearer rth_at_read_/);assert.ok(!call.bearer!.includes(secret));
    assert.notEqual(call.bearer,`Bearer ${pair.accessToken}`);
  }
  await database.query("UPDATE selfhost_token_sessions SET revoked_at=now() WHERE access_token_hash=$1",[hashSecret(pair.accessToken)]);
  await assert.rejects(read("/v1/sessions"),/Reauthenticate/);
  assert.equal(calls.length,4,"Control refuses the revoked parent before the reader is contacted");
});
