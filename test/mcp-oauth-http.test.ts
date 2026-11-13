import assert from "node:assert/strict";
import test from "node:test";
import { createServer, request as nodeRequest } from "node:http";
import { createPublicKey, generateKeyPairSync, randomUUID, verify } from "node:crypto";
import { loadConfig } from "../src/config.js";
import { createMcpOAuthHttpModule, mcpOAuthActiveNotice } from "../src/mcp/oauth/routes.js";
import { pkceS256 } from "../src/mcp/oauth/protocol.js";
import type { McpConsentSession } from "../src/mcp/oauth/consent.js";
import { McpOAuthStore } from "../src/mcp/oauth/store.js";
import { migrate } from "../src/migrations.js";
import { close, listen, PGliteDatabase } from "./support/harness.js";

const ORIGIN="https://relay.example.test";
const API="/cloud/api/oauth";
const SHARED="/api/v1/mcp/shared-sessions";
const resource=ORIGIN+"/cloud"+SHARED;
const client={clientId:"mcpc_fake",clientName:"Fake client",redirectUris:["https://client.example.test/cb"]};
const principal={userId:"fake-user",organizationId:"fake-org",workspaceId:"fake-workspace",scopes:["account"]};
const verifier="fake-verifier-".repeat(4);
const params={client_id:client.clientId,response_type:"code",redirect_uri:client.redirectUris[0]!,
  code_challenge:pkceS256(verifier),code_challenge_method:"S256",resource,state:""};
const registration={client_name:"Fake client",redirect_uris:client.redirectUris};

function config(enabled=true,extra:Record<string,string>={}) {
  return loadConfig({DATABASE_URL:"postgres://unused",SELFHOST_BOOTSTRAP_TOKEN:"fake-bootstrap-token-at-least-32-bytes",
    SELFHOST_PUBLIC_URL:ORIGIN,RELAYCAST_URL:"http://relaycast.test",RELAYCAST_PUBLIC_URL:"https://relaycast.selfhosted.company",
    SESSION_READ_API_URL:"http://history.test",SESSION_READ_API_SECRET:"fake-read-api-secret-at-least-32-bytes",RELAYCONTROL_INTROSPECT_SECRET:"fake-introspect-secret-at-least-32-bytes",SESSION_READ_API_PUBLIC_URL:"https://history.selfhosted.company",
    SELFHOST_ENCRYPTION_KEY_ID:"fake-key",SELFHOST_ENCRYPTION_KEY:Buffer.alloc(32,7).toString("base64"),
    SELFHOST_MCP_OAUTH:enabled?"on":"off",...extra});
}
function harness(options:{enabled?:boolean;access?:boolean;session?:McpConsentSession|null;name?:string|null;fail?:boolean;
  resources?:Array<typeof SHARED|"/mcp">;oidc?:Record<string,string>;redirectUris?:string[];
  availability?:"available"|"yours"|"taken"|"unknown"}={}) {
  const calls:string[]=[];
  const store={
    async registerMcpOAuthClient(input:{clientName:string|null;redirectUris:string[]}) {
      calls.push("register");return {...input,clientId:client.clientId,createdAt:new Date(0)};
    },
    async getMcpOAuthClient(id:string|undefined) {
      if(options.fail) throw new Error("fake secret must not escape");
      return id===client.clientId?{...client,clientName:options.name===undefined?client.clientName:options.name,
        redirectUris:options.redirectUris??client.redirectUris}:null;
    },
    async createMcpOAuthAuthorizationCode(_request:unknown,_owner:unknown,continuation?:string) {
      calls.push(continuation?"code:"+continuation:"code");return "mcpac_fake";},
    async listConnectedAgentNames() {return [];},
    async exchangeMcpOAuthAuthorizationCode() {
      calls.push("exchange");return {ok:true as const,body:{access_token:"mcp_at_fake",refresh_token:"mcp_rt_fake",
        token_type:"Bearer" as const,expires_in:3600,scope:"relay:mcp"}};
    },
    async refreshMcpOAuthToken() {
      calls.push("refresh");return {ok:false as const,status:400,error:{error:"invalid_grant",error_description:"Refused"}};
    },
    async revokeMcpOAuthToken() {calls.push("revoke");},
  };
  const module=createMcpOAuthHttpModule({
    config:config(options.enabled??true,options.oidc),createStore:()=>store,mountedResources:options.resources,
    resolveSession:async()=>options.session===undefined?{transport:"cookie",principal}:options.session,
    workspaceAccess:async()=>options.access!==false,
    workspaceLabel:async()=>"<Fake workspace>",
    checkAgentNameAvailability:async()=>{calls.push("name");return options.availability??"available";},
  });
  return {module,calls};
}
function web(path:string,body?:unknown,headers:Record<string,string>={},method?:string) {
  return new Request(ORIGIN+path,{method:method??(body===undefined?"GET":"POST"),
    headers:body===undefined?headers:{"content-type":"application/json",origin:ORIGIN,...headers},
    ...(body===undefined?{}:{body:JSON.stringify(body)})});
}
const pagePath="/cloud/oauth/authorize?"+new URLSearchParams(params);

test("oversized state returns a local error from both consent endpoints without issuing a code", async () => {
  const {module,calls}=harness({resources:[SHARED]});
  const oversized={...params,state:"x".repeat(4097)};
  const page=(await module.handle(web("/cloud/oauth/authorize?"+new URLSearchParams(oversized))))!;
  const decision=(await module.handle(web(API+"/authorize",{params:oversized,decision:"approve",
    workspace_id:principal.workspaceId,agent_name:"fake-agent"})))!;
  for(const response of [page,decision]) {
    assert.equal(response.status,400);
    assert.equal(response.headers.get("location"),null);
    assert.deepEqual(await response.json(),{error:"invalid_request",error_description:"state must be at most 4096 URL-encoded characters."});
  }
  assert.equal(calls.includes("code"),false);
});

test("HTTP module stays disabled by default and discovery advertises only declared mounted resources",async()=>{
  const off=harness({enabled:false}).module;
  assert.equal(await off.handle(web(API+"/register",registration)),null);
  assert.equal(off.issuer,null);
  assert.equal(off.protocol,null);
  const empty=harness().module;
  const authorizationServer=(await (await empty.handle(web("/cloud/.well-known/oauth-authorization-server")))!.json());
  assert.equal(authorizationServer.issuer,ORIGIN+"/cloud");
  assert.equal(authorizationServer.authorization_endpoint,ORIGIN+"/cloud/oauth/authorize");
  assert.equal(authorizationServer.token_endpoint,ORIGIN+API+"/token");
  assert.equal(authorizationServer.jwks_uri,undefined);
  assert.equal(await empty.handle(web("/.well-known/oauth-protected-resource/mcp")),null);
  assert.equal((await empty.handle(web("/cloud/.well-known/jwks.json")))!.status,404);
  assert.equal(await empty.handle(web("/api/oauth/register",registration)),null);
  const declared=harness({resources:["/mcp",SHARED]}).module;
  for(const path of ["/mcp",SHARED] as const) {
    const url=declared.protocol!.protectedResourceMetadataUrl(path);
    const result=await declared.handle(new Request(url));
    assert.equal(result!.status,200);
    assert.equal((await result!.json()).resource,declared.protocol!.mcpResourceUrl(path));
    assert.equal(result!.headers.get("access-control-allow-origin"),"*");
    const standard="/.well-known/oauth-protected-resource"+new URL(declared.protocol!.mcpResourceUrl(path)).pathname;
    const alias=(await declared.handle(web(standard)))!;
    assert.equal(alias.status,200);
    assert.equal((await alias.json()).resource,declared.protocol!.mcpResourceUrl(path));
    assert.equal(alias.headers.get("access-control-allow-origin"),"*");
    assert.equal((await declared.handle(web(standard,undefined,{},"OPTIONS")))!.status,204);
  }
  assert.equal(await declared.handle(web("/cloud/api/v1/mcp/relay-events")),null);
});

test("same signing configuration gates public registration, discovery and JWKS",async()=>{
  const key=generateKeyPairSync("rsa",{modulusLength:2048});
  const module=harness({resources:[SHARED],oidc:{SELFHOST_MCP_OIDC_SIGNING_KEY_ID:"fake-active",
    SELFHOST_MCP_OIDC_SIGNING_KEY:key.privateKey.export({type:"pkcs8",format:"pem"}).toString(),
    SELFHOST_MCP_OIDC_SUBJECT_SALT:"fake-salt"}}).module;
  assert.equal(module.oidcEnabled,true);
  const discovery=await (await module.handle(web("/cloud/.well-known/openid-configuration")))!.json();
  assert.equal(discovery.jwks_uri,ORIGIN+"/cloud/.well-known/jwks.json");
  assert.ok(discovery.scopes_supported.includes("openid"));
  const jwks=await (await module.handle(web("/cloud/.well-known/jwks.json")))!.json();
  assert.deepEqual(jwks.keys.map((key:{kid:string})=>key.kid),["fake-active"]);
  assert.equal(jwks.keys[0].d,undefined);
  const registered=await (await module.handle(web(API+"/register",registration)))!.json();
  assert.equal(registered.id_token_signed_response_alg,"RS256");
});

test("fallback consent escapes client/workspace/state, uses CSP and refuses forged browser capability",async()=>{
  const {module,calls}=harness({resources:[SHARED],name:'</h1><script>alert("x")</script>'});
  const response=(await module.handle(web(pagePath+"&extra=%3C%2Fscript%3E")))!;
  assert.equal(response.status,200);
  const html=await response.text();
  assert.match(html,/&lt;script&gt;/);
  assert.match(html,/&lt;Fake workspace&gt;/);
  assert.ok(!html.includes('</h1><script>alert("x")</script>'));
  assert.ok(html.includes("\\u003c/script>"));
  assert.match(response.headers.get("content-security-policy")!,/frame-ancestors 'none'/);
  assert.equal(response.headers.get("access-control-allow-origin"),null);
  assert.equal(calls.length,0);
  for(const session of [
    {transport:"bearer",principal},
    {transport:"cookie",principal:{...principal,scopes:["relay:mcp"]}},
    {transport:"cookie",principal:{...principal,pendingHandoff:true}},
    {transport:"cookie",principal:{...principal,handoff:true}},
  ] as McpConsentSession[]) {
    const denied=harness({session,resources:[SHARED]}).module;
    const result=(await denied.handle(web(pagePath,undefined,{"sec-fetch-site":"same-origin"})))!;
    assert.equal(result.status,session.transport==="bearer"?302:403);
  }
  const signedOut=(await harness({session:null,resources:[SHARED]}).module.handle(web(pagePath)))!;
  assert.equal(signedOut.status,302);
  assert.equal(new URL(signedOut.headers.get("location")!,ORIGIN).searchParams.get("next"),pagePath);
  assert.equal((await harness({access:false,resources:[SHARED]}).module.handle(web(pagePath)))!.status,404);
});

test("consent HTTP catches store failures and never redirects unregistered callbacks or duplicate parameters",async()=>{
  const {module,calls}=harness({resources:[SHARED]});
  const foreign=new URL(pagePath,ORIGIN);foreign.searchParams.set("redirect_uri","https://evil.example.test/cb");
  const response=(await module.handle(new Request(foreign)))!;
  assert.equal(response.status,400);
  assert.equal(response.headers.get("location"),null);
  assert.equal((await module.handle(web(pagePath+"&client_id=attacker")))!.status,400);
  assert.equal(calls.length,0);
  const failed=(await harness({resources:[SHARED],fail:true}).module.handle(web(pagePath)))!;
  assert.equal(failed.status,500);
  assert.ok(!(await failed.text()).includes("secret"));
  const failedPost=(await harness({resources:[SHARED],fail:true}).module.handle(web(API+"/authorize",
    {params,decision:"approve",workspace_id:principal.workspaceId,agent_name:"fake-agent"})))!;
  assert.equal(failedPost.status,500);
});

test("bounded public requests, CSRF and per-peer registration limits apply before storage",async()=>{
  const {module,calls}=harness({resources:[SHARED]});
  const preflight=(await module.handle(web(API+"/token",undefined,{},"OPTIONS")))!;
  assert.equal(preflight.status,204);
  assert.equal(preflight.headers.get("access-control-allow-origin"),"*");
  assert.equal(preflight.headers.get("access-control-allow-credentials"),null);
  const huge=web(API+"/register",{client_name:"x".repeat(65*1024)});
  assert.equal((await module.handle(huge))!.status,413);
  assert.equal(calls.length,0);
  for(let index=0;index<21;index++) {
    const response=await module.handle(web(API+"/register",registration,{"x-forwarded-for":"192.0.2."+index}),"fake-peer");
    assert.equal(response!.status,index<20?201:429);
  }
  assert.equal(calls.length,20);
  assert.equal((await module.handle(web(API+"/register",registration),"different-peer"))!.status,201);
  const consent={params,decision:"approve",workspace_id:principal.workspaceId,agent_name:"fake-agent"};
  assert.equal((await module.handle(web(API+"/authorize",consent,{origin:"https://evil.example.test"})))!.status,403);
  assert.equal(calls.includes("code"),false);
  assert.equal((await module.handle(web(API+"/authorize",{...consent,workspace_id:"another-workspace"})))!.status,400);
  const approved=(await module.handle(web(API+"/authorize",consent)))!;
  assert.equal(approved.status,200);
  const redirect=new URL((await approved.json()).redirect_to);
  assert.equal(redirect.searchParams.get("code"),"mcpac_fake");
  assert.equal(redirect.searchParams.get("state"),"");
});

test("token, refresh and revocation for known clients never consume the registration limit",async()=>{
  const {module,calls}=harness({resources:[SHARED]});
  for(let index=0;index<500;index++) {
    const response=await module.handle(web(API+"/register",registration),"fake-peer-"+index);
    assert.equal(response!.status,201);
  }
  assert.equal((await module.handle(web(API+"/register",registration),"fake-peer-new"))!.status,429);
  const before=calls.length;
  const token=await module.handle(web(API+"/token",{grant_type:"authorization_code",client_id:client.clientId,code:"mcpac_fake",
    code_verifier:verifier,redirect_uri:client.redirectUris[0],resource}),"fake-peer-new");
  assert.equal(token!.status,200);
  const refresh=await module.handle(web(API+"/token",{grant_type:"refresh_token",client_id:client.clientId,
    refresh_token:"mcp_rt_fake",resource}),"fake-peer-new");
  assert.equal(refresh!.status,400);assert.equal((await refresh!.json()).error,"invalid_grant");
  const revoke=await module.handle(web(API+"/revoke",{token:"mcp_rt_fake",client_id:client.clientId}),"fake-peer-new");
  assert.equal(revoke!.status,200);
  assert.deepEqual(calls.slice(before),["exchange","refresh","revoke"]);
});

test("native HTTP adapter bounds chunked bodies and uses configured issuer instead of Host",async t=>{
  const {module,calls}=harness();
  const server=createServer((req,res)=>{void module.handleNode(req,res).then(handled=>{
    if(!handled) {res.writeHead(404);res.end();}
  }).catch(()=>{res.writeHead(500);res.end();});});
  const base=await listen(server);t.after(()=>close(server));
  const discovery=await fetch(base+"/cloud/.well-known/oauth-authorization-server",{headers:{host:"evil.example.test"}});
  assert.equal((await discovery.json()).issuer,ORIGIN+"/cloud");
  assert.equal((await fetch(base+"/api/oauth/register",{method:"POST",body:"{}"})).status,404);
  const oversized=await new Promise<{status:number;body:string}>((resolve,reject)=>{
    const req=nodeRequest(base+API+"/register",{method:"POST",headers:{"content-type":"application/json"}},res=>{
      const chunks:Buffer[]=[];res.on("data",chunk=>chunks.push(chunk));res.on("end",()=>resolve({status:res.statusCode!,body:Buffer.concat(chunks).toString()}));
    });
    req.on("error",reject);req.write(" ".repeat(40*1024));req.end(" ".repeat(40*1024));
  });
  assert.equal(oversized.status,413);
  assert.equal(JSON.parse(oversized.body).error,"payload_too_large");
  assert.equal(calls.length,0);
});

for(const oidc of [false,true]) test("real store HTTP consent/exchange/refresh/revoke uses only OAuth credentials; OIDC "+oidc,async t=>{
  const database=new PGliteDatabase();t.after(()=>database.close());await migrate(database);
  const owner={userId:randomUUID(),organizationId:randomUUID(),workspaceId:randomUUID()};
  await database.query("INSERT INTO users(id,email,name) VALUES ($1,'fake@example.test','Fake User')",[owner.userId]);
  await database.query("INSERT INTO organizations(id,name) VALUES ($1,'Fake Organization')",[owner.organizationId]);
  await database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES ($1,$2,'member')",[owner.organizationId,owner.userId]);
  await database.query("INSERT INTO workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext) VALUES ($1,$2,'Fake Workspace','fake-relay','fake-envelope')",
    [owner.workspaceId,owner.organizationId]);
  const signing=oidc?generateKeyPairSync("rsa",{modulusLength:2048}):null;
  const module=createMcpOAuthHttpModule({config:config(true,signing?{
    SELFHOST_MCP_OIDC_SIGNING_KEY_ID:"fake-active",
    SELFHOST_MCP_OIDC_SIGNING_KEY:signing.privateKey.export({format:"pem",type:"pkcs8"}).toString(),
    SELFHOST_MCP_OIDC_SUBJECT_SALT:"fake-stable-salt",
  }:{}),mountedResources:[SHARED],
    createStore:({protocol,issuer})=>new McpOAuthStore(database,{protocol,tenancyMode:"multi",isGrokRoutine:()=>false,
      issueIdToken:issuer?.issueMcpOidcIdToken}),
    resolveSession:async()=>({transport:"cookie",principal:{...owner,scopes:["account"]}}),
    workspaceAccess:async()=>true,checkAgentNameAvailability:async()=>"available"});
  const server=createServer((req,res)=>{void module.handleNode(req,res).then(handled=>{
    if(!handled) {res.writeHead(404);res.end();}
  }).catch(()=>{res.writeHead(500);res.end();});});
  const base=await listen(server);t.after(()=>close(server));
  const call=(path:string,body:unknown)=>fetch(base+path,{method:"POST",
    headers:{"content-type":"application/json",origin:ORIGIN},body:JSON.stringify(body)});
  const registered=await (await call(API+"/register",registration)).json();
  const requested={...params,client_id:registered.client_id,...(oidc?{scope:"relay:mcp openid",nonce:"fake-nonce"}:{})};
  const approval=await call(API+"/authorize",{params:requested,decision:"approve",workspace_id:owner.workspaceId,agent_name:"fake-agent"});
  assert.equal(approval.status,200);
  const code=new URL((await approval.json()).redirect_to).searchParams.get("code")!;
  const tokenBody={grant_type:"authorization_code",client_id:registered.client_id,code,
    code_verifier:verifier,redirect_uri:client.redirectUris[0],resource};
  const wrong=await call(API+"/token",{...tokenBody,code_verifier:"wrong-verifier"});
  assert.equal(wrong.status,400);
  const exchange=await call(API+"/token",tokenBody);
  assert.equal(exchange.status,200);
  const pair=await exchange.json();
  assert.match(pair.access_token,/^mcp_at_/);assert.match(pair.refresh_token,/^mcp_rt_/);
  if(oidc) {
    const [header,payload,signature]=pair.id_token.split(".");
    const keys=await (await fetch(base+"/cloud/.well-known/jwks.json")).json();
    assert.equal(JSON.parse(Buffer.from(header,"base64url").toString()).kid,keys.keys[0].kid);
    assert.ok(verify("RSA-SHA256",Buffer.from(header+"."+payload),
      createPublicKey({key:keys.keys[0],format:"jwk"}),Buffer.from(signature,"base64url")));
    const claims=JSON.parse(Buffer.from(payload,"base64url").toString());
    assert.equal(claims.iss,ORIGIN+"/cloud");assert.equal(claims.aud,registered.client_id);
    assert.equal(claims.nonce,"fake-nonce");assert.notEqual(claims.sub,owner.userId);
  } else assert.equal(pair.id_token,undefined);
  assert.equal((await database.query("SELECT id FROM token_sessions")).rows.length,0);
  const refreshed=await call(API+"/token",{grant_type:"refresh_token",client_id:registered.client_id,refresh_token:pair.refresh_token,resource});
  assert.equal(refreshed.status,200);
  const next=await refreshed.json();
  assert.notEqual(next.refresh_token,pair.refresh_token);
  assert.equal((await call(API+"/revoke",{token:next.refresh_token,client_id:registered.client_id})).status,200);
  const refused=await call(API+"/token",{grant_type:"refresh_token",client_id:registered.client_id,refresh_token:next.refresh_token,resource});
  assert.equal(refused.status,400);
  assert.equal((await refused.json()).error,"invalid_grant");
});

test("an unavailable module answers every OAuth path with 501 naming only the reason and leaves other paths alone",async()=>{
  const off=harness({enabled:false}).module;
  assert.equal(off.degraded,null);
  const created:string[]=[];
  const settings=config(true,{SELFHOST_MCP_OIDC_SIGNING_KEY_ID:"fake-active"});
  const modules=[["oidc_signing_key",settings],["public_url",{...config(),publicBaseUrl:"http://relay.example.test"}]] as const;
  for(const [reason,value] of modules) {
    const module=createMcpOAuthHttpModule({config:value,createStore:()=>{created.push(reason);return {} as never;},
      mountedResources:[SHARED],resolveSession:async()=>null,workspaceAccess:async()=>true,
      checkAgentNameAvailability:async()=>"available"});
    assert.equal(module.enabled,false);
    assert.deepEqual(module.degraded,{reason});
    assert.equal(module.store,null);assert.equal(module.protocol,null);assert.equal(module.issuer,null);
    const publicPaths:Array<[string,unknown?]>=[["/cloud/.well-known/oauth-authorization-server"],["/.well-known/openid-configuration/cloud"],
      ["/cloud/.well-known/jwks.json"],["/.well-known/oauth-protected-resource/cloud"+SHARED],["/.well-known/oauth-protected-resource/mcp"],
      [API+"/register",registration],[API+"/token",{grant_type:"authorization_code"}],[API+"/revoke",{token:"fake"}]];
    for(const [path,body] of publicPaths) {
      const response:Response=(await module.handle(web(path,body)))!;
      assert.equal(response.status,501,path);
      assert.equal(response.headers.get("cache-control"),"no-store");
      assert.equal(response.headers.get("access-control-allow-origin"),"*",path);
      assert.deepEqual(await response.json(),{error:"mcp_oauth_unavailable",reason});
    }
    for(const path of [pagePath,API+"/authorize/agent-name?name=x","/cloud/api/v1/oauth/grants","/cloud/api/v1/oauth/grants/"+randomUUID()]) {
      const response:Response=(await module.handle(web(path)))!;
      assert.equal(response.status,501,path);
      assert.equal(response.headers.get("access-control-allow-origin"),null,path);
      assert.equal((await response.json()).reason,reason);
    }
    for(const path of ["/cloud/api/v1/workspaces","/mcp","/api/oauth/register","/cloud"+SHARED]) assert.equal(await module.handle(web(path)),null,path);
    const server=createServer(async(request,response)=>{
      if(!await module.handleNode(request,response)) {response.writeHead(404);response.end();}
    });
    const base=await listen(server);
    try {
      const token=await fetch(base+API+"/token",{method:"POST",headers:{"content-type":"application/x-www-form-urlencoded"},body:"grant_type=x"});
      assert.equal(token.status,501);assert.equal(token.headers.get("cache-control"),"no-store");
      assert.deepEqual(await token.json(),{error:"mcp_oauth_unavailable",reason});
      assert.equal((await fetch(base+"/cloud/api/v1/workspaces")).status,404);
    } finally { await close(server); }
  }
  assert.deepEqual(created,[],"no OAuth store is built while unavailable");
});

test("consent page names where the code goes, labels the client name as self-reported and suggests no shared name",async()=>{
  const remote=await (await harness({resources:[SHARED]}).module.handle(web(pagePath)))!.text();
  assert.match(remote,/<h1>Connect an app calling itself &quot;Fake client&quot;<\/h1>/);
  assert.match(remote,/<header class="brand">/);
  assert.match(remote,/<style nonce="[^"]+">/);
  assert.match(remote,/Returns to: <strong>client\.example\.test<\/strong>/);
  assert.match(remote,/id="caution"><strong>Caution:<\/strong> the app chose its own name/);
  assert.ok(remote.indexOf("Returns to:")<remote.indexOf("This connection may:"));
  assert.match(remote,/<input id="agent" maxlength="128" required value="">/);
  assert.ok(!remote.includes("mcp-agent"));
  assert.match(remote,/<p id="attach-row" hidden><label><input type="checkbox" id="attach"> Attach to my existing agent<\/label><\/p>/);
  assert.match(remote,/attach_existing:true/);
  const loopback="http://127.0.0.1:5000/callback";
  const local=new URL(pagePath,ORIGIN);local.searchParams.set("redirect_uri",loopback);
  const html=await (await harness({resources:[SHARED],redirectUris:[loopback],name:null}).module.handle(new Request(local)))!.text();
  assert.match(html,/<h1>Connect an unnamed app<\/h1>/);
  assert.match(html,/Returns to: <strong>this computer<\/strong>/);
  assert.ok(!html.includes('id="caution"'));
});

test("authorization errors redirect only a signed-in account to the registered callback",async()=>{
  const bad=new URL(pagePath,ORIGIN);bad.searchParams.set("response_type","nope");
  for(const session of [null,{transport:"bearer",principal},{transport:"cookie",principal:{...principal,pendingHandoff:true}}] as Array<McpConsentSession|null>) {
    const anonymous=(await harness({resources:[SHARED],session}).module.handle(new Request(bad)))!;
    assert.equal(anonymous.status,400);
    assert.equal(anonymous.headers.get("location"),null);
    assert.equal((await anonymous.json()).error,"unsupported_response_type");
  }
  const signedIn=(await harness({resources:[SHARED]}).module.handle(new Request(bad)))!;
  assert.equal(signedIn.status,302);
  const location=new URL(signedIn.headers.get("location")!);
  assert.equal(location.origin+location.pathname,client.redirectUris[0]);
  assert.equal(location.searchParams.get("error"),"unsupported_response_type");
});

test("consent attaches a new connection to the user's existing agent only on explicit confirmation",async()=>{
  const consent={params,decision:"approve",workspace_id:principal.workspaceId,agent_name:"fake-agent"};
  const yours=harness({resources:[SHARED],availability:"yours"});
  const unconfirmed=(await yours.module.handle(web(API+"/authorize",consent)))!;
  assert.equal(unconfirmed.status,409);
  const refusal=await unconfirmed.json();
  assert.equal(refusal.error,"agent_name_in_use");
  assert.match(refusal.error_description,/existing agents\. Confirm/);
  assert.equal((await yours.module.handle(web(API+"/authorize",{...consent,attach_existing:false})))!.status,409);
  assert.equal((await yours.module.handle(web(API+"/authorize",{...consent,attach_existing:"yes"})))!.status,400);
  assert.equal(yours.calls.includes("code"),false);
  assert.equal((await yours.module.handle(web(API+"/authorize",{...consent,attach_existing:true})))!.status,200);
  assert.equal(yours.calls.filter(call=>call==="code").length,1);
  const taken=harness({resources:[SHARED],availability:"taken"});
  for(const extra of [{},{attach_existing:true}]) {
    const response=(await taken.module.handle(web(API+"/authorize",{...consent,...extra})))!;
    assert.equal(response.status,409);
    assert.equal((await response.json()).error,"agent_name_taken");
  }
  const unknown=harness({resources:[SHARED],availability:"unknown"});
  assert.equal((await unknown.module.handle(web(API+"/authorize",{...consent,attach_existing:true})))!.status,503);
  assert.equal([...taken.calls,...unknown.calls].some(call=>call.startsWith("code")),false);
  const continued=harness({resources:[SHARED],availability:"yours"});
  assert.equal((await continued.module.handle(web(API+"/authorize",{...consent,continue_grant_id:"fake-existing-grant"})))!.status,200);
  assert.deepEqual(continued.calls,["code:fake-existing-grant"]);
});

test("the start-up notice names the endpoints default-on exposes and the off switch",async()=>{
  const {module}=harness({resources:[SHARED]});
  const notice=mcpOAuthActiveNotice();
  assert.deepEqual(notice,{authorize:"/cloud/oauth/authorize",token:API+"/token",register:API+"/register",disable:"SELFHOST_MCP_OAUTH=off"});
  const metadata=await (await module.handle(web("/cloud/.well-known/oauth-authorization-server")))!.json();
  assert.equal(metadata.authorization_endpoint,ORIGIN+notice.authorize);
  assert.equal(metadata.token_endpoint,ORIGIN+notice.token);
  assert.equal(metadata.registration_endpoint,ORIGIN+notice.register);
});
