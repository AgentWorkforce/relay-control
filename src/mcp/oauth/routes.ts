import { randomBytes } from "node:crypto";
import type { IncomingMessage,ServerResponse } from "node:http";
import type { SelfhostConfig } from "../../config.js";
import { RateLimiter } from "../../auth/device-approval.js";
import { APP_BASE_PATH,createMcpOAuthProtocol,type McpOAuthResourcePath } from "./protocol.js";
import { createMcpOidcIssuer } from "./oidc.js";
import { createMcpOAuthPublicHandlers,type McpOAuthPublicStore } from "./public-handlers.js";
import { createMcpOAuthConsentHandlers,resolveMcpConsentAccount,type McpConsentPrincipal,
  type McpConsentSession,type McpOAuthConsentStore,type AgentNameAvailability } from "./consent.js";

const MAX_BODY=64*1024;
const API=`${APP_BASE_PATH}/api/oauth`;
const AUTHORIZE=`${APP_BASE_PATH}/oauth/authorize`;
const GRANTS=`${APP_BASE_PATH}/api/v1/oauth/grants`;
class BodyLimit extends Error {}
function json(body:unknown,status=200) {
  return Response.json(body,{status,headers:{"cache-control":"no-store",pragma:"no-cache"}});
}
function escaped(value:string):string {
  return value.replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;")
    .replaceAll('"',"&quot;").replaceAll("'","&#39;");
}
async function bounded(request:Request):Promise<Request> {
  if(Number(request.headers.get("content-length"))>MAX_BODY) throw new BodyLimit();
  const reader=request.body?.getReader();
  if(!reader) return request;
  const chunks:Uint8Array[]=[];let size=0;
  try {
    for(;;) {
      const part=await reader.read();if(part.done) break;
      size+=part.value.byteLength;if(size>MAX_BODY) throw new BodyLimit();chunks.push(part.value);
    }
    return new Request(request.url,{method:request.method,headers:request.headers,body:Buffer.concat(chunks).toString("utf8")});
  } finally { await reader.cancel().catch(()=>{}); }
}

type Connections = Array<{id:string;agentName:string}>;
type TenantOwner = Pick<McpConsentPrincipal,"userId"|"organizationId"|"workspaceId">;
type ManagedGrant = {
  id:string;clientId:string;clientName:string|null;organizationId:string;workspaceId:string;
  agentName:string;scopes:string[];resource:string;createdAt:Date;
};
type OAuthHttpStore = McpOAuthPublicStore & McpOAuthConsentStore & {
  listMcpOAuthGrantsForUser?(owner:Pick<McpConsentPrincipal,"userId"|"organizationId"|"workspaceId">,
    connection?:{clientId:string;resource:string}):Promise<ManagedGrant[]>;
  getOAuthGrant?(id:string,owner:TenantOwner):Promise<ManagedGrant|null>;
  revokeMcpOAuthGrant?(id:string,reason:string):Promise<boolean>;
};

/** An HTTP composition. Callers declare only MCP resources they actually mounted. */
export function createMcpOAuthHttpModule<Store extends OAuthHttpStore>(deps:{
  config:SelfhostConfig;
  createStore(context:{
    protocol:ReturnType<typeof createMcpOAuthProtocol>;
    issuer:ReturnType<typeof createMcpOidcIssuer>|null;
  }):Store;
  mountedResources?:readonly McpOAuthResourcePath[];
  resolveSession(request:Request):Promise<McpConsentSession|null>;
  workspaceAccess(principal:TenantOwner):Promise<boolean>;
  workspaceLabel?(principal:McpConsentPrincipal):Promise<string>;
  checkAgentNameAvailability(principal:TenantOwner,name:string):Promise<AgentNameAvailability>;
  now?:()=>Date;
  afterMutation?():void;
}) {
  const settings=deps.config.mcpOAuth;
  const enabled=settings?.enabled===true;
  if(!enabled) return {enabled:false as const,protocol:null,oidcEnabled:false,issuer:null,store:null,
    handle:async(_request:Request,_clientAddress?:string):Promise<Response|null>=>null,
    handleNode:async(_request:IncomingMessage,_response:ServerResponse)=>false};
  const origin=new URL(deps.config.publicBaseUrl).origin;
  const now=()=>deps.now?.()??new Date();
  const issuer=settings.oidc?createMcpOidcIssuer(settings.oidc):null;
  const oidcEnabled=issuer!==null;
  const resources=[...(deps.mountedResources??[])].filter(resource=>
    resource!=="/api/v1/mcp/relay-events" || settings.eventsEnabled);
  const protocol=createMcpOAuthProtocol({publicOrigin:origin,enabledResources:resources,
    mountedEndpoints:["authorization","token","registration","revocation",...(oidcEnabled?["jwks" as const]:[])],oidcEnabled});
  const store=deps.createStore({protocol,issuer});
  const limiter=new RateLimiter(()=>now().getTime());
  const addresses=new WeakMap<Request,string>();
  const publicHandlers=createMcpOAuthPublicHandlers({store,oidcEnabled,allowRegistration:request=>{
    // TCP peer identity is supplied by the adapter, never an arbitrary forwarded header.
    if(!limiter.consume("registration-global",500,3_600_000).allowed) return false;
    return limiter.consume(`registration:${addresses.get(request)??"unknown"}`,20,3_600_000).allowed;
  }});
  const consent=createMcpOAuthConsentHandlers({protocol,store,resolveSession:deps.resolveSession,
    workspaceAccess:deps.workspaceAccess,checkAgentNameAvailability:deps.checkAgentNameAvailability,
    now:()=>now().getTime()});
  const metadata=new Map(resources.map(resource=>[new URL(protocol!.protectedResourceMetadataUrl(resource)).pathname,resource]));
  const discovery=new Set([`${APP_BASE_PATH}/.well-known/oauth-authorization-server`,`${APP_BASE_PATH}/.well-known/openid-configuration`,
    "/.well-known/oauth-authorization-server/cloud","/.well-known/openid-configuration/cloud"]);
  const jwks=`${APP_BASE_PATH}/.well-known/jwks.json`;

  function recognizes(path:string):boolean {
    return enabled && (discovery.has(path)||metadata.has(path)||path===AUTHORIZE||path===`${API}/authorize`||
      path===`${API}/authorize/agent-name`||path===GRANTS||path.startsWith(GRANTS+"/")||
      [`${API}/register`,`${API}/token`,`${API}/revoke`,jwks].includes(path));
  }
  function cors(response:Response):Response {
    response.headers.set("access-control-allow-origin","*");
    response.headers.set("access-control-allow-methods","GET, POST, OPTIONS");
    response.headers.set("access-control-allow-headers","content-type, authorization");
    return response;
  }
  function publicRoute(path:string) {
    return discovery.has(path)||metadata.has(path)||[`${API}/register`,`${API}/token`,`${API}/revoke`,jwks].includes(path);
  }

  async function page(request:Request,url:URL):Promise<Response> {
    for(const key of new Set(url.searchParams.keys())) {
      if(url.searchParams.getAll(key).length>1) return json({error:"invalid_request",error_description:"Repeated authorization parameter."},400);
    }
    const params=Object.fromEntries(url.searchParams);
    const client=await store.getMcpOAuthClient(params.client_id);
    const validated=protocol!.validateAuthorizationRequest(params,client);
    if(!validated.ok) {
      return validated.redirect?Response.redirect(protocol!.authorizationResponseUrl(validated.redirectUri,
        {...validated.error,state:validated.state}),302):json(validated.error,400);
    }
    const principal=await resolveMcpConsentAccount(request,deps.resolveSession);
    if(principal instanceof Response) {
      if(principal.status===401) return new Response(null,{status:302,headers:{location:`/login?${new URLSearchParams({next:url.pathname+url.search})}`,"cache-control":"no-store"}});
      return principal;
    }
    if(!await deps.workspaceAccess(principal)) return json({error:"invalid_workspace"},404);
    const workspace=await deps.workspaceLabel?.(principal)??principal.workspaceId;
    const requestValue=validated.value;
    const existingRows=protocol!.canContinueEventsConsent(requestValue) && store.listMcpOAuthGrantsForUser
      ?await store.listMcpOAuthGrantsForUser(principal,{clientId:requestValue.clientId,resource:requestValue.resource}):[];
    const existing:Connections=existingRows.map(({id,agentName})=>({id,agentName}));
    const nonce=randomBytes(18).toString("base64url");
    const payload=JSON.stringify({params,workspaceId:principal.workspaceId,connections:existing}).replaceAll("<","\\u003c");
    const suggested=requestValue.requestedAgentName??"mcp-agent";
    const labels:Record<string,string>={"relay:mcp":"Use available MCP tools in this workspace","relay:agents":"Request supported agent actions",
      "relay:events":"Receive subscribed workspace events",openid:"Share a stable identifier specific to this client"};
    const connectionSelect=existing.length?`<label>Existing connection <select id="connection"><option value="">New connection</option>${existing.map(row=>`<option value="${escaped(row.id)}">${escaped(row.agentName)}</option>`).join("")}</select></label>`:"";
    const body=`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect Agent Relay</title>
<body><main><h1>Connect ${escaped(client!.clientName??"MCP client")}</h1><p>Workspace: <strong>${escaped(workspace)}</strong></p>
<p>This connection may:</p><ul>${requestValue.scopes.map(scope=>`<li>${escaped(labels[scope]??scope)}</li>`).join("")}</ul>
<form id="consent">${connectionSelect}<p><label>Approved agent name <input id="agent" maxlength="128" required value="${escaped(suggested)}"></label></p>
<button type="submit">Connect</button> <button type="button" id="deny">Cancel</button></form><p id="error" role="alert"></p></main>
<script nonce="${nonce}">const data=${payload};const form=document.getElementById('consent'),agent=document.getElementById('agent'),connection=document.getElementById('connection');
if(connection)connection.addEventListener('change',()=>{const chosen=data.connections.find(row=>row.id===connection.value);if(chosen)agent.value=chosen.agentName;});
async function decide(decision){const buttons=form.querySelectorAll('button');buttons.forEach(button=>button.disabled=true);try{const response=await fetch('${API}/authorize',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({params:data.params,workspace_id:data.workspaceId,agent_name:agent.value,decision,...(connection&&connection.value?{continue_grant_id:connection.value}:{})})});const value=await response.json();if(response.ok&&typeof value.redirect_to==='string'){location.assign(value.redirect_to);return;}document.getElementById('error').textContent=value.error_description||'Connection could not be completed.';}catch{document.getElementById('error').textContent='Connection could not be completed. Try again.';}buttons.forEach(button=>button.disabled=false);}
form.addEventListener('submit',event=>{event.preventDefault();decide('approve');});document.getElementById('deny').addEventListener('click',()=>decide('deny'));</script></body></html>`;
    return new Response(body,{headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store","referrer-policy":"no-referrer",
      "content-security-policy":`default-src 'none'; script-src 'nonce-${nonce}'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`,
      "x-content-type-options":"nosniff"}});
  }

  async function handle(request:Request,clientAddress="unknown"):Promise<Response|null> {
    const url=new URL(request.url);
    const path=url.pathname.replace(/\/+$/,"")||"/";
    if(!recognizes(path)) return null;
    const isPublic=publicRoute(path);
    const finish=(response:Response)=>isPublic?cors(response):response;
    if(request.method==="OPTIONS" && isPublic) return finish(new Response(null,{status:204}));
    try {
      if(path===GRANTS || path.startsWith(GRANTS+"/")) {
        const principal=await resolveMcpConsentAccount(request,deps.resolveSession);
        if(principal instanceof Response) return principal;
        if(!await deps.workspaceAccess(principal)) return json({error:"not_found"},404);
        if(request.method==="GET" && path===GRANTS && store.listMcpOAuthGrantsForUser) {
          const grants=await store.listMcpOAuthGrantsForUser(principal);
          return json({grants:grants.map(grant=>({
            id:grant.id,client_id:grant.clientId,client_name:grant.clientName,
            organization_id:grant.organizationId,workspace_id:grant.workspaceId,
            agent_name:grant.agentName,scopes:grant.scopes,resource:grant.resource,created_at:grant.createdAt.toISOString(),
          }))});
        }
        if(request.method==="DELETE" && store.getOAuthGrant && store.revokeMcpOAuthGrant) {
          if(request.headers.get("origin")!==origin) return json({error:"forbidden"},403);
          const id=path.slice(GRANTS.length+1);
          if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu.test(id)) return json({error:"not_found"},404);
          const grant=await store.getOAuthGrant(id,principal);
          if(!grant) return json({error:"not_found"},404);
          await store.revokeMcpOAuthGrant(grant.id,"user_revoked");deps.afterMutation?.();
          return new Response(null,{status:204,headers:{"cache-control":"no-store"}});
        }
        const result=json({error:"method_not_allowed"},405);result.headers.set("allow",path===GRANTS?"GET":"DELETE");return result;
      }
      if(request.method==="GET") {
        if(discovery.has(path)) return finish(json(protocol!.authorizationServerMetadata()));
        if(metadata.has(path)) {
          const resource=metadata.get(path)!;
          return finish(json(protocol!.protectedResourceMetadata(resource,protocol!.requestAgentNameHint(request.url,resource))));
        }
        if(path===jwks) return finish(issuer?json(issuer.mcpOidcJwks(now())):json({error:"not_found"},404));
        if(path===AUTHORIZE) return await page(request,url);
        if(path===`${API}/authorize/agent-name`) return await consent!.agentName(request);
      }
      if(request.method==="POST" && [`${API}/register`,`${API}/token`,`${API}/revoke`,`${API}/authorize`].includes(path)) {
        const ready=await bounded(request);addresses.set(ready,clientAddress);
        if(path===`${API}/register`) return finish(await publicHandlers.register(ready));
        if(path===`${API}/token`) {
          const result=await publicHandlers.token(ready);deps.afterMutation?.();return finish(result);
        }
        if(path===`${API}/revoke`) {
          const result=await publicHandlers.revoke(ready);deps.afterMutation?.();return finish(result);
        }
        return await consent!.authorize(ready);
      }
      const response=json({error:"method_not_allowed"},405);
      response.headers.set("allow",path===AUTHORIZE||path===API+"/authorize/agent-name"||discovery.has(path)||metadata.has(path)||path===jwks?"GET":"POST");
      return finish(response);
    } catch(error) {
      return finish(json({error:error instanceof BodyLimit?"payload_too_large":"server_error"},error instanceof BodyLimit?413:500));
    }
  }

  async function handleNode(request:IncomingMessage,response:ServerResponse):Promise<boolean> {
    let url:URL;
    try {
      const parsed=new URL(request.url??"/",origin);
      url=new URL(parsed.pathname+parsed.search,origin);
    } catch { return false; }
    if(!recognizes(url.pathname.replace(/\/+$/,"")||"/")) return false;
    const headers=new Headers();for(const [name,value] of Object.entries(request.headers)) if(value!==undefined) headers.set(name,Array.isArray(value)?value.join(", "):value);
    let text:string|undefined;
    try {
      if(request.method!=="GET" && request.method!=="HEAD") {
        if(Number(request.headers["content-length"])>MAX_BODY) throw new BodyLimit();
        text=await new Promise<string>((resolve,reject)=>{
          const chunks:Buffer[]=[];let size=0;
          const cleanup=()=>{request.off("data",data);request.off("end",end);request.off("error",failed);request.off("aborted",aborted);};
          const failed=(error:Error)=>{cleanup();request.pause();reject(error);};
          const aborted=()=>failed(new Error("Request aborted"));
          const data=(chunk:Buffer|string)=>{
            const part=Buffer.isBuffer(chunk)?chunk:Buffer.from(chunk);size+=part.length;
            if(size>MAX_BODY) {failed(new BodyLimit());return;} chunks.push(part);
          };
          const end=()=>{cleanup();resolve(Buffer.concat(chunks).toString("utf8"));};
          request.on("data",data);request.on("end",end);request.on("error",failed);request.on("aborted",aborted);
        });
      }
    } catch(error) {
      response.writeHead(error instanceof BodyLimit?413:400,{"content-type":"application/json","cache-control":"no-store",connection:"close"});
      response.end(JSON.stringify({error:error instanceof BodyLimit?"payload_too_large":"invalid_request"}));return true;
    }
    const result=await handle(new Request(url,{method:request.method??"GET",headers,...(text===undefined?{}:{body:text})}),request.socket.remoteAddress??"unknown");
    if(!result) return false;
    const responseHeaders:Record<string,string>={};result.headers.forEach((value,key)=>{responseHeaders[key]=value;});
    response.writeHead(result.status,responseHeaders);response.end(Buffer.from(await result.arrayBuffer()));return true;
  }
  return {enabled,protocol,oidcEnabled,issuer,store,handle,handleNode};
}
