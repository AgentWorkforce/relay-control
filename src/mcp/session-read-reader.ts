import { createHash } from "node:crypto";
import { z } from "zod";
import type { SelfhostConfig } from "../config.js";
import { ReadCursorExpiredError, UpstreamError } from "../relayhistory.js";
import { isRecord, WORKSPACE_ATTESTATION_HEADER, UNSUPPORTED_BY_BACKEND, type HistoryIdentity, type HistoryRead } from "../sessions/history.js";

/** Client configuration deliberately excludes the issuer URL and internal secret. */
type ReaderConfig = Pick<SelfhostConfig,"publicBaseUrl"|"sessionReadMcpReads"> & {
  sessionReadApi?: Pick<NonNullable<SelfhostConfig["sessionReadApi"]>,"publicUrl"> | null;
};

/** Per-user reader client. Only Control sees the reader's internal issuer secret. */
const READ_ROUTES = /^\/v1\/(?:events|sessions(?:\/activity|\/[^/]+\/(?:turns|metadata|events))?)$/;
const READ_API_CURSOR = /^b96[a-z][0-9]+:/;
const EXPIRY_MARGIN_MS = 30_000;
const CACHE_LIMIT = 1_000;
const HANDOFF_MAX_BYTES = 16_384;
const opaque = (prefix:string) => z.string().max(4096).regex(new RegExp(`^${prefix}[A-Za-z0-9_-]{43,}$`));
const pairSchema = z.object({
  baseUrl:z.string(), sessionId:z.string().min(1).max(256), userId:z.string(), orgId:z.string(), workspaceId:z.string(),
  audience:z.string(), scopes:z.tuple([z.literal("rth:read")]), tokenType:z.literal("Bearer"),
  accessToken:opaque("rth_at_read_"), refreshToken:opaque("rth_rt_read_"),
  accessTokenExpiresAt:z.iso.datetime({offset:true}), refreshTokenExpiresAt:z.iso.datetime({offset:true}),
});
type Held = { sessionId:string; baseUrl:string; accessToken:string; accessExpiresAt:number; refreshToken:string; refreshExpiresAt:number };
const caches = new WeakMap<ReaderConfig,Map<string,Promise<Held>>>();

function cacheFor(config:ReaderConfig) {
  let cache=caches.get(config);
  if(!cache) { cache=new Map(); caches.set(config,cache); }
  return cache;
}
function cacheKey(identity:HistoryIdentity) {
  const hash=createHash("sha256").update(identity.callerToken).digest("hex");
  return JSON.stringify([identity.userId,identity.organizationId,identity.workspaceId,hash]);
}
export function forgetSessionReadTokens(config:ReaderConfig):void { caches.delete(config); }
function refused(error:unknown):boolean {
  return error instanceof UpstreamError && [401,403,404].includes(error.status??0);
}

async function handoffJson(response:Response):Promise<unknown> {
  const reader=response.body?.getReader();
  if(!reader) throw new UpstreamError("exchange");
  const chunks:Uint8Array[]=[];let size=0;
  try {
    for(;;) {
      const part=await reader.read();if(part.done) break;
      size+=part.value.byteLength;
      if(size>HANDOFF_MAX_BYTES) throw new UpstreamError("exchange");
      chunks.push(part.value);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } finally { await reader.cancel().catch(()=>{}); }
}

async function issue(config:ReaderConfig,identity:HistoryIdentity,previous:Held|null):Promise<Held> {
  const api=config.sessionReadApi!;
  // Caller authority goes only to the configured Control origin. The read
  // client never sends user/org/scopes overrides or an internal/service secret.
  const path=`/api/v1/workspaces/${encodeURIComponent(identity.workspaceId)}/session-read/${previous?"refresh":"session"}`;
  let response:Response;
  try {
    response=await globalThis.fetch(new URL(path,config.publicBaseUrl),{
      method:"POST",redirect:"error",signal:AbortSignal.timeout(10_000),
      headers:{accept:"application/json","content-type":"application/json",authorization:`Bearer ${identity.callerToken}`},
      body:JSON.stringify(previous?{refreshToken:previous.refreshToken}:{label:"mcp"}),
    });
  } catch { throw new UpstreamError("exchange"); }
  if(!response.ok) {
    await response.body?.cancel().catch(()=>{});
    throw new UpstreamError("exchange",response.status);
  }
  let value:unknown;
  try { value=await handoffJson(response); } catch { throw new UpstreamError("exchange"); }
  const result=pairSchema.safeParse(value);
  if(!result.success) throw new UpstreamError("exchange");
  const pair=result.data,now=Date.now();
  const accessExpiresAt=Date.parse(pair.accessTokenExpiresAt),refreshExpiresAt=Date.parse(pair.refreshTokenExpiresAt);
  if(pair.userId!==identity.userId || pair.orgId!==identity.organizationId || pair.workspaceId!==identity.workspaceId ||
    pair.baseUrl!==api.publicUrl || pair.audience!==api.publicUrl || accessExpiresAt<=now || accessExpiresAt>now+3_600_000 ||
    refreshExpiresAt<accessExpiresAt || (previous && (pair.refreshToken===previous.refreshToken || pair.sessionId!==previous.sessionId))) {
    throw new UpstreamError("exchange");
  }
  return {sessionId:pair.sessionId,baseUrl:pair.baseUrl,accessToken:pair.accessToken,accessExpiresAt,refreshToken:pair.refreshToken,refreshExpiresAt};
}

async function heldSession(config:ReaderConfig,identity:HistoryIdentity,rejectedAccess?:string):Promise<Held> {
  const cache=cacheFor(config),key=cacheKey(identity),existing=cache.get(key);
  const current=existing?await existing.catch(error=>{if(refused(error)) throw error;return null;}):null;
  if(current && current.accessToken!==rejectedAccess && current.accessExpiresAt-EXPIRY_MARGIN_MS>Date.now()) return current;
  const latest=cache.get(key);
  if(latest && latest!==existing) return latest;
  const previous=current && current.refreshExpiresAt-EXPIRY_MARGIN_MS>Date.now()?current:null;
  const pending=issue(config,identity,previous);
  if(!cache.has(key) && cache.size>=CACHE_LIMIT) cache.delete(cache.keys().next().value!);
  cache.set(key,pending);
  // Keep a refused session refused for this caller cache entry; do not turn a
  // failed refresh into fresh issuance on the next tool invocation.
  void pending.catch(error=>{
    if(!refused(error) && cache.get(key)===pending) {
      // An unavailable refresh has not authorized new issuance. Retain the
      // previous pair so the next attempt retries the same refresh lineage.
      if(previous) cache.set(key,Promise.resolve(previous));
      else cache.delete(key);
    }
  });
  return pending;
}

export async function readViaSessionRead(config:ReaderConfig,identity:HistoryIdentity,path:string,params:URLSearchParams):Promise<HistoryRead|null> {
  const cursor=params.get("cursor");
  const selected=Boolean(config.sessionReadMcpReads && config.sessionReadApi && READ_ROUTES.test(path));
  // Every History reader is the read API, so its cursors stay valid either way.
  if(!selected) return null;
  // A foreign/legacy cursor cannot silently switch the selected backend.
  if(cursor && !READ_API_CURSOR.test(cursor)) throw new ReadCursorExpiredError();
  const query=new URLSearchParams(params);query.delete("workspace");query.set("workspace",identity.workspaceId);
  let rejectedAccess:string|undefined;
  for(let attempt=0;attempt<2;attempt++) {
    const held=await heldSession(config,identity,rejectedAccess);
    const url=new URL(`${path}?${query}`,held.baseUrl);
    if(url.origin!==new URL(held.baseUrl).origin) throw new UpstreamError("read");
    let response:Response;
    try {
      response=await globalThis.fetch(url,{method:"GET",redirect:"error",signal:AbortSignal.timeout(15_000),
        headers:{accept:"application/json",authorization:`Bearer ${held.accessToken}`}});
    } catch { throw new UpstreamError("read"); }
    if(response.status===401 && attempt===0) {
      await response.body?.cancel().catch(()=>{});
      rejectedAccess=held.accessToken; // Refresh through Control once, never remint.
      continue;
    }
    // Selection is final: every 501 stays unsupported on this backend,
    // regardless of the response's reason or whether this is the first page.
    if(response.status===501) {
      await response.body?.cancel().catch(()=>{});
      return {status:"unsupported",reason:UNSUPPORTED_BY_BACKEND};
    }
    if(!response.ok) {
      await response.body?.cancel().catch(()=>{});
      if(response.status===410 && cursor) throw new ReadCursorExpiredError();
      throw new UpstreamError("read",response.status);
    }
    if(response.headers.get(WORKSPACE_ATTESTATION_HEADER)!==identity.workspaceId) {
      await response.body?.cancel().catch(()=>{});
      throw new UpstreamError("read",response.status,"RelayHistory did not attest the workspace");
    }
    const body:unknown=await response.json().catch(()=>null);
    if(!isRecord(body)) throw new UpstreamError("read",response.status);
    return {status:"ok",body};
  }
  throw new UpstreamError("read",401);
}
