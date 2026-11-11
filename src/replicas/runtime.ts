import { z } from "zod";

/** Native server transport for Cloud902c95ea packages/web/lib/replicas/client.ts.
 * Resolve current person/workspace credentials in the owning service first.
 * No retry, provider session, route, worker or runtime capability is enabled here.
 */
const ORIGIN="https://api.replicas.dev/v1";
const VERSION="2026-10-07";
const TIMEOUT_MS=45_000; // exec asks the provider for a 30-second command budget.
const MAX_RESPONSE_BYTES=2*1024*1024;

export class ReplicasRuntimeError extends Error {
  constructor(readonly outcome:"rejected"|"unknown",readonly code:string,readonly status=0) {
    super(code);this.name="ReplicasRuntimeError";
  }
}
const uuid=z.string().uuid();
const identifier=z.string().min(1).max(512).regex(/^[^\p{Cc}\p{Cf}]+$/u);
const cursor=z.string().min(1).max(4096);
const text=z.string().min(1).max(20_000).refine(s=>s.trim().length>0 && Buffer.byteLength(s)<=64*1024);
const replica=z.object({id:uuid,name:z.string().max(4096),status:identifier,
  chats:z.array(z.object({id:uuid,provider:identifier})).optional()});
const historyEvent=z.object({type:identifier,timestamp:z.union([z.string(),z.number().finite()]).optional(),
  payload:z.record(z.string(),z.unknown()).optional()}).passthrough();
const historyPage=z.object({events:z.array(historyEvent),cursor:cursor.nullable().optional(),
  before_cursor:cursor.nullable().optional(),has_more:z.boolean().optional()});
const createInput=z.object({name:z.string().min(1).max(100).regex(/^\S+$/),environment_id:uuid,
  coding_agent:z.enum(["claude","codex"]),model:identifier.optional(),message:text,lifecycle_policy:z.literal("default")}).strict();
export type Replica=z.infer<typeof replica>;
export type ReplicaHistoryPage=z.infer<typeof historyPage>;
export type ReplicasCreateInput=z.infer<typeof createInput>;

function input<T>(schema:z.ZodType<T>,value:unknown):T {
  const parsed=schema.safeParse(value);
  if(!parsed.success) throw new ReplicasRuntimeError("rejected","replicas_invalid_input");
  return parsed.data;
}
async function bounded<T>(work:()=>Promise<T>,signal:AbortSignal):Promise<T> {
  signal.throwIfAborted();let onAbort!:()=>void;
  const aborted=new Promise<never>((_resolve,reject)=>{
    onAbort=()=>reject(signal.reason);signal.addEventListener("abort",onAbort,{once:true});
  });
  try {return await Promise.race([work(),aborted]);}
  finally {signal.removeEventListener("abort",onAbort);}
}
async function json(response:Response,signal:AbortSignal):Promise<unknown> {
  if(!response.body) throw new Error("invalid_body");
  const reader=response.body.getReader(),chunks:Uint8Array[]=[];let bytes=0;
  try {
    for(;;) {
      const chunk=await bounded(()=>reader.read(),signal);if(chunk.done) break;
      bytes+=chunk.value.byteLength;if(bytes>MAX_RESPONSE_BYTES) throw new Error("invalid_body");
      chunks.push(chunk.value);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } finally {void reader.cancel().catch(()=>undefined);reader.releaseLock();}
}

export function createReplicasRuntime(options:{fetchImpl?:typeof fetch;timeoutMs?:number}={}) {
  const fetchImpl=options.fetchImpl??fetch;
  const timeoutMs=input(z.number().int().min(1).max(TIMEOUT_MS),options.timeoutMs??TIMEOUT_MS);
  async function call<T>(key:string,path:string,schema:z.ZodType<T>,body?:Record<string,unknown>,allowEmpty=false):Promise<T> {
    input(z.string().regex(/^[A-Za-z0-9_.-]{16,512}$/),key); // canonical remote-agent-connections grammar
    const write=body!==undefined,controller=new AbortController(),signal=controller.signal;
    // Own a ref'd deadline: even a non-cooperative fetch in an otherwise
    // idle process must settle the caller, rather than let Node exit early.
    const timer=setTimeout(()=>controller.abort(new Error("replicas_deadline")),timeoutMs);
    try {
      const response=await bounded(()=>fetchImpl(ORIGIN+path,{method:write?"POST":"GET",redirect:"error",cache:"no-store",signal,
        headers:{authorization:`Bearer ${key}`,"X-Replicas-Api-Version":VERSION,accept:"application/json","content-type":"application/json"},
        ...(write?{body:JSON.stringify(body)}:{})}).then(response=>{
          if(signal.aborted) void response.body?.cancel().catch(()=>undefined);return response;
        }),signal);
      if(!response.ok) {
        // No error body is needed or trusted: status-based rejection survives
        // empty/HTML/oversized errors, and cancellation cannot delay the result.
        void response.body?.cancel().catch(()=>undefined);
        throw new ReplicasRuntimeError(write && response.status>=500?"unknown":"rejected",`replicas_http_${response.status}`,response.status);
      }
      // Lifecycle commands can acknowledge with no representation. A 204 does
      // not prove final sleep/wake state; the service must read it separately.
      if(response.status===204 && allowEmpty) return schema.parse(null);
      let decoded:unknown;
      try {decoded=await json(response,signal);}
      catch {throw new ReplicasRuntimeError(write?"unknown":"rejected",signal.aborted?"replicas_deadline":"replicas_invalid_response",signal.aborted?0:response.status);}
      const parsed=schema.safeParse(decoded);
      if(!parsed.success) throw new ReplicasRuntimeError(write?"unknown":"rejected","replicas_invalid_response",response.status);
      return parsed.data;
    } catch(error) {
      if(error instanceof ReplicasRuntimeError) throw error;
      throw new ReplicasRuntimeError(write?"unknown":"rejected",signal.aborted?"replicas_deadline":"replicas_transport_unavailable");
    } finally {clearTimeout(timer);}
  }
  return {
    identity:(key:string)=>call(key,"/whoami",z.object({organization:z.object({id:identifier,name:z.string().max(4096)})})),
    environments:(key:string)=>call(key,"/environments",z.object({environments:z.array(z.object({id:uuid,name:z.string().max(4096)}))})),
    create:async(key:string,value:ReplicasCreateInput)=>call(key,"/replica",z.object({replica}),input(createInput,value)),
    list:async(key:string,page:number)=>{
      input(z.number().int().min(1).max(1_000_000),page);
      return call(key,`/replica?page=${page}&limit=100`,z.object({replicas:z.array(replica).max(100),page:z.number().int(),
        total_pages:z.number().int().min(0)}).refine(value=>value.page===page));
    },
    get:async(key:string,id:string)=>{input(uuid,id);return call(key,`/replica/${id}`,z.object({replica}).refine(value=>value.replica.id.toLowerCase()===id.toLowerCase()));},
    message:async(key:string,id:string,chatId:string,message:string)=>{
      input(uuid,id);input(uuid,chatId);input(text,message);
      return call(key,`/replica/${id}/messages`,z.object({status:identifier,message_id:identifier}),{chat_id:chatId,message});
    },
    history:async(key:string,id:string,chatId:string,beforeCursor?:string)=>{
      input(uuid,id);input(uuid,chatId);if(beforeCursor!==undefined) input(cursor,beforeCursor);
      const query=new URLSearchParams({chat_id:chatId});if(beforeCursor!==undefined) query.set("before_cursor",beforeCursor);
      return call(key,`/replica/${id}/history?${query}`,historyPage);
    },
    exec:async(key:string,id:string,command:string)=>{
      input(uuid,id);input(z.string().min(1).refine(s=>s.trim().length>0 && Buffer.byteLength(s)<=64*1024),command);
      return call(key,`/replica/${id}/exec`,z.object({exit_code:z.number().int().nullable(),timed_out:z.boolean()}),{command,timeout_seconds:30});
    },
    sleep:async(key:string,id:string)=>{input(uuid,id);return call(key,`/replica/${id}/sleep`,z.unknown(),{},true);},
    wake:async(key:string,id:string)=>{input(uuid,id);return call(key,`/replica/${id}/wake`,z.unknown(),{},true);},
  };
}
export type ReplicasRuntime=ReturnType<typeof createReplicasRuntime>;
