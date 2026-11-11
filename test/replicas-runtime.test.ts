import assert from "node:assert/strict";
import test from "node:test";
import { createServer, type Server } from "node:http";
import { createReplicasRuntime, ReplicasRuntimeError } from "../src/replicas/runtime.js";

const KEY="replicas_test_key_123456789";
const RID="14c16b8e-12f4-4f37-b345-a564e41c33fe", CID="5028b49b-29aa-4686-927c-fca5e92614f5", ENV="fc098dd2-f8c1-4b48-86db-056019b65a18";
const replica={id:RID,name:"test-replica",status:"active",chats:[{id:CID,provider:"codex"}]};
const creation={name:"test-replica",environment_id:ENV,coding_agent:"codex" as const,message:"do the task",lifecycle_policy:"default" as const};
const failure=(code:string,outcome:"rejected"|"unknown",status=0)=>(error:unknown)=>{
  assert.ok(error instanceof ReplicasRuntimeError);assert.equal(error.code,code);assert.equal(error.outcome,outcome);assert.equal(error.status,status);
  assert.equal(error.message.includes(KEY),false);return true;
};

test("Replicas uses fixed versioned endpoints and typed replies for every supported operation",async()=>{
  const calls:Array<{url:string;init:RequestInit}>=[];
  const replies=[{organization:{id:"org_replica",name:"Org"}},{environments:[{id:ENV,name:"Dev"}]},
    {replica},{replicas:[replica],page:2,total_pages:3},{replica},{status:"queued",message_id:"msg_opaque"},
    {events:[{type:"claude:user",timestamp:1,payload:{uuid:"event_1",custom:{kept:true}},extra:"kept"}],before_cursor:"opaque?&",has_more:true},
    {exit_code:0,timed_out:false},{status:"sleeping"},null];
  const runtime=createReplicasRuntime({fetchImpl:async(url,init)=>{
    calls.push({url:String(url),init:init!});const value=replies.shift();return value===null?new Response(null,{status:204}):Response.json(value);
  }});
  assert.equal((await runtime.identity(KEY)).organization.id,"org_replica");
  assert.equal((await runtime.environments(KEY)).environments[0]!.id,ENV);
  assert.equal((await runtime.create(KEY,creation)).replica.id,RID);
  assert.equal((await runtime.list(KEY,2)).page,2);
  assert.equal((await runtime.get(KEY,RID)).replica.id,RID);
  assert.equal((await runtime.message(KEY,RID,CID,"preserve\n  indentation")).message_id,"msg_opaque");
  const history=await runtime.history(KEY,RID,CID,"opaque?&");
  assert.deepEqual(history.events[0]!.payload?.custom,{kept:true});assert.equal(history.events[0]!.extra,"kept");
  assert.deepEqual(await runtime.exec(KEY,RID,"printf hello"),{exit_code:0,timed_out:false});
  assert.deepEqual(await runtime.sleep(KEY,RID),{status:"sleeping"});assert.equal(await runtime.wake(KEY,RID),null);
  assert.deepEqual(calls.map(c=>[c.init.method,new URL(c.url).pathname,new URL(c.url).search]),[
    ["GET","/v1/whoami",""],["GET","/v1/environments",""],["POST","/v1/replica",""],
    ["GET","/v1/replica","?page=2&limit=100"],["GET",`/v1/replica/${RID}`,""],
    ["POST",`/v1/replica/${RID}/messages`,""],["GET",`/v1/replica/${RID}/history`,`?chat_id=${CID}&before_cursor=opaque%3F%26`],
    ["POST",`/v1/replica/${RID}/exec`,""],["POST",`/v1/replica/${RID}/sleep`,""],["POST",`/v1/replica/${RID}/wake`,""],
  ]);
  for(const call of calls) {
    assert.equal(new URL(call.url).origin,"https://api.replicas.dev");assert.equal(call.init.redirect,"error");assert.equal(call.init.cache,"no-store");
    const headers=new Headers(call.init.headers);assert.equal(headers.get("authorization"),`Bearer ${KEY}`);
    assert.equal(headers.get("X-Replicas-Api-Version"),"2026-10-07");assert.ok(call.init.signal);
  }
  assert.deepEqual(JSON.parse(String(calls[2]!.init.body)),creation);
  assert.deepEqual(JSON.parse(String(calls[5]!.init.body)),{chat_id:CID,message:"preserve\n  indentation"});
  assert.deepEqual(JSON.parse(String(calls[7]!.init.body)),{command:"printf hello",timeout_seconds:30});
});

test("invalid credentials, identifiers, pagination and writes are rejected before I/O",async()=>{
  let calls=0;const r=createReplicasRuntime({fetchImpl:async()=>{calls++;throw new Error("must not fetch");}});
  for(const invoke of [()=>r.identity("bad\r\nkey"),()=>r.get(KEY,"../whoami"),()=>r.message(KEY,RID,"wrong","x"),
    ()=>r.list(KEY,0),()=>r.list(KEY,1.5),()=>r.create(KEY,{...creation,environment_id:"not-a-uuid"}),
    ()=>r.create(KEY,{...creation,lifecycle_policy:"forever"} as never),()=>r.create(KEY,{...creation,api_key:KEY} as never),
    ()=>r.message(KEY,RID,CID,"   "),()=>r.exec(KEY,RID,"\n"),()=>r.history(KEY,RID,CID,"x".repeat(5000))]) {
    await assert.rejects(invoke,failure("replicas_invalid_input","rejected"));
  }
  assert.equal(calls,0);
  for(const timeoutMs of [0,-1,45_001,1.5]) assert.throws(()=>createReplicasRuntime({timeoutMs}),{code:"replicas_invalid_input"});
});

test("empty or HTML HTTP rejections keep their status; server errors remain unknown writes",async()=>{
  for(const status of [400,401,403,409,429,500,503]) for(const body of ["","<html>secret "+KEY+"</html>"]) {
    let calls=0;const r=createReplicasRuntime({fetchImpl:async()=>{calls++;return new Response(body,{status});}});
    await assert.rejects(()=>r.message(KEY,RID,CID,"test"),failure(`replicas_http_${status}`,status>=500?"unknown":"rejected",status));
    assert.equal(calls,1,"transport never retries a provider write");
  }
});

test("network and unreadable successful acknowledgements never replay uncertain writes or expose bodies",async()=>{
  for(const reply of [()=>{throw new Error(KEY);},()=>new Response(KEY),()=>Response.json({secret:KEY}),()=>new Response(null,{status:204})]) {
    let calls=0;const r=createReplicasRuntime({fetchImpl:async()=>{calls++;return reply();}});
    await assert.rejects(()=>r.create(KEY,creation),error=>{
      assert.ok(error instanceof ReplicasRuntimeError);assert.equal(error.outcome,"unknown");
      assert.equal(JSON.stringify(error).includes(KEY),false);assert.equal(error.message.includes(KEY),false);return true;
    });assert.equal(calls,1);
  }
});

test("response identity and pagination must match the requested object/page",async()=>{
  const wrong=createReplicasRuntime({fetchImpl:async()=>Response.json({replica:{...replica,id:ENV}})});
  await assert.rejects(()=>wrong.get(KEY,RID),failure("replicas_invalid_response","rejected",200));
  const canonical=createReplicasRuntime({fetchImpl:async()=>Response.json({replica})});
  assert.equal((await canonical.get(KEY,RID.toUpperCase())).replica.id,RID,"UUID casing does not change identity");
  const page=createReplicasRuntime({fetchImpl:async()=>Response.json({replicas:[],page:1,total_pages:3})});
  await assert.rejects(()=>page.list(KEY,2),failure("replicas_invalid_response","rejected",200));
});

test("decoded bodies are bounded, including after successful write headers",async()=>{
  for(const write of [false,true]) {
    let canceled=false;const stream=new ReadableStream<Uint8Array>({start(c){c.enqueue(new Uint8Array(2*1024*1024+1));},cancel(){canceled=true;}});
    const r=createReplicasRuntime({timeoutMs:20,fetchImpl:async()=>new Response(stream)});
    await assert.rejects(()=>write?r.create(KEY,creation):r.identity(KEY),failure("replicas_invalid_response",write?"unknown":"rejected",200));
    assert.equal(canceled,true);
  }
});

test("one operation deadline bounds both a non-cooperative fetch and a stalled response body",async()=>{
  for(const stall of ["fetch","body"] as const) {
    let calls=0,canceled=false,signal:AbortSignal|null=null;
    const r=createReplicasRuntime({timeoutMs:20,fetchImpl:async(_url,init)=>{
      calls++;signal=init!.signal!;
      if(stall==="fetch") return new Promise<Response>(()=>{});
      return new Response(new ReadableStream({cancel(){canceled=true;}}));
    }});
    await assert.rejects(()=>r.message(KEY,RID,CID,"test"),failure("replicas_deadline","unknown"));
    assert.equal(calls,1);assert.equal((signal as AbortSignal|null)?.aborted,true);
    if(stall==="body") assert.equal(canceled,true);
  }
});

test("a late response from a fetch that ignored cancellation is canceled",async()=>{
  let finish!:(r:Response)=>void,canceled=false;
  const r=createReplicasRuntime({timeoutMs:20,fetchImpl:async()=>new Promise<Response>(resolve=>{finish=resolve;})});
  await assert.rejects(()=>r.identity(KEY),failure("replicas_deadline","rejected"));
  finish(new Response(new ReadableStream({cancel(){canceled=true;}})));
  await new Promise(resolve=>setImmediate(resolve));assert.equal(canceled,true);
});


test("the same deadline still owns the response after headers",async()=>{
  // A manual deadline avoids elapsed-time assertions on busy hosts.
  const original=AbortSignal.timeout,controllers:AbortController[]=[];
  let reading!:()=>void,settled=false;
  const started=new Promise<void>(resolve=>{reading=resolve;});
  AbortSignal.timeout=()=>{const c=new AbortController();controllers.push(c);return c.signal;};
  let pending:Promise<unknown>|undefined;
  try {
    const r=createReplicasRuntime({fetchImpl:async()=>new Response(new ReadableStream({pull(){reading();}}))});
    pending=r.identity(KEY).then(()=>{settled=true;},error=>{settled=true;return error;});
    await started;await new Promise(resolve=>setImmediate(resolve));
    controllers[0]!.abort(new Error("manual deadline"));
    await new Promise(resolve=>setImmediate(resolve));
    assert.equal(settled,true,"headers must not renew the operation's deadline");
    failure("replicas_deadline","rejected")(await pending);
  } finally {
    for(const c of controllers) c.abort();
    await pending;AbortSignal.timeout=original;
  }
});

test("a stalled error body cannot erase a definitive HTTP rejection",async()=>{
  let canceled=false;
  const r=createReplicasRuntime({timeoutMs:20,fetchImpl:async()=>new Response(new ReadableStream({cancel(){canceled=true;}}),{status:401})});
  await assert.rejects(()=>r.create(KEY,creation),failure("replicas_http_401","rejected",401));
  assert.equal(canceled,true);
});

test("native fetch refuses a redirect before forwarding the write to another origin",async t=>{
  let forwarded=0;
  const target=createServer((_req,res)=>{forwarded++;res.end("{}");});
  const start=async(server:Server)=>{
    await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));
    t.after(async()=>{server.closeAllConnections();await new Promise<void>((resolve,reject)=>server.close(error=>error?reject(error):resolve()));});
    const address=server.address();assert.ok(address && typeof address!=="string");return `http://127.0.0.1:${address.port}`;
  };
  const targetOrigin=await start(target);
  const redirect=createServer((_req,res)=>{res.writeHead(307,{location:targetOrigin+"/capture"});res.end();});
  const redirectOrigin=await start(redirect);
  const r=createReplicasRuntime({fetchImpl:async(url,init)=>{
    assert.equal(new URL(String(url)).origin,"https://api.replicas.dev");
    return fetch(redirectOrigin+new URL(String(url)).pathname,init);
  }});
  let error:unknown;try {await r.create(KEY,creation);} catch(caught) {error=caught;}
  assert.equal(forwarded,0,"a redirect must not forward the provider operation");
  failure("replicas_transport_unavailable","unknown")(error);
});
