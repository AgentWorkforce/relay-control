import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { CapyBindings,capyAgentName } from "../src/capy/bindings.js";
import { CapyCleanup,capyCleanupFetch } from "../src/capy/cleanup.js";
import { HOSTED_SOURCE,ownerHash } from "../src/mcp/relay-participants.js";
import { seedTenant,startControlPlane } from "./flows-helpers.js";

test("Capy cleanup is finite, coalesced, backed off and independent of provider enablement",async t=>{
  const c=await startControlPlane();t.after(()=>c.stop());
  const tenant=await seedTenant(c.api);
  const userId=(await c.database.query<{user_id:string}>("SELECT user_id FROM organization_memberships WHERE organization_id=$1 AND role='owner'",[tenant.organizationId])).rows[0]!.user_id;
  let now=new Date(Date.now()+60_000),rosterReads=0,releases=0,fail=false;
  let onRoster:(()=>Promise<void>)|null=null;
  const agents=new Map<string,{id:string;name:string;metadata:Record<string,unknown>}>();
  const ids:string[]=[];
  for(let i=0;i<8;i++){
    const id=randomUUID(),thread="jam_cleanup"+i,name=capyAgentName(thread),remote=randomUUID();ids.push(id);
    agents.set(name,{id:remote,name,metadata:{source:HOSTED_SOURCE,capy_binding_id:id,cloud_workspace_id:tenant.workspaceId,owner_hash:ownerHash(userId)}});
    await c.database.query(`INSERT INTO capy_bindings(id,workspace_id,organization_id,user_id,thread_id,state,
      connection_digest,relaycast_workspace_id,agent_name,agent_remote_id,registration_attempted,cleanup_pending)
      VALUES($1,$2,$3,$4,$5,'retired','retired-fixture','rc-primary',$6,$7,true,true)`,[id,tenant.workspaceId,tenant.organizationId,userId,thread,name,remote]);
  }
  const service=new CapyBindings({database:c.database,keyring:c.config.encryptionKeyring,now:()=>now,
    runtime:{getThread:async()=>{throw new Error("cleanup must never dispatch Capy");}},
    relaycast:{
      getRosterAgent:async(key,name)=>{assert.equal(key,"rk_live_primary");rosterReads++;await onRoster?.();return agents.get(name) as any ?? null;},
      releaseHosted:async(key,name,id)=>{assert.equal(key,"rk_live_primary");assert.equal(agents.get(name)?.id,id);if(fail)throw new Error("private upstream body");agents.delete(name);releases++;},
      registerHosted:async()=>{throw new Error("no registration during cleanup");},
      recoverHosted:async()=>{throw new Error("no recovery during cleanup");},
      authenticatedAgent:async()=>{throw new Error("no identity admission during cleanup");},
    }});
  const logs:unknown[]=[];
  const worker=new CapyCleanup({database:c.database,bindings:service,now:()=>now,log:e=>logs.push(e)});
  t.after(()=>worker.stop());
  await t.test("one tick releases at most five immutable identities without a provider key",async()=>{
    await worker.tick();assert.equal(releases,5);assert.equal(agents.size,3);
    assert.equal((await c.database.query("SELECT id FROM capy_bindings WHERE cleanup_pending")).rows.length,3);
    assert.equal((await c.database.query("SELECT * FROM remote_agent_connections")).rows.length,0);
  });
  await t.test("a failed release keeps custody and does not hot-loop before the retry interval",async()=>{
    fail=true;await worker.tick();const prior=rosterReads;
    assert.equal((await c.database.query("SELECT id FROM capy_bindings WHERE cleanup_pending AND last_error='capy_cleanup_relay_unavailable'")).rows.length,3);
    await worker.tick();assert.equal(rosterReads,prior);assert.equal(agents.size,3);fail=false;
  });
  await t.test("overlapping ticks coalesce; stop finishes only the active operation",async()=>{
    assert.equal(agents.size,3,"prior failed releases must still have cleanup custody");
    now=new Date(now.getTime()+30_001);let arrive!:()=>void,release!:()=>void;
    const arrived=new Promise<void>(r=>{arrive=r;}),held=new Promise<void>(r=>{release=r;});
    onRoster=async()=>{arrive();await held;};
    const first=worker.tick();
    try {
      await arrived;assert.equal(worker.tick(),first);
      const prior=releases;const stop=worker.stop();release();await stop;await first;
      assert.equal(releases,prior+1);const reads=rosterReads;await worker.tick();assert.equal(rosterReads,reads);
      assert.equal((await c.database.query("SELECT id FROM capy_bindings WHERE cleanup_pending")).rows.length,2);
    } finally {release();onRoster=null;await first;}
  });
  assert.deepEqual(logs,[]);
});

test("Capy cleanup transport preserves caller cancellation without logging credentials",async()=>{
  for(const requestStyle of [false,true]){
    const controller=new AbortController();let seen:AbortSignal|null=null;
    const wrapped=capyCleanupFetch(async(_input,init)=>{seen=init!.signal!;return new Response(null,{status:204});});
    const input=requestStyle?new Request("https://relay.example/v1/agents",{signal:controller.signal}):"https://relay.example/v1/agents";
    await wrapped(input,requestStyle?{}:{signal:controller.signal});assert.ok(seen);assert.equal((seen as AbortSignal).aborted,false);
    controller.abort();assert.equal((seen as AbortSignal).aborted,true);
  }
});

test("Capy cleanup logs only its closed failure code when the database is unavailable",async()=>{
  const events:unknown[]=[];
  const database={
    query:async()=>{throw new Error("private database address and credentials");},
    exec:async()=>{},close:async()=>{},
    transaction:async<T>(_run:unknown):Promise<T>=>{throw new Error("must not transact in this scan");},
  };
  const worker=new CapyCleanup({database,bindings:{cleanup:async()=>{throw new Error("must not release without a scan");}},log:e=>events.push(e)});
  await worker.tick();await worker.stop();assert.deepEqual(events,[{code:"capy_cleanup_scan_failed"}]);
});
