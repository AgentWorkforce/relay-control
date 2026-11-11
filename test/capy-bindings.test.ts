import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { encryptSecret } from "../src/crypto.js";
import { CapyBindings, capyAgentName, type CapyActor } from "../src/capy/bindings.js";
import { RemoteAgentConnections } from "../src/remote-agents/connections.js";
import { CapyRuntimeError } from "../src/capy/runtime.js";
import { RelaycastCallError } from "../src/messaging/relaycast.js";
import { BOOTSTRAP, seedTenant, startControlPlane } from "./flows-helpers.js";

test("Capy native identity custody preserves ownership, unknown outcomes and retirement", async t => {
  const c = await startControlPlane();
  t.after(() => c.stop());
  const tenant = await seedTenant(c.api);
  const ownerId = (await c.database.query<{ user_id: string }>(
    "SELECT user_id FROM organization_memberships WHERE organization_id=$1 AND role='owner'", [tenant.organizationId])).rows[0]!.user_id;
  const memberId = (await c.database.query<{ user_id: string }>(
    "SELECT user_id FROM organization_memberships WHERE organization_id=$1 AND role='member'", [tenant.organizationId])).rows[0]!.user_id;
  const admin = await c.api(`/api/v1/organizations/${tenant.organizationId}/memberships`, {
    method: "POST", token: BOOTSTRAP, body: { email: "capy-admin@acme.test", name: "Admin", role: "admin" },
  });
  assert.equal(admin.status, 200);
  const actor: CapyActor = { userId: ownerId, organizationId: tenant.organizationId, workspaceId: tenant.workspaceId };
  const key = "capy_" + "s".repeat(32);
  const keys = new RemoteAgentConnections(c.database,c.config.encryptionKeyring,async () => Response.json({ items: [] }));
  await keys.connect(actor,"capy",{ key });
  const agents = new Map<string,{ id: string; name: string; token: string; metadata: Record<string,unknown> }>();
  let registers = 0, recovers = 0, releases = 0, providerReads = 0, rosterReads = 0;
  let failure: "before" | "after" | null = null;
  let onThread: (() => Promise<void>) | null = null;
  let onRoster: (() => Promise<void>) | null = null;
  let onAuthenticated: (() => Promise<void>) | null = null;
  let changeIdentity: "id" | "metadata" | "workspace" | null = null;
  let releaseFails = false;
  let hangRegistration = false;
  let nowMillis = Date.now();
  let expectedRelayKey = "rk_live_primary";
  let authenticatedUnavailable = false;
  let authenticationStatus: number | null = null;
  const roster = (a: NonNullable<ReturnType<typeof agents.get>>) => ({ ...a, address: null, kind: "agent", persona: null, status: "active", lastSeen: null });
  const service = new CapyBindings({
    database:c.database, keyring:c.config.encryptionKeyring,now:()=>new Date(nowMillis),
    runtime:{ getThread: async (receivedKey,id) => {
      providerReads++;assert.equal(receivedKey,key);await onThread?.();return { id,title:null,status:"active" };
    } },
    relaycast:{
      getRosterAgent:async (relayKey,name) => { assert.equal(relayKey,expectedRelayKey);rosterReads++;await onRoster?.();const a=agents.get(name);return a?roster(a):null; },
      registerHosted:async (_key,name,metadata) => {
        registers++;
        if (hangRegistration) await new Promise<void>(()=>{});
        if (failure === "before") throw new Error(`network ${key}`);
        assert.equal(agents.has(name),false,"must never register a duplicate identity");
        const a={id:randomUUID(),name,token:`native-agent-${randomUUID()}`,metadata};agents.set(name,a);
        if (failure === "after") throw new Error(`lost ack ${key}`);
        return {id:a.id,name,token:a.token};
      },
      recoverHosted:async (_key,name,id) => {
        recovers++;const a=agents.get(name)!;assert.equal(a.id,id);a.token=`native-agent-${randomUUID()}`;return {id,name,token:a.token};
      },
      authenticatedAgent:async token => {
        if (authenticatedUnavailable) throw new Error(`upstream ${key}`);
        if (authenticationStatus) throw new RelaycastCallError(authenticationStatus,`upstream ${key}`);
        const a=[...agents.values()].find(value=>value.token===token);assert.ok(a);
        await onAuthenticated?.();
        return { ...roster(a),id:changeIdentity==="id"?randomUUID():a.id,
          metadata:changeIdentity==="metadata"?{...a.metadata,owner_hash:"foreign"}:a.metadata,
          workspaceId:changeIdentity==="workspace"?"foreign-relay":"rc-primary",channels:[] };
      },
      releaseHosted:async (relayKey,name,id) => {
        assert.equal(relayKey,expectedRelayKey);
        if (releaseFails) throw new Error(`upstream ${key}`);
        assert.equal(agents.get(name)?.id,id);releases++;agents.delete(name);
      },
    },
  });
  const row = async (threadId:string) => (await c.database.query<any>(
    "SELECT * FROM capy_bindings WHERE thread_id=$1 ORDER BY created_at DESC LIMIT 1",[threadId])).rows[0]!;

  await t.test("only a live manager owning the connected key may reserve a binding",async () => {
    const reads=providerReads;
    await assert.rejects(service.bind({...actor,userId:memberId},"jam_member00"),{code:"capy_forbidden"});
    await assert.rejects(service.bind({...actor,userId:admin.body.userId},"jam_admin000"),{code:"capy_key_owner_required"});
    await assert.rejects(service.bind({...actor,organizationId:randomUUID()},"jam_foreign0"),{code:"capy_forbidden"});
    await assert.rejects(service.bind({...actor,workspaceId:tenant.otherWorkspaceId},"jam_missing0"),{code:"capy_not_connected"});
    assert.equal(providerReads,reads);
  });
  await t.test("bind is repeat-safe, retains encrypted credentials and creates no participant alias",async () => {
    const thread="jam_owned000";const before=registers;
    const bound=await service.bind(actor,thread);
    assert.equal(bound.state,"bound");assert.equal(bound.agent,capyAgentName(thread));
    assert.deepEqual(await service.bind(actor,thread),bound);
    assert.equal(registers,before+1);
    const stored=await row(thread);const native=agents.get(bound.agent)!;
    assert.notEqual(stored.token_ciphertext,native.token);assert.equal(stored.token_ciphertext.includes(native.token),false);
    assert.equal(JSON.stringify(bound).includes(native.token),false);assert.equal(JSON.stringify(bound).includes(key),false);
    assert.equal((await c.database.query("SELECT id FROM hosted_relay_participants")).rows.length,0);
    assert.deepEqual(await service.agentFor(actor.workspaceId,actor.userId,bound.agent),{name:bound.agent,token:native.token});
    assert.equal(await service.agentFor(actor.workspaceId,admin.body.userId,bound.agent),null);
    assert.equal(await service.agentFor(tenant.otherWorkspaceId,actor.userId,bound.agent),null);
    assert.deepEqual(await service.list({...actor,userId:admin.body.userId}),[]);
    await assert.rejects(service.retire({...actor,userId:admin.body.userId},bound.id),{code:"capy_binding_not_found"});
    await assert.rejects(service.retire({...actor,workspaceId:tenant.otherWorkspaceId},bound.id),{code:"capy_binding_not_found"});
  });
  await t.test("each identity use rechecks immutable id, metadata and Relay route",async () => {
    const name=capyAgentName("jam_owned000");
    for (const changed of ["id","metadata","workspace"] as const) {
      changeIdentity=changed;assert.equal(await service.agentFor(actor.workspaceId,actor.userId,name),null);
    }
    changeIdentity=null;
    await c.database.query("UPDATE workspaces SET relaycast_workspace_id='moved-relay' WHERE id=$1",[actor.workspaceId]);
    assert.equal(await service.agentFor(actor.workspaceId,actor.userId,name),null);
    await c.database.query("UPDATE workspaces SET relaycast_workspace_id='rc-primary' WHERE id=$1",[actor.workspaceId]);
  });
  await t.test("a Relay outage stays retryable instead of masquerading as a changed binding",async () => {
    const name=capyAgentName("jam_owned000"),before=registers;
    authenticatedUnavailable=true;
    try {
      for (const invoke of [()=>service.agentFor(actor.workspaceId,actor.userId,name),()=>service.bind(actor,"jam_owned000")]) {
        await assert.rejects(invoke,(error:unknown)=>{
          assert.ok(error && typeof error === "object");
          assert.equal((error as {status:number}).status,503);
          assert.equal((error as {code:string}).code,"capy_relay_unavailable");
          assert.equal(JSON.stringify(error).includes(key),false);return true;
        });
      }
      assert.equal(registers,before);
    } finally { authenticatedUnavailable=false; }
  });
  await t.test("definitive remote identity denial stays distinct from a retryable outage",async () => {
    try {
      for (const status of [401,403,404]) {
        authenticationStatus=status;
        assert.equal(await service.agentFor(actor.workspaceId,actor.userId,capyAgentName("jam_owned000")),null);
      }
      authenticationStatus=503;
      await assert.rejects(service.agentFor(actor.workspaceId,actor.userId,capyAgentName("jam_owned000")),{status:503,code:"capy_relay_unavailable"});
    } finally { authenticationStatus=null; }
  });
  await t.test("the schema refuses a usable token in a preparing identity",async () => {
    const bound=await service.bind(actor,"jam_shape000");
    try {
      await assert.rejects(c.database.query("UPDATE capy_bindings SET state='preparing' WHERE id=$1",[bound.id]),{code:"23514"});
    } finally { await c.database.query("UPDATE capy_bindings SET state='bound' WHERE id=$1",[bound.id]); }
  });
  await t.test("a foreign workspace cannot claim a live thread even with its own valid key",async () => {
    const other={...actor,workspaceId:tenant.otherWorkspaceId};await keys.connect(other,"capy",{key});
    const reads=providerReads;
    await assert.rejects(service.bind(other,"jam_owned000"),{code:"capy_thread_claimed"});
    assert.equal(providerReads,reads+1); // visibility is proved before global claim lookup
  });
  await t.test("an inaccessible thread cannot be globally reserved by another provider key",async () => {
    const thread="jam_invisible0",before=registers;
    onThread=async()=>{throw new CapyRuntimeError("rejected","capy_http_404",404);};
    await assert.rejects(service.bind(actor,thread),{code:"capy_thread_unavailable"});onThread=null;
    assert.equal((await c.database.query("SELECT id FROM capy_bindings WHERE thread_id=$1",[thread])).rows.length,0);
    assert.equal(registers,before);
  });
  await t.test("a key change during provider preflight leaves no thread reservation",async () => {
    const thread="jam_keyrace0";
    onThread=async()=>{await keys.connect(actor,"capy",{key});};
    await assert.rejects(service.bind(actor,thread),{code:"capy_binding_changed"});onThread=null;
    assert.equal((await c.database.query("SELECT id FROM capy_bindings WHERE thread_id=$1",[thread])).rows.length,0);
  });
  await t.test("a lost registration ack recovers only the matching known native id",async () => {
    const thread="jam_lostack0",before=registers,recovered=recovers;
    failure="after";await assert.rejects(service.bind(actor,thread),{code:"capy_binding_unavailable"});
    failure=null;assert.equal((await row(thread)).state,"preparing");
    assert.equal((await row(thread)).registration_attempted,true);
    const result=await service.bind(actor,thread);assert.equal(result.state,"bound");
    assert.equal(registers,before+1);assert.equal(recovers,recovered+1);
  });
  await t.test("unknown registration plus absent roster never blindly re-registers or claims cleanup",async () => {
    const thread="jam_unknown0",before=registers;
    failure="before";await assert.rejects(service.bind(actor,thread),{code:"capy_binding_unavailable"});failure=null;
    await assert.rejects(service.bind(actor,thread),{code:"capy_registration_unknown"});
    assert.equal(registers,before+1);
    await service.retire(actor,(await row(thread)).id);
    assert.equal((await row(thread)).cleanup_pending,true);
  });
  await t.test("a stalled registration ends the caller wait and preserves unknown write custody",{timeout:2000},async () => {
    const thread="jam_timeout0",before=registers;
    const short=new CapyBindings({...service.deps,externalTimeoutMs:20});
    hangRegistration=true;await assert.rejects(short.bind(actor,thread),{code:"capy_binding_unavailable"});hangRegistration=false;
    assert.equal((await row(thread)).registration_attempted,true);
    assert.equal((await row(thread)).lease_owner,null);
    await assert.rejects(short.bind(actor,thread),{code:"capy_registration_unknown"});
    assert.equal(registers,before+1);
  });
  await t.test("retirement during Relay preflight fences the late registration",async () => {
    const thread="jam_retire00",before=registers;
    onRoster=async()=>{onRoster=null;await service.retire(actor,(await row(thread)).id);};
    await assert.rejects(service.bind(actor,thread),{code:"capy_binding_changed"});onRoster=null;
    const stored=await row(thread);assert.equal(stored.state,"retired");assert.equal(stored.generation,2);
    assert.equal(stored.token_ciphertext,null);assert.equal(registers,before);
  });
  await t.test("membership lost after native registration cannot commit a usable identity",async () => {
    const thread="jam_revoked0";
    onAuthenticated=async()=>{await c.database.query("UPDATE organization_memberships SET role='member' WHERE organization_id=$1 AND user_id=$2",[actor.organizationId,actor.userId]);};
    await assert.rejects(service.bind(actor,thread),{code:"capy_forbidden"});onAuthenticated=null;
    const stored=await row(thread);assert.equal(stored.state,"retired");assert.equal(stored.token_ciphertext,null);
    assert.equal(await service.agentFor(actor.workspaceId,actor.userId,stored.agent_name),null);
    // Cleanup of already-owned immutable identity is independent of user admission.
    assert.equal(await service.cleanup(stored.id),true);assert.equal(agents.has(stored.agent_name),false);
    await c.database.query("UPDATE organization_memberships SET role='owner' WHERE organization_id=$1 AND user_id=$2",[actor.organizationId,actor.userId]);
  });
  await t.test("an acknowledgement after the lease expires cannot finalize the binding",async () => {
    const thread="jam_expired0";
    onAuthenticated=async()=>{nowMillis+=120_001;onAuthenticated=null;};
    await assert.rejects(service.bind(actor,thread),{code:"capy_binding_changed"});
    const stored=await row(thread);assert.equal(stored.state,"retired");assert.equal(stored.token_ciphertext,null);
    assert.equal(stored.cleanup_pending,true);assert.equal(await service.cleanup(stored.id),true);
  });
  await t.test("overlapping binds share a durable claim and make one registration",async () => {
    const thread="jam_overlap0",before=registers;let release!:()=>void,arrive!:()=>void;
    const held=new Promise<void>(resolve=>{release=resolve;});const arrived=new Promise<void>(resolve=>{arrive=resolve;});
    onRoster=async()=>{arrive();await held;};const first=service.bind(actor,thread);await arrived;
    await assert.rejects(service.bind(actor,thread),{code:"capy_binding_in_progress"});
    release();await first;onRoster=null;assert.equal(registers,before+1);
  });
  await t.test("identity resolution rechecks membership after the remote token check",async () => {
    const name=capyAgentName("jam_overlap0");
    onAuthenticated=async()=>{onAuthenticated=null;await c.database.query("UPDATE organization_memberships SET role='member' WHERE organization_id=$1 AND user_id=$2",[actor.organizationId,actor.userId]);};
    try { assert.equal(await service.agentFor(actor.workspaceId,actor.userId,name),null); }
    finally {
      onAuthenticated=null;
      await c.database.query("UPDATE organization_memberships SET role='owner' WHERE organization_id=$1 AND user_id=$2",[actor.organizationId,actor.userId]);
    }
  });
  await t.test("retirement blocks use immediately and failed remote release retains cleanup custody",async () => {
    const thread="jam_owned000",stored=await row(thread),before=releases;
    releaseFails=true;await service.retire(actor,stored.id);
    assert.equal(await service.agentFor(actor.workspaceId,actor.userId,stored.agent_name),null);
    assert.equal((await row(thread)).cleanup_pending,true);assert.equal((await row(thread)).token_ciphertext,null);
    releaseFails=false;assert.equal(await service.cleanup(stored.id),true);assert.equal(releases,before+1);
    assert.equal((await row(thread)).cleanup_pending,false);
  });
  await t.test("cleanup never deletes a successor that reused an old binding's agent name",async () => {
    const thread="jam_lostack0",stored=await row(thread),before=releases;
    releaseFails=true;await service.retire(actor,stored.id);releaseFails=false;
    const prior=agents.get(stored.agent_name)!;agents.set(stored.agent_name,{...prior,id:randomUUID()});
    assert.equal(await service.cleanup(stored.id),false);assert.equal(releases,before);
    assert.equal(agents.has(stored.agent_name),true);assert.equal((await row(thread)).cleanup_pending,true);
  });
  await t.test("cleanup uses the rotated live workspace key without retaining a duplicate credential",async () => {
    const thread="jam_relaykey0",bound=await service.bind(actor,thread),before=releases;
    expectedRelayKey="rk_live_rotated";
    await c.database.query("UPDATE workspaces SET relaycast_api_key_ciphertext=$2 WHERE id=$1",[actor.workspaceId,encryptSecret(expectedRelayKey,c.config.encryptionKeyring.active)]);
    await service.retire(actor,bound.id);
    const stored=await row(thread);
    assert.equal(stored.cleanup_pending,false);assert.equal(releases,before+1);
    assert.equal(Object.hasOwn(stored,"relaycast_key_ciphertext"),false);
  });
  await t.test("a moved Relay route keeps a coded cleanup obligation without using an old credential",async () => {
    const thread="jam_movedkey0",bound=await service.bind(actor,thread),before=releases,reads=rosterReads;
    await c.database.query("UPDATE workspaces SET relaycast_workspace_id='moved-relay' WHERE id=$1",[actor.workspaceId]);
    try {
      await service.retire(actor,bound.id);
      const stored=await row(thread);assert.equal(stored.cleanup_pending,true);
      assert.equal(stored.last_error,"capy_cleanup_relay_changed");
      assert.equal(releases,before);assert.equal(rosterReads,reads);
    } finally { await c.database.query("UPDATE workspaces SET relaycast_workspace_id='rc-primary' WHERE id=$1",[actor.workspaceId]); }
  });
  await t.test("key replacement and membership changes immediately stop native identity resolution",async () => {
    const thread="jam_overlap0",name=capyAgentName(thread);
    await c.database.query("UPDATE organization_memberships SET role='member' WHERE organization_id=$1 AND user_id=$2",[actor.organizationId,actor.userId]);
    assert.equal(await service.agentFor(actor.workspaceId,actor.userId,name),null);
    await c.database.query("UPDATE organization_memberships SET role='owner' WHERE organization_id=$1 AND user_id=$2",[actor.organizationId,actor.userId]);
    await keys.connect(actor,"capy",{key}); // new ciphertext generation, even with same key bytes
    assert.equal(await service.agentFor(actor.workspaceId,actor.userId,name),null);
    await assert.rejects(service.bind(actor,thread),{code:"capy_binding_changed"});
  });
});
