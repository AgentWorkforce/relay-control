import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { encryptSecret, hashSecret } from "../src/crypto.js";
import { capyAgentName } from "../src/capy/bindings.js";
import { RemoteAgentConnections } from "../src/remote-agents/connections.js";
import { BOOTSTRAP, seedTenant, startControlPlane } from "./flows-helpers.js";

test("Capy lifecycle revocation commits with its owning control operation", async t => {
  const c=await startControlPlane();t.after(()=>c.stop());
  const tenant=await seedTenant(c.api);
  const userId=(await c.database.query<{user_id:string}>("SELECT user_id FROM organization_memberships WHERE organization_id=$1 AND role='owner'",[tenant.organizationId])).rows[0]!.user_id;
  const actor={userId,organizationId:tenant.organizationId,workspaceId:tenant.workspaceId};
  const keys=new RemoteAgentConnections(c.database,c.config.encryptionKeyring,async()=>Response.json({items:[]}));
  const key="capy_"+"s".repeat(32);
  await keys.connect(actor,"capy",{key});
  await keys.connect({...actor,workspaceId:tenant.otherWorkspaceId},"capy",{key});
  const seed=async(workspaceId=actor.workspaceId,organizationId=actor.organizationId)=>{
    const id=randomUUID(),thread="jam_"+randomUUID().replaceAll("-","").slice(0,12);
    const connection=(await c.database.query<{key_ciphertext:string;relaycast_workspace_id:string}>("SELECT c.key_ciphertext,w.relaycast_workspace_id FROM remote_agent_connections c JOIN workspaces w ON w.id=c.workspace_id WHERE c.workspace_id=$1 AND c.provider='capy'",[workspaceId])).rows[0]!;
    await c.database.query(`INSERT INTO capy_bindings(id,workspace_id,organization_id,user_id,thread_id,state,
      connection_digest,relaycast_workspace_id,agent_name,agent_remote_id,token_ciphertext,registration_attempted)
      VALUES($1,$2,$3,$4,$5,'bound',$6,$7,$8,$9,$10,true)`,
    [id,workspaceId,organizationId,userId,thread,hashSecret(connection.key_ciphertext),connection.relaycast_workspace_id,capyAgentName(thread),randomUUID(),encryptSecret("owned-native-token",c.config.encryptionKeyring.active)]);
    return id;
  };
  const row=async(id:string)=>(await c.database.query<any>("SELECT * FROM capy_bindings WHERE id=$1",[id])).rows[0];
  const retired=async(id:string)=>{const r=await row(id);assert.equal(r.state,"retired");assert.equal(r.generation,2);assert.equal(r.token_ciphertext,null);assert.equal(r.cleanup_pending,true);assert.equal(r.lease_owner,null);};

  await t.test("replacement retires old Capy identity in only the changed workspace",async()=>{
    const own=await seed(),other=await seed(tenant.otherWorkspaceId);
    await keys.connect(actor,"capy",{key});
    await retired(own);assert.equal((await row(other)).state,"bound");
  });
  await t.test("disconnect retires identities before the provider key disappears",async()=>{
    const id=await seed();
    try {
      await keys.disconnect(actor,"capy");await retired(id);
      assert.equal(await keys.keyFor(actor.workspaceId,"capy"),null);
    } finally {await keys.connect(actor,"capy",{key});}
  });
  await t.test("failed key deletion rolls back both key and identity retirement",async()=>{
    const id=await seed();
    await c.database.exec(`CREATE FUNCTION refuse_capy_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture refusal'; END $$;
      CREATE TRIGGER refuse_capy_delete BEFORE DELETE ON remote_agent_connections FOR EACH ROW EXECUTE FUNCTION refuse_capy_delete();`);
    try {await assert.rejects(keys.disconnect(actor,"capy"),/fixture refusal/);}
    finally {await c.database.exec("DROP TRIGGER refuse_capy_delete ON remote_agent_connections; DROP FUNCTION refuse_capy_delete();");}
    assert.equal((await row(id)).state,"bound");assert.equal(await keys.keyFor(actor.workspaceId,"capy"),key);
  });
  await t.test("manager demotion retires authority, last-owner refusal preserves it, promotion never revives it",async()=>{
    const id=await seed();
    const change=(role:"owner"|"admin"|"member")=>c.store.putMembership({organizationId:actor.organizationId,email:"owner@acme.test",name:"Owner",role,operator:true});
    await assert.rejects(change("member"),/last owner cannot be demoted/);
    assert.equal((await row(id)).state,"bound");
    const second=await c.store.putMembership({organizationId:actor.organizationId,email:"demotion-guard@acme.test",name:"Guard",role:"owner",operator:true});
    try {
      await change("admin");assert.equal((await row(id)).state,"bound");
      await change("member");await retired(id);assert.equal((await row(id)).last_error,"capy_member_demoted");
      await change("owner");await retired(id);
    } finally {await change("owner");await c.store.deleteMembership(actor.organizationId,String(second.userId));}
  });
  await t.test("last-owner refusal leaves bindings live; membership removal retires them atomically",async()=>{
    const id=await seed();assert.equal(await c.store.deleteMembership(actor.organizationId,userId),false);
    assert.equal((await row(id)).state,"bound");
    // The API harness is single-organization. Seed a second tenant as a DB
    // isolation fixture; this does not assert a multi-organization product flow.
    const foreignOrg=randomUUID(),foreignWorkspace=randomUUID();
    await c.database.query("INSERT INTO organizations(id,name) VALUES($1,'Other Capy org')",[foreignOrg]);
    await c.database.query("INSERT INTO organization_memberships(organization_id,user_id,role) VALUES($1,$2,'owner')",[foreignOrg,userId]);
    await c.database.query("INSERT INTO workspaces(id,organization_id,name,relaycast_workspace_id,relaycast_api_key_ciphertext) VALUES($1,$2,'foreign','rc-foreign',$3)",[foreignWorkspace,foreignOrg,encryptSecret("rk_live_foreign",c.config.encryptionKeyring.active)]);
    await keys.connect({...actor,organizationId:foreignOrg,workspaceId:foreignWorkspace},"capy",{key});
    const foreign=await seed(foreignWorkspace,foreignOrg);
    assert.equal((await c.api(`/api/v1/organizations/${actor.organizationId}/memberships`,{method:"POST",token:BOOTSTRAP,body:{email:"second-owner@acme.test",name:"Second",role:"owner"}})).status,200);
    await assert.rejects(c.store.deleteMembership(actor.organizationId,userId,async()=>{throw new Error("fixture rollback");}),/fixture rollback/);
    assert.equal((await row(id)).state,"bound");assert.equal(await c.store.memberRole(actor.organizationId,userId),"owner");
    assert.equal((await c.api(`/api/v1/organizations/${actor.organizationId}/memberships/${userId}`,{method:"DELETE",token:BOOTSTRAP})).status,204);
    await retired(id);
    assert.equal((await row(foreign)).state,"bound","leaving one organization must not revoke another organization's binding");
  });
  await t.test("workspace deletion keeps pending custody and removes only completed retired records",async()=>{
    const target=tenant.otherWorkspaceId;
    const pending=(await c.database.query<any>("SELECT * FROM capy_bindings WHERE workspace_id=$1 LIMIT 1",[target])).rows[0]!;
    const primaryBefore=(await c.database.query("SELECT id FROM capy_bindings WHERE workspace_id=$1",[actor.workspaceId])).rows.length;
    assert.equal(await c.store.deleteWorkspace({organizationId:actor.organizationId,workspaceId:target,allowLast:false,actor:{kind:"bootstrap"}}),"in_use");
    assert.ok(await row(pending.id));
    // Fixture represents a completed exact-id remote release; no runtime proof inferred.
    await c.database.query("UPDATE capy_bindings SET state='retired',token_ciphertext=NULL,agent_remote_id=NULL,cleanup_pending=false WHERE workspace_id=$1",[target]);
    assert.equal(await c.store.deleteWorkspace({organizationId:actor.organizationId,workspaceId:target,allowLast:false,actor:{kind:"bootstrap"}}),"deleted");
    assert.equal(await row(pending.id),undefined);
    assert.equal((await c.database.query("SELECT id FROM capy_bindings WHERE workspace_id=$1",[actor.workspaceId])).rows.length,primaryBefore);
  });
});
