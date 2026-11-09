import { decryptSecret, type EncryptionKeyring } from "../../crypto.js";
import type { Database,SqlExecutor } from "../../database.js";
import { lockOrganization,lockUser } from "../../tenancy.js";
import { RelaycastCallError,type RelaycastClient,type RosterAgent } from "../../messaging/relaycast.js";
import { HOSTED_SOURCE,ownerHash } from "../relay-participants.js";

type Intent = {
  id:string; grant_id:string; organization_id:string; workspace_id:string; user_id:string;
  agent_name:string; agent_remote_id:string|null;
};
type Participant = {
  id:string; agent_name:string; agent_remote_id:string; relaycast_workspace_id:string;
  session_hash:string|null; token_ciphertext:string;
};
type Outcome = "completed"|"kept"|"pending"|"skipped";
export type McpOAuthTeardownResult = {completed:number;kept:number;pending:number};

/** Bound the remote work performed while holding lifecycle locks. */
export function mcpOAuthTeardownFetch(upstream:typeof fetch=fetch,timeoutMs=10_000):typeof fetch {
  return (input,init)=>{
    const prior=init?.signal??(input instanceof Request?input.signal:null);
    const timeout=AbortSignal.timeout(timeoutMs);
    return upstream(input,{...init,signal:prior?AbortSignal.any([prior,timeout]):timeout});
  };
}

/** Durable post-commit cleanup. Row locks fence workers; the actor lock fences reconnects. */
export class McpOAuthTeardown {
  private running:Promise<McpOAuthTeardownResult>|null=null;
  private timer:ReturnType<typeof setInterval>|null=null;
  private cursor:{createdAt:Date|string;id:string}|null=null;
  private rerun=false;
  private stopped=false;
  constructor(readonly deps:{
    database:Database; keyring:EncryptionKeyring; client:RelaycastClient; now?:()=>Date;
  }) {}

  drain():Promise<McpOAuthTeardownResult> {
    if(this.running) return this.running;
    const task=this.run().finally(()=>{
      if(this.running===task) this.running=null;
      if(this.rerun && !this.stopped) {this.rerun=false;this.kick();}
    });
    this.running=task;
    return task;
  }
  /** Request handlers commit local revocation without waiting on Relaycast. */
  kick():void {
    if(this.stopped) return;
    if(this.running) {this.rerun=true;return;}
    void this.drain().catch(error=>{
      console.error("[mcp-oauth] teardown deferred",{error:error instanceof Error?error.name:"unknown"});
    });
  }

  start():void {
    if(this.timer) return;
    this.stopped=false;
    const tick=()=>this.kick();
    this.timer=setInterval(tick,15_000);this.timer.unref();tick();
  }
  async stop():Promise<void> {
    this.stopped=true;this.rerun=false;
    if(this.timer) clearInterval(this.timer);
    this.timer=null;
    await this.running?.catch(()=>undefined);
  }

  private async run():Promise<McpOAuthTeardownResult> {
    const page=()=>this.deps.database.query<Intent&{created_at:Date|string}>(`SELECT id,grant_id,organization_id,workspace_id,user_id,agent_name,agent_remote_id,created_at
      FROM selfhost_mcp_oauth_revocations WHERE completed_at IS NULL
      ${this.cursor?"AND (created_at,id)>($1::timestamptz,$2::uuid)":""} ORDER BY created_at,id LIMIT 20`,
    this.cursor?[this.cursor.createdAt,this.cursor.id]:[]);
    let candidates=await page();
    if(!candidates.rows.length && this.cursor) {this.cursor=null;candidates=await page();}
    const last=candidates.rows.at(-1);
    // Rotate through pending work: a blocked old tenant must not monopolize
    // every batch. Row locks still coordinate independent process cursors.
    if(last) this.cursor={createdAt:last.created_at,id:last.id};
    const counts:McpOAuthTeardownResult={completed:0,kept:0,pending:0};
    for(const candidate of candidates.rows) {
      try {
        const outcome=await this.deps.database.transaction(async tx=>{
          await lockUser(tx,candidate.user_id);
          await lockOrganization(tx,candidate.organization_id);
          await tx.query("SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))",
            ["selfhost-hosted-mcp",candidate.workspace_id+":"+candidate.user_id]);
          const intent=(await tx.query<Intent>(`SELECT id,grant_id,organization_id,workspace_id,user_id,agent_name,agent_remote_id
            FROM selfhost_mcp_oauth_revocations WHERE id=$1 AND user_id=$2 AND organization_id=$3
              AND completed_at IS NULL FOR UPDATE SKIP LOCKED`,
          [candidate.id,candidate.user_id,candidate.organization_id])).rows[0];
          if(!intent) return "skipped" as const;
          const result=await this.release(tx,intent);
          if(result!=="pending") await tx.query("UPDATE selfhost_mcp_oauth_revocations SET completed_at=$2 WHERE id=$1 AND completed_at IS NULL",
            [intent.id,this.deps.now?.()??new Date()]);
          return result;
        });
        if(outcome!=="skipped") counts[outcome]++;
      } catch(error) {
        counts.pending++;
        // Never log upstream bodies, token envelopes or credentials.
        console.error("[mcp-oauth] teardown deferred",{error:error instanceof Error?error.name:"unknown"});
      }
    }
    return counts;
  }

  private async release(tx:SqlExecutor,intent:Intent):Promise<Outcome> {
    if(!intent.agent_remote_id) return "completed";
    const workspace=(await tx.query<{relaycast_workspace_id:string;relaycast_api_key_ciphertext:string}>(`SELECT relaycast_workspace_id,relaycast_api_key_ciphertext
      FROM selfhost_workspaces WHERE id=$1 AND organization_id=$2`,[intent.workspace_id,intent.organization_id])).rows[0];
    if(!workspace) return "pending";
    const row=(await tx.query<Participant>(`SELECT p.id,p.agent_name,p.agent_remote_id,p.relaycast_workspace_id,p.session_hash,p.token_ciphertext
      FROM selfhost_hosted_relay_participants p
      WHERE p.workspace_id=$1 AND p.user_id=$2 AND p.agent_remote_id=$3`,
    [intent.workspace_id,intent.user_id,intent.agent_remote_id])).rows[0];
    // Keep the durable intent pending when the credential/location is gone;
    // never pretend a remote release succeeded or substitute another tenant.
    if(row && workspace.relaycast_workspace_id!==row.relaycast_workspace_id) return "pending";
    const key=decryptSecret(workspace.relaycast_api_key_ciphertext,this.deps.keyring);
    const byId=async()=>(await this.deps.client.listAgents(key,"all",{includeStale:true}))
      .find(agent=>agent.id===intent.agent_remote_id && agent.status!=="released")??null;
    let remote:RosterAgent|null;
    if(row) {
      try {
        remote=await this.deps.client.authenticatedAgent(decryptSecret(row.token_ciphertext,this.deps.keyring));
        if(remote.status==="released") remote=null;
      } catch(error) {
        if(!(error instanceof RelaycastCallError) || error.status!==401) throw error;
        remote=await byId();
      }
    } else {
      // The durable intent still identifies its own agent after a user or
      // participant row was deleted. Never select a replacement by name.
      remote=await byId();
    }
    if(remote) {
      if(remote.id!==intent.agent_remote_id || remote.metadata.source!==HOSTED_SOURCE ||
          remote.metadata.owner_hash!==ownerHash(intent.user_id) || remote.metadata.cloud_workspace_id!==intent.workspace_id) {
        return "pending";
      }
      // Consent may have selected an existing identity, or a native session
      // may have reused it. Disconnecting the connector must keep it running.
      if(remote.metadata.created_by!=="mcp-oauth" || row?.session_hash) return "kept";
      // A connection approved after the first pin may still be unused. Before
      // handing cleanup responsibility to it, persist this verified immutable
      // id so its eventual revocation can release the same agent.
      await tx.query(`UPDATE selfhost_mcp_oauth_grants SET agent_remote_id=$4
        WHERE organization_id=$1 AND workspace_id=$2 AND user_id=$3 AND revoked_at IS NULL
          AND agent_remote_id IS NULL AND agent_name=$5`,
      [intent.organization_id,intent.workspace_id,intent.user_id,remote.id,remote.name]);
      const claimed=await tx.query(`SELECT id FROM selfhost_mcp_oauth_grants
        WHERE organization_id=$1 AND workspace_id=$2 AND user_id=$3 AND revoked_at IS NULL
          AND (agent_remote_id=$4 OR (agent_remote_id IS NULL AND agent_name=$5)) LIMIT 1`,
      [intent.organization_id,intent.workspace_id,intent.user_id,remote.id,remote.name]);
      if(claimed.rows.length) return "kept";
      try {
        await this.deps.client.releaseHosted(key,remote.name,remote.id);
      } catch(error) {
        if(!(error instanceof RelaycastCallError) || error.status!==404) throw error;
        if(await byId()) return "pending";
      }
    }
    if(row) await tx.query(`DELETE FROM selfhost_hosted_relay_participants
      WHERE id=$1 AND workspace_id=$2 AND user_id=$3 AND agent_remote_id=$4`,
    [row.id,intent.workspace_id,intent.user_id,intent.agent_remote_id]);
    return "completed";
  }
}
