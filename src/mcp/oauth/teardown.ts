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
type Workspace = {relaycast_workspace_id:string;relaycast_api_key_ciphertext:string};
type Grant = {id:string;agent_remote_id:string|null;agent_name:string};
/** Local state a remote decision is made against. Ciphertexts only; never logged. */
type Snapshot = {workspace:Workspace|null;row:Participant|null;grants:Grant[]};
type Claim = {intent:Intent&{agent_remote_id:string};snapshot:Snapshot};
/** Why a revocation row completed (stored in `outcome`). */
export type McpOAuthTeardownOutcome = "released"|"no_remote"|"kept"|"workspace_mismatch"|"decrypt_failed"
  |"metadata_mismatch"|"operator_abandoned";
type Decision = {outcome:McpOAuthTeardownOutcome;transfer?:RosterAgent;deleteRow?:boolean}|"pending";
type Counted = "completed"|"kept"|"pending"|"skipped";
export type McpOAuthTeardownResult = {completed:number;kept:number;pending:number};

/** Retrying cannot fix these; the row completes so workspace deletion is not blocked forever. */
const TERMINAL=new Set<McpOAuthTeardownOutcome>(["workspace_mismatch","decrypt_failed","metadata_mismatch"]);
const PAGE=20;

/** Exponential retry delay after the given attempt count: 15 s doubling, capped at one hour. */
export function mcpOAuthTeardownBackoffMs(attempts:number):number {
  return Math.min(15_000*2**Math.max(0,attempts-1),3_600_000);
}

/** Bound each remote teardown call. */
export function mcpOAuthTeardownFetch(upstream:typeof fetch=fetch,timeoutMs=10_000):typeof fetch {
  return (input,init)=>{
    const prior=init?.signal??(input instanceof Request?input.signal:null);
    const timeout=AbortSignal.timeout(timeoutMs);
    return upstream(input,{...init,signal:prior?AbortSignal.any([prior,timeout]):timeout});
  };
}

/**
 * Durable post-commit cleanup in three steps: a short claim transaction,
 * Relaycast calls with no tenant lock held, and a short commit transaction
 * that applies the decision only if the local state it was made against is
 * unchanged. The claim pushes `next_attempt_at` out first, so a crash or an
 * inconclusive attempt simply retries after the backoff.
 */
export class McpOAuthTeardown {
  private running:Promise<McpOAuthTeardownResult>|null=null;
  private timer:ReturnType<typeof setInterval>|null=null;
  private cursor:{createdAt:Date|string;id:string}|null=null;
  private rerun=false;
  private stopped=false;
  constructor(readonly deps:{
    database:Database; keyring:EncryptionKeyring; client:RelaycastClient; now?:()=>Date;
    /** Wall-clock budget of one pass; the remainder follows in an immediate rerun. */
    passBudgetMs?:number;
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

  private clock():Date {return this.deps.now?.()??new Date();}

  private async run():Promise<McpOAuthTeardownResult> {
    const started=Date.now(),budget=this.deps.passBudgetMs??30_000,now=this.clock();
    // Only due rows: new intents have no next_attempt_at, so kick() reaches them at once.
    const page=()=>this.deps.database.query<Intent&{created_at:Date|string}>(`SELECT id,grant_id,organization_id,workspace_id,user_id,agent_name,agent_remote_id,created_at
      FROM selfhost_mcp_oauth_revocations WHERE completed_at IS NULL AND (next_attempt_at IS NULL OR next_attempt_at<=$1)
      ${this.cursor?"AND (created_at,id)>($2::timestamptz,$3::uuid)":""} ORDER BY created_at,id LIMIT ${PAGE}`,
    this.cursor?[now,this.cursor.createdAt,this.cursor.id]:[now]);
    let candidates=await page();
    if(!candidates.rows.length && this.cursor) {this.cursor=null;candidates=await page();}
    const counts:McpOAuthTeardownResult={completed:0,kept:0,pending:0};
    for(const [index,candidate] of candidates.rows.entries()) {
      // Every pass makes progress; past the budget the rest follows in a rerun.
      if(index>0 && Date.now()-started>=budget) {this.rerun=true;break;}
      // Rotate through pending work: a blocked old tenant must not monopolize
      // every batch. Row locks still coordinate independent process cursors.
      this.cursor={createdAt:candidate.created_at,id:candidate.id};
      try {
        const outcome=await this.attempt(candidate);
        if(outcome!=="skipped") counts[outcome]++;
      } catch(error) {
        counts.pending++;
        // Never log upstream bodies, token envelopes or credentials.
        console.error("[mcp-oauth] teardown deferred",{error:error instanceof Error?error.name:"unknown"});
      }
    }
    return counts;
  }

  private async attempt(candidate:Intent):Promise<Counted> {
    const claim=await this.claim(candidate);
    if(typeof claim==="string") return claim;
    // Retryable failures (network, timeout, 5xx, 429) throw here and leave
    // the claimed row pending until its next_attempt_at.
    const decision=await this.decide(claim);
    if(decision==="pending") return "pending";
    return this.commit(claim,decision);
  }

  /** The lifecycle locks a reconnect, membership change or MCP join of this owner also takes. */
  private locked<T>(intent:Intent,run:(tx:SqlExecutor)=>Promise<T>):Promise<T> {
    return this.deps.database.transaction(async tx=>{
      await lockUser(tx,intent.user_id);
      await lockOrganization(tx,intent.organization_id);
      await tx.query("SELECT pg_advisory_xact_lock(hashtext($1),hashtext($2))",
        ["selfhost-hosted-mcp",intent.workspace_id+":"+intent.user_id]);
      return run(tx);
    });
  }

  private claim(candidate:Intent):Promise<Claim|"completed"|"skipped"> {
    return this.locked(candidate,async tx=>{
      const now=this.clock();
      const intent=(await tx.query<Intent&{attempts:number}>(`SELECT id,grant_id,organization_id,workspace_id,user_id,agent_name,agent_remote_id,attempts
        FROM selfhost_mcp_oauth_revocations WHERE id=$1 AND user_id=$2 AND organization_id=$3
          AND completed_at IS NULL AND (next_attempt_at IS NULL OR next_attempt_at<=$4) FOR UPDATE SKIP LOCKED`,
      [candidate.id,candidate.user_id,candidate.organization_id,now])).rows[0];
      if(!intent) return "skipped";
      const attempts=intent.attempts+1;
      await tx.query(`UPDATE selfhost_mcp_oauth_revocations SET attempts=$2,next_attempt_at=$3,claimed_at=$4 WHERE id=$1`,
        [intent.id,attempts,new Date(now.getTime()+mcpOAuthTeardownBackoffMs(attempts)),now]);
      const remoteId=intent.agent_remote_id;
      if(!remoteId) {await this.complete(tx,intent.id,"no_remote");return "completed";}
      const snapshot=await this.snapshot(tx,{...intent,agent_remote_id:remoteId});
      // Never substitute another tenant's credential or relay location.
      if(!snapshot.workspace || (snapshot.row && snapshot.workspace.relaycast_workspace_id!==snapshot.row.relaycast_workspace_id)) {
        await this.complete(tx,intent.id,"workspace_mismatch");
        return "completed";
      }
      return {intent:{...intent,agent_remote_id:remoteId},snapshot};
    });
  }

  private async snapshot(tx:SqlExecutor,intent:Claim["intent"]):Promise<Snapshot> {
    const workspace=(await tx.query<Workspace>(`SELECT relaycast_workspace_id,relaycast_api_key_ciphertext
      FROM selfhost_workspaces WHERE id=$1 AND organization_id=$2`,[intent.workspace_id,intent.organization_id])).rows[0]??null;
    const row=(await tx.query<Participant>(`SELECT p.id,p.agent_name,p.agent_remote_id,p.relaycast_workspace_id,p.session_hash,p.token_ciphertext
      FROM selfhost_hosted_relay_participants p
      WHERE p.workspace_id=$1 AND p.user_id=$2 AND p.agent_remote_id=$3`,
    [intent.workspace_id,intent.user_id,intent.agent_remote_id])).rows[0]??null;
    const grants=(await tx.query<Grant>(`SELECT id,agent_remote_id,agent_name FROM selfhost_mcp_oauth_grants
      WHERE organization_id=$1 AND workspace_id=$2 AND user_id=$3 AND revoked_at IS NULL ORDER BY id`,
    [intent.organization_id,intent.workspace_id,intent.user_id])).rows;
    return {workspace,row,grants};
  }

  private async complete(tx:SqlExecutor,id:string,outcome:McpOAuthTeardownOutcome):Promise<void> {
    const done=await tx.query(`UPDATE selfhost_mcp_oauth_revocations SET completed_at=$2,outcome=$3
      WHERE id=$1 AND completed_at IS NULL RETURNING id`,[id,this.clock(),outcome]);
    // Logged once per row, when it completes. No names, agent ids or tokens.
    if(done.rows.length && TERMINAL.has(outcome)) console.warn("[mcp-oauth] teardown abandoned",{outcome,revocationId:id});
  }

  /** Read-only recheck under the locks that the claim's local state still holds. */
  private unchanged({intent,snapshot}:Claim):Promise<boolean> {
    return this.locked(intent,async tx=>{
      const pending=await tx.query("SELECT 1 FROM selfhost_mcp_oauth_revocations WHERE id=$1 AND completed_at IS NULL",[intent.id]);
      return pending.rows.length>0 && same(await this.snapshot(tx,intent),snapshot);
    });
  }

  /** Remote phase. No user, organization or advisory lock is held; secrets stay in memory. */
  private async decide(claim:Claim):Promise<Decision> {
    const {intent,snapshot:{workspace,row,grants}}=claim;
    let key:string;
    try {key=decryptSecret(workspace!.relaycast_api_key_ciphertext,this.deps.keyring);}
    catch {return {outcome:"decrypt_failed"};}
    const byId=async()=>(await this.deps.client.listAgents(key,"all",{includeStale:true}))
      .find(agent=>agent.id===intent.agent_remote_id && agent.status!=="released")??null;
    let remote:RosterAgent|null;
    if(row) {
      let token:string|null=null;
      // A token sealed under a retired key: the workspace-key roster still
      // answers by immutable id, exactly as for a rejected token.
      try {token=decryptSecret(row.token_ciphertext,this.deps.keyring);} catch {token=null;}
      try {
        if(token===null) remote=await byId();
        else {
          remote=await this.deps.client.authenticatedAgent(token);
          if(remote.status==="released") remote=null;
        }
      } catch(error) {
        if(!(error instanceof RelaycastCallError) || error.status!==401) throw error;
        remote=await byId();
      }
    } else {
      // The durable intent still identifies its own agent after a user or
      // participant row was deleted. Never select a replacement by name.
      remote=await byId();
    }
    if(!remote) return {outcome:"no_remote",deleteRow:true};
    if(remote.id!==intent.agent_remote_id || remote.metadata.source!==HOSTED_SOURCE ||
        remote.metadata.owner_hash!==ownerHash(intent.user_id) || remote.metadata.cloud_workspace_id!==intent.workspace_id) {
      return {outcome:"metadata_mismatch"};
    }
    // Consent may have selected an existing identity, or a native session
    // may have reused it. Disconnecting the connector must keep it running.
    if(remote.metadata.created_by!=="mcp-oauth" || row?.session_hash) return {outcome:"kept"};
    // A connection approved after the first pin may still be unused. The
    // commit persists this verified immutable id on it before handing over
    // cleanup responsibility, so its eventual revocation releases the same agent.
    if(grants.some(grant=>grant.agent_remote_id===remote.id || (grant.agent_remote_id===null && grant.agent_name===remote.name))) {
      return {outcome:"kept",transfer:remote};
    }
    // Narrow the irreversible release to state rechecked just before it. A
    // join committed between this recheck and the release is caught by the
    // commit re-read; the row then retries and finds the agent released.
    if(!await this.unchanged(claim)) return "pending";
    try {
      await this.deps.client.releaseHosted(key,remote.name,remote.id);
    } catch(error) {
      if(!(error instanceof RelaycastCallError) || error.status!==404) throw error;
      if(await byId()) return "pending";
    }
    return {outcome:"released",deleteRow:true};
  }

  private commit({intent,snapshot}:Claim,decision:Exclude<Decision,"pending">):Promise<Counted> {
    return this.locked(intent,async tx=>{
      const current=await tx.query(`SELECT id FROM selfhost_mcp_oauth_revocations
        WHERE id=$1 AND completed_at IS NULL FOR UPDATE`,[intent.id]);
      if(!current.rows.length) return "skipped";
      // This re-read replaces the advisory fence that used to span the remote
      // calls: a reconnect, native bind, re-pin, new grant, token rotation or
      // relocation committed meanwhile makes the decision stale. The row stays
      // pending (next_attempt_at was set by the claim) instead of applying it.
      if(!same(await this.snapshot(tx,intent),snapshot)) return "pending";
      const remote=decision.transfer;
      if(remote) await tx.query(`UPDATE selfhost_mcp_oauth_grants SET agent_remote_id=$4
        WHERE organization_id=$1 AND workspace_id=$2 AND user_id=$3 AND revoked_at IS NULL
          AND agent_remote_id IS NULL AND agent_name=$5`,
      [intent.organization_id,intent.workspace_id,intent.user_id,remote.id,remote.name]);
      if(decision.deleteRow && snapshot.row) await tx.query(`DELETE FROM selfhost_hosted_relay_participants
        WHERE id=$1 AND workspace_id=$2 AND user_id=$3 AND agent_remote_id=$4`,
      [snapshot.row.id,intent.workspace_id,intent.user_id,intent.agent_remote_id]);
      await this.complete(tx,intent.id,decision.outcome);
      return decision.outcome==="kept"?"kept":"completed";
    });
  }
}

function same(left:Snapshot,right:Snapshot):boolean {
  return JSON.stringify(left)===JSON.stringify(right);
}
