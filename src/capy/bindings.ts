import { randomUUID } from "node:crypto";
import { decryptSecret, encryptSecret, hashSecret, type EncryptionKeyring } from "../crypto.js";
import type { Database, SqlExecutor } from "../database.js";
import type { RelaycastClient, RemoteAgent } from "../messaging/relaycast.js";
import { HOSTED_SOURCE, ownerHash } from "../mcp/relay-participants.js";
import { lockOrganization, lockUser } from "../tenancy.js";
import { CapyRuntimeError, type CapyRuntime } from "./runtime.js";

/** Internal service, called only after person admission. Never pass model/user
 * supplied acting IDs here. Native integration must use !managed && !oauth,
 * exactly like Factory; this service does not extend OAuth assertActor/pin.
 */
export type CapyActor = { userId: string; organizationId: string; workspaceId: string };
export class CapyBindingError extends Error {
  constructor(readonly status: number, readonly code: string) { super(code); this.name = "CapyBindingError"; }
}
type Row = {
  id: string; workspace_id: string; organization_id: string; user_id: string; thread_id: string;
  state: "preparing" | "bound" | "retired"; generation: number; connection_digest: string;
  relaycast_workspace_id: string; relaycast_key_ciphertext: string | null; agent_name: string;
  agent_remote_id: string | null; token_ciphertext: string | null; registration_attempted: boolean;
  lease_owner: string | null; lease_until: Date | string | null; cleanup_pending: boolean; last_error: string | null;
};
type Access = { key: string; ciphertext: string; relayId: string; relayKeyCiphertext: string };
export type CapyBindingView = { id: string; threadId: string; agent: string; state: Row["state"]; cleanupPending: boolean };
const view = (row: Row): CapyBindingView => ({ id: row.id, threadId: row.thread_id,
  agent: row.agent_name, state: row.state, cleanupPending: row.cleanup_pending });
export const capyAgentName = (threadId: string) => `capy-${hashSecret(threadId).slice(0, 16)}`;
const THREAD = /^jam_[A-Za-z0-9]{6,64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const changed = () => new CapyBindingError(409, "capy_binding_changed");

export class CapyBindings {
  private readonly now: () => Date;
  constructor(readonly deps: {
    database: Database; keyring: EncryptionKeyring;
    runtime: Pick<CapyRuntime, "getThread">;
    relaycast: Pick<RelaycastClient, "getRosterAgent" | "registerHosted" | "recoverHosted" | "authenticatedAgent" | "releaseHosted">;
    now?: () => Date;
    externalTimeoutMs?: number;
  }) {
    this.now = deps.now ?? (() => new Date());
    if (!Number.isInteger(deps.externalTimeoutMs ?? 10_000) || (deps.externalTimeoutMs ?? 10_000) < 1 || (deps.externalTimeoutMs ?? 10_000) > 10_000)
      throw new Error("invalid Capy external timeout");
  }

  /** Bound the caller's wait even if an injected/internal transport stalls.
   * Timed-out writes remain uncertain; this does not assert remote cancellation.
   */
  private async external<T>(work: () => Promise<T>): Promise<T> {
    let timer!: ReturnType<typeof setTimeout>;
    const timeout = new Promise<never>((_resolve,reject) => {
      timer = setTimeout(() => reject(new Error("capy_relay_timeout")),this.deps.externalTimeoutMs ?? 10_000);
    });
    try { return await Promise.race([work(),timeout]); }
    finally { clearTimeout(timer); }
  }

  private async locked<T>(actor: CapyActor, fn: (tx: SqlExecutor) => Promise<T>): Promise<T> {
    return this.deps.database.transaction(async tx => {
      await lockUser(tx, actor.userId);
      await lockOrganization(tx, actor.organizationId);
      // Member deletion uses the organization row; key changes use this exact
      // workspace advisory lock. Keep both fences, in user->org->key order.
      await tx.query("SELECT id FROM organizations WHERE id=$1 FOR SHARE", [actor.organizationId]);
      await tx.query("SELECT pg_advisory_xact_lock(hashtext('remote-agent-connections'),hashtext($1))", [actor.workspaceId]);
      return fn(tx);
    });
  }

  private async access(tx: SqlExecutor, actor: CapyActor, needKey = true): Promise<Access> {
    const found = (await tx.query<{
      role: string; relaycast_workspace_id: string; relaycast_api_key_ciphertext: string;
      key_ciphertext: string | null; created_by_user_id: string | null;
    }>(`SELECT m.role,w.relaycast_workspace_id,w.relaycast_api_key_ciphertext,c.key_ciphertext,c.created_by_user_id
      FROM workspaces w JOIN organization_memberships m ON m.organization_id=w.organization_id AND m.user_id=$3
      LEFT JOIN remote_agent_connections c ON c.workspace_id=w.id AND c.provider='capy'
      WHERE w.id=$1 AND w.organization_id=$2 FOR SHARE OF w,m`,
    [actor.workspaceId,actor.organizationId,actor.userId])).rows[0];
    if (!found || !["owner", "admin"].includes(found.role)) throw new CapyBindingError(403, "capy_forbidden");
    if (needKey && !found.key_ciphertext) throw new CapyBindingError(409, "capy_not_connected");
    if (needKey && found.created_by_user_id !== actor.userId) throw new CapyBindingError(403, "capy_key_owner_required");
    return { key: needKey && found.key_ciphertext ? decryptSecret(found.key_ciphertext, this.deps.keyring) : "",
      ciphertext: found.key_ciphertext ?? "", relayId: found.relaycast_workspace_id,
      relayKeyCiphertext: found.relaycast_api_key_ciphertext };
  }

  private async current(tx: SqlExecutor, actor: CapyActor, row: Row, claim?: string) {
    const access = await this.access(tx, actor);
    const live = (await tx.query<Row>("SELECT * FROM capy_bindings WHERE id=$1 FOR UPDATE", [row.id])).rows[0];
    if (!live || live.workspace_id !== actor.workspaceId || live.user_id !== actor.userId || live.organization_id !== actor.organizationId ||
      live.state === "retired" || live.generation !== row.generation ||
      hashSecret(access.ciphertext) !== row.connection_digest || access.relayId !== row.relaycast_workspace_id ||
      (claim !== undefined && (live.lease_owner !== claim || !live.lease_until || new Date(live.lease_until).getTime() <= this.now().getTime()))) throw changed();
    return live;
  }

  private owns(agent: RemoteAgent, row: Row): boolean {
    return agent.name === row.agent_name && agent.metadata.source === HOSTED_SOURCE &&
      agent.metadata.capy_binding_id === row.id && agent.metadata.cloud_workspace_id === row.workspace_id &&
      agent.metadata.owner_hash === ownerHash(row.user_id);
  }

  async list(actor: CapyActor): Promise<CapyBindingView[]> {
    return this.locked(actor, async tx => {
      await this.access(tx, actor, false);
      return (await tx.query<Row>("SELECT * FROM capy_bindings WHERE workspace_id=$1 AND user_id=$2 ORDER BY created_at,id",
        [actor.workspaceId,actor.userId])).rows.map(view);
    });
  }

  async bind(actor: CapyActor, threadId: string): Promise<CapyBindingView> {
    if (!THREAD.test(threadId)) throw new CapyBindingError(400, "capy_invalid_thread");
    // Prove visibility before a global thread claim. Otherwise a valid key
    // for another Capy account could squat an inaccessible thread id.
    const preflight = await this.locked(actor, tx => this.access(tx,actor));
    try {
      const thread = await this.deps.runtime.getThread(preflight.key,threadId);
      if (thread.id !== threadId) throw new CapyBindingError(502,"capy_thread_mismatch");
    } catch (error) {
      if (error instanceof CapyBindingError) throw error;
      if (error instanceof CapyRuntimeError && [403,404].includes(error.status)) throw new CapyBindingError(404,"capy_thread_unavailable");
      throw new CapyBindingError(503,"capy_binding_unavailable");
    }
    const claim = randomUUID();
    const { row, access } = await this.locked(actor, async tx => {
      const access = await this.access(tx, actor);
      if (access.ciphertext !== preflight.ciphertext || access.relayId !== preflight.relayId) throw changed();
      // Serialize cross-workspace claims as well as same-workspace key changes.
      await tx.query("SELECT pg_advisory_xact_lock(hashtext('capy-thread:' || $1))", [threadId]);
      let row = (await tx.query<Row & { busy: boolean }>(`SELECT *,coalesce(lease_until>$2,false) AS busy
        FROM capy_bindings WHERE thread_id=$1 AND (state<>'retired' OR cleanup_pending)
        ORDER BY created_at DESC LIMIT 1 FOR UPDATE`, [threadId,this.now()])).rows[0];
      if (row) {
        if (row.workspace_id !== actor.workspaceId || row.user_id !== actor.userId) throw new CapyBindingError(409, "capy_thread_claimed");
        if (row.state === "retired") throw new CapyBindingError(409, "capy_cleanup_pending");
        if (row.connection_digest !== hashSecret(access.ciphertext) || row.relaycast_workspace_id !== access.relayId) throw changed();
        if (row.state === "bound") return { row, access };
        if (row.busy) throw new CapyBindingError(409, "capy_binding_in_progress");
      } else {
        row = (await tx.query<Row & { busy: boolean }>(`INSERT INTO capy_bindings
          (id,workspace_id,organization_id,user_id,thread_id,state,connection_digest,
           relaycast_workspace_id,relaycast_key_ciphertext,agent_name)
          VALUES($1,$2,$3,$4,$5,'preparing',$6,$7,$8,$9) RETURNING *`,
        [randomUUID(),actor.workspaceId,actor.organizationId,actor.userId,threadId,
          hashSecret(access.ciphertext),access.relayId,access.relayKeyCiphertext,capyAgentName(threadId)])).rows[0]!;
      }
      await tx.query("UPDATE capy_bindings SET lease_owner=$2,lease_until=$3,updated_at=$4 WHERE id=$1",
        [row.id,claim,new Date(this.now().getTime()+120_000),this.now()]);
      row.lease_owner = claim;
      return { row, access };
    });
    if (row.state === "bound") {
      if (!await this.agentFor(actor.workspaceId, actor.userId, row.agent_name)) throw changed();
      return view(row);
    }
    try {
      await this.locked(actor, tx => this.current(tx, actor, row, claim));
      const relayKey = decryptSecret(access.relayKeyCiphertext, this.deps.keyring);
      const remote = await this.external(() => this.deps.relaycast.getRosterAgent(relayKey, row.agent_name));
      if (remote && (!this.owns(remote, row) || (row.agent_remote_id && remote.id !== row.agent_remote_id)))
        throw new CapyBindingError(409, "capy_agent_conflict");
      if (!remote && row.registration_attempted) throw new CapyBindingError(409, "capy_registration_unknown");
      // Commit write intent before dispatch; a lost response never starts a
      // second blind registration. A matching remote can be recovered by id.
      await this.locked(actor, async tx => {
        await this.current(tx, actor, row, claim);
        await tx.query("UPDATE capy_bindings SET registration_attempted=true WHERE id=$1", [row.id]);
      });
      const registered = remote
        ? await this.external(() => this.deps.relaycast.recoverHosted(relayKey,row.agent_name,remote.id,ownerHash(actor.userId)))
        : await this.external(() => this.deps.relaycast.registerHosted(relayKey,row.agent_name,{
          source: HOSTED_SOURCE, capy_binding_id: row.id, cloud_workspace_id: actor.workspaceId,
          owner_hash: ownerHash(actor.userId), session_kind: "capy", created_by: "capy-binding",
        }));
      const verified = await this.external(() => this.deps.relaycast.authenticatedAgent(registered.token));
      if (registered.name !== row.agent_name || verified.id !== registered.id || verified.workspaceId !== access.relayId || !this.owns(verified,row))
        throw new CapyBindingError(409, "capy_identity_changed");
      // Retain the exact acknowledged id for cleanup even if the user's
      // authority changes before the final bound-state commit.
      await this.deps.database.query(`UPDATE capy_bindings SET agent_remote_id=$3
        WHERE id=$1 AND lease_owner=$2 AND generation=$4 AND state='preparing'`,
      [row.id,claim,registered.id,row.generation]);
      return await this.locked(actor, async tx => {
        await this.current(tx, actor, row, claim);
        const result = await tx.query<Row>(`UPDATE capy_bindings SET state='bound',agent_remote_id=$2,
          token_ciphertext=$3,lease_owner=NULL,lease_until=NULL,last_error=NULL,updated_at=$4 WHERE id=$1 RETURNING *`,
        [row.id,registered.id,encryptSecret(registered.token,this.deps.keyring.active),this.now()]);
        return view(result.rows[0]!);
      });
    } catch (error) {
      // Revocation/key changes leave no usable half-bound identity. For other
      // failures keep the write-intent receipt for safe retry/reconciliation.
      if (error instanceof CapyBindingError && ["capy_forbidden","capy_key_owner_required","capy_not_connected","capy_binding_changed"].includes(error.code)) {
        await this.deps.database.query(`UPDATE capy_bindings SET state='retired',generation=generation+1,
          token_ciphertext=NULL,cleanup_pending=true,lease_owner=NULL,lease_until=NULL,last_error='capy_binding_changed'
          WHERE id=$1 AND lease_owner=$2 AND generation=$3 AND state='preparing'`, [row.id,claim,row.generation]);
      }
      if (error instanceof CapyBindingError) throw error;
      throw new CapyBindingError(503, "capy_binding_unavailable");
    } finally {
      await this.deps.database.query("UPDATE capy_bindings SET lease_owner=NULL,lease_until=NULL WHERE id=$1 AND lease_owner=$2", [row.id,claim]);
    }
  }

  /** Native person-only resolver. Never create a participant or recover a
   * token here. The integration must retain Factory's !managed&&!oauth gate.
   */
  async agentFor(workspaceId: string, userId: string, name: string): Promise<{ name: string; token: string } | null> {
    if (!name.startsWith("capy-")) return null;
    const row = (await this.deps.database.query<Row>(`SELECT b.* FROM capy_bindings b
      JOIN workspaces w ON w.id=b.workspace_id AND w.organization_id=b.organization_id
      JOIN organization_memberships m ON m.organization_id=b.organization_id AND m.user_id=b.user_id
      JOIN remote_agent_connections c ON c.workspace_id=b.workspace_id AND c.provider='capy'
      WHERE b.workspace_id=$1 AND b.user_id=$2 AND b.agent_name=$3 AND b.state='bound'
        AND m.role IN ('owner','admin') AND c.created_by_user_id=b.user_id
        AND w.relaycast_workspace_id=b.relaycast_workspace_id`, [workspaceId,userId,name])).rows[0];
    if (!row?.token_ciphertext || !row.agent_remote_id || capyAgentName(row.thread_id) !== name) return null;
    const actor = { userId,workspaceId,organizationId: row.organization_id };
    try {
      await this.locked(actor, tx => this.current(tx,actor,row));
      const token = decryptSecret(row.token_ciphertext,this.deps.keyring);
      const remote = await this.external(() => this.deps.relaycast.authenticatedAgent(token));
      if (remote.id !== row.agent_remote_id || remote.workspaceId !== row.relaycast_workspace_id || !this.owns(remote,row)) return null;
      await this.locked(actor, tx => this.current(tx,actor,row));
      return { name,token };
    } catch { return null; }
  }

  async retire(actor: CapyActor, id: string): Promise<void> {
    if (!UUID.test(id)) throw new CapyBindingError(404,"capy_binding_not_found");
    await this.locked(actor, async tx => {
      await this.access(tx,actor,false);
      const found = await tx.query(`UPDATE capy_bindings SET state='retired',generation=generation+1,
        token_ciphertext=NULL,lease_owner=NULL,lease_until=NULL,cleanup_pending=true,updated_at=$4
        WHERE id=$1 AND workspace_id=$2 AND user_id=$3 AND organization_id=$5 AND state<>'retired' RETURNING id`,
      [id,actor.workspaceId,actor.userId,this.now(),actor.organizationId]);
      if (!found.rows.length && !(await tx.query("SELECT id FROM capy_bindings WHERE id=$1 AND workspace_id=$2 AND user_id=$3 AND organization_id=$4",
        [id,actor.workspaceId,actor.userId,actor.organizationId])).rows.length) throw new CapyBindingError(404,"capy_binding_not_found");
    });
    await this.cleanup(id);
  }

  /** System cleanup: only the original route and this binding's immutable
   * remote identity are touched. Unknown registration absence stays pending.
   */
  async cleanup(id: string): Promise<boolean> {
    if (!UUID.test(id)) return false;
    const row = (await this.deps.database.query<Row>("SELECT * FROM capy_bindings WHERE id=$1 AND state='retired' AND cleanup_pending", [id])).rows[0];
    if (!row) return true;
    try {
      if (row.registration_attempted) {
        if (!row.relaycast_key_ciphertext) return false;
        const key = decryptSecret(row.relaycast_key_ciphertext,this.deps.keyring);
        const remote = await this.external(() => this.deps.relaycast.getRosterAgent(key,row.agent_name));
        if (!remote && !row.agent_remote_id) return false;
        if (remote) {
          if (!this.owns(remote,row) || (row.agent_remote_id && remote.id !== row.agent_remote_id)) return false;
          await this.external(() => this.deps.relaycast.releaseHosted(key,row.agent_name,remote.id));
        }
      }
      await this.deps.database.query(`UPDATE capy_bindings SET cleanup_pending=false,
        relaycast_key_ciphertext=NULL,agent_remote_id=NULL,last_error=NULL,updated_at=$3
        WHERE id=$1 AND state='retired' AND generation=$2`, [id,row.generation,this.now()]);
      return true;
    } catch { return false; }
  }
}
