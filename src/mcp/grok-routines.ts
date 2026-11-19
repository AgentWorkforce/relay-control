import { randomBytes } from "node:crypto";
import { decryptSecret, encryptSecret, hashSecret, type EncryptionKeyring } from "../crypto.js";
import type { Database, SqlExecutor } from "../database.js";
import { page } from "../identity/pages.js";
import { RelaycastCallError, type RelaycastClient } from "../messaging/relaycast.js";
import { isBindingOwnedIdentity } from "../messaging/binding-identities.js";
import { lockOrganization, lockUser, type TenancyMode } from "../tenancy.js";
import { admissionConnectorKind } from "./oauth/connector-kind.js";
import { enrolHostedAtGate, type GateEnrolment } from "./hosted-gate.js";
import type { McpConsentPrincipal } from "./oauth/consent.js";
import { GrokRoutineError, grokInboxPrompt, parseGrokRoutineCredentials } from "./grok-routine.js";
import { ownerHash, HOSTED_SOURCE } from "./relay-participants.js";

// Shared dashboard ingresses route /cloud/api to Control, and /cloud to the UI.
export const GROK_SETUP_PATH = "/cloud/api/v1/grok-bot/routine";
type Owner = Pick<McpConsentPrincipal, "userId" | "organizationId" | "workspaceId">;
type Grant = { id: string; agent_name: string; agent_remote_id: string | null };
type Routine = { credentials_ciphertext: string; notified_delivery_ids: string[]; failures: number;
  last_delivered_at: Date | string | null; last_error: string | null };
/** A gated participant to enrol again at relaygate after the delivery transaction ends (GrokRoutines.recover). */
type Recovery = { participantId: string; tokenCiphertext: string; relaygateAgentId: string; agentName: string; admittedClients: string[] };

const json = (value: unknown, status = 200) => Response.json(value, { status, headers: { "cache-control": "no-store" } });
const escape = (value: string) => value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;").replaceAll("'", "&#39;");

/** One encrypted routine per grant. User -> organization -> grant locks fence every delivery against revocation. */
/** A gated participant's rg_ token (24 h at relaygate) is renewed once it is this old. */
const GATE_TOKEN_REFRESH_AFTER_MS = 12 * 3_600_000;
/** How long one scan holds a routine while its participant enrols again at relaygate, so another scan does not race it. */
const GATE_RECOVERY_LEASE_MS = 60_000;

export class GrokRoutines {
  constructor(readonly options: { database: Database; keyring: EncryptionKeyring; client: RelaycastClient;
    /** Gate-only installs: participants enrolled through relaygate (relaygate_agent_id set) are read through it. */
    gate?: RelaycastClient;
    publicOrigin: string; tenancyMode: TenancyMode; fetchImpl?: typeof fetch; now?: () => Date; requestTimeoutMs?: number }) {}

  private now() { return this.options.now?.() ?? new Date(); }

  async grant(tx: SqlExecutor, id: string, owner: Owner): Promise<Grant> {
    await lockUser(tx, owner.userId);
    await lockOrganization(tx, owner.organizationId);
    const row = (await tx.query<Grant & { client_name: string | null; redirect_uris: string[] }>(`SELECT g.id,g.agent_name,g.agent_remote_id,c.client_name,c.redirect_uris
      FROM mcp_oauth_grants g JOIN mcp_oauth_clients c ON c.client_id=g.client_id
      JOIN workspaces w ON w.id=g.workspace_id AND w.organization_id=g.organization_id
      JOIN organization_memberships m ON m.organization_id=g.organization_id AND m.user_id=g.user_id
      WHERE g.id=$1 AND g.user_id=$2 AND g.organization_id=$3 AND g.workspace_id=$4
        AND g.revoked_at IS NULL AND 'relay:mcp'=ANY(g.scopes)
        AND g.resource=ANY($5::text[])
        AND EXISTS (SELECT 1 FROM mcp_oauth_sessions s WHERE s.grant_id=g.id AND s.token_family_id=g.token_family_id
          AND s.revoked_at IS NULL AND s.refresh_token_expires_at>$7 AND 'relay:mcp'=ANY(s.scopes))
        AND ($6::text='multi' OR NOT EXISTS (SELECT 1 FROM organizations other WHERE other.id<>g.organization_id))
      FOR UPDATE OF g`, [id, owner.userId, owner.organizationId, owner.workspaceId,
      [this.options.publicOrigin + "/mcp", this.options.publicOrigin + "/cloud/api/v1/mcp/shared-sessions"],
      this.options.tenancyMode, this.now()])).rows[0];
    if (!row || admissionConnectorKind({ clientName: row.client_name, redirectUris: row.redirect_uris }) !== "grok-bot") {
      throw new GrokRoutineError("This Grok Bot connection is no longer available. Reconnect it in this workspace.");
    }
    return row;
  }

  setupUrl(grantId: string): string {
    return `${this.options.publicOrigin}${GROK_SETUP_PATH}?${new URLSearchParams({ grant: grantId })}`;
  }

  async status(grantId: string, owner: Owner) {
    return this.options.database.transaction(async tx => {
      const grant = await this.grant(tx, grantId, owner);
      const routine = (await tx.query<Routine>("SELECT * FROM grok_bot_routines WHERE grant_id=$1", [grantId])).rows[0];
      return { agent: grant.agent_name, configured: Boolean(routine), webhook_accepted: Boolean(routine?.last_delivered_at),
        last_delivered_at: routine?.last_delivered_at ?? null, last_error: routine?.last_error ?? null,
        setup_url: this.setupUrl(grantId), routine_prompt: grokInboxPrompt(grant.agent_name) };
    });
  }

  async disconnect(grantId: string, owner: Owner) {
    return this.options.database.transaction(async tx => {
      await this.grant(tx, grantId, owner);
      const result = await tx.query("DELETE FROM grok_bot_routines WHERE grant_id=$1 RETURNING grant_id", [grantId]);
      return { removed: result.rows.length };
    });
  }

  /** Called only behind the OAuth module's browser account and live workspace admission. */
  async handle(request: Request, owner: Owner): Promise<Response> {
    const url = new URL(request.url);
    const grantId = url.searchParams.get("grant") ?? "";
    if (!/^[0-9a-f-]{36}$/i.test(grantId)) return json({ error: "not_found" }, 404);
    if (request.method !== "GET" && request.headers.get("origin") !== this.options.publicOrigin) return json({ error: "forbidden" }, 403);
    try {
      if (request.method === "POST") {
        let body: Record<string, unknown>;
        try { body = await request.json(); } catch { return json({ error: "invalid_request" }, 400); }
        if (!body || typeof body !== "object" || Array.isArray(body)) return json({ error: "invalid_request" }, 400);
        const credentials = parseGrokRoutineCredentials(body.webhook_url, body.authorization);
        await this.options.database.transaction(async tx => {
          const grant = await this.grant(tx, grantId, owner);
          if (!grant.agent_remote_id) throw new GrokRoutineError("Call join_relay from this bot before saving its routine.");
          await tx.query(`INSERT INTO grok_bot_routines(grant_id,credentials_ciphertext,next_attempt_at,updated_at)
            VALUES ($1,$2,$3,$3) ON CONFLICT (grant_id) DO UPDATE SET credentials_ciphertext=$2,
            next_attempt_at=$3,updated_at=$3,failures=0,last_error=NULL,last_delivered_at=NULL,notified_delivery_ids='{}'`,
          [grantId, encryptSecret(JSON.stringify(credentials), this.options.keyring.active), this.now()]);
        });
        return json({ configured: true, message: "Saved. Send this bot a Relay message to verify delivery in Grok." });
      }
      if (request.method === "DELETE") return json(await this.disconnect(grantId, owner));
      if (request.method !== "GET") return json({ error: "method_not_allowed" }, 405);
      const state = await this.status(grantId, owner);
      const nonce = randomBytes(18).toString("base64url");
      const html = page("Grok Bot wake-ups", `<h1>Wake up ${escape(state.agent)}</h1>
<p>Create a Grok Bot routine named <strong>Agent Relay inbox</strong> with <strong>When a webhook fires</strong>. Use these instructions:</p>
<blockquote>${escape(state.routine_prompt)}</blockquote>
<p>Copy the routine's <strong>POST to</strong> URL and <strong>Authorization</strong> header into this page. Keep the key out of chat.</p>
<form id="routine"><p><label>Webhook URL <input name="webhook_url" type="text" inputmode="url" required autocomplete="off"></label></p>
<p><label>Authorization header <input name="authorization" type="password" required autocomplete="off"></label></p>
<div class="actions"><button class="btn" type="submit">Save wake-ups</button><button class="btn secondary" id="disconnect" type="button">Disconnect</button></div></form>
<p id="status" role="status">${state.configured ? state.last_error ? "Delivery failed. Check the routine URL and header, then save again." : state.webhook_accepted ? "Grok accepted a wake-up. Confirm the message appeared in the bot's chat." : "Saved. Send this bot a Relay message to verify delivery in Grok." : "No routine saved yet."}</p>`,
`const form=document.getElementById('routine'),status=document.getElementById('status');
async function change(method){const buttons=document.querySelectorAll('button');buttons.forEach(b=>b.disabled=true);try{const response=await fetch(location.pathname+location.search,{method,headers:{'content-type':'application/json'},...(method==='POST'?{body:JSON.stringify(Object.fromEntries(new FormData(form)))}:{})});const data=await response.json();status.textContent=response.ok?(data.message||'Wake-ups disconnected.'):(data.error_description||'Could not save wake-ups.');if(response.ok)form.reset();}catch{status.textContent='Could not save wake-ups. Try again.';}buttons.forEach(b=>b.disabled=false);}
form.addEventListener('submit',e=>{e.preventDefault();change('POST');});document.getElementById('disconnect').addEventListener('click',()=>change('DELETE'));`, "", nonce);
      return new Response(html, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store",
        "referrer-policy": "no-referrer", "x-content-type-options": "nosniff",
        "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'` } });
    } catch (error) {
      if (error instanceof GrokRoutineError) return json({ error: "invalid_request", error_description: error.message }, 400);
      throw error;
    }
  }

  /** Bounded round-robin scan; persisted pending IDs dedupe accepted wakes without acknowledging the agent's inbox. */
  async tick(signal?: AbortSignal): Promise<void> {
    const candidates = await this.options.database.query<{ grant_id: string; user_id: string; organization_id: string; workspace_id: string }>(
      `SELECT r.grant_id,g.user_id,g.organization_id,g.workspace_id FROM grok_bot_routines r
       JOIN mcp_oauth_grants g ON g.id=r.grant_id WHERE r.next_attempt_at<=$1 ORDER BY r.next_attempt_at LIMIT 20`, [this.now()]);
    for (const candidate of candidates.rows) {
      if (signal?.aborted) break;
      const owner: Owner = { userId: candidate.user_id, organizationId: candidate.organization_id, workspaceId: candidate.workspace_id };
      const recovery = await this.options.database.transaction(async (tx): Promise<Recovery | null> => {
        let grant: Grant;
        try { grant = await this.grant(tx, candidate.grant_id, owner); } catch (error) {
          if (!(error instanceof GrokRoutineError)) throw error;
          await tx.query("DELETE FROM grok_bot_routines WHERE grant_id=$1", [candidate.grant_id]);
          return null;
        }
        const routine = (await tx.query<Routine>("SELECT * FROM grok_bot_routines WHERE grant_id=$1 AND next_attempt_at<=$2 FOR UPDATE",
          [grant.id, this.now()])).rows[0];
        if (!routine) return null;
        try {
          // One budget bounds all remote reads, response bodies and the wake
          // while the revocation fence is held. stop() aborts the same requests.
          const deadline = AbortSignal.timeout(this.options.requestTimeoutMs ?? 5_000);
          const requestSignal = signal ? AbortSignal.any([signal, deadline]) : deadline;
          const participant = (await tx.query<{ id: string; token_ciphertext: string; relaycast_workspace_id: string;
            relaygate_agent_id: string | null; agent_name: string; admitted_clients: string[]; stale: boolean }>(
            `SELECT p.id,p.token_ciphertext,p.relaycast_workspace_id,p.relaygate_agent_id,p.agent_name,p.admitted_clients,
              p.updated_at < $5 AS stale
            FROM hosted_relay_participants p JOIN workspaces w ON w.id=p.workspace_id AND w.organization_id=$4
            WHERE p.workspace_id=$1 AND p.user_id=$2 AND p.agent_remote_id=$3
              AND p.relaycast_workspace_id=w.relaycast_workspace_id`,
          [candidate.workspace_id, candidate.user_id, grant.agent_remote_id, candidate.organization_id,
            new Date(this.now().getTime() - GATE_TOKEN_REFRESH_AFTER_MS)])).rows[0];
          if (!participant) throw new Error("identity_unavailable");
          // A participant enrolled through relaygate holds an rg_ token: it reads through relaygate only.
          const gated = participant.relaygate_agent_id !== null;
          if (gated && !this.options.gate) throw new Error("identity_unavailable");
          const via = gated ? this.options.gate! : this.options.client;
          let token = decryptSecret(participant.token_ciphertext, this.options.keyring);
          // relaygate enrolled this participant for other hosted clients only, or rejects its token (it lapsed
          // while the routine was idle): enrol it again as Grok Bot once this transaction ends (recover).
          const recover = async (rejected: boolean): Promise<Recovery> => {
            await tx.query("UPDATE grok_bot_routines SET next_attempt_at=$2,updated_at=$3 WHERE grant_id=$1",
              [grant.id, new Date(this.now().getTime() + GATE_RECOVERY_LEASE_MS), this.now()]);
            return { participantId: participant.id, tokenCiphertext: participant.token_ciphertext, relaygateAgentId: participant.relaygate_agent_id!,
              agentName: participant.agent_name,
              admittedClients: rejected ? ["grok-bot"] : [...new Set([...(participant.admitted_clients ?? []), "grok-bot"])] };
          };
          if (gated && !(participant.admitted_clients ?? []).includes("grok-bot")) return await recover(false);
          let remote: Awaited<ReturnType<RelaycastClient["authenticatedAgent"]>>;
          try {
            if (gated && participant.stale) {
              // rg_ tokens last 24 hours; a routine may poll an idle participant for longer, so renew it at half-life.
              token = await via.refreshGateToken(token, requestSignal);
              await tx.query("UPDATE hosted_relay_participants SET token_ciphertext=$2, updated_at=now() WHERE id=$1",
                [participant.id, encryptSecret(token, this.options.keyring.active)]);
            }
            remote = await via.authenticatedAgent(token, requestSignal);
          } catch (error) {
            if (gated && error instanceof RelaycastCallError && error.status === 401) return await recover(true);
            throw error;
          }
          if (remote.id !== grant.agent_remote_id || remote.workspaceId !== participant.relaycast_workspace_id || remote.status === "released" ||
              isBindingOwnedIdentity(remote.metadata) ||
              remote.metadata.source !== HOSTED_SOURCE || remote.metadata.owner_hash !== ownerHash(candidate.user_id) ||
              remote.metadata.cloud_workspace_id !== candidate.workspace_id) throw new Error("identity_unavailable");
          const inbox = (await via.readHostedInbox(token, requestSignal)).slice(0, 100).filter(message => message.sender_id !== remote.id);
          const ids = inbox.map(message => message.delivery_id).sort();
          const fresh = ids.filter(id => !routine.notified_delivery_ids.includes(id));
          if (fresh.length) {
            const saved = JSON.parse(decryptSecret(routine.credentials_ciphertext, this.options.keyring));
            const credentials = parseGrokRoutineCredentials(saved.url, saved.key);
            const eventId = hashSecret(JSON.stringify([grant.id, fresh]));
            const response = await (this.options.fetchImpl ?? fetch)(credentials.url, { method: "POST", redirect: "error",
              signal: requestSignal,
              headers: { "content-type": "application/json", Authorization: `Bearer ${credentials.key}`, "webhook-id": eventId },
              body: JSON.stringify({ eventId, name: "relay.inbox", agent: remote.name, pending_count: ids.length }) });
            await response.body?.cancel();
            if (!response.ok) throw new Error("webhook_unavailable");
          }
          await tx.query(`UPDATE grok_bot_routines SET notified_delivery_ids=$2,failures=0,last_error=NULL,
            next_attempt_at=$3,updated_at=$4,last_delivered_at=CASE WHEN $5 THEN $4 ELSE last_delivered_at END WHERE grant_id=$1`,
          [grant.id, ids, new Date(this.now().getTime() + 5_000), this.now(), fresh.length > 0]);
        } catch {
          await this.failed(tx, grant.id, routine.failures);
        }
        return null;
      });
      if (recovery) await this.recover(owner, candidate.grant_id, recovery);
    }
  }

  /** Neither provider error bodies nor URLs/keys are ever stored or logged. */
  private async failed(tx: SqlExecutor, grantId: string, failures: number): Promise<void> {
    await tx.query(`UPDATE grok_bot_routines SET failures=failures+1,last_error='delivery_unavailable',next_attempt_at=$2,updated_at=$3
      WHERE grant_id=$1`, [grantId, new Date(this.now().getTime() + Math.min(300_000, 5_000 * 2 ** Math.min(failures + 1, 6))), this.now()]);
  }

  /**
   * Enrols a gated participant again at relaygate as Grok Bot (the kind its
   * grant is admitted as), with no transaction open: relaygate introspects
   * the hosted credential with this service. The new token is adopted, under
   * the same user, organization, grant and routine locks as a delivery, only
   * if relaygate answered with the stored relaygate agent and the grant's
   * Relaycast agent and the row is unchanged. Anything else, including a
   * relaygate refusal, records a delivery failure; nothing is released.
   */
  private async recover(owner: Owner, grantId: string, recovery: Recovery): Promise<void> {
    let enrolled: GateEnrolment | null = null;
    if (this.options.gate) {
      try {
        enrolled = await enrolHostedAtGate({ database: this.options.database, gate: this.options.gate }, {
          workspaceId: owner.workspaceId, organizationId: owner.organizationId, userId: owner.userId,
          agentName: recovery.agentName, client: "grok-bot" });
      } catch {
        enrolled = null;
      }
    }
    await this.options.database.transaction(async tx => {
      let grant: Grant;
      try { grant = await this.grant(tx, grantId, owner); } catch (error) {
        if (error instanceof GrokRoutineError) return;
        throw error;
      }
      const routine = (await tx.query<Routine>("SELECT * FROM grok_bot_routines WHERE grant_id=$1 FOR UPDATE", [grant.id])).rows[0];
      if (!routine) return;
      const current = (await tx.query<{ token_ciphertext: string; relaygate_agent_id: string | null; agent_remote_id: string }>(
        `SELECT token_ciphertext,relaygate_agent_id,agent_remote_id FROM hosted_relay_participants
          WHERE id=$1 AND workspace_id=$2 AND user_id=$3 FOR UPDATE`, [recovery.participantId, owner.workspaceId, owner.userId])).rows[0];
      if (enrolled && current && current.token_ciphertext === recovery.tokenCiphertext
          && current.relaygate_agent_id === recovery.relaygateAgentId && enrolled.relaygateAgentId === recovery.relaygateAgentId
          && current.agent_remote_id === grant.agent_remote_id && enrolled.relaycastAgentId === current.agent_remote_id) {
        await tx.query("UPDATE hosted_relay_participants SET token_ciphertext=$2,admitted_clients=$3::text[],updated_at=now() WHERE id=$1",
          [recovery.participantId, encryptSecret(enrolled.token, this.options.keyring.active), recovery.admittedClients]);
        await tx.query("UPDATE grok_bot_routines SET next_attempt_at=$2,updated_at=$2 WHERE grant_id=$1", [grant.id, this.now()]);
        return;
      }
      await this.failed(tx, grant.id, routine.failures);
    });
  }

  private timer?: ReturnType<typeof setTimeout>;
  private active?: Promise<void>;
  private abort?: AbortController;
  start(): void {
    if (this.abort) return;
    this.abort = new AbortController();
    const run = () => {
      if (this.abort?.signal.aborted) return;
      this.active = this.tick(this.abort?.signal).catch(() => console.warn("[grok-routines] scan unavailable")).finally(() => {
        if (!this.abort?.signal.aborted) { this.timer = setTimeout(run, 5_000); this.timer.unref(); }
      });
    };
    run();
  }
  async stop(): Promise<void> {
    this.abort?.abort();
    clearTimeout(this.timer);
    await this.active;
    this.abort = undefined;
  }
}
