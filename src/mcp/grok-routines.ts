import { randomBytes } from "node:crypto";
import { decryptSecret, encryptSecret, hashSecret, type EncryptionKeyring } from "../crypto.js";
import type { Database, SqlExecutor } from "../database.js";
import { page } from "../identity/pages.js";
import type { RelaycastClient } from "../messaging/relaycast.js";
import { isBindingOwnedIdentity } from "../messaging/binding-identities.js";
import { lockOrganization, lockUser, type TenancyMode } from "../tenancy.js";
import { connectorKind } from "./oauth/connector-kind.js";
import type { McpConsentPrincipal } from "./oauth/consent.js";
import { GrokRoutineError, grokInboxPrompt, grokRoutineHeaders, grokRoutinePrompt, parseGrokRoutineCredentials, parseGrokRoutineDetails, parseGrokRoutineUrl } from "./grok-routine.js";
import { REPLY_MODES, type ReplyMode } from "./grok-events-policy.js";
import {
  GROK_EVENT_RETENTION_MS, eventFromDelivery, getEvent, insertEvent, pendingWakes, recentEvents, senderTrust, wakeBody,
} from "./grok-events.js";
import { ownerHash, HOSTED_SOURCE } from "./relay-participants.js";

// Shared dashboard ingresses route /cloud/api to Control, and /cloud to the UI.
export const GROK_SETUP_PATH = "/cloud/api/v1/grok-bot/routine";
type Owner = Pick<McpConsentPrincipal, "userId" | "organizationId" | "workspaceId">;
type Grant = { id: string; agent_name: string; agent_remote_id: string | null };
type Routine = { credentials_ciphertext: string | null; notified_delivery_ids: string[]; failures: number;
  last_delivered_at: Date | string | null; last_error: string | null;
  delivery_mode: "webhook" | "polling"; reply_mode: ReplyMode; from_filter: string | null; polling_since: Date | string | null };
const DUPLICATE_ROUTINE = "This Grok routine is already connected to another Agent Relay connection. Disconnect it there first, or use a different routine.";
const FROM = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,511}$/;

const json = (value: unknown, status = 200) => Response.json(value, { status, headers: { "cache-control": "no-store" } });
const escape = (value: string) => value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;").replaceAll("'", "&#39;");

/** One encrypted routine per grant. User -> organization -> grant locks fence every delivery against revocation. */
export class GrokRoutines {
  constructor(readonly options: { database: Database; keyring: EncryptionKeyring; client: RelaycastClient;
    publicOrigin: string; tenancyMode: TenancyMode; fetchImpl?: typeof fetch; now?: () => Date; requestTimeoutMs?: number;
    /** SELFHOST_GROK_ROUTINES_CLOUD_COPY: Cloud's copied prompt, polling, event log and wakes (spec Phase 1). Default off. */
    cloudCopy?: boolean }) {}

  get cloudCopy(): boolean { return this.options.cloudCopy === true; }

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
    if (!row || connectorKind({ clientName: row.client_name, redirectUris: row.redirect_uris }) !== "grok-bot") {
      throw new GrokRoutineError("This Grok Bot connection is no longer available. Reconnect it in this workspace.");
    }
    return row;
  }

  setupUrl(grantId: string, from?: string): string {
    return `${this.options.publicOrigin}${GROK_SETUP_PATH}?${new URLSearchParams({ grant: grantId, ...(from ? { from } : {}) })}`;
  }

  /** The non-secret routine prompt for this grant: Cloud's copy when enabled, else the #136 inbox prompt. */
  prompt(agent: string, routine?: Pick<Routine, "delivery_mode" | "polling_since" | "from_filter">): string {
    if (!this.cloudCopy) return grokInboxPrompt(agent);
    // Every self-hosted Grok grant holds relay:mcp, so send_relay_message is available.
    return routine?.delivery_mode === "polling" && routine.polling_since
      ? grokRoutinePrompt(agent, { canReply: true, mode: "polling", since: new Date(routine.polling_since).toISOString(),
        ...(routine.from_filter ? { from: routine.from_filter } : {}) })
      : grokRoutinePrompt(agent, { canReply: true });
  }

  async status(grantId: string, owner: Owner) {
    return this.options.database.transaction(async tx => {
      const grant = await this.grant(tx, grantId, owner);
      const routine = (await tx.query<Routine>("SELECT * FROM grok_bot_routines WHERE grant_id=$1", [grantId])).rows[0];
      const base = { agent: grant.agent_name, configured: Boolean(routine && (routine.credentials_ciphertext || routine.delivery_mode === "polling")),
        webhook_accepted: Boolean(routine?.last_delivered_at),
        last_delivered_at: routine?.last_delivered_at ?? null, last_error: routine?.last_error ?? null,
        setup_url: this.setupUrl(grantId), routine_prompt: this.prompt(grant.agent_name, routine) };
      return this.cloudCopy ? { ...base, mode: routine?.delivery_mode ?? null, reply_mode: routine?.reply_mode ?? "notes-only",
        from: routine?.from_filter ?? null } : base;
    });
  }

  async disconnect(grantId: string, owner: Owner, input: { mode?: "webhook" | "polling"; webhookUrl?: string } = {}) {
    return this.options.database.transaction(async tx => {
      await this.grant(tx, grantId, owner);
      // Cloud's disconnect_grok_bot_routine: mode or webhook_url narrows it; neither stops both.
      const urlHash = input.webhookUrl === undefined ? null : hashSecret(parseGrokRoutineUrl(input.webhookUrl));
      const mode = urlHash ? "webhook" : input.mode ?? null;
      const result = await tx.query(`DELETE FROM grok_bot_routines WHERE grant_id=$1 AND ($2::text IS NULL OR delivery_mode=$2)
        AND ($3::text IS NULL OR routine_url_hash=$3) RETURNING grant_id`, [grantId, mode, urlHash]);
      return { removed: result.rows.length };
    });
  }

  /** Cloud's polling mode: an ingest-only row with no credential. Replaces a webhook routine for this grant. */
  async connectPolling(grantId: string, owner: Owner, from: string | undefined) {
    if (from !== undefined && !FROM.test(from)) throw new GrokRoutineError("from must be an Agent Relay agent name.");
    return this.options.database.transaction(async tx => {
      const grant = await this.grant(tx, grantId, owner);
      const now = this.now();
      await tx.query(`INSERT INTO grok_bot_routines(grant_id,credentials_ciphertext,delivery_mode,from_filter,polling_since,next_attempt_at,updated_at)
        VALUES ($1,NULL,'polling',$2,$3,$3,$3) ON CONFLICT (grant_id) DO UPDATE SET credentials_ciphertext=NULL,routine_url_hash=NULL,
        delivery_mode='polling',from_filter=$2,polling_since=$3,next_attempt_at=$3,updated_at=$3,failures=0,last_error=NULL,last_delivered_at=NULL,
        notified_delivery_ids='{}'`, [grantId, from ?? null, now]);
      return { agent: grant.agent_name, since: now.toISOString(),
        routine_prompt: this.prompt(grant.agent_name, { delivery_mode: "polling", polling_since: now, from_filter: from ?? null }) };
    });
  }

  async event(grantId: string, owner: Owner, eventId: string) {
    return this.options.database.transaction(async tx => {
      const grant = await this.grant(tx, grantId, owner);
      const routine = (await tx.query<Routine>("SELECT * FROM grok_bot_routines WHERE grant_id=$1", [grantId])).rows[0];
      return getEvent(tx, this.options.keyring, grant, routine?.reply_mode ?? "notes-only", eventId);
    });
  }

  async recent(grantId: string, owner: Owner, input: { since?: string; limit: number; scheduled?: boolean }) {
    return this.options.database.transaction(async tx => {
      const grant = await this.grant(tx, grantId, owner);
      const routine = (await tx.query<Routine>("SELECT * FROM grok_bot_routines WHERE grant_id=$1", [grantId])).rows[0] ?? null;
      return recentEvents(tx, this.options.keyring, grant, routine, input);
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
        // Cloud copy: one paste box (parseGrokRoutineDetails) as well as the two fields, a reply mode, and a sender filter.
        const pasted = this.cloudCopy && typeof body.routine_details === "string" && body.routine_details.trim() ? body.routine_details : null;
        const credentials = pasted
          ? (({ webhookUrl, apiKey }) => ({ url: webhookUrl, key: apiKey }))(parseGrokRoutineDetails(pasted))
          : parseGrokRoutineCredentials(body.webhook_url, body.authorization);
        const replyMode: ReplyMode = !this.cloudCopy || body.reply_mode === undefined || body.reply_mode === "" ? "notes-only"
          : REPLY_MODES.includes(body.reply_mode as ReplyMode) ? body.reply_mode as ReplyMode
          : (() => { throw new GrokRoutineError("Choose how to reply: notes-only, acknowledge or answer."); })();
        const rawFrom = this.cloudCopy ? (typeof body.from === "string" && body.from.trim() ? body.from.trim() : url.searchParams.get("from")) : null;
        if (rawFrom && !FROM.test(rawFrom)) throw new GrokRoutineError("from must be an Agent Relay agent name.");
        const urlHash = this.cloudCopy ? hashSecret(credentials.url) : null;
        await this.options.database.transaction(async tx => {
          const grant = await this.grant(tx, grantId, owner);
          if (!grant.agent_remote_id) throw new GrokRoutineError("Call join_relay from this bot before saving its routine.");
          if (urlHash && (await tx.query("SELECT 1 FROM grok_bot_routines WHERE routine_url_hash=$1 AND grant_id<>$2", [urlHash, grantId])).rows.length) {
            throw new GrokRoutineError(DUPLICATE_ROUTINE);
          }
          await tx.query(`INSERT INTO grok_bot_routines(grant_id,credentials_ciphertext,next_attempt_at,updated_at,delivery_mode,reply_mode,from_filter,routine_url_hash)
            VALUES ($1,$2,$3,$3,'webhook',$4,$5,$6) ON CONFLICT (grant_id) DO UPDATE SET credentials_ciphertext=$2,
            next_attempt_at=$3,updated_at=$3,failures=0,last_error=NULL,last_delivered_at=NULL,notified_delivery_ids='{}',
            delivery_mode='webhook',reply_mode=$4,from_filter=$5,routine_url_hash=$6,polling_since=NULL`,
          [grantId, encryptSecret(JSON.stringify(credentials), this.options.keyring.active), this.now(), replyMode, rawFrom ?? null, urlHash]);
        });
        return json({ configured: true, message: "Saved. Send this bot a Relay message to verify delivery in Grok." });
      }
      if (request.method === "DELETE") return json(await this.disconnect(grantId, owner));
      if (request.method !== "GET") return json({ error: "method_not_allowed" }, 405);
      const state = await this.status(grantId, owner) as Awaited<ReturnType<GrokRoutines["status"]>> & { reply_mode?: ReplyMode };
      const nonce = randomBytes(18).toString("base64url");
      const html = page("Grok Bot wake-ups", `<h1>Wake up ${escape(state.agent)}</h1>
<p>Create a Grok Bot routine named <strong>Agent Relay inbox</strong> with <strong>When a webhook fires</strong>. Use these instructions:</p>
<blockquote>${escape(state.routine_prompt)}</blockquote>
<p>Copy the routine's <strong>POST to</strong> URL and <strong>Authorization</strong> header into this page. Keep the key out of chat.</p>
<form id="routine">${this.cloudCopy ? `<p><label>Paste the routine's webhook details (URL and Authorization header) <textarea name="routine_details" rows="3" autocomplete="off" spellcheck="false"></textarea></label></p>
<p>Or enter them separately:</p>` : ""}<p><label>Webhook URL <input name="webhook_url" type="text" inputmode="url"${this.cloudCopy ? "" : " required"} autocomplete="off"></label></p>
<p><label>Authorization header <input name="authorization" type="password"${this.cloudCopy ? "" : " required"} autocomplete="off"></label></p>${this.cloudCopy ? `
<p><label>How to reply <select name="reply_mode"><option value="notes-only"${state.reply_mode === "notes-only" ? " selected" : ""}>Notes only: never reply, just tell me</option><option value="acknowledge"${state.reply_mode === "acknowledge" ? " selected" : ""}>Acknowledge my own agents</option><option value="answer"${state.reply_mode === "answer" ? " selected" : ""}>Answer my own agents</option></select></label></p>
<p>Automatic replies go only to agents you own. Register this routine in one place: a routine saved here and in another Agent Relay deployment wakes twice.</p>` : ""}
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
       JOIN mcp_oauth_grants g ON g.id=r.grant_id WHERE r.next_attempt_at<=$1
         AND (r.credentials_ciphertext IS NOT NULL OR r.delivery_mode='polling') ORDER BY r.next_attempt_at LIMIT 20`, [this.now()]);
    const acknowledgements: Array<{ token: string; ids: string[] }> = [];
    for (const candidate of candidates.rows) {
      if (signal?.aborted) break;
      await this.options.database.transaction(async tx => {
        let grant: Grant;
        try { grant = await this.grant(tx, candidate.grant_id, {
          userId: candidate.user_id, organizationId: candidate.organization_id, workspaceId: candidate.workspace_id,
        }); } catch (error) {
          if (!(error instanceof GrokRoutineError)) throw error;
          await tx.query("DELETE FROM grok_bot_routines WHERE grant_id=$1", [candidate.grant_id]);
          return;
        }
        const routine = (await tx.query<Routine>("SELECT * FROM grok_bot_routines WHERE grant_id=$1 AND next_attempt_at<=$2 FOR UPDATE",
          [grant.id, this.now()])).rows[0];
        if (!routine) return;
        try {
          // One budget bounds all remote reads, response bodies and the wake
          // while the revocation fence is held. stop() aborts the same requests.
          const deadline = AbortSignal.timeout(this.options.requestTimeoutMs ?? 5_000);
          const requestSignal = signal ? AbortSignal.any([signal, deadline]) : deadline;
          const participant = (await tx.query<{ token_ciphertext: string; relaycast_workspace_id: string }>(`SELECT p.token_ciphertext,p.relaycast_workspace_id
            FROM hosted_relay_participants p JOIN workspaces w ON w.id=p.workspace_id AND w.organization_id=$4
            WHERE p.workspace_id=$1 AND p.user_id=$2 AND p.agent_remote_id=$3
              AND p.relaycast_workspace_id=w.relaycast_workspace_id`,
          [candidate.workspace_id, candidate.user_id, grant.agent_remote_id, candidate.organization_id])).rows[0];
          if (!participant) throw new Error("identity_unavailable");
          const token = decryptSecret(participant.token_ciphertext, this.options.keyring);
          const remote = await this.options.client.authenticatedAgent(token, requestSignal);
          if (remote.id !== grant.agent_remote_id || remote.workspaceId !== participant.relaycast_workspace_id || remote.status === "released" ||
              isBindingOwnedIdentity(remote.metadata) ||
              remote.metadata.source !== HOSTED_SOURCE || remote.metadata.owner_hash !== ownerHash(candidate.user_id) ||
              remote.metadata.cloud_workspace_id !== candidate.workspace_id) throw new Error("identity_unavailable");
          if (this.cloudCopy) {
            const ingested = await this.copyScan(tx, { grant, routine, token, remote, workspaceId: candidate.workspace_id,
              userId: candidate.user_id, signal: requestSignal });
            if (ingested.length) acknowledgements.push({ token, ids: ingested });
            return;
          }
          // A polling row saved while the Cloud copy was on has no webhook to wake without it.
          if (!routine.credentials_ciphertext) return;
          const credentialsCiphertext = routine.credentials_ciphertext;
          const inbox = (await this.options.client.readHostedInbox(token, requestSignal)).slice(0, 100).filter(message => message.sender_id !== remote.id);
          const ids = inbox.map(message => message.delivery_id).sort();
          const fresh = ids.filter(id => !routine.notified_delivery_ids.includes(id));
          if (fresh.length) {
            const saved = JSON.parse(decryptSecret(credentialsCiphertext, this.options.keyring));
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
          // Neither provider error bodies nor URLs/keys are ever stored or logged.
          await tx.query(`UPDATE grok_bot_routines SET failures=failures+1,last_error='delivery_unavailable',next_attempt_at=$2,updated_at=$3
            WHERE grant_id=$1`, [grant.id, new Date(this.now().getTime() + Math.min(300_000, 5_000 * 2 ** Math.min(routine.failures + 1, 6))), this.now()]);
        }
      });
    }
    // Cloud copy: acknowledge only deliveries whose events have committed. A
    // failed acknowledgement is retried on the next scan; the event id is
    // stable per delivery, so the re-read inserts nothing new.
    for (const { token, ids } of acknowledgements) {
      for (const id of ids) {
        if (signal?.aborted) return;
        try { await this.options.client.acknowledgeDelivery(token, id); } catch { break; }
      }
    }
  }

  /**
   * Cloud copy, inside the grant fence: ingest this inbox page into the event
   * log, then wake a webhook routine once per new event (Cloud's relay.message /
   * relay.channel_message body and grokRoutineHeaders). Returns the delivery ids
   * to acknowledge after commit. Throws to record a retry with backoff.
   */
  private async copyScan(tx: SqlExecutor, input: { grant: Grant; routine: Routine; token: string;
    remote: { id: string; name: string; channels: Array<{ id: string; name: string }> }; workspaceId: string; userId: string; signal: AbortSignal }): Promise<string[]> {
    const { grant, routine, remote } = input;
    const now = this.now();
    await tx.query("DELETE FROM grok_bot_events WHERE grant_id=$1 AND created_at<$2", [grant.id, new Date(now.getTime() - GROK_EVENT_RETENTION_MS)]);
    const inbox = (await this.options.client.readHostedInbox(input.token, input.signal)).slice(0, 100).filter(message => message.sender_id !== remote.id);
    if (inbox.length) {
      const senders = [...new Set(inbox.flatMap(message => message.sender ? [message.sender] : []))];
      const workspace = (await tx.query<{ relaycast_api_key_ciphertext: string }>(
        "SELECT relaycast_api_key_ciphertext FROM workspaces WHERE id=$1", [input.workspaceId])).rows[0];
      const roster = workspace && senders.length ? await this.options.client.findAgentsByNames(
        decryptSecret(workspace.relaycast_api_key_ciphertext, this.options.keyring), senders, input.signal) : [];
      const channels = new Map(remote.channels.map(row => [row.id, row.name]));
      for (const message of inbox) {
        const sender = roster.find(row => row.name === message.sender && row.id === message.sender_id);
        const event = eventFromDelivery({ grantId: grant.id, agent: remote.name, message, now,
          channel: message.channel_id ? channels.get(message.channel_id) ?? null : null,
          senderKind: sender?.metadata.source === "cloud-person" ? "person" : "agent" });
        await insertEvent(tx, this.options.keyring, grant.id, event,
          senderTrust({ name: message.sender, agentId: message.sender_id }, roster, input.userId));
      }
    }
    let woke = false;
    let failure: unknown = null;
    if (routine.delivery_mode === "webhook" && routine.credentials_ciphertext) {
      const saved = JSON.parse(decryptSecret(routine.credentials_ciphertext, this.options.keyring));
      const credentials = parseGrokRoutineCredentials(saved.url, saved.key);
      for (const row of await pendingWakes(tx, grant.id)) {
        // Cloud's `from` narrows which messages wake the routine; others stay readable through get_recent_events.
        if (!routine.from_filter || row.sender === routine.from_filter) {
          try {
            const response = await (this.options.fetchImpl ?? fetch)(credentials.url, { method: "POST", redirect: "error", signal: input.signal,
              headers: { "content-type": "application/json", ...grokRoutineHeaders(credentials.key, grant.id, row.event_id) },
              body: JSON.stringify(wakeBody(row, this.options.keyring, remote.name)) });
            await response.body?.cancel();
            if (!response.ok) throw new Error("webhook_unavailable");
          } catch (error) { failure = error; break; }
          woke = true;
        }
        await tx.query("UPDATE grok_bot_events SET notified_at=$3 WHERE grant_id=$1 AND event_id=$2", [grant.id, row.event_id, now]);
      }
    } else if (routine.delivery_mode === "polling") {
      // A schedule reads the log itself; nothing is pending a wake.
      await tx.query("UPDATE grok_bot_events SET notified_at=$2 WHERE grant_id=$1 AND notified_at IS NULL", [grant.id, now]);
    }
    if (failure) {
      await tx.query(`UPDATE grok_bot_routines SET failures=failures+1,last_error='delivery_unavailable',next_attempt_at=$2,updated_at=$3
        WHERE grant_id=$1`, [grant.id, new Date(now.getTime() + Math.min(300_000, 5_000 * 2 ** Math.min(routine.failures + 1, 6))), now]);
    } else {
      await tx.query(`UPDATE grok_bot_routines SET failures=0,last_error=NULL,next_attempt_at=$2,updated_at=$3,
        last_delivered_at=CASE WHEN $4 THEN $3 ELSE last_delivered_at END WHERE grant_id=$1`,
      [grant.id, new Date(now.getTime() + 5_000), now, woke]);
    }
    return inbox.map(message => message.delivery_id);
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
