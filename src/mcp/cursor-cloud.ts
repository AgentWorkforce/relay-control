import { createHmac, randomBytes } from "node:crypto";
import { recordAudit } from "../admin/audit.js";
import { hashSecret, type EncryptionKeyring } from "../crypto.js";
import type { Database, SqlExecutor } from "../database.js";
import { escapeHtml, page } from "../identity/pages.js";
import type { McpConsentPrincipal } from "./oauth/consent.js";
import { cursorIdentityAudience, cursorJwks, type CursorIdentity, type CursorJwks } from "./cursor-oidc.js";

/**
 * Cursor cloud agents on the hosted MCP endpoint (docs/cursor-cloud-agents.md).
 *
 * A Cursor cloud agent connects with the person's OAuth grant (added at
 * cursor.com/agents; its connector kind is cursor-cloud). Each cloud agent run
 * can get its own relay participant by proving which run it is with a
 * Cursor-signed OIDC token (./cursor-oidc.ts), once the Cursor account behind
 * it is linked to the grant's user: confirmed by that user in the browser
 * (this page), or automatically for an operator-trusted Cursor team whose
 * token carries the user's own email.
 */

export const CURSOR_LINK_PATH = "/cloud/api/v1/cursor-cloud/link";
const LINK_CODE_TTL_MS = 15 * 60_000;

type Env = Record<string, string | undefined>;
export type CursorCloudConfig = {
  enabled: boolean;
  /**
   * optional: a cursor-cloud grant may still act as its connector's approved
   * agent (a Grok Bot routine does); runs that present a token get their own.
   * required: a cursor-cloud grant acts only as a verified run.
   */
  runIdentity: "optional" | "required";
  /** Cursor team ids whose tokens link a user automatically when the token's email is the user's own. */
  trustedTeams: string[];
  /** Accept tokens from self-hosted Cursor workers (agent_runtime self_hosted). */
  allowSelfHosted: boolean;
};

const ON = new Set(["on", "true", "1"]), OFF = new Set(["off", "false", "0"]);
export function loadCursorCloudConfig(env: Env): CursorCloudConfig {
  const flag = (name: string, fallback: boolean) => {
    const value = env[name]?.trim().toLowerCase();
    if (!value) return fallback;
    if (!ON.has(value) && !OFF.has(value)) throw new Error(`${name} must be on or off`);
    return ON.has(value);
  };
  const mode = env.SELFHOST_CURSOR_CLOUD_RUN_IDENTITY?.trim().toLowerCase() || "optional";
  if (mode !== "optional" && mode !== "required") throw new Error("SELFHOST_CURSOR_CLOUD_RUN_IDENTITY must be optional or required");
  const teams = (env.SELFHOST_CURSOR_CLOUD_TRUSTED_TEAMS ?? "").split(",").map(value => value.trim()).filter(Boolean);
  for (const team of teams) if (!/^[0-9]{1,20}$/.test(team)) throw new Error("SELFHOST_CURSOR_CLOUD_TRUSTED_TEAMS must be comma-separated Cursor team ids");
  return { enabled: flag("SELFHOST_CURSOR_CLOUD", true), runIdentity: mode, trustedTeams: teams,
    allowSelfHosted: flag("SELFHOST_CURSOR_CLOUD_ALLOW_SELF_HOSTED", false) };
}

/** Everything a request needs to verify and link runs; one per process. */
export type CursorCloudDeps = {
  config: CursorCloudConfig;
  audience: string;
  /** Nonce key, derived from the active encryption key. */
  nonceSecret: Uint8Array;
  jwks: CursorJwks;
  links: CursorCloudLinks;
  publicOrigin: string;
};

export function createCursorCloud(input: { config: CursorCloudConfig; publicOrigin: string; keyring: EncryptionKeyring;
  database: Database; fetchImpl?: typeof fetch; jwks?: CursorJwks }): CursorCloudDeps | undefined {
  if (!input.config.enabled) return undefined;
  const origin = new URL(input.publicOrigin).origin;
  return {
    config: input.config, audience: cursorIdentityAudience(origin), publicOrigin: origin,
    nonceSecret: createHmac("sha256", input.keyring.active.key).update("cursor-cloud-nonce:v1").digest(),
    jwks: input.jwks ?? cursorJwks({ fetchImpl: input.fetchImpl }),
    links: new CursorCloudLinks(input.database, origin),
  };
}

type Owner = Pick<McpConsentPrincipal, "userId" | "organizationId" | "workspaceId">;
const json = (value: unknown, status = 200) => Response.json(value, { status, headers: { "cache-control": "no-store" } });

export type LinkDecision = { linked: true } | { linked: false; confirmUrl: string } | { linked: false; conflict: true };

export class CursorCloudLinks {
  constructor(private readonly database: Database, private readonly publicOrigin: string) {}

  /**
   * Whether the token's Cursor account belongs to `owner`. When it is not yet
   * linked: an operator-trusted team with the user's own email links it now;
   * otherwise a fresh one-time code is issued and the user confirms it in the
   * browser. A Cursor account already confirmed for another user in this
   * workspace is a conflict, never a second link.
   */
  async decide(tx: SqlExecutor, owner: Owner & { email: string | null }, identity: CursorIdentity, trustedTeams: readonly string[]): Promise<LinkDecision> {
    const rows = (await tx.query<{ user_id: string; confirmed: boolean }>(
      `SELECT user_id, confirmed_at IS NOT NULL AS confirmed FROM cursor_cloud_links
        WHERE workspace_id = $1 AND cursor_subject = $2 FOR UPDATE`, [owner.workspaceId, identity.subject])).rows;
    if (rows.some(row => row.confirmed && row.user_id === owner.userId)) return { linked: true };
    if (rows.some(row => row.confirmed)) return { linked: false, conflict: true };
    const email = owner.email?.trim().toLowerCase() ?? null;
    if (identity.teamId && trustedTeams.includes(identity.teamId) && email && identity.ownerEmail === email) {
      await tx.query(`INSERT INTO cursor_cloud_links (workspace_id, organization_id, user_id, cursor_subject, method, confirmed_at)
        VALUES ($1, $2, $3, $4, 'trusted_team', now())
        ON CONFLICT (workspace_id, user_id, cursor_subject) DO UPDATE SET method = 'trusted_team', confirmed_at = now(),
          code_hash = NULL, code_expires_at = NULL`,
      [owner.workspaceId, owner.organizationId, owner.userId, identity.subject]);
      await recordAudit(tx, { organizationId: owner.organizationId, workspaceId: owner.workspaceId,
        actor: { kind: "user", userId: owner.userId }, action: "cursor_cloud.link.trusted_team", target: `${identity.subject} team=${identity.teamId}` });
      return { linked: true };
    }
    const code = randomBytes(24).toString("base64url");
    await tx.query(`INSERT INTO cursor_cloud_links (workspace_id, organization_id, user_id, cursor_subject, method, code_hash, code_expires_at)
      VALUES ($1, $2, $3, $4, 'confirmed', $5, now() + ($6::integer * interval '1 millisecond'))
      ON CONFLICT (workspace_id, user_id, cursor_subject) DO UPDATE SET code_hash = $5,
        code_expires_at = now() + ($6::integer * interval '1 millisecond')`,
    [owner.workspaceId, owner.organizationId, owner.userId, identity.subject, hashSecret(code), LINK_CODE_TTL_MS]);
    return { linked: false, confirmUrl: `${this.publicOrigin}${CURSOR_LINK_PATH}?${new URLSearchParams({ code })}` };
  }

  /** The confirmation page; called only behind the OAuth module's browser account and live workspace admission. */
  async handle(request: Request, owner: Owner): Promise<Response> {
    const url = new URL(request.url);
    const code = url.searchParams.get("code") ?? "";
    if (!/^[A-Za-z0-9_-]{32}$/.test(code)) return json({ error: "not_found" }, 404);
    if (request.method !== "GET" && request.headers.get("origin") !== this.publicOrigin) return json({ error: "forbidden" }, 403);
    const pending = async (query: SqlExecutor) => (await query.query<{ cursor_subject: string }>(
      `SELECT cursor_subject FROM cursor_cloud_links
        WHERE code_hash = $1 AND code_expires_at > now() AND confirmed_at IS NULL
          AND workspace_id = $2 AND user_id = $3 AND organization_id = $4`,
      [hashSecret(code), owner.workspaceId, owner.userId, owner.organizationId])).rows[0];
    if (request.method === "POST") {
      const confirmed = await this.database.transaction(async tx => {
        const row = await pending(tx);
        if (!row) return null;
        const taken = await tx.query("SELECT 1 FROM cursor_cloud_links WHERE workspace_id = $1 AND cursor_subject = $2 AND confirmed_at IS NOT NULL",
          [owner.workspaceId, row.cursor_subject]);
        if (taken.rows.length) return "conflict" as const;
        await tx.query(`UPDATE cursor_cloud_links SET confirmed_at = now(), code_hash = NULL, code_expires_at = NULL
          WHERE workspace_id = $1 AND user_id = $2 AND cursor_subject = $3`, [owner.workspaceId, owner.userId, row.cursor_subject]);
        await recordAudit(tx, { organizationId: owner.organizationId, workspaceId: owner.workspaceId,
          actor: { kind: "user", userId: owner.userId }, action: "cursor_cloud.link.confirmed", target: row.cursor_subject });
        return row.cursor_subject;
      });
      if (confirmed === "conflict") return json({ error: "conflict", error_description: "That Cursor account is already linked to another person in this workspace." }, 409);
      if (!confirmed) return json({ error: "not_found", error_description: "This link expired or was used. Ask the Cursor agent to call join_relay again." }, 404);
      return json({ linked: true, message: "Linked. Ask the Cursor agent to call join_relay again." });
    }
    if (request.method !== "GET") return json({ error: "method_not_allowed" }, 405);
    const row = await pending(this.database);
    if (!row) return json({ error: "not_found" }, 404);
    const nonce = randomBytes(18).toString("base64url");
    const html = page("Link a Cursor account", `<h1>Link your Cursor account</h1>
<p>A Cursor cloud agent signed in as <strong>${escapeHtml(row.cursor_subject)}</strong> asked to join Agent Relay as you.</p>
<p>Confirm only if this is your own Cursor account. Its cloud agents can then message as their own relay agents on your behalf.</p>
<div class="actions"><button class="btn" id="confirm" type="button">This is my Cursor account</button></div>
<p id="status" role="status"></p>`,
`const status=document.getElementById('status');document.getElementById('confirm').addEventListener('click',async e=>{e.target.disabled=true;try{const r=await fetch(location.pathname+location.search,{method:'POST'});const d=await r.json();status.textContent=d.message||d.error_description||'Could not link.';}catch{status.textContent='Could not link. Try again.';}});`, "", nonce);
    return new Response(html, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store",
      "referrer-policy": "no-referrer", "x-content-type-options": "nosniff",
      "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'` } });
  }
}
