import { createHmac, hkdfSync, randomBytes, randomUUID } from "node:crypto";
import type { Database, SqlExecutor } from "../database.js";
import { RelaycastCallError, type RelaycastClient } from "../messaging/relaycast.js";
import type { DelegationSigner } from "./jws.js";
import { messageSentAt } from "./relaycast-ids.js";
import { logAuditWriteFailed, logRefused, logRevokeFailed, logUnavailable } from "./observe.js";
import {
  actionIsValid,
  actionsCovered,
  APPROVAL_DEFAULT_MS,
  APPROVAL_MAX_MS,
  ATTESTATION_TTL_SECONDS,
  base62,
  canonicalAction,
  classTargetCovered,
  configTarget,
  isUndelegableSetting,
  CLAIM_TTL_MS,
  DEFAULT_TIER_O_CLASSES,
  GITHUB_CONDITIONS,
  highRisk,
  ownerApprovalSchema,
  ownerDisplay,
  PR_TARGET,
  REPO_TARGET,
  repoPart,
  sameActions,
  sha256Hex,
  tierDApprovalId,
  type Action,
  type ActionClass,
  type Condition,
  type ReasonCode,
  type Scope,
} from "./scope.js";

/**
 * Owner-named trusted delegates: grants, claims, attestation and redeem
 * (relay docs/design/owner-trusted-delegates.md §4–§8, §16.3, §16.4), kept
 * check-for-check with Cloud's lib/delegation (cloud#6501).
 *
 * The security properties, as in Cloud's native-authority resolver:
 * - The sender id comes from Relaycast's by-message delivery proof for the
 *   recipient's own token, never from message text or the caller's body.
 * - The approval is read from Relaycast's stored message, never the copy the
 *   recipient holds.
 * - The recipient is proven by its own Relaycast token and must be bound in
 *   Control to the person whose Desktop session calls.
 * - Every failure, including a dependency outage, is a `none` verdict.
 *   Positive verdicts are never cached; revocation applies to the next call.
 */

export type DelegationPolicy = {
  delegation_enabled: boolean;
  max_expiry_days: number;
  allowed_classes: ActionClass[] | null;
  require_tier_o: ActionClass[];
  code_owner_match: "any_path" | "all_paths";
};

/** Org-wide settings (§16.3 /orgs/{org}/delegation-policy) no workspace policy overrides. */
export type DelegationOrgPolicy = {
  /** §15.9 (Khaliq): days audit quotes are kept before redaction to their hash, 1–3650. */
  quote_retention_days: number;
};

/** §15.9: the default quote retention window. */
export const QUOTE_RETENTION_DAYS = 90;
export const QUOTE_RETENTION_MAX_DAYS = 3650;

export const DEFAULT_POLICY: DelegationPolicy = {
  delegation_enabled: false, max_expiry_days: 90, allowed_classes: null, require_tier_o: [], code_owner_match: "any_path",
};

export async function loadOrgPolicy(executor: SqlExecutor, organizationId: string): Promise<DelegationOrgPolicy> {
  const row = (await executor.query<{ quote_retention_days: number }>(
    "SELECT quote_retention_days FROM delegation_org_policies WHERE organization_id = $1", [organizationId],
  )).rows[0];
  return { quote_retention_days: row?.quote_retention_days ?? QUOTE_RETENTION_DAYS };
}

export type DelegationWorkspace = {
  id: string;
  organizationId: string;
  relaycastWorkspaceId: string;
  relaycastApiKey: string;
};

export type DelegationDeps = {
  database: Database;
  relaycast: RelaycastClient;
  signer: DelegationSigner | null;
  /** Gate-only installs keep relaygate ids for Desktop agents; the feature reports unavailable there. */
  gateOnly: boolean;
  /** Server-held key for quote digests (§8); never exported. */
  quoteKey: Buffer;
  now: () => Date;
};

export type AgentBinding = { userId: string; agentId: string; name: string; address: string | null };

type BindingRow = {
  source: string; user_id: string; agent_id: string; agent_name: string; address: string | null; verified: boolean;
};

export type GrantStatus = "active" | "revoked" | "expired";

export type GrantRow = {
  id: string;
  workspace_id: string;
  organization_id: string;
  owner_user_id: string;
  delegate_agent_id: string;
  delegate_agent_name: string;
  scopes: Scope[];
  require_tier_o: ActionClass[];
  status: GrantStatus;
  expires_at: Date | string;
  created_auth_method: string;
  created_at: Date | string;
  updated_at: Date | string;
  revoked_at: Date | string | null;
  revoked_by: string | null;
  revoked_reason: string | null;
};

type ApprovalRow = {
  id: string;
  workspace_id: string;
  owner_user_id: string;
  tier: "D" | "O";
  grant_id: string | null;
  message_id: string | null;
  actions: Action[];
  single_use: boolean;
  expires_at: Date | string;
  invalidated_at: Date | string | null;
  /** Set once every single-use action has been consumed (markSpentIfComplete). */
  consumed_at: Date | string | null;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const time = (value: Date | string) => (value instanceof Date ? value : new Date(value)).getTime();
const iso = (value: Date | string | null) => value === null ? null : new Date(value).toISOString();

/** The grant as the API shows it (Cloud's grantJson). Expiry is reported even before the row is marked. */
export function grantView(row: GrantRow, now = new Date()) {
  const status: GrantStatus = row.status === "active" && time(row.expires_at) <= now.getTime() ? "expired" : row.status;
  return {
    grant_id: row.id,
    owner_id: row.owner_user_id,
    delegate_agent_id: row.delegate_agent_id,
    scopes: row.scopes,
    require_tier_o: row.require_tier_o,
    expires_at: iso(row.expires_at),
    status,
    created_at: iso(row.created_at),
    updated_at: iso(row.updated_at),
    revoked_at: iso(row.revoked_at),
    revoked_reason: row.revoked_reason,
  };
}

/** A fresh opaque id with a type prefix (`grt_`, `apv_`, `clm_`), as Cloud's mintId. */
export function mintId(prefix: "grt" | "apv" | "clm"): string {
  return `${prefix}_${base62(randomBytes(16))}`;
}

/** A one-time claim code, as Cloud: `dlg_` + 24 random bytes, base64url. Only its SHA-256 is stored. */
export function newClaimCode(): string {
  return `dlg_${randomBytes(24).toString("base64url")}`;
}

/**
 * The workspace policy. `lock` (inside a transaction) share-locks the policy
 * row, so a policy PUT (which locks it FOR UPDATE) serializes with whatever
 * the transaction commits. A missing row is the default, disabled policy.
 */
export async function loadPolicy(executor: SqlExecutor, workspaceId: string, lock = false): Promise<DelegationPolicy> {
  const row = (await executor.query<{
    delegation_enabled: boolean; max_expiry_days: number; allowed_classes: ActionClass[] | null;
    require_tier_o: ActionClass[]; code_owner_match: "any_path" | "all_paths";
  }>(
    `SELECT delegation_enabled, max_expiry_days, allowed_classes, require_tier_o, code_owner_match
       FROM delegation_policies WHERE workspace_id = $1${lock ? " FOR SHARE" : ""}`,
    [workspaceId],
  )).rows[0];
  if (!row) return { ...DEFAULT_POLICY };
  return {
    delegation_enabled: row.delegation_enabled,
    max_expiry_days: row.max_expiry_days,
    allowed_classes: row.allowed_classes,
    require_tier_o: row.require_tier_o,
    code_owner_match: row.code_owner_match === "all_paths" ? "all_paths" : "any_path",
  };
}

/** Whether a grant still fits the workspace policy (§4.1: re-checked at every use), as Cloud. */
export function grantFitsPolicy(grant: Pick<GrantRow, "scopes" | "expires_at" | "created_at">, policy: DelegationPolicy): boolean {
  if (policy.allowed_classes && grant.scopes.some(scope => !policy.allowed_classes!.includes(scope.class))) return false;
  return time(grant.expires_at) - time(grant.created_at) <= policy.max_expiry_days * 86_400_000 + 60_000;
}

/**
 * The person an agent id is bound to in Control, using Cloud's uniqueness
 * rule (#4987): exactly one binding across Desktop identities, hosted
 * participants, Control spawns (any state counts toward ambiguity; only
 * `ready` binds), completed delegate claims and, with `includePerson`, the
 * person's own messaging identity. Any duplicate is no binding at all.
 */
export async function resolveBinding(executor: SqlExecutor, workspaceId: string, relaycastWorkspaceId: string,
  agentId: string, includePerson: boolean): Promise<AgentBinding | null> {
  const rows = (await executor.query<BindingRow>(
    `SELECT 'desktop'::text AS source, user_id::text, agent_remote_id AS agent_id, agent_name, address, true AS verified
       FROM desktop_relay_identities
      WHERE workspace_id = $1 AND relaycast_workspace_id = $2 AND agent_remote_id = $3
     UNION ALL
     SELECT 'hosted'::text, user_id::text, agent_remote_id, agent_name, NULL::text, true
       FROM hosted_relay_participants
      WHERE workspace_id = $1 AND relaycast_workspace_id = $2 AND agent_remote_id = $3
     UNION ALL
     SELECT 'spawn'::text, user_id::text, worker_id, agent_name, worker_address, state = 'ready'
       FROM relay_spawns
      WHERE workspace_id = $1 AND relaycast_workspace_id = $2 AND worker_id = $3
     UNION ALL
     SELECT 'claim'::text, user_id::text, agent_id, agent_name, NULL::text, true
       FROM delegation_agent_bindings
      WHERE workspace_id = $1 AND relaycast_workspace_id = $2 AND agent_id = $3
     UNION ALL
     SELECT 'person'::text, user_id::text, agent_remote_id, agent_name, NULL::text, true
       FROM person_identities
      WHERE $4::boolean AND workspace_id = $1 AND relaycast_workspace_id = $2 AND agent_remote_id = $3
     LIMIT 3`,
    [workspaceId, relaycastWorkspaceId, agentId, includePerson],
  )).rows;
  if (rows.length !== 1) return null;
  const row = rows[0]!;
  if (!row.verified) return null;
  return { userId: row.user_id, agentId: row.agent_id, name: row.agent_name, address: row.address };
}

/** Whether any Control binding (of anyone) names this agent id. */
export async function anyBinding(executor: SqlExecutor, workspaceId: string, relaycastWorkspaceId: string,
  agentId: string): Promise<boolean> {
  const rows = (await executor.query(
    `SELECT 1 FROM desktop_relay_identities WHERE relaycast_workspace_id = $2 AND agent_remote_id = $3
     UNION ALL SELECT 1 FROM hosted_relay_participants WHERE relaycast_workspace_id = $2 AND agent_remote_id = $3
     UNION ALL SELECT 1 FROM relay_spawns WHERE workspace_id = $1 AND relaycast_workspace_id = $2 AND worker_id = $3
     UNION ALL SELECT 1 FROM delegation_agent_bindings WHERE relaycast_workspace_id = $2 AND agent_id = $3
     UNION ALL SELECT 1 FROM person_identities WHERE relaycast_workspace_id = $2 AND agent_remote_id = $3
     LIMIT 1`,
    [workspaceId, relaycastWorkspaceId, agentId],
  )).rows;
  return rows.length > 0;
}

/** The person's live role in the workspace's organization, or null when they are not a member. */
export async function memberRole(executor: SqlExecutor, workspaceId: string, userId: string,
  lock = false): Promise<string | null> {
  if (!UUID.test(userId)) return null;
  // `lock` (inside a transaction) share-locks the membership row, so a
  // concurrent removal serializes with what the transaction commits.
  const row = (await executor.query<{ role: string }>(
    `SELECT m.role FROM workspaces w
       JOIN organization_memberships m ON m.organization_id = w.organization_id AND m.user_id = $2
       JOIN organizations o ON o.id = w.organization_id
      WHERE w.id = $1${lock ? " FOR SHARE OF m" : ""}`,
    [workspaceId, userId],
  )).rows[0];
  return row?.role ?? null;
}

export type AuditInput = {
  workspaceId: string;
  event: string;
  actorUserId?: string | null;
  actorAgentId?: string | null;
  authMethod?: string | null;
  ownerUserId?: string | null;
  grantId?: string | null;
  approvalId?: string | null;
  messageId?: string | null;
  recipientAgentId?: string | null;
  reason?: string | null;
  data?: Record<string, unknown>;
  quote?: string | null;
  /** The quote's keyed digest (quoteDigest); required with a quote. */
  quoteHash?: string | null;
  /**
   * The message's quote was already redacted (§15.9): the row keeps the
   * digest, stores no quote text and is marked redacted from the start.
   */
  quoteRedacted?: boolean;
};

/**
 * §8: a quote's digest is an HMAC-SHA256 under a per-workspace key derived
 * (HKDF-SHA256) from the server-held quote secret, never a plain hash, so a
 * reader of the log cannot test guessed quotes against it. Same derivation and
 * `hmac-sha256:v1:<64 hex>` form as Cloud. The version names the key
 * derivation: rotating the secret needs a new version (keep v1's secret to
 * check older digests), or every stored digest stops matching.
 */
export const QUOTE_DIGEST_VERSION = "v1";

export function quoteDigest(quoteKey: Buffer, workspaceId: string, quote: string): string {
  const workspaceKey = Buffer.from(hkdfSync("sha256", quoteKey, "relay-delegation-quote-digest-v1", `workspace:${workspaceId}`, 32));
  return `hmac-sha256:${QUOTE_DIGEST_VERSION}:${createHmac("sha256", workspaceKey).update(quote, "utf8").digest("hex")}`;
}

/**
 * Serializes every quote write and redaction of one message, as Cloud's
 * lockMessageQuote: a transaction-scoped advisory lock on (workspace,
 * message), then whether a redaction was ever requested for it (queued or
 * done). Redaction takes the same lock before nulling quotes, so a quote write
 * either commits first (and is nulled by the redaction) or sees the
 * redaction and stores no quote. Call inside a transaction.
 */
export async function lockMessageQuote(tx: SqlExecutor, workspaceId: string, messageId: string): Promise<boolean> {
  await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`delegation-quote:${workspaceId}:${messageId}`]);
  return (await tx.query(
    "SELECT 1 FROM delegation_quote_redactions WHERE workspace_id = $1 AND message_id = $2 LIMIT 1",
    [workspaceId, messageId],
  )).rows.length > 0;
}

/**
 * Appends one audit event. A quote about a message whose quote was redacted
 * (a Relaycast redaction is queued or done) is never stored again: the row
 * keeps only its keyed digest, marked redacted. A caller writing a quote passes
 * `quoteRedacted` from lockMessageQuote in its own transaction; otherwise the
 * lock is taken on `executor`.
 */
export async function recordDelegationAudit(executor: SqlExecutor, input: AuditInput): Promise<void> {
  if (input.quote && input.messageId && input.quoteRedacted === undefined) {
    input = { ...input, quoteRedacted: await lockMessageQuote(executor, input.workspaceId, input.messageId) };
  }
  await executor.query(
    `INSERT INTO delegation_audit_events
       (workspace_id, event, actor_user_id, actor_agent_id, auth_method, owner_user_id, grant_id,
        approval_id, message_id, recipient_agent_id, reason, data, quote, quote_hash, quote_redacted_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::jsonb, $13, $14,
             CASE WHEN $15::boolean THEN now() END)`,
    [
      input.workspaceId, input.event,
      input.actorUserId && UUID.test(input.actorUserId) ? input.actorUserId : null,
      input.actorAgentId ?? null, input.authMethod ?? null,
      input.ownerUserId && UUID.test(input.ownerUserId) ? input.ownerUserId : null,
      input.grantId ?? null, input.approvalId ?? null, input.messageId ?? null, input.recipientAgentId ?? null,
      input.reason ?? null, JSON.stringify(input.data ?? {}),
      input.quoteRedacted ? null : input.quote ?? null, input.quote ? input.quoteHash ?? null : null,
      Boolean(input.quote && input.quoteRedacted),
    ],
  );
}

/** The audit event as the API shows it (Cloud's listAudit row). */
export function auditView(row: Record<string, unknown>) {
  const at = (value: unknown) => value === null || value === undefined ? null : new Date(value as string).toISOString();
  return {
    id: String(row.id), event: row.event, created_at: at(row.created_at), actor_user_id: row.actor_user_id,
    actor_agent_id: row.actor_agent_id, auth_method: row.auth_method, owner_id: row.owner_user_id, grant_id: row.grant_id,
    approval_id: row.approval_id, message_id: row.message_id, recipient_agent_id: row.recipient_agent_id,
    reason: row.reason, data: row.data, quote: row.quote, quote_hash: row.quote_hash,
    quote_redacted_at: at(row.quote_redacted_at),
  };
}

/**
 * §15.9 retention, as Cloud's sweep: each quote older than its org's
 * `quote_retention_days` (90 without an org policy row) is redacted to its
 * digest, and its message is queued for redaction in Relaycast. A shorter
 * window applies to existing quotes at the next sweep; a longer one cannot
 * restore a quote already redacted.
 *
 * Redaction is per message: a row still quoting a message whose redaction
 * was requested (by its owner or by retention) is redacted too, which covers
 * a write that committed concurrently with the request. Redacting and queueing
 * the Relaycast redaction are one statement, so a crash cannot redact a quote
 * here and lose its Relaycast redaction. Runs in the hourly sweep and on every
 * audit read.
 */
export async function redactExpiredQuotes(executor: SqlExecutor, limit?: number): Promise<number> {
  return Number((await executor.query<{ count: number }>(
    `WITH due AS (
       -- As Cloud: each workspace's cutoff is computed once, then its due
       -- quotes are read as one (workspace_id, created_at) index range, so the
       -- cost follows the due rows, not every quote an org with a long window
       -- keeps. The batch is the oldest due quotes across every workspace
       -- (cloud#6501 9d70f481b), so one workspace's backlog cannot take the
       -- whole budget on every run while others' quotes stay past due.
       (SELECT d.id FROM workspaces w
          LEFT JOIN delegation_org_policies p ON p.organization_id = w.organization_id
          CROSS JOIN LATERAL (
            SELECT e.id, e.created_at FROM delegation_audit_events e
             WHERE e.workspace_id = w.id AND e.quote IS NOT NULL
               AND e.created_at <= now() - make_interval(days => COALESCE(p.quote_retention_days, $1))
             ORDER BY e.created_at, e.id LIMIT $2) d
         ORDER BY d.created_at, d.id LIMIT $2)
       UNION
       -- Any row still quoting a message whose redaction was requested
       -- (relay-control also catches a write that raced the request).
       (SELECT e.id FROM delegation_quote_redactions q
          JOIN delegation_audit_events e ON e.workspace_id = q.workspace_id AND e.message_id = q.message_id
         WHERE e.quote IS NOT NULL
         LIMIT $2)),
     -- Rows another transaction holds (an owner's redaction of the same
     -- message, say) are skipped, never waited on: one conflict never aborts
     -- or stalls the batch, and the skipped row is due again next sweep.
     locked AS (
       SELECT e.id FROM delegation_audit_events e
        WHERE e.id IN (SELECT id FROM due) AND e.quote IS NOT NULL
        FOR UPDATE SKIP LOCKED),
     redacted AS (
       UPDATE delegation_audit_events AS e SET quote = NULL, quote_redacted_at = now()
        WHERE e.id IN (SELECT id FROM locked) AND e.quote IS NOT NULL
        RETURNING e.workspace_id, e.message_id),
     queued AS (
       INSERT INTO delegation_quote_redactions (workspace_id, message_id)
       SELECT DISTINCT workspace_id, message_id FROM redacted WHERE message_id IS NOT NULL
       ON CONFLICT DO NOTHING)
     SELECT count(*)::int AS count FROM redacted`,
    [QUOTE_RETENTION_DAYS, limit ?? null],
  )).rows[0]?.count ?? 0);
}

/** Hours after which an unfinished Relaycast redaction needs an operator (docs/delegation-quote-redaction-runbook.md). */
export const REDACTION_STALE_HOURS = 24;

/**
 * The Relaycast redaction queue for operators, as Cloud's
 * relaycastRedactionBacklog: unfinished (not yet confirmed, any state),
 * rejected (parked for an operator), stale (unfinished and requested more
 * than REDACTION_STALE_HOURS ago) and the oldest unfinished request's age in
 * seconds (null when none).
 */
export async function relaycastRedactionBacklog(executor: SqlExecutor): Promise<{ unfinished: number; rejected: number;
  stale: number; oldestAgeSeconds: number | null }> {
  const row = (await executor.query<{ unfinished: number; rejected: number; stale: number; oldest: number | null }>(
    `SELECT count(*)::int AS unfinished,
            (count(*) FILTER (WHERE relaycast_outcome = 'rejected'))::int AS rejected,
            (count(*) FILTER (WHERE requested_at <= now() - make_interval(hours => $1)))::int AS stale,
            floor(extract(epoch FROM now() - min(requested_at)))::int AS oldest
       FROM delegation_quote_redactions WHERE relaycast_redacted_at IS NULL`,
    [REDACTION_STALE_HOURS],
  )).rows[0];
  return { unfinished: Number(row?.unfinished ?? 0), rejected: Number(row?.rejected ?? 0), stale: Number(row?.stale ?? 0),
    oldestAgeSeconds: row?.oldest === null || row?.oldest === undefined ? null : Math.max(0, Number(row.oldest)) };
}

/** `after_id` names no event of this workspace (400 invalid_request, as Cloud). */
export class AuditCursorError extends Error {
  constructor() {
    super("after_id must be an event id");
  }
}

/** One page of the audit log (Cloud's AuditPage). */
export type AuditPage = {
  events: Record<string, unknown>[];
  /** The cursor to page from (`after_id`): every event at or before it is final. Null when there is none yet. */
  nextAfterId: string | null;
  /** True when nothing more is listable right now: the page is not full and no committed event was held back. */
  complete: boolean;
  /** Events held back by the commit fence on a cursor page (a lower bound). */
  heldBack: number;
};

/**
 * One page of a workspace's audit log, in commit-safe order (xact_id, then
 * id), as Cloud's listAuditPage.
 *
 * A bigserial id is drawn before its transaction commits, so ids do not
 * arrive in commit order. Each event records the id of the transaction that
 * wrote it (`xact_id`). The fence is W, the statement's snapshot xmin
 * (`pg_snapshot_xmin(pg_current_snapshot())`), read in the same statement as
 * the rows: every transaction below W has ended, so the events below W are
 * final, and any event not yet visible has xact_id >= W and sorts after them.
 *
 * - Without `afterId` (the first page) nothing is hidden: every visible event
 *   is listed. `nextAfterId` is the last listed event below W, the cursor that
 *   is safe to page from; events after it may be listed again on the next page.
 * - With `afterId` (an unknown one is AuditCursorError; `0` is the first page)
 *   the page continues after that event's (xact_id, id) and is fenced to
 *   events below W, so paging never skips an event whose transaction committed
 *   late. Events held back by the fence are counted in `heldBack` and make
 *   `complete` false; they appear once older transactions end.
 */
export async function listAuditPage(executor: SqlExecutor, input: {
  workspaceId: string; all: boolean; viewerUserId: string; since: string | null; grantId: string | null;
  limit: number; afterId: string | null;
}): Promise<AuditPage> {
  const paged = Boolean(input.afterId && input.afterId !== "0");
  let cursor: { xact_id: string; id: string } | null = null;
  if (paged) {
    // The cursor must be an event this viewer can list, so a cursor lookup
    // reveals nothing about events outside the viewer's view (as Cloud).
    const row = (await executor.query<{ xact_id: string }>(
      `SELECT xact_id::text FROM delegation_audit_events
        WHERE workspace_id = $1 AND id = $2::bigint
          AND ($3::boolean OR owner_user_id = $4 OR (actor_user_id = $4 AND owner_user_id IS NULL))`,
      [input.workspaceId, input.afterId, input.all, input.viewerUserId],
    )).rows[0];
    if (!row) throw new AuditCursorError();
    cursor = { xact_id: row.xact_id, id: input.afterId! };
  }
  // One statement, so the rows and the fence come from the same snapshot.
  const rows = (await executor.query<Record<string, unknown> & { xact_text: string; fence: string }>(
    `SELECT *, xact_id::text AS xact_text, pg_snapshot_xmin(pg_current_snapshot())::text AS fence
       FROM delegation_audit_events
      WHERE workspace_id = $1
        -- As Cloud: an owner sees events about their own grants and approvals,
        -- and events they caused that are filed under no owner (a policy
        -- change, a refusal before any grant from the claimed owner exists).
        -- As a recipient's owner they do not see another owner's attestations,
        -- refusals or redeems.
        AND ($2::boolean OR owner_user_id = $3 OR (actor_user_id = $3 AND owner_user_id IS NULL))
        AND ($4::timestamptz IS NULL OR created_at > $4::timestamptz)
        AND ($5::text IS NULL OR grant_id = $5)
        AND ($7::bigint IS NULL OR (xact_id, id) > ($7::bigint, $8::bigint))
      ORDER BY xact_id, id LIMIT $6`,
    [input.workspaceId, input.all, input.viewerUserId, input.since, input.grantId, input.limit,
      cursor?.xact_id ?? null, cursor?.id ?? null],
  )).rows;
  const fence = rows.length ? BigInt(rows[0]!.fence) : null;
  // Ordered by xact_id, so the final (below-fence) events are a prefix.
  const final = fence === null ? rows : rows.filter(row => BigInt(row.xact_text) < fence);
  const listed = paged ? final : rows;
  const lastFinal = final.at(-1);
  return {
    // A quote belongs to its owner: on a row filed under no owner a non-admin
    // viewer gets neither quote nor digest (as Cloud).
    events: listed.map(({ fence: _fence, xact_text: _text, xact_id: _xact, ...row }) =>
      input.all || row.owner_user_id === input.viewerUserId ? row : { ...row, quote: null, quote_hash: null }),
    nextAfterId: lastFinal ? String(lastFinal.id) : paged ? input.afterId : null,
    complete: rows.length < input.limit && final.length === rows.length,
    heldBack: paged ? rows.length - final.length : 0,
  };
}

/**
 * The owner (or, asAdmin, an org owner or admin) redacts the quote of one
 * delegate message (§8, §15.9), as Cloud's redactMessageQuotes: the audit
 * copies become null (their digests stay), the message is queued for
 * redaction in Relaycast, and one `quote.redacted` event is written. Returns
 * how many events were redacted (0: none of the caller's).
 */
export async function redactMessageQuotes(database: Database, input: { workspaceId: string; messageId: string;
  actorUserId: string; authMethod: string; asAdmin: boolean }): Promise<number> {
  return database.transaction(async (tx) => {
    // The same lock every quote write of this message takes (lockMessageQuote).
    await lockMessageQuote(tx, input.workspaceId, input.messageId);
    const rows = (await tx.query<{ workspace_id: string; message_id: string }>(
      `UPDATE delegation_audit_events SET quote = NULL, quote_redacted_at = now()
        WHERE workspace_id = $1 AND message_id = $2 AND quote IS NOT NULL
          -- An owner redacts rows filed under them, and the ownerless rows they
          -- caused (a refusal before any grant from the claimed owner); an
          -- admin redacts any. As Cloud.
          AND ($3::boolean OR owner_user_id = $4 OR (owner_user_id IS NULL AND actor_user_id = $4))
        RETURNING workspace_id, message_id`,
      [input.workspaceId, input.messageId, input.asAdmin, input.actorUserId],
    )).rows;
    if (!rows.length) return 0;
    await tx.query(
      `INSERT INTO delegation_quote_redactions (workspace_id, message_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
      [input.workspaceId, input.messageId],
    );
    await recordDelegationAudit(tx, { workspaceId: input.workspaceId, event: "quote.redacted",
      actorUserId: input.actorUserId, authMethod: input.authMethod,
      ownerUserId: input.asAdmin ? null : input.actorUserId, messageId: input.messageId, data: { events: rows.length } });
    return rows.length;
  });
}

/** How one Relaycast redaction try ended, as Cloud's RelaycastRedactOutcome. */
export type RelaycastRedactOutcome = "redacted" | "absent" | "retry" | "rejected";

/**
 * Asks Relaycast to redact one message's stored owner_approval quote. Null
 * when no Relaycast internal credential is configured: redactions then stay
 * queued.
 */
export type RelaycastQuoteRedactor = ((relaycastWorkspaceId: string, messageId: string) =>
  Promise<{ outcome: RelaycastRedactOutcome; status: number | null }>) | null;

/**
 * Works through the queued Relaycast redactions due a try, oldest first, as
 * Cloud's flushRelaycastRedactions. A retryable failure is never dropped: it
 * waits 2^attempts minutes (at most 6 hours) between tries, with no attempt
 * cap. `redacted` and `absent` finish a request; `rejected` parks it for an
 * operator (clear `relaycast_outcome` to retry it), still counted unfinished.
 */
/** One flush stops starting new Relaycast calls after this long (as Cloud). */
export const FLUSH_BUDGET_MS = 20_000;

export async function flushRelaycastRedactions(database: Database, deps: {
  redact: RelaycastQuoteRedactor;
  budgetMs?: number;
  /**
   * Only this workspace's message (as Cloud): an owner's redact request
   * flushes the row it just queued, never other tenants'. The sweep passes none.
   */
  scope?: { workspaceId: string; messageId: string };
  relaycastBinding: (workspaceId: string) => Promise<{ relaycastWorkspaceId: string } | null>;
}): Promise<{ redacted: number; absent: number; rejected: number; pending: number }> {
  const scope = deps.scope ?? null;
  const unfinished = async () => Number((await database.query<{ count: number }>(
    `SELECT count(*)::int AS count FROM delegation_quote_redactions
      WHERE relaycast_redacted_at IS NULL AND ($1::uuid IS NULL OR (workspace_id = $1 AND message_id = $2))`,
    [scope?.workspaceId ?? null, scope?.messageId ?? null],
  )).rows[0]?.count ?? 0);
  const counts = { redacted: 0, absent: 0, rejected: 0 };
  if (!deps.redact) return { ...counts, pending: await unfinished() };
  const due = (await database.query<{ workspace_id: string; message_id: string }>(
    `SELECT workspace_id, message_id FROM delegation_quote_redactions
      WHERE relaycast_redacted_at IS NULL
        AND relaycast_outcome IS DISTINCT FROM 'rejected'
        AND (last_attempt_at IS NULL OR last_attempt_at <= now() -
             make_interval(mins => least(power(2, least(attempts, 9))::int, 360)))
        AND ($1::uuid IS NULL OR (workspace_id = $1 AND message_id = $2))
      ORDER BY requested_at LIMIT 100`,
    [scope?.workspaceId ?? null, scope?.messageId ?? null],
  )).rows;
  const startedAt = Date.now();
  for (const row of due) {
    // One flush stops starting calls after FLUSH_BUDGET_MS; rows not reached
    // stay due and the next sweep starts with them (as Cloud).
    if (Date.now() - startedAt > (deps.budgetMs ?? FLUSH_BUDGET_MS)) break;
    const binding = await deps.relaycastBinding(row.workspace_id).catch(() => null);
    // A workspace whose Relaycast side cannot be resolved right now is retried.
    const answer = binding ? await deps.redact(binding.relaycastWorkspaceId, row.message_id)
      .catch(() => ({ outcome: "retry" as const, status: null })) : { outcome: "retry" as const, status: null };
    await recordRelaycastRedaction(database, { workspaceId: row.workspace_id, messageId: row.message_id, ...answer });
    if (answer.outcome !== "retry") counts[answer.outcome] += 1;
  }
  return { ...counts, pending: await unfinished() };
}

/**
 * Records one try, as Cloud: `redacted` and `absent` finish the request,
 * `retry` backs it off, `rejected` parks it (still unfinished).
 */
export async function recordRelaycastRedaction(executor: SqlExecutor, input: { workspaceId: string; messageId: string;
  outcome: RelaycastRedactOutcome; status: number | null }): Promise<void> {
  const done = input.outcome === "redacted" || input.outcome === "absent";
  await executor.query(
    done
      ? `UPDATE delegation_quote_redactions SET relaycast_redacted_at = now(), relaycast_outcome = $3, relaycast_status = $4
          WHERE workspace_id = $1 AND message_id = $2`
      : `UPDATE delegation_quote_redactions SET attempts = attempts + 1, last_attempt_at = now(), relaycast_status = $4,
            relaycast_outcome = CASE WHEN $3 = 'rejected' THEN 'rejected' END
          WHERE workspace_id = $1 AND message_id = $2`,
    [input.workspaceId, input.messageId, input.outcome, input.status],
  );
}

/**
 * Revokes grants and invalidates every unredeemed approval under them, in
 * the caller's transaction. Returns the revoked rows (inactive ones are skipped).
 */
/**
 * Whether every single-use action of an approval has been consumed (single
 * use is per action, §5.1: a high-risk action always is, and every action of
 * an approval explicitly marked single use). False when it has none.
 */
async function everySingleUseActionSpent(executor: SqlExecutor,
  approval: Pick<ApprovalRow, "id" | "actions" | "single_use">): Promise<boolean> {
  const singleUse = approval.actions.filter(action => approval.single_use || highRisk(action));
  if (!singleUse.length) return false;
  const spent = new Set((await executor.query<{ class: string; target: string }>(
    "SELECT class, target FROM delegation_action_consumptions WHERE approval_id = $1", [approval.id],
  )).rows.map(row => `${row.class} ${row.target}`));
  return singleUse.every(action => spent.has(`${action.class} ${action.target}`));
}

/** Whether one action of an approval has been consumed. */
export async function actionConsumed(executor: SqlExecutor, approvalId: string,
  action: Pick<Action, "class" | "target">): Promise<boolean> {
  return (await executor.query(
    "SELECT 1 FROM delegation_action_consumptions WHERE approval_id = $1 AND class = $2 AND target = $3",
    [approvalId, action.class, action.target],
  )).rows.length > 0;
}

/**
 * Consumes one action atomically; false when it was already consumed. Stamps
 * the approval's `consumed_at` once every single-use action of it has been
 * consumed (markSpentIfComplete). As Cloud's consumeApproval: given a
 * Database (no caller transaction) it opens its own; either way it locks the
 * approval FOR NO KEY UPDATE first, so consumers of one approval serialize
 * (no lock-upgrade deadlock with the stamp, and the stamp is never missed).
 */
export async function consumeAction(executor: SqlExecutor | Database, input: { approvalId: string; workspaceId: string;
  action: Pick<Action, "class" | "target">; consumedBy: string }): Promise<boolean> {
  if ("transaction" in executor) return executor.transaction(tx => consumeLocked(tx, input));
  return consumeLocked(executor, input);
}

async function consumeLocked(tx: SqlExecutor, input: { approvalId: string; workspaceId: string;
  action: Pick<Action, "class" | "target">; consumedBy: string }): Promise<boolean> {
  // Always FOR NO KEY UPDATE (as Cloud): re-locking in a caller's transaction
  // that already holds it is free, and a weaker lock here could deadlock with
  // the consumed_at stamp.
  const live = (await tx.query(
    `SELECT 1 FROM delegation_approvals WHERE workspace_id = $1 AND id = $2 AND invalidated_at IS NULL FOR NO KEY UPDATE`,
    [input.workspaceId, input.approvalId],
  )).rows.length > 0;
  if (!live) return false;
  const consumed = (await tx.query(
    `INSERT INTO delegation_action_consumptions (approval_id, workspace_id, class, target, consumed_by)
     VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING RETURNING approval_id`,
    [input.approvalId, input.workspaceId, input.action.class, input.action.target, input.consumedBy],
  )).rows.length === 1;
  if (consumed) await markSpentIfComplete(tx, input.approvalId);
  return consumed;
}

/**
 * Stamps `consumed_at` once every single-use action of the approval has been
 * consumed (single use is per action, §5.1), as Cloud. A fully spent approval
 * is then no longer "unredeemed": grant revocation and revoke-all leave it
 * alone.
 */
export async function markSpentIfComplete(executor: SqlExecutor, approvalId: string): Promise<void> {
  const approval = (await executor.query<Pick<ApprovalRow, "actions" | "single_use">>(
    "SELECT actions, single_use FROM delegation_approvals WHERE id = $1 AND consumed_at IS NULL", [approvalId],
  )).rows[0];
  if (!approval) return;
  const singleUse = approval.actions.filter(action => approval.single_use || highRisk(action));
  if (!singleUse.length) return;
  const spent = new Set((await executor.query<{ class: string; target: string }>(
    "SELECT class, target FROM delegation_action_consumptions WHERE approval_id = $1", [approvalId],
  )).rows.map(row => `${row.class} ${row.target}`));
  if (!singleUse.every(action => spent.has(`${action.class} ${action.target}`))) return;
  await executor.query("UPDATE delegation_approvals SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL", [approvalId]);
}

export async function revokeGrants(executor: SqlExecutor, input: {
  workspaceId: string; grantIds: string[]; actorUserId: string | null; reason: string; authMethod: string | null;
}): Promise<GrantRow[]> {
  if (!input.grantIds.length) return [];
  const revoked = (await executor.query<GrantRow>(
    `UPDATE delegation_grants
        SET status = 'revoked', revoked_at = now(), revoked_by = $3, revoked_reason = $4, updated_at = now()
      WHERE workspace_id = $1 AND id = ANY($2::text[]) AND status = 'active'
      RETURNING *`,
    [input.workspaceId, input.grantIds, input.actorUserId, input.reason],
  )).rows;
  if (!revoked.length) return [];
  const ids = revoked.map(row => row.id);
  await executor.query(
    `UPDATE delegation_approvals SET invalidated_at = now()
      WHERE workspace_id = $1 AND invalidated_at IS NULL AND consumed_at IS NULL
        AND (grant_id = ANY($2::text[])
          OR id IN (SELECT approval_id FROM delegation_attestations WHERE grant_id = ANY($2::text[])))`,
    [input.workspaceId, ids],
  );
  for (const row of revoked) {
    await recordDelegationAudit(executor, {
      workspaceId: input.workspaceId, event: "grant.revoked", actorUserId: input.actorUserId,
      authMethod: input.authMethod, ownerUserId: row.owner_user_id, grantId: row.id, reason: input.reason,
      data: { delegate_agent_id: row.delegate_agent_id },
    });
  }
  return revoked;
}

/**
 * Releases a claim (DELETE /delegates/claims/{id}), as Cloud's releaseClaim:
 * its owner or an org owner/admin cancels a pending code, or ends a completed
 * claim's binding and revokes the owner's active grants to that agent
 * (`delegate_released`). Lock order, as every path that locks both: the
 * grant rows (by id) first, then the claim row, so it cannot deadlock with
 * revocation or another release. Null when the claim is unknown, already
 * released, or not the caller's.
 */
export async function releaseClaim(database: Database, input: { workspaceId: string; claimId: string; actorUserId: string;
  admin: boolean; authMethod: string }): Promise<{ claimId: string; revokedGrants: string[] } | null> {
  return database.transaction(async (tx) => {
    const seen = (await tx.query<{ user_id: string; agent_id: string | null }>(
      "SELECT user_id, agent_id FROM delegation_claims WHERE workspace_id = $1 AND id = $2 AND released_at IS NULL",
      [input.workspaceId, input.claimId],
    )).rows[0];
    if (!seen || (seen.user_id !== input.actorUserId && !input.admin)) return null;
    // Grants first (by id), then the claim.
    const grantIds = seen.agent_id ? (await tx.query<{ id: string }>(
      `SELECT id FROM delegation_grants
        WHERE workspace_id = $1 AND owner_user_id = $2 AND delegate_agent_id = $3 AND status = 'active'
        ORDER BY id FOR UPDATE`,
      [input.workspaceId, seen.user_id, seen.agent_id],
    )).rows.map(row => row.id) : [];
    const claim = (await tx.query<{ id: string; user_id: string; agent_id: string | null; consumed_at: Date | null }>(
      `SELECT id, user_id, agent_id, consumed_at FROM delegation_claims
        WHERE workspace_id = $1 AND id = $2 AND released_at IS NULL FOR UPDATE`,
      [input.workspaceId, input.claimId],
    )).rows[0];
    if (!claim) return null;
    await tx.query("UPDATE delegation_claims SET released_at = now() WHERE id = $1", [claim.id]);
    let revokedGrants: string[] = [];
    if (claim.consumed_at && claim.agent_id) {
      // The binding the claim created ends, and so does any grant through it.
      await tx.query("DELETE FROM delegation_agent_bindings WHERE workspace_id = $1 AND claim_id = $2", [input.workspaceId, claim.id]);
      revokedGrants = (await revokeGrants(tx, { workspaceId: input.workspaceId, grantIds, actorUserId: input.actorUserId,
        reason: "delegate_released", authMethod: input.authMethod })).map(row => row.id);
    }
    await recordDelegationAudit(tx, { workspaceId: input.workspaceId, event: "delegate.released", actorUserId: input.actorUserId,
      authMethod: input.authMethod, ownerUserId: claim.user_id, actorAgentId: claim.agent_id,
      reason: claim.consumed_at ? "delegate_released" : "claim_cancelled",
      data: { claim_id: claim.id, agent_id: claim.agent_id, revoked_grants: revokedGrants } });
    return { claimId: claim.id, revokedGrants };
  });
}

/**
 * The panic button (§7): every active grant of one owner (or, with null, the
 * whole workspace), plus that owner's unredeemed tier O approvals, as Cloud.
 */
export async function revokeAllGrants(executor: SqlExecutor, input: {
  workspaceId: string; ownerUserId: string | null; actorUserId: string | null; reason: string; authMethod: string | null;
}): Promise<string[]> {
  const ids = (await executor.query<{ id: string }>(
    `SELECT id FROM delegation_grants
      WHERE workspace_id = $1 AND status = 'active' AND ($2::uuid IS NULL OR owner_user_id = $2) FOR UPDATE`,
    [input.workspaceId, input.ownerUserId],
  )).rows.map(row => row.id);
  const revoked = await revokeGrants(executor, { workspaceId: input.workspaceId, grantIds: ids,
    actorUserId: input.actorUserId, reason: input.reason, authMethod: input.authMethod });
  const approvals = (await executor.query<{ id: string }>(
    `UPDATE delegation_approvals SET invalidated_at = now()
      WHERE workspace_id = $1 AND invalidated_at IS NULL AND consumed_at IS NULL
        AND ($2::uuid IS NULL OR owner_user_id = $2)
      RETURNING id`,
    [input.workspaceId, input.ownerUserId],
  )).rows;
  // One summary event for the approvals revoked here (tier O ones have no grant event), as Cloud.
  if (approvals.length) {
    await recordDelegationAudit(executor, { workspaceId: input.workspaceId, event: "approval.revoked",
      actorUserId: input.actorUserId, authMethod: input.authMethod, ownerUserId: input.ownerUserId, reason: input.reason,
      data: { scope: "revoke_all", count: approvals.length, approval_ids: approvals.map(row => row.id) } });
  }
  return revoked.map(row => row.id);
}

/** Marks a pair's lapsed active grants `expired` and logs `grant.expired` once for each. */
export async function expireLapsed(executor: SqlExecutor, workspaceId: string, ownerUserId: string,
  delegateAgentId: string): Promise<void> {
  const rows = (await executor.query<GrantRow>(
    `UPDATE delegation_grants SET status = 'expired', updated_at = now()
      WHERE workspace_id = $1 AND owner_user_id = $2 AND delegate_agent_id = $3
        AND status = 'active' AND expires_at <= now()
      RETURNING *`,
    [workspaceId, ownerUserId, delegateAgentId],
  )).rows;
  for (const row of rows) {
    await recordDelegationAudit(executor, { workspaceId, event: "grant.expired", ownerUserId: row.owner_user_id,
      grantId: row.id, actorAgentId: row.delegate_agent_id, reason: "expired" });
  }
}

class Refusal extends Error {
  constructor(readonly reason: ReasonCode) {
    super(reason);
  }
}

class ConditionUnmet extends Error {
  constructor(readonly unmet: Condition[]) {
    super("condition_unmet");
  }
}

const refuse = (reason: ReasonCode): never => {
  throw new Refusal(reason);
};

export type Standing = "own_owner" | "code_owner";
export type AcceptMode = "code_owners" | "own_owner";

export type AttestationClaims = {
  v: 1;
  ws: string;
  owner_id: string;
  owner_display: string;
  delegate_agent_id: string;
  grant_id: string;
  message_id: string;
  recipient_agent_id: string;
  approval_id: string;
  tier: "D" | "O";
  actions: Action[];
  standing: Standing;
  single_use: boolean;
  /** §16.4: the stored quote, or null once redacted (or never given). */
  quote: string | null;
  iat: number;
  exp: number;
  jti: string;
};

export type TargetOwnerEntry = { pattern: string; repo?: string; owner_ids?: string[] };

export async function loadTargetOwners(executor: SqlExecutor, workspaceId: string): Promise<TargetOwnerEntry[]> {
  const rows = (await executor.query<{ pattern: string; repo: string | null; owner_ids: string[] | null }>(
    "SELECT pattern, repo, owner_ids FROM delegation_target_owners WHERE workspace_id = $1 ORDER BY position",
    [workspaceId],
  )).rows;
  return rows.map(row => ({ pattern: row.pattern, ...(row.repo ? { repo: row.repo } : {}),
    ...(row.owner_ids?.length ? { owner_ids: row.owner_ids } : {}) }));
}

/**
 * §5.4 standing of the approval's owner over every action, for a recipient
 * owned by `recipientOwnerId` (Cloud's resolveStanding). The recipient's own
 * owner always has standing. Under `code_owners`, another person must be a
 * code owner of each target:
 *
 * - Repo targets (`owner/repo`, `owner/repo#N`) resolve from CODEOWNERS
 *   through a verified, linked GitHub account. relay-control has no verified
 *   person-to-GitHub link, so they fail closed.
 * - Other targets use the admin target-owners table: an entry whose
 *   `owner_ids` name the person counts; an entry's `repo` needs CODEOWNERS
 *   and confers nothing here; no entry means only the recipient's own owner.
 * - `prompt_approval` never uses code owners.
 */
export function resolveStanding(input: { approvalOwnerId: string; recipientOwnerId: string; accept: AcceptMode;
  actions: readonly Pick<Action, "class" | "target">[]; targetOwners: readonly TargetOwnerEntry[] }): Standing | null {
  if (input.approvalOwnerId === input.recipientOwnerId) return "own_owner";
  if (input.accept !== "code_owners") return null;
  // prompt_approval and config_change belong to the machine owner alone.
  if (input.actions.some(action => action.class === "prompt_approval" || action.class === "config_change")) return null;
  for (const action of input.actions) {
    const repo = repoPart(action);
    if (PR_TARGET.test(repo) || REPO_TARGET.test(repo)) return null;
    const named = input.targetOwners.some(entry => entry.owner_ids?.includes(input.approvalOwnerId)
      && classTargetCovered(action.class, entry.pattern, action.target));
    if (!named) return null;
  }
  return "code_owner";
}

async function standingFor(executor: SqlExecutor, workspaceId: string, input: Omit<Parameters<typeof resolveStanding>[0],
  "targetOwners">): Promise<Standing | null> {
  const needsTable = input.approvalOwnerId !== input.recipientOwnerId && input.accept === "code_owners";
  return resolveStanding({ ...input, targetOwners: needsTable ? await loadTargetOwners(executor, workspaceId) : [] });
}

/** Clock skew tolerated between Relaycast's message times and Control's grant timestamps (as Cloud). */
export const SEND_TIME_SKEW_MS = 2_000;

/** A repeated identical refusal within this window is logged but not written again (as Cloud). */
export const REFUSAL_DEDUP_MS = 10 * 60 * 1000;

/**
 * Whether the same refusal (workspace, message, recipient, reason) was already
 * audited within REFUSAL_DEDUP_MS: a caller retrying one message in a loop
 * writes one `approval.refused` row per window, not one per call.
 */
export async function refusedRecently(executor: SqlExecutor, input: { workspaceId: string; messageId: string;
  recipientAgentId: string; reason: string }): Promise<boolean> {
  return (await executor.query(
    `SELECT 1 FROM delegation_audit_events
      WHERE workspace_id = $1 AND message_id = $2 AND event = 'approval.refused' AND recipient_agent_id = $3
        AND reason = $4 AND created_at > now() - make_interval(secs => $5)
      LIMIT 1`,
    [input.workspaceId, input.messageId, input.recipientAgentId, input.reason, REFUSAL_DEDUP_MS / 1000],
  )).rows.length > 0;
}

/** Whether the same redeem refusal (approval, recipient, action, reason) was audited within REFUSAL_DEDUP_MS (as Cloud). */
export async function redeemRefusedRecently(executor: SqlExecutor, input: { workspaceId: string; approvalId: string;
  recipientAgentId: string; action: { class: string; target: string }; reason: string }): Promise<boolean> {
  return (await executor.query(
    `SELECT 1 FROM delegation_audit_events
      WHERE workspace_id = $1 AND approval_id = $2 AND event = 'redeem.refused' AND recipient_agent_id = $3
        AND reason = $4 AND data->'action'->>'class' = $5 AND data->'action'->>'target' = $6
        AND created_at > now() - make_interval(secs => $7)
      LIMIT 1`,
    [input.workspaceId, input.approvalId, input.recipientAgentId, input.reason, input.action.class, input.action.target,
      REFUSAL_DEDUP_MS / 1000],
  )).rows.length > 0;
}

export type DelegationVerdict =
  | { verdict: "delegate"; attestation: string; claims: AttestationClaims }
  | { verdict: "none"; reason: ReasonCode };

type RecipientInput = {
  workspace: DelegationWorkspace;
  callerUserId: string;
  recipientAgentId: string;
  recipientToken: string;
};

/**
 * #4987 steps 1–3, shared by attest, redeem and prompt-delegates: the caller
 * is a member, the recipient is the caller's own agent, and its own token
 * proves it. A Relaycast refusal of the token is `not_pending`; any other
 * Relaycast failure throws and becomes `unavailable`.
 */
async function proveRecipient(deps: DelegationDeps, input: RecipientInput): Promise<AgentBinding> {
  const { workspace } = input;
  if (!await memberRole(deps.database, workspace.id, input.callerUserId)) refuse("not_pending");
  // No Relaycast call precedes the owner check, so a foreign recipient cannot
  // probe whether a message or agent exists.
  const recipient = await resolveBinding(deps.database, workspace.id, workspace.relaycastWorkspaceId,
    input.recipientAgentId, false);
  if (!recipient || recipient.userId !== input.callerUserId) refuse("not_pending");
  let authenticated;
  try {
    authenticated = await deps.relaycast.authenticatedAgent(input.recipientToken);
  } catch (error) {
    if (error instanceof RelaycastCallError && [401, 403, 404].includes(error.status)) return refuse("not_pending");
    throw error;
  }
  if (authenticated.id !== recipient!.agentId || authenticated.name !== recipient!.name ||
      (recipient!.address && authenticated.address !== recipient!.address) ||
      (authenticated.workspaceId && authenticated.workspaceId !== workspace.relaycastWorkspaceId)) {
    refuse("not_pending");
  }
  return recipient!;
}

/**
 * Re-proves the delegate (Cloud's delegateStillBound): it still has exactly
 * one Control binding, owned by the grant's owner, Relaycast still names the
 * same live agent, and the owner is still a member. A binding now owned by
 * someone else revokes the grant durably (`binding_changed`), as in Cloud.
 * relay-control has no leave-workspace hook and no release webhook, so an
 * owner who left (`owner_left`) or a released agent (`agent_released`) also
 * revokes the grant durably here (§7 automatic revocation); the reason code
 * returned is `revoked` either way, as in Cloud.
 */
async function delegateStillBound(deps: DelegationDeps, workspace: DelegationWorkspace, grant: GrantRow,
  live: boolean): Promise<ReasonCode | null> {
  const revoke = async (reason: string): Promise<ReasonCode> => {
    // A failed write still refuses this use; it is logged.
    await deps.database.transaction(tx => revokeGrants(tx, {
      workspaceId: workspace.id, grantIds: [grant.id], actorUserId: null, reason, authMethod: "system",
    })).catch((error: unknown) => logRevokeFailed("attest", error, { workspaceId: workspace.id, grantId: grant.id, reason }));
    return "revoked";
  };
  const binding = await resolveBinding(deps.database, workspace.id, workspace.relaycastWorkspaceId,
    grant.delegate_agent_id, true);
  if (!binding) return "not_delegate";
  if (binding.userId !== grant.owner_user_id) return revoke("binding_changed");
  if (live) {
    const agent = await deps.relaycast.getRosterAgent(workspace.relaycastApiKey, binding.name);
    if (!agent || agent.id !== binding.agentId || agent.status === "released") return revoke("agent_released");
  }
  if (!await memberRole(deps.database, workspace.id, grant.owner_user_id)) return revoke("owner_left");
  return null;
}

/** The one active, unexpired grant for (owner, delegate), or why there is none (Cloud's liveGrant). */
function liveGrant(grants: GrantRow[], now: Date): GrantRow | ReasonCode {
  const active = grants.find(grant => grant.status === "active");
  if (active) return time(active.expires_at) > now.getTime() ? active : "expired";
  if (!grants.length) return "not_delegate";
  return grants[0]!.status === "expired" ? "expired" : "revoked";
}

async function grantsFor(executor: SqlExecutor, workspaceId: string, ownerUserId: string, delegateAgentId: string) {
  return (await executor.query<GrantRow>(
    `SELECT * FROM delegation_grants
      WHERE workspace_id = $1 AND owner_user_id = $2 AND delegate_agent_id = $3
      ORDER BY created_at DESC LIMIT 20`,
    [workspaceId, ownerUserId, delegateAgentId],
  )).rows;
}

function tierOClasses(policy: DelegationPolicy, grant: GrantRow): Set<ActionClass> {
  return new Set<ActionClass>([...DEFAULT_TIER_O_CLASSES, ...policy.require_tier_o, ...grant.require_tier_o]);
}

/** Why an action list is outside the grant or the policy, or null (Cloud's scopeRefusal). */
function scopeRefusal(actions: readonly Action[], grant: GrantRow, policy: DelegationPolicy,
  recipientAgentId: string): ReasonCode | null {
  if (!grantFitsPolicy(grant, policy)) return "out_of_scope";
  for (const action of actions) {
    if (!actionIsValid(action)) return "out_of_scope";
    if (policy.allowed_classes && !policy.allowed_classes.includes(action.class)) return "out_of_scope";
    if (!actionsCovered(grant.scopes, [action])) return "out_of_scope";
    // A prompt_approval or config_change names exactly the session it
    // applies to: this recipient.
    if ((action.class === "prompt_approval" || action.class === "config_change") &&
        !action.target.startsWith(`${recipientAgentId}:`)) return "out_of_scope";
    // The recipient's own delegation settings are never delegable (§5.3).
    if (action.class === "config_change" && isUndelegableSetting(configTarget(action.target)?.setting ?? "")) {
      return "out_of_scope";
    }
  }
  return null;
}

/** What the final decision reads under locks (Cloud's DecisionState). */
export type DecisionState = { member: boolean; policy: DelegationPolicy; grant: GrantRow | null; approval: ApprovalRow | null };

/**
 * The final re-check's transaction, as Cloud's decideUnderLocks: it share-
 * locks, in this order, the membership rows of `memberUserIds` (sorted), the
 * workspace policy row, the grant row and the approval row (FOR NO KEY
 * UPDATE instead when `consuming`, so consumers of one approval run one at a
 * time), reads them, and
 * runs `decide` on that state in the same transaction. The caller then
 * re-proves its bearer (share-locking the session row) and commits what it
 * decided (the attestation, a consumption) in that transaction. Policy PUT
 * (policy, grants, approvals) and revocation (grants, approvals) take the same
 * rows in the same order, so a change committing meanwhile decides the answer.
 */
export async function decideUnderLocks<T>(database: Database, input: { workspaceId: string; memberUserIds: string[];
  grantId: string | null; approvalId: string; consuming?: boolean },
  decide: (state: DecisionState, tx: SqlExecutor) => Promise<T>): Promise<T> {
  return database.transaction(async (tx) => {
    let member = true;
    for (const userId of [...new Set(input.memberUserIds)].sort()) {
      member = Boolean(await memberRole(tx, input.workspaceId, userId, true));
      if (!member) break;
    }
    const policy = await loadPolicy(tx, input.workspaceId, true);
    const grant = input.grantId ? (await tx.query<GrantRow>(
      "SELECT * FROM delegation_grants WHERE workspace_id = $1 AND id = $2 FOR SHARE", [input.workspaceId, input.grantId],
    )).rows[0] ?? null : null;
    // A consuming call (redeem, gate redeem) takes FOR NO KEY UPDATE, so
    // consumers of one approval serialize: two share holders that each insert
    // a consumption and then stamp consumed_at would deadlock, and each could
    // miss the other's consumption when deciding the approval is spent.
    // Revocation (an UPDATE) conflicts with either mode. As Cloud.
    const approval = (await tx.query<ApprovalRow>(
      `SELECT * FROM delegation_approvals WHERE workspace_id = $1 AND id = $2 ${input.consuming ? "FOR NO KEY UPDATE" : "FOR SHARE"}`,
      [input.workspaceId, input.approvalId],
    )).rows[0] ?? null;
    return decide({ member, policy, grant, approval }, tx);
  });
}

/**
 * The final re-check on state read under locks (Cloud's freshRefusal): the
 * caller's membership, delegation being on, the approval's revocation and
 * expiry, the grant's status and expiry, the actions against the current
 * grant and policy, and (tier D) the current Tier O lists. `policy` is the one
 * standing was resolved under: if its code-owner rule changed, the standing
 * found is stale and the call is refused as `unavailable`, to be retried. A
 * gate redeeming a tier O approval stands on no grant (`noGrant`); a gate
 * names what a departed member means (`memberGone`).
 */
export function freshRefusal(state: DecisionState, input: { actions: readonly Action[]; tier: "D" | "O";
  policy: DelegationPolicy; recipientAgentId: string; nowMs: number; memberGone?: ReasonCode; noGrant?: boolean }):
  ReasonCode | null {
  if (!state.member) return input.memberGone ?? "not_pending";
  if (!state.policy.delegation_enabled) return "not_enabled";
  if (!state.approval || state.approval.invalidated_at) return "revoked";
  if (input.noGrant) {
    if (time(state.approval.expires_at) <= input.nowMs) return "expired";
    if (state.policy.allowed_classes && input.actions.some(action => !state.policy.allowed_classes!.includes(action.class))) {
      return "out_of_scope";
    }
    return state.policy.code_owner_match !== input.policy.code_owner_match ? "unavailable" : null;
  }
  if (!state.grant || state.grant.status === "revoked") return "revoked";
  if (state.grant.status === "expired" || time(state.grant.expires_at) <= input.nowMs) return "expired";
  if (time(state.approval.expires_at) <= input.nowMs) return "expired";
  const outOfScope = scopeRefusal(input.actions, state.grant, state.policy, input.recipientAgentId);
  if (outOfScope) return outOfScope;
  if (input.tier === "D") {
    const required = tierOClasses(state.policy, state.grant);
    if (input.actions.some(action => required.has(action.class))) return "tier_o_required";
  }
  if (state.policy.code_owner_match !== input.policy.code_owner_match) return "unavailable";
  return null;
}

/**
 * POST .../messaging/delegation. The route has already proven a
 * Desktop-verified bearer of a current member of `workspace`;
 * `stillAuthorized` re-proves it after the network lookups.
 */
export async function attestDelegation(deps: DelegationDeps, input: RecipientInput & {
  messageId: string;
  accept: AcceptMode;
  authMethod: string;
  /** Re-proves the caller's bearer; given a transaction, under a share lock on its session row. */
  stillAuthorized?: (executor?: SqlExecutor) => Promise<boolean>;
}): Promise<DelegationVerdict> {
  const { workspace } = input;
  const now = deps.now();
  const context: { ownerUserId?: string; claimedOwnerId?: string; grantId?: string; approvalId?: string; senderId?: string;
    quote?: string | null; proven?: boolean } = {};
  try {
    const policy = await loadPolicy(deps.database, workspace.id);
    if (!policy.delegation_enabled) refuse("not_enabled");
    if (deps.gateOnly || !deps.signer) refuse("unavailable");
    const recipient = await proveRecipient(deps, input);
    context.proven = true;

    // Relaycast proves this exact message is still pending for this token, and
    // is the only source of the sender id and of the stored owner_approval.
    let delivered;
    try {
      delivered = await deps.relaycast.pendingDeliveryForMessage(input.recipientToken, input.messageId);
    } catch (error) {
      if (error instanceof RelaycastCallError && [401, 403, 404].includes(error.status)) return refuse("not_pending");
      throw error;
    }
    const senderId = delivered?.sender_agent_id ?? null;
    if (!delivered || !senderId || delivered.workspace_id !== workspace.relaycastWorkspaceId ||
        delivered.message_id !== input.messageId) refuse("not_pending");
    context.senderId = senderId!;
    if (!delivered!.owner_approval) refuse("no_approval");
    const parsed = ownerApprovalSchema.safeParse(delivered!.owner_approval);
    if (!parsed.success) refuse("no_approval");
    const approval = parsed.data!;
    if (!UUID.test(approval.owner_id)) refuse("not_delegate");
    // Filed under the claimed owner only once a grant from them exists, as
    // Cloud: a sender cannot put refusals into someone else's view by naming them.
    context.claimedOwnerId = approval.owner_id;
    context.quote = approval.quote ?? null;

    const found = liveGrant(await grantsFor(deps.database, workspace.id, approval.owner_id, senderId!), now);
    if (typeof found === "string") return refuse(found);
    const grant = found;
    context.grantId = grant.id;
    context.ownerUserId = approval.owner_id;
    const unbound = await delegateStillBound(deps, workspace, grant, true);
    if (unbound) refuse(unbound);

    // Notes are sender-chosen text; they never reach a signed claim.
    const messageActions = approval.actions.map(action => canonicalAction(action as Action));
    let tier: "D" | "O";
    let actions: Action[];
    let expiresAt: number;
    let singleUse: boolean;
    if (approval.approval_ref) {
      tier = "O";
      context.approvalId = approval.approval_ref;
      const minted = (await deps.database.query<ApprovalRow>(
        "SELECT * FROM delegation_approvals WHERE id = $1 AND workspace_id = $2",
        [approval.approval_ref, workspace.id],
      )).rows[0];
      if (!minted || minted.tier !== "O" || minted.owner_user_id !== approval.owner_id) refuse("no_approval");
      if (minted!.invalidated_at) refuse("revoked");
      // A tier O approval belongs to the grant's owner (§6.2).
      if (minted!.owner_user_id !== grant.owner_user_id) refuse("no_approval");
      if (await everySingleUseActionSpent(deps.database, minted!)) refuse("consumed");
      if (time(minted!.expires_at) <= now.getTime()) refuse("expired");
      if (!sameActions(minted!.actions, messageActions)) refuse("out_of_scope");
      actions = minted!.actions.map(canonicalAction);
      expiresAt = Math.min(time(minted!.expires_at), time(grant.expires_at));
      // The approval-wide flag is the owner's explicit choice only; a
      // high-risk action is single use per action (at redeem), never the
      // whole approval.
      singleUse = minted!.single_use;
    } else {
      tier = "D";
      actions = messageActions;
      context.approvalId = tierDApprovalId(workspace.id, input.messageId);
      // The message's send time decides two things, as Cloud: its approval
      // window, and whether it predates this grant. A message sent before the
      // grant was created (before a revoke and re-grant, or before any grant)
      // was never authorized by it and is refused. With no known send time
      // (Relaycast's created_at, else the time in its snowflake id) it fails
      // closed.
      const sentDate = messageSentAt(input.messageId, delivered!.created_at, now);
      if (!sentDate) return refuse("unavailable");
      // Relaycast's and Control's clocks differ slightly: a message sent within
      // SEND_TIME_SKEW_MS after the grant's creation is not refused for skew.
      if (sentDate.getTime() < time(grant.created_at) - SEND_TIME_SKEW_MS) refuse("predates_grant");
      const sentAt = sentDate.getTime();
      // Cloud's approvalExpiry: the sender's expires_at, default 1 hour after
      // the send, at most 24 hours after it, never past the grant. The first
      // attestation stores it.
      const requested = approval.expires_at ? Date.parse(approval.expires_at) : sentAt + APPROVAL_DEFAULT_MS;
      expiresAt = Math.min(requested, sentAt + APPROVAL_MAX_MS, time(grant.expires_at));
      // A delegate's approval has no approval-wide single use: high-risk
      // actions are single use per action, at redeem.
      singleUse = false;
    }
    if (expiresAt <= now.getTime()) refuse("expired");
    const outOfScope = scopeRefusal(actions, grant, policy, recipient.agentId);
    if (outOfScope) refuse(outOfScope);
    if (tier === "D") {
      const required = tierOClasses(policy, grant);
      if (actions.some(action => required.has(action.class))) refuse("tier_o_required");
    }
    // §5.4: the owner needs standing over every action's target.
    const standing = await standingFor(deps.database, workspace.id, {
      approvalOwnerId: approval.owner_id, recipientOwnerId: input.callerUserId, accept: input.accept, actions,
    });
    if (!standing) return refuse("recipient_policy");
    if (tier === "D") {
      await deps.database.query(
        `INSERT INTO delegation_approvals
           (id, workspace_id, owner_user_id, tier, grant_id, message_id, actions, single_use, expires_at)
         VALUES ($1, $2, $3, 'D', $4, $5, $6::jsonb, $7, $8)
         ON CONFLICT (id) DO NOTHING`,
        [context.approvalId, workspace.id, approval.owner_id, grant.id, input.messageId,
          JSON.stringify(actions), singleUse, new Date(expiresAt)],
      );
      const stored = (await deps.database.query<ApprovalRow>(
        "SELECT * FROM delegation_approvals WHERE id = $1 AND workspace_id = $2",
        [context.approvalId, workspace.id],
      )).rows[0];
      if (!stored) refuse("unavailable");
      if (stored!.invalidated_at || stored!.grant_id !== grant.id) refuse("revoked");
      if (await everySingleUseActionSpent(deps.database, stored!)) refuse("consumed");
      expiresAt = Math.min(expiresAt, time(stored!.expires_at));
      singleUse = stored!.single_use || singleUse;
    }
    // Check again after network calls: a membership or bearer revoked during
    // resolution must not result in a positive verdict.
    if (!await memberRole(deps.database, workspace.id, input.callerUserId) ||
        (input.stillAuthorized && !await input.stillAuthorized())) refuse("not_pending");

    const owner = (await deps.database.query<{ name: string | null }>(
      "SELECT name FROM users WHERE id = $1", [approval.owner_id],
    )).rows[0];
    // The Relaycast lookups take time: the membership, policy, grant and
    // approval are re-checked under locks, and the attestation is recorded in
    // the same transaction, so a change committing meanwhile decides.
    const { attestation, claims } = await decideUnderLocks(deps.database, { workspaceId: workspace.id,
      memberUserIds: [input.callerUserId], grantId: grant.id, approvalId: context.approvalId! }, async (state, tx) => {
      const stale = freshRefusal(state, { actions, tier, policy, recipientAgentId: recipient.agentId,
        nowMs: deps.now().getTime() });
      if (stale) refuse(stale);
      if (input.stillAuthorized && !await input.stillAuthorized(tx)) refuse("not_pending");
      // Standing against the target owners as committed now (relay-control
      // reads them locally, so this costs no external call).
      if (await standingFor(tx, workspace.id, { approvalOwnerId: approval.owner_id, recipientOwnerId: input.callerUserId,
        accept: input.accept, actions }) !== standing) refuse("recipient_policy");
      // A quote the owner redacted (or whose redaction is queued) is never
      // signed or stored again; the row keeps only the digest.
      const quoteRedacted = approval.quote ? await lockMessageQuote(tx, workspace.id, input.messageId) : false;
      const signedAt = deps.now().getTime();
      const iat = Math.floor(signedAt / 1000);
      // Never past the approval's window, nor the grant's or the approval's
      // expiry as read under the locks.
      const until = Math.min(expiresAt, time(state.grant!.expires_at), time(state.approval!.expires_at));
      if (until <= signedAt) refuse("expired");
      const claims: AttestationClaims = {
        v: 1,
        ws: workspace.id,
        owner_id: approval.owner_id,
        owner_display: ownerDisplay(owner?.name),
        delegate_agent_id: senderId!,
        grant_id: grant.id,
        message_id: input.messageId,
        recipient_agent_id: input.recipientAgentId,
        approval_id: context.approvalId!,
        tier,
        actions: actions.map(canonicalAction),
        standing,
        single_use: singleUse,
        quote: quoteRedacted ? null : approval.quote ?? null,
        iat,
        exp: Math.min(iat + ATTESTATION_TTL_SECONDS, Math.floor(until / 1000)),
        jti: randomUUID(),
      };
      if (claims.exp <= iat) refuse("expired");
      await tx.query(
        `INSERT INTO delegation_attestations
           (jti, workspace_id, approval_id, grant_id, message_id, recipient_agent_id, delegate_agent_id, kid, accept,
            standing, issued_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, to_timestamp($11), to_timestamp($12))`,
        [claims.jti, workspace.id, claims.approval_id, grant.id, input.messageId, input.recipientAgentId, senderId,
          deps.signer!.kid, input.accept, standing, iat, claims.exp],
      );
      await recordDelegationAudit(tx, {
        workspaceId: workspace.id, event: "approval.attested", actorUserId: input.callerUserId,
        authMethod: input.authMethod, ownerUserId: approval.owner_id, grantId: grant.id, approvalId: claims.approval_id,
        actorAgentId: senderId, messageId: input.messageId, recipientAgentId: input.recipientAgentId,
        data: { actions: claims.actions, tier, standing, single_use: singleUse, jti: claims.jti, kid: deps.signer!.kid,
          quote_source: approval.quote_source ?? null, quoted_at: approval.quoted_at ?? null },
        quote: approval.quote ?? null,
        quoteHash: approval.quote ? quoteDigest(deps.quoteKey, workspace.id, approval.quote) : null,
        quoteRedacted,
      });
      // Signed last, inside the transaction: a refusal above signs nothing.
      return { attestation: deps.signer!.sign(claims), claims };
    });
    return { verdict: "delegate", attestation, claims };
  } catch (error) {
    // No dependency error can promote a peer message or expose a
    // message-existence oracle. It is logged (class and SQLSTATE only).
    const reason: ReasonCode = error instanceof Refusal ? error.reason : "unavailable";
    if (!(error instanceof Refusal)) {
      logUnavailable("attest", error, { workspaceId: workspace.id, approvalId: context.approvalId ?? null,
        grantId: context.grantId ?? null });
    }
    // A refusal before the caller's recipient is proven (delegation off, no
    // key, a bad token) is logged and counted only: unproven callers never
    // write audit rows. As Cloud.
    // A repeated identical refusal (message, recipient, reason) within the
    // dedup window is logged but not written again, as Cloud.
    const repeated = context.proven && await refusedRecently(deps.database, { workspaceId: workspace.id,
      messageId: input.messageId, recipientAgentId: input.recipientAgentId, reason }).catch(() => false);
    // The refusal row keeps the sender's quote (and its keyed digest) like any
    // other row, as Cloud: it ages out on the org window and is redactable,
    // and its redaction queues the Relaycast copy's removal. The quote write
    // takes the message's quote lock in its own transaction.
    if (context.proven && !repeated) await deps.database.transaction(tx => recordDelegationAudit(tx, {
      workspaceId: workspace.id, event: "approval.refused", actorUserId: input.callerUserId,
      authMethod: input.authMethod, ownerUserId: context.ownerUserId ?? null, grantId: context.grantId ?? null,
      approvalId: context.approvalId ?? null, actorAgentId: context.senderId ?? null,
      messageId: input.messageId, recipientAgentId: input.recipientAgentId, reason,
      data: context.claimedOwnerId && !context.ownerUserId ? { claimed_owner_id: context.claimedOwnerId } : {},
      quote: context.quote ?? null,
      quoteHash: context.quote ? quoteDigest(deps.quoteKey, workspace.id, context.quote) : null,
    })).catch((auditError: unknown) => logAuditWriteFailed("attest", auditError, { workspaceId: workspace.id,
      approvalId: context.approvalId ?? null, grantId: context.grantId ?? null, event: "approval.refused", reason }));
    logRefused("attest", { workspaceId: workspace.id, reason });
    return { verdict: "none", reason };
  }
}

export type RedeemResult =
  | { ok: true; consumed: boolean }
  | { ok: false; reason: ReasonCode; unmet?: Condition[] };

/**
 * §5.5 conditions at redeem. `not_before` is checked here. The GitHub
 * conditions need the PR's state through a GitHub reader relay-control does
 * not have for delegation, so they fail closed with `condition_unavailable`.
 */
export function evaluateConditions(conditions: readonly Condition[], now: Date):
  { kind: "met" } | { kind: "unmet"; unmet: Condition[] } | { kind: "unavailable" } {
  if (!conditions.length) return { kind: "met" };
  if (conditions.some(condition => GITHUB_CONDITIONS.has(condition.type))) return { kind: "unavailable" };
  const unmet = conditions.filter(condition => condition.type === "not_before" && now.getTime() < Date.parse(condition.at));
  return unmet.length ? { kind: "unmet", unmet } : { kind: "met" };
}

/**
 * POST .../messaging/delegation/redeem (Cloud's redeemApproval). Re-checks
 * revocation, binding, membership, policy, scope and standing, then the
 * action's conditions. An unmet condition does not consume; a single-use
 * approval is consumed with one conditional UPDATE, so a replay or a race with
 * a revocation is refused.
 */
export async function redeemApproval(deps: DelegationDeps, input: RecipientInput & {
  approvalId: string;
  action: { class: ActionClass; target: string };
  authMethod: string;
  /** Re-proves the caller's bearer; given a transaction, under a share lock on its session row. */
  stillAuthorized?: (executor?: SqlExecutor) => Promise<boolean>;
}): Promise<RedeemResult> {
  const { workspace } = input;
  const now = deps.now();
  const context: { ownerUserId?: string; grantId?: string; proven?: boolean } = {};
  try {
    const policy = await loadPolicy(deps.database, workspace.id);
    if (!policy.delegation_enabled) refuse("not_enabled");
    if (deps.gateOnly) refuse("unavailable");
    await proveRecipient(deps, input);
    context.proven = true;
    const approval = (await deps.database.query<ApprovalRow>(
      "SELECT * FROM delegation_approvals WHERE id = $1 AND workspace_id = $2",
      [input.approvalId, workspace.id],
    )).rows[0];
    if (!approval) refuse("no_approval");
    // Only a recipient Control attested this approval to may redeem it. The
    // approval's owner is attached to the refusal row only once that holds: a
    // caller the approval was never attested to writes no row under its owner.
    const attested = (await deps.database.query<{ grant_id: string; accept: string }>(
      `SELECT grant_id, accept FROM delegation_attestations
        WHERE workspace_id = $1 AND approval_id = $2 AND recipient_agent_id = $3
        ORDER BY issued_at DESC LIMIT 1`,
      [workspace.id, input.approvalId, input.recipientAgentId],
    )).rows[0];
    if (!attested) refuse("no_approval");
    context.ownerUserId = approval!.owner_user_id;
    context.grantId = attested!.grant_id;
    if (approval!.invalidated_at) refuse("revoked");
    const grant = (await deps.database.query<GrantRow>(
      "SELECT * FROM delegation_grants WHERE id = $1 AND workspace_id = $2", [attested!.grant_id, workspace.id],
    )).rows[0];
    if (!grant || grant.status === "revoked") refuse("revoked");
    if (grant!.status === "expired" || time(grant!.expires_at) <= now.getTime()) refuse("expired");
    const unbound = await delegateStillBound(deps, workspace, grant!, true);
    if (unbound) refuse(unbound);
    if (time(approval!.expires_at) <= now.getTime()) refuse("expired");
    const action = approval!.actions.find(item => item.class === input.action.class && item.target === input.action.target);
    if (!action) refuse("out_of_scope");
    const outOfScope = scopeRefusal([action!], grant!, policy, input.recipientAgentId);
    if (outOfScope) refuse(outOfScope);
    if (approval!.tier === "D" && tierOClasses(policy, grant!).has(action!.class)) refuse("tier_o_required");
    const standingInput = {
      approvalOwnerId: approval!.owner_user_id, recipientOwnerId: input.callerUserId,
      accept: attested!.accept === "own_owner" ? "own_owner" as const : "code_owners" as const, actions: [action!],
    };
    if (!await standingFor(deps.database, workspace.id, standingInput)) refuse("recipient_policy");
    const singleUse = approval!.single_use || highRisk(action!);
    if (singleUse && await actionConsumed(deps.database, approval!.id, action!)) refuse("consumed");
    const conditions = evaluateConditions(action!.conditions ?? [], now);
    if (conditions.kind === "unavailable") refuse("condition_unavailable");
    if (conditions.kind === "unmet") throw new ConditionUnmet(conditions.unmet);
    if (!await memberRole(deps.database, workspace.id, input.callerUserId) ||
        (input.stillAuthorized && !await input.stillAuthorized())) refuse("not_pending");
    // The lookups above take time: the membership, policy, grant and approval
    // are re-checked under locks, and a single-use action is consumed in the
    // same transaction.
    await decideUnderLocks(deps.database, { workspaceId: workspace.id, memberUserIds: [input.callerUserId],
      grantId: grant!.id, approvalId: input.approvalId, consuming: true }, async (state, tx) => {
      const stale = freshRefusal(state, { actions: [action!], tier: approval!.tier, policy,
        recipientAgentId: input.recipientAgentId, nowMs: deps.now().getTime() });
      if (stale) refuse(stale);
      if (input.stillAuthorized && !await input.stillAuthorized(tx)) refuse("not_pending");
      if (!await standingFor(tx, workspace.id, standingInput)) refuse("recipient_policy");
      // Single use is per action (§5.1): one atomic insert per action.
      if (singleUse && !await consumeAction(tx, { approvalId: input.approvalId, workspaceId: workspace.id, action: action!,
        consumedBy: input.recipientAgentId })) refuse("consumed");
      // Every redeem is audited, multi-use ones included (§6.3), in the
      // transaction that consumes: a failed audit write rolls the consumption
      // back and the answer is `unavailable`, so no use goes unrecorded.
      await recordDelegationAudit(tx, {
        workspaceId: workspace.id, event: "approval.redeemed", actorUserId: input.callerUserId,
        authMethod: input.authMethod, ownerUserId: approval!.owner_user_id, grantId: grant!.id,
        approvalId: input.approvalId, recipientAgentId: input.recipientAgentId,
        data: { action: input.action, consumed: singleUse, conditions: action!.conditions ?? [] },
      });
    });
    return { ok: true, consumed: singleUse };
  } catch (error) {
    const reason: ReasonCode = error instanceof ConditionUnmet ? "condition_unmet"
      : error instanceof Refusal ? error.reason : "unavailable";
    const unmet = error instanceof ConditionUnmet ? error.unmet : undefined;
    if (!(error instanceof ConditionUnmet) && !(error instanceof Refusal)) {
      logUnavailable("redeem", error, { workspaceId: workspace.id, approvalId: input.approvalId,
        grantId: context.grantId ?? null });
    }
    // As at attest: only a proven recipient's refusals are written to the audit
    // log, and an identical one (approval, recipient, action, reason) once per
    // 10 minutes (as Cloud); repeats are still logged.
    const repeated = context.proven && await redeemRefusedRecently(deps.database, { workspaceId: workspace.id,
      approvalId: input.approvalId, recipientAgentId: input.recipientAgentId, action: input.action, reason })
      .catch(() => false);
    if (context.proven && !repeated) await recordDelegationAudit(deps.database, {
      workspaceId: workspace.id, event: "redeem.refused", actorUserId: input.callerUserId,
      authMethod: input.authMethod, ownerUserId: context.ownerUserId ?? null, grantId: context.grantId ?? null,
      approvalId: input.approvalId, recipientAgentId: input.recipientAgentId, reason,
      data: { action: input.action, ...(unmet ? { unmet } : {}) },
    }).catch((auditError: unknown) => logAuditWriteFailed("redeem", auditError, { workspaceId: workspace.id,
      approvalId: input.approvalId, grantId: context.grantId ?? null, event: "redeem.refused", reason }));
    logRefused("redeem", { workspaceId: workspace.id, reason });
    return unmet ? { ok: false, reason, unmet } : { ok: false, reason };
  }
}

/**
 * POST .../messaging/delegation/prompt-delegates (§9.3, Cloud's
 * promptDelegates): the machine owner's delegates whose live grants cover
 * `prompt_approval` for this session. Delegation off, or prompt_approval
 * outside the policy, is an empty list. A session that is not the caller's,
 * or a failed token proof, is null (the route answers 403).
 */
export async function promptDelegates(deps: DelegationDeps, input: RecipientInput):
  Promise<{ delegates: Array<{ agent_id: string; grant_id: string }> } | null> {
  const { workspace } = input;
  const policy = await loadPolicy(deps.database, workspace.id);
  if (!policy.delegation_enabled || (policy.allowed_classes && !policy.allowed_classes.includes("prompt_approval"))) {
    return { delegates: [] };
  }
  if (deps.gateOnly) return { delegates: [] };
  let session: AgentBinding;
  try {
    session = await proveRecipient(deps, input);
  } catch (error) {
    if (error instanceof Refusal) return null;
    throw error;
  }
  const grants = (await deps.database.query<GrantRow>(
    `SELECT * FROM delegation_grants
      WHERE workspace_id = $1 AND owner_user_id = $2 AND status = 'active' AND expires_at > now()
      ORDER BY created_at`,
    [workspace.id, session.userId],
  )).rows.filter(grant => grant.scopes.some(scope => scope.class === "prompt_approval"));
  const delegates: Array<{ agent_id: string; grant_id: string }> = [];
  for (const grant of grants) {
    if (!grantFitsPolicy(grant, policy)) continue;
    // Not the session's own agent: a delegate never answers its own prompts.
    if (grant.delegate_agent_id === session.agentId) continue;
    if (!actionsCovered(grant.scopes, [{ class: "prompt_approval", target: `${session.agentId}:probe:approve` }])) continue;
    // A released or re-bound agent is never offered (its grant is revoked, as
    // at attestation). One grant whose binding cannot be read is skipped (and
    // logged), not the whole list, as Cloud.
    const unbound = await delegateStillBound(deps, workspace, grant, true).catch((error: unknown) => {
      logUnavailable("prompt_delegates", error, { workspaceId: workspace.id, grantId: grant.id });
      return "unavailable" as const;
    });
    if (unbound) continue;
    delegates.push({ agent_id: grant.delegate_agent_id, grant_id: grant.id });
  }
  return { delegates };
}

export { CLAIM_TTL_MS };

/**
 * Relaycast's internal quote redaction route (relaycast#710, advertised as
 * `owner_approval.redact_quote`), called with RELAYCAST_INTERNAL_SECRET and no
 * body:
 *
 *   POST {relaycast}/internal/workspaces/{relay workspace id}/messages/{message id}/owner-approval/redact-quote
 *
 * How an answer is treated, as Cloud's redactRelaycastQuote:
 *   2xx (a repeat returns the first redaction)        → redacted, done
 *   404 owner_approval_not_found                      → absent, done
 *   5xx, 429, a network error or timeout, or a 404
 *       without that code (route not deployed yet)    → retry with backoff
 *   any other answer (400, 401, 403, a redirect)      → rejected: not retried,
 *       still counted as unfinished for an operator
 */
export function relaycastQuoteRedactor(input: { relaycastUrl: string; internalSecret: string | null;
  fetchImpl?: typeof fetch }): RelaycastQuoteRedactor {
  const secret = input.internalSecret;
  if (!secret) return null;
  const base = input.relaycastUrl.replace(/\/+$/u, "");
  const fetchImpl = input.fetchImpl ?? globalThis.fetch;
  return async (relaycastWorkspaceId, messageId) => {
    try {
      const response = await fetchImpl(`${base}/internal/workspaces/${encodeURIComponent(relaycastWorkspaceId)}/messages/${
        encodeURIComponent(messageId)}/owner-approval/redact-quote`, {
        method: "POST", headers: { authorization: `Bearer ${secret}` },
        redirect: "manual", signal: AbortSignal.timeout(10_000),
      });
      const status = response.status;
      if (status >= 200 && status < 300) return { outcome: "redacted", status };
      if (status === 404) {
        const body = await response.json().catch(() => null) as { error?: { code?: unknown } } | null;
        return { outcome: body?.error?.code === "owner_approval_not_found" ? "absent" : "retry", status };
      }
      if (status === 429 || status >= 500) return { outcome: "retry", status };
      return { outcome: "rejected", status };
    } catch {
      return { outcome: "retry", status: null };
    }
  };
}
