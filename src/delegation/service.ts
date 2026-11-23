import { createHmac, randomBytes, randomUUID } from "node:crypto";
import type { Database, SqlExecutor } from "../database.js";
import { RelaycastCallError, type RelaycastClient } from "../messaging/relaycast.js";
import type { DelegationSigner } from "./jws.js";
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
  NEVER_DELEGABLE_SETTINGS,
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
 * from the server-held quote key, never a plain hash, so a reader of the log
 * cannot test guessed quotes against it. The key never leaves the server.
 */
export function quoteDigest(quoteKey: Buffer, workspaceId: string, quote: string): string {
  const workspaceKey = createHmac("sha256", quoteKey).update(`relay-delegation-quote:${workspaceId}`).digest();
  return createHmac("sha256", workspaceKey).update(quote, "utf8").digest("hex");
}

export async function recordDelegationAudit(executor: SqlExecutor, input: AuditInput): Promise<void> {
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
 * `quote_retention_days` (90 without an org policy row) is redacted to its hash.
 * A shorter window applies to existing quotes at the next sweep; a longer one
 * cannot restore a quote already redacted.
 *
 * Redaction is per message: once any row's quote for a message is redacted,
 * every other row quoting that message is redacted too. Attestation already
 * refuses to store a redacted message's quote; this second rule catches an
 * attestation that committed concurrently with the redaction. Runs in the
 * hourly sweep, on every attestation and on every audit read, as one
 * statement, so a crash cannot leave half of it applied.
 */
export async function redactExpiredQuotes(executor: SqlExecutor): Promise<void> {
  await executor.query(
    `UPDATE delegation_audit_events AS e SET quote = NULL, quote_redacted_at = now()
      WHERE e.quote IS NOT NULL
        AND (e.created_at <= now() - make_interval(days => COALESCE(
              (SELECT p.quote_retention_days FROM delegation_org_policies p
                 JOIN workspaces w ON w.organization_id = p.organization_id
                WHERE w.id = e.workspace_id), $1))
          OR (e.message_id IS NOT NULL AND EXISTS (
              SELECT 1 FROM delegation_audit_events r
               WHERE r.workspace_id = e.workspace_id AND r.message_id = e.message_id
                 AND r.quote_redacted_at IS NOT NULL)))`,
    [QUOTE_RETENTION_DAYS],
  );
}

/** Whether any audit row's quote for this message has been redacted (§15.9). */
export async function messageQuoteRedacted(executor: SqlExecutor, workspaceId: string, messageId: string): Promise<boolean> {
  return (await executor.query(
    `SELECT 1 FROM delegation_audit_events
      WHERE workspace_id = $1 AND message_id = $2 AND quote_redacted_at IS NOT NULL LIMIT 1`,
    [workspaceId, messageId],
  )).rows.length > 0;
}

/**
 * The audit log's commit-safe watermark. Event ids come from a sequence when
 * a row is inserted, but rows become visible when their transaction commits,
 * so a reader can see id N+1 before id N. Every row a transaction still in
 * flight has written, or is writing, has `created_at` (clock_timestamp() at
 * insert) at or after that transaction's start, or (before it has a
 * transaction id) its current statement's start. The watermark is the
 * earliest of those across the database's other backends, capped at now: no
 * row with `created_at` before it can still appear.
 *
 * It is read in its own statement, before the page's snapshot, so a
 * transaction that commits between the two is visible to the page. Only
 * Control's own database role writes this log, and pg_stat_activity shows a
 * role's own sessions. With activity tracking off it falls back to a
 * five-minute lag.
 */
export async function auditWatermark(executor: SqlExecutor): Promise<string> {
  return (await executor.query<{ watermark: string }>(
    `SELECT (CASE WHEN current_setting('track_activities') = 'on' THEN LEAST(clock_timestamp(), (
               SELECT min(CASE WHEN backend_xid IS NOT NULL THEN xact_start
                               WHEN state = 'active' THEN query_start END)
                 FROM pg_stat_activity
                WHERE datname = current_database() AND pid <> pg_backend_pid()))
             ELSE clock_timestamp() - interval '5 minutes' END)::text AS watermark`,
  )).rows[0]!.watermark;
}

/**
 * One page of a workspace's audit log in id order, after `afterId`, that
 * never skips an event: it stops before the first event (of any viewer or
 * filter) at or after the commit-safe watermark, so an event committed after
 * this read can only ever have an id above the page's last. A page can be
 * short, or empty, while writes are in flight; the next read with the same
 * `after_id` returns the rest.
 */
export async function listAuditPage(executor: SqlExecutor, input: {
  workspaceId: string; all: boolean; viewerUserId: string; since: string | null; grantId: string | null;
  limit: number; afterId: string | null;
}): Promise<Record<string, unknown>[]> {
  const watermark = await auditWatermark(executor);
  const rows = (await executor.query<Record<string, unknown>>(
    `SELECT * FROM delegation_audit_events
      WHERE workspace_id = $1
        AND ($2::boolean OR owner_user_id = $3 OR actor_user_id = $3)
        AND ($4::timestamptz IS NULL OR created_at > $4::timestamptz)
        AND ($5::text IS NULL OR grant_id = $5)
        AND ($7::bigint IS NULL OR id > $7::bigint)
        AND created_at < $8::timestamptz
      ORDER BY id LIMIT $6`,
    [input.workspaceId, input.all, input.viewerUserId, input.since, input.grantId, input.limit, input.afterId, watermark],
  )).rows;
  if (!rows.length) return rows;
  // An event at or after the watermark below the page's last id (sequence
  // order and clock order can differ by a few microseconds between
  // concurrent inserts) ends the page before it.
  const cut = (await executor.query<{ id: string | null }>(
    `SELECT min(id)::text AS id FROM delegation_audit_events
      WHERE workspace_id = $1 AND id > COALESCE($2::bigint, 0) AND id <= $3::bigint AND created_at >= $4::timestamptz`,
    [input.workspaceId, input.afterId, String(rows.at(-1)!.id), watermark],
  )).rows[0]?.id;
  return cut ? rows.filter(row => BigInt(String(row.id)) < BigInt(cut)) : rows;
}

/**
 * Revokes grants and invalidates every unredeemed approval under them, in
 * the caller's transaction. Returns the revoked rows (inactive ones are skipped).
 */
/** Whether every action of an approval has been consumed (single use is per action, §5.1). */
async function allActionsConsumed(executor: SqlExecutor, approval: Pick<ApprovalRow, "id" | "actions">): Promise<boolean> {
  const consumed = Number((await executor.query<{ count: string | number }>(
    "SELECT count(*) AS count FROM delegation_action_consumptions WHERE approval_id = $1", [approval.id],
  )).rows[0]?.count ?? 0);
  return consumed >= approval.actions.length;
}

/** Whether one action of an approval has been consumed. */
export async function actionConsumed(executor: SqlExecutor, approvalId: string,
  action: Pick<Action, "class" | "target">): Promise<boolean> {
  return (await executor.query(
    "SELECT 1 FROM delegation_action_consumptions WHERE approval_id = $1 AND class = $2 AND target = $3",
    [approvalId, action.class, action.target],
  )).rows.length > 0;
}

/** Consumes one action atomically; false when it was already consumed. */
export async function consumeAction(executor: SqlExecutor, input: { approvalId: string; workspaceId: string;
  action: Pick<Action, "class" | "target">; consumedBy: string }): Promise<boolean> {
  return (await executor.query(
    `INSERT INTO delegation_action_consumptions (approval_id, workspace_id, class, target, consumed_by)
     VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING RETURNING approval_id`,
    [input.approvalId, input.workspaceId, input.action.class, input.action.target, input.consumedBy],
  )).rows.length === 1;
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
      WHERE workspace_id = $1 AND invalidated_at IS NULL
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
  await executor.query(
    `UPDATE delegation_approvals SET invalidated_at = now()
      WHERE workspace_id = $1 AND invalidated_at IS NULL
        AND ($2::uuid IS NULL OR owner_user_id = $2)`,
    [input.workspaceId, input.ownerUserId],
  );
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
    await deps.database.transaction(tx => revokeGrants(tx, {
      workspaceId: workspace.id, grantIds: [grant.id], actorUserId: null, reason, authMethod: "system",
    })).catch(() => undefined);
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
    if (action.class === "config_change" && NEVER_DELEGABLE_SETTINGS.includes(configTarget(action.target)?.setting ?? "")) {
      return "out_of_scope";
    }
  }
  return null;
}

/**
 * The commit-point check, run inside the transaction that signs an
 * attestation or consumes an action, after every slow lookup. Everything is
 * read again from committed state under locks, never from the policy or grant
 * read before the lookups:
 *
 * - the workspace policy, share-locked (a policy PUT locks it FOR UPDATE):
 *   delegation off is `not_enabled`;
 * - the grant, locked FOR UPDATE (revocation and narrowing lock it too):
 *   `revoked` or `expired`;
 * - the actions against the current grant and policy (allowed classes, the
 *   grant's fit, scope coverage, the recipient's own target): `out_of_scope`;
 * - for tier D, the current policy's and grant's tier O classes:
 *   `tier_o_required`.
 *
 * Lock order is policy row, then grant row, then (in the callers) the
 * membership, session and approval rows. A policy PUT takes the policy row,
 * then grants, then approvals; revocation takes grants, then approvals. So
 * none of them can deadlock with this.
 */
export async function recheckAtCommit(tx: SqlExecutor, input: {
  workspaceId: string; grantId: string; tier: "D" | "O"; actions: readonly Action[]; recipientAgentId: string;
  nowMs: number;
}): Promise<{ grant: GrantRow; policy: DelegationPolicy }> {
  const policy = await loadPolicy(tx, input.workspaceId, true);
  if (!policy.delegation_enabled) refuse("not_enabled");
  const grant = (await tx.query<GrantRow>(
    "SELECT * FROM delegation_grants WHERE id = $1 AND workspace_id = $2 FOR UPDATE", [input.grantId, input.workspaceId],
  )).rows[0];
  if (!grant || grant.status === "revoked") refuse("revoked");
  if (grant!.status === "expired" || time(grant!.expires_at) <= input.nowMs) refuse("expired");
  const outOfScope = scopeRefusal(input.actions, grant!, policy, input.recipientAgentId);
  if (outOfScope) refuse(outOfScope);
  if (input.tier === "D") {
    const required = tierOClasses(policy, grant!);
    if (input.actions.some(action => required.has(action.class))) refuse("tier_o_required");
  }
  return { grant: grant!, policy };
}

/**
 * The approval row at the commit point, locked (after the grant): an approval
 * revoked by its owner or an admin, withdrawn by its delegate, or invalidated
 * with its grant while the caller waited is `revoked`.
 */
export async function approvalStillLive(tx: SqlExecutor, workspaceId: string, approvalId: string,
  lock: "FOR SHARE" | "FOR UPDATE"): Promise<void> {
  const live = (await tx.query(
    `SELECT 1 FROM delegation_approvals WHERE id = $1 AND workspace_id = $2 AND invalidated_at IS NULL ${lock}`,
    [approvalId, workspaceId],
  )).rows.length > 0;
  if (!live) refuse("revoked");
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
  const context: { ownerUserId?: string; grantId?: string; approvalId?: string; senderId?: string } = {};
  try {
    const policy = await loadPolicy(deps.database, workspace.id);
    if (!policy.delegation_enabled) refuse("not_enabled");
    if (deps.gateOnly || !deps.signer) refuse("unavailable");
    const recipient = await proveRecipient(deps, input);

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
    context.ownerUserId = approval.owner_id;

    const found = liveGrant(await grantsFor(deps.database, workspace.id, approval.owner_id, senderId!), now);
    if (typeof found === "string") return refuse(found);
    const grant = found;
    context.grantId = grant.id;
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
      if (minted!.single_use && await allActionsConsumed(deps.database, minted!)) refuse("consumed");
      if (time(minted!.expires_at) <= now.getTime()) refuse("expired");
      if (!sameActions(minted!.actions, messageActions)) refuse("out_of_scope");
      actions = minted!.actions.map(canonicalAction);
      expiresAt = Math.min(time(minted!.expires_at), time(grant.expires_at));
      singleUse = minted!.single_use || actions.some(highRisk);
    } else {
      tier = "D";
      actions = messageActions;
      context.approvalId = tierDApprovalId(workspace.id, input.messageId);
      // Cloud's approvalExpiry: the sender's expires_at, default 1 hour after
      // the send (Relaycast's created_at when reported, else now), at most 24
      // hours after it, never past the grant. The first attestation stores it.
      const sentAt = delivered!.created_at && !Number.isNaN(Date.parse(delivered!.created_at))
        ? Date.parse(delivered!.created_at) : now.getTime();
      const requested = approval.expires_at ? Date.parse(approval.expires_at) : sentAt + APPROVAL_DEFAULT_MS;
      expiresAt = Math.min(requested, sentAt + APPROVAL_MAX_MS, time(grant.expires_at));
      singleUse = actions.some(highRisk);
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
      if ((stored!.single_use || actions.every(highRisk)) && await allActionsConsumed(deps.database, stored!)) refuse("consumed");
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
    const { attestation, claims } = await deps.database.transaction(async (tx) => {
      // The policy, grant and approval may have changed during the Relaycast
      // lookups: recheck all of them from committed state, under locks, before
      // signing or recording anything a redeem could rely on.
      await recheckAtCommit(tx, { workspaceId: workspace.id, grantId: grant.id, tier, actions,
        recipientAgentId: recipient.agentId, nowMs: deps.now().getTime() });
      // The caller's membership and bearer, under share locks, so a revocation
      // between the earlier check and this commit cannot be missed.
      if (!await memberRole(tx, workspace.id, input.callerUserId, true) ||
          (input.stillAuthorized && !await input.stillAuthorized(tx))) refuse("not_pending");
      await approvalStillLive(tx, workspace.id, context.approvalId!, "FOR SHARE");
      // Standing against the target owners as committed now.
      if (await standingFor(tx, workspace.id, { approvalOwnerId: approval.owner_id, recipientOwnerId: input.callerUserId,
        accept: input.accept, actions }) !== standing) refuse("recipient_policy");
      // §15.9: a message whose quote has been redacted is never stored or
      // signed again; the row keeps only the digest.
      const quoteRedacted = Boolean(approval.quote) && await messageQuoteRedacted(tx, workspace.id, input.messageId);
      // Time the claims at signing, after every wait above: an attestation is
      // never signed already expired.
      const signedAt = deps.now().getTime();
      if (expiresAt <= signedAt) refuse("expired");
      const iat = Math.floor(signedAt / 1000);
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
        exp: Math.min(iat + ATTESTATION_TTL_SECONDS, Math.floor(expiresAt / 1000)),
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
      await redactExpiredQuotes(tx);
      // Signed last, inside the transaction: a refusal above signs nothing.
      return { attestation: deps.signer!.sign(claims), claims };
    });
    return { verdict: "delegate", attestation, claims };
  } catch (error) {
    // No dependency error can promote a peer message or expose a
    // message-existence oracle.
    const reason: ReasonCode = error instanceof Refusal ? error.reason : "unavailable";
    await recordDelegationAudit(deps.database, {
      workspaceId: workspace.id, event: "approval.refused", actorUserId: input.callerUserId,
      authMethod: input.authMethod, ownerUserId: context.ownerUserId ?? null, grantId: context.grantId ?? null,
      approvalId: context.approvalId ?? null, actorAgentId: context.senderId ?? null,
      messageId: input.messageId, recipientAgentId: input.recipientAgentId, reason,
    }).catch(() => undefined);
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
  const context: { ownerUserId?: string; grantId?: string } = {};
  try {
    const policy = await loadPolicy(deps.database, workspace.id);
    if (!policy.delegation_enabled) refuse("not_enabled");
    if (deps.gateOnly) refuse("unavailable");
    await proveRecipient(deps, input);
    const approval = (await deps.database.query<ApprovalRow>(
      "SELECT * FROM delegation_approvals WHERE id = $1 AND workspace_id = $2",
      [input.approvalId, workspace.id],
    )).rows[0];
    if (!approval) refuse("no_approval");
    context.ownerUserId = approval!.owner_user_id;
    // Only a recipient Control attested this approval to may redeem it.
    const attested = (await deps.database.query<{ grant_id: string; accept: string }>(
      `SELECT grant_id, accept FROM delegation_attestations
        WHERE workspace_id = $1 AND approval_id = $2 AND recipient_agent_id = $3
        ORDER BY issued_at DESC LIMIT 1`,
      [workspace.id, input.approvalId, input.recipientAgentId],
    )).rows[0];
    if (!attested) refuse("no_approval");
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
    await deps.database.transaction(async (tx) => {
      // The policy, grant and approval may have changed during the Relaycast
      // lookups: recheck all of them from committed state, under locks, in
      // both paths, then consume a single-use action in the same transaction.
      await recheckAtCommit(tx, { workspaceId: workspace.id, grantId: grant!.id, tier: approval!.tier, actions: [action!],
        recipientAgentId: input.recipientAgentId, nowMs: deps.now().getTime() });
      // The caller's membership and bearer, under share locks: a revocation
      // while this waited on the grant lock is never missed before consuming.
      if (!await memberRole(tx, workspace.id, input.callerUserId, true) ||
          (input.stillAuthorized && !await input.stillAuthorized(tx))) refuse("not_pending");
      // The approval may have been revoked or withdrawn meanwhile.
      await approvalStillLive(tx, workspace.id, input.approvalId, "FOR UPDATE");
      if (!await standingFor(tx, workspace.id, standingInput)) refuse("recipient_policy");
      if (!singleUse) return;
      // Single use is per action (§5.1): one atomic insert per action.
      if (!await consumeAction(tx, { approvalId: input.approvalId, workspaceId: workspace.id, action: action!,
        consumedBy: input.recipientAgentId })) refuse("consumed");
    });
    // The consumption above is the authority; a failed log write must not turn
    // a spent approval into a refusal the agent would retry.
    await recordDelegationAudit(deps.database, {
      workspaceId: workspace.id, event: "approval.redeemed", actorUserId: input.callerUserId,
      authMethod: input.authMethod, ownerUserId: approval!.owner_user_id, grantId: grant!.id,
      approvalId: input.approvalId, recipientAgentId: input.recipientAgentId,
      data: { action: input.action, consumed: singleUse, conditions: action!.conditions ?? [] },
    }).catch(() => undefined);
    return { ok: true, consumed: singleUse };
  } catch (error) {
    const reason: ReasonCode = error instanceof ConditionUnmet ? "condition_unmet"
      : error instanceof Refusal ? error.reason : "unavailable";
    const unmet = error instanceof ConditionUnmet ? error.unmet : undefined;
    await recordDelegationAudit(deps.database, {
      workspaceId: workspace.id, event: "redeem.refused", actorUserId: input.callerUserId,
      authMethod: input.authMethod, ownerUserId: context.ownerUserId ?? null, grantId: context.grantId ?? null,
      approvalId: input.approvalId, recipientAgentId: input.recipientAgentId, reason,
      data: { action: input.action, ...(unmet ? { unmet } : {}) },
    }).catch(() => undefined);
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
    // A released or re-bound agent is never offered (its grant is revoked, as at attestation).
    if (await delegateStillBound(deps, workspace, grant, true)) continue;
    delegates.push({ agent_id: grant.delegate_agent_id, grant_id: grant.id });
  }
  return { delegates };
}

export { CLAIM_TTL_MS };
