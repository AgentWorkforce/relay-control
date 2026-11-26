import { createHmac, hkdfSync, randomBytes, randomUUID } from "node:crypto";
import type { Database, SqlExecutor } from "../database.js";
import { RelaycastCallError, type RelaycastClient } from "../messaging/relaycast.js";
import type { DelegationSigner } from "./jws.js";
import { drainBody } from "../drain-body.js";
import { messageSentAt } from "./relaycast-ids.js";
import { logAuditWriteFailed, logRefused, logRevokeFailed, logUnavailable } from "./observe.js";
import {
  resolveTrustPath,
  sqlTrustReader,
  trustPathFingerprint,
  trustPathProvenAt,
  trustRelation,
  trustRelationAllowed,
  type TrustPath,
  type TrustProof,
  type TrustReader,
} from "./trust.js";
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
  HIGH_RISK_CLASSES,
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
import { ACTION_CLASSES } from "./scope.js";
import {
  PR_OPS_OPS, PRINCIPAL_KINDS, REQUIRED_CONDITION_TYPES, ROLES, coversNothing, decide, grantedTierO, requiredConditionsOf, sameScopes,
  systemScopes, systemScopesCover, type Authority, type BindingFields, type BindingView, type Decision, type PrOp,
  type PrincipalKind, type RequiredCondition, type RequiredConditions, type Role,
} from "./roles.js";

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
  /** The stored ownership records the trust rule's chain is walked over (default: SQL on `database`). */
  trustReader?: TrustReader;
};

export type AgentBinding = { userId: string; agentId: string; name: string; address: string | null;
  /** Which binding table holds the agent: `hosted` is an MCP connector's hosted participant. */
  source?: string };

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
  /** Set only on a system grant the owner's trust rule created; never on an owner-made grant. */
  trust_rule_id?: string | null;
  /** The ownership chain proven when the system grant was created, for audit. */
  trust_path?: TrustPath | null;
};

/** An owner's set-once trust rule (docs/owner-delegates.md, "Trust rule"). */
export type TrustRuleRow = {
  id: string;
  workspace_id: string;
  owner_user_id: string;
  require_tier_o: ActionClass[];
  created_at: Date | string;
  updated_at: Date | string;
  revoked_at: Date | string | null;
  revoked_reason: string | null;
  revoked_by_user_id: string | null;
  /** `all_agents` (legacy), `relay_agents`, `connector_kind`, `group` or `agent` (migration 0099). */
  principal_kind?: string;
  principal_ref?: string | null;
  /** Null on a legacy rule: every class, spawn tree included. */
  role?: string | null;
  classes?: ActionClass[] | null;
  pr_ops_limit?: string[] | null;
  required_conditions?: Record<string, Array<{ type: string }>> | null;
  targets?: string[] | null;
  expires_at?: Date | string | null;
};

/** The expiry a rule-backed grant carries: never read as authority, only the live rule is. */
export const TRUST_RULE_GRANT_EXPIRY = new Date("9999-12-31T00:00:00.000Z");
/**
 * The revoke reason of a system grant retired because its delegate now proves
 * out through other records. Its end is a hand-over to the new chain, not a
 * gap in coverage, so it does not floor the replacement grant (Cloud's CHAIN_CHANGED).
 */
export const CHAIN_CHANGED = "chain_changed";
/** The revoke reason of a system grant whose bindings no longer cover its delegate. */
export const BINDING_CHANGED = "binding_changed";
/** The revoke reason of a system grant a person revoked: the rule does not cover that agent again. */
export const OWNER_EXCLUDED = "owner_excluded";

/**
 * Whether `next`'s own records date its start reliably enough that a hand-over
 * from `previous` leaves no gap before its provenAt (Cloud's handOverDated). A
 * claim root dates from its completion and a launch from its spawn. A
 * connector root does not: a grant becomes a root only once pinned to the
 * agent, and the pin has no time, so an older grant pinned later would date
 * the new coverage from before the gap. Only the same pinned connector root,
 * with changed launches, counts.
 */
export function handOverDated(previous: TrustPath | null, next: TrustPath): boolean {
  if (next.root.kind === "claim") return true;
  return previous?.root.kind === "connector" && next.root.kind === "connector" &&
    previous.root.oauth_grant_id === next.root.oauth_grant_id;
}

/**
 * A person revoking one system grant excludes that agent (Khaliq, answer 8;
 * Cloud's excludeFromRule): the owner gets an `excluded` binding for the
 * agent, which beats every group and gives nothing, until someone gives the
 * agent a direct setting (PATCH that binding). The exclusion is of the agent,
 * not the row: every active system grant of the owner for that agent is
 * revoked as owner_excluded, and when none is left the retired one the
 * person saw is re-recorded as the exclusion. Runs in the caller's
 * transaction. The owner's binding lock is taken exclusively first, then the
 * owner's live rules FOR UPDATE, then the grants by id. That serializes with
 * every materialization for the owner.
 */
export async function excludeFromRule(tx: SqlExecutor, input: { workspaceId: string; grant: GrantRow; actorUserId: string;
  authMethod: string | null }): Promise<boolean> {
  const { grant } = input;
  const ownerUserId = grant.owner_user_id;
  const agentId = grant.delegate_agent_id;
  await lockOwnerBindings(tx, input.workspaceId, ownerUserId, "exclusive");
  await lockLiveRules(tx, { workspaceId: input.workspaceId, ownerUserId });
  const own = (await tx.query<TrustRuleRow>(
    `SELECT * FROM delegation_trust_rules WHERE workspace_id = $1 AND owner_user_id = $2 AND principal_kind = 'agent'
        AND principal_ref = $3 AND revoked_at IS NULL`,
    [input.workspaceId, ownerUserId, agentId],
  )).rows[0];
  const excluded = EXCLUDED_FIELDS;
  let binding: TrustRuleRow | null = null;
  if (!own) {
    binding = (await tx.query<TrustRuleRow>(
      `INSERT INTO delegation_trust_rules (id, workspace_id, owner_user_id, principal_kind, principal_ref, ${BINDING_COLUMNS},
         created_at, updated_at)
       VALUES ($1, $2, $3, 'agent', $4, $5, $6, $7, $8, $9, $10, $11, clock_timestamp(), clock_timestamp()) RETURNING *`,
      [mintId("dtr"), input.workspaceId, ownerUserId, agentId, ...bindingValues(excluded)],
    )).rows[0]!;
  } else if (own.role !== "excluded") {
    binding = (await tx.query<TrustRuleRow>(
      `UPDATE delegation_trust_rules SET (${BINDING_COLUMNS}) = ($2, $3, $4, $5, $6, $7, $8), updated_at = clock_timestamp()
        WHERE id = $1 RETURNING *`,
      [own.id, ...bindingValues(excluded)],
    )).rows[0]!;
  }
  if (binding) {
    await recordDelegationAudit(tx, { workspaceId: input.workspaceId, event: own ? "binding.updated" : "binding.created",
      actorUserId: input.actorUserId, authMethod: input.authMethod, ownerUserId, reason: OWNER_EXCLUDED,
      data: { ...bindingAudit(binding), delegate_agent_id: agentId, grant_id: grant.id } });
  }
  const revoked = await reresolveOwnerGrants(tx, { workspaceId: input.workspaceId, ownerUserId,
    actorUserId: input.actorUserId, authMethod: input.authMethod, onlyAgent: agentId });
  if (revoked.length) return true;
  // Nothing active: the grant shown had already ended. Its end is re-recorded as the person's exclusion.
  const marked = (await tx.query(
    `UPDATE delegation_grants SET revoked_reason = $3, revoked_by = $4, updated_at = now()
      WHERE workspace_id = $1 AND id = $2 AND status = 'revoked' AND revoked_reason IS DISTINCT FROM $3 RETURNING id`,
    [input.workspaceId, grant.id, OWNER_EXCLUDED, input.actorUserId],
  )).rows.length > 0;
  if (!marked) return Boolean(binding);
  await recordDelegationAudit(tx, { workspaceId: input.workspaceId, event: "grant.revoked", actorUserId: input.actorUserId,
    authMethod: input.authMethod, ownerUserId, grantId: grant.id, reason: OWNER_EXCLUDED,
    data: { delegate_agent_id: agentId, already_ended: true } });
  return true;
}

export type ApprovalRow = {
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
    trust_rule_id: row.trust_rule_id ?? null,
    trust_path: row.trust_path ?? null,
  };
}

/** A fresh opaque id with a type prefix (`grt_`, `apv_`, `clm_`, `gate_`, `dtr_`), as Cloud's mintId. */
export function mintId(prefix: "grt" | "apv" | "clm" | "gate" | "dtr" | "grp"): string {
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
export function grantFitsPolicy(grant: Pick<GrantRow, "scopes" | "expires_at" | "created_at" | "trust_rule_id">,
  policy: DelegationPolicy): boolean {
  // A system grant follows its binding's preset, which may name classes the
  // policy does not allow: those are refused per action (scopeRefusal), so the
  // policy clips the grant instead of refusing all of it (as Cloud).
  if (!grant.trust_rule_id && policy.allowed_classes &&
      grant.scopes.some(scope => !policy.allowed_classes!.includes(scope.class))) return false;
  // The 90-day cap does not apply to the owner's trust rule (#owner-decisions 251238934511685632): the
  // exemption is keyed on the rule link, never on the far expiry date, and the rule is checked live at every use.
  if (grant.trust_rule_id) return true;
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
  return { userId: row.user_id, agentId: row.agent_id, name: row.agent_name, address: row.address, source: row.source };
}

/**
 * Whether a hosted-participant binding still stands for an owner-made grant:
 * the agent must prove out as the owner's connector root (a live OAuth grant
 * and session pinned to its id, exactly one owned participant), as Cloud's
 * ownedDelegateBinding requires. The participant row alone is not enough: a
 * revoked connector must end the owner's grant too.
 */
export async function connectorRootProven(prove: TrustProver, ownerUserId: string, agentId: string): Promise<TrustProof | null> {
  const proof = await prove(ownerUserId, agentId);
  return proof && proof.path.root.kind === "connector" && !proof.path.hops.length ? proof : null;
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
 * Whether an approval is used up (cloud#6603 0592d777c): EVERY action is single
 * use (a high-risk action always is, and every action of an approval
 * explicitly marked single use) and every one has been consumed. An approval
 * with a reusable action is never spent, so attest still delegates it.
 */
function everyActionSingleUse(approval: Pick<ApprovalRow, "actions" | "single_use">): boolean {
  return approval.actions.length > 0 && approval.actions.every(action => approval.single_use || highRisk(action));
}

/**
 * A `consumed_at` stamp on an approval that still has a reusable action. The
 * current rule never stamps one (markSpentIfComplete), so it is left by the
 * earlier rule, which stamped an approval once its single-use actions were
 * consumed. A revoke-all or grant revocation under that rule skipped it, so
 * `invalidated_at` may be missing although its owner revoked it. Such an
 * approval is refused as `revoked` (fail closed: its owner approves again).
 */
export function legacySpentStamp(approval: Pick<ApprovalRow, "consumed_at" | "actions" | "single_use">): boolean {
  return approval.consumed_at !== null && approval.consumed_at !== undefined && !everyActionSingleUse(approval);
}

async function everySingleUseActionSpent(executor: SqlExecutor,
  approval: Pick<ApprovalRow, "id" | "actions" | "single_use">): Promise<boolean> {
  if (!everyActionSingleUse(approval)) return false;
  const spent = new Set((await executor.query<{ class: string; target: string }>(
    "SELECT class, target FROM delegation_action_consumptions WHERE approval_id = $1", [approval.id],
  )).rows.map(row => `${row.class} ${row.target}`));
  return approval.actions.every(action => spent.has(`${action.class} ${action.target}`));
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
 * Stamps `consumed_at` once the approval is spent: EVERY action is single use
 * and consumed (cloud#6603 0592d777c). A spent approval is no longer
 * "unredeemed", so grant revocation and revoke-all leave it alone, unless a
 * release gate redeemed it (revocationSkipsSql); one that still has a
 * reusable action stays live, so a revocation still reaches it.
 */
export async function markSpentIfComplete(executor: SqlExecutor, approvalId: string): Promise<void> {
  const approval = (await executor.query<Pick<ApprovalRow, "id" | "actions" | "single_use">>(
    "SELECT id, actions, single_use FROM delegation_approvals WHERE id = $1 AND consumed_at IS NULL", [approvalId],
  )).rows[0];
  if (!approval || !await everySingleUseActionSpent(executor, approval)) return;
  await executor.query("UPDATE delegation_approvals SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL", [approvalId]);
}

/**
 * SQL: the approval row is spent under the current rule (cloud#6603): stamped,
 * and EVERY action single use (approval-wide `single_use`, or a high-risk
 * class; `$n` is HIGH_RISK_CLASSES). Revocation skips only these. A stamp
 * left by the earlier rule on a mixed approval (one with a reusable action)
 * does not keep it from being revoked.
 */
function spentApprovalSql(param: number): string {
  return `(consumed_at IS NOT NULL AND (single_use OR NOT EXISTS (
    SELECT 1 FROM jsonb_array_elements(actions) AS action WHERE NOT (action->>'class' = ANY($${param}::text[])))))`;
}

/**
 * SQL: the approval row is one revocation leaves alone, spent under the
 * current rule AND never redeemed through a release gate. A gate-redeemed
 * approval is not final when spent: the run that consumed an action may
 * redeem it again (`same_run`: another job, or a later attempt), so a
 * revocation must reach it or that run keeps publishing after the owner
 * revoked (as the hosted twin).
 */
function revocationSkipsSql(param: number): string {
  return `(${spentApprovalSql(param)} AND NOT EXISTS (
    SELECT 1 FROM delegation_gate_redemptions AS redeemed WHERE redeemed.approval_id = delegation_approvals.id))`;
}

export async function revokeGrants(executor: SqlExecutor, input: {
  workspaceId: string; grantIds: string[]; actorUserId: string | null; reason: string; authMethod: string | null;
}): Promise<GrantRow[]> {
  if (!input.grantIds.length) return [];
  const revoked = (await executor.query<GrantRow>(
    `UPDATE delegation_grants
        SET status = 'revoked', revoked_at = clock_timestamp(), revoked_by = $3, revoked_reason = $4, updated_at = clock_timestamp()
      WHERE workspace_id = $1 AND id = ANY($2::text[]) AND status = 'active'
      RETURNING *`,
    [input.workspaceId, input.grantIds, input.actorUserId, input.reason],
  )).rows;
  if (!revoked.length) return [];
  const ids = revoked.map(row => row.id);
  // The candidates are locked (by id) in a statement of their own, so the
  // UPDATE below starts after any consume that held one has committed and its
  // gate-redemption check sees that redemption (as in revokeAllGrants).
  await executor.query(
    `SELECT id FROM delegation_approvals
      WHERE workspace_id = $1 AND invalidated_at IS NULL
        AND (grant_id = ANY($2::text[])
          OR id IN (SELECT approval_id FROM delegation_attestations WHERE grant_id = ANY($2::text[])))
      ORDER BY id FOR NO KEY UPDATE`,
    [input.workspaceId, ids],
  );
  await executor.query(
    `UPDATE delegation_approvals SET invalidated_at = now()
      WHERE workspace_id = $1 AND invalidated_at IS NULL AND NOT ${revocationSkipsSql(3)}
        AND (grant_id = ANY($2::text[])
          OR id IN (SELECT approval_id FROM delegation_attestations WHERE grant_id = ANY($2::text[])))`,
    [input.workspaceId, ids, HIGH_RISK_CLASSES],
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
 * Serializes grant creation and claim release for one delegate agent, before
 * either takes a row lock. Release re-reads the grants after it holds the
 * claim; without this, a second creation holding a new grant's row lock and
 * waiting for the claim would deadlock with that re-read.
 */
async function lockDelegateAgent(tx: SqlExecutor, workspaceId: string, agentId: string): Promise<void> {
  await tx.query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`delegation-agent:${workspaceId}:${agentId}`]);
}

/**
 * Grant creation's locks, in the one order releaseClaim and revocation use
 * (cloud#6603 0592d777c): this owner's active grants to the agent (by id),
 * then the agent's claim rows (by id). expireLapsed then updates those same
 * grant rows, so they are taken first.
 */
export async function lockGrantAndClaims(tx: SqlExecutor, workspaceId: string, ownerUserId: string,
  agentId: string): Promise<void> {
  await lockDelegateAgent(tx, workspaceId, agentId);
  await tx.query(
    `SELECT id FROM delegation_grants
      WHERE workspace_id = $1 AND owner_user_id = $2 AND delegate_agent_id = $3 AND status = 'active'
      ORDER BY id FOR UPDATE`,
    [workspaceId, ownerUserId, agentId],
  );
  await tx.query(
    "SELECT id FROM delegation_claims WHERE workspace_id = $1 AND agent_id = $2 ORDER BY id FOR UPDATE",
    [workspaceId, agentId],
  );
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
    // Serialized with grant creation for this agent, then grants (by id), then the claim.
    if (seen.agent_id) await lockDelegateAgent(tx, input.workspaceId, seen.agent_id);
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
    // A grant created while this release waited on a lock (it holds the
    // claim lock until it commits) is read again now and revoked too, as Cloud.
    const allGrantIds = claim.agent_id ? (await tx.query<{ id: string }>(
      `SELECT id FROM delegation_grants
        WHERE workspace_id = $1 AND owner_user_id = $2 AND delegate_agent_id = $3 AND status = 'active'
        ORDER BY id FOR UPDATE`,
      [input.workspaceId, claim.user_id, claim.agent_id],
    )).rows.map(row => row.id) : grantIds;
    await tx.query("UPDATE delegation_claims SET released_at = now() WHERE id = $1", [claim.id]);
    let revokedGrants: string[] = [];
    if (claim.consumed_at && claim.agent_id) {
      // The binding the claim created ends, and so does any grant through it.
      await tx.query("DELETE FROM delegation_agent_bindings WHERE workspace_id = $1 AND claim_id = $2", [input.workspaceId, claim.id]);
      revokedGrants = (await revokeGrants(tx, { workspaceId: input.workspaceId, grantIds: allGrantIds, actorUserId: input.actorUserId,
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
 * whole workspace), plus that owner's unredeemed tier O approvals and every
 * spent approval a release gate redeemed (its run could redeem it again), as Cloud.
 */
export async function revokeAllGrants(executor: SqlExecutor, input: {
  workspaceId: string; ownerUserId: string | null; actorUserId: string | null; reason: string; authMethod: string | null;
}): Promise<string[]> {
  // The scope's live trust rules are locked first, by id, before any grant
  // (the rule-then-grants order every rule writer uses), so no rule can create
  // a grant once this has read the grants below. Their system grants are
  // revoked with every other grant of the scope: all grants are locked by id
  // before any approval is touched, or a revoke holding a shared approval
  // could wait on an owner-made grant a decision holds (a deadlock).
  const rules = await lockLiveRules(executor, { workspaceId: input.workspaceId, ownerUserId: input.ownerUserId });
  const ids = (await executor.query<{ id: string }>(
    `SELECT id FROM delegation_grants
      WHERE workspace_id = $1 AND status = 'active' AND ($2::uuid IS NULL OR owner_user_id = $2)
      ORDER BY id FOR UPDATE`,
    [input.workspaceId, input.ownerUserId],
  )).rows.map(row => row.id);
  // Then every live approval it may revoke, by id, before any is updated. A
  // gate consume holds its approval's row while it records the redemption and
  // stamps the approval spent. An UPDATE that waited on that row would re-check
  // the row as spent, but judge "a gate redeemed it" on its own earlier
  // snapshot, which misses the new redemption, and leave the approval live
  // for that run. Locking first, in its own statement, makes the UPDATEs
  // below start after the consume committed, so they see the redemption.
  await executor.query(
    `SELECT id FROM delegation_approvals
      WHERE workspace_id = $1 AND invalidated_at IS NULL AND ($2::uuid IS NULL OR owner_user_id = $2)
      ORDER BY id FOR NO KEY UPDATE`,
    [input.workspaceId, input.ownerUserId],
  );
  const revoked = await revokeGrants(executor, { workspaceId: input.workspaceId, grantIds: ids,
    actorUserId: input.actorUserId, reason: input.reason, authMethod: input.authMethod });
  await stampRulesRevoked(executor, rules, revoked, input);
  const approvals = (await executor.query<{ id: string }>(
    `UPDATE delegation_approvals SET invalidated_at = now()
      WHERE workspace_id = $1 AND invalidated_at IS NULL AND NOT ${revocationSkipsSql(3)}
        AND ($2::uuid IS NULL OR owner_user_id = $2)
      RETURNING id`,
    [input.workspaceId, input.ownerUserId, HIGH_RISK_CLASSES],
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

export class Refusal extends Error {
  constructor(readonly reason: ReasonCode) {
    super(reason);
  }
}

export class ConditionUnmet extends Error {
  constructor(readonly unmet: Condition[]) {
    super("condition_unmet");
  }
}

export const refuse = (reason: ReasonCode): never => {
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
 * The ownership-chain reader of one attest, redeem or prompt-delegates call
 * (`cache`): an agent's chain is walked once per call, shared by the rule
 * fallback, the binding re-check and the relation; a failed read is not kept.
 * A gate's last authority check builds an uncached one, so it re-reads on
 * purpose.
 */
export type TrustProver = (ownerUserId: string, agentId: string) => Promise<TrustProof | null>;

export function trustProver(deps: DelegationDeps, workspace: DelegationWorkspace, cache: boolean): TrustProver {
  const reader = deps.trustReader ?? sqlTrustReader(deps.database);
  const read: TrustProver = (ownerUserId, agentId) => resolveTrustPath(reader, { workspaceId: workspace.id,
    relaycastWorkspaceId: workspace.relaycastWorkspaceId, ownerUserId, agentId });
  if (!cache) return read;
  const seen = new Map<string, Promise<TrustProof | null>>();
  return (ownerUserId, agentId) => {
    const key = `${ownerUserId}\u0000${agentId}`;
    let hit = seen.get(key);
    if (!hit) {
      hit = read(ownerUserId, agentId);
      seen.set(key, hit);
      hit.catch(() => seen.delete(key));
    }
    return hit;
  };
}

/**
 * The proof a grant stands on, if it stands on one (Cloud's reliedProof): every
 * rule-backed grant, and an owner-made grant to a connected assistant (a
 * connector root with no launches).
 */
export async function reliedProof(prove: TrustProver, grant: GrantRow): Promise<TrustProof | null> {
  const proof = await prove(grant.owner_user_id, grant.delegate_agent_id);
  if (!proof) return null;
  if (grant.trust_rule_id) return proof;
  return proof.path.root.kind === "connector" && !proof.path.hops.length ? proof : null;
}

/**
 * The deciding transaction's chain re-check for a grant that stands on a proof
 * (Cloud's chainUnderLock): the chain is read again on the transaction with
 * every row share-locked (sqlTrustReader `lock`), and must still stand on the
 * same records (trustPathFingerprint) as the grant's stored path (rule-backed)
 * or the proof read before the transaction (owner-made to a connected
 * assistant). A release that commits after the earlier read, or a chain that
 * re-proved through new records, refuses as `revoked`. Undefined when there
 * is nothing to check. Never cached: it is the decision's own read.
 */
export function chainUnderLock(workspace: DelegationWorkspace, grant: GrantRow, proof: TrustProof | null):
  ((tx: SqlExecutor) => Promise<ReasonCode | null>) | undefined {
  const expected = grant.trust_rule_id && grant.trust_path ? trustPathFingerprint(grant.trust_path) :
    !grant.trust_rule_id && proof ? trustPathFingerprint(proof.path) : null;
  if (!expected) return undefined;
  return async tx => {
    const locked = await resolveTrustPath(sqlTrustReader(tx, true), { workspaceId: workspace.id,
      relaycastWorkspaceId: workspace.relaycastWorkspaceId, ownerUserId: grant.owner_user_id, agentId: grant.delegate_agent_id });
    return locked && trustPathFingerprint(locked.path) === expected ? null : "revoked";
  };
}

/** The live roster's marker of a Control-hosted participant of this owner (src/mcp/relay-participants.ts ownsRemote). */
const HOSTED_SOURCE = "cloud-hosted-mcp";

/**
 * Re-proves the delegate (Cloud's delegateStillBound): it still has exactly
 * one Control binding, owned by the grant's owner, Relaycast still names the
 * same live agent, and the owner is still a member. A binding now owned by
 * someone else revokes the grant durably (`binding_changed`), as in Cloud.
 * relay-control has no leave-workspace hook and no release webhook, so an
 * owner who left (`owner_left`) or a released agent (`agent_released`) also
 * revokes the grant durably here (§7 automatic revocation); the reason code
 * returned is `revoked` either way, as in Cloud.
 *
 * A rule-backed grant re-walks the whole ownership chain instead (trust.ts):
 * a chain that no longer proves out revokes the system grant durably
 * (`binding_changed`, or `delegate_released` for the live check); the rule
 * stays, and covers the agent again only if it proves out again.
 *
 * `durable: false` (a gate dry run) gives the same answer but writes nothing:
 * a delegate found unbound is refused, not revoked.
 */
export async function delegateStillBound(deps: DelegationDeps, workspace: DelegationWorkspace, grant: GrantRow,
  live: boolean, options: { durable?: boolean; prove?: TrustProver } = {}): Promise<ReasonCode | null> {
  const revoke = async (reason: string): Promise<ReasonCode> => {
    if (options.durable === false) return "revoked";
    // A failed write still refuses this use; it is logged.
    await deps.database.transaction(tx => revokeGrants(tx, {
      workspaceId: workspace.id, grantIds: [grant.id], actorUserId: null, reason, authMethod: "system",
    })).catch((error: unknown) => logRevokeFailed("attest", error, { workspaceId: workspace.id, grantId: grant.id, reason }));
    return "revoked";
  };
  if (grant.trust_rule_id) {
    const proof = await (options.prove ?? trustProver(deps, workspace, false))(grant.owner_user_id, grant.delegate_agent_id);
    if (!proof) return revoke("binding_changed");
    // A system grant covers the chain it was created on. One that now proves
    // through other records (a claim released and reclaimed, a connector
    // revoked and reconnected, a relaunch) is a new coverage: this grant ends,
    // with its approvals, and the rule creates a fresh one dated from the new
    // chain's records. CHAIN_CHANGED tells materializeRuleGrant this end is a
    // hand-over, not a gap (as in Cloud).
    if (grant.trust_path && trustPathFingerprint(proof.path) !== trustPathFingerprint(grant.trust_path)) {
      return revoke(CHAIN_CHANGED);
    }
    if (live) {
      const agent = await deps.relaycast.getRosterAgent(workspace.relaycastApiKey, proof.name);
      // A connector root (not launched) must still carry Control's hosted participant marker for this owner.
      const ownerMarked = proof.path.root.kind !== "connector" || proof.path.hops.length > 0 ||
        (agent?.metadata?.source === HOSTED_SOURCE && agent.metadata.owner_hash === sha256Hex(grant.owner_user_id));
      if (!agent || agent.id !== grant.delegate_agent_id || agent.status === "released" || !ownerMarked) {
        return revoke("delegate_released");
      }
    }
    if (!await memberRole(deps.database, workspace.id, grant.owner_user_id)) return revoke("owner_left");
    return null;
  }
  const binding = await resolveBinding(deps.database, workspace.id, workspace.relaycastWorkspaceId,
    grant.delegate_agent_id, true);
  if (!binding) return "not_delegate";
  if (binding.userId !== grant.owner_user_id) return revoke("binding_changed");
  // An owner-made grant to a connected assistant re-proves its connector at
  // every use (live OAuth grant and session, the owner's marker), so revoking
  // the connector ends the grant (cloud#6635 parity, d5-gate-owner P1).
  const connector = binding.source === "hosted" ?
    await connectorRootProven(options.prove ?? trustProver(deps, workspace, false), grant.owner_user_id, grant.delegate_agent_id) : null;
  if (binding.source === "hosted" && !connector) return revoke("binding_changed");
  if (live) {
    const agent = await deps.relaycast.getRosterAgent(workspace.relaycastApiKey, binding.name);
    if (!agent || agent.id !== binding.agentId || agent.status === "released") return revoke("agent_released");
    if (connector && !(agent.metadata?.source === HOSTED_SOURCE && agent.metadata.owner_hash === sha256Hex(grant.owner_user_id))) {
      return revoke("agent_released");
    }
  }
  if (!await memberRole(deps.database, workspace.id, grant.owner_user_id)) return revoke("owner_left");
  return null;
}

/**
 * Whether a rule-backed approval may pass from its sender to this recipient
 * (trustRelationAllowed, the one isolated predicate). The recipient's own
 * chain is read only when it belongs to the same owner; otherwise it is
 * outside the sender's tree. A bot may approve its own requests under an
 * owner-made grant too (#owner-decisions 251252958218768384).
 */
async function ruleRelationRefusal(prove: TrustProver, grant: GrantRow, recipientAgentId: string,
  recipientOwnerId: string): Promise<ReasonCode | null> {
  if (!grant.trust_rule_id) return null;
  const sender = await prove(grant.owner_user_id, grant.delegate_agent_id);
  if (!sender) return "not_delegate";
  const recipient = recipientOwnerId === grant.owner_user_id ? await prove(grant.owner_user_id, recipientAgentId) : null;
  return trustRelationAllowed(trustRelation(sender.path, recipientAgentId, recipient?.path ?? null)) ? null : "not_delegate";
}

/** Whether a system grant's delegate now proves out through records other than the grant's own (a hand-over, not a break). */
async function chainChanged(prove: TrustProver, grant: GrantRow): Promise<boolean> {
  if (!grant.trust_rule_id || !grant.trust_path) return false;
  const proof = await prove(grant.owner_user_id, grant.delegate_agent_id);
  return !!proof && trustPathFingerprint(proof.path) !== trustPathFingerprint(grant.trust_path);
}

/**
 * The owner's trust rule standing in for a missing grant: when the owner has a
 * live rule and the sender's ownership chain proves out, the system grant
 * that carries the rule (created now, or the existing one). Null when no rule
 * covers the sender. An owner-made grant that is live always wins; this is
 * reached only without one.
 */
async function ruleBackedGrant(deps: DelegationDeps, workspace: DelegationWorkspace, prove: TrustProver,
  ownerUserId: string, agentId: string): Promise<GrantRow | null> {
  // Any live binding of the owner may decide (roles.ts decide), under the materialization's locks.
  if (!await hasLiveBindings(deps.database, workspace.id, ownerUserId)) return null;
  const proof = await prove(ownerUserId, agentId);
  if (!proof) return null;
  const grant = await materializeRuleGrant(deps.database, { workspace, ownerUserId, delegateAgentId: agentId,
    delegateAgentName: proof.name, trustPath: proof.path, provenAt: trustPathProvenAt(proof.path),
    ...(proof.path.root.kind === "claim" && !proof.path.hops.length ? { claimId: proof.path.root.claim_id } : {}) });
  return grant && grant.status === "active" ? grant : null;
}

/**
 * A rule-backed grant as the bindings decide now (Cloud's currentSystemGrant,
 * review of cloud#6674). A system grant is re-resolved when a binding or
 * group changes, but not when resolution itself changes: a worker's grant
 * materialized before its spawn default took its root binding's ask-first
 * list would keep the looser authority. materializeRuleGrant returns the
 * stored grant when it still matches, and otherwise supersedes it and returns
 * the replacement, which covers nothing sent before it. An owner-made grant
 * is returned as is.
 */
async function currentSystemGrant(deps: DelegationDeps, workspace: DelegationWorkspace, prove: TrustProver,
  grant: GrantRow): Promise<GrantRow | ReasonCode> {
  if (!grant.trust_rule_id) return grant;
  return await ruleBackedGrant(deps, workspace, prove, grant.owner_user_id, grant.delegate_agent_id) ?? "revoked";
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

export function tierOClasses(policy: DelegationPolicy, grant: GrantRow): Set<ActionClass> {
  return new Set<ActionClass>([...DEFAULT_TIER_O_CLASSES, ...policy.require_tier_o, ...grant.require_tier_o]);
}

/**
 * Whether a grant covers one action's class and target. A system grant covers
 * what its binding's scopes say (roles.ts systemScopesCover). A legacy rule's
 * grant has no scopes and covers every class. The policy's allowed classes
 * still apply, in scopeRefusal. An owner-made grant covers what its scopes name.
 */
export function grantCovers(grant: Pick<GrantRow, "scopes" | "trust_rule_id">, action: Pick<Action, "class" | "target">): boolean {
  return grant.trust_rule_id ? systemScopesCover(grant.scopes, action) : actionsCovered(grant.scopes, [action]);
}

/** Why an action list is outside the grant or the policy, or null (Cloud's scopeRefusal). */
export function scopeRefusal(actions: readonly Action[], grant: GrantRow, policy: DelegationPolicy,
  recipientAgentId: string): ReasonCode | null {
  if (!grantFitsPolicy(grant, policy)) return "out_of_scope";
  for (const action of actions) {
    if (!actionIsValid(action)) return "out_of_scope";
    if (policy.allowed_classes && !policy.allowed_classes.includes(action.class)) return "out_of_scope";
    if (!grantCovers(grant, action)) return "out_of_scope";
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
export type DecisionState = { member: boolean; policy: DelegationPolicy; grant: GrantRow | null; approval: ApprovalRow | null;
  /** The trust rule behind a rule-backed grant, share-locked before the grant (absent for owner-made grants). */
  trustRule?: TrustRuleRow | null;
  /** Why the delegate's ownership chain, re-read under share locks, no longer stands; null when it does. */
  chainRefusal?: ReasonCode | null;
  /** Whether the grant's owner is still a member (share-locked); absent when not asked. */
  ownerMember?: boolean };

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
  grantId: string | null; approvalId: string; consuming?: boolean;
  /**
   * The grant's owner (review D1, as Cloud bd7359b4a). Their membership is
   * share-locked in the same sorted pass as memberUserIds, before the policy:
   * a path that takes the owner's membership FOR UPDATE and then updates their
   * OAuth grants, sessions or launches before touching delegation rows queues
   * behind a decision at its first lock, instead of meeting the decision's
   * rule, grant and chain locks from the other side.
   */
  grantOwnerUserId?: string | null;
  /**
   * The trust rule of a rule-backed grant. A grant's rule never changes, so
   * the caller reads it from the grant before the transaction. Locked after
   * the policy and before the grant: the one order every rule writer uses
   * (membership, policy, rule, then grants by id, then approvals), so a
   * revoke never deadlocks against a decision.
   */
  trustRuleId?: string | null;
  /**
   * Re-proves the delegate's ownership chain on this transaction, share-locking
   * every row it stands on (chainUnderLock). It runs after the grant lock and
   * before the approval lock: a claim release locks grants, then the claim,
   * then approvals, so taking the chain before the approval closes no cycle.
   */
  chain?: (tx: SqlExecutor) => Promise<ReasonCode | null>;
  /**
   * The acting agent of a cross-owner decision (Cloud's actingGrants, review
   * of cloud#6672): its active owner-made grants from its own owner are
   * share-locked with `grantId` in one pass by grant id. Revoke-all locks
   * grants by id too, so taking them later, inside `decide`, could close a
   * cycle with a revoke-all that holds one of them and waits on `grantId`.
   * actingAuthorityLocked reads them under this lock.
   */
  actingGrants?: { ownerUserId: string; agentId: string } | null },
  decide: (state: DecisionState, tx: SqlExecutor) => Promise<T>): Promise<T> {
  return database.transaction(async (tx) => {
    // The workspace row first (FOR KEY SHARE: policy writers' FOR NO KEY UPDATE
    // does not conflict): a workspace deletion locks it FOR UPDATE before its
    // cascade reaches launches, grants and approvals, so it queues behind a
    // decision instead of deleting rows the decision then waits on.
    await tx.query("SELECT 1 FROM workspaces WHERE id = $1 FOR KEY SHARE", [input.workspaceId]);
    let member = true;
    let ownerMember: boolean | undefined;
    const members = new Set(input.memberUserIds);
    for (const userId of [...new Set([...input.memberUserIds, ...(input.grantOwnerUserId ? [input.grantOwnerUserId] : [])])].sort()) {
      const present = Boolean(await memberRole(tx, input.workspaceId, userId, true));
      if (userId === input.grantOwnerUserId) ownerMember = present;
      if (!present && members.has(userId)) member = false;
    }
    const policy = await loadPolicy(tx, input.workspaceId, true);
    const trustRule = input.trustRuleId ? (await tx.query<TrustRuleRow>(
      "SELECT * FROM delegation_trust_rules WHERE workspace_id = $1 AND id = $2 FOR SHARE", [input.workspaceId, input.trustRuleId],
    )).rows[0] ?? null : undefined;
    // One locking read, sorted by id: Postgres locks the rows in that order, the order revoke-all uses.
    const grantRows = input.grantId || input.actingGrants ? (await tx.query<GrantRow>(
      `SELECT * FROM delegation_grants WHERE workspace_id = $1 AND (id = $2 OR (owner_user_id = $3 AND delegate_agent_id = $4
          AND status = 'active' AND trust_rule_id IS NULL)) ORDER BY id FOR SHARE`,
      [input.workspaceId, input.grantId, input.actingGrants?.ownerUserId ?? null, input.actingGrants?.agentId ?? null],
    )).rows : [];
    const grant = input.grantId ? grantRows.find(row => row.id === input.grantId) ?? null : null;
    const chainRefusal = input.chain ? await input.chain(tx) : undefined;
    // A consuming call (redeem, gate redeem) takes FOR NO KEY UPDATE, so
    // consumers of one approval serialize: two share holders that each insert
    // a consumption and then stamp consumed_at would deadlock, and each could
    // miss the other's consumption when deciding the approval is spent.
    // Revocation (an UPDATE) conflicts with either mode. As Cloud.
    const approval = (await tx.query<ApprovalRow>(
      `SELECT * FROM delegation_approvals WHERE workspace_id = $1 AND id = $2 ${input.consuming ? "FOR NO KEY UPDATE" : "FOR SHARE"}`,
      [input.workspaceId, input.approvalId],
    )).rows[0] ?? null;
    return decide({ member, policy, grant, approval, ...(trustRule !== undefined ? { trustRule } : {}),
      ...(chainRefusal !== undefined ? { chainRefusal } : {}), ...(ownerMember === undefined ? {} : { ownerMember }) }, tx);
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
  if (!state.approval || state.approval.invalidated_at || legacySpentStamp(state.approval)) return "revoked";
  if (input.noGrant) {
    if (time(state.approval.expires_at) <= input.nowMs) return "expired";
    if (state.policy.allowed_classes && input.actions.some(action => !state.policy.allowed_classes!.includes(action.class))) {
      return "out_of_scope";
    }
    return state.policy.code_owner_match !== input.policy.code_owner_match ? "unavailable" : null;
  }
  if (!state.grant || state.grant.status === "revoked") return "revoked";
  // The grant's owner left (their membership was read under its share lock).
  if (state.ownerMember === false) return "revoked";
  // A rule-backed grant lives only while its rule does, read under the rule's share lock.
  if (state.grant.trust_rule_id && (!state.trustRule || state.trustRule.id !== state.grant.trust_rule_id ||
      state.trustRule.revoked_at)) return "revoked";
  // The delegate's ownership chain, re-read with its rows share-locked.
  if (state.chainRefusal) return state.chainRefusal;
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

    const prove = trustProver(deps, workspace, true);
    let found = liveGrant(await grantsFor(deps.database, workspace.id, approval.owner_id, senderId!), now);
    // No live grant of the owner's own (an unexpired owner-made grant always
    // wins): the owner's trust rule may cover the sender by ownership.
    if (typeof found === "string") found = await ruleBackedGrant(deps, workspace, prove, approval.owner_id, senderId!) ?? found;
    if (typeof found === "string") return refuse(found);
    let grant = found;
    context.grantId = grant.id;
    context.ownerUserId = approval.owner_id;
    let unbound = await delegateStillBound(deps, workspace, grant, true, { prove });
    // A system grant whose chain changed was just retired: the rule covers the
    // sender again through the chain proven now, in this same call (as in Cloud).
    if (unbound === "revoked" && await chainChanged(prove, grant)) {
      const replaced = await ruleBackedGrant(deps, workspace, prove, grant.owner_user_id, senderId!);
      if (replaced && replaced.id !== grant.id) {
        grant = replaced;
        context.grantId = grant.id;
        unbound = await delegateStillBound(deps, workspace, grant, true, { prove });
      }
    }
    if (unbound) refuse(unbound);
    const current = await currentSystemGrant(deps, workspace, prove, grant);
    if (typeof current === "string") refuse(current);
    if ((current as GrantRow).id !== grant.id) {
      grant = current as GrantRow;
      context.grantId = grant.id;
    }
    const related = await ruleRelationRefusal(prove, grant, recipient.agentId, input.callerUserId);
    if (related) refuse(related);
    // A grant that stands on a proof covers messages only from the proof's
    // records on: a connector reconnected (a new OAuth grant) or a claim made
    // again is never retroactive, even under a grant that already existed.
    const proof = await reliedProof(prove, grant);
    const coveredFrom = Math.max(time(grant.created_at), proof ? trustPathProvenAt(proof.path).getTime() : 0);

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
      if (minted!.invalidated_at || legacySpentStamp(minted!)) refuse("revoked");
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
      if (sentDate.getTime() < coveredFrom - SEND_TIME_SKEW_MS) refuse("predates_grant");
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
    const acting = await actingRefusal(deps, prove, { workspace, actingOwnerId: input.callerUserId,
      actingAgentId: recipient.agentId, grant, tier, actions, now });
    if (acting) refuse(acting);
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
      if (stored!.invalidated_at || legacySpentStamp(stored!) || stored!.grant_id !== grant.id) refuse("revoked");
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
      memberUserIds: [input.callerUserId], grantId: grant.id, approvalId: context.approvalId!,
      trustRuleId: grant.trust_rule_id ?? null, grantOwnerUserId: grant.owner_user_id, chain: chainUnderLock(workspace, grant, proof),
      actingGrants: actingGrantsLock(input.callerUserId, recipient.agentId, grant, tier) },
      async (state, tx) => {
      const stale = freshRefusal(state, { actions, tier, policy, recipientAgentId: recipient.agentId,
        nowMs: deps.now().getTime() });
      if (stale) refuse(stale);
      const actingNow = await actingRefusalLocked(tx, { workspace, actingOwnerId: input.callerUserId,
        actingAgentId: recipient.agentId, grant, tier, actions, now: deps.now() });
      if (actingNow) refuse(actingNow);
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
          quote_source: approval.quote_source ?? null, quoted_at: approval.quoted_at ?? null,
          ...(grant.trust_rule_id ? { trust_rule_id: grant.trust_rule_id } : {}) },
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
  const context: { ownerUserId?: string; grantId?: string; attested?: boolean } = {};
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
    // Only a recipient Control attested this approval to may redeem it.
    const attested = (await deps.database.query<{ grant_id: string; accept: string }>(
      `SELECT grant_id, accept FROM delegation_attestations
        WHERE workspace_id = $1 AND approval_id = $2 AND recipient_agent_id = $3
        ORDER BY issued_at DESC LIMIT 1`,
      [workspace.id, input.approvalId, input.recipientAgentId],
    )).rows[0];
    if (!attested) refuse("no_approval");
    context.attested = true;
    context.ownerUserId = approval!.owner_user_id;
    context.grantId = attested!.grant_id;
    if (approval!.invalidated_at || legacySpentStamp(approval!)) refuse("revoked");
    const grant = (await deps.database.query<GrantRow>(
      "SELECT * FROM delegation_grants WHERE id = $1 AND workspace_id = $2", [attested!.grant_id, workspace.id],
    )).rows[0];
    if (!grant || grant.status === "revoked") refuse("revoked");
    if (grant!.status === "expired" || time(grant!.expires_at) <= now.getTime()) refuse("expired");
    const prove = trustProver(deps, workspace, true);
    const unbound = await delegateStillBound(deps, workspace, grant!, true, { prove });
    if (unbound) refuse(unbound);
    // The attested grant must still be what the bindings decide now: a superseded one redeems nothing.
    const current = await currentSystemGrant(deps, workspace, prove, grant!);
    if (typeof current === "string" || current.id !== grant!.id) refuse("revoked");
    const related = await ruleRelationRefusal(prove, grant!, input.recipientAgentId, input.callerUserId);
    if (related) refuse(related);
    const proof = await reliedProof(prove, grant!);
    if (time(approval!.expires_at) <= now.getTime()) refuse("expired");
    const action = approval!.actions.find(item => item.class === input.action.class && item.target === input.action.target);
    if (!action) refuse("out_of_scope");
    const outOfScope = scopeRefusal([action!], grant!, policy, input.recipientAgentId);
    if (outOfScope) refuse(outOfScope);
    if (approval!.tier === "D" && tierOClasses(policy, grant!).has(action!.class)) refuse("tier_o_required");
    const acting = await actingRefusal(deps, prove, { workspace, actingOwnerId: input.callerUserId,
      actingAgentId: input.recipientAgentId, grant: grant!, tier: approval!.tier, actions: [action!], now });
    if (acting) refuse(acting);
    // A binding's required conditions (Trusted: ci_green and mergeable on a
    // merge) are checked with the action's own conditions, whatever the
    // approval named. relay-control reads no GitHub state, so they answer
    // condition_unavailable here: a binding that requires them fails closed.
    const required: RequiredCondition[] = grant!.trust_rule_id ? requiredConditionsOf(grant!.scopes, action!.class) : [];
    const checkedConditions: Condition[] = [...(action!.conditions ?? []),
      ...required.filter(condition => !(action!.conditions ?? []).some(own => own.type === condition.type)) as Condition[]];
    const standingInput = {
      approvalOwnerId: approval!.owner_user_id, recipientOwnerId: input.callerUserId,
      accept: attested!.accept === "own_owner" ? "own_owner" as const : "code_owners" as const, actions: [action!],
    };
    if (!await standingFor(deps.database, workspace.id, standingInput)) refuse("recipient_policy");
    const singleUse = approval!.single_use || highRisk(action!);
    if (singleUse && await actionConsumed(deps.database, approval!.id, action!)) refuse("consumed");
    const conditions = evaluateConditions(checkedConditions, now);
    if (conditions.kind === "unavailable") refuse("condition_unavailable");
    if (conditions.kind === "unmet") throw new ConditionUnmet(conditions.unmet);
    if (!await memberRole(deps.database, workspace.id, input.callerUserId) ||
        (input.stillAuthorized && !await input.stillAuthorized())) refuse("not_pending");
    // The lookups above take time: the membership, policy, grant and approval
    // are re-checked under locks, and a single-use action is consumed in the
    // same transaction.
    await decideUnderLocks(deps.database, { workspaceId: workspace.id, memberUserIds: [input.callerUserId],
      grantId: grant!.id, approvalId: input.approvalId, consuming: true, trustRuleId: grant!.trust_rule_id ?? null,
      grantOwnerUserId: grant!.owner_user_id, chain: chainUnderLock(workspace, grant!, proof),
      actingGrants: actingGrantsLock(input.callerUserId, input.recipientAgentId, grant!, approval!.tier) },
      async (state, tx) => {
      const stale = freshRefusal(state, { actions: [action!], tier: approval!.tier, policy,
        recipientAgentId: input.recipientAgentId, nowMs: deps.now().getTime() });
      if (stale) refuse(stale);
      const actingNow = await actingRefusalLocked(tx, { workspace, actingOwnerId: input.callerUserId,
        actingAgentId: input.recipientAgentId, grant: grant!, tier: approval!.tier, actions: [action!], now: deps.now() });
      if (actingNow) refuse(actingNow);
      if (input.stillAuthorized && !await input.stillAuthorized(tx)) refuse("not_pending");
      if (!await standingFor(tx, workspace.id, standingInput)) refuse("recipient_policy");
      // The bearer check can itself wait on a session lock (cloud#6603
      // 0592d777c): read the clock again and re-check expiry (and the rest of
      // the locked state) right before consuming.
      const late = freshRefusal(state, { actions: [action!], tier: approval!.tier, policy,
        recipientAgentId: input.recipientAgentId, nowMs: deps.now().getTime() });
      if (late) refuse(late);
      // The acting agent's own authority again, at the time read by this final check: an explicit grant that
      // expired, or an ask-first change, while the bearer check waited decides the answer too.
      const actingLate = await actingRefusalLocked(tx, { workspace, actingOwnerId: input.callerUserId,
        actingAgentId: input.recipientAgentId, grant: grant!, tier: approval!.tier, actions: [action!], now: deps.now() });
      if (actingLate) refuse(actingLate);
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
        data: { action: input.action, consumed: singleUse, conditions: checkedConditions,
          // Who minted the approval: a delegated (Tier D) approval is traceable to its grant and delegate.
          tier: approval!.tier, minter: { grant_id: grant!.id, delegate_agent_id: grant!.delegate_agent_id,
            owner_id: grant!.owner_user_id, ...(grant!.trust_rule_id ? { binding_id: grant!.trust_rule_id } : {}) } },
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
    // As Cloud (cloud#6501 8939eb6c2): a refusal is audited only once the
    // approval is known to have been attested to this recipient. Before that
    // (an unknown approval, or one never attested to it) it is logged only:
    // Tier D ids derive from a message id, so another member's agent could
    // otherwise write rows into the approval owner's audit view. An identical
    // audited refusal (approval, recipient, action, reason) is written once per
    // 10 minutes; repeats are still logged.
    const repeated = context.attested && await redeemRefusedRecently(deps.database, { workspaceId: workspace.id,
      approvalId: input.approvalId, recipientAgentId: input.recipientAgentId, action: input.action, reason })
      .catch(() => false);
    if (context.attested && !repeated) await recordDelegationAudit(deps.database, {
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
  const prove = trustProver(deps, workspace, true);
  // The owner's trust rule covers connected assistants that may not have a
  // system grant yet (it is created at their first attested approval): prove
  // and create one for each root now, so turning the rule on makes them prompt
  // delegates at once. Roots only: agents they launch are workers, not
  // approvers, and are not sent every prompt. One root that cannot be read is
  // skipped (and logged), not the whole list.
  if (await hasLiveBindings(deps.database, workspace.id, session.userId)) {
    for (const agentId of await listTrustRootAgents(deps.database, workspace, session.userId)) {
      if (agentId === session.agentId) continue;
      await ruleBackedGrant(deps, workspace, prove, session.userId, agentId).catch((error: unknown) => {
        logUnavailable("prompt_delegates", error, { workspaceId: workspace.id });
        return null;
      });
    }
  }
  const grants = (await deps.database.query<GrantRow>(
    `SELECT * FROM delegation_grants
      WHERE workspace_id = $1 AND owner_user_id = $2 AND status = 'active' AND expires_at > now()
      ORDER BY created_at`,
    [workspace.id, session.userId],
  )).rows.filter(grant => grant.scopes.some(scope => scope.class === "prompt_approval") ||
    (grant.trust_rule_id && !grant.scopes.length));
  const delegates: Array<{ agent_id: string; grant_id: string }> = [];
  for (const grant of grants) {
    if (!grantFitsPolicy(grant, policy)) continue;
    // Under the rule only roots are prompt delegates: a launched worker that
    // has a system grant (from an approval it carried) is not sent every prompt.
    if (grant.trust_rule_id && grant.trust_path?.hops.length) continue;
    // Not the session's own agent: a delegate never answers its own prompts.
    // This holds under the trust rule too, although it allows a bot to approve
    // its own requests: this list only picks who is sent a session's approval
    // DM, and a session asking itself would loop.
    if (grant.delegate_agent_id === session.agentId) continue;
    if (!grantCovers(grant, { class: "prompt_approval", target: `${session.agentId}:probe:approve` })) continue;
    // A released or re-bound agent is never offered (its grant is revoked, as
    // at attestation). One grant whose binding cannot be read is skipped (and
    // logged), not the whole list, as Cloud.
    const unbound = await delegateStillBound(deps, workspace, grant, true, { prove }).catch((error: unknown) => {
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
      if (status === 404) {
        const body = await response.json().catch(() => null) as { error?: { code?: unknown } } | null;
        return { outcome: body?.error?.code === "owner_approval_not_found" ? "absent" : "retry", status };
      }
      // Only the status matters on every other answer: release the body.
      await drainBody(response, "delegation.relaycast_redact_quote");
      if (status >= 200 && status < 300) return { outcome: "redacted", status };
      if (status === 429 || status >= 500) return { outcome: "retry", status };
      return { outcome: "rejected", status };
    } catch {
      return { outcome: "retry", status: null };
    }
  };
}

// ---------------------------------------------------------------- trust rules

/** Most roots one owner can have considered at once (prompt delegate discovery). */
export const MAX_TRUST_ROOTS = 20;

/**
 * Candidate roots of an owner's trust rule: agents of the owner's completed,
 * unreleased claims, and agents the owner's live connector grants are pinned
 * to that the owner holds as a hosted participant here. Each is still only a
 * candidate: coverage is decided by resolveTrustPath.
 */
export async function listTrustRootAgents(executor: SqlExecutor, workspace: DelegationWorkspace, ownerUserId: string):
  Promise<string[]> {
  const rows = (await executor.query<{ agent_id: string }>(
    `(SELECT b.agent_id FROM delegation_agent_bindings b JOIN delegation_claims c ON c.id = b.claim_id
       WHERE b.workspace_id = $1 AND b.relaycast_workspace_id = $2 AND b.user_id = $3
         AND c.consumed_at IS NOT NULL AND c.released_at IS NULL
       ORDER BY b.agent_id LIMIT $4)
     UNION
     (SELECT DISTINCT p.agent_remote_id FROM mcp_oauth_grants g
        JOIN hosted_relay_participants p ON p.workspace_id = g.workspace_id AND p.user_id = g.user_id
         AND p.agent_remote_id = g.agent_remote_id AND p.relaycast_workspace_id = $2
       WHERE g.workspace_id = $1 AND g.user_id = $3 AND g.revoked_at IS NULL AND g.agent_remote_id IS NOT NULL
       ORDER BY p.agent_remote_id LIMIT $4)`,
    [workspace.id, workspace.relaycastWorkspaceId, ownerUserId, MAX_TRUST_ROOTS],
  )).rows;
  return [...new Set(rows.map(row => row.agent_id))].slice(0, MAX_TRUST_ROOTS);
}

/** The trust rule's owner is no longer a member of the workspace's organization. */
export class TrustRuleMembershipGone extends Error {
  constructor() {
    super("forbidden");
  }
}

/** Delegation is off for the workspace: a rule is never turned on then. */
export class TrustRuleNotEnabled extends Error {
  constructor() {
    super("not_enabled");
  }
}

/** A legacy rule: the set-once trust rule from before roles (`all_agents`, no role). */
const LEGACY_RULE = "principal_kind = 'all_agents' AND role IS NULL";

/** The owner's live legacy trust rule in this workspace, if any (role bindings are listed by listBindings). */
export async function liveTrustRule(executor: SqlExecutor, workspaceId: string, ownerUserId: string): Promise<TrustRuleRow | null> {
  return (await executor.query<TrustRuleRow>(
    `SELECT * FROM delegation_trust_rules WHERE workspace_id = $1 AND owner_user_id = $2 AND revoked_at IS NULL AND ${LEGACY_RULE}`,
    [workspaceId, ownerUserId],
  )).rows[0] ?? null;
}

/** Whether the owner has any live binding, so the trust rule may cover one of their agents. */
export async function hasLiveBindings(executor: SqlExecutor, workspaceId: string, ownerUserId: string): Promise<boolean> {
  return (await executor.query(
    "SELECT 1 FROM delegation_trust_rules WHERE workspace_id = $1 AND owner_user_id = $2 AND revoked_at IS NULL LIMIT 1",
    [workspaceId, ownerUserId],
  )).rows.length > 0;
}

/** One rule by id (live or revoked). */
export async function getTrustRule(executor: SqlExecutor, workspaceId: string, ruleId: string): Promise<TrustRuleRow | null> {
  return (await executor.query<TrustRuleRow>(
    "SELECT * FROM delegation_trust_rules WHERE workspace_id = $1 AND id = $2", [workspaceId, ruleId],
  )).rows[0] ?? null;
}

/** The active system grants a rule created: the agents it covers now. */
export async function ruleGrants(executor: SqlExecutor, workspaceId: string, ruleId: string): Promise<GrantRow[]> {
  return (await executor.query<GrantRow>(
    `SELECT * FROM delegation_grants WHERE workspace_id = $1 AND trust_rule_id = $2 AND status = 'active'
      ORDER BY created_at, id`, [workspaceId, ruleId],
  )).rows;
}

const sameClasses = (a: readonly string[], b: readonly string[]) => a.length === b.length && a.every(item => b.includes(item));

/**
 * Turns the owner's trust rule on, or updates its Tier O list (PUT is
 * idempotent), as Cloud's putTrustRule. Locks in the one order: the owner's
 * membership (a departure either commits first and refuses this, or waits),
 * the policy (delegation turned off meanwhile refuses this), then the rule.
 * A Tier O change reaches every system grant of the rule in the same
 * transaction (rule, then grants by id).
 */
export async function putTrustRule(database: Database, input: { workspaceId: string; ownerUserId: string;
  requireTierO: ActionClass[]; authMethod: string }): Promise<{ rule: TrustRuleRow; created: boolean }> {
  const run = () => database.transaction(async (tx) => {
    if (!await memberRole(tx, input.workspaceId, input.ownerUserId, true)) throw new TrustRuleMembershipGone();
    // The owner's binding lock, after membership (as every binding write): serializes with createBinding.
    await lockOwnerBindings(tx, input.workspaceId, input.ownerUserId, "exclusive");
    if (!(await loadPolicy(tx, input.workspaceId, true)).delegation_enabled) throw new TrustRuleNotEnabled();
    // The legacy rule and a Relay agents binding never stand together: the
    // binding replaced the rule, and a new legacy rule would cover the spawn
    // tree again at the lowest precedence (as Cloud).
    const relay = (await tx.query<{ id: string }>(
      `SELECT id FROM delegation_trust_rules WHERE workspace_id = $1 AND owner_user_id = $2 AND principal_kind = 'relay_agents'
          AND revoked_at IS NULL LIMIT 1`, [input.workspaceId, input.ownerUserId],
    )).rows[0];
    if (relay) throw new BindingExists(relay.id);
    const locked = (await tx.query<TrustRuleRow>(
      `SELECT * FROM delegation_trust_rules WHERE workspace_id = $1 AND owner_user_id = $2 AND revoked_at IS NULL AND ${LEGACY_RULE}
        FOR UPDATE`,
      [input.workspaceId, input.ownerUserId],
    )).rows[0];
    if (!locked) {
      const row = (await tx.query<TrustRuleRow>(
        `INSERT INTO delegation_trust_rules (id, workspace_id, owner_user_id, require_tier_o) VALUES ($1, $2, $3, $4) RETURNING *`,
        [mintId("dtr"), input.workspaceId, input.ownerUserId, input.requireTierO],
      )).rows[0]!;
      await recordDelegationAudit(tx, { workspaceId: input.workspaceId, event: "trust_rule.created",
        actorUserId: input.ownerUserId, authMethod: input.authMethod, ownerUserId: input.ownerUserId,
        data: { trust_rule_id: row.id, require_tier_o: input.requireTierO } });
      return { rule: row, created: true };
    }
    if (sameClasses(locked.require_tier_o, input.requireTierO)) return { rule: locked, created: false };
    const row = (await tx.query<TrustRuleRow>(
      "UPDATE delegation_trust_rules SET require_tier_o = $2, updated_at = now() WHERE id = $1 RETURNING *",
      [locked.id, input.requireTierO],
    )).rows[0]!;
    const grants = (await tx.query<{ id: string }>(
      `SELECT id FROM delegation_grants WHERE trust_rule_id = $1 AND status = 'active' ORDER BY id FOR UPDATE`, [locked.id],
    )).rows.map(grant => grant.id);
    if (grants.length) {
      await tx.query("UPDATE delegation_grants SET require_tier_o = $2, updated_at = now() WHERE id = ANY($1::text[])",
        [grants, input.requireTierO]);
    }
    await recordDelegationAudit(tx, { workspaceId: input.workspaceId, event: "trust_rule.updated",
      actorUserId: input.ownerUserId, authMethod: input.authMethod, ownerUserId: input.ownerUserId,
      data: { trust_rule_id: locked.id, require_tier_o: { before: locked.require_tier_o, after: input.requireTierO },
        updated_grants: grants } });
    return { rule: row, created: false };
  });
  try {
    return await run();
  } catch (error) {
    // Two concurrent first PUTs: the live-owner index decides, and the loser reads the winner's rule.
    if ((error as { code?: string })?.code === "23505") return run();
    throw error;
  }
}

/**
 * Revokes live trust rules (one owner's, or every owner's for an admin
 * revoke-all) and every active system grant they created, with those grants'
 * unredeemed and gate-spent approvals (revokeGrants), in the caller's
 * transaction. Rules are locked FOR UPDATE by id before any grant, so a
 * decision or a materialize holding a rule share lock finishes first and is
 * then revoked here, and one that starts later sees the revoked rule. Each
 * rule carries the ids of the grants revoked here, under its lock.
 */
export async function revokeTrustRulesTx(tx: SqlExecutor, input: { workspaceId: string; ownerUserId: string | null;
  ruleId?: string; actorUserId: string | null; authMethod: string | null; reason: string }):
  Promise<Array<TrustRuleRow & { revokedGrants: string[] }>> {
  const rules = await lockLiveRules(tx, input);
  if (!rules.length) return [];
  const grantIds = (await tx.query<{ id: string }>(
    `SELECT id FROM delegation_grants WHERE workspace_id = $1 AND trust_rule_id = ANY($2::text[]) AND status = 'active'
      ORDER BY id FOR UPDATE`,
    [input.workspaceId, rules.map(rule => rule.id)],
  )).rows.map(row => row.id);
  const revoked = await revokeGrants(tx, { workspaceId: input.workspaceId, grantIds, actorUserId: input.actorUserId,
    reason: "trust_rule_revoked", authMethod: input.authMethod });
  return stampRulesRevoked(tx, rules, revoked, input);
}

/** Locks the live rules of a scope FOR UPDATE, by id: always before any grant. */
async function lockLiveRules(tx: SqlExecutor, input: { workspaceId: string; ownerUserId: string | null; ruleId?: string }):
  Promise<TrustRuleRow[]> {
  return (await tx.query<TrustRuleRow>(
    `SELECT * FROM delegation_trust_rules
      WHERE workspace_id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR owner_user_id = $2)
        AND ($3::text IS NULL OR id = $3)
      ORDER BY id FOR UPDATE`,
    [input.workspaceId, input.ownerUserId, input.ruleId ?? null],
  )).rows;
}

/**
 * Stamps locked rules revoked and audits each `trust_rule.revoked` with the
 * system grants of that rule revoked in this transaction (by id and count).
 */
async function stampRulesRevoked(tx: SqlExecutor, rules: TrustRuleRow[], revoked: GrantRow[],
  input: { workspaceId: string; actorUserId: string | null; authMethod: string | null; reason: string }):
  Promise<Array<TrustRuleRow & { revokedGrants: string[] }>> {
  if (!rules.length) return [];
  const byRule = new Map<string, string[]>();
  for (const grant of revoked) {
    if (grant.trust_rule_id) byRule.set(grant.trust_rule_id, [...(byRule.get(grant.trust_rule_id) ?? []), grant.id]);
  }
  const updated = (await tx.query<TrustRuleRow>(
    `UPDATE delegation_trust_rules SET revoked_at = clock_timestamp(), revoked_reason = $2, revoked_by_user_id = $3,
        updated_at = clock_timestamp()
      WHERE id = ANY($1::text[]) RETURNING *`,
    [rules.map(rule => rule.id), input.reason, input.actorUserId && UUID.test(input.actorUserId) ? input.actorUserId : null],
  )).rows;
  for (const rule of updated) {
    const grants = byRule.get(rule.id) ?? [];
    const legacy = rule.role === null || rule.role === undefined;
    await recordDelegationAudit(tx, { workspaceId: input.workspaceId, event: legacy ? "trust_rule.revoked" : "binding.revoked",
      actorUserId: input.actorUserId, authMethod: input.authMethod, ownerUserId: rule.owner_user_id, reason: input.reason,
      data: { trust_rule_id: rule.id, ...(legacy ? {} : bindingAudit(rule)), revoked_grants: grants, count: grants.length } });
  }
  return updated.map(rule => ({ ...rule, revokedGrants: byRule.get(rule.id) ?? [] }));
}

/**
 * One-click revoke of an owner's rule (the owner, or an admin for any owner):
 * the rule, its system grants and their unredeemed and gate-spent approvals,
 * in one transaction. Null when there is no live rule.
 */
export async function revokeTrustRule(database: Database, input: { workspaceId: string; ownerUserId: string;
  actorUserId: string; authMethod: string; reason: string }): Promise<{ rule: TrustRuleRow; revokedGrants: string[] } | null> {
  return database.transaction(async (tx) => {
    // Only the legacy rule: the owner's role bindings are revoked one by one (revokeBinding).
    const legacy = await liveTrustRule(tx, input.workspaceId, input.ownerUserId);
    if (!legacy) return null;
    const [rule] = await revokeTrustRulesTx(tx, { ...input, ruleId: legacy.id });
    if (!rule) return null;
    const { revokedGrants, ...record } = rule;
    return { rule: record, revokedGrants };
  });
}

// ---------------------------------------------------------------- role bindings

/** The revoke reason of a system grant whose deciding binding or authority changed: the binding re-resolves it. */
export const SUPERSEDED_BY_RULE = "superseded_by_rule";

/** An exclusion's fields: nothing. */
const EXCLUDED_FIELDS: BindingFields = { role: "excluded", classes: [], requireTierO: [], prOpsLimit: null, requiredConditions: {},
  targets: null, expiresAt: null };

/**
 * The binding columns a write sets, in bindingValues' order. Every write
 * that changes authority stamps its time with clock_timestamp(), read after
 * the owner's binding lock, never now() (the transaction's start): a
 * message sent while the write waited on the lock is never newer than the
 * change that first authorized it.
 */
const BINDING_COLUMNS = "role, classes, require_tier_o, pr_ops_limit, required_conditions, targets, expires_at";

function bindingValues(fields: BindingFields): unknown[] {
  return [fields.role, fields.classes, fields.requireTierO, fields.prOpsLimit, JSON.stringify(fields.requiredConditions),
    fields.targets, fields.expiresAt];
}

const PRINCIPAL_SET = new Set<string>(PRINCIPAL_KINDS);
const ROLE_SET = new Set<string>(ROLES);
const OP_SET = new Set<string>(PR_OPS_OPS);
const CONDITION_SET = new Set<string>(REQUIRED_CONDITION_TYPES);
const CLASS_SET = new Set<string>(ACTION_CLASSES);

function requiredConditionsFrom(value: Record<string, Array<{ type: string }>> | null | undefined): RequiredConditions {
  const result: RequiredConditions = {};
  for (const [key, list] of Object.entries(value ?? {})) {
    if (!CLASS_SET.has(key) || !Array.isArray(list)) continue;
    const kept = list.filter(item => CONDITION_SET.has(item?.type)).map(item => ({ type: item.type })) as RequiredCondition[];
    if (kept.length) result[key as ActionClass] = kept;
  }
  return result;
}

/**
 * A stored binding as resolution reads it (Cloud's trustRuleFrom). An unknown
 * principal kind or role reads as a binding that covers nothing: principal
 * `agent` with no ref, role `excluded`. A newer build's row never widens an
 * older build.
 */
export function bindingViewOf(row: TrustRuleRow): BindingView {
  const kind = row.principal_kind ?? "all_agents";
  const role = row.role ?? null;
  const known = PRINCIPAL_SET.has(kind) && (role === null || ROLE_SET.has(role));
  const classes = row.classes === null || row.classes === undefined ? null :
    row.classes.filter(item => CLASS_SET.has(item)) as ActionClass[];
  return {
    id: row.id, principalKind: known ? kind as PrincipalKind : "agent", principalRef: known ? row.principal_ref ?? null : null,
    role: known ? role as Role | null : "excluded", classes,
    requireTierO: (row.require_tier_o ?? []).filter(item => CLASS_SET.has(item)) as ActionClass[],
    prOpsLimit: row.pr_ops_limit === null || row.pr_ops_limit === undefined ? null : row.pr_ops_limit.filter(op => OP_SET.has(op)) as PrOp[],
    requiredConditions: requiredConditionsFrom(row.required_conditions), targets: row.targets ?? null,
    expiresAt: row.expires_at ? new Date(row.expires_at) : null,
  };
}

/** Audit data for a binding: its principal and what it grants. */
function bindingAudit(row: TrustRuleRow) {
  const binding = bindingViewOf(row);
  return { binding_id: binding.id, principal_kind: binding.principalKind, principal_ref: binding.principalRef, role: binding.role,
    classes: binding.classes, require_tier_o: binding.requireTierO, pr_ops_limit: binding.prOpsLimit,
    required_conditions: binding.requiredConditions, targets: binding.targets, expires_at: binding.expiresAt?.toISOString() ?? null };
}

/**
 * Serializes one owner's binding writes (exclusive) with every
 * materialization for that owner (shared), as Cloud's lockOwnerBindings: a
 * transaction-scoped advisory lock. The lock order is:
 * 1. the owner's membership (share), when there is one;
 * 2. this lock;
 * 3. the policy, the owner's binding rows, the delegate's creation lock
 *    (lockDelegateAgent), then grant rows by id.
 * A materialization therefore decides on the bindings and groups as they
 * stand once every earlier write committed, and a write that starts later
 * re-resolves the grant it created.
 */
async function lockOwnerBindings(tx: SqlExecutor, workspaceId: string, ownerUserId: string, mode: "shared" | "exclusive"):
  Promise<void> {
  await tx.query(mode === "shared" ? "SELECT pg_advisory_xact_lock_shared(hashtextextended($1, 0))" :
    "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", [`delegation-bindings:${workspaceId}:${ownerUserId}`]);
}

/** One owner's live bindings and which of their custom groups each agent is a live member of. */
export type BindingState = { rows: TrustRuleRow[]; bindings: BindingView[]; groupsOf(agentId: string): string[];
  /** When the agent joined one of the owner's groups (null when it is not a live member). */
  memberSince(agentId: string, groupId: string): Date | null };

export async function bindingState(executor: SqlExecutor, workspaceId: string, ownerUserId: string,
  lock?: "share" | "update"): Promise<BindingState> {
  const rows = (await executor.query<TrustRuleRow>(
    `SELECT * FROM delegation_trust_rules WHERE workspace_id = $1 AND owner_user_id = $2 AND revoked_at IS NULL
      ORDER BY id${lock === "share" ? " FOR SHARE" : lock === "update" ? " FOR UPDATE" : ""}`,
    [workspaceId, ownerUserId],
  )).rows;
  const members = (await executor.query<{ group_id: string; agent_id: string; added_at: Date | string }>(
    `SELECT m.group_id, m.agent_id, m.added_at FROM delegation_group_members m JOIN delegation_groups g ON g.id = m.group_id
      WHERE g.workspace_id = $1 AND g.owner_user_id = $2 AND g.revoked_at IS NULL AND m.removed_at IS NULL`,
    [workspaceId, ownerUserId],
  )).rows;
  const byAgent = new Map<string, string[]>();
  const since = new Map<string, Date>();
  for (const row of members) {
    byAgent.set(row.agent_id, [...(byAgent.get(row.agent_id) ?? []), row.group_id]);
    since.set(`${row.agent_id}\u0000${row.group_id}`, new Date(row.added_at));
  }
  return { rows, bindings: rows.map(bindingViewOf), groupsOf: agentId => byAgent.get(agentId) ?? [],
    memberSince: (agentId, groupId) => since.get(`${agentId}\u0000${groupId}`) ?? null };
}

/**
 * The acting agent's own authority, read inside a deciding transaction (as
 * Cloud's actingAuthorityLocked): the owner's binding lock (shared), so a
 * binding or group write either committed before this read or waits for the
 * decision. The agent's active owner-made grants from that owner are
 * already share-locked: decideUnderLocks `actingGrants` takes them in its one
 * id-ordered grant pass (review of cloud#6672). Waiting for a grant lock here,
 * after the minter's grant, could deadlock with revoke-all, so this read locks
 * FOR SHARE NOWAIT (Cloud's, review of cloud#6674): a grant the pass locked is
 * taken again at once; one created since is locked now, so a Tier O change to
 * it waits for this decision; one a writer holds fails the read with 55P03,
 * answered `unavailable`. The owner-made grant's Tier O list when there is
 * one, else the owner's binding state.
 */
export async function actingAuthorityLocked(tx: SqlExecutor, input: { workspaceId: string; ownerUserId: string; agentId: string;
  now: Date }): Promise<{ own: ActionClass[] | null; state: BindingState }> {
  await lockOwnerBindings(tx, input.workspaceId, input.ownerUserId, "shared");
  const rows = (await tx.query<GrantRow>(
    `SELECT * FROM delegation_grants WHERE workspace_id = $1 AND owner_user_id = $2 AND delegate_agent_id = $3
        AND status = 'active' AND trust_rule_id IS NULL ORDER BY id FOR SHARE NOWAIT`,
    [input.workspaceId, input.ownerUserId, input.agentId],
  )).rows;
  const own = rows.find(grant => time(grant.expires_at) > input.now.getTime());
  return { own: own ? own.require_tier_o : null, state: await bindingState(tx, input.workspaceId, input.ownerUserId) };
}

/**
 * When a covering decision's authority began (Cloud's decisionSince): the
 * latest creation or change of every binding that contributed. For a custom
 * group that also includes the moment the agent joined each deciding group.
 * A system grant is never dated before it. A legacy rule counts only its
 * creation: its Tier O PUT updates its grants in place and never re-dated
 * them before roles, so it does not date a new grant now.
 */
/**
 * The latest change to anything that decides for one owner's agents (Cloud's
 * ownerChangeFloor): a role binding created, changed, revoked or expired; a
 * group revoked; a member added or removed. A legacy rule's own Tier O change
 * is left out, as in decisionSince. A new system grant is never dated before
 * it. Removing or outliving a more specific, restrictive binding (an
 * exclusion, a Read-only group) must not cover an approval the agent sent
 * while that restriction still decided, even when the agent had no grant yet.
 * Owner-wide on purpose: it never needs to know which binding decided before.
 */
async function ownerChangeFloor(tx: SqlExecutor, workspaceId: string, ownerUserId: string, now: Date): Promise<number> {
  const rules = (await tx.query<{ changed: Date | string | null }>(
    `SELECT max(greatest(
        CASE WHEN role IS NULL AND principal_kind = 'all_agents' THEN created_at ELSE updated_at END,
        revoked_at,
        CASE WHEN expires_at <= $3::timestamptz THEN expires_at END)) AS changed
       FROM delegation_trust_rules WHERE workspace_id = $1 AND owner_user_id = $2`,
    [workspaceId, ownerUserId, now],
  )).rows[0];
  const groups = (await tx.query<{ changed: Date | string | null }>(
    `SELECT max(greatest(g.revoked_at, m.added_at, m.removed_at)) AS changed
       FROM delegation_groups g LEFT JOIN delegation_group_members m ON m.group_id = g.id
      WHERE g.workspace_id = $1 AND g.owner_user_id = $2`,
    [workspaceId, ownerUserId],
  )).rows[0];
  const at = (value: Date | string | null | undefined) => value ? new Date(value).getTime() : 0;
  return Math.max(at(rules?.changed), at(groups?.changed));
}

function decisionSince(state: BindingState, decision: Decision, agentId: string): number {
  if (decision.kind !== "covered") return 0;
  const now = Date.now();
  const contributing = decision.source === "group" ? state.rows.filter(row => {
    const view = bindingViewOf(row);
    return view.principalKind === "group" && view.principalRef !== null && state.groupsOf(agentId).includes(view.principalRef) &&
      (!view.expiresAt || view.expiresAt.getTime() > now);
  }) : state.rows.filter(row => row.id === decision.binding.id);
  return Math.max(0, ...contributing.flatMap(row => [time(row.created_at),
    ...(decision.binding.role === null ? [] : [time(row.updated_at)]),
    ...(decision.source === "group" ? [state.memberSince(agentId, row.principal_ref!)?.getTime() ?? Number.MAX_SAFE_INTEGER] : [])]));
}

/** Which binding decides for one agent of the owner whose chain is `path` (roles.ts decide). */
export function decideFor(state: BindingState, agentId: string, path: TrustPath, now: Date): Decision {
  return decide(state.bindings, { agentId, path, groupIds: state.groupsOf(agentId) }, now);
}

/**
 * Whether a legacy rule's pre-roles exclusion still stands for one agent. A
 * pre-roles exclusion lives only on a revoked grant row (OWNER_EXCLUDED).
 * Once the agent has had an agent binding (any exclusion since roles creates
 * one, and a conversion carries the old ones), that binding decides: an owner
 * who removed it lifted the exclusion, also under a legacy rule. Shared by
 * materializeRuleGrant and the acting agent's ask-first reads, so an agent the
 * legacy rule excludes never inherits its ask-first list (review of cloud#6672).
 */
async function legacyExcludedOn(db: SqlExecutor, input: { workspaceId: string; ownerUserId: string; agentId: string;
  ruleId: string }): Promise<boolean> {
  const ownBinding = (await db.query(
    `SELECT 1 FROM delegation_trust_rules WHERE workspace_id = $1 AND owner_user_id = $2 AND principal_kind = 'agent'
        AND principal_ref = $3 LIMIT 1`, [input.workspaceId, input.ownerUserId, input.agentId],
  )).rows.length > 0;
  if (ownBinding) return false;
  return (await db.query(
    `SELECT 1 FROM delegation_grants
      WHERE workspace_id = $1 AND owner_user_id = $2 AND delegate_agent_id = $3 AND trust_rule_id = $4
        AND status = 'revoked' AND revoked_reason = $5 LIMIT 1`,
    [input.workspaceId, input.ownerUserId, input.agentId, input.ruleId, OWNER_EXCLUDED],
  )).rows.length > 0;
}

/**
 * Which binding decides for one agent, with a legacy rule's pre-roles
 * exclusion applied (Cloud's decideWithLegacyExclusion): an agent the legacy
 * rule excluded reads as excluded.
 */
export async function decideWithLegacyExclusion(db: SqlExecutor, state: BindingState, input: { workspaceId: string;
  ownerUserId: string; agentId: string; path: TrustPath; now: Date }): Promise<Decision> {
  const decision = decideFor(state, input.agentId, input.path, input.now);
  if (decision.kind !== "covered" || decision.source !== "legacy") return decision;
  return await legacyExcludedOn(db, { workspaceId: input.workspaceId, ownerUserId: input.ownerUserId, agentId: input.agentId,
    ruleId: decision.binding.id }) ? { kind: "excluded", binding: decision.binding } : decision;
}

type GrantShape = { binding: BindingView; authority: Authority; scopes: Scope[]; requireTierO: ActionClass[]; expiresAt: Date };

/** The system grant a covering decision stands for. Null when it covers nothing (roles.ts coversNothing, review B1 on cloud#6665). */
function grantShape(decision: Decision): GrantShape | null {
  if (decision.kind !== "covered") return null;
  const { authority } = decision;
  if (coversNothing(authority)) return null;
  return { binding: decision.binding, authority, scopes: systemScopes(authority), requireTierO: grantedTierO(authority),
    expiresAt: authority.expiresAt ?? TRUST_RULE_GRANT_EXPIRY };
}

/** Whether a system grant is exactly what a decision stands for now (binding, scopes, Tier O and expiry). */
function grantMatches(grant: GrantRow, shape: GrantShape): boolean {
  return grant.trust_rule_id === shape.binding.id && sameScopes(grant.scopes, shape.scopes) &&
    grant.require_tier_o.length === shape.requireTierO.length && shape.requireTierO.every(item => grant.require_tier_o.includes(item)) &&
    time(grant.expires_at) === shape.expiresAt.getTime();
}

/**
 * Re-resolves every active system grant of one owner against the bindings as
 * they now stand, in the caller's transaction, which already holds the
 * owner's exclusive binding lock (Cloud's reresolveOwnerGrants). A grant whose
 * deciding binding, scopes, Tier O list or expiry would change is revoked
 * with its approvals:
 * - an agent now excluded ends as owner_excluded;
 * - any other change ends as superseded_by_rule, and the agent's next use
 *   materializes the new grant.
 * Only stored rows are read (each grant keeps its proven chain), so a
 * narrowing takes effect at once.
 */
async function reresolveOwnerGrants(tx: SqlExecutor, input: { workspaceId: string; ownerUserId: string;
  actorUserId: string | null; authMethod: string | null; onlyAgent?: string }): Promise<string[]> {
  const now = new Date();
  const state = await bindingState(tx, input.workspaceId, input.ownerUserId);
  const grants = (await tx.query<GrantRow>(
    `SELECT * FROM delegation_grants WHERE workspace_id = $1 AND owner_user_id = $2 AND status = 'active'
        AND trust_rule_id IS NOT NULL AND ($3::text IS NULL OR delegate_agent_id = $3)
      ORDER BY id FOR UPDATE`,
    [input.workspaceId, input.ownerUserId, input.onlyAgent ?? null],
  )).rows;
  const byReason = new Map<string, string[]>();
  for (const grant of grants) {
    const decision: Decision = grant.trust_path ? decideFor(state, grant.delegate_agent_id, grant.trust_path, now) : { kind: "none" };
    const shape = grantShape(decision);
    if (shape && grantMatches(grant, shape)) continue;
    const reason = decision.kind === "excluded" ? OWNER_EXCLUDED : SUPERSEDED_BY_RULE;
    byReason.set(reason, [...(byReason.get(reason) ?? []), grant.id]);
  }
  const revoked: string[] = [];
  for (const [reason, grantIds] of byReason) {
    for (const row of await revokeGrants(tx, { workspaceId: input.workspaceId, grantIds, actorUserId: input.actorUserId,
      reason, authMethod: input.authMethod })) revoked.push(row.id);
  }
  return revoked;
}

/**
 * Creates (or returns) the system grant through which one of the owner's
 * bindings covers one proven agent, in one transaction (Cloud's
 * materializeRuleGrant).
 *
 * The lock order is:
 * 1. the owner's membership (share);
 * 2. the owner's binding lock (shared);
 * 3. the policy;
 * 4. every live binding of the owner (share);
 * 5. the agent's creation lock and the pair's grants by id (as an owner-made
 *    grant and a claim release take them);
 * 6. a claim root's claim.
 * Under those locks the deciding binding is chosen (roles.ts decide).
 * `ruleId`, when given, must be the binding that decides.
 *
 * - A live owner-made grant wins and is returned instead.
 * - An active system grant that no longer matches the decision is retired
 *   (superseded_by_rule) and replaced.
 * - Lapsed owner-made grants of the pair expire here first.
 * - An agent a person excluded from a legacy rule before bindings existed is
 *   not covered again by that rule.
 * - Concurrent first materializes converge on one grant through the
 *   active-pair unique index.
 *
 * Null when nothing covers the agent: an `excluded` binding, no binding, or
 * a binding that covers nothing.
 */
export async function materializeRuleGrant(database: Database, input: { workspace: DelegationWorkspace; ruleId?: string;
  ownerUserId: string; delegateAgentId: string; delegateAgentName: string; trustPath: TrustPath; provenAt: Date;
  claimId?: string;
  /** Test hook: runs once the binding and grant locks are held. */
  onLocked?: () => Promise<void>;
  /** Test hook: runs after a first decision that covers nothing, before the grant locks. */
  onUncovered?: () => Promise<void> }): Promise<GrantRow | null> {
  const { workspace } = input;
  const pair = [workspace.id, input.ownerUserId, input.delegateAgentId];
  const run = () => database.transaction(async (tx): Promise<GrantRow | null> => {
    if (!await memberRole(tx, workspace.id, input.ownerUserId, true)) return null;
    await lockOwnerBindings(tx, workspace.id, input.ownerUserId, "shared");
    if (!(await loadPolicy(tx, workspace.id, true)).delegation_enabled) return null;
    const state = await bindingState(tx, workspace.id, input.ownerUserId, "share");
    let decision = decideFor(state, input.delegateAgentId, input.trustPath, new Date());
    let shape = grantShape(decision);
    if (!shape) {
      // Nothing covers the agent, yet it may still hold a system grant from
      // before resolution changed (a worker whose spawn default now leaves it
      // no usable action): that grant is retired with its approvals, so the
      // binding no longer lists the agent as covered (Cloud, review of
      // cloud#6676).
      await input.onUncovered?.();
      await lockGrantAndClaims(tx, workspace.id, input.ownerUserId, input.delegateAgentId);
      const held = (await tx.query<{ id: string; trust_rule_id: string | null; expires_at: Date; trust_path: TrustPath | null }>(
        `SELECT id, trust_rule_id, expires_at, trust_path FROM delegation_grants
          WHERE workspace_id = $1 AND owner_user_id = $2 AND delegate_agent_id = $3 AND status = 'active' ORDER BY id`, pair,
      )).rows;
      // Decided again once those grants are locked (review of cloud#6681):
      // every grant read here was committed before this time, and a binding
      // only ever expires, so a grant another attest made after a restrictive
      // binding lapsed is covered again here and is kept.
      const at = new Date();
      decision = decideFor(state, input.delegateAgentId, input.trustPath, at);
      shape = grantShape(decision);
      if (!shape) {
        // Left alone: an owner-made grant; a lapsed one, which the expiry
        // sweep ends without cancelling the owner approvals carried under it;
        // and one standing on another chain, which its own chain check
        // re-proves (review of relay-control#346).
        const stale = held.filter(row => row.trust_rule_id && new Date(row.expires_at).getTime() > at.getTime() &&
          (!row.trust_path || trustPathFingerprint(row.trust_path) === trustPathFingerprint(input.trustPath)));
        if (stale.length) {
          await revokeGrants(tx, { workspaceId: workspace.id, grantIds: stale.map(row => row.id), actorUserId: null,
            reason: BINDING_CHANGED, authMethod: "system" });
        }
        return null;
      }
    }
    const covered = shape;
    if (input.ruleId && covered.binding.id !== input.ruleId) return null;
    const rule = state.rows.find(row => row.id === covered.binding.id)!;
    await lockGrantAndClaims(tx, workspace.id, input.ownerUserId, input.delegateAgentId);
    if (input.claimId) {
      // A claim root: its claim is re-read under its lock (releaseClaim's order).
      const claim = (await tx.query<{ released_at: Date | null }>(
        "SELECT released_at FROM delegation_claims WHERE workspace_id = $1 AND id = $2", [workspace.id, input.claimId],
      )).rows[0];
      if (!claim || claim.released_at) return null;
    }
    await input.onLocked?.();
    await expireLapsed(tx, workspace.id, input.ownerUserId, input.delegateAgentId);
    const active = (await tx.query<GrantRow>(
      `SELECT * FROM delegation_grants WHERE workspace_id = $1 AND owner_user_id = $2 AND delegate_agent_id = $3
          AND status = 'active' LIMIT 1`, pair,
    )).rows[0];
    if (active) {
      if (!active.trust_rule_id || grantMatches(active, shape)) return active;
      await revokeGrants(tx, { workspaceId: workspace.id, grantIds: [active.id], actorUserId: null, reason: SUPERSEDED_BY_RULE,
        authMethod: "system" });
    }
    if (shape.binding.role === null && await legacyExcludedOn(tx, { workspaceId: workspace.id, ownerUserId: input.ownerUserId,
      agentId: input.delegateAgentId, ruleId: rule.id })) return null;
    // Created no earlier than the binding (as last changed), every record of
    // the chain, and the last time any grant of the pair ended:
    // - owner-made grants count too;
    // - so does a grant superseded because its binding changed, since new
    //   authority is never retroactive.
    // A system grant retired for a changed chain (CHAIN_CHANGED) is the one
    // exception, when the new chain's own records date the hand-over
    // (handOverDated, as Cloud).
    const ended = (await tx.query<{ status: string; revoked_at: Date | string | null; expires_at: Date | string;
      trust_rule_id: string | null; revoked_reason: string | null; trust_path: TrustPath | null }>(
      `SELECT status, revoked_at, expires_at, trust_rule_id, revoked_reason, trust_path
         FROM delegation_grants
        WHERE workspace_id = $1 AND owner_user_id = $2 AND delegate_agent_id = $3 AND status <> 'active'`,
      pair,
    )).rows.filter(row => !(row.trust_rule_id && row.status === "revoked" && row.revoked_reason === CHAIN_CHANGED &&
      handOverDated(row.trust_path, input.trustPath)));
    const endedAt = ended.length ? Math.max(...ended.map(row =>
      time(row.status === "revoked" ? row.revoked_at ?? row.expires_at : row.expires_at))) : 0;
    // No earlier than every contributing binding's creation and last change,
    // and a group member's joining (decisionSince): new authority is never retroactive.
    // Nor before the owner's latest change to anything that decides (ownerChangeFloor): removing or outliving a
    // restrictive binding never covers an approval sent while it decided, even for an agent with no grant yet.
    const createdAt = new Date(Math.max(decisionSince(state, decision, input.delegateAgentId),
      await ownerChangeFloor(tx, workspace.id, input.ownerUserId, new Date()), input.provenAt.getTime(), endedAt));
    const row = (await tx.query<GrantRow>(
      `INSERT INTO delegation_grants
         (id, workspace_id, organization_id, owner_user_id, delegate_agent_id, delegate_agent_name, scopes, require_tier_o,
          expires_at, created_auth_method, created_at, trust_rule_id, trust_path)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, 'system', $10, $11, $12::jsonb) RETURNING *`,
      [mintId("grt"), workspace.id, workspace.organizationId, input.ownerUserId, input.delegateAgentId, input.delegateAgentName,
        JSON.stringify(shape.scopes), shape.requireTierO, shape.expiresAt, createdAt, rule.id, JSON.stringify(input.trustPath)],
    )).rows[0]!;
    await recordDelegationAudit(tx, { workspaceId: workspace.id, event: "grant.created", actorUserId: null,
      authMethod: "system", ownerUserId: input.ownerUserId, grantId: row.id, reason: "trust_rule",
      data: { delegate_agent_id: input.delegateAgentId, trust_rule_id: rule.id, trust_path: input.trustPath,
        require_tier_o: shape.requireTierO, binding_id: rule.id, principal_kind: shape.binding.principalKind,
        role: shape.binding.role, source: decision.kind === "covered" ? decision.source : null, scopes: shape.scopes } });
    return row;
  });
  try {
    return await run();
  } catch (error) {
    // Two concurrent first attests of one pair: the active-pair index decides; the loser reads the winner's grant.
    if ((error as { code?: string })?.code === "23505") return run();
    throw error;
  }
}

/** A second live binding for the same (owner, principal); carries the first one's id. */
export class BindingExists extends Error {
  constructor(readonly bindingId: string) {
    super("binding_exists");
  }
}

/** The group a `group` principal names is not the owner's live group. */
export class GroupNotFound extends Error {
  constructor() {
    super("group_not_found");
  }
}

/** Every live binding (one owner's, or every owner's), oldest first. */
export async function listBindings(executor: SqlExecutor, workspaceId: string, ownerUserId: string | null): Promise<TrustRuleRow[]> {
  return (await executor.query<TrustRuleRow>(
    `SELECT * FROM delegation_trust_rules WHERE workspace_id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR owner_user_id = $2)
      ORDER BY created_at, id`,
    [workspaceId, ownerUserId],
  )).rows;
}

/** One live binding of one owner. */
export async function getBinding(executor: SqlExecutor, workspaceId: string, ownerUserId: string, bindingId: string):
  Promise<TrustRuleRow | null> {
  return (await executor.query<TrustRuleRow>(
    "SELECT * FROM delegation_trust_rules WHERE workspace_id = $1 AND owner_user_id = $2 AND id = $3 AND revoked_at IS NULL",
    [workspaceId, ownerUserId, bindingId],
  )).rows[0] ?? null;
}

/** How many active system grants each binding of one owner decides now. */
export async function bindingCoverage(executor: SqlExecutor, workspaceId: string, ownerUserId: string | null):
  Promise<Map<string, number>> {
  const rows = (await executor.query<{ trust_rule_id: string; count: number }>(
    `SELECT trust_rule_id, count(*)::int AS count FROM delegation_grants
      WHERE workspace_id = $1 AND status = 'active' AND trust_rule_id IS NOT NULL AND ($2::uuid IS NULL OR owner_user_id = $2)
      GROUP BY trust_rule_id`,
    [workspaceId, ownerUserId],
  )).rows;
  return new Map(rows.map(row => [row.trust_rule_id, Number(row.count)]));
}

/**
 * Creates one binding (Cloud's createBinding). The owner must be a member, and
 * a `group` principal must be the owner's live group. One live binding exists
 * per (owner, principal); a second is refused with the first one's id. The
 * owner's system grants are re-resolved, so a more specific binding takes
 * over at once.
 */
export async function createBinding(database: Database, input: { workspaceId: string; ownerUserId: string; actorUserId: string;
  authMethod: string; principalKind: Exclude<PrincipalKind, "all_agents">; principalRef: string | null;
  fields: BindingFields }): Promise<TrustRuleRow> {
  const existing = (executor: SqlExecutor) => executor.query<{ id: string }>(
    `SELECT id FROM delegation_trust_rules WHERE workspace_id = $1 AND owner_user_id = $2 AND principal_kind = $3
        AND coalesce(principal_ref, '') = coalesce($4::text, '') AND revoked_at IS NULL LIMIT 1`,
    [input.workspaceId, input.ownerUserId, input.principalKind, input.principalRef]);
  try {
    return await database.transaction(async (tx) => {
      if (!await memberRole(tx, input.workspaceId, input.ownerUserId, true)) throw new TrustRuleMembershipGone();
      await lockOwnerBindings(tx, input.workspaceId, input.ownerUserId, "exclusive");
      const found = (await existing(tx)).rows[0];
      if (found) throw new BindingExists(found.id);
      if (input.principalKind === "relay_agents") {
        // A live legacy rule is the owner's Relay agents binding until it is converted (PATCH it, or the role seed).
        const legacy = (await tx.query<{ id: string }>(
          `SELECT id FROM delegation_trust_rules WHERE workspace_id = $1 AND owner_user_id = $2 AND revoked_at IS NULL AND ${LEGACY_RULE}
            LIMIT 1`, [input.workspaceId, input.ownerUserId],
        )).rows[0];
        if (legacy) throw new BindingExists(legacy.id);
      }
      if (input.principalKind === "group") {
        const group = (await tx.query(
          `SELECT 1 FROM delegation_groups WHERE workspace_id = $1 AND owner_user_id = $2 AND id = $3 AND revoked_at IS NULL
            FOR SHARE`,
          [input.workspaceId, input.ownerUserId, input.principalRef ?? ""],
        )).rows[0];
        if (!group) throw new GroupNotFound();
      }
      const row = (await tx.query<TrustRuleRow>(
        `INSERT INTO delegation_trust_rules (id, workspace_id, owner_user_id, principal_kind, principal_ref, ${BINDING_COLUMNS},
           created_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, clock_timestamp(), clock_timestamp()) RETURNING *`,
        [mintId("dtr"), input.workspaceId, input.ownerUserId, input.principalKind, input.principalRef, ...bindingValues(input.fields)],
      )).rows[0]!;
      await recordDelegationAudit(tx, { workspaceId: input.workspaceId, event: "binding.created", actorUserId: input.actorUserId,
        authMethod: input.authMethod, ownerUserId: input.ownerUserId, data: bindingAudit(row) });
      await reresolveOwnerGrants(tx, input);
      return row;
    });
  } catch (error) {
    if ((error as { code?: string })?.code !== "23505") throw error;
    // A concurrent create of the same principal won the live-principal index.
    const winner = (await existing(database)).rows[0];
    if (winner) throw new BindingExists(winner.id);
    throw error;
  }
}

/**
 * Replaces what one live binding grants (Cloud's updateBinding). Its principal
 * is fixed, but a legacy rule becomes a Relay agents binding the first time
 * it is set. Every system grant of the owner is then re-resolved.
 */
export async function updateBinding(database: Database, input: { workspaceId: string; ownerUserId: string; bindingId: string;
  actorUserId: string; authMethod: string;
  /**
   * The new fields, from the binding as locked here: fields a PATCH omits keep
   * their locked values, never an earlier read's, so two concurrent PATCHes
   * never undo each other's narrowing. A string refuses.
   */
  resolve: (current: TrustRuleRow) => BindingFields | string }): Promise<TrustRuleRow | string | null> {
  return database.transaction(async (tx) => {
    await lockOwnerBindings(tx, input.workspaceId, input.ownerUserId, "exclusive");
    const before = (await tx.query<TrustRuleRow>(
      `SELECT * FROM delegation_trust_rules WHERE workspace_id = $1 AND owner_user_id = $2 AND id = $3 AND revoked_at IS NULL
        FOR UPDATE`,
      [input.workspaceId, input.ownerUserId, input.bindingId],
    )).rows[0];
    if (!before) return null;
    const fields = input.resolve(before);
    if (typeof fields === "string") return fields;
    const legacy = (before.principal_kind ?? "all_agents") === "all_agents";
    if (legacy) {
      // The legacy rule becomes the Relay agents binding: refused while the owner already has one.
      const existing = (await tx.query<{ id: string }>(
        `SELECT id FROM delegation_trust_rules WHERE workspace_id = $1 AND owner_user_id = $2 AND principal_kind = 'relay_agents'
            AND revoked_at IS NULL LIMIT 1`, [input.workspaceId, input.ownerUserId],
      )).rows[0];
      if (existing) throw new BindingExists(existing.id);
      await carryLegacyExclusions(tx, before, input.actorUserId, input.authMethod);
    }
    const row = (await tx.query<TrustRuleRow>(
      `UPDATE delegation_trust_rules SET (${BINDING_COLUMNS}) = ($2, $3, $4, $5, $6, $7, $8),
          principal_kind = CASE WHEN $9::boolean THEN 'relay_agents' ELSE principal_kind END, updated_at = clock_timestamp()
        WHERE id = $1 RETURNING *`,
      [before.id, ...bindingValues(fields), legacy],
    )).rows[0]!;
    await recordDelegationAudit(tx, { workspaceId: input.workspaceId, event: "binding.updated", actorUserId: input.actorUserId,
      authMethod: input.authMethod, ownerUserId: input.ownerUserId,
      data: { binding_id: row.id, before: bindingAudit(before), after: bindingAudit(row) } });
    await reresolveOwnerGrants(tx, input);
    return row;
  });
}

/**
 * Keeps the exclusions a legacy rule recorded when it stops being legacy (as
 * Cloud's carryLegacyExclusions). Before roles, an exclusion was only a
 * system grant of the rule revoked as owner_excluded, and only a legacy rule
 * reads those (materializeRuleGrant). Each such agent gets an `excluded` agent
 * binding, unless it already has an agent binding of its own. Otherwise
 * converting the rule (role seed or PATCH) would cover it again. Runs under
 * the owner's exclusive binding lock.
 */
async function carryLegacyExclusions(tx: SqlExecutor, rule: TrustRuleRow, actorUserId: string | null,
  authMethod: string | null): Promise<string[]> {
  const agents = [...new Set((await tx.query<{ delegate_agent_id: string }>(
    `SELECT delegate_agent_id FROM delegation_grants WHERE trust_rule_id = $1 AND status = 'revoked' AND revoked_reason = $2
      ORDER BY delegate_agent_id`, [rule.id, OWNER_EXCLUDED],
  )).rows.map(row => row.delegate_agent_id))];
  const carried: string[] = [];
  for (const agentId of agents) {
    // Any agent binding, live or revoked, already decides for it: a removed exclusion is not brought back.
    const own = (await tx.query(
      `SELECT 1 FROM delegation_trust_rules WHERE workspace_id = $1 AND owner_user_id = $2 AND principal_kind = 'agent'
          AND principal_ref = $3 LIMIT 1`, [rule.workspace_id, rule.owner_user_id, agentId],
    )).rows[0];
    if (own) continue;
    const row = (await tx.query<TrustRuleRow>(
      `INSERT INTO delegation_trust_rules (id, workspace_id, owner_user_id, principal_kind, principal_ref, ${BINDING_COLUMNS},
         created_at, updated_at)
       VALUES ($1, $2, $3, 'agent', $4, $5, $6, $7, $8, $9, $10, $11, clock_timestamp(), clock_timestamp()) RETURNING *`,
      [mintId("dtr"), rule.workspace_id, rule.owner_user_id, agentId, ...bindingValues(EXCLUDED_FIELDS)],
    )).rows[0]!;
    await recordDelegationAudit(tx, { workspaceId: rule.workspace_id, event: "binding.created", actorUserId, authMethod,
      ownerUserId: rule.owner_user_id, reason: OWNER_EXCLUDED,
      data: { ...bindingAudit(row), delegate_agent_id: agentId, carried_from: rule.id } });
    carried.push(agentId);
  }
  return carried;
}

/**
 * Revokes one binding and every system grant it created, with their
 * approvals (Cloud's revokeBinding). The owner's binding lock is taken first,
 * then the binding (FOR UPDATE), then its grants by id. The owner's other
 * system grants are re-resolved after that: an agent the binding decided for
 * may fall to a less specific binding at its next use. A removed binding
 * allows that fall-through; an exclusion never does.
 */
export async function revokeBinding(database: Database, input: { workspaceId: string; ownerUserId: string; bindingId: string;
  actorUserId: string; authMethod: string; reason: string }): Promise<{ binding: TrustRuleRow; revokedGrants: string[] } | null> {
  return database.transaction(async (tx) => {
    await lockOwnerBindings(tx, input.workspaceId, input.ownerUserId, "exclusive");
    const [rule] = await revokeTrustRulesTx(tx, { workspaceId: input.workspaceId, ownerUserId: input.ownerUserId,
      ruleId: input.bindingId, actorUserId: input.actorUserId, authMethod: input.authMethod, reason: input.reason });
    if (!rule) return null;
    const more = await reresolveOwnerGrants(tx, input);
    const { revokedGrants, ...binding } = rule;
    return { binding, revokedGrants: [...revokedGrants, ...more] };
  });
}

// ---------------------------------------------------------------- groups

export type GroupRecord = { id: string; workspace_id: string; owner_user_id: string; name: string;
  created_at: Date | string; updated_at: Date | string; members: Array<{ agent_id: string; added_at: Date | string }> };

async function readGroups(executor: SqlExecutor, workspaceId: string, ownerUserId: string, groupId?: string): Promise<GroupRecord[]> {
  const groups = (await executor.query<Omit<GroupRecord, "members">>(
    `SELECT id, workspace_id, owner_user_id, name, created_at, updated_at FROM delegation_groups
      WHERE workspace_id = $1 AND owner_user_id = $2 AND revoked_at IS NULL AND ($3::text IS NULL OR id = $3)
      ORDER BY created_at, id`,
    [workspaceId, ownerUserId, groupId ?? null],
  )).rows;
  if (!groups.length) return [];
  const members = (await executor.query<{ group_id: string; agent_id: string; added_at: Date | string }>(
    `SELECT group_id, agent_id, added_at FROM delegation_group_members
      WHERE group_id = ANY($1::text[]) AND removed_at IS NULL ORDER BY added_at, agent_id`,
    [groups.map(group => group.id)],
  )).rows;
  return groups.map(group => ({ ...group, members: members.filter(member => member.group_id === group.id)
    .map(member => ({ agent_id: member.agent_id, added_at: member.added_at })) }));
}

/** One owner's live custom groups with their live members. */
export function listGroups(executor: SqlExecutor, workspaceId: string, ownerUserId: string): Promise<GroupRecord[]> {
  return readGroups(executor, workspaceId, ownerUserId);
}

/** Creates a custom group. Members are agent ids the caller already proved are the owner's; each is re-proved at every use. */
export async function createGroup(database: Database, input: { workspaceId: string; ownerUserId: string; actorUserId: string;
  authMethod: string; name: string; agentIds: string[] }): Promise<GroupRecord> {
  return database.transaction(async (tx) => {
    if (!await memberRole(tx, input.workspaceId, input.ownerUserId, true)) throw new TrustRuleMembershipGone();
    await lockOwnerBindings(tx, input.workspaceId, input.ownerUserId, "exclusive");
    const id = mintId("grp");
    await tx.query("INSERT INTO delegation_groups (id, workspace_id, owner_user_id, name) VALUES ($1, $2, $3, $4)",
      [id, input.workspaceId, input.ownerUserId, input.name]);
    const agentIds = [...new Set(input.agentIds)];
    if (agentIds.length) {
      await tx.query("INSERT INTO delegation_group_members (group_id, agent_id, added_at) SELECT $1, unnest($2::text[]), clock_timestamp()", [id, agentIds]);
    }
    await recordDelegationAudit(tx, { workspaceId: input.workspaceId, event: "group.created", actorUserId: input.actorUserId,
      authMethod: input.authMethod, ownerUserId: input.ownerUserId, data: { group_id: id, name: input.name, agent_ids: agentIds } });
    return (await readGroups(tx, input.workspaceId, input.ownerUserId, id))[0]!;
  });
}

/**
 * Renames a group and adds or removes members (Cloud's updateGroup). A member
 * change re-resolves the owner's system grants at once.
 */
export async function updateGroup(database: Database, input: { workspaceId: string; ownerUserId: string; groupId: string;
  actorUserId: string; authMethod: string; name?: string; add?: string[]; remove?: string[] }): Promise<GroupRecord | null> {
  return database.transaction(async (tx) => {
    await lockOwnerBindings(tx, input.workspaceId, input.ownerUserId, "exclusive");
    const group = (await tx.query<{ id: string; name: string }>(
      `SELECT id, name FROM delegation_groups WHERE workspace_id = $1 AND owner_user_id = $2 AND id = $3 AND revoked_at IS NULL
        FOR UPDATE`,
      [input.workspaceId, input.ownerUserId, input.groupId],
    )).rows[0];
    if (!group) return null;
    const renamed = input.name !== undefined && input.name !== group.name;
    if (renamed) {
      await tx.query("UPDATE delegation_groups SET name = $2, updated_at = now() WHERE id = $1", [group.id, input.name]);
    }
    const live = new Set((await tx.query<{ agent_id: string }>(
      "SELECT agent_id FROM delegation_group_members WHERE group_id = $1 AND removed_at IS NULL", [group.id],
    )).rows.map(row => row.agent_id));
    const remove = [...new Set(input.remove ?? [])].filter(agentId => live.has(agentId));
    const add = [...new Set(input.add ?? [])].filter(agentId => !live.has(agentId) && !remove.includes(agentId));
    if (remove.length) {
      await tx.query(
        "UPDATE delegation_group_members SET removed_at = clock_timestamp() WHERE group_id = $1 AND agent_id = ANY($2::text[]) AND removed_at IS NULL",
        [group.id, remove]);
    }
    if (add.length) {
      await tx.query("INSERT INTO delegation_group_members (group_id, agent_id, added_at) SELECT $1, unnest($2::text[]), clock_timestamp()", [group.id, add]);
    }
    const audit = { workspaceId: input.workspaceId, actorUserId: input.actorUserId, authMethod: input.authMethod,
      ownerUserId: input.ownerUserId };
    if (renamed && !add.length && !remove.length) {
      await recordDelegationAudit(tx, { ...audit, event: "group.updated", data: { group_id: group.id, name: input.name } });
    }
    if (add.length) await recordDelegationAudit(tx, { ...audit, event: "group.member_added", data: { group_id: group.id, agent_ids: add } });
    if (remove.length) {
      await recordDelegationAudit(tx, { ...audit, event: "group.member_removed", data: { group_id: group.id, agent_ids: remove } });
    }
    if (add.length || remove.length) await reresolveOwnerGrants(tx, input);
    return (await readGroups(tx, input.workspaceId, input.ownerUserId, group.id))[0]!;
  });
}

/** Revokes a group and every binding naming it (with their grants), then re-resolves the owner's other grants. */
export async function revokeGroup(database: Database, input: { workspaceId: string; ownerUserId: string; groupId: string;
  actorUserId: string; authMethod: string }): Promise<{ revokedBindings: number; revokedGrants: number } | null> {
  return database.transaction(async (tx) => {
    await lockOwnerBindings(tx, input.workspaceId, input.ownerUserId, "exclusive");
    const group = (await tx.query<{ id: string }>(
      `SELECT id FROM delegation_groups WHERE workspace_id = $1 AND owner_user_id = $2 AND id = $3 AND revoked_at IS NULL
        FOR UPDATE`,
      [input.workspaceId, input.ownerUserId, input.groupId],
    )).rows[0];
    if (!group) return null;
    const bindings = (await tx.query<{ id: string }>(
      `SELECT id FROM delegation_trust_rules WHERE workspace_id = $1 AND owner_user_id = $2 AND principal_kind = 'group'
          AND principal_ref = $3 AND revoked_at IS NULL ORDER BY id`,
      [input.workspaceId, input.ownerUserId, group.id],
    )).rows;
    let revokedGrants = 0;
    for (const binding of bindings) {
      const [rule] = await revokeTrustRulesTx(tx, { workspaceId: input.workspaceId, ownerUserId: input.ownerUserId,
        ruleId: binding.id, actorUserId: input.actorUserId, authMethod: input.authMethod, reason: "group_revoked" });
      revokedGrants += rule?.revokedGrants.length ?? 0;
    }
    await tx.query("UPDATE delegation_groups SET revoked_at = clock_timestamp(), updated_at = clock_timestamp() WHERE id = $1", [group.id]);
    await recordDelegationAudit(tx, { workspaceId: input.workspaceId, event: "group.revoked", actorUserId: input.actorUserId,
      authMethod: input.authMethod, ownerUserId: input.ownerUserId,
      data: { group_id: group.id, revoked_bindings: bindings.map(binding => binding.id) } });
    revokedGrants += (await reresolveOwnerGrants(tx, input)).length;
    return { revokedBindings: bindings.length, revokedGrants };
  });
}

// ---------------------------------------------------------------- role seed

export type RoleSeedReport = { dry_run: boolean; scanned: number; converted: number;
  skipped: { has_relay_agents: number; raced: number };
  rules: Array<{ workspace_id: string; owner_id: string; trust_rule_id: string }>; next_cursor: string | null };

/**
 * Seeds Trusted for the agents owners already work with (Khaliq, answer 9;
 * Cloud's seedTrustedBindings): every live legacy rule becomes a
 * `relay_agents` binding with the Trusted preset.
 * - A dry run (the default) reads and writes nothing.
 * - An apply converts each rule in its own transaction, under the owner's
 *   exclusive binding lock, and re-resolves that owner's system grants.
 * - Idempotent: only legacy rules are converted. An owner who already has a
 *   Relay agents binding is skipped and left for a person to decide.
 * Pages by rule id.
 */
export async function seedTrustedBindings(database: Database, input: { apply: boolean; limit: number; after?: string | null;
  trusted: BindingFields }): Promise<RoleSeedReport> {
  const rules = (await database.query<TrustRuleRow>(
    `SELECT * FROM delegation_trust_rules WHERE revoked_at IS NULL AND ${LEGACY_RULE} AND ($1::text IS NULL OR id > $1)
      ORDER BY id LIMIT $2`,
    [input.after ?? null, input.limit],
  )).rows;
  const report: RoleSeedReport = { dry_run: !input.apply, scanned: rules.length, converted: 0,
    skipped: { has_relay_agents: 0, raced: 0 }, rules: [], next_cursor: rules.length === input.limit ? rules.at(-1)!.id : null };
  for (const rule of rules) {
    const outcome = await database.transaction(async (tx) => {
      if (input.apply) await lockOwnerBindings(tx, rule.workspace_id, rule.owner_user_id, "exclusive");
      const locked = (await tx.query<TrustRuleRow>(
        `SELECT * FROM delegation_trust_rules WHERE id = $1 AND revoked_at IS NULL AND ${LEGACY_RULE}${input.apply ? " FOR UPDATE" : ""}`,
        [rule.id],
      )).rows[0];
      if (!locked) return "raced" as const;
      const relay = (await tx.query(
        `SELECT 1 FROM delegation_trust_rules WHERE workspace_id = $1 AND owner_user_id = $2 AND principal_kind = 'relay_agents'
            AND revoked_at IS NULL LIMIT 1`,
        [rule.workspace_id, rule.owner_user_id],
      )).rows[0];
      if (relay) return "has_relay_agents" as const;
      if (!input.apply) return "convertible" as const;
      await carryLegacyExclusions(tx, locked, null, "system");
      const row = (await tx.query<TrustRuleRow>(
        `UPDATE delegation_trust_rules SET principal_kind = 'relay_agents', (${BINDING_COLUMNS}) = ($2, $3, $4, $5, $6, $7, $8),
            updated_at = clock_timestamp() WHERE id = $1 RETURNING *`,
        [rule.id, ...bindingValues(input.trusted)],
      )).rows[0]!;
      await recordDelegationAudit(tx, { workspaceId: rule.workspace_id, event: "binding.updated", actorUserId: null,
        authMethod: "system", ownerUserId: rule.owner_user_id, reason: "role_seed",
        data: { binding_id: rule.id, before: bindingAudit(locked), after: bindingAudit(row) } });
      await reresolveOwnerGrants(tx, { workspaceId: rule.workspace_id, ownerUserId: rule.owner_user_id, actorUserId: null,
        authMethod: "system" });
      return "converted" as const;
    });
    if (outcome === "raced" || outcome === "has_relay_agents") {
      report.skipped[outcome] += 1;
      continue;
    }
    if (outcome === "converted") report.converted += 1;
    report.rules.push({ workspace_id: rule.workspace_id, owner_id: rule.owner_user_id, trust_rule_id: rule.id });
  }
  return report;
}

/** Most launched agents the agents picker considers for one owner. */
export const MAX_LISTED_WORKERS = 100;

/**
 * Candidates for the owner's agents picker (GET /delegates/agents): the roots
 * (listTrustRootAgents) plus workers the owner launched through Control that
 * reached `ready`, newest first. Each is still only a candidate: the caller
 * proves it with resolveTrustPath and drops the ones that do not prove out.
 */
export async function listOwnerAgentCandidates(executor: SqlExecutor, workspace: DelegationWorkspace, ownerUserId: string):
  Promise<string[]> {
  const roots = await listTrustRootAgents(executor, workspace, ownerUserId);
  const workers = (await executor.query<{ worker_id: string }>(
    `SELECT worker_id FROM relay_spawns
      WHERE relaycast_workspace_id = $1 AND user_id::text = $2 AND state = 'ready' AND worker_id IS NOT NULL
      ORDER BY created_at DESC LIMIT $3`,
    [workspace.relaycastWorkspaceId, ownerUserId, MAX_LISTED_WORKERS],
  )).rows.map(row => row.worker_id);
  return [...new Set([...roots, ...workers])];
}

/**
 * The classes the ACTING agent itself must ask its owner about first (Khaliq,
 * answer 3; Cloud's actingAskFirst). An agent whose own grant or binding puts
 * a class under "ask me first" may act on an approval of that class only when
 * one of these holds:
 * - its owner minted it (Tier O);
 * - another delegate minted it (Tier D) under a live, recorded grant of the
 *   SAME owner, in this workspace, whose own Tier O list does not hold the
 *   class.
 * A Tier D approval minted under another owner's grant never satisfies the
 * acting agent's own ask-first list. The class set comes from:
 * - the acting agent's live owner-made grant from its owner;
 * - otherwise the owner's binding that decides for it.
 * The presets alone never open the delegated path.
 */
async function actingAskFirst(deps: DelegationDeps, prove: TrustProver, workspace: DelegationWorkspace, ownerUserId: string,
  agentId: string, now: Date): Promise<Set<ActionClass>> {
  const own = (await grantsFor(deps.database, workspace.id, ownerUserId, agentId))
    .find(grant => grant.status === "active" && time(grant.expires_at) > now.getTime() && !grant.trust_rule_id);
  if (own) return new Set(own.require_tier_o);
  const proof = await prove(ownerUserId, agentId);
  if (!proof) return new Set();
  const decision = await decideWithLegacyExclusion(deps.database, await bindingState(deps.database, workspace.id, ownerUserId),
    { workspaceId: workspace.id, ownerUserId, agentId, path: proof.path, now });
  return new Set(decision.kind === "covered" ? decision.authority.requireTierO : []);
}

/**
 * The acting agent's own grants that actingRefusalLocked reads, for
 * decideUnderLocks to lock with the minter's grant in one id-ordered pass.
 * Null when the decision never reads them (Tier O, or the same owner).
 */
function actingGrantsLock(actingOwnerId: string, actingAgentId: string, grant: GrantRow, tier: "D" | "O"):
  { ownerUserId: string; agentId: string } | null {
  return tier === "D" && grant.owner_user_id !== actingOwnerId ? { ownerUserId: actingOwnerId, agentId: actingAgentId } : null;
}

/** Refuses a Tier D approval from another owner's grant for a class the acting agent must ask its own owner about. */
async function actingRefusal(deps: DelegationDeps, prove: TrustProver, input: { workspace: DelegationWorkspace;
  actingOwnerId: string; actingAgentId: string; grant: GrantRow; tier: "D" | "O"; actions: readonly Pick<Action, "class">[];
  now: Date }): Promise<ReasonCode | null> {
  if (input.tier !== "D" || input.grant.owner_user_id === input.actingOwnerId) return null;
  const askFirst = await actingAskFirst(deps, prove, input.workspace, input.actingOwnerId, input.actingAgentId, input.now);
  return input.actions.some(action => askFirst.has(action.class)) ? "tier_o_required" : null;
}

/**
 * actingRefusal again, on the deciding transaction (Cloud's
 * actingRefusalLocked): under the acting owner's binding lock and a share
 * lock on the acting agent's own grants, with its chain re-proved on the
 * transaction. An ask-first change committed while the attest or redeem ran
 * decides the answer, and one that starts later waits for this decision.
 */
async function actingRefusalLocked(tx: SqlExecutor, input: { workspace: DelegationWorkspace; actingOwnerId: string;
  actingAgentId: string; grant: GrantRow; tier: "D" | "O"; actions: readonly Pick<Action, "class">[]; now: Date }):
  Promise<ReasonCode | null> {
  if (input.tier !== "D" || input.grant.owner_user_id === input.actingOwnerId) return null;
  const { own, state } = await actingAuthorityLocked(tx, { workspaceId: input.workspace.id, ownerUserId: input.actingOwnerId,
    agentId: input.actingAgentId, now: input.now });
  let askFirst: readonly ActionClass[] = own ?? [];
  if (!own) {
    const proof = await resolveTrustPath(sqlTrustReader(tx, true), { workspaceId: input.workspace.id,
      relaycastWorkspaceId: input.workspace.relaycastWorkspaceId, ownerUserId: input.actingOwnerId, agentId: input.actingAgentId });
    const decision = proof ? await decideWithLegacyExclusion(tx, state, { workspaceId: input.workspace.id,
      ownerUserId: input.actingOwnerId, agentId: input.actingAgentId, path: proof.path, now: input.now }) : null;
    askFirst = decision?.kind === "covered" ? decision.authority.requireTierO : [];
  }
  return input.actions.some(action => askFirst.includes(action.class)) ? "tier_o_required" : null;
}


export type RoleQuiesceReport = { dry_run: boolean; bindings: Array<{ workspace_id: string; owner_id: string; binding_id: string;
  principal_kind: string; role: string | null }>; revoked_grants: number };

/**
 * The rollback step for role bindings (Cloud's quiesceRoleBindings). A build
 * from before roles reads any live row of delegation_trust_rules as an
 * owner's legacy rule (every class, the whole spawn tree), and any system
 * grant as covering every class. So before rolling back below the build that
 * added roles, every owner who has a role binding loses ALL their live
 * rules, their legacy rule included, with every system grant and its
 * approvals, in one transaction per owner under the owner's exclusive
 * binding lock (reason `role_bindings_quiesced`). A legacy rule left live
 * under a revoked exclusion, Read-only group or connector binding would be
 * what those agents fall through to: every class. An owner with only a
 * plain legacy rule is left untouched.
 *
 * It fails closed: agents lose authority, never gain it.
 * - Exclusions made since roles do NOT survive a rollback. The old build
 *   reads owner_excluded grant rows only for the rule's own id, an exclusion
 *   may have none, and a re-enabled legacy rule has a new id. An owner who
 *   re-enables the legacy rule must revoke those agents' grants again.
 * - An owner whose rule the seed converted turns the legacy rule on again
 *   after the rollback.
 * - It pages by owner: at most `limit` owners per call, and the report does
 *   not say whether more remain. Rerun until a dry run lists nothing.
 * - A row written after the call survives it. Stop writes first, and
 *   dry-run again right before cutover.
 *
 * A DRY RUN by default: it lists every rule an apply would end, the legacy
 * rules of affected owners included. See docs/owner-delegates.md, "Rolling
 * back role bindings".
 */
export async function quiesceRoleBindings(database: Database, input: { apply: boolean; limit: number }): Promise<RoleQuiesceReport> {
  const owners = (await database.query<{ workspace_id: string; owner_user_id: string }>(
    `SELECT DISTINCT workspace_id::text AS workspace_id, owner_user_id::text AS owner_user_id FROM delegation_trust_rules
      WHERE revoked_at IS NULL AND NOT (${LEGACY_RULE})
      ORDER BY workspace_id, owner_user_id LIMIT $1`, [input.limit],
  )).rows;
  const report: RoleQuiesceReport = { dry_run: !input.apply, revoked_grants: 0, bindings: [] };
  const view = (row: TrustRuleRow) => ({ workspace_id: row.workspace_id, owner_id: row.owner_user_id, binding_id: row.id,
    principal_kind: row.principal_kind ?? "all_agents", role: row.role ?? null });
  for (const owner of owners) {
    if (!input.apply) {
      // Every live rule of this owner, its legacy rule included, is what an apply ends.
      report.bindings.push(...(await listBindings(database, owner.workspace_id, owner.owner_user_id)).map(view));
      continue;
    }
    const revoked = await database.transaction(async (tx) => {
      await lockOwnerBindings(tx, owner.workspace_id, owner.owner_user_id, "exclusive");
      return revokeTrustRulesTx(tx, { workspaceId: owner.workspace_id, ownerUserId: owner.owner_user_id, actorUserId: null,
        authMethod: "system", reason: "role_bindings_quiesced" });
    });
    for (const rule of revoked) {
      report.bindings.push(view(rule));
      report.revoked_grants += rule.revokedGrants.length;
    }
  }
  return report;
}
