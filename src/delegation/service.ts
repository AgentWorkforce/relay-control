import { randomBytes, randomUUID } from "node:crypto";
import type { Database, SqlExecutor } from "../database.js";
import { RelaycastCallError, type RelaycastClient } from "../messaging/relaycast.js";
import type { DelegationSigner } from "./jws.js";
import {
  actionsCovered,
  APPROVAL_DEFAULT_MS,
  APPROVAL_MAX_MS,
  ATTESTATION_TTL_SECONDS,
  base62,
  canonicalAction,
  classTargetCovered,
  GITHUB_CONDITIONS,
  highRisk,
  promptTarget,
  REPO_TARGET,
  ownerApprovalSchema,
  ownerDisplay,
  sameActions,
  sha256Hex,
  tierDApprovalId,
  tierORequired,
  type Action,
  type ActionClass,
  type Condition,
  type ReasonCode,
  type Scope,
} from "./scope.js";

/**
 * Owner-named trusted delegates: grants, claims, attestation and redeem
 * (relay docs/design/owner-trusted-delegates.md §4–§8, §16.3, §16.4).
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
  updated_at: string | null;
};

export const DEFAULT_POLICY: DelegationPolicy = {
  delegation_enabled: false, max_expiry_days: 90, allowed_classes: null, require_tier_o: [],
  code_owner_match: "any_path", updated_at: null,
};

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
  now: () => Date;
};

export type AgentBinding = { userId: string; agentId: string; name: string; address: string | null };

type BindingRow = {
  source: string; user_id: string; agent_id: string; agent_name: string; address: string | null; verified: boolean;
};

export type GrantRow = {
  id: string;
  workspace_id: string;
  organization_id: string;
  owner_user_id: string;
  delegate_agent_id: string;
  delegate_agent_name: string;
  scopes: Scope[];
  require_tier_o: ActionClass[];
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
  consumed_at: Date | string | null;
  invalidated_at: Date | string | null;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const time = (value: Date | string) => (value instanceof Date ? value : new Date(value)).getTime();
const iso = (value: Date | string | null) => value === null ? null : new Date(value).toISOString();

export function grantView(row: GrantRow, now: Date) {
  const status = row.revoked_at ? "revoked" : time(row.expires_at) <= now.getTime() ? "expired" : "active";
  return {
    grant_id: row.id,
    owner_id: row.owner_user_id,
    delegate_agent_id: row.delegate_agent_id,
    delegate_agent_name: row.delegate_agent_name,
    scopes: row.scopes,
    require_tier_o: row.require_tier_o,
    expires_at: iso(row.expires_at),
    created_at: iso(row.created_at),
    updated_at: iso(row.updated_at),
    revoked_at: iso(row.revoked_at),
    revoked_reason: row.revoked_reason,
    status,
  };
}

export function newGrantId(): string {
  return `grt_${base62(randomBytes(16))}`;
}

export function newApprovalId(): string {
  return `apv_${base62(randomBytes(16))}`;
}

export function newClaimId(): string {
  return `dcl_${base62(randomBytes(16))}`;
}

/** A one-time claim code: 80 random bits as four groups of Crockford base32. */
export function newClaimCode(): string {
  const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const bytes = randomBytes(16);
  let out = "";
  for (let index = 0; index < 16; index += 1) {
    out += alphabet[bytes[index]! & 31];
    if (index % 4 === 3 && index < 15) out += "-";
  }
  return out;
}

/** Claim codes are compared by the SHA-256 of their normalized form. */
export function claimCodeHash(code: string): string {
  return sha256Hex(code.trim().toUpperCase().replace(/[^0-9A-Z]/g, ""));
}

export async function loadPolicy(executor: SqlExecutor, workspaceId: string): Promise<DelegationPolicy> {
  const row = (await executor.query<{
    delegation_enabled: boolean; max_expiry_days: number; allowed_classes: ActionClass[] | null;
    require_tier_o: ActionClass[]; code_owner_match: "any_path" | "all_paths"; updated_at: Date | string;
  }>(
    `SELECT delegation_enabled, max_expiry_days, allowed_classes, require_tier_o, code_owner_match, updated_at
       FROM delegation_policies WHERE workspace_id = $1`,
    [workspaceId],
  )).rows[0];
  if (!row) return { ...DEFAULT_POLICY };
  return {
    delegation_enabled: row.delegation_enabled,
    max_expiry_days: row.max_expiry_days,
    allowed_classes: row.allowed_classes,
    require_tier_o: row.require_tier_o,
    code_owner_match: row.code_owner_match,
    updated_at: iso(row.updated_at),
  };
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
export async function memberRole(executor: SqlExecutor, workspaceId: string, userId: string): Promise<string | null> {
  if (!UUID.test(userId)) return null;
  const row = (await executor.query<{ role: string }>(
    `SELECT m.role FROM workspaces w
       JOIN organization_memberships m ON m.organization_id = w.organization_id AND m.user_id = $2
       JOIN organizations o ON o.id = w.organization_id
      WHERE w.id = $1`,
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
  jti?: string | null;
  details?: Record<string, unknown>;
  quote?: string | null;
};

/** §15.9: quote text is redacted to its hash after 90 days. */
export const QUOTE_RETENTION_DAYS = 90;

export async function recordDelegationAudit(executor: SqlExecutor, input: AuditInput): Promise<void> {
  await executor.query(
    `INSERT INTO delegation_audit_events
       (id, workspace_id, event, actor_user_id, actor_agent_id, auth_method, owner_user_id, grant_id,
        approval_id, message_id, recipient_agent_id, reason, jti, details, quote, quote_sha256)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb, $15, $16)`,
    [
      randomUUID(), input.workspaceId, input.event,
      input.actorUserId && UUID.test(input.actorUserId) ? input.actorUserId : null,
      input.actorAgentId ?? null, input.authMethod ?? null,
      input.ownerUserId && UUID.test(input.ownerUserId) ? input.ownerUserId : null,
      input.grantId ?? null, input.approvalId ?? null, input.messageId ?? null, input.recipientAgentId ?? null,
      input.reason ?? null, input.jti ?? null, JSON.stringify(input.details ?? {}),
      input.quote ?? null, input.quote ? sha256Hex(input.quote) : null,
    ],
  );
}

export async function redactExpiredQuotes(executor: SqlExecutor): Promise<void> {
  await executor.query(
    `UPDATE delegation_audit_events SET quote = NULL
      WHERE quote IS NOT NULL AND occurred_at < now() - make_interval(days => $1)`,
    [QUOTE_RETENTION_DAYS],
  );
}

/**
 * Revokes grants and invalidates every unredeemed approval under them, in
 * one transaction. Returns the revoked rows (already revoked ones are skipped).
 */
export async function revokeGrants(executor: SqlExecutor, input: {
  workspaceId: string; grantIds: string[]; actorUserId: string | null; reason: string; authMethod: string | null;
}): Promise<GrantRow[]> {
  if (!input.grantIds.length) return [];
  const revoked = (await executor.query<GrantRow>(
    `UPDATE delegation_grants
        SET revoked_at = now(), revoked_by = $3, revoked_reason = $4, updated_at = now()
      WHERE workspace_id = $1 AND id = ANY($2::text[]) AND revoked_at IS NULL
      RETURNING *`,
    [input.workspaceId, input.grantIds, input.actorUserId, input.reason],
  )).rows;
  if (!revoked.length) return [];
  const ids = revoked.map(row => row.id);
  await executor.query(
    `UPDATE delegation_approvals SET invalidated_at = now()
      WHERE workspace_id = $1 AND consumed_at IS NULL AND invalidated_at IS NULL
        AND (grant_id = ANY($2::text[])
          OR id IN (SELECT approval_id FROM delegation_attestations WHERE grant_id = ANY($2::text[])))`,
    [input.workspaceId, ids],
  );
  for (const row of revoked) {
    await recordDelegationAudit(executor, {
      workspaceId: input.workspaceId, event: "grant.revoked", actorUserId: input.actorUserId,
      authMethod: input.authMethod, ownerUserId: row.owner_user_id, grantId: row.id, reason: input.reason,
      details: { delegate_agent_id: row.delegate_agent_id },
    });
  }
  return revoked;
}

class Refusal extends Error {
  constructor(readonly reason: ReasonCode) {
    super(reason);
  }
}

const refuse = (reason: ReasonCode): never => {
  throw new Refusal(reason);
};

/** Relaycast refusing the token is a failed proof; anything else is an outage. */
function relaycastReason(error: unknown): ReasonCode {
  if (error instanceof RelaycastCallError && [401, 403, 404].includes(error.status)) return "not_pending";
  return "unavailable";
}

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
  iat: number;
  exp: number;
  jti: string;
};

export type Standing = "own_owner" | "code_owner";
export type AcceptMode = "code_owners" | "own_owner";

export type TargetOwnerEntry = { pattern: string; repo: string | null; owner_ids: string[] | null };

export async function loadTargetOwners(executor: SqlExecutor, workspaceId: string): Promise<TargetOwnerEntry[]> {
  return (await executor.query<TargetOwnerEntry>(
    "SELECT pattern, repo, owner_ids FROM delegation_target_owners WHERE workspace_id = $1 ORDER BY position",
    [workspaceId],
  )).rows;
}

/**
 * §5.4 standing of `ownerUserId` over one action for a recipient owned by
 * `recipientOwnerId`. The recipient's own owner always has standing. Under
 * `code_owners`, another person needs to be a code owner of the target:
 *
 * - Repo targets (`owner/repo`, `owner/repo#N`) are resolved from CODEOWNERS
 *   on GitHub through a verified, linked GitHub account. relay-control has
 *   no verified person-to-GitHub link, so this fails closed (null).
 * - Other targets use the admin target-owners table: an entry naming the
 *   person by id counts; an entry that points at a repo needs CODEOWNERS and
 *   fails closed; no entry means only the recipient's own owner.
 * - `prompt_approval` never uses code owners.
 */
export function standingFor(action: Pick<Action, "class" | "target">, ownerUserId: string, recipientOwnerId: string,
  accept: AcceptMode, targetOwners: readonly TargetOwnerEntry[]): Standing | null {
  if (ownerUserId === recipientOwnerId) return "own_owner";
  if (accept !== "code_owners" || action.class === "prompt_approval") return null;
  if (REPO_TARGET.test(action.target)) return null;
  const named = targetOwners.some(entry => entry.owner_ids?.includes(ownerUserId)
    && classTargetCovered(action.class, entry.pattern, action.target));
  return named ? "code_owner" : null;
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

/** Steps shared by attest and redeem: the recipient is the caller's own agent, proven by its own token. */
async function proveRecipient(deps: DelegationDeps, input: RecipientInput): Promise<AgentBinding> {
  const { workspace } = input;
  // No Relaycast call precedes the owner check, so a foreign recipient cannot
  // probe whether a message or agent exists.
  const recipient = await resolveBinding(deps.database, workspace.id, workspace.relaycastWorkspaceId,
    input.recipientAgentId, false);
  if (!recipient || recipient.userId !== input.callerUserId) refuse("not_pending");
  let authenticated;
  try {
    authenticated = await deps.relaycast.authenticatedAgent(input.recipientToken);
  } catch (error) {
    return refuse(relaycastReason(error));
  }
  if (authenticated.id !== recipient!.agentId || authenticated.name !== recipient!.name ||
      (recipient!.address && authenticated.address !== recipient!.address) ||
      (authenticated.workspaceId && authenticated.workspaceId !== workspace.relaycastWorkspaceId)) {
    refuse("not_pending");
  }
  return recipient!;
}

/**
 * The delegate is still bound to the grant's owner by the same immutable id
 * and still a live agent of that name. When it is not, every live grant of
 * the pair is revoked (§7 automatic revocation).
 */
async function checkDelegateBinding(deps: DelegationDeps, workspace: DelegationWorkspace, ownerUserId: string,
  delegateAgentId: string, grantIds: string[]): Promise<AgentBinding> {
  const revokeAll = async (reason: string): Promise<never> => {
    await deps.database.transaction(tx => revokeGrants(tx, {
      workspaceId: workspace.id, grantIds, actorUserId: null, reason, authMethod: "system",
    }));
    return refuse("revoked");
  };
  if (!await memberRole(deps.database, workspace.id, ownerUserId)) return revokeAll("owner_left");
  const binding = await resolveBinding(deps.database, workspace.id, workspace.relaycastWorkspaceId, delegateAgentId, true);
  if (!binding || binding.userId !== ownerUserId) return revokeAll("binding_changed");
  let live;
  try {
    live = await deps.relaycast.getRosterAgent(workspace.relaycastApiKey, binding.name);
  } catch {
    return refuse("unavailable");
  }
  if (!live || live.id !== delegateAgentId || live.status === "released") return revokeAll("agent_released");
  return binding;
}

async function loadGrants(executor: SqlExecutor, workspaceId: string, ownerUserId: string, delegateAgentId: string) {
  if (!UUID.test(ownerUserId)) return [];
  return (await executor.query<GrantRow>(
    `SELECT * FROM delegation_grants
      WHERE workspace_id = $1 AND owner_user_id = $2 AND delegate_agent_id = $3
      ORDER BY created_at`,
    [workspaceId, ownerUserId, delegateAgentId],
  )).rows;
}

/** No live grant: say why, most specific first. */
function noLiveGrant(grants: GrantRow[]): never {
  if (!grants.length) return refuse("not_delegate");
  return refuse(grants.some(grant => grant.revoked_at) ? "revoked" : "expired");
}

/**
 * POST .../messaging/delegation. The caller (route) has already proven a
 * Desktop-verified bearer of a current member of `workspace`.
 */
export async function attestDelegation(deps: DelegationDeps, input: RecipientInput & {
  messageId: string;
  accept: AcceptMode;
}): Promise<DelegationVerdict> {
  const { workspace } = input;
  const context: { ownerUserId?: string; grantId?: string; approvalId?: string; senderId?: string } = {};
  try {
    if (deps.gateOnly || !deps.signer) refuse("unavailable");
    const policy = await loadPolicy(deps.database, workspace.id);
    if (!policy.delegation_enabled) refuse("not_enabled");
    const recipient = await proveRecipient(deps, input);

    let delivered;
    try {
      delivered = await deps.relaycast.pendingDeliveryForMessage(input.recipientToken, input.messageId);
    } catch (error) {
      return refuse(relaycastReason(error));
    }
    if (!delivered || delivered.message_id !== input.messageId ||
        delivered.workspace_id !== workspace.relaycastWorkspaceId) refuse("not_pending");
    const senderId = delivered!.sender_agent_id;
    if (!senderId) refuse("not_delegate");
    context.senderId = senderId!;
    if (delivered!.owner_approval === null || delivered!.owner_approval === undefined) refuse("no_approval");
    const parsed = ownerApprovalSchema.safeParse(delivered!.owner_approval);
    if (!parsed.success) refuse("no_approval");
    const approval = parsed.data!;
    context.ownerUserId = approval.owner_id;

    const grants = await loadGrants(deps.database, workspace.id, approval.owner_id, senderId!);
    const now = deps.now();
    const live = grants.filter(grant => !grant.revoked_at && time(grant.expires_at) > now.getTime());
    if (!live.length) noLiveGrant(grants);
    await checkDelegateBinding(deps, workspace, approval.owner_id, senderId!, live.map(grant => grant.id));

    // Tier O takes its actions from the owner-minted approval object.
    let tier: "D" | "O" = "D";
    let actions: Action[] = approval.actions.map(canonicalAction);
    let minted: ApprovalRow | undefined;
    if (approval.approval_ref) {
      minted = (await deps.database.query<ApprovalRow>(
        "SELECT * FROM delegation_approvals WHERE id = $1 AND workspace_id = $2 AND tier = 'O'",
        [approval.approval_ref, workspace.id],
      )).rows[0];
      if (!minted || minted.owner_user_id !== approval.owner_id) refuse("no_approval");
      context.approvalId = minted!.id;
      if (minted!.invalidated_at) refuse("revoked");
      if (minted!.consumed_at) refuse("consumed");
      if (time(minted!.expires_at) <= now.getTime()) refuse("expired");
      if (!sameActions(minted!.actions, approval.actions)) refuse("out_of_scope");
      tier = "O";
      actions = minted!.actions.map(canonicalAction);
    }
    // prompt_approval names one request of one session: this recipient's.
    if (actions.some(action => action.class === "prompt_approval" && promptTarget(action.target)?.agentId !== recipient.agentId)) {
      refuse("out_of_scope");
    }

    if (policy.allowed_classes && actions.some(action => !policy.allowed_classes!.includes(action.class))) {
      refuse("out_of_scope");
    }
    const covering = live.filter(grant => actionsCovered(grant.scopes, actions));
    if (!covering.length) refuse("out_of_scope");
    const eligible = tier === "O" ? covering
      : covering.filter(grant => !tierORequired(actions, policy.require_tier_o, grant.require_tier_o));
    if (!eligible.length) refuse("tier_o_required");

    // §5.4: standing is checked per action; one failure refuses the whole approval.
    const targetOwners = input.accept === "code_owners" && approval.owner_id !== recipient.userId
      ? await loadTargetOwners(deps.database, workspace.id) : [];
    const standings = actions.map(action => standingFor(action, approval.owner_id, recipient.userId, input.accept, targetOwners));
    if (standings.some(item => item === null)) refuse("recipient_policy");
    const standing: Standing = standings.every(item => item === "own_owner") ? "own_owner" : "code_owner";
    const grant = eligible[0]!;
    context.grantId = grant.id;

    const singleUse = (minted?.single_use ?? false) || actions.some(highRisk);
    const approvalId = minted?.id ?? tierDApprovalId(workspace.id, input.messageId);
    context.approvalId = approvalId;
    let approvalExpiry: number;
    if (minted) {
      approvalExpiry = time(minted.expires_at);
    } else {
      // The first attestation fixes a tier D approval's expiry: the sender's
      // expires_at, defaulting to 1 hour and never past 24 hours from when
      // Control first saw it (or Relaycast's send time, when it reports one).
      const sentAt = Math.min(now.getTime(), delivered!.created_at ? Date.parse(delivered!.created_at) || now.getTime() : now.getTime());
      const requested = approval.expires_at ? Date.parse(approval.expires_at) : sentAt + APPROVAL_DEFAULT_MS;
      const expiry = new Date(Math.min(requested, sentAt + APPROVAL_MAX_MS));
      await deps.database.query(
        `INSERT INTO delegation_approvals
           (id, workspace_id, owner_user_id, tier, grant_id, message_id, actions, single_use, expires_at)
         VALUES ($1, $2, $3, 'D', $4, $5, $6::jsonb, $7, $8)
         ON CONFLICT (id) DO NOTHING`,
        [approvalId, workspace.id, approval.owner_id, grant.id, input.messageId,
          JSON.stringify(actions), singleUse, expiry],
      );
      const stored = (await deps.database.query<ApprovalRow>(
        "SELECT * FROM delegation_approvals WHERE id = $1 AND workspace_id = $2",
        [approvalId, workspace.id],
      )).rows[0];
      if (!stored || stored.tier !== "D" || stored.message_id !== input.messageId) refuse("no_approval");
      if (stored!.invalidated_at) refuse("revoked");
      if (stored!.consumed_at) refuse("consumed");
      approvalExpiry = time(stored!.expires_at);
    }
    approvalExpiry = Math.min(approvalExpiry, time(grant.expires_at));
    if (approvalExpiry <= now.getTime()) refuse("expired");

    // Membership may have been revoked during the network calls.
    if (!await memberRole(deps.database, workspace.id, input.callerUserId)) refuse("not_pending");

    const owner = (await deps.database.query<{ name: string | null }>(
      "SELECT name FROM users WHERE id = $1", [approval.owner_id],
    )).rows[0];
    const iat = Math.floor(now.getTime() / 1000);
    const claims: AttestationClaims = {
      v: 1,
      ws: workspace.id,
      owner_id: approval.owner_id,
      owner_display: ownerDisplay(owner?.name),
      delegate_agent_id: senderId!,
      grant_id: grant.id,
      message_id: input.messageId,
      recipient_agent_id: recipient.agentId,
      approval_id: approvalId,
      tier,
      actions,
      standing,
      single_use: singleUse,
      iat,
      exp: Math.min(iat + ATTESTATION_TTL_SECONDS, Math.floor(approvalExpiry / 1000)),
      jti: base62(randomBytes(16)),
    };
    if (claims.exp <= iat) refuse("expired");
    const attestation = deps.signer!.sign(claims);
    await deps.database.transaction(async (tx) => {
      await tx.query(
        `INSERT INTO delegation_attestations
           (jti, workspace_id, approval_id, grant_id, message_id, recipient_agent_id, delegate_agent_id, issued_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, to_timestamp($8), to_timestamp($9))`,
        [claims.jti, workspace.id, approvalId, grant.id, input.messageId, recipient.agentId, senderId, iat, claims.exp],
      );
      await recordDelegationAudit(tx, {
        workspaceId: workspace.id, event: "approval.attested", actorAgentId: senderId, ownerUserId: approval.owner_id,
        grantId: grant.id, approvalId, messageId: input.messageId, recipientAgentId: recipient.agentId,
        jti: claims.jti, quote: approval.quote ?? null,
        details: { tier, actions: claims.actions, single_use: singleUse, quote_source: approval.quote_source ?? null,
          quoted_at: approval.quoted_at ?? null, accept: input.accept, standing },
      });
      await redactExpiredQuotes(tx);
    });
    return { verdict: "delegate", attestation, claims };
  } catch (error) {
    const reason: ReasonCode = error instanceof Refusal ? error.reason : "unavailable";
    await recordDelegationAudit(deps.database, {
      workspaceId: workspace.id, event: "approval.refused", actorUserId: input.callerUserId,
      actorAgentId: context.senderId ?? null, ownerUserId: context.ownerUserId ?? null,
      grantId: context.grantId ?? null, approvalId: context.approvalId ?? null,
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
 * conditions need the PR's state through a GitHub App installation that
 * relay-control does not consult for delegation, so they fail closed with
 * `condition_unavailable`.
 */
export function evaluateConditions(conditions: readonly Condition[], now: Date):
  { status: "met" } | { status: "unmet"; unmet: Condition[] } | { status: "unavailable" } {
  if (conditions.some(condition => GITHUB_CONDITIONS.has(condition.type))) return { status: "unavailable" };
  const unmet = conditions.filter(condition => condition.type === "not_before" && Date.parse(condition.at) > now.getTime());
  return unmet.length ? { status: "unmet", unmet } : { status: "met" };
}

class ConditionUnmet extends Error {
  constructor(readonly unmet: Condition[]) {
    super("condition_unmet");
  }
}

/**
 * POST .../messaging/delegation/redeem. Re-checks revocation, binding, scope
 * and expiry, then consumes a single-use approval with one conditional
 * UPDATE: a second redeem, or one racing a revocation, is refused.
 */
export async function redeemApproval(deps: DelegationDeps, input: RecipientInput & {
  approvalId: string;
  action: { class: ActionClass; target: string };
}): Promise<RedeemResult> {
  const { workspace } = input;
  const context: { ownerUserId?: string; grantId?: string } = {};
  try {
    if (deps.gateOnly) refuse("unavailable");
    const policy = await loadPolicy(deps.database, workspace.id);
    if (!policy.delegation_enabled) refuse("not_enabled");
    const recipient = await proveRecipient(deps, input);
    const approval = (await deps.database.query<ApprovalRow>(
      "SELECT * FROM delegation_approvals WHERE id = $1 AND workspace_id = $2",
      [input.approvalId, workspace.id],
    )).rows[0];
    if (!approval) refuse("no_approval");
    context.ownerUserId = approval!.owner_user_id;
    const attestation = (await deps.database.query<{ grant_id: string; delegate_agent_id: string }>(
      `SELECT grant_id, delegate_agent_id FROM delegation_attestations
        WHERE workspace_id = $1 AND approval_id = $2 AND recipient_agent_id = $3
        ORDER BY issued_at DESC LIMIT 1`,
      [workspace.id, input.approvalId, recipient.agentId],
    )).rows[0];
    if (!attestation) refuse("not_pending");
    context.grantId = attestation!.grant_id;
    const grant = (await deps.database.query<GrantRow>(
      "SELECT * FROM delegation_grants WHERE id = $1 AND workspace_id = $2", [attestation!.grant_id, workspace.id],
    )).rows[0];
    const now = deps.now();
    if (!grant || grant.revoked_at || approval!.invalidated_at) refuse("revoked");
    if (time(grant!.expires_at) <= now.getTime()) refuse("expired");
    await checkDelegateBinding(deps, workspace, grant!.owner_user_id, attestation!.delegate_agent_id, [grant!.id]);
    const stored = approval!.actions.find(action => action.class === input.action.class && action.target === input.action.target);
    if (!stored || !actionsCovered(grant!.scopes, [input.action]) ||
        (policy.allowed_classes && !policy.allowed_classes.includes(input.action.class))) refuse("out_of_scope");
    if (approval!.consumed_at) refuse("consumed");
    if (Math.min(time(approval!.expires_at), time(grant!.expires_at)) <= now.getTime()) refuse("expired");
    // Unmet conditions do not consume the approval; the agent may redeem again.
    const checked = evaluateConditions(stored!.conditions ?? [], now);
    if (checked.status === "unavailable") refuse("condition_unavailable");
    if (checked.status === "unmet") throw new ConditionUnmet(checked.unmet);
    if (approval!.single_use) {
      const consumed = await deps.database.transaction(async (tx) => {
        const row = (await tx.query<{ id: string }>(
          `UPDATE delegation_approvals
              SET consumed_at = now(), consumed_by_agent_id = $3, consumed_action = $4::jsonb
            WHERE id = $1 AND workspace_id = $2 AND consumed_at IS NULL AND invalidated_at IS NULL
              AND expires_at > now()
              AND EXISTS (SELECT 1 FROM delegation_grants g
                           WHERE g.id = $5 AND g.revoked_at IS NULL AND g.expires_at > now())
            RETURNING id`,
          [input.approvalId, workspace.id, recipient.agentId, JSON.stringify(input.action), grant!.id],
        )).rows[0];
        if (!row) return false;
        await recordDelegationAudit(tx, {
          workspaceId: workspace.id, event: "approval.redeemed", actorUserId: input.callerUserId,
          ownerUserId: grant!.owner_user_id, grantId: grant!.id, approvalId: input.approvalId,
          recipientAgentId: recipient.agentId, details: { action: input.action, single_use: true },
        });
        return true;
      });
      if (!consumed) {
        const current = (await deps.database.query<ApprovalRow>(
          "SELECT * FROM delegation_approvals WHERE id = $1", [input.approvalId],
        )).rows[0];
        refuse(current?.invalidated_at ? "revoked" : current?.consumed_at ? "consumed" : "expired");
      }
    } else {
      await recordDelegationAudit(deps.database, {
        workspaceId: workspace.id, event: "approval.redeemed", actorUserId: input.callerUserId,
        ownerUserId: grant!.owner_user_id, grantId: grant!.id, approvalId: input.approvalId,
        recipientAgentId: recipient.agentId, details: { action: input.action, single_use: false },
      });
    }
    return { ok: true, consumed: approval!.single_use };
  } catch (error) {
    const reason: ReasonCode = error instanceof ConditionUnmet ? "condition_unmet"
      : error instanceof Refusal ? error.reason : "unavailable";
    await recordDelegationAudit(deps.database, {
      workspaceId: workspace.id, event: "redeem.refused", actorUserId: input.callerUserId,
      ownerUserId: context.ownerUserId ?? null, grantId: context.grantId ?? null, approvalId: input.approvalId,
      recipientAgentId: input.recipientAgentId, reason,
      details: { action: input.action, ...(error instanceof ConditionUnmet ? { unmet: error.unmet } : {}) },
    }).catch(() => undefined);
    return error instanceof ConditionUnmet ? { ok: false, reason, unmet: error.unmet } : { ok: false, reason };
  }
}

/**
 * POST .../messaging/delegation/prompt-delegates (§9.3): the machine owner's
 * delegates whose live grants cover `prompt_approval` for this session. The
 * session is the caller's own agent, proven by its own token. Delegation
 * off, or prompt_approval outside the policy, is an empty list.
 */
export async function promptDelegates(deps: DelegationDeps, input: RecipientInput):
  Promise<{ delegates: Array<{ agent_id: string; grant_id: string }> }> {
  const { workspace } = input;
  if (deps.gateOnly) return { delegates: [] };
  const policy = await loadPolicy(deps.database, workspace.id);
  if (!policy.delegation_enabled || (policy.allowed_classes && !policy.allowed_classes.includes("prompt_approval"))) {
    return { delegates: [] };
  }
  let session: AgentBinding;
  try {
    session = await proveRecipient(deps, input);
  } catch (error) {
    if (error instanceof Refusal) return { delegates: [] };
    throw error;
  }
  const grants = (await deps.database.query<GrantRow>(
    `SELECT * FROM delegation_grants
      WHERE workspace_id = $1 AND owner_user_id = $2 AND revoked_at IS NULL AND expires_at > now()
      ORDER BY created_at`,
    [workspace.id, session.userId],
  )).rows;
  const probe = `${session.agentId}:probe`;
  const delegates: Array<{ agent_id: string; grant_id: string }> = [];
  const seen = new Set<string>();
  for (const grant of grants) {
    if (grant.delegate_agent_id === session.agentId || seen.has(grant.delegate_agent_id)) continue;
    if (!actionsCovered(grant.scopes, [{ class: "prompt_approval", target: probe }])) continue;
    const binding = await resolveBinding(deps.database, workspace.id, workspace.relaycastWorkspaceId,
      grant.delegate_agent_id, true);
    if (!binding || binding.userId !== session.userId) continue;
    seen.add(grant.delegate_agent_id);
    delegates.push({ agent_id: grant.delegate_agent_id, grant_id: grant.id });
  }
  return { delegates };
}
