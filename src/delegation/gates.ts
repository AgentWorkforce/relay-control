import type { SqlExecutor } from "../database.js";
import type { WorkflowClaims } from "./oidc.js";
import { canonicalAction, highRisk, validReleaseTarget, type ActionClass, type Condition, type ReasonCode } from "./scope.js";
import {
  ConditionUnmet,
  delegateStillBound,
  evaluateConditions,
  loadPolicy,
  memberRole,
  recordDelegationAudit,
  refuse,
  Refusal,
  scopeRefusal,
  time,
  tierOClasses,
  type ApprovalRow,
  type DelegationDeps,
  type DelegationWorkspace,
  type GrantRow,
} from "./service.js";

/**
 * Release gates (relay docs/design/owner-trusted-delegates.md §11a.3). The
 * job that publishes redeems the approval itself with its workflow OIDC
 * token. A gate pins exactly which workflow may: repository, job_workflow_ref,
 * ref and event must all match, because a workflow file edited on another
 * branch also gets a token for the same repository.
 */

export type GateRow = {
  id: string;
  workspace_id: string;
  owner_user_id: string;
  repo: string;
  job_workflow_ref: string;
  ref: string | null;
  ref_pattern: string | null;
  event: string;
  target_prefix: string;
  created_auth_method: string;
  created_at: Date | string;
  deleted_at: Date | string | null;
};

export function gateView(row: GateRow) {
  return {
    gate_id: row.id,
    repo: row.repo,
    job_workflow_ref: row.job_workflow_ref,
    ref: row.ref,
    ref_pattern: row.ref_pattern,
    event: row.event,
    target_prefix: row.target_prefix,
    owner_id: row.owner_user_id,
    created_at: new Date(row.created_at).toISOString(),
  };
}

export type GateRedeemResult =
  | { ok: true; consumed: boolean; same_run?: true }
  | { ok: true; dry_run: true }
  | { ok: false; reason: ReasonCode; unmet?: Condition[]; dry_run?: true };

/**
 * A gate's ref check: `ref` matches exactly; `ref_pattern` is
 * `refs/tags/<literal prefix>*` with one trailing `*`, matched as a prefix.
 */
export function gateRefMatches(gate: Pick<GateRow, "ref" | "ref_pattern">, ref: string): boolean {
  if (gate.ref !== null) return gate.ref === ref;
  const pattern = gate.ref_pattern;
  if (!pattern || !pattern.startsWith("refs/tags/") || !pattern.endsWith("*")) return false;
  return ref.startsWith("refs/tags/") && ref.startsWith(pattern.slice(0, -1));
}

/**
 * POST .../delegates/gates/redeem after the route verified the workflow
 * token. Order: the gate (by the token's exact workflow identity), then the
 * normal redeem checks on the approval, then the gate's target prefix, then
 * single-use consumption bound to the run.
 */
export async function redeemThroughGate(deps: DelegationDeps, input: {
  workspace: DelegationWorkspace;
  claims: WorkflowClaims;
  approvalId: string;
  action: { class: ActionClass; target: string };
  /** Runs every check and never consumes (§11a.3 dry run). */
  dryRun?: boolean;
}): Promise<GateRedeemResult> {
  const { workspace, claims } = input;
  const now = deps.now();
  const context: { gateId?: string; ownerUserId?: string; grantId?: string } = {};
  const audit = (event: string, reason: ReasonCode | null, extra: Record<string, unknown> = {}) =>
    recordDelegationAudit(deps.database, {
      workspaceId: workspace.id, event, authMethod: "workflow_oidc", ownerUserId: context.ownerUserId ?? null,
      grantId: context.grantId ?? null, approvalId: input.approvalId, reason,
      data: { gate_id: context.gateId ?? null, action: input.action, issuer: claims.issuer, repository: claims.repository,
        job_workflow_ref: claims.job_workflow_ref, ref: claims.ref, event_name: claims.event_name,
        run_id: claims.run_id, run_attempt: claims.run_attempt, ...extra },
    });
  try {
    const policy = await loadPolicy(deps.database, workspace.id);
    if (!policy.delegation_enabled) refuse("not_enabled");
    const repoGates = (await deps.database.query<GateRow>(
      "SELECT * FROM delegation_gates WHERE workspace_id = $1 AND repo = $2 AND deleted_at IS NULL",
      [workspace.id, claims.repository],
    )).rows;
    if (!repoGates.length) refuse("gate_unknown");
    const approval = (await deps.database.query<ApprovalRow>(
      "SELECT * FROM delegation_approvals WHERE id = $1 AND workspace_id = $2", [input.approvalId, workspace.id],
    )).rows[0];
    if (!approval) refuse("no_approval");
    context.ownerUserId = approval!.owner_user_id;
    // The gate must be the approval owner's own registration.
    const ownerGates = repoGates.filter(gate => gate.owner_user_id === approval!.owner_user_id);
    if (!ownerGates.length) refuse("gate_unknown");
    const gate = ownerGates.find(item => item.job_workflow_ref === claims.job_workflow_ref &&
      gateRefMatches(item, claims.ref) && item.event === claims.event_name);
    if (!gate) refuse("gate_mismatch");
    context.gateId = gate!.id;

    if (approval!.invalidated_at) refuse("revoked");
    if (!await memberRole(deps.database, workspace.id, approval!.owner_user_id)) refuse("revoked");
    const action = approval!.actions.find(item => item.class === input.action.class && item.target === input.action.target);
    if (!action) refuse("out_of_scope");
    if (action!.class === "release" && !validReleaseTarget(action!.target)) refuse("out_of_scope");
    if (policy.allowed_classes && !policy.allowed_classes.includes(action!.class)) refuse("out_of_scope");
    if (approval!.tier === "D") {
      // A delegate's approval: its grant and binding are re-checked, as at redeem.
      const grantId = approval!.grant_id;
      const grant = grantId ? (await deps.database.query<GrantRow>(
        "SELECT * FROM delegation_grants WHERE id = $1 AND workspace_id = $2", [grantId, workspace.id],
      )).rows[0] : undefined;
      context.grantId = grant?.id;
      if (!grant || grant.status === "revoked") refuse("revoked");
      if (grant!.status === "expired" || time(grant!.expires_at) <= now.getTime()) refuse("expired");
      const unbound = await delegateStillBound(deps, workspace, grant!, true);
      if (unbound) refuse(unbound);
      const outOfScope = scopeRefusal([action!], grant!, policy, "");
      if (outOfScope) refuse(outOfScope);
      if (tierOClasses(policy, grant!).has(action!.class)) refuse("tier_o_required");
    }
    if (time(approval!.expires_at) <= now.getTime()) refuse("expired");
    if (!action!.target.startsWith(gate!.target_prefix)) refuse("target_prefix");
    const conditions = evaluateConditions(action!.conditions ?? [], now);
    if (conditions.kind === "unavailable") refuse("condition_unavailable");
    if (conditions.kind === "unmet") throw new ConditionUnmet(conditions.unmet);

    // The run this approval is bound to, if a gate redeem already consumed it.
    const boundRun = async (executor: SqlExecutor) => {
      const bound = (await executor.query<{ run_id: string; repository: string; issuer: string }>(
        "SELECT run_id, repository, issuer FROM delegation_gate_redemptions WHERE approval_id = $1", [approval!.id],
      )).rows[0];
      return Boolean(bound && bound.run_id === claims.run_id && bound.repository === claims.repository &&
        bound.issuer === claims.issuer);
    };
    if (input.dryRun) {
      // What a real redeem would answer, without consuming anything.
      if (approval!.consumed_at && !await boundRun(deps.database)) refuse("consumed");
      await audit("gate.dry_run", null, { dry_run: true }).catch(() => undefined);
      return { ok: true, dry_run: true };
    }
    // Single use per run: the first redeem consumes the approval and binds it
    // to this run; any later redeem in the same run (another job, or a later
    // attempt) is same_run.
    const outcome = await deps.database.transaction(async (tx: SqlExecutor) => {
      const consumed = (await tx.query<{ id: string }>(
        `UPDATE delegation_approvals
            SET consumed_at = now(), consumed_by_agent_id = NULL, consumed_action = $3::jsonb
          WHERE id = $1 AND workspace_id = $2 AND consumed_at IS NULL AND invalidated_at IS NULL
          RETURNING id`,
        [approval!.id, workspace.id, JSON.stringify(canonicalAction(action!))],
      )).rows[0];
      if (consumed) {
        await tx.query(
          `INSERT INTO delegation_gate_redemptions
             (approval_id, workspace_id, gate_id, issuer, repository, run_id, run_attempt, action)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
          [approval!.id, workspace.id, gate!.id, claims.issuer, claims.repository, claims.run_id, claims.run_attempt,
            JSON.stringify(canonicalAction(action!))],
        );
        return "consumed" as const;
      }
      return await boundRun(tx) ? "same_run" as const : "refused" as const;
    });
    if (outcome === "refused") {
      const current = (await deps.database.query<ApprovalRow>(
        "SELECT * FROM delegation_approvals WHERE id = $1", [approval!.id],
      )).rows[0];
      refuse(current?.invalidated_at && !current.consumed_at ? "revoked" : "consumed");
    }
    const sameRun = outcome === "same_run";
    await audit("gate.redeemed", null, { consumed: true, same_run: sameRun, single_use: approval!.single_use || highRisk(action!) })
      .catch(() => undefined);
    return sameRun ? { ok: true, consumed: true, same_run: true } : { ok: true, consumed: true };
  } catch (error) {
    const reason: ReasonCode = error instanceof ConditionUnmet ? "condition_unmet"
      : error instanceof Refusal ? error.reason : "unavailable";
    const unmet = error instanceof ConditionUnmet ? error.unmet : undefined;
    const dry = input.dryRun ? { dry_run: true as const } : {};
    await audit(input.dryRun ? "gate.dry_run" : "gate.refused", reason, { ...(unmet ? { unmet } : {}), ...dry })
      .catch(() => undefined);
    return { ok: false, reason, ...(unmet ? { unmet } : {}), ...dry };
  }
}
