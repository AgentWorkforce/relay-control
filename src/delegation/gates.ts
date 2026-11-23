import type { SqlExecutor } from "../database.js";
import { OidcInvalid, type WorkflowClaims, type WorkflowOidcVerifier } from "./oidc.js";
import { actionIsValid, canonicalAction, type ActionClass, type Condition, type ReasonCode } from "./scope.js";
import {
  delegateStillBound,
  evaluateConditions,
  loadPolicy,
  loadTargetOwners,
  memberRole,
  recordDelegationAudit,
  resolveStanding,
  scopeRefusal,
  time,
  tierOClasses,
  type ApprovalRow,
  type DelegationDeps,
  type DelegationWorkspace,
  type GrantRow,
} from "./service.js";

/**
 * Release gates (relay docs/design/owner-trusted-delegates.md §11a.3), kept
 * check-for-check with Cloud's lib/delegation/gates.ts. The job that publishes
 * redeems the approval itself with its workflow OIDC token. A gate pins
 * exactly which workflow may: repository, job_workflow_ref, ref (or a
 * `refs/tags/<prefix>*` ref_pattern) and event must all match, because a
 * workflow file edited on another branch also gets a token for the same
 * repository.
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

/** The gate as the API shows it (Cloud's Gate): exactly one of `ref` and `ref_pattern` is present. */
export function gateView(row: GateRow) {
  return {
    gate_id: row.id,
    owner_id: row.owner_user_id,
    repo: row.repo,
    job_workflow_ref: row.job_workflow_ref,
    ...(row.ref ? { ref: row.ref } : {}),
    ...(row.ref_pattern ? { ref_pattern: row.ref_pattern } : {}),
    event: row.event,
    target_prefix: row.target_prefix,
    created_at: new Date(row.created_at).toISOString(),
  };
}

export type GateRedeemResult =
  | { ok: true; consumed: true; same_run?: true }
  | { ok: true; dry_run: true }
  | { ok: false; reason: ReasonCode; unmet?: Condition[]; dry_run?: true };

/**
 * Every one of repository, job_workflow_ref, ref and event_name must match
 * exactly. A gate with `ref_pattern` (`refs/tags/<prefix>*`) matches a tag ref
 * that starts with that prefix (and is longer than it) instead of one exact ref.
 */
export function gateMatches(gate: Pick<GateRow, "repo" | "job_workflow_ref" | "ref" | "ref_pattern" | "event">,
  claims: Pick<WorkflowClaims, "repository" | "job_workflow_ref" | "ref" | "event_name">): boolean {
  const refMatches = gate.ref !== null ? gate.ref === claims.ref :
    gate.ref_pattern !== null && /^refs\/tags\/[^\s*]+\*$/u.test(gate.ref_pattern) &&
      claims.ref.startsWith(gate.ref_pattern.slice(0, -1)) && claims.ref.length > gate.ref_pattern.length - 1;
  return gate.repo === claims.repository && gate.job_workflow_ref === claims.job_workflow_ref && refMatches &&
    gate.event === claims.event_name;
}

/**
 * POST .../delegates/gates/redeem. Order, as Cloud: delegation on, the token,
 * the gate (repository, then exact workflow identity, then target prefix), the
 * approval and the normal redeem checks, then single-use consumption bound to
 * the run. `dryRun` runs every check and consumes nothing.
 */
export async function redeemThroughGate(deps: DelegationDeps, input: {
  workspace: DelegationWorkspace;
  verifyOidc: WorkflowOidcVerifier;
  oidcToken: string;
  approvalId: string;
  action: { class: ActionClass; target: string };
  dryRun?: boolean;
}): Promise<GateRedeemResult> {
  const { workspace } = input;
  const dryRun = input.dryRun === true;
  const now = deps.now();
  let claims: WorkflowClaims | null = null;
  let gate: GateRow | null = null;
  let ownerUserId: string | null = null;
  let grantId: string | null = null;
  const audit = (event: string, reason: ReasonCode | null, extra: Record<string, unknown> = {}) =>
    recordDelegationAudit(deps.database, {
      workspaceId: workspace.id, event, authMethod: "github_oidc", ownerUserId, grantId, approvalId: input.approvalId,
      reason,
      data: { action: input.action, gate_id: gate?.id ?? null,
        ...(claims ? { issuer: claims.issuer, repository: claims.repository, job_workflow_ref: claims.job_workflow_ref,
          ref: claims.ref, event_name: claims.event_name, run_id: claims.run_id, run_attempt: claims.run_attempt } : {}),
        ...(dryRun ? { dry_run: true } : {}), ...extra },
    });
  const refuse = async (reason: ReasonCode, unmet?: Condition[], detail?: string): Promise<GateRedeemResult> => {
    await audit("gate.refused", reason, { ...(unmet ? { unmet } : {}), ...(detail ? { detail } : {}) }).catch(() => undefined);
    return { ok: false, reason, ...(unmet ? { unmet } : {}), ...(dryRun ? { dry_run: true as const } : {}) };
  };
  try {
    const policy = await loadPolicy(deps.database, workspace.id);
    if (!policy.delegation_enabled) return await refuse("not_enabled");
    if (deps.gateOnly) return await refuse("unavailable");
    try {
      claims = await input.verifyOidc(input.oidcToken);
    } catch (error) {
      // An unverified token's claims are never trusted, so none are logged.
      return await refuse("oidc_invalid", undefined, error instanceof OidcInvalid ? error.detail : "error");
    }
    const registered = (await deps.database.query<GateRow>(
      "SELECT * FROM delegation_gates WHERE workspace_id = $1 AND repo = $2 AND deleted_at IS NULL",
      [workspace.id, claims.repository],
    )).rows;
    if (!registered.length) return await refuse("gate_unknown");
    // Matching the repository alone is not enough: a workflow edited on
    // another branch also gets a token for the same repository.
    const exact = registered.filter(item => gateMatches(item, claims!));
    if (!exact.length) return await refuse("gate_mismatch");
    gate = exact.find(item => input.action.target.startsWith(item.target_prefix)) ?? null;
    if (!gate) return await refuse("target_prefix");

    const approval = (await deps.database.query<ApprovalRow>(
      "SELECT * FROM delegation_approvals WHERE id = $1 AND workspace_id = $2", [input.approvalId, workspace.id],
    )).rows[0];
    if (!approval) return await refuse("no_approval");
    ownerUserId = approval.owner_user_id;
    grantId = approval.grant_id;
    const action = approval.actions.find(item => item.class === input.action.class && item.target === input.action.target);
    if (!action || !actionIsValid(action)) return await refuse("out_of_scope");
    if (approval.invalidated_at) return await refuse("revoked");

    // Tier D rests on a live grant and a still-bound delegate; both tiers on a current owner.
    if (approval.tier === "D") {
      const grant = approval.grant_id ? (await deps.database.query<GrantRow>(
        "SELECT * FROM delegation_grants WHERE id = $1 AND workspace_id = $2", [approval.grant_id, workspace.id],
      )).rows[0] : undefined;
      if (!grant || grant.status === "revoked") return await refuse("revoked");
      if (grant.status === "expired" || time(grant.expires_at) <= now.getTime()) return await refuse("expired");
      const unbound = await delegateStillBound(deps, workspace, grant, true);
      if (unbound) return await refuse(unbound);
      const outOfScope = scopeRefusal([action], grant, policy, "");
      if (outOfScope) return await refuse(outOfScope);
      if (tierOClasses(policy, grant).has(action.class)) return await refuse("tier_o_required");
    } else {
      if (!await memberRole(deps.database, workspace.id, approval.owner_user_id)) return await refuse("revoked");
      if (policy.allowed_classes && !policy.allowed_classes.includes(action.class)) return await refuse("out_of_scope");
    }

    // A consumed approval answers only the run that consumed it: another job
    // of the same workflow run, or a later attempt of it.
    if (approval.consumed_at) {
      const prior = (await deps.database.query<{ run_id: string; repository: string; issuer: string }>(
        "SELECT run_id, repository, issuer FROM delegation_gate_redemptions WHERE approval_id = $1", [approval.id],
      )).rows[0];
      if (!prior || prior.run_id !== claims.run_id || prior.repository !== claims.repository || prior.issuer !== claims.issuer) {
        return await refuse("consumed");
      }
    } else {
      if (time(approval.expires_at) <= now.getTime()) return await refuse("expired");
      // The gate's owner stands where a recipient's owner would (§5.4).
      const standing = resolveStanding({ approvalOwnerId: approval.owner_user_id, recipientOwnerId: gate.owner_user_id,
        accept: "code_owners", actions: [action],
        targetOwners: approval.owner_user_id === gate.owner_user_id ? [] : await loadTargetOwners(deps.database, workspace.id) });
      if (!standing) return await refuse("recipient_policy");
      const conditions = evaluateConditions(action.conditions ?? [], now);
      if (conditions.kind === "unavailable") return await refuse("condition_unavailable");
      if (conditions.kind === "unmet") return await refuse("condition_unmet", conditions.unmet);
    }

    if (dryRun) {
      await audit("gate.redeemed", null).catch(() => undefined);
      return { ok: true, dry_run: true };
    }
    // Single use per run, atomically: the first redeem wins and records the
    // run; any later redeem in that run is same_run; any other run is consumed.
    const outcome = await deps.database.transaction(async (tx: SqlExecutor) => {
      const consumed = (await tx.query<{ id: string }>(
        `UPDATE delegation_approvals
            SET consumed_at = now(), consumed_by_agent_id = $3, consumed_action = $4::jsonb
          WHERE id = $1 AND workspace_id = $2 AND consumed_at IS NULL AND invalidated_at IS NULL
          RETURNING id`,
        [approval.id, workspace.id, `github-run:${claims!.run_id}`, JSON.stringify(canonicalAction(action))],
      )).rows[0];
      if (consumed) {
        await tx.query(
          `INSERT INTO delegation_gate_redemptions
             (approval_id, workspace_id, gate_id, issuer, repository, run_id, run_attempt, action)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
          [approval.id, workspace.id, gate!.id, claims!.issuer, claims!.repository, claims!.run_id, claims!.run_attempt,
            JSON.stringify(canonicalAction(action))],
        );
        return "consumed" as const;
      }
      const prior = (await tx.query<{ run_id: string; repository: string; issuer: string }>(
        "SELECT run_id, repository, issuer FROM delegation_gate_redemptions WHERE approval_id = $1 FOR UPDATE", [approval.id],
      )).rows[0];
      return prior && prior.run_id === claims!.run_id && prior.repository === claims!.repository &&
        prior.issuer === claims!.issuer ? "same_run" as const : "taken" as const;
    });
    if (outcome === "taken") return await refuse("consumed");
    const sameRun = outcome === "same_run";
    await audit("gate.redeemed", null, { same_run: sameRun }).catch(() => undefined);
    return sameRun ? { ok: true, consumed: true, same_run: true } : { ok: true, consumed: true };
  } catch {
    return refuse("unavailable");
  }
}
