import type { SqlExecutor } from "../database.js";
import { GITHUB_ACTIONS_OIDC_ISSUER, OidcInvalid, type WorkflowClaims, type WorkflowOidcVerifier } from "./oidc.js";
import { actionIsValid, canonicalAction, type ActionClass, type Condition, type ReasonCode } from "./scope.js";
import {
  actionConsumed,
  consumeAction,
  delegateStillBound,
  recheckAtCommit,
  Refusal,
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
  /** The OIDC issuer the gate trusts (GitHub Actions unless a self-host issuer is named). */
  issuer: string;
  repo: string;
  workflow_ref: string;
  job_workflow_ref: string | null;
  ref: string | null;
  ref_pattern: string | null;
  event: string;
  target_prefix: string;
  repository_id: string | null;
  repository_owner_id: string | null;
  created_auth_method: string;
  created_at: Date | string;
  deleted_at: Date | string | null;
};

/** The gate as the API shows it (Cloud's Gate): exactly one of `ref` and `ref_pattern` is present. */
export function gateView(row: GateRow) {
  return {
    gate_id: row.id,
    owner_id: row.owner_user_id,
    // Present only for a gate on a self-host issuer: Cloud's gates are GitHub Actions only.
    ...(row.issuer !== GITHUB_ACTIONS_OIDC_ISSUER ? { issuer: row.issuer } : {}),
    repo: row.repo,
    workflow_ref: row.workflow_ref,
    ...(row.job_workflow_ref ? { job_workflow_ref: row.job_workflow_ref } : {}),
    ...(row.ref ? { ref: row.ref } : {}),
    ...(row.ref_pattern ? { ref_pattern: row.ref_pattern } : {}),
    event: row.event,
    target_prefix: row.target_prefix,
    ...(row.repository_id ? { repository_id: row.repository_id } : {}),
    ...(row.repository_owner_id ? { repository_owner_id: row.repository_owner_id } : {}),
    created_at: new Date(row.created_at).toISOString(),
  };
}

export type GateRedeemResult =
  | { ok: true; consumed: true; same_run?: true }
  | { ok: true; consumed: false; dry_run: true }
  | { ok: false; reason: ReasonCode; unmet?: Condition[]; dry_run?: true };

/**
 * The workflow refs match as Cloud's workflowMatches: `owner/repo/` is
 * case-insensitive on GitHub, the file path and ref are not.
 */
function workflowRefMatches(want: string, have: string): boolean {
  const split = (value: string) => {
    const at = value.indexOf("/.github/workflows/");
    return at < 0 ? [value, ""] : [value.slice(0, at).toLowerCase(), value.slice(at)];
  };
  const [wantRepo, wantRest] = split(want), [haveRepo, haveRest] = split(have);
  return wantRepo === haveRepo && wantRest === haveRest;
}

/**
 * Every one of repository, workflow_ref, ref and event_name must match, plus
 * job_workflow_ref when the gate names a reusable workflow (§11a.3). A gate
 * with `ref_pattern` (`refs/tags/<prefix>*`) matches a tag ref that starts
 * with that prefix (and is longer than it) instead of one exact ref. A gate
 * pinned to GitHub's repository ids also needs them to match, so a
 * repository that later reuses the name never does. Repository names compare
 * case-insensitively, as on GitHub.
 */
export function gateMatches(gate: Pick<GateRow, "issuer" | "repo" | "workflow_ref" | "job_workflow_ref" | "ref" |
  "ref_pattern" | "event" | "repository_id" | "repository_owner_id">,
  claims: Pick<WorkflowClaims, "issuer" | "repository" | "workflow_ref" | "job_workflow_ref" | "ref" | "event_name" |
    "repository_id" | "repository_owner_id">): boolean {
  if (gate.repository_id && gate.repository_id !== claims.repository_id) return false;
  if (gate.repository_owner_id && gate.repository_owner_id !== claims.repository_owner_id) return false;
  const refMatches = gate.ref !== null ? gate.ref === claims.ref :
    gate.ref_pattern !== null && /^refs\/tags\/[^\s*]+\*$/u.test(gate.ref_pattern) &&
      claims.ref.startsWith(gate.ref_pattern.slice(0, -1)) && claims.ref.length > gate.ref_pattern.length - 1;
  // The issuer is part of the identity: a same-named repository on another
  // trusted issuer (a GitHub Enterprise Server, say) is a different repository.
  return gate.issuer === claims.issuer && gate.repo.toLowerCase() === claims.repository.toLowerCase() &&
    workflowRefMatches(gate.workflow_ref, claims.workflow_ref) &&
    (gate.job_workflow_ref === null || workflowRefMatches(gate.job_workflow_ref, claims.job_workflow_ref)) && refMatches &&
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
        ...(claims ? { issuer: claims.issuer, repository: claims.repository, workflow_ref: claims.workflow_ref,
          job_workflow_ref: claims.job_workflow_ref,
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
      "SELECT * FROM delegation_gates WHERE workspace_id = $1 AND lower(repo) = lower($2) AND deleted_at IS NULL",
      [workspace.id, claims.repository],
    )).rows;
    if (!registered.length) return await refuse("gate_unknown");
    // Matching the repository alone is not enough: a workflow edited on
    // another branch also gets a token for the same repository.
    const exact = registered.filter(item => gateMatches(item, claims!));
    if (!exact.length) return await refuse("gate_mismatch");
    // The first verified match pins the gate to GitHub's repository ids.
    if (claims.repository_id && claims.repository_owner_id) {
      for (const item of exact.filter(candidate => !candidate.repository_id)) {
        await deps.database.query(
          `UPDATE delegation_gates SET repository_id = $2, repository_owner_id = $3
            WHERE id = $1 AND repository_id IS NULL`,
          [item.id, claims.repository_id, claims.repository_owner_id],
        ).catch(() => undefined);
      }
    }
    const candidates = exact.filter(item => input.action.target.startsWith(item.target_prefix));
    if (!candidates.length) return await refuse("target_prefix");
    gate = candidates[0]!;

    const approval = (await deps.database.query<ApprovalRow>(
      "SELECT * FROM delegation_approvals WHERE id = $1 AND workspace_id = $2", [input.approvalId, workspace.id],
    )).rows[0];
    if (!approval) return await refuse("no_approval");
    ownerUserId = approval.owner_user_id;
    grantId = approval.grant_id;
    // Several members may register the same workflow: use the approval
    // owner's own gate when there is one, so another member's registration
    // never blocks a valid release.
    gate = candidates.find(item => item.owner_user_id === approval.owner_user_id) ?? candidates[0]!;
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

    // A consumed action answers only the run that consumed it: another job
    // of the same workflow run, or a later attempt of it.
    const boundRun = async (executor: SqlExecutor) => {
      const prior = (await executor.query<{ run_id: string; repository: string; issuer: string }>(
        `SELECT run_id, repository, issuer FROM delegation_gate_redemptions
          WHERE approval_id = $1 AND class = $2 AND target = $3`,
        [approval.id, action.class, action.target],
      )).rows[0];
      return Boolean(prior && prior.run_id === claims!.run_id && prior.repository === claims!.repository &&
        prior.issuer === claims!.issuer);
    };
    if (await actionConsumed(deps.database, approval.id, action)) {
      if (!await boundRun(deps.database)) return await refuse("consumed");
    } else {
      if (time(approval.expires_at) <= now.getTime()) return await refuse("expired");
      // The gate's owner stands where a recipient's owner would (§5.4); any
      // matching gate whose owner gives the approval owner standing will do.
      // A gate serves only while its owner is still a member.
      const served: GateRow[] = [];
      for (const item of candidates) if (await memberRole(deps.database, workspace.id, item.owner_user_id)) served.push(item);
      const targetOwners = served.some(item => item.owner_user_id === approval.owner_user_id) ? []
        : await loadTargetOwners(deps.database, workspace.id);
      const standingGate = served.find(item => item.owner_user_id === approval.owner_user_id) ??
        served.find(item => resolveStanding({ approvalOwnerId: approval.owner_user_id,
          recipientOwnerId: item.owner_user_id, accept: "code_owners", actions: [action], targetOwners }));
      if (!standingGate) return await refuse("recipient_policy");
      gate = standingGate;
      const conditions = evaluateConditions(action.conditions ?? [], now);
      if (conditions.kind === "unavailable") return await refuse("condition_unavailable");
      if (conditions.kind === "unmet") return await refuse("condition_unmet", conditions.unmet);
    }

    if (dryRun) {
      // As Cloud: a passing dry run is `gate.checked`, so `gate.redeemed` counts real uses only.
      await audit("gate.checked", null).catch(() => undefined);
      return { ok: true, consumed: false, dry_run: true };
    }
    // Single use per run, atomically: the first redeem wins and records the
    // run; any later redeem in that run is same_run; any other run is consumed.
    const outcome = await deps.database.transaction(async (tx: SqlExecutor) => {
      // While the checks above waited, the approval may have been revoked,
      // withdrawn or expired, the gate deleted, or the grant revoked or
      // narrowed: decide on the current rows, under their locks.
      // Locks in the order the policy writer and revocation take them:
      // policy, grant, membership, approval.
      const commitNow = deps.now().getTime();
      if (approval.tier === "D" && approval.grant_id) {
        // The current policy and grant decide (not_enabled, revoked, expired,
        // out_of_scope, tier_o_required), as at attest and redeem.
        await recheckAtCommit(tx, { workspaceId: workspace.id, grantId: approval.grant_id, tier: "D", actions: [action],
          recipientAgentId: "", nowMs: commitNow });
      } else {
        const current = await loadPolicy(tx, workspace.id, true);
        if (!current.delegation_enabled) return "not_enabled" as const;
        if (current.allowed_classes && !current.allowed_classes.includes(action.class)) return "out_of_scope" as const;
      }
      // The gate's owner (and, for tier O, the approval's owner) still a member.
      if (!await memberRole(tx, workspace.id, gate!.owner_user_id, true)) return "recipient_policy" as const;
      if (approval.tier === "O" && !await memberRole(tx, workspace.id, approval.owner_user_id, true)) return "revoked" as const;
      const live = (await tx.query<{ expires_at: Date | string }>(
        "SELECT expires_at FROM delegation_approvals WHERE id = $1 AND invalidated_at IS NULL FOR UPDATE", [approval.id],
      )).rows[0];
      if (!live) return "revoked" as const;
      const gateLive = (await tx.query("SELECT 1 FROM delegation_gates WHERE id = $1 AND deleted_at IS NULL FOR SHARE",
        [gate!.id])).rows.length > 0;
      if (!gateLive) return "gate_unknown" as const;
      const alreadyUsed = await actionConsumed(tx, approval.id, action);
      if (!alreadyUsed && time(live.expires_at) <= commitNow) return "expired" as const;
      // Standing against the target owners as committed now.
      if (!alreadyUsed && !resolveStanding({ approvalOwnerId: approval.owner_user_id, recipientOwnerId: gate!.owner_user_id,
        accept: "code_owners", actions: [action],
        targetOwners: gate!.owner_user_id === approval.owner_user_id ? [] : await loadTargetOwners(tx, workspace.id) })) {
        return "recipient_policy" as const;
      }
      if (await consumeAction(tx, { approvalId: approval.id, workspaceId: workspace.id, action,
        consumedBy: `github-run:${claims!.run_id}` })) {
        await tx.query(
          `INSERT INTO delegation_gate_redemptions
             (approval_id, class, target, workspace_id, gate_id, issuer, repository, run_id, run_attempt)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
          [approval.id, action.class, action.target, workspace.id, gate!.id, claims!.issuer, claims!.repository,
            claims!.run_id, claims!.run_attempt],
        );
        return "consumed" as const;
      }
      return await boundRun(tx) ? "same_run" as const : "taken" as const;
    });
    if (outcome === "taken") return await refuse("consumed");
    if (outcome !== "consumed" && outcome !== "same_run") return await refuse(outcome);
    const sameRun = outcome === "same_run";
    await audit("gate.redeemed", null, { same_run: sameRun }).catch(() => undefined);
    return sameRun ? { ok: true, consumed: true, same_run: true } : { ok: true, consumed: true };
  } catch (error) {
    // A commit-time recheck refuses with its own reason; anything else is an outage.
    return refuse(error instanceof Refusal ? error.reason : "unavailable");
  }
}
