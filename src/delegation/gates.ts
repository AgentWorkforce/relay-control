import { drainBody } from "../drain-body.js";
import type { SqlExecutor } from "../database.js";
import { GITHUB_ACTIONS_OIDC_ISSUER, OidcKeysUnavailable, type WorkflowClaims, type WorkflowOidcVerifier } from "./oidc.js";
import { logAuditWriteFailed, logRefused, logRepositoryMismatch, logUnavailable } from "./observe.js";
import type { TrustProof } from "./trust.js";
import { actionIsValid, canonicalAction, releaseTargetSha, type Action, type ActionClass, type Condition, type ReasonCode } from "./scope.js";
import {
  actionConsumed,
  consumeAction,
  delegateStillBound,
  decideUnderLocks,
  getTrustRule,
  chainUnderLock,
  reliedProof,
  trustProver,
  freshRefusal,
  legacySpentStamp,
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
  /** Candidate-run release targets may name a source commit the run is not on (only when true). */
  allow_source_sha_mismatch: boolean;
  /** The repository's default branch as GitHub reported it at registration (or the owner named, for a self-host issuer). */
  default_branch: string;
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
    // Present (true) only when the gate opted out of binding candidate-run release targets to the run's commit, as Cloud.
    ...(row.allow_source_sha_mismatch ? { allow_source_sha_mismatch: true as const } : {}),
    default_branch: row.default_branch,
    created_at: new Date(row.created_at).toISOString(),
  };
}

export type GateRedeemResult =
  | { ok: true; consumed: true; same_run?: true }
  | { ok: true; consumed: false; dry_run: true }
  | { ok: false; reason: ReasonCode; unmet?: Condition[]; dry_run?: true };

/**
 * A workflow reference the gate pinned, as Cloud's workflowMatches. A tag gate
 * stores `<file>@<ref_pattern>` because the token names the tag the run
 * started from, which changes with every release: it matches `<file>@<that
 * tag>` for a tag the pattern covers. `owner/repo/` is case-insensitive on
 * GitHub; the file path and ref (or commit SHA) are not.
 */
function workflowMatches(gateRef: string, claimRef: string | null, gate: Pick<GateRow, "ref_pattern">, ref: string): boolean {
  if (!claimRef) return false;
  const expected = gate.ref_pattern !== null && gateRef.endsWith(`@${gate.ref_pattern}`) ?
    `${gateRef.slice(0, -(gate.ref_pattern.length + 1))}@${ref}` : gateRef;
  const split = (value: string) => {
    const at = value.indexOf("/.github/workflows/");
    return at < 0 ? [value, ""] : [value.slice(0, at).toLowerCase(), value.slice(at)];
  };
  const [wantRepo, wantRest] = split(expected), [haveRepo, haveRest] = split(claimRef);
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
export function gateMatches(gate: GateMatchFields, claims: ClaimMatchFields): boolean {
  return gateMatchesByName(gate, claims) && sameRepositoryIds(gate, claims);
}

type GateMatchFields = Pick<GateRow, "issuer" | "repo" | "workflow_ref" | "job_workflow_ref" | "ref" | "ref_pattern" | "event" |
  "repository_id" | "repository_owner_id">;
type ClaimMatchFields = Pick<WorkflowClaims, "issuer" | "repository" | "workflow_ref" | "job_workflow_ref" | "ref" | "event_name" |
  "repository_id" | "repository_owner_id" | "sha" | "job_workflow_sha">;

/**
 * GitHub's stable ids, resolved at registration, as Cloud: a repository that
 * later reuses the name (after a rename, transfer or delete) never matches. A
 * gate without ids (none are created any more) never serves.
 */
function sameRepositoryIds(gate: GateMatchFields, claims: ClaimMatchFields): boolean {
  return gate.repository_id === claims.repository_id && gate.repository_owner_id === claims.repository_owner_id;
}

/** Every signed field except the repository ids. */
function gateMatchesByName(gate: GateMatchFields, claims: ClaimMatchFields): boolean {
  const refMatches = gate.ref !== null ? gate.ref === claims.ref :
    gate.ref_pattern !== null && /^refs\/tags\/[^\s*]+\*$/u.test(gate.ref_pattern) &&
      claims.ref.startsWith(gate.ref_pattern.slice(0, -1)) && claims.ref.length > gate.ref_pattern.length - 1;
  // The issuer is part of the identity: a same-named repository on another
  // trusted issuer (a GitHub Enterprise Server, say) is a different repository.
  return gate.issuer === claims.issuer && gate.repo.toLowerCase() === claims.repository.toLowerCase() &&
    gate.event === claims.event_name && refMatches &&
    workflowMatches(gate.workflow_ref, claims.workflow_ref, gate, claims.ref) &&
    // A gate without job_workflow_ref covers the jobs defined in its own file
    // only: a job inside some reusable workflow it calls (GitHub then sets
    // job_workflow_ref to that workflow) must be named on the gate explicitly (as Cloud).
    (gate.job_workflow_ref === null ?
      !claims.job_workflow_ref || claims.job_workflow_ref === claims.workflow_ref :
      workflowMatches(gate.job_workflow_ref, claims.job_workflow_ref, gate, claims.ref) && reusableReadAtRunCommit(gate, claims));
}

/**
 * A reusable workflow a gate names by branch (allowed only in the gate's own
 * repository at the gate's ref, D2) is mutable: GitHub reports a local
 * `uses: ./…` call and a `uses: <repo>/…@<branch>` call the same way, and the
 * latter reads the file wherever the branch points when the run starts, not
 * at the caller's commit. Such a job serves only when the issuer read the
 * reusable workflow at the run's own commit (`job_workflow_sha` equals
 * `sha`), which the release binding ties to the approved commit. A reusable
 * workflow pinned to a 40-hex commit serves when read at that very commit;
 * the gate's own file runs at the run's commit already (as Cloud).
 */
function reusableReadAtRunCommit(gate: GateMatchFields, claims: ClaimMatchFields): boolean {
  if (gate.job_workflow_ref === null || gate.job_workflow_ref === gate.workflow_ref) return true;
  if (claims.job_workflow_sha === null) return false;
  // A commit pin is judged by what the issuer read, never by the selector's
  // shape: a branch may itself be named `…@<40 hex>` (as Cloud).
  // The selector is everything after the FIRST `@`: owner, repo and file
  // name hold none, so a branch such as `refs/heads/a@<40 hex>` stays a branch.
  const selector = gate.job_workflow_ref.slice(gate.job_workflow_ref.indexOf("@") + 1);
  // A commit pin must be the commit read; any other selector, the run's commit.
  if (/^[0-9a-f]{40}$/u.test(selector)) return claims.job_workflow_sha === selector;
  return claims.job_workflow_sha === claims.sha;
}

/**
 * POST .../delegates/gates/redeem, as Cloud's redeemViaGate (cloud#6507
 * 80d0886e0). The token is verified first and a gate must match it exactly
 * (repository, workflow identity, ref, event) and be pinned to the token's
 * GitHub repository ids before anything about the workspace is answered or
 * logged: until then a refusal writes nothing to the workspace's log. Then
 * delegation on, the target prefix, the approval and the normal redeem
 * checks, a plain fresh re-read of the authority (a dry run answers from it),
 * and finally the same checks under locks with single-use consumption bound
 * to the run, and the `gate.redeemed` event, in one transaction.
 */
export async function redeemThroughGate(deps: DelegationDeps, input: {
  workspace: DelegationWorkspace;
  verifyOidc: WorkflowOidcVerifier;
  oidcToken: string;
  approvalId: string;
  action: { class: ActionClass; target: string };
  dryRun?: boolean;
  /**
   * The repository's default branch read live from GitHub (the workspace's
   * connection, else the public API): null when GitHub no longer resolves
   * it; throws GithubUnavailable on an outage. Only asked for an off-commit
   * candidate redeem through an opt-out gate.
   */
  liveDefaultBranch?: (repo: string, repositoryId: string) => Promise<string | null>;
}): Promise<GateRedeemResult> {
  const { workspace } = input;
  const dryRun = input.dryRun === true;
  const now = deps.now();
  let claims: WorkflowClaims | null = null;
  let gate: GateRow | null = null;
  let ownerUserId: string | null = null;
  let grantId: string | null = null;
  const audit = (event: string, reason: ReasonCode | null, extra: Record<string, unknown> = {},
    executor: SqlExecutor = deps.database) =>
    recordDelegationAudit(executor, {
      workspaceId: workspace.id, event, authMethod: "github_oidc", ownerUserId, grantId, approvalId: input.approvalId,
      reason,
      data: { action: input.action, gate_id: gate?.id ?? null,
        ...(claims ? { issuer: claims.issuer, repository: claims.repository, workflow_ref: claims.workflow_ref,
          job_workflow_ref: claims.job_workflow_ref,
          ref: claims.ref, event_name: claims.event_name, run_id: claims.run_id, run_attempt: claims.run_attempt, sha: claims.sha } : {}),
        ...(dryRun ? { dry_run: true } : {}), ...extra },
    });
  // Before a verified token matches one of this workspace's pinned gates the
  // caller is nobody in particular: nothing is written to the workspace's log.
  let audited = false;
  // Best-effort audit writes (refusals, dry runs): a failure is logged, never answered.
  const bestEffort = (event: string, reason: ReasonCode | null, extra: Record<string, unknown> = {}) =>
    audit(event, reason, extra).catch((error: unknown) => logAuditWriteFailed("gate_redeem", error,
      { workspaceId: workspace.id, approvalId: input.approvalId, gateId: gate?.id ?? null, event, reason }));
  const refuse = async (reason: ReasonCode, unmet?: Condition[]): Promise<GateRedeemResult> => {
    if (audited) await bestEffort("gate.refused", reason, unmet ? { unmet } : {});
    // Counted per reason. A token no trusted issuer signed is not counted, so
    // forged calls cannot drive events.
    // Not `gate_unknown` either: any GitHub account can mint a genuine token for this audience.
    if (reason !== "oidc_invalid" && reason !== "gate_unknown") {
      logRefused("gate_redeem", { workspaceId: workspace.id, reason, gateId: gate?.id ?? null,
        ...(claims ? { repository: claims.repository, workflow_ref: claims.workflow_ref, ref: claims.ref,
          event_name: claims.event_name } : {}) });
    }
    return { ok: false, reason, ...(unmet ? { unmet } : {}), ...(dryRun ? { dry_run: true as const } : {}) };
  };
  try {
    if (deps.gateOnly) return await refuse("unavailable");
    // Authenticate first: nothing about the workspace (not even whether
    // delegation is on) is answered to a caller no trusted issuer signed for.
    try {
      claims = await input.verifyOidc(input.oidcToken);
    } catch (error) {
      // The issuer's keys could not be read: an outage, not a forged token.
      if (error instanceof OidcKeysUnavailable) throw error;
      return await refuse("oidc_invalid");
    }
    const registered = (await deps.database.query<GateRow>(
      `SELECT * FROM delegation_gates WHERE workspace_id = $1 AND lower(repo) = lower($2) AND deleted_at IS NULL
        ORDER BY created_at, id`,
      [workspace.id, claims.repository],
    )).rows;
    if (!registered.length) return await refuse("gate_unknown");
    // Matching the repository alone is not enough: a workflow edited on
    // another branch also gets a token for the same repository.
    // At most MAX_GATES_PER_WORKFLOW candidates are evaluated, oldest first
    // (registration caps a workflow file at that many).
    const byName = registered.filter(item => gateMatchesByName(item, claims!)).slice(0, MAX_GATES_PER_WORKFLOW);
    if (!byName.length) return await refuse("gate_mismatch");
    // Every gate holds the repository ids GitHub reported at registration;
    // redeem never pins. A token that matches a gate by name but carries
    // other ids comes from a different repository using the name (a squat, a
    // recreated or transferred repo): refused, logged, and audited so the
    // gate's owner sees it, also on a dry run. As Cloud.
    const exact = byName.filter(item => sameRepositoryIds(item, claims!));
    if (!exact.length) {
      // Every gate holds its ids (NOT NULL): audited for the first name-matched gate.
      const squatted = byName[0]!;
      gate = squatted;
      ownerUserId = squatted.owner_user_id;
      audited = true;
      logRepositoryMismatch({ workspaceId: workspace.id, gateId: squatted.id, repository: claims.repository,
        token_repository_id: claims.repository_id, token_repository_owner_id: claims.repository_owner_id });
      return await refuse("repository_mismatch");
    }
    audited = true;
    const policy = await loadPolicy(deps.database, workspace.id);
    if (!policy.delegation_enabled) return await refuse("not_enabled");
    // Several owners may register the same workflow with overlapping
    // prefixes; any of them whose owner has standing can serve (below).
    let candidates = exact.filter(item => input.action.target.startsWith(item.target_prefix));
    if (!candidates.length) return await refuse("target_prefix");
    gate = candidates[0]!;

    const approval = (await deps.database.query<ApprovalRow>(
      "SELECT * FROM delegation_approvals WHERE id = $1 AND workspace_id = $2", [input.approvalId, workspace.id],
    )).rows[0];
    if (!approval) return await refuse("no_approval");
    ownerUserId = approval.owner_user_id;
    grantId = approval.grant_id;
    const action = approval.actions.find(item => item.class === input.action.class && item.target === input.action.target);
    if (!action || !actionIsValid(action)) return await refuse("out_of_scope");
    if (approval.invalidated_at || legacySpentStamp(approval)) return await refuse("revoked");
    // Release gates redeem releases only (§11a), as Cloud: a gate never spends a
    // deploy, destructive, secret_change or spend approval whose target happens
    // to start with its prefix, since only releases are bound to the run's commit.
    if (action.class !== "release") return await refuse("out_of_scope");
    // A release names its commit; the run must be on it (the token's `sha`).
    // Only a candidate-run target (whose source commit a promote run may not
    // be on) can be redeemed off-commit, and only through a gate on the
    // repository's default branch that opted out.
    const named = releaseTargetSha(action.target);
    if (!named) return await refuse("out_of_scope");
    if (named.sha.toLowerCase() !== claims.sha) {
      candidates = named.form === "candidate" ? candidates.filter(mayOptOutOfSourceSha) : [];
      // The stored default branch is only what registration saw: read it live
      // now (as Cloud). If the repository's default branch moved (or GitHub no
      // longer resolves it), the gate's branch is not the reviewed one any more
      // and the opt-out does not apply; an outage answers unavailable. A gate
      // on a self-host issuer keeps the branch its owner named at registration.
      if (candidates.length && claims.issuer === GITHUB_ACTIONS_OIDC_ISSUER && input.liveDefaultBranch) {
        const live = await input.liveDefaultBranch(claims.repository, claims.repository_id!);
        candidates = live === null ? [] : candidates.filter(item => item.ref === `refs/heads/${live}`);
      }
      if (!candidates.length) return await refuse("sha_mismatch");
      gate = candidates[0]!;
    }

    // Tier D rests on a live grant and a still-bound delegate; both tiers on a current owner.
    let ruleId: string | null = null;
    let chain: ReturnType<typeof chainUnderLock>;
    let grantOwnerUserId: string | null = null;
    let reliedChain: TrustProof | null = null;
    if (approval.tier === "D") {
      const grant = approval.grant_id ? (await deps.database.query<GrantRow>(
        "SELECT * FROM delegation_grants WHERE id = $1 AND workspace_id = $2", [approval.grant_id, workspace.id],
      )).rows[0] : undefined;
      if (!grant || grant.status === "revoked") return await refuse("revoked");
      if (grant.status === "expired" || time(grant.expires_at) <= now.getTime()) return await refuse("expired");
      // The chain an owner-made grant to a connected assistant stands on is
      // read BEFORE the binding check, and that same proof is what the
      // deciding transaction re-checks under share locks (chainUnderLock). Read
      // after it, a connector disconnected in between read as "no chain" and
      // the lock-time check was skipped (Cloud's twin, Devin on cloud train #6652).
      reliedChain = await reliedProof(trustProver(deps, workspace, false), grant);
      // A dry run writes nothing: a delegate found unbound is refused, not revoked.
      const unbound = await delegateStillBound(deps, workspace, grant, true, { durable: !dryRun });
      if (unbound) return await refuse(unbound);
      const outOfScope = scopeRefusal([action], grant, policy, "");
      if (outOfScope) return await refuse(outOfScope);
      if (tierOClasses(policy, grant).has(action.class)) return await refuse("tier_o_required");
      // The rule behind the grant, locked with it in the deciding transaction.
      ruleId = grant.trust_rule_id ?? null;
      grantOwnerUserId = grant.owner_user_id;
      // The ownership chain the grant (rule-backed, or owner-made to a connected
      // assistant) stands on, re-read in the deciding transaction under share locks.
      chain = chainUnderLock(workspace, grant, reliedChain);
    } else {
      if (!await memberRole(deps.database, workspace.id, approval.owner_user_id)) return await refuse("revoked");
      if (policy.allowed_classes && !policy.allowed_classes.includes(action.class)) return await refuse("out_of_scope");
    }

    // Every check runs on every redeem, a same-run one included: the run can
    // only ever re-redeem the very action it consumed, and only while the
    // approval is unexpired, in standing and its conditions still hold.
    if (time(approval.expires_at) <= now.getTime()) return await refuse("expired");
    // The gate's owner stands where a recipient's owner would (§5.4); with
    // overlapping gates, the first whose owner is still a member and has
    // standing serves.
    const targetOwners = await loadTargetOwners(deps.database, workspace.id);
    let standingGate: GateRow | null = null;
    // D5 (#owner-decisions 250887862744305664): a gate serves only while its
    // owner is an org owner or admin (relay-control reads no CODEOWNERS, so
    // that is the whole rule here; Cloud also admits whole-repo code owners).
    let unqualified = 0;
    for (const candidate of candidates) {
      const role = await memberRole(deps.database, workspace.id, candidate.owner_user_id);
      if (!role) continue;
      if (!qualifiedGateOwner(role)) { unqualified += 1; continue; }
      if (resolveStanding({ approvalOwnerId: approval.owner_user_id, recipientOwnerId: candidate.owner_user_id,
        accept: "code_owners", actions: [action], targetOwners })) {
        standingGate = candidate;
        break;
      }
    }
    if (!standingGate) {
      return await refuse(unqualified && unqualified === candidates.length ? "gate_owner_unqualified" : "recipient_policy");
    }
    gate = standingGate;
    const conditions = evaluateConditions(action.conditions ?? [], now);
    if (conditions.kind === "unavailable") return await refuse("condition_unavailable");
    if (conditions.kind === "unmet") return await refuse("condition_unmet", conditions.unmet);
    // A spent action answers only the run that consumed it: another job of the
    // same workflow run, or a later attempt of it (single use is per action).
    const spent = await actionConsumed(deps.database, approval.id, action);
    if (spent && !await boundRun(deps.database, approval.id, action, claims)) return await refuse("consumed");

    // The relay and OIDC calls above take time: the policy, approval, grant,
    // memberships and clock as they are now decide, not the ones read before.
    const fresh = await currentGateAuthority(deps, workspace, approval.id, action, standingGate.owner_user_id,
      deps.now().getTime(), !dryRun, reliedChain);
    if (fresh) return await refuse(fresh);

    if (dryRun) {
      // A dry run takes no lock, so it answers from the state as it is now:
      // the gate still live, and the action not consumed meanwhile by another
      // run (#278 review). A change committing after this is not reflected.
      const live = (await deps.database.query(
        "SELECT 1 FROM delegation_gates WHERE workspace_id = $1 AND id = $2 AND deleted_at IS NULL",
        [workspace.id, standingGate.id])).rows.length > 0;
      if (!live) return await refuse("gate_unknown");
      if (!spent && await actionConsumed(deps.database, approval.id, action) &&
          !await boundRun(deps.database, approval.id, action, claims)) {
        return await refuse("consumed");
      }
      // A passing dry run is `gate.checked`, so `gate.redeemed` counts real uses only.
      await bestEffort("gate.checked", null, spent ? { same_run: true } : {});
      return { ok: true, consumed: false, dry_run: true };
    }
    // The check above is a plain read. The commit re-checks the same state
    // under share locks (the gate owner's and, for tier O, the approval owner's
    // membership, the policy, the grant, the approval), consumes, and writes
    // `gate.redeemed` in that transaction: a failure rolls the consumption back.
    const servingGate = standingGate;
    const oidc = claims;
    const outcome = await decideUnderLocks<{ refused: ReasonCode } | { consumed: "consumed" | "same_run" }>(deps.database, { workspaceId: workspace.id,
      memberUserIds: approval.tier === "O" ? [servingGate.owner_user_id, approval.owner_user_id] : [servingGate.owner_user_id],
      grantId: approval.tier === "D" ? approval.grant_id : null, approvalId: approval.id, consuming: true, trustRuleId: ruleId, chain, grantOwnerUserId },
      async (state, tx) => {
      const stale = freshRefusal(state, { actions: [action], tier: approval.tier, policy, recipientAgentId: "",
        nowMs: deps.now().getTime(), memberGone: approval.tier === "O" ? "revoked" : "recipient_policy",
        noGrant: approval.tier === "O" });
      // Refusals and consumptions are kept apart: a refusal reason (even
      // "consumed") can never read as a successful first consumption.
      if (stale) return { refused: stale };
      // Qualification (an org owner or admin), not only membership, as read
      // from the share-locked membership row: a demotion that committed after
      // the plain read decides (#278 review).
      if (!qualifiedGateOwner(await memberRole(tx, workspace.id, servingGate.owner_user_id, true))) {
        return { refused: "gate_owner_unqualified" as const };
      }
      // Standing against the target owners as committed now (read locally).
      if (!resolveStanding({ approvalOwnerId: approval.owner_user_id, recipientOwnerId: servingGate.owner_user_id,
        accept: "code_owners", actions: [action],
        targetOwners: servingGate.owner_user_id === approval.owner_user_id ? [] : await loadTargetOwners(tx, workspace.id) })) {
        return { refused: "recipient_policy" as const };
      }
      const result = await consumeForGateRun(tx, { workspaceId: workspace.id, approvalId: approval.id, gateId: servingGate.id,
        claims: oidc, action, clock: () => deps.now(), grantId: approval.tier === "D" ? approval.grant_id : null });
      if (result === "gate_gone") return { refused: "gate_unknown" as const };
      if (result === "revoked") return { refused: "revoked" as const };
      if (result === "expired") return { refused: "expired" as const };
      // Another run consumed the action first: this run is refused (#278 review).
      if (result === "taken") return { refused: "consumed" as const };
      await audit("gate.redeemed", null, { same_run: result === "same_run" }, tx);
      return { consumed: result } as const;
    });
    if ("refused" in outcome) return await refuse(outcome.refused);
    return outcome.consumed === "same_run" ? { ok: true, consumed: true, same_run: true } : { ok: true, consumed: true };
  } catch (error) {
    // Class and SQLSTATE only: never the token or the error's message.
    logUnavailable("gate_redeem", error, { workspaceId: workspace.id, approvalId: input.approvalId, gateId: gate?.id ?? null });
    return refuse("unavailable");
  }
}

/** Whether a consumed action was consumed by this same run (another job, or a later attempt, of it). */
async function boundRun(executor: SqlExecutor, approvalId: string, action: Pick<Action, "class" | "target">,
  claims: WorkflowClaims): Promise<boolean> {
  const prior = (await executor.query<{ run_id: string; repository_id: string; issuer: string }>(
    `SELECT run_id, repository_id, issuer FROM delegation_gate_redemptions
      WHERE approval_id = $1 AND class = $2 AND target = $3`,
    [approvalId, action.class, action.target],
  )).rows[0];
  // The same run of the same repository, by GitHub's id (a rename changes nothing), as Cloud.
  return Boolean(prior && prior.run_id === claims.run_id && prior.repository_id === claims.repository_id &&
    prior.issuer === claims.issuer);
}

/**
 * Single use per run, in the caller's transaction (Cloud's consumeForGateRun):
 * the gate row and the approval are share-locked, the first redeem wins and
 * records the run, a later one in that run is `same_run`, any other `taken`.
 *
 * The approval's (and a tier D grant's) expiry is judged after both locks are
 * held, on `clock` read then: waiting on the gate's lock (a concurrent gate
 * delete that then rolls back) must not let an approval that expired during
 * the wait be consumed on a time read before it (as the hosted twin).
 */
export async function consumeForGateRun(tx: SqlExecutor, input: { workspaceId: string; approvalId: string; gateId: string;
  claims: WorkflowClaims; action: Action; clock: () => Date; grantId: string | null }):
  Promise<"consumed" | "same_run" | "taken" | "gate_gone" | "revoked" | "expired"> {
  // Both scoped to the workspace, as Cloud.
  const gateLive = (await tx.query(
    "SELECT 1 FROM delegation_gates WHERE workspace_id = $1 AND id = $2 AND deleted_at IS NULL FOR SHARE",
    [input.workspaceId, input.gateId])).rows.length > 0;
  if (!gateLive) return "gate_gone";
  const approval = (await tx.query<{ expires_at: Date | string }>(
    "SELECT expires_at FROM delegation_approvals WHERE workspace_id = $1 AND id = $2 AND invalidated_at IS NULL FOR SHARE",
    [input.workspaceId, input.approvalId])).rows[0];
  // A revoked approval at consume is `revoked`, as Cloud.
  if (!approval) return "revoked";
  // Both locks are held: the clock is read now, after any wait for them.
  const nowMs = input.clock().getTime();
  if (time(approval.expires_at) <= nowMs) return "expired";
  if (input.grantId) {
    // Share-locked already by decideUnderLocks, so this read never waits.
    const grant = (await tx.query<{ status: string; expires_at: Date | string }>(
      "SELECT status, expires_at FROM delegation_grants WHERE workspace_id = $1 AND id = $2 FOR SHARE",
      [input.workspaceId, input.grantId])).rows[0];
    if (!grant || grant.status === "revoked") return "revoked";
    if (grant.status === "expired" || time(grant.expires_at) <= nowMs) return "expired";
  }
  if (await consumeAction(tx, { approvalId: input.approvalId, workspaceId: input.workspaceId, action: input.action,
    consumedBy: `github-run:${input.claims.run_id}` })) {
    await tx.query(
      `INSERT INTO delegation_gate_redemptions
         (approval_id, class, target, workspace_id, gate_id, issuer, repository, repository_id, run_id, run_attempt)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      [input.approvalId, input.action.class, input.action.target, input.workspaceId, input.gateId, input.claims.issuer,
        input.claims.repository, input.claims.repository_id, input.claims.run_id, input.claims.run_attempt],
    );
    return "consumed";
  }
  return await boundRun(tx, input.approvalId, input.action, input.claims) ? "same_run" : "taken";
}

/**
 * Re-reads what a gate redeem rests on, right before it answers (Cloud's
 * currentGateAuthority): delegation on, the approval unrevoked and unexpired,
 * its tier D grant live with the action still in scope and not newly tier O,
 * its tier O owner and the gate's owner still members, and the class still
 * allowed. Null when all hold.
 */
async function currentGateAuthority(deps: DelegationDeps, workspace: DelegationWorkspace, approvalId: string, action: Action,
  gateOwnerId: string, atMs: number, durable: boolean, reliedChain: TrustProof | null = null): Promise<ReasonCode | null> {
  const executor = deps.database;
  const workspaceId = workspace.id;
  const policy = await loadPolicy(executor, workspaceId);
  if (!policy.delegation_enabled) return "not_enabled";
  const approval = (await executor.query<ApprovalRow>(
    "SELECT * FROM delegation_approvals WHERE id = $1 AND workspace_id = $2", [approvalId, workspaceId],
  )).rows[0];
  if (!approval || approval.invalidated_at) return "revoked";
  if (time(approval.expires_at) <= atMs) return "expired";
  if (approval.tier === "D") {
    const grant = approval.grant_id ? (await executor.query<GrantRow>(
      "SELECT * FROM delegation_grants WHERE id = $1 AND workspace_id = $2", [approval.grant_id, workspaceId],
    )).rows[0] : undefined;
    if (!grant || grant.status === "revoked") return "revoked";
    if (grant.status === "expired" || time(grant.expires_at) <= atMs) return "expired";
    const outOfScope = scopeRefusal([action], grant, policy, "");
    if (outOfScope) return outOfScope;
    if (tierOClasses(policy, grant).has(action.class)) return "tier_o_required";
    // A rule-backed grant stands only while its rule is live and the delegate's
    // ownership chain still proves out, read now (never from a cached walk): a
    // dry run (which takes no lock) answers revoked the moment a hop drops,
    // and writes nothing.
    // So does an owner-made grant that stood on a connector root (reliedChain):
    // its connector is re-proved now, so a dry run refuses once it is disconnected.
    if (grant.trust_rule_id || reliedChain) {
      if (grant.trust_rule_id) {
        const rule = await getTrustRule(executor, workspaceId, grant.trust_rule_id);
        if (!rule || rule.revoked_at) return "revoked";
      }
      const unbound = await delegateStillBound(deps, workspace, grant, true, { durable });
      if (unbound) return unbound;
    }
  } else {
    if (!await memberRole(executor, workspaceId, approval.owner_user_id)) return "revoked";
    if (policy.allowed_classes && !policy.allowed_classes.includes(action.class)) return "out_of_scope";
  }
  const role = await memberRole(executor, workspaceId, gateOwnerId);
  if (!role) return "recipient_policy";
  if (!qualifiedGateOwner(role)) return "gate_owner_unqualified";
  return null;
}

/**
 * The redeem route's HTTP status, as Cloud's gateRedeemStatus: 200 for a
 * redeem or any dry run (report-only); otherwise 401 (`oidc_invalid`), 503
 * (`unavailable`, `condition_unavailable`: retry) or 403 (final). The body is
 * the same either way, so a plain `curl -f` step fails closed.
 */
export function gateRedeemStatus(result: GateRedeemResult): number {
  if (result.ok || ("dry_run" in result && result.dry_run)) return 200;
  if (result.reason === "oidc_invalid") return 401;
  return result.reason === "unavailable" || result.reason === "condition_unavailable" ? 503 : 403;
}

/** GitHub's stable ids for a repository, its canonical `owner/name`, and its default branch. */
export type RepositoryIds = { repositoryId: string; repositoryOwnerId: string; fullName: string; defaultBranch: string };

/** GitHub could not answer (network, 5xx, rate limit, a malformed body): registration answers 503. */
export class GithubUnavailable extends Error {
  constructor() {
    super("github_unavailable");
  }
}

/** GitHub answered 403 or 429 (a rate limit): unavailable, never "unresolved", never cached (as Cloud). */
export class GithubRateLimited extends GithubUnavailable {}

/**
 * GitHub's ids for the repository a gate is registered for, resolved before
 * the gate exists, as Cloud's resolveGateRepository: through the workspace's
 * GitHub connection when it has one (its token; a 404 or redirect there is
 * unresolved, without asking the public API), else GitHub's public API. Null
 * when GitHub knows no such repository the caller can see (404), the name
 * moved (a 3xx, never followed), or the canonical name differs from the one
 * registered (case-insensitive). Throws GithubUnavailable when GitHub cannot
 * answer, or omits the default branch.
 */
export async function resolveGateRepository(input: { repo: string; token: string | null; fetchImpl: typeof fetch }):
  Promise<RepositoryIds | null> {
  const [owner, name] = input.repo.split("/");
  let response: Response;
  try {
    response = await input.fetchImpl(`https://api.github.com/repos/${encodeURIComponent(owner!)}/${encodeURIComponent(name!)}`, {
      headers: { accept: "application/vnd.github+json", "user-agent": "relay-control", "x-github-api-version": "2022-11-28",
        ...(input.token ? { authorization: `Bearer ${input.token}` } : {}) },
      redirect: "manual", signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new GithubUnavailable();
  }
  // A redirect means the name moved; it is never followed. Only a 2xx body is
  // read: every other answer's body is released.
  if (response.status === 404 || (response.status >= 300 && response.status < 400) || response.type === "opaqueredirect") {
    await drainBody(response, "delegation.github_repository");
    return null;
  }
  if (!response.ok) {
    await drainBody(response, "delegation.github_repository");
    throw response.status === 403 || response.status === 429 ? new GithubRateLimited() : new GithubUnavailable();
  }
  const body = await response.json().catch(() => null) as Record<string, unknown> | null;
  const id = body?.id, ownerId = (body?.owner as Record<string, unknown> | undefined)?.id, fullName = body?.full_name;
  const defaultBranch = body?.default_branch;
  if (typeof id !== "number" || !Number.isSafeInteger(id) || typeof ownerId !== "number" || !Number.isSafeInteger(ownerId) ||
      typeof fullName !== "string" || typeof defaultBranch !== "string" || !defaultBranch) throw new GithubUnavailable();
  return fullName.toLowerCase() === input.repo.toLowerCase()
    ? { repositoryId: String(id), repositoryOwnerId: String(ownerId), fullName, defaultBranch } : null;
}

/**
 * The source-sha opt-out applies only to a gate on the repository's default
 * branch, as stored at registration (as Cloud): its workflow is the reviewed,
 * protected code that checks the candidate itself. A tag, exact or pattern,
 * or any other branch can carry an edited workflow.
 */
export function mayOptOutOfSourceSha(gate: Pick<GateRow, "allow_source_sha_mismatch" | "ref" | "ref_pattern" | "default_branch">): boolean {
  return gate.allow_source_sha_mismatch === true && gate.ref_pattern === null && Boolean(gate.default_branch) &&
    gate.ref === `refs/heads/${gate.default_branch}`;
}

/** How long a public-API default-branch answer is reused, per repository id (as Cloud). */
export const DEFAULT_BRANCH_CACHE_MS = 300_000;

/**
 * The live default-branch read for an off-commit opt-out redeem (Cloud's
 * liveDefaultBranch). Through the workspace's GitHub connection when it has
 * one (not cached), else GitHub's public API, whose branch answers are
 * cached in memory per repository id for 5 minutes; a null answer and errors
 * are never cached. A branch is returned only when GitHub's id equals the gate's
 * repository id and its full_name equals the repo (case-insensitive), else
 * null; a moved repository (redirect) or 404 is null. 403/429 throw
 * GithubRateLimited, any other failure GithubUnavailable: both answer
 * unavailable.
 */
export function liveDefaultBranchReader(input: { fetchImpl: typeof fetch; now: () => Date;
  connectionToken: (() => Promise<string | null>) }) {
  const cache = new Map<string, { at: number; branch: string | null }>();
  return async (repo: string, repositoryId: string): Promise<string | null> => {
    const token = await input.connectionToken();
    const check = (ids: RepositoryIds | null) => ids && ids.repositoryId === repositoryId ? ids.defaultBranch : null;
    if (token) return check(await resolveGateRepository({ repo, token, fetchImpl: input.fetchImpl }));
    const at = input.now().getTime();
    const cached = cache.get(repositoryId);
    if (cached && at - cached.at < DEFAULT_BRANCH_CACHE_MS) return cached.branch;
    const branch = check(await resolveGateRepository({ repo, token: null, fetchImpl: input.fetchImpl }));
    // Only a branch is cached, never a negative answer (as Cloud): a repository
    // GitHub briefly failed to show must not keep the opt-out off for 5 minutes.
    if (branch) {
      if (cache.size >= 1000) cache.clear();
      cache.set(repositoryId, { at, branch });
    }
    return branch;
  };
}

/** A gate as audited when it is deleted or removed (as Cloud's gateAuditData). */
export function gateAuditData(row: Pick<GateRow, "id" | "repo" | "repository_id" | "workflow_ref" | "job_workflow_ref" | "ref" |
  "ref_pattern" | "event" | "target_prefix">): Record<string, unknown> {
  return { gate_id: row.id, repo: row.repo, repository_id: row.repository_id, workflow_ref: row.workflow_ref,
    ...(row.job_workflow_ref ? { job_workflow_ref: row.job_workflow_ref } : {}),
    ...(row.ref ? { ref: row.ref } : {}), ...(row.ref_pattern ? { ref_pattern: row.ref_pattern } : {}),
    event: row.event, target_prefix: row.target_prefix };
}

/**
 * D5 (#owner-decisions 250887862744305664): who may own a release gate. relay-control has
 * no CODEOWNERS reads, so only an org owner or admin qualifies, at
 * registration and at every redeem.
 */
export function qualifiedGateOwner(role: string | null): boolean {
  return role === "owner" || role === "admin";
}

/**
 * At most this many live gates per (workspace, lower(repo), workflow file),
 * as Cloud: the file path without its `@ref`, so every tag pattern of one
 * workflow shares one cap. One redeem also evaluates at most this many
 * candidate gates.
 */
export const MAX_GATES_PER_WORKFLOW = 10;

/** A gate's workflow file, `/.github/workflows/<file>`, without the repository or `@ref`. */
export function gateWorkflowFile(workflowRef: string): string {
  const at = workflowRef.indexOf("/.github/workflows/");
  const path = at < 0 ? workflowRef : workflowRef.slice(at);
  const ref = path.indexOf("@");
  return ref < 0 ? path : path.slice(0, ref);
}
