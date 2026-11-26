import {
  ACTION_CLASSES, REPO_TARGET, prOpsTarget, repoPart, targetCovered, validTargetPattern, type Action, type ActionClass,
  type Scope,
} from "./scope.js";
import type { TrustPath } from "./trust.js";

/** One scope of a grant (scope.ts Scope), plus the fields only a binding's system grant carries. */
export type GrantScope = Scope;
type TrustPathRow = TrustPath;
/** Classes that name the session they act on, never a repo (Cloud's OWN_OWNER_ONLY_CLASSES). */
const OWN_OWNER_ONLY_CLASSES: readonly ActionClass[] = ["prompt_approval", "config_change"];
const patternWithin = (narrow: string, wide: string) => targetCovered(wide, narrow, true);
const targetCovers = (pattern: string, target: string) => targetCovered(pattern, target);
const isValidTargetPattern = validTargetPattern;

/**
 * Role bindings, the self-hosted twin of Cloud's lib/delegation/roles.ts
 * (cloud#6665; #owner-decisions 251526750352171008): a binding gives one
 * principal (one agent, a custom group, a connector kind or every Relay
 * agent) a role, optionally limited to some repos and up to an expiry. It
 * acts through system grants, so attest, redeem and gates still decide on
 * grant rows. This module is pure: the presets, which binding decides for an
 * agent, and what a binding covers.
 */

export const PRINCIPAL_KINDS = ["all_agents", "relay_agents", "connector_kind", "group", "agent"] as const;
export type PrincipalKind = (typeof PRINCIPAL_KINDS)[number];
export const ROLES = ["trusted", "standard", "read_only", "custom", "excluded"] as const;
export type Role = (typeof ROLES)[number];
export const PRESET_ROLES = ["trusted", "standard", "read_only"] as const;
export type PresetRole = (typeof PRESET_ROLES)[number];
/**
 * The connector kinds `connectorKind()` can classify a connector root as.
 * relay-control's classifier also has `cursor-cloud`, which Cloud's does not.
 */
export const CONNECTOR_KINDS = ["grok-bot", "chatgpt", "cursor-cloud", "muse", "mcp"] as const;
/** The pr_ops operations a binding can limit to (the op of `owner/repo#N:<op>`, without its `=value`). */
export const PR_OPS_OPS = ["close", "reopen", "rerun_ci", "comment", "label", "unlabel", "request_review"] as const;
export type PrOp = (typeof PR_OPS_OPS)[number];
/**
 * Conditions a binding can require: only those with no parameter. relay-control
 * reads no GitHub state, so at redeem these answer condition_unavailable
 * (evaluateConditions). A binding that requires them fails closed here.
 */
export const REQUIRED_CONDITION_TYPES = ["ci_green", "mergeable"] as const;
/**
 * The classes a required condition can apply to: those whose every valid
 * target names a PR (merge `owner/repo#N`, pr_ops `owner/repo#N:<op>`), as
 * Cloud's CONDITIONED_CLASSES. On any other class a condition could never be
 * met, or would go unchecked.
 */
export const CONDITIONED_CLASSES: readonly ActionClass[] = ["merge", "pr_ops"];
export type RequiredCondition = { type: (typeof REQUIRED_CONDITION_TYPES)[number] };
export type RequiredConditions = Partial<Record<ActionClass, RequiredCondition[]>>;

/** What a binding lets its agents do. `classes: null` is a legacy rule: every class, no limits. */
export type Authority = {
  classes: ActionClass[] | null;
  requireTierO: ActionClass[];
  prOpsLimit: PrOp[] | null;
  requiredConditions: RequiredConditions;
  targets: string[] | null;
  expiresAt: Date | null;
};

export type Preset = Pick<Authority, "requireTierO" | "prOpsLimit" | "requiredConditions"> & {
  role: PresetRole; label: string; description: string; classes: ActionClass[];
};

/**
 * The presets (Khaliq's answers, #owner-decisions 251526750352171008):
 * - **Trusted** merges any green PR (config and infra included; ci_green and
 *   mergeable are required at redeem), replies (PR comments, Slack and email)
 *   and does routine PR work. It asks first for deploys, releases, deletes,
 *   secrets and spend.
 * - **Standard** does routine PR work. It asks first for merges, deploys,
 *   deletes and secrets, and is not granted releases, spend or external
 *   messages.
 * - **Read-only** may only comment on PRs.
 * No preset grants prompt_approval or config_change: those stay with a
 * custom role or an explicit grant.
 */
export const PRESETS: Record<PresetRole, Preset> = {
  trusted: {
    role: "trusted", label: "Trusted",
    description: "Merges green PRs, replies and does routine PR work. Asks you before deploys, releases, deletes, secrets and spending.",
    classes: ["merge", "pr_ops", "external_comms", "deploy", "release", "destructive", "secret_change", "spend"],
    requireTierO: ["deploy", "release", "destructive", "secret_change", "spend"],
    prOpsLimit: null,
    requiredConditions: { merge: [{ type: "ci_green" }, { type: "mergeable" }] },
  },
  standard: {
    role: "standard", label: "Standard",
    description: "Does routine PR work. Asks you before merges, deploys, deletes and secrets.",
    classes: ["pr_ops", "merge", "deploy", "destructive", "secret_change"],
    requireTierO: ["merge", "deploy", "destructive", "secret_change"],
    prOpsLimit: null,
    requiredConditions: {},
  },
  read_only: {
    role: "read_only", label: "Read-only",
    description: "Reads and reports. May comment on PRs, nothing else.",
    classes: ["pr_ops"],
    requireTierO: [],
    prOpsLimit: ["comment"],
    requiredConditions: {},
  },
};

/** One live binding, as resolution reads it. */
export type BindingView = {
  id: string;
  principalKind: PrincipalKind;
  principalRef: string | null;
  /** Null for a legacy rule. */
  role: Role | null;
  classes: ActionClass[] | null;
  requireTierO: ActionClass[];
  prOpsLimit: PrOp[] | null;
  requiredConditions: RequiredConditions;
  targets: string[] | null;
  expiresAt: Date | null;
};

/** Which precedence level decided, most specific first. */
export type DecisionSource = "agent" | "group" | "connector_kind" | "relay_agents" | "spawn_default" | "legacy";

export type Decision =
  | { kind: "covered"; binding: BindingView; authority: Authority; source: DecisionSource }
  | { kind: "excluded"; binding: BindingView }
  | { kind: "none" };

const live = (binding: BindingView, now: Date) => !binding.expiresAt || binding.expiresAt > now;

/** A binding's own authority. A preset binding stores its resolved fields, so a later preset change never widens it. */
export function authorityOf(binding: BindingView): Authority {
  if (binding.role === null) {
    return { classes: null, requireTierO: binding.requireTierO, prOpsLimit: null, requiredConditions: {}, targets: null,
      expiresAt: binding.expiresAt };
  }
  return { classes: binding.classes ?? [], requireTierO: binding.requireTierO, prOpsLimit: binding.prOpsLimit,
    requiredConditions: binding.requiredConditions, targets: binding.targets, expiresAt: binding.expiresAt };
}

/**
 * The Read-only preset as an authority: a spawned agent's default. It keeps
 * the covering binding's repo targets and expiry, so a launched agent never
 * reaches beyond the binding that covers its root (as Cloud).
 */
export function readOnlyAuthority(within: Pick<Authority, "expiresAt" | "targets"> = { expiresAt: null, targets: null }): Authority {
  const preset = PRESETS.read_only;
  return { classes: [...preset.classes], requireTierO: [...preset.requireTierO], prOpsLimit: preset.prOpsLimit && [...preset.prOpsLimit],
    requiredConditions: {}, targets: within.targets && [...within.targets], expiresAt: within.expiresAt };
}

function unionConditions(a: RequiredCondition[] = [], b: RequiredCondition[] = []): RequiredCondition[] {
  const types = new Set([...a, ...b].map(condition => condition.type));
  return REQUIRED_CONDITION_TYPES.filter(type => types.has(type)).map(type => ({ type }));
}

/**
 * Target patterns both lists cover. A pattern is kept when the other list has
 * a pattern it lies wholly inside, so `owner/*` with `owner/x` keeps
 * `owner/x`. Two unrelated wildcards keep nothing, which fails closed.
 */
function intersectTargets(a: string[] | null, b: string[] | null): string[] | null {
  if (a === null) return b;
  if (b === null) return a;
  const kept = [...a.filter(p => b.some(q => patternWithin(p, q))), ...b.filter(q => a.some(p => patternWithin(q, p)))];
  return [...new Set(kept)].sort();
}

/**
 * The strictest of two authorities, used when an agent is in two custom
 * groups (Khaliq, answer 7). Classes are intersected. Ask-first lists,
 * required conditions and limits are combined so the result allows no more
 * than either one.
 */
export function strictest(a: Authority, b: Authority): Authority {
  const classes = a.classes === null ? b.classes : b.classes === null ? a.classes :
    a.classes.filter(item => b.classes!.includes(item));
  const requireTierO = [...new Set([...a.requireTierO, ...b.requireTierO])]
    .filter(item => classes === null || classes.includes(item));
  const prOpsLimit = a.prOpsLimit === null ? b.prOpsLimit : b.prOpsLimit === null ? a.prOpsLimit :
    a.prOpsLimit.filter(op => b.prOpsLimit!.includes(op));
  const requiredConditions: RequiredConditions = {};
  for (const item of ACTION_CLASSES) {
    const merged = unionConditions(a.requiredConditions[item], b.requiredConditions[item]);
    if (merged.length && (classes === null || classes.includes(item))) requiredConditions[item] = merged;
  }
  const expiresAt = a.expiresAt && b.expiresAt ? new Date(Math.min(a.expiresAt.getTime(), b.expiresAt.getTime())) :
    a.expiresAt ?? b.expiresAt;
  return { classes, requireTierO: ACTION_CLASSES.filter(item => requireTierO.includes(item)), prOpsLimit, requiredConditions,
    targets: intersectTargets(a.targets, b.targets), expiresAt };
}

/**
 * Which binding decides for one proven agent (Khaliq's answers 5 to 8). The
 * most specific binding wins and nothing is unioned. The order is:
 * 1. an `agent` binding naming the agent. An `excluded` one gives nothing and
 *    stops here: no fall-through.
 * 2. a custom `group` binding; with two groups, the strictest of them.
 * 3. a root agent's `connector_kind` binding, then its `relay_agents` binding.
 *    A root is the connected agent itself, not one it launched.
 * 4. a launched agent's default, Read-only. It applies when the agent's root
 *    is covered at level 3; roles never pass down the spawn tree.
 * 5. a legacy rule (`all_agents`, no role), which covers the whole spawn tree
 *    with every class, as before roles existed.
 * An explicit grant wins over all of these, before resolution is reached.
 * Expired bindings are ignored.
 */
export function decide(bindings: readonly BindingView[], agent: { agentId: string; path: TrustPathRow; groupIds: readonly string[] },
  now: Date): Decision {
  const active = bindings.filter(binding => live(binding, now)).sort((x, y) => x.id.localeCompare(y.id));
  const own = active.find(binding => binding.principalKind === "agent" && binding.principalRef === agent.agentId);
  if (own) {
    return own.role === "excluded" ? { kind: "excluded", binding: own } :
      { kind: "covered", binding: own, authority: authorityOf(own), source: "agent" };
  }
  const groups = active.filter(binding => binding.principalKind === "group" && binding.principalRef !== null &&
    agent.groupIds.includes(binding.principalRef));
  if (groups.length) {
    const authority = groups.map(authorityOf).reduce(strictest);
    return { kind: "covered", binding: groups[0]!, authority, source: "group" };
  }
  const root = agent.path.root;
  const builtIn = (root.kind === "connector" ?
    active.find(binding => binding.principalKind === "connector_kind" && binding.principalRef === root.connector) : undefined) ??
    active.find(binding => binding.principalKind === "relay_agents");
  if (builtIn) {
    if (!agent.path.hops.length) {
      const source: DecisionSource = builtIn.principalKind === "connector_kind" ? "connector_kind" : "relay_agents";
      return { kind: "covered", binding: builtIn, authority: authorityOf(builtIn), source };
    }
    return { kind: "covered", binding: builtIn, authority: readOnlyAuthority(authorityOf(builtIn)), source: "spawn_default" };
  }
  const legacy = active.find(binding => binding.principalKind === "all_agents" && binding.role === null);
  if (legacy) return { kind: "covered", binding: legacy, authority: authorityOf(legacy), source: "legacy" };
  return { kind: "none" };
}

/**
 * Whether an authority grants nothing, so no system grant may stand for it.
 * Either of these covers nothing:
 * - no class: two custom groups with disjoint classes;
 * - no target: two groups whose repo targets do not overlap. A system scope's
 *   empty `targets` means every target, so an empty intersection must never
 *   reach systemScopes (review B1 on cloud#6665).
 * A legacy authority (`classes: null`) always grants.
 */
export function coversNothing(authority: Authority): boolean {
  if (authority.classes === null) return false;
  return !authority.classes.length || (authority.targets !== null && !authority.targets.length);
}

/**
 * The scopes a system grant stores for an authority. A legacy rule stores none,
 * which a system grant reads as every class. Every other authority stores one
 * scope per class it covers, with its targets (empty means every target), its
 * pr_ops limit and its required conditions.
 */
export function systemScopes(authority: Authority): GrantScope[] {
  if (authority.classes === null) return [];
  // Never stored: an empty target list here would read as every target.
  if (coversNothing(authority)) throw new Error("an authority that covers nothing has no system scopes");
  return authority.classes.map(item => ({
    class: item, targets: OWN_OWNER_ONLY_CLASSES.includes(item) ? [] : [...(authority.targets ?? [])],
    ...(item === "pr_ops" && authority.prOpsLimit ? { ops: [...authority.prOpsLimit] } : {}),
    ...(authority.requiredConditions[item]?.length ? { conditions: authority.requiredConditions[item]!.map(c => ({ type: c.type })) } : {}),
  }));
}

/** The op of a pr_ops target, without its `=value` (`label=bug` is `label`). */
export function prOpOf(target: string): string | null {
  const op = prOpsTarget(target)?.op;
  return op ? op.split("=")[0]! : null;
}

/**
 * The repository an action acts on, for a binding's repo targets:
 * - for merge and pr_ops, the PR's repo;
 * - for a release, the repo before its first `:`;
 * - for any other class, an `owner/repo` prefix before a `:` or `#`.
 * Null when there is none. A binding limited to repos then fails closed.
 */
export function actionRepo(action: Pick<Action, "class" | "target">): string | null {
  const head = repoPart(action).split(/[#:]/u)[0]!;
  return REPO_TARGET.test(head) ? head : null;
}

/**
 * Whether a system grant's scopes cover one action. No scopes means a legacy
 * rule: every class. Otherwise the class must have a scope. A pr_ops op must
 * be in its `ops`, and the action's repo must be inside one of its targets
 * (empty targets mean every target). prompt_approval and config_change never
 * take repo targets: they name their own session.
 */
export function systemScopesCover(scopes: readonly GrantScope[], action: Pick<Action, "class" | "target">): boolean {
  if (!scopes.length) return true;
  const scope = scopes.find(item => item.class === action.class);
  if (!scope) return false;
  if (action.class === "pr_ops" && scope.ops) {
    const op = prOpOf(action.target);
    if (!op || !scope.ops.includes(op)) return false;
  }
  if (!scope.targets.length || OWN_OWNER_ONLY_CLASSES.includes(action.class)) return true;
  const repo = actionRepo(action);
  return repo !== null && scope.targets.some(pattern => targetCovers(pattern, repo));
}

/** The conditions a system grant always requires for one class (empty when none). */
export function requiredConditionsOf(scopes: readonly GrantScope[], actionClass: ActionClass): RequiredCondition[] {
  const conditions = scopes.find(item => item.class === actionClass)?.conditions ?? [];
  return conditions.filter((condition): condition is RequiredCondition =>
    (REQUIRED_CONDITION_TYPES as readonly string[]).includes(condition.type));
}

/** Whether a binding's repo target is valid: `owner/repo` or `owner/*` (no `#N`, no `:`). */
export function isValidBindingTarget(pattern: string): boolean {
  // A concrete owner (the action repository's owner grammar); `*` only as the whole repo segment. `*/repo` would
  // cover that repo name under every owner.
  return isValidTargetPattern(pattern) && !/[#:]/u.test(pattern) &&
    /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\/(?:\*|[A-Za-z0-9_.-]{1,100})$/u.test(pattern);
}

/** Two authorities grant exactly the same thing (a system grant then needs no re-resolution). */
export function sameScopes(a: readonly GrantScope[], b: readonly GrantScope[]): boolean {
  const key = (scopes: readonly GrantScope[]) => JSON.stringify([...scopes].map(scope => ({
    class: scope.class, targets: [...scope.targets].sort(), ops: scope.ops ? [...scope.ops].sort() : null,
    conditions: (scope.conditions ?? []).map(c => c.type).sort(),
  })).sort((x, y) => x.class.localeCompare(y.class)));
  return key(a) === key(b);
}

/** What a binding grants, as a write names it. A preset role resolves its classes and limits once, when saved. */
export type BindingFields = {
  role: Role;
  classes: ActionClass[];
  requireTierO: ActionClass[];
  prOpsLimit: PrOp[] | null;
  requiredConditions: RequiredConditions;
  targets: string[] | null;
  expiresAt: Date | null;
};

export type BindingBody = { role?: Role; classes?: ActionClass[]; require_tier_o?: ActionClass[]; pr_ops_limit?: PrOp[] | null;
  required_conditions?: Partial<Record<ActionClass, Array<{ type: (typeof REQUIRED_CONDITION_TYPES)[number] }>>>;
  targets?: string[] | null; expires_at?: string | null };

/**
 * What a binding grants, from a request body and, on PATCH, the binding as
 * stored. Fields a PATCH omits keep their stored values.
 * - A preset role (`trusted`, `standard`, `read_only`) resolves its classes,
 *   ask-first list, pr_ops limit and required conditions from the preset, now,
 *   once. Naming any of those for a preset is refused.
 * - `custom` names its classes. Its ask-first list and conditions must be
 *   inside them, and a pr_ops limit needs pr_ops.
 * - `excluded` takes nothing, and only an `agent` principal may be excluded.
 * `targets` and `expires_at` apply to every role but `excluded`.
 * Returns an error message or the fields.
 */
export function bindingFields(body: BindingBody, principalKind: PrincipalKind, current: BindingFields | null,
  now: Date): BindingFields | string {
  const role = body.role ?? current?.role;
  if (!role) return "role is required";
  const named = body.classes !== undefined || body.require_tier_o !== undefined || body.pr_ops_limit !== undefined ||
    body.required_conditions !== undefined;
  const targets = body.targets !== undefined ? body.targets && [...new Set(body.targets)].sort() : current?.targets ?? null;
  const expiresAt = body.expires_at !== undefined ? (body.expires_at ? new Date(body.expires_at) : null) : current?.expiresAt ?? null;
  if (body.expires_at && expiresAt! <= now) return "expires_at must be in the future";
  if (role === "excluded") {
    if (principalKind !== "agent") return "only one agent can be excluded";
    if (named || body.targets || body.expires_at) return "an exclusion takes no other fields";
    return { role, classes: [], requireTierO: [], prOpsLimit: null, requiredConditions: {}, targets: null, expiresAt: null };
  }
  if (role !== "custom") {
    if (named) return "a preset role sets its own classes; use role custom to choose them";
    // A PATCH that keeps the role (omits it) keeps the authority saved with it: a preset changed in a later
    // build never re-copies into, widens or narrows a binding nobody edited.
    if (body.role === undefined && current && current.role === role) {
      return { role, classes: [...current.classes], requireTierO: [...current.requireTierO],
        prOpsLimit: current.prOpsLimit && [...current.prOpsLimit], requiredConditions: structuredClone(current.requiredConditions),
        targets, expiresAt };
    }
    const preset = PRESETS[role];
    return { role, classes: [...preset.classes], requireTierO: [...preset.requireTierO],
      prOpsLimit: preset.prOpsLimit && [...preset.prOpsLimit], requiredConditions: structuredClone(preset.requiredConditions),
      targets, expiresAt };
  }
  const keep = current?.role === "custom";
  const classes = body.classes ? ACTION_CLASSES.filter(item => body.classes!.includes(item)) : keep ? current!.classes : null;
  if (!classes?.length) return "a custom role names its classes";
  const requireTierO = ACTION_CLASSES.filter(item => (body.require_tier_o ?? (keep ? current!.requireTierO : [])).includes(item));
  if (requireTierO.some(item => !classes.includes(item))) return "require_tier_o must be inside classes";
  const prOpsLimit = body.pr_ops_limit !== undefined ? body.pr_ops_limit && PR_OPS_OPS.filter(op => body.pr_ops_limit!.includes(op)) :
    keep ? current!.prOpsLimit : null;
  if (prOpsLimit && !classes.includes("pr_ops")) return "pr_ops_limit needs the pr_ops class";
  const requiredConditions: RequiredConditions = {};
  const conditions = body.required_conditions ?? (keep ? current!.requiredConditions : {});
  for (const [item, list] of Object.entries(conditions) as Array<[ActionClass, Array<{ type: (typeof REQUIRED_CONDITION_TYPES)[number] }>]>) {
    if (!list?.length) continue;
    if (!classes.includes(item)) return "required_conditions must be inside classes";
    if (!CONDITIONED_CLASSES.includes(item)) return "required_conditions apply only to merge and pr_ops, whose targets name a PR";
    requiredConditions[item] = REQUIRED_CONDITION_TYPES.filter(type => list.some(c => c.type === type)).map(type => ({ type }));
  }
  return { role, classes, requireTierO, prOpsLimit, requiredConditions, targets, expiresAt };
}
