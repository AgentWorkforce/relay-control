import { createHash } from "node:crypto";
import { z } from "zod";

/**
 * Owner-named trusted delegates: the v1 wire contract's data rules
 * (AgentWorkforce/relay docs/design/owner-trusted-delegates.md §16.1, §16.2,
 * §16.4). Pure functions; no I/O.
 */

/** §16.1: the closed, protocol-versioned action classes. */
export const ACTION_CLASSES = [
  "merge", "pr_ops", "deploy", "release", "secret_change", "destructive", "spend", "external_comms", "prompt_approval",
  "config_change",
] as const;
export type ActionClass = typeof ACTION_CLASSES[number];

/** One plain-language line per class, for the Delegates panel (GET delegates/roles), as Cloud's DELEGATION_CLASS_DESCRIPTIONS. */
export const CLASS_DESCRIPTIONS: Record<ActionClass, string> = {
  merge: "Merge a pull request.",
  pr_ops: "Routine pull request work: comment, label, request a review, re-run CI, close or reopen.",
  deploy: "Deploy to an environment.",
  release: "Publish a release, or land a branch for one.",
  secret_change: "Change secrets, credentials or access.",
  destructive: "Delete, or change something that cannot be undone.",
  spend: "Spend money or buy resources.",
  external_comms: "Send messages outside the workspace, such as Slack or email.",
  prompt_approval: "Answer permission prompts in your own sessions.",
  config_change: "Change one setting of your own agent session.",
};

/**
 * §16.1, §15 (Khaliq, 7:43): no class needs an owner-minted (tier O) approval
 * by default. An org can still require it with `require_tier_o`.
 */
export const DEFAULT_TIER_O_CLASSES: readonly ActionClass[] = [];

/**
 * §5.3: the recipient's own delegation settings are never delegable, so a
 * delegate cannot widen its own reach through `config_change`.
 */
export const NEVER_DELEGABLE_SETTINGS: readonly string[] = ["delegated_approvals_from", "spawn_delegate_approvals"];

/**
 * Whether a `config_change` setting is one a delegate may never set (§5.3),
 * as Cloud's isUndelegableSetting: the name is trimmed, lowercased, and `-`
 * and `.` are read as `_` before matching, so `Delegated-Approvals-From` or
 * `delegated_approvals_from.0` is the same setting. Any setting whose name
 * mentions delegation is refused too, so a future delegation setting is
 * undelegable by default.
 */
export function isUndelegableSetting(setting: string): boolean {
  const name = setting.trim().toLowerCase().replace(/[-.]/gu, "_");
  return name.includes("delegat") ||
    NEVER_DELEGABLE_SETTINGS.some(denied => name === denied || name.startsWith(`${denied}_`));
}

export const MAX_TARGET_CHARS = 256;
export const MAX_NOTE_CHARS = 280;
export const MAX_QUOTE_CHARS = 2000;
export const MAX_QUOTE_SOURCE_CHARS = 64;
export const MAX_OWNER_ID_CHARS = 128;
export const MAX_ACTIONS = 20;

/** §16.3 defaults. */
export const GRANT_DEFAULT_DAYS = 30;
export const GRANT_MAX_DAYS = 90;
export const APPROVAL_DEFAULT_MS = 60 * 60 * 1000;
export const APPROVAL_MAX_MS = 24 * 60 * 60 * 1000;
export const ATTESTATION_TTL_SECONDS = 300;
export const CLAIM_TTL_MS = 10 * 60 * 1000;

export const REASON_CODES = [
  "not_enabled", "not_delegate", "no_approval", "out_of_scope", "expired", "revoked",
  "recipient_policy", "tier_o_required", "consumed", "not_pending", "unavailable",
  "condition_unmet", "condition_unavailable", "predates_grant",
  // Release-gate redeem (§11a.3).
  "gate_unknown", "oidc_invalid", "gate_mismatch", "target_prefix", "sha_mismatch", "repository_mismatch", "gate_owner_unqualified",
  // Granted approvers (cloud#6709, #owner-decisions 251907114153873408).
  "identity_mismatch", "protected_path", "self_approval", "unattributed_commit", "unattributable_target",
] as const;
export type ReasonCode = typeof REASON_CODES[number];

export const MAX_CONDITIONS = 5;

const RFC3339_PARTS = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d{1,9})?(Z|([+-])(\d{2}):(\d{2}))$/i;

/**
 * An RFC 3339 timestamp with a real calendar date and clock: `2026-02-30`
 * or `24:00` are refused instead of being normalized by Date.parse. Leap days
 * and numeric offsets are accepted.
 */
export function validRfc3339(value: string): boolean {
  if (value.length > 64) return false;
  const parts = RFC3339_PARTS.exec(value);
  if (!parts) return false;
  const [year, month, day, hour, minute, second] = parts.slice(1, 7).map(Number) as [number, number, number, number, number, number];
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  if (!days || day < 1 || day > days || hour > 23 || minute > 59 || second > 59) return false;
  if (parts[9] && (Number(parts[10]) > 23 || Number(parts[11]) > 59)) return false;
  return Number.isFinite(Date.parse(value));
}

/** PostgreSQL text cannot hold NUL; such text is refused at validation, never at the database. */
const noNul = (value: string) => !value.includes("\u0000");

/** §5.5 / §16.1: the closed set of structured conditions. */
export const conditionSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("ci_green") }).strict(),
  z.object({ type: z.literal("head_sha"), sha: z.string().regex(/^[0-9a-f]{40}$/) }).strict(),
  z.object({ type: z.literal("reviews_approved"), min: z.number().int().min(1).max(10) }).strict(),
  z.object({ type: z.literal("mergeable") }).strict(),
  z.object({ type: z.literal("not_before"), at: z.string().max(64).refine(validRfc3339) }).strict(),
]);
export type Condition = z.infer<typeof conditionSchema>;
export const GITHUB_CONDITIONS: ReadonlySet<string> = new Set(["ci_green", "head_sha", "reviews_approved", "mergeable"]);

export type Action = { class: ActionClass; target: string; conditions?: Condition[]; note?: string | null };
/**
 * One class a grant covers. `ops` and `conditions` appear only on system
 * grants a role binding created (roles.ts): `ops` limits pr_ops operations,
 * and `conditions` are checked at every redeem. On those grants an empty
 * `targets` means every target.
 */
export type Scope = { class: ActionClass; targets: string[]; ops?: string[]; conditions?: Array<{ type: string }> };

const rfc3339 = z.string().max(64).refine(validRfc3339, { message: "must be RFC 3339 with a real date" });
export const APPROVAL_REF = /^apv_[A-Za-z0-9]{8,64}$/;

export const actionClass = z.enum(ACTION_CLASSES);
const target = z.string().min(1).max(MAX_TARGET_CHARS).refine(value => !/[\u0000-\u001f\u007f]/.test(value));

/** `owner/repo#N`: the only target PR conditions apply to (Cloud's PR_TARGET). */
export const PR_TARGET = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\/[A-Za-z0-9_.-]{1,100}#[1-9][0-9]{0,9}$/u;
/** `owner/repo`: a repository target (Cloud's REPO_TARGET). */
export const REPO_TARGET = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\/[A-Za-z0-9_.-]{1,100}$/u;
/** `<session agent id>:<request ref>`: a prompt_approval action target. */
const PROMPT_TARGET = /^([^\s:*#/]{1,200}):([^\s:*#/]{1,200}):(approve|deny)$/u;
/**
 * `owner/repo#N:<op>`: a pr_ops action target names one operation on one PR
 * (§5.1): close, reopen, label=<name>, unlabel=<name>,
 * request_review=<login>, rerun_ci or comment. No `open`, as Cloud
 * (cloud#6603 12ae243d6): a PR's number exists only once it is opened, so an
 * `owner/repo#N:open` target could never be redeemed.
 */
const PR_OPS_TARGET = /^([A-Za-z0-9][A-Za-z0-9_.-]{0,99}\/[A-Za-z0-9_.-]{1,100}#[1-9][0-9]{0,9}):(close|reopen|rerun_ci|comment|(?:label|unlabel)=[^\s:*#/]{1,100}|request_review=[A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))$/u;

/** A pr_ops target's PR (`owner/repo#N`) and operation, or null when it is not one. */
export function prOpsTarget(target: string): { pr: string; op: string } | null {
  const match = PR_OPS_TARGET.exec(target);
  return match ? { pr: match[1]!, op: match[2]! } : null;
}

/** The PR or repo an action's target names, for PR conditions and CODEOWNERS standing. */
export function repoPart(action: Pick<Action, "class" | "target">): string {
  return action.class === "pr_ops" ? prOpsTarget(action.target)?.pr ?? action.target : action.target;
}
/** `<agent id>:<setting>=<value>`: a config_change action target, exact, no `*` (§16.1), as Cloud's CONFIG_TARGET. */
const CONFIG_TARGET = /^([^\s:*#/=]{1,200}):([A-Za-z0-9_.-]{1,100})=([^\s*]{0,200})$/u;

/** A config_change target's parts, or null when it is not one. */
export function configTarget(target: string): { agentId: string; setting: string; value: string } | null {
  if (target.length > MAX_TARGET_CHARS) return null;
  const match = CONFIG_TARGET.exec(target);
  return match ? { agentId: match[1]!, setting: match[2]!, value: match[3]! } : null;
}

/** A concrete target: a valid pattern with no wildcard. */
export function isConcreteTarget(target: string): boolean {
  return validTargetPattern(target) && !target.includes("*");
}

/** Whether an action is well formed: concrete target, and conditions valid for that target (§16.1). */
export function actionIsValid(action: Pick<Action, "class" | "target" | "conditions">): boolean {
  if (!isConcreteTarget(action.target)) return false;
  if (action.class === "prompt_approval" && !PROMPT_TARGET.test(action.target)) return false;
  if (action.class === "config_change" && !configTarget(action.target)) return false;
  if (action.class === "pr_ops" && !prOpsTarget(action.target)) return false;
  if (action.class === "release" && !validReleaseTarget(action.target)) return false;
  // A merge names exactly one PR (`owner/repo#N`), as Cloud: a bare repo or a
  // branch target would be ambiguous and unpinned to any head. Grants may
  // still name `owner/repo` or `owner/*`, which cover that repo's `#N`.
  if (action.class === "merge" && !PR_TARGET.test(action.target)) return false;
  const conditions = action.conditions ?? [];
  if (conditions.length > MAX_CONDITIONS) return false;
  if (new Set(conditions.map(condition => condition.type)).size !== conditions.length) return false;
  // prompt_approval takes no conditions (the node applies it without a redeem);
  // config_change takes `not_before` only.
  if (action.class === "prompt_approval" && conditions.length) return false;
  const prTarget = action.class !== "config_change" && PR_TARGET.test(repoPart(action));
  return conditions.every(condition => condition.type === "not_before" || prTarget);
}

const uniqueActions = (actions: ReadonlyArray<Pick<Action, "class" | "target">>) =>
  new Set(actions.map(action => `${action.class}\u0000${action.target}`)).size === actions.length;

/** An action in a tier O mint body: class, target, conditions (no note), as Cloud. */
export const actionSchema = z.object({
  class: actionClass,
  target,
  conditions: z.array(conditionSchema).max(MAX_CONDITIONS).optional(),
}).strict().refine(actionIsValid, { message: "invalid target or conditions for this action" });
export const mintActionsSchema = z.array(actionSchema).min(1).max(MAX_ACTIONS)
  .refine(uniqueActions, { message: "one entry per class and target" });

/**
 * §16.2: the `owner_approval` object exactly as Relaycast validates it at
 * send. Control re-validates what Relaycast returns and treats anything that
 * fails as no approval at all.
 */
const UUID_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export const ownerApprovalSchema = z.object({
  v: z.literal(1),
  // A UUID is canonicalized to lowercase, as PostgreSQL returns it, so a
  // case-only difference is never read as a different owner.
  owner_id: z.string().min(1).max(MAX_OWNER_ID_CHARS)
    .transform(value => UUID_ID.test(value) ? value.toLowerCase() : value),
  actions: z.array(z.object({
    class: actionClass,
    target,
    conditions: z.array(conditionSchema).max(MAX_CONDITIONS).nullish().transform(value => value ?? undefined),
    note: z.string().max(MAX_NOTE_CHARS).refine(noNul).nullish(),
  }).strict().refine(actionIsValid)).min(1).max(MAX_ACTIONS).refine(uniqueActions, { message: "one entry per class and target" }),
  quote: z.string().max(MAX_QUOTE_CHARS).refine(noNul).nullable().optional(),
  quoted_at: rfc3339.nullable().optional(),
  quote_source: z.string().max(MAX_QUOTE_SOURCE_CHARS).refine(noNul).nullable().optional(),
  expires_at: rfc3339.nullable().optional(),
  approval_ref: z.string().regex(APPROVAL_REF).nullable().optional(),
}).strict();
export type OwnerApproval = z.infer<typeof ownerApprovalSchema>;

/**
 * Splits a target into segments and the separators between them. `/`, `:`
 * and `#` separate segments (`owner/repo#12`, `service:env`).
 */
function tokens(value: string): { segments: string[]; separators: string[] } {
  const segments: string[] = [];
  const separators: string[] = [];
  let current = "";
  for (const char of value) {
    if (char === "/" || char === ":" || char === "#") {
      segments.push(current);
      separators.push(char);
      current = "";
    } else {
      current += char;
    }
  }
  segments.push(current);
  return { segments, separators };
}

/**
 * A grant target pattern is valid when every segment is non-empty and `*`
 * only ever stands for a whole segment (`owner/*`, `*:staging`), never part
 * of one (`relay-*` is refused).
 */
export function validTargetPattern(pattern: string): boolean {
  if (!pattern || pattern.length > MAX_TARGET_CHARS || /[\u0000-\u001f\u007f\s]/.test(pattern)) return false;
  const { segments } = tokens(pattern);
  return segments.every(segment => segment.length > 0 && (segment === "*" || !segment.includes("*")));
}

function segmentsMatch(pattern: string[], patternSeparators: string[], target: string[], targetSeparators: string[],
  literalWildcard: boolean): boolean {
  if (pattern.length !== target.length) return false;
  for (let index = 0; index < pattern.length; index += 1) {
    if (index > 0 && patternSeparators[index - 1] !== targetSeparators[index - 1]) return false;
    const want = pattern[index]!;
    const got = target[index]!;
    if (!got) return false;
    if (want === "*") continue;
    if (got === "*" && !literalWildcard) return false;
    if (want !== got) return false;
  }
  return true;
}

/**
 * §16.1 scope matching. `*` covers one whole segment. An exact target covers
 * only itself, plus `owner/repo#N` for an `owner/repo` pattern; `owner/*`
 * therefore covers `owner/x` and `owner/x#12`. An action target that holds a
 * `*` segment is a wildcard request and is never covered.
 *
 * With `subsumes`, `target` is itself a pattern: true when every target the
 * second pattern covers is covered by the first (used to refuse widening on
 * PATCH).
 */
export function targetCovered(pattern: string, target: string, subsumes = false): boolean {
  if (!validTargetPattern(pattern) || target.length === 0 || target.length > MAX_TARGET_CHARS) return false;
  const want = tokens(pattern);
  const got = tokens(target);
  if (got.segments.some(segment => !segment)) return false;
  if (!subsumes && got.segments.includes("*")) return false;
  if (segmentsMatch(want.segments, want.separators, got.segments, got.separators, subsumes)) return true;
  // `owner/repo` (no `#`) also covers `owner/repo#N`.
  const repoPattern = want.segments.length === 2 && want.separators[0] === "/";
  const prTarget = got.segments.length === 3 && got.separators[0] === "/" && got.separators[1] === "#";
  if (repoPattern && prTarget) {
    const number = got.segments[2]!;
    // Only a numeric PR suffix: `owner/repo#*` would also cover `owner/repo#draft`,
    // so it is never narrower than an `owner/repo` grant.
    if (!/^[0-9]{1,12}$/.test(number)) return false;
    return segmentsMatch(want.segments, want.separators, got.segments.slice(0, 2), got.separators.slice(0, 1), subsumes);
  }
  return false;
}

/**
 * §16.1 prompt_approval: an approval target is
 * `<agent id>:<request ref>:approve` or `:deny` (the decision is bound in the
 * target); a grant target is `*` or `<agent id>:*`.
 */
export function promptTarget(target: string): { agentId: string; ref: string; decision: "approve" | "deny" } | null {
  const match = PROMPT_TARGET.exec(target);
  return match ? { agentId: match[1]!, ref: match[2]!, decision: match[3] as "approve" | "deny" } : null;
}

export function validPromptPattern(pattern: string): boolean {
  if (pattern === "*") return true;
  return pattern.endsWith(":*") && pattern.length > 2 && !pattern.slice(0, -2).includes(":")
    && !pattern.slice(0, -2).includes("*") && !/[\u0000-\u001f\u007f\s]/.test(pattern);
}

/** A config_change grant target names which agents, as Cloud: `<agent id>:*` or `*` (§16.1). */
export function validConfigPattern(pattern: string): boolean {
  return pattern === "*" || /^[^\s:*#/=]{1,200}:\*$/u.test(pattern);
}

/** Whether a grant pattern of `cls` covers `target` (or, with `subsumes`, another pattern). */
export function classTargetCovered(cls: ActionClass, pattern: string, target: string, subsumes = false): boolean {
  if (cls === "config_change") {
    if (!validConfigPattern(pattern)) return false;
    if (subsumes) return pattern === "*" ? validConfigPattern(target) : target === pattern;
    const parsed = configTarget(target);
    return parsed !== null && (pattern === "*" || `${parsed.agentId}:*` === pattern);
  }
  // pr_ops grants (`owner/repo`, `owner/repo#N`, `owner/*`) cover every op on a covered PR.
  if (cls === "pr_ops" && !subsumes) {
    const parsed = prOpsTarget(target);
    return parsed !== null && targetCovered(pattern, parsed.pr);
  }
  if (cls !== "prompt_approval") return targetCovered(pattern, target, subsumes);
  if (!validPromptPattern(pattern)) return false;
  if (pattern === "*") return subsumes ? validPromptPattern(target) : promptTarget(target) !== null;
  if (subsumes) return target === pattern;
  const parsed = promptTarget(target);
  return parsed !== null && `${parsed.agentId}:*` === pattern;
}

/** Every action is covered by a scope of its class. The whole set is judged, never trimmed. */
export function actionsCovered(scopes: readonly Scope[], actions: readonly Pick<Action, "class" | "target">[]): boolean {
  return actions.every(action => scopes.some(scope =>
    scope.class === action.class && scope.targets.some(pattern => classTargetCovered(action.class, pattern, action.target))));
}

/** §16.1: high-risk actions are always single-use. */
/** §16.1: classes that are always single use, per action; `deploy` in every environment. */
export const HIGH_RISK_CLASSES: readonly string[] = ["release", "deploy", "secret_change", "destructive", "spend", "config_change"];

export function highRisk(action: Pick<Action, "class" | "target">): boolean {
  return HIGH_RISK_CLASSES.includes(action.class);
}

/** The classes in `actions` that need tier O under the defaults, the workspace policy and the grant. */
export function tierORequired(actions: readonly Pick<Action, "class">[], ...extra: ReadonlyArray<readonly string[]>): boolean {
  const required = new Set<string>([...DEFAULT_TIER_O_CLASSES, ...extra.flat()]);
  return actions.some(action => required.has(action.class));
}

const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/** Big-endian base62 (alphabet 0-9A-Za-z), no padding. */
export function base62(bytes: Uint8Array): string {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  if (value === 0n) return "0";
  let out = "";
  while (value > 0n) {
    out = BASE62[Number(value % 62n)]! + out;
    value /= 62n;
  }
  return out;
}

/** §16.4: a tier D approval's id, `apv_` + base62(SHA-256(ws|message_id)[0..16]). */
export function tierDApprovalId(workspaceId: string, messageId: string): string {
  const digest = createHash("sha256").update(`${workspaceId}|${messageId}`).digest();
  return `apv_${base62(digest.subarray(0, 16))}`;
}

/** An action as attested and stored: class, target and conditions (notes dropped). */
export function canonicalAction(action: Action): Action {
  return { class: action.class, target: action.target,
    ...(action.conditions?.length ? { conditions: action.conditions.map(condition => ({ ...condition })) } : {}) };
}

/** Compare action lists as sets of (class, target, conditions), notes ignored. */
export function sameActions(left: readonly Action[], right: readonly Action[]): boolean {
  const key = (action: Action) => `${action.class}\u0000${action.target}\u0000${JSON.stringify((action.conditions ?? [])
    .map(condition => JSON.stringify(Object.fromEntries(Object.entries(condition).sort()))).sort())}`;
  const a = new Set(left.map(key));
  const b = new Set(right.map(key));
  return a.size === b.size && [...a].every(item => b.has(item));
}

/** §15.2: the owner's display name on one line, at most 80 characters, or "the owner". */
export function ownerDisplay(name: string | null | undefined): string {
  // Byte-for-byte Cloud's ownerDisplay: brackets stripped (they delimit the
  // delegate line), at most 80 characters cut on a code point boundary (never
  // inside a surrogate pair), trailing space trimmed.
  const flat = (name ?? "").replace(/[\u0000-\u001f\u007f\u2028\u2029[\]]+/gu, " ").replace(/\s+/gu, " ").trim();
  if (!flat || flat.includes("@")) return "the owner";
  const chars = Array.from(flat);
  return chars.length > 80 ? chars.slice(0, 80).join("").trimEnd() : flat;
}

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

// Release targets (§11a.2) --------------------------------------------------

const REPO_PART = "[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9_.-]{1,100}";
const SHA40 = "[0-9a-f]{40}";
/**
 * A land branch: letters, digits, `.`, `_`, `/` and `-`, and only a name
 * `git check-ref-format --branch` accepts (as the hosted twin): no leading
 * `-`, `.` or `/`, no `..`, no component starting with `.` or ending in
 * `.lock`, no `//`, no trailing `/` or `.`, and not `HEAD`. Git refuses every name this
 * leaves out, so no real branch is lost, and a grant pattern such as
 * `owner/repo:land:bad..branch:*` names nothing and is refused.
 */
const BRANCH = String.raw`(?!HEAD:)(?![-./])(?![^:]*\.\.)(?![^:]*/\.)(?![^:]*\.lock(?:/|:))(?![^:]*//)(?![^:]*[/.]:)[A-Za-z0-9._/-]{1,200}`;
/**
 * Release targets (§11a.2), as Cloud's RELEASE_TARGETS. A `release` action
 * names exactly one release:
 * - `<repo>:<channel>:v<version>:<source sha>:<candidate run id>[:<profile id>]`
 * - landing a branch: `<repo>:land:<branch>:<head sha>`
 * - TestFlight and App Store: `<repo>:ios:<distribution>:<build number>:<sha>`
 * "Ship everything" names nothing, so it matches none of these.
 */
export const RELEASE_TARGETS: readonly RegExp[] = [
  new RegExp(`^${REPO_PART}:(?!land:|ios:)[a-z][a-z0-9_-]{0,31}:v[0-9][0-9A-Za-z.+-]{0,63}:${SHA40}:[1-9][0-9]{0,19}(?::[A-Za-z0-9_.-]{1,64})?$`, "u"),
  new RegExp(`^${REPO_PART}:land:${BRANCH}:${SHA40}$`, "u"),
  // A build number is dot-separated digit groups (`42`, `2026.11.7.3`), at most 32 characters.
  new RegExp(`^${REPO_PART}:ios:[a-z][a-z0-9_-]{0,31}:(?=[0-9.]{1,32}:)[0-9]+(?:\\.[0-9]+)*:${SHA40}$`, "u"),
];

export function validReleaseTarget(target: string): boolean {
  return RELEASE_TARGETS.some(pattern => pattern.test(target));
}

/**
 * The commit a release target names, and its form, as Cloud's
 * releaseTargetSha: `candidate` for `<repo>:<channel>:v<version>:<source
 * sha>:<run id>[:<profile>]` (the third segment after the repo), `land` and
 * `ios` for the others (the last segment). Null for anything that is not a
 * release target.
 */
export function releaseTargetSha(target: string): { sha: string; form: "candidate" | "land" | "ios" } | null {
  if (!validReleaseTarget(target)) return null;
  const segments = target.slice(target.indexOf(":") + 1).split(":");
  if (segments[0] === "land" || segments[0] === "ios") return { sha: segments.at(-1)!, form: segments[0] };
  return { sha: segments[2]!, form: "candidate" };
}

/**
 * Release grant patterns match like every other pattern (§16.1): segments
 * between `/`, `:` and `#`, `*` standing for exactly one non-empty segment.
 * So `owner/repo:land:*:*` covers `main` but not `feature/x`, and
 * `owner/repo:land:feature/*:*` covers `feature/x`: a stored grant covers
 * exactly the targets it covered before, as the hosted twin.
 */

/** Per release form, a valid value for each field after `owner/repo`, standing in for a whole-field `*`. */
const RELEASE_FORM_SAMPLES: readonly (readonly string[])[] = [
  ["land", "x", "0".repeat(40)],
  ["ios", "x", "1", "0".repeat(40)],
  ["x", "v0", "0".repeat(40), "1"],
  ["x", "v0", "0".repeat(40), "1", "x"],
];

/**
 * Whether a release grant pattern can cover some release target (§11a.2), as
 * the hosted twin. It is a valid pattern (`*` a whole segment), and its
 * literals fit one release form: the pattern with each `*` replaced by a
 * valid value is itself a release target within the length limit.
 * `owner/repo`, `owner/*`, `owner/repo:land:bad..branch:*` or a candidate
 * without a 40-character sha cover nothing, so they are refused at grant
 * create and PATCH rather than stored as a grant that silently covers nothing.
 */
export function validReleasePattern(pattern: string): boolean {
  if (!validTargetPattern(pattern)) return false;
  // Git forbids `:` in a branch and the repo has none, so `:` only ever separates fields.
  const [head, ...fields] = pattern.split(":");
  const fill = (field: string, sample: string) =>
    field === "*" ? sample : field.split(/([/#])/u).map(token => token === "*" ? "x" : token).join("");
  return RELEASE_FORM_SAMPLES.some(samples => samples.length === fields.length && (() => {
    const target = [fill(head!, "x"), ...fields.map((field, index) => fill(field, samples[index]!))].join(":");
    return target.length <= MAX_TARGET_CHARS && validReleaseTarget(target);
  })());
}
