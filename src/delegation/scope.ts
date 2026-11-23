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
] as const;
export type ActionClass = typeof ACTION_CLASSES[number];

/** §16.1: classes that need an owner-minted (tier O) approval by default. */
export const DEFAULT_TIER_O_CLASSES: readonly ActionClass[] = ["secret_change", "destructive", "spend"];

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
  "condition_unmet", "condition_unavailable",
] as const;
export type ReasonCode = typeof REASON_CODES[number];

export const MAX_CONDITIONS = 5;

/** §5.5 / §16.1: the closed set of structured conditions. */
export const conditionSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("ci_green") }).strict(),
  z.object({ type: z.literal("head_sha"), sha: z.string().regex(/^[0-9a-f]{40}$/) }).strict(),
  z.object({ type: z.literal("reviews_approved"), min: z.number().int().min(1).max(10) }).strict(),
  z.object({ type: z.literal("mergeable") }).strict(),
  z.object({ type: z.literal("not_before"), at: z.string().max(64).refine(value =>
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/i.test(value) && Number.isFinite(Date.parse(value))) }).strict(),
]);
export type Condition = z.infer<typeof conditionSchema>;
export const GITHUB_CONDITIONS: ReadonlySet<string> = new Set(["ci_green", "head_sha", "reviews_approved", "mergeable"]);

export type Action = { class: ActionClass; target: string; conditions?: Condition[]; note?: string | null };
export type Scope = { class: ActionClass; targets: string[] };

const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/i;
const rfc3339 = z.string().max(64).refine(value => RFC3339.test(value) && Number.isFinite(Date.parse(value)),
  { message: "must be RFC 3339" });
export const APPROVAL_REF = /^apv_[A-Za-z0-9]{8,64}$/;

export const actionClass = z.enum(ACTION_CLASSES);
const target = z.string().min(1).max(MAX_TARGET_CHARS).refine(value => !/[\u0000-\u001f\u007f]/.test(value));

/** `owner/repo#N`: the only target PR conditions apply to (Cloud's PR_TARGET). */
export const PR_TARGET = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\/[A-Za-z0-9_.-]{1,100}#[1-9][0-9]{0,9}$/u;
/** `owner/repo`: a repository target (Cloud's REPO_TARGET). */
export const REPO_TARGET = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\/[A-Za-z0-9_.-]{1,100}$/u;
/** `<session agent id>:<request ref>`: a prompt_approval action target. */
const PROMPT_TARGET = /^[^\s:*#/]{1,200}:[^\s:*#/]{1,200}$/u;

/** A concrete target: a valid pattern with no wildcard. */
export function isConcreteTarget(target: string): boolean {
  return validTargetPattern(target) && !target.includes("*");
}

/** Whether an action is well formed: concrete target, and conditions valid for that target (§16.1). */
export function actionIsValid(action: Pick<Action, "class" | "target" | "conditions">): boolean {
  if (!isConcreteTarget(action.target)) return false;
  if (action.class === "prompt_approval" && !PROMPT_TARGET.test(action.target)) return false;
  const conditions = action.conditions ?? [];
  if (conditions.length > MAX_CONDITIONS) return false;
  if (new Set(conditions.map(condition => condition.type)).size !== conditions.length) return false;
  const prTarget = action.class !== "prompt_approval" && PR_TARGET.test(action.target);
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
export const ownerApprovalSchema = z.object({
  v: z.literal(1),
  owner_id: z.string().min(1).max(MAX_OWNER_ID_CHARS),
  actions: z.array(z.object({
    class: actionClass,
    target,
    conditions: z.array(conditionSchema).max(MAX_CONDITIONS).nullish().transform(value => value ?? undefined),
    note: z.string().max(MAX_NOTE_CHARS).nullish(),
  }).strict().refine(actionIsValid)).min(1).max(MAX_ACTIONS).refine(uniqueActions, { message: "one entry per class and target" }),
  quote: z.string().max(MAX_QUOTE_CHARS).nullable().optional(),
  quoted_at: rfc3339.nullable().optional(),
  quote_source: z.string().max(MAX_QUOTE_SOURCE_CHARS).nullable().optional(),
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
    if (!/^[0-9]{1,12}$/.test(number) && !(subsumes && number === "*")) return false;
    return segmentsMatch(want.segments, want.separators, got.segments.slice(0, 2), got.separators.slice(0, 1), subsumes);
  }
  return false;
}

/**
 * §16.1 prompt_approval: an approval target is `<agent id>:<request ref>`,
 * split at the first `:`; a grant target is `*` or `<agent id>:*`.
 */
export function promptTarget(target: string): { agentId: string; ref: string } | null {
  const at = target.indexOf(":");
  if (at <= 0 || at === target.length - 1) return null;
  const agentId = target.slice(0, at);
  const ref = target.slice(at + 1);
  return agentId.includes("*") || ref.includes("*") ? null : { agentId, ref };
}

export function validPromptPattern(pattern: string): boolean {
  if (pattern === "*") return true;
  return pattern.endsWith(":*") && pattern.length > 2 && !pattern.slice(0, -2).includes(":")
    && !pattern.slice(0, -2).includes("*") && !/[\u0000-\u001f\u007f\s]/.test(pattern);
}

/** Whether a grant pattern of `cls` covers `target` (or, with `subsumes`, another pattern). */
export function classTargetCovered(cls: ActionClass, pattern: string, target: string, subsumes = false): boolean {
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
export function highRisk(action: Pick<Action, "class" | "target">): boolean {
  if (["release", "secret_change", "destructive", "spend"].includes(action.class)) return true;
  return action.class === "deploy" && /:(prod|production)$/.test(action.target);
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
  // As Cloud's ownerDisplay: brackets stripped (they delimit the delegate
  // line), at most 80 UTF-16 units cut on a character boundary (never between
  // the halves of a surrogate pair), trailing space trimmed.
  const flat = (name ?? "").replace(/[\u0000-\u001f\u007f\u2028\u2029[\]]+/gu, " ").replace(/\s+/gu, " ").trim();
  if (!flat || flat.includes("@")) return "the owner";
  if (flat.length <= 80) return flat;
  const high = flat.charCodeAt(79);
  const cut = high >= 0xd800 && high <= 0xdbff ? 79 : 80;
  return flat.slice(0, cut).trimEnd();
}

export function sha256Hex(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
