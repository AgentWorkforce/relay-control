/**
 * Delegation observability, as Cloud's lib/delegation/observe.ts. Every
 * failure the attest, redeem, gate and retention paths would otherwise
 * swallow is logged here once, as one JSON line with a fixed `message` (the
 * metric name) and only safe fields.
 *
 * Never logged: bearer, Relaycast or OIDC tokens, quotes, message text, or an
 * error's message (a driver error's message can carry query parameters). An
 * error is described only by its class name and, for Postgres, its SQLSTATE.
 *
 * Messages:
 *   delegation.unavailable        an attest, redeem, gate redeem or retention sweep answered `unavailable` because something threw
 *   delegation.audit_write_failed a best-effort audit write failed (the answer is unchanged)
 *   delegation.revoke_failed      a durable system revocation failed (the use is still refused)
 *   delegation.dependency_failed  a JWKS (or other dependency) read failed (fails closed)
 *   delegation.refused            one refusal, by `op` and `reason` (info level)
 *   delegation.redaction_backlog  the Relaycast redaction queue after a sweep (warn when it needs an operator)
 *   delegation.audit_fenced       a paged audit read held events back behind a running transaction (info)
 *   delegation.repository_mismatch a gate redeem token matched a gate by name but carried other repository ids (warn)
 *
 * relay-control writes each line synchronously to the console, so a line is
 * never lost when the request ends (Cloud registers its async delivery with
 * the Worker's waitUntil for the same reason).
 */
export type DelegationOp = "attest" | "redeem" | "gate_redeem" | "prompt_delegates" | "conditions" | "standing" |
  "github_oidc_jwks" | "retention" | "audit" | "gate_registry";

export type SafeContext = {
  workspaceId?: string | null;
  approvalId?: string | null;
  grantId?: string | null;
  gateId?: string | null;
  reason?: string | null;
  event?: string | null;
  [key: string]: string | number | boolean | null | undefined;
};

type Level = "info" | "warn" | "error";
type Sink = (level: Level, line: string) => void;

const consoleSink: Sink = (level, line) => {
  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.info(line);
};
let sink: Sink = consoleSink;

/** Tests capture the lines; null restores the console. */
export function setDelegationLogSinkForTesting(next: Sink | null): void {
  sink = next ?? consoleSink;
}

/** The error's class and, for a Postgres error, its SQLSTATE: never its message. */
export function errorShape(error: unknown): { error_class: string; error_code?: string } {
  const name = error instanceof Error ? (error.constructor?.name && error.constructor.name !== "Object" ?
    error.constructor.name : error.name) : typeof error;
  const code = (error as { code?: unknown } | null)?.code ?? (error as { cause?: { code?: unknown } } | null)?.cause?.code;
  return typeof code === "string" && /^[0-9A-Z]{5}$/u.test(code) ? { error_class: name, error_code: code } : { error_class: name };
}

function fields(op: DelegationOp, ctx: SafeContext, error?: unknown): Record<string, unknown> {
  const { workspaceId, ...rest } = ctx;
  const out: Record<string, unknown> = { area: "delegation", op, ...(workspaceId ? { workspaceId } : {}) };
  for (const [key, value] of Object.entries(rest)) if (value !== undefined && value !== null) out[key] = value;
  return error === undefined ? out : { ...out, ...errorShape(error) };
}

/** Logging never throws and never changes an answer. */
function emit(level: Level, message: string, data: Record<string, unknown>): void {
  try {
    sink(level, JSON.stringify({ level, message, ...data }));
  } catch {
    // Observability must not change an answer.
  }
}

export function logUnavailable(op: DelegationOp, error: unknown, ctx: SafeContext = {}): void {
  emit("error", "delegation.unavailable", fields(op, ctx, error));
}

export function logAuditWriteFailed(op: DelegationOp, error: unknown, ctx: SafeContext = {}): void {
  emit("error", "delegation.audit_write_failed", fields(op, ctx, error));
}

export function logRevokeFailed(op: DelegationOp, error: unknown, ctx: SafeContext = {}): void {
  emit("error", "delegation.revoke_failed", fields(op, ctx, error));
}

export function logDependencyFailed(op: DelegationOp, error: unknown, ctx: SafeContext = {}): void {
  emit("error", "delegation.dependency_failed", fields(op, ctx, error));
}

export function logRefused(op: DelegationOp, ctx: SafeContext): void {
  emit("info", "delegation.refused", fields(op, ctx));
}

export function logRedactionBacklog(level: "info" | "warn", ctx: SafeContext): void {
  emit(level, "delegation.redaction_backlog", fields("retention", ctx));
}

export function logAuditFenced(ctx: SafeContext): void {
  emit("info", "delegation.audit_fenced", fields("audit", ctx));
}

export function logRepositoryMismatch(ctx: SafeContext): void {
  emit("warn", "delegation.repository_mismatch", fields("gate_redeem", ctx));
}
