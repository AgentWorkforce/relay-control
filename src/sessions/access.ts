import type { SelfhostConfig } from "../config.js";
import { isRecord } from "./history.js";

/**
 * Session access management: who may read one session.
 *
 * The policy lives in relaygate (its contract, "Session access"); Control keeps
 * no allow-list and stores nothing. Control only:
 * - validates the change before anything is sent;
 * - resolves member emails to opaque user ids of current members of the
 *   caller's organization (only the ids go upstream);
 * - forwards the call with the acting person's own read token (the transport,
 *   `accessViaSessionRead` for MCP and `accessViaDashboardReader` for the
 *   dashboard), never a
 *   workspace or service credential;
 * - maps the answer back, naming current members by email and name.
 *
 * Both the MCP tools (../mcp/session-access.ts) and the dashboard routes
 * (./access-routes.ts) use this module.
 */

/**
 * The one configuration condition for both surfaces: the read API is
 * relaygate (SELFHOST_RELAYGATE_PUBLIC_URL set, so read-token mints name a
 * reader kind) and the per-person MCP reader is on (SESSION_READ_API_MCP_READS),
 * as gate-only installs configure it.
 */
export function sessionAccessConfigured(
  config: Pick<SelfhostConfig, "relaygatePublicUrl" | "sessionReadMcpReads"> & {
    sessionReadApi?: Pick<NonNullable<SelfhostConfig["sessionReadApi"]>, "mintReaderKind"> | null;
  },
): boolean {
  return Boolean(config.relaygatePublicUrl && config.sessionReadApi?.mintReaderKind && config.sessionReadMcpReads);
}

export type AccessMember = { userId: string; email: string; name: string | null };

export type AccessRequest = {
  method: "GET" | "PATCH" | "POST";
  /** `/v1/sessions/<id>/access[/reset|/history]`. */
  path: string;
  query?: URLSearchParams;
  body?: Record<string, unknown>;
};

/**
 * What the transport saw:
 * - `response`: relaygate answered;
 * - `not_sent`: the person's read token could not be obtained, so nothing was sent;
 * - `lost`: the request was sent (or may have been) and no answer arrived
 *   (timeout or network error);
 * - `not_configured`: this install's read API is not relaygate.
 */
export type AccessReply =
  | { kind: "response"; status: number; body: unknown }
  | { kind: "not_sent" }
  | { kind: "lost" }
  | { kind: "not_configured" };

export type AccessTransport = (request: AccessRequest) => Promise<AccessReply>;

/** Bound to one acting person in one workspace. */
export type AccessDeps = {
  send: AccessTransport;
  /** Current members of the caller's organization. */
  members: () => Promise<AccessMember[]>;
};

export type Perm = "r" | "w" | "rw";

export type AccessGrant =
  | { userId: string; email: string; name: string | null; perm: Perm; member: true }
  | { userId: string; perm: Perm; member: false };

export type AccessPolicy = {
  sessionId: string;
  /** True when a runtime policy is in force; false when the defaults apply. */
  runtime: boolean;
  /** True when the last change was a reset to the defaults. */
  reset: boolean;
  version: number;
  mode: string;
  gid: number | null;
  groups: Array<{ gid: number; perm: Perm }>;
  members: AccessGrant[];
  label: string | null;
  updatedAt: string | null;
};

export type AccessHistoryRow = {
  seq: number;
  at: string;
  actorId: string | null;
  actorName: string | null;
  version: number;
  reason: string | null;
  before: AccessSnapshot | null;
  after: AccessSnapshot | null;
};

export type AccessSnapshot = {
  mode: string | null;
  gid: number | null;
  groups: Array<{ gid: number; perm: Perm }>;
  members: AccessGrant[];
  label: string | null;
  reset: boolean;
};

export type AccessFailure =
  | { outcome: "not_found"; message: string }
  | { outcome: "not_access_admin"; message: string }
  | { outcome: "conflict"; currentVersion: number | null; message: string }
  | { outcome: "unknown_members"; emails: string[]; message: string }
  | { outcome: "invalid_request"; message: string }
  | { outcome: "unavailable"; message: string }
  | { outcome: "outcome_unknown"; message: string }
  | { outcome: "not_configured"; message: string };

export type AccessResult<T> = { outcome: "ok"; value: T } | AccessFailure;

export const ACCESS_MESSAGES = {
  not_found: "Session not found, or you may not read it.",
  not_access_admin: "You are not a session access administrator.",
  conflict: "Session access changed since the version you gave. Read the access again and retry with the current version.",
  unknown_members: "Some emails are not current members of this organization; nothing was changed.",
  unavailable: "Session access is temporarily unavailable. Please try again.",
  outcome_unknown: "The change may or may not have been applied. Read the session access again before deciding; do not retry blindly.",
  not_configured: "Session access management is not available on this installation.",
} as const;

/** relaygate's limits (SessionAccessPatch). */
export const MAX_ACCESS_ENTRIES = 64;
export const MAX_REASON_LENGTH = 200;
export const DEFAULT_HISTORY_LIMIT = 50;
export const MAX_HISTORY_LIMIT = 200;

const SESSION_ID = /^[A-Za-z0-9._:@-]{1,256}$/;
const MODE = /^[0246]{3}$/;
const LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9 ._-]{0,22}[A-Za-z0-9._-])?$/;
const CONTROL = /[\u0000-\u001f\u007f]/u;
const PERMS: readonly string[] = ["r", "w", "rw"];
const MAX_EMAIL_LENGTH = 320;

export type AccessChange = {
  mode?: unknown;
  members?: unknown;
  groups?: unknown;
  /** Present (even as null) means "change the label". */
  label?: unknown;
  reason?: unknown;
  expectedVersion?: unknown;
};

export type ResetInput = { reason?: unknown; expectedVersion?: unknown };
export type HistoryInput = { after?: unknown; limit?: unknown };

function invalid(message: string): AccessFailure {
  return { outcome: "invalid_request", message };
}

function failure(outcome: Exclude<AccessFailure["outcome"], "conflict" | "unknown_members" | "invalid_request">): AccessFailure {
  return { outcome, message: ACCESS_MESSAGES[outcome] };
}

function sessionPath(sessionId: string, suffix = ""): string {
  return `/v1/sessions/${encodeURIComponent(sessionId)}/access${suffix}`;
}

function validSessionId(sessionId: unknown): sessionId is string {
  return typeof sessionId === "string" && SESSION_ID.test(sessionId);
}

function reasonOf(value: unknown): string | AccessFailure {
  if (typeof value !== "string") return invalid("reason is required");
  const reason = value.trim();
  if (reason.length < 1 || reason.length > MAX_REASON_LENGTH || CONTROL.test(reason)) {
    return invalid(`reason must be 1 to ${MAX_REASON_LENGTH} characters without control characters`);
  }
  return reason;
}

function versionOf(value: unknown): number | undefined | AccessFailure {
  if (value === undefined || value === null) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) < 0) return invalid("expected version must be a non-negative integer");
  return value as number;
}

function isFailure(value: unknown): value is AccessFailure {
  return isRecord(value) && typeof value.outcome === "string";
}

type ValidChange = {
  mode?: string;
  members?: Array<{ email: string; perm: Perm }>;
  groups?: Array<{ gid: number; perm: Perm }>;
  label?: string | null;
  labelGiven: boolean;
  reason: string;
  expectedVersion?: number;
};

function validateChange(change: AccessChange): ValidChange | AccessFailure {
  if (!isRecord(change)) return invalid("Invalid session access change");
  const result: ValidChange = { labelGiven: false, reason: "" };
  if (change.mode !== undefined) {
    if (typeof change.mode !== "string" || !MODE.test(change.mode)) {
      return invalid("mode must be three digits, each 0, 2, 4 or 6");
    }
    result.mode = change.mode;
  }
  if (change.members !== undefined) {
    if (!Array.isArray(change.members) || change.members.length > MAX_ACCESS_ENTRIES) {
      return invalid(`members must be a list of at most ${MAX_ACCESS_ENTRIES} entries`);
    }
    const seen = new Set<string>();
    const members: Array<{ email: string; perm: Perm }> = [];
    for (const entry of change.members) {
      if (!isRecord(entry) || typeof entry.email !== "string" || typeof entry.perm !== "string") {
        return invalid("each member needs an email and a perm");
      }
      const email = entry.email.trim();
      if (!email || email.length > MAX_EMAIL_LENGTH || CONTROL.test(email)) return invalid("Invalid member email");
      if (!PERMS.includes(entry.perm)) return invalid("perm must be r, w or rw");
      const key = email.toLowerCase();
      if (seen.has(key)) return invalid("Each member email may appear only once");
      seen.add(key);
      members.push({ email, perm: entry.perm as Perm });
    }
    result.members = members;
  }
  if (change.groups !== undefined) {
    if (!Array.isArray(change.groups) || change.groups.length > MAX_ACCESS_ENTRIES) {
      return invalid(`groups must be a list of at most ${MAX_ACCESS_ENTRIES} entries`);
    }
    const groups: Array<{ gid: number; perm: Perm }> = [];
    for (const entry of change.groups) {
      if (!isRecord(entry) || !Number.isSafeInteger(entry.gid) || (entry.gid as number) < 0 ||
          typeof entry.perm !== "string" || !PERMS.includes(entry.perm)) {
        return invalid("each group needs a non-negative integer gid and a perm of r, w or rw");
      }
      groups.push({ gid: entry.gid as number, perm: entry.perm as Perm });
    }
    result.groups = groups;
  }
  if ("label" in change && change.label !== undefined) {
    if (change.label !== null && (typeof change.label !== "string" || !LABEL.test(change.label))) {
      return invalid("label must be null or 1 to 24 letters, digits, spaces, dots, underscores or hyphens");
    }
    result.label = change.label as string | null;
    result.labelGiven = true;
  }
  if (result.mode === undefined && result.members === undefined && result.groups === undefined && !result.labelGiven) {
    return invalid("Give at least one of mode, members, groups or label");
  }
  const reason = reasonOf(change.reason);
  if (typeof reason !== "string") return reason;
  result.reason = reason;
  const version = versionOf(change.expectedVersion);
  if (isFailure(version)) return version;
  if (version !== undefined) result.expectedVersion = version;
  return result;
}

async function loadMembers(deps: AccessDeps): Promise<AccessMember[] | null> {
  try {
    return await deps.members();
  } catch {
    return null;
  }
}

/** An email names a member only when exactly one current member has it (case-insensitive). */
function resolveEmails(
  members: AccessMember[],
  requested: Array<{ email: string; perm: Perm }>,
): { users: Array<{ userId: string; perm: Perm }> } | { unknown: string[] } {
  const byEmail = new Map<string, AccessMember[]>();
  for (const member of members) {
    const key = member.email.trim().toLowerCase();
    byEmail.set(key, [...(byEmail.get(key) ?? []), member]);
  }
  const users: Array<{ userId: string; perm: Perm }> = [];
  const unknown: string[] = [];
  for (const entry of requested) {
    const matches = byEmail.get(entry.email.toLowerCase()) ?? [];
    if (matches.length !== 1) unknown.push(entry.email);
    else users.push({ userId: matches[0]!.userId, perm: entry.perm });
  }
  return unknown.length ? { unknown } : { users };
}

function permOf(value: unknown): Perm | null {
  return typeof value === "string" && PERMS.includes(value) ? value as Perm : null;
}

function groupsOf(value: unknown): Array<{ gid: number; perm: Perm }> | null {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) return null;
  const result: Array<{ gid: number; perm: Perm }> = [];
  for (const entry of value) {
    if (!isRecord(entry) || !Number.isSafeInteger(entry.gid)) return null;
    const perm = permOf(entry.perm);
    if (!perm) return null;
    result.push({ gid: entry.gid as number, perm });
  }
  return result;
}

function grantsOf(value: unknown, members: Map<string, AccessMember>): AccessGrant[] | null {
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) return null;
  const result: AccessGrant[] = [];
  for (const entry of value) {
    if (!isRecord(entry) || typeof entry.userId !== "string" || !entry.userId) return null;
    const perm = permOf(entry.perm);
    if (!perm) return null;
    const member = members.get(entry.userId);
    result.push(member
      ? { userId: entry.userId, email: member.email, name: member.name, perm, member: true }
      : { userId: entry.userId, perm, member: false });
  }
  return result;
}

function gidOf(value: unknown): number | null | undefined {
  if (value === undefined || value === null) return null;
  return Number.isSafeInteger(value) ? value as number : undefined;
}

function labelOf(value: unknown): string | null | undefined {
  if (value === undefined || value === null) return null;
  return typeof value === "string" ? value : undefined;
}

/**
 * relaygate's GET/PATCH/reset answer: `{runtime, reset?, access: {sessionId,
 * gid, mode, acl, users, label, reset?, version, updatedAt?}}`.
 */
function policyOf(body: unknown, sessionId: string, members: Map<string, AccessMember>): AccessPolicy | null {
  if (!isRecord(body) || !isRecord(body.access) || typeof body.runtime !== "boolean") return null;
  const access = body.access;
  if (typeof access.sessionId !== "string" || access.sessionId !== sessionId) return null;
  if (!Number.isSafeInteger(access.version) || (access.version as number) < 0) return null;
  if (typeof access.mode !== "string") return null;
  const gid = gidOf(access.gid);
  const label = labelOf(access.label);
  const groups = groupsOf(access.acl);
  const grants = grantsOf(access.users, members);
  if (gid === undefined || label === undefined || !groups || !grants) return null;
  return {
    sessionId,
    runtime: body.runtime,
    reset: body.reset === true || access.reset === true,
    version: access.version as number,
    mode: access.mode,
    gid,
    groups,
    members: grants,
    label,
    updatedAt: typeof access.updatedAt === "string" ? access.updatedAt : null,
  };
}

function snapshotOf(value: unknown, members: Map<string, AccessMember>): AccessSnapshot | null | undefined {
  if (value === null || value === undefined) return null;
  if (!isRecord(value)) return undefined;
  const gid = gidOf(value.gid);
  const label = labelOf(value.label);
  const groups = groupsOf(value.acl);
  const grants = grantsOf(value.users, members);
  if (gid === undefined || label === undefined || !groups || !grants) return undefined;
  return {
    mode: typeof value.mode === "string" ? value.mode : null,
    gid,
    groups,
    members: grants,
    label,
    reset: value.reset === true,
  };
}

/** `{rows: [{seq, at, session_id, actor_id, actor_name, version, before, after, reason}]}`. */
function historyOf(body: unknown, sessionId: string, members: Map<string, AccessMember>): AccessHistoryRow[] | null {
  if (!isRecord(body) || !Array.isArray(body.rows)) return null;
  const rows: AccessHistoryRow[] = [];
  for (const row of body.rows) {
    if (!isRecord(row) || !Number.isSafeInteger(row.seq) || typeof row.at !== "string" ||
        !Number.isSafeInteger(row.version)) return null;
    if (row.session_id !== undefined && row.session_id !== sessionId) return null;
    const before = snapshotOf(row.before, members);
    const after = snapshotOf(row.after, members);
    if (before === undefined || after === undefined) return null;
    rows.push({
      seq: row.seq as number,
      at: row.at,
      actorId: typeof row.actor_id === "string" ? row.actor_id : null,
      actorName: typeof row.actor_name === "string" ? row.actor_name : null,
      version: row.version as number,
      reason: typeof row.reason === "string" ? row.reason : null,
      before,
      after,
    });
  }
  return rows;
}

function currentVersionOf(body: unknown): number | null {
  if (!isRecord(body)) return null;
  const direct = body.currentVersion;
  if (Number.isSafeInteger(direct) && (direct as number) >= 0) return direct as number;
  // relaygate errors are `{error: {code, message, ...}}`; accept the field there too.
  if (isRecord(body.error) && Number.isSafeInteger(body.error.currentVersion) && (body.error.currentVersion as number) >= 0) {
    return body.error.currentVersion as number;
  }
  return null;
}

/**
 * Status mapping shared by every operation. `write` decides what a lost
 * request means: on a read it is `unavailable`; on PATCH or reset the change
 * may have applied, so `outcome_unknown`.
 */
function mapFailure(reply: AccessReply, write: boolean): AccessFailure | null {
  if (reply.kind === "not_configured") return failure("not_configured");
  if (reply.kind === "not_sent") return failure("unavailable");
  if (reply.kind === "lost") return failure(write ? "outcome_unknown" : "unavailable");
  const { status, body } = reply;
  if (status >= 200 && status < 300) return null;
  if (status === 404) return failure("not_found");
  if (status === 403) return failure("not_access_admin");
  if (status === 409) {
    return { outcome: "conflict", currentVersion: currentVersionOf(body), message: ACCESS_MESSAGES.conflict };
  }
  if (status === 400) return invalid("relaygate refused the change as invalid");
  // 401 (the read token was refused), 5xx and anything else. A retried write
  // still carries its expectedVersion, so a change that did apply conflicts
  // instead of applying twice.
  return failure("unavailable");
}

async function readPolicy(
  deps: AccessDeps,
  sessionId: string,
  members: Map<string, AccessMember>,
): Promise<AccessResult<AccessPolicy>> {
  let reply: AccessReply;
  try {
    reply = await deps.send({ method: "GET", path: sessionPath(sessionId) });
  } catch {
    return failure("unavailable");
  }
  const failed = mapFailure(reply, false);
  if (failed) return failed;
  const policy = policyOf((reply as { body: unknown }).body, sessionId, members);
  return policy ? { outcome: "ok", value: policy } : failure("unavailable");
}

async function writePolicy(
  deps: AccessDeps,
  sessionId: string,
  request: AccessRequest,
  members: Map<string, AccessMember>,
): Promise<AccessResult<AccessPolicy>> {
  let reply: AccessReply;
  try {
    reply = await deps.send(request);
  } catch {
    // The transport's own errors are mapped to `lost`; anything else may have
    // happened after the request left.
    return failure("outcome_unknown");
  }
  const failed = mapFailure(reply, true);
  if (failed) return failed;
  const policy = policyOf((reply as { body: unknown }).body, sessionId, members);
  // A 2xx we cannot read: the change was accepted, but what it is now is not
  // known here. The caller reads the access again.
  return policy ? { outcome: "ok", value: policy } : failure("outcome_unknown");
}

function memberIndex(members: AccessMember[]): Map<string, AccessMember> {
  return new Map(members.map((member) => [member.userId, member]));
}

/** The effective policy of one session and its version. */
export async function getAccess(deps: AccessDeps, sessionId: unknown): Promise<AccessResult<AccessPolicy>> {
  if (!validSessionId(sessionId)) return invalid("Invalid session id");
  const members = await loadMembers(deps);
  if (!members) return failure("unavailable");
  return readPolicy(deps, sessionId, memberIndex(members));
}

/**
 * Change the policy. `members` and `groups`, when given, replace the current
 * per-person and group lists (relaygate's PATCH replaces `users` and `acl`).
 * Without `expectedVersion` the current version is read first; a stale
 * version is a `conflict` and is never retried.
 */
export async function setAccess(deps: AccessDeps, sessionId: unknown, change: AccessChange): Promise<AccessResult<AccessPolicy>> {
  if (!validSessionId(sessionId)) return invalid("Invalid session id");
  const valid = validateChange(change);
  if (isFailure(valid)) return valid;
  const members = await loadMembers(deps);
  if (!members) return failure("unavailable");
  let users: Array<{ userId: string; perm: Perm }> | undefined;
  if (valid.members) {
    const resolved = resolveEmails(members, valid.members);
    if ("unknown" in resolved) {
      return { outcome: "unknown_members", emails: resolved.unknown, message: ACCESS_MESSAGES.unknown_members };
    }
    users = resolved.users;
  }
  const index = memberIndex(members);
  let expectedVersion = valid.expectedVersion;
  if (expectedVersion === undefined) {
    const current = await readPolicy(deps, sessionId, index);
    if (current.outcome !== "ok") return current;
    expectedVersion = current.value.version;
  }
  // Only opaque user ids go upstream: never an email or a name.
  const body: Record<string, unknown> = {
    ...(valid.mode !== undefined ? { mode: valid.mode } : {}),
    ...(valid.groups !== undefined ? { acl: valid.groups } : {}),
    ...(users !== undefined ? { users } : {}),
    ...(valid.labelGiven ? { label: valid.label ?? null } : {}),
    expectedVersion,
    reason: valid.reason,
  };
  return writePolicy(deps, sessionId, { method: "PATCH", path: sessionPath(sessionId), body }, index);
}

/** Remove the runtime override: authorization follows the policy defaults again. */
export async function resetAccess(deps: AccessDeps, sessionId: unknown, input: ResetInput): Promise<AccessResult<AccessPolicy>> {
  if (!validSessionId(sessionId)) return invalid("Invalid session id");
  if (!isRecord(input)) return invalid("Invalid session access reset");
  const reason = reasonOf(input.reason);
  if (typeof reason !== "string") return reason;
  const given = versionOf(input.expectedVersion);
  if (isFailure(given)) return given;
  const members = await loadMembers(deps);
  if (!members) return failure("unavailable");
  const index = memberIndex(members);
  let expectedVersion = given;
  if (expectedVersion === undefined) {
    const current = await readPolicy(deps, sessionId, index);
    if (current.outcome !== "ok") return current;
    expectedVersion = current.value.version;
  }
  return writePolicy(deps, sessionId, {
    method: "POST", path: sessionPath(sessionId, "/reset"), body: { expectedVersion, reason },
  }, index);
}

/** The immutable before/after rows of every change, oldest first, from `after` (a seq). */
export async function accessHistory(
  deps: AccessDeps,
  sessionId: unknown,
  input: HistoryInput = {},
): Promise<AccessResult<{ rows: AccessHistoryRow[]; nextAfter: number | null }>> {
  if (!validSessionId(sessionId)) return invalid("Invalid session id");
  const after = input.after ?? 0;
  if (!Number.isSafeInteger(after) || (after as number) < 0) return invalid("after must be a non-negative integer");
  const limit = input.limit ?? DEFAULT_HISTORY_LIMIT;
  if (!Number.isSafeInteger(limit) || (limit as number) < 1 || (limit as number) > MAX_HISTORY_LIMIT) {
    return invalid(`limit must be an integer from 1 to ${MAX_HISTORY_LIMIT}`);
  }
  const members = await loadMembers(deps);
  if (!members) return failure("unavailable");
  let reply: AccessReply;
  try {
    reply = await deps.send({
      method: "GET",
      path: sessionPath(sessionId, "/history"),
      query: new URLSearchParams({ after: String(after), limit: String(limit) }),
    });
  } catch {
    return failure("unavailable");
  }
  const failed = mapFailure(reply, false);
  if (failed) return failed;
  const rows = historyOf((reply as { body: unknown }).body, sessionId, memberIndex(members));
  if (!rows || rows.length > (limit as number)) return failure("unavailable");
  const last = rows[rows.length - 1];
  return { outcome: "ok", value: { rows, nextAfter: rows.length === limit && last ? last.seq : null } };
}
