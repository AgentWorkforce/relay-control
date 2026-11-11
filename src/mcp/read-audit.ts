import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { randomUUID } from "node:crypto";
import type { SqlExecutor } from "../database.js";
import type { McpContext } from "./context.js";

/**
 * Shared-session read audit (docs/shared-session-read-audit.md): one
 * append-only row per shared-session read tool call, successful or not, in
 * `shared_session_read_audit`. It records who asked, from which calling chat,
 * what they asked for, and which sessions (and their recorded owners) came
 * back. It never stores transcript content: only ids, the caller's own query
 * text (bounded), counts and the public error message.
 */

export const AUDITED_READ_TOOLS = [
  "open_shared_sessions",
  "search_shared_sessions",
  "get_shared_session",
  "get_shared_session_context",
  "list_session_timings",
] as const;

export const MAX_AUDIT_QUERY_LENGTH = 500;
export const MAX_AUDIT_SESSIONS = 50;
export const MAX_AUDIT_OWNERS_PER_SESSION = 10;
const MAX_ID_LENGTH = 512;
const MAX_ERROR_LENGTH = 500;
const MAX_FILTER_LENGTH = 512;

/** How the caller reached the MCP endpoint. */
export type ReadAuditIdentityKind = "desktop" | "hosted" | "oauth";

export type ReadAuditSession = { session_id: string; source: string | null; owner_user_ids: string[] };

export type ReadAuditRecord = {
  id: string;
  /** Null: the database clock (microsecond precision) stamps the row. */
  occurredAt: Date | null;
  organizationId: string;
  workspaceId: string;
  callerUserId: string;
  identityKind: ReadAuditIdentityKind;
  authMode: string;
  desktopProvider: string | null;
  oauthClientId: string | null;
  oauthGrantId: string | null;
  mcpSessionId: string | null;
  nativeSessionId: string | null;
  nativeSessionProvider: string | null;
  nativeSessionVerified: boolean;
  toolName: string;
  outcome: "ok" | "error";
  errorMessage: string | null;
  queryText: string | null;
  agentFilter: string | null;
  requestedSessionId: string | null;
  requestedSource: string | null;
  filters: Record<string, string | boolean>;
  resultCount: number;
  resultSessions: ReadAuditSession[];
  resultSessionsTruncated: boolean;
  correlationId: string | null;
  durationMs: number;
};

type ToolResult = {
  isError?: boolean;
  structuredContent?: Record<string, unknown>;
  content?: Array<{ type: string; text?: string }>;
};

function bounded(value: unknown, max: number): string | null {
  if (typeof value !== "string") return null;
  return value.length > max ? value.slice(0, max) : value;
}

function identityOf(context: McpContext) {
  const identityKind: ReadAuditIdentityKind = context.oauth
    ? "oauth"
    : context.desktopCall.required ? "desktop" : "hosted";
  const native = context.desktopCall.nativeSession;
  return {
    identityKind,
    authMode: context.authMode,
    desktopProvider: context.desktopCall.provider ?? null,
    oauthClientId: context.oauth?.access.clientId ?? null,
    oauthGrantId: context.oauth?.access.grantId ?? null,
    mcpSessionId: context.relay.sessionId ?? null,
    nativeSessionId: native?.id ?? null,
    nativeSessionProvider: native?.kind ?? null,
    // Only a signed Claude or Copilot hook proof names the desktop source;
    // other native ids are injected by the client and not cryptographically verified.
    nativeSessionVerified: Boolean(native && context.desktopCall.nativeSourceId),
  };
}

/** Request filters worth keeping for the ledger: never content, never the cursor value. */
function filtersOf(input: Record<string, unknown>): Record<string, string | boolean> {
  const filters: Record<string, string | boolean> = {};
  for (const key of ["source", "project", "since", "until", "user_id", "focus_timestamp", "order"]) {
    const value = bounded(input[key], MAX_FILTER_LENGTH);
    if (value !== null) filters[key] = value;
  }
  if (typeof input.cursor === "string") filters.cursor = true;
  return filters;
}

/**
 * Owners a tool knows but does not return (an agent search's recorded
 * `userIds`), keyed by the result object so the tool's output contract is
 * unchanged.
 */
const knownOwners = new WeakMap<object, Map<string, string[]>>();

export function noteResultOwners(result: object, owners: Array<{ sessionId: string; source: string | null; userIds: string[] }>): void {
  knownOwners.set(result, new Map(owners.map((owner) => [JSON.stringify([owner.sessionId, owner.source]), owner.userIds])));
}

/** The sessions a result cites, with the owners recorded on their events or member list. */
export function resultSessionsOf(toolName: string, structured: Record<string, unknown> | undefined,
  owners?: Map<string, string[]>): {
  count: number; sessions: ReadAuditSession[]; truncated: boolean;
} {
  if (!structured) return { count: 0, sessions: [], truncated: false };
  const bySession = new Map<string, { session_id: string; source: string | null; owners: Set<string> }>();
  const add = (sessionId: unknown, source: unknown, owners: unknown[]) => {
    if (typeof sessionId !== "string" || !sessionId) return;
    const src = typeof source === "string" ? source : null;
    const key = JSON.stringify([sessionId, src]);
    let entry = bySession.get(key);
    if (!entry) {
      entry = { session_id: sessionId.slice(0, MAX_ID_LENGTH), source: src, owners: new Set() };
      bySession.set(key, entry);
    }
    for (const owner of owners) if (typeof owner === "string" && owner) entry.owners.add(owner.slice(0, MAX_ID_LENGTH));
  };
  const list = (value: unknown): Array<Record<string, unknown>> =>
    Array.isArray(value) ? value.filter((item): item is Record<string, unknown> => item !== null && typeof item === "object") : [];

  let count = 0;
  if (toolName === "search_shared_sessions") {
    const matches = list(structured.matches);
    const sessions = list(structured.sessions);
    count = matches.length + sessions.length;
    for (const match of matches) add(match.session_id, match.source, [match.user_id]);
    for (const session of sessions) {
      const source = typeof session.source === "string" ? session.source : null;
      add(session.session_id, session.source, owners?.get(JSON.stringify([session.session_id, source])) ?? []);
    }
  } else if (toolName === "get_shared_session" || toolName === "get_shared_session_context") {
    const events = list(structured.events);
    count = events.length;
    // Each event names its own source: a read without `source` can span several.
    for (const event of events) add(event.session_id, event.source, [event.user_id]);
    if (events.length === 0) add(structured.session_id, structured.source, []);
  } else if (toolName === "list_session_timings") {
    const sessions = list(structured.sessions);
    count = sessions.length;
    for (const session of sessions) {
      add(session.session_id, session.source, list(session.members).map((member) => member.user_id));
    }
  }
  const all = [...bySession.values()];
  return {
    count,
    truncated: all.length > MAX_AUDIT_SESSIONS || all.some((entry) => entry.owners.size > MAX_AUDIT_OWNERS_PER_SESSION),
    sessions: all.slice(0, MAX_AUDIT_SESSIONS).map((entry) => ({
      session_id: entry.session_id,
      source: entry.source,
      owner_user_ids: [...entry.owners].sort().slice(0, MAX_AUDIT_OWNERS_PER_SESSION),
    })),
  };
}

function errorMessageOf(result: ToolResult | undefined): { message: string | null; correlationId: string | null } {
  const text = result?.content?.find((item) => item.type === "text")?.text ?? "";
  const found = /\ncorrelation_id: (\S+)$/.exec(text);
  const message = found ? text.slice(0, found.index) : text;
  return { message: bounded(message, MAX_ERROR_LENGTH) || null, correlationId: found?.[1] ?? null };
}

export function buildReadAuditRecord(input: {
  context: McpContext;
  toolName: string;
  args: Record<string, unknown>;
  result: ToolResult | undefined;
  startedAt: number;
  now: Date | null;
}): ReadAuditRecord {
  const { context, toolName, args, result } = input;
  const failed = !result || result.isError === true;
  const error = failed ? errorMessageOf(result) : { message: null, correlationId: null };
  const sessions = failed
    ? { count: 0, sessions: [], truncated: false }
    : resultSessionsOf(toolName, result.structuredContent, knownOwners.get(result));
  const structuredCorrelation = result?.structuredContent?.correlation_id;
  return {
    id: randomUUID(),
    occurredAt: input.now,
    organizationId: context.workspace.organizationId,
    workspaceId: context.workspace.id,
    callerUserId: context.principal.userId,
    ...identityOf(context),
    toolName,
    outcome: failed ? "error" : "ok",
    errorMessage: failed ? (error.message ?? "Tool call failed.") : null,
    queryText: bounded(args.query, MAX_AUDIT_QUERY_LENGTH),
    agentFilter: bounded(args.agent, MAX_FILTER_LENGTH),
    requestedSessionId: bounded(args.session_id, MAX_ID_LENGTH),
    requestedSource: bounded(args.source, MAX_FILTER_LENGTH),
    filters: filtersOf(args),
    resultCount: sessions.count,
    resultSessions: sessions.sessions,
    resultSessionsTruncated: sessions.truncated,
    correlationId: typeof structuredCorrelation === "string"
      ? structuredCorrelation.slice(0, 256)
      : error.correlationId,
    durationMs: Math.max(0, Math.round(Date.now() - input.startedAt)),
  };
}

export async function insertReadAudit(executor: SqlExecutor, record: ReadAuditRecord): Promise<void> {
  await executor.query(
    `INSERT INTO shared_session_read_audit
       (id, occurred_at, organization_id, workspace_id, caller_user_id, identity_kind, auth_mode,
        desktop_provider, oauth_client_id, oauth_grant_id, mcp_session_id,
        native_session_id, native_session_provider, native_session_verified,
        tool_name, outcome, error_message, query_text, agent_filter, requested_session_id, requested_source,
        filters, result_count, result_sessions, result_sessions_truncated, correlation_id, duration_ms)
     VALUES ($1, COALESCE($2::timestamptz, clock_timestamp()), $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21,
       $22::jsonb, $23, $24::jsonb, $25, $26, $27)`,
    [
      record.id, record.occurredAt?.toISOString() ?? null, record.organizationId, record.workspaceId, record.callerUserId,
      record.identityKind, record.authMode, record.desktopProvider, record.oauthClientId, record.oauthGrantId,
      record.mcpSessionId, record.nativeSessionId, record.nativeSessionProvider, record.nativeSessionVerified,
      record.toolName, record.outcome, record.errorMessage, record.queryText, record.agentFilter,
      record.requestedSessionId, record.requestedSource, JSON.stringify(record.filters), record.resultCount,
      JSON.stringify(record.resultSessions), record.resultSessionsTruncated, record.correlationId, record.durationMs,
    ],
  );
}

type Handler = (args: unknown, extra: unknown) => Promise<ToolResult>;

const INVALID_ARGUMENTS_MESSAGE = "Input validation error.";

function requestIdOf(extra: unknown): string | null {
  const id = (extra as { requestId?: unknown } | null)?.requestId;
  return typeof id === "string" || typeof id === "number" ? JSON.stringify(id) : null;
}

/**
 * Returns a view of `server` whose `registerTool` audits every call of the
 * shared-session read tools. One insert per call, awaited so the record is
 * durable before the answer; an audit failure is logged and never fails the read.
 */
export function withReadAudit(server: McpServer, context: McpContext): McpServer {
  const audit = context.readAudit;
  if (!audit) return server;
  const audited = new Set<string>(AUDITED_READ_TOOLS);
  const register = server.registerTool.bind(server) as (name: string, config: unknown, handler: Handler) => unknown;
  const registerTool = (name: string, config: unknown, handler: Handler) => {
    if (!audited.has(name)) return register(name, config, handler);
    return register(name, config, async (args, extra) => {
      const startedAt = Date.now();
      const requestId = requestIdOf(extra);
      if (requestId !== null) audit.handled?.add(requestId);
      let result: ToolResult | undefined;
      try {
        result = await handler(args, extra);
        return result;
      } finally {
        try {
          await insertReadAudit(audit.database, buildReadAuditRecord({
            context,
            toolName: name,
            args: args !== null && typeof args === "object" ? args as Record<string, unknown> : {},
            result,
            startedAt,
            now: audit.now?.() ?? null,
          }));
        } catch (error) {
          console.error("[selfhost-mcp] Shared-session read audit write failed", {
            tool: name,
            error: error instanceof Error ? error.message : "unknown",
          });
        }
      }
    });
  };
  return new Proxy(server, {
    get(target, property, receiver) {
      if (property === "registerTool") return registerTool;
      return Reflect.get(target, property, receiver);
    },
  });
}

/**
 * The SDK refuses arguments that fail a tool's input schema before the
 * wrapped handler runs. After the transport answers, this writes one error
 * record for each audited `tools/call` in `body` that no handler recorded.
 * The validation detail is not stored, only a fixed message.
 */
export async function auditUnhandledReadCalls(context: McpContext, body: unknown, startedAt: number): Promise<void> {
  const audit = context.readAudit;
  if (!audit) return;
  const audited = new Set<string>(AUDITED_READ_TOOLS);
  for (const message of Array.isArray(body) ? body : [body]) {
    const call = message as { method?: unknown; id?: unknown; params?: { name?: unknown; arguments?: unknown } } | null;
    if (call?.method !== "tools/call" || typeof call.params?.name !== "string" || !audited.has(call.params.name)) continue;
    const id = typeof call.id === "string" || typeof call.id === "number" ? JSON.stringify(call.id) : null;
    if (id === null || audit.handled?.has(id)) continue;
    const args = call.params.arguments;
    try {
      await insertReadAudit(audit.database, buildReadAuditRecord({
        context,
        toolName: call.params.name,
        args: args !== null && typeof args === "object" && !Array.isArray(args) ? args as Record<string, unknown> : {},
        result: { isError: true, content: [{ type: "text", text: INVALID_ARGUMENTS_MESSAGE }] },
        startedAt,
        now: audit.now?.() ?? null,
      }));
    } catch (error) {
      console.error("[selfhost-mcp] Shared-session read audit write failed", {
        tool: call.params.name,
        error: error instanceof Error ? error.message : "unknown",
      });
    }
  }
}

// ---- Export ---------------------------------------------------------------

export const DEFAULT_EXPORT_LIMIT = 100;
export const MAX_EXPORT_LIMIT = 1_000;

export class ReadAuditQueryError extends Error {}

export type ReadAuditExportQuery = {
  since: Date | null;
  until: Date | null;
  limit: number;
  cursor: { occurredAt: string; id: string } | null;
  format: "json" | "csv";
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function encodeCursor(occurredAt: string, id: string): string {
  return Buffer.from(JSON.stringify([occurredAt, id])).toString("base64url");
}

function decodeCursor(value: string): { occurredAt: string; id: string } {
  try {
    const parsed = JSON.parse(Buffer.from(value, "base64url").toString("utf8")) as unknown;
    if (Array.isArray(parsed) && parsed.length === 2 && typeof parsed[0] === "string" &&
        Number.isFinite(Date.parse(parsed[0])) && typeof parsed[1] === "string" && UUID.test(parsed[1])) {
      return { occurredAt: parsed[0], id: parsed[1] };
    }
  } catch { /* fall through */ }
  throw new ReadAuditQueryError("cursor is not valid");
}

/** Parses `since`, `until`, `limit`, `cursor` and `format`; anything else is refused. */
export function parseReadAuditQuery(url: URL): ReadAuditExportQuery {
  const allowed = new Set(["since", "until", "limit", "cursor", "format"]);
  for (const key of url.searchParams.keys()) {
    if (!allowed.has(key)) throw new ReadAuditQueryError(`Unknown query parameter: ${key}`);
    if (url.searchParams.getAll(key).length > 1) throw new ReadAuditQueryError(`${key} may be given once`);
  }
  const date = (key: string): Date | null => {
    const value = url.searchParams.get(key);
    if (value === null) return null;
    const parsed = Date.parse(value);
    if (!Number.isFinite(parsed)) throw new ReadAuditQueryError(`${key} must be an ISO-8601 date-time`);
    return new Date(parsed);
  };
  const since = date("since");
  const until = date("until");
  if (since && until && since > until) throw new ReadAuditQueryError("since must not be after until");
  const rawLimit = url.searchParams.get("limit");
  const limit = rawLimit === null ? DEFAULT_EXPORT_LIMIT : Number(rawLimit);
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_EXPORT_LIMIT) {
    throw new ReadAuditQueryError(`limit must be an integer from 1 to ${MAX_EXPORT_LIMIT}`);
  }
  const format = url.searchParams.get("format") ?? "json";
  if (format !== "json" && format !== "csv") throw new ReadAuditQueryError("format must be json or csv");
  const cursor = url.searchParams.get("cursor");
  return { since, until, limit, cursor: cursor === null ? null : decodeCursor(cursor), format };
}

export type ReadAuditExportRow = {
  id: string;
  occurred_at: string;
  organization_id: string;
  workspace_id: string;
  caller_user_id: string;
  identity_kind: ReadAuditIdentityKind;
  auth_mode: string;
  desktop_provider: string | null;
  oauth_client_id: string | null;
  oauth_grant_id: string | null;
  mcp_session_id: string | null;
  native_session_id: string | null;
  native_session_provider: string | null;
  native_session_verified: boolean;
  tool_name: string;
  outcome: "ok" | "error";
  error_message: string | null;
  query_text: string | null;
  agent_filter: string | null;
  requested_session_id: string | null;
  requested_source: string | null;
  filters: Record<string, string | boolean>;
  result_count: number;
  result_sessions: ReadAuditSession[];
  result_sessions_truncated: boolean;
  correlation_id: string | null;
  duration_ms: number;
};

export const EXPORT_COLUMNS: ReadonlyArray<keyof ReadAuditExportRow> = [
  "id", "occurred_at", "organization_id", "workspace_id", "caller_user_id", "identity_kind", "auth_mode",
  "desktop_provider", "oauth_client_id", "oauth_grant_id", "mcp_session_id",
  "native_session_id", "native_session_provider", "native_session_verified",
  "tool_name", "outcome", "error_message", "query_text", "agent_filter", "requested_session_id", "requested_source",
  "filters", "result_count", "result_sessions", "result_sessions_truncated", "correlation_id", "duration_ms",
];

function parseJson<T>(value: unknown, fallback: T): T {
  if (typeof value === "string") {
    try { return JSON.parse(value) as T; } catch { return fallback; }
  }
  return (value ?? fallback) as T;
}

/** One page of a workspace's records, oldest first, keyed on (occurred_at, id). */
export async function listReadAudit(executor: SqlExecutor, workspaceId: string, query: ReadAuditExportQuery): Promise<{
  records: ReadAuditExportRow[]; nextCursor: string | null;
}> {
  const params: unknown[] = [workspaceId];
  const where = ["workspace_id = $1"];
  if (query.since) { params.push(query.since.toISOString()); where.push(`occurred_at >= $${params.length}::timestamptz`); }
  if (query.until) { params.push(query.until.toISOString()); where.push(`occurred_at < $${params.length}::timestamptz`); }
  if (query.cursor) {
    params.push(query.cursor.occurredAt, query.cursor.id);
    where.push(`(occurred_at, id) > ($${params.length - 1}::timestamptz, $${params.length}::uuid)`);
  }
  params.push(query.limit + 1);
  const result = await executor.query<Record<string, unknown>>(
    `SELECT id, to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS occurred_at,
            organization_id, workspace_id, caller_user_id, identity_kind, auth_mode,
            desktop_provider, oauth_client_id, oauth_grant_id, mcp_session_id,
            native_session_id, native_session_provider, native_session_verified,
            tool_name, outcome, error_message, query_text, agent_filter, requested_session_id, requested_source,
            filters, result_count, result_sessions, result_sessions_truncated, correlation_id, duration_ms
       FROM shared_session_read_audit audit
      WHERE ${where.join(" AND ")}
      ORDER BY audit.occurred_at, audit.id
      LIMIT $${params.length}`,
    params,
  );
  const rows = result.rows.slice(0, query.limit).map((row): ReadAuditExportRow => ({
    id: String(row.id),
    occurred_at: String(row.occurred_at),
    organization_id: String(row.organization_id),
    workspace_id: String(row.workspace_id),
    caller_user_id: String(row.caller_user_id),
    identity_kind: row.identity_kind as ReadAuditIdentityKind,
    auth_mode: String(row.auth_mode),
    desktop_provider: (row.desktop_provider as string | null) ?? null,
    oauth_client_id: (row.oauth_client_id as string | null) ?? null,
    oauth_grant_id: (row.oauth_grant_id as string | null) ?? null,
    mcp_session_id: (row.mcp_session_id as string | null) ?? null,
    native_session_id: (row.native_session_id as string | null) ?? null,
    native_session_provider: (row.native_session_provider as string | null) ?? null,
    native_session_verified: row.native_session_verified === true,
    tool_name: String(row.tool_name),
    outcome: row.outcome as "ok" | "error",
    error_message: (row.error_message as string | null) ?? null,
    query_text: (row.query_text as string | null) ?? null,
    agent_filter: (row.agent_filter as string | null) ?? null,
    requested_session_id: (row.requested_session_id as string | null) ?? null,
    requested_source: (row.requested_source as string | null) ?? null,
    filters: parseJson(row.filters, {}),
    result_count: Number(row.result_count),
    result_sessions: parseJson(row.result_sessions, []),
    result_sessions_truncated: row.result_sessions_truncated === true,
    correlation_id: (row.correlation_id as string | null) ?? null,
    duration_ms: Number(row.duration_ms),
  }));
  const last = rows.at(-1);
  // The cursor keeps microseconds so a page boundary never skips or repeats a row.
  const nextCursor = result.rows.length > query.limit && last ? encodeCursor(last.occurred_at, last.id) : null;
  return { records: rows, nextCursor };
}

function csvCell(value: unknown): string {
  if (value === null || value === undefined) return "";
  let text = typeof value === "object" ? JSON.stringify(value) : String(value);
  // Spreadsheet formula injection: query text is caller input.
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

export function readAuditCsv(rows: ReadAuditExportRow[]): string {
  const lines = [EXPORT_COLUMNS.join(",")];
  for (const row of rows) lines.push(EXPORT_COLUMNS.map((column) => csvCell(row[column])).join(","));
  return `${lines.join("\r\n")}\r\n`;
}
