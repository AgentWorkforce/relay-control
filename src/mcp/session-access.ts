import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  accessHistory,
  getAccess,
  resetAccess,
  setAccess,
  type AccessDeps,
  type AccessGrant,
  type AccessHistoryRow,
  type AccessPolicy,
  type AccessResult,
  type AccessSnapshot,
} from "../sessions/access.js";

/**
 * Session access management tools (group `session_access`). Registered only
 * for a person's own exchanged session on an installation whose read API is
 * relaygate (see sessionAccessConfigured and the MCP route); never for an
 * OAuth connection, a Desktop provider credential, a staff read grant or a
 * workspace agent identity. relaygate decides who is a session access
 * administrator; Control resolves emails and forwards the person's own read
 * token (reader kind `mcp`).
 */

const sessionId = z.string().describe("The session id, as shown by the session read tools.");
const reason = z.string().describe("Why access changes, 1 to 200 characters. It is kept in relaygate's audit history: never put session content in it.");
const expectedVersion = z.number().int().optional()
  .describe("The access version this change is based on (from get_session_access). Omit it to use the current version. A stale version is refused as a conflict and never retried.");
const perm = z.string().describe("r, w or rw.");

function grant(entry: AccessGrant) {
  return entry.member
    ? { user_id: entry.userId, email: entry.email, name: entry.name, perm: entry.perm, member: true }
    : { user_id: entry.userId, perm: entry.perm, member: false };
}

function policy(value: AccessPolicy) {
  return {
    session_id: value.sessionId,
    runtime: value.runtime,
    reset: value.reset,
    version: value.version,
    mode: value.mode,
    gid: value.gid,
    groups: value.groups,
    members: value.members.map(grant),
    label: value.label,
    updated_at: value.updatedAt,
  };
}

function snapshot(value: AccessSnapshot | null) {
  return value && {
    mode: value.mode, gid: value.gid, groups: value.groups, members: value.members.map(grant),
    label: value.label, reset: value.reset,
  };
}

function historyRow(row: AccessHistoryRow) {
  return {
    seq: row.seq, at: row.at, actor_id: row.actorId, actor_name: row.actorName, version: row.version,
    reason: row.reason, before: snapshot(row.before), after: snapshot(row.after),
  };
}

function answer<T>(result: AccessResult<T>, render: (value: T) => Record<string, unknown>) {
  if (result.outcome === "ok") {
    const data = { outcome: "ok", ...render(result.value) };
    return { structuredContent: data, content: [{ type: "text" as const, text: JSON.stringify(data) }] };
  }
  const data: Record<string, unknown> = { outcome: result.outcome, message: result.message };
  if (result.outcome === "conflict") data.current_version = result.currentVersion;
  if (result.outcome === "unknown_members") data.emails = result.emails;
  return { isError: true, structuredContent: data, content: [{ type: "text" as const, text: JSON.stringify(data) }] };
}

export function registerSessionAccessTools(server: McpServer, deps: AccessDeps): void {
  server.registerTool("get_session_access", {
    title: "Get session access",
    description: "Show who may read one session: its mode, group entries (gid and perm), per-person entries (email and name for current members; member:false for a former member, who can then be removed) and the version to change it from. Only session access administrators may use this.",
    inputSchema: { session_id: sessionId },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async input => answer(await getAccess(deps, input.session_id), value => ({ access: policy(value) })));

  server.registerTool("set_session_access", {
    title: "Set session access",
    description: "Change who may read one session. members and groups, when given, REPLACE the current per-person and group lists (they are not merged): include every entry that should remain. Members are emails of current members of this organization; an unknown email refuses the whole change. To restrict a session to named people and groups, use mode \"000\" with r entries. reason is audited and must not contain session content. Only session access administrators may use this.",
    inputSchema: {
      session_id: sessionId,
      mode: z.string().optional().describe("Three digits, each 0, 2, 4 or 6 (owner, group, other). \"000\" plus r entries restricts reading to those entries."),
      members: z.array(z.object({ email: z.string(), perm })).optional()
        .describe("Replaces the per-person list. At most 64."),
      groups: z.array(z.object({ gid: z.number().int(), perm })).optional()
        .describe("Replaces the group list. At most 64. gid values are relaygate group ids."),
      label: z.string().nullable().optional().describe("The session's badge label, or null to remove it."),
      reason,
      expected_version: expectedVersion,
    },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  }, async input => answer(await setAccess(deps, input.session_id, {
    ...(input.mode !== undefined ? { mode: input.mode } : {}),
    ...(input.members !== undefined ? { members: input.members } : {}),
    ...(input.groups !== undefined ? { groups: input.groups } : {}),
    ...("label" in input && input.label !== undefined ? { label: input.label } : {}),
    reason: input.reason,
    ...(input.expected_version !== undefined ? { expectedVersion: input.expected_version } : {}),
  }), value => ({ access: policy(value) })));

  server.registerTool("reset_session_access", {
    title: "Reset session access",
    description: "Remove one session's access override so the installation's default policy applies again. The reset is versioned and audited; reason must not contain session content. Only session access administrators may use this.",
    inputSchema: { session_id: sessionId, reason, expected_version: expectedVersion },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: false },
  }, async input => answer(await resetAccess(deps, input.session_id, {
    reason: input.reason,
    ...(input.expected_version !== undefined ? { expectedVersion: input.expected_version } : {}),
  }), value => ({ access: policy(value) })));

  server.registerTool("get_session_access_history", {
    title: "Get session access history",
    description: "List the audited before/after changes to one session's access, oldest first. Follow next_after for more. Only session access administrators may use this.",
    inputSchema: {
      session_id: sessionId,
      after: z.number().int().optional().describe("Return changes after this seq (default 0)."),
      limit: z.number().int().optional().describe("1 to 200, default 50."),
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async input => answer(await accessHistory(deps, input.session_id, {
    ...(input.after !== undefined ? { after: input.after } : {}),
    ...(input.limit !== undefined ? { limit: input.limit } : {}),
  }), value => ({ session_id: input.session_id, rows: value.rows.map(historyRow), next_after: value.nextAfter })));
}
