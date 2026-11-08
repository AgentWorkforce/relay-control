import type { IncomingMessage, ServerResponse } from "node:http";
import type { SelfhostConfig } from "../config.js";
import { UpstreamError } from "../relayhistory.js";
import type { ControlPlaneStore, Principal } from "../store.js";
import {
  isRecord,
  nonEmptyString,
  readWorkspaceHistory as readHistory,
  UNSUPPORTED_BY_BACKEND,
  type HistoryIdentity,
} from "./history.js";

/**
 * Dashboard session reads: hosted-parity list, search, activity, output,
 * transcript (events + turns), timing, and subagent catalog. Every route is
 * workspace-scoped: the caller must be a member of the workspace named in the
 * path (checked by `workspaceAccess`), and RelayHistory is queried with that
 * workspace and must attest it (see ./history.ts).
 */

type WorkspaceAccess = (
  request: IncomingMessage,
  workspaceId: string,
) => Promise<{
  principal: Principal;
  workspace: { id: string; organizationId: string };
  /** The caller's raw access token, forwarded to History when RelayAuth is off. */
  token: string;
}>;

export type SessionRouteContext = {
  method: string;
  path: string;
  url: URL;
  request: IncomingMessage;
  response: ServerResponse;
  config: SelfhostConfig;
  store: ControlPlaneStore;
  workspaceAccess: WorkspaceAccess;
  httpError: (status: number, code: string, message: string) => Error;
  json: (response: ServerResponse, status: number, body: unknown, noStore?: boolean) => void;
  now?: () => Date;
};

const PREFIX = /^\/api\/v1\/workspaces\/([^/]+)\/sessions(?:\/(.*))?$/;
const CONTROL = /[\u0000-\u001f\u007f]/u;
const DAY_MS = 86_400_000;
/** Most UTC days RelayHistory serves in one activity or output read. */
export const ACTIVITY_DAYS_PER_READ = 92;
const MAX_ACTIVITY_DAYS = 366;

type Rule = { max?: number; pattern?: RegExp; values?: readonly string[] };

/** Strict query validation: unknown or repeated parameters are rejected. */
function query(
  ctx: SessionRouteContext,
  rules: Record<string, Rule>,
  required: string[] = [],
): Record<string, string | undefined> {
  const params = ctx.url.searchParams;
  const result: Record<string, string | undefined> = {};
  for (const name of new Set(params.keys())) {
    const rule = rules[name];
    if (!rule || params.getAll(name).length !== 1) {
      throw ctx.httpError(400, "invalid_request", `Invalid session parameter: ${name}`);
    }
    const value = params.get(name)!.trim();
    if (
      CONTROL.test(value) ||
      value.length > (rule.max ?? 512) ||
      (rule.pattern && value && !rule.pattern.test(value)) ||
      (rule.values && !rule.values.includes(value))
    ) {
      throw ctx.httpError(400, "invalid_request", `Invalid session parameter: ${name}`);
    }
    result[name] = value || undefined;
  }
  for (const name of required) {
    if (!result[name]) {
      throw ctx.httpError(400, "invalid_request", `${name} is required`);
    }
  }
  return result;
}

const ISO_TIME = /^\d{4}-\d{2}-\d{2}(?:T[\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)?$/;
const DAY = /^\d{4}-\d{2}-\d{2}$/;

function instant(ctx: SessionRouteContext, value: string | undefined, name: string) {
  if (value === undefined) return undefined;
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) {
    throw ctx.httpError(400, "invalid_request", `${name} must be an ISO date or time`);
  }
  return new Date(parsed).toISOString();
}

function validDay(value: string | undefined): value is string {
  return !!value && DAY.test(value) && Number.isFinite(Date.parse(value)) &&
    new Date(value).toISOString().slice(0, 10) === value;
}

/** Inclusive [first, last] UTC days, at most 366 and never in the future. */
function dayRange(ctx: SessionRouteContext, first?: string, last?: string) {
  const today = (ctx.now?.() ?? new Date()).toISOString().slice(0, 10);
  if (!validDay(first) || !validDay(last) || first > last || last > today) {
    throw ctx.httpError(400, "invalid_request", "first and last must be valid UTC days up to today");
  }
  const length = Math.floor((Date.parse(last) - Date.parse(first)) / DAY_MS) + 1;
  if (length > MAX_ACTIVITY_DAYS) {
    throw ctx.httpError(400, "invalid_request", "Range is limited to 366 days");
  }
  return Array.from({ length }, (_, index) =>
    new Date(Date.parse(first) + index * DAY_MS).toISOString().slice(0, 10));
}

function windows(dates: string[], now: Date) {
  const result: Array<{ dates: string[]; since: string; until: string }> = [];
  for (let offset = 0; offset < dates.length; offset += ACTIVITY_DAYS_PER_READ) {
    const slice = dates.slice(offset, offset + ACTIVITY_DAYS_PER_READ);
    // `until` is inclusive: the last day's final millisecond, or now.
    const until = new Date(Math.min(
      Date.parse(slice[slice.length - 1]!) + DAY_MS - 1,
      now.getTime(),
    ));
    result.push({ dates: slice, since: `${slice[0]}T00:00:00.000Z`, until: until.toISOString() });
  }
  return result;
}

function isCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

/**
 * The session backend answered 501 for a view (e.g. the self-host read API
 * container does not serve output metrics, or cannot answer a first page
 * exactly). Caught in `handleSessionRoutes` and answered as 501.
 */
class UnsupportedView extends Error {
  constructor(readonly reason: string) {
    super("The configured session backend does not serve this view");
  }
}

/** `readWorkspaceHistory`, with an upstream 501 turned into `UnsupportedView`. */
async function readWorkspaceHistory(...args: Parameters<typeof readHistory>) {
  const read = await readHistory(...args);
  if (read.status === "unsupported") throw new UnsupportedView(read.reason);
  return read;
}

function upstreamShape(message: string): UpstreamError {
  return new UpstreamError("read", undefined, message);
}

function sessionPathId(ctx: SessionRouteContext, raw: string): string {
  let sessionId: string;
  try {
    sessionId = decodeURIComponent(raw).trim();
  } catch {
    throw ctx.httpError(400, "invalid_request", "Invalid session identity");
  }
  if (!sessionId || sessionId.length > 512 || CONTROL.test(sessionId)) {
    throw ctx.httpError(400, "invalid_request", "Invalid session identity");
  }
  return sessionId;
}

function identityOf(access: Awaited<ReturnType<WorkspaceAccess>>): HistoryIdentity {
  return {
    userId: access.principal.userId,
    organizationId: access.workspace.organizationId,
    workspaceId: access.workspace.id,
    callerToken: access.token,
  };
}

function params(entries: Record<string, string | undefined>): URLSearchParams {
  const result = new URLSearchParams();
  for (const [name, value] of Object.entries(entries)) {
    if (value !== undefined && value !== "") result.set(name, value);
  }
  return result;
}

function sessionItem(value: unknown): Record<string, unknown> {
  if (!isRecord(value) || !nonEmptyString(value.sessionId) || !nonEmptyString(value.source)) {
    throw upstreamShape("RelayHistory returned an invalid session");
  }
  return {
    ...value,
    project: typeof value.projectId === "string" && value.projectId.trim()
      ? { name: value.projectId }
      : null,
  };
}

function eventItem(value: unknown): Record<string, unknown> {
  if (
    !isRecord(value) ||
    !nonEmptyString(value.eventId) ||
    typeof value.ts !== "string" ||
    !Number.isFinite(Date.parse(value.ts))
  ) {
    throw upstreamShape("RelayHistory returned an invalid event");
  }
  return value;
}

function cursorOf(body: Record<string, unknown>): string | null {
  return typeof body.nextCursor === "string" && body.nextCursor ? body.nextCursor : null;
}

/** Hosted citation path: `/dashboard/sessions/<id>?source=<source>`. */
export function citationPath(sessionId: string, source: string): string {
  return `/dashboard/sessions/${encodeURIComponent(sessionId)}?${new URLSearchParams({ source })}`;
}

const LIST_RULES: Record<string, Rule> = {
  q: { max: 500 },
  cursor: { max: 4_096 },
  metadata: { values: ["deferred"] },
  source: { max: 64 },
  project: { max: 512 },
  since: { max: 64, pattern: ISO_TIME },
  until: { max: 64, pattern: ISO_TIME },
  ranking: { values: ["hybrid"] },
  limit: { pattern: /^\d{1,2}$/ },
};

export async function handleSessionRoutes(ctx: SessionRouteContext): Promise<boolean> {
  try {
    return await routeSessions(ctx);
  } catch (error) {
    if (!(error instanceof UnsupportedView)) throw error;
    ctx.json(ctx.response, 501, {
      error: UNSUPPORTED_BY_BACKEND,
      reason: error.reason,
      message: error.message,
    }, true);
    return true;
  }
}

async function routeSessions(ctx: SessionRouteContext): Promise<boolean> {
  const match = PREFIX.exec(ctx.path);
  if (!match || ctx.method !== "GET") return false;
  let workspaceId: string;
  try {
    workspaceId = decodeURIComponent(match[1]!);
  } catch {
    return false;
  }
  const rest = match[2];
  const segments = rest === undefined ? [] : rest.split("/");
  const send = (body: unknown) => ctx.json(ctx.response, 200, body, true);
  const now = ctx.now?.() ?? new Date();

  // GET .../sessions
  if (segments.length === 0) {
    const input = query(ctx, LIST_RULES);
    if (input.limit !== undefined && input.ranking !== "hybrid") {
      throw ctx.httpError(400, "invalid_request", "limit requires ranking=hybrid");
    }
    const limit = input.limit === undefined ? undefined : Number(input.limit);
    if (limit !== undefined && (limit < 1 || limit > 25)) {
      throw ctx.httpError(400, "invalid_request", "limit must be between 1 and 25");
    }
    if (input.ranking === "hybrid" && (input.q?.length ?? 0) < 2) {
      throw ctx.httpError(400, "invalid_request", "ranking=hybrid requires q");
    }
    const since = instant(ctx, input.since, "since");
    const until = instant(ctx, input.until, "until");
    const access = await ctx.workspaceAccess(ctx.request, workspaceId);
    const read = await readWorkspaceHistory(ctx.config, identityOf(access), "/v1/sessions", params({
      limit: String(limit ?? 50),
      q: input.q,
      cursor: input.cursor,
      source: input.source,
      project: input.project,
      since,
      until,
      ...(input.ranking ? { search: "hybrid" } : {}),
    }));
    if (read.status !== "ok" || !Array.isArray(read.body.sessions)) {
      throw upstreamShape("RelayHistory returned an invalid session page");
    }
    const items = read.body.sessions.map(sessionItem).map((item) =>
      input.ranking ? { ...item, sessionURL: citationPath(String(item.sessionId), String(item.source)) } : item);
    send({
      items,
      members: await workspaceMembers(ctx, access.workspace.organizationId),
      nextCursor: cursorOf(read.body),
      error: false,
      now: now.toISOString(),
      ...(input.ranking ? { ranking: "hybrid" } : {}),
    });
    return true;
  }

  // GET .../sessions/activity?first&last[&q]
  if (segments.length === 1 && segments[0] === "activity") {
    const input = query(ctx, { first: {}, last: {}, q: { max: 500 } }, ["first", "last"]);
    const dates = dayRange(ctx, input.first, input.last);
    const access = await ctx.workspaceAccess(ctx.request, workspaceId);
    const days: Array<{ date: string; conversations: number; bySource: Record<string, number> }> = [];
    for (const window of windows(dates, now)) {
      const read = await readWorkspaceHistory(ctx.config, identityOf(access), "/v1/sessions/activity",
        params({ since: window.since, until: window.until, q: input.q }));
      const rows = read.status === "ok" && Array.isArray(read.body.days) ? read.body.days : null;
      if (!rows || rows.length !== window.dates.length) {
        throw upstreamShape("RelayHistory returned an invalid activity window");
      }
      rows.forEach((value, index) => {
        if (
          !isRecord(value) || value.date !== window.dates[index] || !isCount(value.total) ||
          !isRecord(value.bySource)
        ) {
          throw upstreamShape("RelayHistory returned an invalid activity day");
        }
        const bySource: Record<string, number> = {};
        let sum = 0;
        for (const [source, count] of Object.entries(value.bySource)) {
          if (!isCount(count)) throw upstreamShape("RelayHistory returned an invalid activity count");
          if (count === 0) continue;
          bySource[source] = count;
          sum += count;
        }
        if (sum !== value.total) throw upstreamShape("RelayHistory returned inconsistent activity");
        days.push({ date: window.dates[index]!, conversations: value.total, bySource });
      });
    }
    send({ days });
    return true;
  }

  // GET .../sessions/output?first&last (RelayHistory >= session output metrics)
  if (segments.length === 1 && segments[0] === "output") {
    const input = query(ctx, { first: {}, last: {} }, ["first", "last"]);
    const dates = dayRange(ctx, input.first, input.last);
    const access = await ctx.workspaceAccess(ctx.request, workspaceId);
    const totals = {
      agentMessages: 0,
      commits: 0,
      linesAdded: 0,
      linesRemoved: 0,
      commitsWithoutLineCounts: 0,
    };
    for (const window of windows(dates, now)) {
      const read = await readWorkspaceHistory(ctx.config, identityOf(access), "/v1/sessions/output",
        params({ since: window.since, until: window.until }), { allowNotFound: true });
      if (read.status === "not_found") {
        // Older RelayHistory builds do not serve output metrics.
        send({ output: null, unsupported: true });
        return true;
      }
      const output = isRecord(read.body.output) ? read.body.output : read.body;
      for (const key of Object.keys(totals) as Array<keyof typeof totals>) {
        const value = output[key];
        if (value === undefined || value === null) continue;
        if (!isCount(value)) throw upstreamShape("RelayHistory returned invalid output metrics");
        totals[key] += value;
      }
    }
    send({ output: totals });
    return true;
  }

  // GET .../sessions/search?q[&source&project&since&until&cursor&limit]
  if (segments.length === 1 && segments[0] === "search") {
    const input = query(ctx, {
      q: { max: 500 },
      source: { max: 64 },
      project: { max: 512 },
      since: { max: 64, pattern: ISO_TIME },
      until: { max: 64, pattern: ISO_TIME },
      cursor: { max: 4_096 },
      limit: { pattern: /^\d{1,2}$/ },
    }, ["q"]);
    const limit = input.limit === undefined ? 25 : Number(input.limit);
    if (limit < 1 || limit > 50) {
      throw ctx.httpError(400, "invalid_request", "limit must be between 1 and 50");
    }
    const since = instant(ctx, input.since, "since");
    const until = instant(ctx, input.until, "until");
    const access = await ctx.workspaceAccess(ctx.request, workspaceId);
    const read = await readWorkspaceHistory(ctx.config, identityOf(access), "/v1/events", params({
      q: input.q,
      limit: String(limit),
      order: "desc",
      maxContent: "600",
      source: input.source,
      project: input.project,
      since,
      until,
      cursor: input.cursor,
    }));
    if (read.status !== "ok" || !Array.isArray(read.body.events)) {
      throw upstreamShape("RelayHistory returned an invalid search page");
    }
    const matches = read.body.events.map(eventItem).map((event) => ({
      ...event,
      citationPath: nonEmptyString(event.sessionId) && nonEmptyString(event.source)
        ? citationPath(event.sessionId, event.source)
        : null,
    }));
    send({
      matches,
      members: await workspaceMembers(ctx, access.workspace.organizationId),
      nextCursor: cursorOf(read.body),
    });
    return true;
  }

  // GET .../sessions/:sessionId/{events|turns|timing|catalog}?source=
  if (segments.length === 2) {
    const sessionId = sessionPathId(ctx, segments[0]!);
    const resource = segments[1];
    if (resource === "events") {
      const input = query(ctx, {
        source: { max: 512 },
        cursor: { max: 4_096 },
        order: { values: ["asc", "desc"] },
        limit: { pattern: /^\d{1,4}$/ },
      }, ["source"]);
      const limit = input.limit === undefined ? 1_000 : Number(input.limit);
      if (limit < 1 || limit > 1_000) {
        throw ctx.httpError(400, "invalid_request", "limit must be between 1 and 1000");
      }
      const order = input.order ?? "asc";
      const access = await ctx.workspaceAccess(ctx.request, workspaceId);
      const read = await readWorkspaceHistory(
        ctx.config,
        identityOf(access),
        `/v1/sessions/${encodeURIComponent(sessionId)}/events`,
        params({
          source: input.source,
          order,
          limit: String(limit),
          maxContent: "100000",
          includeMessageId: "true",
          cursor: input.cursor,
        }),
      );
      if (read.status !== "ok" || !Array.isArray(read.body.events)) {
        throw upstreamShape("RelayHistory returned invalid events");
      }
      const events = read.body.events.map(eventItem).sort((left, right) => {
        const byTime = Date.parse(String(left.ts)) - Date.parse(String(right.ts));
        return byTime || String(left.eventId).localeCompare(String(right.eventId));
      });
      send({
        events,
        members: await workspaceMembers(ctx, access.workspace.organizationId),
        nextCursor: cursorOf(read.body),
        error: false,
      });
      return true;
    }
    if (resource === "turns") {
      const input = query(ctx, { source: { max: 512 }, cursor: { max: 4_096 } }, ["source"]);
      const access = await ctx.workspaceAccess(ctx.request, workspaceId);
      const read = await readWorkspaceHistory(
        ctx.config,
        identityOf(access),
        `/v1/sessions/${encodeURIComponent(sessionId)}/turns`,
        params({ source: input.source, cursor: input.cursor }),
      );
      if (read.status !== "ok" || !Array.isArray(read.body.turns)) {
        throw upstreamShape("RelayHistory returned invalid turns");
      }
      const turns = read.body.turns.filter((turn) =>
        isRecord(turn) && nonEmptyString(turn.id) && typeof turn.ts === "string" &&
        Number.isFinite(Date.parse(turn.ts)));
      send({ turns, nextCursor: cursorOf(read.body) });
      return true;
    }
    if (resource === "timing") {
      const input = query(ctx, { source: { max: 512 } }, ["source"]);
      const access = await ctx.workspaceAccess(ctx.request, workspaceId);
      const read = await readWorkspaceHistory(
        ctx.config,
        identityOf(access),
        `/v1/sessions/${encodeURIComponent(sessionId)}/timing`,
        params({ source: input.source }),
        { allowNotFound: true },
      );
      if (read.status === "not_found") {
        send({ timing: null });
        return true;
      }
      const body = read.body;
      const timestamp = (value: unknown) =>
        value === null || (typeof value === "string" && Number.isFinite(Date.parse(value)));
      const duration = (value: unknown) =>
        value === null || (typeof value === "number" && Number.isFinite(value) && value >= 0);
      if (
        body.sessionId !== sessionId || body.source !== input.source ||
        !timestamp(body.startedAt) || !timestamp(body.lastActionAt) ||
        !duration(body.workMs) || !duration(body.waitingMs)
      ) {
        throw upstreamShape("RelayHistory returned invalid timing");
      }
      const { correlationId: _correlationId, ...timing } = body;
      void _correlationId;
      send({ timing });
      return true;
    }
    if (resource === "catalog") {
      const input = query(ctx, { source: { max: 512 } }, ["source"]);
      const access = await ctx.workspaceAccess(ctx.request, workspaceId);
      const read = await readWorkspaceHistory(
        ctx.config,
        identityOf(access),
        `/v1/sessions/${encodeURIComponent(sessionId)}/catalog`,
        params({ source: input.source }),
        { allowNotFound: true },
      );
      if (read.status === "not_found") {
        send({ catalog: null, parents: [], children: [], commitLinks: [], truncated: false });
        return true;
      }
      const body = read.body;
      if (body.workspaceId !== undefined && body.workspaceId !== access.workspace.id) {
        throw upstreamShape("RelayHistory catalog belongs to another workspace");
      }
      const list = (value: unknown) => Array.isArray(value) ? value.filter(isRecord) : [];
      send({
        catalog: isRecord(body.catalog) ? body.catalog : null,
        parents: list(body.parents),
        children: list(body.children),
        commitLinks: list(body.commitLinks),
        truncated: body.truncated === true,
      });
      return true;
    }
  }
  return false;
}

/** Display names for session attribution; organization members only. */
async function workspaceMembers(ctx: SessionRouteContext, organizationId: string) {
  const rows = await ctx.store.listMemberships(organizationId);
  return rows.flatMap((row) =>
    typeof row.userId === "string"
      ? [{ id: row.userId, name: typeof row.name === "string" ? row.name : null }]
      : []);
}
