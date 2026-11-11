import type { Database } from "../database.js";
import type { SelfhostConfig } from "../config.js";
import type { ControlPlaneStore } from "../store.js";
import { recordAudit } from "../admin/audit.js";
import { isRecord, nonEmptyString, readWorkspaceHistory, type HistoryIdentity } from "../sessions/history.js";
import { recordedSummary } from "../sessions/summary.js";
import { usageDates } from "./routes.js";

/**
 * Usage page, People drill-down (docs/usage.md, "People"). Owner-only and
 * behind SELFHOST_FEATURES=usage_people, independent of `usage`.
 *
 * Unlike the v1 counters this view is per member, keyed by the real user id:
 * - searches and lastActiveAt: Control's `usage_people_daily`, written only
 *   while the feature is on;
 * - sessions, projects, titles and summaries: the session read API with the
 *   owner's authority, one workspace per read, filtered by `user`. Erased
 *   sessions are removed upstream, so they never appear.
 * Every drill-down request (each page) writes an audit row that owners can list.
 */
export const PEOPLE_AUDIT_ACTION = "usage.people.viewed";
const DAY_MS = 86_400_000;
/**
 * Largest page the read API's directory list serves (DIRECTORY_LIST_MAX_LIMIT;
 * more is 501 `limit`). Every /v1/sessions read here stays at or below it.
 */
export const READ_API_MAX_LIMIT = 200;
/** List page size when the read API has no /v1/sessions/users aggregate. */
const AGGREGATE_PAGE = READ_API_MAX_LIMIT;
const DRILL_PAGE = 20;
const SUMMARY_CONCURRENCY = 5;
const TOP_PROJECTS = 3;
const ROLLUP_TITLES = 20;

export class UsagePeopleStore {
  constructor(private readonly database: Database, private readonly now: () => Date = () => new Date()) {}

  private today(): string {
    return this.now().toISOString().slice(0, 10);
  }

  async recordActive(organizationId: string, userId: string): Promise<void> {
    await this.database.query(
      `INSERT INTO usage_people_daily (organization_id, user_id, day, last_active_at) VALUES ($1, $2, $3, $4)
       ON CONFLICT (organization_id, user_id, day)
       DO UPDATE SET last_active_at = GREATEST(usage_people_daily.last_active_at, EXCLUDED.last_active_at)`,
      [organizationId, userId, this.today(), this.now().toISOString()],
    );
  }

  async recordSearch(organizationId: string, userId: string): Promise<void> {
    await this.database.query(
      `INSERT INTO usage_people_daily (organization_id, user_id, day, searches) VALUES ($1, $2, $3, 1)
       ON CONFLICT (organization_id, user_id, day)
       DO UPDATE SET searches = usage_people_daily.searches + 1`,
      [organizationId, userId, this.today()],
    );
  }

  async read(organizationId: string, first: string, last: string): Promise<Map<string, { searches: number; lastActiveAt: string | null }>> {
    const result = await this.database.query<{ user_id: string; searches: string | number; last_active_at: Date | string | null }>(
      `SELECT user_id, sum(searches) AS searches, max(last_active_at) AS last_active_at FROM usage_people_daily
        WHERE organization_id = $1 AND day BETWEEN $2 AND $3 GROUP BY user_id`,
      [organizationId, first, last],
    );
    return new Map(result.rows.map((row) => [row.user_id, {
      searches: Number(row.searches),
      lastActiveAt: row.last_active_at ? new Date(row.last_active_at).toISOString() : null,
    }]));
  }
}

export class PeopleInputError extends Error {}
export class PersonNotFoundError extends Error {}

type Range = { days: number; from: string; to: string; lastTsAfter: string; lastTsBefore: string };

function rangeOf(days: number, now: Date): Range {
  const dates = usageDates(days, now);
  return {
    days,
    from: dates[0]!,
    to: dates[dates.length - 1]!,
    lastTsAfter: `${dates[0]}T00:00:00.000Z`,
    lastTsBefore: new Date(Math.min(Date.parse(dates[dates.length - 1]!) + DAY_MS - 1, now.getTime())).toISOString(),
  };
}

type Session = {
  sessionId: string;
  source: string;
  workspaceId: string;
  title: string | null;
  project: string | null;
  agentName: string | null;
  firstTs: string | null;
  lastTs: string | null;
  userIds: string[];
};

function sessionOf(value: unknown, workspaceId: string): Session | null {
  if (!isRecord(value) || !nonEmptyString(value.sessionId) || !nonEmptyString(value.source)) return null;
  const text = (v: unknown) => (typeof v === "string" && v.trim() ? v : null);
  return {
    sessionId: value.sessionId,
    source: value.source,
    workspaceId,
    title: text(value.title) ?? text(value.taskTitle),
    project: text(value.projectId),
    agentName: text(value.agentName),
    firstTs: text(value.firstTs),
    lastTs: text(value.lastTs),
    userIds: Array.isArray(value.userIds) ? value.userIds.filter((id): id is string => typeof id === "string") : [],
  };
}

async function ownerIdentities(store: ControlPlaneStore, organizationId: string, owner: { userId: string; token: string }) {
  const identities: HistoryIdentity[] = [];
  for (const workspace of await store.listWorkspaces(organizationId)) {
    const workspaceId = String(workspace.id);
    if (!await store.workspaceForUser(workspaceId, owner.userId)) continue;
    identities.push({ userId: owner.userId, organizationId, workspaceId, callerToken: owner.token });
  }
  return identities;
}

async function sessionPage(
  config: SelfhostConfig,
  identity: HistoryIdentity,
  range: Range,
  input: { limit: number; cursor?: string; user?: string },
): Promise<{ sessions: Session[]; nextCursor: string | null }> {
  const params = new URLSearchParams({
    limit: String(input.limit),
    lastTsAfter: range.lastTsAfter,
    lastTsBefore: range.lastTsBefore,
    includeAgentName: "recorded",
  });
  if (input.user) params.set("user", input.user);
  if (input.cursor) params.set("cursor", input.cursor);
  const read = await readWorkspaceHistory(config, identity, "/v1/sessions", params);
  if (read.status !== "ok" || !Array.isArray(read.body.sessions)) throw new Error("invalid session page");
  const sessions = read.body.sessions.map((value) => sessionOf(value, identity.workspaceId));
  if (sessions.some((value) => value === null)) throw new Error("invalid session");
  return {
    sessions: sessions as Session[],
    nextCursor: typeof read.body.nextCursor === "string" && read.body.nextCursor ? read.body.nextCursor : null,
  };
}

function topProjects(sessions: Session[], limit: number) {
  const counts = new Map<string, number>();
  for (const session of sessions) {
    if (session.project) counts.set(session.project, (counts.get(session.project) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, limit)
    .map(([name, sessions]) => ({ name, sessions }));
}

function newest(a: string | null, b: string | null): string | null {
  if (!a) return b;
  if (!b) return a;
  return Date.parse(a) >= Date.parse(b) ? a : b;
}

type UserTotals = { sessions: number; lastSessionAt: string | null; projects: Map<string, number> };

/** At most this many read API calls and this much time per People load; past either, counts are partial. */
export const PEOPLE_MAX_UPSTREAM_CALLS = 3;
export const PEOPLE_BUDGET_MS = 2_000;
const PEOPLE_CACHE_MS = 5 * 60_000;
const PEOPLE_CACHE_ENTRIES = 200;
/** How long a read API without /v1/sessions/users is remembered as such. */
const AGGREGATE_ABSENT_MS = 10 * 60_000;

type SessionTotals = { byUser: Map<string, UserTotals>; partial: boolean; source: "aggregate" | "sample" | "mixed" };
const peopleCaches = new WeakMap<SelfhostConfig, Map<string, { expiresAt: number; value: SessionTotals }>>();
const aggregateAbsent = new WeakMap<SelfhostConfig, number>();

/** Test hook: drop cached People session totals for this configuration. */
export function forgetPeopleCache(config: SelfhostConfig): void {
  peopleCaches.delete(config);
  aggregateAbsent.delete(config);
}

class BudgetExhausted extends Error {}

function addTotals(byUser: Map<string, UserTotals>, userId: string, count: number, lastSessionAt: string | null, projects: Array<[string, number]>) {
  const totals = byUser.get(userId) ?? { sessions: 0, lastSessionAt: null, projects: new Map<string, number>() };
  totals.sessions += count;
  totals.lastSessionAt = newest(totals.lastSessionAt, lastSessionAt);
  for (const [name, sessions] of projects) totals.projects.set(name, (totals.projects.get(name) ?? 0) + sessions);
  byUser.set(userId, totals);
}

/**
 * Per-user session totals for the owner's workspaces, bounded: at most
 * PEOPLE_MAX_UPSTREAM_CALLS read API calls (each list page <= 200) within
 * PEOPLE_BUDGET_MS. Prefers the read API aggregate /v1/sessions/users (one
 * call per workspace); without it, counts the newest sessions from list
 * pages. Anything not read in budget makes the totals `partial` (lower
 * bounds). Throws when the read API cannot be read at all.
 */
async function sessionTotals(config: SelfhostConfig, identities: HistoryIdentity[], range: Range): Promise<SessionTotals> {
  const byUser = new Map<string, UserTotals>();
  const deadline = Date.now() + PEOPLE_BUDGET_MS;
  let calls = 0;
  let partial = false;
  const used = new Set<"aggregate" | "sample">();
  const call = async <T>(run: () => Promise<T>): Promise<T> => {
    const remaining = deadline - Date.now();
    if (calls >= PEOPLE_MAX_UPSTREAM_CALLS || remaining <= 0) throw new BudgetExhausted();
    calls += 1;
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        run(),
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new BudgetExhausted()), remaining); }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  };
  try {
    for (const identity of identities) {
      const absentUntil = aggregateAbsent.get(config) ?? 0;
      if (absentUntil <= Date.now()) {
        const read = await call(() => readWorkspaceHistory(config, identity, "/v1/sessions/users", new URLSearchParams({
          lastTsAfter: range.lastTsAfter, lastTsBefore: range.lastTsBefore,
        }), { allowNotFound: true }));
        if (read.status === "ok" && Array.isArray(read.body.users)) {
          used.add("aggregate");
          if (read.body.truncated === true) partial = true;
          for (const row of read.body.users) {
            if (!isRecord(row) || !nonEmptyString(row.userId) || !Number.isSafeInteger(row.sessions) || (row.sessions as number) < 0) {
              throw new Error("invalid users aggregate");
            }
            const projects = Array.isArray(row.topProjects)
              ? row.topProjects.flatMap((project): Array<[string, number]> =>
                isRecord(project) && nonEmptyString(project.name) && Number.isSafeInteger(project.sessions)
                  ? [[project.name, project.sessions as number]] : [])
              : [];
            addTotals(byUser, row.userId, row.sessions as number,
              typeof row.lastSessionAt === "string" ? row.lastSessionAt : null, projects);
          }
          continue;
        }
        if (read.status === "ok") throw new Error("invalid users aggregate");
        // 404 or 501: an older read API. Remember it and sample instead.
        aggregateAbsent.set(config, Date.now() + AGGREGATE_ABSENT_MS);
      }
      used.add("sample");
      let cursor: string | undefined;
      for (;;) {
        let page: Awaited<ReturnType<typeof sessionPage>>;
        try {
          page = await call(() => sessionPage(config, identity, range, { limit: AGGREGATE_PAGE, cursor }));
        } catch (error) {
          if (!(error instanceof BudgetExhausted)) throw error;
          partial = true;
          break;
        }
        for (const session of page.sessions) {
          for (const userId of new Set(session.userIds)) {
            addTotals(byUser, userId, 1, session.lastTs, session.project ? [[session.project, 1]] : []);
          }
        }
        if (!page.nextCursor) break;
        cursor = page.nextCursor;
      }
    }
  } catch (error) {
    if (!(error instanceof BudgetExhausted)) throw error;
    partial = true;
  }
  return { byUser, partial, source: used.size === 2 ? "mixed" : used.has("aggregate") ? "aggregate" : "sample" };
}

async function cachedSessionTotals(config: SelfhostConfig, identities: HistoryIdentity[], range: Range, key: string) {
  let cache = peopleCaches.get(config);
  if (!cache) {
    cache = new Map();
    peopleCaches.set(config, cache);
  }
  const hit = cache.get(key);
  if (hit && hit.expiresAt > Date.now()) return hit.value;
  const value = await sessionTotals(config, identities, range);
  if (cache.size >= PEOPLE_CACHE_ENTRIES) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(key, { expiresAt: Date.now() + PEOPLE_CACHE_MS, value });
  return value;
}

export async function peopleReport(input: {
  config: SelfhostConfig;
  store: ControlPlaneStore;
  people: UsagePeopleStore;
  organizationId: string;
  owner: { userId: string; token: string };
  days: number;
  now: Date;
}) {
  const range = rangeOf(input.days, input.now);
  const members = await input.store.listMemberships(input.organizationId);
  // Control's own counters are one indexed query: always fresh.
  const counters = await input.people.read(input.organizationId, range.from, range.to);
  const identities = await ownerIdentities(input.store, input.organizationId, input.owner);
  let totals: SessionTotals | null = null;
  try {
    totals = await cachedSessionTotals(input.config, identities, range, JSON.stringify([
      input.organizationId, input.owner.userId, range.days, range.to, identities.map((i) => i.workspaceId),
    ]));
  } catch {
    totals = null;
  }
  const rows = members.flatMap((member) => {
    if (typeof member.userId !== "string") return [];
    const own = totals?.byUser.get(member.userId);
    const counted = counters.get(member.userId);
    return [{
      userId: member.userId,
      name: typeof member.name === "string" ? member.name : null,
      email: typeof member.email === "string" ? member.email : null,
      role: member.role,
      sessionsUploaded: totals ? own?.sessions ?? 0 : null,
      searches: counted?.searches ?? 0,
      lastActiveAt: counted?.lastActiveAt ?? null,
      lastSessionAt: own?.lastSessionAt ?? null,
      topProjects: own
        ? [...own.projects.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
          .slice(0, TOP_PROJECTS).map(([name, sessions]) => ({ name, sessions }))
        : [],
    }];
  });
  rows.sort((a, b) => (b.sessionsUploaded ?? 0) - (a.sessionsUploaded ?? 0) || String(a.email).localeCompare(String(b.email)));
  return {
    range: { days: range.days, from: range.from, to: range.to },
    members: rows,
    // Lower bounds: not every session was read within the budget.
    truncated: totals?.partial ?? false,
    source: totals?.source ?? null,
    unavailable: totals ? [] : ["sessionsUploaded"],
  };
}

/**
 * Opaque drill-down cursor: per workspace, the read API cursor of the page
 * being consumed (null = its first page), how many of that page's sessions
 * are already shown, and whether the workspace is exhausted.
 */
type Stream = { c: string | null; k: number; d: boolean };

function encodeCursor(streams: Stream[]): string {
  return Buffer.from(JSON.stringify({ s: streams }), "utf8").toString("base64url");
}

function decodeCursor(raw: string | undefined, workspaces: number): Stream[] {
  if (raw === undefined) return Array.from({ length: workspaces }, () => ({ c: null, k: 0, d: false }));
  try {
    const value: unknown = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
    if (isRecord(value) && Array.isArray(value.s) && value.s.length === workspaces && value.s.every((stream) =>
      isRecord(stream) && typeof stream.d === "boolean" &&
      Number.isSafeInteger(stream.k) && (stream.k as number) >= 0 && (stream.k as number) <= AGGREGATE_PAGE &&
      (stream.c === null || (typeof stream.c === "string" && stream.c.length > 0 && stream.c.length <= 4096)))) {
      return value.s as Stream[];
    }
  } catch {
    // fall through
  }
  throw new PeopleInputError("Invalid cursor");
}

async function mapLimited<T, R>(values: T[], limit: number, run: (value: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(values.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, values.length) }, async () => {
    while (next < values.length) {
      const index = next++;
      results[index] = await run(values[index]!);
    }
  }));
  return results;
}

async function summaryOf(config: SelfhostConfig, identity: HistoryIdentity, session: Session): Promise<string | null> {
  try {
    const read = await readWorkspaceHistory(config, identity,
      `/v1/sessions/${encodeURIComponent(session.sessionId)}/summary`,
      new URLSearchParams({ source: session.source }), { allowNotFound: true });
    if (read.status !== "ok") return null;
    const summary = recordedSummary(read.body);
    return summary && summary.status === "ready" ? summary.summary : null;
  } catch {
    return null;
  }
}

export async function personSessions(input: {
  config: SelfhostConfig;
  store: ControlPlaneStore;
  organizationId: string;
  owner: { userId: string; token: string };
  subjectUserId: string;
  days: number;
  cursor?: string;
  now: Date;
}) {
  const member = (await input.store.listMemberships(input.organizationId))
    .find((row) => row.userId === input.subjectUserId);
  if (!member) throw new PersonNotFoundError("user_not_found");
  const range = rangeOf(input.days, input.now);
  const identities = await ownerIdentities(input.store, input.organizationId, input.owner);
  const streams = decodeCursor(input.cursor, identities.length);
  // Merge the workspaces newest first: read each live workspace's next
  // DRILL_PAGE sessions (past the ones already shown), then take the newest
  // DRILL_PAGE overall. A workspace advances only by what was shown.
  type Candidate = Session & { stream: number };
  const candidates: Candidate[] = [];
  const fetched: Array<{ count: number; next: string | null }> = [];
  for (const [index, stream] of streams.entries()) {
    if (stream.d) {
      fetched.push({ count: 0, next: null });
      continue;
    }
    const limit = Math.min(stream.k + DRILL_PAGE, AGGREGATE_PAGE);
    const page = await sessionPage(input.config, identities[index]!, range, {
      limit, cursor: stream.c ?? undefined, user: input.subjectUserId,
    });
    fetched.push({ count: page.sessions.length, next: page.nextCursor });
    for (const session of page.sessions.slice(stream.k)) candidates.push({ ...session, stream: index });
  }
  // Each workspace's rows are newest first, so what a page takes from one is
  // always a prefix of it; `k` counts that prefix.
  candidates.sort((a, b) => Date.parse(b.lastTs ?? "") - Date.parse(a.lastTs ?? "") || a.sessionId.localeCompare(b.sessionId));
  const taken = candidates.slice(0, DRILL_PAGE);
  for (const session of taken) streams[session.stream]!.k += 1;
  // The read API filters by user; anything else is consumed but never shown.
  const shown = taken.filter((session) => session.userIds.includes(input.subjectUserId));
  for (const [index, stream] of streams.entries()) {
    if (stream.d) continue;
    const { count, next } = fetched[index]!;
    if (stream.k < count) continue;
    if (next) {
      stream.c = next;
      stream.k = 0;
    } else {
      stream.d = true;
      stream.c = null;
      stream.k = 0;
    }
  }
  // Recorded summaries for this page only, within the same time budget: a
  // summary not read in time is shown as none rather than slowing the page.
  const summaryDeadline = Date.now() + PEOPLE_BUDGET_MS;
  const sessions = await mapLimited(shown, SUMMARY_CONCURRENCY, async (session) => {
    const remaining = summaryDeadline - Date.now();
    let timer: NodeJS.Timeout | undefined;
    const summary = remaining <= 0 ? null : await Promise.race([
      summaryOf(input.config, identities[session.stream]!, session),
      new Promise<null>((resolve) => { timer = setTimeout(() => resolve(null), remaining); }),
    ]).finally(() => clearTimeout(timer));
    return { ...session, summary };
  });
  const nextCursor = streams.every((stream) => stream.d) ? null : encodeCursor(streams);

  let rollup: { titles: string[]; projects: Array<{ name: string; sessions: number }> } | null = null;
  if (input.cursor === undefined) {
    // Built only from recorded titles and projects: no new generation.
    const titles = [...new Set(sessions.map((session) => session.title).filter((title): title is string => !!title))];
    rollup = { titles: titles.slice(0, ROLLUP_TITLES), projects: topProjects(sessions, 10) };
  }
  return {
    person: {
      userId: input.subjectUserId,
      name: typeof member.name === "string" ? member.name : null,
      email: typeof member.email === "string" ? member.email : null,
      role: member.role,
    },
    range: { days: range.days, from: range.from, to: range.to },
    rollup,
    sessions: sessions.map(({ userIds: _users, stream: _stream, ...session }) => session),
    nextCursor,
  };
}

export async function recordPeopleView(database: Database, input: {
  organizationId: string;
  viewerUserId: string;
  subjectUserId: string;
  days: number;
  page: "first" | "next";
}): Promise<void> {
  await recordAudit(database, {
    organizationId: input.organizationId,
    actor: { kind: "user", userId: input.viewerUserId },
    action: PEOPLE_AUDIT_ACTION,
    target: `user:${input.subjectUserId} days:${input.days} page:${input.page}`,
  });
}

export async function peopleAudit(database: Database, store: ControlPlaneStore, organizationId: string) {
  const result = await database.query<{ actor_id: string | null; target: string | null; created_at: Date | string }>(
    `SELECT actor_id, target, created_at FROM admin_audit_events
      WHERE organization_id = $1 AND action = $2 ORDER BY created_at DESC LIMIT 200`,
    [organizationId, PEOPLE_AUDIT_ACTION],
  );
  const names = new Map((await store.listMemberships(organizationId))
    .map((row) => [String(row.userId), typeof row.name === "string" ? row.name : null]));
  return result.rows.map((row) => {
    const match = /^user:(\S+) days:(\d+)(?: page:(first|next))?$/.exec(row.target ?? "");
    return {
      viewerUserId: row.actor_id,
      viewerName: row.actor_id ? names.get(row.actor_id) ?? null : null,
      subjectUserId: match?.[1] ?? null,
      subjectName: match ? names.get(match[1]!) ?? null : null,
      days: match ? Number(match[2]) : null,
      page: match?.[3] ?? "first",
      createdAt: new Date(row.created_at).toISOString(),
    };
  });
}
