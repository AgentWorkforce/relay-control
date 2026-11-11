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
/** Read API page size for the aggregate; at most this many pages per workspace. */
const AGGREGATE_PAGE = 500;
const AGGREGATE_PAGES = 10;
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
  const counters = await input.people.read(input.organizationId, range.from, range.to);
  const byUser = new Map<string, Session[]>();
  let truncated = false;
  let sessionsAvailable = true;
  try {
    for (const identity of await ownerIdentities(input.store, input.organizationId, input.owner)) {
      let cursor: string | undefined;
      for (let page = 0; page < AGGREGATE_PAGES; page += 1) {
        const result = await sessionPage(input.config, identity, range, { limit: AGGREGATE_PAGE, cursor });
        for (const session of result.sessions) {
          for (const userId of new Set(session.userIds)) {
            const list = byUser.get(userId) ?? [];
            list.push(session);
            byUser.set(userId, list);
          }
        }
        if (!result.nextCursor) break;
        cursor = result.nextCursor;
        if (page === AGGREGATE_PAGES - 1) truncated = true;
      }
    }
  } catch {
    sessionsAvailable = false;
    byUser.clear();
  }
  const rows = members.flatMap((member) => {
    if (typeof member.userId !== "string") return [];
    const sessions = byUser.get(member.userId) ?? [];
    const counted = counters.get(member.userId);
    return [{
      userId: member.userId,
      name: typeof member.name === "string" ? member.name : null,
      email: typeof member.email === "string" ? member.email : null,
      role: member.role,
      sessionsUploaded: sessionsAvailable ? sessions.length : null,
      searches: counted?.searches ?? 0,
      lastActiveAt: counted?.lastActiveAt ?? null,
      lastSessionAt: sessions.reduce<string | null>((latest, session) => newest(latest, session.lastTs), null),
      topProjects: topProjects(sessions, TOP_PROJECTS),
    }];
  });
  rows.sort((a, b) => (b.sessionsUploaded ?? 0) - (a.sessionsUploaded ?? 0) || String(a.email).localeCompare(String(b.email)));
  return {
    range: { days: range.days, from: range.from, to: range.to },
    members: rows,
    truncated,
    unavailable: sessionsAvailable ? [] : ["sessionsUploaded"],
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
      Number.isSafeInteger(stream.k) && (stream.k as number) >= 0 && (stream.k as number) < AGGREGATE_PAGE &&
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
    }
  }
  const sessions = await mapLimited(shown, SUMMARY_CONCURRENCY, async (session) => ({
    ...session,
    summary: await summaryOf(input.config, identities[session.stream]!, session),
  }));
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
