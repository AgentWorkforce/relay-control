import type { Database } from "../database.js";
import type { SelfhostConfig } from "../config.js";
import type { ControlPlaneStore } from "../store.js";
import { recordAudit } from "../admin/audit.js";
import type { HistoryIdentity } from "../sessions/history.js";
import type { ReaderKind } from "../session-read.js";
import {
  BudgetExhausted,
  newest,
  ownerIdentities,
  PEOPLE_BUDGET_MS,
  PEOPLE_MAX_UPSTREAM_CALLS,
  rangeOf,
  READ_API_MAX_LIMIT,
  sessionPage,
  type Range,
  type UsagePeopleStore,
} from "./people.js";

/**
 * Usage page, Teams (docs/usage.md, "Teams"). Owner-only and behind both
 * SELFHOST_FEATURES=teams and usage_people: a team of one shows one person's
 * figures. Sessions come only from the read API's session list, where each
 * session carries its own user set, so every session read lands in exactly
 * one row and the rows sum to the total.
 */
export const TEAMS_AUDIT_ACTION = "usage.teams.viewed";
const TEAMS_CACHE_MS = 5 * 60_000;
const TEAMS_CACHE_ENTRIES = 200;

/**
 * A user-set bucket of sessions. Wider than the session-list path needs, so a
 * per-user-set aggregate can be added later without changing the rule.
 */
export type Bucket =
  | { kind: "users"; userIds: string[]; sessions: number; lastSessionAt: string | null }
  | { kind: "sharedCount"; users: number; sessions: number }
  | { kind: "other"; sessions: number }
  | { kind: "unattributed"; sessions: number };

export type TeamInfo = { teamId: string; name: string; archived: boolean; members: number };

export type TeamsRow =
  | {
    kind: "team"; teamId: string; name: string; archived: boolean; members: number; activeUsers: number;
    sessions: number | null; searches: number; lastSessionAt: string | null; spend: null;
  }
  | { kind: "crossTeam"; teamIds: Array<string | null>; sessions: number; spend: null }
  | { kind: "noTeam"; activeUsers: number; sessions: number | null; searches: number; spend: null }
  | { kind: "unattributed"; sessions: number | null; spend: null }
  | { kind: "notResolved"; sessions: number | null; spend: null };

type TeamRow = Extract<TeamsRow, { kind: "team" }>;

const teamIdsKey = (ids: Array<string | null>) => JSON.stringify(ids);

function sortTeamIds(ids: Iterable<string | null>): Array<string | null> {
  const unique = [...new Set(ids)];
  const named = unique.filter((id): id is string => id !== null).sort();
  return unique.includes(null) ? [...named, null] : named;
}

/**
 * Pure: groups buckets into rows. `buckets` null means the read API could not
 * be read, so session figures are null and searches are still served.
 * `teamOf` holds only users who resolved to a team; anyone else has none.
 */
export function groupTeamRows(input: {
  buckets: Bucket[] | null;
  teamOf: ReadonlyMap<string, string>;
  teams: TeamInfo[];
  searches?: ReadonlyMap<string, number>;
  currentMembers?: ReadonlySet<string>;
}): { rows: TeamsRow[]; total: { sessions: number | null; searches: number } } {
  const read = input.buckets !== null;
  const known = new Map(input.teams.map((team) => [team.teamId, team]));
  // A team id outside the given teams cannot be shown, so it counts as no team.
  const teamOf = (userId: string): string | null => {
    const teamId = input.teamOf.get(userId);
    return teamId !== undefined && known.has(teamId) ? teamId : null;
  };
  type Tally = { sessions: number; searches: number; active: Set<string>; lastSessionAt: string | null };
  const tally = (): Tally => ({ sessions: 0, searches: 0, active: new Set(), lastSessionAt: null });
  const byTeam = new Map(input.teams.map((team) => [team.teamId, tally()]));
  const noTeam = tally();
  const cross = new Map<string, { teamIds: Array<string | null>; sessions: number }>();
  let unattributed = 0;
  let notResolved = 0;

  for (const bucket of input.buckets ?? []) {
    if (bucket.kind === "unattributed") {
      unattributed += bucket.sessions;
      continue;
    }
    if (bucket.kind !== "users") {
      notResolved += bucket.sessions;
      continue;
    }
    const userIds = [...new Set(bucket.userIds)];
    if (userIds.length === 0) {
      unattributed += bucket.sessions;
      continue;
    }
    for (const userId of userIds) {
      const teamId = teamOf(userId);
      (teamId === null ? noTeam : byTeam.get(teamId)!).active.add(userId);
    }
    const teamIds = sortTeamIds(userIds.map(teamOf));
    if (teamIds.length === 1) {
      const row = teamIds[0] === null ? noTeam : byTeam.get(teamIds[0]!)!;
      row.sessions += bucket.sessions;
      row.lastSessionAt = newest(row.lastSessionAt, bucket.lastSessionAt);
      continue;
    }
    const key = teamIdsKey(teamIds);
    const row = cross.get(key) ?? { teamIds, sessions: 0 };
    row.sessions += bucket.sessions;
    cross.set(key, row);
  }

  for (const [userId, searches] of input.searches ?? []) {
    const teamId = teamOf(userId);
    if (teamId !== null) {
      const row = byTeam.get(teamId)!;
      row.searches += searches;
      row.active.add(userId);
      continue;
    }
    noTeam.searches += searches;
    // A person who left without a team is not shown as an active no-team user.
    if (input.currentMembers?.has(userId)) noTeam.active.add(userId);
  }

  const inCross = new Set([...cross.values()].flatMap((row) => row.teamIds));
  const teamRows = input.teams.flatMap((team): TeamRow[] => {
    const row = byTeam.get(team.teamId)!;
    if (team.archived && row.sessions === 0 && row.searches === 0 && !inCross.has(team.teamId)) return [];
    return [{
      kind: "team", teamId: team.teamId, name: team.name, archived: team.archived, members: team.members,
      activeUsers: row.active.size, sessions: read ? row.sessions : null, searches: row.searches,
      lastSessionAt: read ? row.lastSessionAt : null, spend: null,
    }];
  }).sort((a, b) => (b.sessions ?? 0) - (a.sessions ?? 0) || a.name.localeCompare(b.name) || a.teamId.localeCompare(b.teamId));
  const crossRows = [...cross.entries()]
    .sort((a, b) => b[1].sessions - a[1].sessions || a[0].localeCompare(b[0]))
    .map(([, row]): TeamsRow => ({ kind: "crossTeam", teamIds: row.teamIds, sessions: row.sessions, spend: null }));
  const rows: TeamsRow[] = [
    ...teamRows,
    ...crossRows,
    { kind: "noTeam", activeUsers: noTeam.active.size, sessions: read ? noTeam.sessions : null, searches: noTeam.searches, spend: null },
    { kind: "unattributed", sessions: read ? unattributed : null, spend: null },
    { kind: "notResolved", sessions: read ? notResolved : null, spend: null },
  ];
  let sessions = 0;
  let searches = 0;
  for (const row of rows) {
    sessions += row.sessions ?? 0;
    if (row.kind === "team" || row.kind === "noTeam") searches += row.searches;
  }
  return { rows, total: { sessions: read ? sessions : null, searches } };
}

/**
 * Each user's team for a report, in one query (docs/usage.md, "Teams"): the
 * window open at `teamAsOf`, else the one that closed last inside
 * [rangeStart, teamAsOf], else none. Users absent from the map have no team.
 * `teamAsOf` comes from the application clock while assignment windows are
 * stamped by the database clock, so a change made within the difference
 * between the two clocks just before a request counts from the next request.
 */
export async function resolveTeams(database: Database, organizationId: string, rangeStart: string, teamAsOf: string): Promise<Map<string, string>> {
  const result = await database.query<{ user_id: string; team_id: string }>(
    `SELECT DISTINCT ON (user_id) user_id::text AS user_id, team_id::text AS team_id
       FROM organization_team_assignments
      WHERE organization_id = $1
        AND ((starts_at <= $2::timestamptz AND (ends_at IS NULL OR ends_at > $2::timestamptz))
          OR (ends_at >= $3::timestamptz AND ends_at <= $2::timestamptz))
      ORDER BY user_id, (ends_at IS NULL OR ends_at > $2::timestamptz) DESC, ends_at DESC`,
    [organizationId, teamAsOf, rangeStart],
  );
  return new Map(result.rows.map((row) => [row.user_id, row.team_id]));
}

async function organizationTeams(database: Database, organizationId: string): Promise<TeamInfo[]> {
  // members: open windows of current members, as on the Teams page.
  const result = await database.query<{ id: string; name: string; archived_at: Date | string | null; members: number | string }>(
    `SELECT t.id::text AS id, t.name, t.archived_at,
            (SELECT count(*)::int
               FROM organization_team_assignments a
               JOIN organization_memberships m
                 ON m.organization_id = a.organization_id AND m.user_id = a.user_id
              WHERE a.team_id = t.id AND a.ends_at IS NULL) AS members
       FROM organization_teams t
      WHERE t.organization_id = $1`,
    [organizationId],
  );
  return result.rows.map((row) => ({
    teamId: row.id, name: row.name, archived: row.archived_at !== null, members: Number(row.members),
  }));
}

type Sample = { buckets: Bucket[]; truncated: boolean };
const teamsCaches = new WeakMap<SelfhostConfig, Map<string, { expiresAt: number; value: Sample }>>();

/** Test hook: drop cached team samples for this configuration. */
export function forgetTeamsCache(config: SelfhostConfig): void {
  teamsCaches.delete(config);
}

/**
 * Reads session list pages under the People view's bounds. A session listed
 * twice for one workspace (a moved cursor) counts once; the same session id in
 * two workspaces counts in each, as in the People view. Throws when a read
 * fails, as the People view does.
 */
async function sampleSessions(config: SelfhostConfig, identities: HistoryIdentity[], range: Range): Promise<Sample> {
  const seen = new Set<string>();
  const buckets: Bucket[] = [];
  const deadline = Date.now() + PEOPLE_BUDGET_MS;
  let calls = 0;
  let truncated = false;
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
      let cursor: string | undefined;
      for (;;) {
        const page = await call(() => sessionPage(config, identity, range, { limit: READ_API_MAX_LIMIT, cursor }));
        for (const session of page.sessions) {
          const key = JSON.stringify([session.workspaceId, session.source, session.sessionId]);
          if (seen.has(key)) continue;
          seen.add(key);
          const userIds = [...new Set(session.userIds)];
          buckets.push(userIds.length === 0
            ? { kind: "unattributed", sessions: 1 }
            : { kind: "users", userIds, sessions: 1, lastSessionAt: session.lastTs });
        }
        if (!page.nextCursor) break;
        cursor = page.nextCursor;
      }
    }
  } catch (error) {
    if (!(error instanceof BudgetExhausted)) throw error;
    truncated = true;
  }
  return { buckets, truncated };
}

async function cachedSample(config: SelfhostConfig, identities: HistoryIdentity[], range: Range, key: string): Promise<Sample> {
  let cache = teamsCaches.get(config);
  if (!cache) {
    cache = new Map();
    teamsCaches.set(config, cache);
  }
  const hit = cache.get(key);
  if (hit && hit.expiresAt > Date.now()) return hit.value;
  const value = await sampleSessions(config, identities, range);
  if (cache.size >= TEAMS_CACHE_ENTRIES) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(key, { expiresAt: Date.now() + TEAMS_CACHE_MS, value });
  return value;
}

export async function teamsReport(input: {
  config: SelfhostConfig;
  store: ControlPlaneStore;
  people: UsagePeopleStore;
  organizationId: string;
  owner: { userId: string; token: string; readerKind: ReaderKind };
  days: number;
  now: Date;
}) {
  const range = rangeOf(input.days, input.now);
  const teamAsOf = range.lastTsBefore;
  const database = input.store.database;
  const teams = await organizationTeams(database, input.organizationId);
  const teamOf = await resolveTeams(database, input.organizationId, range.lastTsAfter, teamAsOf);
  const counters = await input.people.read(input.organizationId, range.from, range.to);
  const currentMembers = new Set((await input.store.listMemberships(input.organizationId))
    .flatMap((member) => typeof member.userId === "string" ? [member.userId] : []));
  const identities = await ownerIdentities(input.store, input.organizationId, input.owner);
  let sample: Sample | null = null;
  try {
    sample = await cachedSample(input.config, identities, range, JSON.stringify([
      input.organizationId, input.owner.userId, range.days, range.to, identities.map((i) => i.workspaceId),
    ]));
  } catch {
    sample = null;
  }
  const grouped = groupTeamRows({
    buckets: sample?.buckets ?? null,
    teamOf,
    teams,
    searches: new Map([...counters].map(([userId, counted]) => [userId, counted.searches])),
    currentMembers,
  });
  return {
    range: { days: range.days, from: range.from, to: range.to },
    teamAsOf,
    rows: grouped.rows,
    total: grouped.total,
    source: sample ? "sample" as const : null,
    // Lower bounds: not every session in the range was read within the bounds.
    truncated: sample?.truncated ?? false,
    unavailable: sample ? ["spend"] : ["sessions", "spend"],
  };
}

export async function recordTeamsView(database: Database, input: { organizationId: string; viewerUserId: string; days: number }): Promise<void> {
  await recordAudit(database, {
    organizationId: input.organizationId,
    actor: { kind: "user", userId: input.viewerUserId },
    action: TEAMS_AUDIT_ACTION,
    target: `days:${input.days}`,
  });
}

export async function teamsAudit(database: Database, store: ControlPlaneStore, organizationId: string) {
  const result = await database.query<{ actor_id: string | null; target: string | null; created_at: Date | string }>(
    `SELECT actor_id, target, created_at FROM admin_audit_events
      WHERE organization_id = $1 AND action = $2 ORDER BY created_at DESC LIMIT 200`,
    [organizationId, TEAMS_AUDIT_ACTION],
  );
  const names = new Map((await store.listMemberships(organizationId))
    .map((row) => [String(row.userId), typeof row.name === "string" ? row.name : null]));
  return result.rows.map((row) => {
    const match = /^days:(\d+)$/.exec(row.target ?? "");
    return {
      viewerUserId: row.actor_id,
      viewerName: row.actor_id ? names.get(row.actor_id) ?? null : null,
      days: match ? Number(match[1]) : null,
      createdAt: new Date(row.created_at).toISOString(),
    };
  });
}
