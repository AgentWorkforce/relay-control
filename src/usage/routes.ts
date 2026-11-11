import type { SelfhostConfig } from "../config.js";
import type { ControlPlaneStore } from "../store.js";
import { isRecord, readWorkspaceHistory, type HistoryIdentity } from "../sessions/history.js";
import type { UsageStore } from "./store.js";

/**
 * GET /api/v1/organizations/{org}/usage?days=7|30|90 (docs/usage.md).
 *
 * Owner-only, counts only. Sources:
 * - activeUsers, searches: Control's own daily counters (UsageStore);
 * - sessionsUploaded: the session directory, through the read API's
 *   /v1/sessions/activity, summed over the organization's workspaces;
 * - summaries: the read API's /v1/sessions/summaries/activity when it serves
 *   it; otherwise null and listed in `unavailable`.
 * A source that cannot be read is reported as unavailable (null), never as 0.
 */
export const USAGE_RANGES = [7, 30, 90] as const;
export const DEFAULT_USAGE_DAYS = 30;
const DAY_MS = 86_400_000;

export type UsageMetric = "activeUsers" | "sessionsUploaded" | "searches" | "summaries";

export type UsageDayReport = Record<UsageMetric, number | null> & { date: string };

export type UsageReport = {
  range: { days: number; from: string; to: string };
  totals: Record<UsageMetric, number | null>;
  days: UsageDayReport[];
  unavailable: UsageMetric[];
};

export class UsageRangeError extends Error {
  constructor() {
    super(`days must be one of ${USAGE_RANGES.join(", ")}`);
  }
}

/** Parses the strict query: only `days`, once, one of 7/30/90. */
export function usageDays(url: URL): number {
  for (const name of new Set(url.searchParams.keys())) {
    if (name !== "days" || url.searchParams.getAll(name).length !== 1) throw new UsageRangeError();
  }
  const raw = url.searchParams.get("days");
  if (raw === null) return DEFAULT_USAGE_DAYS;
  const value = /^\d{1,3}$/.test(raw) ? Number(raw) : Number.NaN;
  if (!(USAGE_RANGES as readonly number[]).includes(value)) throw new UsageRangeError();
  return value;
}

/** The `days` UTC days ending today, oldest first. */
export function usageDates(days: number, now: Date): string[] {
  const today = Date.parse(now.toISOString().slice(0, 10));
  return Array.from({ length: days }, (_, index) =>
    new Date(today - (days - 1 - index) * DAY_MS).toISOString().slice(0, 10));
}

function isCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

/**
 * Per-day totals from one read API activity-style path, summed over the
 * workspaces. Null when any workspace read fails or the backend does not
 * serve the path (404/501), so a partial sum is never shown as the total.
 */
async function historyDaily(
  config: SelfhostConfig,
  identities: HistoryIdentity[],
  path: string,
  dates: string[],
  now: Date,
): Promise<Map<string, number> | null> {
  const totals = new Map(dates.map((date) => [date, 0]));
  const since = `${dates[0]}T00:00:00.000Z`;
  const until = new Date(Math.min(Date.parse(dates[dates.length - 1]!) + DAY_MS - 1, now.getTime())).toISOString();
  try {
    for (const identity of identities) {
      const read = await readWorkspaceHistory(config, identity, path, new URLSearchParams({ since, until }), {
        allowNotFound: true,
      });
      if (read.status !== "ok" || !Array.isArray(read.body.days)) return null;
      for (const row of read.body.days) {
        if (!isRecord(row) || typeof row.date !== "string" || !isCount(row.total)) return null;
        if (totals.has(row.date)) totals.set(row.date, totals.get(row.date)! + row.total);
      }
    }
  } catch {
    return null;
  }
  return totals;
}

export async function usageReport(input: {
  config: SelfhostConfig;
  store: ControlPlaneStore;
  usage: UsageStore;
  organizationId: string;
  owner: { userId: string; token: string };
  days: number;
  now: Date;
}): Promise<UsageReport> {
  const { config, store, usage, organizationId, owner, days, now } = input;
  const dates = usageDates(days, now);
  // Only workspaces the owner is a member of; the read API is asked for
  // exactly one workspace per read token.
  const identities: HistoryIdentity[] = [];
  for (const workspace of await store.listWorkspaces(organizationId)) {
    const workspaceId = String(workspace.id);
    if (!await store.workspaceForUser(workspaceId, owner.userId)) continue;
    identities.push({ userId: owner.userId, organizationId, workspaceId, callerToken: owner.token });
  }
  const [counters, sessions, summaries] = await Promise.all([
    usage.read(organizationId, dates),
    historyDaily(config, identities, "/v1/sessions/activity", dates, now),
    historyDaily(config, identities, "/v1/sessions/summaries/activity", dates, now),
  ]);
  const unavailable: UsageMetric[] = [];
  if (!sessions) unavailable.push("sessionsUploaded");
  if (!summaries) unavailable.push("summaries");
  const sum = (values: Map<string, number> | null) =>
    values ? [...values.values()].reduce((total, value) => total + value, 0) : null;
  return {
    range: { days, from: dates[0]!, to: dates[dates.length - 1]! },
    totals: {
      activeUsers: counters.activeUsers,
      sessionsUploaded: sum(sessions),
      searches: counters.days.reduce((total, entry) => total + entry.searches, 0),
      summaries: sum(summaries),
    },
    days: counters.days.map((entry) => ({
      date: entry.date,
      activeUsers: entry.activeUsers,
      sessionsUploaded: sessions ? sessions.get(entry.date)! : null,
      searches: entry.searches,
      summaries: summaries ? summaries.get(entry.date)! : null,
    })),
    unavailable,
  };
}
