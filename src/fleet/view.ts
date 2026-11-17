import type { SqlExecutor } from "../database.js";
import { PERSON_ONLY_KEYS, type WorkspacePolicy } from "../workspace-policy.js";

/**
 * Fleet view (docs/fleet.md): every member of an organization with the
 * Agent Relay Desktop machines signed in for them, what each machine last
 * reported (token_sessions client telemetry, migration 0075) and whether it
 * runs the current workspace policy. Owners and admins read it.
 *
 * A machine is one device-client token session: the same rows that record
 * client telemetry (recordsClientTelemetry). Refresh rotates a session row in
 * place, so one row stays one machine sign-in.
 */
export const FLEET_AUDIT_ACTION = "fleet.viewed";
/** Members per page. */
export const FLEET_PAGE_SIZE = 200;
/** Revoked or expired sessions stay listed this long after they ended. */
export const FLEET_ENDED_WINDOW_DAYS = 30;
const DAY_MS = 86_400_000;

export class FleetInputError extends Error {}

export type PolicyMatch = "current" | "stale" | "unknown" | "mismatch";
export type MachineStatus = "active" | "revoked" | "expired";

/**
 * Whether a machine runs the current workspace policy.
 * - `unknown`: the session never reported an applied revision;
 * - `current` / `stale`: the reported revision equals / differs from the
 *   workspace revision;
 * - `mismatch` overrides either when the organization sets a widening value
 *   on a person-only key and the session is not managed: such a value never
 *   applies there, so the client reports the key as mismatched
 *   (docs/workspace-policy.md, "Consent").
 */
export function policyMatchFor(input: {
  applied: number | null;
  current: number;
  managed: boolean;
  lockedPersonOnlyKey: boolean;
}): PolicyMatch {
  if (input.applied === null) return "unknown";
  if (input.lockedPersonOnlyKey && !input.managed) return "mismatch";
  return input.applied === input.current ? "current" : "stale";
}

/**
 * Whether the policy locks or defaults a person-only key to a widening value
 * (`true`, or a non-empty list). Narrowing values apply on every session, so
 * they never cause a mismatch. Consent is not consulted: an unmanaged session
 * cannot apply the value whatever consent names.
 */
export function lockedPersonOnlyKey(policy: WorkspacePolicy): boolean {
  for (const name of ["spawn", "join", "delivery", "analytics"] as const) {
    const section = policy.sections[name];
    for (const tier of [section.locked, section.defaults]) {
      for (const key of PERSON_ONLY_KEYS) {
        if (!Object.hasOwn(tier, key)) continue;
        const value = tier[key];
        if (value === true || (Array.isArray(value) && value.length > 0)) return true;
      }
    }
  }
  return false;
}

/** Position after the last member of a page: members order by email, then user id. */
export type FleetCursor = { email: string; userId: string };

export function encodeFleetCursor(cursor: FleetCursor): string {
  return Buffer.from(JSON.stringify({ after: [cursor.email, cursor.userId] }), "utf8").toString("base64url");
}

export function decodeFleetCursor(raw: string): FleetCursor {
  if (raw.length > 0 && raw.length <= 2048 && /^[A-Za-z0-9_-]+$/.test(raw)) {
    try {
      const value: unknown = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
      if (typeof value === "object" && value !== null && !Array.isArray(value) &&
        Object.keys(value).length === 1) {
        const after = (value as { after?: unknown }).after;
        if (Array.isArray(after) && after.length === 2 &&
          typeof after[0] === "string" && typeof after[1] === "string" && after[1].length > 0) {
          return { email: after[0], userId: after[1] };
        }
      }
    } catch {
      // fall through
    }
  }
  throw new FleetInputError("Invalid cursor");
}

/** Per-member usage, as the People report computes it. */
export type FleetUsage = {
  sessionsUploaded: number | null;
  lastSessionAt: string | null;
  topProjects: Array<{ name: string; sessions: number }>;
};

export type FleetUsageInput = {
  byUser: Map<string, FleetUsage>;
  unavailable: string[];
  truncated: boolean;
} | null;

type MemberRow = { user_id: string; email: string; name: string | null; role: string };

type MachineRow = {
  id: string;
  user_id: string;
  desktop_host_name: string | null;
  client_version: string | null;
  client_platform: string | null;
  policy_revision_applied: number | string | null;
  key_id: string | null;
  key_label: string | null;
  managed: boolean | null;
  last_seen_at: Date | string;
  revoked_at: Date | string | null;
  refresh_token_expires_at: Date | string;
};

function iso(value: Date | string): string {
  return (value instanceof Date ? value : new Date(value)).toISOString();
}

/**
 * The device-flow session predicate (alias `s`): Desktop's device-client
 * sessions, the rows recordsClientTelemetry writes to. Browser account
 * sessions, Desktop handoff rows and MCP desktop credentials (no
 * rth:acquire) are left out.
 */
export const DEVICE_SESSION_SQL =
  `'rth:acquire' = ANY(s.scopes) AND NOT ('account' = ANY(s.scopes)) AND s.desktop_exchange_challenge IS NULL`;

export async function fleetView(input: {
  executor: SqlExecutor;
  organizationId: string;
  policy: WorkspacePolicy;
  days: number;
  range: { from: string; to: string };
  after: FleetCursor | null;
  usage: FleetUsageInput;
  now: Date;
}) {
  const members = (await input.executor.query<MemberRow>(
    `SELECT u.id AS user_id, u.email, u.name, m.role
       FROM organization_memberships m
       JOIN users u ON u.id = m.user_id
      WHERE m.organization_id = $1
        AND ($2::text IS NULL OR (u.email, u.id::text) > ($2::text, $3::text))
      ORDER BY u.email, u.id::text
      LIMIT $4`,
    [input.organizationId, input.after?.email ?? null, input.after?.userId ?? null, FLEET_PAGE_SIZE + 1],
  )).rows;
  const more = members.length > FLEET_PAGE_SIZE;
  const page = more ? members.slice(0, FLEET_PAGE_SIZE) : members;
  const endedSince = new Date(input.now.getTime() - FLEET_ENDED_WINDOW_DAYS * DAY_MS);
  // One query per page: the provisioning key (managed, enrolledVia) is joined in.
  const machines = page.length === 0 ? [] : (await input.executor.query<MachineRow>(
    `SELECT s.id, s.user_id, s.desktop_host_name, s.client_version, s.client_platform,
            s.policy_revision_applied,
            ek.id AS key_id, ek.label AS key_label,
            COALESCE(ek.policy_consent = 'admin', false) AS managed,
            COALESCE(s.policy_seen_at, s.last_refreshed_at, s.created_at) AS last_seen_at,
            s.revoked_at, s.refresh_token_expires_at
       FROM token_sessions s
       LEFT JOIN workspace_api_tokens ek
         ON ek.id = s.provisioned_by_token_id AND ek.purpose = 'desktop-enrollment'
      WHERE s.organization_id = $1
        AND s.user_id = ANY($2::uuid[])
        AND ${DEVICE_SESSION_SQL}
        AND COALESCE(s.revoked_at, s.refresh_token_expires_at) > $3
      ORDER BY last_seen_at DESC, s.id`,
    [input.organizationId, page.map((member) => member.user_id), endedSince],
  )).rows;
  const current = input.policy.revision;
  const locked = lockedPersonOnlyKey(input.policy);
  const totals = {
    members: page.length,
    machines: 0,
    managed: 0,
    policy: { current: 0, stale: 0, unknown: 0, mismatch: 0 },
    clientVersions: [] as Array<{ version: string | null; machines: number }>,
  };
  const versions = new Map<string | null, number>();
  const byUser = new Map<string, ReturnType<typeof machineOf>[]>();
  function machineOf(row: MachineRow) {
    const applied = row.policy_revision_applied === null ? null : Number(row.policy_revision_applied);
    const managed = row.managed === true;
    const status: MachineStatus = row.revoked_at !== null
      ? "revoked"
      : new Date(row.refresh_token_expires_at).getTime() <= input.now.getTime() ? "expired" : "active";
    return {
      sessionId: row.id,
      hostName: row.desktop_host_name,
      clientVersion: row.client_version,
      platform: row.client_platform,
      enrolledVia: row.key_id === null ? null : { keyId: row.key_id, label: row.key_label },
      policyRevision: applied,
      policyMatch: policyMatchFor({ applied, current, managed, lockedPersonOnlyKey: locked }),
      managed,
      lastSeenAt: iso(row.last_seen_at),
      status,
    };
  }
  for (const row of machines) {
    const machine = machineOf(row);
    const list = byUser.get(row.user_id) ?? [];
    list.push(machine);
    byUser.set(row.user_id, list);
    totals.machines += 1;
    if (machine.managed) totals.managed += 1;
    totals.policy[machine.policyMatch] += 1;
    versions.set(machine.clientVersion, (versions.get(machine.clientVersion) ?? 0) + 1);
  }
  totals.clientVersions = [...versions.entries()]
    .map(([version, count]) => ({ version, machines: count }))
    .sort((a, b) => b.machines - a.machines || String(a.version ?? "").localeCompare(String(b.version ?? "")));
  const last = page[page.length - 1];
  return {
    policy_revision: current,
    range: { days: input.days, from: input.range.from, to: input.range.to },
    totals,
    members: page.map((member) => ({
      user: { id: member.user_id, email: member.email, name: member.name },
      role: member.role,
      machines: byUser.get(member.user_id) ?? [],
      usage: input.usage === null ? null : input.usage.byUser.get(member.user_id) ?? {
        sessionsUploaded: input.usage.unavailable.length > 0 ? null : 0,
        lastSessionAt: null,
        topProjects: [],
      },
    })),
    usage_unavailable: input.usage === null ? ["usage"] : input.usage.unavailable,
    truncated: input.usage?.truncated ?? false,
    next_cursor: more && last ? encodeFleetCursor({ email: last.email, userId: last.user_id }) : null,
  };
}
