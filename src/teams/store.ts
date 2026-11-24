import { randomUUID } from "node:crypto";
import { recordAudit, type AuditActor } from "../admin/audit.js";
import type { Database, SqlExecutor } from "../database.js";

/**
 * Organization teams (docs/teams.md): flat, organization-level groups. A
 * person has at most one current team per organization; an assignment is a
 * window [starts_at, ends_at). Assign, unassign and member removal hold the
 * person's membership row lock (removal deletes that row), so one person's
 * windows in one organization never overlap. Assign and unassign hold the team
 * row lock shared; archive holds it exclusively and locks each open window row
 * as it closes it. A window is only ever closed under its own row lock, and
 * one that would end at or before its start is deleted instead.
 */

export const TEAM_NAME_MAX = 80;

export type Team = {
  id: string;
  name: string;
  memberCount: number;
  archivedAt: string | null;
  createdAt: string;
  updatedAt: string;
};

export type TeamAssignment = { userId: string; teamId: string; startsAt: string };

/** A refusal the routes answer as `{ error: code, message }` with `status`. */
export class TeamsError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const teamNotFound = () => new TeamsError(404, "team_not_found", "Team not found");
const teamArchived = () => new TeamsError(409, "team_archived", "The team is archived");
const nameTaken = () => new TeamsError(409, "team_name_taken", "A team with this name already exists");

/**
 * Trimmed; 1..80 characters (code points, as Postgres char_length counts); no
 * C0 control character or DEL left after trimming (Postgres refuses NUL).
 */
export function teamName(value: unknown): string {
  const name = typeof value === "string" ? value.trim() : "";
  const length = [...name].length;
  if (length < 1 || length > TEAM_NAME_MAX) {
    throw new TeamsError(400, "invalid_request", `name must be a string of 1 to ${TEAM_NAME_MAX} characters`);
  }
  if (/[\u0000-\u001f\u007f]/.test(name)) {
    throw new TeamsError(400, "invalid_request", "name must not contain control characters");
  }
  return name;
}

type TeamRow = {
  id: string;
  name: string;
  archived_at: Date | string | null;
  created_at: Date | string;
  updated_at: Date | string;
  member_count: number | string;
};

const iso = (value: Date | string): string => new Date(value).toISOString();

// memberCount: open assignments whose user is still a member.
const TEAM_SELECT = `
  SELECT t.id, t.name, t.archived_at, t.created_at, t.updated_at,
         (SELECT count(*)::int
            FROM organization_team_assignments a
            JOIN organization_memberships m
              ON m.organization_id = a.organization_id AND m.user_id = a.user_id
           WHERE a.team_id = t.id AND a.ends_at IS NULL) AS member_count
    FROM organization_teams t`;

function toTeam(row: TeamRow): Team {
  return {
    id: row.id,
    name: row.name,
    memberCount: Number(row.member_count),
    archivedAt: row.archived_at === null ? null : iso(row.archived_at),
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

async function readTeam(executor: SqlExecutor, organizationId: string, teamId: string): Promise<Team> {
  const result = await executor.query<TeamRow>(
    `${TEAM_SELECT} WHERE t.id = $1 AND t.organization_id = $2`,
    [teamId, organizationId],
  );
  if (!result.rows[0]) throw teamNotFound();
  return toTeam(result.rows[0]);
}

async function uniqueName<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (error) {
    if ((error as { code?: string }).code === "23505") throw nameTaken();
    throw error;
  }
}

/**
 * The instant a window of this person closes or opens at: the clock, read
 * after the caller's locks, and never before the person's latest closed window
 * ended. Text keeps microsecond precision through the round trip.
 */
async function windowInstant(tx: SqlExecutor, organizationId: string, userId: string): Promise<string> {
  const result = await tx.query<{ at: string }>(
    `SELECT GREATEST(clock_timestamp(), (
              SELECT max(ends_at) FROM organization_team_assignments
               WHERE organization_id = $1 AND user_id = $2
            ))::text AS at`,
    [organizationId, userId],
  );
  return result.rows[0]!.at;
}

/**
 * Closes one open window at `at`. A window that would end at or before its
 * start (CHECK ends_at > starts_at) is deleted instead.
 */
async function closeWindow(tx: SqlExecutor, assignmentId: string, at: string): Promise<void> {
  await tx.query(
    `DELETE FROM organization_team_assignments
      WHERE id = $1 AND ends_at IS NULL AND starts_at >= $2::timestamptz`,
    [assignmentId, at],
  );
  await tx.query(
    `UPDATE organization_team_assignments SET ends_at = $2::timestamptz
      WHERE id = $1 AND ends_at IS NULL`,
    [assignmentId, at],
  );
}

type OpenRow = { id: string; team_id: string; starts_at: Date | string };

async function lockOpenWindow(tx: SqlExecutor, organizationId: string, userId: string): Promise<OpenRow | undefined> {
  const result = await tx.query<OpenRow>(
    `SELECT id, team_id, starts_at FROM organization_team_assignments
      WHERE organization_id = $1 AND user_id = $2 AND ends_at IS NULL
      FOR UPDATE`,
    [organizationId, userId],
  );
  return result.rows[0];
}

/**
 * Member removal: closes the person's open window in the removal transaction
 * (store.deleteMembership), whether or not the teams feature is on. Closed
 * windows stay until the user or the organization is deleted.
 */
export async function closeOpenTeamAssignmentInTx(
  tx: SqlExecutor,
  member: { organizationId: string; userId: string },
): Promise<void> {
  const open = await lockOpenWindow(tx, member.organizationId, member.userId);
  if (!open) return;
  await closeWindow(tx, open.id, await windowInstant(tx, member.organizationId, member.userId));
}

export class OrganizationTeams {
  constructor(private readonly database: Database) {}

  /** Live teams by lower(name), then id; with `archived`, archived teams follow. */
  async list(organizationId: string, archived: boolean): Promise<Team[]> {
    const result = await this.database.query<TeamRow>(
      `${TEAM_SELECT}
        WHERE t.organization_id = $1 AND ($2::boolean OR t.archived_at IS NULL)
        ORDER BY (t.archived_at IS NOT NULL), lower(t.name), t.id`,
      [organizationId, archived],
    );
    return result.rows.map(toTeam);
  }

  async create(input: { organizationId: string; name: string; actor: AuditActor }): Promise<Team> {
    return this.database.transaction(async (tx) => {
      const id = randomUUID();
      await uniqueName(() => tx.query(
        `INSERT INTO organization_teams (id, organization_id, name) VALUES ($1, $2, $3)`,
        [id, input.organizationId, input.name],
      ));
      await recordAudit(tx, { organizationId: input.organizationId, actor: input.actor, action: "team.create", target: id });
      return readTeam(tx, input.organizationId, id);
    });
  }

  /** The exact current name is a no-op (no write, no audit row); a case-only change renames. */
  async rename(input: { organizationId: string; teamId: string; name: string; actor: AuditActor }): Promise<Team> {
    if (!UUID.test(input.teamId)) throw teamNotFound();
    return this.database.transaction(async (tx) => {
      const found = await tx.query<{ name: string; archived_at: Date | string | null }>(
        `SELECT name, archived_at FROM organization_teams
          WHERE id = $1 AND organization_id = $2 FOR UPDATE`,
        [input.teamId, input.organizationId],
      );
      const team = found.rows[0];
      if (!team) throw teamNotFound();
      if (team.archived_at !== null) throw teamArchived();
      if (team.name === input.name) return readTeam(tx, input.organizationId, input.teamId);
      const taken = await tx.query(
        `SELECT 1 FROM organization_teams
          WHERE organization_id = $1 AND archived_at IS NULL AND lower(name) = lower($2) AND id <> $3`,
        [input.organizationId, input.name, input.teamId],
      );
      if (taken.rows.length > 0) throw nameTaken();
      await uniqueName(() => tx.query(
        `UPDATE organization_teams SET name = $3, updated_at = now()
          WHERE id = $1 AND organization_id = $2`,
        [input.teamId, input.organizationId, input.name],
      ));
      await recordAudit(tx, { organizationId: input.organizationId, actor: input.actor, action: "team.rename", target: input.teamId });
      return readTeam(tx, input.organizationId, input.teamId);
    });
  }

  /** Archives the team and closes its open windows. Already archived: unassigned 0, no audit row. */
  async archive(input: { organizationId: string; teamId: string; actor: AuditActor }): Promise<{ team: Team; unassigned: number }> {
    if (!UUID.test(input.teamId)) throw teamNotFound();
    return this.database.transaction(async (tx) => {
      const found = await tx.query<{ archived_at: Date | string | null }>(
        `SELECT archived_at FROM organization_teams
          WHERE id = $1 AND organization_id = $2 FOR UPDATE`,
        [input.teamId, input.organizationId],
      );
      if (!found.rows[0]) throw teamNotFound();
      if (found.rows[0].archived_at !== null) {
        return { team: await readTeam(tx, input.organizationId, input.teamId), unassigned: 0 };
      }
      const at = (await tx.query<{ at: string }>("SELECT clock_timestamp()::text AS at")).rows[0]!.at;
      const removed = await tx.query(
        `DELETE FROM organization_team_assignments
          WHERE team_id = $1 AND ends_at IS NULL AND starts_at >= $2::timestamptz
          RETURNING id`,
        [input.teamId, at],
      );
      const closed = await tx.query(
        `UPDATE organization_team_assignments SET ends_at = $2::timestamptz
          WHERE team_id = $1 AND ends_at IS NULL
          RETURNING id`,
        [input.teamId, at],
      );
      await tx.query(
        `UPDATE organization_teams SET archived_at = now(), updated_at = now()
          WHERE id = $1 AND organization_id = $2`,
        [input.teamId, input.organizationId],
      );
      await recordAudit(tx, { organizationId: input.organizationId, actor: input.actor, action: "team.archive", target: input.teamId });
      return {
        team: await readTeam(tx, input.organizationId, input.teamId),
        unassigned: removed.rows.length + closed.rows.length,
      };
    });
  }

  /**
   * Puts a current member in the team, closing their current window first.
   * Already in this team: nothing is written and previousTeamId is teamId.
   */
  async assign(input: {
    organizationId: string;
    teamId: string;
    userId: string;
    actor: AuditActor;
  }): Promise<{ assignment: TeamAssignment; previousTeamId: string | null }> {
    if (!UUID.test(input.teamId)) throw teamNotFound();
    const { organizationId, teamId, userId } = input;
    return this.database.transaction(async (tx) => {
      // Lock order: membership row, team, open window (archive takes the team,
      // then windows; removal takes the membership row, then the window).
      const member = UUID.test(userId)
        ? (await tx.query(
          `SELECT user_id FROM organization_memberships
            WHERE organization_id = $1 AND user_id = $2 FOR UPDATE`,
          [organizationId, userId],
        )).rows.length > 0
        : false;
      const team = (await tx.query<{ archived_at: Date | string | null }>(
        `SELECT archived_at FROM organization_teams
          WHERE id = $1 AND organization_id = $2 FOR SHARE`,
        [teamId, organizationId],
      )).rows[0];
      if (!team) throw teamNotFound();
      if (!member) throw new TeamsError(404, "membership_not_found", "This person is not a member of the organization");
      if (team.archived_at !== null) throw teamArchived();
      const open = await lockOpenWindow(tx, organizationId, userId);
      if (open?.team_id === teamId) {
        return { assignment: { userId, teamId, startsAt: iso(open.starts_at) }, previousTeamId: teamId };
      }
      const at = await windowInstant(tx, organizationId, userId);
      if (open) await closeWindow(tx, open.id, at);
      const inserted = await tx.query<{ starts_at: Date | string }>(
        `INSERT INTO organization_team_assignments (id, organization_id, team_id, user_id, starts_at)
         VALUES ($1, $2, $3, $4, $5::timestamptz)
         RETURNING starts_at`,
        [randomUUID(), organizationId, teamId, userId, at],
      );
      await recordAudit(tx, { organizationId, actor: input.actor, action: "team.assign", target: `${userId} team=${teamId}` });
      return {
        assignment: { userId, teamId, startsAt: iso(inserted.rows[0]!.starts_at) },
        previousTeamId: open?.team_id ?? null,
      };
    });
  }

  /** Closes the person's window in this team; false (nothing written) when they are not in it. */
  async unassign(input: { organizationId: string; teamId: string; userId: string; actor: AuditActor }): Promise<boolean> {
    if (!UUID.test(input.teamId)) throw teamNotFound();
    const { organizationId, teamId, userId } = input;
    return this.database.transaction(async (tx) => {
      if (UUID.test(userId)) {
        await tx.query(
          `SELECT user_id FROM organization_memberships
            WHERE organization_id = $1 AND user_id = $2 FOR UPDATE`,
          [organizationId, userId],
        );
      }
      const team = await tx.query(
        `SELECT 1 FROM organization_teams WHERE id = $1 AND organization_id = $2 FOR SHARE`,
        [teamId, organizationId],
      );
      if (team.rows.length === 0) throw teamNotFound();
      if (!UUID.test(userId)) return false;
      const open = await lockOpenWindow(tx, organizationId, userId);
      if (!open || open.team_id !== teamId) return false;
      await closeWindow(tx, open.id, await windowInstant(tx, organizationId, userId));
      await recordAudit(tx, { organizationId, actor: input.actor, action: "team.unassign", target: `${userId} team=${teamId}` });
      return true;
    });
  }
}
