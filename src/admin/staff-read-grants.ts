import { randomUUID } from "node:crypto";
import { hashSecret, opaqueToken } from "../crypto.js";
import type { Database, SqlExecutor } from "../database.js";
import { capturePolicyFromRow, type CapturePolicy } from "../capture-policy.js";
import { asciiDomain, emailDomain } from "../identity/config.js";
import type { Principal } from "../store.js";
import type { TenancyMode } from "../tenancy.js";
import { iso, recordAudit } from "./audit.js";

/**
 * Staff read grants (docs/staff-read-grants.md, migration 0061): a read-only,
 * sessions-only credential `sh_sr_` pinned to one workspace, minted by an
 * owner of the operator organization. Honoured only by the shared-sessions
 * MCP facade and by token introspection; every other bearer gate refuses it
 * by shape. The holder comes only from the grant row and the staff rule is
 * re-read on every use.
 */
export const STAFF_READ_GRANT_PREFIX = "sh_sr_";
export const STAFF_READ_GRANT_SCOPES: readonly string[] = ["rth:read"];
export const STAFF_READ_GRANT_MAX_DAYS = 90;
export const STAFF_READ_GRANT_REASON_MAX = 500;
const DAY_MS = 86_400_000;

export type StaffReadGrant = {
  id: string;
  workspaceId: string;
  organizationId: string;
  staffUserId: string;
  staffOrganizationId: string;
  reason: string;
  createdAt: string;
  expiresAt: string;
  revokedAt: string | null;
  revokedBy: string | null;
  lastUsedAt: string | null;
  status: "active" | "revoked" | "expired";
};

/** A live staff person: an owner of the operator organization who passes its domain rule. */
export type StaffPerson = { userId: string; email: string; name: string; operatorOrganizationId: string };

/** What MCP admission gets for a live grant: the pinned workspace and a principal built from the row. */
export type StaffReadGrantAdmission = {
  grant: StaffReadGrant;
  principal: Principal;
  workspace: {
    id: string;
    organizationId: string;
    name: string;
    relaycastWorkspaceId: string;
    relaycastApiKey: string;
    role: Principal["role"];
  };
};

export type StaffReadGrantIntrospection = {
  grantId: string;
  staffUserId: string;
  email: string;
  workspaceId: string;
  organizationId: string;
  cloudRelayWorkspaceId: string | null;
  relayhistoryOrigin: string | null;
  tokenHash: string;
  revoked: boolean;
  expired: boolean;
  staff: boolean;
  createdAt: Date;
  expiresAt: Date;
  capturePolicy: CapturePolicy;
};

type GrantRow = {
  id: string;
  workspace_id: string;
  organization_id: string;
  staff_user_id: string;
  staff_organization_id: string;
  reason: string;
  created_at: Date | string;
  expires_at: Date | string;
  revoked_at: Date | string | null;
  revoked_by: string | null;
  last_used_at: Date | string | null;
};

const GRANT_COLUMNS = `id, workspace_id, organization_id, staff_user_id, staff_organization_id, reason,
  created_at, expires_at, revoked_at, revoked_by, last_used_at`;

export class StaffReadGrantError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
    this.name = "StaffReadGrantError";
  }
}

function grantFrom(row: GrantRow, now: number = Date.now()): StaffReadGrant {
  const expiresAt = iso(row.expires_at);
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    organizationId: row.organization_id,
    staffUserId: row.staff_user_id,
    staffOrganizationId: row.staff_organization_id,
    reason: row.reason,
    createdAt: iso(row.created_at),
    expiresAt,
    revokedAt: row.revoked_at === null ? null : iso(row.revoked_at),
    revokedBy: row.revoked_by,
    lastUsedAt: row.last_used_at === null ? null : iso(row.last_used_at),
    status: row.revoked_at !== null ? "revoked" : Date.parse(expiresAt) <= now ? "expired" : "active",
  };
}

/** The public JSON shape: never any token material. */
export function grantJson(grant: StaffReadGrant): Record<string, unknown> {
  return {
    id: grant.id,
    workspace_id: grant.workspaceId,
    organization_id: grant.organizationId,
    staff_user_id: grant.staffUserId,
    staff_organization_id: grant.staffOrganizationId,
    reason: grant.reason,
    status: grant.status,
    created_at: grant.createdAt,
    expires_at: grant.expiresAt,
    revoked_at: grant.revokedAt,
    revoked_by: grant.revokedBy,
    last_used_at: grant.lastUsedAt,
  };
}

/** `{ reason, expires_in_days? }` from a request body, or a 400. */
export function parseMintRequest(body: Record<string, unknown>): { reason: string; expiresInDays: number } {
  const reason = typeof body.reason === "string" ? body.reason.trim() : "";
  if (!reason || reason.length > STAFF_READ_GRANT_REASON_MAX) {
    throw new StaffReadGrantError(400, "invalid_request",
      `reason must be a non-empty string of at most ${STAFF_READ_GRANT_REASON_MAX} characters`);
  }
  const days = body.expires_in_days ?? STAFF_READ_GRANT_MAX_DAYS;
  if (typeof days !== "number" || !Number.isInteger(days) || days < 1 || days > STAFF_READ_GRANT_MAX_DAYS) {
    throw new StaffReadGrantError(400, "invalid_request",
      `expires_in_days must be an integer from 1 to ${STAFF_READ_GRANT_MAX_DAYS}`);
  }
  return { reason, expiresInDays: days };
}

export class StaffReadGrants {
  constructor(
    private readonly database: Database,
    private readonly tenancy: TenancyMode,
    private readonly now: () => Date = () => new Date(),
  ) {}

  /**
   * The operator organization: the one recorded in installation_bootstrap in
   * multi tenancy, the only organization in single tenancy (none while a
   * single-tenancy database holds more than one).
   */
  async operatorOrganization(executor: SqlExecutor = this.database): Promise<string | null> {
    if (this.tenancy === "multi") {
      const result = await executor.query<{ organization_id: string | null }>(
        "SELECT organization_id FROM installation_bootstrap WHERE installation_slot = 1",
      );
      return result.rows[0]?.organization_id ?? null;
    }
    const result = await executor.query<{ id: string }>("SELECT id FROM organizations LIMIT 2");
    return result.rows.length === 1 ? result.rows[0]!.id : null;
  }

  /**
   * The staff rule, read live: an `owner` membership in the operator
   * organization and, when that organization has assigned domains, a primary
   * email on one of them. Null for everyone else.
   */
  async staff(userId: string, executor: SqlExecutor = this.database): Promise<StaffPerson | null> {
    const operator = await this.operatorOrganization(executor);
    if (!operator) return null;
    const result = await executor.query<{ email: string; name: string; domains: string[] }>(
      `SELECT u.email, u.name,
              COALESCE((SELECT array_agg(d.domain) FROM organization_domains d WHERE d.organization_id = m.organization_id),
                       ARRAY[]::text[]) AS domains
         FROM organization_memberships m
         JOIN users u ON u.id = m.user_id
        WHERE m.organization_id = $1 AND m.user_id = $2 AND m.role = 'owner'`,
      [operator, userId],
    );
    const row = result.rows[0];
    if (!row) return null;
    if (row.domains.length > 0) {
      const domain = asciiDomain(emailDomain(row.email));
      if (!domain || !row.domains.includes(domain)) return null;
    }
    return { userId, email: row.email, name: row.name, operatorOrganizationId: operator };
  }

  async list(workspaceId: string): Promise<StaffReadGrant[]> {
    const result = await this.database.query<GrantRow>(
      `SELECT ${GRANT_COLUMNS} FROM staff_read_grants WHERE workspace_id = $1 ORDER BY created_at DESC, id`,
      [workspaceId],
    );
    const now = this.now().getTime();
    return result.rows.map(row => grantFrom(row, now));
  }

  /** Writes the grant and its audit row in one transaction; the token is returned only here. */
  async mint(input: {
    workspaceId: string;
    organizationId: string;
    staff: StaffPerson;
    reason: string;
    expiresInDays: number;
  }): Promise<{ grant: StaffReadGrant; accessToken: string }> {
    const id = randomUUID();
    const accessToken = opaqueToken(STAFF_READ_GRANT_PREFIX);
    const createdAt = this.now();
    const expiresAt = new Date(createdAt.getTime() + input.expiresInDays * DAY_MS);
    const row = await this.database.transaction(async (tx) => {
      const inserted = await tx.query<GrantRow>(
        `INSERT INTO staff_read_grants
           (id, workspace_id, organization_id, staff_user_id, staff_organization_id, reason, token_hash, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         RETURNING ${GRANT_COLUMNS}`,
        [id, input.workspaceId, input.organizationId, input.staff.userId, input.staff.operatorOrganizationId,
          input.reason, hashSecret(accessToken), createdAt, expiresAt],
      );
      await recordAudit(tx, {
        organizationId: input.organizationId,
        workspaceId: input.workspaceId,
        actor: { kind: "user", userId: input.staff.userId },
        action: "staff_read_grant.minted",
        target: `${id} workspace ${input.workspaceId} (expires ${expiresAt.toISOString()})`,
      });
      return inserted.rows[0]!;
    });
    return { grant: grantFrom(row, createdAt.getTime()), accessToken };
  }

  /**
   * Revokes and audits once; repeating it returns the already-revoked grant
   * without a second audit row. Null when no such grant is on the workspace.
   */
  async revoke(workspaceId: string, grantId: string, userId: string): Promise<StaffReadGrant | null> {
    return this.database.transaction(async (tx) => {
      const revoked = await tx.query<GrantRow>(
        `UPDATE staff_read_grants SET revoked_at = $4, revoked_by = $3
          WHERE id = $1 AND workspace_id = $2 AND revoked_at IS NULL
          RETURNING ${GRANT_COLUMNS}`,
        [grantId, workspaceId, userId, this.now()],
      );
      const row = revoked.rows[0];
      if (row) {
        await recordAudit(tx, {
          organizationId: row.organization_id,
          workspaceId,
          actor: { kind: "user", userId },
          action: "staff_read_grant.revoked",
          target: `${grantId} workspace ${workspaceId}`,
        });
        return grantFrom(row, this.now().getTime());
      }
      const existing = await tx.query<GrantRow>(
        `SELECT ${GRANT_COLUMNS} FROM staff_read_grants WHERE id = $1 AND workspace_id = $2`,
        [grantId, workspaceId],
      );
      return existing.rows[0] ? grantFrom(existing.rows[0], this.now().getTime()) : null;
    });
  }

  /**
   * The per-use fence for MCP admission: one UPDATE refuses a revoked or
   * expired grant and records the use, then the staff rule is re-read. Null
   * unless both hold. The principal and workspace come only from the row.
   */
  async use(token: string): Promise<StaffReadGrantAdmission | null> {
    if (!token.startsWith(STAFF_READ_GRANT_PREFIX)) return null;
    const fenced = await this.database.query<GrantRow>(
      `UPDATE staff_read_grants SET last_used_at = now()
        WHERE token_hash = $1 AND revoked_at IS NULL AND expires_at > now()
        RETURNING ${GRANT_COLUMNS}`,
      [hashSecret(token)],
    );
    const row = fenced.rows[0];
    if (!row) return null;
    const staff = await this.staff(row.staff_user_id);
    if (!staff) return null;
    const workspace = await this.database.query<{
      name: string;
      relaycast_workspace_id: string;
      organization_name: string;
    }>(
      `SELECT w.name, w.relaycast_workspace_id, o.name AS organization_name
         FROM workspaces w JOIN organizations o ON o.id = w.organization_id
        WHERE w.id = $1 AND w.organization_id = $2`,
      [row.workspace_id, row.organization_id],
    );
    const pinned = workspace.rows[0];
    if (!pinned) return null;
    const grant = grantFrom(row);
    return {
      grant,
      principal: {
        sessionId: grant.id,
        tokenFamilyId: grant.id,
        userId: staff.userId,
        email: staff.email,
        name: staff.name,
        organizationId: grant.organizationId,
        organizationName: pinned.organization_name,
        workspaceId: grant.workspaceId,
        workspaceName: pinned.name,
        // Not a membership: the least role, never read for authorization on this path.
        role: "member",
        scopes: [...STAFF_READ_GRANT_SCOPES],
      },
      workspace: {
        id: grant.workspaceId,
        organizationId: grant.organizationId,
        name: pinned.name,
        relaycastWorkspaceId: pinned.relaycast_workspace_id,
        // No Relaycast key: a grant never reaches a messaging or roster tool.
        relaycastApiKey: "",
        role: "member",
      },
    };
  }

  /** Read-only lookup for token introspection (does not record a use). */
  async introspect(token: string): Promise<StaffReadGrantIntrospection | null> {
    if (!token.startsWith(STAFF_READ_GRANT_PREFIX)) return null;
    const result = await this.database.query<{
      id: string;
      staff_user_id: string;
      email: string;
      workspace_id: string;
      organization_id: string;
      cloud_relay_workspace_id: string | null;
      relayhistory_origin: string | null;
      token_hash: string;
      revoked: boolean;
      expired: boolean;
      created_at: Date | string;
      expires_at: Date | string;
      policy_revision: number | null;
      policy_settings: unknown;
      policy_sharing_mode_since: Date | string | null;
    }>(
      `SELECT g.id, g.staff_user_id, u.email, g.workspace_id, g.organization_id,
              w.cloud_relay_workspace_id, w.relayhistory_origin, g.token_hash,
              g.revoked_at IS NOT NULL AS revoked, g.expires_at <= now() AS expired,
              g.created_at, g.expires_at,
              cp.revision AS policy_revision, cp.settings AS policy_settings,
              cp.sharing_mode_since AS policy_sharing_mode_since
         FROM staff_read_grants g
         JOIN users u ON u.id = g.staff_user_id
         JOIN workspaces w ON w.id = g.workspace_id AND w.organization_id = g.organization_id
         LEFT JOIN capture_policies cp ON cp.organization_id = g.organization_id
        WHERE g.token_hash = $1`,
      [hashSecret(token)],
    );
    const row = result.rows[0];
    if (!row) return null;
    const staff = row.revoked || row.expired ? false : Boolean(await this.staff(row.staff_user_id));
    return {
      grantId: row.id,
      staffUserId: row.staff_user_id,
      email: row.email,
      workspaceId: row.workspace_id,
      organizationId: row.organization_id,
      cloudRelayWorkspaceId: row.cloud_relay_workspace_id,
      relayhistoryOrigin: row.relayhistory_origin,
      tokenHash: row.token_hash,
      revoked: row.revoked,
      expired: row.expired,
      staff,
      createdAt: new Date(row.created_at),
      expiresAt: new Date(row.expires_at),
      capturePolicy: capturePolicyFromRow(
        row.policy_revision === null ? null : {
          revision: row.policy_revision,
          settings: row.policy_settings,
          sharing_mode_since: row.policy_sharing_mode_since,
        },
      ),
    };
  }
}
