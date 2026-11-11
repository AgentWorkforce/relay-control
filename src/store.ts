import { randomBytes, randomUUID } from "node:crypto";
import { recordAudit, type AuditActor } from "./admin/audit.js";
import { capturePolicyFromRow, type CapturePolicy } from "./capture-policy.js";
import { consentAttemptKey, type ConsentAttempt } from "./auth/desktop-login.js";
import type { Database, SqlExecutor } from "./database.js";
import { revokeMcpOAuthGrantRows } from "./mcp/oauth/store.js";
import { DASHBOARD_DEVICE_CLIENT, isDeviceReservedClientName } from "./reserved-client-names.js";
import {
  lockIdentity,
  lockOrganization,
  lockOrganizationCreate,
  lockUser,
  type TenancyMode,
} from "./tenancy.js";
import {
  ciphertextKeyReference,
  decryptSecret,
  encryptSecret,
  generateUserCode,
  hashSecret,
  normalizeUserCode,
  opaqueToken,
  secureEqual,
  type EncryptionKeyring,
} from "./crypto.js";

const ACCESS_TOKEN_TTL_MS = 24 * 60 * 60 * 1_000;
const REFRESH_TOKEN_TTL_MS = 90 * 24 * 60 * 60 * 1_000;
const DEVICE_CODE_TTL_MS = 10 * 60 * 1_000;
/**
 * Dashboard browser sessions (/login device page, OIDC / email sign-in) start
 * from these; they never carry `rth:acquire`.
 */
const BROWSER_SESSION_SCOPES = ["cli:auth", "rth:read", "rth:sync"];
/**
 * Sessions issued to a device client (the Desktop and CLI device flow, and the
 * Desktop browser handoff and its exchange). `rth:acquire` lets the Desktop
 * acquire sessions through RelayHistory.
 */
const DEVICE_SCOPES = [...BROWSER_SESSION_SCOPES, "rth:acquire"];
/**
 * DG-001: capabilities are issue-time scopes on the token session row, never
 * the transport. ACCOUNT_SCOPE marks a browser sign-in session (cookie under
 * /cloud): it may list the person's workspaces, switch the session, and mint
 * workspace-bound tokens through the desktop picker and device approval.
 * DESKTOP_WORKSPACES_SCOPE marks a Desktop session: it may list workspaces
 * and mint a new bound pair (POST /api/v1/auth/desktop/workspaces). Device,
 * CLI, MCP and service tokens never carry either.
 */
export const ACCOUNT_SCOPE = "account";
export const DESKTOP_WORKSPACES_SCOPE = "desktop:workspaces";
export { DASHBOARD_DEVICE_CLIENT };
/** Browser sign-in sessions: no rth:acquire, plus "account". */
const ACCOUNT_SCOPES = [...BROWSER_SESSION_SCOPES, ACCOUNT_SCOPE];
/** Desktop sessions: device scopes (with rth:acquire) plus "desktop:workspaces". */
const DESKTOP_SCOPES = [...DEVICE_SCOPES, DESKTOP_WORKSPACES_SCOPE];
/** desktop-auth lane, browser flow: hosted Cloud's 15-minute loopback handoff. */
const DESKTOP_HANDOFF_TTL_MS = 15 * 60 * 1_000;
/** The Desktop consent screen's single-use token lives as long as the screen. */
const DESKTOP_CONSENT_TOKEN_TTL_MS = 10 * 60 * 1_000;
const DESKTOP_SESSION_LABEL = "Agent Relay Desktop";

export type Principal = {
  sessionId: string;
  tokenFamilyId: string;
  userId: string;
  email: string;
  name: string;
  organizationId: string;
  organizationName: string;
  workspaceId: string;
  workspaceName: string;
  role: "owner" | "admin" | "member";
  scopes: string[];
  /**
   * A Desktop browser handoff whose PKCE verifier exchange has not happened
   * yet (POST /api/v1/auth/desktop/session). Such a token must not reach the
   * capability routes: whoever intercepted the redirect lacks the verifier.
   */
  pendingHandoff?: boolean;
  /**
   * Any Desktop browser handoff row, exchanged or not. Redeeming the handoff
   * issues a separate PKCE-proven pair; the original redirect token never
   * gains capability-route authority from that exchange.
   */
  handoff?: boolean;
};

export type IssuedTokens = {
  sessionId: string;
  accessToken: string;
  accessTokenExpiresAt: string;
  refreshToken: string;
  refreshTokenExpiresAt: string;
  scopes: string[];
};

export type EncryptionRotationStatus = {
  activeKeyId: string;
  previousKeyId: string | null;
  rotationInProgress: boolean;
  totalCredentials: number;
  activeKeyCredentials: number;
  previousKeyCredentials: number;
  legacyCredentials: number;
  unknownKeyCredentials: number;
  malformedCredentials: number;
  unreadableCredentials: number;
  retirementSafe: boolean | null;
};

export class MembershipConflictError extends Error {}
export class OrganizationConflictError extends Error {}
export class OrganizationBoundaryError extends Error {}
/** A device authorization asked for the reserved dashboard client name. */
export class ReservedClientNameError extends Error {}
/**
 * Multi mode: an organization admin tried to add a person who already has an
 * account (in another organization) directly; they must accept an invitation.
 */
export class InvitationRequiredError extends Error {}
/** A refused fleet node claim or release, with hosted Cloud's status. */
export class NodeClaimError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

/**
 * A Relaycast node id as claimed through POST /api/v1/fleet/nodes/claim and
 * as a machine id presented to token introspection. Shared by app.ts and
 * auth/introspect.ts.
 */
export const NODE_ID_PATTERN = /^[A-Za-z0-9._:-]{1,200}$/;

export type IntrospectedToken = {
  userId: string;
  email: string;
  organizationId: string;
  workspaceId: string;
  role: Principal["role"];
  scopes: string[];
  /** SHA-256 of the access token as stored; never returned to callers. */
  accessTokenHash: string;
  revoked: boolean;
  expired: boolean;
  issuedAt: Date;
  expiresAt: Date;
  /**
   * The organization's capture policy (docs/capture-policy.md) read in the
   * same query, so the sessions pipeline can enforce it without its own copy.
   */
  capturePolicy: CapturePolicy;
};

type TokenContextRow = {
  session_id: string;
  token_family_id: string;
  user_id: string;
  email: string;
  user_name: string;
  organization_id: string;
  organization_name: string;
  workspace_id: string;
  workspace_name: string;
  role: Principal["role"];
  scopes: string[];
  pending_handoff: boolean;
  handoff: boolean;
};

function cleanName(value: string, field: string): string {
  const cleaned = value.replace(/[\p{C}]/gu, " ").trim().slice(0, 120);
  if (!cleaned) throw new Error(`${field} is required`);
  return cleaned;
}

function normalizeEmail(value: string): string {
  const email = value.trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email) || email.length > 320) {
    throw new Error("email is invalid");
  }
  return email;
}

export class ControlPlaneStore {
  constructor(
    readonly database: Database,
    private readonly encryptionKeyring: EncryptionKeyring,
    private readonly devicePollIntervalSeconds = 5,
    options: { tenancy?: TenancyMode } = {},
  ) {
    this.tenancy = options.tenancy ?? "single";
  }

  /** SELFHOST_TENANCY: the request-time gate that replaced the schema singleton (0014). */
  readonly tenancy: TenancyMode;

  async ready(): Promise<boolean> {
    return (await this.readiness()).ready;
  }

  /**
   * Schema present (0014 applied) and the database answers. Single mode also
   * fails with tenancy_mismatch when more than one organization exists (an
   * installation switched back from multi); nothing is ever deleted.
   */
  async readiness(): Promise<{ ready: true } | { ready: false; reason: "schema" | "tenancy_mismatch"; message: string }> {
    try {
      const result = await this.database.query<{ present: boolean; organizations: number }>(
        `SELECT
           to_regclass('public.control_schema_migrations') IS NOT NULL
           AND to_regclass('public.token_sessions') IS NOT NULL
           AND to_regclass('public.workspaces') IS NOT NULL
           AND to_regclass('public.organization_domains') IS NOT NULL
           -- Runtime roles deliberately cannot read the migration ledger.
           -- Check the minimum multi-tenant schema through visible columns.
           AND (
             SELECT count(*) = 5 FROM information_schema.columns
              WHERE table_schema = 'public'
                AND (
                  (table_name = 'users'
                   AND column_name IN ('last_organization_id', 'last_workspace_id'))
                  OR (table_name = 'installation_bootstrap'
                      AND column_name IN ('personal_org_signup_enabled', 'self_serve_organizations_enabled'))
                  OR (table_name = 'telemetry_outbox' AND column_name = 'organization_id')
                )
           ) AS present,
           (SELECT count(*)::int FROM organizations) AS organizations`,
      );
      const row = result.rows[0];
      if (row?.present !== true) {
        return { ready: false, reason: "schema", message: "Database migrations are not applied" };
      }
      if (this.tenancy === "single" && row.organizations > 1) {
        return {
          ready: false,
          reason: "tenancy_mismatch",
          message: `SELFHOST_TENANCY=single but ${row.organizations} organisations exist`,
        };
      }
      return { ready: true };
    } catch {
      return { ready: false, reason: "schema", message: "Database is unreachable or not migrated" };
    }
  }

  /** Whether the organization exists (the 404 boundary for org-scoped routes). */
  async organizationExists(organizationId: string): Promise<boolean> {
    const result = await this.database.query<{ id: string }>(
      "SELECT id FROM organizations WHERE id = $1",
      [organizationId],
    );
    return result.rows.length === 1;
  }

  async createOrganization(input: {
    name: string;
    ownerEmail: string;
    ownerName: string;
  }): Promise<{ id: string; name: string; owner: { id: string; email: string; name: string } }> {
    const id = randomUUID();
    const name = cleanName(input.name, "name");
    const ownerEmail = normalizeEmail(input.ownerEmail);
    return this.database.transaction(async (tx) => {
      // Lock order (src/tenancy.ts): the owner's email lock and user row
      // first, the organization-creation lock last.
      await lockIdentity(tx, ownerEmail);
      const owner = await this.upsertUser(tx, ownerEmail, input.ownerName);
      await lockUser(tx, owner.id);
      if (this.tenancy === "single") {
        // Single mode: the advisory lock serialises creators, so the count
        // check is the singleton (0014 dropped the schema constraint).
        await lockOrganizationCreate(tx);
        const existing = await tx.query<{ id: string }>(
          "SELECT id FROM organizations LIMIT 1",
        );
        if (existing.rows.length > 0) {
          throw new OrganizationConflictError(
            "This self-hosted installation already has its organization",
          );
        }
      }
      await tx.query(
        "INSERT INTO organizations (id, name) VALUES ($1, $2)",
        [id, name],
      );
      await tx.query(
        `INSERT INTO organization_memberships
          (organization_id, user_id, role) VALUES ($1, $2, 'owner')`,
        [id, owner.id],
      );
      return { id, name, owner };
    });
  }

  async listOrganizations(userId?: string): Promise<Array<Record<string, unknown>>> {
    const result = await this.database.query<{
      id: string;
      name: string;
      role: Principal["role"] | null;
    }>(
      `SELECT o.id, o.name, m.role
         FROM organizations o
         LEFT JOIN organization_memberships m
           ON m.organization_id = o.id AND m.user_id = $1
        WHERE $1::uuid IS NULL OR m.user_id IS NOT NULL
        ORDER BY o.created_at, o.id`,
      [userId ?? null],
    );
    return result.rows.map((row) => ({
      id: row.id,
      name: row.name,
      ...(row.role ? { role: row.role } : {}),
    }));
  }

  async createWorkspace(input: {
    organizationId: string;
    name: string;
    relaycastWorkspaceId?: string;
    relaycastApiKey: string;
  }): Promise<{ id: string; organizationId: string; name: string; relaycastWorkspaceId: string }> {
    const id = randomUUID();
    const name = cleanName(input.name, "name");
    const relaycastWorkspaceId = input.relaycastWorkspaceId?.trim() || id;
    const apiKey = input.relaycastApiKey.trim();
    if (!apiKey) throw new Error("relaycastApiKey is required");
    await this.database.transaction(async (tx) => {
      await this.requireOrganization(tx, input.organizationId);
      await tx.query(
        `INSERT INTO workspaces
          (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
         VALUES ($1, $2, $3, $4, $5)`,
        [
          id,
          input.organizationId,
          name,
          relaycastWorkspaceId,
          encryptSecret(apiKey, this.encryptionKeyring.active),
        ],
      );
    });
    return { id, organizationId: input.organizationId, name, relaycastWorkspaceId };
  }

  /**
   * Replaces a workspace's Relaycast key (and optionally its Relaycast
   * workspace id or name), e.g. after the Relaycast it points at was reset
   * and a new key was minted there. The old ciphertext is overwritten.
   */
  async updateWorkspace(input: {
    organizationId: string;
    workspaceId: string;
    name?: string;
    relaycastWorkspaceId?: string;
    relaycastApiKey?: string;
  }): Promise<{ id: string; organizationId: string; name: string; relaycastWorkspaceId: string } | null> {
    const name = input.name === undefined ? null : cleanName(input.name, "name");
    const relaycastWorkspaceId = input.relaycastWorkspaceId?.trim() || null;
    const apiKey = input.relaycastApiKey?.trim() || null;
    if (input.relaycastApiKey !== undefined && !apiKey) throw new Error("relaycastApiKey is required");
    if (name === null && relaycastWorkspaceId === null && apiKey === null) throw new Error("nothing to update");
    return this.database.transaction(async (tx) => {
      await this.requireOrganization(tx, input.organizationId);
      const result = await tx.query<{ id: string; name: string; relaycast_workspace_id: string }>(
        `UPDATE workspaces
            SET name = COALESCE($3, name),
                relaycast_workspace_id = COALESCE($4, relaycast_workspace_id),
                relaycast_api_key_ciphertext = COALESCE($5, relaycast_api_key_ciphertext),
                updated_at = now()
          WHERE id = $1 AND organization_id = $2
          RETURNING id, name, relaycast_workspace_id`,
        [
          input.workspaceId,
          input.organizationId,
          name,
          relaycastWorkspaceId,
          apiKey === null ? null : encryptSecret(apiKey, this.encryptionKeyring.active),
        ],
      );
      const row = result.rows[0];
      if (!row) return null;
      return {
        id: row.id,
        organizationId: input.organizationId,
        name: row.name,
        relaycastWorkspaceId: row.relaycast_workspace_id,
      };
    });
  }

  /**
   * Deletes a workspace of this organization. Foreign keys cascade its
   * sessions, tokens, credentials, flows and workspace-scoped audit events;
   * the deletion itself is recorded at organization level so it outlives them.
   * Factory connections/bindings and live MCP OAuth grants or pending cleanup
   * restrict deletion until teardown finishes. The organization's rows are locked so two concurrent deletes cannot
   * both pass the last-workspace check. The Relaycast workspace is not touched.
   */
  async deleteWorkspace(input: {
    organizationId: string;
    workspaceId: string;
    allowLast: boolean;
    actor: AuditActor;
  }): Promise<"deleted" | "not_found" | "last_workspace" | "in_use"> {
    try {
      return await this.database.transaction(async (tx) => {
        const rows = await tx.query<{ id: string; name: string }>(
          "SELECT id, name FROM workspaces WHERE organization_id = $1 ORDER BY id FOR UPDATE",
          [input.organizationId],
        );
        const target = rows.rows.find((row) => row.id === input.workspaceId);
        if (!target) return "not_found";
        if (rows.rows.length === 1 && !input.allowLast) return "last_workspace";
        // Keep the workspace key/location until connector cleanup commits.
        // The workspace row lock also fences a new grant's FK insertion;
        // revocation alone must not let CASCADE discard pending remote work.
        const oauth = await tx.query(`SELECT 1 FROM mcp_oauth_grants
          WHERE organization_id=$1 AND workspace_id=$2 AND revoked_at IS NULL
          UNION ALL SELECT 1 FROM mcp_oauth_revocations
          WHERE organization_id=$1 AND workspace_id=$2 AND completed_at IS NULL
          LIMIT 1`, [input.organizationId,input.workspaceId]);
        if (oauth.rows.length) return "in_use";
        await tx.query("DELETE FROM workspaces WHERE id = $1 AND organization_id = $2", [
          input.workspaceId,
          input.organizationId,
        ]);
        await recordAudit(tx, {
          organizationId: input.organizationId,
          actor: input.actor,
          action: "workspace.deleted",
          target: `${input.workspaceId} (${target.name})`,
        });
        return "deleted";
      });
    } catch (error) {
      if ((error as { code?: string }).code === "23503") return "in_use";
      throw error;
    }
  }

  /**
   * Operator override for connector cleanup that can never finish (for
   * example a Relaycast workspace that no longer exists). Completes every
   * pending MCP OAuth teardown row of the workspace without a remote release,
   * under the workspace row lock that deletion also takes. Live grants are
   * untouched unless `revokeLive` is set: then every live grant of the
   * workspace is revoked first (reason operator_abandoned, through the normal
   * revocation path, so its sessions end and a revocation row is written),
   * and that row is completed in the same transaction. This is the way out
   * when the module is off or unavailable and nobody can disconnect.
   * Returns null for an unknown workspace.
   */
  async abandonMcpOAuthCleanup(input: {
    organizationId: string;
    workspaceId: string;
    actor: AuditActor;
    revokeLive?: boolean;
  }): Promise<{ abandoned: number; revoked: number } | null> {
    for (let attempt = 0; ; attempt += 1) {
      const result = await this.database.transaction(async (tx) => {
        // Revocation needs the tenancy lock order: grant owners (user id
        // order), then the organization, then the workspace row.
        const owners = input.revokeLive ? (await tx.query<{ user_id: string }>(
          `SELECT DISTINCT user_id FROM mcp_oauth_grants
            WHERE organization_id = $1 AND workspace_id = $2 AND revoked_at IS NULL ORDER BY user_id`,
          [input.organizationId, input.workspaceId],
        )).rows.map((row) => row.user_id) : [];
        for (const userId of owners) await lockUser(tx, userId);
        if (input.revokeLive) await lockOrganization(tx, input.organizationId);
        const workspace = await tx.query(
          "SELECT id FROM workspaces WHERE id = $1 AND organization_id = $2 FOR UPDATE",
          [input.workspaceId, input.organizationId],
        );
        if (!workspace.rows.length) return null;
        let revoked = 0;
        if (input.revokeLive) {
          const live = await tx.query<{ id: string; user_id: string }>(
            `SELECT id, user_id FROM mcp_oauth_grants
              WHERE organization_id = $1 AND workspace_id = $2 AND revoked_at IS NULL ORDER BY id`,
            [input.organizationId, input.workspaceId],
          );
          // A grant issued to a new owner after the owner scan: start over
          // so its owner is locked in order too.
          if (live.rows.some((row) => !owners.includes(row.user_id))) return "retry" as const;
          const now = new Date();
          // Unredeemed codes would otherwise mint a fresh grant once the module is on.
          await tx.query(`UPDATE mcp_oauth_authorization_codes SET expires_at = $3
            WHERE organization_id = $1 AND workspace_id = $2 AND expires_at > $3`,
          [input.organizationId, input.workspaceId, now]);
          for (const { id } of live.rows) {
            if (await revokeMcpOAuthGrantRows(tx, id, "operator_abandoned", now)) revoked += 1;
          }
        }
        const abandoned = await tx.query(`UPDATE mcp_oauth_revocations
          SET completed_at = now(), outcome = 'operator_abandoned'
          WHERE organization_id = $1 AND workspace_id = $2 AND completed_at IS NULL RETURNING id`,
        [input.organizationId, input.workspaceId]);
        await recordAudit(tx, {
          organizationId: input.organizationId,
          actor: input.actor,
          action: "mcp_oauth.cleanup_abandoned",
          target: input.revokeLive
            ? `${input.workspaceId} (${abandoned.rows.length} pending, ${revoked} live revoked)`
            : `${input.workspaceId} (${abandoned.rows.length} pending)`,
        });
        return { abandoned: abandoned.rows.length, revoked };
      });
      if (result !== "retry") return result;
      if (attempt >= 4) throw new Error("MCP OAuth grants kept changing during operator cleanup; retry");
    }
  }

  async listWorkspaces(organizationId: string): Promise<Array<Record<string, unknown>>> {
    const result = await this.database.query<{
      id: string;
      organization_id: string;
      name: string;
      relaycast_workspace_id: string;
      runtime_config: unknown;
    }>(
      `SELECT id, organization_id, name, relaycast_workspace_id, runtime_config
         FROM workspaces WHERE organization_id = $1 ORDER BY created_at, id`,
      [organizationId],
    );
    return result.rows.map((row) => ({
      id: row.id,
      organizationId: row.organization_id,
      name: row.name,
      relaycastWorkspaceId: row.relaycast_workspace_id,
      runtime: row.runtime_config,
    }));
  }

  async listMemberships(organizationId: string): Promise<Array<Record<string, unknown>>> {
    const result = await this.database.query<{
      user_id: string;
      email: string;
      name: string;
      role: Principal["role"];
      created_at: Date | string;
    }>(
      `SELECT u.id AS user_id, u.email, u.name, m.role, m.created_at
         FROM organization_memberships m
         JOIN users u ON u.id = m.user_id
        WHERE m.organization_id = $1 ORDER BY u.email`,
      [organizationId],
    );
    return result.rows.map((row) => ({
      userId: row.user_id,
      email: row.email,
      name: row.name,
      role: row.role,
      joinedAt: new Date(row.created_at).toISOString(),
    }));
  }

  async putMembership(input: {
    organizationId: string;
    email: string;
    name: string;
    role: Principal["role"];
    /** The installation operator (bootstrap bearer) may add existing people directly. */
    operator?: boolean;
  }): Promise<Record<string, unknown>> {
    if (!["owner", "admin", "member"].includes(input.role)) {
      throw new Error("role is invalid");
    }
    const email = normalizeEmail(input.email);
    return this.database.transaction(async (tx) => {
      await lockIdentity(tx, email);
      await lockOrganization(tx, input.organizationId);
      await this.requireOrganization(tx, input.organizationId);
      if (this.tenancy === "multi" && !input.operator) {
        // Multi mode: a person who already has an account belongs to other
        // organizations too; an admin here may not enrol them (or rename
        // them) without their consent. They accept an invitation instead.
        const found = await tx.query<{ member: boolean }>(
          `SELECT EXISTS (
                    SELECT 1 FROM organization_memberships m
                     WHERE m.organization_id = $2 AND m.user_id = u.id
                  ) AS member
             FROM users u WHERE u.email = $1`,
          [email, input.organizationId],
        );
        if (found.rows[0] && found.rows[0].member !== true) {
          throw new InvitationRequiredError("This person already has an account; invite them instead (POST /api/v1/organizations/{organizationId}/invitations)");
        }
      }
      const user = await this.upsertUser(tx, email, input.name);
      const existing = await tx.query<{ role: Principal["role"] }>(
        `SELECT role FROM organization_memberships
          WHERE organization_id = $1 AND user_id = $2`,
        [input.organizationId, user.id],
      );
      if (existing.rows[0]?.role === "owner" && input.role !== "owner") {
        const owners = await tx.query<{ count: string }>(
          `SELECT count(*)::text AS count FROM organization_memberships
            WHERE organization_id = $1 AND role = 'owner'`,
          [input.organizationId],
        );
        if (Number(owners.rows[0]?.count ?? "0") <= 1) {
          throw new MembershipConflictError("The last owner cannot be demoted");
        }
      }
      await tx.query(
        `INSERT INTO organization_memberships (organization_id, user_id, role)
         VALUES ($1, $2, $3)
         ON CONFLICT (organization_id, user_id) DO UPDATE
           SET role = EXCLUDED.role, updated_at = now()`,
        [input.organizationId, user.id, input.role],
      );
      return { userId: user.id, ...user, role: input.role };
    });
  }

  /**
   * `beforeCommit` runs in the removal transaction after deletion (or an
   * already-absent retry), with user->org locks held. A failure rolls back
   * membership and dependent cleanup together. A remaining last owner never
   * invokes cleanup.
   */
  async deleteMembership(
    organizationId: string,
    userId: string,
    beforeCommit?: (tx: SqlExecutor, member: { organizationId: string; userId: string }) => Promise<void>,
  ): Promise<boolean> {
    return this.database.transaction(async (tx) => {
      // Consent/refresh and rejoin use this same order, before any membership row lock.
      await lockUser(tx, userId);
      await lockOrganization(tx, organizationId);
      await this.requireOrganization(tx, organizationId);
      const result = await tx.query<{ user_id: string }>(
        `DELETE FROM organization_memberships
          WHERE organization_id = $1 AND user_id = $2
            AND (
              role <> 'owner' OR
              (SELECT count(*) FROM organization_memberships
                WHERE organization_id = $1 AND role = 'owner') > 1
            )
          RETURNING user_id`,
        [organizationId, userId],
      );
      const deleted=result.rows.length===1;
      // An idempotent retry can repair credentials from an earlier departure;
      // never invoke the hook when a remaining last-owner row blocks deletion.
      if (deleted || !(await tx.query("SELECT user_id FROM organization_memberships WHERE organization_id=$1 AND user_id=$2",
        [organizationId,userId])).rows.length) {
        await beforeCommit?.(tx, { organizationId, userId });
      }
      return deleted;
    });
  }

  async memberRole(organizationId: string, userId: string): Promise<Principal["role"] | null> {
    const result = await this.database.query<{ role: Principal["role"] }>(
      `SELECT role FROM organization_memberships
        WHERE organization_id = $1 AND user_id = $2`,
      [organizationId, userId],
    );
    return result.rows[0]?.role ?? null;
  }

  async memberRoleByEmail(organizationId: string, email: string): Promise<Principal["role"] | null> {
    const result = await this.database.query<{ role: Principal["role"] }>(
      `SELECT m.role FROM organization_memberships m
         JOIN users u ON u.id = m.user_id
        WHERE m.organization_id = $1 AND u.email = $2`,
      [organizationId, email.trim().toLowerCase()],
    );
    return result.rows[0]?.role ?? null;
  }

  /** How many workspaces the person can reach (whoami's workspaceCount). */
  async memberWorkspaceCount(userId: string): Promise<number> {
    const result = await this.database.query<{ n: number }>(
      `SELECT count(*)::int AS n
         FROM organization_memberships m
         JOIN workspaces w ON w.organization_id = m.organization_id
        WHERE m.user_id = $1`,
      [userId],
    );
    return result.rows[0]?.n ?? 0;
  }

  /** Every workspace the person can use, across all their organizations. */
  async memberWorkspaces(userId: string): Promise<Array<{
    id: string;
    name: string;
    organizationId: string;
    organizationName: string;
    role: Principal["role"];
  }>> {
    const result = await this.database.query<{
      id: string;
      name: string;
      organization_id: string;
      organization_name: string;
      role: Principal["role"];
    }>(
      `SELECT w.id, w.name, w.organization_id, o.name AS organization_name, m.role
         FROM organization_memberships m
         JOIN organizations o ON o.id = m.organization_id
         JOIN workspaces w ON w.organization_id = m.organization_id
        WHERE m.user_id = $1
        ORDER BY o.created_at, o.id, w.created_at, w.id`,
      [userId],
    );
    return result.rows.map((row) => ({
      id: row.id,
      name: row.name,
      organizationId: row.organization_id,
      organizationName: row.organization_name,
      role: row.role,
    }));
  }

  /** A workspace's Relaycast credentials, for the Flows service that assigns its runs. */
  async relaycastBinding(workspaceId: string): Promise<{ relaycastWorkspaceId: string; relaycastApiKey: string } | null> {
    const result = await this.database.query<{ relaycast_workspace_id: string; relaycast_api_key_ciphertext: string }>(
      "SELECT relaycast_workspace_id, relaycast_api_key_ciphertext FROM workspaces WHERE id = $1",
      [workspaceId],
    );
    const row = result.rows[0];
    return row
      ? { relaycastWorkspaceId: row.relaycast_workspace_id, relaycastApiKey: decryptSecret(row.relaycast_api_key_ciphertext, this.encryptionKeyring) }
      : null;
  }

  async workspaceForUser(
    workspaceId: string,
    userId: string,
  ): Promise<{
    id: string;
    organizationId: string;
    name: string;
    relaycastWorkspaceId: string;
    relaycastApiKey: string;
    runtime: unknown;
    role: Principal["role"];
  } | null> {
    const result = await this.database.query<{
      id: string;
      organization_id: string;
      name: string;
      relaycast_workspace_id: string;
      relaycast_api_key_ciphertext: string;
      runtime_config: unknown;
      role: Principal["role"];
    }>(
      `SELECT w.id, w.organization_id, w.name, w.relaycast_workspace_id,
              w.relaycast_api_key_ciphertext, w.runtime_config, m.role
         FROM workspaces w
         JOIN organization_memberships m
           ON m.organization_id = w.organization_id AND m.user_id = $2
        WHERE w.id = $1`,
      [workspaceId, userId],
    );
    const row = result.rows[0];
    if (!row) return null;
    return {
      id: row.id,
      organizationId: row.organization_id,
      name: row.name,
      relaycastWorkspaceId: row.relaycast_workspace_id,
      relaycastApiKey: decryptSecret(row.relaycast_api_key_ciphertext, this.encryptionKeyring),
      runtime: row.runtime_config,
      role: row.role,
    };
  }

  async setRuntime(workspaceId: string, runtime: unknown): Promise<boolean> {
    const result = await this.database.query<{ id: string }>(
      `UPDATE workspaces SET runtime_config = $2::jsonb, updated_at = now()
        WHERE id = $1
        RETURNING id`,
      [workspaceId, JSON.stringify(runtime)],
    );
    return result.rows.length === 1;
  }

  /**
   * The dashboard's own /login flow passes `{ reserved: true }`; any other
   * caller asking for DASHBOARD_DEVICE_CLIENT (after the same cleaning the
   * stored name gets, so invisible characters and padding don't slip past)
   * gets ReservedClientNameError.
   */
  async startDeviceAuthorization(clientName?: string, desktopHostName?: string | null, options: { reserved?: boolean } = {}): Promise<{
    deviceCode: string;
    userCode: string;
    expiresAt: string;
    intervalSeconds: number;
  }> {
    const deviceCode = opaqueToken("sh_dc_");
    const expiresAt = new Date(Date.now() + DEVICE_CODE_TTL_MS);
    const client = clientName ? cleanName(clientName, "clientName") : null;
    if (client !== null && isDeviceReservedClientName(client) && !options.reserved) {
      throw new ReservedClientNameError("client_name is reserved");
    }
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const userCode = generateUserCode();
      try {
        await this.database.query(
          `INSERT INTO device_authorizations
            (id, device_code_hash, user_code, client_name, interval_seconds, expires_at,
             desktop_host_name)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [
            randomUUID(),
            hashSecret(deviceCode),
            userCode,
            client,
            this.devicePollIntervalSeconds,
            expiresAt,
            desktopHostName ?? null,
          ],
        );
        return {
          deviceCode,
          userCode,
          expiresAt: expiresAt.toISOString(),
          intervalSeconds: this.devicePollIntervalSeconds,
        };
      } catch (error) {
        if (attempt === 4) throw error;
      }
    }
    throw new Error("Unable to allocate device authorization");
  }

  /**
   * What the approval page shows before anyone commits: the code, the client
   * that asked, and its state. Never returns the device code, so a browser
   * cannot complete the poll and impersonate the device.
   */
  async findDeviceAuthorization(input: string): Promise<{
    userCode: string;
    clientName: string | null;
    desktopHostName: string | null;
    status: "pending" | "approved" | "denied" | "expired" | "consumed";
    expiresAt: string;
  } | null> {
    const userCode = normalizeUserCode(input);
    if (!userCode) return null;
    const found = await this.database.query<{
      user_code: string;
      client_name: string | null;
      desktop_host_name: string | null;
      status: "pending" | "approved" | "denied" | "expired" | "consumed";
      expires_at: Date | string;
    }>(
      `SELECT user_code, client_name, desktop_host_name, status, expires_at
         FROM device_authorizations WHERE user_code = $1`,
      [userCode],
    );
    const row = found.rows[0];
    if (!row) return null;
    const expiresAt = new Date(row.expires_at);
    const lapsed = expiresAt.getTime() <= Date.now() &&
      (row.status === "pending" || row.status === "approved");
    return {
      userCode: row.user_code,
      clientName: row.client_name,
      desktopHostName: row.desktop_host_name,
      status: lapsed ? "expired" : row.status,
      expiresAt: expiresAt.toISOString(),
    };
  }

  async decideDeviceAuthorization(input: {
    userCode: string;
    approve: boolean;
    userId: string;
    workspaceId: string;
  }): Promise<"approved" | "denied" | "not_found" | "expired" | "already_decided" | "not_member"> {
    const userCode = normalizeUserCode(input.userCode);
    if (!userCode) return "not_found";
    const found = await this.database.query<{ status: string; expires_at: Date | string }>(
      "SELECT status, expires_at FROM device_authorizations WHERE user_code = $1",
      [userCode],
    );
    const current = found.rows[0];
    if (!current) return "not_found";
    if (new Date(current.expires_at).getTime() <= Date.now()) return "expired";
    if (current.status !== "pending") return "already_decided";

    const workspace = await this.workspaceForUser(input.workspaceId, input.userId);
    if (!workspace) return "not_member";
    const result = await this.database.query<{ id: string }>(
      `UPDATE device_authorizations
          SET status = $2, approved_at = now(), approved_by_user_id = $3,
              organization_id = $4, workspace_id = $5, updated_at = now()
        WHERE user_code = $1 AND status = 'pending' AND expires_at > now()
        RETURNING id`,
      [
        userCode,
        input.approve ? "approved" : "denied",
        input.userId,
        workspace.organizationId,
        workspace.id,
      ],
    );
    if (!result.rows[0]) return "already_decided";
    return input.approve ? "approved" : "denied";
  }

  /**
   * `client` is who receives the session: a device client (the default) gets
   * DEVICE_SCOPES; the dashboard's /login page gets ACCOUNT_SCOPES when the
   * attempt was started by GET /login (DASHBOARD_DEVICE_CLIENT), otherwise
   * BROWSER_SESSION_SCOPES. Neither browser case carries rth:acquire.
   */
  async pollDeviceAuthorization(deviceCode: string, client: "device" | "browser" = "device"): Promise<
    | { kind: "issued"; tokens: IssuedTokens }
    | { kind: "error"; error: string; intervalSeconds: number }
  > {
    return this.database.transaction(async (tx) => {
      const found = await tx.query<{
        id: string;
        status: string;
        client_name: string | null;
        interval_seconds: number;
        last_polled_at: Date | string | null;
        expires_at: Date | string;
        approved_by_user_id: string | null;
        organization_id: string | null;
        workspace_id: string | null;
      }>(
        `SELECT id, status, client_name, interval_seconds, last_polled_at, expires_at,
                approved_by_user_id, organization_id, workspace_id
           FROM device_authorizations
          WHERE device_code_hash = $1 FOR UPDATE`,
        [hashSecret(deviceCode)],
      );
      const row = found.rows[0];
      if (!row) return { kind: "error", error: "invalid_grant", intervalSeconds: 5 };
      const fail = (error: string, intervalSeconds = row.interval_seconds) =>
        ({ kind: "error" as const, error, intervalSeconds });
      if (row.status === "consumed") return fail("invalid_grant");
      if (row.status === "denied") return fail("access_denied");
      if (row.status === "expired" || new Date(row.expires_at).getTime() <= Date.now()) {
        await tx.query(
          "UPDATE device_authorizations SET status = 'expired', updated_at = now() WHERE id = $1",
          [row.id],
        );
        return fail("expired_token");
      }
      if (
        row.last_polled_at &&
        Date.now() < new Date(row.last_polled_at).getTime() + row.interval_seconds * 1_000
      ) {
        const interval = Math.min(60, row.interval_seconds + 5);
        await tx.query(
          `UPDATE device_authorizations
              SET interval_seconds = $2, last_polled_at = now(), updated_at = now()
            WHERE id = $1`,
          [row.id, interval],
        );
        return fail("slow_down", interval);
      }
      await tx.query(
        "UPDATE device_authorizations SET last_polled_at = now(), updated_at = now() WHERE id = $1",
        [row.id],
      );
      if (row.status !== "approved") return fail("authorization_pending");
      if (!row.approved_by_user_id || !row.organization_id || !row.workspace_id) {
        return fail("invalid_grant");
      }
      const tokens = await this.issueTokens(tx, {
        userId: row.approved_by_user_id,
        organizationId: row.organization_id,
        workspaceId: row.workspace_id,
        label: row.client_name,
      }, {
        scopes: client === "browser"
          ? (row.client_name === DASHBOARD_DEVICE_CLIENT ? ACCOUNT_SCOPES : BROWSER_SESSION_SCOPES)
          : DEVICE_SCOPES,
      });
      await tx.query(
        `UPDATE device_authorizations
            SET status = 'consumed', api_token_session_id = $2, updated_at = now()
          WHERE id = $1 AND status = 'approved'`,
        [row.id, tokens.sessionId],
      );
      return { kind: "issued", tokens };
    });
  }

  /**
   * Called after every successful access-token authentication, whichever
   * route did it (the usage page's active-user counter). Must not throw or block.
   */
  onAuthenticated: ((user: { organizationId: string; userId: string }) => void) | null = null;

  private notifyAuthenticated(user: { organizationId: string; userId: string }): void {
    try {
      this.onAuthenticated?.(user);
    } catch {
      // Usage counters never fail authentication.
    }
  }

  async authenticateAccessToken(token: string): Promise<Principal | null> {
    const principal = await this.lookupAccessToken(token);
    if (principal) this.notifyAuthenticated(principal);
    return principal;
  }

  private async lookupAccessToken(token: string): Promise<Principal | null> {
    const result = await this.database.query<TokenContextRow>(
      `SELECT s.id AS session_id, s.token_family_id, s.user_id, u.email,
              u.name AS user_name, s.organization_id, o.name AS organization_name,
              s.workspace_id, w.name AS workspace_name, m.role, s.scopes,
              (s.desktop_exchange_challenge IS NOT NULL AND s.desktop_exchanged_at IS NULL) AS pending_handoff,
              (s.desktop_exchange_challenge IS NOT NULL) AS handoff
         FROM token_sessions s
         JOIN users u ON u.id = s.user_id
         JOIN organizations o ON o.id = s.organization_id
         JOIN workspaces w
           ON w.id = s.workspace_id AND w.organization_id = s.organization_id
         JOIN organization_memberships m
           ON m.organization_id = s.organization_id AND m.user_id = s.user_id
        WHERE s.access_token_hash = $1
          AND s.revoked_at IS NULL AND s.access_token_expires_at > now()
          -- Desktop-provider MCP credentials authenticate only at the MCP
          -- endpoint (DesktopMcpCredentials.resolve), never at app routes.
          AND NOT ('mcp:desktop' = ANY(s.scopes))`,
      [hashSecret(token)],
    );
    const row = result.rows[0];
    if (!row) return null;
    return {
      sessionId: row.session_id,
      tokenFamilyId: row.token_family_id,
      userId: row.user_id,
      email: row.email,
      name: row.user_name,
      organizationId: row.organization_id,
      organizationName: row.organization_name,
      workspaceId: row.workspace_id,
      workspaceName: row.workspace_name,
      role: row.role,
      scopes: row.scopes,
      pendingHandoff: row.pending_handoff === true,
      handoff: row.handoff === true,
    };
  }

  /**
   * The token session behind an access token for introspection, including
   * revoked and expired rows so the caller can say why it is inactive. Same
   * joins as authenticateAccessToken: a session whose membership or workspace
   * no longer holds is not found at all, nor in single tenancy is one on a
   * database that has gained a second organization. The joins bind the answer
   * to the session's own organization in either mode. A Desktop handoff whose
   * PKCE exchange has not happened is not found either: until then, whoever
   * holds it may only have intercepted the redirect.
   */
  async introspectAccessToken(token: string): Promise<IntrospectedToken | null> {
    const result = await this.database.query<{
      user_id: string;
      email: string;
      organization_id: string;
      workspace_id: string;
      role: Principal["role"];
      scopes: string[];
      access_token_hash: string;
      revoked: boolean;
      expired: boolean;
      issued_at: Date | string;
      expires_at: Date | string;
      policy_revision: number | null;
      policy_settings: unknown;
    }>(
      `SELECT s.user_id, u.email, s.organization_id, s.workspace_id, m.role, s.scopes,
              s.access_token_hash,
              (s.revoked_at IS NOT NULL OR (
                'mcp:desktop' = ANY(s.scopes) AND NOT EXISTS (
                  SELECT 1
                    FROM desktop_mcp_credentials c
                    JOIN token_sessions p ON p.id = c.parent_session_id
                   WHERE c.token_session_id = s.id
                     AND p.revoked_at IS NULL AND p.refresh_token_expires_at > now()
                     AND p.desktop_verified_at IS NOT NULL
                ))) AS revoked,
              s.access_token_expires_at <= now() AS expired,
              COALESCE(s.last_refreshed_at, s.created_at) AS issued_at,
              s.access_token_expires_at AS expires_at,
              cp.revision AS policy_revision, cp.settings AS policy_settings
         FROM token_sessions s
         JOIN users u ON u.id = s.user_id
         JOIN workspaces w
           ON w.id = s.workspace_id AND w.organization_id = s.organization_id
         JOIN organization_memberships m
           ON m.organization_id = s.organization_id AND m.user_id = s.user_id
         LEFT JOIN capture_policies cp ON cp.organization_id = s.organization_id
        WHERE s.access_token_hash = $1
          AND NOT (s.desktop_exchange_challenge IS NOT NULL AND s.desktop_exchanged_at IS NULL)
          AND ($2::text = 'multi' OR NOT EXISTS (
            SELECT 1
              FROM organizations other
             WHERE other.id <> s.organization_id
          ))`,
      [hashSecret(token), this.tenancy],
    );
    const row = result.rows[0];
    if (!row) return null;
    // A live token presented to another service (ingest, read API) is use too.
    if (!row.revoked && !row.expired) {
      this.notifyAuthenticated({ organizationId: row.organization_id, userId: row.user_id });
    }
    return {
      userId: row.user_id,
      email: row.email,
      organizationId: row.organization_id,
      workspaceId: row.workspace_id,
      role: row.role,
      scopes: row.scopes,
      accessTokenHash: row.access_token_hash,
      revoked: row.revoked,
      expired: row.expired,
      issuedAt: new Date(row.issued_at),
      expiresAt: new Date(row.expires_at),
      capturePolicy: capturePolicyFromRow(
        row.policy_revision === null ? null : { revision: row.policy_revision, settings: row.policy_settings },
      ),
    };
  }

  async refresh(refreshToken: string): Promise<IssuedTokens | null> {
    const accessToken = opaqueToken("sh_at_");
    const nextRefreshToken = opaqueToken("sh_rt_");
    const accessExpires = new Date(Date.now() + ACCESS_TOKEN_TTL_MS);
    const refreshExpires = new Date(Date.now() + REFRESH_TOKEN_TTL_MS);
    const result = await this.database.query<{
      id: string;
      scopes: string[];
    }>(
      `UPDATE token_sessions AS s
          SET access_token_hash = $2, refresh_token_hash = $3,
              access_token_expires_at = $4, refresh_token_expires_at = $5,
              last_refreshed_at = now(), updated_at = now()
        WHERE refresh_token_hash = $1 AND revoked_at IS NULL
          AND refresh_token_expires_at > now()
        RETURNING id, scopes`,
      [
        hashSecret(refreshToken),
        hashSecret(accessToken),
        hashSecret(nextRefreshToken),
        accessExpires,
        refreshExpires,
      ],
    );
    const row = result.rows[0];
    if (!row) return null;
    return {
      sessionId: row.id,
      accessToken,
      accessTokenExpiresAt: accessExpires.toISOString(),
      refreshToken: nextRefreshToken,
      refreshTokenExpiresAt: refreshExpires.toISOString(),
      scopes: row.scopes,
    };
  }

  /**
   * The browser sign-in handoff for Agent Relay Desktop: a 15-minute session
   * bound to the app's S256 code_challenge. It authenticates like any access
   * token until it expires; the verifier redeems it once for a renewable pair
   * (exchangeDesktopHandoff). Its refresh token is never handed out.
   * `consentedHostName` is set only when the person approved "Agent Relay
   * Desktop on <host>" on the consent screen; it is what makes the redeemed
   * session a verified Desktop sign-in (desktop MCP provider credentials).
   */
  async issueDesktopHandoff(input: {
    userId: string;
    organizationId: string;
    workspaceId: string;
    codeChallenge: string;
    consentedHostName?: string;
  }): Promise<IssuedTokens> {
    return this.database.transaction((tx) =>
      this.issueTokens(tx, {
        userId: input.userId,
        organizationId: input.organizationId,
        workspaceId: input.workspaceId,
        label: DESKTOP_SESSION_LABEL,
      }, {
        accessTtlMs: DESKTOP_HANDOFF_TTL_MS,
        refreshTtlMs: DESKTOP_HANDOFF_TTL_MS,
        desktopExchangeChallenge: input.codeChallenge,
        scopes: DESKTOP_SCOPES,
        desktopHostName: input.consentedHostName,
      }));
  }

  /**
   * A single-use consent token for the "approve Agent Relay Desktop on <host>"
   * screen, bound to one person and one sign-in attempt. It is a shared row
   * (only its hash is stored), so any replica may receive the form post.
   * Expired rows are swept on the way in.
   */
  async issueDesktopConsentToken(attempt: ConsentAttempt): Promise<string> {
    const token = randomBytes(32).toString("base64url");
    await this.database.transaction(async (tx) => {
      await tx.query(`DELETE FROM desktop_consent_tokens WHERE expires_at <= now()`);
      await tx.query(
        `INSERT INTO desktop_consent_tokens (id, token_hash, attempt_key, user_id, expires_at)
         VALUES ($1, $2, $3, $4, now() + ($5::int * interval '1 millisecond'))`,
        [randomUUID(), hashSecret(token), consentAttemptKey(attempt), attempt.userId, DESKTOP_CONSENT_TOKEN_TTL_MS],
      );
    });
    return token;
  }

  /**
   * True once, for the matching attempt; the token is consumed either way.
   * One DELETE claims the row, so across replicas exactly one post wins.
   */
  async consumeDesktopConsentToken(token: unknown, attempt: ConsentAttempt): Promise<boolean> {
    if (typeof token !== "string" || !token) return false;
    const claimed = await this.database.query<{ attempt_key: string; live: boolean }>(
      `DELETE FROM desktop_consent_tokens
        WHERE token_hash = $1
        RETURNING attempt_key, expires_at > now() AS live`,
      [hashSecret(token)],
    );
    const row = claimed.rows[0];
    if (!row || !row.live) return false;
    return secureEqual(row.attempt_key, consentAttemptKey(attempt));
  }

  /**
   * Redeems a handoff once. `challengeMatches` is the S256 check; the row is
   * claimed in one conditional update so a verifier can be used a single
   * time, and the renewable session joins the handoff's token family.
   */
  async exchangeDesktopHandoff(
    accessToken: string,
    challengeMatches: (challenge: string) => boolean,
  ): Promise<IssuedTokens | null> {
    return this.database.transaction(async (tx) => {
      const found = await tx.query<{
        id: string;
        user_id: string;
        organization_id: string;
        workspace_id: string;
        token_family_id: string;
        desktop_exchange_challenge: string | null;
        scopes: string[];
        desktop_host_name: string | null;
      }>(
        `SELECT id, user_id, organization_id, workspace_id, token_family_id,
                desktop_exchange_challenge, scopes, desktop_host_name
           FROM token_sessions
          WHERE access_token_hash = $1 AND revoked_at IS NULL
            AND desktop_exchanged_at IS NULL AND desktop_exchange_challenge IS NOT NULL
            AND access_token_expires_at > now()
          FOR UPDATE`,
        [hashSecret(accessToken)],
      );
      const row = found.rows[0];
      if (!row?.desktop_exchange_challenge || !challengeMatches(row.desktop_exchange_challenge)) {
        return null;
      }
      const claimed = await tx.query<{ id: string }>(
        `UPDATE token_sessions
            SET desktop_exchanged_at = now(), updated_at = now()
          WHERE id = $1 AND desktop_exchanged_at IS NULL AND revoked_at IS NULL
          RETURNING id`,
        [row.id],
      );
      if (claimed.rows.length !== 1) return null;
      return this.issueTokens(tx, {
        userId: row.user_id,
        organizationId: row.organization_id,
        workspaceId: row.workspace_id,
        label: DESKTOP_SESSION_LABEL,
      }, {
        tokenFamilyId: row.token_family_id,
        // The handoff's own scopes: a handoff minted before desktop:workspaces
        // existed never gains it.
        scopes: row.scopes,
        // Proven: consented host on the handoff plus the S256 verifier now.
        ...(row.desktop_host_name ? { desktopHostName: row.desktop_host_name, desktopVerified: true } : {}),
      });
    });
  }

  /**
   * POST /api/v1/auth/desktop/workspaces: a new renewable Desktop pair bound
   * to another workspace the person is a member of (checked live by
   * issueTokens), in the presenting session's token family.
   */
  async issueDesktopSession(input: {
    userId: string;
    organizationId: string;
    workspaceId: string;
    tokenFamilyId: string;
  }): Promise<IssuedTokens> {
    return this.database.transaction((tx) =>
      this.issueTokens(tx, {
        userId: input.userId,
        organizationId: input.organizationId,
        workspaceId: input.workspaceId,
        label: DESKTOP_SESSION_LABEL,
      }, { tokenFamilyId: input.tokenFamilyId, scopes: DESKTOP_SCOPES }));
  }

  /**
   * POST /cloud/api/auth/workspace: replaces an account session with a new
   * one bound to the chosen workspace (membership checked live), revokes the
   * old one and remembers the selection in users.last_*.
   */
  async switchAccountSession(input: {
    sessionId: string;
    userId: string;
    workspaceId: string;
  }): Promise<IssuedTokens | null> {
    return this.database.transaction(async (tx) => {
      const current = await tx.query<{ label: string | null; token_family_id: string }>(
        `SELECT label, token_family_id FROM token_sessions
          WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND $3 = ANY(scopes)
          FOR UPDATE`,
        [input.sessionId, input.userId, ACCOUNT_SCOPE],
      );
      const session = current.rows[0];
      if (!session) return null;
      const target = await tx.query<{ organization_id: string }>(
        `SELECT w.organization_id
           FROM workspaces w
           JOIN organization_memberships m
             ON m.organization_id = w.organization_id AND m.user_id = $2
          WHERE w.id = $1
          FOR SHARE OF m`,
        [input.workspaceId, input.userId],
      );
      const organizationId = target.rows[0]?.organization_id;
      if (!organizationId) return null;
      const tokens = await this.issueTokens(tx, {
        userId: input.userId,
        organizationId,
        workspaceId: input.workspaceId,
        label: session.label,
      }, { scopes: ACCOUNT_SCOPES });
      await tx.query(
        `UPDATE token_sessions
            SET revoked_at = now(), revoked_reason = 'workspace_switch', updated_at = now()
          WHERE id = $1`,
        [input.sessionId],
      );
      await tx.query(
        "UPDATE users SET last_organization_id = $2, last_workspace_id = $3, updated_at = now() WHERE id = $1",
        [input.userId, organizationId, input.workspaceId],
      );
      return tokens;
    });
  }

  /**
   * Records a proven Relaycast node as the claimant's own (hosted Cloud's
   * claimNode). Idempotent for the same person; another owner, or ownership
   * through another workspace or a previous relay binding, is refused.
   */
  async claimNode(input: {
    workspaceId: string;
    organizationId: string;
    relaycastWorkspaceId: string;
    nodeId: string;
    nodeName: string;
    userId: string;
  }): Promise<{ nodeId: string; claimed: boolean }> {
    return this.database.transaction(async (tx) => {
      const member = await tx.query<{ role: string }>(
        `SELECT role FROM organization_memberships
          WHERE organization_id = $1 AND user_id = $2 FOR SHARE`,
        [input.organizationId, input.userId],
      );
      if (!member.rows[0]) {
        throw new NodeClaimError(403, "Only an active member of this workspace's organization can claim its nodes.");
      }
      const existing = await tx.query<{ workspace_id: string; user_id: string; relaycast_workspace_id: string }>(
        `SELECT workspace_id, user_id, relaycast_workspace_id FROM fleet_node_owners
          WHERE (relaycast_workspace_id = $1 AND node_id = $2) OR (workspace_id = $3 AND node_id = $2)
          FOR UPDATE`,
        [input.relaycastWorkspaceId, input.nodeId, input.workspaceId],
      );
      for (const owner of existing.rows) {
        if (owner.relaycast_workspace_id !== input.relaycastWorkspaceId) {
          throw new NodeClaimError(409, "This workspace still owns that node through its previous relay. Release it first, then claim it again.");
        }
        if (owner.workspace_id !== input.workspaceId) {
          throw new NodeClaimError(409, "This node is owned through another workspace that shares its relay. Release it there first.");
        }
        if (owner.user_id === input.userId) return { nodeId: input.nodeId, claimed: false };
        throw new NodeClaimError(409, "Another person owns this node. They, or a workspace owner, must release it first.");
      }
      await tx.query(
        `INSERT INTO fleet_node_owners
          (id, workspace_id, organization_id, relaycast_workspace_id, node_id, node_name, user_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [randomUUID(), input.workspaceId, input.organizationId, input.relaycastWorkspaceId,
          input.nodeId, input.nodeName, input.userId],
      );
      return { nodeId: input.nodeId, claimed: true };
    });
  }

  /**
   * Every claim of a node id across the install's workspaces (at most one
   * per workspace), for verifying a machine id inside token introspection.
   * Read-only.
   */
  async nodeClaimsFor(nodeId: string): Promise<Array<{ workspaceId: string; userId: string }>> {
    const result = await this.database.query<{ workspace_id: string; user_id: string }>(
      `SELECT workspace_id, user_id FROM fleet_node_owners WHERE node_id = $1`,
      [nodeId],
    );
    return result.rows.map((row) => ({ workspaceId: row.workspace_id, userId: row.user_id }));
  }

  /** Removes a node's owner: the owner themselves, or an organization owner. */
  async releaseNode(input: {
    workspaceId: string;
    organizationId: string;
    nodeId: string;
    actorUserId: string;
  }): Promise<{ released: true }> {
    return this.database.transaction(async (tx) => {
      const member = await tx.query<{ role: string }>(
        `SELECT role FROM organization_memberships
          WHERE organization_id = $1 AND user_id = $2 FOR SHARE`,
        [input.organizationId, input.actorUserId],
      );
      const role = member.rows[0]?.role;
      const existing = await tx.query<{ id: string; user_id: string }>(
        `SELECT id, user_id FROM fleet_node_owners
          WHERE workspace_id = $1 AND node_id = $2 FOR UPDATE`,
        [input.workspaceId, input.nodeId],
      );
      const owner = existing.rows[0];
      if (!owner) throw new NodeClaimError(404, "No one owns that node in this workspace.");
      if (role !== "owner" && !(role && owner.user_id === input.actorUserId)) {
        throw new NodeClaimError(403, "Only the node's owner or a workspace owner can release it.");
      }
      await tx.query("DELETE FROM fleet_node_owners WHERE id = $1", [owner.id]);
      return { released: true as const };
    });
  }

  async revoke(token: string): Promise<boolean> {
    const hash = hashSecret(token);
    const result = await this.database.query<{ id: string }>(
      `UPDATE token_sessions AS s
          SET revoked_at = now(), revoked_reason = 'user_requested', updated_at = now()
        WHERE (access_token_hash = $1 OR refresh_token_hash = $1) AND revoked_at IS NULL
        RETURNING id`,
      [hash],
    );
    return result.rows.length === 1;
  }

  /**
   * Revokes every live session of a person (browser, CLI and Desktop token
   * sessions, and MCP OAuth grants) and deletes the Desktop relay identity
   * tokens they synced, e.g. after a password reset. Workspace API keys
   * belong to the workspace, and person messaging identities
   * (person_identities, the person's human agent per workspace)
   * are not sessions, so neither is touched.
   */
  async revokeAllForUser(
    executor: SqlExecutor,
    userId: string,
    reason: string,
  ): Promise<{ sessions: number; mcpGrants: number; desktopRelayIdentities: number }> {
    // The user lock comes first, before any row is changed: it is the lock
    // order (identity, user, organizations in id order) every writer of
    // this person's sessions and grants follows, so nothing for this person
    // commits between the session UPDATE and the grant revocation below.
    await lockUser(executor, userId);
    const sessions = await executor.query<{ id: string }>(
      `UPDATE token_sessions
          SET revoked_at = now(), revoked_reason = $2, updated_at = now()
        WHERE user_id = $1 AND revoked_at IS NULL
        RETURNING id`,
      [userId, reason],
    );
    // Desktop relay identity tokens let the MCP endpoint act as the person's
    // Desktop agents. They are deleted (the table has no revoked state), so
    // this server stops using them; Desktop syncs them again after the
    // person signs in. The Relaycast-issued tokens themselves are not
    // revoked at Relaycast (no revocation path exists for them here).
    const desktopRelayIdentities = await executor.query<{ id: string }>(
      "DELETE FROM desktop_relay_identities WHERE user_id = $1 RETURNING id",
      [userId],
    );
    // MCP OAuth grants go through the MCP store's revoker so each grant's
    // session family ends and a revocation tombstone (Relaycast teardown)
    // commits with it. That revoker needs user->org locks, taken in the
    // tenancy lock order (user above, then organizations in id order).
    const organizations = await executor.query<{ organization_id: string }>(
      `SELECT DISTINCT organization_id FROM mcp_oauth_grants
        WHERE user_id = $1 AND revoked_at IS NULL ORDER BY organization_id`,
      [userId],
    );
    for (const { organization_id } of organizations.rows) await lockOrganization(executor, organization_id);
    const grants = await executor.query<{ id: string }>(
      `SELECT id FROM mcp_oauth_grants WHERE user_id = $1 AND revoked_at IS NULL ORDER BY id`,
      [userId],
    );
    const now = new Date();
    let mcpGrants = 0;
    for (const { id } of grants.rows) {
      if (await revokeMcpOAuthGrantRows(executor, id, reason, now)) mcpGrants += 1;
    }
    return { sessions: sessions.rows.length, mcpGrants, desktopRelayIdentities: desktopRelayIdentities.rows.length };
  }

  /**
   * Ends what a person approved but nobody has collected yet: device and
   * browser authorizations approved by them (CLI, Desktop, dashboard) become
   * expired, and unredeemed MCP OAuth authorization codes are voided. Run
   * with revokeAllForUser so a credential change leaves no way back in.
   */
  async voidPendingAuthorizationsForUser(executor: SqlExecutor, userId: string): Promise<{ deviceAuthorizations: number; mcpCodes: number }> {
    const devices = await executor.query<{ id: string }>(
      `UPDATE device_authorizations
          SET status = 'expired', updated_at = now()
        WHERE approved_by_user_id = $1 AND status = 'approved'
        RETURNING id`,
      [userId],
    );
    // Expired, not consumed: redeeming a consumed code is treated as a
    // replay, which is a different path. The MCP store's membership
    // departure hooks void codes the same way.
    const codes = await executor.query<{ code_hash: string }>(
      `UPDATE mcp_oauth_authorization_codes
          SET expires_at = now()
        WHERE user_id = $1 AND consumed_at IS NULL AND expires_at > now()
        RETURNING code_hash`,
      [userId],
    );
    return { deviceAuthorizations: devices.rows.length, mcpCodes: codes.rows.length };
  }

  private async upsertUser(
    tx: SqlExecutor,
    emailInput: string,
    nameInput: string,
  ): Promise<{ id: string; email: string; name: string }> {
    const email = normalizeEmail(emailInput);
    const name = cleanName(nameInput, "name");
    // Multi mode: a person's name is global across organizations, so only an
    // insert sets it; an existing row keeps the name its owner chose.
    const result = await tx.query<{ id: string; email: string; name: string }>(
      this.tenancy === "multi"
        ? `INSERT INTO users (id, email, name) VALUES ($1, $2, $3)
           ON CONFLICT (email) DO UPDATE SET email = users.email
           RETURNING id, email, name`
        : `INSERT INTO users (id, email, name) VALUES ($1, $2, $3)
           ON CONFLICT (email) DO UPDATE SET name = EXCLUDED.name, updated_at = now()
           RETURNING id, email, name`,
      [randomUUID(), email, name],
    );
    return result.rows[0]!;
  }

  private async requireOrganization(
    executor: SqlExecutor,
    organizationId: string,
  ): Promise<void> {
    const result = await executor.query<{ id: string }>(
      `SELECT id
         FROM organizations
        WHERE id = $1
        FOR UPDATE`,
      [organizationId],
    );
    if (result.rows.length !== 1) {
      throw new OrganizationBoundaryError("Organization does not exist");
    }
  }

  /**
   * bootstrap-signup lane: a browser session (OIDC or email-link sign-in)
   * issued inside the caller's transaction, after it resolved the membership.
   */
  async issueBrowserSession(
    tx: SqlExecutor,
    input: { userId: string; organizationId: string; workspaceId: string; label: string },
  ): Promise<IssuedTokens> {
    return this.issueTokens(tx, input, { scopes: ACCOUNT_SCOPES });
  }

  private async issueTokens(
    tx: SqlExecutor,
    input: {
      userId: string;
      organizationId: string;
      workspaceId: string;
      label: string | null;
    },
    options: {
      scopes: readonly string[];
      accessTtlMs?: number;
      refreshTtlMs?: number;
      tokenFamilyId?: string;
      desktopExchangeChallenge?: string;
      desktopHostName?: string;
      desktopVerified?: boolean;
    },
  ): Promise<IssuedTokens> {
    const context = await tx.query<{ valid: boolean }>(
      `SELECT true AS valid
         FROM organizations o
         JOIN organization_memberships m
           ON m.organization_id = o.id AND m.user_id = $2
         JOIN workspaces w
           ON w.organization_id = o.id AND w.id = $3
        WHERE o.id = $1`,
      [input.organizationId, input.userId, input.workspaceId],
    );
    if (!context.rows[0]?.valid) {
      throw new OrganizationBoundaryError(
        "Token context is not part of this installation",
      );
    }
    const sessionId = randomUUID();
    const accessToken = opaqueToken("sh_at_");
    const refreshToken = opaqueToken("sh_rt_");
    const accessExpires = new Date(Date.now() + (options.accessTtlMs ?? ACCESS_TOKEN_TTL_MS));
    const refreshExpires = new Date(Date.now() + (options.refreshTtlMs ?? REFRESH_TOKEN_TTL_MS));
    await tx.query(
      `INSERT INTO token_sessions
        (id, token_family_id, user_id, organization_id, workspace_id, label, scopes,
         access_token_hash, refresh_token_hash, access_token_expires_at, refresh_token_expires_at,
         desktop_exchange_challenge, desktop_host_name, desktop_verified_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
               CASE WHEN $14::boolean THEN now() ELSE NULL END)`,
      [
        sessionId,
        options.tokenFamilyId ?? randomUUID(),
        input.userId,
        input.organizationId,
        input.workspaceId,
        input.label,
        [...options.scopes],
        hashSecret(accessToken),
        hashSecret(refreshToken),
        accessExpires,
        refreshExpires,
        options.desktopExchangeChallenge ?? null,
        options.desktopHostName ?? null,
        options.desktopVerified === true,
      ],
    );
    return {
      sessionId,
      accessToken,
      accessTokenExpiresAt: accessExpires.toISOString(),
      refreshToken,
      refreshTokenExpiresAt: refreshExpires.toISOString(),
      scopes: [...options.scopes],
    };
  }
}
