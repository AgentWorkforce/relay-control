import { randomUUID } from "node:crypto";
import type { Database, SqlExecutor } from "../database.js";
import { hashSecret, opaqueToken } from "../crypto.js";
import type { Principal } from "../store.js";

/**
 * Desktop-provider MCP credentials, ported from Cloud's
 * `packages/web/lib/auth/desktop-provider-credentials.ts` onto the self-host
 * token class. Agent Relay Desktop mints a secret (`sh_at_` + 43 base64url),
 * saves it before any I/O, and registers it here with its own verified
 * sign-in. The secret becomes a child token session: scopes `rth:read` and
 * `mcp:desktop`, a 15-minute lease Desktop renews, never longer than the
 * parent's refresh lifetime, and usable only at the shared-sessions MCP
 * endpoint. Only the hash is stored; no route ever returns a secret.
 */

export const DESKTOP_MCP_SCOPE = "mcp:desktop";
export const DESKTOP_MCP_SCOPES = ["rth:read", DESKTOP_MCP_SCOPE] as const;
export const DESKTOP_MCP_CAPABILITY = "com.agentrelay/desktop-provider-credentials";
export const DESKTOP_MCP_LEASE_SECONDS = 15 * 60;
export const MAX_CREDENTIALS_PER_PARENT = 128;
export const DESKTOP_MCP_TOKEN = /^sh_at_[A-Za-z0-9_-]{43}$/;
export const PROVIDER = /^[a-z][a-z0-9-]{0,63}$/;
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class DesktopMcpCredentialError extends Error {
  constructor(readonly status: number, readonly code: string, message: string, readonly extra?: Record<string, string>) {
    super(message);
    this.name = "DesktopMcpCredentialError";
  }
}

export type DesktopMcpCredential = {
  id: string;
  workspaceId: string;
  provider: string;
  installationId: string;
  accessTokenExpiresAt: string;
  leaseExpiresAt: string;
  createdAt: string;
  scopes: string[];
};

type ParentRow = {
  id: string;
  user_id: string;
  organization_id: string;
  workspace_id: string;
  token_family_id: string;
  refresh_token_expires_at: Date | string;
};

type CredentialRow = {
  id: string;
  workspace_id: string;
  provider: string;
  installation_id: string;
  access_token_expires_at: Date | string;
  created_at: Date | string;
  scopes: string[];
};

const PARENT_REQUIRED = () => new DesktopMcpCredentialError(
  403, "desktop_login_required", "An Agent Relay app login is required.");
const NOT_FOUND = () => new DesktopMcpCredentialError(404, "token_not_found", "Token not found");
const CONFLICT = (existingId?: string) => new DesktopMcpCredentialError(
  409, "credential_conflict", "This provider credential must be removed before it can be replaced.",
  existingId ? { credential_id: existingId } : undefined);

function iso(value: Date | string): string {
  return new Date(value).toISOString();
}

function credential(row: CredentialRow): DesktopMcpCredential {
  const expires = iso(row.access_token_expires_at);
  return {
    id: row.id,
    workspaceId: row.workspace_id,
    provider: row.provider,
    installationId: row.installation_id,
    accessTokenExpiresAt: expires,
    leaseExpiresAt: expires,
    createdAt: iso(row.created_at),
    scopes: [...row.scopes],
  };
}

function isUniqueViolation(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  if ((error as { code?: unknown }).code === "23505") return true;
  return error instanceof Error && error.message.includes("duplicate key");
}

const CREDENTIAL_COLUMNS = `s.id, s.workspace_id, c.provider, c.installation_id,
       s.access_token_expires_at, c.created_at, s.scopes`;

export class DesktopMcpCredentials {
  constructor(private readonly database: Database) {}

  /**
   * The caller's own verified Desktop sign-in, locked. `parentToken` is the
   * presented bearer: the row is matched by its own access hash (never by
   * token family), must be a redeemed browser-consent session (host name and
   * verification recorded, not a pending handoff), carry `cli:auth` and not
   * be a child, and be live for both access and refresh. The membership is
   * locked first so a concurrent removal cannot race the issue.
   */
  private async lockParent(tx: SqlExecutor, parentToken: string, workspaceId: string): Promise<ParentRow> {
    const parent = await tx.query<ParentRow>(
      `SELECT p.id, p.user_id, p.organization_id, p.workspace_id, p.token_family_id,
              p.refresh_token_expires_at
         FROM token_sessions p
        WHERE p.access_token_hash = $1 AND p.workspace_id = $2
          AND p.revoked_at IS NULL
          AND p.access_token_expires_at > now() AND p.refresh_token_expires_at > now()
          AND p.desktop_host_name IS NOT NULL AND p.desktop_verified_at IS NOT NULL
          AND p.desktop_exchange_challenge IS NULL
          AND 'cli:auth' = ANY(p.scopes) AND NOT ('mcp:desktop' = ANY(p.scopes))
        FOR UPDATE`,
      [hashSecret(parentToken), workspaceId],
    );
    const row = parent.rows[0];
    if (!row) throw PARENT_REQUIRED();
    const member = await tx.query<{ role: string }>(
      `SELECT m.role
         FROM organization_memberships m
         JOIN workspaces w ON w.organization_id = m.organization_id AND w.id = $3
        WHERE m.organization_id = $1 AND m.user_id = $2
          AND NOT EXISTS (
            SELECT 1 FROM organizations other WHERE other.id <> m.organization_id
          )
        FOR UPDATE OF m`,
      [row.organization_id, row.user_id, workspaceId],
    );
    if (member.rows.length !== 1) {
      throw new DesktopMcpCredentialError(403, "workspace_access_changed", "Workspace access changed. Refresh and try again.");
    }
    return row;
  }

  private async renewChild(tx: SqlExecutor, parent: ParentRow, childId: string): Promise<CredentialRow | null> {
    const renewed = await tx.query<{ id: string }>(
      `UPDATE token_sessions
          SET access_token_expires_at = LEAST(now() + make_interval(secs => $2), $3::timestamptz),
              refresh_token_expires_at = LEAST(now() + make_interval(secs => $2), $3::timestamptz),
              last_refreshed_at = now(), updated_at = now()
        WHERE id = $1 AND revoked_at IS NULL
        RETURNING id`,
      [childId, DESKTOP_MCP_LEASE_SECONDS, new Date(parent.refresh_token_expires_at)],
    );
    if (renewed.rows.length !== 1) return null;
    return this.read(tx, parent.id, childId);
  }

  private async read(tx: SqlExecutor, parentId: string, childId: string): Promise<CredentialRow | null> {
    const found = await tx.query<CredentialRow>(
      `SELECT ${CREDENTIAL_COLUMNS}
         FROM desktop_mcp_credentials c
         JOIN token_sessions s ON s.id = c.token_session_id
        WHERE c.parent_session_id = $1 AND c.token_session_id = $2`,
      [parentId, childId],
    );
    return found.rows[0] ?? null;
  }

  /**
   * Registers (or, for Desktop's retry with the same saved secret, renews)
   * the provider credential for this installation and provider. A different
   * secret, or one that was revoked, must be removed first.
   */
  async issue(input: {
    parentToken: string;
    workspaceId: string;
    provider: string;
    installationId: string;
    accessToken: string;
  }): Promise<DesktopMcpCredential> {
    const installationId = input.installationId.toLowerCase();
    try {
      return await this.database.transaction(async (tx) => {
        const parent = await this.lockParent(tx, input.parentToken, input.workspaceId);
        const existing = await tx.query<{ id: string; access_token_hash: string; revoked: boolean }>(
          `SELECT s.id, s.access_token_hash, s.revoked_at IS NOT NULL AS revoked
             FROM desktop_mcp_credentials c
             JOIN token_sessions s ON s.id = c.token_session_id
            WHERE c.parent_session_id = $1 AND c.installation_id = $2 AND c.provider = $3
            FOR UPDATE OF s`,
          [parent.id, installationId, input.provider],
        );
        const prior = existing.rows[0];
        if (prior) {
          if (prior.revoked || prior.access_token_hash !== hashSecret(input.accessToken)) throw CONFLICT(prior.id);
          const renewed = await this.renewChild(tx, parent, prior.id);
          if (!renewed) throw CONFLICT(prior.id);
          return credential(renewed);
        }
        const count = await tx.query<{ count: number | string }>(
          `SELECT count(*) AS count FROM desktop_mcp_credentials WHERE parent_session_id = $1`,
          [parent.id],
        );
        if (Number(count.rows[0]?.count ?? 0) >= MAX_CREDENTIALS_PER_PARENT) {
          throw new DesktopMcpCredentialError(409, "too_many_credentials", "Too many provider credentials for this app login.");
        }
        const childId = randomUUID();
        await tx.query(
          `INSERT INTO token_sessions
            (id, token_family_id, user_id, organization_id, workspace_id, label, scopes,
             access_token_hash, refresh_token_hash, access_token_expires_at, refresh_token_expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                   LEAST(now() + make_interval(secs => $10), $11::timestamptz),
                   LEAST(now() + make_interval(secs => $10), $11::timestamptz))`,
          [
            childId,
            parent.token_family_id,
            parent.user_id,
            parent.organization_id,
            parent.workspace_id,
            `Agent Relay: ${input.provider}`,
            [...DESKTOP_MCP_SCOPES],
            hashSecret(input.accessToken),
            // A refresh token nobody holds: the child renews only through PUT.
            hashSecret(opaqueToken("sh_rt_")),
            DESKTOP_MCP_LEASE_SECONDS,
            new Date(parent.refresh_token_expires_at),
          ],
        );
        await tx.query(
          `INSERT INTO desktop_mcp_credentials
             (token_session_id, parent_session_id, installation_id, provider)
           VALUES ($1, $2, $3, $4)`,
          [childId, parent.id, installationId, input.provider],
        );
        const row = await this.read(tx, parent.id, childId);
        return credential(row!);
      });
    } catch (error) {
      // The secret is already a token (another binding or session): refuse
      // without saying whose.
      if (isUniqueViolation(error)) throw CONFLICT();
      throw error;
    }
  }

  /** This verified sign-in's live provider credentials, metadata only. */
  async list(parentToken: string, workspaceId: string): Promise<DesktopMcpCredential[]> {
    return this.database.transaction(async (tx) => {
      const parent = await this.lockParent(tx, parentToken, workspaceId);
      const rows = await tx.query<CredentialRow>(
        `SELECT ${CREDENTIAL_COLUMNS}
           FROM desktop_mcp_credentials c
           JOIN token_sessions s ON s.id = c.token_session_id
          WHERE c.parent_session_id = $1 AND s.revoked_at IS NULL
          ORDER BY c.created_at, s.id`,
        [parent.id],
      );
      return rows.rows.map(credential);
    });
  }

  /** Extends the lease by 15 minutes (capped at the parent's refresh expiry). */
  async renew(parentToken: string, workspaceId: string, tokenId: string): Promise<DesktopMcpCredential> {
    if (!UUID.test(tokenId)) throw NOT_FOUND();
    return this.database.transaction(async (tx) => {
      const parent = await this.lockParent(tx, parentToken, workspaceId);
      const row = await this.read(tx, parent.id, tokenId.toLowerCase());
      if (!row) throw NOT_FOUND();
      const renewed = await this.renewChild(tx, parent, row.id);
      if (!renewed) throw NOT_FOUND();
      return credential(renewed);
    });
  }

  /** Revokes the child session and removes its binding. */
  async revoke(parentToken: string, workspaceId: string, tokenId: string): Promise<void> {
    if (!UUID.test(tokenId)) throw NOT_FOUND();
    await this.database.transaction(async (tx) => {
      const parent = await this.lockParent(tx, parentToken, workspaceId);
      const removed = await tx.query<{ token_session_id: string }>(
        `DELETE FROM desktop_mcp_credentials
          WHERE parent_session_id = $1 AND token_session_id = $2
          RETURNING token_session_id`,
        [parent.id, tokenId.toLowerCase()],
      );
      if (removed.rows.length !== 1) throw NOT_FOUND();
      await tx.query(
        `UPDATE token_sessions
            SET revoked_at = now(), revoked_reason = 'desktop_provider_removed', updated_at = now()
          WHERE id = $1 AND revoked_at IS NULL`,
        [tokenId.toLowerCase()],
      );
    });
  }

  /**
   * The MCP endpoint's resolution of a child credential, checked live on
   * every request: the child is unrevoked inside its lease; its parent is
   * still an unrevoked, verified Desktop sign-in inside its refresh
   * lifetime; the person is still a member of the same organization and
   * workspace. Returns null for anything else, including non-child tokens.
   */
  async resolve(token: string): Promise<{ principal: Principal; provider: string } | null> {
    if (!DESKTOP_MCP_TOKEN.test(token)) return null;
    const result = await this.database.query<{
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
      provider: string;
    }>(
      `SELECT s.id AS session_id, s.token_family_id, s.user_id, u.email,
              u.name AS user_name, s.organization_id, o.name AS organization_name,
              s.workspace_id, w.name AS workspace_name, m.role, s.scopes, c.provider
         FROM token_sessions s
         JOIN desktop_mcp_credentials c ON c.token_session_id = s.id
         JOIN token_sessions p ON p.id = c.parent_session_id
         JOIN users u ON u.id = s.user_id
         JOIN organizations o ON o.id = s.organization_id
         JOIN workspaces w
           ON w.id = s.workspace_id AND w.organization_id = s.organization_id
         JOIN organization_memberships m
           ON m.organization_id = s.organization_id AND m.user_id = s.user_id
        WHERE s.access_token_hash = $1
          AND 'mcp:desktop' = ANY(s.scopes)
          AND s.revoked_at IS NULL AND s.access_token_expires_at > now()
          AND p.user_id = s.user_id AND p.workspace_id = s.workspace_id
          AND p.organization_id = s.organization_id
          AND p.revoked_at IS NULL AND p.refresh_token_expires_at > now()
          AND p.desktop_host_name IS NOT NULL AND p.desktop_verified_at IS NOT NULL
          AND NOT EXISTS (
            SELECT 1 FROM organizations other WHERE other.id <> s.organization_id
          )`,
      [hashSecret(token)],
    );
    const row = result.rows[0];
    if (!row) return null;
    return {
      provider: row.provider,
      principal: {
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
      },
    };
  }
}
