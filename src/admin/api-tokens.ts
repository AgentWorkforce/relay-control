import { randomUUID } from "node:crypto";
import type { Database, SqlExecutor } from "../database.js";
import { hashSecret, opaqueToken } from "../crypto.js";
import { normalizedOrigin } from "../auth/introspect.js";
import { normalizeEmailAddress } from "../identity/config.js";
import { NODE_ID_PATTERN } from "../store.js";
import { lockIdentity, lockOrganization } from "../tenancy.js";
import { iso, recordAudit, type AuditActor } from "./audit.js";

export const API_TOKEN_PREFIX = "sh_wk_";
/**
 * Desktop enrollment keys (docs/identity.md, "Desktop enrollment keys"). Never
 * `sh_wk_`: every bearer gate and introspection refuse this prefix by its
 * shape, without a lookup. Only POST /api/v1/auth/enrollment/token reads it.
 */
export const ENROLLMENT_KEY_PREFIX = "sh_ek_";
export const MAX_API_TOKEN_EXPIRY_DAYS = 365;
export const MAX_ENROLLMENT_KEY_EXPIRY_DAYS = 30;
export const DEFAULT_ENROLLMENT_KEY_EXPIRY_DAYS = 7;
/** Member self-mint (gate-only): longest and default relay-node token lifetime. */
export const MAX_SELF_MINTED_RELAY_NODE_EXPIRY_DAYS = 90;
/** Member self-mint: live relay-node tokens one person may hold in a workspace. */
export const MAX_SELF_MINTED_RELAY_NODE_TOKENS = 3;

/** Mirrors hosted lib/auth/api-token-types.ts, plus self-host runtime scopes. */
export const API_TOKEN_PURPOSE_SCOPES = {
  "agent-runtime": ["runtime:env:read", "runtime:integrations:read"],
  workflow: [
    "flows:listeners:write",
    "workflow:invoke:read",
    "workflow:invoke:write",
    "workflow:runs:read",
    "workflow:logs:read",
    "runtime:env:read",
    "runtime:integrations:read",
  ],
  deployment: ["deployments:ci:read", "deployments:ci:write"],
  /**
   * Presented by an agent to relayfile, which verifies it through
   * POST /internal/v1/auth/introspect. Never carries admin scopes.
   */
  "relayfile-agent": ["fs:read", "fs:write", "sync:read", "sync:trigger"],
  /**
   * Presented by an operator service (Backend, Cloud) to RelayHistory, which
   * verifies it through introspection as a `service` principal.
   */
  "acquisition-operator": ["acquisition:operate"],
  /**
   * Presented by an agent-relay-node host to this service's /relay-node/v1
   * broker (docs/relay-node-credential.md) instead of the workspace's
   * Relaycast key. Bound to one node name; never passes the /api/v1 gate.
   */
  "relay-node": ["relay:workspace:read", "relay:nodes:read", "relay:nodes:enroll", "relay:agents:read"],
  /**
   * A single-use `sh_ek_` key bound to one member, exchanged once for a
   * device session (POST /api/v1/auth/enrollment/token). The key is never a
   * bearer, so it carries no scopes; the session it yields carries the
   * device scopes.
   */
  "desktop-enrollment": [],
} as const satisfies Record<string, readonly string[]>;

export type ApiTokenPurpose = keyof typeof API_TOKEN_PURPOSE_SCOPES;

export const RELAYFILE_AGENT_PURPOSE = "relayfile-agent" satisfies ApiTokenPurpose;
export const ACQUISITION_OPERATOR_PURPOSE = "acquisition-operator" satisfies ApiTokenPurpose;
export const RELAY_NODE_PURPOSE = "relay-node" satisfies ApiTokenPurpose;
export const DESKTOP_ENROLLMENT_PURPOSE = "desktop-enrollment" satisfies ApiTokenPurpose;
/** The one desktop-enrollment consent value (docs/identity.md, "MCP consent"). */
export const ENROLLMENT_MCP_CONSENT_ADMIN = "admin";

export class ApiTokenError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
    this.name = "ApiTokenError";
  }
}

export type ApiTokenRecord = {
  id: string;
  label: string;
  purpose: ApiTokenPurpose;
  scopes: string[];
  tokenPrefix: string;
  createdBy: { id: string; name: string | null; email: string | null } | null;
  createdAt: string;
  accessTokenExpiresAt: string | null;
  lastUsedAt: string | null;
  revokedAt: string | null;
  /** `exchanged`: a spent desktop-enrollment key (revoked wins over it, it wins over expired). */
  status: "active" | "expired" | "revoked" | "exchanged";
  /**
   * relayfile-agent: the agent the token speaks for; relay-node: the node
   * name (same value as nodeName); else null.
   */
  agent_name: string | null;
  /** relay-node only: the node the token is bound to; else null. */
  nodeName: string | null;
  /** relayfile-agent and acquisition-operator: the normalized audience origin; else null. */
  aud: string | null;
  /** desktop-enrollment only: the member the key signs in; else null. */
  userId: string | null;
  userEmail: string | null;
  /** desktop-enrollment only: "admin" when the minting admin granted MCP consent; else null. */
  mcpConsent: "admin" | null;
  /** desktop-enrollment only: when the single exchange happened, and for which host. */
  exchangedAt: string | null;
  exchangedHostName: string | null;
};

export type ApiTokenPrincipal = {
  tokenId: string;
  workspaceId: string;
  organizationId: string;
  scopes: string[];
};

/** A live relay-node token, as the /relay-node/v1 broker sees it. */
export type RelayNodePrincipal = {
  tokenId: string;
  workspaceId: string;
  organizationId: string;
  nodeName: string;
};

type Row = {
  id: string;
  label: string;
  purpose: ApiTokenPurpose;
  scopes: string[];
  token_prefix: string;
  created_by_user_id: string | null;
  creator_name: string | null;
  creator_email: string | null;
  created_at: Date | string;
  expires_at: Date | string | null;
  last_used_at: Date | string | null;
  revoked_at: Date | string | null;
  agent_name: string | null;
  aud: string | null;
  user_id: string | null;
  user_email: string | null;
  mcp_consent: "admin" | null;
  exchanged_at: Date | string | null;
  exchanged_host_name: string | null;
};

/** What introspection needs to judge a presented sh_wk_ token. */
export type ApiTokenIntrospection = {
  tokenId: string;
  workspaceId: string;
  cloudRelayWorkspaceId: string | null;
  organizationId: string;
  purpose: ApiTokenPurpose;
  scopes: string[];
  agentName: string | null;
  aud: string | null;
  createdAt: Date;
  expiresAt: Date | null;
  revoked: boolean;
  expired: boolean;
};

function toRecord(row: Row): ApiTokenRecord {
  const expired = row.expires_at !== null && Date.parse(iso(row.expires_at)) <= Date.now();
  return {
    id: row.id,
    label: row.label,
    purpose: row.purpose,
    scopes: row.scopes,
    tokenPrefix: row.token_prefix,
    createdBy: row.created_by_user_id
      ? { id: row.created_by_user_id, name: row.creator_name, email: row.creator_email }
      : null,
    createdAt: iso(row.created_at),
    accessTokenExpiresAt: row.expires_at ? iso(row.expires_at) : null,
    lastUsedAt: row.last_used_at ? iso(row.last_used_at) : null,
    revokedAt: row.revoked_at ? iso(row.revoked_at) : null,
    status: row.revoked_at
      ? "revoked"
      : row.purpose === DESKTOP_ENROLLMENT_PURPOSE && row.exchanged_at
        ? "exchanged"
        : expired ? "expired" : "active",
    agent_name: row.agent_name,
    nodeName: row.purpose === RELAY_NODE_PURPOSE ? row.agent_name : null,
    aud: row.aud,
    userId: row.user_id,
    userEmail: row.user_email,
    mcpConsent: row.mcp_consent,
    exchangedAt: row.exchanged_at ? iso(row.exchanged_at) : null,
    exchangedHostName: row.exchanged_host_name,
  };
}

const SELECT = `SELECT t.id, t.label, t.purpose, t.scopes, t.token_prefix, t.created_by_user_id,
         u.name AS creator_name, u.email AS creator_email, t.created_at, t.expires_at,
         t.last_used_at, t.revoked_at, t.agent_name, t.aud, t.user_id, bu.email AS user_email,
         t.mcp_consent, t.exchanged_at, t.exchanged_host_name
    FROM workspace_api_tokens t
    LEFT JOIN users u ON u.id = t.created_by_user_id
    LEFT JOIN users bu ON bu.id = t.user_id`;

/** A desktop-enrollment key as its bound member sees it (GET /api/v1/me/enrollment-keys). */
export type EnrollmentKeySummary = {
  id: string;
  label: string;
  status: ApiTokenRecord["status"];
  mcpConsent: "admin" | null;
  createdAt: string;
  expiresAt: string | null;
  exchangedAt: string | null;
  exchangedHostName: string | null;
  mintedBy: { id: string; name: string | null } | null;
};

function toEnrollmentKeySummary(record: ApiTokenRecord): EnrollmentKeySummary {
  return {
    id: record.id,
    label: record.label,
    status: record.status,
    mcpConsent: record.mcpConsent,
    createdAt: record.createdAt,
    expiresAt: record.accessTokenExpiresAt,
    exchangedAt: record.exchangedAt,
    exchangedHostName: record.exchangedHostName,
    mintedBy: record.createdBy ? { id: record.createdBy.id, name: record.createdBy.name } : null,
  };
}

export type CreateApiTokenInput = {
  workspaceId: string;
  organizationId: string;
  label: unknown;
  purpose: unknown;
  expiryDays: unknown;
  neverExpires: unknown;
  agentName?: unknown;
  /** relay-node only (the body's `nodeName`); refused for every other purpose. */
  nodeName?: unknown;
  aud?: unknown;
  /** Any value here (the body's `scope` or `scopes`) is refused. */
  scope?: unknown;
  scopes?: unknown;
  /** desktop-enrollment only (required there): the member the key signs in. */
  email?: unknown;
  /** desktop-enrollment only: "admin" makes the exchanged session Desktop-verified. */
  mcpConsent?: unknown;
  actor: AuditActor & { kind: "user" };
};

export class ApiTokenStore {
  /**
   * `audiences` lists the normalized origins introspection accepts (empty while
   * introspection is disabled); a relayfile-agent or acquisition-operator
   * token's aud must be one.
   */
  constructor(
    private readonly database: Database,
    private readonly audiences: () => string[] = () => [],
  ) {}

  /**
   * The newest 100 tokens of a workspace, optionally of one purpose (so
   * mass-minted enrollment keys cannot push other tokens off the list).
   */
  async list(workspaceId: string, purpose?: ApiTokenPurpose): Promise<ApiTokenRecord[]> {
    const result = await this.database.query<Row>(
      `${SELECT} WHERE t.workspace_id = $1 AND ($2::text IS NULL OR t.purpose = $2)
        ORDER BY t.created_at DESC LIMIT 100`,
      [workspaceId, purpose ?? null],
    );
    return result.rows.map(toRecord);
  }

  /** Mints one token in its own transaction; see createIn. */
  async create(input: CreateApiTokenInput): Promise<ApiTokenRecord & { accessToken: string }> {
    return this.database.transaction((tx) => this.createIn(tx, input));
  }

  /**
   * Validates, inserts and audits one token on the caller's executor, so a
   * caller can mint inside its own transaction (Factory acquisition
   * enrollment). The plaintext `accessToken` is returned once and is never
   * stored or audited.
   */
  async createIn(
    tx: SqlExecutor,
    input: CreateApiTokenInput,
  ): Promise<ApiTokenRecord & { accessToken: string }> {
    if (typeof input.label !== "string" || !input.label.trim() || input.label.trim().length > 128) {
      throw new ApiTokenError(400, "invalid_request", "label must be 1-128 characters");
    }
    const label = input.label.replace(/[\p{C}]/gu, " ").trim();
    const purpose = (input.purpose ?? "deployment") as ApiTokenPurpose;
    if (!Object.hasOwn(API_TOKEN_PURPOSE_SCOPES, purpose)) {
      throw new ApiTokenError(
        400,
        "invalid_request",
        `purpose must be one of ${Object.keys(API_TOKEN_PURPOSE_SCOPES).join(", ")}`,
      );
    }
    if (input.scope !== undefined || input.scopes !== undefined) {
      throw new ApiTokenError(400, "invalid_request", "scopes are fixed by purpose");
    }
    let agentName: string | null = null;
    let aud: string | null = null;
    if (purpose === RELAYFILE_AGENT_PURPOSE) {
      if (typeof input.agentName !== "string" || !NODE_ID_PATTERN.test(input.agentName)) {
        throw new ApiTokenError(
          400,
          "invalid_request",
          "agent_name is required: 1-200 characters of letters, digits, '.', '_', ':' or '-'",
        );
      }
      agentName = input.agentName;
    } else if (input.agentName !== undefined) {
      throw new ApiTokenError(
        400,
        "invalid_request",
        "agent_name is only accepted for relayfile-agent tokens",
      );
    }
    if (purpose === RELAY_NODE_PURPOSE) {
      if (typeof input.nodeName !== "string" || !NODE_ID_PATTERN.test(input.nodeName)) {
        throw new ApiTokenError(
          400,
          "invalid_request",
          "nodeName is required: 1-200 characters of letters, digits, '.', '_', ':' or '-'",
        );
      }
      // Stored in agent_name. Several live tokens per node are allowed (rotation).
      agentName = input.nodeName;
    } else if (input.nodeName !== undefined) {
      throw new ApiTokenError(400, "invalid_request", "nodeName is only accepted for relay-node tokens");
    }
    if (purpose === RELAYFILE_AGENT_PURPOSE || purpose === ACQUISITION_OPERATOR_PURPOSE) {
      const accepted = this.audiences();
      if (accepted.length === 0) {
        throw new ApiTokenError(
          400,
          "invalid_request",
          `${purpose} tokens need token introspection enabled (RELAYCONTROL_INTROSPECT_SECRET)`,
        );
      }
      const normalized = typeof input.aud === "string" ? normalizedOrigin(input.aud) : null;
      if (normalized === null || !accepted.includes(normalized)) {
        throw new ApiTokenError(
          400,
          "invalid_request",
          `aud must be one of the accepted introspection audiences: ${accepted.join(", ")}`,
        );
      }
      aud = normalized;
    } else if (input.aud !== undefined) {
      throw new ApiTokenError(
        400,
        "invalid_request",
        "aud is only accepted for relayfile-agent and acquisition-operator tokens",
      );
    }
    const enrollment = purpose === DESKTOP_ENROLLMENT_PURPOSE;
    let email: string | null = null;
    let mcpConsent: "admin" | null = null;
    if (enrollment) {
      email = typeof input.email === "string" ? normalizeEmailAddress(input.email) : null;
      if (email === null) {
        throw new ApiTokenError(400, "invalid_request", "email is required for desktop-enrollment keys");
      }
      if (input.mcpConsent !== undefined && input.mcpConsent !== null) {
        if (input.mcpConsent !== ENROLLMENT_MCP_CONSENT_ADMIN) {
          throw new ApiTokenError(400, "invalid_request", "mcpConsent must be \"admin\" or absent");
        }
        mcpConsent = ENROLLMENT_MCP_CONSENT_ADMIN;
      }
    } else if (input.email !== undefined || input.mcpConsent !== undefined) {
      throw new ApiTokenError(
        400,
        "invalid_request",
        "email and mcpConsent are only accepted for desktop-enrollment keys",
      );
    }
    let expiresAt: Date | null;
    if (enrollment) {
      if (input.neverExpires !== undefined && input.neverExpires !== false) {
        throw new ApiTokenError(400, "invalid_request", "desktop-enrollment keys always expire");
      }
      const days = input.expiryDays ?? DEFAULT_ENROLLMENT_KEY_EXPIRY_DAYS;
      if (!Number.isInteger(days) || (days as number) < 1 || (days as number) > MAX_ENROLLMENT_KEY_EXPIRY_DAYS) {
        throw new ApiTokenError(
          400,
          "invalid_request",
          `expiryDays must be an integer from 1 to ${MAX_ENROLLMENT_KEY_EXPIRY_DAYS} for desktop-enrollment keys`,
        );
      }
      expiresAt = new Date(Date.now() + (days as number) * 24 * 60 * 60 * 1_000);
    } else if (input.neverExpires === true) {
      if (input.expiryDays !== undefined) {
        throw new ApiTokenError(400, "invalid_request", "neverExpires cannot be combined with expiryDays");
      }
      if (
        purpose !== "workflow" &&
        purpose !== RELAYFILE_AGENT_PURPOSE &&
        purpose !== ACQUISITION_OPERATOR_PURPOSE
      ) {
        throw new ApiTokenError(
          400,
          "invalid_request",
          "Only workflow, relayfile-agent and acquisition-operator tokens may never expire",
        );
      }
      expiresAt = null;
    } else {
      const days = input.expiryDays ?? 90;
      if (!Number.isInteger(days) || (days as number) < 1 || (days as number) > MAX_API_TOKEN_EXPIRY_DAYS) {
        throw new ApiTokenError(
          400,
          "invalid_request",
          `expiryDays must be an integer from 1 to ${MAX_API_TOKEN_EXPIRY_DAYS}`,
        );
      }
      expiresAt = new Date(Date.now() + (days as number) * 24 * 60 * 60 * 1_000);
    }
    const prefix = enrollment ? ENROLLMENT_KEY_PREFIX : API_TOKEN_PREFIX;
    const accessToken = opaqueToken(prefix);
    const id = randomUUID();
    const userId = enrollment
      ? await this.resolveEnrollmentMember(tx, {
          organizationId: input.organizationId,
          workspaceId: input.workspaceId,
          email: email!,
          actor: input.actor,
        })
      : null;
    const scopes = [...API_TOKEN_PURPOSE_SCOPES[purpose]];
    const duplicate = () =>
      new ApiTokenError(
        409,
        "agent_name_conflict",
        "An active relayfile-agent token already exists for this agent_name; revoke it first",
      );
    const oneLivePerAgent = purpose === RELAYFILE_AGENT_PURPOSE;
    try {
      if (oneLivePerAgent) {
        const existing = await tx.query(
          `SELECT 1 FROM workspace_api_tokens
            WHERE workspace_id = $1 AND purpose = $2 AND agent_name = $3 AND revoked_at IS NULL`,
          [input.workspaceId, RELAYFILE_AGENT_PURPOSE, agentName],
        );
        if (existing.rows.length > 0) throw duplicate();
      }
      await tx.query(
        `INSERT INTO workspace_api_tokens
           (id, workspace_id, label, purpose, scopes, token_hash, token_prefix,
            created_by_user_id, expires_at, agent_name, aud, user_id, mcp_consent)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
        [
          id,
          input.workspaceId,
          label,
          purpose,
          scopes,
          hashSecret(accessToken),
          accessToken.slice(0, prefix.length + 4),
          input.actor.userId,
          expiresAt?.toISOString() ?? null,
          agentName,
          aud,
          userId,
          mcpConsent,
        ],
      );
    } catch (error) {
      // A concurrent mint for the same agent loses on the partial unique index.
      if (oneLivePerAgent && String((error as { code?: unknown }).code) === "23505") throw duplicate();
      throw error;
    }
    await recordAudit(tx, {
      organizationId: input.organizationId,
      workspaceId: input.workspaceId,
      actor: input.actor,
      action: "api_token.create",
      target: enrollment
        ? `${id} (desktop-enrollment: user ${userId}${mcpConsent ? ` mcpConsent=${mcpConsent}` : ""})`
        : purpose === RELAY_NODE_PURPOSE
        ? `${id} (relay-node: ${agentName})`
        : agentName !== null
        ? `${id} (${purpose}: ${agentName} -> ${aud})`
        : aud !== null
          ? `${id} (${purpose} -> ${aud})`
          : `${id} (${purpose})`,
    });
    const record = (await tx.query<Row>(`${SELECT} WHERE t.id = $1`, [id])).rows[0]!;
    return { ...toRecord(record), accessToken };
  }

  /**
   * The member a desktop-enrollment key binds (docs/identity.md, "Desktop
   * enrollment keys"). An existing member of the organization is bound as
   * is. An email with no account is pre-created: the user (no password, no
   * verified-email claim; its name is the email's local part) and a `member`
   * membership, audited `membership.provision`. Someone who already has an
   * account but belongs only to other organizations is refused like an admin
   * adding them directly in multi tenancy: they accept an invitation instead.
   * Locks follow the tenancy order (identity, then organization) before any
   * row is read.
   */
  private async resolveEnrollmentMember(
    tx: SqlExecutor,
    input: {
      organizationId: string;
      workspaceId: string;
      email: string;
      actor: AuditActor & { kind: "user" };
    },
  ): Promise<string> {
    await lockIdentity(tx, input.email);
    await lockOrganization(tx, input.organizationId);
    const found = await tx.query<{ id: string; member: boolean; elsewhere: boolean }>(
      `SELECT u.id,
              EXISTS (SELECT 1 FROM organization_memberships m
                       WHERE m.organization_id = $2 AND m.user_id = u.id) AS member,
              EXISTS (SELECT 1 FROM organization_memberships m
                       WHERE m.organization_id <> $2 AND m.user_id = u.id) AS elsewhere
         FROM users u WHERE u.email = $1`,
      [input.email, input.organizationId],
    );
    const existing = found.rows[0];
    if (existing?.member) return existing.id;
    if (existing?.elsewhere) {
      throw new ApiTokenError(
        409,
        "invitation_required",
        "This person already has an account in another organization; invite them first",
      );
    }
    let userId = existing?.id;
    if (!userId) {
      const created = await tx.query<{ id: string }>(
        `INSERT INTO users (id, email, name) VALUES ($1, $2, $3)
         ON CONFLICT (email) DO UPDATE SET email = users.email
         RETURNING id`,
        [randomUUID(), input.email, input.email.slice(0, input.email.indexOf("@"))],
      );
      userId = created.rows[0]!.id;
    }
    await tx.query(
      `INSERT INTO organization_memberships (organization_id, user_id, role)
       VALUES ($1, $2, 'member')
       ON CONFLICT (organization_id, user_id) DO NOTHING`,
      [input.organizationId, userId],
    );
    await recordAudit(tx, {
      organizationId: input.organizationId,
      // The minting workspace, so the row shows in that workspace's audit
      // list beside the key's api_token.create.
      workspaceId: input.workspaceId,
      actor: input.actor,
      action: "membership.provision",
      target: `${userId} ${input.email} role member`,
    });
    return userId;
  }

  /**
   * The desktop-enrollment keys bound to one person in one organization,
   * newest first (GET /api/v1/me/enrollment-keys). Never the key itself.
   */
  async listForUser(input: { organizationId: string; userId: string }): Promise<EnrollmentKeySummary[]> {
    const result = await this.database.query<Row>(
      `${SELECT}
         JOIN workspaces w ON w.id = t.workspace_id
        WHERE t.user_id = $1 AND t.purpose = 'desktop-enrollment' AND w.organization_id = $2
        ORDER BY t.created_at DESC LIMIT 100`,
      [input.userId, input.organizationId],
    );
    return result.rows.map((row) => toEnrollmentKeySummary(toRecord(row)));
  }

  /**
   * whoami's `provisioning` for a session exchanged from a desktop-enrollment
   * key; null when the key row is gone.
   */
  async enrollmentProvisioning(tokenId: string): Promise<{
    kind: "enrollment_key";
    keyId: string;
    label: string;
    mcpConsent: "admin" | null;
    mintedBy: { id: string; name: string | null } | null;
    mintedAt: string;
    exchangedAt: string | null;
  } | null> {
    const result = await this.database.query<Row>(
      `${SELECT} WHERE t.id = $1 AND t.purpose = 'desktop-enrollment'`,
      [tokenId],
    );
    const row = result.rows[0];
    if (!row) return null;
    const summary = toEnrollmentKeySummary(toRecord(row));
    return {
      kind: "enrollment_key",
      keyId: summary.id,
      label: summary.label,
      mcpConsent: summary.mcpConsent,
      mintedBy: summary.mintedBy,
      mintedAt: summary.createdAt,
      exchangedAt: summary.exchangedAt,
    };
  }

  /**
   * DELETE /api/v1/me/enrollment-keys/{id}: the bound person revokes one of
   * their own live keys (with its sessions, as revokeIn does). False when the
   * key is absent, revoked already, or bound to someone else.
   */
  async revokeForUser(input: { organizationId: string; userId: string; tokenId: string }): Promise<boolean> {
    if (!/^[0-9a-f-]{36}$/i.test(input.tokenId)) return false;
    return this.database.transaction(async (tx) => {
      const found = await tx.query<{ workspace_id: string }>(
        `SELECT t.workspace_id
           FROM workspace_api_tokens t
           JOIN workspaces w ON w.id = t.workspace_id
          WHERE t.id = $1 AND t.user_id = $2 AND t.purpose = 'desktop-enrollment'
            AND w.organization_id = $3`,
        [input.tokenId, input.userId, input.organizationId],
      );
      const row = found.rows[0];
      if (!row) return false;
      return this.revokeIn(tx, {
        workspaceId: row.workspace_id,
        organizationId: input.organizationId,
        tokenId: input.tokenId,
        actor: { kind: "user", userId: input.userId },
      });
    });
  }

  /**
   * Membership removal: revokes every live desktop-enrollment key of the
   * departing person in the organization, exchanged ones included, so the
   * sessions they provisioned (Desktop-verified ones too) are revoked with
   * the membership instead of lying dormant until the person is re-added.
   * One `api_token.revoke` audit row each (target suffix
   * `reason=member_removed`). Runs inside the removal transaction.
   */
  async revokeEnrollmentKeysForMemberIn(
    tx: SqlExecutor,
    input: { organizationId: string; userId: string; actor: AuditActor },
  ): Promise<number> {
    const keys = await tx.query<{ id: string; workspace_id: string }>(
      `SELECT t.id, t.workspace_id
         FROM workspace_api_tokens t
         JOIN workspaces w ON w.id = t.workspace_id
        WHERE t.user_id = $1 AND t.purpose = 'desktop-enrollment' AND w.organization_id = $2
          AND t.revoked_at IS NULL
        ORDER BY t.id`,
      [input.userId, input.organizationId],
    );
    let revoked = 0;
    for (const key of keys.rows) {
      if (await this.revokeIn(tx, {
        workspaceId: key.workspace_id,
        organizationId: input.organizationId,
        tokenId: key.id,
        actor: input.actor,
        reason: "member_removed",
      })) revoked += 1;
    }
    return revoked;
  }

  /**
   * POST /api/v1/workspaces/{id}/relay-node/self-tokens (gate-only installs,
   * docs/relay-node-credential.md "Member self-mint"): the caller's signed-in
   * Desktop mints a relay-node token for its own node. One transaction under
   * a workspace-scoped lock, so the checks below and the insert cannot
   * interleave with another self-mint: 409 `node_name_taken` when another
   * person holds a live relay-node token for this node name (the same caller
   * may hold several, for rotation), 409 `too_many_tokens` when the caller
   * already holds MAX_SELF_MINTED_RELAY_NODE_TOKENS live relay-node tokens.
   * Audited `api_token.create` (by createIn) and `relay_node.token.self_minted`.
   */
  async createSelfMintedRelayNode(input: {
    workspaceId: string;
    organizationId: string;
    nodeName: unknown;
    label: unknown;
    expiryDays: unknown;
    neverExpires: unknown;
    desktopHostName: string;
    actor: AuditActor & { kind: "user" };
  }): Promise<ApiTokenRecord & { accessToken: string }> {
    if (typeof input.nodeName !== "string" || !NODE_ID_PATTERN.test(input.nodeName)) {
      throw new ApiTokenError(
        400,
        "invalid_request",
        "nodeName is required: 1-200 characters of letters, digits, '.', '_', ':' or '-'",
      );
    }
    if (input.neverExpires !== undefined && input.neverExpires !== false) {
      throw new ApiTokenError(400, "invalid_request", "Self-minted relay-node tokens always expire");
    }
    const days = input.expiryDays ?? MAX_SELF_MINTED_RELAY_NODE_EXPIRY_DAYS;
    if (!Number.isInteger(days) || (days as number) < 1 || (days as number) > MAX_SELF_MINTED_RELAY_NODE_EXPIRY_DAYS) {
      throw new ApiTokenError(
        400,
        "invalid_request",
        `expiryDays must be an integer from 1 to ${MAX_SELF_MINTED_RELAY_NODE_EXPIRY_DAYS} for self-minted relay-node tokens`,
      );
    }
    const nodeName = input.nodeName;
    const label = input.label === undefined ? `desktop ${input.desktopHostName}` : input.label;
    const userId = input.actor.userId;
    return this.database.transaction(async (tx) => {
      await tx.query(
        `SELECT pg_advisory_xact_lock(hashtext('relay-node-self-mint:' || $1::text))`,
        [input.workspaceId],
      );
      const live = `workspace_id = $1 AND purpose = '${RELAY_NODE_PURPOSE}' AND revoked_at IS NULL
                AND (expires_at IS NULL OR expires_at > now())`;
      const taken = await tx.query(
        `SELECT 1 FROM workspace_api_tokens
          WHERE ${live} AND agent_name = $2 AND created_by_user_id IS DISTINCT FROM $3
          LIMIT 1`,
        [input.workspaceId, nodeName, userId],
      );
      if (taken.rows.length > 0) {
        throw new ApiTokenError(
          409,
          "node_name_taken",
          "Another member holds a live relay-node token for this nodeName; pick another node name",
        );
      }
      const held = await tx.query<{ count: number | string }>(
        `SELECT count(*) AS count FROM workspace_api_tokens
          WHERE ${live} AND created_by_user_id = $2`,
        [input.workspaceId, userId],
      );
      if (Number(held.rows[0]?.count ?? 0) >= MAX_SELF_MINTED_RELAY_NODE_TOKENS) {
        throw new ApiTokenError(
          409,
          "too_many_tokens",
          `You already hold ${MAX_SELF_MINTED_RELAY_NODE_TOKENS} live relay-node tokens; revoke one first`,
        );
      }
      const created = await this.createIn(tx, {
        workspaceId: input.workspaceId,
        organizationId: input.organizationId,
        label,
        purpose: RELAY_NODE_PURPOSE,
        expiryDays: days,
        neverExpires: undefined,
        nodeName,
        actor: input.actor,
      });
      await recordAudit(tx, {
        organizationId: input.organizationId,
        workspaceId: input.workspaceId,
        actor: input.actor,
        action: "relay_node.token.self_minted",
        target: `${created.id} (relay-node: ${nodeName}) host=${input.desktopHostName}`,
      });
      return created;
    });
  }

  /**
   * GET .../relay-node/self-tokens: the caller's own live relay-node tokens
   * (created by them, not revoked, not expired), newest first. Never a value.
   */
  async listSelfMintedRelayNode(input: { workspaceId: string; userId: string }): Promise<ApiTokenRecord[]> {
    const result = await this.database.query<Row>(
      `${SELECT}
        WHERE t.workspace_id = $1 AND t.purpose = '${RELAY_NODE_PURPOSE}' AND t.created_by_user_id = $2
          AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > now())
        ORDER BY t.created_at DESC LIMIT 100`,
      [input.workspaceId, input.userId],
    );
    return result.rows.map(toRecord);
  }

  /**
   * DELETE .../relay-node/self-tokens/{tokenId}: revokes one of the caller's
   * own live relay-node tokens (audited `api_token.revoke` by revokeIn and
   * `relay_node.token.self_revoked`). False for any other token, so an
   * admin-minted or another member's token reads as absent.
   */
  async revokeSelfMintedRelayNode(input: {
    workspaceId: string;
    organizationId: string;
    tokenId: string;
    desktopHostName: string;
    actor: AuditActor & { kind: "user" };
  }): Promise<boolean> {
    if (!/^[0-9a-f-]{36}$/i.test(input.tokenId)) return false;
    return this.database.transaction(async (tx) => {
      const found = await tx.query<{ agent_name: string | null }>(
        `SELECT agent_name FROM workspace_api_tokens
          WHERE id = $1 AND workspace_id = $2 AND purpose = '${RELAY_NODE_PURPOSE}'
            AND created_by_user_id = $3 AND revoked_at IS NULL
          FOR UPDATE`,
        [input.tokenId, input.workspaceId, input.actor.userId],
      );
      const row = found.rows[0];
      if (!row) return false;
      if (!(await this.revokeIn(tx, input))) return false;
      await recordAudit(tx, {
        organizationId: input.organizationId,
        workspaceId: input.workspaceId,
        actor: input.actor,
        action: "relay_node.token.self_revoked",
        target: `${input.tokenId} (relay-node: ${row.agent_name}) host=${input.desktopHostName}`,
      });
      return true;
    });
  }

  async revoke(input: {
    workspaceId: string;
    organizationId: string;
    tokenId: string;
    actor: AuditActor & { kind: "user" };
  }): Promise<boolean> {
    if (!/^[0-9a-f-]{36}$/i.test(input.tokenId)) return false;
    return this.database.transaction((tx) => this.revokeIn(tx, input));
  }

  /**
   * Revokes one active token of the workspace on the caller's executor and
   * audits it. A non-user actor (a background reconciler) leaves
   * revoked_by_user_id null. False when the token is absent or already revoked.
   *
   * A desktop-enrollment key also revokes, in the same transaction, every
   * live session it provisioned and every session in those sessions' token
   * families (Desktop MCP child credentials), with revoked_reason
   * `enrollment_key_revoked`. The audit target names the bound user and the
   * session count. Desktop relay identities are not deleted: they are keyed
   * by person and Desktop source, not by session, and only a live verified
   * session can use them (docs/identity.md, "Desktop enrollment keys").
   */
  async revokeIn(
    tx: SqlExecutor,
    input: {
      workspaceId: string;
      organizationId: string;
      tokenId: string;
      actor: AuditActor;
      /** Appended to the audit target as `reason=<reason>`. */
      reason?: string;
    },
  ): Promise<boolean> {
    if (!/^[0-9a-f-]{36}$/i.test(input.tokenId)) return false;
    const result = await tx.query<{ agent_name: string | null; purpose: ApiTokenPurpose; user_id: string | null }>(
      `UPDATE workspace_api_tokens
          SET revoked_at = now(), revoked_by_user_id = $3
        WHERE id = $1 AND workspace_id = $2 AND revoked_at IS NULL
        RETURNING id, agent_name, purpose, user_id`,
      [input.tokenId, input.workspaceId, input.actor.kind === "user" ? input.actor.userId : null],
    );
    const revoked = result.rows[0];
    if (!revoked) return false;
    let target = revoked.agent_name === null ? input.tokenId : `${input.tokenId} (${revoked.agent_name})`;
    if (revoked.purpose === DESKTOP_ENROLLMENT_PURPOSE) {
      const sessions = await tx.query<{ id: string }>(
        `UPDATE token_sessions
            SET revoked_at = now(), revoked_reason = 'enrollment_key_revoked', updated_at = now()
          WHERE revoked_at IS NULL
            AND (provisioned_by_token_id = $1
                 OR token_family_id IN (
                   SELECT token_family_id FROM token_sessions WHERE provisioned_by_token_id = $1))
          RETURNING id`,
        [input.tokenId],
      );
      target = `${input.tokenId} (desktop-enrollment: user ${revoked.user_id}) sessions=${sessions.rows.length}`;
    }
    if (input.reason) target = `${target} reason=${input.reason}`;
    await recordAudit(tx, {
      organizationId: input.organizationId,
      workspaceId: input.workspaceId,
      actor: input.actor,
      action: "api_token.revoke",
      target,
    });
    return true;
  }

  /**
   * The /api/v1 gate (and every "workspace tokens are not a person" check):
   * a live token of any purpose except relay-node, which is valid only at
   * the /relay-node/v1 broker (authenticateRelayNode).
   */
  async authenticate(token: string): Promise<ApiTokenPrincipal | null> {
    if (!token.startsWith(API_TOKEN_PREFIX)) return null;
    const result = await this.database.query<{
      id: string;
      workspace_id: string;
      organization_id: string;
      scopes: string[];
    }>(
      `UPDATE workspace_api_tokens t
          SET last_used_at = now()
         FROM workspaces w
        WHERE t.token_hash = $1
          AND t.revoked_at IS NULL
          AND (t.expires_at IS NULL OR t.expires_at > now())
          AND t.purpose <> 'relay-node'
          AND w.id = t.workspace_id
        RETURNING t.id, t.workspace_id, w.organization_id, t.scopes`,
      [hashSecret(token)],
    );
    const row = result.rows[0];
    return row
      ? {
          tokenId: row.id,
          workspaceId: row.workspace_id,
          organizationId: row.organization_id,
          scopes: row.scopes,
        }
      : null;
  }

  /** A live relay-node token (not revoked, not expired), recording its use; else null. */
  async authenticateRelayNode(token: string): Promise<RelayNodePrincipal | null> {
    if (!token.startsWith(API_TOKEN_PREFIX)) return null;
    const result = await this.database.query<{
      id: string;
      workspace_id: string;
      organization_id: string;
      agent_name: string | null;
    }>(
      `UPDATE workspace_api_tokens t
          SET last_used_at = now()
         FROM workspaces w
        WHERE t.token_hash = $1
          AND t.revoked_at IS NULL
          AND (t.expires_at IS NULL OR t.expires_at > now())
          AND t.purpose = 'relay-node'
          AND w.id = t.workspace_id
        RETURNING t.id, t.workspace_id, w.organization_id, t.agent_name`,
      [hashSecret(token)],
    );
    const row = result.rows[0];
    return row && row.agent_name
      ? {
          tokenId: row.id,
          workspaceId: row.workspace_id,
          organizationId: row.organization_id,
          nodeName: row.agent_name,
        }
      : null;
  }

  /**
   * Looks a presented token up for introspection, including revoked and
   * expired rows so the caller can name the reason. Records last use only
   * for a live relayfile-agent or acquisition-operator token.
   */
  async introspect(token: string): Promise<ApiTokenIntrospection | null> {
    if (!token.startsWith(API_TOKEN_PREFIX)) return null;
    const result = await this.database.query<{
      id: string;
      workspace_id: string;
      cloud_relay_workspace_id: string | null;
      organization_id: string;
      purpose: ApiTokenPurpose;
      scopes: string[];
      agent_name: string | null;
      aud: string | null;
      created_at: Date | string;
      expires_at: Date | string | null;
      revoked: boolean;
      expired: boolean;
    }>(
      `SELECT t.id, t.workspace_id, w.cloud_relay_workspace_id, w.organization_id,
              t.purpose, t.scopes, t.agent_name, t.aud,
              t.created_at, t.expires_at,
              t.revoked_at IS NOT NULL AS revoked,
              (t.expires_at IS NOT NULL AND t.expires_at <= now()) AS expired
         FROM workspace_api_tokens t
         JOIN workspaces w ON w.id = t.workspace_id
        WHERE t.token_hash = $1`,
      [hashSecret(token)],
    );
    const row = result.rows[0];
    if (!row) return null;
    if (
      (row.purpose === RELAYFILE_AGENT_PURPOSE || row.purpose === ACQUISITION_OPERATOR_PURPOSE) &&
      !row.revoked && !row.expired
    ) {
      await this.database.query(
        "UPDATE workspace_api_tokens SET last_used_at = now() WHERE id = $1",
        [row.id],
      );
    }
    return {
      tokenId: row.id,
      workspaceId: row.workspace_id,
      cloudRelayWorkspaceId: row.cloud_relay_workspace_id,
      organizationId: row.organization_id,
      purpose: row.purpose,
      scopes: row.scopes,
      agentName: row.agent_name,
      aud: row.aud,
      createdAt: new Date(iso(row.created_at)),
      expiresAt: row.expires_at === null ? null : new Date(iso(row.expires_at)),
      revoked: row.revoked,
      expired: row.expired,
    };
  }
}
