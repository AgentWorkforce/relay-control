import { randomUUID } from "node:crypto";
import type { Database } from "../database.js";
import { hashSecret, opaqueToken } from "../crypto.js";
import { normalizedOrigin } from "../auth/introspect.js";
import { NODE_ID_PATTERN } from "../store.js";
import { iso, recordAudit, type AuditActor } from "./audit.js";

export const API_TOKEN_PREFIX = "sh_wk_";
export const MAX_API_TOKEN_EXPIRY_DAYS = 365;

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
} as const satisfies Record<string, readonly string[]>;

export type ApiTokenPurpose = keyof typeof API_TOKEN_PURPOSE_SCOPES;

export const RELAYFILE_AGENT_PURPOSE = "relayfile-agent" satisfies ApiTokenPurpose;
export const ACQUISITION_OPERATOR_PURPOSE = "acquisition-operator" satisfies ApiTokenPurpose;

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
  status: "active" | "expired" | "revoked";
  /** relayfile-agent only: the agent the token speaks for; else null. */
  agent_name: string | null;
  /** relayfile-agent and acquisition-operator: the normalized audience origin; else null. */
  aud: string | null;
};

export type ApiTokenPrincipal = {
  tokenId: string;
  workspaceId: string;
  organizationId: string;
  scopes: string[];
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
};

/** What introspection needs to judge a presented sh_wk_ token. */
export type ApiTokenIntrospection = {
  tokenId: string;
  workspaceId: string;
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
    status: row.revoked_at ? "revoked" : expired ? "expired" : "active",
    agent_name: row.agent_name,
    aud: row.aud,
  };
}

const SELECT = `SELECT t.id, t.label, t.purpose, t.scopes, t.token_prefix, t.created_by_user_id,
         u.name AS creator_name, u.email AS creator_email, t.created_at, t.expires_at,
         t.last_used_at, t.revoked_at, t.agent_name, t.aud
    FROM selfhost_workspace_api_tokens t
    LEFT JOIN selfhost_users u ON u.id = t.created_by_user_id`;

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

  async list(workspaceId: string): Promise<ApiTokenRecord[]> {
    const result = await this.database.query<Row>(
      `${SELECT} WHERE t.workspace_id = $1 ORDER BY t.created_at DESC LIMIT 100`,
      [workspaceId],
    );
    return result.rows.map(toRecord);
  }

  async create(input: {
    workspaceId: string;
    organizationId: string;
    label: unknown;
    purpose: unknown;
    expiryDays: unknown;
    neverExpires: unknown;
    agentName?: unknown;
    aud?: unknown;
    /** Any value here (the body's `scope` or `scopes`) is refused. */
    scope?: unknown;
    scopes?: unknown;
    actor: AuditActor & { kind: "user" };
  }): Promise<ApiTokenRecord & { accessToken: string }> {
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
    let expiresAt: Date | null;
    if (input.neverExpires === true) {
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
    const accessToken = opaqueToken(API_TOKEN_PREFIX);
    const id = randomUUID();
    const scopes = [...API_TOKEN_PURPOSE_SCOPES[purpose]];
    const duplicate = () =>
      new ApiTokenError(
        409,
        "agent_name_conflict",
        "An active relayfile-agent token already exists for this agent_name; revoke it first",
      );
    try {
      await this.database.transaction(async (tx) => {
        if (agentName !== null) {
          const existing = await tx.query(
            `SELECT 1 FROM selfhost_workspace_api_tokens
              WHERE workspace_id = $1 AND purpose = $2 AND agent_name = $3 AND revoked_at IS NULL`,
            [input.workspaceId, RELAYFILE_AGENT_PURPOSE, agentName],
          );
          if (existing.rows.length > 0) throw duplicate();
        }
        await tx.query(
          `INSERT INTO selfhost_workspace_api_tokens
             (id, workspace_id, label, purpose, scopes, token_hash, token_prefix,
              created_by_user_id, expires_at, agent_name, aud)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
          [
            id,
            input.workspaceId,
            label,
            purpose,
            scopes,
            hashSecret(accessToken),
            accessToken.slice(0, API_TOKEN_PREFIX.length + 4),
            input.actor.userId,
            expiresAt?.toISOString() ?? null,
            agentName,
            aud,
          ],
        );
        await recordAudit(tx, {
          organizationId: input.organizationId,
          workspaceId: input.workspaceId,
          actor: input.actor,
          action: "api_token.create",
          target: agentName !== null
            ? `${id} (${purpose}: ${agentName} -> ${aud})`
            : aud !== null
              ? `${id} (${purpose} -> ${aud})`
              : `${id} (${purpose})`,
        });
      });
    } catch (error) {
      // A concurrent mint for the same agent loses on the partial unique index.
      if (agentName !== null && String((error as { code?: unknown }).code) === "23505") throw duplicate();
      throw error;
    }
    const record = (await this.database.query<Row>(`${SELECT} WHERE t.id = $1`, [id])).rows[0]!;
    return { ...toRecord(record), accessToken };
  }

  async revoke(input: {
    workspaceId: string;
    organizationId: string;
    tokenId: string;
    actor: AuditActor & { kind: "user" };
  }): Promise<boolean> {
    if (!/^[0-9a-f-]{36}$/i.test(input.tokenId)) return false;
    return this.database.transaction(async (tx) => {
      const result = await tx.query(
        `UPDATE selfhost_workspace_api_tokens
            SET revoked_at = now(), revoked_by_user_id = $3
          WHERE id = $1 AND workspace_id = $2 AND revoked_at IS NULL
          RETURNING id, agent_name`,
        [input.tokenId, input.workspaceId, input.actor.userId],
      );
      const revoked = result.rows[0] as { agent_name: string | null } | undefined;
      if (!revoked) return false;
      await recordAudit(tx, {
        organizationId: input.organizationId,
        workspaceId: input.workspaceId,
        actor: input.actor,
        action: "api_token.revoke",
        target: revoked.agent_name === null ? input.tokenId : `${input.tokenId} (${revoked.agent_name})`,
      });
      return true;
    });
  }

  async authenticate(token: string): Promise<ApiTokenPrincipal | null> {
    if (!token.startsWith(API_TOKEN_PREFIX)) return null;
    const result = await this.database.query<{
      id: string;
      workspace_id: string;
      organization_id: string;
      scopes: string[];
    }>(
      `UPDATE selfhost_workspace_api_tokens t
          SET last_used_at = now()
         FROM selfhost_workspaces w
        WHERE t.token_hash = $1
          AND t.revoked_at IS NULL
          AND (t.expires_at IS NULL OR t.expires_at > now())
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
      `SELECT t.id, t.workspace_id, w.organization_id, t.purpose, t.scopes, t.agent_name, t.aud,
              t.created_at, t.expires_at,
              t.revoked_at IS NOT NULL AS revoked,
              (t.expires_at IS NOT NULL AND t.expires_at <= now()) AS expired
         FROM selfhost_workspace_api_tokens t
         JOIN selfhost_workspaces w ON w.id = t.workspace_id
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
        "UPDATE selfhost_workspace_api_tokens SET last_used_at = now() WHERE id = $1",
        [row.id],
      );
    }
    return {
      tokenId: row.id,
      workspaceId: row.workspace_id,
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
