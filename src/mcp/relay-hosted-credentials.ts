import { randomUUID } from "node:crypto";
import { recordAudit } from "../admin/audit.js";
import { hashSecret, opaqueToken } from "../crypto.js";
import type { Database } from "../database.js";

/**
 * One-time hosted participant credentials for gate-only installs
 * (SELFHOST_RELAYGATE_PUBLIC_URL set; docs/identity.md, "Hosted participants
 * on gate-only installs"). Migration 0079.
 *
 * Every hosted MCP participant (an MCP connector's agent: ChatGPT, Grok Bot,
 * Muse, Cursor cloud agents, any MCP client) enrols at relaygate, so the
 * install's relaygate policy decides what it may do, never the workspace
 * Relaycast key. relay-control mints one opaque `sh_ht_` credential per
 * enrolment, bound to the workspace, organization, owning user, the exact
 * agent name and the hosted client, and presents it itself to relaygate's
 * POST /v1/register at once. relaygate introspects it at
 * POST /internal/v1/auth/introspect, which answers principal_type
 * `relay_hosted` and burns it on the first active answer (peek for the
 * checks, then the atomic redeem). Only the hash is stored; the plaintext
 * exists only for that one call and is never logged, audited or returned.
 */
export const RELAY_HOSTED_CREDENTIAL_PREFIX = "sh_ht_";
/** Long enough for one relaygate round trip; never reused. */
export const RELAY_HOSTED_CREDENTIAL_TTL_MS = 2 * 60 * 1_000;
export const RELAY_HOSTED_SCOPE = "relay:hosted:enrol";
/** relaygate's hosted clients (relaygate src/hosted-clients.ts); a connector kind outside it is refused there. */
export const RELAY_HOSTED_CLIENTS = ["chatgpt", "grok-bot", "muse", "cursor-cloud", "mcp"] as const;
export type RelayHostedClient = (typeof RELAY_HOSTED_CLIENTS)[number];

export type RelayHostedCredentialInput = {
  workspaceId: string;
  organizationId: string;
  /** The participant's owner. */
  userId: string;
  agentName: string;
  client: RelayHostedClient;
};

export type RelayHostedCredentialRow = RelayHostedCredentialInput & { id: string; createdAt: Date; expiresAt: Date };

export type RelayHostedCredentialLookup =
  | { state: "unknown" }
  | { state: "expired" }
  | { state: "redeemed" }
  | { state: "active"; credential: RelayHostedCredentialRow };

const COLUMNS = "id, workspace_id, organization_id, user_id, agent_name, client, created_at, expires_at";

function rowFrom(row: Record<string, unknown>): RelayHostedCredentialRow {
  return {
    id: String(row.id),
    workspaceId: String(row.workspace_id),
    organizationId: String(row.organization_id),
    userId: String(row.user_id),
    agentName: String(row.agent_name),
    client: String(row.client) as RelayHostedClient,
    createdAt: new Date(row.created_at as string | Date),
    expiresAt: new Date(row.expires_at as string | Date),
  };
}

const detail = (row: Pick<RelayHostedCredentialRow, "id" | "agentName" | "client">) =>
  `${row.id} agent=${row.agentName} client=${row.client}`;

export function relayHostedCredentials(database: Database) {
  /** Read-only state of a presented token; never burns it. */
  async function peek(token: string): Promise<RelayHostedCredentialLookup> {
    if (!token.startsWith(RELAY_HOSTED_CREDENTIAL_PREFIX)) return { state: "unknown" };
    const result = await database.query(
      `SELECT ${COLUMNS}, redeemed_at, expires_at <= now() AS expired FROM relay_hosted_credentials WHERE token_hash = $1`,
      [hashSecret(token)],
    );
    const row = result.rows[0];
    if (!row) return { state: "unknown" };
    if (row.redeemed_at) return { state: "redeemed" };
    if (row.expired === true) return { state: "expired" };
    return { state: "active", credential: rowFrom(row) };
  }

  return {
    /**
     * Mints a credential and records `relay_hosted.credential.issued`. The
     * plaintext is for the caller's single relaygate registration only.
     */
    async issue(input: RelayHostedCredentialInput): Promise<{ id: string; token: string; expiresAt: Date }> {
      const token = opaqueToken(RELAY_HOSTED_CREDENTIAL_PREFIX);
      const id = randomUUID();
      return database.transaction(async (tx) => {
        const inserted = await tx.query<{ expires_at: Date | string }>(
          `INSERT INTO relay_hosted_credentials
             (id, workspace_id, organization_id, user_id, agent_name, client, token_hash, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, now() + ($8::integer * interval '1 millisecond'))
           RETURNING expires_at`,
          [id, input.workspaceId, input.organizationId, input.userId, input.agentName, input.client,
            hashSecret(token), RELAY_HOSTED_CREDENTIAL_TTL_MS],
        );
        const expiresAt = new Date(inserted.rows[0]!.expires_at);
        await recordAudit(tx, {
          organizationId: input.organizationId,
          workspaceId: input.workspaceId,
          actor: { kind: "user", userId: input.userId },
          action: "relay_hosted.credential.issued",
          target: `${detail({ id, ...input })} expires=${expiresAt.toISOString()}`,
        });
        return { id, token, expiresAt };
      });
    },

    peek,

    /**
     * Burns the credential atomically and records
     * `relay_hosted.credential.redeemed`. Call only after every introspection
     * check on peek() passed; a lost race never answers active twice.
     */
    async redeem(token: string): Promise<RelayHostedCredentialLookup> {
      if (!token.startsWith(RELAY_HOSTED_CREDENTIAL_PREFIX)) return { state: "unknown" };
      const burned = await database.transaction(async (tx) => {
        const result = await tx.query(
          `UPDATE relay_hosted_credentials SET redeemed_at = now()
            WHERE token_hash = $1 AND redeemed_at IS NULL AND expires_at > now()
            RETURNING ${COLUMNS}`,
          [hashSecret(token)],
        );
        const row = result.rows[0];
        if (!row) return null;
        const credential = rowFrom(row);
        await recordAudit(tx, {
          organizationId: credential.organizationId,
          workspaceId: credential.workspaceId,
          actor: { kind: "user", userId: credential.userId },
          action: "relay_hosted.credential.redeemed",
          target: detail(credential),
        });
        return credential;
      });
      if (burned) return { state: "active", credential: burned };
      const current = await peek(token);
      return current.state === "active" ? { state: "redeemed" } : current;
    },
  };
}

export type RelayHostedCredentials = ReturnType<typeof relayHostedCredentials>;
