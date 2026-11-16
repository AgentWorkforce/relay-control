import { randomUUID } from "node:crypto";
import { recordAudit } from "../admin/audit.js";
import { decryptSecret, encryptSecret, hashSecret, opaqueToken, type EncryptionKeyring } from "../crypto.js";
import type { Database } from "../database.js";

/**
 * One-time relay launch credentials for gate-only installs
 * (SELFHOST_RELAYGATE_PUBLIC_URL set; docs/identity.md, "Gate-only installs
 * (relaygate)"). Migration 0060.
 *
 * Every agent launch journaled in relay_spawns gets one opaque `sh_lt_`
 * credential, bound to its workspace, organization, target node name, agent
 * name and launching user, valid for RELAY_LAUNCH_CREDENTIAL_TTL_MS. The
 * launched agent presents it to relaygate's POST /v1/register;
 * relaygate introspects it at POST /internal/v1/auth/introspect, which answers
 * principal_type `relay_launch` and burns it on the first active answer
 * (peek for the checks, then the atomic redeem).
 *
 * The credential is NOT sent to Relaycast in the spawn invocation body:
 * Relaycast never sees it. This module only mints it and stores it sealed
 * (sha256 hash for lookup, ciphertext under the active encryption key). The
 * relay-node socket bridge (src/relay-node/socket.ts) reads it with
 * sealedFor() and attaches it to the spawn invocation frame it forwards to the
 * node. No route returns the plaintext, and it is never logged or audited.
 */
export const RELAY_LAUNCH_CREDENTIAL_PREFIX = "sh_lt_";
export const RELAY_LAUNCH_CREDENTIAL_TTL_MS = 10 * 60 * 1_000;
export const RELAY_LAUNCH_SCOPE = "relay:agent:enrol";

export type RelayLaunchCredentialInput = {
  spawnId: string;
  workspaceId: string;
  organizationId: string;
  /** The launching user. */
  userId: string;
  nodeName: string;
  agentName: string;
};

export type RelayLaunchCredentialRow = RelayLaunchCredentialInput & {
  id: string;
  createdAt: Date;
  expiresAt: Date;
};

export type RelayLaunchCredentialLookup =
  | { state: "unknown" }
  | { state: "expired" }
  | { state: "redeemed" }
  | { state: "active"; credential: RelayLaunchCredentialRow };

const COLUMNS = "id, spawn_id, workspace_id, organization_id, user_id, node_name, agent_name, created_at, expires_at";

function rowFrom(row: Record<string, unknown>): RelayLaunchCredentialRow {
  return {
    id: String(row.id),
    spawnId: String(row.spawn_id),
    workspaceId: String(row.workspace_id),
    organizationId: String(row.organization_id),
    userId: String(row.user_id),
    nodeName: String(row.node_name),
    agentName: String(row.agent_name),
    createdAt: new Date(row.created_at as string | Date),
    expiresAt: new Date(row.expires_at as string | Date),
  };
}

const detail = (row: Pick<RelayLaunchCredentialRow, "id" | "spawnId" | "nodeName" | "agentName">) =>
  `${row.id} spawn=${row.spawnId} node=${row.nodeName} agent=${row.agentName}`;

export function relayLaunchCredentials(database: Database, keyring: EncryptionKeyring) {
  /** Read-only state of a presented token; never burns it. */
  async function peek(token: string): Promise<RelayLaunchCredentialLookup> {
    if (!token.startsWith(RELAY_LAUNCH_CREDENTIAL_PREFIX)) return { state: "unknown" };
    const result = await database.query(
      `SELECT ${COLUMNS}, redeemed_at, expires_at <= now() AS expired
         FROM relay_launch_credentials WHERE token_hash = $1`,
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
     * Mints the launch credential for one journaled spawn and records
     * `relay_launch.credential.issued`. Returns only the id and expiry: the
     * plaintext never reaches the MCP caller.
     */
    async issue(input: RelayLaunchCredentialInput): Promise<{ id: string; expiresAt: Date }> {
      const token = opaqueToken(RELAY_LAUNCH_CREDENTIAL_PREFIX);
      const id = randomUUID();
      return database.transaction(async (tx) => {
        const inserted = await tx.query<{ expires_at: Date | string }>(
          `INSERT INTO relay_launch_credentials
             (id, spawn_id, workspace_id, organization_id, user_id, node_name, agent_name, token_hash, token_ciphertext, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now() + ($10::integer * interval '1 millisecond'))
           RETURNING expires_at`,
          [id, input.spawnId, input.workspaceId, input.organizationId, input.userId, input.nodeName, input.agentName,
            hashSecret(token), encryptSecret(token, keyring.active), RELAY_LAUNCH_CREDENTIAL_TTL_MS],
        );
        const expiresAt = new Date(inserted.rows[0]!.expires_at);
        await recordAudit(tx, {
          organizationId: input.organizationId,
          workspaceId: input.workspaceId,
          actor: { kind: "user", userId: input.userId },
          action: "relay_launch.credential.issued",
          target: `${detail({ id, ...input })} expires=${expiresAt.toISOString()}`,
        });
        return { id, expiresAt };
      });
    },

    peek,

    /**
     * Burns the credential atomically and records
     * `relay_launch.credential.redeemed`. Call only after every introspection
     * check on peek() passed; a lost race answers unknown, expired or
     * redeemed, never active twice.
     */
    async redeem(token: string): Promise<RelayLaunchCredentialLookup> {
      if (!token.startsWith(RELAY_LAUNCH_CREDENTIAL_PREFIX)) return { state: "unknown" };
      const burned = await database.transaction(async (tx) => {
        const result = await tx.query(
          `UPDATE relay_launch_credentials SET redeemed_at = now(), token_ciphertext = NULL
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
          action: "relay_launch.credential.redeemed",
          target: detail(credential),
        });
        return credential;
      });
      if (burned) return { state: "active", credential: burned };
      const current = await peek(token);
      // A row that still looks active lost a race we cannot explain: never answer active.
      return current.state === "active" ? { state: "redeemed" } : current;
    },

    /** Deletes the credential of a launch Relaycast rejected outright (state `failed`). */
    async discard(spawnId: string): Promise<void> {
      await database.query("DELETE FROM relay_launch_credentials WHERE spawn_id = $1", [spawnId]);
    },

    /**
     * The plaintext credential of a launch, or null once redeemed, expired or
     * absent. Only for the relay-node socket bridge,
     * which attaches it to the spawn frame it forwards to the node. Never
     * exposed over any route, MCP tool or Relaycast call.
     */
    async sealedFor(spawnId: string): Promise<string | null> {
      const result = await database.query<{ token_ciphertext: string | null }>(
        `SELECT token_ciphertext FROM relay_launch_credentials
          WHERE spawn_id = $1 AND redeemed_at IS NULL AND expires_at > now()`,
        [spawnId],
      );
      const sealed = result.rows[0]?.token_ciphertext;
      return sealed ? decryptSecret(sealed, keyring) : null;
    },
  };
}

export type RelayLaunchCredentials = ReturnType<typeof relayLaunchCredentials>;
