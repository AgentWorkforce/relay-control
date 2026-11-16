import { randomUUID } from "node:crypto";
import { decryptSecret, encryptSecret, type EncryptionKeyring } from "../crypto.js";
import type { Database } from "../database.js";

/**
 * Relaycast node tokens held by Control on gate-only installs
 * (SELFHOST_RELAYGATE_PUBLIC_URL set; docs/relay-node-credential.md,
 * "Gate-only installs"). Migration 0059.
 *
 * The /relay-node/v1 broker stores the node token Relaycast answers to an
 * enrolment instead of returning it to the node host; the node-socket bridge
 * reads it to open the upstream Relaycast node socket. The token is stored
 * sealed under the active encryption key and never returned over any route,
 * logged or audited.
 */
export type RelayNodeCredentialKey = { workspaceId: string; nodeName: string };

export type RelayNodeCredentialRow = RelayNodeCredentialKey & {
  id: string;
  organizationId: string;
  relaycastNodeId: string;
  apiTokenId: string;
};

export function relayNodeCredentials(database: Database, keyring: EncryptionKeyring) {
  return {
    /**
     * The stored node token for (workspace, node name), with its row, or null
     * when the node never enrolled through this Control. `token` is null when
     * the sealed copy cannot be read with the current keyring (the node must
     * re-enrol).
     */
    async find(key: RelayNodeCredentialKey): Promise<(RelayNodeCredentialRow & { token: string | null }) | null> {
      const result = await database.query<{
        id: string; workspace_id: string; organization_id: string; node_name: string;
        relaycast_node_id: string; api_token_id: string; token_ciphertext: string;
      }>(
        `SELECT id, workspace_id, organization_id, node_name, relaycast_node_id, api_token_id, token_ciphertext
           FROM relay_node_credentials WHERE workspace_id = $1 AND node_name = $2`,
        [key.workspaceId, key.nodeName],
      );
      const row = result.rows[0];
      if (!row) return null;
      let token: string | null;
      try {
        token = decryptSecret(row.token_ciphertext, keyring);
      } catch {
        token = null;
      }
      return {
        id: String(row.id),
        workspaceId: String(row.workspace_id),
        organizationId: String(row.organization_id),
        nodeName: String(row.node_name),
        relaycastNodeId: String(row.relaycast_node_id),
        apiTokenId: String(row.api_token_id),
        token,
      };
    },

    /** Stores (or rotates in place) the node token Relaycast answered to an enrolment. */
    async save(input: RelayNodeCredentialKey & {
      organizationId: string; relaycastNodeId: string; apiTokenId: string; token: string;
    }): Promise<void> {
      await database.query(
        `INSERT INTO relay_node_credentials
           (id, workspace_id, organization_id, node_name, relaycast_node_id, api_token_id, token_ciphertext)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (workspace_id, node_name) DO UPDATE SET
           organization_id = EXCLUDED.organization_id,
           relaycast_node_id = EXCLUDED.relaycast_node_id,
           api_token_id = EXCLUDED.api_token_id,
           token_ciphertext = EXCLUDED.token_ciphertext,
           enrolled_at = now(),
           updated_at = now()`,
        [randomUUID(), input.workspaceId, input.organizationId, input.nodeName, input.relaycastNodeId,
          input.apiTokenId, encryptSecret(input.token, keyring.active)],
      );
    },

    /** Records that the node's socket reported in (register or heartbeat). */
    async heartbeat(key: RelayNodeCredentialKey): Promise<void> {
      await database.query(
        `UPDATE relay_node_credentials SET last_heartbeat_at = now()
          WHERE workspace_id = $1 AND node_name = $2`,
        [key.workspaceId, key.nodeName],
      );
    },
  };
}

export type RelayNodeCredentials = ReturnType<typeof relayNodeCredentials>;
