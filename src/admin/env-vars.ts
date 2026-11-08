import type { Database } from "../database.js";
import {
  decryptSecret,
  EncryptedSecretError,
  encryptSecret,
  type EncryptionKeyring,
} from "../crypto.js";
import { iso, recordAudit, type AuditActor } from "./audit.js";
import {
  deliveredEnvEntryBytes,
  envKeyReachesRuntime,
  EnvVarValidationError,
  maskValue,
  MAX_DELIVERED_ENV_COUNT,
  MAX_DELIVERED_ENV_TOTAL_BYTES,
  validateEnvName,
  validateEnvValue,
} from "./env-policy.js";

/** Public record. Never carries the value or ciphertext. Mirrors hosted shape. */
export type EnvVarRecord = {
  name: string;
  envVar: string;
  kind: "environment";
  deliveredToFlowRuns: boolean;
  maskedValue: string;
  setBy: string | null;
  createdBy: string | null;
  updatedBy: string | null;
  createdAt: string;
  updatedAt: string;
};

type Row = {
  name: string;
  masked_value: string;
  value_bytes: number;
  created_by_user_id: string | null;
  updated_by_user_id: string | null;
  created_at: Date | string;
  updated_at: Date | string;
};

export type RuntimeEnvironment = {
  env: Record<string, string>;
  names: string[];
  skipped: Array<{ name: string; reason: "reserved" | "undecryptable" }>;
};

function toRecord(row: Row): EnvVarRecord {
  return {
    name: row.name,
    envVar: row.name,
    kind: "environment",
    deliveredToFlowRuns: envKeyReachesRuntime(row.name),
    maskedValue: row.masked_value,
    setBy: row.updated_by_user_id,
    createdBy: row.created_by_user_id,
    updatedBy: row.updated_by_user_id,
    createdAt: iso(row.created_at),
    updatedAt: iso(row.updated_at),
  };
}

const COLUMNS = `name, masked_value, value_bytes, created_by_user_id, updated_by_user_id,
                 created_at, updated_at`;

export class EnvVarStore {
  constructor(
    private readonly database: Database,
    private readonly keyring: EncryptionKeyring,
  ) {}

  async list(workspaceId: string): Promise<EnvVarRecord[]> {
    const result = await this.database.query<Row>(
      `SELECT ${COLUMNS} FROM selfhost_workspace_env_vars
        WHERE workspace_id = $1 ORDER BY name`,
      [workspaceId],
    );
    return result.rows.map(toRecord);
  }

  async get(workspaceId: string, name: string): Promise<EnvVarRecord | null> {
    const result = await this.database.query<Row>(
      `SELECT ${COLUMNS} FROM selfhost_workspace_env_vars
        WHERE workspace_id = $1 AND name = $2`,
      [workspaceId, name],
    );
    return result.rows[0] ? toRecord(result.rows[0]) : null;
  }

  /** Creates or replaces a variable (hosted POST semantics). */
  async put(input: {
    workspaceId: string;
    organizationId: string;
    name: unknown;
    value: unknown;
    actor: AuditActor & { kind: "user" };
  }): Promise<{ record: EnvVarRecord; created: boolean }> {
    const name = validateEnvName(input.name);
    const value = validateEnvValue(input.value);
    const bytes = Buffer.byteLength(value, "utf8");
    const ciphertext = encryptSecret(value, this.keyring.active);
    const masked = maskValue(value);
    return this.database.transaction(async (tx) => {
      // Serialize writers per workspace so count/size limits hold.
      await tx.query(
        "SELECT id FROM selfhost_workspaces WHERE id = $1 FOR UPDATE",
        [input.workspaceId],
      );
      const totals = await tx.query<{ name: string; value_bytes: number }>(
        `SELECT name, value_bytes FROM selfhost_workspace_env_vars WHERE workspace_id = $1`,
        [input.workspaceId],
      );
      const others = totals.rows.filter((row) => row.name !== name);
      if (others.length + 1 > MAX_DELIVERED_ENV_COUNT) {
        throw new EnvVarValidationError(
          `a workspace can hold at most ${MAX_DELIVERED_ENV_COUNT} environment variables`,
        );
      }
      const total = others.reduce(
        (sum, row) => sum + Buffer.byteLength(row.name) + Number(row.value_bytes) + 2,
        0,
      ) + deliveredEnvEntryBytes(name, value);
      if (total > MAX_DELIVERED_ENV_TOTAL_BYTES) {
        throw new EnvVarValidationError(
          `workspace environment would exceed ${MAX_DELIVERED_ENV_TOTAL_BYTES} bytes`,
        );
      }
      const result = await tx.query<Row & { inserted: boolean }>(
        `INSERT INTO selfhost_workspace_env_vars
           (workspace_id, name, value_ciphertext, masked_value, value_bytes,
            created_by_user_id, updated_by_user_id)
         VALUES ($1, $2, $3, $4, $5, $6, $6)
         ON CONFLICT (workspace_id, name) DO UPDATE SET
           value_ciphertext = EXCLUDED.value_ciphertext,
           masked_value = EXCLUDED.masked_value,
           value_bytes = EXCLUDED.value_bytes,
           updated_by_user_id = EXCLUDED.updated_by_user_id,
           updated_at = now()
         RETURNING ${COLUMNS}, (xmax = 0) AS inserted`,
        [input.workspaceId, name, ciphertext, masked, bytes, input.actor.userId],
      );
      const row = result.rows[0]!;
      await recordAudit(tx, {
        organizationId: input.organizationId,
        workspaceId: input.workspaceId,
        actor: input.actor,
        action: row.inserted ? "env_var.create" : "env_var.update",
        target: name,
      });
      return { record: toRecord(row), created: row.inserted === true };
    });
  }

  async delete(input: {
    workspaceId: string;
    organizationId: string;
    name: string;
    actor: AuditActor;
  }): Promise<EnvVarRecord | null> {
    return this.database.transaction(async (tx) => {
      const result = await tx.query<Row>(
        `DELETE FROM selfhost_workspace_env_vars
          WHERE workspace_id = $1 AND name = $2
          RETURNING ${COLUMNS}`,
        [input.workspaceId, input.name],
      );
      const row = result.rows[0];
      if (!row) return null;
      await recordAudit(tx, {
        organizationId: input.organizationId,
        workspaceId: input.workspaceId,
        actor: input.actor,
        action: "env_var.delete",
        target: input.name,
      });
      return toRecord(row);
    });
  }

  /**
   * Internal runtime read: decrypts deliverable variables for a runtime
   * consumer. Only reachable through service/worker credentials.
   */
  async readRuntimeEnvironment(
    workspaceId: string,
    actor: AuditActor,
  ): Promise<RuntimeEnvironment> {
    const result = await this.database.query<{ name: string; value_ciphertext: string }>(
      `SELECT name, value_ciphertext FROM selfhost_workspace_env_vars
        WHERE workspace_id = $1 ORDER BY name`,
      [workspaceId],
    );
    const env: Record<string, string> = Object.create(null) as Record<string, string>;
    const skipped: RuntimeEnvironment["skipped"] = [];
    for (const row of result.rows) {
      if (!envKeyReachesRuntime(row.name)) {
        skipped.push({ name: row.name, reason: "reserved" });
        continue;
      }
      try {
        env[row.name] = decryptSecret(row.value_ciphertext, this.keyring);
      } catch (error) {
        if (!(error instanceof EncryptedSecretError)) throw error;
        console.error("[selfhost-api] undecryptable workspace env var", {
          workspaceId,
          name: row.name,
          code: error.code,
        });
        skipped.push({ name: row.name, reason: "undecryptable" });
      }
    }
    await recordAudit(this.database, {
      workspaceId,
      actor,
      action: "env_var.runtime_read",
      target: `${Object.keys(env).length} variables`,
    });
    return { env: { ...env }, names: Object.keys(env), skipped };
  }
}
