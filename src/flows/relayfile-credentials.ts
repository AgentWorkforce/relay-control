import { randomUUID } from "node:crypto";
import type { Database } from "../database.js";
import { hashSecret, opaqueToken } from "../crypto.js";
import { FLOW_RUN_CREDENTIAL_PREFIX, normalizedOrigin } from "../auth/introspect.js";
import { iso, recordAudit } from "../admin/audit.js";

/**
 * Per-run, path-scoped Relayfile credentials for Flows workers
 * (docs/flows-relayfile-credential.md). An opaque `sh_fr_` bearer bound to one
 * run, scoped to the run's mount paths, verified by Relayfile through
 * POST /internal/v1/auth/introspect. The token is returned once and never
 * stored, logged or audited in clear.
 */
export const MAX_FLOW_RELAYFILE_MOUNT_PATHS = 16;
const MAX_MOUNT_PATH_LENGTH = 512;
const SCHEDULE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export class FlowRelayfileCredentialError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
    this.name = "FlowRelayfileCredentialError";
  }
}

export type FlowRelayfileCredentialConfig = {
  /**
   * Hard horizon (FlowsConfig.relayfileCredentialTtlMs); the real end of life
   * is revocation when the run ends.
   */
  ttlMs: number;
  /** SELFHOST_FLOWS_WORKER_RELAYFILE_URL; empty when Relayfile is not deployed. */
  workerRelayfileUrl: string;
  /** acceptedAudiences(config): empty while introspection is disabled. */
  audiences: () => string[];
};

export type IssuedFlowRelayfileCredential = {
  /** The row id; equals introspection's `sub`/`token_id` for this token. */
  credentialId: string;
  relayfileToken: string;
  relayfileTokenExpiresAt: string;
  relayfileMountPaths: string[];
  scopes: string[];
  aud: string;
};

/** What the legacy Flows store needs at assignment time. */
export type FlowRelayfileCredentialInput = {
  workspaceId: string;
  runId: string;
  mountPaths: string[];
  readOnly?: boolean;
  aud?: string;
  issuer?: string;
};

export type FlowRelayfileCredentialIssuer = {
  issue(input: FlowRelayfileCredentialInput): Promise<IssuedFlowRelayfileCredential>;
  issueForLocalRun(input: FlowRelayfileCredentialInput): Promise<IssuedFlowRelayfileCredential>;
};

/** What introspection needs to judge a presented `sh_fr_` token. */
export type FlowRunCredentialIntrospection = {
  credentialId: string;
  workspaceId: string;
  organizationId: string;
  runId: string;
  scopes: string[];
  aud: string;
  createdAt: Date;
  expiresAt: Date;
  revoked: boolean;
  expired: boolean;
};

function invalidPaths(message: string): FlowRelayfileCredentialError {
  return new FlowRelayfileCredentialError(400, "invalid_mount_paths", message);
}

/**
 * 1-16 absolute, normalized paths; the first is this run's root or a schedule
 * root. Returns the paths unchanged, or throws 400 invalid_mount_paths.
 */
export function validateMountPaths(mountPaths: unknown, runId: string): string[] {
  if (!Array.isArray(mountPaths) || mountPaths.length < 1 || mountPaths.length > MAX_FLOW_RELAYFILE_MOUNT_PATHS) {
    throw invalidPaths(`mountPaths must list 1 to ${MAX_FLOW_RELAYFILE_MOUNT_PATHS} paths`);
  }
  for (const path of mountPaths) {
    if (
      typeof path !== "string" ||
      path.length < 2 ||
      path.length > MAX_MOUNT_PATH_LENGTH ||
      !path.startsWith("/") ||
      path.endsWith("/") ||
      path.includes("*") ||
      /[\s\p{C}]/u.test(path) ||
      path.slice(1).split("/").some((segment) => segment === "" || segment === "." || segment === "..")
    ) {
      throw invalidPaths(
        `each mount path must be absolute and normalized (no '.' or '..' segments, no trailing slash, no '*', no whitespace or control characters, at most ${MAX_MOUNT_PATH_LENGTH} characters)`,
      );
    }
  }
  const first = mountPaths[0] as string;
  const schedule = /^\/workflows\/schedules\/([^/]+)$/.exec(first);
  if (first !== `/workflows/runs/${runId}` && !(schedule && SCHEDULE_ID.test(schedule[1]!))) {
    throw invalidPaths("the first mount path must be /workflows/runs/<runId> for this run or /workflows/schedules/<id>");
  }
  return [...mountPaths] as string[];
}

/** Mirrors Cloud's relayAuthTokenPathsForMountPaths. Never fs:*, sync:*, manage or *. */
export function relayfileScopesForMountPaths(mountPaths: string[], readOnly: boolean): string[] {
  return mountPaths.flatMap((path) => [
    `relayfile:fs:read:${path}`,
    `relayfile:fs:read:${path}/*`,
    ...(readOnly ? [] : [`relayfile:fs:write:${path}`, `relayfile:fs:write:${path}/*`]),
  ]);
}

export class FlowRunRelayfileCredentials implements FlowRelayfileCredentialIssuer {
  readonly #config: () => FlowRelayfileCredentialConfig | null;

  /**
   * `config` may be a getter so the Flows settings are read only when a
   * credential is issued; null (or no getter result) = not configured.
   */
  constructor(
    private readonly database: Database,
    private readonly now: () => Date = () => new Date(),
    config: FlowRelayfileCredentialConfig | (() => FlowRelayfileCredentialConfig | null) | null = null,
  ) {
    this.#config = typeof config === "function" ? config : () => config;
  }

  /**
   * The audience a new credential would carry, or the refusal. A requested
   * `aud` must normalize to the worker Relayfile origin.
   */
  #audience(config: FlowRelayfileCredentialConfig | null, requested: string | undefined): string {
    const accepted = config?.audiences() ?? [];
    const aud = config?.workerRelayfileUrl ? normalizedOrigin(config.workerRelayfileUrl) : null;
    if (!config || aud === null || accepted.length === 0) {
      throw new FlowRelayfileCredentialError(
        404,
        "relayfile_not_configured",
        "Relayfile credentials need SELFHOST_FLOWS_WORKER_RELAYFILE_URL and token introspection (RELAYCONTROL_INTROSPECT_SECRET)",
      );
    }
    if (requested !== undefined && normalizedOrigin(requested) !== aud) {
      throw new FlowRelayfileCredentialError(
        409,
        "relayfile_audience_not_accepted",
        "The requested audience does not match the origin of the configured worker Relayfile URL (SELFHOST_FLOWS_WORKER_RELAYFILE_URL)",
      );
    }
    if (!accepted.includes(aud)) {
      throw new FlowRelayfileCredentialError(
        409,
        "relayfile_audience_not_accepted",
        `The origin of SELFHOST_FLOWS_WORKER_RELAYFILE_URL (${aud}) must be listed in SELFHOST_INTROSPECT_AUDIENCES`,
      );
    }
    return aud;
  }

  /**
   * Mints the run's credential, revoking any earlier active one for the run.
   * The audit row names the credential id, run, paths and expiry only.
   */
  async issue(input: FlowRelayfileCredentialInput): Promise<IssuedFlowRelayfileCredential> {
    // Broker runs may live in relayfile-control rather than workflow_runs.
    return this.#issue(input, false);
  }

  /** Serializes local assignment issuance with the run's terminal transition. */
  async issueForLocalRun(input: FlowRelayfileCredentialInput): Promise<IssuedFlowRelayfileCredential> {
    return this.#issue(input, true);
  }

  async #issue(input: FlowRelayfileCredentialInput, localRun: boolean): Promise<IssuedFlowRelayfileCredential> {
    const config = this.#config();
    const aud = this.#audience(config, input.aud);
    const mountPaths = validateMountPaths(input.mountPaths, input.runId);
    const readOnly = input.readOnly === true;
    const scopes = relayfileScopesForMountPaths(mountPaths, readOnly);
    const issuedAt = this.now();
    const expiresAt = new Date(issuedAt.getTime() + config!.ttlMs);
    const token = opaqueToken(FLOW_RUN_CREDENTIAL_PREFIX);
    const id = randomUUID();
    await this.database.transaction(async (tx) => {
      if (localRun) {
        // finishRun's UPDATE holds this same row lock until its credential
        // revocation commits. Whichever transaction gets the row first wins:
        // mint then finish revokes it; finish then mint refuses it.
        const run = await tx.query<{ status: string }>(
          "SELECT status FROM workflow_runs WHERE id = $1 AND workspace_id = $2 FOR UPDATE",
          [input.runId, input.workspaceId],
        );
        if (!run.rows[0]) {
          throw new FlowRelayfileCredentialError(404, "run_not_found", "Run not found");
        }
        if (run.rows[0].status !== "pending" && run.rows[0].status !== "running") {
          throw new FlowRelayfileCredentialError(409, "run_not_active", "Run is no longer active");
        }
      }
      const workspace = await tx.query<{ organization_id: string }>(
        "SELECT organization_id FROM workspaces WHERE id = $1",
        [input.workspaceId],
      );
      const organizationId = workspace.rows[0]?.organization_id;
      if (!organizationId) {
        throw new FlowRelayfileCredentialError(404, "workspace_not_found", "Workspace not found");
      }
      await tx.query(
        `UPDATE flow_run_relayfile_credentials SET revoked_at = $2
          WHERE run_id = $1 AND revoked_at IS NULL`,
        [input.runId, issuedAt.toISOString()],
      );
      await tx.query(
        `INSERT INTO flow_run_relayfile_credentials
           (id, workspace_id, run_id, token_hash, token_prefix, aud, mount_paths, scopes,
            read_only, expires_at, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [
          id,
          input.workspaceId,
          input.runId,
          hashSecret(token),
          token.slice(0, FLOW_RUN_CREDENTIAL_PREFIX.length + 4),
          aud,
          mountPaths,
          scopes,
          readOnly,
          expiresAt.toISOString(),
          issuedAt.toISOString(),
        ],
      );
      await recordAudit(tx, {
        organizationId,
        workspaceId: input.workspaceId,
        actor: { kind: "service", subject: input.issuer ?? "relayfile-control" },
        action: "flows.relayfile_credential.issue",
        target: `${id} (run ${input.runId}${readOnly ? ", read-only" : ""}: ${mountPaths.join(", ")}; expires ${expiresAt.toISOString()})`,
      });
    });
    return {
      credentialId: id,
      relayfileToken: token,
      relayfileTokenExpiresAt: expiresAt.toISOString(),
      relayfileMountPaths: mountPaths,
      scopes,
      aud,
    };
  }

  /** Revokes the run's active credential, if any (the run ended). Idempotent. */
  async revokeForRun(runId: string): Promise<void> {
    await this.database.query(
      `UPDATE flow_run_relayfile_credentials SET revoked_at = $2
        WHERE run_id = $1 AND revoked_at IS NULL`,
      [runId, this.now().toISOString()],
    );
  }

  /**
   * Looks a presented token up for introspection, including revoked and
   * expired rows so the caller can name the reason.
   */
  async introspect(token: string): Promise<FlowRunCredentialIntrospection | null> {
    if (!token.startsWith(FLOW_RUN_CREDENTIAL_PREFIX)) return null;
    const result = await this.database.query<{
      id: string;
      workspace_id: string;
      organization_id: string;
      run_id: string;
      scopes: string[];
      aud: string;
      created_at: Date | string;
      expires_at: Date | string;
      revoked_at: Date | string | null;
    }>(
      `SELECT c.id, c.workspace_id, w.organization_id, c.run_id, c.scopes, c.aud,
              c.created_at, c.expires_at, c.revoked_at
         FROM flow_run_relayfile_credentials c
         JOIN workspaces w ON w.id = c.workspace_id
        WHERE c.token_hash = $1`,
      [hashSecret(token)],
    );
    const row = result.rows[0];
    if (!row) return null;
    const expiresAt = new Date(iso(row.expires_at));
    return {
      credentialId: row.id,
      workspaceId: row.workspace_id,
      organizationId: row.organization_id,
      runId: row.run_id,
      scopes: row.scopes,
      aud: row.aud,
      createdAt: new Date(iso(row.created_at)),
      expiresAt,
      revoked: row.revoked_at !== null,
      expired: expiresAt.getTime() <= this.now().getTime(),
    };
  }
}
