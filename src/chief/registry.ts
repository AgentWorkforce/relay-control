import { createHash, randomUUID } from "node:crypto";
import { z } from "zod";
import { recordAudit } from "../admin/audit.js";
import { hashSecret, opaqueToken } from "../crypto.js";
import type { Database, SqlExecutor } from "../database.js";
import type { ChiefBackend } from "./routes.js";

export type WorkspaceContext = { organizationId: string; workspaceId: string };

export type RepositoryCatalog = {
  connected: boolean;
  repositories: { id: string; fullName: string }[];
};
/** Implemented by relay-chief's GitHub adapter. Control has no catalog of its own. */
export interface RepositorySource {
  list(context: WorkspaceContext): Promise<RepositoryCatalog>;
}

type Worker = Record<string, unknown>;
export type ChiefIdentities = { relayCallerId: string; workers: Worker[] };

/** The checks `provisionPlan()` in relay-chief names. Every one must pass. */
export const READINESS_CHECKS = [
  "configuration_valid",
  "ledger_writable",
  "relay_identity_matches",
  "evidence_source_authorized",
  "execution_worker_available",
  "verification_authority_available",
] as const;

const SERVICE_TOKEN_PREFIX = "sh_chief_";
const SERVICE_TOKEN_TTL_MS = 90 * 24 * 60 * 60 * 1_000;
const PENDING_CALLER_PREFIX = "pending-";
// Serializes slot claims against slot registration, so a chief cannot be left
// awaiting capacity beside a slot that became free while it was being created.
const SLOT_ASSIGNMENT_LOCK = 1947182642;

export class ChiefError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: Record<string, unknown>,
  ) {
    super(message);
  }
}

/** Accepts the legacy `region` field until relay-webapp sends `placement`. */
function withPlacement(raw: unknown): unknown {
  if (raw === null || typeof raw !== "object" || !("region" in raw)) return raw;
  const { region, ...rest } = raw as Record<string, unknown>;
  return "placement" in rest ? raw : { ...rest, placement: region };
}

const setupSchema = z.preprocess(withPlacement, z.strictObject({
  requestId: z.string().uuid(),
  repositoryIds: z
    .array(z.string().regex(/^[0-9]+$/))
    .min(1)
    .max(100)
    .transform((ids) => [...new Set(ids)].sort()),
  // Opaque: only infrastructure maps a placement to a cloud location.
  placement: z.string().regex(/^[a-z0-9][a-z0-9-]{0,39}$/),
  budgetDollars: z.number().min(1).max(10_000),
  maxConcurrentTasks: z.number().int().min(1).max(10),
  allowedActions: z.array(z.enum(["investigate", "coordinate", "unblock"])).min(1).max(3),
}));

const slotSchema = z.strictObject({ slotId: z.string().regex(/^slot-[a-z0-9]{8,32}$/) });

const readySchema = z.strictObject({
  // Self-declared: the operator bearer is installation-wide and names no person.
  attestedBy: z.string().regex(/^[\w.@:-]{1,128}$/),
  configurationDigest: z.string().regex(/^[a-f0-9]{64}$/),
  checks: z
    .array(z.strictObject({ name: z.enum(READINESS_CHECKS), passed: z.boolean() }))
    .max(READINESS_CHECKS.length),
});

const identitiesSchema = z
  .strictObject({
    relayCallerId: z.string().min(1).max(500),
    workers: z
      .array(
        z.strictObject({
          agentId: z.string().min(1).max(500),
          address: z.string().regex(/^[^\s@]+@[^\s@]+$/).max(200),
          actions: z.array(z.enum(["investigate", "coordinate", "unblock"])).min(1),
        }),
      )
      .min(1)
      .max(100),
  })
  // The same rules as relay-chief's chiefConfigSchema, so the host accepts the config.
  .refine(
    ({ relayCallerId, workers }) =>
      !relayCallerId.startsWith(PENDING_CALLER_PREFIX) &&
      new Set(workers.map((worker) => worker.agentId)).size === workers.length &&
      new Set(workers.map((worker) => worker.address)).size === workers.length &&
      !workers.some((worker) => worker.agentId === relayCallerId),
  );

// Byte-for-byte the same as canonical() in relay-chief's contracts.ts.
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
}

function digestOf(value: unknown): string {
  return createHash("sha256").update(canonical(value)).digest("hex");
}

type ChiefConfig = {
  revision: number;
  chiefId: string;
  organizationId: string;
  workspaceId: string;
  projectId: string;
  repositories: string[];
  relayCallerId: string;
  workers: Worker[];
  policy: {
    version: string;
    allowedActions: string[];
    maxEvidenceAgeMs: number;
    minConfidence: number;
    maxConcurrentTasks: number;
    budgetMicros: number;
    taskReservationMicros: number;
  };
};

type ChiefRow = {
  id: string;
  organization_id: string;
  workspace_id: string;
  name: string;
  repository: string;
  request_id: string;
  digest: string;
  config: ChiefConfig;
  placement: string;
  state: "awaiting_capacity" | "awaiting_binding" | "ready";
  created_at: Date | string;
};

function conflict(code: string, message: string): ChiefError {
  return new ChiefError(409, code, message);
}

function identitiesBound(config: ChiefConfig): boolean {
  return !config.relayCallerId.startsWith(PENDING_CALLER_PREFIX) && config.workers.length > 0;
}

/** Postgres chief registry. Runtime state (tasks, decisions) stays in each slot's ledger. */
export class ChiefRegistry implements ChiefBackend {
  readonly #database: Database;
  readonly #source: RepositorySource | undefined;
  readonly #identities: ((context: WorkspaceContext, chiefId: string) => ChiefIdentities) | undefined;

  constructor(options: {
    database: Database;
    repositories?: RepositorySource;
    identities?: (context: WorkspaceContext, chiefId: string) => ChiefIdentities;
  }) {
    this.#database = options.database;
    this.#source = options.repositories;
    this.#identities = options.identities;
  }

  async list(context: WorkspaceContext) {
    const rows = await this.#database.query<ChiefRow>(
      `SELECT * FROM selfhost_chiefs
        WHERE organization_id = $1 AND workspace_id = $2
        ORDER BY created_at DESC, id`,
      [context.organizationId, context.workspaceId],
    );
    return { mode: "slots", chiefs: rows.rows.map((row) => this.#view(row)) };
  }

  async repositories(context: WorkspaceContext): Promise<RepositoryCatalog> {
    if (!this.#source) {
      throw new ChiefError(503, "github_unavailable", "GitHub repository discovery is not configured.");
    }
    return this.#source.list(context);
  }

  async get(context: WorkspaceContext, id: string) {
    return this.#view(await this.#tenantRow(this.#database, context, id));
  }

  async create(context: WorkspaceContext, raw: unknown) {
    const parsed = setupSchema.safeParse(raw);
    if (!parsed.success) {
      throw new ChiefError(400, "invalid_setup", "Check the project, repository, placement and operating policy.");
    }
    const input = parsed.data;
    const digest = digestOf(input);
    // A retry replays before the catalog read, so it survives a GitHub outage.
    const replay = await this.#replay(this.#database, context, input.requestId, digest);
    if (replay) return replay;

    const catalog = await this.repositories(context);
    if (!catalog.connected) throw conflict("github_disconnected", "Connect GitHub before setting up a chief.");
    const selected = input.repositoryIds.map((id) => {
      const repository = catalog.repositories.find((candidate) => candidate.id === id);
      if (!repository) {
        throw new ChiefError(400, "repository_access_changed", "Refresh repositories and select an accessible repository.");
      }
      return { id, repository: repository.fullName.toLowerCase(), fullName: repository.fullName };
    });
    const repositories = selected.map((item) => item.repository).sort();
    const chiefId = `chief-${digestOf([context.organizationId, context.workspaceId, repositories]).slice(0, 24)}`;
    const name = selected.length === 1
      ? selected[0]!.fullName.split("/")[1]!
      : `${selected[0]!.fullName.split("/")[0]} · ${selected.length} repositories`;
    const identities = this.#identities?.(context, chiefId) ?? {
      relayCallerId: `${PENDING_CALLER_PREFIX}${chiefId}`,
      workers: [],
    };
    const config: ChiefConfig = {
      revision: 1,
      chiefId,
      organizationId: context.organizationId,
      workspaceId: context.workspaceId,
      projectId: chiefId,
      repositories,
      ...identities,
      policy: {
        version: "1",
        allowedActions: input.allowedActions,
        maxEvidenceAgeMs: 3_600_000,
        minConfidence: 0.8,
        maxConcurrentTasks: input.maxConcurrentTasks,
        budgetMicros: Math.round(input.budgetDollars * 1_000_000),
        taskReservationMicros: 1_000_000,
      },
    };

    return this.#database.transaction(async (tx) => {
      await tx.query("SELECT pg_advisory_xact_lock($1)", [SLOT_ASSIGNMENT_LOCK]);
      const inserted = await tx.query(
        `INSERT INTO selfhost_chiefs
           (id, organization_id, workspace_id, name, repository, request_id, digest, config, placement)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9)
         ON CONFLICT DO NOTHING
         RETURNING id`,
        [
          chiefId,
          context.organizationId,
          context.workspaceId,
          name,
          repositories[0],
          input.requestId,
          digest,
          JSON.stringify(config),
          input.placement,
        ],
      );
      if (inserted.rows.length === 0) {
        const raced = await this.#replay(tx, context, input.requestId, digest);
        if (raced) return raced;
        throw conflict("project_already_configured", "A selected repository already has a chief in this workspace.");
      }
      for (const item of selected) {
        const claimed = await tx.query(
          `INSERT INTO selfhost_chief_repositories (workspace_id, repository_id, repository, chief_id)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT DO NOTHING
           RETURNING chief_id`,
          [context.workspaceId, item.id, item.repository, chiefId],
        );
        // Throwing rolls back the chief row and any repositories claimed so far.
        if (claimed.rows.length === 0) {
          throw conflict("project_already_configured", "A selected repository already has a chief in this workspace.");
        }
      }
      const free = await tx.query<{ slot_id: string }>(
        `SELECT slot_id FROM selfhost_chief_slots
          WHERE state = 'free'
          ORDER BY created_at, slot_id
          LIMIT 1
          FOR UPDATE`,
      );
      if (free.rows[0]) await this.#assign(tx, free.rows[0].slot_id, chiefId);
      return this.#view(await this.#tenantRow(tx, context, chiefId));
    });
  }

  async scan(context: WorkspaceContext, id: string): Promise<never> {
    const row = await this.#tenantRow(this.#database, context, id);
    if (row.state !== "ready") throw conflict("chief_not_ready", "Finish runtime setup before scanning sessions.");
    // Cycles run on the slot host's timer; Control holds no runtime to scan with.
    throw conflict("scan_runs_on_host", "Scans run on the chief's own schedule.");
  }

  /** Operator: adds a slot, or returns it unchanged. A new slot serves the oldest waiting chief. */
  async registerSlot(raw: unknown) {
    const parsed = slotSchema.safeParse(raw);
    if (!parsed.success) throw new ChiefError(400, "invalid_slot", "slotId must be an opaque slot ID.");
    const { slotId } = parsed.data;
    return this.#database.transaction(async (tx) => {
      await tx.query("SELECT pg_advisory_xact_lock($1)", [SLOT_ASSIGNMENT_LOCK]);
      const inserted = await tx.query(
        `INSERT INTO selfhost_chief_slots (slot_id) VALUES ($1) ON CONFLICT DO NOTHING RETURNING slot_id`,
        [slotId],
      );
      if (inserted.rows.length > 0) {
        const waiting = await tx.query<{ id: string; organization_id: string; workspace_id: string }>(
          `SELECT id, organization_id, workspace_id FROM selfhost_chiefs
            WHERE state = 'awaiting_capacity'
            ORDER BY created_at, id
            LIMIT 1
            FOR UPDATE`,
        );
        const chief = waiting.rows[0];
        await recordAudit(tx, {
          organizationId: chief?.organization_id ?? null,
          workspaceId: chief?.workspace_id ?? null,
          actor: { kind: "bootstrap" },
          action: "chief_slot.register",
          target: slotId,
        });
        if (chief) await this.#assign(tx, slotId, chief.id);
      }
      const slot = await tx.query<{ state: string; chief_id: string | null }>(
        "SELECT state, chief_id FROM selfhost_chief_slots WHERE slot_id = $1",
        [slotId],
      );
      return {
        created: inserted.rows.length > 0,
        slotId,
        state: slot.rows[0]!.state,
        chiefId: slot.rows[0]!.chief_id,
      };
    });
  }

  /** Operator: what `relay-chief-bind-slot` needs. The config schema holds no credentials. */
  async slotBinding(slotId: string) {
    const result = await this.#database.query<{ state: string; config: ChiefConfig | null; chief_id: string | null }>(
      `SELECT s.state, s.chief_id, c.config
         FROM selfhost_chief_slots s
         LEFT JOIN selfhost_chiefs c ON c.id = s.chief_id
        WHERE s.slot_id = $1`,
      [slotId],
    );
    const slot = result.rows[0];
    if (!slot) throw new ChiefError(404, "slot_not_found", "Slot not found.");
    if (!slot.config) return { slotId, state: slot.state, chiefId: null };
    return {
      slotId,
      state: slot.state,
      chiefId: slot.chief_id,
      configurationDigest: digestOf(slot.config),
      identitiesBound: identitiesBound(slot.config),
      readinessChecks: READINESS_CHECKS,
      config: slot.config,
    };
  }

  /**
   * Operator: sets the pre-provisioned chief's Relay identities at bind time.
   * Any change increases the revision, which also changes the digest ready checks.
   */
  async bindIdentities(chiefId: string, raw: unknown) {
    const parsed = identitiesSchema.safeParse(raw);
    if (!parsed.success) throw new ChiefError(400, "invalid_identities", "Check the Relay caller and worker identities.");
    return this.#database.transaction(async (tx) => {
      const found = await tx.query<ChiefRow>("SELECT * FROM selfhost_chiefs WHERE id = $1 FOR UPDATE", [chiefId]);
      const row = found.rows[0];
      if (!row) throw new ChiefError(404, "chief_not_found", "Chief not found.");
      if (row.state === "awaiting_capacity") throw conflict("chief_not_bound", "This chief has no slot yet.");
      const unchanged =
        digestOf({ relayCallerId: row.config.relayCallerId, workers: row.config.workers }) === digestOf(parsed.data);
      let config = row.config;
      if (!unchanged) {
        if (row.state === "ready") throw conflict("chief_already_ready", "A ready chief cannot change identities.");
        config = { ...row.config, ...parsed.data, revision: row.config.revision + 1 };
        await tx.query("UPDATE selfhost_chiefs SET config = $2::jsonb WHERE id = $1", [chiefId, JSON.stringify(config)]);
        await recordAudit(tx, {
          organizationId: row.organization_id,
          workspaceId: row.workspace_id,
          actor: { kind: "bootstrap" },
          action: "chief.identities_bind",
          target: chiefId,
        });
      }
      return { chiefId, revision: config.revision, configurationDigest: digestOf(config) };
    });
  }

  /**
   * Operator: records the named readiness results and marks the chief ready only
   * when every one passed. Control cannot observe the host, so these are operator
   * attestations, bound to the exact configuration by its digest.
   */
  async markReady(chiefId: string, raw: unknown) {
    const parsed = readySchema.safeParse(raw);
    if (!parsed.success) throw new ChiefError(400, "invalid_readiness", "Report each named readiness check.");
    const { attestedBy, configurationDigest, checks } = parsed.data;
    if (new Set(checks.map((check) => check.name)).size !== checks.length) {
      throw new ChiefError(400, "invalid_readiness", "Report each readiness check once.");
    }
    const outcome = await this.#database.transaction(async (tx) => {
      const found = await tx.query<ChiefRow>("SELECT * FROM selfhost_chiefs WHERE id = $1 FOR UPDATE", [chiefId]);
      const row = found.rows[0];
      if (!row) throw new ChiefError(404, "chief_not_found", "Chief not found.");
      if (row.state === "ready") return { unmet: [] as string[] };
      if (row.state !== "awaiting_binding") throw conflict("chief_not_bound", "This chief has no slot yet.");
      if (digestOf(row.config) !== configurationDigest) {
        throw conflict("configuration_changed", "The configuration does not match this chief.");
      }
      if (!identitiesBound(row.config)) {
        throw conflict("chief_identity_unbound", "This chief has no Relay caller and worker identities yet.");
      }
      const passed = new Set(checks.filter((check) => check.passed).map((check) => check.name));
      const unmet = READINESS_CHECKS.filter((name) => !passed.has(name));
      await tx.query(
        `UPDATE selfhost_chiefs
            SET readiness = $2::jsonb,
                state = CASE WHEN $3::boolean THEN 'ready' ELSE state END,
                ready_at = CASE WHEN $3::boolean THEN now() ELSE ready_at END
          WHERE id = $1`,
        [
          chiefId,
          JSON.stringify({
            source: "operator_attestation",
            attestedBy,
            attestedAt: new Date().toISOString(),
            checks,
          }),
          unmet.length === 0,
        ],
      );
      await recordAudit(tx, {
        organizationId: row.organization_id,
        workspaceId: row.workspace_id,
        actor: { kind: "bootstrap" },
        action: unmet.length === 0 ? "chief.ready" : "chief.readiness_incomplete",
        target: `${chiefId} attested by ${attestedBy}`,
      });
      return { unmet };
    });
    // Outside the transaction, so the recorded results survive the refusal.
    if (outcome.unmet.length > 0) {
      throw new ChiefError(409, "readiness_incomplete", "Every readiness check must pass.", { unmet: outcome.unmet });
    }
    return { chiefId, status: "ready" };
  }

  /** Operator: issues this chief's service credential, revoking any earlier one. Shown once. */
  async issueServiceCredential(chiefId: string) {
    const token = opaqueToken(SERVICE_TOKEN_PREFIX);
    const expiresAt = new Date(Date.now() + SERVICE_TOKEN_TTL_MS);
    await this.#database.transaction(async (tx) => {
      const found = await tx.query<ChiefRow>("SELECT * FROM selfhost_chiefs WHERE id = $1 FOR UPDATE", [chiefId]);
      const row = found.rows[0];
      if (!row) throw new ChiefError(404, "chief_not_found", "Chief not found.");
      if (row.state === "awaiting_capacity") throw conflict("chief_not_bound", "This chief has no slot yet.");
      await tx.query(
        `UPDATE selfhost_chief_service_credentials SET revoked_at = now()
          WHERE chief_id = $1 AND revoked_at IS NULL`,
        [chiefId],
      );
      await tx.query(
        `INSERT INTO selfhost_chief_service_credentials (id, chief_id, token_hash, expires_at)
         VALUES ($1, $2, $3, $4)`,
        [randomUUID(), chiefId, hashSecret(token), expiresAt.toISOString()],
      );
      await recordAudit(tx, {
        organizationId: row.organization_id,
        workspaceId: row.workspace_id,
        actor: { kind: "bootstrap" },
        action: "chief.service_credential_issue",
        target: chiefId,
      });
    });
    return { token, expiresAt: expiresAt.toISOString() };
  }

  /** Resolves a service credential only for the one chief it was issued to. */
  async authenticateService(token: string, projectId: string): Promise<(WorkspaceContext & { projectId: string }) | null> {
    if (!token.startsWith(SERVICE_TOKEN_PREFIX)) return null;
    const result = await this.#database.query<{ organization_id: string; workspace_id: string }>(
      `SELECT c.organization_id, c.workspace_id
         FROM selfhost_chief_service_credentials k
         JOIN selfhost_chiefs c ON c.id = k.chief_id
        WHERE k.token_hash = $1
          AND k.chief_id = $2
          AND k.revoked_at IS NULL
          AND k.expires_at > now()`,
      [hashSecret(token), projectId],
    );
    const row = result.rows[0];
    return row ? { organizationId: row.organization_id, workspaceId: row.workspace_id, projectId } : null;
  }

  async #assign(tx: SqlExecutor, slotId: string, chiefId: string): Promise<void> {
    await tx.query(
      `UPDATE selfhost_chief_slots SET state = 'assigned', chief_id = $2, assigned_at = now() WHERE slot_id = $1`,
      [slotId, chiefId],
    );
    await tx.query(`UPDATE selfhost_chiefs SET state = 'awaiting_binding' WHERE id = $1`, [chiefId]);
  }

  async #replay(executor: SqlExecutor, context: WorkspaceContext, requestId: string, digest: string) {
    const found = await executor.query<ChiefRow>(
      `SELECT * FROM selfhost_chiefs WHERE organization_id = $1 AND workspace_id = $2 AND request_id = $3`,
      [context.organizationId, context.workspaceId, requestId],
    );
    const row = found.rows[0];
    if (!row) return null;
    if (row.digest !== digest) {
      throw conflict("setup_conflict", "This setup request was already used with different settings.");
    }
    return this.#view(row);
  }

  async #tenantRow(executor: SqlExecutor, context: WorkspaceContext, id: string): Promise<ChiefRow> {
    const found = await executor.query<ChiefRow>(
      `SELECT * FROM selfhost_chiefs WHERE id = $1 AND organization_id = $2 AND workspace_id = $3`,
      [id, context.organizationId, context.workspaceId],
    );
    if (!found.rows[0]) throw new ChiefError(404, "chief_not_found", "Chief not found in this workspace.");
    return found.rows[0];
  }

  /** The tenant's view. The slot ID is operator-only and never appears here. */
  #view(row: ChiefRow) {
    const ready = row.state === "ready";
    return {
      id: row.id,
      name: row.name,
      repository: row.repository,
      repositories: row.config.repositories,
      mode: "slots",
      status: row.state,
      createdAt: new Date(row.created_at).toISOString(),
      placement: row.placement,
      // Compatibility alias until relay-webapp reads `placement`.
      region: row.placement,
      budgetDollars: row.config.policy.budgetMicros / 1_000_000,
      maxConcurrentTasks: row.config.policy.maxConcurrentTasks,
      allowedActions: row.config.policy.allowedActions,
      setupSteps: [
        { label: "Project and policy saved", complete: true },
        { label: "Capacity assigned", complete: row.state !== "awaiting_capacity" },
        { label: "Readiness checks passed", complete: ready },
      ],
    };
  }
}
