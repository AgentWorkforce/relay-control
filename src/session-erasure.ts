import { randomUUID } from "node:crypto";
import { z } from "zod";
import { iso, recordAudit, type AuditActor } from "./admin/audit.js";
import type { SelfhostConfig } from "./config.js";
import type { Database } from "./database.js";

type ErasureApi = NonNullable<SelfhostConfig["sessionErasureApi"]>;

/** A session is only unique within its organization, workspace and source. */
export type ErasureTarget = {
  organizationId: string;
  workspaceId: string;
  source: string;
  sessionId: string;
};

const MAX_RECEIPT_BYTES = 16_384;
const MAX_IDENTITY = 512;
const CONTROL = /[\u0000-\u001f\u007f]/;
const code = z.string().regex(/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/);
const timestamp = z.iso.datetime({ offset: true });

/** The stores a completed receipt must account for, exactly. */
const ARTIFACT_KEYS = [
  "transcriptObjects", "stagedObjects", "bufferedBatches", "bufferedRows", "pointerRows", "ledgerRows",
  "directoryRows", "catalogRows", "largeReadJobs", "searchDocuments", "briefDocuments", "summaries", "briefs",
  "replayPublications", "analysisPublications", "historyDerivedObjects",
];

// Unknown fields are stripped and artifact values are counts and states, so
// nothing but ids, categories and numbers can be relayed to the operator.
const receiptSchema = z.object({
  orgId: z.string().min(1).max(MAX_IDENTITY),
  workspaceId: z.string().min(1).max(MAX_IDENTITY),
  source: z.string().min(1).max(MAX_IDENTITY),
  sessionId: z.string().min(1).max(MAX_IDENTITY),
  requestId: z.string().min(1).max(MAX_IDENTITY),
  status: z.enum(["in_progress", "completed", "failed"]),
  requestedAt: timestamp,
  completedAt: timestamp.nullable(),
  artifacts: z.record(code, z.object({
    count: z.number().int().nonnegative(),
    state: z.enum(["done", "pending", "not_applicable"]),
  })),
  uploadsFenced: z.boolean(),
  unreadable: z.boolean(),
  unreadableAt: timestamp.nullable(),
  bytesErased: z.boolean(),
  bytesErasedAt: timestamp.nullable(),
  legacyScope: code,
  failure: z.object({ step: code, code, retryable: z.boolean() }).nullable(),
});

export type ErasureReceipt = z.infer<typeof receiptSchema>;

export type ErasureAudit = {
  action: "session.hard_deleted";
  actorKind: string;
  actorId: string | null;
  recordedAt: string;
};

export type ErasureResult = ErasureReceipt & { audit: ErasureAudit | null };

/** Fixed metadata only: never carries upstream bodies or the service secret. */
export class SessionErasureError extends Error {
  constructor(
    readonly status: 400 | 404 | 501 | 502 | 503,
    readonly code: string,
    message: string,
    readonly erasure?: ErasureResult,
  ) {
    super(message);
  }
}

/** The pipeline's id rules: 1-512 UTF-8 bytes, no control characters. */
function validIdentity(value: string): boolean {
  return Boolean(value.trim()) && value === value.trim() && Buffer.byteLength(value) <= MAX_IDENTITY && !CONTROL.test(value);
}

/** Resolves the required `workspaceId` and `source` query parameters. */
export async function erasureTarget(
  database: Database,
  organizationId: string,
  sessionId: string,
  query: URLSearchParams,
): Promise<ErasureTarget> {
  if (!validIdentity(sessionId)) {
    throw new SessionErasureError(400, "invalid_session_id", "Session id is not valid");
  }
  const workspaceId = query.get("workspaceId") ?? "";
  const source = query.get("source") ?? "";
  if (!validIdentity(workspaceId) || !validIdentity(source)) {
    throw new SessionErasureError(400, "invalid_session_target", "workspaceId and source are required");
  }
  const workspace = await database.query(
    `SELECT 1 FROM workspaces WHERE id::text = $1 AND organization_id = $2`,
    [workspaceId, organizationId],
  );
  if (workspace.rows.length === 0) {
    throw new SessionErasureError(404, "workspace_not_found", "Workspace not found");
  }
  return { organizationId, workspaceId, source, sessionId };
}

export function requireErasureApi(config: SelfhostConfig): ErasureApi {
  if (!config.sessionErasureApi) throw notImplemented();
  return config.sessionErasureApi;
}

function notImplemented(): SessionErasureError {
  return new SessionErasureError(501, "not_implemented", "Session erasure is not configured for this installation");
}

function unavailable(): SessionErasureError {
  return new SessionErasureError(503, "session_erasure_unavailable", "The session pipeline is unavailable; retry the request");
}

function invalid(): SessionErasureError {
  return new SessionErasureError(502, "invalid_session_erasure_response", "The session pipeline returned an invalid response");
}

async function callPipeline(
  api: ErasureApi,
  method: "GET" | "POST",
  target: ErasureTarget,
  body?: unknown,
): Promise<{ status: number; value: unknown }> {
  const enc = encodeURIComponent;
  const path = `/internal/v1/session-erase/organizations/${enc(target.organizationId)}/workspaces/${enc(target.workspaceId)}/sources/${enc(target.source)}/sessions/${enc(target.sessionId)}`;
  let response: Response;
  try {
    response = await fetch(new URL(path, api.url), {
      method,
      redirect: "error",
      signal: AbortSignal.timeout(30_000),
      headers: {
        authorization: `Bearer ${api.secret}`,
        accept: "application/json",
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  } catch {
    throw unavailable();
  }
  if (response.status >= 500) {
    await response.body?.cancel();
    throw response.status === 501 ? notImplemented() : unavailable();
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    const reader = response.body?.getReader();
    if (!reader) throw new Error("empty");
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        size += chunk.value.byteLength;
        if (size > MAX_RECEIPT_BYTES) throw new Error("too large");
        chunks.push(chunk.value);
      }
    } finally {
      await reader.cancel();
    }
    return { status: response.status, value: JSON.parse(Buffer.concat(chunks).toString("utf8")) };
  } catch {
    throw invalid();
  }
}

/**
 * Every receipt must name this exact target. A completed one is only believed
 * when it has a completion time, confirms late uploads are fenced, the session
 * is unreadable, its bytes are verified erased, and every store is accounted
 * for with nothing pending. Anything less is an error: the route must never
 * report an erase that did not happen.
 */
function parseReceipt(value: unknown, target: ErasureTarget): ErasureReceipt {
  const parsed = receiptSchema.safeParse(value);
  if (!parsed.success) throw invalid();
  const receipt = parsed.data;
  if (
    receipt.orgId !== target.organizationId || receipt.workspaceId !== target.workspaceId ||
    receipt.source !== target.source || receipt.sessionId !== target.sessionId
  ) throw invalid();
  const keys = Object.keys(receipt.artifacts);
  if (
    receipt.status === "completed" &&
    (!receipt.completedAt || !receipt.uploadsFenced || !receipt.unreadable || !receipt.bytesErased ||
      keys.length !== ARTIFACT_KEYS.length || !ARTIFACT_KEYS.every((key) => keys.includes(key)) ||
      Object.values(receipt.artifacts).some((artifact) => artifact.state === "pending"))
  ) throw invalid();
  return receipt;
}

function upstreamError(value: unknown): string | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const error = (value as { error?: unknown }).error;
  return typeof error === "string" ? error : null;
}

function auditFrom(row: { actor_kind: string; actor_id: string | null; completed_at: Date | string | null }): ErasureAudit | null {
  if (!row.completed_at) return null;
  return {
    action: "session.hard_deleted",
    actorKind: row.actor_kind,
    actorId: row.actor_id,
    recordedAt: iso(row.completed_at),
  };
}

function actorFrom(kind: string, id: string | null): AuditActor {
  if (kind === "user" && id) return { kind: "user", userId: id };
  if (kind === "service" && id) return { kind: "service", subject: id };
  return { kind: "bootstrap" };
}

function auditTarget(target: ErasureTarget, requestId: string): string {
  return `session:${target.sessionId} source=${target.source} request=${requestId}`;
}

type ErasureRow = {
  request_id: string;
  actor_kind: string;
  actor_id: string | null;
  completed_at: Date | string | null;
};

const TARGET_WHERE = "organization_id = $1 AND workspace_id::text = $2 AND source = $3 AND session_id = $4";

/**
 * Audits a completed erase exactly once, attributed to whoever first asked for
 * it, and returns the ledger's audit view. Safe to call on every read: the
 * `completed_at IS NULL` claim makes concurrent callers race for one insert. A
 * receipt for another request id is not this erase, so it is never audited as one.
 */
async function withAudit(database: Database, target: ErasureTarget, receipt: ErasureReceipt): Promise<ErasureResult> {
  const key = [target.organizationId, target.workspaceId, target.source, target.sessionId];
  const row = await database.transaction(async (tx) => {
    if (receipt.status === "completed") {
      const claimed = await tx.query<ErasureRow>(
        `UPDATE session_erasures SET completed_at = now()
          WHERE ${TARGET_WHERE} AND completed_at IS NULL AND request_id::text = $5
          RETURNING request_id, actor_kind, actor_id, completed_at`,
        [...key, receipt.requestId],
      );
      const first = claimed.rows[0];
      if (first) {
        await recordAudit(tx, {
          organizationId: target.organizationId,
          workspaceId: target.workspaceId,
          actor: actorFrom(first.actor_kind, first.actor_id),
          action: "session.hard_deleted",
          target: auditTarget(target, first.request_id),
        });
        return first;
      }
    }
    const existing = await tx.query<ErasureRow>(
      `SELECT request_id, actor_kind, actor_id, completed_at FROM session_erasures WHERE ${TARGET_WHERE}`,
      key,
    );
    return existing.rows[0] ?? null;
  });
  return { ...receipt, audit: row ? auditFrom(row) : null };
}

/**
 * Asks the pipeline to erase one session. The attempt is audited before any
 * data is touched, so an erase can never run without a trail. Idempotent: the
 * request id is stable per session and the pipeline repeats its receipt.
 */
export async function eraseSession(
  database: Database,
  api: ErasureApi,
  target: ErasureTarget,
  actor: AuditActor,
): Promise<ErasureResult> {
  const key = [target.organizationId, target.workspaceId, target.source, target.sessionId];
  const actorId = actor.kind === "user" ? actor.userId : actor.kind === "service" ? actor.subject : null;
  const requestId = await database.transaction(async (tx) => {
    await tx.query(
      `INSERT INTO session_erasures
         (organization_id, workspace_id, source, session_id, request_id, actor_kind, actor_id)
       VALUES ($1, $2::uuid, $3, $4, $5, $6, $7)
       ON CONFLICT (organization_id, workspace_id, source, session_id) DO NOTHING`,
      [...key, randomUUID(), actor.kind, actorId],
    );
    const row = await tx.query<{ request_id: string }>(
      `SELECT request_id FROM session_erasures WHERE ${TARGET_WHERE}`,
      key,
    );
    const id = row.rows[0]!.request_id;
    await recordAudit(tx, {
      organizationId: target.organizationId,
      workspaceId: target.workspaceId,
      actor,
      action: "session.hard_delete.requested",
      target: auditTarget(target, id),
    });
    return id;
  });

  const { status, value } = await callPipeline(api, "POST", target, {
    requestId,
    // The pipeline requires a non-empty actor id; the bootstrap bearer has none.
    actor: { kind: actor.kind, id: actorId ?? "bootstrap" },
  });
  if (status !== 200 && status !== 202) throw invalid();
  const result = await withAudit(database, target, parseReceipt(value, target));
  if (result.status === "failed") {
    throw new SessionErasureError(502, "session_erasure_failed", "The session could not be fully erased; retry the request", result);
  }
  return result;
}

/** Reads the pipeline's receipt. Records the completion audit if it is due. */
export async function readSessionErasure(
  database: Database,
  api: ErasureApi,
  target: ErasureTarget,
): Promise<ErasureResult> {
  const { status, value } = await callPipeline(api, "GET", target);
  if (status === 404 && upstreamError(value) === "erasure_not_found") {
    throw new SessionErasureError(404, "erasure_not_found", "No erasure exists for this session");
  }
  if (status !== 200) throw invalid();
  return withAudit(database, target, parseReceipt(value, target));
}
