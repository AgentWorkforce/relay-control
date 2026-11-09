import { randomUUID } from "node:crypto";
import { z } from "zod";
import { iso, recordAudit, type AuditActor } from "./admin/audit.js";
import type { SelfhostConfig } from "./config.js";
import type { Database } from "./database.js";

type ErasureApi = NonNullable<SelfhostConfig["sessionErasureApi"]>;

const MAX_RECEIPT_BYTES = 16_384;
const MAX_SESSION_ID = 512;
const CONTROL = /[\u0000-\u001f\u007f]/;
const code = z.string().regex(/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/);
const timestamp = z.iso.datetime({ offset: true });

// Unknown fields are stripped and artifact values are counts, so nothing but
// ids, categories and numbers can be relayed to the operator.
const receiptSchema = z.object({
  orgId: z.string().min(1).max(256),
  sessionId: z.string().min(1).max(MAX_SESSION_ID),
  requestId: z.string().min(1).max(256),
  status: z.enum(["in_progress", "completed", "failed"]),
  requestedAt: timestamp,
  completedAt: timestamp.nullable(),
  artifacts: z.record(code, z.number().int().nonnegative()),
  uploadsFenced: z.boolean(),
  failure: z.object({ code }).nullable(),
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

/** Accepts every id the session read routes accept, so any readable session can be erased. */
export function assertSessionId(sessionId: string): void {
  if (!sessionId.trim() || sessionId !== sessionId.trim() || sessionId.length > MAX_SESSION_ID || CONTROL.test(sessionId)) {
    throw new SessionErasureError(400, "invalid_session_id", "Session id is not valid");
  }
}

export function requireErasureApi(config: SelfhostConfig): ErasureApi {
  if (!config.sessionErasureApi) {
    throw new SessionErasureError(501, "not_implemented", "Session erasure is not configured for this installation");
  }
  return config.sessionErasureApi;
}

function unavailable(): SessionErasureError {
  return new SessionErasureError(503, "session_erasure_unavailable", "The session pipeline could not be reached; retry the request");
}

function invalid(): SessionErasureError {
  return new SessionErasureError(502, "invalid_session_erasure_response", "The session pipeline returned an invalid response");
}

async function callPipeline(
  api: ErasureApi,
  method: "GET" | "POST",
  organizationId: string,
  sessionId: string,
  body?: unknown,
): Promise<{ status: number; value: unknown }> {
  const path = `/internal/v1/session-erase/organizations/${encodeURIComponent(organizationId)}/sessions/${encodeURIComponent(sessionId)}`;
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
    throw unavailable();
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
 * A completed receipt is only believed when it names this session, has a
 * completion time and confirms late uploads are fenced. Anything less is an
 * error: the route must never report an erase that did not happen.
 */
function parseReceipt(value: unknown, organizationId: string, sessionId: string): ErasureReceipt {
  const parsed = receiptSchema.safeParse(value);
  if (!parsed.success) throw invalid();
  const receipt = parsed.data;
  if (receipt.orgId !== organizationId || receipt.sessionId !== sessionId) throw invalid();
  if (receipt.status === "completed" && (!receipt.completedAt || !receipt.uploadsFenced)) throw invalid();
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

type ErasureRow = {
  request_id: string;
  actor_kind: string;
  actor_id: string | null;
  completed_at: Date | string | null;
};

/**
 * Audits a completed erase exactly once, attributed to whoever first asked for
 * it, and returns the ledger's audit view. Safe to call on every read: the
 * `completed_at IS NULL` claim makes concurrent callers race for one insert. A
 * receipt for another request id is not this erase, so it is never audited as one.
 */
async function withAudit(
  database: Database,
  organizationId: string,
  sessionId: string,
  receipt: ErasureReceipt,
): Promise<ErasureResult> {
  const row = await database.transaction(async (tx) => {
    if (receipt.status === "completed") {
      const claimed = await tx.query<ErasureRow>(
        `UPDATE selfhost_session_erasures SET completed_at = now()
          WHERE organization_id = $1 AND session_id = $2 AND completed_at IS NULL AND request_id::text = $3
          RETURNING request_id, actor_kind, actor_id, completed_at`,
        [organizationId, sessionId, receipt.requestId],
      );
      const first = claimed.rows[0];
      if (first) {
        await recordAudit(tx, {
          organizationId,
          actor: actorFrom(first.actor_kind, first.actor_id),
          action: "session.hard_deleted",
          target: `session:${sessionId} request=${first.request_id}`,
        });
        return first;
      }
    }
    const existing = await tx.query<ErasureRow>(
      `SELECT request_id, actor_kind, actor_id, completed_at
         FROM selfhost_session_erasures WHERE organization_id = $1 AND session_id = $2`,
      [organizationId, sessionId],
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
  input: { organizationId: string; sessionId: string; actor: AuditActor },
): Promise<ErasureResult> {
  const { organizationId, sessionId, actor } = input;
  const actorId = actor.kind === "user" ? actor.userId : actor.kind === "service" ? actor.subject : null;
  const requestId = await database.transaction(async (tx) => {
    await tx.query(
      `INSERT INTO selfhost_session_erasures (organization_id, session_id, request_id, actor_kind, actor_id)
       VALUES ($1, $2, $3, $4, $5)
       ON CONFLICT (organization_id, session_id) DO NOTHING`,
      [organizationId, sessionId, randomUUID(), actor.kind, actorId],
    );
    const row = await tx.query<{ request_id: string }>(
      `SELECT request_id FROM selfhost_session_erasures WHERE organization_id = $1 AND session_id = $2`,
      [organizationId, sessionId],
    );
    const id = row.rows[0]!.request_id;
    await recordAudit(tx, {
      organizationId,
      actor,
      action: "session.hard_delete.requested",
      target: `session:${sessionId} request=${id}`,
    });
    return id;
  });

  const { status, value } = await callPipeline(api, "POST", organizationId, sessionId, {
    requestId,
    actor: { kind: actor.kind, id: actorId },
  });
  if (status === 404 && upstreamError(value) === "session_not_found") {
    // Nothing was erased, so nothing may be left looking like an erase.
    await database.query(
      `DELETE FROM selfhost_session_erasures
        WHERE organization_id = $1 AND session_id = $2 AND completed_at IS NULL`,
      [organizationId, sessionId],
    );
    throw new SessionErasureError(404, "session_not_found", "Session not found");
  }
  if (status !== 200 && status !== 202) throw invalid();
  const result = await withAudit(database, organizationId, sessionId, parseReceipt(value, organizationId, sessionId));
  if (result.status === "failed") {
    throw new SessionErasureError(502, "session_erasure_failed", "The session could not be fully erased; retry the request", result);
  }
  return result;
}

/** Reads the pipeline's receipt. Records the completion audit if it is due. */
export async function readSessionErasure(
  database: Database,
  api: ErasureApi,
  input: { organizationId: string; sessionId: string },
): Promise<ErasureResult> {
  const { organizationId, sessionId } = input;
  const { status, value } = await callPipeline(api, "GET", organizationId, sessionId);
  if (status === 404 && upstreamError(value) === "erasure_not_found") {
    throw new SessionErasureError(404, "erasure_not_found", "No erasure exists for this session");
  }
  if (status !== 200) throw invalid();
  return withAudit(database, organizationId, sessionId, parseReceipt(value, organizationId, sessionId));
}
