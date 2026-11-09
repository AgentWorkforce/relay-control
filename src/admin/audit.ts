import { randomUUID } from "node:crypto";
import type { SqlExecutor } from "../database.js";

export type AuditActor =
  | { kind: "user"; userId: string }
  | { kind: "service"; subject: string }
  | { kind: "bootstrap" };

export type AuditEvent = {
  id: string;
  actorKind: AuditActor["kind"];
  actorId: string | null;
  action: string;
  target: string | null;
  createdAt: string;
};

/** Records an admin action. Never pass secret values as `target`. */
export async function recordAudit(
  executor: SqlExecutor,
  input: {
    organizationId?: string | null;
    workspaceId?: string | null;
    actor: AuditActor;
    action: string;
    target?: string | null;
  },
): Promise<void> {
  const actorId = input.actor.kind === "user"
    ? input.actor.userId
    : input.actor.kind === "service"
      ? input.actor.subject
      : null;
  await executor.query(
    `INSERT INTO admin_audit_events
       (id, organization_id, workspace_id, actor_kind, actor_id, action, target)
     VALUES ($1, $2, $3, $4, $5, $6, $7)`,
    [
      randomUUID(),
      input.organizationId ?? null,
      input.workspaceId ?? null,
      input.actor.kind,
      actorId,
      input.action,
      input.target ?? null,
    ],
  );
}

export async function listAudit(
  executor: SqlExecutor,
  workspaceId: string,
  limit = 100,
): Promise<AuditEvent[]> {
  const result = await executor.query<{
    id: string;
    actor_kind: AuditActor["kind"];
    actor_id: string | null;
    action: string;
    target: string | null;
    created_at: Date | string;
  }>(
    `SELECT id, actor_kind, actor_id, action, target, created_at
       FROM admin_audit_events
      WHERE workspace_id = $1
      ORDER BY created_at DESC
      LIMIT $2`,
    [workspaceId, Math.max(1, Math.min(500, limit))],
  );
  return result.rows.map((row) => ({
    id: row.id,
    actorKind: row.actor_kind,
    actorId: row.actor_id,
    action: row.action,
    target: row.target,
    createdAt: iso(row.created_at),
  }));
}

export function iso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}
