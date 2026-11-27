import { z } from "zod";
import type { Database, SqlExecutor } from "../database.js";
import { loadPolicy, memberRole, mintId, recordDelegationAudit, type DelegationPolicy } from "./service.js";
import {
  APPROVAL_DEFAULT_MS, APPROVAL_MAX_MS, MAX_ACTIONS, actionSchema, canonicalAction, configTarget, isUndelegableSetting,
  type Action,
} from "./scope.js";

/**
 * One-tap Tier O approval requests, the self-hosted twin of Cloud's
 * lib/delegation/approval-requests.ts (cloud#6704).
 *
 * A delegate asks its own owner to approve exact actions. The owner opens the
 * approve link and approves or denies through their own human session; only
 * then does Control mint the Tier O approval, exactly as POST
 * delegates/approvals would. Nothing here mints on the requester's behalf: a
 * request and its status grant nothing, and the requester learns the
 * `approval_id` only after the owner approved. The delegate then sends it as
 * `approval_ref`, and attest and redeem decide as for any Tier O approval.
 */
export const APPROVAL_REQUEST_DEFAULT_MINUTES = 60;
export const APPROVAL_REQUEST_MAX_MINUTES = APPROVAL_MAX_MS / 60_000;
export const APPROVAL_REQUEST_NOTE_MAX = 500;
export const APPROVAL_REQUEST_ID = /^apq_[A-Za-z0-9]{8,64}$/u;

export const approvalRequestInputSchema = z.object({
  actions: z.array(actionSchema).min(1).max(MAX_ACTIONS)
    .refine(actions => new Set(actions.map(action => `${action.class}\u0000${action.target}`)).size === actions.length,
      "one entry per class and target"),
  note: z.string().trim().min(1).max(APPROVAL_REQUEST_NOTE_MAX).optional(),
  single_use: z.boolean().optional(),
  expires_in_minutes: z.number().int().min(1).max(APPROVAL_REQUEST_MAX_MINUTES).optional(),
}).strict();
export type ApprovalRequestInput = z.infer<typeof approvalRequestInputSchema>;

/** The first schema issue as the field it names, e.g. `actions[0]: invalid target or conditions for this action`. */
export function approvalRequestIssue(error: z.ZodError): string {
  const issue = error.issues[0];
  if (!issue) return "invalid approval request";
  const field = issue.path.map((part, index) => typeof part === "number" ? `[${part}]` : `${index ? "." : ""}${String(part)}`).join("");
  return `${field || "request"}: ${issue.message}`;
}

export type ApprovalRequestRefusal = { code: "not_enabled" | "out_of_scope"; error: string };

/**
 * Why the workspace policy refuses these actions now, if it does: the same
 * checks, in the same order, as POST delegates/approvals.
 */
export function approvalRequestRefusal(actions: readonly Action[], policy: DelegationPolicy): ApprovalRequestRefusal | null {
  if (!policy.delegation_enabled) return { code: "not_enabled", error: "Delegation is off for this workspace" };
  if (actions.some(action => action.class === "config_change" && isUndelegableSetting(configTarget(action.target)?.setting ?? ""))) {
    return { code: "out_of_scope", error: "Delegation settings themselves are never delegable" };
  }
  const refused = policy.allowed_classes ? [...new Set(actions.map(action => action.class))]
    .filter(item => !policy.allowed_classes!.includes(item)) : [];
  return refused.length ? { code: "out_of_scope", error: `Policy does not allow delegating: ${refused.join(", ")}` } : null;
}

/** The dashboard page the owner taps to decide a request, as Cloud's approveUrl. */
export function approveUrl(origin: string, workspaceId: string, requestId: string): string {
  const url = new URL(`/dashboard/approvals/${encodeURIComponent(requestId)}`, origin);
  url.searchParams.set("workspace", workspaceId);
  return url.toString();
}

export type ApprovalRequestStatus = "pending" | "approved" | "denied" | "expired";
type ApprovalRequestRow = {
  id: string;
  workspace_id: string;
  owner_user_id: string;
  requester_agent_id: string;
  requester_agent_name: string;
  actions: Action[];
  note: string | null;
  single_use: boolean;
  status: ApprovalRequestStatus;
  approval_id: string | null;
  expires_at: Date | string;
  created_at: Date | string;
  decided_at: Date | string | null;
};
export type ApprovalRequestRecord = {
  id: string;
  workspaceId: string;
  ownerUserId: string;
  requesterAgentId: string;
  requesterAgentName: string;
  actions: Action[];
  note: string | null;
  singleUse: boolean;
  status: ApprovalRequestStatus;
  approvalId: string | null;
  expiresAt: Date;
  createdAt: Date;
  decidedAt: Date | null;
};

const COLUMNS = `id, workspace_id, owner_user_id::text AS owner_user_id, requester_agent_id, requester_agent_name, actions, note,
  single_use, status, approval_id, expires_at, created_at, decided_at`;

function recordFrom(row: ApprovalRequestRow): ApprovalRequestRecord {
  return { id: row.id, workspaceId: row.workspace_id, ownerUserId: row.owner_user_id, requesterAgentId: row.requester_agent_id,
    requesterAgentName: row.requester_agent_name, actions: row.actions, note: row.note, singleUse: row.single_use,
    status: row.status, approvalId: row.approval_id, expiresAt: new Date(row.expires_at), createdAt: new Date(row.created_at),
    decidedAt: row.decided_at === null ? null : new Date(row.decided_at) };
}

/** A request as its owner and its requester read it. Carries no secret: an approval id grants nothing alone. */
export function approvalRequestView(request: ApprovalRequestRecord) {
  return { request_id: request.id, status: request.status, actions: request.actions, note: request.note,
    single_use: request.singleUse, requester: { agent_id: request.requesterAgentId, name: request.requesterAgentName },
    approval_id: request.approvalId, expires_at: request.expiresAt.toISOString(), created_at: request.createdAt.toISOString(),
    decided_at: request.decidedAt?.toISOString() ?? null };
}

export class ApprovalRequestRefused extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
  }
}

/** The owner is no longer a member of the workspace (Cloud's MembershipGoneError). */
export class ApprovalRequestMembershipGone extends Error {}

/**
 * Inserts one Tier O approval and its `approval.minted` event, as POST
 * delegates/approvals does; `requestId` names the request it decides.
 */
export async function insertOwnerApproval(tx: SqlExecutor, input: { workspaceId: string; ownerUserId: string; actions: Action[];
  singleUse: boolean; expiresAt: Date; actorUserId: string; authMethod: string; requestId?: string }): Promise<string> {
  const id = mintId("apv");
  await tx.query(
    `INSERT INTO delegation_approvals (id, workspace_id, owner_user_id, tier, actions, single_use, expires_at)
     VALUES ($1, $2, $3, 'O', $4::jsonb, $5, $6)`,
    [id, input.workspaceId, input.ownerUserId, JSON.stringify(input.actions), input.singleUse, input.expiresAt],
  );
  await recordDelegationAudit(tx, {
    workspaceId: input.workspaceId, event: "approval.minted", actorUserId: input.actorUserId, authMethod: input.authMethod,
    ownerUserId: input.ownerUserId, approvalId: id,
    data: { actions: input.actions, single_use: input.singleUse, expires_at: input.expiresAt.toISOString(),
      ...(input.requestId ? { request_id: input.requestId } : {}) },
  });
  return id;
}

/**
 * Opens a request from one of the caller's own Relay identities to the
 * caller's own user: the delegate's owner. Refused when delegation is off or
 * the policy would refuse minting these actions anyway. Records the request
 * and its `approval_request.requested` event under the owner's membership
 * lock, and grants nothing.
 */
export async function openApprovalRequest(database: Database, input: { workspaceId: string; ownerUserId: string; authMethod: string;
  requester: { agentId: string; name: string }; request: ApprovalRequestInput; origin: string }, now = new Date()) {
  const actions = input.request.actions.map(action => canonicalAction(action));
  const refused = approvalRequestRefusal(actions, await loadPolicy(database, input.workspaceId));
  if (refused) throw new ApprovalRequestRefused(refused.code, refused.error);
  const minutes = input.request.expires_in_minutes ?? APPROVAL_REQUEST_DEFAULT_MINUTES;
  const expiresAt = new Date(now.getTime() + minutes * 60_000);
  const singleUse = Boolean(input.request.single_use);
  const note = input.request.note ?? null;
  const request = await database.transaction(async (tx) => {
    if (!await memberRole(tx, input.workspaceId, input.ownerUserId, true)) throw new ApprovalRequestMembershipGone();
    const row = (await tx.query<ApprovalRequestRow>(
      `INSERT INTO delegation_approval_requests
         (id, workspace_id, owner_user_id, requester_agent_id, requester_agent_name, actions, note, single_use, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8, $9)
       RETURNING ${COLUMNS}`,
      [mintId("apq"), input.workspaceId, input.ownerUserId, input.requester.agentId, input.requester.name,
        JSON.stringify(actions), note, singleUse, expiresAt],
    )).rows[0]!;
    await recordDelegationAudit(tx, {
      workspaceId: input.workspaceId, event: "approval_request.requested", actorUserId: input.ownerUserId,
      actorAgentId: input.requester.agentId, authMethod: input.authMethod, ownerUserId: input.ownerUserId,
      data: { request_id: row.id, requester_agent_name: input.requester.name, actions, single_use: singleUse,
        expires_at: expiresAt.toISOString() },
    });
    return recordFrom(row);
  });
  return { ...approvalRequestView(request), approve_url: approveUrl(input.origin, input.workspaceId, request.id) };
}

/** Marks a pending request past its expiry as expired, once, with its audit event. */
async function expireRequestRow(tx: SqlExecutor, row: ApprovalRequestRow, now: Date): Promise<ApprovalRequestRow | null> {
  const expired = (await tx.query<ApprovalRequestRow>(
    `UPDATE delegation_approval_requests SET status = 'expired', decided_at = $2
      WHERE id = $1 AND status = 'pending' RETURNING ${COLUMNS}`,
    [row.id, now],
  )).rows[0];
  if (!expired) return null;
  await recordDelegationAudit(tx, {
    workspaceId: row.workspace_id, event: "approval_request.expired", actorUserId: null, authMethod: "system",
    ownerUserId: row.owner_user_id, actorAgentId: row.requester_agent_id, reason: "expired",
    data: { request_id: row.id, expires_at: new Date(row.expires_at).toISOString() },
  });
  return expired;
}

/** One request, read now: a pending one past its expiry is expired first. */
export async function getApprovalRequest(database: Database, workspaceId: string, requestId: string,
  now = new Date()): Promise<ApprovalRequestRecord | null> {
  const row = (await database.query<ApprovalRequestRow>(
    `SELECT ${COLUMNS} FROM delegation_approval_requests WHERE workspace_id = $1 AND id = $2`, [workspaceId, requestId])).rows[0];
  if (!row) return null;
  if (row.status !== "pending" || new Date(row.expires_at) > now) return recordFrom(row);
  const expired = await database.transaction(tx => expireRequestRow(tx, row, now));
  if (expired) return recordFrom(expired);
  return getApprovalRequest(database, workspaceId, requestId, now);
}

/** The requester's read: only its own requests, addressed to the caller's own user. */
export async function readApprovalRequest(database: Database, input: { workspaceId: string; ownerUserId: string; requestId: string;
  requesterAgentId: string }) {
  const request = await getApprovalRequest(database, input.workspaceId, input.requestId);
  if (!request || request.ownerUserId !== input.ownerUserId || request.requesterAgentId !== input.requesterAgentId) return null;
  return approvalRequestView(request);
}

export type ApprovalRequestDecision =
  | { ok: true; request: ApprovalRequestRecord }
  | { ok: false; reason: "not_found" }
  | { ok: false; reason: "refused"; code: ApprovalRequestRefusal["code"]; error: string }
  | { ok: false; reason: "decided" | "expired"; request: ApprovalRequestRecord };

/**
 * The owner approves or denies one pending request. The request row is locked
 * FOR UPDATE, so two taps decide it once. Only the request's owner may decide;
 * anyone else is answered as if it did not exist. Approving mints exactly the
 * requested actions as a Tier O approval, with the default one-hour approval
 * window from now, under the owner's membership lock, in the same transaction
 * that marks the request approved. Approving re-checks the policy in that
 * transaction on a share-locked policy row (Cloud's c2ddd8ed): turning
 * delegation off or narrowing the classes either commits first and refuses
 * this mint, or waits for it.
 */
export async function decideApprovalRequest(database: Database, input: { workspaceId: string; requestId: string; userId: string;
  authMethod: string; decision: "approve" | "deny" }, now = new Date()): Promise<ApprovalRequestDecision> {
  return database.transaction(async (tx): Promise<ApprovalRequestDecision> => {
    const row = (await tx.query<ApprovalRequestRow>(
      `SELECT ${COLUMNS} FROM delegation_approval_requests WHERE workspace_id = $1 AND id = $2 FOR UPDATE`,
      [input.workspaceId, input.requestId])).rows[0];
    if (!row || row.owner_user_id !== input.userId) return { ok: false, reason: "not_found" };
    // A request the read just before this expired answers `expired`, not `decided`.
    if (row.status !== "pending") return { ok: false, reason: row.status === "expired" ? "expired" : "decided", request: recordFrom(row) };
    if (new Date(row.expires_at) <= now) {
      const expired = await expireRequestRow(tx, row, now);
      return { ok: false, reason: "expired", request: recordFrom(expired ?? row) };
    }
    if (!await memberRole(tx, input.workspaceId, input.userId, true)) throw new ApprovalRequestMembershipGone();
    if (input.decision === "approve") {
      const refused = approvalRequestRefusal(row.actions, await loadPolicy(tx, input.workspaceId, true));
      if (refused) return { ok: false, reason: "refused", ...refused };
    }
    const approvalId = input.decision === "approve" ? await insertOwnerApproval(tx, { workspaceId: input.workspaceId,
      ownerUserId: input.userId, actions: row.actions, singleUse: row.single_use,
      expiresAt: new Date(now.getTime() + APPROVAL_DEFAULT_MS), actorUserId: input.userId, authMethod: input.authMethod,
      requestId: row.id }) : null;
    const decided = (await tx.query<ApprovalRequestRow>(
      `UPDATE delegation_approval_requests SET status = $2, approval_id = $3, decided_at = $4, decided_auth_method = $5
        WHERE id = $1 RETURNING ${COLUMNS}`,
      [row.id, approvalId ? "approved" : "denied", approvalId, now, input.authMethod],
    )).rows[0]!;
    await recordDelegationAudit(tx, {
      workspaceId: input.workspaceId, event: approvalId ? "approval_request.approved" : "approval_request.denied",
      actorUserId: input.userId, authMethod: input.authMethod, ownerUserId: input.userId, actorAgentId: row.requester_agent_id,
      approvalId, data: { request_id: row.id, actions: row.actions },
    });
    return { ok: true, request: recordFrom(decided) };
  });
}
