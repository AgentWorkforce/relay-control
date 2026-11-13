import { createHash } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { z } from "zod";
import type { SelfhostConfig } from "../config.js";
import { secureEqual } from "../crypto.js";
import type { ControlPlaneStore } from "../store.js";
import { findDesktopIdentityByAddress, findDesktopIdentityBySession, linkedDesktopIdentity, verifyDesktopIdentity } from "../messaging/desktop-identities.js";
import { ensurePersonIdentity, type MessagingDeps } from "../messaging/identity.js";
import { createRelaycastClient } from "../messaging/relaycast.js";
import type { McpContext } from "./context.js";

export const CUSTOMER_SUPPORT_NOTICE_PATH = "/internal/v1/customer-support/reply-notice";
export const SupportReplyNotice = z.object({
  version: z.literal(1), organizationId: z.string().uuid(), workspaceId: z.string().uuid(), userId: z.string().uuid(),
  desktopAddress: z.string().max(512).regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}@[A-Za-z0-9][A-Za-z0-9._-]{0,382}$/),
  conversationId: z.string().regex(/^[0-9a-f]{32}$/), revision: z.number().int().nonnegative(), replyId: z.number().int(),
}).strict();

/** Identical ownership checks to relay messaging, without creating or joining a participant. */
export async function customerSupportDesktop(context: McpContext): Promise<string | null> {
  if (context.oauth) return null;
  const { database, keyring, client, sessionId } = context.relay;
  const common = { keyring, client, userId: context.principal.userId, relaycastWorkspaceId: context.workspace.relaycastWorkspaceId };
  if (context.desktopCall.required || context.desktopCall.provider !== undefined) {
    const nativeSession = context.desktopCall.nativeSession;
    if (!nativeSession) return null;
    return (await linkedDesktopIdentity({ ...common, database, workspaceId: context.workspace.id, nativeSession,
      sourceId: context.desktopCall.nativeSourceId })).address;
  }
  if (!sessionId) return null;
  const row = await findDesktopIdentityBySession(database, context.workspace.id, common.userId,
    createHash("sha256").update(sessionId).digest("hex"));
  return row ? (await verifyDesktopIdentity({ ...common, row })).address : null;
}

export async function deliverCustomerSupportNotice(store: ControlPlaneStore, deps: MessagingDeps, raw: unknown) {
  const parsed = SupportReplyNotice.safeParse(raw);
  if (!parsed.success) return "invalid";
  const notice = parsed.data;
  const workspace = await store.workspaceForUser(notice.workspaceId, notice.userId);
  if (!workspace || workspace.organizationId !== notice.organizationId) return "not_authorized";
  const row = await findDesktopIdentityByAddress(store.database, notice.workspaceId, notice.userId, notice.desktopAddress);
  if (!row || row.relaycastWorkspaceId !== workspace.relaycastWorkspaceId) return "no_desktop";
  const client = createRelaycastClient({ internalOrigin: deps.relaycastUrl, fetchImpl: deps.fetchImpl });
  const desktop = await verifyDesktopIdentity({ keyring: deps.keyring, client, userId: notice.userId,
    relaycastWorkspaceId: workspace.relaycastWorkspaceId, row });
  const users = await store.database.query<{ email: string; name: string }>("SELECT email, name FROM users WHERE id = $1", [notice.userId]);
  if (!users.rows[0]) return "not_authorized";
  const identity = await ensurePersonIdentity(deps, { workspaceId: workspace.id, organizationId: workspace.organizationId,
    relaycastWorkspaceId: workspace.relaycastWorkspaceId, relaycastApiKey: workspace.relaycastApiKey,
    user: { userId: notice.userId, ...users.rows[0] } });
  const current = await store.workspaceForUser(notice.workspaceId, notice.userId);
  if (!current || current.organizationId !== notice.organizationId || current.relaycastWorkspaceId !== workspace.relaycastWorkspaceId) return "not_authorized";
  const id = createHash("sha256").update(JSON.stringify(["support-reply-notice-v1", notice.conversationId, notice.revision,
    notice.replyId, notice.desktopAddress])).digest("hex").slice(0, 40);
  await client.sendDirectMessage({ token: identity.token, to: desktop.name, address: desktop.address,
    text: `Agent Relay support replied on your case. Call ask_customer_support with conversation_id "${notice.conversationId}" and an empty message to read it.`,
    idempotencyKey: `support-reply-${id}` });
  return "sent";
}

export function createCustomerSupportNoticeHandler(config: SelfhostConfig, store: ControlPlaneStore, deps: MessagingDeps) {
  return async (request: IncomingMessage, response: ServerResponse, path: string, method: string): Promise<boolean> => {
    if (path !== CUSTOMER_SUPPORT_NOTICE_PATH) return false;
    const json = (status: number, body: unknown) => {
      response.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
      response.end(JSON.stringify(body));
    };
    if (!config.customerSupport) { json(404, { error: "not_found" }); return true; }
    const token = /^Bearer ([^\s]+)$/.exec(request.headers.authorization ?? "")?.[1];
    if (!token || !secureEqual(token, config.customerSupport.token)) { json(401, { error: "unauthorized" }); return true; }
    if (method !== "POST") { json(405, { error: "method_not_allowed" }); return true; }
    let bytes = 0;
    const chunks: Buffer[] = [];
    for await (const chunk of request) {
      const buffer = Buffer.from(chunk);
      bytes += buffer.length;
      if (bytes > 2048) { json(413, { error: "payload_too_large" }); return true; }
      chunks.push(buffer);
    }
    let body: unknown;
    try { body = JSON.parse(Buffer.concat(chunks).toString("utf8")); }
    catch { json(400, { error: "invalid_request" }); return true; }
    try {
      const status = await deliverCustomerSupportNotice(store, deps, body);
      json(status === "invalid" ? 400 : 200, { status });
    } catch {
      console.warn("[customer-support] notice_failed", { stage: "notify_send", status: 503 });
      json(503, { error: "unavailable" });
    }
    return true;
  };
}
