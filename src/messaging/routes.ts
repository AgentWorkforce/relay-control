import type { IncomingMessage, ServerResponse } from "node:http";
import { ApiTokenStore } from "../admin/api-tokens.js";
import { cookieRequestAllowed } from "../auth/device-approval.js";
import { secureEqual } from "../crypto.js";
import type { Principal } from "../store.js";
import {
  claimSend,
  ensurePersonIdentity,
  findPersonIdentity,
  finishSend,
  isRefusedToken,
  recoverPersonIdentity,
  sweepRevocations,
  waitForSend,
  type MessagingDeps,
  type PersonIdentity,
  type SendClaim,
} from "./identity.js";
import { MessagingHttpError, SEND_UNCERTAIN_MESSAGE, SendAbandoned } from "./http.js";
import { createRelaycastClient, RelaycastCallError } from "./relaycast.js";

export { MessagingHttpError } from "./http.js";

const CLIENT_MESSAGE_ID = /^[A-Za-z0-9_-]{8,64}$/;
const PEER_NAME = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MESSAGE_CURSOR = /^[A-Za-z0-9_-]{1,64}$/;
const MAX_MESSAGE_CHARS = 16_000;

type WorkspaceAccess = {
  principal: Principal;
  workspace: {
    id: string;
    organizationId: string;
    name: string;
    relaycastWorkspaceId: string;
    relaycastApiKey: string;
    role: Principal["role"];
  };
};

type JsonWriter = (response: ServerResponse, status: number, body: unknown, noStore?: boolean) => void;

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch (error) {
    if (error instanceof URIError) {
      throw new MessagingHttpError(400, "invalid_recipient", "Malformed path");
    }
    throw error;
  }
}

function peerName(value: string): string {
  const name = value.trim().replace(/^@/, "");
  if (!PEER_NAME.test(name)) {
    throw new MessagingHttpError(400, "invalid_recipient", "Recipient name is not a relay handle");
  }
  return name;
}

function duplicateBody(identity: PersonIdentity, claim: SendClaim, clientMessageId: string) {
  return {
    you: identity.name,
    duplicate: true,
    message: {
      id: claim.relay_message_id,
      clientMessageId,
      text: claim.body,
      mine: true,
    },
  };
}

export function createMessagingHandler(input: MessagingDeps & {
  relaycastPublicUrl: string;
  internalServiceToken: string | null;
  browserOrigins: readonly string[];
}) {
  const relaycast = createRelaycastClient({
    internalOrigin: input.relaycastUrl,
    fetchImpl: input.fetchImpl,
  });
  const apiTokens = new ApiTokenStore(input.database);
  const publicOrigin = input.relaycastPublicUrl.replace(/\/+$/, "");
  const deps: MessagingDeps = input;

  function accessInput(access: WorkspaceAccess) {
    return {
      workspaceId: access.workspace.id,
      organizationId: access.workspace.organizationId,
      relaycastWorkspaceId: access.workspace.relaycastWorkspaceId,
      relaycastApiKey: access.workspace.relaycastApiKey,
      user: access.principal,
    };
  }

  async function rejectServiceCredential(
    request: IncomingMessage,
    bearer: (request: IncomingMessage) => string | null,
    response: ServerResponse,
    json: JsonWriter,
  ): Promise<boolean> {
    const token = bearer(request);
    if (!token) return false;
    if (input.internalServiceToken && secureEqual(token, input.internalServiceToken)) {
      json(response, 403, { error: "forbidden", message: "Service credentials cannot mint a person credential" }, true);
      return true;
    }
    if (token.startsWith("sh_wk_")) {
      const principal = await apiTokens.authenticate(token);
      if (principal) {
        json(response, 403, { error: "forbidden", message: "Agent, CI, and service tokens cannot mint a person credential" }, true);
        return true;
      }
    }
    return false;
  }

  async function readHistory(identity: PersonIdentity, peer: string, before: string | undefined) {
    const conversation = (await relaycast.listConversations(identity.token)).find((candidate) =>
      candidate.participants.length === 2
      && candidate.participants.includes(identity.name)
      && candidate.participants.includes(peer));
    const page = conversation
      ? await relaycast.listMessages(identity.token, conversation.id, { before })
      : { messages: [], hasEarlier: false };
    if (!before) {
      try {
        const deliveries = await relaycast.listDeliveries(identity.token);
        await Promise.all(deliveries
          .filter((delivery) => delivery.sender === peer)
          .map((delivery) => relaycast.acknowledgeDelivery(identity.token, delivery.id).catch(() => undefined)));
      } catch {
        // The next read acknowledges anything still queued.
      }
    }
    return {
      you: identity.name,
      peer,
      messages: page.messages.map((message) => ({
        id: message.id,
        text: message.text,
        mine: message.sender === identity.name,
        sender: message.sender,
        createdAt: message.createdAt,
      })),
      earlier: page.hasEarlier ? page.messages[0]?.id ?? null : null,
    };
  }

  async function send(
    access: WorkspaceAccess,
    identity: PersonIdentity,
    peer: string,
    text: string,
    clientMessageId: string,
  ) {
    const claimInput = {
      workspaceId: access.workspace.id,
      userId: access.principal.userId,
      relaycastWorkspaceId: access.workspace.relaycastWorkspaceId,
      peer,
      clientMessageId,
      text,
    };
    let decision = await claimSend(deps, claimInput);
    if (decision.kind === "wait") {
      const settled = await waitForSend(deps, claimInput);
      if (settled?.status === "accepted") return { status: 200, body: duplicateBody(identity, settled, clientMessageId) };
      if (settled?.status === "rejected") {
        throw new MessagingHttpError(404, settled.terminal_code ?? "recipient_not_found", "No one by that name is on the relay.");
      }
      if (settled?.status === "uncertain") {
        throw new MessagingHttpError(502, "send_uncertain", SEND_UNCERTAIN_MESSAGE);
      }
      decision = await claimSend(deps, claimInput);
    }
    if (decision.kind === "duplicate") return { status: 200, body: duplicateBody(identity, decision.claim, clientMessageId) };
    if (decision.kind === "rejected") {
      throw new MessagingHttpError(404, decision.claim.terminal_code ?? "recipient_not_found", "No one by that name is on the relay.");
    }
    if (decision.kind === "uncertain" || decision.kind === "wait") {
      throw new MessagingHttpError(502, "send_uncertain", SEND_UNCERTAIN_MESSAGE);
    }
    try {
      if (input.beforeDispatch) await input.beforeDispatch();
      const sent = await relaycast.sendDirectMessage({
        token: identity.token,
        to: peer,
        text,
        idempotencyKey: `selfhost-dm:${access.principal.userId}:${clientMessageId}`,
      });
      if (input.afterUpstream) await input.afterUpstream();
      await finishSend(deps, {
        ...claimInput,
        status: "accepted",
        relayMessageId: sent.message.id,
        conversationId: sent.conversationId,
      });
      return {
        status: 201,
        body: {
          you: identity.name,
          message: { id: sent.message.id, clientMessageId, text, mine: true },
        },
      };
    } catch (error) {
      if (error instanceof SendAbandoned) {
        throw new MessagingHttpError(502, "send_uncertain", SEND_UNCERTAIN_MESSAGE);
      }
      if (error instanceof MessagingHttpError) throw error;
      if (!(error instanceof RelaycastCallError)) {
        await finishSend(deps, { ...claimInput, status: "uncertain" });
        throw new MessagingHttpError(502, "send_uncertain", SEND_UNCERTAIN_MESSAGE);
      }
      if (error.status === 404 || error.code === "agent_not_found" || error.code === "not_found") {
        await finishSend(deps, { ...claimInput, status: "rejected", terminalCode: "recipient_not_found" });
        throw new MessagingHttpError(404, "recipient_not_found", "No one by that name is on the relay.");
      }
      if (isRefusedToken(error)) {
        await finishSend(deps, { ...claimInput, status: "retryable" });
        throw error;
      }
      if (error.outcomeUnknown || error.code === "idempotency_key_reused") {
        await finishSend(deps, { ...claimInput, status: "uncertain" });
        throw new MessagingHttpError(502, "send_uncertain", SEND_UNCERTAIN_MESSAGE);
      }
      await finishSend(deps, { ...claimInput, status: "retryable" });
      throw new MessagingHttpError(502, "upstream_unavailable", "The relay is not reachable right now. Try again shortly.");
    }
  }

  return async function handleMessaging(
    request: IncomingMessage,
    response: ServerResponse,
    path: string,
    method: string,
    helpers: {
      workspaceAccess: (request: IncomingMessage, workspaceId: string) => Promise<WorkspaceAccess>;
      bearer: (request: IncomingMessage) => string | null;
      json: JsonWriter;
    },
  ): Promise<boolean> {
    const people = /^\/api\/v1\/workspaces\/([^/]+)\/messaging\/people$/.exec(path);
    const credential = /^\/api\/v1\/workspaces\/([^/]+)\/messaging\/identity\/credential$/.exec(path);
    const conversation = /^\/api\/v1\/workspaces\/([^/]+)\/messaging\/conversations\/([^/]+)$/.exec(path);
    if (!people && !credential && !conversation) return false;

    if (await rejectServiceCredential(request, helpers.bearer, response, helpers.json)) return true;
    const workspaceId = safeDecode((people ?? credential ?? conversation)![1]!);
    const access = await helpers.workspaceAccess(request, workspaceId);
    if (!access.principal.scopes.includes("cli:auth")) {
      throw new MessagingHttpError(403, "forbidden", "Person credential requires a browser session or cli:auth");
    }
    const bearerToken = helpers.bearer(request);
    if (method === "POST" && !bearerToken && !cookieRequestAllowed(request, input.browserOrigins)) {
      throw new MessagingHttpError(403, "csrf_rejected", "Cross-origin messaging write refused");
    }
    await sweepRevocations(deps, access.workspace.organizationId);
    const person = accessInput(access);

    if (people && method === "GET") {
      const rows = await input.database.query<{
        user_id: string;
        display_name: string;
        email: string;
        agent_name: string;
      }>(
        `SELECT u.id AS user_id, u.name AS display_name, u.email, i.agent_name
           FROM person_identities i
           JOIN users u ON u.id = i.user_id
           JOIN organization_memberships m
             ON m.organization_id = $2 AND m.user_id = i.user_id
          WHERE i.workspace_id = $1 AND i.relaycast_workspace_id = $3
          ORDER BY u.name`,
        [access.workspace.id, access.workspace.organizationId, access.workspace.relaycastWorkspaceId],
      );
      helpers.json(response, 200, {
        people: rows.rows.map((row) => ({
          userId: row.user_id,
          displayName: row.display_name,
          email: row.email,
          handle: `@${row.agent_name}`,
          name: row.agent_name,
          photo: null,
        })),
      }, true);
      return true;
    }

    if (credential && method === "POST") {
      const identity = await ensurePersonIdentity(deps, person);
      helpers.json(response, 200, {
        identity: {
          name: identity.name,
          agentId: identity.agentId,
          token: identity.token,
          relaycastUrl: publicOrigin,
        },
      }, true);
      return true;
    }

    if (!conversation) {
      helpers.json(response, 405, { error: "method_not_allowed", message: "Method not allowed" }, true);
      return true;
    }
    if (method !== "GET" && method !== "POST") {
      helpers.json(response, 405, { error: "method_not_allowed", message: "Method not allowed" }, true);
      return true;
    }
    const peer = peerName(safeDecode(conversation[2]!));
    if (method === "GET") {
      const before = new URL(request.url ?? "/", "http://127.0.0.1").searchParams.get("before") ?? undefined;
      if (before !== undefined && !MESSAGE_CURSOR.test(before)) {
        throw new MessagingHttpError(400, "invalid_message", "That is not a valid message cursor.");
      }
      const identity = await findPersonIdentity(deps, person);
      if (!identity) {
        helpers.json(response, 200, { you: null, peer, messages: [], earlier: null }, true);
        return true;
      }
      try {
        helpers.json(response, 200, await readHistory(identity, peer, before), true);
      } catch (error) {
        if (!isRefusedToken(error)) throw translateSend(error);
        try {
          const recovered = await recoverPersonIdentity(deps, person, identity);
          helpers.json(response, 200, await readHistory(recovered, peer, before), true);
        } catch (retryError) {
          throw translateSend(retryError);
        }
      }
      return true;
    }

    const raw = await requestBody(request);
    let payload: Record<string, unknown>;
    try {
      const parsed: unknown = raw ? JSON.parse(raw) : {};
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid");
      payload = parsed as Record<string, unknown>;
    } catch {
      throw new MessagingHttpError(400, "invalid_message", "Invalid request body");
    }
    const text = typeof payload.text === "string" ? payload.text.trim() : "";
    const clientMessageId = payload.clientMessageId;
    if (!text || text.length > MAX_MESSAGE_CHARS || typeof clientMessageId !== "string" || !CLIENT_MESSAGE_ID.test(clientMessageId)) {
      throw new MessagingHttpError(400, "invalid_message", `Messages must be 1–${MAX_MESSAGE_CHARS} characters and clientMessageId must be 8–64 letters, digits, _ or -.`);
    }
    try {
      const result = await sendOnce(person, peer, text, clientMessageId);
      helpers.json(response, result.status, result.body, true);
    } catch (error) {
      if (!isRefusedToken(error)) throw error;
      try {
        await recoverPersonIdentity(deps, person, await ensurePersonIdentity(deps, person));
        const result = await sendOnce(person, peer, text, clientMessageId);
        helpers.json(response, result.status, result.body, true);
      } catch (retryError) {
        if (isRefusedToken(retryError)) {
          throw new MessagingHttpError(502, "upstream_unavailable", "The relay is not reachable right now. Try again shortly.");
        }
        throw retryError;
      }
    }
    return true;

    async function sendOnce(
      current: ReturnType<typeof accessInput>,
      recipient: string,
      message: string,
      clientId: string,
    ) {
      const identity = await ensurePersonIdentity(deps, current);
      if (identity.name === recipient) {
        throw new MessagingHttpError(400, "invalid_recipient", "You can't message yourself");
      }
      return send(access, identity, recipient, message, clientId);
    }
  };
}

function translateSend(error: unknown): Error {
  if (error instanceof MessagingHttpError) return error;
  if (error instanceof RelaycastCallError) {
    if (error.status === 404 || error.code === "agent_not_found" || error.code === "not_found") {
      return new MessagingHttpError(404, "recipient_not_found", "No one by that name is on the relay.");
    }
    if (error.outcomeUnknown || error.code === "idempotency_key_reused") {
      return new MessagingHttpError(502, "send_uncertain", SEND_UNCERTAIN_MESSAGE);
    }
    return new MessagingHttpError(502, "upstream_unavailable", "The relay is not reachable right now. Try again shortly.");
  }
  return new MessagingHttpError(502, "upstream_unavailable", "The relay is not reachable right now. Try again shortly.");
}

async function requestBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > 1024 * 1024) throw new MessagingHttpError(413, "payload_too_large", "Body exceeds 1 MiB");
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}
