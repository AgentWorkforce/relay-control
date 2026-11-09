import type { IncomingMessage, ServerResponse } from "node:http";
import { z } from "zod";
import { secureEqual } from "./crypto.js";
import type { RelaycastClient } from "./messaging/relaycast.js";

const ROUTE = /^\/internal\/v1\/chief\/workspaces\/([^/]+)\/relay-agents$/;
const bodySchema = z.strictObject({ chiefId: z.string().regex(/^chief-[a-f0-9]{24}$/) });

export type ChiefRelayDeps = {
  secret: string | null | undefined;
  relaycast: Pick<RelaycastClient, "getAgent" | "registerHosted" | "recoverHosted" | "authenticatedAgent">;
  relaycastBinding(workspaceId: string): Promise<{ relaycastWorkspaceId: string; relaycastApiKey: string } | null>;
  requireChief(): void;
  bearer(request: IncomingMessage): string | null;
  requestObject(request: IncomingMessage): Promise<Record<string, unknown>>;
  json(response: ServerResponse, status: number, body: unknown, noStore: boolean): void;
};

/**
 * Registers a chief as a Relaycast agent for relaychief-control, which never
 * sees the workspace key. A repeat call reissues the token, so the caller must
 * keep the latest answer. Unset secret: the route is a 404, as if it did not exist.
 */
export async function handleChiefRelay(
  request: IncomingMessage,
  response: ServerResponse,
  method: string,
  path: string,
  deps: ChiefRelayDeps,
): Promise<boolean> {
  const match = ROUTE.exec(path);
  if (!match || !deps.secret) return false;
  const send = (status: number, body: unknown) => deps.json(response, status, body, true);
  const token = deps.bearer(request);
  if (!token || !secureEqual(token, deps.secret)) {
    send(401, { error: "unauthorized", message: "Service credential required" });
    return true;
  }
  deps.requireChief();
  if (method !== "POST") {
    send(405, { error: "method_not_allowed" });
    return true;
  }
  let segment = "";
  try {
    segment = decodeURIComponent(match[1]!);
  } catch {
    // Malformed percent-encoding fails the uuid check below.
  }
  const workspaceId = z.uuid().safeParse(segment);
  const body = bodySchema.safeParse(await deps.requestObject(request));
  if (!workspaceId.success || !body.success) {
    send(400, { error: "invalid_request", message: "Invalid chief registration" });
    return true;
  }
  const binding = await deps.relaycastBinding(workspaceId.data);
  if (!binding) {
    send(404, { error: "workspace_not_found", message: "Workspace not found" });
    return true;
  }
  const { chiefId } = body.data;
  const key = binding.relaycastApiKey;
  try {
    const existing = await deps.relaycast.getAgent(key, chiefId);
    // The name alone proves nothing: only an agent registered for this chief is reissued.
    if (existing && existing.metadata.chief_id !== chiefId) {
      send(409, { error: "relay_agent_conflict", message: "That agent name is taken by another agent" });
      return true;
    }
    const agent = existing
      ? await deps.relaycast.recoverHosted(key, chiefId, existing.id, `chief:${chiefId}`)
      : await deps.relaycast.registerHosted(key, chiefId, {
          source: "relaychief-control",
          created_by: "relaychief-control",
          chief_id: chiefId,
          cloud_workspace_id: workspaceId.data,
        });
    // Relay's own answer: the stored relaycast_workspace_id can be Control's UUID, and a chief refuses to run on a mismatch.
    const self = await deps.relaycast.authenticatedAgent(agent.token);
    if (self.id !== agent.id || !self.workspaceId) throw new Error("relay_identity_unresolved");
    send(200, { agentId: agent.id, agentName: agent.name, token: agent.token, relayWorkspaceId: self.workspaceId });
  } catch {
    // Relaycast diagnostics stay here.
    send(502, { error: "relaycast_unavailable", message: "Relaycast could not register the agent" });
  }
  return true;
}
