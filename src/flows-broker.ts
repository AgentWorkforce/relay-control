import type { IncomingMessage, ServerResponse } from "node:http";
import { z } from "zod";
import { CodingAgentError } from "./admin/coding-agents.js";
import type { AdminModule } from "./admin/routes.js";
import { secureEqual } from "./crypto.js";

const PREFIX = "/internal/v1/flows/credentials/";
const uuid = z.uuid();
const reference = z.string().min(1).max(512).nullable();
const issueBody = z.strictObject({ workspaceId: uuid, runId: uuid });
const readBody = z.strictObject({ ref: reference, runId: uuid });
const writeBody = z.strictObject({ ref: reference, runId: uuid, credentialId: uuid, content: z.unknown() });
const revokeBody = z.strictObject({ runId: uuid });

export type FlowsBrokerDeps = {
  secret: string | null | undefined;
  admin: Pick<AdminModule, "logins" | "runtimeEnvironment"> | undefined;
  relaycastBinding(workspaceId: string): Promise<{ relaycastWorkspaceId: string; relaycastApiKey: string } | null>;
  requireFlows(): void;
  bearer(request: IncomingMessage): string | null;
  requestObject(request: IncomingMessage): Promise<Record<string, unknown>>;
  json(response: ServerResponse, status: number, body: unknown, noStore: boolean): void;
};

/**
 * The credentials relayfile-control's Flows service cannot hold itself, served
 * to it alone. Unset secret: every route is a 404, as if it did not exist.
 */
export async function handleFlowsBroker(
  request: IncomingMessage,
  response: ServerResponse,
  method: string,
  path: string,
  deps: FlowsBrokerDeps,
): Promise<boolean> {
  if (!path.startsWith(PREFIX) || !deps.secret || !deps.admin) return false;
  const send = (status: number, body: unknown) => deps.json(response, status, body, true);
  const token = deps.bearer(request);
  if (!token || !secureEqual(token, deps.secret)) {
    send(401, { error: "unauthorized", message: "Service credential required" });
    return true;
  }
  deps.requireFlows();
  const invalid = () => send(400, { error: "invalid_request", message: "Invalid broker request" });
  const { logins, runtimeEnvironment } = deps.admin;
  const action = path.slice(PREFIX.length);
  const workspace = /^workspaces\/([^/]+)\/(relaycast|environment)$/.exec(action);
  try {
    if (workspace) {
      if (method !== "GET") return send(405, { error: "method_not_allowed" }), true;
      const id = uuid.safeParse(decodeURIComponent(workspace[1]!));
      if (!id.success) return invalid(), true;
      if (workspace[2] === "environment") {
        send(200, await runtimeEnvironment(id.data, { kind: "service", subject: "relayfile-control" }, true));
        return true;
      }
      const binding = await deps.relaycastBinding(id.data);
      if (!binding) send(404, { error: "workspace_not_found", message: "Workspace not found" });
      else send(200, binding);
      return true;
    }
    if (!["references", "read", "write-back", "revoke"].includes(action)) return false;
    if (method !== "POST") return send(405, { error: "method_not_allowed" }), true;
    const raw = await deps.requestObject(request);
    if (action === "references") {
      const body = issueBody.safeParse(raw);
      if (!body.success) return invalid(), true;
      const issued = await logins.issueRunReference(body.data.workspaceId, body.data.runId);
      if (issued) send(200, issued);
      else {
        response.writeHead(204, { "cache-control": "no-store" });
        response.end();
      }
    } else if (action === "read") {
      const body = readBody.safeParse(raw);
      if (!body.success) return invalid(), true;
      send(200, await logins.readForRun(body.data.ref, body.data.runId));
    } else if (action === "write-back") {
      const body = writeBody.safeParse(raw);
      if (!body.success) return invalid(), true;
      send(200, await logins.writeBack(body.data.ref, body.data.runId, body.data.credentialId, body.data.content));
    } else {
      const body = revokeBody.safeParse(raw);
      if (!body.success) return invalid(), true;
      await logins.revokeRun(body.data.runId);
      send(200, { revoked: true });
    }
    return true;
  } catch (error) {
    if (error instanceof CodingAgentError) {
      send(error.status, { error: error.code, message: error.message });
      return true;
    }
    throw error;
  }
}
