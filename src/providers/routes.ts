import type { IncomingMessage, ServerResponse } from "node:http";
import { providerStatuses, type ProviderProbes } from "./registry.js";

const PROVIDERS_PATH = /^\/api\/v1\/workspaces\/([^/]+)\/providers$/;

/**
 * GET /api/v1/workspaces/{workspaceId}/providers (and the /cloud alias, via
 * the caller's normalized path): the provider catalog with this build's
 * runtime state, for workspace members. Read-only.
 */
export async function handleProviderRoutes(
  request: IncomingMessage,
  response: ServerResponse,
  path: string,
  method: string,
  deps: {
    probes: ProviderProbes;
    workspaceAccess(request: IncomingMessage, workspaceId: string): Promise<unknown>;
    json(response: ServerResponse, status: number, body: unknown, noStore: boolean): void;
  },
): Promise<boolean> {
  const match = PROVIDERS_PATH.exec(path);
  if (!match) return false;
  await deps.workspaceAccess(request, decodeURIComponent(match[1]!));
  if (method !== "GET") {
    response.setHeader("allow", "GET");
    deps.json(response, 405, { error: "method_not_allowed", message: "Method not allowed" }, true);
    return true;
  }
  deps.json(response, 200, { providers: await providerStatuses(deps.probes) }, true);
  return true;
}
