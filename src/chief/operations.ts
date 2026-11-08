import type { IncomingMessage, ServerResponse } from "node:http";
import { z } from "zod";
import { ChiefError, type ChiefRegistry, type WorkspaceContext } from "./registry.js";

type ProjectContext = WorkspaceContext & { projectId: string };

const identifier = z.string().min(1).max(500);
const evidencePageSchema = z.object({
  cursor: z.string().min(1).max(2000),
  evidence: z
    .array(
      z.looseObject({
        organizationId: identifier,
        workspaceId: identifier,
        projectId: identifier,
      }),
    )
    .max(100),
});
const verificationSchema = z.strictObject({
  taskId: identifier,
  assignmentDigest: z.string().regex(/^[a-f0-9]{64}$/),
  sequence: z.number().int().positive(),
  ok: z.boolean(),
  checks: z.array(z.string().min(1).max(500)).max(100),
});

/**
 * Supplies evidence and independent verification. Control has no repository or
 * CI state, and does not know the immutable assignments, so without an authority
 * both routes refuse. Implementations own project authorization, redaction and
 * checking the exact revision.
 */
export interface ChiefAuthority {
  evidence(context: ProjectContext, page: { limit: number; cursor?: string }): Promise<unknown>;
  verification(context: ProjectContext, taskId: string, sequence: number): Promise<unknown>;
}

export type ChiefOperations = { registry: ChiefRegistry; authority?: ChiefAuthority };

type Deps = {
  operations?: ChiefOperations;
  operatorAuthorized(request: IncomingMessage): boolean;
  bearer(request: IncomingMessage): string | null;
  requestObject(request: IncomingMessage): Promise<Record<string, unknown>>;
  json(response: ServerResponse, status: number, body: unknown, noStore: boolean): void;
};

function unavailable(): ChiefError {
  return new ChiefError(503, "chief_authority_unavailable", "Chief authority is unavailable.");
}

async function respond(
  response: ServerResponse,
  json: Deps["json"],
  run: () => Promise<{ status: number; body: unknown }>,
): Promise<void> {
  try {
    const result = await run();
    json(response, result.status, result.body, true);
  } catch (error) {
    if (error instanceof ChiefError) {
      json(response, error.status, { error: error.code, message: error.message, ...error.details }, true);
      return;
    }
    // Never serialize authority or provider diagnostics.
    json(response, 503, { error: "chief_unavailable", message: "Chief service is temporarily unavailable." }, true);
  }
}

async function operatorRoute(
  request: IncomingMessage,
  response: ServerResponse,
  path: string,
  deps: Deps,
  registry: ChiefRegistry,
): Promise<boolean> {
  const slots = path === "/api/v1/operator/chief-slots";
  const binding = /^\/api\/v1\/operator\/chief-slots\/([^/]+)\/binding$/.exec(path);
  const chief = /^\/api\/v1\/operator\/chiefs\/([^/]+)\/(ready|service-credential|identities)$/.exec(path);
  if (!slots && !binding && !chief) return false;
  if (!deps.bearer(request)) {
    deps.json(response, 401, { error: "unauthorized", message: "Authentication required" }, true);
    return true;
  }
  if (!deps.operatorAuthorized(request)) {
    deps.json(response, 403, { error: "forbidden", message: "Operator access required" }, true);
    return true;
  }
  const method = request.method ?? "GET";
  if ((binding ? method !== "GET" : method !== "POST")) {
    deps.json(response, 405, { error: "method_not_allowed" }, true);
    return true;
  }
  await respond(response, deps.json, async () => {
    if (slots) {
      const result = await registry.registerSlot(await deps.requestObject(request));
      return { status: result.created ? 201 : 200, body: result };
    }
    if (binding) return { status: 200, body: await registry.slotBinding(decodeURIComponent(binding[1]!)) };
    const id = decodeURIComponent(chief![1]!);
    if (chief![2] === "ready") {
      return { status: 200, body: await registry.markReady(id, await deps.requestObject(request)) };
    }
    if (chief![2] === "identities") {
      return { status: 200, body: await registry.bindIdentities(id, await deps.requestObject(request)) };
    }
    return { status: 201, body: await registry.issueServiceCredential(id) };
  });
  return true;
}

async function serviceRoute(
  request: IncomingMessage,
  response: ServerResponse,
  path: string,
  url: URL,
  deps: Deps,
  operations: ChiefOperations,
): Promise<boolean> {
  const match = /^\/chief\/v1\/projects\/([^/]+)\/(?:(evidence)|tasks\/([^/]+)\/verification)$/.exec(path);
  if (!match) return false;
  if ((request.method ?? "GET") !== "GET") {
    deps.json(response, 405, { error: "method_not_allowed" }, true);
    return true;
  }
  const token = deps.bearer(request);
  if (!token) {
    deps.json(response, 401, { error: "unauthorized", message: "Authentication required" }, true);
    return true;
  }
  await respond(response, deps.json, async () => {
    const projectId = decodeURIComponent(match[1]!);
    const context = await operations.registry.authenticateService(token, projectId);
    // Unknown, expired and other-chief credentials are indistinguishable.
    if (!context) throw new ChiefError(401, "unauthorized", "Invalid credential for this project.");
    if (match[2]) return { status: 200, body: await readEvidence(context, url, operations.authority) };
    return {
      status: 200,
      body: await readVerification(context, decodeURIComponent(match[3]!), url, operations.authority),
    };
  });
  return true;
}

async function readEvidence(context: ProjectContext, url: URL, authority: ChiefAuthority | undefined) {
  const rawLimit = url.searchParams.get("limit") ?? "100";
  const limit = /^[0-9]{1,3}$/.test(rawLimit) ? Number(rawLimit) : 0;
  const cursor = url.searchParams.get("cursor") ?? undefined;
  if (limit < 1 || limit > 100 || (cursor !== undefined && (!cursor || cursor.length > 2000))) {
    throw new ChiefError(400, "invalid_request", "limit must be 1-100 and cursor at most 2000 characters.");
  }
  if (!authority) throw unavailable();
  const page = evidencePageSchema.safeParse(
    await authority.evidence(context, { limit, ...(cursor ? { cursor } : {}) }),
  );
  if (!page.success || page.data.evidence.length > limit) throw unavailable();
  const foreign = page.data.evidence.some(
    (item) =>
      item.organizationId !== context.organizationId ||
      item.workspaceId !== context.workspaceId ||
      item.projectId !== context.projectId,
  );
  if (foreign) throw unavailable();
  return page.data;
}

async function readVerification(
  context: ProjectContext,
  taskId: string,
  url: URL,
  authority: ChiefAuthority | undefined,
) {
  const rawSequence = url.searchParams.get("sequence") ?? "";
  const sequence = /^[1-9][0-9]{0,14}$/.test(rawSequence) ? Number(rawSequence) : 0;
  if (!sequence || !identifier.safeParse(taskId).success) {
    throw new ChiefError(400, "invalid_request", "sequence must be a positive integer.");
  }
  if (!authority) throw unavailable();
  const result = verificationSchema.safeParse(await authority.verification(context, taskId, sequence));
  if (
    !result.success ||
    result.data.taskId !== taskId ||
    result.data.sequence !== sequence ||
    (result.data.ok && result.data.checks.length === 0)
  ) {
    throw unavailable();
  }
  return result.data;
}

/** Returns false for any other path, and for every path when chiefs are not enabled. */
export async function handleChiefOperations(
  request: IncomingMessage,
  response: ServerResponse,
  path: string,
  url: URL,
  deps: Deps,
): Promise<boolean> {
  if (!deps.operations) return false;
  return (
    (await operatorRoute(request, response, path, deps, deps.operations.registry)) ||
    (await serviceRoute(request, response, path, url, deps, deps.operations))
  );
}
