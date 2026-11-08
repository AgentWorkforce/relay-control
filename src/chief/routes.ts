import type { IncomingMessage, ServerResponse } from "node:http";

type Context = { organizationId: string; workspaceId: string };
/** The core and provider implementations live in relay-chief. This gateway owns authorization. */
export interface ChiefBackend {
  repositories?(context: Context): unknown | Promise<unknown>;
  list(context: Context): unknown | Promise<unknown>;
  get(context: Context, id: string): unknown | Promise<unknown>;
  create(context: Context, body: unknown): unknown | Promise<unknown>;
  scan(context: Context, id: string): unknown | Promise<unknown>;
}
export async function handleChiefRoutes(
  request: IncomingMessage,
  response: ServerResponse,
  path: string,
  deps: {
    backend?: ChiefBackend;
    workspaceAccess(
      request: IncomingMessage,
      id: string,
      admin: boolean,
    ): Promise<{ workspace: { id: string; organizationId: string } }>;
    requestObject(request: IncomingMessage): Promise<Record<string, unknown>>;
    csrfAllowed(request: IncomingMessage): boolean;
    json(
      response: ServerResponse,
      status: number,
      body: unknown,
      noStore: boolean,
    ): void;
  },
): Promise<boolean> {
  const match =
    /^\/api\/v1\/workspaces\/([^/]+)\/chiefs(?:\/([^/]+))?(?:\/(scan))?$/.exec(
      path,
    );
  if (!match) return false;
  const method = request.method ?? "GET";
  const access = await deps.workspaceAccess(
    request,
    decodeURIComponent(match[1]!),
    method !== "GET",
  );
  if (method !== "GET" && !deps.csrfAllowed(request)) {
    deps.json(
      response,
      403,
      { error: "forbidden", message: "Use a same-origin JSON request." },
      true,
    );
    return true;
  }
  if (!deps.backend) {
    deps.json(
      response,
      503,
      {
        error: "chief_unavailable",
        message: "Chief setup is not enabled on this installation.",
      },
      true,
    );
    return true;
  }
  const context = {
    organizationId: access.workspace.organizationId,
    workspaceId: access.workspace.id,
  };
  const id = match[2] ? decodeURIComponent(match[2]) : undefined;
  try {
    let result: unknown;
    let status = 200;
    if (method === "GET" && id === "repositories" && !match[3]) {
      if (!deps.backend.repositories) throw new Error("github_unavailable");
      result = await deps.backend.repositories(context);
    } else if (method === "GET" && !match[3])
      result = id
        ? await deps.backend.get(context, id)
        : await deps.backend.list(context);
    else if (method === "POST" && !id) {
      result = await deps.backend.create(
        context,
        await deps.requestObject(request),
      );
      status = 202;
    } else if (method === "POST" && id && match[3] === "scan") {
      result = await deps.backend.scan(context, id);
      status = 202;
    } else {
      deps.json(response, 405, { error: "method_not_allowed" }, true);
      return true;
    }
    deps.json(response, status, result, true);
  } catch (error) {
    // The adapter's public errors carry bounded codes; never serialize provider diagnostics.
    const failure = error as { status?: number; code?: string };
    if ([400, 404, 409].includes(failure?.status ?? 0)) {
      deps.json(
        response,
        failure.status!,
        {
          error: failure.code ?? "chief_request_failed",
          message:
            failure.status === 400
              ? "Check the project settings."
              : failure.status === 404
                ? "Chief not found."
                : "This request conflicts with the current chief state.",
        },
        true,
      );
    } else
      deps.json(
        response,
        503,
        {
          error: "chief_unavailable",
          message: "Chief service is temporarily unavailable.",
        },
        true,
      );
  }
  return true;
}
