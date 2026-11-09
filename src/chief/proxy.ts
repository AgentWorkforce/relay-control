import type { Env, SelfhostConfig } from "../config.js";
import type { ChiefBackend, ChiefContext } from "./routes.js";

const REQUEST_TIMEOUT_MS = 30_000;
const ERROR_CODE = /^[a-z][a-z0-9_]{0,63}$/;

/** The workspace routes on relaychief-control mirror these routes under /api/v1. */
function chiefsPath(context: ChiefContext, id?: string): string {
  // Dot segments would be collapsed by the URL parser and reach another route.
  if (id === "." || id === "..") throw upstreamError(404, "chief_not_found");
  const base = `/api/v1/workspaces/${encodeURIComponent(context.workspaceId)}/chiefs`;
  return id === undefined ? base : `${base}/${encodeURIComponent(id)}`;
}

function upstreamError(status: number, code: string): Error {
  return Object.assign(new Error(code), { status, code });
}

/**
 * RELAYCHIEF_CONTROL_URL: internal origin of the relaychief-control add-on, or
 * undefined to leave Chief unavailable. The add-on checks each caller through
 * this service's token introspection, so the secret must be set as well.
 */
export function loadChiefControlUrl(
  env: Env,
  config: Pick<SelfhostConfig, "introspectSecret">,
): string | undefined {
  const raw = env.RELAYCHIEF_CONTROL_URL?.trim();
  if (!raw) return undefined;
  const invalid = () => new Error("RELAYCHIEF_CONTROL_URL must be an http(s) origin with no path");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw invalid();
  }
  if (
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    url.username || url.password || url.search || url.hash || url.pathname !== "/"
  ) {
    throw invalid();
  }
  if (!config.introspectSecret) {
    throw new Error("RELAYCHIEF_CONTROL_URL requires RELAYCONTROL_INTROSPECT_SECRET");
  }
  return url.origin;
}

/**
 * Chief backend that forwards to relaychief-control. The route has already
 * checked membership, role, the feature and CSRF; the caller's own token goes
 * upstream because the add-on re-checks it. Nothing here logs the token or an
 * upstream body.
 */
export function relayChiefControlBackend(options: {
  url: string;
  fetchImpl?: typeof fetch;
  warn?: (message: string, fields: Record<string, unknown>) => void;
}): ChiefBackend {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const warn = options.warn ?? ((message, fields) => console.warn(message, fields));

  async function call(
    operation: string,
    context: ChiefContext,
    path: string,
    body?: unknown,
  ): Promise<unknown> {
    if (!context.accessToken) throw new Error("chief_missing_credential");
    let response: Response;
    try {
      response = await fetchImpl(new URL(path, options.url), {
        method: body === undefined ? "GET" : "POST",
        headers: {
          authorization: `Bearer ${context.accessToken}`,
          accept: "application/json",
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        // A redirect would carry the caller's token somewhere unchecked.
        redirect: "error",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (error) {
      warn("[selfhost-api] chief backend unreachable", {
        operation,
        reason: error instanceof Error ? error.name : "unknown",
      });
      throw new Error("chief_unreachable");
    }
    if (response.ok) return response.json();
    const failure = (await response.json().catch(() => null)) as { error?: unknown } | null;
    const code = typeof failure?.error === "string" && ERROR_CODE.test(failure.error)
      ? failure.error
      : "chief_request_failed";
    if ([400, 404, 409].includes(response.status)) throw upstreamError(response.status, code);
    // A 401 here usually means this origin is missing from SELFHOST_INTROSPECT_AUDIENCES.
    warn("[selfhost-api] chief backend refused request", { operation, status: response.status, error: code });
    throw new Error("chief_upstream_failed");
  }

  return {
    repositories: (context) => call("repositories", context, `${chiefsPath(context)}/repositories`),
    list: (context) => call("list", context, chiefsPath(context)),
    get: (context, id) => call("get", context, chiefsPath(context, id)),
    create: (context, body) => call("create", context, chiefsPath(context), body),
    scan: (context, id) => call("scan", context, `${chiefsPath(context, id)}/scan`, {}),
  };
}
