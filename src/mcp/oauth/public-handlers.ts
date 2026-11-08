/**
 * Unmounted Cloud 1776499a register/token/revoke handlers. Storage is injected
 * so this port can be exercised while the tenant SQL integration is pending.
 * App-level body bounds, trusted client IP/rate limiting and the module flag
 * remain the mounting adapter's responsibility.
 */
import { parseClientRegistration, type ClientRegistrationInput, type OAuthErrorBody } from "./protocol.js";

export type McpOAuthTokenResponse = {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
  id_token?: string;
};
export type McpOAuthTokenResult = { ok: true; body: McpOAuthTokenResponse }
  | { ok: false; status: number; error: OAuthErrorBody };

/** Function boundaries lifted from Cloud mcp-oauth-store.ts. No tenant choice here. */
export interface McpOAuthPublicStore {
  registerMcpOAuthClient(input: ClientRegistrationInput): Promise<{
    clientId: string; clientName: string | null; redirectUris: string[]; createdAt: Date;
  }>;
  exchangeMcpOAuthAuthorizationCode(input: {
    code: string; clientId: string; redirectUri: string | undefined; codeVerifier: string; resource: string | undefined;
  }): Promise<McpOAuthTokenResult>;
  refreshMcpOAuthToken(input: {
    refreshToken: string; clientId: string; resource: string | undefined;
  }): Promise<McpOAuthTokenResult>;
  revokeMcpOAuthToken(input: { token: string; clientId: string | undefined }): Promise<void>;
}

function oauthJson(body: unknown, status = 200): Response {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store", Pragma: "no-cache" } });
}

// Cloud lib/auth/oauth-request-body.ts: select encoding by media type, never
// guess malformed JSON as form data; preserve the source's last-value rule.
async function readOAuthRequestBody(request: Request): Promise<Record<string, unknown> | null> {
  let raw: string;
  try { raw = await request.text(); } catch { return null; }
  const mediaType = (request.headers.get("content-type") ?? "").split(";")[0]!.trim().toLowerCase();
  if (mediaType === "application/x-www-form-urlencoded") return Object.fromEntries(new URLSearchParams(raw));
  if (!raw.trim()) return {};
  try {
    const body: unknown = JSON.parse(raw);
    return body && typeof body === "object" && !Array.isArray(body) ? body as Record<string, unknown> : null;
  } catch { return null; }
}

function param(body: Record<string, unknown>, key: string): string | undefined {
  const value = body[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function createMcpOAuthPublicHandlers(deps: {
  store: McpOAuthPublicStore;
  oidcEnabled?: boolean;
  // Mounting must inject the trusted-IP limiter (Cloud: 20 registrations/hour).
  allowRegistration(request: Request): boolean | Promise<boolean>;
}) {
  async function register(request: Request): Promise<Response> {
    if (!await deps.allowRegistration(request)) return oauthJson({ error: "slow_down", error_description: "Too many registrations." }, 429);
    let body: unknown;
    try { body = await request.json(); } catch {
      return oauthJson({ error: "invalid_client_metadata", error_description: "Body must be JSON." }, 400);
    }
    const parsed = parseClientRegistration(body);
    if (!parsed.ok) return oauthJson(parsed.error, 400);
    const client = await deps.store.registerMcpOAuthClient(parsed.value);
    return oauthJson({
      client_id: client.clientId, client_id_issued_at: Math.floor(client.createdAt.getTime() / 1000),
      client_name: client.clientName ?? undefined, redirect_uris: client.redirectUris,
      grant_types: ["authorization_code", "refresh_token"], response_types: ["code"], token_endpoint_auth_method: "none",
      // Mounting enables this only once signer/JWKS are present.
      ...(deps.oidcEnabled ? { id_token_signed_response_alg: "RS256" } : {}),
    }, 201);
  }

  async function token(request: Request): Promise<Response> {
    const body = await readOAuthRequestBody(request);
    if (!body) return oauthJson({ error: "invalid_request", error_description: "Body must be form-encoded or JSON." }, 400);
    const clientId = param(body, "client_id");
    if (!clientId) return oauthJson({ error: "invalid_client", error_description: "client_id is required." }, 401);
    const grantType = param(body, "grant_type");
    let result: McpOAuthTokenResult;
    if (grantType === "authorization_code") {
      const code = param(body, "code");
      const codeVerifier = param(body, "code_verifier");
      if (!code || !codeVerifier) return oauthJson({ error: "invalid_request", error_description: "code and code_verifier are required." }, 400);
      result = await deps.store.exchangeMcpOAuthAuthorizationCode({ code, clientId, codeVerifier,
        redirectUri: param(body, "redirect_uri"), resource: param(body, "resource") });
    } else if (grantType === "refresh_token") {
      const refreshToken = param(body, "refresh_token");
      if (!refreshToken) return oauthJson({ error: "invalid_request", error_description: "refresh_token is required." }, 400);
      result = await deps.store.refreshMcpOAuthToken({ refreshToken, clientId, resource: param(body, "resource") });
    } else return oauthJson({ error: "unsupported_grant_type", error_description: "Use authorization_code or refresh_token." }, 400);
    return result.ok ? oauthJson(result.body) : oauthJson(result.error, result.status);
  }

  async function revoke(request: Request): Promise<Response> {
    const body = await readOAuthRequestBody(request);
    const token = typeof body?.token === "string" ? body.token : "";
    if (!body || !token) return oauthJson({ error: "invalid_request", error_description: "token is required." }, 400);
    const clientId = typeof body.client_id === "string" ? body.client_id : undefined;
    await deps.store.revokeMcpOAuthToken({ token, clientId });
    return new Response(null, { status: 200, headers: { "Cache-Control": "no-store" } });
  }

  return { register, token, revoke };
}
