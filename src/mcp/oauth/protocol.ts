import { createHash } from "node:crypto";

/**
 * Pure OAuth wire contract ported from Cloud 1776499a's lib/auth/mcp-oauth.ts.
 * No routes, tokens, database or ambient environment. Callers explicitly enable
 * only mounted resources; this module never changes the MCP tool-group plan.
 */
/** Relay tools + RelayHistory reads on the shared-sessions MCP. */
export const MCP_RELAY_SCOPE = "relay:mcp" as const;
/** MCP Events (`events/*`, `get_event`, `get_recent_events`); granted by endpoints that list it. */
export const MCP_EVENTS_SCOPE = "relay:events" as const;
/** OpenID Connect identity scope. It is opt-in and never implied by MCP access. */
export const MCP_OIDC_SCOPE = "openid" as const;
/**
 * Legacy launch scope, retained only when explicitly requested. Its presence
 * never replaces the live owner/admin role check in tool admission.
 */
export const MCP_AGENTS_SCOPE = "relay:agents" as const;
export const MCP_OAUTH_SCOPES = [MCP_RELAY_SCOPE, MCP_EVENTS_SCOPE, MCP_AGENTS_SCOPE] as const;
export type McpOAuthScope = (typeof MCP_OAUTH_SCOPES)[number];
export type McpAuthorizationScope = McpOAuthScope | typeof MCP_OIDC_SCOPE;

export type McpOAuthResourcePath = "/mcp" | "/api/v1/mcp/shared-sessions" | "/api/v1/mcp/relay-events";
type McpOAuthResource = { name: string; scopes: readonly McpOAuthScope[]; publicPath?: string };

const MCP_OAUTH_RESOURCES: Readonly<Record<McpOAuthResourcePath, McpOAuthResource>> = {
  "/mcp": { name: "Agent Relay", scopes: [MCP_RELAY_SCOPE, MCP_AGENTS_SCOPE], publicPath: "/mcp" },
  "/api/v1/mcp/shared-sessions": { name: "Agent Relay Sessions", scopes: [MCP_RELAY_SCOPE, MCP_AGENTS_SCOPE] },
  "/api/v1/mcp/relay-events": { name: "Agent Relay events", scopes: [MCP_EVENTS_SCOPE, MCP_RELAY_SCOPE, MCP_AGENTS_SCOPE] },
};
const APP_BASE_PATH = "/cloud";
const toAppPath = (path: string) => `${APP_BASE_PATH}${path}`;
const stripAppBasePath = (path: string) => path.startsWith(`${APP_BASE_PATH}/`) ? path.slice(APP_BASE_PATH.length) : path;
const MCP_RESOURCE_AGENT_NAME_PARAM = "agent_name";
const AGENT_NAME_HINT_RESOURCES = new Set(["/api/v1/mcp/relay-events"]);
const AGENT_NAME_HINT_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/u;
const ENDPOINT_PATHS = {
  authorization: "/oauth/authorize", token: "/api/oauth/token", registration: "/api/oauth/register",
  revocation: "/api/oauth/revoke", jwks: "/.well-known/jwks.json",
} as const;
export type McpOAuthEndpoint = keyof typeof ENDPOINT_PATHS;

const CODE_CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const CODE_VERIFIER_PATTERN = /^[A-Za-z0-9._~-]{43,128}$/u;
const MAX_REDIRECT_URIS = 10;
const MAX_URL_LENGTH = 2048;
const MAX_STATE_LENGTH = 1024;
const MAX_NONCE_LENGTH = 1024;
// WHATWG URL keeps IPv6 brackets in `hostname`; the bare form is accepted defensively.
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

export function isValidCodeChallenge(value: string): boolean {
  return CODE_CHALLENGE_PATTERN.test(value);
}

export function isValidCodeVerifier(value: string): boolean {
  return CODE_VERIFIER_PATTERN.test(value);
}

export function pkceS256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

/** Shared syntax/scheme gate for configured origins, redirects and audiences. */
function parseSafeOAuthUrl(raw: string): URL | null {
  if (raw.length > MAX_URL_LENGTH || raw.includes("#") || raw.trim() !== raw || /[\u0000-\u001f\u007f]/u.test(raw)) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.hash || url.username || url.password) return null;
  return url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname)) ? url : null;
}

/** Redirect URIs must be absolute https (or loopback http), without fragments or credentials. */
export function isAllowedRedirectUri(raw: string): boolean {
  return parseSafeOAuthUrl(raw) !== null;
}

/** OIDC pairwise-subject sector when no sector_identifier_uri is registered. */
export function oidcSectorIdentifierForRedirectUri(raw: string): string {
  return new URL(raw).hostname.toLowerCase();
}

export type ClientRegistrationInput = { clientName: string | null; redirectUris: string[] };

export type OAuthErrorBody = { error: string; error_description: string };

export class McpOAuthScopeError extends Error {
  readonly error = "invalid_scope";
  constructor() { super("invalid_scope: scope must include a supported resource permission."); }
}

/** Validates an RFC 7591 registration request for a public PKCE client. */
export function parseClientRegistration(body: unknown):
  | { ok: true; value: ClientRegistrationInput }
  | { ok: false; error: OAuthErrorBody } {
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { ok: false, error: { error: "invalid_client_metadata", error_description: "Body must be a JSON object." } };
  }
  const input = body as Record<string, unknown>;
  const redirectUris = input.redirect_uris;
  if (
    !Array.isArray(redirectUris) ||
    redirectUris.length === 0 ||
    redirectUris.length > MAX_REDIRECT_URIS ||
    !redirectUris.every((uri): uri is string => typeof uri === "string" && isAllowedRedirectUri(uri))
  ) {
    return {
      ok: false,
      error: {
        error: "invalid_redirect_uri",
        error_description: `redirect_uris must hold 1-${MAX_REDIRECT_URIS} absolute https (or loopback http) URIs without fragments.`,
      },
    };
  }
  if (input.token_endpoint_auth_method !== undefined && input.token_endpoint_auth_method !== "none") {
    return { ok: false, error: { error: "invalid_client_metadata", error_description: "Only public clients with token_endpoint_auth_method=none are supported." } };
  }
  if (input.sector_identifier_uri !== undefined) {
    return {
      ok: false,
      error: {
        error: "invalid_client_metadata",
        error_description: "sector_identifier_uri is not supported.",
      },
    };
  }
  // Redirects may span hosts (hosted plus loopback is a normal OAuth-only
  // connector). Pairwise OIDC subjects need one sector, so the one-host rule is
  // enforced at authorize time, only when openid is requested.
  const grantTypes = input.grant_types;
  if (
    grantTypes !== undefined &&
    (!Array.isArray(grantTypes) ||
      !grantTypes.every((type) => type === "authorization_code" || type === "refresh_token"))
  ) {
    return {
      ok: false,
      error: { error: "invalid_client_metadata", error_description: "Only authorization_code and refresh_token grants are supported." },
    };
  }
  const responseTypes = input.response_types;
  if (responseTypes !== undefined && (!Array.isArray(responseTypes) || !responseTypes.every((type) => type === "code"))) {
    return { ok: false, error: { error: "invalid_client_metadata", error_description: "Only the code response type is supported." } };
  }
  if (
    input.id_token_signed_response_alg !== undefined &&
    input.id_token_signed_response_alg !== "RS256"
  ) {
    return {
      ok: false,
      error: { error: "invalid_client_metadata", error_description: "Only RS256 ID tokens are supported." },
    };
  }
  return {
    ok: true,
    value: { clientName: sanitizeClientName(input.client_name), redirectUris: [...new Set(redirectUris)] },
  };
}

export function sanitizeClientName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const cleaned = value.replace(/[\u0000-\u001f\u007f]/gu, "").trim().slice(0, 100);
  return cleaned || null;
}

export type AuthorizationRequest = {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state: string | null;
  scopes: McpAuthorizationScope[];
  oidcNonce: string | null;
  resource: string;
  resourcePath: string;
  /** Agent name suggested by the resource URL; a consent default, never identity. */
  requestedAgentName: string | null;
};

type RegisteredClient = { clientId: string; redirectUris: string[] };

export type McpOAuthProtocolConfig = {
  /** A configured public origin, never a URL inferred from a request header. */
  publicOrigin: string;
  /** Defaults to none. Listing a resource here does not mount its route. */
  enabledResources?: readonly McpOAuthResourcePath[];
  /** Endpoints actually mounted by the caller; defaults to none. */
  mountedEndpoints?: readonly McpOAuthEndpoint[];
  /** Requires mounted authorization/token/JWKS plus configured signing support. */
  oidcEnabled?: boolean;
};

export function createMcpOAuthProtocol(config: McpOAuthProtocolConfig) {
  const url = parseSafeOAuthUrl(config.publicOrigin);
  if (!url || (url.pathname !== "/" && url.pathname !== "") ||
      /[?#]/u.test(config.publicOrigin)) {
    throw new Error("publicOrigin must be an HTTPS origin (or loopback HTTP), without path, credentials, query or fragment");
  }
  const origin = url.origin;
  const enabled = new Set(config.enabledResources ?? []);
  for (const path of enabled) {
    if (!Object.hasOwn(MCP_OAUTH_RESOURCES, path)) throw new Error("Unknown MCP OAuth resource");
  }
  const mounted = new Set(config.mountedEndpoints ?? []);
  for (const endpoint of mounted) {
    if (!Object.hasOwn(ENDPOINT_PATHS, endpoint)) throw new Error("Unknown MCP OAuth endpoint");
  }
  const authorizationAvailable = mounted.has("authorization") && mounted.has("token");
  const oidcEnabled = config.oidcEnabled === true;
  if (oidcEnabled && (!authorizationAvailable || !mounted.has("jwks"))) {
    throw new Error("oidcEnabled requires mounted authorization, token and jwks endpoints");
  }
  const mcpOAuthOrigin = () => origin;
  const mcpOAuthIssuer = () => `${origin}${APP_BASE_PATH}`;
  function mcpOAuthResourceAvailable(path: string): boolean {
    return Object.hasOwn(MCP_OAUTH_RESOURCES, path) && enabled.has(path as McpOAuthResourcePath);
  }
  function requireResource(path: string): McpOAuthResource {
    if (!mcpOAuthResourceAvailable(path)) throw new Error(`MCP OAuth resource ${path} is unavailable`);
    return MCP_OAUTH_RESOURCES[path as McpOAuthResourcePath];
  }
  function advertisedScopes(): McpOAuthScope[] {
    const scopes = new Set([...enabled].flatMap(path => [...requireResource(path).scopes]));
    return MCP_OAUTH_SCOPES.filter(scope => scopes.has(scope));
  }
  function isGrokRedirect(raw: string): boolean {
    if (!isAllowedRedirectUri(raw)) return false;
    const url = new URL(raw);
    const under = (domain: string) => url.hostname === domain || url.hostname.endsWith(`.${domain}`);
    return (under("cursor.com") && url.pathname.startsWith("/agents/")) || under("x.ai");
  }
  /** App path (no base path) for a request or URL path; `null` if not an MCP resource. */
  function mcpResourcePathFor(pathname: string): string | null {
    const path = pathname.replace(/\/+$/u, "") || "/";
    const appPath = stripAppBasePath(path);
    return mcpOAuthResourceAvailable(appPath) && path === publicResourcePath(appPath) ? appPath : null;
  }

  /** An Events reauthorization requesting every scope may continue an existing connection and its state. */
  function isEventsLaunchConsent(request: { resource: string; scopes: readonly string[] }): boolean {
    return parseMcpResource(request.resource) === "/api/v1/mcp/relay-events" &&
      [MCP_EVENTS_SCOPE, MCP_RELAY_SCOPE, MCP_AGENTS_SCOPE].every(scope => request.scopes.includes(scope));
  }

  /** Grok reauthentication also retains an explicitly selected baseline Events grant. */
  function canContinueEventsConsent(request: { resource: string; scopes: readonly string[]; redirectUri: string }): boolean {
    return isEventsLaunchConsent(request) || (
      parseMcpResource(request.resource) === "/api/v1/mcp/relay-events" &&
      request.scopes.includes(MCP_EVENTS_SCOPE) &&
      isGrokRedirect(request.redirectUri)
    );
  }

  /** Path the resource is served at publicly: its root alias, else under the base path. */
  function publicResourcePath(resourcePath: string): string {
    return requireResource(resourcePath).publicPath ?? toAppPath(resourcePath);
  }

  function mcpResourceUrl(resourcePath: string): string {
    return `${mcpOAuthOrigin()}${publicResourcePath(resourcePath)}`;
  }

  /**
   * The one query parameter a resource URL may carry: the agent name a Grok Bot
   * asks the consent screen to suggest (`relay-events?agent_name=<bot>`). It is
   * a display hint only. Grants, tokens and audience checks always use the
   * canonical resource URL without it, and the consent decision re-validates
   * whatever name the person approves.
   * Reads the agent name hint from a resource URL's query. `undefined` means no
   * query at all; `null` means the query is not exactly one valid hint.
   */
  function resourceAgentNameHint(url: URL, resourcePath: string): string | null | undefined {
    if (!url.search) return undefined;
    if (!AGENT_NAME_HINT_RESOURCES.has(resourcePath)) return null;
    const keys = [...url.searchParams.keys()];
    if (keys.length !== 1 || keys[0] !== MCP_RESOURCE_AGENT_NAME_PARAM) return null;
    const name = url.searchParams.get(MCP_RESOURCE_AGENT_NAME_PARAM) ?? "";
    return AGENT_NAME_HINT_PATTERN.test(name) ? name : null;
  }

  /**
   * Resolves an RFC 8707 `resource` parameter to its app path and optional agent
   * name hint, or null.
   */
  function parseMcpResourceRequest(
    raw: string | null | undefined,
  ): { resourcePath: string; agentNameHint: string | null } | null {
    if (!raw) return null;
    const url = parseSafeOAuthUrl(raw);
    if (!url) return null;
    if (url.origin !== mcpOAuthOrigin()) return null;
    const resourcePath = mcpResourcePathFor(url.pathname);
    // Internal aliases cannot become token audiences.
    if (!resourcePath) return null;
    const agentNameHint = resourceAgentNameHint(url, resourcePath);
    if (agentNameHint === null) return null;
    return { resourcePath, agentNameHint: agentNameHint ?? null };
  }

  /** Resolves an RFC 8707 `resource` parameter to its app path, or null. */
  function parseMcpResource(raw: string | null | undefined): string | null {
    return parseMcpResourceRequest(raw)?.resourcePath ?? null;
  }

  /**
   * A token-endpoint `resource` compared against a stored grant: drops a valid
   * agent name hint (the grant holds the canonical URL) and a trailing slash.
   * Anything else is returned as-is, so it still fails the exact comparison.
   */
  function canonicalMcpResourceParam(raw: string): string {
    const request = parseMcpResourceRequest(raw);
    return request ? mcpResourceUrl(request.resourcePath) : raw;
  }

  /** The valid agent name hint on an MCP request or metadata URL, if any. */
  function requestAgentNameHint(requestUrl: string, resourcePath: string): string | null {
    const url = parseRequestUrl(requestUrl);
    return url ? resourceAgentNameHint(url, resourcePath) ?? null : null;
  }

  /** IncomingMessage.url is usually relative; its host never supplies issuer authority. */
  function parseRequestUrl(raw: string): URL | null {
    try { return new URL(raw, origin); }
    catch { return null; }
  }

  function validAgentNameHint(resourcePath: string, value: string | null | undefined): string | null {
    return AGENT_NAME_HINT_RESOURCES.has(resourcePath) && value && AGENT_NAME_HINT_PATTERN.test(value) ? value : null;
  }

  function withAgentNameHint(url: string, agentNameHint: string | null | undefined): string {
    return agentNameHint ? `${url}?${new URLSearchParams({ [MCP_RESOURCE_AGENT_NAME_PARAM]: agentNameHint })}` : url;
  }

  function protectedResourceMetadataUrl(resourcePath: string, agentNameHint?: string | null): string {
    const publicPath = requireResource(resourcePath).publicPath;
    agentNameHint = validAgentNameHint(resourcePath, agentNameHint);
    if (publicPath) {
      return withAgentNameHint(`${mcpOAuthOrigin()}/.well-known/oauth-protected-resource${publicPath}`, agentNameHint);
    }
    return withAgentNameHint(`${mcpOAuthIssuer()}/.well-known/oauth-protected-resource${toAppPath(resourcePath)}`, agentNameHint);
  }

  /** RFC 9728 document for one MCP endpoint. */
  function protectedResourceMetadata(resourcePath: string, agentNameHint?: string | null) {
    const resource = requireResource(resourcePath);
    agentNameHint = validAgentNameHint(resourcePath, agentNameHint);
    return {
      // RFC 9728 echoes the identifier the client fetched, so a client that
      // sends this value as `resource` keeps the agent name hint.
      resource: withAgentNameHint(mcpResourceUrl(resourcePath), agentNameHint),
      authorization_servers: authorizationAvailable ? [mcpOAuthIssuer()] : [],
      scopes_supported: [...resource.scopes],
      bearer_methods_supported: ["header"],
      resource_name: resource.name,
      resource_documentation: "https://agentrelay.com/docs",
    };
  }

  /** RFC 8414 document. Also served at the OIDC discovery path for MCP clients. */
  function authorizationServerMetadata() {
    const issuer = mcpOAuthIssuer();
    return {
      issuer,
      ...(mounted.has("authorization") ? {
        authorization_endpoint: `${issuer}${ENDPOINT_PATHS.authorization}`,
        response_types_supported: ["code"], response_modes_supported: ["query"],
        code_challenge_methods_supported: ["S256"], authorization_response_iss_parameter_supported: true,
      } : {}),
      ...(mounted.has("token") ? {
        token_endpoint: `${issuer}${ENDPOINT_PATHS.token}`,
        grant_types_supported: ["authorization_code", "refresh_token"], token_endpoint_auth_methods_supported: ["none"],
      } : {}),
      ...(mounted.has("registration") ? { registration_endpoint: `${issuer}${ENDPOINT_PATHS.registration}` } : {}),
      ...(mounted.has("revocation") ? {
        revocation_endpoint: `${issuer}${ENDPOINT_PATHS.revocation}`, revocation_endpoint_auth_methods_supported: ["none"],
      } : {}),
      ...(mounted.has("jwks") ? { jwks_uri: `${issuer}${ENDPOINT_PATHS.jwks}` } : {}),
      scopes_supported: authorizationAvailable && enabled.size
        ? [...(oidcEnabled ? [MCP_OIDC_SCOPE] : []), ...advertisedScopes()] : [],
      ...(oidcEnabled ? {
        subject_types_supported: ["pairwise"], id_token_signing_alg_values_supported: ["RS256"],
        claims_supported: ["iss", "sub", "aud", "exp", "iat", "nonce", "at_hash"],
      } : {}),
      client_id_metadata_document_supported: false,
    };
  }

  function quoteHeaderValue(value: string): string {
    return `"${value.replace(/[^\x20-\x7e]|["\\]/gu, "")}"`;
  }

  /** `WWW-Authenticate` challenge for an MCP endpoint (RFC 6750 + RFC 9728). */
  function mcpOAuthChallenge(
    requestUrl: string,
    options: { error?: "invalid_token" | "insufficient_scope"; description?: string; scopes?: readonly string[] } = {},
  ): string {
    const url = parseRequestUrl(requestUrl);
    const resourcePath = url ? mcpResourcePathFor(url.pathname) : null;
    const parts = ['Bearer realm="Agent Relay"'];
    if (resourcePath) {
      const agentNameHint = requestAgentNameHint(requestUrl, resourcePath);
      parts.push(`resource_metadata=${quoteHeaderValue(protectedResourceMetadataUrl(resourcePath, agentNameHint))}`);
      // A discovery/expired-token challenge asks only for baseline access.
      // Launch consent is optional and requested by the spawn tool's step-up.
      const scopes = options.scopes ?? grantedScopesFor(resourcePath, undefined);
      parts.push(`scope=${quoteHeaderValue(scopes.join(" "))}`);
    }
    if (options.error) parts.push(`error=${quoteHeaderValue(options.error)}`);
    if (options.description) parts.push(`error_description=${quoteHeaderValue(options.description)}`);
    return parts.join(", ");
  }

  function jsonRpcAuthError(status: number, code: number, message: string, challenge: string): Response {
    return Response.json(
      { jsonrpc: "2.0", error: { code, message }, id: null },
      { status, headers: { "Cache-Control": "no-store", "WWW-Authenticate": challenge } },
    );
  }

  /** 401 for a missing/invalid/expired token. MCP clients start OAuth discovery from this. */
  function mcpOAuthUnauthorized(request: { url: string }, bearerPresent = false): Response {
    return jsonRpcAuthError(
      401,
      -32001,
      "Unauthorized",
      mcpOAuthChallenge(request.url, bearerPresent ? { error: "invalid_token" } : {}),
    );
  }

  /** 403 step-up challenge naming every scope the operation needs. */
  function mcpOAuthInsufficientScope(request: { url: string }, scopes: readonly McpAuthorizationScope[]): Response {
    return jsonRpcAuthError(
      403,
      -32003,
      "Forbidden",
      mcpOAuthChallenge(request.url, { error: "insufficient_scope", scopes }),
    );
  }

  /** Scopes granted for a request: explicit supported scopes, or baseline scopes when omitted. */
  function grantedScopesFor(resourcePath: string, requested: string | null | undefined): McpOAuthScope[] {
    const supported = requireResource(resourcePath).scopes;
    // Only omission grants the baseline. An explicit request must retain a
    // resource permission; OIDC identity alone cannot authorize MCP access.
    if (requested === undefined || requested === null) return supported.filter(scope => scope !== MCP_AGENTS_SCOPE);
    const wanted = requested.split(/\s+/u).filter(Boolean);
    const granted = supported.filter((scope) => wanted.includes(scope));
    if (granted.length === 0) throw new McpOAuthScopeError();
    return granted;
  }

  /** Resource access plus an explicitly requested OIDC identity scope. */
  function grantedAuthorizationScopes(
    resourcePath: string,
    requested: string | null | undefined,
  ): McpAuthorizationScope[] {
    const scopes: McpAuthorizationScope[] = [...grantedScopesFor(resourcePath, requested)];
    if (oidcEnabled && (requested ?? "").split(/\s+/u).includes(MCP_OIDC_SCOPE)) scopes.unshift(MCP_OIDC_SCOPE);
    return scopes;
  }

  /**
   * Validates an authorization request. Failures before the redirect URI is
   * trusted (`redirect: false`) must be shown to the user and never redirected,
   * otherwise the endpoint becomes an open redirector.
   */
  function validateAuthorizationRequest(
    params: Record<string, string | undefined>,
    client: RegisteredClient | null,
  ):
    | { ok: true; value: AuthorizationRequest }
    | { ok: false; redirect: false; error: OAuthErrorBody }
    | { ok: false; redirect: true; redirectUri: string; state: string | null; error: OAuthErrorBody } {
    if (!client || params.client_id !== client.clientId) {
      return { ok: false, redirect: false, error: { error: "invalid_client", error_description: "Unknown client_id. Reconnect the app to register it again." } };
    }
    const requestedRedirect = params.redirect_uri;
    const redirectUri = requestedRedirect ?? (client.redirectUris.length === 1 ? client.redirectUris[0] : undefined);
    if (!redirectUri || !client.redirectUris.includes(redirectUri) || !isAllowedRedirectUri(redirectUri)) {
      return { ok: false, redirect: false, error: { error: "invalid_request", error_description: "redirect_uri does not match a registered redirect URI." } };
    }
    const state = params.state ?? null;
    const fail = (error: string, description: string) => ({
      ok: false as const,
      redirect: true as const,
      redirectUri,
      state: state !== null && state.length <= MAX_STATE_LENGTH ? state : null,
      error: { error, error_description: description },
    });
    if (state !== null && state.length > MAX_STATE_LENGTH) return fail("invalid_request", "state is too long.");
    if (params.response_type !== "code") return fail("unsupported_response_type", "response_type must be code.");
    if (params.code_challenge_method !== "S256" || !params.code_challenge || !isValidCodeChallenge(params.code_challenge)) {
      return fail("invalid_request", "PKCE with code_challenge_method=S256 is required.");
    }
    const resourceRequest = parseMcpResourceRequest(params.resource);
    if (!resourceRequest) return fail("invalid_target", "resource must be an Agent Relay MCP endpoint URL.");
    const { resourcePath } = resourceRequest;
    let scopes: McpAuthorizationScope[];
    try { scopes = grantedAuthorizationScopes(resourcePath, params.scope); }
    catch (error) {
      if (error instanceof McpOAuthScopeError) return fail(error.error, error.message);
      throw error;
    }
    const oidc = scopes.includes(MCP_OIDC_SCOPE);
    if (oidc && new Set(client.redirectUris.map(oidcSectorIdentifierForRedirectUri)).size !== 1) {
      return fail("invalid_request", "openid requires a client whose registered redirect URIs use one host. Reconnect the app.");
    }
    const nonce = oidc ? params.nonce ?? null : null;
    if (nonce !== null && (nonce.length === 0 || nonce.length > MAX_NONCE_LENGTH || /[\u0000-\u001f\u007f]/u.test(nonce))) {
      return fail("invalid_request", "nonce must be 1-1024 characters without control characters.");
    }
    return {
      ok: true,
      value: {
        clientId: client.clientId,
        redirectUri,
        codeChallenge: params.code_challenge,
        state,
        scopes,
        oidcNonce: oidc ? nonce : null,
        resource: mcpResourceUrl(resourcePath),
        resourcePath,
        requestedAgentName: resourceRequest.agentNameHint,
      },
    };
  }

  /** Authorization response redirect; always carries `iss` (RFC 9207). */
  function authorizationResponseUrl(
    redirectUri: string,
    params: { code?: string; error?: string; error_description?: string; state: string | null },
  ): string {
    const url = new URL(redirectUri);
    for (const key of ["code", "error", "error_description", "error_uri", "state", "iss"]) url.searchParams.delete(key);
    for (const [key, value] of Object.entries(params)) {
      if (value !== null && value !== undefined) url.searchParams.set(key, value);
    }
    url.searchParams.set("iss", mcpOAuthIssuer());
    return url.toString();
  }

  return {
    mcpOAuthOrigin, mcpOAuthIssuer, mcpResourcePathFor, mcpResourceUrl,
    parseMcpResourceRequest, parseMcpResource, canonicalMcpResourceParam,
    requestAgentNameHint, protectedResourceMetadataUrl, protectedResourceMetadata,
    authorizationServerMetadata, mcpOAuthChallenge, mcpOAuthUnauthorized,
    mcpOAuthInsufficientScope, grantedScopesFor, grantedAuthorizationScopes,
    isEventsLaunchConsent, canContinueEventsConsent, validateAuthorizationRequest,
    authorizationResponseUrl,
  };
}
