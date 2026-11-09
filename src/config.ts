import { loadMcpOAuthConfig, type McpOAuthConfig } from "./mcp/oauth/config.js";
import { readFileSync } from "node:fs";
import { createHash, createPrivateKey, type KeyObject } from "node:crypto";
import { isIP } from "node:net";
import type { EncryptionKey, EncryptionKeyring } from "./crypto.js";
import { trustedProxyHops } from "./auth/device-approval.js";
import {
  isAcquisitionIdentifier,
  rawEd25519PublicKey,
  strictRawPublicKey,
} from "./acquisition/assertion.js";

export type SelfhostConfig = {
  databaseUrl: string;
  publicBaseUrl: string;
  relaycastUrl: string;
  relaycastPublicUrl: string;
  /**
   * Transitional: when set (with relayauthApiKey), RelayHistory sessions are
   * issued from a RelayAuth assertion. When null, relaycontrol forwards the
   * caller's own access token and RelayHistory introspects it.
   */
  relayauthUrl: string | null;
  relayhistoryUrl: string;
  /**
   * RELAYHISTORY_BACKEND=native: no RelayAuth and no standalone RelayHistory.
   * relayhistoryUrl and relayhistoryPublicUrl are the read API's (see
   * loadConfig); uploads go to the pipeline ingest edge at the same public
   * origin. Absent means the legacy RelayHistory exchange.
   */
  relayhistoryBackend?: "native" | null;
  /** Optional GET-only pipeline reader for unsearched session lists and turns. */
  relayhistoryReadApiUrl?: string | null;
  /** RELAYHISTORY_READ_API_EVENTS: opt in to native session-event reads. Default off. */
  relayhistoryReadApiEvents?: boolean;
  /** RELAYFILE_CONTROL_BROKER_SECRET: Flows credential broker routes. Unset: they 404. */
  relayfileControlBrokerSecret?: string | null;
  /** Independent read service; owns issuance, rotation and verification of its tokens. */
  sessionReadApi?: { url: string; publicUrl: string; secret: string } | null;
  /** Session pipeline per-session erase; null keeps the hard-delete routes at 501. */
  sessionErasureApi?: { url: string; secret: string } | null;
  /** SESSION_READ_API_MCP_READS: MCP session reads use the read API. Default off. */
  sessionReadMcpReads?: boolean;
  /** SESSION_SEARCH_AGENT_TOKENS: read `@name` tokens in search text as agent filters. Default off. */
  sessionSearchAgentTokens?: boolean;
  relayhistoryPublicUrl: string;
  relayauthApiKey: string | null;
  bootstrapToken: string;
  encryptionKeyring: EncryptionKeyring;
  /** admin lane: service bearer for /internal/v1 runtime reads; null disables them. */
  internalServiceToken: string | null;
  /** admin lane: OAuth redirect URI registered with each provider's OAuth app. */
  oauthRedirectUrl: string;
  /** admin lane: where the OAuth callback page links back to. */
  dashboardUrl: string;
  /**
   * Operator-configured integration OAuth apps (installation-wide), from
   * SELFHOST_OAUTH_<PROVIDER>_CLIENT_ID / _CLIENT_SECRET[_FILE] / _SCOPES.
   * They take precedence over per-workspace apps stored through the API.
   */
  operatorOAuthApps?: Record<string, OperatorOAuthApp>;
  /**
   * Bearer secret for POST /internal/v1/auth/introspect (RelayHistory and
   * relayfile pods only). Unset or null turns the endpoint off (404).
   */
  introspectSecret?: string | null;
  /**
   * Origins accepted as the introspection `aud`, from
   * SELFHOST_INTROSPECT_AUDIENCES. Defaults to [relayhistoryPublicUrl].
   */
  introspectAudiences?: string[];
  /**
   * Dormant cloud-class acquisition assertion issuer
   * (SELFHOST_ACQUISITION_ISSUER_ENABLED). Unset or null: off, and every
   * /api/v1/acquisition/* route answers 404.
   */
  acquisitionIssuer?: AcquisitionIssuerConfig | null;
  /** Factory sessions (src/factory). Unset or enabled=false: routes 404, worker off. */
  factory?: FactoryConfig;
  /** Hosted MCP module settings; omitted is off. Loading does not mount routes. */
  mcpOAuth?: McpOAuthConfig;
  /**
   * Desktop feed (docs/desktop-feed.md). Null or absent turns the feature off
   * and every feed route answers 404 like any unknown path.
   */
  desktopFeed?: DesktopFeedConfig | null;
  port: number;
  host: string;
};

export type DesktopFeedSignerConfig =
  | { kind: "memory"; label: string }
  | { kind: "awskms"; region: string; label: string; keyAliases: Record<string, string> };

export type DesktopFeedStorageConfig =
  | { kind: "memory" }
  | { kind: "s3"; bucket: string; region: string; prefix: string };

export type DesktopFeedConfig = {
  signer: DesktopFeedSignerConfig;
  storage: DesktopFeedStorageConfig;
  /** sha256 hex of each env-configured publisher token, by profile id. */
  publisherTokenHashes?: Record<string, string[]>;
};

export type Env = Record<string, string | undefined>;

export type AcquisitionPublishedKey = {
  issuerKeyId: string;
  issuerClass: "cloud";
  /** Base64 of the raw 32-byte Ed25519 public key (ACQUISITION_PINNED_KEYS shape). */
  publicKeyBase64: string;
};

export type AcquisitionIssuerConfig = {
  /** SELFHOST_ACQUISITION_ORIGIN as a normalized origin (scheme, lowercase host, port). */
  origin: string;
  /** SELFHOST_ACQUISITION_ISSUER_KEY_ID: stamped into every issued payload. */
  keyId: string;
  /** Ed25519 private key; never logged, never published. */
  privateKey: KeyObject;
  /** Active key first, then SELFHOST_ACQUISITION_ISSUER_PREVIOUS_PUBLIC_KEYS (never used to sign). */
  publishedKeys: AcquisitionPublishedKey[];
};

export type FactoryConfig = {
  enabled: boolean;
  /** Factory API origin; https only, redirects are never followed. */
  apiUrl: string;
  /** Dormant history-intent loop cadence. */
  historyIntervalMs: number;
};

export type OperatorOAuthApp = { clientId: string; clientSecret: string; scopes: string[] | null };

/**
 * SELFHOST_OAUTH_GITHUB_CLIENT_ID + SELFHOST_OAUTH_GITHUB_CLIENT_SECRET (or
 * _CLIENT_SECRET_FILE, a mounted Secret) configure the GitHub app; provider ids
 * are upper-cased with "-" as "_" (google-mail -> GOOGLE_MAIL). Optional
 * _SCOPES overrides the default scopes (space or comma separated).
 */
export function loadOperatorOAuthApps(env: Env): Record<string, OperatorOAuthApp> {
  const apps: Record<string, OperatorOAuthApp> = {};
  for (const key of Object.keys(env)) {
    const found = /^SELFHOST_OAUTH_([A-Z0-9_]+)_CLIENT_ID$/.exec(key);
    if (!found) continue;
    const prefix = `SELFHOST_OAUTH_${found[1]}`;
    const clientId = env[key]?.trim();
    if (!clientId) continue;
    const clientSecret = readSecret(env, `${prefix}_CLIENT_SECRET`);
    if (!clientSecret) throw new Error(`${prefix}_CLIENT_SECRET (or _FILE) is required with ${key}`);
    const scopes = env[`${prefix}_SCOPES`]?.trim();
    apps[found[1]!.toLowerCase().replaceAll("_", "-")] = {
      clientId,
      clientSecret,
      scopes: scopes ? scopes.split(/[\s,]+/).filter(Boolean) : null,
    };
  }
  return apps;
}
export const SELFHOST_API_VERSION = "0.1.0";

export function readSecret(env: Env, name: string): string | undefined {
  const direct = env[name]?.trim();
  const file = env[`${name}_FILE`]?.trim();
  if (direct && file) {
    throw new Error(`${name} and ${name}_FILE are mutually exclusive`);
  }
  if (direct) return direct;
  if (!file) return undefined;
  const value = readFileSync(file, "utf8").trim();
  return value || undefined;
}

function required(env: Env, name: string, secret = false): string {
  const value = secret ? readSecret(env, name) : env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function serviceUrl(env: Env, name: string): string {
  const value = required(env, name);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute URL`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`${name} must use http or https`);
  }
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (url.pathname !== "" && url.pathname !== "/")
  ) {
    throw new Error(`${name} must be an origin without credentials, query, or fragment`);
  }
  return value.replace(/\/+$/, "");
}

function publicServiceUrl(env: Env, name: string): string {
  const value = required(env, name);
  const maxOriginLength = 253 + "https://".length + ":65535".length;
  if (value.length > maxOriginLength) {
    throw new Error(`${name} must use a public multi-label DNS hostname`);
  }
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute URL`);
  }
  if (url.protocol !== "https:") {
    throw new Error(`${name} must use https`);
  }
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (url.pathname !== "" && url.pathname !== "/") ||
    // URL normalizes a trailing bare `?` or `#` to an empty search/hash.
    /[?#]/.test(value)
  ) {
    throw new Error(`${name} must be an origin without credentials, path, query, or fragment`);
  }
  const hostname = url.hostname.toLowerCase();
  const unbracketedHostname = hostname.replace(/^\[|\]$/g, "");
  const labels = hostname.split(".");
  const specialSuffixes = [
    "localhost",
    "local",
    "internal",
    "lan",
    "invalid",
    "test",
    "example",
    "home.arpa",
    "onion",
  ];
  const reservedExampleHosts = ["example.com", "example.net", "example.org"];
  const special = specialSuffixes.some(
    (suffix) => hostname === suffix || hostname.endsWith(`.${suffix}`),
  ) || reservedExampleHosts.some(
    (reserved) => hostname === reserved || hostname.endsWith(`.${reserved}`),
  );
  if (
    isIP(unbracketedHostname) !== 0 ||
    labels.length < 2 ||
    labels.some((label) =>
      !label ||
      label.length > 63 ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)
    ) ||
    special
  ) {
    throw new Error(`${name} must use a public multi-label DNS hostname`);
  }
  return url.origin;
}

function encryptionKey(value: string, name: string): Buffer {
  const decoded = /^[a-f0-9]{64}$/i.test(value)
    ? Buffer.from(value, "hex")
    : Buffer.from(value, "base64");
  if (decoded.length !== 32) {
    throw new Error(`${name} must encode exactly 32 bytes`);
  }
  return decoded;
}

function encryptionKeyId(value: string, name: string): string {
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(value)) {
    throw new Error(`${name} must contain 1-64 URL-safe characters`);
  }
  return value;
}

function loadEncryptionKeyring(env: Env): EncryptionKeyring {
  const active: EncryptionKey = {
    id: encryptionKeyId(required(env, "SELFHOST_ENCRYPTION_KEY_ID"), "SELFHOST_ENCRYPTION_KEY_ID"),
    key: encryptionKey(required(env, "SELFHOST_ENCRYPTION_KEY", true), "SELFHOST_ENCRYPTION_KEY"),
  };
  const previousIdValue = env.SELFHOST_ENCRYPTION_PREVIOUS_KEY_ID?.trim();
  const previousKeyValue = readSecret(env, "SELFHOST_ENCRYPTION_PREVIOUS_KEY");
  if (Boolean(previousIdValue) !== Boolean(previousKeyValue)) {
    throw new Error(
      "SELFHOST_ENCRYPTION_PREVIOUS_KEY_ID and SELFHOST_ENCRYPTION_PREVIOUS_KEY must be set together",
    );
  }
  if (!previousIdValue || !previousKeyValue) return { active };

  const previous: EncryptionKey = {
    id: encryptionKeyId(
      previousIdValue,
      "SELFHOST_ENCRYPTION_PREVIOUS_KEY_ID",
    ),
    key: encryptionKey(previousKeyValue, "SELFHOST_ENCRYPTION_PREVIOUS_KEY"),
  };
  if (previous.id === active.id) {
    throw new Error("Active and previous encryption key IDs must differ");
  }
  if (previous.key.equals(active.key)) {
    throw new Error("Active and previous encryption key material must differ");
  }
  return { active, previous };
}

function boundedPort(value: string | undefined): number {
  const port = Number(value ?? "3000");
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("PORT must be an integer from 1 to 65535");
  }
  return port;
}

export function loadConfig(env: Env = process.env): SelfhostConfig {
  const bootstrapToken = required(env, "SELFHOST_BOOTSTRAP_TOKEN", true);
  if (Buffer.byteLength(bootstrapToken) < 32) {
    throw new Error("SELFHOST_BOOTSTRAP_TOKEN must be at least 32 bytes");
  }
  // Validated at boot; clientIp (src/auth/device-approval.ts) reads it per request.
  trustedProxyHops(env);

  const relayhistoryBackend = loadRelayhistoryBackend(env);
  const sessionReadApi = loadSessionReadApiConfig(env);
  const relayauth = loadRelayauthConfig(env);
  // Native: one History origin, the read API's. Nothing may name a second one.
  const nativeReadApi = relayhistoryBackend === "native"
    ? nativeReadApiConfig(env, sessionReadApi, relayauth)
    : null;
  const relayhistoryPublicUrl = nativeReadApi ? nativeReadApi.publicUrl : publicServiceUrl(env, "RELAYHISTORY_PUBLIC_URL");
  const introspection = loadIntrospectionConfig(env, relayhistoryPublicUrl);
  if (nativeReadApi) assertNativeIntrospection(introspection, nativeReadApi.publicUrl);
  const relayhistoryReadApiUrl = env.RELAYHISTORY_READ_API_URL?.trim()
    ? publicServiceUrl(env, "RELAYHISTORY_READ_API_URL") : null;
  const eventsFlag = env.RELAYHISTORY_READ_API_EVENTS?.trim();
  if (eventsFlag && eventsFlag !== "true" && eventsFlag !== "false") {
    throw new Error("RELAYHISTORY_READ_API_EVENTS must be true or false");
  }
  const relayhistoryReadApiEvents = eventsFlag === "true";
  if (relayhistoryReadApiEvents && !relayhistoryReadApiUrl) {
    throw new Error("RELAYHISTORY_READ_API_EVENTS requires RELAYHISTORY_READ_API_URL");
  }
  if (relayhistoryReadApiUrl) {
    if (!introspection.introspectSecret) {
      throw new Error("RELAYHISTORY_READ_API_URL requires RELAYCONTROL_INTROSPECT_SECRET");
    }
    const readerOrigin = new URL(relayhistoryReadApiUrl).origin;
    if (!introspection.introspectAudiences.some((audience) => new URL(audience).origin === readerOrigin)) {
      throw new Error("SELFHOST_INTROSPECT_AUDIENCES must include RELAYHISTORY_READ_API_URL");
    }
  }
  return {
    databaseUrl: loadDatabaseUrl(env),
    publicBaseUrl: serviceUrl(env, "SELFHOST_PUBLIC_URL"),
    relaycastUrl: serviceUrl(env, "RELAYCAST_URL"),
    relaycastPublicUrl: publicServiceUrl(env, "RELAYCAST_PUBLIC_URL"),
    ...relayauth,
    relayhistoryBackend,
    relayhistoryUrl: nativeReadApi ? nativeReadApi.url : serviceUrl(env, "RELAYHISTORY_URL"),
    relayhistoryPublicUrl,
    relayhistoryReadApiUrl,
    relayhistoryReadApiEvents,
    sessionReadApi,
    relayfileControlBrokerSecret: loadBrokerSecret(env),
    sessionErasureApi: loadSessionErasureApiConfig(env),
    sessionReadMcpReads: loadSessionReadMcpReads(env),
    sessionSearchAgentTokens: loadSessionSearchAgentTokens(env),
    ...introspection,
    acquisitionIssuer: loadAcquisitionIssuerConfig(env, introspection),
    bootstrapToken,
    encryptionKeyring: loadEncryptionKeyring(env),
    ...loadAdminConfig(env, serviceUrl(env, "SELFHOST_PUBLIC_URL")),
    factory: loadFactoryConfig(env),
    mcpOAuth: loadMcpOAuthConfig(env, name => readSecret(env, name), serviceUrl(env, "SELFHOST_PUBLIC_URL")),
    port: boundedPort(env.PORT),
    host: env.HOST?.trim() || "0.0.0.0",
  };
}

function loadSessionSearchAgentTokens(env: Env): boolean {
  const value = env.SESSION_SEARCH_AGENT_TOKENS?.trim();
  if (!value || value === "false") return false;
  if (value !== "true") throw new Error("SESSION_SEARCH_AGENT_TOKENS must be true or false");
  return true;
}

function loadSessionReadMcpReads(env: Env): boolean {
  const value = env.SESSION_READ_API_MCP_READS?.trim();
  if (!value || value === "false") return false;
  if (value !== "true") throw new Error("SESSION_READ_API_MCP_READS must be true or false");
  if (!readSecret(env, "SESSION_READ_API_SECRET")) {
    throw new Error("SESSION_READ_API_MCP_READS requires the session read API to be configured");
  }
  return true;
}

function loadSessionErasureApiConfig(env: Env): SelfhostConfig["sessionErasureApi"] {
  const secret = readSecret(env, "SESSION_ERASE_API_SECRET");
  if (!secret && !env.SESSION_ERASE_API_URL?.trim()) return null;
  if (!secret || Buffer.byteLength(secret) < 32) {
    throw new Error("SESSION_ERASE_API_SECRET (or _FILE) must be at least 32 bytes");
  }
  return { url: serviceUrl(env, "SESSION_ERASE_API_URL"), secret };
}

function loadBrokerSecret(env: Env): string | null {
  const secret = readSecret(env, "RELAYFILE_CONTROL_BROKER_SECRET");
  if (!secret) return null;
  if (Buffer.byteLength(secret) < 32) throw new Error("RELAYFILE_CONTROL_BROKER_SECRET (or _FILE) must be at least 32 bytes");
  return secret;
}

/** RELAYHISTORY_BACKEND: unset or `legacy` (default), or `native`; anything else refuses startup. */
function loadRelayhistoryBackend(env: Env): "native" | null {
  const raw = env.RELAYHISTORY_BACKEND?.trim() ?? "";
  if (raw === "" || raw === "legacy") return null;
  if (raw === "native") return "native";
  throw new Error("RELAYHISTORY_BACKEND must be legacy or native");
}

/**
 * RELAYHISTORY_BACKEND=native needs the read API handoff, refuses RelayAuth,
 * and permits RELAYHISTORY_URL / _PUBLIC_URL only when they name the read API.
 * Uploads use the same public origin: the ingest edge is routed there, so a
 * caller's token is valid at exactly one audience.
 */
function nativeReadApiConfig(
  env: Env,
  sessionReadApi: SelfhostConfig["sessionReadApi"],
  relayauth: { relayauthUrl: string | null; relayauthApiKey: string | null },
): { url: string; publicUrl: string } {
  if (!sessionReadApi) {
    throw new Error("RELAYHISTORY_BACKEND=native requires SESSION_READ_API_URL, SESSION_READ_API_PUBLIC_URL and SESSION_READ_API_SECRET");
  }
  if (relayauth.relayauthUrl || relayauth.relayauthApiKey) {
    throw new Error("RELAYHISTORY_BACKEND=native refuses RELAYAUTH_URL and RELAYAUTH_API_KEY");
  }
  if (env.RELAYHISTORY_READ_API_URL?.trim()) {
    throw new Error("RELAYHISTORY_BACKEND=native refuses RELAYHISTORY_READ_API_URL");
  }
  if (new URL(sessionReadApi.publicUrl).origin !== sessionReadApi.publicUrl) {
    throw new Error("SESSION_READ_API_PUBLIC_URL must be a bare origin with RELAYHISTORY_BACKEND=native");
  }
  if (env.RELAYHISTORY_URL?.trim() && serviceUrl(env, "RELAYHISTORY_URL") !== sessionReadApi.url) {
    throw new Error("RELAYHISTORY_URL must equal SESSION_READ_API_URL (or be unset) with RELAYHISTORY_BACKEND=native");
  }
  if (env.RELAYHISTORY_PUBLIC_URL?.trim() && publicServiceUrl(env, "RELAYHISTORY_PUBLIC_URL") !== sessionReadApi.publicUrl) {
    throw new Error("RELAYHISTORY_PUBLIC_URL must equal SESSION_READ_API_PUBLIC_URL (or be unset) with RELAYHISTORY_BACKEND=native");
  }
  return { url: sessionReadApi.url, publicUrl: sessionReadApi.publicUrl };
}

/** The ingest edge authorizes every upload through introspection of this audience. */
function assertNativeIntrospection(
  introspection: { introspectSecret: string | null; introspectAudiences: string[] },
  publicUrl: string,
): void {
  if (!introspection.introspectSecret) {
    throw new Error("RELAYHISTORY_BACKEND=native requires RELAYCONTROL_INTROSPECT_SECRET");
  }
  if (!introspection.introspectAudiences.includes(publicUrl)) {
    throw new Error("SELFHOST_INTROSPECT_AUDIENCES must include SESSION_READ_API_PUBLIC_URL with RELAYHISTORY_BACKEND=native");
  }
}

function loadSessionReadApiConfig(env: Env): SelfhostConfig["sessionReadApi"] {
  const secret = readSecret(env, "SESSION_READ_API_SECRET");
  const names = ["SESSION_READ_API_URL", "SESSION_READ_API_PUBLIC_URL"] as const;
  if (!secret && !names.some((name) => env[name]?.trim())) return null;
  if (!secret || Buffer.byteLength(secret) < 32) {
    throw new Error("SESSION_READ_API_SECRET (or _FILE) must be at least 32 bytes");
  }
  return {
    url: serviceUrl(env, "SESSION_READ_API_URL"),
    publicUrl: publicServiceUrl(env, "SESSION_READ_API_PUBLIC_URL"),
    secret,
  };
}

/**
 * SELFHOST_FACTORY_ENABLED (default false), SELFHOST_FACTORY_API_URL (https,
 * default https://api.factory.ai) and SELFHOST_FACTORY_HISTORY_INTERVAL_MS
 * (default 300000, minimum 60000).
 */
export function loadFactoryConfig(env: Env): FactoryConfig {
  const flag = env.SELFHOST_FACTORY_ENABLED?.trim().toLowerCase() ?? "";
  if (!["", "true", "1", "false", "0"].includes(flag)) {
    throw new Error("SELFHOST_FACTORY_ENABLED must be true or false");
  }
  const rawUrl = env.SELFHOST_FACTORY_API_URL?.trim() || "https://api.factory.ai";
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("SELFHOST_FACTORY_API_URL must be an absolute https URL");
  }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash) {
    throw new Error("SELFHOST_FACTORY_API_URL must be an absolute https URL");
  }
  const rawInterval = env.SELFHOST_FACTORY_HISTORY_INTERVAL_MS?.trim();
  const historyIntervalMs = rawInterval ? Number(rawInterval) : 300_000;
  if (!Number.isSafeInteger(historyIntervalMs) || historyIntervalMs < 60_000) {
    throw new Error("SELFHOST_FACTORY_HISTORY_INTERVAL_MS must be an integer of at least 60000");
  }
  return {
    enabled: flag === "true" || flag === "1",
    apiUrl: url.toString().replace(/\/+$/, ""),
    historyIntervalMs,
  };
}

/**
 * RELAYAUTH_URL and RELAYAUTH_API_KEY: both (transitional assertion path) or
 * neither (RelayHistory introspects relaycontrol's own access tokens).
 */
function loadRelayauthConfig(env: Env): {
  relayauthUrl: string | null;
  relayauthApiKey: string | null;
} {
  const url = env.RELAYAUTH_URL?.trim();
  const apiKey = readSecret(env, "RELAYAUTH_API_KEY");
  if (!url && !apiKey) return { relayauthUrl: null, relayauthApiKey: null };
  if (!url || !apiKey) {
    throw new Error("RELAYAUTH_URL and RELAYAUTH_API_KEY must be set together or both left unset");
  }
  return { relayauthUrl: serviceUrl(env, "RELAYAUTH_URL"), relayauthApiKey: apiKey };
}

/**
 * One http(s) origin without credentials, path, query or fragment, trailing
 * slashes dropped (SELFHOST_INTROSPECT_AUDIENCES entries and
 * SELFHOST_ACQUISITION_ORIGIN). `label` names the variable in errors; the
 * value is never echoed.
 */
function audienceOrigin(value: string, label: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be an absolute origin`);
  }
  if (
    (url.protocol !== "http:" && url.protocol !== "https:") ||
    url.username || url.password || url.search || url.hash ||
    (url.pathname !== "" && url.pathname !== "/") || /[?#]/.test(value)
  ) {
    throw new Error(
      `${label} must be an http(s) origin without credentials, path, query, or fragment`,
    );
  }
  return value.replace(/\/+$/, "");
}

function loadIntrospectionConfig(env: Env, relayhistoryPublicUrl: string): {
  introspectSecret: string | null;
  introspectAudiences: string[];
} {
  const introspectSecret = readSecret(env, "RELAYCONTROL_INTROSPECT_SECRET") ?? null;
  if (introspectSecret !== null && Buffer.byteLength(introspectSecret) < 32) {
    throw new Error("RELAYCONTROL_INTROSPECT_SECRET must be at least 32 bytes");
  }
  const raw = env.SELFHOST_INTROSPECT_AUDIENCES?.trim();
  const introspectAudiences = raw
    ? raw.split(",").map((value) => value.trim()).filter(Boolean).map((value) =>
      audienceOrigin(value, "each SELFHOST_INTROSPECT_AUDIENCES entry"))
    : [relayhistoryPublicUrl];
  if (introspectAudiences.length === 0) {
    throw new Error("SELFHOST_INTROSPECT_AUDIENCES must name at least one origin");
  }
  return { introspectSecret, introspectAudiences };
}

/**
 * SELFHOST_ACQUISITION_ISSUER_ENABLED (strict `true` / `false` / unset,
 * default off). Off: null, and no other acquisition variable is read, so no
 * key is loaded or parsed. On: every variable must be present and valid, and
 * startup fails naming the variable (never its value) otherwise.
 *
 * The acquisition origin must also be an accepted introspection audience with
 * introspection enabled: acquisition-operator tokens can only be minted for,
 * and only introspect against, an accepted audience, and the pipeline
 * verifies its callers through the same introspection.
 */
export function loadAcquisitionIssuerConfig(
  env: Env,
  introspection: { introspectSecret: string | null; introspectAudiences: string[] },
): AcquisitionIssuerConfig | null {
  const flag = env.SELFHOST_ACQUISITION_ISSUER_ENABLED?.trim() ?? "";
  if (flag !== "" && flag !== "true" && flag !== "false") {
    throw new Error("SELFHOST_ACQUISITION_ISSUER_ENABLED must be true or false");
  }
  if (flag !== "true") return null;

  const originValue = required(env, "SELFHOST_ACQUISITION_ORIGIN");
  const origin = new URL(audienceOrigin(originValue, "SELFHOST_ACQUISITION_ORIGIN")).origin;
  if (!introspection.introspectSecret) {
    throw new Error("RELAYCONTROL_INTROSPECT_SECRET is required when SELFHOST_ACQUISITION_ISSUER_ENABLED=true");
  }
  if (!introspection.introspectAudiences.some((audience) => new URL(audience).origin === origin)) {
    throw new Error("SELFHOST_ACQUISITION_ORIGIN must be listed in SELFHOST_INTROSPECT_AUDIENCES");
  }

  const keyId = env.SELFHOST_ACQUISITION_ISSUER_KEY_ID;
  if (keyId === undefined || keyId === "") throw new Error("SELFHOST_ACQUISITION_ISSUER_KEY_ID is required");
  if (!isAcquisitionIdentifier(keyId)) {
    throw new Error(
      "SELFHOST_ACQUISITION_ISSUER_KEY_ID must be at most 512 UTF-8 bytes without control characters",
    );
  }

  const pem = readSecret(env, "SELFHOST_ACQUISITION_ISSUER_PRIVATE_KEY");
  if (!pem) throw new Error("SELFHOST_ACQUISITION_ISSUER_PRIVATE_KEY (or _FILE) is required");
  let privateKey: KeyObject;
  try {
    if (!pem.startsWith("-----BEGIN PRIVATE KEY-----")) throw new Error("not PKCS#8 PEM");
    privateKey = createPrivateKey({ key: pem, format: "pem" });
  } catch {
    throw new Error("SELFHOST_ACQUISITION_ISSUER_PRIVATE_KEY must be an unencrypted PKCS#8 PEM Ed25519 private key");
  }
  if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("SELFHOST_ACQUISITION_ISSUER_PRIVATE_KEY must be an unencrypted PKCS#8 PEM Ed25519 private key");
  }
  const active: AcquisitionPublishedKey = {
    issuerKeyId: keyId,
    issuerClass: "cloud",
    publicKeyBase64: rawEd25519PublicKey(privateKey).toString("base64"),
  };
  return {
    origin,
    keyId,
    privateKey,
    publishedKeys: [active, ...loadPreviousAcquisitionKeys(env, active)],
  };
}

/** SELFHOST_ACQUISITION_ISSUER_PREVIOUS_PUBLIC_KEYS: JSON [{issuerKeyId, publicKeyBase64}]. */
function loadPreviousAcquisitionKeys(env: Env, active: AcquisitionPublishedKey): AcquisitionPublishedKey[] {
  const name = "SELFHOST_ACQUISITION_ISSUER_PREVIOUS_PUBLIC_KEYS";
  const raw = env[name]?.trim();
  if (!raw) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`${name} must be a JSON array`);
  }
  if (!Array.isArray(parsed)) throw new Error(`${name} must be a JSON array`);
  const ids = new Set([active.issuerKeyId]);
  const keys = new Set([active.publicKeyBase64]);
  return parsed.map((entry: unknown) => {
    if (!entry || typeof entry !== "object" || Array.isArray(entry) ||
        Object.keys(entry).sort().join(",") !== "issuerKeyId,publicKeyBase64") {
      throw new Error(`${name} entries need exactly issuerKeyId and publicKeyBase64`);
    }
    const { issuerKeyId, publicKeyBase64 } = entry as Record<string, unknown>;
    if (!isAcquisitionIdentifier(issuerKeyId)) throw new Error(`${name} has an invalid issuerKeyId`);
    if (!strictRawPublicKey(publicKeyBase64)) {
      throw new Error(`${name} publicKeyBase64 must be base64 of a raw 32-byte Ed25519 public key`);
    }
    if (ids.has(issuerKeyId)) throw new Error(`${name} repeats an issuerKeyId (or the active one)`);
    if (keys.has(publicKeyBase64 as string)) throw new Error(`${name} repeats a public key (or the active one)`);
    ids.add(issuerKeyId);
    keys.add(publicKeyBase64 as string);
    return { issuerKeyId, issuerClass: "cloud" as const, publicKeyBase64: publicKeyBase64 as string };
  });
}

function absoluteHttpUrl(env: Env, name: string, fallback: string): string {
  const value = env[name]?.trim() || fallback;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute URL`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`${name} must use http or https`);
  }
  if (url.username || url.password || url.hash) {
    throw new Error(`${name} must not contain credentials or a fragment`);
  }
  return url.toString();
}

function loadAdminConfig(env: Env, publicBaseUrl: string): {
  internalServiceToken: string | null;
  oauthRedirectUrl: string;
  dashboardUrl: string;
  operatorOAuthApps: Record<string, OperatorOAuthApp>;
  desktopFeed: DesktopFeedConfig | null;
} {
  const internalServiceToken = readSecret(env, "SELFHOST_INTERNAL_TOKEN") ?? null;
  if (internalServiceToken !== null && Buffer.byteLength(internalServiceToken) < 32) {
    throw new Error("SELFHOST_INTERNAL_TOKEN must be at least 32 bytes");
  }
  const oauthRedirectUrl = absoluteHttpUrl(
    env,
    "SELFHOST_OAUTH_REDIRECT_URL",
    `${publicBaseUrl}/api/v1/integrations/oauth/callback`,
  );
  if (new URL(oauthRedirectUrl).search) {
    throw new Error("SELFHOST_OAUTH_REDIRECT_URL must not contain a query string");
  }
  return {
    internalServiceToken,
    oauthRedirectUrl,
    dashboardUrl: absoluteHttpUrl(env, "SELFHOST_DASHBOARD_URL", `${publicBaseUrl}/`),
    operatorOAuthApps: loadOperatorOAuthApps(env),
    desktopFeed: loadDesktopFeedConfig(env),
  };
}

const FEED_PROFILE_ID = /^[a-z0-9]{1,32}$/;
const KMS_ALIAS = /^alias\/(?!aws\/)[A-Za-z0-9/_-]{1,250}$/;

function feedProfileMap(env: Env, name: string): Record<string, unknown> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(env[name] ?? "");
  } catch {
    throw new Error(`${name} must be a JSON object keyed by profile id`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`${name} must be a JSON object keyed by profile id`);
  }
  for (const profile of Object.keys(parsed)) {
    if (!FEED_PROFILE_ID.test(profile)) throw new Error(`${name} has a profile id that is not ^[a-z0-9]{1,32}$`);
  }
  return parsed as Record<string, unknown>;
}

/**
 * SELFHOST_DESKTOP_FEED_SIGNER (awskms | memory) and
 * SELFHOST_DESKTOP_FEED_STORAGE (s3 | memory) together turn the feed on;
 * with neither set it is off. Setting only one is a configuration error, so a
 * half-configured feed never starts silently disabled.
 */
export function loadDesktopFeedConfig(env: Env = process.env): DesktopFeedConfig | null {
  const signerKind = env.SELFHOST_DESKTOP_FEED_SIGNER?.trim();
  const storageKind = env.SELFHOST_DESKTOP_FEED_STORAGE?.trim();
  if (!signerKind && !storageKind) return null;
  if (!signerKind || !storageKind) {
    throw new Error("SELFHOST_DESKTOP_FEED_SIGNER and SELFHOST_DESKTOP_FEED_STORAGE must be set together");
  }
  // The memory backends lose their key and objects on restart: tests and dev only.
  if (env.NODE_ENV === "production" && (signerKind === "memory" || storageKind === "memory")) {
    throw new Error("The memory desktop feed signer and storage are for tests and development, not NODE_ENV=production");
  }
  const label = env.SELFHOST_DESKTOP_FEED_KEY_LABEL?.trim() || (signerKind === "awskms" ? "k1" : "dev");
  if (!/^[a-z0-9]{1,16}$/.test(label)) throw new Error("SELFHOST_DESKTOP_FEED_KEY_LABEL must match ^[a-z0-9]{1,16}$");
  let signer: DesktopFeedSignerConfig;
  if (signerKind === "awskms") {
    const region = env.SELFHOST_DESKTOP_FEED_KMS_REGION?.trim() || env.AWS_REGION?.trim() || "";
    if (!/^[a-z0-9-]+$/.test(region)) {
      throw new Error("SELFHOST_DESKTOP_FEED_KMS_REGION (or AWS_REGION) is required for the awskms feed signer");
    }
    const aliases = feedProfileMap(env, "SELFHOST_DESKTOP_FEED_KMS_KEY_ALIASES");
    if (Object.keys(aliases).length === 0) {
      throw new Error("SELFHOST_DESKTOP_FEED_KMS_KEY_ALIASES must name at least one profile");
    }
    for (const alias of Object.values(aliases)) {
      if (typeof alias !== "string" || !KMS_ALIAS.test(alias)) {
        throw new Error("SELFHOST_DESKTOP_FEED_KMS_KEY_ALIASES values must look like alias/name");
      }
    }
    signer = { kind: "awskms", region, label, keyAliases: aliases as Record<string, string> };
  } else if (signerKind === "memory") {
    signer = { kind: "memory", label };
  } else {
    throw new Error("SELFHOST_DESKTOP_FEED_SIGNER must be awskms or memory");
  }
  let storage: DesktopFeedStorageConfig;
  if (storageKind === "s3") {
    const bucket = required(env, "SELFHOST_DESKTOP_FEED_S3_BUCKET");
    // Dots would break TLS on the virtual-hosted host signed URLs point at.
    if (!/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(bucket)) {
      throw new Error("SELFHOST_DESKTOP_FEED_S3_BUCKET must be a bucket name without dots");
    }
    const region = env.SELFHOST_DESKTOP_FEED_S3_REGION?.trim() || env.AWS_REGION?.trim()
      || (signer.kind === "awskms" ? signer.region : "");
    if (!region || !/^[a-z0-9-]+$/.test(region)) {
      throw new Error("SELFHOST_DESKTOP_FEED_S3_REGION (or AWS_REGION) is required for s3 feed storage");
    }
    // Unset, empty or only slashes: the default. Segments use only characters
    // that encodeURIComponent and SigV4 canonical encoding agree on.
    const prefix = (env.SELFHOST_DESKTOP_FEED_S3_PREFIX ?? "").trim().replace(/^\/+|\/+$/g, "") || "desktop-feed";
    if (!/^[A-Za-z0-9._-]+(?:\/[A-Za-z0-9._-]+)*$/.test(prefix)
      || prefix.split("/").some((segment) => segment === "." || segment === "..")) {
      throw new Error("SELFHOST_DESKTOP_FEED_S3_PREFIX must be [A-Za-z0-9._-] segments separated by /");
    }
    storage = { kind: "s3", bucket, region, prefix };
  } else if (storageKind === "memory") {
    storage = { kind: "memory" };
  } else {
    throw new Error("SELFHOST_DESKTOP_FEED_STORAGE must be s3 or memory");
  }
  const publisherTokenHashes: Record<string, string[]> = {};
  if (env.SELFHOST_DESKTOP_FEED_PUBLISHER_TOKEN_HASHES?.trim()) {
    const entries = feedProfileMap(env, "SELFHOST_DESKTOP_FEED_PUBLISHER_TOKEN_HASHES");
    for (const [profile, hashes] of Object.entries(entries)) {
      if (!Array.isArray(hashes) || !hashes.every((hash) => typeof hash === "string" && /^[0-9a-f]{64}$/.test(hash))) {
        throw new Error("SELFHOST_DESKTOP_FEED_PUBLISHER_TOKEN_HASHES values must be arrays of sha256 hex");
      }
      publisherTokenHashes[profile] = hashes as string[];
    }
  }
  return { signer, storage, publisherTokenHashes };
}
export function loadDatabaseUrl(env: Env = process.env): string {
  return required(env, "DATABASE_URL", true);
}

export function loadMigrationsDatabaseUrl(env: Env = process.env): string {
  return required(env, "DATABASE_MIGRATIONS_URL", true);
}

export function loadRuntimeDatabaseRole(env: Env = process.env): string {
  const role = required(env, "SELFHOST_RUNTIME_DATABASE_ROLE");
  if (
    !/^[A-Za-z_][A-Za-z0-9_$]{0,62}$/.test(role) ||
    role.toLowerCase() === "public"
  ) {
    throw new Error(
      "SELFHOST_RUNTIME_DATABASE_ROLE must be a valid non-PUBLIC PostgreSQL role name",
    );
  }
  return role;
}

/** Stable, non-secret fingerprint for startup diagnostics. */
export function configFingerprint(config: SelfhostConfig): string {
  return createHash("sha256")
    .update([
      config.publicBaseUrl,
      config.relaycastUrl,
      config.relaycastPublicUrl,
      config.relayauthUrl ?? "",
      config.relayhistoryUrl,
      config.relayhistoryPublicUrl,
      ...(config.relayhistoryReadApiUrl ? [config.relayhistoryReadApiUrl] : []),
      ...(config.relayhistoryReadApiEvents ? ["native-session-events"] : []),
      ...(config.sessionReadApi ? [config.sessionReadApi.url, config.sessionReadApi.publicUrl] : []),
      ...(config.sessionErasureApi ? [config.sessionErasureApi.url] : []),
    ].join("\n"))
    .digest("hex")
    .slice(0, 12);
}
