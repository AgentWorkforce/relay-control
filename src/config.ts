import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { isIP } from "node:net";
import type { EncryptionKey, EncryptionKeyring } from "./crypto.js";

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
  /** Optional GET-only pipeline reader for unsearched session lists and turns. */
  relayhistoryReadApiUrl?: string | null;
  /** Independent read service; owns issuance, rotation and verification of its tokens. */
  sessionReadApi?: { url: string; publicUrl: string; secret: string } | null;
  /** SESSION_READ_API_MCP_READS: MCP session reads use the read API. Default off. */
  sessionReadMcpReads?: boolean;
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
  /** Factory sessions (src/factory). Unset or enabled=false: routes 404, worker off. */
  factory?: FactoryConfig;
  port: number;
  host: string;
};

export type Env = Record<string, string | undefined>;

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

  const relayhistoryPublicUrl = publicServiceUrl(env, "RELAYHISTORY_PUBLIC_URL");
  const introspection = loadIntrospectionConfig(env, relayhistoryPublicUrl);
  const relayhistoryReadApiUrl = env.RELAYHISTORY_READ_API_URL?.trim()
    ? publicServiceUrl(env, "RELAYHISTORY_READ_API_URL") : null;
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
    ...loadRelayauthConfig(env),
    relayhistoryUrl: serviceUrl(env, "RELAYHISTORY_URL"),
    relayhistoryPublicUrl,
    relayhistoryReadApiUrl,
    sessionReadApi: loadSessionReadApiConfig(env),
    sessionReadMcpReads: loadSessionReadMcpReads(env),
    ...introspection,
    bootstrapToken,
    encryptionKeyring: loadEncryptionKeyring(env),
    ...loadAdminConfig(env, serviceUrl(env, "SELFHOST_PUBLIC_URL")),
    factory: loadFactoryConfig(env),
    port: boundedPort(env.PORT),
    host: env.HOST?.trim() || "0.0.0.0",
  };
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
    ? raw.split(",").map((value) => value.trim()).filter(Boolean).map((value) => {
      let url: URL;
      try {
        url = new URL(value);
      } catch {
        throw new Error("SELFHOST_INTROSPECT_AUDIENCES entries must be absolute origins");
      }
      if (
        (url.protocol !== "http:" && url.protocol !== "https:") ||
        url.username || url.password || url.search || url.hash ||
        (url.pathname !== "" && url.pathname !== "/") || /[?#]/.test(value)
      ) {
        throw new Error(
          "SELFHOST_INTROSPECT_AUDIENCES entries must be http(s) origins without credentials, path, query, or fragment",
        );
      }
      return value.replace(/\/+$/, "");
    })
    : [relayhistoryPublicUrl];
  if (introspectAudiences.length === 0) {
    throw new Error("SELFHOST_INTROSPECT_AUDIENCES must name at least one origin");
  }
  return { introspectSecret, introspectAudiences };
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
  };
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
      ...(config.sessionReadApi ? [config.sessionReadApi.url, config.sessionReadApi.publicUrl] : []),
    ].join("\n"))
    .digest("hex")
    .slice(0, 12);
}
