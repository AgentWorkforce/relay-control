// analytics lane: configuration (prefix SELFHOST_ANALYTICS_). The destination
// is chosen only here; there are no hosted defaults and no fallback between
// destinations. Collector contract: infra docs/analytics-collector-interface.md,
// infra #84 @62599fb as amended by infra #85 @ca91118 (merged 91c9b79).
import { readFileSync } from "node:fs";
import { isIP } from "node:net";
import { readSecret } from "../config.js";
import { ANALYTICS_BATCH_OVERHEAD_BYTES, type AnalyticsDestination } from "./types.js";

type Env = Record<string, string | undefined>;

export type AnalyticsLimits = {
  maxEventBytes: number;
  maxBatchEvents: number;
  maxBatchBytes: number;
  queueMaxEvents: number;
  queueMaxBytes: number;
  requestTimeoutMs: number;
  /** Total per-event budget from enqueue: queue time, every attempt and every wait. */
  deliveryDeadlineMs: number;
  maxAttempts: number;
  flushIntervalMs: number;
  shutdownDeadlineMs: number;
};

export type AnalyticsProfile = "production" | "development";

/** Bounds of the client gateway (`POST /api/v1/analytics/events`). */
export type AnalyticsGatewayLimits = {
  /** Request body limit, enforced on the streamed bytes. */
  maxBodyBytes: number;
  /** Events per request. */
  maxEvents: number;
};

export type AnalyticsConfig = AnalyticsLimits & {
  destination: AnalyticsDestination;
  profile: AnalyticsProfile;
  /** Opaque producer-registration identity; null only for `none`. */
  deploymentId: string | null;
  collector: {
    /**
     * Complete endpoint URL including /v1/events (contract infra #85); the
     * adapter uses it as-is and appends nothing.
     */
    url: string;
    /** Opaque producer credential. Never logged or described. */
    token: string;
    /** PEM installation CA bundle that replaces the system roots for this sink; null uses the system roots. */
    ca: string | null;
  } | null;
  posthog: {
    host: string;
    /** Never logged or described. */
    projectKey: string;
  } | null;
  gateway: AnalyticsGatewayLimits;
};

const PREFIX = "SELFHOST_ANALYTICS_";
const DESTINATIONS: readonly AnalyticsDestination[] = ["none", "collector", "posthog"];
const DEPLOYMENT_ID = /^[A-Za-z0-9_-]{8,64}$/;
// Visible ASCII without spaces: safe as a single Authorization header value.
const HEADER_TOKEN = /^[\x21-\x7e]+$/;

const COLLECTOR_VARS = ["COLLECTOR_URL", "COLLECTOR_TOKEN", "COLLECTOR_TOKEN_FILE", "COLLECTOR_CA_FILE"];
const POSTHOG_VARS = ["POSTHOG_HOST", "POSTHOG_PROJECT_KEY", "POSTHOG_PROJECT_KEY_FILE"];

function boundedInt(env: Env, name: string, fallback: number, min: number, max: number): number {
  const raw = env[name]?.trim();
  if (!raw) return fallback;
  // Decimal digits only: Number() would also accept "0x10", "1e2" or "1_0"-like forms.
  const value = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`);
  }
  return value;
}

function isLoopback(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "");
  return host === "localhost" || host === "::1" || (isIP(host) === 4 && host.startsWith("127."));
}

/** service.namespace.svc or service.namespace.svc.cluster.local */
function isClusterLocal(hostname: string): boolean {
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.svc(\.cluster\.local)?$/i
    .test(hostname);
}

function origin(name: string, value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute URL`);
  }
  if (
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    (url.pathname !== "" && url.pathname !== "/") ||
    /[?#]/.test(value)
  ) {
    throw new Error(`${name} must be an origin without credentials, path, query, or fragment`);
  }
  return url;
}

/** A complete endpoint URL: a non-root path, and no credentials, query, or fragment. */
function endpoint(name: string, value: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute URL`);
  }
  if (url.username || url.password || url.search || url.hash || /[?#]/.test(value)) {
    throw new Error(`${name} must not contain credentials, a query, or a fragment`);
  }
  if (url.pathname === "" || url.pathname === "/") {
    throw new Error(`${name} must be the complete endpoint URL including its path (for example /v1/events)`);
  }
  return url;
}

function collectorUrl(env: Env, profile: AnalyticsProfile): URL {
  const name = `${PREFIX}COLLECTOR_URL`;
  const value = env[name]?.trim();
  if (!value) throw new Error(`${name} is required for the collector destination`);
  const url = endpoint(name, value);
  if (url.protocol === "https:") return url;
  if (url.protocol === "http:") {
    if (profile !== "development") {
      throw new Error(`${name} must use https unless ${PREFIX}PROFILE is development`);
    }
    if (!isLoopback(url.hostname) && !isClusterLocal(url.hostname)) {
      throw new Error(`${name} may use http only for loopback or *.svc[.cluster.local] hosts`);
    }
    return url;
  }
  throw new Error(`${name} must use https`);
}

/**
 * Secrets of this deployment that an analytics credential must never reuse
 * (contract: no shared credentials). Each is read directly or from its _FILE
 * form, as the owning loader reads it.
 */
const FORBIDDEN_SECRET_NAMES = [
  "SELFHOST_INTERNAL_TOKEN",
  "SELFHOST_BOOTSTRAP_TOKEN",
  "DATABASE_URL",
  "DATABASE_MIGRATIONS_URL",
  "RELAYAUTH_API_KEY",
  "RELAYCAST_INTERNAL_SECRET",
  "SELFHOST_ENCRYPTION_KEY",
  "SELFHOST_ENCRYPTION_PREVIOUS_KEY",
  "SELFHOST_TELEMETRY_INSTALL_KEY",
  "SELFHOST_OIDC_CLIENT_SECRET",
  "SELFHOST_SMTP_PASSWORD",
];
/** Operator OAuth app secrets: SELFHOST_OAUTH_<PROVIDER>_CLIENT_SECRET[_FILE]. */
const OAUTH_CLIENT_SECRET = /^(SELFHOST_OAUTH_[A-Z0-9_]+_CLIENT_SECRET)(?:_FILE)?$/;

function forbiddenCredentials(env: Env): string[] {
  const names = new Set(FORBIDDEN_SECRET_NAMES);
  for (const key of Object.keys(env)) {
    const found = OAUTH_CLIENT_SECRET.exec(key);
    if (found) names.add(found[1]!);
  }
  const values: string[] = [];
  for (const name of names) {
    let value: string | undefined;
    try {
      value = readSecret(env, name);
    } catch {
      // Malformed or unreadable: the owning loader reports it.
      continue;
    }
    if (!value) continue;
    values.push(value);
    if (name.startsWith("DATABASE_")) {
      try {
        const password = decodeURIComponent(new URL(value).password);
        if (password) values.push(password);
      } catch {
        // Not a URL: the whole value is still compared.
      }
    }
  }
  return values;
}

/** Plain equality is enough: both sides are local configuration. Never echoes either value. */
function rejectReusedCredential(env: Env, name: string, value: string): void {
  if (forbiddenCredentials(env).includes(value)) {
    throw new Error(`${name} must be a dedicated analytics credential, not a reused service, database, encryption, telemetry, identity or OAuth secret`);
  }
}

function collectorConfig(env: Env, profile: AnalyticsProfile): NonNullable<AnalyticsConfig["collector"]> {
  const url = collectorUrl(env, profile);
  const tokenName = `${PREFIX}COLLECTOR_TOKEN`;
  const token = readSecret(env, tokenName);
  if (!token) throw new Error(`${tokenName} (or _FILE) is required for the collector destination`);
  // Never echo the value: these errors reach startup logs.
  if (!HEADER_TOKEN.test(token)) {
    throw new Error(`${tokenName} must be a single bearer token of visible ASCII characters`);
  }
  rejectReusedCredential(env, tokenName, token);
  const caName = `${PREFIX}COLLECTOR_CA_FILE`;
  const caFile = env[caName]?.trim();
  let ca: string | null = null;
  if (caFile) {
    if (url.protocol !== "https:") throw new Error(`${caName} requires an https ${PREFIX}COLLECTOR_URL`);
    ca = readFileSync(caFile, "utf8");
    if (!ca.includes("-----BEGIN CERTIFICATE-----")) {
      throw new Error(`${caName} must contain PEM certificates`);
    }
  }
  return { url: url.href, token, ca };
}

function posthogConfig(env: Env): NonNullable<AnalyticsConfig["posthog"]> {
  const hostName = `${PREFIX}POSTHOG_HOST`;
  const hostValue = env[hostName]?.trim();
  if (!hostValue) throw new Error(`${hostName} is required for the posthog destination`);
  const host = origin(hostName, hostValue);
  if (host.protocol !== "https:") throw new Error(`${hostName} must use https`);
  const keyName = `${PREFIX}POSTHOG_PROJECT_KEY`;
  const projectKey = readSecret(env, keyName);
  if (!projectKey) throw new Error(`${keyName} (or _FILE) is required for the posthog destination`);
  rejectReusedCredential(env, keyName, projectKey);
  return { host: host.origin, projectKey };
}

function present(env: Env, names: string[]): string[] {
  return names.filter((name) => env[`${PREFIX}${name}`]?.trim()).map((name) => `${PREFIX}${name}`);
}

export function loadAnalyticsConfig(env: Env = process.env): AnalyticsConfig {
  const destinationRaw = (env[`${PREFIX}DESTINATION`]?.trim() || "none").toLowerCase();
  if (!DESTINATIONS.includes(destinationRaw as AnalyticsDestination)) {
    throw new Error(`${PREFIX}DESTINATION must be none, collector, or posthog`);
  }
  const destination = destinationRaw as AnalyticsDestination;
  const profileRaw = (env[`${PREFIX}PROFILE`]?.trim() || "production").toLowerCase();
  if (profileRaw !== "production" && profileRaw !== "development") {
    throw new Error(`${PREFIX}PROFILE must be production or development`);
  }
  const profile = profileRaw as AnalyticsProfile;

  // No cross-destination settings: a hosted key never sits in self-host config.
  const strayPosthog = destination === "posthog" ? [] : present(env, POSTHOG_VARS);
  if (strayPosthog.length) {
    throw new Error(`${strayPosthog.join(", ")} must not be set unless ${PREFIX}DESTINATION is posthog`);
  }
  const strayCollector = destination === "collector" ? [] : present(env, COLLECTOR_VARS);
  if (strayCollector.length) {
    throw new Error(`${strayCollector.join(", ")} must not be set unless ${PREFIX}DESTINATION is collector`);
  }

  const deploymentIdName = `${PREFIX}DEPLOYMENT_ID`;
  const deploymentIdRaw = env[deploymentIdName]?.trim() || null;
  if (deploymentIdRaw !== null && !DEPLOYMENT_ID.test(deploymentIdRaw)) {
    throw new Error(`${deploymentIdName} must be 8-64 characters of A-Z, a-z, 0-9, _ or -`);
  }
  if (destination !== "none" && deploymentIdRaw === null) {
    throw new Error(`${deploymentIdName} is required unless ${PREFIX}DESTINATION is none`);
  }

  const limits: AnalyticsLimits = {
    maxEventBytes: boundedInt(env, `${PREFIX}MAX_EVENT_BYTES`, 4096, 512, 32_768),
    maxBatchEvents: boundedInt(env, `${PREFIX}MAX_BATCH_EVENTS`, 50, 1, 500),
    maxBatchBytes: boundedInt(env, `${PREFIX}MAX_BATCH_BYTES`, 262_144, 4096, 1_048_576),
    queueMaxEvents: boundedInt(env, `${PREFIX}QUEUE_MAX_EVENTS`, 1000, 10, 10_000),
    queueMaxBytes: boundedInt(env, `${PREFIX}QUEUE_MAX_BYTES`, 1_048_576, 65_536, 16_777_216),
    requestTimeoutMs: boundedInt(env, `${PREFIX}REQUEST_TIMEOUT_MS`, 5000, 500, 30_000),
    deliveryDeadlineMs: boundedInt(env, `${PREFIX}DELIVERY_DEADLINE_MS`, 60_000, 1000, 600_000),
    maxAttempts: boundedInt(env, `${PREFIX}MAX_ATTEMPTS`, 4, 1, 10),
    flushIntervalMs: boundedInt(env, `${PREFIX}FLUSH_INTERVAL_MS`, 5000, 500, 60_000),
    shutdownDeadlineMs: boundedInt(env, `${PREFIX}SHUTDOWN_DEADLINE_MS`, 3000, 100, 8000),
  };
  // A batch of one maximum-size event must fit in MAX_BATCH_BYTES with the
  // batch envelope around it.
  if (limits.maxEventBytes + ANALYTICS_BATCH_OVERHEAD_BYTES > limits.maxBatchBytes) {
    throw new Error(
      `${PREFIX}MAX_BATCH_BYTES must be at least ${PREFIX}MAX_EVENT_BYTES + ${ANALYTICS_BATCH_OVERHEAD_BYTES} `
        + `(the batch envelope), so ${limits.maxEventBytes + ANALYTICS_BATCH_OVERHEAD_BYTES} or more`,
    );
  }
  if (limits.maxBatchBytes > limits.queueMaxBytes) {
    throw new Error(`${PREFIX}MAX_BATCH_BYTES <= ${PREFIX}QUEUE_MAX_BYTES must hold`);
  }
  if (limits.deliveryDeadlineMs < limits.requestTimeoutMs) {
    throw new Error(`${PREFIX}DELIVERY_DEADLINE_MS must be at least ${PREFIX}REQUEST_TIMEOUT_MS`);
  }

  const gateway: AnalyticsGatewayLimits = {
    maxBodyBytes: boundedInt(env, `${PREFIX}GATEWAY_MAX_BODY_BYTES`, 32_768, 1024, 262_144),
    maxEvents: boundedInt(env, `${PREFIX}GATEWAY_MAX_EVENTS`, 20, 1, 100),
  };

  return {
    destination,
    profile,
    deploymentId: deploymentIdRaw,
    gateway,
    collector: destination === "collector" ? collectorConfig(env, profile) : null,
    posthog: destination === "posthog" ? posthogConfig(env) : null,
    ...limits,
  };
}

/** Safe description for the startup log: never a token or key. */
export function describeAnalyticsConfig(config: AnalyticsConfig): Record<string, unknown> {
  return {
    destination: config.destination,
    profile: config.profile,
    deploymentId: config.deploymentId,
    collectorUrl: config.collector?.url ?? null,
    collectorTokenConfigured: Boolean(config.collector?.token),
    collectorCaConfigured: Boolean(config.collector?.ca),
    posthogHost: config.posthog?.host ?? null,
    posthogKeyConfigured: Boolean(config.posthog?.projectKey),
    maxEventBytes: config.maxEventBytes,
    maxBatchEvents: config.maxBatchEvents,
    maxBatchBytes: config.maxBatchBytes,
    queueMaxEvents: config.queueMaxEvents,
    queueMaxBytes: config.queueMaxBytes,
    requestTimeoutMs: config.requestTimeoutMs,
    deliveryDeadlineMs: config.deliveryDeadlineMs,
    maxAttempts: config.maxAttempts,
    flushIntervalMs: config.flushIntervalMs,
    shutdownDeadlineMs: config.shutdownDeadlineMs,
    gatewayMaxBodyBytes: config.gateway.maxBodyBytes,
    gatewayMaxEvents: config.gateway.maxEvents,
  };
}
