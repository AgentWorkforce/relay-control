// analytics collector: configuration (prefix ANALYTICS_COLLECTOR_). A separate
// entrypoint from the control server; it imports nothing from the app except
// src/analytics/types.ts and src/analytics/events.ts. Every limit is finite and
// bounded. Errors name the variable only, never its value. Contract: infra
// docs/analytics-collector-interface.md, infra #84 @62599fb as amended by
// infra #85 @ca91118 (merged 91c9b79).

type Env = Record<string, string | undefined>;

export const COLLECTOR_ENV_PREFIX = "ANALYTICS_COLLECTOR_";

export type RetentionPolicy = "reject-new" | "delete-oldest-closed";

export type CollectorLimits = {
  /** Streamed request body cap (bytes); 413 as soon as it is passed. */
  maxBatchBytes: number;
  /** Events per batch; more is 400 invalid_batch. */
  maxBatchEvents: number;
  /** One canonical NDJSON line, without its newline (bytes); more is 413 event_too_large. */
  maxEventBytes: number;
  /** Body read deadline after authorization; 408 timeout. */
  requestTimeoutMs: number;
  /** Concurrent authorized requests; more is 429 busy. */
  maxInFlight: number;
  /** Closed segment files. */
  maxSegments: number;
  /** Sum of closed segment sizes (bytes). */
  maxDiskBytes: number;
  /** SIGTERM: stop accepting, finish in-flight commits, then close within this. */
  shutdownDeadlineMs: number;
};

export type CollectorConfig = CollectorLimits & {
  host: string;
  /** 0 picks an ephemeral port (tests). */
  port: number;
  dataDir: string;
  producersFile: string;
  retention: RetentionPolicy;
  /** delete-oldest-closed only: closed segments older than this are removed at startup and on each commit. */
  retentionMaxAgeMs: number | null;
};

const RETENTIONS: readonly RetentionPolicy[] = ["reject-new", "delete-oldest-closed"];
const HOST = /^[A-Za-z0-9.:_-]{1,253}$/;

function name(suffix: string): string {
  return `${COLLECTOR_ENV_PREFIX}${suffix}`;
}

/** Decimal digits only, within [min, max]. Missing returns the fallback (or throws when required). */
export function boundedInt(env: Env, variable: string, fallback: number | null, min: number, max: number): number {
  const raw = env[variable]?.trim();
  if (!raw) {
    if (fallback === null) throw new Error(`${variable} is required`);
    return fallback;
  }
  // Number() would also accept "0x10", "1e2" or " 1 "-like forms.
  const value = /^\d+$/.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${variable} must be an integer from ${min} to ${max}`);
  }
  return value;
}

function required(env: Env, variable: string): string {
  const value = env[variable]?.trim();
  if (!value) throw new Error(`${variable} is required`);
  return value;
}

export function loadCollectorConfig(env: Env = process.env): CollectorConfig {
  const hostName = name("HOST");
  const host = env[hostName]?.trim() || "127.0.0.1";
  if (!HOST.test(host)) throw new Error(`${hostName} must be a hostname or IP address`);

  const retentionName = name("RETENTION");
  const retentionRaw = env[retentionName]?.trim() || "reject-new";
  if (!RETENTIONS.includes(retentionRaw as RetentionPolicy)) {
    throw new Error(`${retentionName} must be reject-new or delete-oldest-closed`);
  }
  const retention = retentionRaw as RetentionPolicy;
  const maxAgeName = name("RETENTION_MAX_AGE_MS");
  let retentionMaxAgeMs: number | null = null;
  if (env[maxAgeName]?.trim()) {
    if (retention !== "delete-oldest-closed") {
      throw new Error(`${maxAgeName} requires ${retentionName}=delete-oldest-closed`);
    }
    retentionMaxAgeMs = boundedInt(env, maxAgeName, null, 60_000, 3_153_600_000_000);
  }

  const config: CollectorConfig = {
    host,
    port: boundedInt(env, name("PORT"), null, 0, 65_535),
    dataDir: required(env, name("DATA_DIR")),
    producersFile: required(env, name("PRODUCERS_FILE")),
    maxBatchBytes: boundedInt(env, name("MAX_BATCH_BYTES"), 262_144, 1024, 16_777_216),
    maxBatchEvents: boundedInt(env, name("MAX_BATCH_EVENTS"), 500, 1, 10_000),
    maxEventBytes: boundedInt(env, name("MAX_EVENT_BYTES"), 4096, 256, 1_048_576),
    requestTimeoutMs: boundedInt(env, name("REQUEST_TIMEOUT_MS"), 10_000, 100, 300_000),
    maxInFlight: boundedInt(env, name("MAX_IN_FLIGHT"), 16, 1, 1024),
    maxSegments: boundedInt(env, name("MAX_SEGMENTS"), 100_000, 1, 10_000_000),
    maxDiskBytes: boundedInt(env, name("MAX_DISK_BYTES"), 1_073_741_824, 1_048_576, 17_592_186_044_416),
    shutdownDeadlineMs: boundedInt(env, name("SHUTDOWN_DEADLINE_MS"), 5000, 100, 60_000),
    retention,
    retentionMaxAgeMs,
  };
  if (config.maxEventBytes > config.maxBatchBytes) {
    throw new Error(`${name("MAX_EVENT_BYTES")} must not exceed ${name("MAX_BATCH_BYTES")}`);
  }
  if (config.maxBatchBytes > config.maxDiskBytes) {
    throw new Error(`${name("MAX_DISK_BYTES")} must be at least ${name("MAX_BATCH_BYTES")}`);
  }
  return config;
}

