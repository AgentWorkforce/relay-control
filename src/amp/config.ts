import { readSecret, type Env } from "../config.js";

export type AmpTransportConfig = { origin: string; token: string };

export type AmpConfig = {
  /** SELFHOST_AMP_ENABLED=true. Off: every Amp route answers 404 before auth and no worker runs. */
  enabled: boolean;
  /** Persistent Amp process service; null leaves every Amp call rejected as not configured. */
  transport: AmpTransportConfig | null;
  /** Bearer for POST /api/v1/internal/amp/job. Null: that route answers 404. */
  internalSecret: string | null;
  workerIntervalMs: number;
  leaseMs: number;
};

function boundedInt(env: Env, name: string, fallback: number, min: number, max: number): number {
  const raw = env[name]?.trim();
  if (!raw) return fallback;
  if (!/^\d+$/.test(raw)) throw new Error(`${name} must be an integer`);
  const value = Number(raw);
  if (value < min || value > max) throw new Error(`${name} must be between ${min} and ${max}`);
  return value;
}

/** Validates without ever echoing a secret value in an error. */
export function loadAmpConfig(env: Env): AmpConfig {
  const flag = env.SELFHOST_AMP_ENABLED?.trim().toLowerCase();
  if (flag && !["true", "false", "1", "0"].includes(flag)) {
    throw new Error("SELFHOST_AMP_ENABLED must be true or false");
  }
  const enabled = flag === "true" || flag === "1";
  const origin = env.AMP_TRANSPORT_ORIGIN?.trim() || null;
  const token = readSecret(env, "AMP_TRANSPORT_TOKEN") ?? null;
  if (Boolean(origin) !== Boolean(token)) {
    throw new Error("AMP_TRANSPORT_ORIGIN and AMP_TRANSPORT_TOKEN must be set together");
  }
  if (origin) {
    let url: URL;
    try {
      url = new URL(origin);
    } catch {
      throw new Error("AMP_TRANSPORT_ORIGIN must be an https origin");
    }
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") {
      throw new Error("AMP_TRANSPORT_ORIGIN must be an https origin");
    }
    if (token!.length < 32 || token === "unset") throw new Error("AMP_TRANSPORT_TOKEN must be at least 32 bytes");
  }
  const internalSecret = readSecret(env, "SELFHOST_AMP_INTERNAL_SECRET") ?? null;
  if (internalSecret !== null && Buffer.byteLength(internalSecret) < 32) {
    throw new Error("SELFHOST_AMP_INTERNAL_SECRET must be at least 32 bytes");
  }
  return {
    enabled,
    transport: origin && token ? { origin, token } : null,
    internalSecret,
    workerIntervalMs: boundedInt(env, "SELFHOST_AMP_WORKER_INTERVAL_MS", 5_000, 250, 600_000),
    leaseMs: boundedInt(env, "SELFHOST_AMP_LEASE_MS", 120_000, 1_000, 3_600_000),
  };
}
