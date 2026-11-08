// telemetry lane: configuration. One switch (SELFHOST_TELEMETRY_LEVEL) decides
// what is collected; the transport decides whether it leaves over HTTPS or is
// only exported to a file by an operator (air-gapped).
import { readFileSync } from "node:fs";
import { isIP } from "node:net";

export type TelemetryLevel = "off" | "errors" | "full";
export type TelemetryTransport = "https" | "file";

export type TelemetryProbe = { name: string; url: string };

export type TelemetryConfig = {
  level: TelemetryLevel;
  transport: TelemetryTransport;
  /** Hosted ingest URL; null when nothing is sent over the network. */
  endpoint: string | null;
  installId: string | null;
  /** HMAC key issued by Agent Relay for this install. Never logged or sent. */
  installKey: string | null;
  digestIntervalSeconds: number;
  burstThreshold: number;
  burstWindowSeconds: number;
  probes: TelemetryProbe[];
  /** Non-secret deployment shape rendered by the chart (validated, allowlisted). */
  deployment: Record<string, unknown>;
  /** Same service bearer the admin lane uses for /internal/v1 (SELFHOST_INTERNAL_TOKEN). */
  internalServiceToken: string | null;
};

type Env = Record<string, string | undefined>;

export const TELEMETRY_LEVELS: readonly TelemetryLevel[] = ["off", "errors", "full"];

function readSecret(env: Env, name: string): string | undefined {
  const direct = env[name]?.trim();
  const file = env[`${name}_FILE`]?.trim();
  if (direct && file) throw new Error(`${name} and ${name}_FILE are mutually exclusive`);
  if (direct) return direct;
  if (!file) return undefined;
  return readFileSync(file, "utf8").trim() || undefined;
}

function isLoopback(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "");
  return host === "localhost" || host === "127.0.0.1" || host === "::1" ||
    (isIP(host) === 4 && host.startsWith("127."));
}

function endpointUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("SELFHOST_TELEMETRY_ENDPOINT must be an absolute URL");
  }
  if (url.username || url.password || url.hash || url.search) {
    throw new Error("SELFHOST_TELEMETRY_ENDPOINT must not contain credentials, query, or fragment");
  }
  // Plain HTTP only for loopback (local testing); everything else must be TLS.
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopback(url.hostname))) {
    throw new Error("SELFHOST_TELEMETRY_ENDPOINT must use https");
  }
  return url.toString();
}

function boundedInt(env: Env, name: string, fallback: number, min: number, max: number): number {
  const raw = env[name]?.trim();
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}`);
  }
  return value;
}

function probeUrl(name: string, value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`SELFHOST_TELEMETRY_PROBES entry ${name} must be an absolute URL`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`SELFHOST_TELEMETRY_PROBES entry ${name} must use http or https`);
  }
  if (url.username || url.password || url.hash) {
    throw new Error(`SELFHOST_TELEMETRY_PROBES entry ${name} must not contain credentials`);
  }
  return url.toString();
}

/**
 * `name=url` pairs separated by commas. The URL is the full health/metrics URL
 * (e.g. `relayhistory=http://relayhistory:8080/health`).
 */
export function parseProbes(raw: string | undefined): TelemetryProbe[] {
  if (!raw?.trim()) return [];
  const probes: TelemetryProbe[] = [];
  for (const entry of raw.split(",")) {
    const trimmed = entry.trim();
    if (!trimmed) continue;
    const separator = trimmed.indexOf("=");
    const name = separator > 0 ? trimmed.slice(0, separator).trim() : "";
    if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(name)) {
      throw new Error("SELFHOST_TELEMETRY_PROBES entries must be name=url with a lowercase name");
    }
    if (probes.some((probe) => probe.name === name)) {
      throw new Error(`SELFHOST_TELEMETRY_PROBES has a duplicate entry for ${name}`);
    }
    probes.push({ name, url: probeUrl(name, trimmed.slice(separator + 1).trim()) });
  }
  if (probes.length > 20) throw new Error("SELFHOST_TELEMETRY_PROBES allows at most 20 entries");
  return probes;
}

const SHAPE_KEY = /^[A-Za-z][A-Za-z0-9_.-]{0,47}$/;
const SHAPE_VALUE = /^[A-Za-z0-9][A-Za-z0-9_.+:@/-]{0,79}$/;

/**
 * The deployment shape is chart-rendered JSON: only nested objects of short
 * keys with numbers, booleans, or short version-like strings survive. Anything
 * else (URLs with hosts, free text) is rejected so it cannot carry data.
 */
export function sanitizeDeploymentShape(value: unknown, depth = 0): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || depth > 3) return {};
  const output: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value).slice(0, 64)) {
    if (!SHAPE_KEY.test(key)) continue;
    if (typeof entry === "number" && Number.isFinite(entry)) output[key] = entry;
    else if (typeof entry === "boolean") output[key] = entry;
    else if (typeof entry === "string" && SHAPE_VALUE.test(entry) && !entry.includes("//")) {
      output[key] = entry;
    } else if (entry && typeof entry === "object" && !Array.isArray(entry)) {
      const nested = sanitizeDeploymentShape(entry, depth + 1);
      if (Object.keys(nested).length) output[key] = nested;
    }
  }
  return output;
}

export function loadTelemetryConfig(
  env: Env = process.env,
  defaults: { probes?: TelemetryProbe[] } = {},
): TelemetryConfig {
  const levelRaw = (env.SELFHOST_TELEMETRY_LEVEL?.trim() || "off").toLowerCase();
  if (!TELEMETRY_LEVELS.includes(levelRaw as TelemetryLevel)) {
    throw new Error("SELFHOST_TELEMETRY_LEVEL must be off, errors, or full");
  }
  const level = levelRaw as TelemetryLevel;
  const transportRaw = (env.SELFHOST_TELEMETRY_TRANSPORT?.trim() || "https").toLowerCase();
  if (transportRaw !== "https" && transportRaw !== "file") {
    throw new Error("SELFHOST_TELEMETRY_TRANSPORT must be https or file");
  }
  const transport = transportRaw as TelemetryTransport;

  const endpointRaw = env.SELFHOST_TELEMETRY_ENDPOINT?.trim();
  const endpoint = endpointRaw ? endpointUrl(endpointRaw) : null;
  const installId = env.SELFHOST_TELEMETRY_INSTALL_ID?.trim() || null;
  if (installId !== null && !/^inst_[A-Za-z0-9]{8,64}$/.test(installId)) {
    throw new Error("SELFHOST_TELEMETRY_INSTALL_ID must look like inst_<8-64 alphanumerics>");
  }
  const installKey = readSecret(env, "SELFHOST_TELEMETRY_INSTALL_KEY") ?? null;
  if (installKey !== null && Buffer.byteLength(installKey) < 32) {
    throw new Error("SELFHOST_TELEMETRY_INSTALL_KEY must be at least 32 bytes");
  }
  if (Boolean(installId) !== Boolean(installKey)) {
    throw new Error(
      "SELFHOST_TELEMETRY_INSTALL_ID and SELFHOST_TELEMETRY_INSTALL_KEY must be set together",
    );
  }
  if (level !== "off") {
    if (!installId) {
      throw new Error("SELFHOST_TELEMETRY_INSTALL_ID and _INSTALL_KEY are required unless the level is off");
    }
    if (transport === "https" && !endpoint) {
      throw new Error("SELFHOST_TELEMETRY_ENDPOINT is required for the https transport");
    }
  }

  let deployment: Record<string, unknown> = {};
  const shapeRaw = env.SELFHOST_TELEMETRY_DEPLOYMENT?.trim();
  if (shapeRaw) {
    try {
      deployment = sanitizeDeploymentShape(JSON.parse(shapeRaw));
    } catch {
      throw new Error("SELFHOST_TELEMETRY_DEPLOYMENT must be a JSON object");
    }
  }

  const internalServiceToken = readSecret(env, "SELFHOST_INTERNAL_TOKEN") ?? null;
  if (internalServiceToken !== null && Buffer.byteLength(internalServiceToken) < 32) {
    throw new Error("SELFHOST_INTERNAL_TOKEN must be at least 32 bytes");
  }

  const explicitProbes = parseProbes(env.SELFHOST_TELEMETRY_PROBES);
  const probes = [...explicitProbes];
  for (const probe of defaults.probes ?? []) {
    if (!probes.some((existing) => existing.name === probe.name)) probes.push(probe);
  }

  return {
    level,
    transport,
    endpoint,
    installId,
    installKey,
    digestIntervalSeconds: boundedInt(env, "SELFHOST_TELEMETRY_DIGEST_INTERVAL_SECONDS", 3600, 300, 86_400),
    burstThreshold: boundedInt(env, "SELFHOST_TELEMETRY_BURST_THRESHOLD", 20, 3, 100_000),
    burstWindowSeconds: boundedInt(env, "SELFHOST_TELEMETRY_BURST_WINDOW_SECONDS", 300, 60, 3600),
    probes,
    deployment,
    internalServiceToken,
  };
}

/** Safe description for status/preview: never includes the key. */
export function describeTelemetryConfig(config: TelemetryConfig): Record<string, unknown> {
  return {
    level: config.level,
    transport: config.transport,
    endpoint: config.endpoint,
    installId: config.installId,
    installKeyConfigured: Boolean(config.installKey),
    digestIntervalSeconds: config.digestIntervalSeconds,
    burstThreshold: config.burstThreshold,
    burstWindowSeconds: config.burstWindowSeconds,
    probes: config.probes.map((probe) => probe.name),
  };
}
