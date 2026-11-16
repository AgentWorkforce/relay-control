import type { Env } from "../config.js";

/**
 * Replicas bridge settings. New settings (for example a workspace-identity
 * issuer or a public endpoint URL) are added as further optional keys; the
 * existing key names stay stable.
 */
export type ReplicasConfig = {
  /**
   * SELFHOST_REPLICAS_ENABLED=true. Off: every Replicas bridge route answers
   * 404 before authentication and no Replicas MCP tool is registered. The
   * Replicas API key itself is managed through remote-agent-connections.
   */
  enabled: boolean;
  /**
   * SELFHOST_REPLICAS_IDENTITY_ISSUER (default https://api.replicas.dev).
   * The only issuer whose workspace_identity tokens the environment-level
   * MCP accepts; its discovery document and JWKS are fetched from it alone.
   */
  identityIssuer?: string;
  /**
   * SELFHOST_REPLICAS_SYNC_INTERVAL_SECONDS (default 60, minimum 30, 0 = off).
   * Interval of the in-process environment sync sweep (./sync-sweep.ts).
   * Absent means off; only the server entry point starts the sweep.
   */
  syncIntervalSeconds?: number;
};

export const DEFAULT_REPLICAS_SYNC_INTERVAL_SECONDS = 60;
export const MIN_REPLICAS_SYNC_INTERVAL_SECONDS = 30;

function syncInterval(raw: string | undefined): number {
  const value = raw?.trim();
  if (!value) return DEFAULT_REPLICAS_SYNC_INTERVAL_SECONDS;
  if (!/^\d+$/.test(value)) throw new Error("SELFHOST_REPLICAS_SYNC_INTERVAL_SECONDS must be a whole number of seconds (0 = off)");
  const seconds = Number(value);
  if (seconds === 0) return 0;
  return Math.max(MIN_REPLICAS_SYNC_INTERVAL_SECONDS, seconds);
}

export const DEFAULT_REPLICAS_IDENTITY_ISSUER = "https://api.replicas.dev";

export function loadReplicasConfig(env: Env): ReplicasConfig {
  const flag = env.SELFHOST_REPLICAS_ENABLED?.trim().toLowerCase();
  if (flag && !["true", "false", "1", "0"].includes(flag)) {
    throw new Error("SELFHOST_REPLICAS_ENABLED must be true or false");
  }
  const issuer = env.SELFHOST_REPLICAS_IDENTITY_ISSUER?.trim() || DEFAULT_REPLICAS_IDENTITY_ISSUER;
  let parsed: URL;
  try {
    parsed = new URL(issuer);
  } catch {
    throw new Error("SELFHOST_REPLICAS_IDENTITY_ISSUER must be an https URL");
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash
    || issuer.endsWith("/") || issuer !== `${parsed.origin}${parsed.pathname === "/" ? "" : parsed.pathname}`) {
    throw new Error("SELFHOST_REPLICAS_IDENTITY_ISSUER must be an https URL without credentials, query or trailing slash");
  }
  return {
    enabled: flag === "true" || flag === "1",
    identityIssuer: issuer,
    syncIntervalSeconds: syncInterval(env.SELFHOST_REPLICAS_SYNC_INTERVAL_SECONDS),
  };
}
