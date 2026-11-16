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
};

export function loadReplicasConfig(env: Env): ReplicasConfig {
  const flag = env.SELFHOST_REPLICAS_ENABLED?.trim().toLowerCase();
  if (flag && !["true", "false", "1", "0"].includes(flag)) {
    throw new Error("SELFHOST_REPLICAS_ENABLED must be true or false");
  }
  return { enabled: flag === "true" || flag === "1" };
}
