import { RelaycastCallError } from "../../messaging/relaycast.js";

export const MCP_CLEANUP_MAX_ATTEMPTS = 8;
export const MCP_CLEANUP_MAX_JOBS = 20;
export const MCP_CLEANUP_PASS_MS = 10_000;
export const MCP_CLEANUP_LEASE_MS = 60_000;
const FIRST_RETRY_MS = 15_000;
const MAX_RETRY_MS = 60 * 60_000;

export type McpCleanupBlockReason =
  | "attempt_limit"
  | "workspace_missing"
  | "workspace_location_unknown"
  | "workspace_moved"
  | "workspace_key_unavailable"
  | "agent_ownership_changed"
  | "active_identity_conflict"
  | "native_identity_conflict"
  | "upstream_auth_refused"
  | "upstream_refused";

/** Fixed reason codes are safe to persist and display; upstream bodies are not. */
export class McpCleanupBlocked extends Error {
  constructor(readonly reason: McpCleanupBlockReason) {
    super("Remote cleanup needs operator attention.");
    this.name = "McpCleanupBlocked";
  }
}

export function cleanupRetryAt(attempts: number, now: Date): Date {
  const exponent = Math.max(0, Math.min(8, Math.trunc(attempts) - 1));
  return new Date(now.getTime() + Math.min(MAX_RETRY_MS, FIRST_RETRY_MS * 2 ** exponent));
}

export function cleanupFailure(error: unknown):
  | { retryable: false; reason: McpCleanupBlockReason }
  | { retryable: true; reason: "upstream_unavailable" | "internal_error" } {
  if (error instanceof McpCleanupBlocked) return { retryable: false, reason: error.reason };
  if (error instanceof RelaycastCallError) {
    if (error.status === 401 || error.status === 403) return { retryable: false, reason: "upstream_auth_refused" };
    if ([0, 408, 409, 429].includes(error.status) || error.status >= 500) {
      return { retryable: true, reason: "upstream_unavailable" };
    }
    return { retryable: false, reason: "upstream_refused" };
  }
  return { retryable: true, reason: "internal_error" };
}
