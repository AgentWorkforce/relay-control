import type { IncomingHttpHeaders } from "node:http";
import type { SqlExecutor } from "../database.js";
import type { Principal } from "../store.js";

/**
 * Fleet rollout C1: what an Agent Relay Desktop says about itself on the
 * access/me read it already makes. Desktop sends
 * `User-Agent: AgentRelayDesktop/<version>`, optionally followed by
 * ` (<platform>)`, and `X-Agent-Relay-Policy-Revision: <n>` for the workspace
 * policy revision it applied. Parsing is strict and silent: anything invalid
 * is null, never an error, so old clients keep working. (The uploader's
 * X-Agent-Relay-Capture-Policy-Revision is a different header.)
 */
export type ClientTelemetry = {
  clientVersion: string | null;
  clientPlatform: string | null;
  policyRevisionApplied: number | null;
};

export const POLICY_REVISION_HEADER = "x-agent-relay-policy-revision";
/** A row is rewritten with unchanged values at most this often. */
export const CLIENT_TELEMETRY_REFRESH_MS = 10 * 60 * 1_000;

const MAX_VERSION_LENGTH = 64;
const MAX_PLATFORM_LENGTH = 32;
const MAX_REVISION = 2_147_483_647;
const VERSION_PATTERN = /^[0-9A-Za-z.+-]+$/;
const PLATFORM_PATTERN = /^[a-z0-9_-]+$/;
/** Product token at the start or after whitespace; platform directly after it. */
const USER_AGENT_PATTERN = /(?:^|\s)AgentRelayDesktop\/(\S+)(?:\s+\(([^()]*)\))?/;

function singleHeader(value: string | string[] | undefined): string | null {
  if (typeof value === "string") return value;
  return null;
}

export function parseClientTelemetry(headers: IncomingHttpHeaders): ClientTelemetry {
  let clientVersion: string | null = null;
  let clientPlatform: string | null = null;
  const userAgent = singleHeader(headers["user-agent"]);
  // Bound the work on a hostile header before matching.
  const match = userAgent && userAgent.length <= 512 ? USER_AGENT_PATTERN.exec(userAgent) : null;
  if (match) {
    const version = match[1]!;
    if (version.length <= MAX_VERSION_LENGTH && VERSION_PATTERN.test(version)) clientVersion = version;
    const platform = match[2]?.trim().toLowerCase();
    if (platform && platform.length <= MAX_PLATFORM_LENGTH && PLATFORM_PATTERN.test(platform)) {
      clientPlatform = platform;
    }
  }
  let policyRevisionApplied: number | null = null;
  const revision = singleHeader(headers[POLICY_REVISION_HEADER])?.trim();
  if (revision && /^\d{1,10}$/.test(revision)) {
    const value = Number(revision);
    if (value <= MAX_REVISION) policyRevisionApplied = value;
  }
  return { clientVersion, clientPlatform, policyRevisionApplied };
}

/**
 * Only device-client sessions record telemetry: the device flow, the Desktop
 * browser sign-in's redeemed pair (and its workspace pairs) and enrollment-key
 * exchanges, all of which carry `rth:acquire`. Browser account sessions,
 * unredeemed or original handoffs, and every non-session credential (OAuth,
 * API tokens, staff read grants never reach a Principal) are skipped.
 */
export function recordsClientTelemetry(principal: Principal): boolean {
  return principal.scopes.includes("rth:acquire") &&
    !principal.scopes.includes("account") &&
    !principal.pendingHandoff &&
    !principal.handoff;
}

/**
 * Applies parsed telemetry to a token session row. A null value leaves its
 * column untouched. Nothing is written when every value is null, or when no
 * provided value differs and policy_seen_at is younger than
 * CLIENT_TELEMETRY_REFRESH_MS (the guarded UPDATE matches no row). Returns
 * whether the row was written.
 */
export async function recordClientTelemetry(
  database: SqlExecutor,
  sessionId: string,
  telemetry: ClientTelemetry,
): Promise<boolean> {
  const { clientVersion, clientPlatform, policyRevisionApplied } = telemetry;
  if (clientVersion === null && clientPlatform === null && policyRevisionApplied === null) return false;
  const result = await database.query<{ id: string }>(
    `UPDATE token_sessions
        SET client_version = COALESCE($2::text, client_version),
            client_platform = COALESCE($3::text, client_platform),
            policy_revision_applied = COALESCE($4::integer, policy_revision_applied),
            policy_seen_at = now(),
            updated_at = now()
      WHERE id = $1
        AND revoked_at IS NULL
        AND (
          ($2::text IS NOT NULL AND client_version IS DISTINCT FROM $2::text)
          OR ($3::text IS NOT NULL AND client_platform IS DISTINCT FROM $3::text)
          OR ($4::integer IS NOT NULL AND policy_revision_applied IS DISTINCT FROM $4::integer)
          OR policy_seen_at IS NULL
          OR policy_seen_at <= now() - ($5::integer * interval '1 millisecond')
        )
      RETURNING id`,
    [sessionId, clientVersion, clientPlatform, policyRevisionApplied, CLIENT_TELEMETRY_REFRESH_MS],
  );
  return result.rows.length === 1;
}
