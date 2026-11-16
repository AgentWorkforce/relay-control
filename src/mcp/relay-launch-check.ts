import { recordAudit } from "../admin/audit.js";
import type { SqlExecutor } from "../database.js";
import type { ControlPlaneStore } from "../store.js";

/**
 * Pre-spawn relaygate check for gate-only installs
 * (SELFHOST_RELAYGATE_PUBLIC_URL set; docs/identity.md, "Launch check").
 *
 * Before spawn_relay_agent reserves a journal row, mints the `sh_lt_` launch
 * credential or sends anything to Relaycast, Control asks relaygate whether
 * the launching person may write this task to the target node:
 *
 *   POST <relaygate>/v1/check
 *   {"op":"w","resource":{"kind":"stream","id":"node:<workspace>/<node>"},"content":<task>}
 *
 * The MCP caller's own credential may be an OAuth grant or an API key, so
 * Control mints a one-use `sh_at_` for the launching person (60 s, no
 * scopes: relaygate's check needs none, and a scopeless token is useless
 * elsewhere while a cached introspection outlives the revoke), presents it
 * once and revokes it right after, whatever the answer. Neither that token nor the task text is ever logged or audited.
 */
export const RELAY_LAUNCH_CHECK_TIMEOUT_MS = 5_000;

export type RelayLaunchCheckOutcome =
  | { decision: "allow" }
  | { decision: "deny"; code: "relaygate_denied" | "relaygate_classified" }
  | { decision: "unavailable" };

export type RelayLaunchCheckInput = {
  /** The launching user. */
  userId: string;
  organizationId: string;
  workspaceId: string;
  /** The target node's name, as relaygate's stream id names it. */
  nodeName: string;
  /** The exact task text the caller passed; sent unaltered. */
  task: string;
};

export interface RelayLaunchCheck {
  check(input: RelayLaunchCheckInput): Promise<RelayLaunchCheckOutcome>;
}

type LaunchCheckLog = (message: string, fields: { status: number | null; outcome: string; nodeName: string }) => void;

export function relayLaunchCheck(deps: {
  relaygatePublicUrl: string;
  store: Pick<ControlPlaneStore, "issueLaunchCheckSession" | "revoke">;
  /** Where `relay_launch.check.*` audit rows go. */
  database: SqlExecutor;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  log?: LaunchCheckLog;
}): RelayLaunchCheck {
  const endpoint = `${deps.relaygatePublicUrl.replace(/\/+$/, "")}/v1/check`;
  const fetchImpl = deps.fetchImpl ?? fetch;
  const log: LaunchCheckLog = deps.log ?? ((message, fields) => console.warn(message, fields));

  async function ask(token: string, input: RelayLaunchCheckInput): Promise<{ status: number | null; outcome: RelayLaunchCheckOutcome }> {
    let response: Response;
    try {
      response = await fetchImpl(endpoint, {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "application/json", accept: "application/json" },
        body: JSON.stringify({
          op: "w",
          resource: { kind: "stream", id: `node:${input.workspaceId}/${input.nodeName}` },
          content: input.task,
        }),
        signal: AbortSignal.timeout(deps.timeoutMs ?? RELAY_LAUNCH_CHECK_TIMEOUT_MS),
      });
    } catch {
      return { status: null, outcome: { decision: "unavailable" } };
    }
    let body: Record<string, unknown> | null = null;
    try {
      const parsed: unknown = JSON.parse(await response.text());
      if (typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)) body = parsed as Record<string, unknown>;
    } catch {
      body = null;
    }
    const status = response.status;
    if (status === 200) {
      return { status, outcome: body?.decision === "allow" ? { decision: "allow" } : { decision: "unavailable" } };
    }
    if (status === 403) {
      return { status, outcome: { decision: "deny",
        code: body?.error === "relaygate_classified" ? "relaygate_classified" : "relaygate_denied" } };
    }
    return { status, outcome: { decision: "unavailable" } };
  }

  async function audit(input: RelayLaunchCheckInput, outcome: RelayLaunchCheckOutcome, status: number | null): Promise<void> {
    if (outcome.decision === "allow") return;
    try {
      await recordAudit(deps.database, {
        organizationId: input.organizationId,
        workspaceId: input.workspaceId,
        actor: { kind: "user", userId: input.userId },
        action: outcome.decision === "deny" ? "relay_launch.check.denied" : "relay_launch.check.unavailable",
        target: outcome.decision === "deny"
          ? `node=${input.nodeName} code=${outcome.code}`
          : `node=${input.nodeName} status=${status ?? "none"}`,
      });
    } catch {
      log("[selfhost-mcp] relay launch check audit failed", { status, outcome: outcome.decision, nodeName: input.nodeName });
    }
  }

  return {
    async check(input) {
      let token: string | null = null;
      let status: number | null = null;
      let outcome: RelayLaunchCheckOutcome = { decision: "unavailable" };
      try {
        token = (await deps.store.issueLaunchCheckSession({
          userId: input.userId, organizationId: input.organizationId, workspaceId: input.workspaceId,
        })).accessToken;
        ({ status, outcome } = await ask(token, input));
      } catch {
        outcome = { decision: "unavailable" };
      } finally {
        if (token) await deps.store.revoke(token).catch(() => false);
      }
      if (outcome.decision !== "allow") {
        log("[selfhost-mcp] relay launch check refused", { status, outcome: outcome.decision === "deny" ? outcome.code : "unavailable",
          nodeName: input.nodeName });
      }
      await audit(input, outcome, status);
      return outcome;
    },
  };
}
