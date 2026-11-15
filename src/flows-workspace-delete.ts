import type { SelfhostConfig } from "./config.js";
import type { Database } from "./database.js";

export const FLOWS_DELETE_INTERVAL_MS = 30_000;
const BATCH = 10;
const BASE_BACKOFF_MS = 30_000;
const MAX_BACKOFF_MS = 60 * 60_000;
// A claimed row is invisible to other replicas for this long; the remote delete is idempotent.
const LEASE_MS = 2 * 60_000;
const TIMEOUT_MS = 10_000;

type Endpoint = NonNullable<SelfhostConfig["flowsWorkspaceDelete"]>;

export type FlowsDeleteEvent = {
  code: "flows_workspace_delete_refused" | "flows_workspace_delete_deferred" | "flows_workspace_delete_scan_failed";
  workspaceId?: string;
  status?: number;
  attempts?: number;
};

/** The delay before attempt n+1, after n failures: 30 s doubling to 1 h. */
export function flowsDeleteBackoffMs(attempts: number): number {
  return Math.min(MAX_BACKOFF_MS, BASE_BACKOFF_MS * 2 ** Math.min(Math.max(attempts - 1, 0), 20));
}

/**
 * Sends queued workspace deletes to relayfile-control's
 * DELETE /internal/v1/flows/workspaces/{id}. 200 and 404 (Flows off there,
 * nothing held) complete the row. Every other answer keeps it and backs off:
 * a refusal is a configuration fault, never a reason to drop deleted data.
 */
export class FlowsWorkspaceDeletions {
  private timer: ReturnType<typeof setInterval> | null = null;
  private busy: Promise<void> | null = null;
  private stopped = false;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => Date;

  constructor(private readonly deps: {
    database: Database;
    endpoint: Endpoint;
    fetchImpl?: typeof fetch;
    now?: () => Date;
    log?: (event: FlowsDeleteEvent) => void;
  }) {
    this.fetchImpl = deps.fetchImpl ?? fetch;
    this.now = deps.now ?? (() => new Date());
  }

  tick(): Promise<void> {
    if (this.stopped) return Promise.resolve();
    if (this.busy) return this.busy;
    this.busy = this.run().finally(() => { this.busy = null; });
    return this.busy;
  }

  private async run(): Promise<void> {
    let rows: Array<{ workspace_id: string; attempts: number }>;
    try {
      const now = this.now();
      rows = (await this.deps.database.query<{ workspace_id: string; attempts: number }>(
        `UPDATE flows_workspace_deletions SET next_attempt_at = $2
          WHERE workspace_id IN (SELECT workspace_id FROM flows_workspace_deletions
            WHERE next_attempt_at <= $1 ORDER BY next_attempt_at, workspace_id LIMIT $3 FOR UPDATE SKIP LOCKED)
          RETURNING workspace_id, attempts`,
        [now, new Date(now.getTime() + LEASE_MS), BATCH],
      )).rows;
    } catch {
      this.deps.log?.({ code: "flows_workspace_delete_scan_failed" });
      return;
    }
    for (const row of rows) {
      if (this.stopped) break;
      await this.deliver(row.workspace_id, row.attempts);
    }
  }

  private async deliver(workspaceId: string, attempts: number): Promise<void> {
    let status = 0;
    try {
      const url = new URL(`/internal/v1/flows/workspaces/${encodeURIComponent(workspaceId)}`, this.deps.endpoint.url);
      const response = await this.fetchImpl(url, {
        method: "DELETE",
        headers: { authorization: `Bearer ${this.deps.endpoint.secret}` },
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      status = response.status;
      await response.body?.cancel().catch(() => undefined);
    } catch {
      // Network failure or timeout: status stays 0.
    }
    try {
      if (status === 200 || status === 404) {
        await this.deps.database.query("DELETE FROM flows_workspace_deletions WHERE workspace_id = $1", [workspaceId]);
        return;
      }
      const failures = attempts + 1;
      const refused = status >= 400 && status < 500;
      await this.deps.database.query(
        "UPDATE flows_workspace_deletions SET attempts = $2, next_attempt_at = $3, last_error = $4 WHERE workspace_id = $1",
        [workspaceId, failures, new Date(this.now().getTime() + flowsDeleteBackoffMs(failures)),
          status ? `http_${status}` : "unreachable"],
      );
      this.deps.log?.({
        code: refused ? "flows_workspace_delete_refused" : "flows_workspace_delete_deferred",
        workspaceId, ...(status ? { status } : {}), attempts: failures,
      });
    } catch {
      // The lease expires and the row is retried.
      this.deps.log?.({ code: "flows_workspace_delete_scan_failed", workspaceId });
    }
  }

  start(): void {
    if (this.timer || this.stopped) return;
    this.timer = setInterval(() => { void this.tick(); }, FLOWS_DELETE_INTERVAL_MS);
    this.timer.unref();
    void this.tick();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    await this.busy;
  }
}
