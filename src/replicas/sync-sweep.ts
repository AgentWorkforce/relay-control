import { syncEnvironments } from "./environments.js";
import { abandonStaleBindings, retirePendingCleanup, type ReplicasActor, type ReplicasDeps } from "./service.js";

export const REPLICAS_SYNC_SERVICE = "replicas-sync";

export type ReplicasSyncLog = (event: {
  code: "replicas_sync_failed" | "replicas_sync_scan_failed" | "replicas_cleanup_failed" | "replicas_cleanup_scan_failed";
  workspaceId?: string;
  spawnId?: string;
}) => void;

/**
 * Periodic environment sync: the semantics of `POST
 * /replicas/environments/sync` for every Replicas connection whose
 * all-environments default is on (no settings row = on). Runs once at start,
 * then every interval; a run never overlaps the previous one. A failing
 * connection is logged and the sweep moves on. It acts as a service, never as
 * a person, and never sets or infers the VM principal. Like every sync, it
 * never re-sends a create whose earlier outcome is unconfirmed. After the
 * sync it retries incomplete remote cleanup of gone bindings for every
 * Replicas connection (whatever its default), with per-row backoff, and
 * abandons launches and binds stuck for 7 days without a relay identity.
 */
export class ReplicasSyncSweep {
  private timer: ReturnType<typeof setInterval> | null = null;
  private busy: Promise<void> | null = null;
  private stopped = false;

  constructor(private readonly deps: { replicas: ReplicasDeps; intervalSeconds: number; log?: ReplicasSyncLog }) {}

  /** Runs one sweep; while one is running, returns that run instead of starting another. */
  tick(): Promise<void> {
    if (this.stopped) return Promise.resolve();
    if (this.busy) return this.busy;
    this.busy = this.run().finally(() => { this.busy = null; });
    return this.busy;
  }

  private async run(): Promise<void> {
    await this.sync();
    await this.cleanup();
  }

  private actor(target: { workspace_id: string; organization_id: string }): ReplicasActor {
    return { userId: "", workspaceId: target.workspace_id, organizationId: target.organization_id, service: REPLICAS_SYNC_SERVICE };
  }

  private async cleanup(): Promise<void> {
    let targets: Array<{ workspace_id: string; organization_id: string }>;
    try {
      targets = (await this.deps.replicas.database.query<{ workspace_id: string; organization_id: string }>(
        `SELECT c.workspace_id, w.organization_id
           FROM remote_agent_connections c
           JOIN workspaces w ON w.id = c.workspace_id
          WHERE c.provider = 'replicas'
          ORDER BY c.workspace_id`,
      )).rows;
    } catch {
      this.deps.log?.({ code: "replicas_cleanup_scan_failed" });
      return;
    }
    for (const target of targets) {
      if (this.stopped) break;
      try {
        await retirePendingCleanup(this.deps.replicas, this.actor(target),
          (spawnId) => this.deps.log?.({ code: "replicas_cleanup_failed", workspaceId: target.workspace_id, spawnId }));
        // Launches and binds that never got a relay identity: abandoned after 7 days.
        await abandonStaleBindings(this.deps.replicas, this.actor(target));
      } catch {
        this.deps.log?.({ code: "replicas_cleanup_scan_failed", workspaceId: target.workspace_id });
      }
    }
  }

  private async sync(): Promise<void> {
    let targets: Array<{ workspace_id: string; organization_id: string }>;
    try {
      targets = (await this.deps.replicas.database.query<{ workspace_id: string; organization_id: string }>(
        `SELECT c.workspace_id, w.organization_id
           FROM remote_agent_connections c
           JOIN workspaces w ON w.id = c.workspace_id
           LEFT JOIN replica_environment_settings s ON s.workspace_id = c.workspace_id
          WHERE c.provider = 'replicas' AND COALESCE(s.all_environments, true)
          ORDER BY c.workspace_id`,
      )).rows;
    } catch {
      this.deps.log?.({ code: "replicas_sync_scan_failed" });
      return;
    }
    for (const target of targets) {
      if (this.stopped) break;
      try {
        await syncEnvironments(this.deps.replicas, this.actor(target));
      } catch {
        this.deps.log?.({ code: "replicas_sync_failed", workspaceId: target.workspace_id });
      }
    }
  }

  /** Starts the sweep (no-op when the interval is 0 or it was stopped). */
  start(): void {
    if (this.timer || this.stopped || this.deps.intervalSeconds <= 0) return;
    this.timer = setInterval(() => { void this.tick(); }, this.deps.intervalSeconds * 1000);
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
