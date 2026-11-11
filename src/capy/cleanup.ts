import type { Database } from "../database.js";
import type { CapyBindings } from "./bindings.js";

export const CAPY_CLEANUP_INTERVAL_MS=30_000;
const BATCH=5;

/** Cleanup-only: never registers an agent or calls Capy. Independent of runtime
 * enablement. Exact-id release is idempotent across replicas; binding generation
 * and immutable identity checks remain in CapyBindings.cleanup, not this scan.
 */
export class CapyCleanup {
  private timer: ReturnType<typeof setInterval> | null=null;
  private busy: Promise<void> | null=null;
  private stopped=false;
  constructor(private readonly deps:{
    database:Database;
    bindings:Pick<CapyBindings,"cleanup">;
    now?:()=>Date;
    log?:(event:{code:"capy_cleanup_scan_failed"})=>void;
  }) {}

  tick():Promise<void> {
    if (this.stopped) return Promise.resolve();
    if (this.busy) return this.busy;
    this.busy=this.run().finally(()=>{this.busy=null;});
    return this.busy;
  }

  private async run():Promise<void> {
    try {
      // cleanup() refreshes updated_at on every inconclusive attempt. A fixed
      // backoff prevents a moved route or unknown registration from hot-looping.
      const cutoff=new Date((this.deps.now?.() ?? new Date()).getTime()-CAPY_CLEANUP_INTERVAL_MS);
      const rows=await this.deps.database.query<{id:string}>(`SELECT id FROM capy_bindings
        WHERE state='retired' AND cleanup_pending AND updated_at <= $1
        ORDER BY updated_at,id LIMIT $2`,[cutoff,BATCH]);
      for (const row of rows.rows) {
        if (this.stopped) break;
        await this.deps.bindings.cleanup(row.id);
      }
    } catch { this.deps.log?.({code:"capy_cleanup_scan_failed"}); }
  }

  start():void {
    if (this.timer || this.stopped) return;
    this.timer=setInterval(()=>{void this.tick();},CAPY_CLEANUP_INTERVAL_MS);
    this.timer.unref();
    void this.tick();
  }

  async stop():Promise<void> {
    this.stopped=true;
    if (this.timer) clearInterval(this.timer);
    this.timer=null;
    await this.busy;
  }
}

/** Bound actual native I/O as well as the service's caller wait. */
export function capyCleanupFetch(upstream:typeof fetch=fetch):typeof fetch {
  return (input,init)=>{
    const previous=init?.signal ?? (input instanceof Request ? input.signal : null);
    const timeout=AbortSignal.timeout(10_000);
    return upstream(input,{...init,signal:previous ? AbortSignal.any([previous,timeout]) : timeout});
  };
}
