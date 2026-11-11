import { recoverStalledWakes, type EventsShimStore } from "@agent-relay/events-shim";

export const EVENTS_SHIM_SWEEP_INTERVAL_MS = 60_000;

/**
 * Re-drains webhook inboxes whose posts a temporary Relaycast failure left
 * pending (`recoverStalledWakes`), so an idle agent still gets woken when no
 * new post arrives. Runs only while the events_shim feature is on. One sweep
 * at a time; overlapping ticks share the running one.
 */
export class EventsShimWakeSweeper {
  private timer: ReturnType<typeof setInterval> | null = null;
  private busy: Promise<void> | null = null;
  private stopped = false;

  constructor(private readonly deps: {
    store: EventsShimStore;
    fetchImpl?: typeof fetch;
    now?: () => Date;
    intervalMs?: number;
    log?: (event: { code: "events_shim_wake_sweep_failed" }) => void;
  }) {}

  tick(): Promise<void> {
    if (this.stopped) return Promise.resolve();
    if (this.busy) return this.busy;
    this.busy = this.run().finally(() => { this.busy = null; });
    return this.busy;
  }

  private async run(): Promise<void> {
    try {
      await recoverStalledWakes({
        store: this.deps.store,
        ...(this.deps.fetchImpl ? { fetchImpl: this.deps.fetchImpl } : {}),
        ...(this.deps.now ? { now: this.deps.now } : {}),
      });
    } catch {
      this.deps.log?.({ code: "events_shim_wake_sweep_failed" });
    }
  }

  start(): void {
    if (this.timer || this.stopped) return;
    this.timer = setInterval(() => { void this.tick(); }, this.deps.intervalMs ?? EVENTS_SHIM_SWEEP_INTERVAL_MS);
    this.timer.unref();
  }

  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
    await this.busy;
  }
}
