import { claimNext, processClaim, recoverInbox, sweep, type InboxCursor } from "./delivery.js";
import { historyPass } from "./history.js";
import { releaseRetired, type AmpDeps } from "./service.js";

export type AmpWorker = {
  /**
   * One pass: expire leases, recover missed messages from hosted inboxes,
   * inject due deliveries, retry pending releases, then history (schedule and
   * a few leased runs, or only the blocked reason when no push session exists).
   */
  tick(): Promise<void>;
  /** Schedules an immediate pass (after a relay event queued a delivery). */
  wake(): void;
  stop(): Promise<void>;
};

const MAX_PER_TICK = 25;

/**
 * In-process outbox drain. The timer is unref'd so it never holds the process
 * open; leases and FOR UPDATE SKIP LOCKED make several replicas safe.
 */
export function startAmpWorker(deps: AmpDeps, intervalMs: number): AmpWorker {
  let running: Promise<void> | null = null;
  let again = false;
  let stopped = false;
  // Round-robin position over bound bindings: each pass polls the next few
  // inboxes, so every binding is visited in turn (oldest-polled first).
  const cursor: InboxCursor = { after: null };

  const pass = async () => {
    await sweep(deps);
    // Per-binding failures are contained and logged inside recoverInbox; the
    // drain below injects whatever it queued in this same pass.
    if (!stopped) await recoverInbox(deps, cursor);
    for (let index = 0; index < MAX_PER_TICK && !stopped; index += 1) {
      const claim = await claimNext(deps);
      if (!claim) break;
      await processClaim(deps, claim);
    }
    const retired = await deps.database.query<{ id: string }>(
      "SELECT id FROM selfhost_amp_bindings WHERE state = 'retired' ORDER BY updated_at LIMIT 10",
    );
    for (const row of retired.rows) {
      if (stopped) break;
      await releaseRetired(deps, row.id);
    }
    // History last: a slow export never delays message delivery. Failures are
    // contained per binding inside runHistory.
    if (!stopped) await historyPass(deps, () => stopped);
  };

  const tick = (): Promise<void> => {
    if (running) {
      again = true;
      return running;
    }
    running = (async () => {
      do {
        again = false;
        try {
          await pass();
        } catch (error) {
          console.warn("[amp] worker_pass_failed", { error: error instanceof Error ? error.name : "unknown" });
        }
      } while (again && !stopped);
    })().finally(() => {
      running = null;
    });
    return running;
  };

  const timer = setInterval(() => void tick(), intervalMs);
  timer.unref();
  return {
    tick,
    wake: () => {
      if (!stopped) setImmediate(() => void tick());
    },
    async stop() {
      stopped = true;
      clearInterval(timer);
      await running;
    },
  };
}
