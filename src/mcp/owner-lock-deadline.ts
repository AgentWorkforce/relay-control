import { AsyncLocalStorage } from "node:async_hooks";

/** Total time Relaycast and relaygate calls may take while one hosted-MCP owner lock is held. */
export const OWNER_LOCK_RELAY_BUDGET_MS = 10_000;

const held = new AsyncLocalStorage<{ since: number }>();

/**
 * Runs `work` as holding the owner lock: ownerLockFetch bounds its remote
 * calls to one shared budget counted from now. Call it only once the locks are
 * held, so time spent waiting for them does not count. A nested call keeps the
 * outer budget.
 */
export function underOwnerLock<T>(work: () => Promise<T>): Promise<T> {
  return held.getStore() ? work() : held.run({ since: performance.now() }, work);
}

/**
 * The hosted-MCP clients' fetch. A call made under the owner lock gets what is
 * left of the lock's budget as a deadline, composed with the caller's own
 * signal; once the budget is spent it is rejected without being sent. Every
 * other call (sends, inbox reads, launches) passes through unchanged.
 */
export function ownerLockFetch(upstream: typeof fetch = fetch, timeoutMs = OWNER_LOCK_RELAY_BUDGET_MS): typeof fetch {
  return (input, init) => {
    const lock = held.getStore();
    if (!lock) return upstream(input, init);
    const remaining = timeoutMs - (performance.now() - lock.since);
    if (remaining <= 0) {
      return Promise.reject(new DOMException("The owner lock's relay time budget is spent.", "TimeoutError"));
    }
    const prior = init?.signal ?? (input instanceof Request ? input.signal : null);
    // AbortSignal.timeout takes whole milliseconds only.
    const timeout = AbortSignal.timeout(Math.ceil(remaining));
    return upstream(input, { ...init, signal: prior ? AbortSignal.any([prior, timeout]) : timeout });
  };
}
