// telemetry lane: cheap in-memory aggregation between flushes. Nothing here
// holds request bodies, headers, query strings, or error messages.
import type { CounterDelta, ErrorDelta } from "./store.js";
import { errorFingerprint, routeTemplate } from "./identity.js";

/** Feature area for a request path (usage per area). */
export function featureArea(path: string): string {
  const normalized = path.startsWith("/cloud/api/") ? path.slice("/cloud".length) : path;
  if (normalized === "/login" || normalized.startsWith("/login/")) return "login";
  if (normalized.startsWith("/internal/")) return "internal";
  const match = /^\/api\/v1\/(?:workspaces\/[^/]+\/)?([a-z-]+)/.exec(normalized);
  if (!match) return normalized.startsWith("/cloud/api") ? "dashboard" : "other";
  const head = match[1]!;
  const aliases: Record<string, string> = {
    auth: "device-login",
    relayhistory: "history",
    "deployment-api-tokens": "api-tokens",
    secrets: "env-vars",
  };
  return aliases[head] ?? head;
}

export type ObservedError = {
  component: string;
  route: string;
  status: number;
  errorClass: string;
  fingerprint: string;
};

export function describeError(
  error: unknown,
  context: { component: string; path: string; status: number },
): ObservedError {
  const errorClass = error instanceof Error
    ? (error.constructor?.name || error.name || "Error").slice(0, 64)
    : typeof error;
  const code = error && typeof error === "object" && "code" in error
    ? String((error as { code: unknown }).code).slice(0, 64)
    : null;
  const stack = error instanceof Error ? error.stack ?? null : null;
  const route = routeTemplate(context.path);
  return {
    component: context.component,
    route,
    status: context.status,
    errorClass: code && /^[A-Za-z0-9_.-]+$/.test(code) ? `${errorClass}:${code}` : errorClass,
    fingerprint: errorFingerprint({ component: context.component, errorClass, code, stack }),
  };
}

export class TelemetryAggregator {
  #counters = new Map<string, number>();
  #errors = new Map<string, ErrorDelta>();
  /** fingerprint|component -> timestamps (ms) within the burst window */
  #recent = new Map<string, number[]>();

  constructor(
    private readonly options: { burstThreshold: number; burstWindowSeconds: number },
  ) {}

  count(area: string, metric: string, value = 1): void {
    const key = `${area}\u0000${metric}`;
    this.#counters.set(key, (this.#counters.get(key) ?? 0) + value);
  }

  /** Returns true when this error just crossed the burst threshold. */
  error(observed: ObservedError, now = Date.now()): boolean {
    const key = [observed.fingerprint, observed.component, observed.route, observed.status, observed.errorClass].join("\u0000");
    const at = new Date(now).toISOString();
    const existing = this.#errors.get(key);
    if (existing) {
      existing.count += 1;
      existing.lastSeen = at;
    } else {
      this.#errors.set(key, {
        fingerprint: observed.fingerprint,
        component: observed.component,
        route: observed.route,
        status: observed.status,
        errorClass: observed.errorClass,
        count: 1,
        firstSeen: at,
        lastSeen: at,
      });
    }
    const burstKey = `${observed.fingerprint}\u0000${observed.component}`;
    const cutoff = now - this.options.burstWindowSeconds * 1000;
    const recent = (this.#recent.get(burstKey) ?? []).filter((time) => time >= cutoff);
    recent.push(now);
    this.#recent.set(burstKey, recent.slice(-this.options.burstThreshold * 2));
    return recent.length === this.options.burstThreshold;
  }

  recentCount(fingerprint: string, component: string, now = Date.now()): { count: number; since: string | null } {
    const cutoff = now - this.options.burstWindowSeconds * 1000;
    const recent = (this.#recent.get(`${fingerprint}\u0000${component}`) ?? []).filter((time) => time >= cutoff);
    return { count: recent.length, since: recent[0] ? new Date(recent[0]).toISOString() : null };
  }

  drain(): { counters: CounterDelta[]; errors: ErrorDelta[] } {
    const counters = [...this.#counters].map(([key, value]) => {
      const [area, metric] = key.split("\u0000") as [string, string];
      return { area, metric, value };
    });
    const errors = [...this.#errors.values()];
    this.#counters = new Map();
    this.#errors = new Map();
    return { counters, errors };
  }

  /** Put drained deltas back (flush failed; keep them for the next attempt). */
  restore(deltas: { counters: CounterDelta[]; errors: ErrorDelta[] }): void {
    for (const counter of deltas.counters) this.count(counter.area, counter.metric, counter.value);
    for (const error of deltas.errors) {
      const key = [error.fingerprint, error.component, error.route, error.status, error.errorClass].join("\u0000");
      const existing = this.#errors.get(key);
      if (existing) {
        existing.count += error.count;
        if (error.firstSeen < existing.firstSeen) existing.firstSeen = error.firstSeen;
      } else {
        this.#errors.set(key, { ...error });
      }
    }
  }
}
