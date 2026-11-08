// analytics lane: the PostHog adapter (hosted only; configured explicitly, no
// default host or key). It follows PostHog's own /batch/ contract, so any 2xx
// is success here; the collector's 204-only rule does not apply.
import type { AnalyticsEnvelope, AnalyticsSink, SinkResult } from "../types.js";
import { parseRetryAfter } from "../retry.js";

export type PosthogSinkOptions = { host: string; projectKey: string; fetch?: typeof fetch };

export function classifyPosthogStatus(status: number, retryAfter: string | null): SinkResult {
  if (status >= 200 && status < 300) return { outcome: "accepted" };
  if (status >= 300 && status < 400) return { outcome: "redirect", status };
  if (status === 401 || status === 403) return { outcome: "auth", status };
  if (status === 413) return { outcome: "oversize", status };
  if (status === 408) return { outcome: "retry", reason: "timeout", status };
  if (status === 429 || status === 503) {
    return { outcome: "retry", reason: "backpressure", status, retryAfterMs: parseRetryAfter(retryAfter) };
  }
  if (status >= 500 && status < 600) return { outcome: "retry", reason: "server", status };
  if (status >= 400 && status < 500) return { outcome: "rejected", status };
  return { outcome: "protocol", status };
}

export function createPosthogSink(options: PosthogSinkOptions): AnalyticsSink {
  const endpoint = new URL("/batch/", options.host).toString();
  // Held only in this closure; never logged or described.
  const apiKey = options.projectKey;
  const doFetch = options.fetch ?? fetch;
  return {
    name: "posthog",
    async send(events: AnalyticsEnvelope[], signal: AbortSignal): Promise<SinkResult> {
      const body = JSON.stringify({
        api_key: apiKey,
        batch: events.map((event) => ({
          event: event.event,
          uuid: event.event_id,
          timestamp: event.occurred_at,
          distinct_id: event.deployment_id,
          properties: {
            ...event.properties,
            component: event.component,
            trace_id: event.trace_id,
            ...(event.tenant_id ? { tenant_id: event.tenant_id } : {}),
            ...(event.workspace_id ? { workspace_id: event.workspace_id } : {}),
            $process_person_profile: false,
          },
        })),
      });
      try {
        const response = await doFetch(endpoint, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body,
          redirect: "manual",
          signal,
        });
        await response.body?.cancel().catch(() => undefined);
        return classifyPosthogStatus(response.status, response.headers.get("retry-after"));
      } catch {
        return { outcome: "retry", reason: signal.aborted ? "timeout" : "transport" };
      }
    },
  };
}
