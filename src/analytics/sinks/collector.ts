// analytics lane: the collector adapter. POST to COLLECTOR_URL (the complete
// endpoint URL, including /v1/events; nothing is appended) with exactly one
// bearer header, per infra docs/analytics-collector-interface.md, infra #84
// @62599fb as amended by infra #85 @ca91118 (merged 91c9b79). 204 is the only acceptance; any
// other 2xx is a protocol error. Redirects are never followed.
//
// node:http(s) rather than global fetch: fetch cannot take an installation CA
// bundle without a dispatcher dependency. With a CA bundle, node:https uses it
// INSTEAD of the system roots for this sink only, pinning the collector to the
// installation CA; hostname verification stays on.
import { Agent as HttpAgent, request as httpRequest } from "node:http";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import {
  ANALYTICS_BATCH_SCHEMA,
  type AnalyticsBatch,
  type AnalyticsEnvelope,
  type AnalyticsSink,
  type SinkResult,
} from "../types.js";
import { parseRetryAfter } from "../retry.js";

/** Status handling from the contract's response table (with 404/408/422 per design D4). */
export function classifyCollectorStatus(status: number, retryAfter: string | null): SinkResult {
  if (status === 204) return { outcome: "accepted" };
  if (status >= 200 && status < 300) return { outcome: "protocol", status };
  if (status >= 300 && status < 400) return { outcome: "redirect", status };
  if (status === 401 || status === 403) return { outcome: "auth", status };
  if (status === 413) return { outcome: "oversize", status };
  if (status === 408) return { outcome: "retry", reason: "timeout", status };
  if (status === 429 || status === 503) {
    return { outcome: "retry", reason: "backpressure", status, retryAfterMs: parseRetryAfter(retryAfter) };
  }
  if (status === 507) {
    return { outcome: "retry", reason: "storage", status, retryAfterMs: parseRetryAfter(retryAfter) };
  }
  if (status >= 500 && status < 600) return { outcome: "retry", reason: "server", status };
  if (status >= 400 && status < 500) return { outcome: "rejected", status };
  return { outcome: "protocol", status };
}

export type CollectorSinkOptions = {
  /** Complete endpoint URL, including /v1/events; used as-is. */
  url: string;
  token: string;
  /** PEM bundle that replaces the system roots for this sink's TLS verification. */
  ca?: string | null;
};

type TransportResponse = { status: number; retryAfter: string | null };

export function createCollectorSink(options: CollectorSinkOptions): AnalyticsSink {
  const endpoint = new URL(options.url);
  const secure = endpoint.protocol === "https:";
  // Held only in this closure; never logged.
  const authorization = `Bearer ${options.token}`;
  const agent = secure
    ? new HttpsAgent({ keepAlive: true, maxSockets: 1, ...(options.ca ? { ca: options.ca } : {}) })
    : new HttpAgent({ keepAlive: true, maxSockets: 1 });

  function post(body: string, signal: AbortSignal): Promise<TransportResponse> {
    return new Promise((resolve, reject) => {
      const send = secure ? httpsRequest : httpRequest;
      const request = send(endpoint, {
        method: "POST",
        agent,
        signal,
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
          authorization,
        },
      }, (response) => {
        // The body is never read for content: error responses carry only a code.
        response.resume();
        response.on("end", () => resolve({
          status: response.statusCode ?? 0,
          retryAfter: typeof response.headers["retry-after"] === "string"
            ? response.headers["retry-after"]
            : null,
        }));
        response.on("error", reject);
      });
      request.on("error", reject);
      request.end(body);
    });
  }

  return {
    name: "collector",
    async send(events: AnalyticsEnvelope[], signal: AbortSignal): Promise<SinkResult> {
      const batch: AnalyticsBatch = { schema: ANALYTICS_BATCH_SCHEMA, events };
      try {
        const response = await post(JSON.stringify(batch), signal);
        return classifyCollectorStatus(response.status, response.retryAfter);
      } catch {
        return { outcome: "retry", reason: signal.aborted ? "timeout" : "transport" };
      }
    },
  };
}
