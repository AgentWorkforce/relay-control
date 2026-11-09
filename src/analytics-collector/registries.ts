// Closed collector vocabularies. These do not add client-gateway kinds: every
// service still needs its own token bound to its component and deployment.
import { EVENT_REGISTRY, type PropertySpec } from "../analytics/events.js";
import type { CollectorRegistries } from "./validate.js";

// Sessions producer contract: relayhistory-pipeline src/shared/analytics.ts at
// c8c892feb8bfc87aec6898cd4c4a0db816b0e595. A vocabulary change needs review
// in both repositories; request paths and session content are never properties.
const LATENCY: PropertySpec = {
  type: "enum",
  values: ["lt_100ms", "lt_250ms", "lt_500ms", "lt_1s", "lt_2500ms", "lt_5s", "lt_30s", "ge_30s"],
};
const COUNT: PropertySpec = { type: "integer", min: 0, max: 1_000_000 };

export const COLLECTOR_REGISTRIES: CollectorRegistries = {
  relaycontrol: EVENT_REGISTRY,
  "session-ingest": {
    "session_ingest.batch_completed": {
      scope: "workspace",
      properties: {
        route: { type: "enum", values: ["delivery", "turns"] },
        outcome: {
          type: "enum",
          values: ["accepted", "replay", "rejected", "conflict", "too_large", "unauthorized", "busy", "unavailable"],
        },
        record_count: COUNT,
        latency_bucket: LATENCY,
      },
    },
  },
  "session-read-api": {
    "session_read.request_completed": {
      scope: "workspace",
      properties: {
        route: {
          type: "enum",
          values: [
            "/v1/events", "/v1/sessions", "/v1/sessions/activity", "/v1/sessions/output", "/v1/sessions/titles",
            "/v1/sessions/:sessionId/events", "/v1/sessions/:sessionId/timing", "/v1/sessions/:sessionId/turns",
            "/v1/sessions/:sessionId/metadata", "/v1/sessions/:sessionId/summary", "/v1/sessions/:sessionId/catalog",
            "/v1/digest/daily", "/v1/delivery/records", "other",
          ],
        },
        outcome: {
          type: "enum",
          values: ["served", "invalid", "unauthorized", "forbidden", "not_found", "busy", "unsupported", "unavailable", "other"],
        },
        status_class: { type: "enum", values: ["1xx", "2xx", "3xx", "4xx", "5xx", "other"] },
        latency_bucket: LATENCY,
      },
    },
  },
  "session-pipeline-consumer": {
    "session_pipeline.index_tick_completed": {
      scope: "installation",
      properties: {
        collected: COUNT,
        failed: COUNT,
        requeued: COUNT,
        stale: COUNT,
        tombstoned: COUNT,
        complete: { type: "boolean" },
        latency_bucket: LATENCY,
      },
    },
  },
};
