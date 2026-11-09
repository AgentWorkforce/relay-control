// analytics collector: whole-batch validation (design §3 steps 5-8). The
// first problem wins and nothing is written; per-event problems carry the
// event's index. Errors carry only a stable code: never event content.
import {
  OPAQUE_ID,
  propertyValue,
  RESERVED_FIELDS,
  TRACE_ID,
  UUID_VALUE,
  type EventSpec,
} from "../analytics/events.js";
import { ANALYTICS_BATCH_SCHEMA, type AnalyticsPropertyValue } from "../analytics/types.js";
import type { Producer } from "./producers.js";

/** Event kinds per component. The CLI wires `relaycontrol` → EVENT_REGISTRY. */
export type CollectorRegistries = Readonly<Record<string, Readonly<Record<string, EventSpec>>>>;

export type RejectionCode = "invalid_batch" | "forbidden" | "event_too_large";

/** A refused batch. `message` is the code itself, so logging it leaks nothing. */
export class BatchRejection extends Error {
  override name = "BatchRejection";
  constructor(
    readonly status: 400 | 403 | 413,
    readonly code: RejectionCode,
    readonly index?: number,
  ) {
    super(code);
  }
}

export type ValidatedBatch = {
  /** Canonical NDJSON lines, one per event, without newlines. */
  lines: string[];
};

const TOP_LEVEL_KEYS = new Set(["schema", "events"]);
const REQUIRED_EVENT_KEYS = [
  "version",
  "event_id",
  "occurred_at",
  "component",
  "deployment_id",
  "event",
  "trace_id",
  "properties",
] as const;
const EVENT_KEYS = new Set<string>([...REQUIRED_EVENT_KEYS, "tenant_id", "workspace_id"]);
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;

type ShapedEvent = {
  event_id: string;
  occurred_at: string;
  component: string;
  deployment_id: string;
  event: string;
  trace_id: string;
  tenant_id?: string;
  workspace_id?: string;
  properties: Record<string, AnalyticsPropertyValue>;
};

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function invalid(index?: number): BatchRejection {
  return new BatchRejection(400, "invalid_batch", index);
}

function isPrimitive(value: unknown): value is AnalyticsPropertyValue {
  return value === null || typeof value === "string" || typeof value === "boolean"
    || (typeof value === "number" && Number.isFinite(value));
}

/** Step 5: exactly the envelope keys, each in its grammar. */
function shape(value: unknown, index: number): ShapedEvent {
  if (!isObject(value)) throw invalid(index);
  for (const key of Object.keys(value)) if (!EVENT_KEYS.has(key)) throw invalid(index);
  for (const key of REQUIRED_EVENT_KEYS) if (!Object.hasOwn(value, key)) throw invalid(index);
  const event = value as Record<string, unknown>;
  if (event.version !== 1) throw invalid(index);
  if (typeof event.event_id !== "string" || !UUID_VALUE.test(event.event_id)) throw invalid(index);
  if (
    typeof event.occurred_at !== "string"
    || !ISO_TIME.test(event.occurred_at)
    || !Number.isFinite(Date.parse(event.occurred_at))
  ) {
    throw invalid(index);
  }
  if (typeof event.component !== "string" || !event.component) throw invalid(index);
  if (typeof event.deployment_id !== "string" || !OPAQUE_ID.test(event.deployment_id)) throw invalid(index);
  if (typeof event.event !== "string" || !event.event) throw invalid(index);
  if (typeof event.trace_id !== "string" || !TRACE_ID.test(event.trace_id)) throw invalid(index);
  for (const field of ["tenant_id", "workspace_id"] as const) {
    if (Object.hasOwn(event, field) && (typeof event[field] !== "string" || !OPAQUE_ID.test(event[field] as string))) {
      throw invalid(index);
    }
  }
  if (!isObject(event.properties)) throw invalid(index);
  for (const property of Object.values(event.properties)) if (!isPrimitive(property)) throw invalid(index);
  return event as ShapedEvent;
}

/** Step 6 (registry part): the kind, its scope's attribution, and the typed property allowlist. */
function registered(event: ShapedEvent, index: number, registry: Readonly<Record<string, EventSpec>>): ShapedEvent {
  const spec = Object.hasOwn(registry, event.event) ? registry[event.event] : undefined;
  if (!spec) throw invalid(index);
  const tenant = Object.hasOwn(event, "tenant_id");
  const workspace = Object.hasOwn(event, "workspace_id");
  const scopeOk = spec.scope === "installation" ? !tenant && !workspace
    : spec.scope === "tenant" ? tenant && !workspace
    : spec.scope === "workspace" ? tenant && workspace
    : spec.scope === "native_workspace" ? !tenant && workspace
    : false;
  if (!scopeOk) throw invalid(index);
  const properties: Record<string, AnalyticsPropertyValue> = {};
  for (const [key, value] of Object.entries(event.properties)) {
    if (RESERVED_FIELDS.has(key)) throw invalid(index);
    const propertySpec = Object.hasOwn(spec.properties, key) ? spec.properties[key] : undefined;
    if (!propertySpec) throw invalid(index);
    const projected = propertyValue(propertySpec, value);
    if (projected === undefined) throw invalid(index);
    properties[key] = projected;
  }
  return { ...event, properties };
}

/** Step 8: one canonical line in envelope key order. */
function canonicalLine(event: ShapedEvent): string {
  return JSON.stringify({
    version: 1,
    event_id: event.event_id,
    occurred_at: event.occurred_at,
    component: event.component,
    deployment_id: event.deployment_id,
    event: event.event,
    trace_id: event.trace_id,
    ...(event.tenant_id !== undefined ? { tenant_id: event.tenant_id } : {}),
    ...(event.workspace_id !== undefined ? { workspace_id: event.workspace_id } : {}),
    properties: event.properties,
  });
}

const UTF8 = new TextDecoder("utf-8", { fatal: true });

/**
 * Validates a whole batch body for an authenticated producer (design §3 steps
 * 5-8, in that order across the whole batch): shape, then authority (403 for
 * the whole batch), then registry, scope and properties, then line size.
 * Throws BatchRejection; returns the lines to commit otherwise.
 */
export function validateBatch(
  body: Uint8Array,
  options: {
    producer: Producer;
    registries: CollectorRegistries;
    maxBatchEvents: number;
    maxEventBytes: number;
  },
): ValidatedBatch {
  let parsed: unknown;
  try {
    parsed = JSON.parse(UTF8.decode(body));
  } catch {
    throw invalid();
  }
  if (!isObject(parsed)) throw invalid();
  for (const key of Object.keys(parsed)) if (!TOP_LEVEL_KEYS.has(key)) throw invalid();
  if (parsed.schema !== ANALYTICS_BATCH_SCHEMA) throw invalid();
  const events = parsed.events;
  if (!Array.isArray(events) || events.length === 0 || events.length > options.maxBatchEvents) throw invalid();

  const shaped = events.map((event, index) => shape(event, index));
  const { producer } = options;
  // Body fields can never override the producer registration's binding.
  if (shaped.some((event) => event.component !== producer.component || event.deployment_id !== producer.deploymentId)) {
    throw new BatchRejection(403, "forbidden");
  }
  const registry = Object.hasOwn(options.registries, producer.component)
    ? options.registries[producer.component]
    : undefined;
  if (!registry) throw new BatchRejection(403, "forbidden");
  const checked = shaped.map((event, index) => registered(event, index, registry));
  const lines = checked.map(canonicalLine);
  lines.forEach((line, index) => {
    if (Buffer.byteLength(line, "utf8") > options.maxEventBytes) {
      throw new BatchRejection(413, "event_too_large", index);
    }
  });
  return { lines };
}
