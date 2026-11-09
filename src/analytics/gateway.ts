// analytics lane: the client gateway's request validation. Dashboard and
// Desktop send registered client kinds over their existing credential
// (POST /api/v1/analytics/events, mounted in src/app.ts); this module checks a
// whole request body against the registry before anything is captured. It is
// stricter than the projector: unknown properties and values that fail their
// spec are refused here rather than silently dropped.
import {
  EVENT_REGISTRY,
  propertyValue,
  SERVER_SET_CLIENT_PROPERTIES,
  type EventSpec,
} from "./events.js";
import type {
  AnalyticsClient,
  AnalyticsEventKind,
  AnalyticsGatewayRejection,
  AnalyticsProperties,
  AnalyticsPropertyValue,
  CaptureInput,
} from "./types.js";

export const CLIENT_BATCH_SCHEMA = "agent-relay.analytics.client-batch/v1";

export const ANALYTICS_CLIENTS: readonly AnalyticsClient[] = ["dashboard", "desktop"];

/** Envelope and authority fields a client may never name, anywhere in the body. */
export const GATEWAY_RESERVED_FIELDS: ReadonlySet<string> = new Set([
  "deployment_id",
  "component",
  "tenant_id",
  "workspace_id",
  "event_id",
  "trace_id",
  "version",
]);

/** A client `occurred_at` further than this from server time is replaced. */
export const GATEWAY_CLOCK_SKEW_MS = 5 * 60_000;

/** Through the app's RateLimiter: per principal session and per client IP. */
export const GATEWAY_RATE_LIMITS = {
  session: { limit: 60, windowMs: 60_000 },
  ip: { limit: 300, windowMs: 60_000 },
} as const;

/** The scope a client principal needs; the only scope list the server issues carries it. */
export const GATEWAY_REQUIRED_SCOPE = "cli:auth";

const TOP_LEVEL_FIELDS = new Set(["schema", "client", "events"]);
const EVENT_FIELDS = new Set(["event", "occurred_at", "client_event_id", "properties"]);
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** A refused gateway request: HTTP status, `{error}` code, and the `gateway.rejected.*` counter. */
export class GatewayRequestError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly counter: AnalyticsGatewayRejection,
  ) {
    super(message);
  }
}

export type ClientEvent = {
  event: AnalyticsEventKind;
  scope: EventSpec["scope"];
  /** Epoch ms: the client's time when inside the skew window, else server time. */
  occurredAt: number;
  /** The client supplied an `occurred_at` that was replaced by server time. */
  clockAdjusted: boolean;
  /** Validated properties plus the server-set `client` (and `client_event_id` when given). */
  properties: AnalyticsProperties;
};

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** First reserved key at any depth; iterative so a deeply nested body cannot overflow the stack. */
function findReservedField(root: unknown): string | null {
  const stack: unknown[] = [root];
  while (stack.length > 0) {
    const value = stack.pop();
    if (Array.isArray(value)) {
      for (const item of value) stack.push(item);
    } else if (isObject(value)) {
      for (const [key, nested] of Object.entries(value)) {
        if (GATEWAY_RESERVED_FIELDS.has(key)) return key;
        stack.push(nested);
      }
    }
  }
  return null;
}

function bodyError(message: string): GatewayRequestError {
  return new GatewayRequestError(400, "invalid_request", message, "body");
}

function eventError(index: number, message: string): GatewayRequestError {
  return new GatewayRequestError(400, "invalid_event", `events[${index}]: ${message}`, "invalid");
}

function occurredAt(value: unknown, index: number, now: number): { at: number; adjusted: boolean } {
  if (value === undefined) return { at: now, adjusted: false };
  if (typeof value !== "string") throw eventError(index, "occurred_at must be an ISO-8601 string");
  const parsed = ISO_TIME.test(value) ? Date.parse(value) : Number.NaN;
  if (Number.isFinite(parsed) && Math.abs(parsed - now) <= GATEWAY_CLOCK_SKEW_MS) {
    return { at: parsed, adjusted: false };
  }
  return { at: now, adjusted: true };
}

function clientEvent(
  value: unknown,
  index: number,
  client: AnalyticsClient,
  now: number,
  registry: Readonly<Record<string, EventSpec>>,
): ClientEvent {
  if (!isObject(value)) throw eventError(index, "must be an object");
  for (const key of Object.keys(value)) {
    if (!EVENT_FIELDS.has(key)) throw eventError(index, `unknown field ${JSON.stringify(key)}`);
  }
  const kind = value.event;
  if (typeof kind !== "string") throw eventError(index, "event must be a string");
  const spec = Object.hasOwn(registry, kind) ? registry[kind] : undefined;
  if (!spec) throw eventError(index, `event ${JSON.stringify(kind)} is not registered`);
  // Installation kinds and other server-only kinds have no `clients`.
  if (!spec.clients?.includes(client)) {
    throw eventError(index, `event ${JSON.stringify(kind)} is not registered for the ${client} client`);
  }
  const time = occurredAt(value.occurred_at, index, now);
  const clientEventId = value.client_event_id;
  if (clientEventId !== undefined && (typeof clientEventId !== "string" || !UUID.test(clientEventId))) {
    throw eventError(index, "client_event_id must be a UUID");
  }
  const raw = value.properties;
  if (raw !== undefined && !isObject(raw)) throw eventError(index, "properties must be an object");
  const properties: AnalyticsProperties = {};
  for (const [key, propertyRaw] of Object.entries(raw ?? {})) {
    if (SERVER_SET_CLIENT_PROPERTIES.has(key)) {
      throw eventError(index, `property ${JSON.stringify(key)} is set by the server`);
    }
    const propertySpec = Object.hasOwn(spec.properties, key) ? spec.properties[key] : undefined;
    if (!propertySpec) throw eventError(index, `property ${JSON.stringify(key)} is not registered for ${kind}`);
    const projected = propertyRaw === null || ["string", "number", "boolean"].includes(typeof propertyRaw)
      ? propertyValue(propertySpec, propertyRaw as AnalyticsPropertyValue)
      : undefined;
    if (projected === undefined) throw eventError(index, `property ${JSON.stringify(key)} has an invalid value`);
    properties[key] = projected;
  }
  properties.client = client;
  if (clientEventId !== undefined) properties.client_event_id = (clientEventId as string).toLowerCase();
  return {
    event: kind as AnalyticsEventKind,
    scope: spec.scope,
    occurredAt: time.at,
    clockAdjusted: time.adjusted,
    properties,
  };
}

/**
 * Validates a whole client batch. Throws GatewayRequestError on the first
 * problem, so either every event is returned or none is captured.
 * `client` is the client implied by the credential (cookie = dashboard,
 * bearer = desktop); `now` is server time in epoch ms.
 */
export function parseClientBatch(
  raw: string,
  options: {
    client: AnalyticsClient;
    maxEvents: number;
    now: number;
    registry?: Readonly<Record<string, EventSpec>>;
  },
): ClientEvent[] {
  let body: unknown;
  try {
    body = JSON.parse(raw);
  } catch {
    throw bodyError("Body must be valid JSON");
  }
  if (!isObject(body)) throw bodyError("Body must be a JSON object");
  const reserved = findReservedField(body);
  if (reserved !== null) {
    throw new GatewayRequestError(
      400,
      "reserved_field",
      `${reserved} is set by the server and may not appear in the request`,
      "reserved_field",
    );
  }
  for (const key of Object.keys(body)) {
    if (!TOP_LEVEL_FIELDS.has(key)) throw bodyError(`Unknown field ${JSON.stringify(key)}`);
  }
  if (body.schema !== CLIENT_BATCH_SCHEMA) throw bodyError(`schema must be ${CLIENT_BATCH_SCHEMA}`);
  if (typeof body.client !== "string" || !ANALYTICS_CLIENTS.includes(body.client as AnalyticsClient)) {
    throw bodyError("client must be dashboard or desktop");
  }
  if (body.client !== options.client) {
    throw new GatewayRequestError(
      400,
      "client_mismatch",
      options.client === "dashboard"
        ? "A session cookie may only send dashboard events"
        : "A bearer token may only send desktop events",
      "client_mismatch",
    );
  }
  const events = body.events;
  if (!Array.isArray(events) || events.length === 0) throw bodyError("events must be a non-empty array");
  if (events.length > options.maxEvents) {
    throw new GatewayRequestError(
      400,
      "too_many_events",
      `At most ${options.maxEvents} events per request`,
      "body",
    );
  }
  const registry = options.registry ?? EVENT_REGISTRY;
  return events.map((event, index) => clientEvent(event, index, options.client, options.now, registry));
}

/** Attribution the registry scope asks for, from the authenticated principal only. */
export function clientAttribution(
  scope: EventSpec["scope"],
  authority: { organizationId: string; workspaceId: string },
): Pick<CaptureInput, "tenantId" | "workspaceId"> {
  switch (scope) {
    case "tenant":
      return { tenantId: authority.organizationId };
    case "workspace":
      return { tenantId: authority.organizationId, workspaceId: authority.workspaceId };
    default:
      // Installation and native-workspace kinds are never client kinds under
      // relaycontrol's tenant model; the projector refuses any attribution.
      return {};
  }
}
