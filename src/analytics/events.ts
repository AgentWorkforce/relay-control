// analytics lane: the event-kind registry and the projector. Every envelope is
// built here from a typed allowlist; nothing reaches a sink that the registry
// does not name. Identity model per infra docs/analytics-collector-interface.md,
// infra #84 @62599fb as amended by infra #85 @ca91118 (merged 91c9b79): each kind's registered
// scope fixes its attribution, and callers cannot choose a weaker scope.
import { randomUUID } from "node:crypto";
import type {
  AnalyticsClient,
  AnalyticsEnvelope,
  AnalyticsEventKind,
  AnalyticsIdentityModel,
  AnalyticsProperties,
  AnalyticsPropertyValue,
  AnalyticsScope,
  CaptureInput,
} from "./types.js";

export type PropertySpec =
  | { type: "boolean" }
  | { type: "integer"; min: number; max: number }
  | { type: "enum"; values: readonly string[] }
  /** Short identifier-like strings only: no spaces, no URLs (no "//"). */
  | { type: "token"; maxLength: number }
  /** A UUID in canonical 8-4-4-4-12 hex form. */
  | { type: "uuid" }
  /**
   * A client-reported release version: `MAJOR.MINOR.PATCH` (1-5 digits each),
   * optional `-prerelease` and `+build` of dot-separated `[0-9A-Za-z-]+`
   * identifiers, at most VERSION_MAX_LENGTH characters. Nothing else.
   */
  | { type: "version" };

export type EventSpec = {
  scope: AnalyticsScope;
  properties: Record<string, PropertySpec>;
  /**
   * Clients that may send this kind through the client gateway. Absent: a
   * server-only kind that no client may send.
   */
  clients?: readonly AnalyticsClient[];
};

const TELEMETRY_LEVEL = { type: "enum", values: ["off", "errors", "full"] } as const;
const TELEMETRY_TRANSPORT = { type: "enum", values: ["https", "file"] } as const;

/**
 * relaycontrol's identity model: organization = tenant. Its kinds are
 * installation, tenant or workspace (tenant_id + workspace_id) scoped; no
 * native_workspace kind may be registered under it.
 */
export const RELAYCONTROL_IDENTITY_MODEL: AnalyticsIdentityModel = "tenant";

/** Scopes each identity model may register. Installation scope is valid in both. */
const MODEL_SCOPES: Record<AnalyticsIdentityModel, readonly AnalyticsScope[]> = {
  tenant: ["installation", "tenant", "workspace"],
  native_workspace: ["installation", "native_workspace"],
};

/**
 * Properties every client kind allows. `client` is set by the gateway from the
 * credential check, never from the request body; `client_event_id` is the
 * client's own dedupe id (the exported event_id is still minted at capture).
 */
export const CLIENT_PROPERTIES = {
  client: { type: "enum", values: ["dashboard", "desktop"] },
  client_event_id: { type: "uuid" },
} as const satisfies Record<string, PropertySpec>;

/** Properties of client kinds that only the gateway sets; a body naming them is invalid. */
export const SERVER_SET_CLIENT_PROPERTIES: ReadonlySet<string> = new Set(Object.keys(CLIENT_PROPERTIES));

/**
 * Dashboard pages for `dashboard.page_viewed`. The repo names no full list of
 * dashboard routes (only `#/device` and `#/flows/runs/{id}`), so this is a
 * small fixed enum; a new page is a registry change.
 */
export const DASHBOARD_PAGES = [
  "overview",
  "sessions",
  "agents",
  "workflows",
  "flows",
  "settings",
  "members",
  "device",
] as const;

/**
 * The registered event kinds. Server lifecycle kinds are installation-scoped
 * and have no `clients`; client kinds are tenant- or workspace-scoped and name
 * the one client that may send them.
 */
export const EVENT_REGISTRY: Record<AnalyticsEventKind, EventSpec> = {
  config_loaded: {
    scope: "installation",
    properties: {
      telemetry_level: TELEMETRY_LEVEL,
      telemetry_transport: TELEMETRY_TRANSPORT,
      sign_in_oidc: { type: "boolean" },
      sign_in_email_link: { type: "boolean" },
      sign_in_smtp: { type: "boolean" },
      flows_enabled: { type: "boolean" },
      operator_oauth_apps: { type: "integer", min: 0, max: 1000 },
    },
  },
  service_started: {
    scope: "installation",
    properties: {
      component_version: { type: "token", maxLength: 64 },
      config_fingerprint: { type: "token", maxLength: 64 },
    },
  },
  service_stopping: {
    scope: "installation",
    properties: {
      reason: { type: "enum", values: ["SIGINT", "SIGTERM", "startup_failed"] },
    },
  },
  "dashboard.page_viewed": {
    scope: "workspace",
    clients: ["dashboard"],
    properties: {
      ...CLIENT_PROPERTIES,
      page: { type: "enum", values: DASHBOARD_PAGES },
    },
  },
  "dashboard.session_opened": {
    scope: "workspace",
    clients: ["dashboard"],
    properties: {
      ...CLIENT_PROPERTIES,
      source: { type: "enum", values: ["list", "search", "link"] },
    },
  },
  "desktop.app_started": {
    scope: "tenant",
    clients: ["desktop"],
    properties: {
      ...CLIENT_PROPERTIES,
      // Client-reported, so a reviewed version grammar rather than a generic
      // token: an email, a secret or product text is not a version.
      desktop_version: { type: "version" },
      os: { type: "enum", values: ["macos", "windows", "linux"] },
    },
  },
  "desktop.sign_in_completed": {
    scope: "tenant",
    clients: ["desktop"],
    properties: { ...CLIENT_PROPERTIES },
  },
};

/** Envelope fields that `properties` may never set. */
export const RESERVED_FIELDS: ReadonlySet<string> = new Set([
  "version",
  "event_id",
  "occurred_at",
  "component",
  "deployment_id",
  "event",
  "trace_id",
  "tenant_id",
  "workspace_id",
  "properties",
  "schema",
]);

/** Grammar of tenant_id, workspace_id (and the collector's deployment_id check). */
export const OPAQUE_ID = /^[A-Za-z0-9_-]{1,128}$/;
/** Grammar of trace_id. */
export const TRACE_ID = /^[A-Za-z0-9_-]{8,128}$/;
const TOKEN_VALUE = /^[A-Za-z0-9][A-Za-z0-9_.+:@-]*$/;
/** Longest accepted `version` property value. */
export const VERSION_MAX_LENGTH = 32;
const VERSION_IDENTIFIERS = "[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*";
const VERSION_VALUE = new RegExp(
  `^\\d{1,5}\\.\\d{1,5}\\.\\d{1,5}(?:-${VERSION_IDENTIFIERS})?(?:\\+${VERSION_IDENTIFIERS})?$`,
);
/** A UUID in canonical 8-4-4-4-12 hex form (either case). */
export const UUID_VALUE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export class AnalyticsProjectionError extends Error {
  override name = "AnalyticsProjectionError";
}

export type ProjectionContext = {
  deploymentId: string;
  traceId: string;
  now: () => number;
};

/** The value if it satisfies its spec, else undefined. */
export function propertyValue(spec: PropertySpec, value: AnalyticsPropertyValue): AnalyticsPropertyValue | undefined {
  switch (spec.type) {
    case "boolean":
      return typeof value === "boolean" ? value : undefined;
    case "integer":
      return typeof value === "number" && Number.isInteger(value) && value >= spec.min && value <= spec.max
        ? value
        : undefined;
    case "enum":
      return typeof value === "string" && spec.values.includes(value) ? value : undefined;
    case "token":
      return typeof value === "string" && value.length <= spec.maxLength && TOKEN_VALUE.test(value)
        ? value
        : undefined;
    case "uuid":
      return typeof value === "string" && UUID_VALUE.test(value) ? value.toLowerCase() : undefined;
    case "version":
      return typeof value === "string" && value.length <= VERSION_MAX_LENGTH && VERSION_VALUE.test(value)
        ? value
        : undefined;
  }
}

function attribution(
  spec: EventSpec,
  input: CaptureInput,
  model: AnalyticsIdentityModel,
): { tenant_id?: string; workspace_id?: string } {
  const scopes = Object.hasOwn(MODEL_SCOPES, model) ? MODEL_SCOPES[model] : undefined;
  if (!scopes) throw new AnalyticsProjectionError("unregistered identity model");
  if (!scopes.includes(spec.scope)) {
    throw new AnalyticsProjectionError(`scope ${String(spec.scope)} is not registered under the ${model} identity model`);
  }
  const tenant = input.tenantId;
  const workspace = input.workspaceId;
  for (const [field, value] of [["tenant_id", tenant], ["workspace_id", workspace]] as const) {
    if (value !== undefined && (typeof value !== "string" || !OPAQUE_ID.test(value))) {
      throw new AnalyticsProjectionError(`${field} is not an opaque identifier`);
    }
  }
  // Every scope names exactly the fields it requires; anything missing or
  // extra is refused, so a kind can never be sent under a weaker scope.
  switch (spec.scope) {
    case "installation":
      if (tenant !== undefined || workspace !== undefined) {
        throw new AnalyticsProjectionError("installation events carry no tenant or workspace attribution");
      }
      return {};
    case "tenant":
      if (tenant === undefined) throw new AnalyticsProjectionError("tenant events require tenant_id");
      if (workspace !== undefined) {
        throw new AnalyticsProjectionError("tenant events carry no workspace attribution");
      }
      return { tenant_id: tenant };
    case "workspace":
      if (tenant === undefined || workspace === undefined) {
        throw new AnalyticsProjectionError("workspace events require tenant_id and workspace_id");
      }
      return { tenant_id: tenant, workspace_id: workspace };
    case "native_workspace":
      if (workspace === undefined) {
        throw new AnalyticsProjectionError("native workspace events require workspace_id");
      }
      if (tenant !== undefined) {
        throw new AnalyticsProjectionError("native workspace events carry no tenant attribution");
      }
      return { workspace_id: workspace };
    default:
      throw new AnalyticsProjectionError("unregistered event scope");
  }
}

/**
 * Build the wire envelope for one capture. Unknown property keys and values
 * that fail their spec are dropped; reserved keys, unregistered kinds or
 * scopes, a scope outside the identity model, and missing or extra attribution
 * for the kind's scope throw AnalyticsProjectionError.
 */
export function projectEvent(
  input: CaptureInput,
  context: ProjectionContext,
  registry: Readonly<Record<string, EventSpec>> = EVENT_REGISTRY,
  model: AnalyticsIdentityModel = RELAYCONTROL_IDENTITY_MODEL,
): AnalyticsEnvelope {
  const spec = Object.hasOwn(registry, input.event) ? registry[input.event] : undefined;
  if (!spec) throw new AnalyticsProjectionError("unregistered event kind");
  const properties: AnalyticsProperties = {};
  for (const [key, value] of Object.entries(input.properties ?? {})) {
    if (RESERVED_FIELDS.has(key)) {
      throw new AnalyticsProjectionError("properties cannot set reserved envelope fields");
    }
    const propertySpec = Object.hasOwn(spec.properties, key) ? spec.properties[key] : undefined;
    if (!propertySpec) continue;
    const projected = propertyValue(propertySpec, value);
    if (projected !== undefined) properties[key] = projected;
  }
  const traceId = input.traceId ?? context.traceId;
  if (typeof traceId !== "string" || !TRACE_ID.test(traceId)) {
    throw new AnalyticsProjectionError("trace_id is not an opaque identifier");
  }
  const occurredAt = input.occurredAt ?? context.now();
  if (typeof occurredAt !== "number" || !Number.isFinite(occurredAt) || Number.isNaN(new Date(occurredAt).getTime())) {
    throw new AnalyticsProjectionError("occurred_at is not a valid time");
  }
  return {
    version: 1,
    event_id: randomUUID(),
    occurred_at: new Date(occurredAt).toISOString(),
    component: "relaycontrol",
    deployment_id: context.deploymentId,
    event: input.event,
    trace_id: traceId,
    ...attribution(spec, input, model),
    properties,
  };
}
