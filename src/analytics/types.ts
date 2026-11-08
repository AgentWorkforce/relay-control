// analytics lane: the product-analytics port, its wire envelope, and the sink
// contract. Separate from src/telemetry/ (operational telemetry keeps its own
// report, signature and outbox contract). Wire field names follow the
// collector interface (infra docs/analytics-collector-interface.md, infra #84
// @62599fb as amended by infra #85 @ca91118 (merged 91c9b79)).

export type AnalyticsEventKind = "config_loaded" | "service_started" | "service_stopping";

/**
 * Registry scope of an event kind; fixes which attribution fields it carries.
 * - installation: neither tenant_id nor workspace_id
 * - tenant: tenant_id only
 * - workspace: a workspace inside a tenant model, both tenant_id and workspace_id
 * - native_workspace: a component with no separate tenant model, workspace_id only
 */
export type AnalyticsScope = "installation" | "tenant" | "workspace" | "native_workspace";

/**
 * A component's identity model. relaycontrol uses `tenant` (organization =
 * tenant): its kinds are installation, tenant or workspace scoped. A
 * `native_workspace` model allows only installation and native_workspace kinds.
 */
export type AnalyticsIdentityModel = "tenant" | "native_workspace";

export type AnalyticsPropertyValue = string | number | boolean | null;
export type AnalyticsProperties = Record<string, AnalyticsPropertyValue>;

export type CaptureInput = {
  event: AnalyticsEventKind;
  /** Filtered through the per-kind allowlist; unknown keys are dropped. */
  properties?: AnalyticsProperties;
  /** Defaults to the per-boot trace id. */
  traceId?: string;
  /** Only where the kind's registered scope requires it, after application authorization. */
  tenantId?: string;
  workspaceId?: string;
};

export type FlushResult = { sent: number; dropped: number };

export type AnalyticsFailureReason =
  | "auth"
  | "config"
  | "storage"
  | "redirect"
  | "transport"
  | "timeout"
  | "backpressure"
  | "server"
  | "protocol"
  | "rejected"
  | "oversize";

export type AnalyticsStats = {
  captured: number;
  sent: { batches: number; events: number };
  dropped: {
    oversize: number;
    queueFull: number;
    rejected: number;
    /**
     * Attempt budget ran out and the last answer was a non-204 2xx (or
     * another status outside the collector contract).
     */
    protocol: number;
    retryExhausted: number;
    /**
     * Total delivery deadline (enqueue + DELIVERY_DEADLINE_MS) passed before
     * the event was accepted; dropped without starting another request or wait.
     */
    deadline: number;
    /** Still queued and never attempted when a flush reached its deadline. */
    shutdown: number;
    /**
     * In flight when a flush reached its deadline: the request was aborted, so
     * the collector may or may not have committed these events.
     */
    aborted: number;
    invalid: number;
  };
  failures: { auth: number; config: number; storage: number; redirect: number; transport: number };
  queueEvents: number;
  queueBytes: number;
  lastFailureReason: AnalyticsFailureReason | null;
  lastSuccessAt: string | null;
};

export interface AnalyticsPort {
  /** Synchronous; never awaits export and never throws. Enqueues or counts a drop. */
  capture(input: CaptureInput): void;
  /** `deadline` is epoch ms on the port's clock. Resolves by the deadline; never rejects. */
  flush(deadline: number): Promise<FlushResult>;
  stats(): AnalyticsStats;
}

export type AnalyticsEnvelope = {
  version: 1;
  /** randomUUID() at capture; retained across retries. */
  event_id: string;
  /** UTC ISO-8601. */
  occurred_at: string;
  component: "relaycontrol";
  deployment_id: string;
  event: AnalyticsEventKind;
  trace_id: string;
  tenant_id?: string;
  workspace_id?: string;
  properties: AnalyticsProperties;
};

export const ANALYTICS_BATCH_SCHEMA = "agent-relay.analytics.batch/v1";

/**
 * Bytes of the batch envelope around the events:
 * `{"schema":"agent-relay.analytics.batch/v1","events":[]}`.
 */
export const ANALYTICS_BATCH_OVERHEAD_BYTES = Buffer.byteLength(
  JSON.stringify({ schema: ANALYTICS_BATCH_SCHEMA, events: [] }),
);

export type AnalyticsBatch = {
  schema: typeof ANALYTICS_BATCH_SCHEMA;
  events: AnalyticsEnvelope[];
};

export type AnalyticsDestination = "none" | "collector" | "posthog";

/**
 * What one delivery attempt meant for the batch. Sinks classify their own
 * provider's responses; the queue only acts on the outcome.
 */
export type SinkResult =
  | { outcome: "accepted" }
  /**
   * A response outside the provider contract's success rule (collector: any
   * 2xx but 204). Never a success: retried within the attempt budget, then
   * counted as dropped.protocol.
   */
  | { outcome: "protocol"; status: number }
  /** Terminal invalid batch (400, 404, 422, other 4xx). */
  | { outcome: "rejected"; status: number }
  /** Terminal authentication (401) or authority (403) failure. */
  | { outcome: "auth"; status: 401 | 403 }
  /** 413: the batch is too large; the queue splits it. */
  | { outcome: "oversize"; status: number }
  /** 3xx: never followed. */
  | { outcome: "redirect"; status: number }
  | {
    outcome: "retry";
    reason: "backpressure" | "storage" | "server" | "timeout" | "transport";
    status?: number;
    retryAfterMs?: number;
  };

export interface AnalyticsSink {
  readonly name: AnalyticsDestination;
  send(events: AnalyticsEnvelope[], signal: AbortSignal): Promise<SinkResult>;
}

/** Injectable time source so the queue can be tested without real waits. */
export type AnalyticsClock = {
  now(): number;
  /**
   * Background timers may be unref'd. `keepAlive: true` asks for a timer that
   * holds the process open (used only for the bounded flush deadline).
   */
  setTimeout(callback: () => void, ms: number, options?: { keepAlive?: boolean }): unknown;
  clearTimeout(handle: unknown): void;
};

export type AnalyticsLog = (message: string, fields?: Record<string, unknown>) => void;
