// telemetry lane: builds the outbound payloads (digest, error burst) from the
// stored window, live DB gauges, and lightweight pulls from the other
// services. Everything returned here is scrubbed by the caller.
import { randomUUID } from "node:crypto";
import { decryptSecret, type EncryptionKeyring } from "../crypto.js";
import type { TelemetryConfig, TelemetryLevel, TelemetryProbe } from "./config.js";
import { hashIdentifier } from "./identity.js";
import type { CounterDelta, ErrorAggregate, TelemetryStore } from "./store.js";

export const TELEMETRY_SCHEMA = "agent-relay.selfhost.telemetry/v1";

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export type ComponentHealth = {
  name: string;
  healthy: boolean;
  status: number | null;
  latencyMs: number | null;
  version?: string;
  build?: string;
  reason?: string;
};

export type CollectorDeps = {
  config: TelemetryConfig;
  store: TelemetryStore;
  keyring: EncryptionKeyring;
  relaycontrolVersion: string;
  /** Internal Relaycast origin; per-workspace /v1/console/stats pulls. */
  relaycastUrl: string | null;
  fetchImpl: FetchLike;
};

const SHORT_TOKEN = /^[A-Za-z0-9][A-Za-z0-9_.+:-]{0,63}$/;

function shortToken(value: unknown): string | undefined {
  return typeof value === "string" && SHORT_TOKEN.test(value) ? value : undefined;
}

async function timedFetch(fetchImpl: FetchLike, url: string, init: RequestInit = {}, timeoutMs = 3_000): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetchImpl(url, { ...init, signal: controller.signal, redirect: "manual" });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Health pull. Only allowlisted short fields are kept from the response
 * (ok/version/build/reason/blockedReason); the body itself never leaves.
 */
export async function probeComponent(fetchImpl: FetchLike, probe: TelemetryProbe): Promise<ComponentHealth> {
  const started = Date.now();
  try {
    const response = await timedFetch(fetchImpl, probe.url);
    const latencyMs = Date.now() - started;
    let body: Record<string, unknown> = {};
    if (response.headers.get("content-type")?.includes("json")) {
      try {
        const parsed = await response.json() as unknown;
        if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) body = parsed as Record<string, unknown>;
      } catch {
        body = {};
      }
    } else {
      await response.arrayBuffer().catch(() => undefined);
    }
    const execution = body.execution && typeof body.execution === "object"
      ? body.execution as Record<string, unknown>
      : {};
    const okField = typeof body.ok === "boolean" ? body.ok : undefined;
    const health: ComponentHealth = {
      name: probe.name,
      healthy: response.ok && okField !== false,
      status: response.status,
      latencyMs,
    };
    const version = shortToken(body.version);
    const build = shortToken(body.build);
    const reason = shortToken(body.reason) ?? shortToken(execution.blockedReason) ??
      shortToken((body.status as unknown) === "ok" ? undefined : body.status);
    if (version) health.version = version;
    if (build) health.build = build;
    if (reason) health.reason = reason;
    return health;
  } catch (error) {
    return {
      name: probe.name,
      healthy: false,
      status: null,
      latencyMs: null,
      reason: error instanceof Error && error.name === "AbortError" ? "timeout" : "unreachable",
    };
  }
}

async function count(store: TelemetryStore, sql: string, params: unknown[] = []): Promise<number | null> {
  try {
    const result = await store.database.query<{ count: string | number }>(sql, params);
    return Number(result.rows[0]?.count ?? 0);
  } catch {
    return null;
  }
}

async function grouped(store: TelemetryStore, sql: string, params: unknown[] = []): Promise<Record<string, number> | null> {
  try {
    const result = await store.database.query<{ key: string; count: string | number }>(sql, params);
    return Object.fromEntries(result.rows.map((row) => [String(row.key), Number(row.count)]));
  } catch {
    return null;
  }
}

/** Aggregate gauges from the control-plane database (counts only). */
export async function collectGauges(store: TelemetryStore, windowStart: string): Promise<Record<string, unknown>> {
  const gauges: Record<string, unknown> = {
    organizations: await count(store, "SELECT count(*) AS count FROM selfhost_organizations"),
    workspaces: await count(store, "SELECT count(*) AS count FROM selfhost_workspaces"),
    members: await count(store, "SELECT count(*) AS count FROM selfhost_users"),
    activeMembers24h: await count(store,
      `SELECT count(DISTINCT user_id) AS count FROM selfhost_token_sessions
        WHERE revoked_at IS NULL AND COALESCE(last_refreshed_at, created_at) > now() - interval '24 hours'`),
    activeMembers7d: await count(store,
      `SELECT count(DISTINCT user_id) AS count FROM selfhost_token_sessions
        WHERE revoked_at IS NULL AND COALESCE(last_refreshed_at, created_at) > now() - interval '7 days'`),
    logins: await grouped(store,
      `SELECT CASE WHEN client_name = 'relay-dashboard' THEN 'dashboard' ELSE 'cli' END AS key,
              count(*) AS count
         FROM selfhost_device_authorizations
        WHERE approved_at >= $1 GROUP BY 1`, [windowStart]),
  };
  // Other lanes' tables: counted only when their migrations are present.
  if (await store.tableExists("selfhost_workflow_runs")) {
    gauges.flowRuns = await grouped(store,
      `SELECT status AS key, count(*) AS count FROM selfhost_workflow_runs
        WHERE created_at >= $1 GROUP BY status`, [windowStart]);
  }
  if (await store.tableExists("selfhost_flow_definitions")) {
    gauges.flowDefinitions = await count(store, "SELECT count(*) AS count FROM selfhost_flow_definitions");
  }
  if (await store.tableExists("selfhost_workers")) {
    gauges.workers = await grouped(store,
      "SELECT status AS key, count(*) AS count FROM selfhost_workers GROUP BY status");
  }
  if (await store.tableExists("selfhost_workspace_env_vars")) {
    gauges.envVars = await count(store, "SELECT count(*) AS count FROM selfhost_workspace_env_vars");
  }
  if (await store.tableExists("selfhost_integration_connections")) {
    gauges.integrationConnections = await count(store, "SELECT count(*) AS count FROM selfhost_integration_connections");
  }
  if (await store.tableExists("selfhost_workspace_api_tokens")) {
    gauges.apiTokens = await count(store, "SELECT count(*) AS count FROM selfhost_workspace_api_tokens");
  }
  return gauges;
}

/**
 * Messages and agents: Relaycast exposes only per-workspace stats, read with
 * each workspace's own key (already held encrypted by relaycontrol).
 */
export async function collectRelaycastUsage(deps: CollectorDeps, salt: string): Promise<Record<string, unknown> | null> {
  if (!deps.relaycastUrl) return null;
  let rows: Array<{ id: string; relaycast_api_key_ciphertext: string }>;
  try {
    rows = (await deps.store.database.query<{ id: string; relaycast_api_key_ciphertext: string }>(
      "SELECT id, relaycast_api_key_ciphertext FROM selfhost_workspaces ORDER BY created_at LIMIT 50",
    )).rows;
  } catch {
    return null;
  }
  let messages = 0;
  let channelMessages = 0;
  let dmMessages = 0;
  let agents = 0;
  let failures = 0;
  const perWorkspace: Array<Record<string, unknown>> = [];
  for (const row of rows) {
    try {
      const key = decryptSecret(row.relaycast_api_key_ciphertext, deps.keyring);
      const response = await timedFetch(deps.fetchImpl, `${deps.relaycastUrl}/v1/console/stats?days=1`, {
        headers: { authorization: `Bearer ${key}`, accept: "application/json" },
      });
      if (!response.ok) {
        failures += 1;
        await response.arrayBuffer().catch(() => undefined);
        continue;
      }
      const raw = await response.json() as Record<string, unknown>;
      const data = (raw.data && typeof raw.data === "object" ? raw.data : raw) as Record<string, unknown>;
      const total = Number(data.total_messages ?? 0) || 0;
      const unique = Number(data.unique_agents ?? 0) || 0;
      messages += total;
      channelMessages += Number(data.channel_messages ?? 0) || 0;
      dmMessages += Number(data.dm_messages ?? 0) || 0;
      agents += unique;
      perWorkspace.push({ workspace: hashIdentifier(salt, row.id), messages24h: total, activeAgents24h: unique });
    } catch {
      failures += 1;
    }
  }
  return {
    windowDays: 1,
    messages24h: messages,
    channelMessages24h: channelMessages,
    dmMessages24h: dmMessages,
    activeAgents24h: agents,
    activeWorkspaces24h: perWorkspace.filter((entry) => Number(entry.messages24h) > 0).length,
    statsFailures: failures,
    perWorkspace,
  };
}

function usageFromCounters(counters: CounterDelta[]): Record<string, unknown> {
  const requests: Record<string, Record<string, number>> = {};
  const events: Record<string, Record<string, number>> = {};
  const workspaces: Array<{ workspace: string; requests: number }> = [];
  for (const counter of counters) {
    if (counter.area === "workspace") {
      workspaces.push({ workspace: counter.metric, requests: counter.value });
    } else if (counter.area.startsWith("req:")) {
      const area = counter.area.slice(4);
      (requests[area] ??= {})[counter.metric] = counter.value;
    } else {
      (events[counter.area] ??= {})[counter.metric] = counter.value;
    }
  }
  workspaces.sort((a, b) => b.requests - a.requests);
  return {
    requestsByArea: requests,
    events,
    activeWorkspaces: workspaces.length,
    workspaceActivity: workspaces.slice(0, 50),
  };
}

export function errorEntries(errors: ErrorAggregate[], limit = 100): Array<Record<string, unknown>> {
  return errors.slice(0, limit).map((error) => ({
    component: error.component,
    errorClass: error.errorClass,
    route: error.route,
    status: error.status,
    count: error.count,
    firstSeen: error.firstSeen,
    lastSeen: error.lastSeen,
    firstSeenEver: error.firstSeenEver,
    fingerprint: error.fingerprint,
  }));
}

export async function collectComponents(deps: CollectorDeps): Promise<ComponentHealth[]> {
  const components = await Promise.all(deps.config.probes.map((probe) => probeComponent(deps.fetchImpl, probe)));
  return [
    { name: "relaycontrol", healthy: true, status: 200, latencyMs: 0, version: deps.relaycontrolVersion },
    ...components,
  ];
}

export function envelopeBase(deps: CollectorDeps, kind: string, level: TelemetryLevel): Record<string, unknown> {
  return {
    schema: TELEMETRY_SCHEMA,
    kind,
    reportId: randomUUID(),
    installId: deps.config.installId,
    level,
    generatedAt: new Date().toISOString(),
    relaycontrol: { version: deps.relaycontrolVersion },
    deployment: deps.config.deployment,
  };
}

/** The periodic digest for the given window at the given level. */
export async function buildDigest(
  deps: CollectorDeps,
  window: { counters: CounterDelta[]; errors: ErrorAggregate[]; windowStartedAt: string },
  level: TelemetryLevel,
): Promise<Record<string, unknown> | null> {
  if (level === "off") return null;
  const components = await collectComponents(deps);
  const payload: Record<string, unknown> = {
    ...envelopeBase(deps, "digest", level),
    window: { start: window.windowStartedAt, end: new Date().toISOString() },
    components,
    errors: errorEntries(window.errors),
  };
  if (level === "full") {
    const salt = await deps.store.salt();
    payload.usage = {
      ...usageFromCounters(window.counters),
      gauges: await collectGauges(deps.store, window.windowStartedAt),
      relaycast: await collectRelaycastUsage(deps, salt),
    };
  }
  return payload;
}

export async function buildBurst(
  deps: CollectorDeps,
  level: TelemetryLevel,
  burst: {
    component: string;
    fingerprint: string;
    route: string;
    status: number;
    errorClass: string;
    count: number;
    since: string | null;
    windowSeconds: number;
  },
): Promise<Record<string, unknown>> {
  return {
    ...envelopeBase(deps, "error_burst", level),
    burst,
    components: await collectComponents(deps),
  };
}
