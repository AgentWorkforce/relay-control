// telemetry lane: the module mounted from src/app.ts (same handle/helpers
// shape as the admin lane's module). Owns the instrumentation hooks, the
// background loops, and the /telemetry routes.
import type { IncomingMessage, ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { secureEqual, type EncryptionKeyring } from "../crypto.js";
import type { Database } from "../database.js";
import { TelemetryAggregator, describeError, featureArea, type ObservedError } from "./aggregator.js";
import {
  buildBurst,
  buildDigest,
  collectComponents,
  envelopeBase,
  errorEntries,
  type CollectorDeps,
  type ComponentHealth,
  type FetchLike,
} from "./collector.js";
import { describeTelemetryConfig, TELEMETRY_LEVELS, type TelemetryConfig, type TelemetryLevel } from "./config.js";
import { errorFingerprint, hashIdentifier } from "./identity.js";
import {
  IssueValidationError,
  issueSection,
  parseIssue,
  REPORT_ISSUE_TOOL,
  sanitizeSupportBundle,
} from "./issues.js";
import { scrubPayload, TELEMETRY_SCRUBBER_VERSION } from "./scrub.js";
import { sendOne } from "./sender.js";
import { EXPORT_FORMAT, exportEnvelope } from "./sign.js";
import { TelemetryStore, type OutboxKind } from "./store.js";
import { adminPage } from "./page.js";
import type { TenancyMode } from "../tenancy.js";

type JsonObject = Record<string, unknown>;

/** Same actor shape as the admin lane's audit log (src/admin/audit.ts). */
export type TelemetryAuditActor =
  | { kind: "user"; userId: string }
  | { kind: "service"; subject: string }
  | { kind: "bootstrap" };

export type TelemetryAudit = (event: {
  organizationId?: string | null;
  actor: TelemetryAuditActor;
  action: string;
  target?: string | null;
}) => Promise<void>;

/** Helpers app.ts already has; passed in so auth stays in one place. */
export type TelemetryRouteHelpers = {
  organizationAccess(request: IncomingMessage, organizationId: string, admin: boolean): Promise<unknown>;
  requestObject(request: IncomingMessage): Promise<JsonObject>;
  bearer(request: IncomingMessage): string | null;
};

export type ServiceCredentialVerifier = (token: string) => Promise<{ subject: string; scopes?: string[] } | null>;

export const TELEMETRY_ISSUE_SCOPE = "telemetry:issues:write";

class TelemetryHttpError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

function json(response: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...headers,
  });
  response.end(JSON.stringify(body, null, headers["content-disposition"] ? 2 : undefined));
}

function installationScope(): TelemetryHttpError {
  return new TelemetryHttpError(403, "installation_scope",
    "Installation-wide telemetry is available to the installation operator (bootstrap token) only");
}

function actorFor(auth: unknown): TelemetryAuditActor {
  const value = auth as { kind?: string; principal?: { userId: string } };
  return value?.kind === "user" && value.principal
    ? { kind: "user", userId: value.principal.userId }
    : { kind: "bootstrap" };
}

export type TelemetryModule = {
  readonly config: TelemetryConfig;
  readonly store: TelemetryStore;
  observeRequest(input: { method: string; path: string; status: number }): void;
  observeError(error: unknown, input: { path: string; status: number; component?: string }): void;
  handle(
    request: IncomingMessage,
    response: ServerResponse,
    path: string,
    url: URL,
    helpers: TelemetryRouteHelpers,
  ): Promise<boolean>;
  start(): void;
  stop(): Promise<void>;
  /** Exposed for tests and the admin page. */
  flush(): Promise<void>;
  digestNow(): Promise<string | null>;
  sendDue(): Promise<number>;
  previewNext(level?: TelemetryLevel): Promise<JsonObject | null>;
  probeOnce(): Promise<ComponentHealth[]>;
};

export function createTelemetryModule(input: {
  config: TelemetryConfig;
  database: Database;
  keyring: EncryptionKeyring;
  relaycontrolVersion: string;
  relaycastUrl?: string | null;
  fetchImpl?: FetchLike;
  audit?: TelemetryAudit;
  serviceCredentialVerifier?: ServiceCredentialVerifier;
  log?: (message: string, fields: JsonObject) => void;
  /**
   * SELFHOST_TENANCY. In multi mode the installation-wide views (config,
   * digests, the whole outbox, snapshots) are for the bootstrap bearer only;
   * an organisation admin sees the issue reports filed in that organisation.
   */
  tenancy?: TenancyMode;
}): TelemetryModule {
  const { config } = input;
  const store = new TelemetryStore(input.database);
  const fetchImpl = input.fetchImpl ?? ((url, init) => fetch(url, init));
  const log = input.log ?? ((message, fields) => console.log(`[selfhost-api] ${message}`, fields));
  const aggregator = new TelemetryAggregator(config);
  const deps: CollectorDeps = {
    config,
    store,
    keyring: input.keyring,
    relaycontrolVersion: input.relaycontrolVersion,
    relaycastUrl: input.relaycastUrl ?? null,
    fetchImpl,
  };
  const userAgent = `relaycontrol-telemetry/${input.relaycontrolVersion}`;
  const collectErrors = config.level !== "off";
  const collectUsage = config.level === "full";
  const canSend = config.transport === "https" && Boolean(config.endpoint && config.installId && config.installKey);
  const timers: NodeJS.Timeout[] = [];
  const unhealthyStreak = new Map<string, number>();
  const issueTimes: number[] = [];
  /** Multi mode: the organisation-admin lane, rate-limited per organisation. */
  const organizationIssueTimes = new Map<string, number[]>();
  let salt: string | null = null;
  let sending: Promise<number> | null = null;
  let stopped = false;

  void store.salt().then((value) => { salt = value; }).catch(() => undefined);

  async function enqueue(kind: OutboxKind, payload: JsonObject): Promise<{ id: string; body: string; redactions: number }> {
    const id = String(payload.reportId ?? randomUUID());
    const scrubbed = scrubPayload({ ...payload, scrubber: { version: TELEMETRY_SCRUBBER_VERSION } });
    const body = JSON.stringify({ ...scrubbed.value, scrubber: { version: TELEMETRY_SCRUBBER_VERSION, redactions: scrubbed.redactions } });
    await store.enqueueStandalone(kind, body, id);
    return { id, body, redactions: scrubbed.redactions };
  }

  async function reportBurst(observed: ObservedError, count: number, since: string | null): Promise<void> {
    if (!await store.claimBurst(observed.fingerprint, observed.component, 30 * 60)) return;
    const payload = await buildBurst(deps, config.level, {
      component: observed.component,
      fingerprint: observed.fingerprint,
      route: observed.route,
      status: observed.status,
      errorClass: observed.errorClass,
      count,
      since,
      windowSeconds: config.burstWindowSeconds,
    });
    await enqueue("error_burst", payload);
    log("telemetry error burst queued", { component: observed.component, fingerprint: observed.fingerprint });
    void sendDue().catch(() => undefined);
  }

  function recordError(observed: ObservedError): void {
    if (!collectErrors) return;
    if (aggregator.error(observed)) {
      const recent = aggregator.recentCount(observed.fingerprint, observed.component);
      void reportBurst(observed, recent.count, recent.since).catch((error: unknown) => {
        log("telemetry burst report failed", { error: error instanceof Error ? error.name : "unknown" });
      });
    }
  }

  function observeRequest(request: { method: string; path: string; status: number }): void {
    if (!collectUsage) return;
    const area = featureArea(request.path);
    if (area === "telemetry") return;
    const statusClass = `${Math.floor(request.status / 100)}xx`;
    aggregator.count(`req:${area}`, "total");
    aggregator.count(`req:${area}`, statusClass);
    const workspace = /\/workspaces\/([0-9a-f-]{36})(?:\/|$)/i.exec(request.path)?.[1];
    if (workspace && salt) aggregator.count("workspace", hashIdentifier(salt, workspace.toLowerCase()));
    if (request.path.endsWith("/login/poll") && request.status === 200) aggregator.count("login", "dashboard");
    if (request.path.endsWith("/auth/device/token") && request.status === 200) aggregator.count("login", "cli");
  }

  function observeError(error: unknown, context: { path: string; status: number; component?: string }): void {
    if (!collectErrors) return;
    // UpstreamError carries the upstream service; attribute the error to it.
    const upstream = error && typeof error === "object" && "stage" in error ? "relayhistory" : null;
    recordError(describeError(error, {
      component: context.component ?? upstream ?? "relaycontrol",
      path: context.path,
      status: context.status,
    }));
  }

  async function flush(): Promise<void> {
    const deltas = aggregator.drain();
    try {
      await store.flush(deltas.counters, deltas.errors);
    } catch (error) {
      aggregator.restore(deltas);
      throw error;
    }
  }

  async function probeOnce(): Promise<ComponentHealth[]> {
    const components = await collectComponents(deps);
    for (const component of components.slice(1)) {
      if (component.healthy) {
        unhealthyStreak.delete(component.name);
        continue;
      }
      const streak = (unhealthyStreak.get(component.name) ?? 0) + 1;
      unhealthyStreak.set(component.name, streak);
      const errorClass = `HealthCheckFailed:${component.reason ?? `http_${component.status ?? 0}`}`;
      const observed: ObservedError = {
        component: component.name,
        route: "/health",
        status: component.status ?? 0,
        errorClass,
        fingerprint: errorFingerprint({ component: component.name, errorClass }),
      };
      if (collectErrors) aggregator.error(observed);
      // Three consecutive failed probes is an outage: report it immediately.
      if (collectErrors && streak === 3) {
        void reportBurst(observed, streak, null).catch(() => undefined);
      }
    }
    return components;
  }

  async function digestNow(): Promise<string | null> {
    await flush();
    const id = await store.closeWindow(async (window) => {
      const payload = await buildDigest(deps, window, config.level);
      if (!payload) return null;
      const scrubbed = scrubPayload(payload);
      const body = JSON.stringify({
        ...scrubbed.value,
        scrubber: { version: TELEMETRY_SCRUBBER_VERSION, redactions: scrubbed.redactions },
      });
      return { id: String(payload.reportId), body };
    });
    if (id) void sendDue().catch(() => undefined);
    return id;
  }

  async function sendDue(): Promise<number> {
    if (!canSend) return 0;
    if (sending) return sending;
    sending = (async () => {
      let sent = 0;
      for (const row of await store.due(20)) {
        const outcome = await sendOne({
          row,
          endpoint: config.endpoint!,
          installId: config.installId!,
          installKey: config.installKey!,
          userAgent,
          fetchImpl,
          store,
        });
        if (outcome === "sent") sent += 1;
        else break; // endpoint unhappy: back off the whole queue this round
      }
      return sent;
    })().finally(() => { sending = null; });
    return sending;
  }

  async function previewNext(level: TelemetryLevel = config.level): Promise<JsonObject | null> {
    await flush();
    const window = await store.peekWindow();
    const state = await store.state();
    const payload = await buildDigest(deps, { ...window, windowStartedAt: state.windowStartedAt }, level);
    if (!payload) return null;
    const scrubbed = scrubPayload(payload);
    return { ...scrubbed.value as JsonObject, scrubber: { version: TELEMETRY_SCRUBBER_VERSION, redactions: scrubbed.redactions } };
  }

  function every(seconds: number, task: () => Promise<unknown>): void {
    const timer = setInterval(() => {
      if (stopped) return;
      void task().catch((error: unknown) => {
        log("telemetry task failed", { error: error instanceof Error ? error.name : "unknown" });
      });
    }, seconds * 1000);
    timer.unref();
    timers.push(timer);
  }

  function start(): void {
    if (collectErrors) {
      every(30, flush);
      every(60, probeOnce);
      every(60, async () => {
        const state = await store.state();
        const since = Date.parse(state.lastDigestAt ?? state.windowStartedAt);
        if (Date.now() - since >= config.digestIntervalSeconds * 1000) await digestNow();
      });
    }
    if (canSend) every(15, sendDue);
    every(3600, () => store.prune());
    log("telemetry started", describeTelemetryConfig(config));
  }

  async function stop(): Promise<void> {
    stopped = true;
    for (const timer of timers) clearInterval(timer);
    await flush().catch(() => undefined);
  }

  // ------------------------------------------------------------- routes

  async function serviceAccess(request: IncomingMessage, helpers: TelemetryRouteHelpers, scope: string): Promise<TelemetryAuditActor> {
    const token = helpers.bearer(request);
    if (!token) throw new TelemetryHttpError(401, "unauthorized", "Service credential required");
    if (config.internalServiceToken && secureEqual(token, config.internalServiceToken)) {
      return { kind: "service", subject: "internal-service-token" };
    }
    const verified = input.serviceCredentialVerifier ? await input.serviceCredentialVerifier(token) : null;
    if (!verified) throw new TelemetryHttpError(401, "unauthorized", "Service credential required");
    if (verified.scopes && !verified.scopes.includes(scope)) {
      throw new TelemetryHttpError(403, "insufficient_scope", `Credential lacks ${scope}`);
    }
    return { kind: "service", subject: verified.subject.slice(0, 200) };
  }

  async function status(): Promise<JsonObject> {
    return {
      config: describeTelemetryConfig(config),
      sending: canSend,
      ...await store.stats(),
    };
  }

  async function preview(): Promise<JsonObject> {
    const next = await previewNext();
    const pending = await store.list(["pending"], 20);
    return {
      level: config.level,
      transport: config.transport,
      endpoint: config.endpoint,
      note: config.level === "off"
        ? "Telemetry is off: nothing is collected or sent automatically. Issue reports are sent only when you file one."
        : config.transport === "file"
          ? "Air-gapped: nothing is sent over the network. Use the export download to send reports manually."
          : "This is exactly the body of the next digest, after scrubbing. Pending entries are already queued.",
      nextDigest: next,
      pending: pending.map((row) => ({
        id: row.id,
        kind: row.kind,
        attempts: row.attempts,
        nextAttemptAt: row.nextAttemptAt,
        lastError: row.lastError,
        body: JSON.parse(row.body) as unknown,
      })),
    };
  }

  async function exportFile(url: URL): Promise<{ body: JsonObject; exportedIds: string[] }> {
    if (!config.installId || !config.installKey) {
      throw new TelemetryHttpError(409, "telemetry_not_configured",
        "An install ID and install key are required to sign exports");
    }
    const envelopes: JsonObject[] = [];
    const exportedIds: string[] = [];
    if (url.searchParams.get("snapshot") === "1") {
      // Explicit operator action: a one-off snapshot, even when the level is off.
      const requested = url.searchParams.get("level") ?? (config.level === "off" ? "errors" : config.level);
      if (requested !== "errors" && requested !== "full") {
        throw new TelemetryHttpError(400, "invalid_request", "level must be errors or full");
      }
      const snapshot = await previewNext(requested);
      if (snapshot) {
        envelopes.push(exportEnvelope(config.installId, config.installKey, JSON.stringify({ ...snapshot, kind: "digest" })));
      }
    }
    for (const row of await store.list(["pending"], 500)) {
      envelopes.push(exportEnvelope(config.installId, config.installKey, row.body));
      exportedIds.push(row.id);
    }
    return {
      body: {
        format: `${EXPORT_FORMAT}+bundle`,
        installId: config.installId,
        exportedAt: new Date().toISOString(),
        envelopes,
      },
      exportedIds,
    };
  }

  /**
   * `organizationScoped`: a multi-mode organisation admin filed it. Their
   * report carries no installation-wide diagnostics (they can read it back
   * through preview/export/dryRun) and counts against a per-organisation
   * limit; the operator lanes keep the installation-wide limit.
   */
  async function fileIssue(
    body: JsonObject,
    actor: TelemetryAuditActor,
    organizationId: string | null,
    organizationScoped = false,
  ): Promise<{ status: number; body: JsonObject }> {
    let issue;
    try {
      issue = parseIssue(body);
    } catch (error) {
      if (error instanceof IssueValidationError) throw new TelemetryHttpError(400, "invalid_request", error.message);
      throw error;
    }
    const now = Date.now();
    let times = issueTimes;
    if (organizationScoped && organizationId) {
      times = organizationIssueTimes.get(organizationId) ?? [];
      organizationIssueTimes.set(organizationId, times);
    }
    while (times.length && times[0]! < now - 3_600_000) times.shift();
    if (!issue.dryRun && times.length >= 20) {
      throw new TelemetryHttpError(429, "rate_limited", "At most 20 issue reports per hour");
    }
    const currentSalt = salt ?? await store.salt();
    const window = await store.peekWindow();
    const payload: JsonObject = {
      ...envelopeBase(deps, "issue_report", config.level),
      issue: issueSection(issue),
      reporter: {
        kind: actor.kind,
        id: actor.kind === "user"
          ? hashIdentifier(currentSalt, actor.userId)
          : actor.kind === "service" ? hashIdentifier(currentSalt, actor.subject) : null,
      },
      diagnostics: organizationScoped
        ? { scope: "organization" }
        : {
          components: await collectComponents(deps),
          recentErrors: errorEntries(window.errors, 20),
        },
      supportBundle: sanitizeSupportBundle(issue.supportBundle),
    };
    const scrubbed = scrubPayload(payload);
    const finalBody = { ...scrubbed.value, scrubber: { version: TELEMETRY_SCRUBBER_VERSION, redactions: scrubbed.redactions } };
    if (issue.dryRun) {
      return { status: 200, body: { dryRun: true, wouldSend: finalBody } };
    }
    if (!config.installId || !config.installKey) {
      throw new TelemetryHttpError(409, "telemetry_not_configured",
        "Telemetry install ID and key are not configured; use dryRun to preview, or configure telemetry");
    }
    const id = String(payload.reportId);
    await store.enqueueStandalone("issue_report", JSON.stringify(finalBody), id, organizationId);
    times.push(now);
    await input.audit?.({ organizationId, actor, action: "telemetry.issue.create", target: id });
    if (canSend) void sendDue().catch(() => undefined);
    return {
      status: 202,
      body: {
        id,
        delivery: canSend ? "queued" : "export",
        message: canSend
          ? "Queued for delivery to Agent Relay support."
          : "Queued for manual export (air-gapped). Download it from the telemetry export endpoint.",
        sent: finalBody,
      },
    };
  }

  async function routes(
    request: IncomingMessage,
    response: ServerResponse,
    path: string,
    url: URL,
    helpers: TelemetryRouteHelpers,
  ): Promise<boolean> {
    const method = request.method ?? "GET";

    if (path === "/api/v1/telemetry/admin" && method === "GET") {
      response.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store",
        "referrer-policy": "no-referrer",
        "content-security-policy":
          "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
      });
      response.end(adminPage());
      return true;
    }
    if (path === "/api/v1/telemetry/mcp-tool" && method === "GET") {
      json(response, 200, {
        tool: REPORT_ISSUE_TOOL,
        endpoints: {
          user: "POST /api/v1/organizations/{organizationId}/telemetry/issues",
          service: "POST /internal/v1/telemetry/issues",
        },
      });
      return true;
    }

    if (path === "/internal/v1/telemetry/issues" && method === "POST") {
      const actor = await serviceAccess(request, helpers, TELEMETRY_ISSUE_SCOPE);
      const result = await fileIssue(await helpers.requestObject(request), actor, null);
      json(response, result.status, result.body);
      return true;
    }
    if (path === "/internal/v1/telemetry/preview" && method === "GET") {
      await serviceAccess(request, helpers, TELEMETRY_ISSUE_SCOPE);
      json(response, 200, await preview());
      return true;
    }

    const orgRoute = /^\/api\/v1\/organizations\/([^/]+)\/telemetry(?:\/(preview|export|issues))?$/.exec(path);
    if (!orgRoute) return false;
    const organizationId = decodeURIComponent(orgRoute[1]!);
    const action = orgRoute[2] ?? "status";
    const auth = await helpers.organizationAccess(request, organizationId, true);

    // Multi mode: an organisation admin (not the bootstrap bearer) gets the
    // view of the path organisation only; organizationAccess already refused
    // any other organisation with 404.
    if ((input.tenancy ?? "single") === "multi" && actorFor(auth).kind !== "bootstrap" && action !== "issues") {
      if (method !== "GET") throw new TelemetryHttpError(405, "method_not_allowed", "Method not allowed");
      if (action === "status") {
        json(response, 200, {
          scope: "organization",
          organizationId,
          level: config.level,
          transport: config.transport,
          issueReports: await store.statsForOrganization(organizationId),
        });
        return true;
      }
      if (action === "preview") {
        if (url.searchParams.has("level")) throw installationScope();
        const pending = await store.listForOrganization(organizationId, ["pending"], 20);
        json(response, 200, {
          scope: "organization",
          organizationId,
          level: config.level,
          transport: config.transport,
          note: "Digests and error reports are installation-wide and visible to the installation operator only. These are the issue reports filed in this organization.",
          nextDigest: null,
          pending: pending.map((row) => ({
            id: row.id,
            kind: row.kind,
            attempts: row.attempts,
            nextAttemptAt: row.nextAttemptAt,
            lastError: row.lastError,
            body: JSON.parse(row.body) as unknown,
          })),
        });
        return true;
      }
      if (action !== "export") throw new TelemetryHttpError(404, "not_found", "Not found");
      // export: this organisation's pending issue reports, signed. Delivery
      // stays with the operator, so nothing is marked exported.
      if (url.searchParams.get("snapshot") === "1") throw installationScope();
      if (!config.installId || !config.installKey) {
        throw new TelemetryHttpError(409, "telemetry_not_configured",
          "An install ID and install key are required to sign exports");
      }
      const rows = await store.listForOrganization(organizationId, ["pending"], 500);
      const body = {
        format: `${EXPORT_FORMAT}+bundle`,
        installId: config.installId,
        organizationId,
        exportedAt: new Date().toISOString(),
        envelopes: rows.map((row) => exportEnvelope(config.installId!, config.installKey!, row.body)),
      };
      await input.audit?.({ organizationId, actor: actorFor(auth), action: "telemetry.export", target: String(rows.length) });
      json(response, 200, body, {
        "content-disposition": `attachment; filename="agent-relay-telemetry-${new Date().toISOString().slice(0, 10)}.json"`,
      });
      return true;
    }

    if (action === "status" && method === "GET") {
      json(response, 200, await status());
      return true;
    }
    if (action === "preview" && method === "GET") {
      const level = url.searchParams.get("level");
      if (level && level !== config.level) {
        if (!TELEMETRY_LEVELS.includes(level as TelemetryLevel)) {
          throw new TelemetryHttpError(400, "invalid_request", "level must be off, errors, or full");
        }
        // "What would we send at this level?" without changing anything.
        json(response, 200, { level, nextDigest: await previewNext(level as TelemetryLevel), hypothetical: true });
        return true;
      }
      json(response, 200, await preview());
      return true;
    }
    if (action === "export" && method === "GET") {
      const { body, exportedIds } = await exportFile(url);
      // Air-gapped installs hand these to an operator, so mark them exported.
      if (config.transport === "file") await store.markExported(exportedIds);
      await input.audit?.({ organizationId, actor: actorFor(auth), action: "telemetry.export", target: String(body.envelopes && (body.envelopes as unknown[]).length) });
      json(response, 200, body, {
        "content-disposition": `attachment; filename="agent-relay-telemetry-${new Date().toISOString().slice(0, 10)}.json"`,
      });
      return true;
    }
    if (action === "issues" && method === "POST") {
      const type = request.headers["content-type"]?.split(";")[0]?.trim().toLowerCase();
      if (!helpers.bearer(request) && type !== "application/json") {
        throw new TelemetryHttpError(415, "unsupported_media_type", "Use application/json");
      }
      const actor = actorFor(auth);
      const organizationScoped = (input.tenancy ?? "single") === "multi" && actor.kind !== "bootstrap";
      const result = await fileIssue(await helpers.requestObject(request), actor, organizationId, organizationScoped);
      json(response, result.status, result.body);
      return true;
    }
    throw new TelemetryHttpError(405, "method_not_allowed", "Method not allowed");
  }

  async function handle(
    request: IncomingMessage,
    response: ServerResponse,
    path: string,
    url: URL,
    helpers: TelemetryRouteHelpers,
  ): Promise<boolean> {
    if (!path.startsWith("/api/v1/telemetry") && !path.startsWith("/internal/v1/telemetry") &&
      !/^\/api\/v1\/organizations\/[^/]+\/telemetry/.test(path)) {
      return false;
    }
    try {
      return await routes(request, response, path, url, helpers);
    } catch (error) {
      if (error instanceof TelemetryHttpError) {
        json(response, error.status, { error: error.code, message: error.message });
        return true;
      }
      throw error;
    }
  }

  return {
    config,
    store,
    observeRequest,
    observeError,
    handle,
    start,
    stop,
    flush,
    digestNow,
    sendDue,
    previewNext,
    probeOnce,
  };
}
