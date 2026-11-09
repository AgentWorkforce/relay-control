// analytics lane: lifecycle wiring. Export failures never reach the product
// path, and the three lifecycle events share one trace_id end to end.
import assert from "node:assert/strict";
import { createServer, type IncomingHttpHeaders } from "node:http";
import test from "node:test";
import { loadAnalyticsConfig } from "../src/analytics/config.js";
import {
  buildAnalytics,
  emitConfigLoaded,
  emitServiceStarted,
  emitStopping,
} from "../src/analytics/lifecycle.js";
import type { AnalyticsSink } from "../src/analytics/types.js";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase } from "./support/harness.js";

const TOKEN = "producer-token-lifecycle-test";
const FACTS = {
  telemetry: { level: "off", transport: "https" },
  signIn: { oidc: false, emailLink: true, smtp: false },
  flowsEnabled: true,
  operatorOAuthApps: 2,
  componentVersion: "0.1.0",
  configFingerprint: "fp_test_0001",
};
const quiet = () => {};

function collectorEnv(url: string): NodeJS.ProcessEnv {
  return {
    SELFHOST_ANALYTICS_DESTINATION: "collector",
    SELFHOST_ANALYTICS_PROFILE: "development",
    // The complete endpoint URL: the adapter appends nothing.
    SELFHOST_ANALYTICS_COLLECTOR_URL: `${url}/v1/events`,
    SELFHOST_ANALYTICS_COLLECTOR_TOKEN: TOKEN,
    SELFHOST_ANALYTICS_DEPLOYMENT_ID: "dep_lifecycle_01",
    SELFHOST_ANALYTICS_REQUEST_TIMEOUT_MS: "1000",
  };
}

async function healthyApp() {
  const database = new PGliteDatabase();
  await migrate(database);
  const config: SelfhostConfig = {
    databaseUrl: "unused-in-test",
    publicBaseUrl: "https://control.internal.example",
    relaycastUrl: "http://relaycast.relay.svc.cluster.local",
    relaycastPublicUrl: "https://relaycast.internal.example",
    relayhistoryUrl: "http://relayhistory.relay.svc.cluster.local",
    relayhistoryPublicUrl: "https://history.internal.example",
    sessionReadApi: { url: "http://relayhistory.relay.svc.cluster.local", publicUrl: "https://history.internal.example", secret: "session-read-secret-".repeat(2) },
    bootstrapToken: "bootstrap-token-that-is-at-least-32-bytes",
    encryptionKeyring: { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    internalServiceToken: null,
    oauthRedirectUrl: "https://control.internal.example/api/v1/integrations/oauth/callback",
    dashboardUrl: "https://control.internal.example/",
    port: 3000,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  const server = createServer(createApp({ config, store }));
  const origin = await listen(server);
  return {
    origin,
    async stop() {
      await close(server);
      await database.close();
    },
  };
}

async function unreachableOrigin(): Promise<string> {
  const server = createServer();
  const origin = await listen(server);
  await close(server);
  return origin;
}

test("collector failures never reach capture, startup, or the health route", async (t) => {
  const failing = createServer((request, response) => {
    request.resume();
    request.on("end", () => {
      response.writeHead(500).end();
    });
  });
  const failingOrigin = await listen(failing);
  const app = await healthyApp();
  t.after(async () => {
    await close(failing);
    await app.stop();
  });
  const throwing: AnalyticsSink = {
    name: "collector",
    send() {
      throw new Error("sink exploded synchronously");
    },
  };

  const cases: Array<{ name: string; url: string; sink?: AnalyticsSink; check(stats: any): void }> = [
    {
      name: "unreachable",
      url: await unreachableOrigin(),
      check: (stats) => {
        assert.ok(stats.failures.transport >= 1);
        assert.equal(stats.lastFailureReason, "transport");
      },
    },
    {
      name: "synchronous throw",
      url: "http://127.0.0.1:9",
      sink: throwing,
      check: (stats) => assert.ok(stats.failures.transport >= 1),
    },
    {
      name: "500",
      url: failingOrigin,
      check: (stats) => assert.equal(stats.lastFailureReason, "server"),
    },
  ];

  for (const entry of cases) {
    const config = loadAnalyticsConfig(collectorEnv(entry.url));
    const analytics = buildAnalytics(config, { log: quiet, sink: entry.sink });
    // As src/server.ts: config_loaded at load, service_started once listening.
    assert.doesNotThrow(() => emitConfigLoaded(analytics, FACTS), entry.name);
    assert.doesNotThrow(() => emitServiceStarted(analytics, FACTS), entry.name);
    // The product path is unaffected while exports are failing.
    const health = await fetch(`${app.origin}/healthz`);
    assert.equal(health.status, 200, entry.name);
    await health.arrayBuffer();

    const started = Date.now();
    const flushed = await emitStopping(analytics, "SIGTERM", 1200, { log: quiet });
    assert.ok(Date.now() - started < 3000, `${entry.name} flush is deadline bounded`);
    assert.equal(flushed.sent, 0, entry.name);
    const stats = analytics.stats();
    assert.equal(stats.captured, 3, entry.name);
    assert.equal(stats.sent.events, 0, entry.name);
    assert.equal(stats.queueEvents, 0, entry.name);
    const dropped = Object.values(stats.dropped as Record<string, number>).reduce((sum, value) => sum + value, 0);
    assert.equal(dropped, 3, entry.name);
    entry.check(stats);
  }
});

test("config_loaded, service_started and service_stopping reach the collector with one trace_id", async (t) => {
  const received: Array<{ headers: IncomingHttpHeaders; rawHeaders: string[]; body: any }> = [];
  const collector = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      received.push({
        headers: request.headers,
        rawHeaders: request.rawHeaders,
        body: JSON.parse(Buffer.concat(chunks).toString("utf8")),
      });
      response.writeHead(request.url === "/v1/events" ? 204 : 404).end();
    });
  });
  const origin = await listen(collector);
  t.after(() => close(collector));

  const logs: string[] = [];
  const config = loadAnalyticsConfig(collectorEnv(origin));
  const analytics = buildAnalytics(config, { log: (message, fields) => logs.push(`${message} ${JSON.stringify(fields ?? {})}`) });
  emitConfigLoaded(analytics, FACTS);
  emitServiceStarted(analytics, FACTS);
  const flushed = await emitStopping(analytics, "SIGTERM", 2000, { log: (message, fields) => logs.push(`${message} ${JSON.stringify(fields ?? {})}`) });
  assert.deepEqual(flushed, { sent: 3, dropped: 0 });

  const events = received.flatMap((entry) => entry.body.events);
  assert.deepEqual(events.map((event: any) => event.event), ["config_loaded", "service_started", "service_stopping"]);
  const traceIds = new Set(events.map((event: any) => event.trace_id));
  assert.equal(traceIds.size, 1);
  assert.equal([...traceIds][0], analytics.bootTraceId);
  assert.equal(new Set(events.map((event: any) => event.event_id)).size, 3);
  for (const event of events) {
    assert.equal(event.deployment_id, "dep_lifecycle_01");
    assert.equal(event.version, 1);
    assert.equal("tenant_id" in event, false);
    assert.equal("workspace_id" in event, false);
  }
  assert.deepEqual(events[0].properties, {
    telemetry_level: "off",
    telemetry_transport: "https",
    sign_in_oidc: false,
    sign_in_email_link: true,
    sign_in_smtp: false,
    flows_enabled: true,
    operator_oauth_apps: 2,
  });
  assert.deepEqual(events[1].properties, { component_version: "0.1.0", config_fingerprint: "fp_test_0001" });
  assert.deepEqual(events[2].properties, { reason: "SIGTERM" });
  for (const entry of received) {
    assert.equal(entry.body.schema, "agent-relay.analytics.batch/v1");
    assert.equal(entry.headers.authorization, `Bearer ${TOKEN}`);
    assert.equal(entry.rawHeaders.filter((name, index) => index % 2 === 0 && name.toLowerCase() === "authorization").length, 1);
  }
  // Startup and stop logs describe the configuration without the token.
  assert.ok(logs.some((line) => line.startsWith("analytics started")));
  assert.ok(logs.some((line) => line.startsWith("analytics stopped")));
  assert.equal(logs.some((line) => line.includes(TOKEN)), false);
});
