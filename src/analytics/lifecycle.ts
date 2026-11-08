// analytics lane: construction from config and the three installation-scoped
// lifecycle events wired in src/server.ts. Kept here so they can be tested
// without starting the server.
import { describeAnalyticsConfig, type AnalyticsConfig } from "./config.js";
import { createAnalytics, type AnalyticsQueue } from "./queue.js";
import { createCollectorSink } from "./sinks/collector.js";
import { noneSink } from "./sinks/none.js";
import { createPosthogSink } from "./sinks/posthog.js";
import type { AnalyticsClock, AnalyticsLog, AnalyticsPort, AnalyticsSink, FlushResult } from "./types.js";

export function createAnalyticsSink(config: AnalyticsConfig): AnalyticsSink {
  switch (config.destination) {
    case "collector":
      if (!config.collector) throw new Error("collector configuration is missing");
      return createCollectorSink(config.collector);
    case "posthog":
      if (!config.posthog) throw new Error("posthog configuration is missing");
      return createPosthogSink(config.posthog);
    case "none":
      return noneSink;
  }
}

export function buildAnalytics(
  config: AnalyticsConfig,
  options: { log?: AnalyticsLog; clock?: AnalyticsClock; sink?: AnalyticsSink } = {},
): AnalyticsQueue {
  const log = options.log ?? ((message, fields) => console.log(`[selfhost-api] ${message}`, fields ?? {}));
  const analytics = createAnalytics({
    limits: config,
    sink: options.sink ?? createAnalyticsSink(config),
    deploymentId: config.deploymentId,
    clock: options.clock,
    log,
  });
  log("analytics started", describeAnalyticsConfig(config));
  return analytics;
}

export type ConfigLoadedFacts = {
  telemetry: { level: string; transport: string };
  signIn: { oidc: boolean; emailLink: boolean; smtp: boolean };
  flowsEnabled: boolean;
  operatorOAuthApps: number;
};

/** Never the issuer URL or any secret: booleans, enums and counts only. */
export function emitConfigLoaded(analytics: AnalyticsPort, facts: ConfigLoadedFacts): void {
  analytics.capture({
    event: "config_loaded",
    properties: {
      telemetry_level: facts.telemetry.level,
      telemetry_transport: facts.telemetry.transport,
      sign_in_oidc: facts.signIn.oidc,
      sign_in_email_link: facts.signIn.emailLink,
      sign_in_smtp: facts.signIn.smtp,
      flows_enabled: facts.flowsEnabled,
      operator_oauth_apps: facts.operatorOAuthApps,
    },
  });
}

export function emitServiceStarted(
  analytics: AnalyticsPort,
  facts: { componentVersion: string; configFingerprint: string },
): void {
  analytics.capture({
    event: "service_started",
    properties: {
      component_version: facts.componentVersion,
      config_fingerprint: facts.configFingerprint,
    },
  });
}

export type StopReason = "SIGINT" | "SIGTERM" | "startup_failed";

/** Captures service_stopping and flushes by `now + deadlineMs`; never rejects. */
export async function emitStopping(
  analytics: AnalyticsPort,
  reason: StopReason,
  deadlineMs: number,
  options: { log?: AnalyticsLog; now?: () => number } = {},
): Promise<FlushResult> {
  analytics.capture({ event: "service_stopping", properties: { reason } });
  const result = await analytics.flush((options.now ?? Date.now)() + deadlineMs);
  const stats = analytics.stats();
  (options.log ?? ((message, fields) => console.log(`[selfhost-api] ${message}`, fields ?? {})))(
    "analytics stopped",
    { flushed: result, sent: stats.sent, dropped: stats.dropped, failures: stats.failures },
  );
  return result;
}
