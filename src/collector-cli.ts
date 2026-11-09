#!/usr/bin/env node
// Analytics collector entrypoint (bin agent-relay-analytics-collector). A
// separate process from the control server: internal POST /v1/events and
// GET /healthz, atomic NDJSON segments under ANALYTICS_COLLECTOR_DATA_DIR.
// See docs/analytics-collector.md.
import { COLLECTOR_REGISTRIES } from "./analytics-collector/registries.js";
import { createCollector, loadCollectorConfig, loadProducers, type Collector } from "./analytics-collector/index.js";

const log = (message: string, fields: Record<string, unknown> = {}): void => {
  console.log(`[analytics-collector] ${message}`, fields);
};

let collector: Collector | null = null;
let shutdownDeadlineMs = 5000;

async function start(): Promise<void> {
  const config = loadCollectorConfig(process.env);
  shutdownDeadlineMs = config.shutdownDeadlineMs;
  const producers = loadProducers(config.producersFile);
  collector = await createCollector({
    config,
    producers,
    registries: COLLECTOR_REGISTRIES,
    log,
  });
  const address = await collector.listen();
  const { producersFile: _file, ...limits } = config;
  log("listening", { ...limits, host: address.host, port: address.port, producers: producers.describe() });
}

async function shutdown(signal: "SIGINT" | "SIGTERM"): Promise<void> {
  // Hard stop just past the deadline, whatever happens below.
  setTimeout(() => process.exit(1), shutdownDeadlineMs + 1000).unref();
  log("shutting down", { signal });
  if (!collector) process.exit(0);
  const { completed } = await collector.shutdown(shutdownDeadlineMs);
  log("stopped", { completed });
  process.exit(completed ? 0 : 1);
}

process.once("SIGINT", () => void shutdown("SIGINT"));
process.once("SIGTERM", () => void shutdown("SIGTERM"));

void start().catch((error: unknown) => {
  process.exitCode = 1;
  // Configuration errors from the collector modules name variables or
  // producers only, never values. System errors (listen, fs) report their code
  // only, never their text.
  const code = (error as { code?: unknown } | null)?.code;
  console.error("[analytics-collector] startup failed", typeof code === "string"
    ? { code }
    : { error: error instanceof Error ? error.message : "unknown" });
  void collector?.shutdown(0);
});
