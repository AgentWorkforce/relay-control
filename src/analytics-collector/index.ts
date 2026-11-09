// analytics collector: assembly. Opens (and recovers) the segment store, then
// builds the listener. Imports nothing from the app except
// src/analytics/types.ts and src/analytics/events.ts (through the modules here),
// so it can move to another repository unchanged.
import type { AddressInfo } from "node:net";
import type { CollectorConfig } from "./config.js";
import type { ProducerRegistry } from "./producers.js";
import { createCollectorServer, type CollectorHealth, type CollectorLog } from "./server.js";
import { SegmentStore, type CollectorFs } from "./storage.js";
import type { CollectorRegistries } from "./validate.js";

export { loadCollectorConfig, type CollectorConfig, type CollectorLimits, type RetentionPolicy } from "./config.js";
export { createProducerRegistry, loadProducers, type Producer, type ProducerRegistry } from "./producers.js";
export { EVENTS_PATH, HEALTH_PATH, type CollectorHealth, type CollectorLog } from "./server.js";
export { SEGMENT_NAME, SegmentStore, type CollectorFs } from "./storage.js";
export { validateBatch, BatchRejection, type CollectorRegistries } from "./validate.js";

export type CollectorOptions = {
  config: Omit<CollectorConfig, "producersFile">;
  producers: ProducerRegistry;
  registries: CollectorRegistries;
  fsImpl?: CollectorFs;
  now?: () => number;
  log?: CollectorLog;
};

export type Collector = {
  readonly server: import("node:http").Server;
  /** Listens on config.host:config.port; resolves with the bound address. */
  listen(): Promise<{ host: string; port: number }>;
  health(): CollectorHealth;
  /** Stops accepting, finishes in-flight commits, closes. Defaults to config.shutdownDeadlineMs. */
  shutdown(deadlineMs?: number): Promise<{ completed: boolean }>;
};

export async function createCollector(options: CollectorOptions): Promise<Collector> {
  const { config, producers, registries } = options;
  for (const producer of producers.list()) {
    if (!Object.hasOwn(registries, producer.component)) {
      throw new Error(`producer ${producer.name}: component has no registered event kinds`);
    }
  }
  const storage = await SegmentStore.open({
    dataDir: config.dataDir,
    maxSegments: config.maxSegments,
    maxDiskBytes: config.maxDiskBytes,
    retention: config.retention,
    retentionMaxAgeMs: config.retentionMaxAgeMs,
    fsImpl: options.fsImpl,
    now: options.now,
    log: options.log,
  });
  const http = createCollectorServer({ limits: config, producers, registries, storage, log: options.log });
  return {
    server: http.server,
    listen: () => new Promise((resolve, reject) => {
      http.server.once("error", reject);
      http.server.listen(config.port, config.host, () => {
        http.server.off("error", reject);
        const address = http.server.address() as AddressInfo;
        resolve({ host: address.address, port: address.port });
      });
    }),
    health: http.health,
    shutdown: (deadlineMs = config.shutdownDeadlineMs) => http.shutdown(deadlineMs),
  };
}
