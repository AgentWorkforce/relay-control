// Shared fixtures for the analytics collector tests: a collector on
// 127.0.0.1:0 over a temp data directory, synthetic envelopes, a raw poster
// and an fs wrapper that injects failures through the FileHandle.
import { randomUUID } from "node:crypto";
import * as nodeFs from "node:fs/promises";
import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TestContext } from "node:test";
import { EVENT_REGISTRY } from "../../src/analytics/events.js";
import { ANALYTICS_BATCH_SCHEMA } from "../../src/analytics/types.js";
import {
  createCollector,
  createProducerRegistry,
  type Collector,
  type CollectorConfig,
  type CollectorFs,
  type CollectorRegistries,
  type ProducerRegistry,
} from "../../src/analytics-collector/index.js";

export const TOKEN_A = "producer-a-token-0123456789abcdefghijklmnop";
export const TOKEN_B = "producer-b-token-qrstuvwxyz9876543210fedcba";
export const DEPLOYMENT_A = "deploy_a";
export const DEPLOYMENT_B = "deploy_b";

export const PRODUCERS = [
  { name: "control-a", component: "relaycontrol", deploymentId: DEPLOYMENT_A, token: TOKEN_A },
  { name: "control-b", component: "relaycontrol", deploymentId: DEPLOYMENT_B, token: TOKEN_B },
];

export type Envelope = Record<string, unknown>;

export function installEvent(overrides: Envelope = {}): Envelope {
  return {
    version: 1,
    event_id: randomUUID(),
    occurred_at: "2026-11-08T10:00:00.000Z",
    component: "relaycontrol",
    deployment_id: DEPLOYMENT_A,
    event: "service_started",
    trace_id: "trace-synthetic-0001",
    properties: { component_version: "0.1.0" },
    ...overrides,
  };
}

export function workspaceEvent(overrides: Envelope = {}): Envelope {
  return installEvent({
    event: "dashboard.page_viewed",
    tenant_id: "org_synthetic",
    workspace_id: "ws_synthetic",
    properties: { client: "dashboard", page: "overview" },
    ...overrides,
  });
}

export function tenantEvent(overrides: Envelope = {}): Envelope {
  return installEvent({
    event: "desktop.sign_in_completed",
    tenant_id: "org_synthetic",
    properties: { client: "desktop" },
    ...overrides,
  });
}

export function batch(events: unknown[]): { schema: string; events: unknown[] } {
  return { schema: ANALYTICS_BATCH_SCHEMA, events };
}

export async function tempDir(t: TestContext): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "analytics-collector-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

export type PostResult = { status: number; headers: Headers; raw: string; body: any };

export async function post(
  origin: string,
  body: unknown,
  options: { token?: string; contentType?: string; raw?: string | Uint8Array },
): Promise<PostResult> {
  const headers: Record<string, string> = { "content-type": options.contentType ?? "application/json" };
  if (options.token !== undefined) headers.authorization = `Bearer ${options.token}`;
  const response = await fetch(`${origin}/v1/events`, {
    method: "POST",
    headers,
    body: (options.raw ?? JSON.stringify(body)) as BodyInit,
  });
  const raw = await response.text();
  let parsed: unknown;
  try {
    parsed = raw ? JSON.parse(raw) : undefined;
  } catch {
    parsed = undefined;
  }
  return { status: response.status, headers: response.headers, raw, body: parsed };
}

export async function dirState(dataDir: string): Promise<{ tmp: string[]; segments: string[] }> {
  return {
    tmp: (await readdir(join(dataDir, "tmp"))).sort(),
    segments: (await readdir(join(dataDir, "segments"))).sort(),
  };
}

export async function readSegments(dataDir: string): Promise<Array<{ name: string; events: Envelope[] }>> {
  const { segments } = await dirState(dataDir);
  return Promise.all(segments.map(async (name) => {
    const content = await readFile(join(dataDir, "segments", name), "utf8");
    return { name, events: content.trimEnd().split("\n").map((line) => JSON.parse(line) as Envelope) };
  }));
}

export type FsHooks = {
  /** Before a FileHandle write (writeFile) on `path`. */
  write?: (path: string) => Promise<void> | void;
  /** Before a FileHandle sync on `path` (files and the segments directory). */
  sync?: (path: string) => Promise<void> | void;
  rename?: (from: string, to: string) => Promise<void> | void;
  unlink?: (path: string) => Promise<void> | void;
};

export function fsError(code: string): NodeJS.ErrnoException {
  const error = new Error(`${code}: injected failure with secret text`) as NodeJS.ErrnoException;
  error.code = code;
  return error;
}

/** node:fs/promises with hooks; FileHandle methods are wrapped through a Proxy. */
export function faultyFs(hooks: FsHooks): CollectorFs {
  return {
    ...nodeFs,
    open: (async (path: string, flags?: string, mode?: number) => {
      const handle = await nodeFs.open(path, flags, mode);
      return new Proxy(handle, {
        get(target, property, receiver) {
          const value = Reflect.get(target, property, receiver);
          if (property === "writeFile" && hooks.write) {
            return async (...args: unknown[]) => {
              await hooks.write!(String(path));
              return (value as (...a: unknown[]) => unknown).apply(target, args);
            };
          }
          if (property === "sync" && hooks.sync) {
            return async () => {
              await hooks.sync!(String(path));
              return target.sync();
            };
          }
          return typeof value === "function" ? value.bind(target) : value;
        },
      });
    }) as CollectorFs["open"],
    rename: async (from, to) => {
      await hooks.rename?.(String(from), String(to));
      return nodeFs.rename(from, to);
    },
    unlink: async (path) => {
      await hooks.unlink?.(String(path));
      return nodeFs.unlink(path);
    },
  };
}

export type SetupOptions = {
  config?: Partial<Omit<CollectorConfig, "producersFile">>;
  producers?: ProducerRegistry;
  registries?: CollectorRegistries;
  fsImpl?: CollectorFs;
  now?: () => number;
  /** Use this data directory instead of a fresh one (to restart over the same store). */
  dataDir?: string;
};

export type CollectorContext = {
  origin: string;
  dataDir: string;
  collector: Collector;
  logs: Array<{ message: string; fields?: Record<string, unknown> }>;
};

export async function setup(t: TestContext, options: SetupOptions = {}): Promise<CollectorContext> {
  const dataDir = options.dataDir ?? await tempDir(t);
  const logs: CollectorContext["logs"] = [];
  const collector = await createCollector({
    config: {
      host: "127.0.0.1",
      port: 0,
      dataDir,
      maxBatchBytes: 262_144,
      maxBatchEvents: 500,
      maxEventBytes: 4096,
      requestTimeoutMs: 10_000,
      maxInFlight: 16,
      maxSegments: 100_000,
      maxDiskBytes: 64 * 1024 * 1024,
      shutdownDeadlineMs: 2000,
      retention: "reject-new",
      retentionMaxAgeMs: null,
      ...options.config,
    },
    producers: options.producers ?? createProducerRegistry(PRODUCERS),
    registries: options.registries ?? { relaycontrol: EVENT_REGISTRY },
    fsImpl: options.fsImpl,
    now: options.now,
    log: (message, fields) => logs.push({ message, fields }),
  });
  const { port } = await collector.listen();
  t.after(async () => {
    if (collector.server.listening) await collector.shutdown(1000);
  });
  return { origin: `http://127.0.0.1:${port}`, dataDir, collector, logs };
}
