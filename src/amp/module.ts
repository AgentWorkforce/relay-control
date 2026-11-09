import type { SelfhostConfig } from "../config.js";
import type { Database } from "../database.js";
import { createRelaycastClient } from "../messaging/relaycast.js";
import type { AmpConfig } from "./config.js";
import { createAmpHandler } from "./routes.js";
import { createAmpRuntime, type AmpRuntime } from "./runtime.js";
import type { HistoryUploader, PushSessionFactory } from "./history.js";
import type { AmpDeps } from "./service.js";
import { startAmpWorker, type AmpWorker } from "./worker.js";

export type AmpModule = {
  config: AmpConfig;
  deps: AmpDeps;
  handle: ReturnType<typeof createAmpHandler>;
  /** Starts the outbox worker; a no-op returning null when the feature is off. */
  start(): AmpWorker | null;
  stop(): Promise<void>;
};

export function createAmpModule(input: {
  amp: AmpConfig;
  config: SelfhostConfig;
  database: Database;
  /** Relaycast fetch (tests inject a fake). */
  relaycastFetch?: typeof fetch;
  /** Amp transport fetch (tests inject a fake transport). */
  transportFetch?: typeof fetch;
  runtime?: AmpRuntime;
  now?: () => Date;
  /** Tests only: a fake push-session factory and uploader. Production never sets these. */
  pushSession?: PushSessionFactory | null;
  historyUpload?: HistoryUploader;
}): AmpModule {
  const deps: AmpDeps = {
    database: input.database,
    keyring: input.config.encryptionKeyring,
    relaycast: createRelaycastClient({ internalOrigin: input.config.relaycastUrl, fetchImpl: input.relaycastFetch }),
    run: input.runtime ?? createAmpRuntime(input.amp.transport, input.transportFetch ?? fetch),
    publicBaseUrl: input.config.publicBaseUrl,
    now: input.now ?? (() => new Date()),
    leaseMs: input.amp.leaseMs,
    // Missing capability: a workspace-scoped, push-only (rth:sync) RelayHistory
    // session issued without a caller token. src/relayhistory.ts
    // issueRelayhistorySession only exchanges the caller's sh_at_ token, and
    // POST /internal/v1/auth/introspect answers only sh_at_ person tokens, so a
    // background job has nothing to upload with. History stays inactive (no
    // Amp export or poll) until such an issuer exists; no fallback is wired.
    pushSession: input.pushSession ?? null,
    ...(input.historyUpload ? { historyUpload: input.historyUpload } : {}),
  };
  let worker: AmpWorker | null = null;
  const handle = createAmpHandler({
    config: input.amp,
    deps,
    database: input.database,
    internalServiceToken: input.config.internalServiceToken,
    browserOrigins: [...new Set([new URL(input.config.publicBaseUrl).origin, new URL(input.config.dashboardUrl).origin])],
    wake: () => worker?.wake(),
  });
  return {
    config: input.amp,
    deps,
    handle,
    start() {
      if (!input.amp.enabled) return null;
      worker ??= startAmpWorker(deps, input.amp.workerIntervalMs);
      return worker;
    },
    async stop() {
      await worker?.stop();
      worker = null;
    },
  };
}
