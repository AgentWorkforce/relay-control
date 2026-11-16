import type { SelfhostConfig } from "../config.js";
import type { Database } from "../database.js";
import { createRelaycastClient } from "../messaging/relaycast.js";
import type { ReplicasConfig } from "./config.js";
import { createReplicasHandler } from "./routes.js";
import { createReplicasRuntime, type ReplicasRuntime } from "./runtime.js";
import type { ReplicasDeps } from "./service.js";

export type ReplicasModule = {
  config: ReplicasConfig;
  deps: ReplicasDeps;
  handle: ReturnType<typeof createReplicasHandler>;
};

export function createReplicasModule(input: {
  replicas: ReplicasConfig;
  config: SelfhostConfig;
  database: Database;
  /** Relaycast fetch (tests inject a fake). */
  relaycastFetch?: typeof fetch;
  /** Replicas provider fetch (tests inject a fake provider). */
  replicasFetch?: typeof fetch;
  runtime?: ReplicasRuntime;
  now?: () => Date;
}): ReplicasModule {
  const deps: ReplicasDeps = {
    database: input.database,
    keyring: input.config.encryptionKeyring,
    relaycast: createRelaycastClient({ internalOrigin: input.config.relaycastUrl, fetchImpl: input.relaycastFetch }),
    replicas: input.runtime ?? createReplicasRuntime({ fetchImpl: input.replicasFetch }),
    publicBaseUrl: input.config.publicBaseUrl,
    now: input.now ?? (() => new Date()),
  };
  const handle = createReplicasHandler({
    enabled: input.replicas.enabled,
    deps,
    database: input.database,
    internalServiceToken: input.config.internalServiceToken,
    browserOrigins: [...new Set([new URL(input.config.publicBaseUrl).origin, new URL(input.config.dashboardUrl).origin])],
  });
  return { config: input.replicas, deps, handle };
}
