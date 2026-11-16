import type { SelfhostConfig } from "../config.js";
import type { Database } from "../database.js";
import { createRelaycastClient } from "../messaging/relaycast.js";
import { DEFAULT_REPLICAS_IDENTITY_ISSUER, type ReplicasConfig } from "./config.js";
import { environmentMcpUrl } from "./environments.js";
import { createReplicaIdentityVerifier } from "./identity.js";
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
  /** workspace_identity discovery/JWKS fetch (tests inject a fake issuer). */
  identityFetch?: typeof fetch;
  now?: () => Date;
  /** Test hook: environment MCP limits (ip guard, per-identity quota). Production leaves this unset. */
  rateLimits?: Parameters<typeof createReplicasHandler>[0]["rateLimits"];
  /**
   * The canonical lazy Relay binding (the store's): provisions an unbound
   * workspace once. Absent: an unbound workspace cannot be provisioned from here.
   */
  relaycastBinding?: ReplicasDeps["relaycastBinding"];
}): ReplicasModule {
  const issuer = input.replicas.identityIssuer ?? DEFAULT_REPLICAS_IDENTITY_ISSUER;
  const mcpUrl = environmentMcpUrl(input.config.publicBaseUrl);
  const deps: ReplicasDeps = {
    database: input.database,
    keyring: input.config.encryptionKeyring,
    relaycast: createRelaycastClient({ internalOrigin: input.config.relaycastUrl, fetchImpl: input.relaycastFetch }),
    replicas: input.runtime ?? createReplicasRuntime({ fetchImpl: input.replicasFetch }),
    publicBaseUrl: input.config.publicBaseUrl,
    now: input.now ?? (() => new Date()),
    identity: {
      issuer,
      mcpUrl,
      verifier: createReplicaIdentityVerifier({ issuer, audience: mcpUrl, fetchImpl: input.identityFetch, now: input.now }),
    },
    ...(input.relaycastBinding ? { relaycastBinding: input.relaycastBinding } : {}),
  };
  const handle = createReplicasHandler({
    enabled: input.replicas.enabled,
    deps,
    database: input.database,
    internalServiceToken: input.config.internalServiceToken,
    browserOrigins: [...new Set([new URL(input.config.publicBaseUrl).origin, new URL(input.config.dashboardUrl).origin])],
    ...(input.rateLimits ? { rateLimits: input.rateLimits } : {}),
  });
  return { config: input.replicas, deps, handle };
}
