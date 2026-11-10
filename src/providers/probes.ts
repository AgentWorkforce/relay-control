import type { AmpModule } from "../amp/module.js";
import type { SelfhostConfig } from "../config.js";
import type { FactoryModule } from "../factory/routes.js";
import type { ProviderProbes } from "./registry.js";

/**
 * Runtime probes for the provider modules mounted in this build. Synchronous
 * and side-effect free: they read the already-loaded config and module state,
 * never the environment. Providers without a module here are absent, so the
 * providers route reports them as not implemented.
 */
export function buildProviderProbes(input: {
  factory: FactoryModule;
  amp: AmpModule;
  config: SelfhostConfig;
}): ProviderProbes {
  return {
    factory: {
      implemented: true,
      configured: () => Boolean(input.config.factory),
      enabled: () => input.factory.enabled,
    },
    amp: {
      implemented: true,
      configured: () => input.amp.config.transport !== null,
      enabled: () => input.amp.config.enabled,
    },
    // The Desktop MCP credential roundtrip and Copilot attestation are mounted
    // unconditionally; there is no switch to read.
    copilot: {
      implemented: true,
      configured: () => true,
      enabled: () => true,
    },
  };
}
