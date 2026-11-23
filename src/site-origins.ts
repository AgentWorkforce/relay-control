import type { SelfhostConfig } from "./config.js";

// Dependency-free so feature modules (Amp, Replicas) that src/app.ts imports
// can share one origin list without an import cycle.

/** Origins allowed to send cookie-authenticated writes: the primary site, then each extra site. */
export function browserOriginsFor(config: SelfhostConfig): string[] {
  return [...new Set([
    new URL(config.publicBaseUrl).origin,
    new URL(config.dashboardUrl).origin,
    ...(config.extraSites ?? []).flatMap((site) => [site.dashboardOrigin, site.apiOrigin]),
  ])];
}
