/**
 * Agent-selected placement, ported from Cloud's
 * `lib/mcp/relay-spawn-placement.ts`. The agent names the node; this server
 * explains the workspace fleet so it can choose, and refuses a node the
 * caller may not use or (under `enforce`) one without the memory for the
 * launch. Relaycast still makes the atomic capacity decision.
 *
 * - parse.ts: allowlisted facts from the raw node record
 * - permission.ts: who may spawn where
 * - messages.ts: this site's wording
 * - policy.ts: adapter to the shared `@agent-relay/spawn-placement` policy
 */

export { spawnPlacement, type Placement, type PlacementLoad } from "./parse.js";
export { permission, type Permission, type SpawnNodeOwner } from "./permission.js";
export { notAllowedMessage, TEAMMATES_SETTING } from "./messages.js";
export {
  alternativesFor, availableSlots, rankTargets,
  type PlacedTarget, type PlacementKind, type PlacementOptions, type PlacementOwner, type PlacementRanking, type RankedTarget,
} from "./policy.js";
