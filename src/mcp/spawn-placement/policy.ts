import {
  alternativesFor as sharedAlternatives, availableSlots as sharedAvailableSlots, DEFAULT_MEMORY_POLICY, memoryClause,
  rankCandidates, type MemoryAssessment, type MemoryPolicy, type PlacementCandidate, type RankedCandidate,
} from "@agent-relay/spawn-placement";
import type { RelaySpawnTarget } from "../../messaging/relaycast.js";
import { ownerName, why } from "./messages.js";
import { spawnPlacement, type PlacementLoad } from "./parse.js";
import { permission, type SpawnNodeOwner } from "./permission.js";

/**
 * Adapter between this server's launch targets and the shared placement
 * policy (`@agent-relay/spawn-placement`, docs/specs/spawn-placement-memory.md).
 * Parsing, permission and wording are this site's; order, memory assessment
 * and alternatives are the shared package's, so Cloud ranks the same way.
 */

export type PlacementKind = "desktop" | "broker";
export type PlacementOwner = { user_id: string; name: string; is_you: boolean };
export type PlacedTarget = {
  target_node: string;
  name: string;
  harnesses: string[];
  available_slots: number | null;
  kind: PlacementKind;
  machine: string;
  owner: PlacementOwner | null;
  allowed: boolean;
  repositories: string[];
  harness_versions: Record<string, string>;
  load: PlacementLoad | null;
  why: string;
  /** Present unless the memory policy is off: whether this target would take the launch now. */
  admissible?: boolean;
  /** Present unless the memory policy is off. */
  memory?: MemoryAssessment;
};

type Candidate = PlacementCandidate & { placed: PlacedTarget };
export type RankedTarget = RankedCandidate<Candidate>;
export type PlacementOptions = {
  policy?: MemoryPolicy;
  now?: Date;
  /** The harness the caller intends to launch; budgets and admissibility use it. */
  harness?: string | null;
  /** When this server's own in-flight launches to each node were reserved. */
  pending?: ReadonlyMap<string, readonly Date[]>;
};
export type PlacementRanking = { targets: PlacedTarget[]; ranked: RankedTarget[]; policy: MemoryPolicy };

export function availableSlots(target: RelaySpawnTarget): number | null {
  return sharedAvailableSlots(target);
}

function candidate(target: RelaySpawnTarget, owner: SpawnNodeOwner | undefined, userId: string,
  pending: readonly Date[] | undefined): Candidate {
  const placement = spawnPlacement(target.raw);
  const kind: PlacementKind = placement.nodeKind === "desktop" ? "desktop" : "broker";
  const decision = permission(placement, owner, userId);
  const sampled = placement.memory?.observedAt ? Date.parse(placement.memory.observedAt) : NaN;
  // Only launches the sample cannot reflect yet: reserved after it was taken.
  const pendingLaunches = (pending ?? []).filter(at => !Number.isFinite(sampled) || at.getTime() > sampled).length;
  const placed: PlacedTarget = {
    target_node: target.id,
    name: target.name,
    harnesses: target.capabilities.map(capability => capability.slice("spawn:".length)),
    available_slots: availableSlots(target),
    kind,
    machine: placement.machine ?? target.name,
    owner: owner ? { user_id: owner.userId, name: ownerName(owner), is_you: owner.userId === userId } : null,
    allowed: decision.allowed,
    repositories: placement.repositories,
    harness_versions: placement.harnessVersions,
    load: placement.load,
    why: why(kind, owner, decision),
  };
  return {
    id: target.id, kind, allowed: decision.allowed, isYours: owner?.userId === userId,
    harnesses: placed.harnesses, repositories: placed.repositories,
    maxAgents: target.maxAgents, activeAgents: target.activeAgents, reservedAgents: target.reservedAgents,
    utilization: placement.load?.utilization ?? null, load1m: placement.load?.load_1m ?? null, cpus: placement.load?.cpus ?? null,
    memory: placement.memory, nodeFloorBytes: placement.nodeFloorBytes, pendingLaunches, placed,
  };
}

/** Best first, by the shared policy. With the policy off, targets carry no memory fields. */
export function rankTargets(targets: RelaySpawnTarget[], owners: ReadonlyMap<string, SpawnNodeOwner>, userId: string,
  options: PlacementOptions = {}): PlacementRanking {
  const policy = options.policy ?? DEFAULT_MEMORY_POLICY;
  const ranked = rankCandidates(targets.map(target => candidate(target, owners.get(target.id), userId, options.pending?.get(target.id))),
    { harness: options.harness ?? null, policy, now: options.now ?? new Date() });
  for (const entry of ranked) {
    if (policy.mode === "off") continue;
    const clause = memoryClause(entry.memory, options.harness);
    entry.candidate.placed = { ...entry.candidate.placed, ...(clause ? { why: `${entry.candidate.placed.why} ${clause}` } : {}),
      admissible: entry.admissible, memory: entry.memory };
  }
  return { targets: ranked.map(entry => entry.candidate.placed), ranked, policy };
}

/** Allowed targets that would take the same launch now (and, when memory ranks, have the memory), sharing a repository first. */
export function alternativesFor(ranking: PlacementRanking, harness: string,
  refused: { id: string; repositories?: readonly string[] }): PlacedTarget[] {
  return sharedAlternatives(ranking.ranked, harness, refused).map(entry => entry.candidate.placed);
}
