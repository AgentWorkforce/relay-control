import type { RelaySpawnTarget } from "../messaging/relaycast.js";

/**
 * Agent-selected placement, ported from Cloud's
 * `lib/mcp/relay-spawn-placement.ts`. The agent names the node; this server
 * explains the workspace fleet so it can choose, and refuses a node the
 * caller may not use. Relaycast still makes the atomic capacity decision.
 *
 * Who may spawn where (the launch gate already requires an owner or admin):
 * - your own node (you claimed it): always;
 * - a teammate's claimed node: only when its spawn capabilities advertise
 *   `metadata.configured.teammates: true`; a missing flag means not allowed;
 * - an unclaimed desktop, or an unclaimed node that states no `node_kind`
 *   (older desktops omit it): nobody;
 * - an unclaimed broker (`node_kind: "broker"`): any owner or admin.
 *
 * Self-host has no Cloud sandboxes, so there is no `hosted` kind: a node
 * cannot open itself by carrying a sandbox tag here.
 */

export type SpawnNodeOwner = { userId: string; name: string | null };
export type PlacementKind = "desktop" | "broker";
export type PlacementOwner = { user_id: string; name: string; is_you: boolean };
export type PlacementLoad = {
  utilization: number | null; load_1m: number | null; cpus: number | null;
  memory_available_bytes: number | null; memory_total_bytes: number | null;
};
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
};

type Placement = {
  nodeKind: "desktop" | "broker" | null;
  machine: string | null;
  teammates: boolean | null;
  repositories: string[];
  harnessVersions: Record<string, string>;
  load: PlacementLoad | null;
};
type Permission = { allowed: true; reason: "yours" | "teammates" | "shared" } |
  { allowed: false; reason: "owned_by_other" | "unclaimed_desktop" | "unclaimed_unidentified" };

const KIND_ORDER: Record<PlacementKind, number> = { desktop: 0, broker: 1 };
const MAX_ALTERNATIVES = 3;
const MAX_REPOSITORIES = 100;
const REPOSITORY_KEY = /^[A-Za-z0-9_.-]{1,100}(?:\/[A-Za-z0-9_.-]{1,100})?$/;
export const TEAMMATES_SETTING = "Allow teammates to spawn here";
const UNNAMED_OWNER = "a teammate";

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}
function label(value: unknown, max: number): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed.length > 0 && trimmed.length <= max && !/[\x00-\x1f\x7f]/.test(trimmed) ? trimmed : null;
}
function repositoryKey(value: unknown): string | null {
  return typeof value === "string" && REPOSITORY_KEY.test(value) &&
    value.split("/").every(segment => segment !== "." && segment !== "..") ? value : null;
}
function measure(value: unknown, integer = false): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && (!integer || Number.isInteger(value)) ? value : null;
}

/** Placement facts from allowlisted node fields only; anything malformed is dropped, never guessed. */
export function spawnPlacement(node: Record<string, unknown>): Placement {
  const configured = (Array.isArray(node.capabilities) ? node.capabilities : []).map(record)
    .filter((capability): capability is Record<string, unknown> =>
      !!capability && typeof capability.name === "string" && /^spawn:[a-z0-9][a-z0-9-]{0,31}$/.test(capability.name))
    .map(capability => ({
      harness: (capability.name as string).slice("spawn:".length),
      configured: record(record(capability.metadata)?.configured),
      live: record(record(capability.metadata)?.live),
    }));
  const kinds = configured.map(entry => entry.configured?.node_kind).filter(kind => kind !== undefined);
  const teammates = configured.map(entry => entry.configured?.teammates).filter(flag => flag !== undefined);
  const tags = (Array.isArray(node.tags) ? node.tags : []).filter((tag): tag is string => typeof tag === "string");
  const repositories = new Set<string>();
  for (const entry of configured) {
    for (const repository of Array.isArray(entry.configured?.repositories) ? entry.configured.repositories : []) {
      const key = repositoryKey(repository);
      if (key) repositories.add(key);
    }
  }
  for (const tag of tags) {
    const key = tag.startsWith("repo:") ? repositoryKey(tag.slice("repo:".length)) : null;
    if (key) repositories.add(key);
  }
  const harnessVersions: Record<string, string> = {};
  for (const entry of configured) {
    const version = label(entry.configured?.version, 64) ?? label(entry.live?.version, 64);
    if (version && !(entry.harness in harnessVersions)) harnessVersions[entry.harness] = version;
  }
  const resources = configured.map(entry => record(entry.live?.resources)).filter(Boolean);
  const first = (read: (resource: Record<string, unknown> | null) => number | null) =>
    resources.map(read).find(value => value !== null) ?? null;
  const utilization = measure(node.load);
  const load: PlacementLoad = {
    utilization: utilization !== null && utilization <= 1 ? utilization : null,
    load_1m: first(resource => measure(resource?.load_1m)),
    cpus: first(resource => measure(resource?.cpus, true) || null),
    memory_available_bytes: first(resource => measure(resource?.memory_available_bytes, true)),
    memory_total_bytes: first(resource => measure(resource?.memory_total_bytes, true)),
  };
  return {
    nodeKind: kinds.includes("desktop") ? "desktop" : kinds.includes("broker") ? "broker" : null,
    machine: configured.map(entry => label(entry.configured?.machine, 128)).find(Boolean) ?? null,
    teammates: teammates.length === 0 ? null : teammates.every(flag => flag === true),
    repositories: [...repositories].slice(0, MAX_REPOSITORIES),
    harnessVersions,
    load: Object.values(load).some(value => value !== null) ? load : null,
  };
}

function ownerName(owner: SpawnNodeOwner): string {
  return owner.name?.trim() || UNNAMED_OWNER;
}
function opening(name: string): string {
  return name === UNNAMED_OWNER ? "A teammate" : name;
}

function permission(placement: Placement, owner: SpawnNodeOwner | undefined, userId: string): Permission {
  if (!owner) {
    if (placement.nodeKind === "desktop") return { allowed: false, reason: "unclaimed_desktop" };
    return placement.nodeKind === "broker" ? { allowed: true, reason: "shared" } : { allowed: false, reason: "unclaimed_unidentified" };
  }
  if (owner.userId === userId) return { allowed: true, reason: "yours" };
  return placement.teammates === true ? { allowed: true, reason: "teammates" } : { allowed: false, reason: "owned_by_other" };
}

function why(kind: PlacementKind, owner: SpawnNodeOwner | undefined, decision: Permission): string {
  const name = owner ? ownerName(owner) : "";
  const place = kind === "desktop" ? "computer" : "machine";
  switch (decision.reason) {
    case "yours": return `Your ${place}.`;
    case "teammates": return `${opening(name)}'s ${place}; they allow teammates to spawn here.`;
    case "shared": return "Shared workspace machine with no recorded owner; workspace owners and admins can spawn here.";
    case "owned_by_other": return kind === "desktop"
      ? `${opening(name)}'s computer. Not allowed: ${name} has not turned on "${TEAMMATES_SETTING}" in Agent Relay Desktop.`
      : `${opening(name)}'s ${place}. Not allowed: its owner has not allowed teammates to spawn here (teammates: true).`;
    case "unclaimed_desktop": return "Not allowed: this computer hasn't been claimed yet. Its owner claims it by signing in to this " +
      "Agent Relay site in Agent Relay Desktop.";
    case "unclaimed_unidentified": return "Not allowed: this machine hasn't been claimed and doesn't say whether it is a person's computer. " +
      "Its owner claims it by signing in to this Agent Relay site in Agent Relay Desktop.";
  }
}

export function availableSlots(target: RelaySpawnTarget): number | null {
  return target.maxAgents === 0 ? null : Math.max(0, target.maxAgents - target.activeAgents - target.reservedAgents);
}

export function placeTarget(target: RelaySpawnTarget, owner: SpawnNodeOwner | undefined, userId: string): PlacedTarget {
  const placement = spawnPlacement(target.raw);
  const kind: PlacementKind = placement.nodeKind === "desktop" ? "desktop" : "broker";
  const decision = permission(placement, owner, userId);
  return {
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
}

function loadScore(target: PlacedTarget): number {
  const load = target.load;
  if (load?.load_1m !== null && load?.load_1m !== undefined && load.cpus) return load.load_1m / load.cpus;
  return load?.utilization ?? Number.POSITIVE_INFINITY;
}

/** Allowed first; then yours; then desktop before broker; then room; then lowest load; then free slots. */
export function compareTargets(a: PlacedTarget, b: PlacedTarget): number {
  const hasRoom = (target: PlacedTarget) => target.available_slots === null || target.available_slots > 0;
  const slots = (target: PlacedTarget) => target.available_slots ?? 0;
  return Number(b.allowed) - Number(a.allowed) ||
    Number(b.owner?.is_you === true) - Number(a.owner?.is_you === true) ||
    KIND_ORDER[a.kind] - KIND_ORDER[b.kind] ||
    Number(hasRoom(b)) - Number(hasRoom(a)) ||
    (loadScore(a) === loadScore(b) ? 0 : loadScore(a) < loadScore(b) ? -1 : 1) ||
    slots(b) - slots(a);
}

export function rankTargets(targets: RelaySpawnTarget[], owners: ReadonlyMap<string, SpawnNodeOwner>, userId: string): PlacedTarget[] {
  return targets.map(target => placeTarget(target, owners.get(target.id), userId)).sort(compareTargets);
}

/** Allowed targets that would take the same request now, sharing a repository with the refused one first. */
export function alternativesFor(ranked: PlacedTarget[], harness: string, refused: { id: string; repositories?: readonly string[] }): PlacedTarget[] {
  const repositories = new Set(refused.repositories ?? []);
  const fits = ranked.filter(target => target.allowed && target.target_node !== refused.id &&
    target.harnesses.includes(harness) && (target.available_slots === null || target.available_slots > 0));
  const shares = (target: PlacedTarget) => target.repositories.some(repository => repositories.has(repository));
  return [...fits.filter(shares), ...fits.filter(target => !shares(target))].slice(0, MAX_ALTERNATIVES);
}

export function notAllowedMessage(target: PlacedTarget): string {
  const owner = target.owner;
  if (!owner && target.kind !== "desktop") return `Node "${target.name}" hasn't been claimed yet and doesn't say whether it is a ` +
    "person's computer, so no one can spawn there. Its owner claims it by signing in to this Agent Relay site in Agent Relay Desktop " +
    "on that machine. Until then, choose one of the alternatives.";
  if (!owner) return `Node "${target.name}" is a computer that hasn't been claimed yet, so no one can spawn there. ` +
    "Its owner claims it by signing in to this Agent Relay site in Agent Relay Desktop on that computer. " +
    "Until then, choose one of the alternatives.";
  return target.kind === "desktop"
    ? `Node "${target.name}" is ${owner.name}'s computer. ${opening(owner.name)} has not allowed teammates to spawn there; ` +
      `they can turn on "${TEAMMATES_SETTING}" in Agent Relay Desktop.`
    : `Node "${target.name}" belongs to ${owner.name}. Only its owner can spawn there unless it advertises teammates: true.`;
}
