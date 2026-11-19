import type { MemorySample } from "@agent-relay/spawn-placement";

/**
 * Placement facts read from a raw Relaycast node record: allowlisted fields
 * only; anything malformed is dropped, never guessed.
 */

export type PlacementLoad = {
  utilization: number | null; load_1m: number | null; cpus: number | null;
  memory_available_bytes: number | null; memory_total_bytes: number | null;
};

export type Placement = {
  nodeKind: "desktop" | "broker" | null;
  machine: string | null;
  teammates: boolean | null;
  repositories: string[];
  harnessVersions: Record<string, string>;
  load: PlacementLoad | null;
  /** The newest `metadata.live` memory sample across the node's spawn capabilities. */
  memory: MemorySample | null;
  /** `metadata.configured.memory_floor_bytes`: a floor the node asks for; it can only raise the policy floor. */
  nodeFloorBytes: number | null;
};

const MAX_REPOSITORIES = 100;
const REPOSITORY_KEY = /^[A-Za-z0-9_.-]{1,100}(?:\/[A-Za-z0-9_.-]{1,100})?$/;

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
function instant(value: unknown): { text: string; ms: number } | null {
  if (typeof value !== "string" || value.length > 64) return null;
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? { text: value, ms } : null;
}

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
  // Each capability carries its own live frame; judge memory on the newest stamped one that reports memory.
  const stamped = configured
    .map(entry => ({ at: instant(entry.live?.observed_at), resources: record(entry.live?.resources) }))
    // Only frames that carry a memory figure: a newer frame without one must not hide an older one that has it.
    .filter((entry): entry is { at: { text: string; ms: number }; resources: Record<string, unknown> | null } =>
      entry.at !== null && measure(entry.resources?.memory_available_bytes, true) !== null)
    .sort((a, b) => b.at.ms - a.at.ms)[0];
  const memory: MemorySample | null = stamped
    ? { availableBytes: measure(stamped.resources?.memory_available_bytes, true),
      totalBytes: measure(stamped.resources?.memory_total_bytes, true), observedAt: stamped.at.text }
    : load.memory_available_bytes !== null || load.memory_total_bytes !== null
      ? { availableBytes: load.memory_available_bytes, totalBytes: load.memory_total_bytes, observedAt: null }
      : null;
  const floors = configured.map(entry => measure(entry.configured?.memory_floor_bytes, true)).filter((value): value is number => value !== null);
  return {
    nodeKind: kinds.includes("desktop") ? "desktop" : kinds.includes("broker") ? "broker" : null,
    machine: configured.map(entry => label(entry.configured?.machine, 128)).find(Boolean) ?? null,
    teammates: teammates.length === 0 ? null : teammates.every(flag => flag === true),
    repositories: [...repositories].slice(0, MAX_REPOSITORIES),
    harnessVersions,
    load: Object.values(load).some(value => value !== null) ? load : null,
    memory,
    nodeFloorBytes: floors.length === 0 ? null : Math.max(...floors),
  };
}
