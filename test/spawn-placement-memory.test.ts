import assert from "node:assert/strict";
import test from "node:test";
import { GIB } from "@agent-relay/spawn-placement";
import { loadSpawnMemoryPolicy } from "../src/config.js";
import type { RelaySpawnTarget } from "../src/messaging/relaycast.js";
import { rankTargets, spawnPlacement } from "../src/mcp/spawn-placement/index.js";

const NOW = new Date("2026-11-19T12:00:00.000Z");
const at = (secondsAgo: number) => new Date(NOW.getTime() - secondsAgo * 1000).toISOString();
function capability(harness: string, live: Record<string, unknown> | null, configured: Record<string, unknown> = { node_kind: "desktop" }) {
  return { name: `spawn:${harness}`, metadata: { configured, ...(live ? { live } : {}) } };
}
function target(raw: Record<string, unknown>, overrides: Partial<RelaySpawnTarget> = {}): RelaySpawnTarget {
  return { id: "node-1", name: "studio", live: true, handlersLive: true, capabilities: ["spawn:claude"], activeAgents: 0,
    reservedAgents: 0, maxAgents: 0, stale: false, raw, ...overrides };
}
const resources = (availableGiB: number, totalGiB = 16) =>
  ({ cpus: 8, load_1m: 1, memory_available_bytes: availableGiB * GIB, memory_total_bytes: totalGiB * GIB });

test("placement reads the newest stamped memory sample across capabilities", () => {
  const placement = spawnPlacement({ capabilities: [
    capability("codex", { observed_at: at(30), resources: resources(9) }),
    capability("claude", { observed_at: at(2), resources: resources(3) }),
    capability("grok", { observed_at: "not a time", resources: resources(12) }),
  ] });
  assert.deepEqual(placement.memory, { availableBytes: 3 * GIB, totalBytes: 16 * GIB, observedAt: at(2) });
});

test("a newer stamped frame without memory does not hide an older one that has it", () => {
  const placement = spawnPlacement({ capabilities: [
    capability("codex", { observed_at: at(20), resources: resources(9) }),
    capability("claude", { observed_at: at(2), resources: { cpus: 8, load_1m: 1 } }),
  ] });
  assert.deepEqual(placement.memory, { availableBytes: 9 * GIB, totalBytes: 16 * GIB, observedAt: at(20) });
});

test("placement keeps an unstamped sample as unknown age, and the largest node floor", () => {
  const placement = spawnPlacement({ capabilities: [
    capability("codex", { resources: resources(9) }, { node_kind: "desktop", memory_floor_bytes: GIB }),
    capability("claude", { resources: resources(9) }, { node_kind: "desktop", memory_floor_bytes: 3 * GIB }),
    capability("grok", null, { node_kind: "desktop", memory_floor_bytes: -1 }),
  ] });
  assert.deepEqual(placement.memory, { availableBytes: 9 * GIB, totalBytes: 16 * GIB, observedAt: null });
  assert.equal(placement.nodeFloorBytes, 3 * GIB);
  assert.equal(spawnPlacement({ capabilities: [capability("codex", null)] }).memory, null);
});

test("off: targets carry no memory fields and keep today's why", () => {
  const raw = { capabilities: [capability("claude", { observed_at: at(1), resources: resources(2.5) })] };
  const ranking = rankTargets([target(raw)], new Map([["node-1", { userId: "me", name: "Me" }]]), "me",
    { policy: loadSpawnMemoryPolicy({ SELFHOST_SPAWN_MEMORY_POLICY: "off" }), now: NOW, harness: "claude" });
  assert.equal("memory" in ranking.targets[0]!, false);
  assert.equal("admissible" in ranking.targets[0]!, false);
  assert.equal(ranking.targets[0]!.why, "Your computer.");
});

test("observe: memory is reported and explained, and only launches after the sample count as pending", () => {
  const raw = { capabilities: [capability("claude", { observed_at: at(10), resources: resources(6.5) })] };
  const pending = new Map([["node-1", [new Date(NOW.getTime() - 20_000), new Date(NOW.getTime() - 5_000), NOW]]]);
  const ranking = rankTargets([target(raw)], new Map([["node-1", { userId: "me", name: "Me" }]]), "me",
    { policy: loadSpawnMemoryPolicy({}), now: NOW, harness: "claude", pending });
  const placed = ranking.targets[0]!;
  // Two launches after the sample: 6.5 − 2 × 1.5 = 3.5 GiB projected; 3.5 − 2 − 1.5 = 0: tight.
  assert.equal(placed.memory!.projected_available_bytes, 3.5 * GIB);
  assert.equal(placed.memory!.tier, "tight");
  assert.equal(placed.admissible, true);
  assert.equal(placed.why, "Your computer. Memory is tight: 3.5 GB free of 16 GB.");
});

test("config: defaults to observe and refuses invalid values naming the variable", () => {
  assert.equal(loadSpawnMemoryPolicy({}).mode, "observe");
  const policy = loadSpawnMemoryPolicy({ SELFHOST_SPAWN_MEMORY_POLICY: "enforce", SELFHOST_SPAWN_HARNESS_MEMORY: "claude=2GiB",
    SELFHOST_SPAWN_MEMORY_FLOOR: "desktop=3GiB/10%", SELFHOST_SPAWN_AGENT_MEMORY: "512MiB",
    SELFHOST_SPAWN_DENSITY_CAPS_CONFIGURED: "true", SELFHOST_SPAWN_MEMORY_FRESH_SECONDS: "60" });
  assert.equal(policy.mode, "enforce");
  assert.equal(policy.harnessNeedBytes.claude, 2 * GIB);
  assert.deepEqual(policy.floor.desktop, { bytes: 3 * GIB, fraction: 0.1 });
  assert.equal(policy.agentSteadyBytes, 512 * 1024 ** 2);
  assert.equal(policy.densityCapsConfigured, true);
  assert.equal(policy.freshSeconds, 60);
  for (const [name, value] of [["SELFHOST_SPAWN_MEMORY_POLICY", "strict"], ["SELFHOST_SPAWN_MEMORY_FLOOR", "desktop=2GiB"],
    ["SELFHOST_SPAWN_HARNESS_MEMORY", "claude=none"], ["SELFHOST_SPAWN_AGENT_MEMORY", "0"],
    ["SELFHOST_SPAWN_DENSITY_CAPS_CONFIGURED", "maybe"], ["SELFHOST_SPAWN_MEMORY_FRESH_SECONDS", "0"]] as const) {
    assert.throws(() => loadSpawnMemoryPolicy({ [name]: value }), new RegExp(`^Error: ${name} is invalid`), name);
  }
});
