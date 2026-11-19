import assert from "node:assert/strict";
import test from "node:test";
import { memoryRefusal, parseMemoryPolicy } from "@agent-relay/spawn-placement";
import { GOLDEN_FIXTURES } from "@agent-relay/spawn-placement/fixtures";
import type { RelaySpawnTarget } from "../src/messaging/relaycast.js";
import { alternativesFor, rankTargets } from "../src/mcp/spawn-placement/index.js";

/**
 * Parity with Cloud (docs/specs/spawn-placement-memory.md §6): the shared
 * package's golden fixtures, run through this server's own adapter from raw
 * Relaycast node records. A fixture this site cannot express (Cloud-hosted
 * sandboxes) is skipped.
 */

/** As `listSpawnTargets` reads a node (src/messaging/relaycast.ts). */
function target(node: Record<string, unknown>): RelaySpawnTarget {
  const capabilities = (node.capabilities as Array<{ name: string }>).map(capability => capability.name);
  return {
    id: String(node.id), name: String(node.name), live: node.live === true, handlersLive: node.handlers_live === true, capabilities,
    activeAgents: node.active_agents as number, reservedAgents: (node.reserved_agents as number | undefined) ?? 0,
    maxAgents: node.max_agents as number, stale: node.live !== true, raw: node,
  };
}

for (const fixture of GOLDEN_FIXTURES) {
  test(`golden: ${fixture.name}`, { skip: fixture.tags.includes("hosted") ? "no hosted sandboxes on self-host" : false }, () => {
    const now = new Date(fixture.now);
    const policy = parseMemoryPolicy(fixture.settings);
    const owners = new Map(Object.entries(fixture.owners));
    // In-flight launches reserved just now: after every fixture sample.
    const pending = new Map(Object.entries(fixture.pendingLaunches ?? {})
      .map(([id, count]) => [id, Array.from({ length: count }, () => now)]));
    const ranking = rankTargets(fixture.nodes.map(target), owners, fixture.userId,
      { policy, now, harness: fixture.harness, pending });
    assert.deepEqual(ranking.targets.map(item => item.target_node), fixture.expected.order);
    for (const item of ranking.targets) {
      const { tier, admissible, reason } = item.memory!;
      assert.deepEqual({ tier, admissible, reason }, fixture.expected.memory[item.target_node], item.target_node);
    }
    const refusal = fixture.expected.refusal;
    if (refusal) {
      const entry = ranking.ranked.find(item => item.candidate.id === refusal.target)!;
      assert.equal(memoryRefusal(entry, policy) !== null, refusal.memoryLow);
      assert.deepEqual(alternativesFor(ranking, fixture.harness ?? "claude",
        { id: refusal.target, repositories: entry.candidate.repositories }).map(item => item.target_node), refusal.alternatives);
    }
  });
}
