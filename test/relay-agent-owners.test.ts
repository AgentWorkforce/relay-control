import assert from "node:assert/strict";
import test from "node:test";
import type { SqlExecutor } from "../src/database.js";
import type { McpMember } from "../src/mcp/context.js";
import { loadRelayAgentOwners, relayAgentOwnerTarget } from "../src/mcp/relay-agent-owners.js";

type Candidate = {
  agent_id: string;
  agent_name: string | null;
  source: "desktop" | "hosted" | "spawn";
  user_id: string;
  verified: boolean;
};

const members: McpMember[] = [
  { userId: "user-1", email: "one@example.test", name: "One" },
  { userId: "user-2", email: "two@example.test", name: "Two" },
];
const agent = {
  id: "ag_upstream",
  name: "cursor-chat",
  metadata: { relaygate: { agent_id: "rga_gate" } },
};

function executor(rows: Candidate[]): SqlExecutor {
  return {
    query: async <T extends Record<string, unknown>>() => ({ rows: rows as unknown as T[] }),
    exec: async () => {},
  };
}

test("gate-only owner lookup maps the relaygate id and exact Desktop agent name back to the roster id", async () => {
  assert.deepEqual(relayAgentOwnerTarget(agent, true), {
    agentId: "ag_upstream", lookupId: "rga_gate", name: "cursor-chat",
  });
  assert.deepEqual(relayAgentOwnerTarget(agent, false), {
    agentId: "ag_upstream", lookupId: "ag_upstream", name: "cursor-chat",
  });
  const rows: Candidate[] = [
    { agent_id: "rga_gate", agent_name: "cursor-chat", source: "desktop", user_id: "user-1", verified: true },
    // The id alone is insufficient: this row belongs to another named identity.
    { agent_id: "rga_gate", agent_name: "someone-else", source: "desktop", user_id: "user-2", verified: true },
  ];
  const owners = await loadRelayAgentOwners(executor(rows), "workspace", "relaycast", [agent], members, true);
  assert.equal(owners.get(agent.id)?.userId, "user-1");
});

test("conflicting trusted journals make ownership unknown", async () => {
  const rows: Candidate[] = [
    { agent_id: "rga_gate", agent_name: "cursor-chat", source: "desktop", user_id: "user-1", verified: true },
    { agent_id: "ag_upstream", agent_name: null, source: "hosted", user_id: "user-2", verified: true },
  ];
  const owners = await loadRelayAgentOwners(executor(rows), "workspace", "relaycast", [agent], members, true);
  assert.equal(owners.has(agent.id), false);
});

test("a non-ready spawn is not trusted and still makes an otherwise trusted binding ambiguous", async () => {
  const rows: Candidate[] = [
    { agent_id: "rga_gate", agent_name: "cursor-chat", source: "desktop", user_id: "user-1", verified: true },
    { agent_id: "ag_upstream", agent_name: null, source: "spawn", user_id: "user-2", verified: false },
  ];
  const owners = await loadRelayAgentOwners(executor(rows), "workspace", "relaycast", [agent], members, true);
  assert.equal(owners.has(agent.id), false);
});

test("a journal binding for a user outside the current workspace membership is not exposed", async () => {
  const rows: Candidate[] = [
    { agent_id: "ag_upstream", agent_name: null, source: "hosted", user_id: "former-user", verified: true },
  ];
  const owners = await loadRelayAgentOwners(executor(rows), "workspace", "relaycast", [agent], members, false);
  assert.equal(owners.has(agent.id), false);
});
