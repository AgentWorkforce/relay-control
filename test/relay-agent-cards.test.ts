import assert from "node:assert/strict";
import test from "node:test";
import { buildAgentCard, cardSummary, storedCard, storedSkills } from "../src/mcp/relay-agent-cards.js";

// Stored skills and cards are written by other agents: reads are bounded and shape-checked.

test("stored skills are bounded, get derived ids and unique ids as Relaycast reads them", () => {
  const skills = storedSkills({ skills: [
    { name: "  Review PRs ", description: "x".repeat(600), tags: ["a", 3, ""], examples: ["one", "two", "three", "four", "five", "six"] },
    { id: "review-prs", name: "Duplicate id" },
    { id: "Bad Id", name: "Ship Releases" },
    { description: "no name" },
    "not a skill",
    ...Array.from({ length: 30 }, (_, index) => ({ id: `s-${index}`, name: `Skill ${index}` })),
  ] });
  assert.equal(skills.length, 20);
  assert.deepEqual(skills[0], { id: "review-prs-2", name: "Review PRs", description: "x".repeat(500), tags: ["a"],
    examples: ["one", "two", "three", "four", "five"] });
  assert.deepEqual(skills.slice(1, 3).map(skill => [skill.id, skill.name]), [["review-prs", "Duplicate id"], ["Bad Id", "Ship Releases"]]);
  assert.deepEqual(skills[2], { id: "Bad Id", name: "Ship Releases", description: "", tags: [] });
  assert.deepEqual(storedSkills({ skills: "nope" }), []);
});

test("a card needs a description; documentation_url must be https", () => {
  assert.equal(storedCard({}), null);
  assert.equal(storedCard({ card: { description: "  " } }), null);
  assert.deepEqual(storedCard({ card: { description: "Does things", documentation_url: "http://insecure.test", tags: ["x"], updated_at: "2026-11-13T00:00:00.000Z" } }),
    { description: "Does things", tags: ["x"], updated_at: "2026-11-13T00:00:00.000Z", version: "1" });
  assert.deepEqual(cardSummary({ card: { description: "Does things" }, skills: Array.from({ length: 12 }, (_, index) => ({ name: `S${index}` })) }),
    { has_card: true, skills: Array.from({ length: 10 }, (_, index) => `S${index}`) });
});

test("the card fills x-agent-relay from metadata as Relaycast does", () => {
  const options = { organization: "Acme", relaycastUrl: "https://cast.example.test/" };
  const agent = { id: "ag_1", name: "worker", metadata: { where: "build-box", owner: "Ops", skills: [{ name: "Ship It" }] },
    address: "worker@laptop", kind: "agent", persona: "Ships builds", status: "idle", lastSeen: null };
  const card = buildAgentCard(agent, options);
  assert.equal(card.url, "https://cast.example.test/a2a/rpc");
  assert.equal(card.description, "Ships builds");
  assert.deepEqual(card.skills, [{ id: "ship-it", name: "Ship It", description: "", tags: [] }]);
  assert.deepEqual(card["x-agent-relay"], { address: "worker@laptop", kind: "agent", owner: "Ops", where: "build-box",
    status: "live", tags: [], hasCard: true });
  const bare = buildAgentCard({ ...agent, metadata: {}, persona: null, address: null, status: "offline" }, options);
  assert.equal(bare.description, "worker on Agent Relay");
  assert.deepEqual(bare["x-agent-relay"], { address: "worker", kind: "agent", status: "offline", tags: [], hasCard: false });
});
