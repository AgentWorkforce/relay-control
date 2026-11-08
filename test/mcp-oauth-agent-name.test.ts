// Port of Cloud 1776499a packages/web/lib/agent-name.test.ts.
import assert from "node:assert/strict";
import { test } from "node:test";
import { agentNameError, isValidAgentName } from "../src/mcp/oauth/agent-name.js";

for (const name of ["MuseMCPGrok", "cursor-will", "a", "a.b_c-d", "9lives", "x".repeat(128), "  padded  "]) {
  test(`agent-name accepts ${JSON.stringify(name)}`, () => {
    assert.equal(agentNameError(name), null);
    assert.equal(isValidAgentName(name), true);
  });
}

const invalidNames = [
  ["", "Enter a name."],
  ["   ", "Enter a name."],
  ["-grok", "Start with a letter or digit."],
  [".grok", "Start with a letter or digit."],
  ["muse grok", "Use only letters, digits, dots, dashes or underscores."],
  ["grok/bot", "Use only letters, digits, dots, dashes or underscores."],
  ["grök", "Use only letters, digits, dots, dashes or underscores."],
  ["x".repeat(129), "Use at most 128 characters."],
  ["cloud-github", "That name is reserved. Pick another."],
] as const;
for (const [name, reason] of invalidNames) {
  test(`agent-name rejects ${JSON.stringify(name)} with the source reason`, () => {
    assert.equal(agentNameError(name), reason);
    assert.equal(isValidAgentName(name), false);
  });
}

test("all internal trust-bearing names remain reserved, including trimmed inputs", () => {
  for (const name of ["cloud-github", "github-clone-worker", "nango-sync-worker", "nango-sync-workflow"]) {
    assert.equal(agentNameError(name), "That name is reserved. Pick another.");
    assert.equal(isValidAgentName(` ${name} `), false);
  }
});
