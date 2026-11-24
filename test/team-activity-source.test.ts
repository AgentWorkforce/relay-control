import assert from "node:assert/strict";
import { test } from "node:test";
import { activityCandidate, type TeamAgent } from "../src/mcp/team-activity.js";

const agent = (session_kind: string | null): TeamAgent =>
  ({ session_id: "6e0af963-e21c-4fb8-a8e8-7f34765b6d64", session_kind }) as unknown as TeamAgent;

test("activity reads are scoped to the History source Desktop uploads each kind under", () => {
  const cases: Array<[string | null, string | undefined]> = [
    ["cursor-cli", "cursor"],
    ["Cursor-CLI", "cursor"],
    ["cursor", "cursor"],
    ["claude-terminal", "claude"],
    ["opencode-open", "opencode"],
    ["codex", "codex"],
    ["unknown-harness", undefined],
    [null, undefined],
  ];
  for (const [kind, source] of cases) {
    const candidate = activityCandidate(agent(kind));
    assert.equal(candidate?.source, source, String(kind));
    assert.equal(candidate?.key, `${source ?? "*"}:6e0af963-e21c-4fb8-a8e8-7f34765b6d64`);
  }
});
