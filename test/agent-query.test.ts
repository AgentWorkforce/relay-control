import assert from "node:assert/strict";
import test from "node:test";
import { agentPrefixTooShort, parseAgentQuery, selectAgent } from "../src/sessions/agent-query.js";

// Shared vectors: every client that parses `@name` should agree with these.
const VECTORS: Array<[string, string, string[]]> = [
  ["@example-agent", "", ["example-agent"]],
  ["@Example-Agent", "", ["example-agent"]],
  ["@example-agent@node", "", ["example-agent@node"]],
  ["@example-*", "", ["example-*"]],
  ["@example-agent@no*", "", ["example-agent@no*"]],
  ["fix the bug @a", "fix the bug", ["a"]],
  ["@a fix @b the bug", "fix the bug", ["a", "b"]],
  ["@a @A @b", "", ["a", "b"]],
  ["@a_b.c-1", "", ["a_b.c-1"]],
  ["  @a \t  two   words ", "two words", ["a"]],
  ["plain text", "plain text", []],
  ["", "", []],
  ["someone@example.com", "someone@example.com", []],
  ["@", "@", []],
  ["@*", "@*", []],
  ["@foo!", "@foo!", []],
  ["@a@b@c", "@a@b@c", []],
  ["@a*b", "@a*b", []],
  ["\"@a\"", "\"@a\"", []],
];

test("the first agent applies and the rest are reported", () => {
  assert.deepEqual(selectAgent(undefined, "@a @b", true), { agent: "a", ignored: ["b"] });
  assert.deepEqual(selectAgent("X", "@a fix", true), { agent: "x", ignored: ["a"], text: "fix" });
  assert.deepEqual(selectAgent("a", "@A", true), { agent: "a", ignored: [] });
});

test("tokens stay free text until parsing is enabled", () => {
  assert.deepEqual(selectAgent(undefined, "@a fix", false), { ignored: [], text: "@a fix" });
  assert.deepEqual(selectAgent("a", "fix", false), { agent: "a", ignored: [], text: "fix" });
  assert.deepEqual(selectAgent(undefined, undefined, true), { ignored: [] });
});

test("an agent prefix needs three letters or digits", () => {
  assert.equal(agentPrefixTooShort("ab*"), true);
  assert.equal(agentPrefixTooShort("a-.*"), true);
  assert.equal(agentPrefixTooShort("abc*"), false);
  assert.equal(agentPrefixTooShort("ab"), false);
});

test("agent query vectors", () => {
  for (const [query, text, agents] of VECTORS) {
    assert.deepEqual(parseAgentQuery(query), { text, agents }, JSON.stringify(query));
  }
});
