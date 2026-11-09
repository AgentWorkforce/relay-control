import assert from "node:assert/strict";
import test from "node:test";
import { parseAgentQuery } from "../src/sessions/agent-query.js";

// Shared vectors: every client that parses `@name` should agree with these.
const VECTORS: Array<[string, string, string[]]> = [
  ["@layered-control", "", ["layered-control"]],
  ["@Layered-Control", "", ["layered-control"]],
  ["@layered-control@node", "", ["layered-control@node"]],
  ["@layered-*", "", ["layered-*"]],
  ["@layered-control@no*", "", ["layered-control@no*"]],
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

test("agent query vectors", () => {
  for (const [query, text, agents] of VECTORS) {
    assert.deepEqual(parseAgentQuery(query), { text, agents }, JSON.stringify(query));
  }
});
