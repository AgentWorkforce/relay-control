import assert from "node:assert/strict";
import test from "node:test";
import { candidateNames, GATE_ONLY_PERSON_IDENTITY_NAME_PREFIX } from "../src/messaging/identity.js";

const suffixes = () => {
  let next = 0;
  return () => ["aaaa", "bbbb", "cccc", "dddd"][next++ % 4]!;
};

const users = [
  { userId: "0d4f6c1e-0000-4000-8000-000000000001", name: "Ada Lovelace", email: "ada@example.test" },
  { userId: "0d4f6c1e-0000-4000-8000-000000000002", name: "Same", email: "same@example.test" },
  { userId: "0d4f6c1e-0000-4000-8000-000000000003", name: "", email: "x@example.test" },
  {
    userId: "0d4f6c1e-0000-4000-8000-000000000004",
    name: "A very long display name that goes well past every limit we have",
    email: "another-extremely-long-mailbox-name-for-testing@example.test",
  },
];

test("candidateNames: an empty prefix keeps the existing names", () => {
  const user = users[0]!;
  const names = candidateNames(user, suffixes());
  assert.deepEqual(names.slice(0, 2), ["ada-lovelace", "ada"]);
  assert.deepEqual(candidateNames(user, suffixes(), ""), names);
  for (const each of users) assert.deepEqual(candidateNames(each, suffixes(), ""), candidateNames(each, suffixes()));
});

test("candidateNames: the gate-only prefix applies to every candidate within 48 characters, deduped", () => {
  assert.equal(GATE_ONLY_PERSON_IDENTITY_NAME_PREFIX, "control-");
  for (const user of users) {
    const plain = candidateNames(user, suffixes());
    const prefixed = candidateNames(user, suffixes(), GATE_ONLY_PERSON_IDENTITY_NAME_PREFIX);
    assert.ok(prefixed.length > 0);
    assert.equal(new Set(prefixed).size, prefixed.length);
    for (const name of prefixed) {
      assert.ok(name.startsWith("control-"), name);
      assert.ok(name.length <= 48, name);
    }
    assert.deepEqual(prefixed, plain.map((name) => `control-${name}`.slice(0, 48)));
  }
  // "Same" and "same@" slug to one base, so the prefixed list dedupes it too.
  const same = candidateNames(users[1]!, suffixes(), GATE_ONLY_PERSON_IDENTITY_NAME_PREFIX);
  assert.equal(same.filter((name) => name === "control-same").length, 1);
});
