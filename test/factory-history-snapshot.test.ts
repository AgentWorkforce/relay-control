import assert from "node:assert/strict";
import test from "node:test";
import { createFactoryRuntime } from "../src/factory/runtime.js";

const metadata = { sessionId: "session", computerId: "computer", updatedAt: 123, messageCount: 2 };
const message = (id: string) => ({ id, role: "user", createdAt: 100, content: [{ type: "text", text: id }] });
const page = (id: string, nextCursor: string | null) => ({
  messages: [message(id)], pagination: { hasMore: nextCursor !== null, nextCursor },
});

function snapshot(responses: unknown[]) {
  const urls: URL[] = [];
  const runtime = createFactoryRuntime({
    apiUrl: "https://factory.invalid",
    async fetchImpl(input, init) {
      assert.equal(init?.method, "GET");
      const url = new URL(String(input));
      assert.equal(url.searchParams.get("computerId"), "computer");
      urls.push(url);
      assert.ok(responses.length > 0);
      return Response.json(responses.shift());
    },
  });
  return { urls, read: () => runtime.readHistory("offline-fixture-key", "session", "computer") };
}

test("projects both pages with local-reader event identities after the second metadata read", async () => {
  const fixture = snapshot([metadata, page("first", "next"), page("second", null), metadata]);
  const { records } = await fixture.read();
  assert.deepEqual(records.filter(r => r.kind === "session_event").map(r => r.key), [
    ["session_event", "droid", "session", "first:0"], ["session_event", "droid", "session", "second:0"],
  ]);
  assert.deepEqual(fixture.urls.map(u => [u.pathname, u.searchParams.get("cursor")]), [
    ["/api/v0/sessions/session", null], ["/api/v0/sessions/session/messages", null],
    ["/api/v0/sessions/session/messages", "next"], ["/api/v0/sessions/session", null],
  ]);
});

test("scrubs the connection key and injected reply capabilities from evidence and raw metadata", async () => {
  const reply = "factory_reply_" + "a".repeat(43);
  const source = page("first", null);
  source.messages[0]!.content[0]!.text = `use ${reply} or offline-fixture-key`;
  Object.assign(source.messages[0]!, { meta: { [reply]: ["offline-fixture-key"] } });
  const meta = { ...metadata, messageCount: 1 };
  const { records } = await snapshot([meta, source, meta]).read();
  const projection = JSON.stringify(records);
  assert.ok(projection.includes("[REDACTED]"));
  assert.ok(!projection.includes(reply));
  assert.ok(!projection.includes("offline-fixture-key"));
});

for (const [name, responses, error] of [
  ["short snapshot", [metadata, page("first", null), metadata], /snapshot_incomplete/],
  ["moving snapshot", [metadata, page("first", null), { ...metadata, updatedAt: 124 }], /snapshot_changed/],
  ["changed computer", [metadata, page("first", null), { ...metadata, computerId: "other" }], /computer_changed/],
  ["duplicate native IDs", [metadata, page("first", "next"), page("first", null), metadata], /DUPLICATE_MESSAGE_ID/],
  ["repeated cursor", [metadata, page("first", "next"), page("second", "next")], /pagination_incomplete/],
] as const) {
  test(`refuses ${name}`, async () => {
    await assert.rejects(snapshot([...responses]).read(), error);
  });
}
