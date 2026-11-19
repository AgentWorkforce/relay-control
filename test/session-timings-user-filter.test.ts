import assert from "node:assert/strict";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerSessionTimings } from "../src/mcp/session-timings.js";

/** list_session_timings asks History to filter by member and skips empty pages. */

const since = "2026-01-01T00:00:00Z";

const session = (sessionId: string, userIds: string[]) => ({ sessionId, source: "claude", userIds });
const page = (sessions: unknown[], nextCursor: string | null) => ({ sessions, nextCursor, correlationId: "page" });
const timing = (sessionId: string) => ({
  sessionId, source: "claude", startedAt: "2026-01-01T00:00:00Z", lastActionAt: "2026-01-01T00:10:00Z",
  workMs: 1000, waitingMs: 500,
  coverage: {
    scope: "stored_session", method: "recorded_intervals", eventCount: 1, turnCount: 1, markerCount: 0,
    workIntervalCount: 1, waitingIntervalCount: 0, lifecycleIntervalCount: 0,
    unmatchedToolCallCount: 0, unmatchedLifecycleCount: 0,
  },
  correlationId: "timing",
});

async function harness(respond: (path: string, calls: string[]) => unknown) {
  const calls: string[] = [];
  const server = new McpServer({ name: "test", version: "0.0.0" });
  registerSessionTimings(server, async () => ({
    workspaceId: "ws",
    read: async (path: string) => { calls.push(path); return respond(path, calls); },
    members: async () => [{ userId: "u1", name: "One" }, { userId: "u2", name: "Two" }],
    citation: (id: string, source: string) => `https://control.example.com/s/${source}/${id}`,
  }), (error) => ({ isError: true, content: [{ type: "text" as const, text: String(error) }] }));
  const client = new Client({ name: "test-client", version: "0.0.0" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return {
    calls,
    call: (args: Record<string, unknown>) => client.callTool({ name: "list_session_timings", arguments: args }),
    close: async () => { await client.close(); await server.close(); },
  };
}

const query = (path: string) => new URLSearchParams(path.split("?")[1]);
const isList = (path: string) => path.startsWith("/v1/sessions?");

test("asks History to filter by member, so a matching session is not lost to an empty page", async () => {
  // History honors `user`: without it the page holds only another member's session.
  const h = await harness((path) => {
    if (!isList(path)) return timing("s2");
    return query(path).get("user") === "u2" ? page([session("s2", ["u2"])], null) : page([session("s1", ["u1"])], "next");
  });
  try {
    const r = await h.call({ since, user_id: "u2", cursor: "old" });
    const data = r.structuredContent as { sessions: Array<{ session_id: string; members: Array<{ user_id: string }> }>; next_cursor: string | null };
    assert.equal(data.sessions.length, 1);
    assert.equal(data.sessions[0]?.session_id, "s2");
    assert.equal(data.sessions[0]?.members[0]?.user_id, "u2");
    assert.equal(data.next_cursor, null);
    assert.equal(query(h.calls[0]!).get("user"), "u2");
    assert.equal(query(h.calls[0]!).get("cursor"), "old");
  } finally { await h.close(); }
});

test("follows History's cursor past empty filtered pages when History ignores the member filter", async () => {
  const pages = [
    page([session("a", ["u1"])], "c1"),
    page([session("b", ["u1"])], "c2"),
    page([session("c", ["u2"]), session("d", ["u1"])], "c3"),
  ];
  let i = 0;
  const h = await harness((path) => (isList(path) ? pages[i++] : timing("c")));
  try {
    const r = await h.call({ since, user_id: "u2" });
    const data = r.structuredContent as { sessions: Array<{ session_id: string }>; sessions_scanned: number; next_cursor: string | null };
    assert.equal(data.sessions.length, 1);
    assert.equal(data.sessions[0]?.session_id, "c");
    assert.equal(data.sessions_scanned, 4);
    assert.equal(data.next_cursor, "c3");
    assert.equal(query(h.calls[1]!).get("cursor"), "c1");
    assert.equal(query(h.calls[2]!).get("cursor"), "c2");
  } finally { await h.close(); }
});

test("bounds the skip-ahead and returns History's cursor without reading unrelated timings", async () => {
  let n = 0;
  const h = await harness(() => page([session(`s${n}`, ["u1"])], `c${++n}`));
  try {
    const r = await h.call({ since, user_id: "u2" });
    const data = r.structuredContent as { sessions: unknown[]; sessions_scanned: number; next_cursor: string | null };
    assert.deepEqual(data.sessions, []);
    assert.equal(data.sessions_scanned, 5);
    assert.equal(data.next_cursor, "c5");
    assert.equal(h.calls.length, 5);
    assert.ok(h.calls.every(isList));
    assert.ok(h.calls.every((path) => !path.includes("/timing")));
  } finally { await h.close(); }
});

test("reads one page and sends no user filter when no member is given", async () => {
  const h = await harness((path) => (isList(path) ? page([session("s1", ["u1"])], "next") : timing("s1")));
  try {
    const r = await h.call({ since });
    const data = r.structuredContent as { sessions_scanned: number; next_cursor: string | null };
    assert.equal(data.sessions_scanned, 1);
    assert.equal(data.next_cursor, "next");
    assert.ok(!h.calls[0]!.includes("user="));
    assert.equal(h.calls.filter(isList).length, 1);
  } finally { await h.close(); }
});

test("keeps a safe cause when a session timing is unavailable", async () => {
  const cases = [
    { reason: "read_failed", response: () => { throw new Error("private upstream detail"); } },
    { reason: "invalid_response", response: () => ({}) },
    { reason: "identity_mismatch", response: () => timing("other") },
  ];
  for (const item of cases) {
    const h = await harness((path) => isList(path) ? page([session("s1", ["u1"])], null) : item.response());
    try {
      const r = await h.call({ since });
      const data = r.structuredContent as { sessions: Array<{
        timing_status: string; timing_unavailable_reason: string | null; timing: unknown;
      }> };
      assert.deepEqual(data.sessions[0], {
        session_id: "s1", source: "claude", task_title: null, project_id: null,
        attribution: "single_member", members: [{ user_id: "u1", name: "One" }],
        timing_status: "unavailable", timing_unavailable_reason: item.reason,
        timing: null, recorded_span_ms: null,
        citation_url: "https://control.example.com/s/claude/s1",
      });
      assert.ok(!JSON.stringify(data).includes("private upstream detail"));
    } finally { await h.close(); }
  }
});
