import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpContext } from "../src/mcp/context.js";
import { groupTwinEvents, registerSharedSessionReads, type RecallEvent } from "../src/mcp/shared-session-reads.js";

const T0 = "2026-11-12T12:00:00.000Z";
const at = (offsetMs: number) => new Date(Date.parse(T0) + offsetMs).toISOString();
function ev(eventId: string, patch: Partial<RecallEvent> = {}): RecallEvent {
  return { eventId, sessionId: "fake/session", source: "codex", kind: "session_event", type: "assistant",
    ts: T0, machineId: "machine-a", projectId: "Example/relay-control", content: "Ran the build.", ...patch };
}
const toolTwin = (id: string, patch: Partial<RecallEvent> = {}) =>
  ev(id, { kind: "tool_call", type: "tool_call", toolName: "shell", projectId: null, ts: at(1_500), ...patch });
const historyTwin = (id: string, patch: Partial<RecallEvent> = {}) => ev(id, { kind: "history", type: "user", ...patch });

async function fixture(t: TestContext, body: (path: string) => unknown) {
  const paths: string[] = [];
  const context = { workspace: { id: "ws-a", organizationId: "org-a" }, origin: "https://relay.example.test",
    agentTokens: true,
    members: async () => [],
    readHistory: async (path: string) => { paths.push(path); return body(path); },
  } as unknown as McpContext;
  const server = new McpServer({ name: "grouping-test", version: "1" });
  registerSharedSessionReads(server, context);
  const [a, b] = InMemoryTransport.createLinkedPair(); await server.connect(b);
  const client = new Client({ name: "grouping-test", version: "1" }); await client.connect(a);
  t.after(async () => { await client.close(); await server.close(); });
  return { client, paths };
}
function data(result: any): any {
  assert.notEqual(result.isError, true, JSON.stringify(result));
  return result.structuredContent;
}
const call = (client: Client, name: string, args = {}) => client.callTool({ name, arguments: args });
const eventsPage = (events: RecallEvent[]) => ({ events, nextCursor: null, correlationId: "corr-1" });

test("text search sends projectContains, not project, and reports history_ms", async t => {
  const f = await fixture(t, () => eventsPage([ev("e1")]));
  const value = data(await call(f.client, "search_shared_sessions", { query: "build", project: "relay-control" }));
  const url = new URL(f.paths[0]!, "https://reader.test");
  assert.equal(url.pathname, "/v1/events");
  assert.equal(url.searchParams.get("projectContains"), "relay-control");
  assert.equal(url.searchParams.has("project"), false);
  assert.ok(Number.isInteger(value.history_ms) && value.history_ms >= 0, String(value.history_ms));
});

test("agent listing sends projectContains, not project, and reports history_ms", async t => {
  const f = await fixture(t, () => ({ sessions: [{ sessionId: "fake/session", source: "codex", lastTs: T0, userIds: [] }], nextCursor: null }));
  const value = data(await call(f.client, "search_shared_sessions", { agent: "builder", project: "relay-control" }));
  const url = new URL(f.paths[0]!, "https://reader.test");
  assert.equal(url.pathname, "/v1/sessions");
  assert.equal(url.searchParams.get("projectContains"), "relay-control");
  assert.equal(url.searchParams.has("project"), false);
  assert.ok(Number.isInteger(value.history_ms) && value.history_ms >= 0, String(value.history_ms));
});

test("tool description and project input describe substring matching and since", async t => {
  const f = await fixture(t, () => eventsPage([]));
  const tool = (await f.client.listTools()).tools.find(tool => tool.name === "search_shared_sessions")!;
  assert.match(tool.description!, /since makes searches markedly faster/);
  assert.match((tool.inputSchema.properties as any).project.description, /substring of the session's project id/);
});

test("a tool_call twin folds into the session_event row with provenance", () => {
  const grouped = groupTwinEvents([ev("e1"), toolTwin("t1")]);
  assert.deepEqual(grouped.map(row => row.eventId), ["e1"]);
  assert.deepEqual(grouped[0]!.alsoRecordedAs, [{ eventId: "t1", kind: "tool_call", type: "tool_call", ts: at(1_500) }]);
});

test("a history twin at the same timestamp folds, whichever comes first, and both twins collect on one row", () => {
  const grouped = groupTwinEvents([historyTwin("h1"), ev("e1"), toolTwin("t1"), ev("other", { content: "Different." })]);
  assert.deepEqual(grouped.map(row => row.eventId), ["e1", "other"]);
  assert.deepEqual(grouped[0]!.alsoRecordedAs!.map(twin => twin.eventId).sort(), ["h1", "t1"]);
  assert.equal(grouped[1]!.alsoRecordedAs, undefined);
});

test("the window is 2000 ms inclusive", () => {
  assert.equal(groupTwinEvents([ev("e1"), toolTwin("t1", { ts: at(2_000) })]).length, 1);
  assert.equal(groupTwinEvents([ev("e1"), toolTwin("t1", { ts: at(2_001) })]).length, 2);
});

test("conservative cases stay untouched", () => {
  const cases: Array<[string, RecallEvent[]]> = [
    ["identical prompt repeated 5 s apart", [ev("e1", { type: "user" }), historyTwin("h1", { ts: at(5_000) })]],
    ["two session_event rows", [ev("e1"), ev("e2", { ts: at(500) })]],
    ["different machine", [ev("e1"), toolTwin("t1", { machineId: "machine-b" })]],
    ["null machine vs set machine", [ev("e1", { machineId: null }), toolTwin("t1")]],
    ["different content", [ev("e1"), toolTwin("t1", { content: "Ran the build!" })]],
    ["different session", [ev("e1"), toolTwin("t1", { sessionId: "fake/other" })]],
    ["different source", [ev("e1"), toolTwin("t1", { source: "claude" })]],
    ["null content", [ev("e1", { content: null }), toolTwin("t1", { content: null })]],
    ["tool_call and history only", [toolTwin("t1"), historyTwin("h1", { ts: at(1_500) })]],
  ];
  for (const [label, events] of cases) {
    const grouped = groupTwinEvents(events);
    assert.deepEqual(grouped.map(row => row.eventId), events.map(row => row.eventId), label);
    assert.ok(grouped.every(row => row.alsoRecordedAs === undefined), label);
  }
});

test("null machine ids on both rows count as equal", () => {
  assert.equal(groupTwinEvents([ev("e1", { machineId: null }), toolTwin("t1", { machineId: null })]).length, 1);
});

test("search matches carry also_recorded_as and drop the twin row", async t => {
  const f = await fixture(t, () => eventsPage([toolTwin("t1"), ev("e1"), ev("e2", { content: "Next.", ts: at(9_000) })]));
  const value = data(await call(f.client, "search_shared_sessions", { query: "build" }));
  assert.deepEqual(value.matches.map((row: any) => row.event_id), ["e1", "e2"]);
  assert.deepEqual(value.matches[0].also_recorded_as, [{ event_id: "t1", kind: "tool_call", type: "tool_call", timestamp: at(1_500) }]);
  assert.equal("also_recorded_as" in value.matches[1], false);
});

test("get_shared_session groups twins and counts returned rows in events_returned", async t => {
  const events = [ev("e1"), toolTwin("t1"), historyTwin("h1"), ev("e2", { type: "user", content: "Again.", ts: at(10_000) })];
  const f = await fixture(t, () => ({ sessionId: "fake/session", ...eventsPage(events) }));
  const value = data(await call(f.client, "get_shared_session", { session_id: "fake/session" }));
  assert.deepEqual(value.events.map((row: any) => row.event_id), ["e1", "e2"]);
  assert.equal(value.page_overview.events_returned, 2);
  assert.deepEqual(value.events[0].also_recorded_as.map((twin: any) => twin.event_id).sort(), ["h1", "t1"]);
});
