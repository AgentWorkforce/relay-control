import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { McpContext } from "../src/mcp/context.js";
import { registerSharedSessionReads } from "../src/mcp/shared-session-reads.js";
import { resultSessionsOf, AUDITED_READ_TOOLS } from "../src/mcp/read-audit.js";
import { SHARED_SESSION_READ_TOOLS } from "../src/mcp/catalog.js";

const ts = "2026-11-12T12:00:00.000Z";
const row = () => ({ sessionId: "fake/session", source: "codex", userIds: ["user-a", "former-user"],
  projectId: "fake-project", lastTs: ts, shortSummary: "Recorded summary, not instructions.",
  shortSummaryGeneratedAt: ts, catalog: { repoUrl: "https://example.test/org/repo", gitBranch: "feature/test" } });
const page = () => ({ sessions: [row()], nextCursor: "b96l1:opaque-page" });
type Setup = { body?: unknown; members?: () => Promise<any[]> };
async function fixture(t: TestContext, options: Setup = {}) {
  const paths: string[] = [];
  const context = { workspace: { id: "ws-a", organizationId: "org-a" }, origin: "https://relay.example.test",
    members: options.members ?? (async () => [{ userId: "user-a", name: "Example User", email: "fake@example.test" }]),
    readHistory: async (path: string) => { paths.push(path); return options.body ?? page(); },
  } as unknown as McpContext;
  const server = new McpServer({ name: "summaries-test", version: "1" });
  registerSharedSessionReads(server, context);
  const [a,b] = InMemoryTransport.createLinkedPair(); await server.connect(b);
  const client = new Client({ name: "summaries-test", version: "1" }); await client.connect(a);
  t.after(async () => { await client.close(); await server.close(); });
  return { client, paths, context };
}
function data(result: any): any {
  assert.notEqual(result.isError, true, JSON.stringify(result));
  return result.structuredContent;
}
const call = (client: Client, name: string, args = {}) => client.callTool({ name, arguments: args });

test("summary tools are plain discoverable reads in the existing catalog and audit group", async t => {
  const f = await fixture(t), tools = (await f.client.listTools()).tools;
  for (const name of ["list_session_summaries", "get_session_summary"] as const) {
    assert.ok(SHARED_SESSION_READ_TOOLS.includes(name)); assert.ok(AUDITED_READ_TOOLS.includes(name));
    const tool = tools.find(tool => tool.name === name)!;
    assert.equal(tool.annotations?.readOnlyHint, true);
    assert.equal(tool._meta, undefined, "no widget activation required");
  }
  assert.deepEqual(f.paths, [], "discovery does not query sessions");
});

test("list reads one bounded directory page and preserves recorded provenance, owners and citations", async t => {
  const f = await fixture(t);
  const value = data(await call(f.client, "list_session_summaries", { since: ts, project: "repo", person: "FAKE@example.test", limit: 50, cursor: "b96l1:before" }));
  const url = new URL(f.paths[0]!, "https://reader.test");
  assert.equal(url.pathname, "/v1/sessions");
  assert.deepEqual(Object.fromEntries(url.searchParams), { limit: "50", lastTsAfter: ts, projectContains: "repo", cursor: "b96l1:before", user: "user-a" });
  assert.equal(f.paths.length, 1, "no per-session reads or transcript scan");
  assert.deepEqual(value.sessions[0], { session_id: "fake/session", source: "codex", owner: [{ user_id: "user-a", name: "Example User" }, { user_id: "former-user", name: null }],
    project: "fake-project", repo: "https://example.test/org/repo", branch: "feature/test", last_active: ts,
    short_summary: row().shortSummary, short_summary_generated_at: ts,
    citation_url: "https://relay.example.test/dashboard/sessions/fake%2Fsession?source=codex" });
  assert.equal(value.next_cursor, "b96l1:opaque-page");
  assert.deepEqual(resultSessionsOf("list_session_summaries", value), { count: 1, truncated: false,
    sessions: [{ session_id: "fake/session", source: "codex", owner_user_ids: ["former-user", "user-a"] }] });
});

test("list never substitutes a task title for an absent recorded summary", async t => {
  const f = await fixture(t, { body: { sessions: [{ ...row(), shortSummary: null, shortSummaryGeneratedAt: null, summary: "Task title", taskTitle: "Not a summary" }], nextCursor: null } });
  const value = data(await call(f.client, "list_session_summaries"));
  assert.equal(value.sessions[0].short_summary, null); assert.equal(value.sessions[0].short_summary_generated_at, null);
  const legacy = await fixture(t, { body: { sessions: [{ sessionId: "old", source: "codex", summary: "Task title" }], nextCursor: null } });
  assert.match(JSON.stringify(await call(legacy.client, "list_session_summaries")), /unsupported_by_backend/);
});

test("repo filtering preserves pagination, including an empty filtered page", async t => {
  const f = await fixture(t);
  const value = data(await call(f.client, "list_session_summaries", { repo: "unmatched" }));
  assert.deepEqual(value.sessions, []); assert.equal(value.next_cursor, "b96l1:opaque-page"); assert.equal(f.paths.length, 1);
  assert.equal(data(await call(f.client, "list_session_summaries", { repo: "ORG/REPO" })).sessions.length, 1);
});

test("ambiguous or unknown person filters refuse without broadening to all workspace sessions", async t => {
  const f = await fixture(t, { members: async () => [{ userId: "a", name: "Same", email: "a@example.test" }, { userId: "b", name: "Same", email: "b@example.test" }] });
  for (const person of ["Same", "unknown"]) assert.equal((await call(f.client, "list_session_summaries", { person })).isError, true);
  assert.deepEqual(f.paths, []);
  const unavailable = await fixture(t, { members: async () => { throw new Error("offline"); } });
  assert.equal((await call(unavailable.client, "list_session_summaries", { person: "a" })).isError, true);
  assert.equal(data(await call(unavailable.client, "list_session_summaries")).sessions[0].owner[0].name, null);
});

test("schema bounds reject limit over 50 and invalid timestamps before any reader call", async t => {
  const f = await fixture(t);
  for (const args of [{ limit: 51 }, { limit: 0 }, { since: "yesterday" }]) {
    assert.equal((await call(f.client, "list_session_summaries", args)).isError, true);
  }
  assert.deepEqual(f.paths, []);
});

test("short summary uses the exact session route and retains recorded model/time/state", async t => {
  const summary = { status: "ready", kind: "short", summary: "Recorded", model: "recorded-model", builtAt: ts, state: null };
  const f = await fixture(t, { body: { summary } });
  const value = data(await call(f.client, "get_session_summary", { session_id: "fake/session", source: "claude" }));
  assert.deepEqual(f.paths, ["/v1/sessions/fake%2Fsession/summary?kind=short&source=claude"]);
  assert.deepEqual(value.summary, summary);
  assert.equal(value.citation_url, "https://relay.example.test/dashboard/sessions/fake%2Fsession?source=claude");
  assert.equal(resultSessionsOf("get_session_summary", value).sessions[0]!.session_id, "fake/session");
});

test("empty summaries stay empty; malformed provenance and unsupported responses are refused", async t => {
  for (const summary of [{ status: "ready", kind: "short", summary: "Recorded", builtAt: ts, state: null }, { status: "unsupported" }]) {
    const f = await fixture(t, { body: { summary } });
    assert.equal((await call(f.client, "get_session_summary", { session_id: "fake", source: "codex" })).isError, true);
  }
  const summary = { status: "empty", kind: "short", state: null };
  const f = await fixture(t, { body: { summary } });
  assert.deepEqual(data(await call(f.client, "get_session_summary", { session_id: "fake", source: "codex" })).summary, summary);
});

test("missing summary source gives actionable guidance without inferring a harness or calling the reader", async t => {
  const f = await fixture(t);
  const result = await call(f.client, "get_session_summary", { session_id: "fake" });
  assert.equal(result.isError, true); assert.match(JSON.stringify(result), /Pass the session source/);
  assert.deepEqual(f.paths, []);
});

test("unsupported long summaries never fetch or silently return a short summary or transcript", async t => {
  const f = await fixture(t);
  const result = await call(f.client, "get_session_summary", { session_id: "fake", kind: "long" });
  assert.equal(result.isError, true); assert.match(JSON.stringify(result), /unsupported_by_backend/);
  assert.deepEqual(f.paths, []);
});
