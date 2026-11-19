import assert from "node:assert/strict";
import test from "node:test";
import type { McpContext } from "../src/mcp/context.js";
import { readTeamActivity, type TeamActivityInput } from "../src/mcp/team-activity.js";
import type { PresenceRow, RosterAgent } from "../src/messaging/relaycast.js";

const INPUT: TeamActivityInput = { status: "all", stale_after_seconds: 300, max_agents: 100, max_agents_with_activity: 50, max_content: 600 };
// One shared timestamp keeps the roster order (ranking ties are stable).
const SEEN = new Date().toISOString();
const LIMITS = { rosterTimeoutMs: 30, presenceTimeoutMs: 30, activityDeadlineMs: 50 };

/** An agent declaring session `sess-<name>` (no session_kind: History is read by bare session ID). */
const agent = (name: string): RosterAgent => ({
  id: `id-${name}`, name, address: null, kind: "agent", persona: null, status: "online", lastSeen: SEEN,
  metadata: { session_id: `sess-${name}`, injectable: "true" },
});
const emptyPage = (path: string) => ({
  sessionId: decodeURIComponent(/sessions\/([^/?]+)/.exec(path)![1]!), events: [], nextCursor: null, correlationId: "c",
});

/** A promise that never settles on its own; `release` settles it so nothing is left pending. */
function hung<T>() {
  let release!: (value: T) => void;
  const promise = new Promise<T>(resolve => { release = resolve; });
  return { promise, release };
}

function context(overrides: {
  listAgents?: McpContext["relaycast"]["listAgents"];
  listPresence?: McpContext["relaycast"]["listPresence"];
  readHistory?: McpContext["readHistory"];
}): McpContext {
  return {
    principal: { userId: "user-1" }, origin: "https://control.example", workspace: { id: "ws-1" },
    members: async () => [],
    readHistory: overrides.readHistory ?? (async () => assert.fail("no history read expected")),
    relaycast: {
      listAgents: overrides.listAgents ?? (async () => []),
      listPresence: overrides.listPresence ?? (async () => [] as PresenceRow[]),
    },
  } as unknown as McpContext;
}

test("a roster read that never settles fails with the roster-unavailable error and aborts its signal", async (t) => {
  const roster = hung<RosterAgent[]>();
  t.after(() => roster.release([]));
  let seen: AbortSignal | undefined;
  const started = Date.now();
  await assert.rejects(readTeamActivity(context({
    listAgents: (_status, options) => { seen = options?.signal; return roster.promise; },
  }), INPUT, LIMITS), /roster is temporarily unavailable/);
  assert.ok(Date.now() - started < 1_000);
  assert.ok(seen);
  assert.equal(seen.aborted, true);
});

test("a presence read that never settles reports presence unavailable and still lists agents", async (t) => {
  const presence = hung<PresenceRow[]>();
  t.after(() => presence.release([]));
  let seen: AbortSignal | undefined;
  const started = Date.now();
  // Presence has its own, shorter bound: the roster bound here is far away.
  const data = await readTeamActivity(context({
    listAgents: async () => [{ ...agent("a"), metadata: {} }],
    listPresence: (options) => { seen = options?.signal; return presence.promise; },
  }), INPUT, { ...LIMITS, rosterTimeoutMs: 5_000, presenceTimeoutMs: 20 });
  assert.ok(Date.now() - started < 1_000);
  assert.equal(seen?.aborted, true);
  assert.equal(data.presence_source, "unavailable");
  assert.deepEqual(data.agents.map(row => row.name), ["a"]);
  assert.equal(data.agents[0]!.presence.liveness, "unknown");
});

test("a History read still pending at the deadline is unavailable and its late answer is ignored", async (t) => {
  const stuck = hung<unknown>();
  t.after(() => stuck.release({}));
  const data = await readTeamActivity(context({
    listAgents: async () => [agent("fast"), agent("slow")],
    readHistory: async (path) => path.includes("sess-slow") ? stuck.promise : emptyPage(path),
  }), INPUT, LIMITS);
  // The late answer arrives after the result was built; it must change nothing.
  stuck.release(emptyPage("/sessions/sess-slow/events"));
  await new Promise(resolve => setImmediate(resolve));
  const byName = new Map(data.agents.map(row => [row.name, row]));
  assert.equal(byName.get("fast")!.activity_status, "no_recent_events");
  assert.equal(byName.get("slow")!.activity_status, "unavailable");
  assert.equal(byName.get("slow")!.activity, null);
  assert.equal(data.activity_source, "unavailable");
  assert.equal(data.truncated.agents_sampled, 2);
});

test("candidates after the deadline are unavailable without a History read", async () => {
  const names = ["a1", "a2", "a3", "a4", "a5", "b1", "b2"];
  const read: string[] = [];
  const data = await readTeamActivity(context({
    listAgents: async () => names.map(agent),
    readHistory: async (path) => {
      // The first batch answers, but only once the whole deadline has passed
      // (synchronously, so the answer still wins over the batch's own timer).
      if (!read.length) for (const end = Date.now() + 40; Date.now() < end;);
      read.push(path);
      return emptyPage(path);
    },
  }), INPUT, { rosterTimeoutMs: 1_000, activityDeadlineMs: 20 });
  assert.equal(read.length, 5);
  assert.equal(read.some(path => path.includes("sess-b")), false);
  const byName = new Map(data.agents.map(row => [row.name, row.activity_status]));
  for (const name of names) assert.equal(byName.get(name), name.startsWith("a") ? "no_recent_events" : "unavailable", name);
  assert.equal(data.activity_source, "unavailable");
  assert.equal(data.truncated.agents_with_session, 7);
  assert.equal(data.truncated.agents_sampled, 7);
});
