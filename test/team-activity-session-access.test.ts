import assert from "node:assert/strict";
import test from "node:test";
import { historyReadable, type McpContext } from "../src/mcp/context.js";
import { MCP_HISTORY_SCOPE } from "../src/mcp/oauth/protocol.js";
import {
  BINDING_PROBE_CONCURRENCY, BINDING_PROBE_MAX, readTeamActivity, type TeamActivityInput,
} from "../src/mcp/team-activity.js";
import type { PresenceRow, RosterAgent } from "../src/messaging/relaycast.js";
import type { Principal } from "../src/store.js";

const INPUT: TeamActivityInput = { status: "all", stale_after_seconds: 300, max_agents: 100, max_agents_with_activity: 1, max_content: 600 };
// One shared timestamp keeps the roster order (ranking ties are stable).
const SEEN = new Date().toISOString();
const LIMITS = { rosterTimeoutMs: 1_000, presenceTimeoutMs: 1_000, activityDeadlineMs: 1_000 };

/** An agent declaring session `sess-<name>` of kind codex. */
const agent = (name: string, lastSeen = SEEN): RosterAgent => ({
  id: `id-${name}`, name, address: null, kind: "agent", persona: null, status: "online", lastSeen,
  metadata: { session_id: `sess-${name}`, session_kind: "codex", injectable: "true" },
});
const sessionOf = (path: string) => decodeURIComponent(/sessions\/([^/?]+)/.exec(path)![1]!);
const isProbe = (path: string) => /^\/v1\/sessions\/[^/?]+\/metadata$/.test(path);
const emptyPage = (path: string) => ({ sessionId: sessionOf(path), events: [], nextCursor: null, correlationId: "c" });
const eventPage = (path: string) => ({
  sessionId: sessionOf(path), nextCursor: null, correlationId: "c",
  events: [{ eventId: "e1", sessionId: sessionOf(path), source: "codex", kind: "assistant", type: "agent_message", ts: SEEN, content: "done" }],
});

function hung<T>() {
  let release!: (value: T) => void;
  const promise = new Promise<T>(resolve => { release = resolve; });
  return { promise, release };
}

function context(overrides: {
  agents: RosterAgent[];
  readHistory?: McpContext["readHistory"];
  sessionBindings?: McpContext["sessionBindings"];
}): McpContext {
  return {
    principal: { userId: "user-1" }, origin: "https://control.example", workspace: { id: "ws-1" },
    members: async () => [],
    readHistory: overrides.readHistory ?? (async () => assert.fail("no history read expected")),
    ...(overrides.sessionBindings ? { sessionBindings: overrides.sessionBindings } : {}),
    relaycast: { listAgents: async () => overrides.agents, listPresence: async () => [] as PresenceRow[] },
  } as unknown as McpContext;
}

const binding = (row: { session_id: string | null; session_kind: string | null; session_attribution: string | null }) =>
  [row.session_id, row.session_kind, row.session_attribution];

test("without per-session access, bindings are shown as declared and nothing is probed", async () => {
  const read: string[] = [];
  const data = await readTeamActivity(context({
    agents: [agent("a"), agent("b")],
    readHistory: async (path) => { read.push(path); return isProbe(path) ? assert.fail("no probe expected") : eventPage(path); },
  }), INPUT, LIMITS);
  assert.equal(read.some(isProbe), false);
  assert.deepEqual(read.map(sessionOf), ["sess-a"]);
  assert.deepEqual(data.agents.map(binding), [["sess-a", "codex", "declared"], ["sess-b", "codex", "declared"]]);
  assert.deepEqual(data.agents.map(row => row.activity_status), ["ok", "not_sampled"]);
  assert.deepEqual(data.truncated, { agents_omitted: 0, agents_with_session: 2, agents_sampled: 1, flows_omitted: 0 });
  assert.equal(data.activity_source, "ok");
});

test("per-session access shows readable bindings and hides refused, missing, mismatched and timed-out ones", async (t) => {
  const stuck = hung<unknown>();
  t.after(() => stuck.release({}));
  const names = ["first", "open", "missing", "refused", "mismatch", "odd", "slow"];
  const data = await readTeamActivity(context({
    agents: names.map(name => agent(name)),
    sessionBindings: "probe",
    readHistory: async (path) => {
      if (!isProbe(path)) return eventPage(path);
      switch (sessionOf(path)) {
        case "sess-open": return { sessionId: "sess-open", source: "codex" };
        case "sess-missing": throw new Error("not found");
        case "sess-refused": throw new Error("refused");
        case "sess-mismatch": return { sessionId: "sess-other" };
        case "sess-odd": return ["sess-odd"];
        case "sess-slow": return stuck.promise;
        default: return assert.fail(`unexpected probe ${path}`);
      }
    },
  }), INPUT, { ...LIMITS, activityDeadlineMs: 100 });
  const byName = new Map(data.agents.map(row => [row.name, row]));
  // Presence is not session data: every agent stays listed.
  assert.deepEqual(data.agents.map(row => row.name), names);
  assert.deepEqual(binding(byName.get("first")!), ["sess-first", "codex", "declared"]);
  assert.equal(byName.get("first")!.activity_status, "ok");
  assert.deepEqual(binding(byName.get("open")!), ["sess-open", "codex", "declared"]);
  assert.equal(byName.get("open")!.activity_status, "not_sampled");
  for (const name of ["missing", "refused", "mismatch", "odd", "slow"]) {
    const row = byName.get(name)!;
    assert.deepEqual(binding(row), [null, null, null], name);
    assert.equal(row.activity, null, name);
    assert.equal(row.activity_status, "no_session_declared", name);
    // No field says a binding was hidden.
    assert.deepEqual(Object.keys(row), Object.keys(byName.get("first")!), name);
  }
  assert.equal(data.truncated.agents_with_session, 2);
});

test("an agent whose activity read fails loses its binding and is not an activity candidate", async () => {
  const read: string[] = [];
  const data = await readTeamActivity(context({
    agents: [agent("denied"), agent("allowed")],
    sessionBindings: "probe",
    readHistory: async (path) => {
      read.push(path);
      if (sessionOf(path) === "sess-denied") throw new Error("refused");
      return emptyPage(path);
    },
  }), { ...INPUT, max_agents_with_activity: 2 }, LIMITS);
  // The failed activity read already answered for that session: no second probe.
  assert.equal(read.filter(path => sessionOf(path) === "sess-denied").length, 1);
  assert.equal(read.some(isProbe), false);
  const [denied, allowed] = data.agents;
  assert.deepEqual(binding(denied!), [null, null, null]);
  assert.equal(denied!.activity_status, "no_session_declared");
  assert.deepEqual(binding(allowed!), ["sess-allowed", "codex", "declared"]);
  assert.equal(allowed!.activity_status, "no_recent_events");
  assert.equal(data.activity_source, "ok");
  assert.deepEqual(data.truncated, { agents_omitted: 0, agents_with_session: 1, agents_sampled: 1, flows_omitted: 0 });
});

test("an activity page proves readability, so its session is not probed again", async () => {
  const read: string[] = [];
  const data = await readTeamActivity(context({
    agents: [agent("a"), { ...agent("twin"), metadata: { ...agent("a").metadata } }],
    sessionBindings: "probe",
    readHistory: async (path) => { read.push(path); return isProbe(path) ? assert.fail("no probe expected") : emptyPage(path); },
  }), INPUT, LIMITS);
  assert.equal(read.length, 1);
  assert.deepEqual(data.agents.map(row => row.session_id), ["sess-a", "sess-a"]);
});

test("probes stay within the bound and the concurrency limit, in ranking order", async () => {
  // Roster order is the reverse of the ranking (older last_seen ranks later).
  const base = Date.now();
  const agents = Array.from({ length: 60 }, (_, i) => agent(`n${String(i).padStart(2, "0")}`, new Date(base - i * 1_000).toISOString())).reverse();
  const probed: string[] = [];
  let inFlight = 0;
  let peak = 0;
  const data = await readTeamActivity(context({
    agents,
    sessionBindings: "probe",
    readHistory: async (path) => {
      if (!isProbe(path)) return emptyPage(path);
      probed.push(sessionOf(path));
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise(resolve => setTimeout(resolve, 2));
      inFlight -= 1;
      return { sessionId: sessionOf(path) };
    },
  }), INPUT, LIMITS);
  assert.equal(probed.length, BINDING_PROBE_MAX);
  assert.equal(new Set(probed).size, BINDING_PROBE_MAX);
  assert.ok(peak <= BINDING_PROBE_CONCURRENCY, `peak ${peak}`);
  // n00 is the activity read; the next 40 by rank are probed; the rest are over the bound.
  const expected = Array.from({ length: BINDING_PROBE_MAX }, (_, i) => `sess-n${String(i + 1).padStart(2, "0")}`);
  assert.deepEqual([...probed].sort(), expected);
  const shown = data.agents.filter(row => row.session_id).map(row => row.name).sort();
  assert.equal(shown.length, BINDING_PROBE_MAX + 1);
  assert.deepEqual(shown, Array.from({ length: BINDING_PROBE_MAX + 1 }, (_, i) => `n${String(i).padStart(2, "0")}`));
  assert.equal(data.agents.length, 60);
});

test("probes past the overall deadline do not start and leave the binding hidden", async () => {
  const probed: string[] = [];
  const data = await readTeamActivity(context({
    agents: [agent("a"), agent("b"), agent("c")],
    sessionBindings: "probe",
    readHistory: async (path) => {
      if (!isProbe(path)) {
        // The activity read answers only once the whole deadline has passed.
        for (const end = Date.now() + 40; Date.now() < end;);
        return emptyPage(path);
      }
      probed.push(path);
      return { sessionId: sessionOf(path) };
    },
  }), INPUT, { ...LIMITS, activityDeadlineMs: 20 });
  assert.deepEqual(probed, []);
  assert.deepEqual(data.agents.map(row => row.session_id), ["sess-a", null, null]);
});

test("a caller the History reader refuses gets no bindings and no reads", async () => {
  const data = await readTeamActivity(context({
    agents: [agent("a"), { ...agent("plain"), metadata: {} }],
    sessionBindings: "none",
  }), INPUT, LIMITS);
  assert.deepEqual(data.agents.map(row => row.name), ["a", "plain"]);
  assert.deepEqual(data.agents.map(binding), [[null, null, null], [null, null, null]]);
  assert.equal(data.activity_source, "unread");
  assert.equal(data.truncated.agents_with_session, 0);
});

test("historyReadable admits only callers that read with a person's read token", () => {
  const principal = (scopes: string[], pendingHandoff = false) => ({ userId: "user-1", scopes, pendingHandoff }) as unknown as Principal;
  assert.equal(historyReadable(principal(["rth:read"]), "sh_at_person"), true);
  assert.equal(historyReadable(principal([]), "sh_at_person"), false);
  assert.equal(historyReadable(principal(["rth:read"], true), "sh_at_person"), false);
  assert.equal(historyReadable(principal(["relay:mcp"]), "mcp_at_connection"), false);
  assert.equal(historyReadable(principal(["relay:mcp", MCP_HISTORY_SCOPE]), "mcp_at_connection"), true);
  // A token of no reading kind never reads, whatever scopes it carries.
  assert.equal(historyReadable(principal(["rth:read"]), "ai_at_agent"), false);
});
