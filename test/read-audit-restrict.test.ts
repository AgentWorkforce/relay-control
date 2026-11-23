import assert from "node:assert/strict";
import test from "node:test";
import {
  EXPORT_COLUMNS, RESTRICT_PROBE_CONCURRENCY, RESTRICT_PROBE_MAX, readAuditCsv, restrictReadAudit,
  type ReadAuditAccessProbe, type ReadAuditExportRow,
} from "../src/mcp/read-audit.js";
import { confirmsAccessAdministrator } from "../src/sessions/access.js";

/**
 * Read audit export redaction under per-session access
 * (docs/shared-session-read-audit.md): the page is redacted after the
 * database read, from the exporter's own session access.
 */

let serial = 0;
function row(overrides: Partial<ReadAuditExportRow> = {}): ReadAuditExportRow {
  serial += 1;
  return {
    id: `00000000-0000-4000-8000-${String(serial).padStart(12, "0")}`,
    occurred_at: "2026-01-01T00:00:00.000000Z",
    organization_id: "org-1", workspace_id: "ws-1", caller_user_id: "user-caller",
    identity_kind: "hosted", auth_mode: "session",
    desktop_provider: null, oauth_client_id: null, oauth_grant_id: null, mcp_session_id: "mcp-1",
    native_session_id: null, native_session_provider: null, native_session_verified: false,
    tool_name: "search_shared_sessions", outcome: "ok", error_message: null,
    query_text: "deploy", agent_filter: null, requested_session_id: null, requested_source: null,
    filters: { status: "all" }, result_count: 0, result_sessions: [], result_sessions_truncated: false,
    correlation_id: "corr-1", duration_ms: 12,
    ...overrides,
  };
}

const session = (id: string, owners = [`owner-of-${id}`]) => ({ session_id: id, source: "codex", owner_user_ids: owners });

/** A probe answering from fixed sets, recording every call. */
function probe(options: { admin?: boolean | Error; readable?: string[] } = {}) {
  const calls = { administrator: [] as string[], readable: [] as string[] };
  const readable = new Set(options.readable ?? []);
  const value: ReadAuditAccessProbe = {
    administrator: async (id) => {
      calls.administrator.push(id);
      if (options.admin instanceof Error) throw options.admin;
      return options.admin === true;
    },
    readable: async (id) => {
      calls.readable.push(id);
      return readable.has(id);
    },
  };
  return { probe: value, calls };
}

test("an administrator's export is unchanged after exactly one administrator check", async () => {
  const rows = [
    row({ requested_session_id: "sess-a", result_sessions: [session("sess-a")] }),
    row({ result_sessions: [session("sess-b"), session("sess-c")] }),
  ];
  const before = structuredClone(rows);
  const { probe: p, calls } = probe({ admin: true });
  const shown = await restrictReadAudit(rows, p);
  assert.equal(shown.restricted, false);
  assert.deepEqual(shown.records, before);
  assert.equal(shown.records.some((record) => "restricted" in record), false);
  assert.deepEqual(calls.administrator, ["sess-a"], "one check, with an id from the page");
  assert.deepEqual(calls.readable, []);
  assert.equal(readAuditCsv(shown.records, { restricted: shown.restricted }), readAuditCsv(before));
});

test("the administrator check asks about the first id relaygate accepts, and is skipped when none is", async () => {
  const { probe: p, calls } = probe({ admin: true });
  const rows = [row({ requested_session_id: "bad id/with space" }), row({ requested_session_id: "sess-ok" })];
  const shown = await restrictReadAudit(rows, p);
  assert.deepEqual(calls.administrator, ["sess-ok"]);
  assert.equal(shown.restricted, false);

  const { probe: q, calls: none } = probe({ admin: true, readable: ["bad id/with space"] });
  const refused = await restrictReadAudit([row({ requested_session_id: "bad id/with space" })], q);
  assert.deepEqual(none.administrator, [], "no id relaygate accepts: no check, not an administrator");
  assert.equal(refused.restricted, true);
});

test("confirmsAccessAdministrator fails closed on every answer but relaygate's own", () => {
  assert.equal(confirmsAccessAdministrator(200, { runtime: true, access: { sessionId: "sess-a", version: 1 } }, "sess-a"), true);
  assert.equal(confirmsAccessAdministrator(200, { access: { sessionId: "sess-b" } }, "sess-a"), false);
  assert.equal(confirmsAccessAdministrator(200, { sessionId: "sess-a" }, "sess-a"), false);
  assert.equal(confirmsAccessAdministrator(200, "", "sess-a"), false);
  assert.equal(confirmsAccessAdministrator(404, { ok: false, error: { code: "relaygate_not_found", message: "x" } }, "sess-a"), true);
  assert.equal(confirmsAccessAdministrator(404, { error: "relaygate_not_found" }, "sess-a"), true);
  assert.equal(confirmsAccessAdministrator(404, { ok: false, error: { code: "relaygate_route_not_proxied" } }, "sess-a"), false);
  assert.equal(confirmsAccessAdministrator(404, { error: "Not Found" }, "sess-a"), false);
  assert.equal(confirmsAccessAdministrator(404, null, "sess-a"), false);
  assert.equal(confirmsAccessAdministrator(404, "<html>not found</html>", "sess-a"), false);
  assert.equal(confirmsAccessAdministrator(403, { error: { code: "relaygate_not_found" } }, "sess-a"), false);
});

test("a failed administrator check is the restrictive answer", async () => {
  const { probe: p, calls } = probe({ admin: new Error("lost"), readable: ["sess-a"] });
  const shown = await restrictReadAudit([row({ requested_session_id: "sess-a" }), row({ requested_session_id: "sess-b" })], p);
  assert.equal(shown.restricted, true);
  assert.deepEqual(calls.administrator, ["sess-a"]);
  const records = shown.records as Array<ReadAuditExportRow & { restricted: boolean }>;
  assert.deepEqual(records.map((record) => [record.requested_session_id, record.restricted]), [["sess-a", false], [null, true]]);
});

test("a non-administrator sees only readable session ids and owners; other fields are kept", async () => {
  const rows = [
    row({
      native_session_id: "sess-own", native_session_provider: "codex", native_session_verified: true,
      requested_session_id: "sess-open", requested_source: "codex",
      result_count: 3, result_sessions: [session("sess-open"), session("sess-private", ["owner-x", "owner-y"]), session("sess-own")],
      result_sessions_truncated: true,
    }),
    row({ requested_session_id: "sess-open", result_sessions: [session("sess-open")] }),
    row({ tool_name: "list_session_timings", requested_session_id: "sess-private", outcome: "error", error_message: "refused" }),
  ];
  const { probe: p, calls } = probe({ admin: false, readable: ["sess-own", "sess-open"] });
  const shown = await restrictReadAudit(rows, p);
  assert.equal(shown.restricted, true);
  // Each distinct id is probed once.
  assert.deepEqual([...calls.readable].sort(), ["sess-open", "sess-own", "sess-private"]);
  const [mixed, open, hidden] = shown.records as Array<ReadAuditExportRow & { restricted: boolean }>;
  assert.deepEqual(mixed!.result_sessions, [
    session("sess-open"),
    { session_id: null, source: "codex", owner_user_ids: null },
    session("sess-own"),
  ]);
  assert.equal(mixed!.native_session_id, "sess-own");
  assert.equal(mixed!.requested_session_id, "sess-open");
  assert.equal(mixed!.restricted, true);
  assert.equal(open!.restricted, false);
  assert.deepEqual(open!.result_sessions, [session("sess-open")]);
  assert.equal(hidden!.requested_session_id, null);
  assert.equal(hidden!.restricted, true);
  // Everything that is not a session id or an owner is exported as read.
  for (const [index, record] of shown.records.entries()) {
    const { requested_session_id: _r, native_session_id: _n, result_sessions: _s, restricted, ...rest } = record as ReadAuditExportRow & { restricted: boolean };
    const { requested_session_id: _r2, native_session_id: _n2, result_sessions: _s2, ...original } = rows[index]!;
    assert.deepEqual(rest, original);
    assert.equal(typeof restricted, "boolean");
  }
  assert.equal(mixed!.result_count, 3);
  assert.equal(mixed!.result_sessions_truncated, true);
});

test("the calling chat's own session id is withheld too when it is not readable", async () => {
  const { probe: p } = probe({ admin: false });
  const shown = await restrictReadAudit([row({ native_session_id: "sess-chat", native_session_provider: "claude" })], p);
  const [record] = shown.records as Array<ReadAuditExportRow & { restricted: boolean }>;
  assert.equal(record!.native_session_id, null);
  assert.equal(record!.native_session_provider, "claude");
  assert.equal(record!.restricted, true);
});

test("the restricted CSV adds a last restricted column and keeps every other column in place", async () => {
  const { probe: p } = probe({ admin: false, readable: ["sess-open"] });
  const shown = await restrictReadAudit([
    row({ requested_session_id: "sess-open" }),
    row({ result_sessions: [session("sess-private")] }),
  ], p);
  const lines = readAuditCsv(shown.records, { restricted: shown.restricted }).trimEnd().split("\r\n");
  assert.equal(lines[0], [...EXPORT_COLUMNS, "restricted"].join(","));
  assert.ok(lines[1]!.endsWith(",false"));
  assert.ok(lines[2]!.endsWith(",true"));
  assert.ok(!lines[2]!.includes("sess-private") && !lines[2]!.includes("owner-of-sess-private"));
  assert.ok(lines[2]!.includes('""session_id"":null'));
  assert.equal(readAuditCsv([row()]).split("\r\n")[0], EXPORT_COLUMNS.join(","));
});

test("at most RESTRICT_PROBE_MAX ids are probed, RESTRICT_PROBE_CONCURRENCY at a time; the rest are withheld", async () => {
  const ids = Array.from({ length: RESTRICT_PROBE_MAX + 20 }, (_, i) => `sess-${String(i).padStart(3, "0")}`);
  const rows = ids.map((id) => row({ requested_session_id: id }));
  const probed: string[] = [];
  let inFlight = 0;
  let peak = 0;
  const shown = await restrictReadAudit(rows, {
    administrator: async () => false,
    readable: async (id) => {
      probed.push(id);
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 1));
      inFlight -= 1;
      return true;
    },
  });
  assert.equal(probed.length, RESTRICT_PROBE_MAX);
  assert.deepEqual([...probed].sort(), ids.slice(0, RESTRICT_PROBE_MAX));
  assert.ok(peak <= RESTRICT_PROBE_CONCURRENCY, `peak ${peak}`);
  const records = shown.records as Array<ReadAuditExportRow & { restricted: boolean }>;
  assert.equal(records.filter((record) => !record.restricted).length, RESTRICT_PROBE_MAX);
  for (const record of records.slice(RESTRICT_PROBE_MAX)) {
    assert.equal(record.requested_session_id, null);
    assert.equal(record.restricted, true);
  }
});

test("past the deadline, unanswered ids are withheld and the export still answers", async (t) => {
  const pending: Array<() => void> = [];
  t.after(() => { for (const release of pending) release(); });
  const hang = () => new Promise<boolean>((resolve) => { pending.push(() => resolve(true)); });
  const started = Date.now();
  const slowAdmin = await restrictReadAudit([row({ requested_session_id: "sess-a" })], {
    administrator: hang, readable: async () => true,
  }, { deadlineMs: 30 });
  // The administrator check used the whole deadline: no probe may start after it.
  assert.equal(slowAdmin.restricted, true);
  assert.equal((slowAdmin.records[0] as { requested_session_id: string | null }).requested_session_id, null);

  const slowRead = await restrictReadAudit([
    row({ requested_session_id: "sess-fast" }), row({ requested_session_id: "sess-slow" }),
  ], {
    administrator: async () => false,
    readable: (id) => id === "sess-slow" ? hang() : Promise.resolve(true),
  }, { deadlineMs: 30 });
  assert.deepEqual(slowRead.records.map((record) => record.requested_session_id), ["sess-fast", null]);
  assert.ok(Date.now() - started < 2_000);
});

test("an exporter without a person read token sees no session id and nothing is asked", async () => {
  const shown = await restrictReadAudit([
    row({ requested_session_id: "sess-a", result_sessions: [session("sess-a")] }),
    row({ native_session_id: "sess-b" }),
  ], null);
  assert.equal(shown.restricted, true);
  const records = shown.records as Array<ReadAuditExportRow & { restricted: boolean }>;
  assert.deepEqual(records.map((record) => [record.requested_session_id, record.native_session_id, record.restricted]),
    [[null, null, true], [null, null, true]]);
  assert.deepEqual(records[0]!.result_sessions, [{ session_id: null, source: "codex", owner_user_ids: null }]);
});

test("a page naming no session is exported as read without asking", async () => {
  const rows = [row(), row({ outcome: "error", error_message: "refused" })];
  const before = structuredClone(rows);
  const { probe: p, calls } = probe({ admin: false });
  const shown = await restrictReadAudit(rows, p);
  assert.equal(shown.restricted, false);
  assert.deepEqual(shown.records, before);
  assert.deepEqual(calls, { administrator: [], readable: [] });
  assert.deepEqual(await restrictReadAudit([], null), { restricted: false, records: [] });
});
