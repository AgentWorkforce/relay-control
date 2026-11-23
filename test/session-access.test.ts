import assert from "node:assert/strict";
import test from "node:test";
import {
  accessHistory,
  getAccess,
  resetAccess,
  sessionAccessConfigured,
  setAccess,
  type AccessDeps,
  type AccessMember,
  type AccessReply,
  type AccessRequest,
} from "../src/sessions/access.js";

/**
 * The session access service (src/sessions/access.ts) against a stub
 * transport: validation, email resolution, version handling and the outcome
 * mapping. The HTTP and MCP surfaces are covered in
 * test/session-access-routes.test.ts.
 */

const SESSION = "fake-session-1";
const MEMBERS: AccessMember[] = [
  { userId: "user-a", email: "alpha@example.test", name: "Alpha" },
  { userId: "user-b", email: "Beta@Example.test", name: null },
];

function policyBody(version: number, users: Array<{ userId: string; perm: string }> = [], extra: Record<string, unknown> = {}) {
  return {
    runtime: true,
    access: {
      sessionId: SESSION, gid: 7, mode: "640", acl: [{ gid: 12, perm: "r" }], users, label: "Review",
      version, updatedAt: "2026-01-01T00:00:00.000Z", ...extra,
    },
  };
}

type Script = (request: AccessRequest, index: number) => AccessReply;

function stub(script: Script, members: () => Promise<AccessMember[]> = async () => MEMBERS) {
  const calls: AccessRequest[] = [];
  const deps: AccessDeps = {
    send: async (request) => {
      calls.push(request);
      return script(request, calls.length - 1);
    },
    members,
  };
  return { deps, calls };
}

const ok = (body: unknown): AccessReply => ({ kind: "response", status: 200, body });

test("configuration: reader-kind mints with per-person MCP reads, with or without the relaygate public URL", () => {
  const api = { mintReaderKind: true };
  assert.equal(sessionAccessConfigured({ sessionReadApi: api, sessionReadMcpReads: true }), true);
  // Sessions-only install: no SELFHOST_RELAYGATE_PUBLIC_URL, mints still carry the reader kind.
  const sessionsOnly = { relaygatePublicUrl: null, sessionReadApi: api, sessionReadMcpReads: true };
  assert.equal(sessionAccessConfigured(sessionsOnly), true);
  assert.equal(sessionAccessConfigured({ sessionReadApi: { mintReaderKind: false }, sessionReadMcpReads: true }), false);
  assert.equal(sessionAccessConfigured({ sessionReadApi: {}, sessionReadMcpReads: true }), false);
  assert.equal(sessionAccessConfigured({ sessionReadApi: null, sessionReadMcpReads: true }), false);
  assert.equal(sessionAccessConfigured({ sessionReadApi: api, sessionReadMcpReads: false }), false);
});

test("get: maps user ids to current members and shows a former member as member:false", async () => {
  const { deps, calls } = stub(() => ok(policyBody(3, [
    { userId: "user-a", perm: "rw" }, { userId: "user-gone", perm: "r" },
  ])));
  const result = await getAccess(deps, SESSION);
  assert.equal(result.outcome, "ok");
  assert.ok(result.outcome === "ok");
  assert.equal(result.value.version, 3);
  assert.deepEqual(result.value.groups, [{ gid: 12, perm: "r" }]);
  assert.deepEqual(result.value.members, [
    { userId: "user-a", email: "alpha@example.test", name: "Alpha", perm: "rw", member: true },
    { userId: "user-gone", perm: "r", member: false },
  ]);
  assert.deepEqual(calls.map((call) => [call.method, call.path]), [["GET", `/v1/sessions/${SESSION}/access`]]);
});

test("set: without a version reads first, then PATCHes with that version and only user ids", async () => {
  const { deps, calls } = stub((request) => request.method === "GET"
    ? ok(policyBody(4))
    : ok(policyBody(5, [{ userId: "user-a", perm: "r" }, { userId: "user-b", perm: "rw" }])));
  const result = await setAccess(deps, SESSION, {
    mode: "000",
    members: [{ email: "ALPHA@example.test", perm: "r" }, { email: "beta@example.test", perm: "rw" }],
    groups: [{ gid: 12, perm: "r" }],
    label: null,
    reason: "  restrict for review  ",
  });
  assert.equal(result.outcome, "ok");
  assert.ok(result.outcome === "ok");
  assert.equal(result.value.version, 5);
  assert.deepEqual(calls.map((call) => call.method), ["GET", "PATCH"]);
  const patch = calls[1]!;
  assert.deepEqual(patch.body, {
    mode: "000",
    acl: [{ gid: 12, perm: "r" }],
    users: [{ userId: "user-a", perm: "r" }, { userId: "user-b", perm: "rw" }],
    label: null,
    expectedVersion: 4,
    reason: "restrict for review",
  });
  const sent = JSON.stringify(patch.body).toLowerCase();
  for (const member of MEMBERS) {
    assert.ok(!sent.includes(member.email.toLowerCase()), "no email upstream");
    if (member.name) assert.ok(!sent.includes(member.name.toLowerCase()), "no name upstream");
  }
});

test("set: a given version is sent as is, with no read first", async () => {
  const { deps, calls } = stub(() => ok(policyBody(10)));
  const result = await setAccess(deps, SESSION, { mode: "640", reason: "open", expectedVersion: 9 });
  assert.equal(result.outcome, "ok");
  assert.deepEqual(calls.map((call) => call.method), ["PATCH"]);
  assert.equal(calls[0]!.body!.expectedVersion, 9);
});

test("set: 409 is a conflict with the current version and is never retried", async () => {
  const { deps, calls } = stub(() => ({ kind: "response", status: 409, body: { currentVersion: 12 } }));
  const result = await setAccess(deps, SESSION, { mode: "640", reason: "open", expectedVersion: 9 });
  assert.equal(result.outcome, "conflict");
  assert.ok(result.outcome === "conflict");
  assert.equal(result.currentVersion, 12);
  assert.equal(calls.length, 1);
});

test("set: the nested error form of a 409 also carries the current version", async () => {
  const { deps } = stub(() => ({ kind: "response", status: 409, body: { error: { code: "conflict", currentVersion: 2 } } }));
  const result = await resetAccess(deps, SESSION, { reason: "back to defaults", expectedVersion: 1 });
  assert.ok(result.outcome === "conflict");
  assert.equal(result.currentVersion, 2);
});

test("set: an unknown email and an email from another organization refuse with nothing sent", async () => {
  // The member list is the caller's organization only, so another
  // organization's member is simply not in it.
  const { deps, calls } = stub(() => ok(policyBody(1)));
  const result = await setAccess(deps, SESSION, {
    members: [
      { email: "alpha@example.test", perm: "r" },
      { email: "nobody@example.test", perm: "r" },
      { email: "member@other-org.example.test", perm: "rw" },
    ],
    reason: "share",
  });
  assert.equal(result.outcome, "unknown_members");
  assert.ok(result.outcome === "unknown_members");
  assert.deepEqual(result.emails, ["nobody@example.test", "member@other-org.example.test"]);
  assert.equal(calls.length, 0);
});

test("set: an email shared by two members is ambiguous and refused", async () => {
  const { deps, calls } = stub(() => ok(policyBody(1)), async () => [
    ...MEMBERS, { userId: "user-c", email: "alpha@EXAMPLE.test", name: null },
  ]);
  const result = await setAccess(deps, SESSION, { members: [{ email: "alpha@example.test", perm: "r" }], reason: "share" });
  assert.equal(result.outcome, "unknown_members");
  assert.equal(calls.length, 0);
});

test("validation refuses before any upstream call", async () => {
  const cases: Array<[string, Record<string, unknown>]> = [
    ["mode out of range", { mode: "777", reason: "x" }],
    ["mode wrong length", { mode: "64", reason: "x" }],
    ["reason missing", { mode: "640" }],
    ["reason empty", { mode: "640", reason: "   " }],
    ["reason too long", { mode: "640", reason: "x".repeat(201) }],
    ["reason with a control character", { mode: "640", reason: "a\nb" }],
    ["empty change", { reason: "nothing" }],
    ["bad perm", { members: [{ email: "alpha@example.test", perm: "x" }], reason: "x" }],
    ["duplicate email", { members: [{ email: "alpha@example.test", perm: "r" }, { email: "ALPHA@example.test", perm: "rw" }], reason: "x" }],
    ["too many groups", { groups: Array.from({ length: 65 }, (_, gid) => ({ gid, perm: "r" })), reason: "x" }],
    ["bad label", { label: "x".repeat(25), reason: "x" }],
    ["negative version", { mode: "640", reason: "x", expectedVersion: -1 }],
  ];
  for (const [name, change] of cases) {
    let members = 0;
    const { deps, calls } = stub(() => ok(policyBody(1)), async () => { members++; return MEMBERS; });
    const result = await setAccess(deps, SESSION, change);
    assert.equal(result.outcome, "invalid_request", name);
    assert.equal(calls.length, 0, name);
    assert.equal(members, 0, `${name}: refused before the member list is read`);
  }
  const { deps, calls } = stub(() => ok(policyBody(1)));
  assert.equal((await getAccess(deps, "bad/session")).outcome, "invalid_request");
  assert.equal((await resetAccess(deps, SESSION, { reason: "" })).outcome, "invalid_request");
  assert.equal((await accessHistory(deps, SESSION, { limit: 0 })).outcome, "invalid_request");
  assert.equal((await accessHistory(deps, SESSION, { limit: 201 })).outcome, "invalid_request");
  assert.equal(calls.length, 0);
});

test("a reason of exactly 200 characters is accepted", async () => {
  const { deps, calls } = stub(() => ok(policyBody(2)));
  const result = await setAccess(deps, SESSION, { mode: "640", reason: "x".repeat(200), expectedVersion: 1 });
  assert.equal(result.outcome, "ok");
  assert.equal(calls.length, 1);
});

test("404 and 403 map to not_found and not_access_admin", async () => {
  // relaygate answers 403 before it looks the session up; 404 reaches only an
  // administrator, and only for an unknown session.
  const notFound = stub(() => ({ kind: "response", status: 404, body: null }));
  const missing = await getAccess(notFound.deps, SESSION);
  assert.deepEqual(missing.outcome === "not_found" && missing.message, "Session not found.");
  const forbidden = stub(() => ({ kind: "response", status: 403, body: null }));
  assert.equal((await getAccess(forbidden.deps, SESSION)).outcome, "not_access_admin");
  assert.equal((await setAccess(forbidden.deps, SESSION, { mode: "640", reason: "x", expectedVersion: 1 })).outcome, "not_access_admin");
  assert.equal((await accessHistory(forbidden.deps, SESSION)).outcome, "not_access_admin");
  // Without a version, a 403 on the first read stops before any PATCH.
  const first = stub(() => ({ kind: "response", status: 403, body: null }));
  assert.equal((await setAccess(first.deps, SESSION, { mode: "640", reason: "x" })).outcome, "not_access_admin");
  assert.deepEqual(first.calls.map((call) => call.method), ["GET"]);
});

test("a lost PATCH or reset is outcome_unknown after exactly one write", async () => {
  const patch = stub(() => ({ kind: "lost" }));
  const result = await setAccess(patch.deps, SESSION, { mode: "640", reason: "x", expectedVersion: 1 });
  assert.equal(result.outcome, "outcome_unknown");
  assert.equal(patch.calls.filter((call) => call.method === "PATCH").length, 1);
  assert.equal(patch.calls.length, 1);

  const reset = stub(() => ({ kind: "lost" }));
  assert.equal((await resetAccess(reset.deps, SESSION, { reason: "x", expectedVersion: 1 })).outcome, "outcome_unknown");
  assert.equal(reset.calls.length, 1);

  // A 2xx whose body cannot be read: the write was accepted, the result is unknown.
  const unreadable = stub(() => ok({ nope: true }));
  assert.equal((await setAccess(unreadable.deps, SESSION, { mode: "640", reason: "x", expectedVersion: 1 })).outcome, "outcome_unknown");
});

test("a lost read, a refused token, 5xx and a missing member list are unavailable", async () => {
  assert.equal((await getAccess(stub(() => ({ kind: "lost" })).deps, SESSION)).outcome, "unavailable");
  assert.equal((await accessHistory(stub(() => ({ kind: "lost" })).deps, SESSION)).outcome, "unavailable");
  assert.equal((await getAccess(stub(() => ({ kind: "not_sent" })).deps, SESSION)).outcome, "unavailable");
  assert.equal((await getAccess(stub(() => ({ kind: "response", status: 401, body: null })).deps, SESSION)).outcome, "unavailable");
  assert.equal((await getAccess(stub(() => ({ kind: "response", status: 503, body: null })).deps, SESSION)).outcome, "unavailable");
  const noMembers = stub(() => ok(policyBody(1)), async () => { throw new Error("database down"); });
  assert.equal((await getAccess(noMembers.deps, SESSION)).outcome, "unavailable");
  assert.equal(noMembers.calls.length, 0);
  // A read lost while preparing a write (no version given) sends no PATCH.
  const firstRead = stub(() => ({ kind: "lost" }));
  assert.equal((await setAccess(firstRead.deps, SESSION, { mode: "640", reason: "x" })).outcome, "unavailable");
  assert.deepEqual(firstRead.calls.map((call) => call.method), ["GET"]);
});

test("not configured passes through", async () => {
  const { deps } = stub(() => ({ kind: "not_configured" }));
  assert.equal((await getAccess(deps, SESSION)).outcome, "not_configured");
  assert.equal((await setAccess(deps, SESSION, { mode: "640", reason: "x", expectedVersion: 1 })).outcome, "not_configured");
});

test("reset: reads the version first when none is given", async () => {
  const { deps, calls } = stub((request) => request.method === "GET"
    ? ok(policyBody(6))
    : ok({ runtime: false, reset: true, access: { ...policyBody(7).access, reset: true } }));
  const result = await resetAccess(deps, SESSION, { reason: "back to defaults" });
  assert.ok(result.outcome === "ok");
  assert.equal(result.value.reset, true);
  assert.equal(result.value.runtime, false);
  assert.deepEqual(calls.map((call) => [call.method, call.path]), [
    ["GET", `/v1/sessions/${SESSION}/access`],
    ["POST", `/v1/sessions/${SESSION}/access/reset`],
  ]);
  assert.deepEqual(calls[1]!.body, { expectedVersion: 6, reason: "back to defaults" });
});

test("history: maps actors and grants, passes after and limit, and pages", async () => {
  const { deps, calls } = stub(() => ok({
    rows: [
      {
        seq: 4, at: "2026-01-01T00:00:00.000Z", session_id: SESSION, actor_id: "agent-41", actor_name: "ctl:user-a",
        version: 2, reason: "share",
        before: null,
        after: { mode: "000", gid: 7, acl: [], users: [{ userId: "user-b", perm: "r" }, { userId: "user-gone", perm: "r" }], label: null },
      },
      {
        seq: 5, at: "2026-01-02T00:00:00.000Z", session_id: SESSION, actor_id: "agent-42", actor_name: "ctl:user-gone",
        version: 3, reason: "reset",
        before: { mode: "000", gid: 7, acl: [], users: [{ userId: "user-a", perm: "rw" }, { userId: "user-gone", perm: "r" }], label: null },
        after: { reset: true },
      },
      {
        seq: 6, at: "2026-01-03T00:00:00.000Z", session_id: SESSION, actor_id: "agent-43", actor_name: "gate-operator",
        version: 4, reason: "operator change", before: { reset: true },
        after: { mode: "640", gid: 7, acl: [], users: [], label: null },
      },
    ],
  }));
  const result = await accessHistory(deps, SESSION, { after: 3, limit: 3 });
  assert.ok(result.outcome === "ok");
  assert.equal(result.value.nextAfter, 6);
  const [first, second, third] = result.value.rows;
  // A current member, a former member, and a name that is not a Control person.
  assert.deepEqual([first!.actorId, first!.actorName], ["agent-41", "ctl:user-a"]);
  assert.deepEqual(first!.actor, { userId: "user-a", email: "alpha@example.test", name: "Alpha", member: true });
  assert.deepEqual(second!.actor, { userId: "user-gone", member: false });
  assert.deepEqual([third!.actorName, third!.actor], ["gate-operator", null]);
  // before is null on the first change; before and after users are bare ids
  // resolved like grants.
  assert.equal(first!.before, null);
  assert.deepEqual(first!.after!.members, [
    { userId: "user-b", email: "Beta@Example.test", name: null, perm: "r", member: true },
    { userId: "user-gone", perm: "r", member: false },
  ]);
  assert.deepEqual(second!.before!.members, [
    { userId: "user-a", email: "alpha@example.test", name: "Alpha", perm: "rw", member: true },
    { userId: "user-gone", perm: "r", member: false },
  ]);
  assert.equal(second!.after!.reset, true);
  assert.equal(third!.before!.reset, true);
  assert.equal(calls[0]!.path, `/v1/sessions/${SESSION}/access/history`);
  assert.equal(calls[0]!.query!.get("after"), "3");
  assert.equal(calls[0]!.query!.get("limit"), "3");

  const noActor = stub(() => ok({
    rows: [{ seq: 1, at: "2026-01-01T00:00:00.000Z", version: 1, actor_id: null, actor_name: null, before: null, after: null }],
  }));
  const bare = await accessHistory(noActor.deps, SESSION);
  assert.ok(bare.outcome === "ok");
  assert.deepEqual([bare.value.rows[0]!.actor, bare.value.rows[0]!.before], [null, null]);
  for (const name of ["ctl:", "ctl", "user-a"]) {
    const other = stub(() => ok({ rows: [{ seq: 1, at: "2026-01-01T00:00:00.000Z", version: 1, actor_name: name, before: null }] }));
    const answer = await accessHistory(other.deps, SESSION);
    assert.ok(answer.outcome === "ok");
    assert.equal(answer.value.rows[0]!.actor, null, name);
  }

  const short = stub(() => ok({ rows: [] }));
  const empty = await accessHistory(short.deps, SESSION);
  assert.ok(empty.outcome === "ok");
  assert.equal(empty.value.nextAfter, null);
  assert.equal(short.calls[0]!.query!.get("limit"), "50");
});
