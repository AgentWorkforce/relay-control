import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { NO_FEATURES, type SelectedFeatures } from "../src/features.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { PEOPLE_MAX_UPSTREAM_CALLS } from "../src/usage/people.js";
import { forgetTeamsCache, groupTeamRows, type TeamsRow } from "../src/usage/teams.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * Usage per team (docs/usage.md, "Teams"). Multi tenancy, so one person can
 * belong to two organizations. Assignment windows are written through SQL
 * with explicit timestamps: the app clock is fixed, the database clock is not.
 */

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const HISTORY = "https://history.selfhosted.test";
const READ_API_SECRET = "session-read-secret-".repeat(2);
const NOW = new Date("2026-11-02T20:00:00.000Z");
const TODAY = "2026-11-02";
// days=7 at NOW: the range is 2026-10-27..2026-11-02 and teams resolve at NOW.
const TEAM_AS_OF = NOW.toISOString();
const ON: SelectedFeatures = { ...NO_FEATURES, teams: true, usage_people: true };

type Role = "owner" | "admin" | "member";
type SessionRow = { sessionId: string; workspaceId: string; userIds: string[]; lastTs: string };

/**
 * A read API double: mints one read session per workspace, then serves
 * /v1/sessions for the token's workspace with an offset cursor, the lastTs
 * bounds, the 200 limit and the workspace attestation.
 */
async function startReadApi(t: TestContext) {
  const rows: SessionRow[] = [];
  const reads: Array<{ workspaceId: string; limit: number; cursor: string | null }> = [];
  const tokens = new Map<string, string>();
  const state = { down: false, served: 0, mints: 0 };
  let origin = "";
  const server = createServer(async (incoming, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of incoming) chunks.push(Buffer.from(chunk));
    const raw = Buffer.concat(chunks).toString("utf8");
    const body = raw ? JSON.parse(raw) as Record<string, any> : {};
    const url = new URL(incoming.url!, origin);
    const token = /^Bearer (.+)$/.exec(incoming.headers.authorization ?? "")?.[1];
    response.setHeader("content-type", "application/json");
    const send = (status: number, value: unknown) => {
      response.statusCode = status;
      response.end(JSON.stringify(value));
    };
    if (url.pathname === "/internal/v1/session-read/sessions") {
      if (incoming.method !== "POST" || token !== READ_API_SECRET) {
        send(401, { error: "unauthorized" });
        return;
      }
      state.mints += 1;
      const serial = String(state.mints).padStart(43, "0");
      const accessToken = `rth_at_read_${serial}`;
      tokens.set(accessToken, String(body.workspaceId));
      send(200, {
        sessionId: `read-${state.mints}`,
        userId: body.userId,
        orgId: body.orgId,
        workspaceId: body.workspaceId,
        audience: body.audience,
        scopes: ["rth:read"],
        accessToken,
        accessTokenExpiresAt: new Date(Date.now() + 30 * 60_000).toISOString(),
        refreshToken: `rth_rt_read_${serial}`,
        refreshTokenExpiresAt: new Date(Date.now() + 24 * 3_600_000).toISOString(),
        tokenType: "Bearer",
      });
      return;
    }
    const workspaceId = token ? tokens.get(token) : undefined;
    if (!workspaceId) {
      send(401, { error: { code: "unauthorized" } });
      return;
    }
    const requested = url.searchParams.getAll("workspace");
    if (requested.length !== 1 || requested[0] !== workspaceId) {
      send(403, { error: { code: "forbidden" } });
      return;
    }
    if (url.pathname !== "/v1/sessions") {
      send(404, { error: { code: "not_found" } });
      return;
    }
    const limit = Number(url.searchParams.get("limit"));
    reads.push({ workspaceId, limit, cursor: url.searchParams.get("cursor") });
    if (state.down) {
      send(503, { error: { code: "not_configured" } });
      return;
    }
    response.setHeader("x-relayhistory-workspace-id", workspaceId);
    if (!(limit >= 1 && limit <= 200)) {
      send(501, { error: { code: "unsupported", reason: "limit" } });
      return;
    }
    const after = Date.parse(url.searchParams.get("lastTsAfter")!);
    const before = Date.parse(url.searchParams.get("lastTsBefore")!);
    const offset = Number(url.searchParams.get("cursor") ?? "0");
    const matching = rows
      .filter((row) => row.workspaceId === workspaceId)
      .filter((row) => Date.parse(row.lastTs) >= after && Date.parse(row.lastTs) <= before)
      .sort((a, b) => Date.parse(b.lastTs) - Date.parse(a.lastTs));
    const page = matching.slice(offset, offset + limit);
    state.served += page.length;
    send(200, {
      sessions: page.map((row) => ({
        sessionId: row.sessionId, source: "claude", userIds: row.userIds, projectId: null,
        title: null, firstTs: row.lastTs, lastTs: row.lastTs, agentName: "reviewer",
      })),
      nextCursor: offset + limit < matching.length ? String(offset + limit) : null,
    });
  });
  origin = await listen(server);
  t.after(() => close(server));
  return { origin, rows, reads, state };
}

async function setup(t: TestContext, features: SelectedFeatures = ON) {
  const readApi = await startReadApi(t);
  const database = new PGliteDatabase();
  await migrate(database);
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: origin,
    relaycastUrl: "http://relaycast.invalid",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayhistoryUrl: readApi.origin,
    relayhistoryPublicUrl: HISTORY,
    sessionReadApi: { url: readApi.origin, publicUrl: HISTORY, secret: READ_API_SECRET },
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: null,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${origin}/`,
    port: 0,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, KEYRING, 0, { tenancy: "multi" });
  control.on("request", createApp({ config, store, features, now: () => NOW }));
  t.after(async () => {
    await close(control);
    await database.close();
  });

  const workspace = async (organizationId: string, name: string) => {
    const created = await request(origin, `/api/v1/organizations/${organizationId}/workspaces`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { name, relaycastApiKey: `rk_${name}`, relaycastWorkspaceId: `rw_${name}` },
    });
    assert.equal(created.status, 201, created.raw);
    return created.body.id as string;
  };
  const organization = async (name: string, ownerEmail: string) => {
    const created = await request(origin, "/api/v1/organizations", {
      method: "POST",
      token: BOOTSTRAP,
      body: { name, ownerEmail, ownerName: ownerEmail },
    });
    assert.equal(created.status, 201, created.raw);
    return { id: created.body.id as string, ownerId: created.body.owner.id as string };
  };
  const addMember = async (organizationId: string, email: string, role: Role = "member") => {
    const added = await request(origin, `/api/v1/organizations/${organizationId}/memberships`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { email, name: email, role },
    });
    assert.equal(added.status, 200, added.raw);
    return added.body.userId as string;
  };
  const tokenFor = async (userId: string, workspaceId: string) => {
    const started = await request(origin, "/api/v1/auth/device/start", {
      method: "POST",
      body: { client_name: "usage-teams-test" },
    });
    assert.equal(started.status, 201, started.raw);
    const approved = await request(origin, "/api/v1/auth/device/approve", {
      method: "POST",
      token: BOOTSTRAP,
      body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: workspaceId },
    });
    assert.equal(approved.status, 200, approved.raw);
    const issued = await request(origin, "/api/v1/auth/device/token", {
      method: "POST",
      body: { device_code: started.body.device_code },
    });
    assert.equal(issued.status, 200, issued.raw);
    return issued.body.access_token as string;
  };
  /** Activity counting is fire-and-forget, so each owner's row for today exists up front. */
  const daily = (organizationId: string, userId: string, day: string, searches = 0) => database.query(
    `INSERT INTO usage_people_daily (organization_id, user_id, day, searches, last_active_at)
     VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (organization_id, user_id, day) DO UPDATE SET searches = EXCLUDED.searches`,
    [organizationId, userId, day, searches, `${day}T12:00:00.000Z`],
  );

  const a = await organization("acme", "owner@acme.test");
  const alpha = await workspace(a.id, "alpha");
  const beta = await workspace(a.id, "beta");
  await daily(a.id, a.ownerId, TODAY);
  const owner = await tokenFor(a.ownerId, alpha);

  const team = async (name: string, options: { organizationId?: string; archived?: boolean } = {}) => {
    const id = randomUUID();
    await database.query(
      `INSERT INTO organization_teams (id, organization_id, name, archived_at, created_at, updated_at)
       VALUES ($1, $2, $3, $4, '2026-09-01T00:00:00Z', '2026-09-01T00:00:00Z')`,
      [id, options.organizationId ?? a.id, name, options.archived ? "2026-10-31T00:00:00Z" : null],
    );
    return id;
  };
  const assign = (userId: string, teamId: string, startsAt: string, endsAt: string | null = null, organizationId = a.id) =>
    database.query(
      `INSERT INTO organization_team_assignments (id, organization_id, team_id, user_id, starts_at, ends_at)
       VALUES ($1, $2, $3, $4, $5::timestamptz, $6::timestamptz)`,
      [randomUUID(), organizationId, teamId, userId, startsAt, endsAt],
    );
  const remove = (userId: string, organizationId = a.id) => database.query(
    "DELETE FROM organization_memberships WHERE organization_id = $1 AND user_id = $2",
    [organizationId, userId],
  );
  const report = async (query = "?days=7", token = owner, organizationId = a.id) =>
    request(origin, `/api/v1/organizations/${organizationId}/usage/teams${query}`, { token });
  const auditCount = async () => (await database.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM admin_audit_events WHERE action = 'usage.teams.viewed'",
  )).rows[0]!.n;
  return {
    database, store, origin, config, readApi, a, alpha, beta, owner,
    workspace, organization, addMember, tokenFor, daily, team, assign, remove, report, auditCount,
  };
}

const session = (sessionId: string, workspaceId: string, userIds: string[], lastTs: string): SessionRow =>
  ({ sessionId, workspaceId, userIds, lastTs });

function rowsOf(body: Record<string, any>): TeamsRow[] {
  return body.teams.rows as TeamsRow[];
}

function only<K extends TeamsRow["kind"]>(rows: TeamsRow[], kind: K): Extract<TeamsRow, { kind: K }> {
  const matching = rows.filter((row) => row.kind === kind);
  assert.equal(matching.length, 1, kind);
  return matching[0] as Extract<TeamsRow, { kind: K }>;
}

function teamRow(rows: TeamsRow[], teamId: string): Extract<TeamsRow, { kind: "team" }> | undefined {
  return rows.find((row): row is Extract<TeamsRow, { kind: "team" }> => row.kind === "team" && row.teamId === teamId);
}

function assertSums(body: Record<string, any>) {
  const rows = rowsOf(body);
  const sessions = rows.reduce((sum, row) => sum + (row.sessions ?? 0), 0);
  assert.equal(body.teams.total.sessions, sessions, "rows sum to the session total");
  const searches = rows.reduce((sum, row) => sum + (row.kind === "team" || row.kind === "noTeam" ? row.searches : 0), 0);
  assert.equal(body.teams.total.searches, searches, "rows sum to the search total");
}

test("usage teams: every session lands in exactly one row and the rows sum to the total", async (t) => {
  const env = await setup(t);
  const [m1, m2, m3, m4] = [
    await env.addMember(env.a.id, "m1@acme.test"), await env.addMember(env.a.id, "m2@acme.test"),
    await env.addMember(env.a.id, "m3@acme.test"), await env.addMember(env.a.id, "m4@acme.test"),
  ];
  const platform = await env.team("Platform");
  const infra = await env.team("Infra");
  await env.assign(m1!, platform, "2026-10-01T00:00:00Z");
  await env.assign(m2!, platform, "2026-10-01T00:00:00Z");
  await env.assign(m3!, infra, "2026-10-01T00:00:00Z");
  env.readApi.rows.push(
    session("s1", env.alpha, [m1!], "2026-11-02T10:00:00.000Z"),
    // The same session id in a second workspace counts in that workspace too.
    session("s1", env.beta, [m1!], "2026-11-02T10:00:00.000Z"),
    session("s2", env.alpha, [m3!], "2026-11-01T10:00:00.000Z"),
    // Listed twice for one workspace: counts once.
    session("s2", env.alpha, [m3!], "2026-11-01T10:00:00.000Z"),
    session("s3", env.alpha, [m1!, m2!], "2026-10-31T10:00:00.000Z"),
    session("s4", env.beta, [m2!, m3!], "2026-10-30T10:00:00.000Z"),
    session("s5", env.alpha, [m3!, m4!], "2026-10-29T10:00:00.000Z"),
    session("s6", env.alpha, [], "2026-10-28T10:00:00.000Z"),
    session("s7", env.alpha, [m4!], "2026-10-28T12:00:00.000Z"),
    session("old", env.alpha, [m1!], "2026-09-01T10:00:00.000Z"),
  );

  const result = await env.report();
  assert.equal(result.status, 200, result.raw);
  const teams = result.body.teams;
  assert.deepEqual(teams.range, { days: 7, from: "2026-10-27", to: "2026-11-02" });
  assert.equal(teams.teamAsOf, TEAM_AS_OF);
  assert.equal(teams.source, "sample");
  assert.equal(teams.truncated, false);
  assert.deepEqual(teams.unavailable, ["spend"]);
  const rows = rowsOf(result.body);
  assert.deepEqual(rows[0], {
    kind: "team", teamId: platform, name: "Platform", archived: false, members: 2, activeUsers: 2,
    sessions: 3, searches: 0, lastSessionAt: "2026-11-02T10:00:00.000Z", spend: null,
  });
  assert.deepEqual(rows[1], {
    kind: "team", teamId: infra, name: "Infra", archived: false, members: 1, activeUsers: 1,
    sessions: 1, searches: 0, lastSessionAt: "2026-11-01T10:00:00.000Z", spend: null,
  });
  const cross = rows.filter((row) => row.kind === "crossTeam").map((row) => JSON.stringify(row)).sort();
  assert.deepEqual(cross, [
    { kind: "crossTeam", teamIds: [platform, infra].sort(), sessions: 1, spend: null },
    { kind: "crossTeam", teamIds: [infra, null], sessions: 1, spend: null },
  ].map((row) => JSON.stringify(row)).sort());
  // m4 and the owner: neither has a team.
  assert.deepEqual(rows.slice(-3), [
    { kind: "noTeam", activeUsers: 2, sessions: 1, searches: 0, spend: null },
    { kind: "unattributed", sessions: 1, spend: null },
    { kind: "notResolved", sessions: 0, spend: null },
  ]);
  assert.equal(rows.length, 7);
  assert.deepEqual(teams.total, { sessions: 8, searches: 0 });
  assertSums(result.body);
});

test("usage teams: shared-count and other buckets are not resolved, and the rows still sum (pure)", () => {
  const teams = [{ teamId: "t-1", name: "Platform", archived: false, members: 1 }];
  const teamOf = new Map([["u-1", "t-1"], ["u-gone", "t-unknown"]]);
  const grouped = groupTeamRows({
    buckets: [
      { kind: "users", userIds: ["u-1"], sessions: 3, lastSessionAt: "2026-11-01T00:00:00.000Z" },
      // A team id outside the organization's teams counts as no team.
      { kind: "users", userIds: ["u-gone"], sessions: 1, lastSessionAt: null },
      { kind: "sharedCount", users: 3, sessions: 4 },
      { kind: "other", sessions: 2 },
      { kind: "unattributed", sessions: 1 },
      { kind: "users", userIds: [], sessions: 5, lastSessionAt: null },
    ],
    teamOf,
    teams,
    searches: new Map([["u-1", 2], ["u-none", 1]]),
    currentMembers: new Set(["u-1", "u-gone"]),
  });
  assert.deepEqual(grouped.rows, [
    {
      kind: "team", teamId: "t-1", name: "Platform", archived: false, members: 1, activeUsers: 1,
      sessions: 3, searches: 2, lastSessionAt: "2026-11-01T00:00:00.000Z", spend: null,
    },
    { kind: "noTeam", activeUsers: 1, sessions: 1, searches: 1, spend: null },
    { kind: "unattributed", sessions: 6, spend: null },
    { kind: "notResolved", sessions: 6, spend: null },
  ]);
  assert.deepEqual(grouped.total, { sessions: 16, searches: 3 });

  const unread = groupTeamRows({ buckets: null, teamOf, teams, searches: new Map([["u-1", 2]]) });
  assert.ok(unread.rows.every((row) => row.sessions === null));
  assert.deepEqual(unread.total, { sessions: null, searches: 2 });
});

test("usage teams: an archived team named only by a cross-team row stays listed (pure)", () => {
  const teams = [
    { teamId: "t-live", name: "Platform", archived: false, members: 1 },
    { teamId: "t-old", name: "Old Ops", archived: true, members: 0 },
    { teamId: "t-quiet", name: "Quiet", archived: true, members: 0 },
  ];
  const grouped = groupTeamRows({
    buckets: [{ kind: "users", userIds: ["u-live", "u-old"], sessions: 2, lastSessionAt: "2026-11-01T00:00:00.000Z" }],
    teamOf: new Map([["u-live", "t-live"], ["u-old", "t-old"]]),
    teams,
  });
  const old = grouped.rows.find((row) => row.kind === "team" && row.teamId === "t-old");
  assert.ok(old && old.kind === "team", "the archived team named by a cross row is listed");
  assert.equal(old.sessions, 0);
  assert.deepEqual(grouped.rows.filter((row) => row.kind === "crossTeam"), [
    { kind: "crossTeam", teamIds: ["t-live", "t-old"], sessions: 2, spend: null },
  ]);
  assert.ok(!grouped.rows.some((row) => row.kind === "team" && row.teamId === "t-quiet"),
    "an archived team with no figures and no cross row is absent");
  assert.deepEqual(grouped.total, { sessions: 2, searches: 0 });
});

test("usage teams: moves, removals and later assignments resolve at teamAsOf", async (t) => {
  const env = await setup(t);
  const mover = await env.addMember(env.a.id, "mover@acme.test");
  const leaver = await env.addMember(env.a.id, "leaver@acme.test");
  const edge = await env.addMember(env.a.id, "edge@acme.test");
  const late = await env.addMember(env.a.id, "late@acme.test");
  const gone = await env.addMember(env.a.id, "gone@acme.test");
  const twice = await env.addMember(env.a.id, "twice@acme.test");
  const platform = await env.team("Platform");
  const infra = await env.team("Infra");
  // Moved inside the range: the later team.
  await env.assign(mover, platform, "2026-10-01T00:00:00Z", "2026-10-30T00:00:00Z");
  await env.assign(mover, infra, "2026-10-30T00:00:00Z");
  // Removed inside the range: the team they left.
  await env.assign(leaver, platform, "2026-10-01T00:00:00Z", "2026-10-31T00:00:00Z");
  await env.remove(leaver);
  // A window that ends exactly at teamAsOf still counts.
  await env.assign(edge, platform, "2026-10-01T00:00:00Z", TEAM_AS_OF);
  // Assigned after teamAsOf: no team.
  await env.assign(late, infra, "2026-11-02T21:00:00Z");
  // Left before the range: no team.
  await env.assign(gone, infra, "2026-09-01T00:00:00Z", "2026-10-20T00:00:00Z");
  // Two closed windows in the range and none open: the one that closed last.
  await env.assign(twice, platform, "2026-10-28T00:00:00Z", "2026-10-30T00:00:00Z");
  await env.assign(twice, infra, "2026-10-30T00:00:00Z", "2026-10-31T00:00:00Z");
  env.readApi.rows.push(
    session("twice", env.alpha, [twice], "2026-10-31T10:00:00.000Z"),
    session("mover", env.alpha, [mover], "2026-10-28T10:00:00.000Z"),
    session("leaver", env.alpha, [leaver], "2026-10-29T10:00:00.000Z"),
    session("edge", env.alpha, [edge], "2026-10-30T10:00:00.000Z"),
    session("late", env.alpha, [late], "2026-11-01T10:00:00.000Z"),
    session("gone", env.alpha, [gone], "2026-11-02T10:00:00.000Z"),
  );

  const result = await env.report();
  assert.equal(result.status, 200, result.raw);
  const rows = rowsOf(result.body);
  assert.equal(teamRow(rows, platform)?.sessions, 2);
  assert.equal(teamRow(rows, platform)?.activeUsers, 2);
  assert.equal(teamRow(rows, infra)?.sessions, 2);
  assert.equal(teamRow(rows, infra)?.activeUsers, 2);
  assert.equal(only(rows, "noTeam").sessions, 2);
  assert.equal(rows.filter((row) => row.kind === "crossTeam").length, 0);
  assert.equal(result.body.teams.total.sessions, 6);
  assertSums(result.body);
});

test("usage teams: a read cut short by the call bound is truncated and counts only what was read", async (t) => {
  const env = await setup(t);
  const member = await env.addMember(env.a.id, "busy@acme.test");
  for (let index = 0; index < 700; index += 1) {
    env.readApi.rows.push(session(`busy-${index}`, env.alpha, [member],
      new Date(Date.parse("2026-11-02T19:00:00.000Z") - index * 60_000).toISOString()));
  }
  const result = await env.report();
  assert.equal(result.status, 200, result.raw);
  assert.equal(result.body.teams.truncated, true);
  assert.equal(result.body.teams.source, "sample");
  assert.equal(env.readApi.reads.length, PEOPLE_MAX_UPSTREAM_CALLS);
  assert.ok(env.readApi.reads.every((read) => read.limit >= 1 && read.limit <= 200));
  assert.ok(env.readApi.state.served > 0 && env.readApi.state.served < 700);
  assert.equal(result.body.teams.total.sessions, env.readApi.state.served);
  assert.equal(only(rowsOf(result.body), "noTeam").sessions, env.readApi.state.served);
  assertSums(result.body);
});

test("usage teams: another organization's team and figures never appear", async (t) => {
  const env = await setup(t);
  const shared = await env.addMember(env.a.id, "shared@acme.test");
  const b = await env.organization("globex", "owner@globex.test");
  const gamma = await env.workspace(b.id, "gamma");
  assert.equal(await env.addMember(b.id, "shared@acme.test"), shared, "one person in both organizations");
  const platform = await env.team("Platform");
  const globexTeam = await env.team("Globex Eng", { organizationId: b.id });
  await env.assign(shared, platform, "2026-10-01T00:00:00Z");
  await env.assign(shared, globexTeam, "2026-10-01T00:00:00Z", null, b.id);
  await env.daily(env.a.id, shared, "2026-10-30", 2);
  await env.daily(b.id, shared, "2026-10-30", 50);
  env.readApi.rows.push(
    session("acme-1", env.alpha, [shared], "2026-10-30T10:00:00.000Z"),
    session("globex-1", gamma, [shared], "2026-10-30T11:00:00.000Z"),
  );

  const result = await env.report();
  assert.equal(result.status, 200, result.raw);
  assert.ok(!result.raw.includes(globexTeam), "organization B's team id is absent");
  assert.ok(!result.raw.includes("Globex Eng"), "organization B's team name is absent");
  const rows = rowsOf(result.body);
  assert.deepEqual([teamRow(rows, platform)?.sessions, teamRow(rows, platform)?.searches], [1, 2]);
  assert.deepEqual(result.body.teams.total, { sessions: 1, searches: 2 });
  assert.ok(env.readApi.reads.every((read) => read.workspaceId !== gamma), "organization B's workspace is not read");
  assertSums(result.body);
});

test("usage teams: an archived team shows while it has figures and hides when it has none", async (t) => {
  const env = await setup(t);
  const member = await env.addMember(env.a.id, "ops@acme.test");
  const oldOps = await env.team("Old Ops", { archived: true });
  const retired = await env.team("Retired", { archived: true });
  await env.assign(member, oldOps, "2026-10-01T00:00:00Z", "2026-10-31T00:00:00Z");
  env.readApi.rows.push(session("ops-1", env.alpha, [member], "2026-10-29T10:00:00.000Z"));

  const shown = await env.report();
  assert.equal(shown.status, 200, shown.raw);
  const row = teamRow(rowsOf(shown.body), oldOps);
  assert.ok(row, "the archived team with sessions is listed");
  assert.deepEqual([row.archived, row.sessions, row.members], [true, 1, 0]);
  assert.equal(teamRow(rowsOf(shown.body), retired), undefined);
  assertSums(shown.body);

  env.readApi.rows.length = 0;
  forgetTeamsCache(env.config);
  const hidden = await env.report();
  assert.equal(hidden.status, 200, hidden.raw);
  assert.equal(teamRow(rowsOf(hidden.body), oldOps), undefined);
  assert.equal(teamRow(rowsOf(hidden.body), retired), undefined);
  assertSums(hidden.body);
});

test("usage teams: searches are summed per resolved team, and a search without a team is in noTeam", async (t) => {
  const env = await setup(t);
  const m1 = await env.addMember(env.a.id, "m1@acme.test");
  const m2 = await env.addMember(env.a.id, "m2@acme.test");
  const m3 = await env.addMember(env.a.id, "m3@acme.test");
  const m4 = await env.addMember(env.a.id, "m4@acme.test");
  const left = await env.addMember(env.a.id, "left@acme.test");
  const platform = await env.team("Platform");
  const infra = await env.team("Infra");
  await env.assign(m1, platform, "2026-10-01T00:00:00Z");
  await env.assign(m2, platform, "2026-10-01T00:00:00Z");
  await env.assign(m3, infra, "2026-10-01T00:00:00Z");
  await env.daily(env.a.id, m1, "2026-10-30", 3);
  await env.daily(env.a.id, m2, "2026-11-01", 2);
  await env.daily(env.a.id, m3, "2026-10-28", 4);
  await env.daily(env.a.id, m4, "2026-10-29", 5);
  // Outside the range.
  await env.daily(env.a.id, m1, "2026-10-01", 100);
  // Removed without a team: counted in noTeam searches, not as an active user.
  await env.daily(env.a.id, left, "2026-10-29", 1);
  await env.remove(left);

  const result = await env.report();
  assert.equal(result.status, 200, result.raw);
  const rows = rowsOf(result.body);
  assert.deepEqual([teamRow(rows, platform)?.searches, teamRow(rows, platform)?.activeUsers], [5, 2]);
  assert.deepEqual([teamRow(rows, infra)?.searches, teamRow(rows, infra)?.activeUsers], [4, 1]);
  // m4 and the owner.
  assert.deepEqual(only(rows, "noTeam"), { kind: "noTeam", activeUsers: 2, sessions: 0, searches: 6, spend: null });
  assert.deepEqual(result.body.teams.total, { sessions: 0, searches: 15 });
  assertSums(result.body);
});

test("usage teams: owner only, both features after the role check, and bad parameters", async (t) => {
  const env = await setup(t);
  const adminId = await env.addMember(env.a.id, "admin@acme.test", "admin");
  const memberId = await env.addMember(env.a.id, "member@acme.test");
  const admin = await env.tokenFor(adminId, env.alpha);
  const member = await env.tokenFor(memberId, env.alpha);
  for (const token of [admin, member, BOOTSTRAP]) {
    for (const path of ["?days=7", "/audit"]) {
      const refused = await env.report(path, token);
      assert.equal(refused.status, 403, path);
      assert.equal(refused.body.error, "forbidden", path);
    }
  }
  for (const query of ["?days=14", "?days=7&days=30", "?days=", "?foo=1", "?days=7&cursor=x"]) {
    const refused = await env.report(query);
    assert.equal(refused.status, 400, query);
    assert.equal(refused.body.error, "invalid_request", query);
  }
  assert.equal((await env.report("/audit?days=7")).status, 400);
  assert.equal(await env.auditCount(), 0);
  assert.equal(env.readApi.reads.length, 0);
  for (const days of [7, 30, 90]) assert.equal((await env.report(`?days=${days}`)).status, 200, `days=${days}`);
  assert.equal((await env.report("")).body.teams.range.days, 30, "the default range");

  for (const [features, missing] of [
    [{ ...NO_FEATURES, usage_people: true }, "teams"],
    [{ ...NO_FEATURES, teams: true }, "usage_people"],
  ] as const) {
    const off = await setup(t, features);
    const offMemberId = await off.addMember(off.a.id, "member@acme.test");
    const offMember = await off.tokenFor(offMemberId, off.alpha);
    for (const path of ["?days=7", "/audit"]) {
      const refused = await off.report(path);
      assert.equal(refused.status, 403, `${missing} ${path}`);
      assert.equal(refused.body.error, "feature_not_enabled", `${missing} ${path}`);
      assert.equal(refused.body.feature, missing, `${missing} ${path}`);
      assert.equal((await off.report(path, offMember)).body.error, "forbidden", `${missing} ${path} member`);
    }
    assert.equal(await off.auditCount(), 0);
    assert.equal(off.readApi.reads.length, 0);
  }
});

test("usage teams: an unreachable read API makes sessions unavailable and still serves searches", async (t) => {
  const env = await setup(t);
  const m1 = await env.addMember(env.a.id, "m1@acme.test");
  const platform = await env.team("Platform");
  await env.assign(m1, platform, "2026-10-01T00:00:00Z");
  await env.daily(env.a.id, m1, "2026-10-30", 3);
  env.readApi.state.down = true;

  const result = await env.report();
  assert.equal(result.status, 200, result.raw);
  const teams = result.body.teams;
  assert.equal(teams.source, null);
  assert.equal(teams.truncated, false);
  assert.ok(teams.unavailable.includes("sessions"));
  assert.deepEqual(teams.unavailable, ["sessions", "spend"]);
  assert.equal(teams.total.sessions, null);
  assert.equal(teams.total.searches, 3);
  const rows = rowsOf(result.body);
  assert.ok(rows.every((row) => row.sessions === null));
  assert.deepEqual([teamRow(rows, platform)?.searches, teamRow(rows, platform)?.lastSessionAt], [3, null]);
  assert.ok(env.readApi.reads.length > 0, "the read API was asked");
  assert.equal(await env.auditCount(), 1);
});

test("usage teams: one audit row per served report, listed by the audit route, People audit unchanged", async (t) => {
  const env = await setup(t);
  const member = await env.addMember(env.a.id, "m1@acme.test");
  env.readApi.rows.push(session("s1", env.alpha, [member], "2026-11-01T10:00:00.000Z"));

  const first = await env.report();
  assert.equal(first.status, 200, first.raw);
  const readsAfterFirst = env.readApi.reads.length;
  const second = await env.report();
  assert.equal(second.status, 200, second.raw);
  // The second report is served from the cache and is still audited.
  assert.equal(env.readApi.reads.length, readsAfterFirst);
  assert.deepEqual(second.body.teams.rows, first.body.teams.rows);
  assert.equal(await env.auditCount(), 2);

  const audit = await env.report("/audit");
  assert.equal(audit.status, 200, audit.raw);
  assert.deepEqual(audit.body.events.map((event: any) => ({ ...event, createdAt: undefined })), [
    { viewerUserId: env.a.ownerId, viewerName: "owner@acme.test", days: 7, createdAt: undefined },
    { viewerUserId: env.a.ownerId, viewerName: "owner@acme.test", days: 7, createdAt: undefined },
  ]);
  assert.ok(audit.body.events.every((event: any) => !Number.isNaN(Date.parse(event.createdAt))));
  const { rows: written } = await env.database.query<{ workspace_id: string | null; target: string }>(
    "SELECT workspace_id, target FROM admin_audit_events WHERE action = 'usage.teams.viewed'",
  );
  // Organization-level: not listed by a workspace admin's audit view.
  assert.deepEqual(written, [{ workspace_id: null, target: "days:7" }, { workspace_id: null, target: "days:7" }]);

  const people = await request(env.origin, `/api/v1/organizations/${env.a.id}/usage/people/audit`, { token: env.owner });
  assert.equal(people.status, 200, people.raw);
  assert.deepEqual(people.body.events, []);
});
