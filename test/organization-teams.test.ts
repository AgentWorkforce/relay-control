import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { NO_FEATURES, type SelectedFeatures } from "../src/features.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * Organization teams (docs/teams.md): the `teams` feature switch, owner/admin
 * access, name rules, archive, assign/move/unassign, member removal, user
 * deletion, two organizations and the audit rows. Multi tenancy, so one
 * person can belong to two organizations.
 */

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const HISTORY = "https://history.selfhosted.test";
const TEAMS_ON: SelectedFeatures = { ...NO_FEATURES, teams: true };

type Role = "owner" | "admin" | "member";

async function setup(t: TestContext, features: SelectedFeatures = TEAMS_ON) {
  const database = new PGliteDatabase();
  await migrate(database);
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: origin,
    relaycastUrl: "http://relaycast.invalid",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: HISTORY,
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: HISTORY, secret: "r".repeat(32) },
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: null,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${origin}/`,
    port: 0,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, KEYRING, 0, { tenancy: "multi" });
  control.on("request", createApp({ config, store, features }));
  t.after(async () => {
    await close(control);
    await database.close();
  });

  const organization = async (name: string, ownerEmail: string) => {
    const created = await request(origin, "/api/v1/organizations", {
      method: "POST",
      token: BOOTSTRAP,
      body: { name, ownerEmail, ownerName: ownerEmail },
    });
    assert.equal(created.status, 201, created.raw);
    const id = created.body.id as string;
    const workspace = await request(origin, `/api/v1/organizations/${id}/workspaces`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { name: `${name}-ws`, relaycastApiKey: `rk_${name}`, relaycastWorkspaceId: `rw_${name}` },
    });
    assert.equal(workspace.status, 201, workspace.raw);
    return { id, ownerId: created.body.owner.id as string, workspaceId: workspace.body.id as string };
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
      body: { client_name: "organization-teams-test" },
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

  const a = await organization("acme", "owner@acme.test");
  const b = await organization("globex", "owner@globex.test");
  const owner = await tokenFor(a.ownerId, a.workspaceId);
  const api = (token: string, method: string, path: string, body?: unknown) =>
    request(origin, `/api/v1/organizations/${a.id}${path}`, { method, token, body });
  const createTeam = async (name: string, organizationId = a.id) => {
    const created = await request(origin, `/api/v1/organizations/${organizationId}/teams`, {
      method: "POST", token: BOOTSTRAP, body: { name },
    });
    assert.equal(created.status, 201, created.raw);
    return created.body as { id: string; name: string };
  };
  /** Every assignment row of one person in one organization, oldest first. */
  const windows = async (userId: string, organizationId = a.id) => (await database.query<{
    team_id: string; open: boolean;
  }>(
    `SELECT team_id, ends_at IS NULL AS open FROM organization_team_assignments
      WHERE organization_id = $1 AND user_id = $2 ORDER BY starts_at, id`,
    [organizationId, userId],
  )).rows;
  /** Moves every open window back an hour, so the next close keeps the row (closed, not deleted). */
  const age = () => database.query(
    "UPDATE organization_team_assignments SET starts_at = starts_at - interval '1 hour' WHERE ends_at IS NULL",
  );
  const teamAudit = async (organizationId = a.id) => (await database.query<{
    action: string; target: string; workspace_id: string | null; actor_kind: string; actor_id: string | null;
  }>(
    `SELECT action, target, workspace_id, actor_kind, actor_id FROM admin_audit_events
      WHERE organization_id = $1 AND action LIKE 'team.%'`,
    [organizationId],
  )).rows;
  return { database, store, origin, a, b, owner, addMember, tokenFor, api, createTeam, windows, age, teamAudit };
}

test("teams off: every route answers 403 feature_not_enabled after the role check, and memberships keep their shape", async (t) => {
  const env = await setup(t, NO_FEATURES);
  const memberId = await env.addMember(env.a.id, "member@acme.test");
  const member = await env.tokenFor(memberId, env.a.workspaceId);
  const someTeam = randomUUID();
  for (const [method, path] of [
    ["GET", "/teams"], ["POST", "/teams"], ["PATCH", `/teams/${someTeam}`], ["DELETE", `/teams/${someTeam}`],
    ["PUT", `/teams/${someTeam}/members/${memberId}`], ["DELETE", `/teams/${someTeam}/members/${memberId}`],
  ] as const) {
    const refused = await env.api(env.owner, method, path, method === "POST" || method === "PATCH" ? { name: "x" } : undefined);
    assert.equal(refused.status, 403, `${method} ${path}`);
    assert.equal(refused.body.error, "feature_not_enabled");
    assert.equal(refused.body.feature, "teams");
    assert.equal((await env.api(member, method, path)).body.error, "forbidden", `${method} ${path} member`);
  }
  const listed = await env.api(env.owner, "GET", "/memberships");
  assert.equal(listed.status, 200);
  for (const item of listed.body.memberships) {
    assert.deepEqual(Object.keys(item).sort(), ["email", "joinedAt", "name", "role", "userId"]);
  }
  const capabilities = await request(env.origin, "/api/v1/capabilities", { token: env.owner });
  assert.equal(capabilities.body.capabilities.teams, false);
});

test("teams on: capabilities report it and memberships carry teamId", async (t) => {
  const env = await setup(t);
  const memberId = await env.addMember(env.a.id, "member@acme.test");
  const team = await env.createTeam("Platform");
  assert.equal((await env.api(env.owner, "PUT", `/teams/${team.id}/members/${memberId}`)).status, 200);
  const capabilities = await request(env.origin, "/api/v1/capabilities", { token: env.owner });
  assert.equal(capabilities.body.capabilities.teams, true);
  const listed = await env.api(env.owner, "GET", "/memberships");
  const byUser = new Map(listed.body.memberships.map((item: { userId: string; teamId: string | null }) => [item.userId, item.teamId]));
  assert.equal(byUser.get(memberId), team.id);
  assert.equal(byUser.get(env.a.ownerId), null);
});

test("teams on: memberships carry teamId for owners, admins and the bootstrap bearer only, never for a member", async (t) => {
  const env = await setup(t);
  const memberId = await env.addMember(env.a.id, "member@acme.test");
  const adminId = await env.addMember(env.a.id, "admin@acme.test", "admin");
  const member = await env.tokenFor(memberId, env.a.workspaceId);
  const admin = await env.tokenFor(adminId, env.a.workspaceId);
  const team = await env.createTeam("Platform");
  assert.equal((await env.api(env.owner, "PUT", `/teams/${team.id}/members/${memberId}`)).status, 200);
  for (const token of [env.owner, admin, BOOTSTRAP]) {
    const listed = await env.api(token, "GET", "/memberships");
    assert.equal(listed.status, 200, listed.raw);
    assert.equal(listed.body.memberships.find((item: { userId: string }) => item.userId === memberId).teamId, team.id);
  }
  const plain = await env.api(member, "GET", "/memberships");
  assert.equal(plain.status, 200, plain.raw);
  assert.equal(plain.body.memberships.length, 3);
  for (const item of plain.body.memberships) {
    assert.deepEqual(Object.keys(item).sort(), ["email", "joinedAt", "name", "role", "userId"]);
  }
});

test("create, list and rename: trimmed names of 1 to 80 characters without control characters, unique among live teams ignoring case", async (t) => {
  const env = await setup(t);
  const created = await env.api(env.owner, "POST", "/teams", { name: "  Platform  " });
  assert.equal(created.status, 201);
  assert.equal(created.body.name, "Platform");
  assert.equal(created.body.memberCount, 0);
  assert.equal(created.body.archivedAt, null);
  assert.equal(typeof created.body.createdAt, "string");
  assert.equal(typeof created.body.updatedAt, "string");
  for (const name of ["", "   ", "x".repeat(81), 7, null, "a\u0000b", "a\u001fb", "a\u007fb"]) {
    const refused = await env.api(env.owner, "POST", "/teams", { name });
    assert.equal(refused.status, 400, JSON.stringify(name));
    assert.equal(refused.body.error, "invalid_request");
  }
  assert.equal((await env.api(env.owner, "POST", "/teams", {})).status, 400);
  assert.equal((await env.api(env.owner, "POST", "/teams", { name: "x".repeat(80) })).status, 201);
  const taken = await env.api(env.owner, "POST", "/teams", { name: "PLATFORM" });
  assert.equal(taken.status, 409);
  assert.equal(taken.body.error, "team_name_taken");
  const other = await env.api(env.owner, "POST", "/teams", { name: "apps" });
  assert.equal(other.status, 201);

  const listed = await env.api(env.owner, "GET", "/teams");
  assert.equal(listed.status, 200);
  assert.deepEqual(listed.body.teams.map((team: { name: string }) => team.name), ["apps", "Platform", "x".repeat(80)]);

  const id = created.body.id as string;
  const conflict = await env.api(env.owner, "PATCH", `/teams/${id}`, { name: "APPS" });
  assert.equal(conflict.status, 409);
  assert.equal(conflict.body.error, "team_name_taken");
  const same = await env.api(env.owner, "PATCH", `/teams/${id}`, { name: " Platform " });
  assert.equal(same.status, 200);
  assert.equal(same.body.updatedAt, created.body.updatedAt);
  const cased = await env.api(env.owner, "PATCH", `/teams/${id}`, { name: "platform" });
  assert.equal(cased.status, 200);
  assert.equal(cased.body.name, "platform");
  assert.equal((await env.api(env.owner, "PATCH", `/teams/${id}`, { name: "" })).status, 400);
  const control = await env.api(env.owner, "PATCH", `/teams/${id}`, { name: "a\u0000b" });
  assert.equal(control.status, 400, control.raw);
  assert.equal(control.body.error, "invalid_request");
  assert.equal((await env.api(env.owner, "PATCH", `/teams/${randomUUID()}`, { name: "Nope" })).body.error, "team_not_found");
  assert.equal((await env.api(env.owner, "PATCH", "/teams/not-a-uuid", { name: "Nope" })).body.error, "team_not_found");
});

test("archive: closes the team's assignments, frees the name, refuses renames and repeats with unassigned 0", async (t) => {
  const env = await setup(t);
  const one = await env.addMember(env.a.id, "one@acme.test");
  const two = await env.addMember(env.a.id, "two@acme.test");
  const team = await env.createTeam("Platform");
  const keep = await env.createTeam("Apps");
  await env.api(env.owner, "PUT", `/teams/${team.id}/members/${one}`);
  await env.api(env.owner, "PUT", `/teams/${team.id}/members/${two}`);
  await env.age();
  assert.equal((await env.api(env.owner, "GET", "/teams")).body.teams.find((row: { id: string }) => row.id === team.id).memberCount, 2);

  const archived = await env.api(env.owner, "DELETE", `/teams/${team.id}`);
  assert.equal(archived.status, 200);
  assert.equal(archived.body.unassigned, 2);
  assert.equal(archived.body.team.memberCount, 0);
  assert.equal(typeof archived.body.team.archivedAt, "string");
  assert.deepEqual(await env.windows(one), [{ team_id: team.id, open: false }]);

  const again = await env.api(env.owner, "DELETE", `/teams/${team.id}`);
  assert.equal(again.status, 200);
  assert.equal(again.body.unassigned, 0);
  assert.equal(again.body.team.archivedAt, archived.body.team.archivedAt);
  assert.equal((await env.api(env.owner, "PATCH", `/teams/${team.id}`, { name: "Other" })).body.error, "team_archived");
  assert.equal((await env.api(env.owner, "PUT", `/teams/${team.id}/members/${one}`)).body.error, "team_archived");
  assert.equal((await env.api(env.owner, "DELETE", `/teams/${randomUUID()}`)).body.error, "team_not_found");

  // The name is free again; archived teams list after the live ones only on request.
  const reused = await env.createTeam("platform");
  assert.deepEqual((await env.api(env.owner, "GET", "/teams")).body.teams.map((row: { id: string }) => row.id), [keep.id, reused.id]);
  const all = await env.api(env.owner, "GET", "/teams?archived=true");
  assert.equal(all.status, 200);
  assert.deepEqual(all.body.teams.map((row: { id: string }) => row.id), [keep.id, reused.id, team.id]);
  for (const query of ["?archived=false", "?archived=1", "?archived=", "?archived=true&archived=true"]) {
    const refused = await env.api(env.owner, "GET", `/teams${query}`);
    assert.equal(refused.status, 400, query);
    assert.equal(refused.body.error, "invalid_request");
  }
});

test("assign and move: one open assignment, the old one closed, previousTeamId, and a repeat writes nothing", async (t) => {
  const env = await setup(t);
  const memberId = await env.addMember(env.a.id, "member@acme.test");
  const platform = await env.createTeam("Platform");
  const apps = await env.createTeam("Apps");

  const first = await env.api(env.owner, "PUT", `/teams/${platform.id}/members/${memberId}`);
  assert.equal(first.status, 200);
  assert.deepEqual(Object.keys(first.body.assignment).sort(), ["startsAt", "teamId", "userId"]);
  assert.equal(first.body.assignment.userId, memberId);
  assert.equal(first.body.assignment.teamId, platform.id);
  assert.equal(first.body.previousTeamId, null);

  const auditBefore = (await env.teamAudit()).length;
  const repeat = await env.api(env.owner, "PUT", `/teams/${platform.id}/members/${memberId}`);
  assert.equal(repeat.status, 200);
  assert.deepEqual(repeat.body, { assignment: first.body.assignment, previousTeamId: platform.id });
  assert.equal((await env.teamAudit()).length, auditBefore);
  assert.deepEqual(await env.windows(memberId), [{ team_id: platform.id, open: true }]);

  await env.age();
  const moved = await env.api(env.owner, "PUT", `/teams/${apps.id}/members/${memberId}`);
  assert.equal(moved.status, 200);
  assert.equal(moved.body.previousTeamId, platform.id);
  assert.equal(moved.body.assignment.teamId, apps.id);
  assert.deepEqual(await env.windows(memberId), [{ team_id: platform.id, open: false }, { team_id: apps.id, open: true }]);
  const bounds = (await env.database.query<{ ok: boolean }>(
    `SELECT bool_and(ends_at IS NULL OR ends_at <= (
              SELECT starts_at FROM organization_team_assignments WHERE user_id = $1 AND ends_at IS NULL)) AS ok
       FROM organization_team_assignments WHERE user_id = $1`,
    [memberId],
  )).rows[0]!;
  assert.equal(bounds.ok, true);

  // An immediate move back still leaves exactly one open window (a window that
  // would close at or before its start is deleted, not closed).
  const back = await env.api(env.owner, "PUT", `/teams/${platform.id}/members/${memberId}`);
  assert.equal(back.status, 200);
  assert.equal(back.body.previousTeamId, apps.id);
  const rows = await env.windows(memberId);
  assert.equal(rows.filter((row) => row.open).length, 1);
  assert.equal(rows.at(-1)!.team_id, platform.id);

  const teams = (await env.api(env.owner, "GET", "/teams")).body.teams as Array<{ id: string; memberCount: number }>;
  assert.equal(teams.find((row) => row.id === platform.id)!.memberCount, 1);
  assert.equal(teams.find((row) => row.id === apps.id)!.memberCount, 0);
});

test("unassign: true once, then false; a different team's unassign is false and writes nothing", async (t) => {
  const env = await setup(t);
  const memberId = await env.addMember(env.a.id, "member@acme.test");
  const platform = await env.createTeam("Platform");
  const apps = await env.createTeam("Apps");
  await env.api(env.owner, "PUT", `/teams/${platform.id}/members/${memberId}`);
  await env.age();
  assert.deepEqual((await env.api(env.owner, "DELETE", `/teams/${apps.id}/members/${memberId}`)).body, { unassigned: false });
  assert.deepEqual((await env.api(env.owner, "DELETE", `/teams/${platform.id}/members/${memberId}`)).body, { unassigned: true });
  assert.deepEqual(await env.windows(memberId), [{ team_id: platform.id, open: false }]);
  assert.deepEqual((await env.api(env.owner, "DELETE", `/teams/${platform.id}/members/${memberId}`)).body, { unassigned: false });
  assert.deepEqual((await env.api(env.owner, "DELETE", `/teams/${platform.id}/members/${randomUUID()}`)).body, { unassigned: false });
  const unknown = await env.api(env.owner, "DELETE", `/teams/${randomUUID()}/members/${memberId}`);
  assert.equal(unknown.status, 404);
  assert.equal(unknown.body.error, "team_not_found");
  const listed = await env.api(env.owner, "GET", "/memberships");
  assert.equal(listed.body.memberships.find((item: { userId: string }) => item.userId === memberId).teamId, null);
});

test("errors: team_not_found before membership_not_found before team_archived; another organization's team or person", async (t) => {
  const env = await setup(t);
  const memberId = await env.addMember(env.a.id, "member@acme.test");
  const outsider = await env.addMember(env.b.id, "outsider@globex.test");
  const team = await env.createTeam("Platform");
  const foreign = await env.createTeam("Platform", env.b.id);

  const expect = async (path: string, status: number, error: string) => {
    const answer = await env.api(env.owner, "PUT", path);
    assert.equal(answer.status, status, path);
    assert.equal(answer.body.error, error, path);
  };
  await expect(`/teams/${randomUUID()}/members/${randomUUID()}`, 404, "team_not_found");
  await expect(`/teams/not-a-uuid/members/${memberId}`, 404, "team_not_found");
  await expect(`/teams/${foreign.id}/members/${memberId}`, 404, "team_not_found");
  await expect(`/teams/${team.id}/members/${outsider}`, 404, "membership_not_found");
  await expect(`/teams/${team.id}/members/not-a-uuid`, 404, "membership_not_found");
  assert.equal((await env.api(env.owner, "PATCH", `/teams/${foreign.id}`, { name: "Mine" })).body.error, "team_not_found");
  assert.equal((await env.api(env.owner, "DELETE", `/teams/${foreign.id}`)).body.error, "team_not_found");
  assert.equal((await env.api(env.owner, "DELETE", `/teams/${foreign.id}/members/${outsider}`)).body.error, "team_not_found");
  await env.api(env.owner, "DELETE", `/teams/${team.id}`);
  await expect(`/teams/${team.id}/members/${outsider}`, 404, "membership_not_found");
  await expect(`/teams/${team.id}/members/${memberId}`, 409, "team_archived");
  // The foreign team is untouched.
  const theirs = await request(env.origin, `/api/v1/organizations/${env.b.id}/teams`, { token: BOOTSTRAP });
  assert.deepEqual(theirs.body.teams.map((row: { id: string; archivedAt: string | null }) => [row.id, row.archivedAt]), [[foreign.id, null]]);
});

test("roles: a member is 403, an admin and the owner manage teams, another organization's token is 404", async (t) => {
  const env = await setup(t);
  const memberId = await env.addMember(env.a.id, "member@acme.test");
  const adminId = await env.addMember(env.a.id, "admin@acme.test", "admin");
  const member = await env.tokenFor(memberId, env.a.workspaceId);
  const admin = await env.tokenFor(adminId, env.a.workspaceId);
  const stranger = await env.tokenFor(env.b.ownerId, env.b.workspaceId);
  const team = await env.createTeam("Platform");

  for (const [method, path] of [
    ["GET", "/teams"], ["POST", "/teams"], ["PATCH", `/teams/${team.id}`], ["DELETE", `/teams/${team.id}`],
    ["PUT", `/teams/${team.id}/members/${memberId}`], ["DELETE", `/teams/${team.id}/members/${memberId}`],
  ] as const) {
    const body = method === "POST" || method === "PATCH" ? { name: "Ops" } : undefined;
    const refused = await env.api(member, method, path, body);
    assert.equal(refused.status, 403, `${method} ${path}`);
    assert.equal(refused.body.error, "forbidden");
    const foreign = await env.api(stranger, method, path, body);
    assert.equal(foreign.status, 404, `${method} ${path} stranger`);
    assert.equal(foreign.body.error, "organization_not_found");
  }
  assert.equal((await env.api(admin, "POST", "/teams", { name: "Ops" })).status, 201);
  assert.equal((await env.api(admin, "PUT", `/teams/${team.id}/members/${memberId}`)).status, 200);
  assert.equal((await env.api(env.owner, "PATCH", `/teams/${team.id}`, { name: "Platform 2" })).status, 200);
  assert.equal((await env.api(admin, "GET", "/teams")).body.teams.length, 2);
  assert.equal((await env.api(env.owner, "DELETE", `/teams/${team.id}/members/${memberId}`)).body.unassigned, true);
});

test("cookie writes: refused without an allowed Origin, and nothing changes; an allowed Origin creates", async (t) => {
  const env = await setup(t);
  const memberId = await env.addMember(env.a.id, "member@acme.test");
  const other = await env.addMember(env.a.id, "other@acme.test");
  const team = await env.createTeam("Platform");
  assert.equal((await env.api(env.owner, "PUT", `/teams/${team.id}/members/${memberId}`)).status, 200);
  await env.age();
  const pair = await env.database.transaction((tx) => env.store.issueBrowserSession(tx, {
    userId: env.a.ownerId, organizationId: env.a.id, workspaceId: env.a.workspaceId, label: "organization-teams-test",
  }));
  const cookie = `agent_relay_session=${pair.accessToken}`;
  const cookiePath = (path: string) => `/cloud/api/v1/organizations/${env.a.id}${path}`;
  const snapshot = async () => ({
    teams: (await env.api(env.owner, "GET", "/teams?archived=true")).body.teams,
    member: await env.windows(memberId),
    other: await env.windows(other),
    audit: (await env.teamAudit()).length,
  });
  const before = await snapshot();

  for (const [method, path, body] of [
    ["POST", "/teams", { name: "Ops" }],
    ["PATCH", `/teams/${team.id}`, { name: "Renamed" }],
    ["PUT", `/teams/${team.id}/members/${other}`, undefined],
    ["DELETE", `/teams/${team.id}/members/${memberId}`, undefined],
    ["DELETE", `/teams/${team.id}`, undefined],
  ] as const) {
    for (const headers of [{ origin: "https://attacker.example" }, {} as Record<string, string>]) {
      const refused = await request(env.origin, cookiePath(path), { method, cookie, headers, body });
      assert.equal(refused.status, 403, `${method} ${path} ${JSON.stringify(headers)}: ${refused.raw}`);
      assert.equal(refused.body.error, "csrf_rejected");
    }
  }
  assert.deepEqual(await snapshot(), before);

  const created = await request(env.origin, cookiePath("/teams"), {
    method: "POST", cookie, headers: { origin: env.origin }, body: { name: "Ops" },
  });
  assert.equal(created.status, 201, created.raw);
  assert.equal(created.body.name, "Ops");
});

test("member removal closes the open assignment with the feature off, keeps the closed rows, and a re-added member has no team", async (t) => {
  const env = await setup(t, NO_FEATURES);
  const memberId = await env.addMember(env.a.id, "member@acme.test");
  const teamId = randomUUID();
  const earlier = randomUUID();
  await env.database.query("INSERT INTO organization_teams (id, organization_id, name) VALUES ($1, $3, 'Platform'), ($2, $3, 'Apps')", [teamId, earlier, env.a.id]);
  await env.database.query(
    `INSERT INTO organization_team_assignments (id, organization_id, team_id, user_id, starts_at, ends_at) VALUES
       ($1, $3, $4, $5, now() - interval '2 hours', now() - interval '1 hour'),
       ($2, $3, $6, $5, now() - interval '1 hour', NULL)`,
    [randomUUID(), randomUUID(), env.a.id, earlier, memberId, teamId],
  );
  const removed = await request(env.origin, `/api/v1/organizations/${env.a.id}/memberships/${memberId}`, { method: "DELETE", token: BOOTSTRAP });
  assert.equal(removed.status, 204, removed.raw);
  assert.deepEqual(await env.windows(memberId), [{ team_id: earlier, open: false }, { team_id: teamId, open: false }]);
  assert.equal(await env.addMember(env.a.id, "member@acme.test"), memberId);
  assert.equal((await env.windows(memberId)).filter((row) => row.open).length, 0);
  // Removal writes no team audit row; membership.remove covers it.
  assert.deepEqual(await env.teamAudit(), []);
});

test("member removal with the feature on: the team's memberCount drops and the memberships list shows no team after re-adding", async (t) => {
  const env = await setup(t);
  const memberId = await env.addMember(env.a.id, "member@acme.test");
  const team = await env.createTeam("Platform");
  await env.api(env.owner, "PUT", `/teams/${team.id}/members/${memberId}`);
  await env.age();
  assert.equal((await env.api(env.owner, "DELETE", `/memberships/${memberId}`)).status, 204);
  assert.equal((await env.api(env.owner, "GET", "/teams")).body.teams[0].memberCount, 0);
  assert.deepEqual(await env.windows(memberId), [{ team_id: team.id, open: false }]);
  await env.addMember(env.a.id, "member@acme.test");
  const listed = await env.api(env.owner, "GET", "/memberships");
  assert.equal(listed.body.memberships.find((item: { userId: string }) => item.userId === memberId).teamId, null);
});

test("deleting the user removes their assignment rows", async (t) => {
  const env = await setup(t);
  const memberId = await env.addMember(env.a.id, "member@acme.test");
  const platform = await env.createTeam("Platform");
  const apps = await env.createTeam("Apps");
  await env.api(env.owner, "PUT", `/teams/${platform.id}/members/${memberId}`);
  await env.age();
  await env.api(env.owner, "PUT", `/teams/${apps.id}/members/${memberId}`);
  assert.equal((await env.windows(memberId)).length, 2);
  await env.database.query("DELETE FROM organization_memberships WHERE user_id = $1", [memberId]);
  await env.database.query("DELETE FROM users WHERE id = $1", [memberId]);
  const left = await env.database.query("SELECT 1 FROM organization_team_assignments WHERE user_id = $1", [memberId]);
  assert.equal(left.rows.length, 0);
});

test("a person in two organizations has an independent team in each", async (t) => {
  const env = await setup(t);
  const both = await env.addMember(env.a.id, "both@acme.test");
  assert.equal(await env.addMember(env.b.id, "both@acme.test"), both);
  const ours = await env.createTeam("Platform");
  const theirs = await env.createTeam("Platform", env.b.id);
  assert.equal((await env.api(env.owner, "PUT", `/teams/${ours.id}/members/${both}`)).status, 200);
  const put = await request(env.origin, `/api/v1/organizations/${env.b.id}/teams/${theirs.id}/members/${both}`, { method: "PUT", token: BOOTSTRAP });
  assert.equal(put.status, 200);
  assert.equal(put.body.previousTeamId, null);
  assert.deepEqual(await env.windows(both, env.a.id), [{ team_id: ours.id, open: true }]);
  assert.deepEqual(await env.windows(both, env.b.id), [{ team_id: theirs.id, open: true }]);
  await env.age();
  assert.equal((await env.api(env.owner, "DELETE", `/teams/${ours.id}/members/${both}`)).body.unassigned, true);
  assert.deepEqual(await env.windows(both, env.b.id), [{ team_id: theirs.id, open: true }]);
  const removed = await request(env.origin, `/api/v1/organizations/${env.b.id}/memberships/${both}`, { method: "DELETE", token: BOOTSTRAP });
  assert.equal(removed.status, 204);
  assert.deepEqual(await env.windows(both, env.a.id), [{ team_id: ours.id, open: false }]);
});

test("audit: one organization-level row per effective change, with ids and no team names", async (t) => {
  const env = await setup(t);
  const memberId = await env.addMember(env.a.id, "member@acme.test");
  const created = await env.api(env.owner, "POST", "/teams", { name: "Secret Project" });
  const id = created.body.id as string;
  const other = (await env.api(env.owner, "POST", "/teams", { name: "Apps" })).body.id as string;
  await env.api(env.owner, "PATCH", `/teams/${id}`, { name: "Secret Project" });
  await env.api(env.owner, "PATCH", `/teams/${id}`, { name: "Renamed Project" });
  await env.api(env.owner, "PUT", `/teams/${id}/members/${memberId}`);
  await env.api(env.owner, "PUT", `/teams/${id}/members/${memberId}`);
  await env.age();
  await env.api(env.owner, "PUT", `/teams/${other}/members/${memberId}`);
  await env.age();
  await env.api(env.owner, "DELETE", `/teams/${id}/members/${memberId}`);
  await env.api(env.owner, "DELETE", `/teams/${other}/members/${memberId}`);
  await env.api(env.owner, "DELETE", `/teams/${other}/members/${memberId}`);
  await env.api(env.owner, "DELETE", `/teams/${id}`);
  await env.api(env.owner, "DELETE", `/teams/${id}`);

  const rows = await env.teamAudit();
  const actual = rows.map((row) => `${row.action} ${row.target}`).sort();
  const expected = [
    `team.create ${id}`,
    `team.create ${other}`,
    `team.rename ${id}`,
    `team.assign ${memberId} team=${id}`,
    `team.assign ${memberId} team=${other}`,
    `team.unassign ${memberId} team=${other}`,
    `team.archive ${id}`,
  ].sort();
  assert.deepEqual(actual, expected);
  for (const row of rows) {
    assert.equal(row.workspace_id, null);
    assert.equal(row.actor_kind, "user");
    assert.equal(row.actor_id, env.a.ownerId);
    assert.doesNotMatch(row.target, /Project|Apps/);
  }
});
