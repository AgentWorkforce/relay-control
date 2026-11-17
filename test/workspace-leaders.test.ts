import assert from "node:assert/strict";
import test from "node:test";
import { request } from "./support/harness.js";
import { BOOTSTRAP, copilotDesktopSetup } from "./support/copilot-desktop.js";
import { MAX_LEADER_PATTERN_LENGTH, MAX_LEADER_PATTERNS } from "../src/workspace-leaders.js";

const leadersPath = (workspaceId: string) => `/api/v1/workspaces/${workspaceId}/leaders`;

test("workspace leaders: members read, owner/admin replace, engine resolves leaders", async (t) => {
  const env = await copilotDesktopSetup(t);
  const path = leadersPath(env.workspaceId);
  const memberId = await env.addMember("member@acme.test");
  const admin = await request(env.origin, `/api/v1/organizations/${env.orgId}/memberships`, {
    method: "POST", token: BOOTSTRAP, body: { email: "admin@acme.test", name: "admin", role: "admin" },
  });
  assert.equal(admin.status, 200, admin.raw);
  const ownerToken = await env.deviceLogin();
  const memberToken = await env.deviceLogin(memberId);
  const adminToken = await env.deviceLogin(admin.body.userId as string);

  // Unset: empty lists, never 404.
  const unset = await request(env.origin, path, { token: memberToken });
  assert.equal(unset.status, 200, unset.raw);
  assert.equal(unset.headers.get("cache-control"), "no-store");
  assert.deepEqual(unset.body, { leaders: [], patterns: [] });
  assert.equal((await request(env.origin, path)).status, 401);
  assert.equal((await request(env.origin, path, { token: BOOTSTRAP })).status, 401);

  const review = env.world.addAgent("reviewgrok");
  const lead = env.world.addAgent("lead");
  env.world.addAgent("Review-helper");

  const put = await request(env.origin, path, {
    method: "PUT", token: ownerToken, body: { patterns: ["*grok", " lead ", "Grok*", "*grok"] },
  });
  assert.equal(put.status, 200, put.raw);
  assert.equal(put.headers.get("cache-control"), "no-store");
  // Trimmed and deduplicated in first-seen order; `Grok*` is case-sensitive and matches nothing.
  assert.deepEqual(put.body.patterns, ["*grok", "lead", "Grok*"]);
  assert.deepEqual(
    [...put.body.leaders].sort((a: { name: string }, b: { name: string }) => a.name.localeCompare(b.name)),
    [{ name: "lead", agent_id: lead.id }, { name: "reviewgrok", agent_id: review.id }],
  );
  assert.deepEqual(env.world.leaderPatterns.get("rk_primary"), ["*grok", "lead", "Grok*"]);
  // Proxied with the workspace key and the normalised list.
  const sent = env.world.bodies.filter((row) => row.method === "PUT" && row.path === "/v1/workspace/leaders");
  assert.deepEqual(sent.map((row) => row.body), [{ patterns: ["*grok", "lead", "Grok*"] }]);

  const read = await request(env.origin, path, { token: memberToken });
  assert.equal(read.status, 200, read.raw);
  assert.deepEqual(read.body, put.body);
  // Another workspace's setting is its own.
  assert.equal(env.world.leaderPatterns.has("rk_other"), false);

  // Members cannot write; admins can.
  const refused = await request(env.origin, path, { method: "PUT", token: memberToken, body: { patterns: ["x"] } });
  assert.equal(refused.status, 403, refused.raw);
  assert.equal(refused.body.error, "forbidden");
  const byAdmin = await request(env.origin, path, { method: "PUT", token: adminToken, body: { patterns: ["lead"] } });
  assert.equal(byAdmin.status, 200, byAdmin.raw);
  assert.deepEqual(byAdmin.body, { leaders: [{ name: "lead", agent_id: lead.id }], patterns: ["lead"] });

  // An empty list clears.
  const cleared = await request(env.origin, path, { method: "PUT", token: ownerToken, body: { patterns: [] } });
  assert.equal(cleared.status, 200, cleared.raw);
  assert.deepEqual(cleared.body, { leaders: [], patterns: [] });
  assert.deepEqual(env.world.leaderPatterns.get("rk_primary"), []);

  const audit = (await env.database.query<{ action: string; actor_id: string | null; target: string | null; workspace_id: string | null }>(
    `SELECT action, actor_id, target, workspace_id FROM admin_audit_events
      WHERE action = 'workspace_leaders.set' ORDER BY created_at`,
  )).rows;
  assert.equal(audit.length, 3);
  assert.equal(audit[0]!.actor_id, env.ownerId);
  assert.equal(audit[0]!.workspace_id, env.workspaceId);
  assert.equal(audit[0]!.target, `${env.workspaceId} patterns=3 ["*grok","lead","Grok*"]`);
  assert.equal(audit[1]!.actor_id, admin.body.userId);
  assert.equal(audit[2]!.target, `${env.workspaceId} patterns=0 []`);
});

test("workspace leaders: invalid patterns are refused before the engine is called", async (t) => {
  const env = await copilotDesktopSetup(t);
  const path = leadersPath(env.workspaceId);
  const ownerToken = await env.deviceLogin();
  const tooMany = Array.from({ length: MAX_LEADER_PATTERNS + 1 }, (_, index) => `agent-${index}`);
  const bodies: unknown[] = [
    { patterns: tooMany },
    { patterns: [""] },
    { patterns: ["   "] },
    { patterns: ["a".repeat(MAX_LEADER_PATTERN_LENGTH + 1)] },
    { patterns: ["lead\u0007"] },
    { patterns: ["le\nad"] },
    { patterns: [42] },
    { patterns: "lead" },
    {},
    { patterns: ["lead"], extra: true },
  ];
  for (const body of bodies) {
    const refused = await request(env.origin, path, { method: "PUT", token: ownerToken, body });
    assert.equal(refused.status, 400, `${JSON.stringify(body).slice(0, 80)} ${refused.raw}`);
    assert.equal(refused.body.error, "invalid_request");
  }
  assert.equal(env.world.bodies.some((row) => row.path === "/v1/workspace/leaders"), false);

  // The limits themselves are accepted.
  const exact = Array.from({ length: MAX_LEADER_PATTERNS }, (_, index) => `${index}`.padEnd(MAX_LEADER_PATTERN_LENGTH, "x"));
  const accepted = await request(env.origin, path, { method: "PUT", token: ownerToken, body: { patterns: exact } });
  assert.equal(accepted.status, 200, accepted.raw);
  assert.equal(accepted.body.patterns.length, MAX_LEADER_PATTERNS);

  // An engine 400 stays a 400.
  env.world.failNext("PUT", "/v1/workspace/leaders", 400, { code: "invalid_request" });
  const engineRefused = await request(env.origin, path, { method: "PUT", token: ownerToken, body: { patterns: ["lead"] } });
  assert.equal(engineRefused.status, 400, engineRefused.raw);
  assert.equal(engineRefused.body.error, "invalid_request");
});

test("workspace leaders: engine failure is a 502, nothing audited", async (t) => {
  const env = await copilotDesktopSetup(t);
  const path = leadersPath(env.workspaceId);
  const ownerToken = await env.deviceLogin();

  env.world.failNext("GET", "/v1/workspace/leaders", 503);
  const read = await request(env.origin, path, { token: ownerToken });
  assert.equal(read.status, 502, read.raw);
  assert.equal(read.body.error, "workspace_leaders_unavailable");

  env.world.failNext("PUT", "/v1/workspace/leaders", 500);
  const write = await request(env.origin, path, { method: "PUT", token: ownerToken, body: { patterns: ["lead"] } });
  assert.equal(write.status, 502, write.raw);
  assert.equal(write.body.error, "workspace_leaders_unavailable");
  assert.equal(env.world.leaderPatterns.has("rk_primary"), false);
  const audit = await env.database.query("SELECT 1 FROM admin_audit_events WHERE action = 'workspace_leaders.set'");
  assert.equal(audit.rows.length, 0);
});

test("workspace leaders: cookie writes need an allowed Origin", async (t) => {
  const env = await copilotDesktopSetup(t);
  const cookiePath = `/cloud${leadersPath(env.workspaceId)}`;
  const cookie = await env.browserSession();

  const read = await request(env.origin, cookiePath, { cookie });
  assert.equal(read.status, 200, read.raw);
  assert.deepEqual(read.body, { leaders: [], patterns: [] });

  for (const headers of [{ origin: "https://attacker.example" }, {} as Record<string, string>]) {
    const refused = await request(env.origin, cookiePath, { method: "PUT", cookie, headers, body: { patterns: ["lead"] } });
    assert.equal(refused.status, 403, refused.raw);
    assert.equal(refused.body.error, "csrf_rejected");
  }
  assert.equal(env.world.leaderPatterns.has("rk_primary"), false);

  const allowed = await request(env.origin, cookiePath, {
    method: "PUT", cookie, headers: { origin: env.origin }, body: { patterns: ["lead"] },
  });
  assert.equal(allowed.status, 200, allowed.raw);
  assert.deepEqual(allowed.body, { leaders: [], patterns: ["lead"] });
});
