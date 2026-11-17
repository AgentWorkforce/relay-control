import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createAdminModule } from "../src/admin/routes.js";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { NO_FEATURES, type SelectedFeatures } from "../src/features.js";
import {
  decodeFleetCursor, encodeFleetCursor, FLEET_AUDIT_ACTION, FleetInputError, lockedPersonOnlyKey, policyMatchFor,
} from "../src/fleet/view.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { UNSET_WORKSPACE_POLICY, type WorkspacePolicy } from "../src/workspace-policy.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * Fleet view (docs/fleet.md): owner/admin access, machines from device-client
 * sessions, policyMatch, totals, cursor, usage and the audit row. Same
 * harness as enrollment-key-uses.test.ts.
 */

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const SERVICE = "internal-service-token-that-is-at-least-32-bytes";
const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const HISTORY = "https://history.selfhosted.test";
const EXCHANGE = "/api/v1/auth/enrollment/token";

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");

async function setup(t: TestContext, features: SelectedFeatures = NO_FEATURES) {
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
    introspectSecret: INTROSPECT_SECRET,
    introspectAudiences: [HISTORY],
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: SERVICE,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${origin}/dashboard/`,
    port: 0,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, KEYRING, 0);
  const admin = createAdminModule({ config, database, keyring: KEYRING });
  control.on("request", createApp({ config, store, admin, features }));
  t.after(async () => {
    await close(control);
    await database.close();
  });

  const org = await request(origin, "/api/v1/organizations", {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Acme", ownerEmail: "owner@acme.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const organizationId = org.body.id as string;
  const ownerId = org.body.owner.id as string;
  const created = await request(origin, `/api/v1/organizations/${organizationId}/workspaces`, {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "primary", relaycastApiKey: "rk_primary" },
  });
  assert.equal(created.status, 201);
  const workspaceId = created.body.id as string;

  const deviceToken = async (userId: string) => {
    const started = await request(origin, "/api/v1/auth/device/start", { method: "POST", body: {} });
    const approved = await request(origin, "/api/v1/auth/device/approve", {
      method: "POST",
      token: BOOTSTRAP,
      body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: workspaceId },
    });
    assert.equal(approved.status, 200);
    const issued = await request(origin, "/api/v1/auth/device/token", {
      method: "POST",
      body: { device_code: started.body.device_code },
    });
    assert.equal(issued.status, 200);
    return issued.body.access_token as string;
  };
  const owner = await deviceToken(ownerId);
  const addMember = async (email: string, role: "member" | "admin" = "member") => {
    const added = await request(origin, `/api/v1/organizations/${organizationId}/memberships`, {
      method: "POST",
      token: BOOTSTRAP,
      body: { email, name: email, role },
    });
    assert.equal(added.status, 200);
    return added.body.userId as string;
  };
  const mintKey = async (email: string, extra: Record<string, unknown> = {}) => {
    const answer = await request(origin, `/api/v1/workspaces/${workspaceId}/deployment-api-tokens`, {
      method: "POST",
      token: owner,
      body: { label: "laptop rollout", purpose: "desktop-enrollment", email, ...extra },
    });
    assert.equal(answer.status, 201, `mint ${email}: ${answer.status} ${answer.body?.error ?? ""}`);
    return answer.body as { id: string; accessToken: string } & Record<string, any>;
  };
  const exchange = async (key: string, hostName: string) => {
    const answer = await request(origin, EXCHANGE, {
      method: "POST",
      body: { enrollment_key: key, client_name: "Agent Relay Desktop", desktop_host_name: hostName },
    });
    assert.equal(answer.status, 200, answer.raw);
    return answer.body.access_token as string;
  };
  /** An access/me read as Agent Relay Desktop: records client telemetry. */
  const report = async (token: string, version: string, revision: number) => {
    const read = await request(origin, `/api/v1/workspaces/${workspaceId}/access/me`, {
      token,
      headers: {
        "user-agent": `AgentRelayDesktop/${version} (darwin)`,
        "x-agent-relay-policy-revision": String(revision),
      },
    });
    assert.equal(read.status, 200, read.raw);
  };
  const putPolicy = async (body: Record<string, unknown>) => {
    const put = await request(origin, `/api/v1/organizations/${organizationId}/workspace-policy`, {
      method: "PUT",
      token: BOOTSTRAP,
      body,
    });
    assert.equal(put.status, 200, put.raw);
    return put.body.revision as number;
  };
  const revoke = (token: string) => database.query(
    `UPDATE token_sessions SET revoked_at = now(), revoked_reason = 'test' WHERE access_token_hash = $1`,
    [sha256(token)],
  );
  const fleet = (token: string, query = "") =>
    request(origin, `/api/v1/organizations/${organizationId}/fleet${query}`, { token });
  return {
    database, origin, organizationId, ownerId, workspaceId, owner,
    deviceToken, addMember, mintKey, exchange, report, putPolicy, revoke, fleet,
  };
}

type Machine = Record<string, any>;
const machinesOf = (body: Record<string, any>, email: string): Machine[] =>
  (body.members as Array<Record<string, any>>).find((member) => member.user.email === email)!.machines;

test("policyMatchFor: unknown, current, stale and mismatch", () => {
  const base = { current: 4, managed: false, lockedPersonOnlyKey: false };
  assert.equal(policyMatchFor({ ...base, applied: null }), "unknown");
  assert.equal(policyMatchFor({ ...base, applied: 4 }), "current");
  assert.equal(policyMatchFor({ ...base, applied: 3 }), "stale");
  assert.equal(policyMatchFor({ ...base, applied: 5 }), "stale");
  // A widening person-only value never applies on an unmanaged session.
  assert.equal(policyMatchFor({ ...base, applied: 4, lockedPersonOnlyKey: true }), "mismatch");
  assert.equal(policyMatchFor({ ...base, applied: 3, lockedPersonOnlyKey: true }), "mismatch");
  // Managed sessions apply it, so they keep current/stale.
  assert.equal(policyMatchFor({ ...base, applied: 4, managed: true, lockedPersonOnlyKey: true }), "current");
  assert.equal(policyMatchFor({ ...base, applied: 3, managed: true, lockedPersonOnlyKey: true }), "stale");
  // No report stays unknown, whatever the policy.
  assert.equal(policyMatchFor({ ...base, applied: null, lockedPersonOnlyKey: true }), "unknown");
});

test("lockedPersonOnlyKey: widening locks and defaults on person-only keys only", () => {
  const withSpawn = (spawn: WorkspacePolicy["sections"]["spawn"]): WorkspacePolicy => ({
    ...UNSET_WORKSPACE_POLICY,
    sections: { ...UNSET_WORKSPACE_POLICY.sections, spawn },
  });
  assert.equal(lockedPersonOnlyKey(UNSET_WORKSPACE_POLICY), false);
  assert.equal(lockedPersonOnlyKey(withSpawn({ locked: { accept_spawns: true }, defaults: {} })), true);
  assert.equal(lockedPersonOnlyKey(withSpawn({ locked: {}, defaults: { spawn_native_input: true } })), true);
  assert.equal(lockedPersonOnlyKey(withSpawn({ locked: { spawn_repositories: ["acme/app"] }, defaults: {} })), true);
  // Narrowing values apply everywhere.
  assert.equal(lockedPersonOnlyKey(withSpawn({ locked: { accept_spawns: false }, defaults: {} })), false);
  assert.equal(lockedPersonOnlyKey(withSpawn({ locked: { spawn_repositories: [] }, defaults: {} })), false);
  // Keys that are not person-only never count.
  assert.equal(lockedPersonOnlyKey(withSpawn({ locked: { spawn_max_agents: 4 }, defaults: {} })), false);
});

test("fleet cursor: round trip, and anything malformed is refused", () => {
  const cursor = { email: "ana@acme.test", userId: "6f1c1a52-0d0e-4b8e-9d55-0d8f6f3f1c10" };
  const encoded = encodeFleetCursor(cursor);
  assert.match(encoded, /^[A-Za-z0-9_-]+$/);
  assert.deepEqual(JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")), { after: [cursor.email, cursor.userId] });
  assert.deepEqual(decodeFleetCursor(encoded), cursor);
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
  for (const bad of [
    "",
    "not base64!",
    Buffer.from("not json").toString("base64url"),
    encode(null),
    encode([]),
    encode({}),
    encode({ after: "ana@acme.test" }),
    encode({ after: ["ana@acme.test"] }),
    encode({ after: ["ana@acme.test", ""] }),
    encode({ after: ["ana@acme.test", 7] }),
    encode({ after: ["ana@acme.test", "id"], extra: 1 }),
    "a".repeat(4096),
  ]) {
    assert.throws(() => decodeFleetCursor(bad), FleetInputError, bad.slice(0, 40));
  }
});

test("owners and admins read the fleet; members, the bootstrap bearer and bad queries are refused", async (t) => {
  const env = await setup(t);
  const adminId = await env.addMember("admin@acme.test", "admin");
  const memberId = await env.addMember("member@acme.test");
  const adminToken = await env.deviceToken(adminId);
  const memberToken = await env.deviceToken(memberId);

  const byOwner = await env.fleet(env.owner);
  assert.equal(byOwner.status, 200, byOwner.raw);
  const byAdmin = await env.fleet(adminToken, "?days=7");
  assert.equal(byAdmin.status, 200, byAdmin.raw);
  assert.equal(byAdmin.body.range.days, 7);
  assert.equal(byOwner.body.range.days, 30);
  assert.equal(byOwner.body.policy_revision, 1);
  assert.deepEqual(byOwner.body.members.map((member: any) => member.user.email),
    ["admin@acme.test", "member@acme.test", "owner@acme.test"]);
  assert.deepEqual(byOwner.body.members.map((member: any) => member.role), ["admin", "member", "owner"]);
  assert.equal(byOwner.body.next_cursor, null);

  const refused = await env.fleet(memberToken);
  assert.equal(refused.status, 403);
  assert.equal(refused.body.error, "forbidden");
  assert.equal((await env.fleet(BOOTSTRAP)).status, 403);

  for (const query of ["?limit=5", "?days=14", "?days=7&days=7", "?cursor=!!", "?cursor=a&cursor=b"]) {
    const answer = await env.fleet(env.owner, query);
    assert.equal(answer.status, 400, query);
    assert.equal(answer.body.error, "invalid_request", query);
  }

  // The cursor resumes after the member it names.
  const after = await env.fleet(env.owner, `?cursor=${encodeFleetCursor({ email: "admin@acme.test", userId: adminId })}`);
  assert.equal(after.status, 200, after.raw);
  assert.deepEqual(after.body.members.map((member: any) => member.user.email), ["member@acme.test", "owner@acme.test"]);
  assert.equal(after.body.totals.members, 2);

  // usage_people is off: no usage, and no feature error.
  for (const member of byOwner.body.members) assert.equal(member.usage, null);
  assert.deepEqual(byOwner.body.usage_unavailable, ["usage"]);
  assert.equal(byOwner.body.truncated, false);

  // One audit row per successful read: actor = caller, target = organization.
  const audit = (await env.database.query<{ actor_id: string | null; target: string | null; organization_id: string | null }>(
    `SELECT actor_id, target, organization_id FROM admin_audit_events WHERE action = $1 ORDER BY created_at`,
    [FLEET_AUDIT_ACTION],
  )).rows;
  assert.equal(audit.length, 3);
  assert.deepEqual(audit.map((row) => row.actor_id).sort(), [env.ownerId, adminId, env.ownerId].sort());
  for (const row of audit) {
    assert.equal(row.target, env.organizationId);
    assert.equal(row.organization_id, env.organizationId);
  }
});

test("machines: managed enrollment, policyMatch, revoked sessions and totals", async (t) => {
  const env = await setup(t);
  await env.addMember("member@acme.test");
  const devId = await env.addMember("dev@acme.test");
  const key = await env.mintKey("member@acme.test", { policyConsent: "admin" });
  const managed = await env.exchange(key.accessToken, "build-01");
  const dev = await env.deviceToken(devId);

  // Managed session reports the current revision; the owner's session never reports.
  await env.report(managed, "1.4.2", 1);
  await env.report(dev, "1.3.0", 1);
  let view = await env.fleet(env.owner);
  assert.equal(view.status, 200, view.raw);
  const [enrolled] = machinesOf(view.body, "member@acme.test");
  assert.ok(enrolled);
  assert.equal(enrolled.managed, true);
  assert.equal(enrolled.hostName, "build-01");
  assert.deepEqual(enrolled.enrolledVia, { keyId: key.id, label: "laptop rollout" });
  assert.equal(enrolled.clientVersion, "1.4.2");
  assert.equal(enrolled.platform, "darwin");
  assert.equal(enrolled.policyRevision, 1);
  assert.equal(enrolled.policyMatch, "current");
  assert.equal(enrolled.status, "active");
  assert.ok(!Number.isNaN(Date.parse(enrolled.lastSeenAt)));
  const [own] = machinesOf(view.body, "owner@acme.test");
  assert.ok(own);
  assert.equal(own.policyMatch, "unknown");
  assert.equal(own.policyRevision, null);
  assert.equal(own.managed, false);
  assert.equal(own.enrolledVia, null);
  assert.equal(own.clientVersion, null);
  assert.equal(machinesOf(view.body, "dev@acme.test")[0]!.policyMatch, "current");

  // A narrowing policy write moves the revision: earlier reports are stale.
  assert.equal(await env.putPolicy({ sections: { spawn: { locked: { accept_spawns: false } } } }), 2);
  view = await env.fleet(env.owner);
  assert.equal(view.body.policy_revision, 2);
  assert.equal(machinesOf(view.body, "member@acme.test")[0]!.policyMatch, "stale");
  assert.equal(machinesOf(view.body, "dev@acme.test")[0]!.policyMatch, "stale");
  assert.equal(machinesOf(view.body, "owner@acme.test")[0]!.policyMatch, "unknown");
  await env.report(managed, "1.4.2", 2);
  assert.equal(machinesOf((await env.fleet(env.owner)).body, "member@acme.test")[0]!.policyMatch, "current");

  // A widening lock on a person-only key: unmanaged sessions that report are
  // mismatched, the managed one is not; a revoked session stays listed.
  await env.revoke(dev);
  assert.equal(await env.putPolicy({
    sections: { spawn: { locked: { accept_spawns: true } } },
    consent: ["accept_spawns"],
  }), 3);
  await env.report(env.owner, "1.5.0", 3);
  view = await env.fleet(env.owner);
  const revoked = machinesOf(view.body, "dev@acme.test")[0]!;
  assert.equal(revoked.status, "revoked");
  assert.equal(revoked.policyMatch, "mismatch");
  assert.equal(machinesOf(view.body, "owner@acme.test")[0]!.policyMatch, "mismatch");
  assert.equal(machinesOf(view.body, "member@acme.test")[0]!.policyMatch, "stale");

  assert.deepEqual(view.body.totals, {
    members: 3,
    machines: 3,
    managed: 1,
    policy: { current: 0, stale: 1, unknown: 0, mismatch: 2 },
    clientVersions: [
      { version: "1.3.0", machines: 1 },
      { version: "1.4.2", machines: 1 },
      { version: "1.5.0", machines: 1 },
    ],
  });

  // A session revoked more than 30 days ago is no longer listed.
  await env.database.query(
    `UPDATE token_sessions SET revoked_at = now() - interval '31 days' WHERE access_token_hash = $1`,
    [sha256(dev)],
  );
  view = await env.fleet(env.owner);
  assert.deepEqual(machinesOf(view.body, "dev@acme.test"), []);
  assert.equal(view.body.totals.machines, 2);
});

test("usage_people on: per-member usage, unavailable passed through, people route stays owner-only", async (t) => {
  const env = await setup(t, { ...NO_FEATURES, usage_people: true });
  const adminId = await env.addMember("admin@acme.test", "admin");
  const adminToken = await env.deviceToken(adminId);
  for (const token of [env.owner, adminToken]) {
    const view = await env.fleet(token);
    assert.equal(view.status, 200, view.raw);
    // The read API is unreachable here, so session totals are unavailable.
    assert.deepEqual(view.body.usage_unavailable, ["sessionsUploaded"]);
    for (const member of view.body.members) {
      assert.deepEqual(member.usage, { sessionsUploaded: null, lastSessionAt: null, topProjects: [] });
    }
  }
  const people = await request(env.origin, `/api/v1/organizations/${env.organizationId}/usage/people`, { token: adminToken });
  assert.equal(people.status, 403);
});
