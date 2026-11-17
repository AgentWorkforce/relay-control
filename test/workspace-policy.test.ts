import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import test from "node:test";
import { BOOTSTRAP, seedTenant, startControlPlane } from "./flows-helpers.js";
import { request } from "./support/harness.js";
import { copilotDesktopSetup, identitiesPath } from "./support/copilot-desktop.js";
import type { Database } from "../src/database.js";
import { PERSON_ONLY_KEYS } from "../src/workspace-policy.js";

const ORIGIN = "https://control.selfhosted.company";
const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";

const emptySections = () => ({
  capture: { locked: {}, defaults: {} },
  spawn: { locked: {}, defaults: {} },
  join: { locked: {}, defaults: {} },
  delivery: { locked: {}, defaults: {} },
  analytics: { locked: {}, defaults: {} },
});

const unset = (revision = 1) => ({ version: 2, revision, managed: false, consent: [], sections: emptySections() });

async function auditRows(database: Database, organizationId: string) {
  return (await database.query<{ action: string; actor_id: string | null; target: string | null }>(
    `SELECT action, actor_id, target FROM admin_audit_events
      WHERE organization_id = $1 AND action LIKE 'workspace_policy.%' ORDER BY created_at, target`,
    [organizationId],
  )).rows;
}

test("workspace policy: unset shape on access/me, route access", async (t) => {
  const app = await startControlPlane();
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  const accessMe = `/api/v1/workspaces/${tenant.workspaceId}/access/me`;
  const policyPath = `/api/v1/organizations/${tenant.organizationId}/workspace-policy`;

  const me = await app.api(accessMe, { token: tenant.memberToken });
  assert.equal(me.status, 200);
  assert.deepEqual(me.body.workspace_policy, unset());
  // The v1 capture policy is unchanged beside it.
  assert.deepEqual(me.body.policy, { version: 1, revision: 1, settings: {} });
  assert.deepEqual(Object.keys(me.body), ["workspace", "role", "policy", "workspace_policy"]);

  assert.equal((await app.api(accessMe, { token: BOOTSTRAP })).status, 401);
  assert.equal((await app.api(accessMe)).status, 401);

  assert.equal((await app.api(policyPath, { token: tenant.memberToken })).status, 403);
  assert.equal((await app.api(policyPath, {
    method: "PUT", token: tenant.memberToken, body: { sections: {} },
  })).status, 403);
  assert.equal((await app.api(policyPath, { method: "DELETE", token: tenant.memberToken })).status, 403);
  assert.equal(
    (await app.api(`/api/v1/organizations/${randomUUID()}/workspace-policy`, { token: tenant.ownerToken })).status,
    404,
  );

  const owner = await app.api(policyPath, { token: tenant.ownerToken });
  assert.equal(owner.status, 200);
  assert.equal(owner.headers.get("cache-control"), "no-store");
  assert.deepEqual(owner.body, unset());
  assert.deepEqual((await app.api(policyPath, { token: BOOTSTRAP })).body, unset());
});

test("workspace policy: owner PUT with every section populated", async (t) => {
  const app = await startControlPlane();
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  const accessMe = `/api/v1/workspaces/${tenant.workspaceId}/access/me`;
  const policyPath = `/api/v1/organizations/${tenant.organizationId}/workspace-policy`;

  const sections = {
    spawn: {
      locked: {
        spawn_max_agents: 8,
        spawn_billing_claude: "subscription",
        spawn_full_access_codex: false,
      },
      defaults: {
        accept_spawns: true,
        spawn_allow_teammates: false,
        spawn_native_input: true,
        spawn_requester_approvals: true,
        spawn_repositories: ["web", "api"],
        spawn_full_access_claude: false,
        spawn_billing_codex: "api",
      },
    },
    join: {
      locked: { auto_join_repositories: ["Acme/Web", "acme/web", "acme/api", "Acme/*"] },
      defaults: { auto_join_general: true, trust_workspace_members: false },
    },
    delivery: { locked: { trusted_relay_senders: ["lead"] }, defaults: { inbound_default: "deliver" } },
    analytics: { locked: { analytics_enabled: false } },
  };
  const put = await app.api(policyPath, {
    method: "PUT",
    token: tenant.ownerToken,
    body: { sections, consent: ["spawn_requester_approvals", "accept_spawns", "spawn_requester_approvals"] },
  });
  assert.equal(put.status, 200, put.text);
  const expected = {
    version: 2,
    revision: 2,
    managed: false,
    consent: ["accept_spawns", "spawn_requester_approvals"],
    sections: {
      capture: { locked: {}, defaults: {} },
      spawn: sections.spawn,
      join: {
        locked: { auto_join_repositories: ["acme/web", "acme/api", "acme/*"] },
        defaults: sections.join.defaults,
      },
      delivery: sections.delivery,
      analytics: { locked: { analytics_enabled: false }, defaults: {} },
    },
  };
  assert.deepEqual(put.body, expected);
  assert.deepEqual((await app.api(policyPath, { token: tenant.ownerToken })).body, expected);

  // The capture section was empty, so the v1 revision stays 1.
  const me = await app.api(accessMe, { token: tenant.memberToken });
  assert.deepEqual(me.body.policy, { version: 1, revision: 1, settings: {} });
  // inbound_default is set but no admin has a synced identity: an empty list.
  assert.deepEqual(me.body.workspace_policy, {
    ...expected,
    sections: {
      ...expected.sections,
      delivery: { locked: { admin_senders: [], trusted_relay_senders: ["lead"] }, defaults: { inbound_default: "deliver" } },
    },
  });

  const audit = await auditRows(app.database, tenant.organizationId);
  assert.equal(audit.length, 1);
  assert.equal(audit[0]!.action, "workspace_policy.set");
  assert.ok(audit[0]!.actor_id);
  assert.equal(
    audit[0]!.target,
    `${tenant.organizationId} revision=2 keys=`
      + [
        "analytics.analytics_enabled",
        "consent.accept_spawns",
        "consent.spawn_requester_approvals",
        "delivery.inbound_default",
        "delivery.trusted_relay_senders",
        "join.auto_join_general",
        "join.auto_join_repositories",
        "join.trust_workspace_members",
        "spawn.accept_spawns",
        "spawn.spawn_allow_teammates",
        "spawn.spawn_billing_claude",
        "spawn.spawn_billing_codex",
        "spawn.spawn_full_access_claude",
        "spawn.spawn_full_access_codex",
        "spawn.spawn_max_agents",
        "spawn.spawn_native_input",
        "spawn.spawn_repositories",
        "spawn.spawn_requester_approvals",
      ].join(","),
  );
  assert.doesNotMatch(audit[0]!.target!, /subscription|deliver\b|acme|lead\b/);
});

test("workspace policy: capture via v2 and via the capture route, and which counters move", async (t) => {
  const app = await startControlPlane();
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  const policyPath = `/api/v1/organizations/${tenant.organizationId}/workspace-policy`;
  const capturePath = `/api/v1/organizations/${tenant.organizationId}/capture-policy`;

  // Capture through v2: both counters move.
  const v2 = await app.api(policyPath, {
    method: "PUT", token: tenant.ownerToken,
    body: { sections: { capture: { locked: { sharing_mode: "selected", user_retroactive_delete: false } } } },
  });
  assert.equal(v2.status, 200, v2.text);
  assert.equal(v2.body.revision, 2);
  assert.deepEqual(v2.body.sections.capture, { locked: { sharing_mode: "selected", user_retroactive_delete: false }, defaults: {} });
  const capture = await app.api(capturePath, { token: tenant.ownerToken });
  assert.deepEqual(capture.body, { version: 1, revision: 2, settings: { sharing_mode: "selected", user_retroactive_delete: false } });

  // Through the capture route: both move.
  const v1 = await app.api(capturePath, {
    method: "PUT", token: tenant.ownerToken, body: { settings: { upload_control: "operator" } },
  });
  assert.equal(v1.body.revision, 3);
  const afterV1 = await app.api(policyPath, { token: tenant.ownerToken });
  assert.equal(afterV1.body.revision, 3);
  // The capture route's write keeps the other sections and serves the projection.
  assert.deepEqual(afterV1.body.sections.capture, {
    locked: { upload_control: "operator", oops_window_seconds: 900 }, defaults: {},
  });

  // A non-capture write that repeats the stored capture settings moves only v2.
  const spawnOnly = await app.api(policyPath, {
    method: "PUT", token: tenant.ownerToken,
    body: {
      sections: {
        capture: { locked: { upload_control: "operator" } },
        spawn: { locked: { spawn_max_agents: 4 } },
      },
    },
  });
  assert.equal(spawnOnly.status, 200, spawnOnly.text);
  assert.equal(spawnOnly.body.revision, 4);
  assert.equal((await app.api(capturePath, { token: tenant.ownerToken })).body.revision, 3);

  // Omitting the capture section clears it: a capture change, both move.
  const cleared = await app.api(policyPath, {
    method: "PUT", token: tenant.ownerToken, body: { sections: { spawn: { locked: { spawn_max_agents: 4 } } } },
  });
  assert.equal(cleared.body.revision, 5);
  assert.deepEqual(cleared.body.sections.capture, { locked: {}, defaults: {} });
  assert.deepEqual((await app.api(capturePath, { token: tenant.ownerToken })).body, { version: 1, revision: 4, settings: {} });

  // Same again: only v2.
  const repeat = await app.api(policyPath, {
    method: "PUT", token: tenant.ownerToken, body: { sections: { spawn: { locked: { spawn_max_agents: 4 } } } },
  });
  assert.equal(repeat.body.revision, 6);
  assert.equal((await app.api(capturePath, { token: tenant.ownerToken })).body.revision, 4);
});

test("workspace policy: validation", async (t) => {
  const app = await startControlPlane();
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  const policyPath = `/api/v1/organizations/${tenant.organizationId}/workspace-policy`;

  const cases: Array<[unknown, RegExp]> = [
    [{}, /sections/],
    [{ sections: [] }, /sections/],
    [{ sections: {}, extra: 1 }, /Unknown field: extra/],
    [{ sections: { telemetry: {} } }, /Unknown policy section: telemetry/],
    [{ sections: { spawn: { pinned: {} } } }, /Unknown spawn policy tier/],
    [{ sections: { spawn: { locked: { spawn_everything: true } } } }, /spawn_everything/],
    [{ sections: { join: { locked: { accept_spawns: true } } } }, /accept_spawns/],
    [{ sections: { spawn: { locked: { accept_spawns: true }, defaults: { accept_spawns: false } } } }, /not both/],
    [{ sections: { capture: { defaults: { sharing_mode: "all" } } } }, /always locked/],
    [{ sections: { capture: { locked: { sharing_mode: "everyone" } } } }, /sharing_mode/],
    [{ sections: { delivery: { locked: { admin_senders: ["x"] } } } }, /admin_senders is computed by the server/],
    [{ sections: { delivery: { defaults: { admin_senders: ["x"] } } } }, /admin_senders is computed by the server/],
    [{ sections: {}, consent: ["spawn_max_agents"] }, /consent/],
    [{ sections: {}, consent: "accept_spawns" }, /consent/],
    [{ sections: { spawn: { locked: { accept_spawns: "yes" } } } }, /accept_spawns/],
    [{ sections: { spawn: { locked: { spawn_max_agents: 0 } } } }, /spawn_max_agents/],
    [{ sections: { spawn: { locked: { spawn_max_agents: 33 } } } }, /spawn_max_agents/],
    [{ sections: { spawn: { locked: { spawn_max_agents: 2.5 } } } }, /spawn_max_agents/],
    [{ sections: { spawn: { locked: { spawn_billing_claude: "free" } } } }, /spawn_billing_claude/],
    [{ sections: { spawn: { locked: { spawn_repositories: [""] } } } }, /spawn_repositories/],
    [{ sections: { spawn: { locked: { spawn_repositories: ["x".repeat(201)] } } } }, /spawn_repositories/],
    [{ sections: { spawn: { locked: { spawn_repositories: Array.from({ length: 201 }, (_, i) => `r${i}`) } } } }, /spawn_repositories/],
    [{ sections: { join: { locked: { auto_join_repositories: ["no-slash"] } } } }, /auto_join_repositories/],
    [{ sections: { join: { locked: { auto_join_repositories: ["a/b/c"] } } } }, /auto_join_repositories/],
    [{ sections: { join: { locked: { auto_join_repositories: ["*/web"] } } } }, /auto_join_repositories/],
    [{ sections: { join: { locked: { auto_join_repositories: ["acme/*x"] } } } }, /auto_join_repositories/],
    [{ sections: { join: { locked: { auto_join_repositories: ["*"] } } } }, /auto_join_repositories/],
    [{ sections: { delivery: { locked: { inbound_default: "drop" } } } }, /inbound_default/],
    [{ sections: { delivery: { locked: { trusted_relay_senders: [1] } } } }, /trusted_relay_senders/],
    [{ sections: { analytics: { locked: { analytics_enabled: 1 } } } }, /analytics_enabled/],
    [{ sections: { spawn: { locked: { constructor: true } } } }, /constructor/],
  ];
  for (const [body, pattern] of cases) {
    const response = await app.api(policyPath, { method: "PUT", token: tenant.ownerToken, body });
    assert.equal(response.status, 400, JSON.stringify(body));
    assert.equal(response.body.error, "invalid_policy", JSON.stringify(body));
    assert.match(response.body.message, pattern, JSON.stringify(body));
  }
  // Nothing was written.
  assert.deepEqual((await app.api(policyPath, { token: tenant.ownerToken })).body, unset());
  assert.equal((await auditRows(app.database, tenant.organizationId)).length, 0);

  // Every person-only key may be named in consent.
  const consent = await app.api(policyPath, {
    method: "PUT", token: tenant.ownerToken, body: { sections: {}, consent: [...PERSON_ONLY_KEYS].reverse() },
  });
  assert.equal(consent.status, 200, consent.text);
  assert.deepEqual(consent.body.consent, [...PERSON_ONLY_KEYS].sort());
});

test("workspace policy: If-Match, DELETE and monotonic revisions", async (t) => {
  const app = await startControlPlane();
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  const policyPath = `/api/v1/organizations/${tenant.organizationId}/workspace-policy`;
  const body = {
    sections: { capture: { locked: { sharing_mode: "selected" } }, analytics: { locked: { analytics_enabled: true } } },
    consent: ["accept_spawns"],
  };

  const stale = await app.api(policyPath, {
    method: "PUT", token: tenant.ownerToken, body, headers: { "if-match": "7" },
  });
  assert.equal(stale.status, 409);
  assert.equal(stale.body.error, "revision_mismatch");
  assert.equal(stale.body.message, "Workspace policy is at revision 1, not 7");

  const set = await app.api(policyPath, {
    method: "PUT", token: tenant.ownerToken, body, headers: { "if-match": "\"1\"" },
  });
  assert.equal(set.status, 200, set.text);
  assert.equal(set.body.revision, 2);

  // If-Match is the workspace revision, not the capture revision.
  await app.api(policyPath, {
    method: "PUT", token: tenant.ownerToken, body: { ...body, consent: [] }, headers: { "if-match": "2" },
  });
  const capture = await app.api(`/api/v1/organizations/${tenant.organizationId}/capture-policy`, { token: tenant.ownerToken });
  assert.equal(capture.body.revision, 2);
  const mismatch = await app.api(policyPath, {
    method: "PUT", token: tenant.ownerToken, body, headers: { "if-match": "2" },
  });
  assert.equal(mismatch.status, 409);
  assert.equal(mismatch.body.message, "Workspace policy is at revision 3, not 2");

  const staleDelete = await app.api(policyPath, { method: "DELETE", token: tenant.ownerToken, headers: { "if-match": "1" } });
  assert.equal(staleDelete.status, 409);

  const deleted = await app.api(policyPath, { method: "DELETE", token: tenant.ownerToken, headers: { "if-match": "3" } });
  assert.equal(deleted.status, 200, deleted.text);
  assert.deepEqual(deleted.body, unset(4));
  assert.deepEqual((await app.api(policyPath, { token: tenant.ownerToken })).body, unset(4));
  // The capture settings were cleared too, so the capture revision moved.
  assert.deepEqual(
    (await app.api(`/api/v1/organizations/${tenant.organizationId}/capture-policy`, { token: tenant.ownerToken })).body,
    { version: 1, revision: 3, settings: {} },
  );

  // Deleting again still moves the workspace revision forward.
  const again = await app.api(policyPath, { method: "DELETE", token: tenant.ownerToken });
  assert.deepEqual(again.body, unset(5));

  const audit = await auditRows(app.database, tenant.organizationId);
  assert.deepEqual(audit.map((row) => row.action), [
    "workspace_policy.set", "workspace_policy.set", "workspace_policy.cleared", "workspace_policy.cleared",
  ]);
  assert.equal(audit[0]!.target, `${tenant.organizationId} revision=2 keys=analytics.analytics_enabled,capture.sharing_mode,consent.accept_spawns`);
  assert.equal(audit[2]!.target, `${tenant.organizationId} revision=4`);

  // Cookie writes follow the capture policy route's CSRF rules.
  const cookie = `agent_relay_session=${tenant.ownerToken}`;
  const refused = await app.api(`/cloud${policyPath}`, {
    method: "PUT", headers: { cookie, origin: "https://attacker.example" }, body: { sections: {} },
  });
  assert.equal(refused.status, 403);
  assert.equal(refused.body.error, "csrf_rejected");
  const refusedDelete = await app.api(`/cloud${policyPath}`, { method: "DELETE", headers: { cookie } });
  assert.equal(refusedDelete.status, 403);
  const allowed = await app.api(`/cloud${policyPath}`, {
    method: "PUT", headers: { cookie, origin: ORIGIN }, body: { sections: {} },
  });
  assert.equal(allowed.status, 200, allowed.text);
  assert.equal(allowed.body.revision, 6);
});

test("workspace policy: SELFHOST_OPERATOR_CONTROLS gates writes only", async (t) => {
  const previous = process.env.SELFHOST_OPERATOR_CONTROLS;
  t.after(() => {
    if (previous === undefined) delete process.env.SELFHOST_OPERATOR_CONTROLS;
    else process.env.SELFHOST_OPERATOR_CONTROLS = previous;
  });
  const app = await startControlPlane();
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  const policyPath = `/api/v1/organizations/${tenant.organizationId}/workspace-policy`;
  const accessMe = `/api/v1/workspaces/${tenant.workspaceId}/access/me`;

  delete process.env.SELFHOST_OPERATOR_CONTROLS;
  const entitled = await app.api(policyPath, {
    method: "PUT", token: tenant.ownerToken, body: { sections: { analytics: { locked: { analytics_enabled: false } } } },
  });
  assert.equal(entitled.status, 200, entitled.text);

  for (const mode of ["off", "bogus"]) {
    process.env.SELFHOST_OPERATOR_CONTROLS = mode;
    const put = await app.api(policyPath, { method: "PUT", token: tenant.ownerToken, body: { sections: {} } });
    assert.equal(put.status, 403, mode);
    assert.equal(put.body.error, "operator_controls_not_entitled");
    const del = await app.api(policyPath, { method: "DELETE", token: tenant.ownerToken });
    assert.equal(del.status, 403, mode);
    assert.equal(del.body.error, "operator_controls_not_entitled");
    // Reads are never gated.
    const me = await app.api(accessMe, { token: tenant.memberToken });
    assert.equal(me.status, 200);
    assert.deepEqual(me.body.workspace_policy, entitled.body);
    const read = await app.api(policyPath, { token: tenant.ownerToken });
    assert.equal(read.status, 200);
    assert.deepEqual(read.body, entitled.body);
  }
});

test("workspace policy: admin_senders lists owner/admin Desktop identities only, on access/me only", async (t) => {
  const env = await copilotDesktopSetup(t);
  const ownerHash = (userId: string) => createHash("sha256").update(userId).digest("hex");
  const memberId = await env.addMember("member@acme.test");
  const ownerToken = await env.deviceLogin();
  const memberToken = await env.deviceLogin(memberId);
  const sync = async (token: string, userId: string, name: string) => {
    const agent = env.world.addAgent(name, { source: "relay-desktop", owner_hash: ownerHash(userId) });
    const address = `${name}@cloud-${agent.id}`;
    const synced = await request(env.origin, identitiesPath(env.workspaceId), {
      method: "PUT", token,
      body: { source_id: randomUUID(), identities: [{ name, address, agent_id: agent.id, token: agent.token }] },
    });
    assert.equal(synced.status, 200, synced.raw);
    assert.equal(synced.body.synced, 1, synced.raw);
    return address;
  };
  const ownerAddress = await sync(ownerToken, env.ownerId, "lead");
  await sync(memberToken, memberId, "helper");

  const policyPath = `/api/v1/organizations/${env.orgId}/workspace-policy`;
  const accessMe = `/api/v1/workspaces/${env.workspaceId}/access/me`;

  // Without inbound_default the key is absent.
  const plain = await request(env.origin, policyPath, {
    method: "PUT", token: BOOTSTRAP, body: { sections: { delivery: { locked: { trusted_relay_senders: ["x"] } } } },
  });
  assert.equal(plain.status, 200, plain.raw);
  const plainMe = await request(env.origin, accessMe, { token: memberToken });
  assert.equal(plainMe.status, 200, plainMe.raw);
  assert.deepEqual(plainMe.body.workspace_policy.sections.delivery, { locked: { trusted_relay_senders: ["x"] }, defaults: {} });

  const held = await request(env.origin, policyPath, {
    method: "PUT", token: BOOTSTRAP, body: { sections: { delivery: { locked: { inbound_default: "hold" } } } },
  });
  assert.equal(held.status, 200, held.raw);
  // Never on the organization route.
  assert.deepEqual(held.body.sections.delivery, { locked: { inbound_default: "hold" }, defaults: {} });
  assert.deepEqual((await request(env.origin, policyPath, { token: BOOTSTRAP })).body.sections.delivery, {
    locked: { inbound_default: "hold" }, defaults: {},
  });

  const expected = ["lead", ownerAddress].sort();
  for (const token of [memberToken, ownerToken]) {
    const me = await request(env.origin, accessMe, { token });
    assert.equal(me.status, 200, me.raw);
    assert.deepEqual(me.body.workspace_policy.sections.delivery, {
      locked: { admin_senders: expected, inbound_default: "hold" }, defaults: {},
    });
  }

  // A defaults-tier inbound_default serves them too; nothing is stored.
  await request(env.origin, policyPath, {
    method: "PUT", token: BOOTSTRAP, body: { sections: { delivery: { defaults: { inbound_default: "deliver" } } } },
  });
  const defaultsMe = await request(env.origin, accessMe, { token: memberToken });
  assert.deepEqual(defaultsMe.body.workspace_policy.sections.delivery, {
    locked: { admin_senders: expected }, defaults: { inbound_default: "deliver" },
  });
  const stored = await env.database.query<{ workspace_settings: Record<string, any> }>(
    "SELECT workspace_settings FROM capture_policies WHERE organization_id = $1", [env.orgId],
  );
  assert.equal(JSON.stringify(stored.rows[0]!.workspace_settings).includes("admin_senders"), false);

  // Another workspace sees none of this workspace's identities.
  const otherToken = await env.deviceLogin(env.ownerId, env.otherWorkspaceId);
  const otherMe = await request(env.origin, `/api/v1/workspaces/${env.otherWorkspaceId}/access/me`, { token: otherToken });
  assert.deepEqual(otherMe.body.workspace_policy.sections.delivery.locked, { admin_senders: [] });
});

test("workspace policy: introspection carries workspace_policy.revision and managed", async (t) => {
  const app = await startControlPlane({}, undefined, { introspectSecret: INTROSPECT_SECRET });
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  const policyPath = `/api/v1/organizations/${tenant.organizationId}/workspace-policy`;
  const introspect = () => app.api("/internal/v1/auth/introspect", {
    method: "POST",
    token: INTROSPECT_SECRET,
    body: { token: tenant.memberToken, aud: app.config.relayhistoryPublicUrl, workspace: tenant.workspaceId },
  });

  const before = await introspect();
  assert.equal(before.status, 200, before.text);
  assert.equal(before.body.active, true, before.text);
  assert.deepEqual(before.body.workspace_policy, { revision: 1 });
  assert.equal(before.body.managed, false);
  assert.deepEqual(before.body.capture_policy, { version: 1, revision: 1, settings: {} });

  await app.api(policyPath, {
    method: "PUT", token: tenant.ownerToken, body: { sections: { spawn: { locked: { accept_spawns: false } } } },
  });
  const after = await introspect();
  assert.deepEqual(after.body.workspace_policy, { revision: 2 });
  assert.equal(after.body.managed, false);
  // A non-capture write leaves the capture policy where it was.
  assert.equal(after.body.capture_policy.revision, 1);
});
