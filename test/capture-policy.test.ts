import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { BOOTSTRAP, seedTenant, startControlPlane } from "./flows-helpers.js";

const ORIGIN = "https://control.selfhosted.company";

test("capture policy: member read, owner/admin write, revisions, audit and CSRF", async (t) => {
  const app = await startControlPlane();
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  const accessMe = `/api/v1/workspaces/${tenant.workspaceId}/access/me`;
  const policyPath = `/api/v1/organizations/${tenant.organizationId}/capture-policy`;

  // Unset default: never a defaulted sharing_mode.
  const unset = await app.api(accessMe, { token: tenant.memberToken });
  assert.equal(unset.status, 200);
  assert.deepEqual(unset.body, {
    workspace: { id: tenant.workspaceId, name: "primary" },
    role: "member",
    policy: { version: 1, revision: 1, settings: {} },
  });
  assert.equal(unset.headers.get("cache-control"), "no-store");

  // Bootstrap and anonymous callers are refused on access/me; other workspaces 404.
  assert.equal((await app.api(accessMe, { token: BOOTSTRAP })).status, 401);
  assert.equal((await app.api(accessMe)).status, 401);
  assert.equal((await app.api(accessMe, { token: tenant.otherOwnerToken })).status, 404);

  // Members cannot read or write the org policy.
  assert.equal((await app.api(policyPath, { token: tenant.memberToken })).status, 403);
  const memberPut = await app.api(policyPath, {
    method: "PUT", token: tenant.memberToken, body: { settings: { sharing_mode: "all" } },
  });
  assert.equal(memberPut.status, 403);
  assert.equal((await app.api(policyPath, { method: "DELETE", token: tenant.memberToken })).status, 403);
  // Another organization id is not found.
  assert.equal(
    (await app.api(`/api/v1/organizations/${randomUUID()}/capture-policy`, { token: tenant.ownerToken })).status,
    404,
  );

  // Owner sets; revision increments from the unset revision 1.
  const settings = {
    sharing_mode: "all",
    upload_control: "operator",
    oops_window_seconds: 900,
    user_retroactive_delete: true,
  };
  const set = await app.api(policyPath, { method: "PUT", token: tenant.ownerToken, body: { settings } });
  assert.equal(set.status, 200);
  assert.deepEqual(set.body, { version: 1, revision: 2, settings });
  assert.deepEqual((await app.api(policyPath, { token: tenant.ownerToken })).body, set.body);
  const reflected = await app.api(accessMe, { token: tenant.memberToken });
  assert.deepEqual(reflected.body.policy, set.body);

  const replaced = await app.api(policyPath, {
    method: "PUT", token: tenant.ownerToken, body: { settings: { sharing_mode: "selected" } },
  });
  assert.deepEqual(replaced.body, { version: 1, revision: 3, settings: { sharing_mode: "selected" } });

  const audit = await app.database.query<{ action: string; actor_id: string | null; target: string | null }>(
    `SELECT action, actor_id, target FROM selfhost_admin_audit_events
      WHERE organization_id = $1 AND action LIKE 'capture_policy.%' ORDER BY created_at, target`,
    [tenant.organizationId],
  );
  assert.equal(audit.rows.length, 2);
  assert.equal(audit.rows[0]!.action, "capture_policy.set");
  assert.equal(
    audit.rows[0]!.target,
    `${tenant.organizationId} revision=2 keys=oops_window_seconds,sharing_mode,upload_control,user_retroactive_delete`,
  );
  assert.ok(audit.rows[0]!.actor_id);
  assert.doesNotMatch(audit.rows.map((row) => row.target).join(" "), /operator|900|selected/);

  // Invalid input is refused with the key named; nothing changes.
  for (const [body, pattern] of [
    [{ settings: { sharing_mode: "all", capture_everything: true } }, /capture_everything/],
    [{ settings: { sharing_mode: "everyone" } }, /sharing_mode/],
    [{ settings: { upload_control: "admin" } }, /upload_control/],
    [{ settings: { oops_window_seconds: 86_401 } }, /oops_window_seconds/],
    [{ settings: { oops_window_seconds: 1.5 } }, /oops_window_seconds/],
    [{ settings: { user_retroactive_delete: "yes" } }, /user_retroactive_delete/],
    [{ settings: [] }, /settings/],
    [{}, /settings/],
  ] as const) {
    const refused = await app.api(policyPath, { method: "PUT", token: tenant.ownerToken, body });
    assert.equal(refused.status, 400, JSON.stringify(body));
    assert.equal(refused.body.error, "invalid_policy");
    assert.match(refused.body.message, pattern);
  }
  assert.equal((await app.api(policyPath, { token: tenant.ownerToken })).body.revision, 3);

  // If-Match concurrency.
  const stale = await app.api(policyPath, {
    method: "PUT", token: tenant.ownerToken, headers: { "if-match": "2" }, body: { settings: {} },
  });
  assert.equal(stale.status, 409);
  assert.equal(stale.body.error, "revision_mismatch");
  const fresh = await app.api(policyPath, {
    method: "PUT", token: tenant.ownerToken, headers: { "if-match": '"3"' },
    body: { settings: { upload_control: "user" } },
  });
  assert.equal(fresh.status, 200);
  assert.equal(fresh.body.revision, 4);

  // DELETE resets to empty settings with a higher revision (row kept).
  const cleared = await app.api(policyPath, { method: "DELETE", token: tenant.ownerToken });
  assert.equal(cleared.status, 200);
  assert.deepEqual(cleared.body, { version: 1, revision: 5, settings: {} });
  assert.deepEqual((await app.api(accessMe, { token: tenant.ownerToken })).body.policy, cleared.body);
  const clearedAudit = await app.database.query<{ target: string }>(
    "SELECT target FROM selfhost_admin_audit_events WHERE action = 'capture_policy.cleared'",
  );
  assert.deepEqual(clearedAudit.rows.map((row) => row.target), [`${tenant.organizationId} revision=5`]);

  // /cloud alias with the session cookie: reads work; writes need an allowed origin.
  const cookie = `agent_relay_session=${tenant.ownerToken}`;
  const cloudMe = await app.api(`/cloud${accessMe}`, { headers: { cookie } });
  assert.equal(cloudMe.status, 200);
  assert.equal(cloudMe.body.role, "owner");
  assert.equal((await app.api(`/cloud${policyPath}`, { headers: { cookie } })).status, 200);
  // The cookie is not honoured outside /cloud.
  assert.equal((await app.api(accessMe, { headers: { cookie } })).status, 401);

  const body = { settings: { sharing_mode: "new" } };
  for (const headers of <Record<string, string>[]>[
    { cookie, origin: "https://attacker.example" },
    { cookie },
    { cookie, origin: "null" },
  ]) {
    assert.equal(
      (await app.api(`/cloud${policyPath}`, { method: "PUT", headers, body })).status,
      403,
    );
    assert.equal(
      (await app.api(`/cloud${policyPath}`, { method: "DELETE", headers })).status,
      403,
    );
  }
  const cookiePut = await app.api(`/cloud${policyPath}`, {
    method: "PUT", headers: { cookie, origin: ORIGIN }, body,
  });
  assert.equal(cookiePut.status, 200);
  assert.deepEqual(cookiePut.body, { version: 1, revision: 6, settings: { sharing_mode: "new" } });
  const cookieDelete = await app.api(`/cloud${policyPath}`, {
    method: "DELETE", headers: { cookie, origin: ORIGIN },
  });
  assert.equal(cookieDelete.status, 200);
  assert.equal(cookieDelete.body.revision, 7);
});

test("capture policy: operator upload_control without a window serves the 900 s default", async (t) => {
  const app = await startControlPlane();
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  const policyPath = `/api/v1/organizations/${tenant.organizationId}/capture-policy`;
  const put = await app.api(policyPath, {
    method: "PUT", token: tenant.ownerToken, body: { settings: { upload_control: "operator" } },
  });
  assert.equal(put.status, 200);
  const projected = { upload_control: "operator", oops_window_seconds: 900 };
  assert.deepEqual(put.body.settings, projected);
  assert.deepEqual((await app.api(policyPath, { token: tenant.ownerToken })).body.settings, projected);
  const me = await app.api(`/api/v1/workspaces/${tenant.workspaceId}/access/me`, { token: tenant.memberToken });
  assert.deepEqual(me.body.policy.settings, projected);
  // Storage keeps exactly what was written.
  const stored = await app.database.query<{ settings: unknown }>(
    "SELECT settings FROM selfhost_capture_policies WHERE organization_id = $1",
    [tenant.organizationId],
  );
  assert.deepEqual(stored.rows[0]!.settings, { upload_control: "operator" });
  // An explicit window (including 0) is served as written; user control gets no default.
  for (const settings of [
    { upload_control: "operator", oops_window_seconds: 0 },
    { upload_control: "user" },
    { sharing_mode: "all" },
  ]) {
    const written = await app.api(policyPath, { method: "PUT", token: tenant.ownerToken, body: { settings } });
    assert.deepEqual(written.body.settings, settings);
    assert.deepEqual((await app.api(policyPath, { token: tenant.ownerToken })).body.settings, settings);
  }
});

test("capture policy: SELFHOST_OPERATOR_CONTROLS gates writes only", async (t) => {
  const previous = process.env.SELFHOST_OPERATOR_CONTROLS;
  t.after(() => {
    if (previous === undefined) delete process.env.SELFHOST_OPERATOR_CONTROLS;
    else process.env.SELFHOST_OPERATOR_CONTROLS = previous;
  });
  const { operatorControlsEntitled } = await import("../src/admin/operator-controls.js");
  assert.equal(operatorControlsEntitled({}), true);
  assert.equal(operatorControlsEntitled({ SELFHOST_OPERATOR_CONTROLS: "always" }), true);
  assert.equal(operatorControlsEntitled({ SELFHOST_OPERATOR_CONTROLS: "licence" }), false);
  assert.equal(operatorControlsEntitled({ SELFHOST_OPERATOR_CONTROLS: "off" }), false);

  const app = await startControlPlane();
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  const policyPath = `/api/v1/organizations/${tenant.organizationId}/capture-policy`;
  const accessMe = `/api/v1/workspaces/${tenant.workspaceId}/access/me`;

  delete process.env.SELFHOST_OPERATOR_CONTROLS;
  const entitled = await app.api(policyPath, {
    method: "PUT", token: tenant.ownerToken, body: { settings: { sharing_mode: "new" } },
  });
  assert.equal(entitled.status, 200);

  for (const mode of ["off", "licence"]) {
    process.env.SELFHOST_OPERATOR_CONTROLS = mode;
    const put = await app.api(policyPath, {
      method: "PUT", token: tenant.ownerToken, body: { settings: { sharing_mode: "all" } },
    });
    assert.equal(put.status, 403, mode);
    assert.equal(put.body.error, "operator_controls_not_entitled");
    const del = await app.api(policyPath, { method: "DELETE", token: tenant.ownerToken });
    assert.equal(del.status, 403, mode);
    assert.equal(del.body.error, "operator_controls_not_entitled");
    // Reads are never gated.
    const me = await app.api(accessMe, { token: tenant.memberToken });
    assert.equal(me.status, 200);
    assert.deepEqual(me.body.policy, { version: 1, revision: 2, settings: { sharing_mode: "new" } });
    assert.equal((await app.api(policyPath, { token: tenant.ownerToken })).status, 200);
  }
});
