import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import type { ChiefAuthority } from "../src/chief/operations.js";
import { ChiefRegistry, READINESS_CHECKS, type RepositoryCatalog } from "../src/chief/registry.js";
import { BOOTSTRAP, seedTenant, startControlPlane } from "./flows-helpers.js";

const catalog: RepositoryCatalog = {
  connected: true,
  repositories: [
    { id: "1", fullName: "Acme/one" },
    { id: "2", fullName: "Acme/two" },
    { id: "3", fullName: "Acme/three" },
  ],
};
const identities = () => ({
  relayCallerId: "caller-1",
  workers: [{ agentId: "worker-1", address: "worker@machine", actions: ["investigate"] }],
});
const setup = (repositoryIds: string[], requestId: string = randomUUID()) => ({
  requestId,
  repositoryIds,
  region: "us-east-1",
  budgetDollars: 10,
  maxConcurrentTasks: 1,
  allowedActions: ["investigate"],
});
const allChecks = READINESS_CHECKS.map((name) => ({ name, passed: true }));
const SLOT = "slot-aaaaaaaa";
const SLOT_2 = "slot-bbbbbbbb";

async function harness(
  t: test.TestContext,
  options: { authority?: ChiefAuthority; bound?: boolean } = {},
) {
  const app = await startControlPlane({}, undefined, (database) => ({
    registry: new ChiefRegistry({
      database,
      repositories: { list: async () => catalog },
      ...(options.bound === false ? {} : { identities }),
    }),
    ...(options.authority ? { authority: options.authority } : {}),
  }));
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  const route = `/cloud/api/v1/workspaces/${tenant.workspaceId}/chiefs`;
  const operator = (path: string, body?: unknown) =>
    app.api(`/api/v1/operator/${path}`, {
      method: body === undefined ? "GET" : "POST",
      token: BOOTSTRAP,
      ...(body === undefined ? {} : { body }),
    });
  const create = (body: unknown) =>
    app.api(route, { method: "POST", token: tenant.ownerToken, body });
  const slotCount = async (state: string) =>
    (
      await app.database.query<{ count: string }>(
        "SELECT count(*)::text AS count FROM selfhost_chief_slots WHERE state = $1",
        [state],
      )
    ).rows[0]!.count;
  return { app, tenant, route, operator, create, slotCount };
}

async function boundChief(h: Awaited<ReturnType<typeof harness>>) {
  await h.operator("chief-slots", { slotId: SLOT });
  const created = await h.create(setup(["1"]));
  assert.equal(created.status, 202);
  assert.equal(created.body.status, "awaiting_binding");
  const binding = await h.operator(`chief-slots/${SLOT}/binding`);
  const issued = await h.operator(`chiefs/${created.body.id}/service-credential`, {});
  assert.equal(issued.status, 201);
  return { id: created.body.id as string, digest: binding.body.configurationDigest as string, token: issued.body.token as string };
}

test("create without a free slot waits, and a new slot serves the oldest waiting chief", async (t) => {
  const h = await harness(t);
  const first = await h.create(setup(["1"]));
  assert.equal(first.status, 202);
  assert.equal(first.body.status, "awaiting_capacity");
  const second = await h.create(setup(["2"]));
  assert.equal(second.body.status, "awaiting_capacity");

  const registered = await h.operator("chief-slots", { slotId: SLOT });
  assert.equal(registered.status, 201);
  assert.equal(registered.body.chiefId, first.body.id);
  const seen = await h.app.api(`${h.route}/${first.body.id}`, { token: h.tenant.ownerToken });
  assert.equal(seen.body.status, "awaiting_binding");
  const waiting = await h.app.api(`${h.route}/${second.body.id}`, { token: h.tenant.ownerToken });
  assert.equal(waiting.body.status, "awaiting_capacity");
});

test("a retry claims no second slot, and a changed request is refused", async (t) => {
  const h = await harness(t);
  await h.operator("chief-slots", { slotId: SLOT });
  await h.operator("chief-slots", { slotId: SLOT_2 });
  const body = setup(["1"]);
  const first = await h.create(body);
  const retry = await h.create(body);
  assert.equal(retry.status, 202);
  assert.equal(retry.body.id, first.body.id);
  assert.equal(await h.slotCount("assigned"), "1");

  const changed = await h.create({ ...body, budgetDollars: 11 });
  assert.equal(changed.status, 409);
  assert.equal(changed.body.error, "setup_conflict");
  assert.equal(await h.slotCount("assigned"), "1");
});

test("concurrent identical requests produce one chief and one claimed slot", async (t) => {
  const h = await harness(t);
  await h.operator("chief-slots", { slotId: SLOT });
  await h.operator("chief-slots", { slotId: SLOT_2 });
  const body = setup(["1"]);
  const results = await Promise.all([h.create(body), h.create(body), h.create(body)]);
  assert.deepEqual(results.map((r) => r.status), [202, 202, 202]);
  assert.equal(new Set(results.map((r) => r.body.id)).size, 1);
  assert.equal(await h.slotCount("assigned"), "1");
});

test("idempotency is per tenant: the same request ID in another workspace is its own chief", async (t) => {
  const h = await harness(t);
  await h.operator("chief-slots", { slotId: SLOT });
  await h.operator("chief-slots", { slotId: SLOT_2 });
  const body = setup(["1"]);
  const first = await h.create(body);
  const other = await h.app.api(`/cloud/api/v1/workspaces/${h.tenant.otherWorkspaceId}/chiefs`, {
    method: "POST",
    token: h.tenant.otherOwnerToken,
    body,
  });
  assert.equal(other.status, 202);
  assert.notEqual(other.body.id, first.body.id);
  assert.equal(await h.slotCount("assigned"), "2");
  assert.equal(
    (await h.app.api(`${h.route}/${other.body.id}`, { token: h.tenant.ownerToken })).status,
    404,
  );
});

test("an overlapping repository rolls back the chief without consuming a slot", async (t) => {
  const h = await harness(t);
  await h.operator("chief-slots", { slotId: SLOT });
  await h.operator("chief-slots", { slotId: SLOT_2 });
  assert.equal((await h.create(setup(["1", "2"]))).status, 202);
  const overlap = await h.create(setup(["2", "3"]));
  assert.equal(overlap.status, 409);
  assert.equal(overlap.body.error, "project_already_configured");
  assert.equal(await h.slotCount("assigned"), "1");
  const listed = await h.app.api(h.route, { token: h.tenant.ownerToken });
  assert.equal(listed.body.chiefs.length, 1);
});

test("an assigned slot cannot be freed, reassigned or removed", async (t) => {
  const h = await harness(t);
  await boundChief(h);
  await assert.rejects(
    h.app.database.query("UPDATE selfhost_chief_slots SET state = 'free', chief_id = NULL WHERE slot_id = $1", [SLOT]),
    /single-use/,
  );
  await assert.rejects(
    h.app.database.query("DELETE FROM selfhost_chief_slots WHERE slot_id = $1", [SLOT]),
    /single-use/,
  );
  const again = await h.operator("chief-slots", { slotId: SLOT });
  assert.equal(again.status, 200);
  assert.equal(again.body.state, "assigned");
});

test("operator routes refuse tenants, and tenants never see the slot", async (t) => {
  const h = await harness(t);
  const chief = await boundChief(h);
  const paths: [string, string][] = [
    ["POST", "/api/v1/operator/chief-slots"],
    ["GET", `/api/v1/operator/chief-slots/${SLOT}/binding`],
    ["POST", `/api/v1/operator/chiefs/${chief.id}/ready`],
    ["POST", `/api/v1/operator/chiefs/${chief.id}/service-credential`],
  ];
  for (const [method, path] of paths) {
    const body = method === "POST" ? {} : undefined;
    assert.equal((await h.app.api(path, { method, ...(body ? { body } : {}) })).status, 401, path);
    assert.equal(
      (await h.app.api(path, { method, token: h.tenant.ownerToken, ...(body ? { body } : {}) })).status,
      403,
      path,
    );
  }
  const view = await h.app.api(`${h.route}/${chief.id}`, { token: h.tenant.ownerToken });
  assert.equal(view.status, 200);
  assert.ok(!view.text.includes(SLOT));
});

test("the binding carries identifiers and no credential", async (t) => {
  const h = await harness(t);
  const chief = await boundChief(h);
  const binding = await h.operator(`chief-slots/${SLOT}/binding`);
  assert.equal(binding.status, 200);
  assert.equal(binding.body.chiefId, chief.id);
  assert.equal(binding.body.identitiesBound, true);
  assert.deepEqual(binding.body.readinessChecks, [...READINESS_CHECKS]);
  assert.ok(!binding.text.includes(chief.token));
  assert.ok(!/token|secret|password/i.test(JSON.stringify(binding.body.config)));
  assert.equal((await h.operator("chief-slots/slot-missing00/binding")).status, 404);
});

test("ready requires every named check to pass against the exact configuration", async (t) => {
  const h = await harness(t);
  const chief = await boundChief(h);
  const ready = (checks: unknown, configurationDigest = chief.digest) =>
    h.operator(`chiefs/${chief.id}/ready`, { attestedBy: "operator@acme.test", configurationDigest, checks });
  const status = async () =>
    (await h.app.api(`${h.route}/${chief.id}`, { token: h.tenant.ownerToken })).body.status;

  const missing = await ready(allChecks.slice(1));
  assert.equal(missing.status, 409);
  assert.equal(missing.body.error, "readiness_incomplete");
  assert.deepEqual(missing.body.unmet, [READINESS_CHECKS[0]]);

  const failed = await ready(allChecks.map((c, i) => (i === 2 ? { ...c, passed: false } : c)));
  assert.equal(failed.status, 409);
  assert.deepEqual(failed.body.unmet, [READINESS_CHECKS[2]]);

  assert.equal((await ready([{ name: "made_up", passed: true }])).status, 400);
  assert.equal((await ready([...allChecks, allChecks[0]])).status, 400);
  const stale = await ready(allChecks, "0".repeat(64));
  assert.equal(stale.body.error, "configuration_changed");
  assert.equal(await status(), "awaiting_binding");

  const unattested = await h.operator(`chiefs/${chief.id}/ready`, {
    configurationDigest: chief.digest,
    checks: allChecks,
  });
  assert.equal(unattested.status, 400);

  assert.equal((await ready(allChecks)).status, 200);
  assert.equal(await status(), "ready");
  const stored = await h.app.database.query<{ readiness: Record<string, unknown> }>(
    "SELECT readiness FROM selfhost_chiefs WHERE id = $1",
    [chief.id],
  );
  assert.equal(stored.rows[0]!.readiness.source, "operator_attestation");
  assert.equal(stored.rows[0]!.readiness.attestedBy, "operator@acme.test");
});

test("ready is refused without a slot and without real identities", async (t) => {
  const h = await harness(t, { bound: false });
  const waiting = await h.create(setup(["1"]));
  const unslotted = await h.operator(`chiefs/${waiting.body.id}/ready`, {
    attestedBy: "operator@acme.test",
    configurationDigest: "0".repeat(64),
    checks: allChecks,
  });
  assert.equal(unslotted.body.error, "chief_not_bound");

  await h.operator("chief-slots", { slotId: SLOT });
  const binding = await h.operator(`chief-slots/${SLOT}/binding`);
  assert.equal(binding.body.identitiesBound, false);
  const placeholder = await h.operator(`chiefs/${waiting.body.id}/ready`, {
    attestedBy: "operator@acme.test",
    configurationDigest: binding.body.configurationDigest,
    checks: allChecks,
  });
  assert.equal(placeholder.status, 409);
  assert.equal(placeholder.body.error, "chief_identity_unbound");
});

test("service routes fail closed with no authority configured", async (t) => {
  const h = await harness(t);
  const chief = await boundChief(h);
  const base = `/chief/v1/projects/${chief.id}`;
  const evidence = await h.app.api(`${base}/evidence?limit=100`, { token: chief.token });
  assert.equal(evidence.status, 503);
  assert.equal(evidence.body.error, "chief_authority_unavailable");
  const verification = await h.app.api(`${base}/tasks/task-1/verification?sequence=1`, { token: chief.token });
  assert.equal(verification.status, 503);
  assert.equal(verification.body.ok, undefined);
});

test("a service credential is bound to one chief and can be rotated", async (t) => {
  const h = await harness(t);
  await h.operator("chief-slots", { slotId: SLOT });
  await h.operator("chief-slots", { slotId: SLOT_2 });
  const one = await h.create(setup(["1"]));
  const two = await h.create(setup(["2"]));
  const first = (await h.operator(`chiefs/${one.body.id}/service-credential`, {})).body.token as string;
  const path = (id: string) => `/chief/v1/projects/${id}/evidence`;
  assert.equal((await h.app.api(path(one.body.id))).status, 401);
  assert.equal((await h.app.api(path(one.body.id), { token: first })).status, 503);
  assert.equal((await h.app.api(path(two.body.id), { token: first })).status, 401);
  assert.equal((await h.app.api(path(one.body.id), { token: h.tenant.ownerToken })).status, 401);
  assert.equal((await h.app.api(path(one.body.id), { token: BOOTSTRAP })).status, 401);

  const rotated = (await h.operator(`chiefs/${one.body.id}/service-credential`, {})).body.token as string;
  assert.equal((await h.app.api(path(one.body.id), { token: first })).status, 401);
  assert.equal((await h.app.api(path(one.body.id), { token: rotated })).status, 503);
});

test("service routes refuse authority output that is unbound or unproven", async (t) => {
  let evidence: unknown;
  let verification: unknown;
  const h = await harness(t, {
    authority: {
      evidence: async () => evidence,
      verification: async () => verification,
    },
  });
  const chief = await boundChief(h);
  const organizationId = h.tenant.organizationId;
  const workspaceId = h.tenant.workspaceId;
  const evidencePath = `/chief/v1/projects/${chief.id}/evidence`;
  const record = { organizationId, workspaceId, projectId: chief.id, sessionId: "s1" };

  evidence = { cursor: "next", evidence: [record] };
  const good = await h.app.api(evidencePath, { token: chief.token });
  assert.equal(good.status, 200);
  assert.deepEqual(good.body, evidence);

  evidence = { cursor: "next", evidence: [{ ...record, workspaceId: "someone-else" }] };
  assert.equal((await h.app.api(evidencePath, { token: chief.token })).status, 503);
  assert.equal((await h.app.api(`${evidencePath}?limit=101`, { token: chief.token })).status, 400);

  const verify = (sequence: string) =>
    h.app.api(`/chief/v1/projects/${chief.id}/tasks/task-1/verification?sequence=${sequence}`, { token: chief.token });
  const proof = { taskId: "task-1", assignmentDigest: "a".repeat(64), sequence: 3 };

  verification = { ...proof, ok: true, checks: ["acme/one@abc123:ci"] };
  const verified = await verify("3");
  assert.equal(verified.status, 200);
  assert.equal(verified.body.ok, true);

  verification = { ...proof, ok: true, checks: [] };
  assert.equal((await verify("3")).status, 503);
  verification = { ...proof, taskId: "task-2", ok: true, checks: ["x"] };
  assert.equal((await verify("3")).status, 503);
  verification = { ...proof, sequence: 2, ok: true, checks: ["x"] };
  assert.equal((await verify("3")).status, 503);
  assert.equal((await verify("0")).status, 400);
});

test("operator-bound identities raise the revision and unlock ready", async (t) => {
  const h = await harness(t, { bound: false });
  const waiting = await h.create(setup(["1"]));
  const path = `chiefs/${waiting.body.id}/identities`;
  const body = identities();
  assert.equal((await h.operator(path, body)).body.error, "chief_not_bound");
  await h.operator("chief-slots", { slotId: SLOT });
  assert.equal(
    (await h.app.api(`/api/v1/operator/${path}`, { method: "POST", token: h.tenant.ownerToken, body })).status,
    403,
  );

  const invalid = [
    { ...body, relayCallerId: "pending-x" },
    { ...body, relayCallerId: "worker-1" },
    { ...body, workers: [] },
    { ...body, workers: [body.workers[0], body.workers[0]] },
    { ...body, token: "not-accepted" },
  ];
  for (const candidate of invalid) assert.equal((await h.operator(path, candidate)).status, 400);

  const before = await h.operator(`chief-slots/${SLOT}/binding`);
  const bound = await h.operator(path, body);
  assert.equal(bound.status, 200);
  assert.equal(bound.body.revision, 2);
  assert.notEqual(bound.body.configurationDigest, before.body.configurationDigest);
  const repeat = await h.operator(path, body);
  assert.equal(repeat.body.revision, 2);
  assert.equal(repeat.body.configurationDigest, bound.body.configurationDigest);

  const stale = await h.operator(`chiefs/${waiting.body.id}/ready`, {
    attestedBy: "operator@acme.test",
    configurationDigest: before.body.configurationDigest,
    checks: allChecks,
  });
  assert.equal(stale.body.error, "configuration_changed");
  const ready = await h.operator(`chiefs/${waiting.body.id}/ready`, {
    attestedBy: "operator@acme.test",
    configurationDigest: bound.body.configurationDigest,
    checks: allChecks,
  });
  assert.equal(ready.status, 200);

  const changed = await h.operator(path, { ...body, relayCallerId: "caller-2" });
  assert.equal(changed.body.error, "chief_already_ready");
  assert.equal((await h.operator(path, body)).status, 200);
});

test("placement is opaque, and the legacy region alias replays the same request", async (t) => {
  const h = await harness(t);
  await h.operator("chief-slots", { slotId: SLOT });
  await h.operator("chief-slots", { slotId: SLOT_2 });
  const { region, ...rest } = setup(["1"]);
  const created = await h.create({ ...rest, placement: region });
  assert.equal(created.status, 202);
  assert.equal(created.body.placement, region);
  assert.equal(created.body.region, region);

  const alias = await h.create({ ...rest, region });
  assert.equal(alias.status, 202);
  assert.equal(alias.body.id, created.body.id);
  assert.equal(await h.slotCount("assigned"), "1");

  const opaque = await h.create({ ...setup(["2"]), region: undefined, placement: "default" });
  assert.equal(opaque.status, 202);
  assert.equal((await h.create({ ...setup(["3"]), region: undefined, placement: "US EAST" })).status, 400);
  assert.equal((await h.create({ ...setup(["3"]), placement: "default" })).status, 400);
});
