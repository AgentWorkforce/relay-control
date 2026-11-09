import assert from "node:assert/strict";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createAdminModule } from "../src/admin/routes.js";
import { createApp } from "../src/app.js";
import type { ChiefBackend } from "../src/chief/routes.js";
import { gateCredentialVerifier, loadSelectedFeatures, NO_FEATURES, type SelectedFeatures } from "../src/features.js";
import { apiClient, BOOTSTRAP, close, listen, seedTenant, startControlPlane } from "./flows-helpers.js";
import { testFeatures } from "./support/features.js";

const chiefBackend: ChiefBackend = {
  list: () => ({ chiefs: [] }),
  get: () => ({ id: "chief-1" }),
  create: () => ({ id: "chief-1" }),
  scan: () => ({ id: "chief-1" }),
  repositories: () => ({ repositories: [] }),
};

async function plane(t: TestContext, features: SelectedFeatures, chief?: ChiefBackend) {
  const cp = await startControlPlane({}, chief, {}, features);
  t.after(() => cp.stop());
  return { ...cp, tenant: await seedTenant(cp.api) };
}

/** A second app over the same database with a different selection (as after a restart). */
async function restartWith(t: TestContext, cp: Awaited<ReturnType<typeof plane>>, features: SelectedFeatures) {
  const admin = createAdminModule({
    config: cp.config,
    database: cp.database,
    keyring: cp.config.encryptionKeyring,
    runtimeCredentialVerifier: gateCredentialVerifier((token: string) => cp.flows.verifyRuntimeCredential(token), features, "flows"),
  });
  const server = createServer(createApp({ config: cp.config, store: cp.store, flows: cp.flows, admin, features }));
  const api = apiClient(await listen(server));
  t.after(() => close(server));
  return api;
}

test("SELFHOST_FEATURES: parsing, empty selects nothing, unknown names stop startup", () => {
  assert.deepEqual(loadSelectedFeatures({}), NO_FEATURES);
  assert.deepEqual(loadSelectedFeatures({ SELFHOST_FEATURES: "" }), NO_FEATURES);
  assert.deepEqual(loadSelectedFeatures({ SELFHOST_FEATURES: " Flows , ,chief," }), { flows: true, relayfile: false, chief: true });
  assert.throws(() => loadSelectedFeatures({ SELFHOST_FEATURES: "flows,teleport" }), /unknown feature "teleport"/);
});

test("GET /api/v1/capabilities: exact shape, any member, cookie alias, 401 without a user token", async (t) => {
  const cp = await plane(t, testFeatures("flows,chief"));
  assert.equal((await cp.api("/api/v1/capabilities")).status, 401);
  assert.equal((await cp.api("/api/v1/capabilities", { token: "not-a-token" })).status, 401);
  assert.equal((await cp.api("/api/v1/capabilities", { token: BOOTSTRAP })).status, 401, "bootstrap token is not a member");

  const read = await cp.api("/api/v1/capabilities", { token: cp.tenant.memberToken });
  assert.equal(read.status, 200);
  assert.equal(read.headers.get("cache-control"), "no-store");
  assert.deepEqual(read.body, { capabilities: { flows: true, relayfile: false, chief: true } });

  const cookie = await cp.api("/cloud/api/v1/capabilities", {
    headers: { cookie: `agent_relay_session=${cp.tenant.ownerToken}` },
  });
  assert.equal(cookie.status, 200);
  assert.deepEqual(cookie.body, read.body);
  assert.equal((await cp.api("/api/v1/capabilities", { headers: { cookie: `agent_relay_session=${cp.tenant.ownerToken}` } })).status, 401,
    "the session cookie is scoped to /cloud");
});

test("the licence read is gone", async (t) => {
  const cp = await plane(t, testFeatures());
  assert.equal((await cp.api("/api/v1/license", { token: cp.tenant.memberToken })).status, 404);
});

test("flows selected: Flows routes serve", async (t) => {
  const cp = await plane(t, testFeatures("flows"));
  assert.equal((await cp.api("/api/v1/flows", { token: cp.tenant.memberToken })).status, 200);
  const enrollment = await cp.api("/api/v1/workers/enrollment-tokens", {
    method: "POST", token: cp.tenant.ownerToken, body: { name: "w1" },
  });
  assert.equal(enrollment.status, 200);
});

test("flows not selected: 403 feature_not_enabled", async (t) => {
  const cp = await plane(t, testFeatures("relayfile"));
  const refused = await cp.api("/api/v1/flows", { token: cp.tenant.memberToken });
  assert.equal(refused.status, 403);
  assert.deepEqual(refused.body, {
    error: "feature_not_enabled",
    message: "Flows is not enabled on this installation.",
    feature: "flows",
  });
  assert.equal((await cp.api("/cloud/api/v1/workflows/runs", { token: cp.tenant.memberToken })).body.error, "feature_not_enabled");
});

test("Chief: unselected -> feature_not_enabled; selected without a backend -> 503; with one -> served", async (t) => {
  const off = await plane(t, testFeatures("flows"), chiefBackend);
  const route = `/api/v1/workspaces/${off.tenant.workspaceId}/chiefs`;
  const refused = await off.api(route, { token: off.tenant.memberToken });
  assert.equal(refused.status, 403);
  assert.deepEqual(refused.body, {
    error: "feature_not_enabled",
    message: "Chief is not enabled on this installation.",
    feature: "chief",
  });
  assert.equal((await off.api(`${route}/chief-1/scan`, { method: "POST", token: off.tenant.ownerToken })).body.error,
    "feature_not_enabled");

  const noBackend = await plane(t, testFeatures("chief"));
  const unavailable = await noBackend.api(`/api/v1/workspaces/${noBackend.tenant.workspaceId}/chiefs`, {
    token: noBackend.tenant.memberToken,
  });
  assert.equal(unavailable.status, 503);
  assert.equal(unavailable.body.error, "chief_unavailable");

  const served = await plane(t, testFeatures("chief"), chiefBackend);
  assert.equal((await served.api(`/api/v1/workspaces/${served.tenant.workspaceId}/chiefs`, {
    token: served.tenant.memberToken,
  })).status, 200);
});

test("membership checks run before the feature check", async (t) => {
  const cp = await plane(t, NO_FEATURES, chiefBackend);
  const chiefs = `/api/v1/workspaces/${cp.tenant.workspaceId}/chiefs`;
  assert.equal((await cp.api(chiefs)).status, 401);
  const nonMember = await cp.api(chiefs, { token: cp.tenant.otherOwnerToken });
  assert.equal(nonMember.status, 404);
  assert.equal(nonMember.body.error, "workspace_not_found");
  const notAdmin = await cp.api(chiefs, { method: "POST", token: cp.tenant.memberToken, body: {} });
  assert.equal(notAdmin.status, 403);
  assert.equal(notAdmin.body.error, "forbidden");

  assert.equal((await cp.api("/api/v1/flows")).status, 401);
  const flowsNotAdmin = await cp.api("/api/v1/workers/enrollment-tokens", { token: cp.tenant.memberToken });
  assert.equal(flowsNotAdmin.status, 403);
  assert.equal(flowsNotAdmin.body.error, "forbidden");
  assert.equal((await cp.api("/api/v1/workers/not-a-worker/heartbeat", { method: "POST", token: "sh_wrk_bad" })).status, 401);
  assert.equal((await cp.api("/api/v1/workflows/runs/not-a-run/events", {
    method: "POST", token: "bad", body: { eventType: "x" },
  })).status, 401);
});

test("workers: enrol, heartbeat, queue and runtime credentials refused once Flows is deselected", async (t) => {
  const cp = await plane(t, testFeatures("flows"));
  const enrollment = await cp.api("/api/v1/workers/enrollment-tokens", {
    method: "POST", token: cp.tenant.ownerToken, body: { name: "w1" },
  });
  const spare = await cp.api("/api/v1/workers/enrollment-tokens", {
    method: "POST", token: cp.tenant.ownerToken, body: { name: "w2" },
  });
  const registered = await cp.api("/api/v1/workers/register", {
    method: "POST", body: { enrollmentToken: enrollment.body.token, name: "w1" },
  });
  assert.equal(registered.status, 200);
  const { workerId, workerToken } = registered.body;
  assert.equal((await cp.api(`/api/v1/workers/${workerId}/heartbeat`, { method: "POST", token: workerToken })).status, 200);

  const code = "feature_not_enabled";
  const api = await restartWith(t, cp, testFeatures("relayfile"));
  const heartbeat = await api(`/api/v1/workers/${workerId}/heartbeat`, { method: "POST", token: workerToken });
  assert.equal(heartbeat.status, 403);
  assert.deepEqual([heartbeat.body.error, heartbeat.body.feature], [code, "flows"]);
  assert.equal((await api(`/api/v1/workers/${workerId}/queue`, { token: workerToken })).body.error, code);
  const enrol = await api("/api/v1/workers/register", {
    method: "POST", body: { enrollmentToken: spare.body.token, name: "w2" },
  });
  assert.equal(enrol.status, 403);
  assert.equal(enrol.body.error, code);
  assert.equal((await api("/api/v1/workers/enrollment-tokens", { token: cp.tenant.ownerToken })).body.error, code);
  const runtime = await api(`/internal/v1/workspaces/${cp.tenant.workspaceId}/environment`, { token: workerToken });
  assert.equal(runtime.status, 403);
  assert.equal(runtime.body.error, code);
  // An unknown credential is still a plain 401.
  assert.equal((await api(`/internal/v1/workspaces/${cp.tenant.workspaceId}/environment`, { token: "sh_wrk_nope" })).status, 401);

  // The refused enrolment did not spend the token.
  const later = await cp.api("/api/v1/workers/register", {
    method: "POST", body: { enrollmentToken: spare.body.token, name: "w2" },
  });
  assert.equal(later.status, 200);
});

test("/readyz reports capabilities and no licence field", async (t) => {
  const cp = await plane(t, testFeatures("flows,chief"));
  const ready = await cp.api("/readyz");
  assert.equal(ready.status, 200);
  assert.equal("license" in ready.body, false);
  assert.deepEqual(ready.body.capabilities, { flows: true, relayfile: false, chief: true });
});
