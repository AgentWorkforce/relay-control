import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import { createAdminModule } from "../src/admin/routes.js";
import { lazyFlowsStore } from "../src/flows/lazy.js";
import { createLicenseLoader, loadLicense, loadSelectedFeatures } from "../src/license/load.js";
import { publicKeyFromBase64, verifyLicenseDocument } from "../src/license/document.js";
import { LICENSE_PUBLIC_KEY } from "../src/license/public-key.js";
import { CORE_LICENSE, gateCredentialVerifier, requireCapability, resolveLicense, type LoadedLicense } from "../src/license/resolver.js";
import { apiClient, BOOTSTRAP, close, listen, seedTenant, startControlPlane } from "./flows-helpers.js";
import { licenseClaims, signLicense, testKeys, testLicense } from "./support/license.js";

const NONE = { flows: false, relayfile: false, chief: false };
const quiet = () => {};
const load = (env: Record<string, string | undefined>) => loadLicense(env, { log: quiet });
const now = new Date("2026-11-09T00:00:00Z");

async function app(t: TestContext, license = CORE_LICENSE) {
  const cp = await startControlPlane({}, undefined, license);
  t.after(() => cp.stop());
  return { ...cp, tenant: await seedTenant(cp.api) };
}
async function restart(t: TestContext, cp: Awaited<ReturnType<typeof app>>, license: LoadedLicense, clock?: () => Date) {
  const admin = createAdminModule({
    config: cp.config, database: cp.database, keyring: cp.config.encryptionKeyring,
    runtimeCredentialVerifier: gateCredentialVerifier((token: string) => cp.flows.verifyRuntimeCredential(token), license, "flows"),
  });
  const server = createServer(createApp({ config: cp.config, store: cp.store, flows: cp.flows, admin, license, now: clock }));
  const api = apiClient(await listen(server));
  t.after(() => close(server));
  return api;
}

test("core has no licence, key or selected optional features", () => {
  assert.equal(LICENSE_PUBLIC_KEY, null);
  assert.deepEqual(load({}), CORE_LICENSE);
  assert.deepEqual(resolveLicense(CORE_LICENSE, now).capabilities, NONE);
  assert.deepEqual(loadSelectedFeatures({ SELFHOST_FEATURES: " chief,CHIEF " }), { ...NONE, chief: true });
  assert.throws(() => load({ SELFHOST_FEATURES: "core" }), /unknown feature/);
  assert.throws(() => load({ SELFHOST_FEATURES: "typo" }), /unknown feature/);
  assert.throws(() => load({ SELFHOST_LICENSE: "x", SELFHOST_LICENSE_FILE: "x" }), /mutually exclusive/);
});

test("NODE_ENV and a runtime key override cannot enable a paid feature", () => {
  const keys = testKeys();
  const previous = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = "test";
    const loaded = load({
      NODE_ENV: "test", SELFHOST_FEATURES: "flows,relayfile",
      SELFHOST_LICENSE_PUBLIC_KEY_OVERRIDE: keys.publicKeyBase64,
      SELFHOST_LICENSE: signLicense(keys.privateKey, licenseClaims()),
    });
    assert.equal(loaded.supplied, true);
    assert.equal(loaded.claims, null);
    assert.equal(resolveLicense(loaded, now).status, "invalid");
    assert.deepEqual(resolveLicense(loaded, now).capabilities, NONE);
  } finally {
    if (previous === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = previous;
  }
});

test("the pure loader verifies a synthetic signature before accepting any claims", () => {
  const keys = testKeys();
  const key = publicKeyFromBase64(keys.publicKeyBase64);
  const loader = createLicenseLoader(document => verifyLicenseDocument(document, key));
  const good = signLicense(keys.privateKey, licenseClaims({ features: ["flows", "unknown"] }));
  const loaded = loader({ SELFHOST_LICENSE: good, SELFHOST_FEATURES: "flows,relayfile" }, { log: quiet });
  assert.deepEqual(resolveLicense(loaded, now).capabilities, { ...NONE, flows: true });
  const pieces = good.split(".");
  const changed = Buffer.from(JSON.stringify(licenseClaims({ features: ["relayfile"] }))).toString("base64url");
  assert.equal(loader({ SELFHOST_LICENSE: `${changed}.${pieces[1]}` }, { log: quiet }).claims, null);
  const wrong = publicKeyFromBase64(testKeys().publicKeyBase64);
  assert.equal(verifyLicenseDocument(good, wrong).ok, false);
  for (const bad of ["garbage", "a.b", "x".repeat(17_000), `${pieces[0]}.`]) {
    assert.equal(verifyLicenseDocument(bad, key).ok, false);
  }
  assert.throws(() => publicKeyFromBase64("bad"), /32 bytes/);
});

test("signed malformed claims refuse and expiry never authorizes a paid feature", () => {
  const keys = testKeys();
  const key = publicKeyFromBase64(keys.publicKeyBase64);
  for (const claims of [
    { v: 2 }, { license_id: "not-a-uuid" }, { customer: "" }, { issued_at: "yesterday" },
    { expires_at: "2020-01-01T00:00:00Z" }, { seats: 0 }, { features: [1] }, { notes: 7 },
  ]) assert.equal(verifyLicenseDocument(signLicense(keys.privateKey, licenseClaims(claims)), key).ok, false);
  const expired = testLicense({ features: "flows,relayfile,chief", claims: { expires_at: "2026-02-01T00:00:00Z" } });
  assert.equal(resolveLicense(expired, now).status, "expired");
  assert.deepEqual(resolveLicense(expired, now).capabilities, { ...NONE, chief: true });
  assert.throws(() => requireCapability(expired, "flows", now), { code: "feature_not_licensed" });
  const unselected = testLicense({ features: "" });
  assert.throws(() => requireCapability(unselected, "flows", now), { code: "feature_not_enabled" });
});

test("inline/file licence loading stays fail closed without logging licence data", (t) => {
  const dir = mkdtempSync(join(tmpdir(), "control-license-unit-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, "license");
  const keys = testKeys();
  const document = signLicense(keys.privateKey, licenseClaims({ customer: "private-customer" }));
  writeFileSync(file, document);
  const logs: unknown[] = [];
  const loaded = loadLicense({ SELFHOST_LICENSE_FILE: file }, { log: (message, fields) => logs.push({ message, fields }) });
  assert.equal(loaded.claims, null);
  assert.equal(load({ SELFHOST_LICENSE_FILE: join(dir, "missing") }).supplied, true);
  assert.doesNotMatch(JSON.stringify(logs), /private-customer/);
  assert.equal(JSON.stringify(logs).includes(document), false);
});

test("member-facing capabilities expose no installation customer or seat metadata", async (t) => {
  const license = testLicense({ features: "chief", claims: { customer: "private-customer", seats: 419 } });
  const cp = await app(t, license);
  const expected = {
    status: "valid", selected: { ...NONE, chief: true }, entitled: { flows: true, relayfile: true },
    capabilities: { ...NONE, chief: true },
  };
  for (const token of [cp.tenant.ownerToken, cp.tenant.memberToken, cp.tenant.otherOwnerToken]) {
    const result = await cp.api("/api/v1/license", { token });
    assert.equal(result.status, 200);
    assert.equal(result.headers.get("cache-control"), "no-store");
    assert.deepEqual(result.body, expected);
    assert.doesNotMatch(JSON.stringify(result.body), /private-customer|419|license_id|customer|seats|notes/);
  }
  const cookie = await cp.api("/cloud/api/v1/license", { headers: { cookie: `agent_relay_session=${cp.tenant.memberToken}` } });
  assert.deepEqual(cookie.body, expected);
  for (const token of [undefined, "bad", BOOTSTRAP]) {
    assert.equal((await cp.api("/api/v1/license", { token })).status, 401);
  }
});

test("core default: authenticated capability response and readiness are all off", async (t) => {
  const cp = await app(t);
  assert.deepEqual((await cp.api("/cloud/api/v1/license", { token: cp.tenant.memberToken })).body, {
    status: "absent", selected: NONE, entitled: { flows: false, relayfile: false }, capabilities: NONE,
  });
  const ready = await cp.api("/readyz");
  assert.equal(ready.status, 200);
  assert.deepEqual(ready.body.capabilities, NONE);
  assert.deepEqual(ready.body.license, { status: "absent" });
  assert.deepEqual(ready.body.introspection, { enabled: false, audiences: [] });
});

test("core startup, readiness and ordinary authenticated reads do not initialize Flows storage", async (t) => {
  const cp = await app(t);
  let initialized = 0;
  const flows = lazyFlowsStore(() => { initialized++; throw new Error("optional storage must not initialize"); });
  const server = createServer(createApp({ config: cp.config, store: cp.store, flows }));
  const api = apiClient(await listen(server));
  t.after(() => close(server));
  for (const path of ["/healthz", "/readyz", "/api/v1/license", "/api/v1/organizations"]) {
    const response = await api(path, { token: cp.tenant.ownerToken });
    assert.equal(response.status, 200, path);
  }
  assert.equal(initialized, 0);
  const lazy = lazyFlowsStore(() => { initialized++; return cp.flows; });
  assert.equal(lazy(), cp.flows);
  assert.equal(lazy(), cp.flows);
  assert.equal(initialized, 1);
});

test("core denies flow APIs after user authentication, before mutations and maintenance", async (t) => {
  const cp = await app(t);
  let maintenance = 0;
  cp.flows.maintenance = async () => { maintenance++; return { timedOut: [] }; };
  assert.equal((await cp.api("/api/v1/flows")).status, 401);
  for (const path of ["/api/v1/flows", "/api/v1/workflows/runs", "/api/v1/workers"]) {
    const refused = await cp.api(path, { token: cp.tenant.ownerToken });
    assert.equal(refused.status, 403, path);
    assert.equal(refused.body.error, "feature_not_enabled");
    assert.equal(refused.body.feature, "flows");
  }
  const create = await cp.api("/api/v1/flows", { method: "POST", token: cp.tenant.ownerToken, body: {} });
  assert.equal(create.status, 403);
  assert.equal(maintenance, 0);
  const flows = await cp.database.query<{ n: number }>("SELECT count(*)::int AS n FROM selfhost_flow_definitions");
  assert.equal(flows.rows[0]!.n, 0);
});

test("core refuses worker registration without spending a valid enrollment token", async (t) => {
  const cp = await app(t, testLicense());
  const enrollment = await cp.api("/api/v1/workers/enrollment-tokens", {
    method: "POST", token: cp.tenant.ownerToken, body: { name: "unit-worker" },
  });
  assert.equal(enrollment.status, 200);
  const core = await restart(t, cp, CORE_LICENSE);
  const register = await core("/api/v1/workers/register", {
    method: "POST", body: { enrollmentToken: enrollment.body.token, name: "unit-worker" },
  });
  assert.equal(register.status, 403);
  const state = await cp.database.query<{ used_at: string | null }>("SELECT used_at FROM selfhost_worker_enrollment_tokens");
  assert.equal(state.rows[0]!.used_at, null);
  const workers = await cp.database.query<{ n: number }>("SELECT count(*)::int AS n FROM selfhost_workers");
  assert.equal(workers.rows[0]!.n, 0);
});

test("previously enrolled workers cannot heartbeat, queue or read runtime secrets in core", async (t) => {
  const cp = await app(t, testLicense());
  const enrollment = await cp.api("/api/v1/workers/enrollment-tokens", {
    method: "POST", token: cp.tenant.ownerToken, body: {},
  });
  const register = await cp.api("/api/v1/workers/register", {
    method: "POST", body: { enrollmentToken: enrollment.body.token, name: "existing-unit-worker" },
  });
  assert.equal(register.status, 200);
  const core = await restart(t, cp, CORE_LICENSE);
  let maintenance = 0, touches = 0;
  cp.flows.maintenance = async () => { maintenance++; return { timedOut: [] }; };
  cp.flows.touchWorker = async () => { touches++; };
  for (const [path, method] of [
    [`/api/v1/workers/${register.body.workerId}/heartbeat`, "POST"],
    [`/api/v1/workers/${register.body.workerId}/queue`, "GET"],
    [`/internal/v1/workspaces/${cp.tenant.workspaceId}/environment`, "GET"],
  ] as const) {
    const result = await core(path, { method, token: register.body.workerToken, ...(method === "POST" ? { body: {} } : {}) });
    assert.equal(result.status, 403, path);
    assert.equal(result.body.error, "feature_not_enabled");
  }
  assert.equal(maintenance, 0);
  assert.equal(touches, 0);
  const unknown = await core(`/api/v1/workers/${register.body.workerId}/heartbeat`, { method: "POST", token: "unknown", body: {} });
  assert.equal(unknown.status, 401);
});

test("selected paid features still require a currently valid entitlement", async (t) => {
  const cp = await app(t, load({ SELFHOST_FEATURES: "flows,relayfile" }));
  const denied = await cp.api("/api/v1/flows", { token: cp.tenant.ownerToken });
  assert.equal(denied.status, 403);
  assert.equal(denied.body.error, "feature_not_licensed");
  const license = testLicense({ features: "flows", claims: { expires_at: "2026-11-10T00:00:00Z" } });
  let clock = now;
  const entitled = await restart(t, cp, license, () => clock);
  assert.equal((await entitled("/api/v1/flows", { token: cp.tenant.ownerToken })).status, 200);
  clock = new Date("2026-11-11T00:00:00Z");
  assert.equal((await entitled("/api/v1/flows", { token: cp.tenant.ownerToken })).body.error, "feature_not_licensed");
  assert.deepEqual((await entitled("/api/v1/license", { token: cp.tenant.memberToken })).body.capabilities, NONE);
});

test("Chief selection preserves authorization and returns real unavailable without a backend", async (t) => {
  const cp = await app(t);
  const path = `/api/v1/workspaces/${cp.tenant.workspaceId}/chiefs`;
  assert.equal((await cp.api(path)).status, 401);
  assert.equal((await cp.api(path, { token: cp.tenant.otherOwnerToken })).status, 404);
  assert.equal((await cp.api(path, { token: cp.tenant.memberToken })).body.error, "feature_not_enabled");
  const selected = await restart(t, cp, load({ SELFHOST_FEATURES: "chief" }));
  const unavailable = await selected(path, { token: cp.tenant.memberToken });
  assert.equal(unavailable.status, 503);
  assert.equal(unavailable.body.error, "chief_unavailable");
  assert.equal((await selected(path, { method: "POST", token: cp.tenant.memberToken, body: {} })).status, 403);
});


test("invalid enrollment and callback credentials remain unauthorized in core", async (t) => {
  const cp = await app(t);
  const register = await cp.api("/api/v1/workers/register", {
    method: "POST", body: { enrollmentToken: "sh_wrk_enr_unknown", name: "unknown-worker" },
  });
  assert.equal(register.status, 401);
  assert.equal(register.body.code, "invalid_enrollment_token");
  const callback = await cp.api("/api/v1/workflows/callback", {
    method: "POST", body: { runId: "00000000-0000-4000-8000-000000000001", status: "completed" },
  });
  assert.equal(callback.status, 401);
  assert.equal(callback.body.code, "unauthorized");
});

test("authenticated callback refusal leaves the run and events unchanged; mutation rechecks the credential", async (t) => {
  const cp = await app(t, testLicense());
  const local = await cp.api("/api/v1/workflows/local-run", {
    method: "POST", token: cp.tenant.memberToken,
    body: { workflow: "version: '0.1.0'\nname: synthetic\nsteps: []\n", fileType: "yaml" },
  });
  assert.equal(local.status, 201);
  const core = await restart(t, cp, CORE_LICENSE);
  const runId = local.body.runId as string;
  const snapshot = async () => ({
    run: (await cp.database.query("SELECT status, result, completed_at FROM selfhost_workflow_runs WHERE id = $1", [runId])).rows,
    events: (await cp.database.query("SELECT * FROM selfhost_run_events WHERE run_id = $1 ORDER BY sequence", [runId])).rows,
  });
  const before = await snapshot();
  const body = { runId, callbackToken: local.body.callbackToken, status: "completed", result: { ok: true } };
  const invalid = await core("/api/v1/workflows/callback", {
    method: "POST", token: local.body.accessToken, body: { ...body, callbackToken: "wrong" },
  });
  assert.equal(invalid.status, 401);
  const denied = await core("/api/v1/workflows/callback", { method: "POST", token: local.body.accessToken, body });
  assert.equal(denied.status, 403);
  assert.equal(denied.body.error, "feature_not_enabled");
  assert.deepEqual(await snapshot(), before);
  // A successful preflight is never cached as mutation authority.
  const credentials = { runId, accessToken: local.body.accessToken, callbackToken: local.body.callbackToken };
  await cp.flows.authenticateCallback(credentials);
  await cp.database.query("UPDATE selfhost_workflow_runs SET callback_token_hash = 'rotated' WHERE id = $1", [runId]);
  await assert.rejects(cp.flows.callback({ ...credentials, status: "completed" }), { code: "unauthorized" });
  assert.deepEqual(await snapshot(), before);
});
