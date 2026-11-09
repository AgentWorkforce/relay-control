import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { createAdminModule } from "../src/admin/routes.js";
import { createApp } from "../src/app.js";
import type { ChiefBackend } from "../src/chief/routes.js";
import { loadLicense } from "../src/license/load.js";
import { LICENSE_PUBLIC_KEY } from "../src/license/public-key.js";
import { CORE_LICENSE, gateCredentialVerifier, type LoadedLicense } from "../src/license/resolver.js";
import { apiClient, BOOTSTRAP, close, listen, seedTenant, startControlPlane } from "./flows-helpers.js";
import { licenseClaims, signLicense, testKeys, testLicense } from "./support/license.js";

const LICENSE_KEYS = [
  "status", "license_id", "customer", "expires_at", "seats", "features", "paid", "selected", "entitled", "capabilities",
];
const NONE = { flows: false, relayfile: false, chief: false };

function load(env: Record<string, string | undefined>) {
  const lines: Array<{ message: string; fields?: Record<string, unknown> }> = [];
  const loaded = loadLicense(env, { log: (message, fields) => lines.push({ message, fields }) });
  return { loaded, lines };
}

const chiefBackend: ChiefBackend = {
  list: () => ({ chiefs: [] }),
  get: () => ({ id: "chief-1" }),
  create: () => ({ id: "chief-1" }),
  scan: () => ({ id: "chief-1" }),
  repositories: () => ({ repositories: [] }),
};

async function plane(t: TestContext, license: LoadedLicense, chief?: ChiefBackend) {
  const cp = await startControlPlane({}, chief, {}, license);
  t.after(() => cp.stop());
  return { ...cp, tenant: await seedTenant(cp.api) };
}

/** A second app over the same database with a different licence (as after a restart). */
async function restartWith(t: TestContext, cp: Awaited<ReturnType<typeof plane>>, license: LoadedLicense) {
  const admin = createAdminModule({
    config: cp.config,
    database: cp.database,
    keyring: cp.config.encryptionKeyring,
    runtimeCredentialVerifier: gateCredentialVerifier((token: string) => cp.flows.verifyRuntimeCredential(token), license, "flows"),
  });
  const server = createServer(createApp({ config: cp.config, store: cp.store, flows: cp.flows, admin, license }));
  const api = apiClient(await listen(server));
  t.after(() => close(server));
  return api;
}

test("the compiled public key ships null, so any licence without the test override is invalid", () => {
  assert.equal(LICENSE_PUBLIC_KEY, null);
  const keys = testKeys();
  const { loaded, lines } = load({ SELFHOST_LICENSE: signLicense(keys.privateKey, licenseClaims()) });
  assert.equal(loaded.supplied, true);
  assert.equal(loaded.claims, null);
  assert.equal(lines.length, 1);
  assert.equal(lines[0]!.fields?.status, "invalid");
  assert.match(String(lines[0]!.fields?.reason), /no licence public key/);
});

test("absent licence: status absent and every capability false", async (t) => {
  const { loaded, lines } = load({});
  assert.deepEqual(loaded, CORE_LICENSE);
  assert.deepEqual(lines.map((line) => line.fields?.status), ["absent"]);
  const cp = await plane(t, loaded);
  const read = await cp.api("/api/v1/license", { token: cp.tenant.memberToken });
  assert.equal(read.status, 200);
  assert.deepEqual(read.body, {
    status: "absent",
    license_id: null,
    customer: null,
    expires_at: null,
    seats: null,
    features: [],
    paid: ["flows", "relayfile"],
    selected: NONE,
    entitled: { flows: false, relayfile: false },
    capabilities: NONE,
  });
});

test("GET /api/v1/license: exact shape, any member, cookie alias, 401 without a user token, seats count owners", async (t) => {
  const license = testLicense({ features: "flows,chief", claims: { seats: 25, customer: "Acme Corp" } });
  const cp = await plane(t, license);
  assert.equal((await cp.api("/api/v1/license")).status, 401);
  assert.equal((await cp.api("/api/v1/license", { token: "not-a-token" })).status, 401);
  assert.equal((await cp.api("/api/v1/license", { token: BOOTSTRAP })).status, 401, "bootstrap token is not a member");

  const read = await cp.api("/api/v1/license", { token: cp.tenant.memberToken });
  assert.equal(read.status, 200);
  assert.equal(read.headers.get("cache-control"), "no-store");
  assert.deepEqual(Object.keys(read.body), LICENSE_KEYS);
  assert.deepEqual(read.body, {
    status: "valid",
    license_id: license.claims!.licenseId,
    customer: "Acme Corp",
    expires_at: "2099-01-01T00:00:00Z",
    // seedTenant makes one owner and one member: the owner counts.
    seats: { limit: 25, used: 2 },
    features: ["flows", "relayfile"],
    paid: ["flows", "relayfile"],
    selected: { flows: true, relayfile: false, chief: true },
    entitled: { flows: true, relayfile: true },
    capabilities: { flows: true, relayfile: false, chief: true },
  });
  const owners = await cp.database.query<{ count: string }>(
    "SELECT count(*)::text AS count FROM organization_memberships WHERE role = 'owner'",
  );
  assert.equal(owners.rows[0]!.count, "1");
  assert.equal(JSON.stringify(read.body).includes("."), false, "no licence document or signature");

  const added = await cp.api(`/api/v1/organizations/${cp.tenant.organizationId}/memberships`, {
    method: "POST",
    token: BOOTSTRAP,
    body: { email: "admin@acme.test", name: "Admin", role: "admin" },
  });
  assert.equal(added.status, 200);
  const cookie = await cp.api("/cloud/api/v1/license", {
    headers: { cookie: `agent_relay_session=${cp.tenant.ownerToken}` },
  });
  assert.equal(cookie.status, 200);
  assert.deepEqual(cookie.body.seats, { limit: 25, used: 3 });
  assert.equal((await cp.api("/api/v1/license", { headers: { cookie: `agent_relay_session=${cp.tenant.ownerToken}` } })).status, 401,
    "the session cookie is scoped to /cloud");
});

test("valid licence with flows selected: capability true and Flows routes serve", async (t) => {
  const cp = await plane(t, testLicense({ features: "flows" }));
  const read = await cp.api("/api/v1/license", { token: cp.tenant.memberToken });
  assert.equal(read.body.capabilities.flows, true);
  const flows = await cp.api("/api/v1/flows", { token: cp.tenant.memberToken });
  assert.equal(flows.status, 200);
  const enrollment = await cp.api("/api/v1/workers/enrollment-tokens", {
    method: "POST", token: cp.tenant.ownerToken, body: { name: "w1" },
  });
  assert.equal(enrollment.status, 200);
});

test("valid licence but flows not selected: 403 feature_not_enabled", async (t) => {
  const cp = await plane(t, testLicense({ features: "relayfile" }));
  const refused = await cp.api("/api/v1/flows", { token: cp.tenant.memberToken });
  assert.equal(refused.status, 403);
  assert.deepEqual(Object.keys(refused.body).sort(), ["error", "feature", "message"]);
  assert.equal(refused.body.error, "feature_not_enabled");
  assert.equal(refused.body.feature, "flows");
  assert.equal((await cp.api("/cloud/api/v1/workflows/runs", { token: cp.tenant.memberToken })).body.error, "feature_not_enabled");
});

test("flows selected without a licence: 403 feature_not_licensed", async (t) => {
  const cp = await plane(t, testLicense({ features: "flows", claims: null }));
  const refused = await cp.api("/api/v1/flows", { token: cp.tenant.memberToken });
  assert.equal(refused.status, 403);
  assert.deepEqual(refused.body, {
    error: "feature_not_licensed",
    message: "Flows is not licensed on this installation.",
    feature: "flows",
  });
});

test("flows selected but missing from a valid licence: 403 feature_not_licensed", async (t) => {
  const cp = await plane(t, testLicense({ features: "flows", claims: { features: ["relayfile"] } }));
  assert.equal((await cp.api("/api/v1/flows", { token: cp.tenant.memberToken })).body.error, "feature_not_licensed");
});

test("expired licence: status expired, no features, Flows refused as not licensed", async (t) => {
  const license = testLicense({
    features: "flows",
    claims: { issued_at: "2020-01-01T00:00:00Z", expires_at: "2021-01-01T00:00:00Z" },
  });
  const cp = await plane(t, license);
  const read = await cp.api("/api/v1/license", { token: cp.tenant.memberToken });
  assert.equal(read.body.status, "expired");
  assert.deepEqual(read.body.features, []);
  assert.deepEqual(read.body.entitled, { flows: false, relayfile: false });
  assert.equal(read.body.capabilities.flows, false);
  assert.equal(read.body.expires_at, "2021-01-01T00:00:00Z");
  const refused = await cp.api("/api/v1/flows", { token: cp.tenant.memberToken });
  assert.equal(refused.status, 403);
  assert.equal(refused.body.error, "feature_not_licensed");
});

test("tampered signature or payload: status invalid", () => {
  const keys = testKeys();
  const good = signLicense(keys.privateKey, licenseClaims());
  const [payload, signature] = good.split(".") as [string, string];
  const flipped = Buffer.from(signature, "base64url");
  flipped[0] = flipped[0]! ^ 1;
  const forged = Buffer.from(JSON.stringify(licenseClaims({ seats: 9999 }))).toString("base64url");
  const env = { SELFHOST_LICENSE_PUBLIC_KEY_OVERRIDE: keys.publicKeyBase64 };
  assert.equal(load({ ...env, SELFHOST_LICENSE: good }).loaded.claims?.seats, 25);
  for (const document of [`${payload}.${flipped.toString("base64url")}`, `${forged}.${signature}`, "garbage", `${payload}.`]) {
    const { loaded, lines } = load({ ...env, SELFHOST_LICENSE: document });
    assert.equal(loaded.claims, null, document);
    assert.equal(lines[0]!.fields?.status, "invalid");
  }
  // Signed by another key.
  const other = testKeys();
  assert.equal(load({ ...env, SELFHOST_LICENSE: signLicense(other.privateKey, licenseClaims()) }).loaded.claims, null);
});

test("signed but malformed claims are invalid; unknown claims and feature names are ignored", () => {
  const keys = testKeys();
  const env = { SELFHOST_LICENSE_PUBLIC_KEY_OVERRIDE: keys.publicKeyBase64 };
  const status = (claims: Record<string, unknown>) =>
    load({ ...env, SELFHOST_LICENSE: signLicense(keys.privateKey, claims) }).lines[0]!.fields?.status;
  assert.equal(status(licenseClaims({ v: 2 })), "invalid");
  assert.equal(status(licenseClaims({ license_id: "nope" })), "invalid");
  assert.equal(status(licenseClaims({ seats: 0 })), "invalid");
  assert.equal(status(licenseClaims({ expires_at: "2099-01-01" })), "invalid");
  assert.equal(status(licenseClaims({ features: "flows" })), "invalid");
  const lenient = load({
    ...env,
    SELFHOST_FEATURES: "flows,chief",
    SELFHOST_LICENSE: signLicense(keys.privateKey, licenseClaims({ features: ["flows", "chief", "bogus"], future_claim: true })),
  }).loaded;
  assert.deepEqual(lenient.claims?.features, ["flows", "chief", "bogus"]);
});

test("SELFHOST_LICENSE_FILE is read; an unreadable file is invalid, not fatal", () => {
  const keys = testKeys();
  const directory = mkdtempSync(join(tmpdir(), "license-"));
  const file = join(directory, "license");
  writeFileSync(file, `${signLicense(keys.privateKey, licenseClaims())}\n`);
  const env = { SELFHOST_LICENSE_PUBLIC_KEY_OVERRIDE: keys.publicKeyBase64 };
  assert.equal(load({ ...env, SELFHOST_LICENSE_FILE: file }).lines[0]!.fields?.status, "valid");
  const missing = load({ ...env, SELFHOST_LICENSE_FILE: join(directory, "missing") });
  assert.equal(missing.lines[0]!.fields?.status, "invalid");
  assert.match(String(missing.lines[0]!.fields?.reason), /could not be read/);
});

test("the key override is ignored, with one log line, when NODE_ENV is not test", () => {
  const keys = testKeys();
  const previous = process.env.NODE_ENV;
  try {
    for (const nodeEnv of ["production", "development", undefined]) {
      if (nodeEnv === undefined) delete process.env.NODE_ENV;
      else process.env.NODE_ENV = nodeEnv;
      const { loaded, lines } = load({
        SELFHOST_FEATURES: "flows",
        SELFHOST_LICENSE_PUBLIC_KEY_OVERRIDE: keys.publicKeyBase64,
        SELFHOST_LICENSE: signLicense(keys.privateKey, licenseClaims()),
      });
      assert.equal(loaded.claims, null, String(nodeEnv));
      assert.equal(lines.filter((line) => /OVERRIDE ignored/.test(line.message)).length, 1);
      assert.equal(lines.at(-1)!.fields?.status, "invalid");
    }
  } finally {
    process.env.NODE_ENV = previous;
  }
});

test("configuration errors: both licence sources set, unknown SELFHOST_FEATURES name", () => {
  assert.throws(
    () => load({ SELFHOST_LICENSE: "a.b", SELFHOST_LICENSE_FILE: "/run/secrets/license" }),
    /SELFHOST_LICENSE and SELFHOST_LICENSE_FILE are mutually exclusive/,
  );
  assert.throws(() => load({ SELFHOST_FEATURES: "flows,teleport" }), /unknown feature "teleport"/);
  assert.deepEqual(load({ SELFHOST_FEATURES: " Flows , ,chief," }).loaded.selected, { flows: true, relayfile: false, chief: true });
  assert.deepEqual(load({ SELFHOST_FEATURES: "" }).loaded.selected, NONE);
});

test("Chief is optional core: unselected -> feature_not_enabled; selected with no licence -> 503 or served", async (t) => {
  const off = await plane(t, testLicense({ features: "flows" }), chiefBackend);
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

  // Selected with no licence at all and no backend: unavailable, never a licence code.
  const noBackend = await plane(t, testLicense({ features: "chief", claims: null }));
  const unavailable = await noBackend.api(`/api/v1/workspaces/${noBackend.tenant.workspaceId}/chiefs`, {
    token: noBackend.tenant.memberToken,
  });
  assert.equal(unavailable.status, 503);
  assert.equal(unavailable.body.error, "chief_unavailable");
  assert.deepEqual((await noBackend.api("/api/v1/license", { token: noBackend.tenant.memberToken })).body.capabilities,
    { flows: false, relayfile: false, chief: true });

  const served = await plane(t, testLicense({ features: "chief", claims: null }), chiefBackend);
  assert.equal((await served.api(`/api/v1/workspaces/${served.tenant.workspaceId}/chiefs`, {
    token: served.tenant.memberToken,
  })).status, 200);
});

test("membership checks run before the feature check", async (t) => {
  const cp = await plane(t, CORE_LICENSE, chiefBackend);
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

test("workers: enrol, heartbeat, queue and runtime credentials refused once Flows is not a capability", async (t) => {
  const cp = await plane(t, testLicense({ features: "flows" }));
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

  for (const [license, code] of [
    [testLicense({ features: "flows", claims: null }), "feature_not_licensed"],
    [testLicense({ features: "relayfile" }), "feature_not_enabled"],
  ] as const) {
    const api = await restartWith(t, cp, license);
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
  }
  // The refused enrolment did not spend the token.
  const later = await cp.api("/api/v1/workers/register", {
    method: "POST", body: { enrollmentToken: spare.body.token, name: "w2" },
  });
  assert.equal(later.status, 200);
});

test("/readyz echoes license.status and capabilities", async (t) => {
  const cp = await plane(t, testLicense({ features: "flows,chief", claims: { features: ["flows"] } }));
  const ready = await cp.api("/readyz");
  assert.equal(ready.status, 200);
  assert.deepEqual(ready.body.license, { status: "valid" });
  assert.deepEqual(ready.body.capabilities, { flows: true, relayfile: false, chief: true });
  const expired = await plane(t, testLicense({
    features: "flows",
    claims: { issued_at: "2020-01-01T00:00:00Z", expires_at: "2021-01-01T00:00:00Z" },
  }));
  const expiredReady = await expired.api("/readyz");
  assert.deepEqual(expiredReady.body.license, { status: "expired" });
  assert.deepEqual(expiredReady.body.capabilities, NONE);
});
