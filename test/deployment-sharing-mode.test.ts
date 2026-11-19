import assert from "node:assert/strict";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createAdminModule } from "../src/admin/routes.js";
import { createApp } from "../src/app.js";
import {
  capturePolicyForCaller,
  capturePolicyFromRow,
  sharingDeployment,
  type CapturePolicy,
  type SharingDeployment,
} from "../src/capture-policy.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { workspacePolicyForCaller, workspacePolicyFromRow } from "../src/workspace-policy.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * Deployment default sharing mode and override roles
 * (docs/capture-policy.md, "Deployment default and override roles"):
 * SELFHOST_DEFAULT_SHARING_MODE and SELFHOST_SHARING_MODE_OVERRIDE_ROLES
 * project the served capture and workspace policies per caller role.
 */

// Every value here is a fake test fixture.
const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const SERVICE = "internal-service-token-that-is-at-least-32-bytes";
const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const HISTORY = "https://history.selfhosted.test";
const SINCE = "2026-01-02T03:04:05.000Z";
const EMPTY_SECTION = { locked: {}, defaults: {} };

type Mode = "all" | "new" | "selected";
type Role = "owner" | "admin" | "member";

function row(settings: Record<string, unknown> | null, since: string | null = null) {
  return settings === null
    ? null
    : {
      revision: 4,
      settings,
      sharing_mode_since: since,
      workspace_settings: { spawn: { locked: { allowed: true }, defaults: {} } },
      workspace_revision: 7,
      consent: [],
    };
}

// ---- pure projection ----

test("both values unset: the served policies are returned as the same objects", () => {
  const none: SharingDeployment = {};
  for (const stored of [null, { sharing_mode: "all" }, { sharing_mode: "new" }, { upload_control: "operator" }]) {
    const source = row(stored, stored?.sharing_mode === "new" ? SINCE : null);
    const v1 = capturePolicyFromRow(source);
    const v2 = workspacePolicyFromRow(source);
    for (const role of ["owner", "admin", "member", undefined, null, "Owner"]) {
      assert.equal(capturePolicyForCaller(v1, role, none), v1);
      assert.equal(workspacePolicyForCaller(v2, role, none), v2);
    }
  }
  assert.deepEqual(sharingDeployment({}), { defaultSharingMode: undefined, overrideRoles: undefined });
  assert.deepEqual(sharingDeployment({ defaultSharingMode: "new", sharingModeOverrideRoles: ["admin"] }),
    { defaultSharingMode: "new", overrideRoles: ["admin"] });
});

test("every stored mode x deployment default x role x override roles combination", () => {
  const storedCases: Array<{ name: string; settings: Record<string, unknown> | null; since: string | null }> = [
    { name: "no policy", settings: null, since: null },
    { name: "no stored mode", settings: { upload_control: "operator", user_retroactive_delete: false }, since: null },
    { name: "stored all", settings: { sharing_mode: "all", upload_control: "user" }, since: null },
    { name: "stored new", settings: { sharing_mode: "new", oops_window_seconds: 60 }, since: SINCE },
  ];
  const defaults: Array<Mode | undefined> = [undefined, "selected", "new"];
  const roles: Role[] = ["owner", "admin", "member"];
  const overrideSets: Array<readonly ("owner" | "admin")[] | undefined> = [undefined, ["owner"], ["owner", "admin"]];

  for (const stored of storedCases) {
    const source = row(stored.settings, stored.since);
    const v1 = capturePolicyFromRow(source);
    const v2 = workspacePolicyFromRow(source);
    const v1Before = structuredClone(v1);
    const v2Before = structuredClone(v2);
    // The served (oops-projected) settings, without sharing_mode.
    const { sharing_mode: storedMode, ...others } = v1.settings;
    for (const defaultSharingMode of defaults) {
      for (const overrideRoles of overrideSets) {
        const deployment: SharingDeployment = { defaultSharingMode, overrideRoles };
        for (const role of roles) {
          const label = `${stored.name} default=${defaultSharingMode} overrides=${overrideRoles} role=${role}`;
          const overridden = overrideRoles?.includes(role as "owner" | "admin") ?? false;
          const effective = storedMode ?? defaultSharingMode;

          const served = capturePolicyForCaller(v1, role, deployment);
          const expectedV1: CapturePolicy = overridden
            ? { version: 1, revision: v1.revision, settings: others }
            : {
              version: 1,
              revision: v1.revision,
              settings: effective === undefined ? others : { sharing_mode: effective, ...others },
              ...(storedMode === "new" ? { sharing_mode_since: SINCE } : {}),
            };
          assert.deepEqual(served, expectedV1, label);
          assert.equal(served.revision, stored.settings === null ? 1 : 4, label);
          assert.equal(JSON.stringify(served).includes("null"), false, label);
          assert.equal(Object.hasOwn(served.settings, "sharing_mode"), !overridden && effective !== undefined, label);
          assert.equal(Object.hasOwn(served, "sharing_mode_since"), !overridden && storedMode === "new", label);

          const servedV2 = workspacePolicyForCaller(v2, role, deployment);
          assert.equal(servedV2.revision, stored.settings === null ? 1 : 7, label);
          assert.deepEqual(servedV2.sections.capture, overridden
            ? { locked: others, defaults: effective === undefined ? {} : { sharing_mode: effective } }
            : { locked: effective === undefined ? others : { sharing_mode: effective, ...others }, defaults: {} }, label);
          // Every other part of the document is unchanged.
          assert.deepEqual({ ...servedV2, sections: { ...servedV2.sections, capture: null } },
            { ...v2, sections: { ...v2.sections, capture: null } }, label);
          assert.deepEqual(Object.keys(servedV2.sections), ["capture", "spawn", "join", "delivery", "analytics"], label);
        }
      }
    }
    // Never mutated.
    assert.deepEqual(v1, v1Before, stored.name);
    assert.deepEqual(v2, v2Before, stored.name);
  }
});

test("the 900 s oops window projection still applies for every caller", () => {
  const v1 = capturePolicyFromRow(row({ upload_control: "operator" }));
  const deployment: SharingDeployment = { defaultSharingMode: "selected", overrideRoles: ["owner"] };
  assert.deepEqual(capturePolicyForCaller(v1, "member", deployment).settings,
    { sharing_mode: "selected", upload_control: "operator", oops_window_seconds: 900 });
  assert.deepEqual(capturePolicyForCaller(v1, "owner", deployment).settings,
    { upload_control: "operator", oops_window_seconds: 900 });
  const v2 = workspacePolicyFromRow(row({ upload_control: "operator" }));
  assert.deepEqual(workspacePolicyForCaller(v2, "owner", deployment).sections.capture, {
    locked: { upload_control: "operator", oops_window_seconds: 900 },
    defaults: { sharing_mode: "selected" },
  });
});

test("unknown or missing roles are locked; role names compare case-sensitively", () => {
  const v1 = capturePolicyFromRow(null);
  const deployment: SharingDeployment = { defaultSharingMode: "all", overrideRoles: ["owner", "admin"] };
  for (const role of [undefined, null, "", "Owner", "ADMIN", "staff"]) {
    assert.deepEqual(capturePolicyForCaller(v1, role, deployment).settings, { sharing_mode: "all" }, String(role));
  }
});

test("an override role with nothing to remove gets the same object back", () => {
  const deployment: SharingDeployment = { overrideRoles: ["owner"] };
  const v1 = capturePolicyFromRow(row({ upload_control: "user" }));
  const v2 = workspacePolicyFromRow(row({ upload_control: "user" }));
  assert.equal(capturePolicyForCaller(v1, "owner", deployment), v1);
  assert.equal(workspacePolicyForCaller(v2, "owner", deployment), v2);
});

// ---- HTTP ----

async function setup(t: TestContext, deployment: Pick<SelfhostConfig, "defaultSharingMode" | "sharingModeOverrideRoles">) {
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
    ...deployment,
  };
  const store = new ControlPlaneStore(database, KEYRING, 0);
  const admin = createAdminModule({ config, database, keyring: KEYRING });
  control.on("request", createApp({ config, store, admin }));
  t.after(async () => {
    await close(control);
    await database.close();
  });

  const org = await request(origin, "/api/v1/organizations", {
    method: "POST", token: BOOTSTRAP, body: { name: "Acme", ownerEmail: "owner@acme.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const organizationId = org.body.id as string;
  const created = await request(origin, `/api/v1/organizations/${organizationId}/workspaces`, {
    method: "POST", token: BOOTSTRAP, body: { name: "primary", relaycastApiKey: "rk_primary" },
  });
  assert.equal(created.status, 201);
  const workspaceId = created.body.id as string;
  const addMember = async (email: string, role: Role) => {
    const added = await request(origin, `/api/v1/organizations/${organizationId}/memberships`, {
      method: "POST", token: BOOTSTRAP, body: { email, name: email, role },
    });
    assert.equal(added.status, 200);
    return added.body.userId as string;
  };
  const login = async (userId: string) => {
    const started = await request(origin, "/api/v1/auth/device/start", { method: "POST", body: {} });
    const approved = await request(origin, "/api/v1/auth/device/approve", {
      method: "POST", token: BOOTSTRAP,
      body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: workspaceId },
    });
    assert.equal(approved.status, 200);
    const issued = await request(origin, "/api/v1/auth/device/token", {
      method: "POST", body: { device_code: started.body.device_code },
    });
    assert.equal(issued.status, 200);
    return issued.body.access_token as string;
  };
  const ownerToken = await login(org.body.owner.id as string);
  const adminToken = await login(await addMember("admin@acme.test", "admin"));
  const memberToken = await login(await addMember("member@acme.test", "member"));
  const accessMe = (token: string) => request(origin, `/api/v1/workspaces/${workspaceId}/access/me`, { token });
  const capturePath = `/api/v1/organizations/${organizationId}/capture-policy`;
  const workspacePolicyPath = `/api/v1/organizations/${organizationId}/workspace-policy`;
  const introspect = (token: string) => request(origin, "/internal/v1/auth/introspect", {
    method: "POST", token: INTROSPECT_SECRET, body: { token, aud: HISTORY, workspace: workspaceId },
  });
  const exchangeFor = async (email: string) => {
    const minted = await request(origin, `/api/v1/workspaces/${workspaceId}/deployment-api-tokens`, {
      method: "POST", token: ownerToken, body: { label: "rollout", purpose: "desktop-enrollment", email },
    });
    assert.equal(minted.status, 201, `mint ${email}: ${minted.body?.error ?? ""}`);
    const exchanged = await request(origin, "/api/v1/auth/enrollment/token", {
      method: "POST",
      body: { enrollment_key: minted.body.accessToken, client_name: "Agent Relay Desktop", desktop_host_name: "build-01" },
    });
    assert.equal(exchanged.status, 200);
    return exchanged.body;
  };
  return {
    origin, database, organizationId, workspaceId, ownerToken, adminToken, memberToken,
    accessMe, capturePath, workspacePolicyPath, introspect, exchangeFor,
  };
}

const capture = (locked: Record<string, unknown>, defaults: Record<string, unknown> = {}) => ({ locked, defaults });

test("route: default selected, override owner: members locked, owner unlocked, org routes show what is stored", async (t) => {
  const env = await setup(t, { defaultSharingMode: "selected", sharingModeOverrideRoles: ["owner"] });

  const member = await env.accessMe(env.memberToken);
  assert.equal(member.status, 200);
  assert.deepEqual(member.body.policy, { version: 1, revision: 1, settings: { sharing_mode: "selected" } });
  assert.equal(member.body.workspace_policy.revision, 1);
  assert.deepEqual(member.body.workspace_policy.sections.capture, capture({ sharing_mode: "selected" }));
  for (const name of ["spawn", "join", "delivery", "analytics"]) {
    assert.deepEqual(member.body.workspace_policy.sections[name], EMPTY_SECTION, name);
  }

  // An admin is not in the override roles here: locked like a member.
  const adminMe = await env.accessMe(env.adminToken);
  assert.deepEqual(adminMe.body.policy.settings, { sharing_mode: "selected" });
  assert.deepEqual(adminMe.body.workspace_policy.sections.capture, capture({ sharing_mode: "selected" }));

  const owner = await env.accessMe(env.ownerToken);
  assert.deepEqual(owner.body.policy, { version: 1, revision: 1, settings: {} });
  assert.deepEqual(owner.body.workspace_policy.sections.capture, capture({}, { sharing_mode: "selected" }));
  assert.equal(owner.body.workspace_policy.revision, 1);

  // The editing surface returns only what is stored.
  const stored = await request(env.origin, env.capturePath, { token: env.ownerToken });
  assert.equal(stored.status, 200);
  assert.deepEqual(stored.body, { version: 1, revision: 1, settings: {} });
  const storedV2 = await request(env.origin, env.workspacePolicyPath, { token: env.ownerToken });
  assert.equal(storedV2.status, 200);
  assert.deepEqual(storedV2.body.sections.capture, EMPTY_SECTION);
  assert.equal(storedV2.body.revision, 1);

  // Introspection: the same projection by the token's role.
  const memberAnswer = await env.introspect(env.memberToken);
  assert.equal(memberAnswer.status, 200);
  assert.equal(memberAnswer.body.active, true);
  assert.deepEqual(memberAnswer.body.capture_policy, { version: 1, revision: 1, settings: { sharing_mode: "selected" } });
  assert.deepEqual(memberAnswer.body.workspace_policy, { revision: 1 });
  const ownerAnswer = await env.introspect(env.ownerToken);
  assert.equal(ownerAnswer.body.active, true);
  assert.deepEqual(ownerAnswer.body.capture_policy, { version: 1, revision: 1, settings: {} });

  // The organization saves its own mode: it wins for members, the owner stays unlocked.
  const saved = await request(env.origin, env.capturePath, {
    method: "PUT", token: env.ownerToken, body: { settings: { sharing_mode: "new", user_retroactive_delete: false } },
  });
  assert.equal(saved.status, 200);
  assert.deepEqual(saved.body.settings, { sharing_mode: "new", user_retroactive_delete: false });
  assert.ok(saved.body.sharing_mode_since);
  const since = saved.body.sharing_mode_since as string;

  const memberAfter = await env.accessMe(env.memberToken);
  assert.deepEqual(memberAfter.body.policy, {
    version: 1, revision: 2, settings: { sharing_mode: "new", user_retroactive_delete: false }, sharing_mode_since: since,
  });
  assert.deepEqual(memberAfter.body.workspace_policy.sections.capture,
    capture({ sharing_mode: "new", user_retroactive_delete: false }));
  assert.equal(memberAfter.body.workspace_policy.revision, 2);

  const ownerAfter = await env.accessMe(env.ownerToken);
  assert.deepEqual(ownerAfter.body.policy, { version: 1, revision: 2, settings: { user_retroactive_delete: false } });
  assert.deepEqual(ownerAfter.body.workspace_policy.sections.capture,
    capture({ user_retroactive_delete: false }, { sharing_mode: "new" }));
  assert.equal(ownerAfter.body.workspace_policy.revision, 2);

  assert.deepEqual((await env.introspect(env.memberToken)).body.capture_policy, memberAfter.body.policy);
  assert.deepEqual((await env.introspect(env.ownerToken)).body.capture_policy, ownerAfter.body.policy);
  assert.deepEqual((await request(env.origin, env.capturePath, { token: env.ownerToken })).body, saved.body);

  // A capture key in `defaults` is still refused on write, even the served one.
  const refused = await request(env.origin, env.workspacePolicyPath, {
    method: "PUT", token: env.ownerToken, body: { sections: ownerAfter.body.workspace_policy.sections },
  });
  assert.equal(refused.status, 400);
  assert.equal(refused.body.error, "invalid_policy");
});

test("route: enrollment key exchange serves the workspace policy by the bound user's role", async (t) => {
  const env = await setup(t, { defaultSharingMode: "all", sharingModeOverrideRoles: ["owner", "admin"] });
  const member = await env.exchangeFor("member@acme.test");
  assert.equal(member.policy_revision, 1);
  assert.equal(member.workspace_policy.revision, 1);
  assert.deepEqual(member.workspace_policy.sections.capture, capture({ sharing_mode: "all" }));
  const adminAnswer = await env.exchangeFor("admin@acme.test");
  assert.deepEqual(adminAnswer.workspace_policy.sections.capture, capture({}, { sharing_mode: "all" }));
  const owner = await env.exchangeFor("owner@acme.test");
  assert.deepEqual(owner.workspace_policy.sections.capture, capture({}, { sharing_mode: "all" }));
  // The exchanged sessions read the same through access/me.
  assert.deepEqual((await env.accessMe(member.access_token)).body.workspace_policy, member.workspace_policy);
  assert.deepEqual((await env.accessMe(owner.access_token)).body.workspace_policy, owner.workspace_policy);
});

test("route: both values unset, access/me serves exactly the stored policies to every role", async (t) => {
  const env = await setup(t, {});
  const saved = await request(env.origin, env.capturePath, {
    method: "PUT", token: env.ownerToken, body: { settings: { sharing_mode: "selected" } },
  });
  assert.equal(saved.status, 200);
  const storedV2 = (await request(env.origin, env.workspacePolicyPath, { token: env.ownerToken })).body;
  for (const token of [env.ownerToken, env.adminToken, env.memberToken]) {
    const me = await env.accessMe(token);
    assert.deepEqual(me.body.policy, saved.body);
    assert.deepEqual(me.body.workspace_policy, storedV2);
    assert.deepEqual((await env.introspect(token)).body.capture_policy, saved.body);
  }
});
