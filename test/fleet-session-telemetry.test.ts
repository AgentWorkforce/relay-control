import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { hashSecret } from "../src/crypto.js";
import {
  parseClientTelemetry,
  recordClientTelemetry,
} from "../src/sessions/client-telemetry.js";
import { seedTenant, startControlPlane } from "./flows-helpers.js";

type TelemetryRow = {
  client_version: string | null;
  client_platform: string | null;
  policy_revision_applied: number | null;
  policy_seen_at: Date | string | null;
};

const NONE = { clientVersion: null, clientPlatform: null, policyRevisionApplied: null };

test("parseClientTelemetry: plain and suffixed User-Agent, revision header", () => {
  assert.deepEqual(parseClientTelemetry({ "user-agent": "AgentRelayDesktop/1.4.2" }), {
    clientVersion: "1.4.2", clientPlatform: null, policyRevisionApplied: null,
  });
  assert.deepEqual(parseClientTelemetry({
    "user-agent": "AgentRelayDesktop/1.5.0-beta.3+build.7 (Darwin-arm64)",
    "x-agent-relay-policy-revision": "12",
  }), { clientVersion: "1.5.0-beta.3+build.7", clientPlatform: "darwin-arm64", policyRevisionApplied: 12 });
  // The product token may follow another one.
  assert.deepEqual(parseClientTelemetry({ "user-agent": "Mozilla/5.0 AgentRelayDesktop/2.0.0 (win32)" }), {
    clientVersion: "2.0.0", clientPlatform: "win32", policyRevisionApplied: null,
  });
  assert.deepEqual(parseClientTelemetry({}), NONE);
  // The uploader's capture-policy header is not this one.
  assert.deepEqual(parseClientTelemetry({ "x-agent-relay-capture-policy-revision": "4" }), NONE);
});

test("parseClientTelemetry: invalid or oversize values are ignored", () => {
  for (const userAgent of [
    "node",
    "agentrelaydesktop/1.0.0",
    "XAgentRelayDesktop/1.0.0",
    `AgentRelayDesktop/${"1".repeat(65)}`,
    "AgentRelayDesktop/1.0.0;rm",
    "AgentRelayDesktop/1.0_0",
    `AgentRelayDesktop/1.0.0 ${"x".repeat(600)}`,
  ]) {
    assert.equal(parseClientTelemetry({ "user-agent": userAgent }).clientVersion, null, userAgent);
  }
  // A valid version keeps; an invalid platform is dropped on its own.
  for (const platform of ["(mac os)", `(${"a".repeat(33)})`, "(linux/x64)", "()", "(é)"]) {
    const parsed = parseClientTelemetry({ "user-agent": `AgentRelayDesktop/1.0.0 ${platform}` });
    assert.equal(parsed.clientVersion, "1.0.0", platform);
    assert.equal(parsed.clientPlatform, null, platform);
  }
  assert.equal(
    parseClientTelemetry({ "user-agent": `AgentRelayDesktop/1 (${"a".repeat(32)})` }).clientPlatform,
    "a".repeat(32),
  );
  assert.equal(parseClientTelemetry({ "user-agent": `AgentRelayDesktop/${"1".repeat(64)}` }).clientVersion, "1".repeat(64));
});

test("parseClientTelemetry: revision bounds", () => {
  const revision = (value: string) =>
    parseClientTelemetry({ "x-agent-relay-policy-revision": value }).policyRevisionApplied;
  assert.equal(revision("0"), 0);
  assert.equal(revision(" 7 "), 7);
  assert.equal(revision("2147483647"), 2_147_483_647);
  for (const value of ["2147483648", "99999999999", "-1", "1.5", "1e3", "0x10", "", "abc", "+3"]) {
    assert.equal(revision(value), null, value);
  }
});

test("access/me records Desktop telemetry on a device-flow session, without no-op writes", async (t) => {
  const app = await startControlPlane();
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  const accessMe = `/api/v1/workspaces/${tenant.workspaceId}/access/me`;
  const row = async (token: string) => (await app.database.query<TelemetryRow>(
    `SELECT client_version, client_platform, policy_revision_applied, policy_seen_at
       FROM token_sessions WHERE access_token_hash = $1`,
    [hashSecret(token)],
  )).rows[0]!;
  const seen = (value: TelemetryRow) => new Date(value.policy_seen_at!).getTime();

  // No headers (an old client): 200, nothing written.
  const plain = await app.api(accessMe, { token: tenant.memberToken, headers: { "user-agent": "node" } });
  assert.equal(plain.status, 200);
  assert.deepEqual(await row(tenant.memberToken), {
    client_version: null, client_platform: null, policy_revision_applied: null, policy_seen_at: null,
  });

  const headers = { "user-agent": "AgentRelayDesktop/1.4.2 (darwin)", "x-agent-relay-policy-revision": "3" };
  const first = await app.api(accessMe, { token: tenant.memberToken, headers });
  assert.equal(first.status, 200);
  assert.equal(first.body.role, "member");
  const written = await row(tenant.memberToken);
  assert.equal(written.client_version, "1.4.2");
  assert.equal(written.client_platform, "darwin");
  assert.equal(written.policy_revision_applied, 3);
  assert.ok(written.policy_seen_at);

  // Identical read inside 10 minutes: no write, policy_seen_at unchanged.
  assert.equal((await app.api(accessMe, { token: tenant.memberToken, headers })).status, 200);
  assert.equal(seen(await row(tenant.memberToken)), seen(written));

  // A changed revision writes; a header that is now absent leaves its column.
  await app.database.query(
    "UPDATE token_sessions SET policy_seen_at = now() - interval '1 minute' WHERE access_token_hash = $1",
    [hashSecret(tenant.memberToken)],
  );
  const before = seen(await row(tenant.memberToken));
  const changed = await app.api(accessMe, {
    token: tenant.memberToken, headers: { "user-agent": "AgentRelayDesktop/1.4.2", "x-agent-relay-policy-revision": "4" },
  });
  assert.equal(changed.status, 200);
  const updated = await row(tenant.memberToken);
  assert.equal(updated.client_version, "1.4.2");
  assert.equal(updated.client_platform, "darwin");
  assert.equal(updated.policy_revision_applied, 4);
  assert.ok(seen(updated) > before);

  // Invalid values are ignored without an error and change nothing.
  const invalid = await app.api(accessMe, {
    token: tenant.memberToken,
    headers: { "user-agent": "AgentRelayDesktop/<script>", "x-agent-relay-policy-revision": "-2" },
  });
  assert.equal(invalid.status, 200);
  assert.equal(seen(await row(tenant.memberToken)), seen(updated));

  // Unchanged values older than 10 minutes refresh policy_seen_at.
  await app.database.query(
    "UPDATE token_sessions SET policy_seen_at = now() - interval '11 minutes' WHERE access_token_hash = $1",
    [hashSecret(tenant.memberToken)],
  );
  const current = { "user-agent": "AgentRelayDesktop/1.4.2 (darwin)", "x-agent-relay-policy-revision": "4" };
  const stale = seen(await row(tenant.memberToken));
  assert.equal((await app.api(accessMe, { token: tenant.memberToken, headers: current })).status, 200);
  assert.ok(seen(await row(tenant.memberToken)) > stale);

  // The store helper reports the skip directly.
  const sessionId = (await app.database.query<{ id: string }>(
    "SELECT id FROM token_sessions WHERE access_token_hash = $1",
    [hashSecret(tenant.memberToken)],
  )).rows[0]!.id;
  assert.equal(await recordClientTelemetry(app.database, sessionId, parseClientTelemetry(current)), false);
  assert.equal(await recordClientTelemetry(app.database, sessionId, NONE), false);
  assert.equal(await recordClientTelemetry(app.database, sessionId, {
    ...parseClientTelemetry(current), policyRevisionApplied: 5,
  }), true);

  // Other sessions are untouched.
  assert.equal((await row(tenant.ownerToken)).client_version, null);
});

test("access/me records telemetry on a Desktop sign-in pair, never on browser or handoff sessions", async (t) => {
  const app = await startControlPlane();
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  const accessMe = `/api/v1/workspaces/${tenant.workspaceId}/access/me`;
  const ownerId = (await app.database.query<{ id: string }>(
    "SELECT id FROM users WHERE email = 'owner@acme.test'",
  )).rows[0]!.id;
  const identity = { userId: ownerId, organizationId: tenant.organizationId, workspaceId: tenant.workspaceId };
  const headers = { "user-agent": "AgentRelayDesktop/1.4.2 (linux)", "x-agent-relay-policy-revision": "2" };
  const columns = async (sessionId: string) => (await app.database.query<TelemetryRow>(
    `SELECT client_version, client_platform, policy_revision_applied, policy_seen_at
       FROM token_sessions WHERE id = $1`,
    [sessionId],
  )).rows[0]!;
  const empty = { client_version: null, client_platform: null, policy_revision_applied: null, policy_seen_at: null };

  // Desktop pair (desktop:workspaces): recorded.
  const desktop = await app.store.issueDesktopSession({ ...identity, tokenFamilyId: randomUUID() });
  assert.equal((await app.api(accessMe, { token: desktop.accessToken, headers })).status, 200);
  const desktopRow = await columns(desktop.sessionId);
  assert.equal(desktopRow.client_version, "1.4.2");
  assert.equal(desktopRow.client_platform, "linux");
  assert.equal(desktopRow.policy_revision_applied, 2);

  // Browser account session: read works, nothing written.
  const browser = await app.database.transaction((tx) => app.store.issueBrowserSession(tx, {
    ...identity, label: "Browser sign-in",
  }));
  assert.equal((await app.api(accessMe, { token: browser.accessToken, headers })).status, 200);
  assert.deepEqual(await columns(browser.sessionId), empty);

  // Unredeemed Desktop browser handoff: nothing written.
  const handoff = await app.store.issueDesktopHandoff({ ...identity, codeChallenge: "c".repeat(43) });
  assert.equal((await app.api(accessMe, { token: handoff.accessToken, headers })).status, 200);
  assert.deepEqual(await columns(handoff.sessionId), empty);

  // Non-session credentials never reach the write: refused before it, and no row changed.
  assert.equal((await app.api(accessMe, { token: "sh_wk_not-a-session", headers })).status, 401);
  assert.equal((await app.api(accessMe, { token: "sh_sr_not-a-session", headers })).status, 401);
  const touched = await app.database.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM token_sessions WHERE policy_seen_at IS NOT NULL",
  );
  assert.equal(touched.rows[0]!.n, 1);
});

test("access/me still answers when the telemetry write fails", async (t) => {
  const app = await startControlPlane();
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  await app.database.query("ALTER TABLE token_sessions DROP COLUMN client_platform");
  const warn = t.mock.method(console, "warn", () => {});
  const response = await app.api(`/api/v1/workspaces/${tenant.workspaceId}/access/me`, {
    token: tenant.memberToken,
    headers: { "user-agent": "AgentRelayDesktop/1.4.2 (darwin)", "x-agent-relay-policy-revision": "1" },
  });
  assert.equal(response.status, 200);
  assert.equal(response.body.role, "member");
  assert.ok(warn.mock.calls.some((call) => String(call.arguments[0]).includes("client telemetry write failed")));
});
