import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { FlowRunRelayfileCredentials } from "../src/flows/relayfile-credentials.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

/**
 * Relayfile verifies a Flows run credential (`sh_fr_`) through the same
 * POST /internal/v1/auth/introspect contract as every other bearer.
 */

const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const FILES = "https://files.selfhosted.test";
const HISTORY = "https://history.selfhosted.test";
const TTL_MS = 60 * 60 * 1_000;

async function setup(t: TestContext) {
  const database = new PGliteDatabase();
  await migrate(database);
  const config: SelfhostConfig = {
    databaseUrl: "unused", publicBaseUrl: "https://control.selfhosted.test",
    relaycastUrl: "http://relaycast.internal", relaycastPublicUrl: "https://relay.selfhosted.test",
    relayhistoryUrl: "http://history.internal", relayhistoryPublicUrl: HISTORY,
    sessionReadApi: { url: "http://history.internal", publicUrl: HISTORY, secret: "session-read-secret-".repeat(2) },
    introspectSecret: INTROSPECT_SECRET,
    introspectAudiences: [FILES],
    bootstrapToken: "bootstrap-secret-".repeat(3),
    encryptionKeyring: { active: { id: "test", key: Buffer.alloc(32, 3) } },
    internalServiceToken: null, port: 3000, host: "127.0.0.1",
    oauthRedirectUrl: "https://control.selfhosted.test/callback", dashboardUrl: "https://app.selfhosted.test",
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0, { tenancy: "multi" });
  const org = await store.createOrganization({ name: "Tenant", ownerEmail: "owner@example.test", ownerName: "Owner" });
  const alpha = await store.createWorkspace({ organizationId: org.id, name: "Alpha", relaycastApiKey: "rk_alpha" });
  const beta = await store.createWorkspace({ organizationId: org.id, name: "Beta", relaycastApiKey: "rk_beta" });
  let clock = new Date("2026-11-09T12:00:00.000Z");
  const credentials = new FlowRunRelayfileCredentials(database, () => clock, {
    ttlMs: TTL_MS,
    workerRelayfileUrl: `${FILES}/fs`,
    audiences: () => [FILES, HISTORY],
  });
  const server = createServer(createApp({ config, store, flowRelayfileCredentials: credentials }));
  const origin = await listen(server);
  t.after(async () => { await close(server); await database.close(); });
  const introspect = (body: Record<string, unknown>) =>
    request(origin, "/internal/v1/auth/introspect", { method: "POST", token: INTROSPECT_SECRET, body });
  const issue = (runId = randomUUID()) => credentials.issue({
    workspaceId: alpha.id, runId, mountPaths: [`/workflows/runs/${runId}`, "/github/acme/repo"], readOnly: true,
  });
  return {
    database, org, alpha, beta, credentials, introspect, issue,
    advance: (ms: number) => { clock = new Date(clock.getTime() + ms); },
  };
}

test("an active sh_fr_ credential introspects as the run's agent with its path scopes", async (t) => {
  const env = await setup(t);
  const runId = randomUUID();
  const issued = await env.issue(runId);
  const answer = await env.introspect({ token: issued.relayfileToken, aud: `${FILES}/any/path`, workspace: env.alpha.id });
  assert.equal(answer.status, 200);
  const issuedAt = Date.parse("2026-11-09T12:00:00.000Z") / 1_000;
  assert.deepEqual(answer.body, {
    active: true,
    sub: issued.credentialId,
    email: null,
    principal_type: "agent",
    agent_name: `flows-run-${runId}`,
    machine_id: null,
    org: env.org.id,
    workspace: env.alpha.id,
    scopes: [
      `relayfile:fs:read:/workflows/runs/${runId}`,
      `relayfile:fs:read:/workflows/runs/${runId}/*`,
      "relayfile:fs:read:/github/acme/repo",
      "relayfile:fs:read:/github/acme/repo/*",
    ],
    aud: FILES,
    iat: issuedAt,
    exp: issuedAt + TTL_MS / 1_000,
    token_id: issued.credentialId,
  });
  // The workspace is optional for the caller.
  assert.equal((await env.introspect({ token: issued.relayfileToken, aud: FILES })).body.active, true);
});

test("sh_fr_ credentials name one inactive reason each", async (t) => {
  const env = await setup(t);
  const inactive = async (body: Record<string, unknown>, reason: string) => {
    const answer = await env.introspect(body);
    assert.equal(answer.status, 200, reason);
    assert.deepEqual(answer.body, { active: false, reason }, reason);
  };
  await inactive({ token: `sh_fr_${"x".repeat(43)}`, aud: FILES }, "unknown");

  const live = await env.issue();
  await inactive({ token: live.relayfileToken, aud: HISTORY }, "audience");
  await inactive({ token: live.relayfileToken, aud: "https://elsewhere.selfhosted.test" }, "audience");
  await inactive({ token: live.relayfileToken, aud: FILES, workspace: env.beta.id }, "workspace");
  await inactive({ token: live.relayfileToken, aud: FILES, workspace: env.alpha.id, machine: "node-1" }, "machine_not_owned");

  const runId = randomUUID();
  const revoked = await env.issue(runId);
  await env.credentials.revokeForRun(runId);
  await inactive({ token: revoked.relayfileToken, aud: FILES }, "revoked");

  const expiring = await env.issue();
  env.advance(TTL_MS);
  await inactive({ token: expiring.relayfileToken, aud: FILES }, "expired");
  // Revocation wins over expiry, matching the other token kinds.
  await inactive({ token: revoked.relayfileToken, aud: FILES }, "revoked");
});

test("no sh_fr_ token or hash reaches the audit trail", async (t) => {
  const env = await setup(t);
  const tokens = [(await env.issue()).relayfileToken, (await env.issue()).relayfileToken];
  const rows = (await env.database.query("SELECT * FROM admin_audit_events")).rows;
  assert.equal(rows.length, 2);
  const everything = JSON.stringify(rows);
  for (const token of tokens) assert.equal(everything.includes(token), false);
  assert.equal(everything.includes("sh_fr_"), false);
  const hashes = (await env.database.query<{ token_hash: string }>(
    "SELECT token_hash FROM flow_run_relayfile_credentials",
  )).rows.map((row) => row.token_hash);
  for (const hash of hashes) assert.equal(everything.includes(hash), false);
});
