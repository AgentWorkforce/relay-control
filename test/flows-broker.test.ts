import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import { CodingAgentError } from "../src/admin/coding-agents.js";
import type { AdminModule } from "../src/admin/routes.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";
import { testLicense } from "./support/license.js";

const secret = "broker-secret-that-is-at-least-32-bytes";
const PREFIX = "/internal/v1/flows/credentials";

async function setup(t: TestContext, options: { secret?: string | null; licensed?: boolean } = {}) {
  const database = new PGliteDatabase();
  await migrate(database);
  const config: SelfhostConfig = {
    databaseUrl: "unused", publicBaseUrl: "https://control.selfhosted.company",
    relaycastUrl: "http://relaycast.internal", relaycastPublicUrl: "https://relay.selfhosted.company",
    relayhistoryUrl: "http://history.internal", relayhistoryPublicUrl: "https://history.selfhosted.company",
    relayauthUrl: null, relayauthApiKey: null, bootstrapToken: "bootstrap-secret-".repeat(3),
    encryptionKeyring: { active: { id: "test", key: Buffer.alloc(32, 5) } },
    internalServiceToken: "service-secret-".repeat(3), port: 3000, host: "127.0.0.1",
    oauthRedirectUrl: "https://control.selfhosted.company/callback", dashboardUrl: "https://app.selfhosted.company",
    relayfileControlBrokerSecret: options.secret === undefined ? secret : options.secret,
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0, { tenancy: "multi" });
  const org = await store.createOrganization({ name: "Tenant", ownerEmail: "owner@example.test", ownerName: "Owner" });
  const workspace = await store.createWorkspace({ organizationId: org.id, name: "Alpha", relaycastApiKey: "fake-relaycast-key" });
  const calls: unknown[][] = [];
  let issued: unknown = { ref: "sh_clicred_x", expiresAt: "2026-11-09T00:00:00.000Z", credentials: [] };
  let failure: Error | null = null;
  const record = (name: string, result: unknown) => async (...args: unknown[]) => {
    calls.push([name, ...args]);
    if (failure) throw failure;
    return typeof result === "function" ? result() : result;
  };
  const admin = {
    handle: async () => false,
    logins: {
      issueRunReference: record("issue", () => issued),
      readForRun: record("read", { files: [], skipped: [] }),
      writeBack: record("write", { updated: true }),
      revokeRun: record("revoke", undefined),
    },
    runtimeEnvironment: record("environment", { workspaceId: workspace.id, env: { A: "1" }, secretEnvNames: ["A"], skipped: [], integrationErrors: [] }),
  } as unknown as AdminModule;
  const app = createApp({ config, store, admin, ...(options.licensed === false ? {} : { license: testLicense() }) });
  const server = createServer(app);
  const origin = await listen(server);
  t.after(async () => { await close(server); await database.close(); });
  const post = (action: string, body: unknown, token: string | undefined = secret) =>
    request(origin, `${PREFIX}/${action}`, { method: "POST", ...(token ? { token } : {}), body });
  const get = (action: string, token = secret) => request(origin, `${PREFIX}/${action}`, { token });
  return { database, workspace, calls, origin, post, get, setIssued: (v: unknown) => { issued = v; }, setFailure: (e: Error | null) => { failure = e; } };
}

test("the broker routes do not exist without their secret", async (t) => {
  const env = await setup(t, { secret: null });
  assert.equal((await env.post("revoke", { runId: randomUUID() })).status, 404);
  assert.deepEqual(env.calls, []);
});

test("only the broker secret reaches the store, and never through /cloud", async (t) => {
  const env = await setup(t);
  const body = { runId: randomUUID() };
  assert.equal((await env.post("revoke", body, "")).status, 401);
  assert.equal((await env.post("revoke", body, "wrong-secret-wrong-secret-wrong-secret")).status, 401);
  assert.equal((await request(env.origin, `/cloud${PREFIX}/revoke`, { method: "POST", token: secret, body })).status, 404);
  assert.deepEqual(env.calls, []);
});

test("an installation without Flows refuses the broker", async (t) => {
  const env = await setup(t, { licensed: false });
  const answer = await env.post("revoke", { runId: randomUUID() });
  assert.equal(answer.status, 403);
  assert.deepEqual(env.calls, []);
});

test("each operation passes its bound identifiers through", async (t) => {
  const env = await setup(t);
  const runId = randomUUID();
  const credentialId = randomUUID();
  const issue = await env.post("references", { workspaceId: env.workspace.id, runId });
  assert.equal(issue.status, 200);
  assert.equal(issue.body.ref, "sh_clicred_x");
  assert.equal(issue.headers.get("cache-control"), "no-store");
  assert.equal((await env.post("read", { ref: "sh_clicred_x", runId })).status, 200);
  assert.deepEqual((await env.post("write-back", { ref: "sh_clicred_x", runId, credentialId, content: "file" })).body, { updated: true });
  assert.equal((await env.post("revoke", { runId })).status, 200);
  assert.deepEqual(env.calls, [
    ["issue", env.workspace.id, runId],
    ["read", "sh_clicred_x", runId],
    ["write", "sh_clicred_x", runId, credentialId, "file"],
    ["revoke", runId],
  ]);
});

test("a workspace without logins answers 204, and refusals keep their code", async (t) => {
  const env = await setup(t);
  env.setIssued(null);
  assert.equal((await env.post("references", { workspaceId: env.workspace.id, runId: randomUUID() })).status, 204);
  env.setFailure(new CodingAgentError(401, "unauthorized", "Credential reference is invalid or expired"));
  const refused = await env.post("read", { ref: "sh_clicred_x", runId: randomUUID() });
  assert.equal(refused.status, 401);
  assert.equal(refused.body.error, "unauthorized");
});

test("malformed requests are refused before the store", async (t) => {
  const env = await setup(t);
  assert.equal((await env.post("references", { workspaceId: "nope", runId: randomUUID() })).status, 400);
  assert.equal((await env.post("read", { ref: "x", runId: randomUUID(), extra: 1 })).status, 400);
  assert.equal((await env.post("revoke", {})).status, 400);
  assert.equal((await env.get("workspaces/nope/relaycast")).status, 400);
  assert.equal((await env.get("revoke")).status, 405);
  assert.equal((await env.post("unknown", {})).status, 404);
  assert.deepEqual(env.calls, []);
});

test("the Relaycast binding and environment are served per workspace", async (t) => {
  const env = await setup(t);
  const binding = await env.get(`workspaces/${env.workspace.id}/relaycast`);
  assert.equal(binding.status, 200);
  assert.equal(binding.body.relaycastApiKey, "fake-relaycast-key");
  assert.equal(typeof binding.body.relaycastWorkspaceId, "string");
  assert.equal((await env.get(`workspaces/${randomUUID()}/relaycast`)).status, 404);
  const environment = await env.get(`workspaces/${env.workspace.id}/environment`);
  assert.equal(environment.status, 200);
  assert.deepEqual(environment.body.env, { A: "1" });
  assert.deepEqual(env.calls.at(-1), ["environment", env.workspace.id, { kind: "service", subject: "relayfile-control" }, true]);
});

test("a credential reference can name a run this database has never seen", async (t) => {
  const env = await setup(t);
  await env.database.query(
    `INSERT INTO selfhost_cli_credential_refs (ref_hash, run_id, workspace_id, credential_ids, expires_at)
     VALUES ('hash', $1, $2, '{}', now() + interval '1 hour')`,
    [randomUUID(), env.workspace.id],
  );
});
