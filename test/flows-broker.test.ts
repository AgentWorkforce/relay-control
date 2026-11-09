import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import { CodingAgentError } from "../src/admin/coding-agents.js";
import type { AdminModule } from "../src/admin/routes.js";
import type { SelfhostConfig } from "../src/config.js";
import { FlowRunRelayfileCredentials } from "../src/flows/relayfile-credentials.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";
import { testFeatures } from "./support/features.js";

const secret = "broker-secret-that-is-at-least-32-bytes";
const PREFIX = "/internal/v1/flows/credentials";

const FILES = "https://files.selfhosted.company";
const TTL_MS = 2 * 60 * 60 * 1_000;

async function setup(t: TestContext, options: {
  secret?: string | null;
  flows?: boolean;
  workerRelayfileUrl?: string;
  audiences?: string[];
} = {}) {
  const database = new PGliteDatabase();
  await migrate(database);
  const config: SelfhostConfig = {
    databaseUrl: "unused", publicBaseUrl: "https://control.selfhosted.company",
    relaycastUrl: "http://relaycast.internal", relaycastPublicUrl: "https://relay.selfhosted.company",
    relayhistoryUrl: "http://history.internal", relayhistoryPublicUrl: "https://history.selfhosted.company",
    sessionReadApi: { url: "http://history.internal", publicUrl: "https://history.selfhosted.company", secret: "session-read-secret-".repeat(2) },
    bootstrapToken: "bootstrap-secret-".repeat(3),
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
  let clock = new Date("2026-11-09T12:00:00.000Z");
  const relayfile = new FlowRunRelayfileCredentials(database, () => clock, {
    ttlMs: TTL_MS,
    workerRelayfileUrl: options.workerRelayfileUrl ?? `${FILES}/`,
    audiences: () => options.audiences ?? [FILES, "https://history.selfhosted.company"],
  });
  const app = createApp({
    config, store, admin, flowRelayfileCredentials: relayfile,
    ...(options.flows === false ? {} : { features: testFeatures() }),
  });
  const server = createServer(app);
  const origin = await listen(server);
  t.after(async () => { await close(server); await database.close(); });
  const post = (action: string, body: unknown, token: string | undefined = secret) =>
    request(origin, `${PREFIX}/${action}`, { method: "POST", ...(token ? { token } : {}), body });
  const get = (action: string, token = secret) => request(origin, `${PREFIX}/${action}`, { token });
  return {
    database, workspace, calls, origin, post, get, relayfile,
    now: () => clock, advance: (ms: number) => { clock = new Date(clock.getTime() + ms); },
    setIssued: (v: unknown) => { issued = v; }, setFailure: (e: Error | null) => { failure = e; } };
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
  const env = await setup(t, { flows: false });
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
    `INSERT INTO cli_credential_refs (ref_hash, run_id, workspace_id, credential_ids, expires_at)
     VALUES ('hash', $1, $2, '{}', now() + interval '1 hour')`,
    [randomUUID(), env.workspace.id],
  );
});

test("relayfile issues a run-scoped sh_fr_ credential with exact scopes", async (t) => {
  const env = await setup(t);
  const runId = randomUUID();
  const mountPaths = [`/workflows/runs/${runId}`, "/github/acme/repo"];
  const answer = await env.post("relayfile", { workspaceId: env.workspace.id, runId, mountPaths });
  assert.equal(answer.status, 200);
  assert.equal(answer.headers.get("cache-control"), "no-store");
  assert.match(answer.body.relayfileToken, /^sh_fr_[A-Za-z0-9_-]{43}$/);
  assert.deepEqual(answer.body.relayfileMountPaths, mountPaths);
  assert.equal(answer.body.aud, FILES);
  assert.equal(Date.parse(answer.body.relayfileTokenExpiresAt), env.now().getTime() + TTL_MS);
  assert.deepEqual(answer.body.scopes, [
    `relayfile:fs:read:/workflows/runs/${runId}`,
    `relayfile:fs:read:/workflows/runs/${runId}/*`,
    `relayfile:fs:write:/workflows/runs/${runId}`,
    `relayfile:fs:write:/workflows/runs/${runId}/*`,
    "relayfile:fs:read:/github/acme/repo",
    "relayfile:fs:read:/github/acme/repo/*",
    "relayfile:fs:write:/github/acme/repo",
    "relayfile:fs:write:/github/acme/repo/*",
  ]);
  const looked = await env.relayfile.introspect(answer.body.relayfileToken);
  assert.equal(looked?.credentialId, answer.body.credentialId);
  assert.equal(looked?.runId, runId);
  const readOnly = await env.post("relayfile", {
    workspaceId: env.workspace.id, runId: randomUUID(), mountPaths: ["/workflows/schedules/nightly.sync"], readOnly: true,
  });
  assert.equal(readOnly.status, 200);
  assert.deepEqual(readOnly.body.scopes, [
    "relayfile:fs:read:/workflows/schedules/nightly.sync",
    "relayfile:fs:read:/workflows/schedules/nightly.sync/*",
  ]);
  // The audit trail names the credential and run, never the token.
  const audit = await env.database.query<{ action: string; target: string; actor_id: string }>(
    "SELECT action, target, actor_id FROM admin_audit_events WHERE action = 'flows.relayfile_credential.issue'",
  );
  assert.equal(audit.rows.length, 2);
  const row = audit.rows.find((entry) => entry.target.includes(runId))!;
  assert.ok(row.target.includes(answer.body.credentialId));
  assert.ok(row.target.includes(answer.body.relayfileTokenExpiresAt));
  assert.equal(row.actor_id, "relayfile-control");
  const everything = JSON.stringify((await env.database.query("SELECT * FROM admin_audit_events")).rows);
  assert.equal(everything.includes(answer.body.relayfileToken), false);
  assert.equal(everything.includes(readOnly.body.relayfileToken), false);
  assert.equal(everything.includes("sh_fr_"), false);
});

test("relayfile refuses mount paths outside the rules", async (t) => {
  const env = await setup(t);
  const runId = randomUUID();
  const root = `/workflows/runs/${runId}`;
  const refused = async (mountPaths: unknown) => {
    const answer = await env.post("relayfile", { workspaceId: env.workspace.id, runId, mountPaths });
    assert.equal(answer.status, 400, JSON.stringify(mountPaths));
    assert.equal(answer.body.error, "invalid_mount_paths", JSON.stringify(mountPaths));
  };
  await refused([`workflows/runs/${runId}`]);
  await refused([root, "/github/../secrets"]);
  await refused([`${root}/`]);
  await refused([root, "/github/*"]);
  await refused([root, "/github/./repo"]);
  await refused([root, "/github//repo"]);
  await refused([root, "/github/a b"]);
  await refused([root, `/${"a".repeat(512)}`]);
  await refused([`/workflows/runs/${randomUUID()}`]);
  await refused(["/github/acme/repo", root]);
  await refused(["/workflows/schedules/.hidden"]);
  await refused([root, ...Array.from({ length: 16 }, (_, index) => `/p/${index}`)]);
  await refused([]);
  const malformed = await env.post("relayfile", { workspaceId: env.workspace.id, runId, mountPaths: [root], extra: 1 });
  assert.equal(malformed.status, 400);
  assert.equal(malformed.body.error, "invalid_request");
  const sixteen = await env.post("relayfile", {
    workspaceId: env.workspace.id, runId, mountPaths: [root, ...Array.from({ length: 15 }, (_, index) => `/p/${index}`)],
  });
  assert.equal(sixteen.status, 200);
});

test("relayfile is not configured without a worker Relayfile URL or introspection", async (t) => {
  for (const options of [{ workerRelayfileUrl: "" }, { audiences: [] }]) {
    const env = await setup(t, options);
    const runId = randomUUID();
    const answer = await env.post("relayfile", { workspaceId: env.workspace.id, runId, mountPaths: [`/workflows/runs/${runId}`] });
    assert.equal(answer.status, 404);
    assert.equal(answer.body.error, "relayfile_not_configured");
  }
});

test("relayfile refuses an audience introspection would not accept, or a mismatched requested aud", async (t) => {
  const env = await setup(t, { audiences: ["https://history.selfhosted.company"] });
  const runId = randomUUID();
  const body = { workspaceId: env.workspace.id, runId, mountPaths: [`/workflows/runs/${runId}`] };
  const answer = await env.post("relayfile", body);
  assert.equal(answer.status, 409);
  assert.equal(answer.body.error, "relayfile_audience_not_accepted");
  assert.match(answer.body.message, /SELFHOST_FLOWS_WORKER_RELAYFILE_URL/);
  assert.match(answer.body.message, /SELFHOST_INTROSPECT_AUDIENCES/);

  const accepted = await setup(t);
  const ok = { workspaceId: accepted.workspace.id, runId, mountPaths: [`/workflows/runs/${runId}`] };
  const matching = await accepted.post("relayfile", { ...ok, aud: "HTTPS://files.selfhosted.company:443/any/path" });
  assert.equal(matching.status, 200);
  assert.equal(matching.body.aud, FILES);
  const mismatched = await accepted.post("relayfile", { ...ok, aud: "https://elsewhere.selfhosted.company" });
  assert.equal(mismatched.status, 409);
  assert.equal(mismatched.body.error, "relayfile_audience_not_accepted");
  assert.match(mismatched.body.message, /does not match/);
  assert.doesNotMatch(mismatched.body.message, /SELFHOST_INTROSPECT_AUDIENCES/);
  assert.equal((await accepted.post("relayfile", { ...ok, aud: "" })).status, 400);
});

test("relayfile answers 404 for an unknown workspace", async (t) => {
  const env = await setup(t);
  const runId = randomUUID();
  const answer = await env.post("relayfile", { workspaceId: randomUUID(), runId, mountPaths: [`/workflows/runs/${runId}`] });
  assert.equal(answer.status, 404);
  assert.equal(answer.body.error, "workspace_not_found");
});

test("re-issue revokes the earlier credential and run-end revoke ends the current one", async (t) => {
  const env = await setup(t);
  const runId = randomUUID();
  const body = { workspaceId: env.workspace.id, runId, mountPaths: [`/workflows/runs/${runId}`] };
  const first = await env.post("relayfile", body);
  const second = await env.post("relayfile", body);
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.notEqual(first.body.relayfileToken, second.body.relayfileToken);
  assert.equal((await env.relayfile.introspect(first.body.relayfileToken))?.revoked, true);
  assert.equal((await env.relayfile.introspect(second.body.relayfileToken))?.revoked, false);
  const revoke = await env.post("revoke", { runId });
  assert.equal(revoke.status, 200);
  assert.deepEqual(revoke.body, { revoked: true });
  assert.equal((await env.relayfile.introspect(second.body.relayfileToken))?.revoked, true);
  // Idempotent, and fine for a run that never had a Relayfile credential.
  assert.deepEqual((await env.post("revoke", { runId })).body, { revoked: true });
  const never = await env.post("revoke", { runId: randomUUID() });
  assert.equal(never.status, 200);
  assert.deepEqual(never.body, { revoked: true });
});
