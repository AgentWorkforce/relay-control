import assert from "node:assert/strict";
import test from "node:test";
import { ApiTokenStore } from "../src/admin/api-tokens.js";
import { hashSecret } from "../src/crypto.js";
import { REACHABILITY_WARNING } from "../src/factory/runtime.js";
import {
  assertNoSecrets,
  bindingRow,
  connectAndBind,
  FACTORY_KEY,
  FACTORY_KEY_2,
  factoryPath,
  INTERNAL,
  PUBLIC_URL,
  startFactoryEnv,
} from "./factory-helpers.js";

test("factory gating off: every factory route answers the generic 404 before auth", async (t) => {
  const env = await startFactoryEnv(t, { enabled: false });
  const unknownRoute = await env.api("/api/v1/definitely-not-a-route", { token: env.ownerToken });
  const probes = [
    { path: factoryPath(env.workspaceId, "/connection"), method: "GET" },
    { path: factoryPath(env.workspaceId, "/connection"), method: "PUT" },
    { path: factoryPath(env.workspaceId, "/bindings"), method: "POST" },
    { path: `/cloud${factoryPath(env.workspaceId, "/computers")}`, method: "GET" },
    { path: "/api/v1/factory-sessions/agents/00000000-0000-0000-0000-000000000000/messages", method: "POST" },
    { path: "/api/v1/factory-sessions/relay-events/00000000-0000-0000-0000-000000000000", method: "POST" },
  ];
  for (const probe of probes) {
    // No credential at all: a live route would answer 401; the flag answers 404 first.
    const anonymous = await env.api(probe.path, { method: probe.method });
    assert.equal(anonymous.status, 404, `${probe.method} ${probe.path}`);
    assert.deepEqual(anonymous.body, unknownRoute.body);
    const authed = await env.api(probe.path, { method: probe.method, token: env.ownerToken, ...(probe.method === "GET" ? {} : { body: {} }) });
    assert.equal(authed.status, 404);
  }
  // Same anonymous request with the flag on reaches auth.
  const on = await startFactoryEnv(t);
  assert.equal((await on.api(factoryPath(on.workspaceId, "/connection"))).status, 401);
  assert.equal(env.factory.requests.length, 0);
});

test("factory relay-events route is registered but always 404 while subscriptions are deferred", async (t) => {
  const env = await startFactoryEnv(t);
  const { binding_id } = await connectAndBind(env);
  const response = await env.api(`/api/v1/factory-sessions/relay-events/${binding_id}`, {
    method: "POST",
    headers: { "webhook-signature": "v1,abc", "webhook-id": "x", "webhook-timestamp": "1" },
    body: { type: "message.created" },
  });
  assert.equal(response.status, 404);
  assert.equal(response.body.error, "not_found");
});

test("factory gates refuse workspace tokens, the internal token, members, missing scope and cross-site cookies", async (t) => {
  const env = await startFactoryEnv(t);
  const path = factoryPath(env.workspaceId, "/connection");
  const workspaceToken = await new ApiTokenStore(env.database).create({
    workspaceId: env.workspaceId,
    organizationId: env.organizationId,
    label: "ci",
    purpose: "agent-runtime",
    expiryDays: 1,
    neverExpires: undefined,
    actor: { kind: "user", userId: env.ownerId },
  });
  for (const token of [workspaceToken.accessToken, INTERNAL]) {
    const refused = await env.api(path, { token });
    assert.equal(refused.status, 403);
    assert.deepEqual(refused.body, { error: "factory_workspace_token", message: "Workspace tokens cannot use Factory" });
  }
  const member = await env.api(path, { token: env.memberToken });
  assert.equal(member.status, 403);
  assert.equal(member.body.message, "Workspace admin role required");

  const foreign = await env.api(factoryPath(env.otherWorkspaceId, "/connection"), { token: env.ownerToken });
  assert.equal(foreign.status, 404);

  await env.database.query(
    "UPDATE token_sessions SET scopes = array_remove(scopes, 'cli:auth') WHERE access_token_hash = $1",
    [hashSecret(env.adminToken)],
  );
  const scope = await env.api(path, { token: env.adminToken });
  assert.deepEqual(scope.body, { error: "insufficient_scope", message: "Insufficient scope" });

  // Cookie-authenticated write from a foreign origin (session cookie only works under /cloud).
  const cookie = await env.api(`/cloud${path}`, {
    method: "PUT",
    headers: { cookie: `agent_relay_session=${encodeURIComponent(env.ownerToken)}`, origin: "https://evil.example", "content-type": "application/json" },
    raw: JSON.stringify({ key: FACTORY_KEY }),
  });
  assert.equal(cookie.status, 403);
  assert.equal(cookie.body.error, "csrf_rejected");
  const sameSite = await env.api(`/cloud${path}`, {
    method: "PUT",
    headers: { cookie: `agent_relay_session=${encodeURIComponent(env.ownerToken)}`, origin: new URL(PUBLIC_URL).origin, "content-type": "application/json" },
    raw: JSON.stringify({ key: FACTORY_KEY }),
  });
  assert.equal(sameSite.status, 200, JSON.stringify(sameSite.body));
  // The session cookie is honoured only under /cloud: the bare API path wants a bearer.
  const bareCookie = await env.api(path, {
    headers: { cookie: `agent_relay_session=${encodeURIComponent(env.ownerToken)}`, origin: new URL(PUBLIC_URL).origin },
  });
  assert.equal(bareCookie.status, 401);
  // Nothing was written by the refused requests: only the same-site write connected.
  const rows = await env.database.query("SELECT user_id FROM factory_connections");
  assert.equal(rows.rows.length, 1);
});

test("factory connect validates the key, stores only an envelope and a hint, and summarizes for owner and admin", async (t) => {
  const env = await startFactoryEnv(t);
  const path = factoryPath(env.workspaceId, "/connection");
  assert.deepEqual((await env.api(path, { token: env.ownerToken })).body, {
    connected: false, key_hint: null, validated_at: null, user_is_owner: false, bindings_count: 0, history: "deferred",
    acquisition: { state: "unconfigured" },
  });
  const bad = await env.api(path, { method: "PUT", token: env.ownerToken, body: { key: "short" } });
  assert.deepEqual(bad.body, { error: "invalid_factory_key", message: "Invalid Factory key" });
  const rejected = await env.api(path, { method: "PUT", token: env.ownerToken, body: { key: "fk_live_not_a_known_key" } });
  assert.equal(rejected.status, 502);
  assert.equal(rejected.body.error, "factory_key_rejected");
  assert.equal((await env.database.query("SELECT 1 FROM factory_connections")).rows.length, 0);

  const ok = await env.api(path, { method: "PUT", token: env.ownerToken, body: { key: FACTORY_KEY } });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.connected, true);
  assert.equal(ok.body.key_hint, `…${FACTORY_KEY.slice(-4)}`);
  assert.equal(ok.body.user_is_owner, true);
  assertNoSecrets(env, ok.body);
  const stored = await env.database.query<{ key_envelope: string }>("SELECT key_envelope FROM factory_connections");
  assert.ok(!stored.rows[0]!.key_envelope.includes(FACTORY_KEY));

  // Authorized acceptance: a second workspace admin reads the summary (count only, not owner).
  const admin = await env.api(path, { token: env.adminToken });
  assert.equal(admin.status, 200);
  assert.equal(admin.body.connected, true);
  assert.equal(admin.body.user_is_owner, false);
  const audit = await env.database.query<{ action: string }>("SELECT action FROM admin_audit_events WHERE action LIKE 'factory.%'");
  assert.deepEqual(audit.rows.map((row) => row.action), ["factory.connection.put"]);
  assertNoSecrets(env, env.logs);
});

test("factory discovery is owner-only and marks sessions bound here or elsewhere", async (t) => {
  const env = await startFactoryEnv(t);
  assert.equal((await env.api(factoryPath(env.workspaceId, "/computers"), { token: env.ownerToken })).body.error, "factory_not_connected");
  await connectAndBind(env, { sessionId: "sess-a" });
  // Another workspace binds sess-b through its own connection.
  await connectAndBind(env, { token: env.ownerOtherToken, workspaceId: env.otherWorkspaceId, sessionId: "sess-b" });

  const computers = await env.api(factoryPath(env.workspaceId, "/computers"), { token: env.ownerToken });
  assert.equal(computers.status, 200);
  assert.deepEqual(computers.body.computers.map((row: any) => row.id), ["cmp-1", "cmp-2"]);
  const sessions = await env.api(factoryPath(env.workspaceId, "/computers/cmp-1/sessions"), { token: env.ownerToken });
  assert.deepEqual(sessions.body.sessions, [
    { id: "sess-a", title: "Session A", computer_id: "cmp-1", bound: "here" },
    { id: "sess-b", title: "Session B", computer_id: "cmp-1", bound: "elsewhere" },
  ]);
  env.factory.unreachable.add("cmp-2");
  const unreachable = await env.api(factoryPath(env.workspaceId, "/computers/cmp-2/sessions"), { token: env.ownerToken });
  assert.deepEqual(unreachable.body, { sessions: [], warning: REACHABILITY_WARNING });

  const admin = await env.api(factoryPath(env.workspaceId, "/computers"), { token: env.adminToken });
  assert.equal(admin.status, 403);
  assert.equal(admin.body.message, "Only the person who connected Factory can browse its sessions.");
});

test("factory connect refuses a different admin while the owner holds live bindings, and replaces its own key after re-verifying", async (t) => {
  const env = await startFactoryEnv(t);
  const { binding_id } = await connectAndBind(env);
  const takeover = await env.api(factoryPath(env.workspaceId, "/connection"), { method: "PUT", token: env.adminToken, body: { key: FACTORY_KEY_2 } });
  assert.equal(takeover.status, 409);
  assert.equal(takeover.body.error, "factory_other_member_bindings");

  // The owner's key replacement re-verifies each bound session on the new key.
  env.factory.sessions.get("sess-a")!.computerId = "cmp-2";
  const moved = await env.api(factoryPath(env.workspaceId, "/connection"), { method: "PUT", token: env.ownerToken, body: { key: FACTORY_KEY_2 } });
  assert.equal(moved.status, 409);
  assert.equal(moved.body.error, "factory_session_moved");
  env.factory.sessions.get("sess-a")!.computerId = "cmp-1";
  const replaced = await env.api(factoryPath(env.workspaceId, "/connection"), { method: "PUT", token: env.ownerToken, body: { key: FACTORY_KEY_2 } });
  assert.equal(replaced.status, 200);
  assert.equal(replaced.body.key_hint, `…${FACTORY_KEY_2.slice(-4)}`);
  assert.equal((await bindingRow(env, binding_id)).state, "bound");
});

test("factory bind, list, get, unbind and disconnect round trip with owner checks", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await connectAndBind(env);
  assert.match(bound.agent.name, /^factory-[0-9a-f]{16}$/);
  assertNoSecrets(env, bound);
  const remote = env.relay.agents.get(bound.agent.name)!;
  assert.equal(remote.metadata.factory_binding_id, bound.binding_id);
  assert.equal(remote.metadata.session_kind, "droid");
  assert.ok(!("factory_history_owner" in remote.metadata));
  assert.equal(remote.key, "rk_live_primary");

  const row = await bindingRow(env, bound.binding_id);
  assert.equal(row.state, "bound");
  for (const column of ["hosted_token_envelope", "hook_secret_envelope", "helper_secret_envelope"]) {
    assert.ok(row[column] && !String(row[column]).startsWith("whsec_") && !String(row[column]).includes(remote.token));
  }

  const listed = await env.api(factoryPath(env.workspaceId, "/bindings"), { token: env.ownerToken });
  assert.deepEqual(listed.body.bindings.map((b: any) => [b.id, b.state, b.history]), [[bound.binding_id, "bound", "deferred"]]);
  assertNoSecrets(env, listed.body);
  const one = await env.api(factoryPath(env.workspaceId, `/bindings/${bound.binding_id}`), { token: env.ownerToken });
  assert.equal(one.body.computer_id, "cmp-1");
  // Foreign rows are indistinguishable from missing.
  assert.equal((await env.api(factoryPath(env.workspaceId, `/bindings/${bound.binding_id}`), { token: env.adminToken })).status, 404);
  assert.deepEqual((await env.api(factoryPath(env.workspaceId, "/bindings"), { token: env.adminToken })).body.bindings, []);

  // Another admin cannot bind on the owner's connection or unbind the owner's session.
  const adminBind = await env.api(factoryPath(env.workspaceId, "/bindings"), {
    method: "POST", token: env.adminToken, body: { session_id: "sess-b", computer_id: "cmp-1" },
  });
  assert.equal(adminBind.status, 403);
  assert.equal(adminBind.body.message, "Only the person who connected Factory can manage this connection.");
  const adminUnbind = await env.api(factoryPath(env.workspaceId, `/bindings/${bound.binding_id}`), { method: "DELETE", token: env.adminToken });
  assert.equal(adminUnbind.status, 403);
  assert.equal(adminUnbind.body.message, "Only the person who connected Factory can disconnect this session.");
  const adminDisconnect = await env.api(factoryPath(env.workspaceId, "/connection"), { method: "DELETE", token: env.adminToken });
  assert.equal(adminDisconnect.status, 403);

  // Idempotent re-bind returns the same binding without a second registration.
  const again = await env.api(factoryPath(env.workspaceId, "/bindings"), {
    method: "POST", token: env.ownerToken, body: { session_id: "sess-a", computer_id: "cmp-1" },
  });
  assert.equal(again.body.binding_id, bound.binding_id);
  assert.equal(env.relay.registered, 1);

  const second = await env.api(factoryPath(env.workspaceId, "/bindings"), {
    method: "POST", token: env.ownerToken, body: { session_id: "sess-b", computer_id: "cmp-1" },
  });
  assert.equal(second.status, 201);

  const unbind = await env.api(factoryPath(env.workspaceId, `/bindings/${bound.binding_id}`), { method: "DELETE", token: env.ownerToken });
  assert.equal(unbind.status, 204);
  assert.equal((await bindingRow(env, bound.binding_id)).state, "retired");
  assert.ok(!env.relay.agents.has(bound.agent.name));
  assert.equal((await env.api(factoryPath(env.workspaceId, `/bindings/${bound.binding_id}`), { method: "DELETE", token: env.ownerToken })).status, 204);
  assert.equal((await env.api(factoryPath(env.workspaceId, "/bindings/00000000-0000-0000-0000-000000000000"), { method: "DELETE", token: env.ownerToken })).status, 204);

  const disconnect = await env.api(factoryPath(env.workspaceId, "/connection"), { method: "DELETE", token: env.ownerToken });
  assert.equal(disconnect.status, 204);
  assert.equal((await bindingRow(env, second.body.binding_id)).state, "retired");
  assert.equal(env.relay.agents.size, 0);
  assert.equal((await env.database.query("SELECT 1 FROM factory_connections")).rows.length, 0);
  assert.equal((await env.api(factoryPath(env.workspaceId, "/connection"), { method: "DELETE", token: env.ownerToken })).status, 204);
  const audit = await env.database.query<{ action: string }>(
    "SELECT action FROM admin_audit_events WHERE action LIKE 'factory.%' ORDER BY created_at, action",
  );
  assert.deepEqual(audit.rows.map((r) => r.action).sort(), [
    "factory.binding.create", "factory.binding.create", "factory.binding.delete",
    "factory.connection.delete", "factory.connection.put",
  ]);
  assertNoSecrets(env, env.logs);
});

test("factory history schedule records a dormant intent and reports deferred", async (t) => {
  const env = await startFactoryEnv(t);
  const { binding_id } = await connectAndBind(env);
  const scheduled = await env.api(factoryPath(env.workspaceId, `/bindings/${binding_id}/history/schedule`), { method: "POST", token: env.ownerToken });
  assert.equal(scheduled.status, 202);
  assert.deepEqual(scheduled.body, { queued: 0, deferred: true });
  const rows = await env.database.query<{ session_id: string; active_job_id: string | null }>(
    "SELECT session_id, active_job_id FROM factory_history_syncs",
  );
  assert.deepEqual(rows.rows, [{ session_id: "sess-a", active_job_id: null }]);
  assert.equal((await env.api(factoryPath(env.workspaceId, "/connection"), { token: env.ownerToken })).body.history, "deferred");
  // Nothing was sent to Factory or History for it.
  assert.ok(!env.factory.requests.some((line) => line.includes("export") || line.startsWith("POST")));
});

test("factory routes are documented in openapi.yaml with their methods and the shared error shape", async () => {
  const { readFile } = await import("node:fs/promises");
  const { parse } = await import("yaml");
  const spec = parse(await readFile(new URL("../openapi.yaml", import.meta.url), "utf8")) as {
    paths: Record<string, Record<string, unknown>>;
    components: { schemas: Record<string, { required?: string[] }> };
  };
  const user = "/api/v1/workspaces/{workspaceId}/factory";
  const expected: Record<string, string[]> = {
    [`${user}/connection`]: ["get", "put", "delete"],
    [`${user}/connection/acquisition/rotate`]: ["post"],
    [`${user}/connection/acquisition/revoke`]: ["post"],
    [`${user}/computers`]: ["get"],
    [`${user}/computers/{computerId}/sessions`]: ["get"],
    [`${user}/bindings`]: ["get", "post"],
    [`${user}/bindings/{bindingId}`]: ["get", "delete"],
    [`${user}/bindings/{bindingId}/deliveries/{messageId}`]: ["get"],
    [`${user}/bindings/{bindingId}/history/schedule`]: ["post"],
    "/api/v1/factory-sessions/agents/{bindingId}/messages": ["post"],
    "/api/v1/factory-sessions/relay-events/{bindingId}": ["post"],
    "/internal/v1/factory/job": ["post"],
  };
  for (const [path, methods] of Object.entries(expected)) {
    assert.ok(spec.paths[path], `${path} is documented`);
    const documented = Object.keys(spec.paths[path]!).filter((key) => key !== "parameters").sort();
    assert.deepEqual(documented, [...methods].sort(), path);
  }
  const extra = Object.keys(spec.paths).filter((path) => /factory/.test(path) && !(path in expected));
  assert.deepEqual(extra, []);
  assert.deepEqual(spec.components.schemas.FactoryError!.required, ["error", "message"]);
});
