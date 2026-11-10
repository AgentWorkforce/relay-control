import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { createApp } from "../src/app.js";
import { ApiTokenStore } from "../src/admin/api-tokens.js";
import { RemoteAgentConnections } from "../src/remote-agents/connections.js";
import { apiClient, close, listen, seedTenant, startControlPlane } from "./flows-helpers.js";

test("provider connection API validates upstream, encrypts keys, and preserves person/workspace authority", async t => {
  const control = await startControlPlane();
  t.after(() => control.stop());
  const tenant = await seedTenant(control.api);
  const calls: Array<{ url: string; init: RequestInit }> = [];
  let replyOverride: Response | null = null;
  let onFetch: (() => Promise<void>) | undefined;
  const fetchImpl: typeof fetch = async (input, init = {}) => {
    calls.push({ url: String(input), init });
    await onFetch?.();
    if (replyOverride) return replyOverride.clone();
    const url = String(input);
    if (url.endsWith("/projects")) return Response.json({ items: [] });
    if (url.endsWith("/whoami")) return Response.json({ organization: { id: "replica-org" } });
    if (url.endsWith("/v1/me")) return Response.json({ userId: 42, apiKeyName: "workspace-key", createdAt: "2026-11-10T00:00:00Z" });
    if (url.includes("devin-00000000000000000000000000000000/messages")) return new Response(null, { status: 404 });
    if (url.endsWith("/sessions?first=1")) return Response.json({ items: [] });
    throw new Error("Unexpected provider request");
  };
  const server = createServer(createApp({ config: control.config, store: control.store, remoteAgentFetch: fetchImpl }));
  const api = apiClient(await listen(server));
  t.after(() => close(server));
  const path = `/cloud/api/v1/workspaces/${tenant.workspaceId}/remote-agent-connections`;
  const token = tenant.ownerToken;
  const storage = new RemoteAgentConnections(control.database, control.config.encryptionKeyring, fetchImpl);
  const owner = await control.database.query<{ user_id: string }>("SELECT user_id FROM organization_memberships WHERE organization_id=$1 AND role='owner'", [tenant.organizationId]);

  await t.test("missing auth and foreign workspace cannot read settings", async () => {
    assert.equal((await api(path)).status, 401);
    assert.equal((await api(path.replace(tenant.workspaceId, tenant.otherWorkspaceId), { token })).status, 404);
    assert.equal(calls.length, 0);
  });
  await t.test("non-person and member writes are refused before provider I/O", async () => {
    assert.equal((await api(`${path}/capy`, { method: "POST", token: tenant.memberToken, body: { key: "capy_" + "s".repeat(32) } })).status, 403);
    const ci = await new ApiTokenStore(control.database).create({
      workspaceId: tenant.workspaceId, organizationId: tenant.organizationId, label: "CI", purpose: "deployment",
      expiryDays: 7, neverExpires: false, actor: { kind: "user", userId: owner.rows[0]!.user_id },
    });
    assert.equal((await api(`${path}/capy`, { method: "POST", token: ci.accessToken, body: { key: "capy_" + "s".repeat(32) } })).status, 401);
    assert.equal(calls.length, 0);
  });
  await t.test("all provider connection checks persist encrypted keys and return hints only", async () => {
    for (const id of ["capy", "replicas", "devin", "cursor-cloud"] as const) {
      const key = id === "capy" ? "capy_" + "s".repeat(32) : "provider_key_" + "s".repeat(32);
      const saved = await api(`${path}/${id}`, { method: "POST", token, body: { key, ...(id === "devin" ? { orgId: "cognition-org" } : {}) } });
      assert.equal(saved.status, 200, saved.text);
      assert.equal(saved.body.connection.keyHint, "…ssss");
      assert.equal(saved.text.includes(key), false);
      const stored = await control.database.query<{ key_ciphertext: string }>("SELECT key_ciphertext FROM remote_agent_connections WHERE workspace_id=$1 AND provider=$2", [tenant.workspaceId, id]);
      assert.equal(stored.rows[0]!.key_ciphertext.includes(key), false);
      assert.equal(await storage.keyFor(tenant.workspaceId, id), key);
      assert.equal(await storage.keyFor(tenant.otherWorkspaceId, id), null);
    }
    assert.equal(calls.length, 5);
    for (const call of calls) {
      assert.equal(call.init.redirect, "error");
      assert.ok(call.init.signal instanceof AbortSignal);
    }
    assert.ok(calls.some(call => call.url === "https://api.cursor.com/v1/me"));
    const listed = await api(path, { token: tenant.memberToken });
    assert.equal(listed.status, 200);
    assert.equal(listed.body.providers.length, 4);
    assert.equal(listed.text.includes("ciphertext"), false);
    assert.equal(listed.text.includes("provider_key_"), false);
    assert.ok(listed.body.providers.every((p: any) => p.connection && !p.capabilities.relayBinding && !p.capabilities.historySync));
  });
  await t.test("provider-body errors, invalid key and arbitrary transport overrides never leak or save", async () => {
    const count = calls.length;
    assert.equal((await api(`${path}/capy`, { method: "POST", token, body: { key: "bad" } })).status, 400);
    assert.equal((await api(`${path}/capy`, { method: "POST", token, body: { key: "capy_" + "s".repeat(32), baseUrl: "https://attacker.test" } })).status, 400);
    assert.equal(calls.length, count);
    replyOverride = Response.json({ key: "secret-provider-error-body" }, { status: 401 });
    const result = await api(`${path}/capy`, { method: "POST", token, body: { key: "capy_" + "x".repeat(32) } });
    assert.equal(result.status, 502);
    assert.equal(result.text.includes("secret-provider-error-body"), false);
    assert.equal(await storage.keyFor(tenant.workspaceId, "capy"), "capy_" + "s".repeat(32));
    replyOverride = Response.json(null);
    assert.equal((await api(`${path}/capy`, { method: "POST", token, body: { key: "capy_" + "x".repeat(32) } })).status, 502);
    replyOverride = null;
  });
  await t.test("cookie writes reject cross-site Origin and allow same-origin JSON", async () => {
    const count = calls.length;
    const headers = { cookie: `agent_relay_session=${token}`, origin: "https://attacker.test" };
    assert.equal((await api(`${path}/capy`, { method: "POST", headers, body: { key: "capy_" + "s".repeat(32) } })).status, 403);
    assert.equal(calls.length, count);
    assert.equal((await api(`${path}/capy`, { method: "POST", headers: { ...headers, origin: new URL(control.config.dashboardUrl).origin }, body: { key: "capy_" + "s".repeat(32) } })).status, 200);
  });
  await t.test("replacing a different provider account requires disconnect", async () => {
    replyOverride = Response.json({ organization: { id: "different-replica-org" } });
    const result = await api(`${path}/replicas`, { method: "POST", token, body: { key: "changed_provider_key_" + "s".repeat(32) } });
    assert.equal(result.status, 409);
    assert.equal(result.body.error, "provider_account_changed");
    assert.equal(await storage.keyFor(tenant.workspaceId, "replicas"), "provider_key_" + "s".repeat(32));
    replyOverride = null;
  });
  await t.test("a disconnect during validation cannot resurrect a previously stored key", async () => {
    onFetch = async () => {
      await control.database.query("DELETE FROM remote_agent_connections WHERE workspace_id=$1 AND provider='cursor-cloud'", [tenant.workspaceId]);
    };
    const result = await api(`${path}/cursor-cloud`, { method: "POST", token, body: { key: "rotated_provider_key_" + "s".repeat(32) } });
    assert.equal(result.status, 409);
    assert.equal(result.body.error, "connection_changed");
    assert.equal(await storage.keyFor(tenant.workspaceId, "cursor-cloud"), null);
    onFetch = undefined;
  });
  await t.test("saving credentials does not advertise an unimplemented Relay runtime", async () => {
    const result = await api(`/cloud/api/v1/workspaces/${tenant.workspaceId}/providers`, { token });
    // Connecting Capy credentials must NOT report a nonexistent Relay runtime.
    const capy = result.body.providers.find((p: any) => p.id === "capy");
    assert.equal(capy.implemented, false);
  });
  await t.test("disconnect deletes only this workspace's key and audits without secrets", async () => {
    assert.equal((await api(`${path}/replicas`, { method: "DELETE", token })).status, 200);
    assert.equal(await storage.keyFor(tenant.workspaceId, "replicas"), null);
    assert.ok(await storage.keyFor(tenant.workspaceId, "capy"));
    const audit = await control.database.query<{ target: string }>("SELECT target FROM admin_audit_events WHERE action LIKE 'remote_agent.%'");
    assert.ok(audit.rows.length >= 6);
    assert.ok(audit.rows.every(row => ["capy", "replicas", "devin", "cursor-cloud"].includes(row.target)));
  });
  await t.test("membership revoked during validation cannot write after the upstream call", async () => {
    onFetch = async () => { await control.database.query("UPDATE organization_memberships SET role='member' WHERE organization_id=$1 AND user_id=$2", [tenant.organizationId, owner.rows[0]!.user_id]); };
    const result = await api(`${path}/capy`, { method: "POST", token, body: { key: "capy_" + "r".repeat(32) } });
    assert.equal(result.status, 403);
    assert.equal(await storage.keyFor(tenant.workspaceId, "capy"), "capy_" + "s".repeat(32));
    onFetch = undefined;
  });
});
