import assert from "node:assert/strict";
import { createServer } from "node:http";
import test from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const MISSING = "00000000-0000-4000-8000-00000000abcd";

async function setup(t: test.TestContext) {
  const database = new PGliteDatabase();
  await migrate(database);
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: origin,
    relaycastUrl: "http://relaycast.invalid",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayauthUrl: "http://relayauth.invalid",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.selfhosted.test",
    relayauthApiKey: "rak_test",
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: null,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: "https://dashboard.selfhosted.test/",
    port: 0,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, KEYRING, 0, { tenancy: "multi" });
  control.on("request", createApp({ config, store }));
  t.after(async () => {
    await close(control);
    await database.close();
  });

  const api = (path: string, options: Parameters<typeof request>[2] = {}) => request(origin, path, options);
  const organization = async (name: string, ownerEmail: string) => {
    const org = await api("/api/v1/organizations", {
      method: "POST", token: BOOTSTRAP, body: { name, ownerEmail, ownerName: "Owner" },
    });
    assert.equal(org.status, 201);
    return { id: org.body.id as string, ownerId: org.body.owner.id as string };
  };
  const workspace = async (organizationId: string, name: string) => {
    const created = await api(`/api/v1/organizations/${organizationId}/workspaces`, {
      method: "POST", token: BOOTSTRAP, body: { name, relaycastApiKey: `rk_${name}` },
    });
    assert.equal(created.status, 201);
    return created.body.id as string;
  };
  const login = async (userId: string, workspaceId: string) => {
    const start = await api("/api/v1/auth/device/start", { method: "POST", body: { client_name: "cli" } });
    assert.equal(start.status, 201);
    const approved = await api("/api/v1/auth/device/approve", {
      method: "POST",
      token: BOOTSTRAP,
      body: { action: "approve", user_code: start.body.user_code, user_id: userId, workspace_id: workspaceId },
    });
    assert.equal(approved.status, 200);
    const poll = await api("/api/v1/auth/device/token", {
      method: "POST", body: { device_code: start.body.device_code },
    });
    assert.equal(poll.status, 200);
    return poll.body.access_token as string;
  };
  const remove = (organizationId: string, workspaceId: string, token?: string) =>
    api(`/api/v1/organizations/${organizationId}/workspaces/${workspaceId}`, { method: "DELETE", ...(token ? { token } : {}) });
  const names = async (organizationId: string) =>
    (await api(`/api/v1/organizations/${organizationId}/workspaces`, { token: BOOTSTRAP }))
      .body.workspaces.map((row: { name: string }) => row.name);
  return { origin, database, api, organization, workspace, login, remove, names };
}

test("workspace delete requires authentication, an admin of that organization, and a workspace in it", async (t) => {
  const env = await setup(t);
  const acme = await env.organization("Acme", "owner@acme.test");
  const keep = await env.workspace(acme.id, "keep");
  const doomed = await env.workspace(acme.id, "doomed");
  const other = await env.organization("Other", "owner@other.test");
  const otherWorkspace = await env.workspace(other.id, "foreign");
  const otherSpare = await env.workspace(other.id, "spare");
  const ownerToken = await env.login(acme.ownerId, keep);
  const otherOwnerToken = await env.login(other.ownerId, otherWorkspace);

  assert.equal((await env.remove(acme.id, doomed)).status, 401);
  // Another organization's admin: not found, no existence oracle.
  assert.equal((await env.remove(acme.id, doomed, otherOwnerToken)).status, 404);
  // Another organization's workspace through this organization's path.
  assert.equal((await env.remove(acme.id, otherSpare, ownerToken)).status, 404);
  assert.equal((await env.remove(acme.id, otherSpare, BOOTSTRAP)).status, 404);
  assert.equal((await env.remove(acme.id, MISSING, ownerToken)).status, 404);
  assert.equal((await env.remove(acme.id, "not-a-uuid", BOOTSTRAP)).status, 404);

  await env.database.query("UPDATE organization_memberships SET role = 'member' WHERE user_id = $1", [acme.ownerId]);
  assert.equal((await env.remove(acme.id, doomed, ownerToken)).status, 403);
  await env.database.query("UPDATE organization_memberships SET role = 'admin' WHERE user_id = $1", [acme.ownerId]);

  assert.deepEqual(await env.names(acme.id), ["keep", "doomed"]);
  assert.deepEqual(await env.names(other.id), ["foreign", "spare"]);

  assert.equal((await env.remove(acme.id, doomed, ownerToken)).status, 204);
  assert.deepEqual(await env.names(acme.id), ["keep"]);
  assert.equal((await env.remove(acme.id, doomed, ownerToken)).status, 404);
  const audit = await env.database.query<{ actor_kind: string; workspace_id: string | null; target: string }>(
    "SELECT actor_kind, workspace_id, target FROM admin_audit_events WHERE action = 'workspace.deleted'",
  );
  assert.deepEqual(audit.rows, [{ actor_kind: "user", workspace_id: null, target: `${doomed} (doomed)` }]);
});

test("deleting a workspace ends its sessions and leaves the rest of the organization working", async (t) => {
  const env = await setup(t);
  const acme = await env.organization("Acme", "owner@acme.test");
  const keep = await env.workspace(acme.id, "keep");
  const doomed = await env.workspace(acme.id, "doomed");
  const keptToken = await env.login(acme.ownerId, keep);
  const doomedToken = await env.login(acme.ownerId, doomed);
  assert.equal((await env.api("/api/v1/auth/whoami", { token: doomedToken })).status, 200);

  assert.equal((await env.remove(acme.id, doomed, BOOTSTRAP)).status, 204);

  assert.equal((await env.api("/api/v1/auth/whoami", { token: doomedToken })).status, 401);
  assert.equal((await env.api("/api/v1/auth/whoami", { token: keptToken })).status, 200);
});

test("a person cannot delete the last workspace, and the bootstrap bearer can", async (t) => {
  const env = await setup(t);
  const acme = await env.organization("Acme", "owner@acme.test");
  const only = await env.workspace(acme.id, "only");
  const ownerToken = await env.login(acme.ownerId, only);

  const refused = await env.remove(acme.id, only, ownerToken);
  assert.equal(refused.status, 409);
  assert.equal(refused.body.error, "last_workspace");
  assert.deepEqual(await env.names(acme.id), ["only"]);

  assert.equal((await env.remove(acme.id, only, BOOTSTRAP)).status, 204);
  assert.deepEqual(await env.names(acme.id), []);
});

test("a workspace with a Factory connection is refused and left intact", async (t) => {
  const env = await setup(t);
  const acme = await env.organization("Acme", "owner@acme.test");
  await env.workspace(acme.id, "keep");
  const bound = await env.workspace(acme.id, "bound");
  await env.database.query(
    `INSERT INTO factory_connections
       (workspace_id, organization_id, user_id, key_envelope, key_hint, validated_at)
     VALUES ($1, $2, $3, 'envelope', 'hint', now())`,
    [bound, acme.id, acme.ownerId],
  );

  const refused = await env.remove(acme.id, bound, BOOTSTRAP);
  assert.equal(refused.status, 409);
  assert.equal(refused.body.error, "workspace_in_use");
  assert.deepEqual(await env.names(acme.id), ["keep", "bound"]);
  const audit = await env.database.query("SELECT 1 FROM admin_audit_events WHERE action = 'workspace.deleted'");
  assert.equal(audit.rows.length, 0);
});

test("a session cookie may delete only from an allowed origin", async (t) => {
  const env = await setup(t);
  const acme = await env.organization("Acme", "owner@acme.test");
  const keep = await env.workspace(acme.id, "keep");
  const doomed = await env.workspace(acme.id, "doomed");
  const token = await env.login(acme.ownerId, keep);

  const crossSite = await fetch(`${env.origin}/cloud/api/v1/organizations/${acme.id}/workspaces/${doomed}`, {
    method: "DELETE",
    headers: { cookie: `agent_relay_session=${token}`, origin: "https://evil.example" },
  });
  assert.equal(crossSite.status, 403);
  assert.equal(((await crossSite.json()) as { error: string }).error, "csrf_rejected");
  assert.deepEqual(await env.names(acme.id), ["keep", "doomed"]);
});
