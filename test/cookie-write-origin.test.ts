// Cookie writes to the fleet claim, workspace, membership and runtime routes
// apply the same origin check as the other cookie writes: a session cookie
// needs an allowed Origin (and JSON when there is a body); bearer callers,
// which send no Origin, are unaffected.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { request } from "./support/harness.js";
import { BOOTSTRAP, copilotDesktopSetup } from "./support/copilot-desktop.js";

const FOREIGN = "https://elsewhere.example";

/** The two refused shapes: a foreign Origin and no Origin at all. */
const refusedOrigins = [
  { label: "foreign Origin", headers: { origin: FOREIGN } as Record<string, string> },
  { label: "no Origin", headers: {} as Record<string, string> },
];

function assertRefused(response: { status: number; body: Record<string, any> }, label: string): void {
  assert.equal(response.status, 403, label);
  assert.equal(response.body.error, "csrf_rejected", label);
}

test("fleet node claim and release: cookie writes need an allowed Origin; bearer callers are unaffected", async (t) => {
  const ctx = await copilotDesktopSetup(t);
  const cookie = await ctx.browserSession();
  const path = "/cloud/api/v1/fleet/nodes/claim";
  const owners = async () => (await ctx.database.query<{ node_id: string }>(
    "SELECT node_id FROM fleet_node_owners WHERE workspace_id = $1 ORDER BY node_id", [ctx.workspaceId])).rows.map((row) => row.node_id);
  const seed = (nodeId: string) => ctx.database.query(
    `INSERT INTO fleet_node_owners (id, workspace_id, organization_id, relaycast_workspace_id, node_id, node_name, user_id)
      VALUES ($1, $2, $3, 'rw_primary', $4, $4, $5)`,
    [randomUUID(), ctx.workspaceId, ctx.orgId, nodeId, ctx.ownerId],
  );
  await seed("node-cookie");
  await seed("node-bearer");

  for (const { label, headers } of refusedOrigins) {
    const release = await request(ctx.origin, path, {
      method: "DELETE", cookie, headers, body: { workspaceId: ctx.workspaceId, nodeId: "node-cookie" },
    });
    assertRefused(release, `release, ${label}`);
    const claim = await request(ctx.origin, path, {
      method: "POST", cookie, headers, body: { workspaceId: ctx.workspaceId, nodeToken: "at_live_unused" },
    });
    assertRefused(claim, `claim, ${label}`);
  }
  assert.deepEqual(await owners(), ["node-bearer", "node-cookie"], "refused cookie writes keep every claim");

  const allowed = await request(ctx.origin, path, {
    method: "DELETE", cookie, headers: { origin: ctx.origin }, body: { workspaceId: ctx.workspaceId, nodeId: "node-cookie" },
  });
  assert.equal(allowed.status, 200, allowed.raw);
  assert.deepEqual(allowed.body, { released: true });

  const token = await ctx.deviceLogin();
  const bearer = await request(ctx.origin, path, {
    method: "DELETE", token, body: { workspaceId: ctx.workspaceId, nodeId: "node-bearer" },
  });
  assert.equal(bearer.status, 200, bearer.raw);
  assert.deepEqual(await owners(), []);
});

test("organization workspaces: cookie create and update need an allowed Origin; bearer callers are unaffected", async (t) => {
  const ctx = await copilotDesktopSetup(t);
  const cookie = await ctx.browserSession();
  const collection = `/cloud/api/v1/organizations/${ctx.orgId}/workspaces`;
  const item = `${collection}/${ctx.workspaceId}`;
  const names = async () => (await ctx.database.query<{ name: string }>(
    "SELECT name FROM workspaces WHERE organization_id = $1 ORDER BY name", [ctx.orgId])).rows.map((row) => row.name);
  const before = await names();
  assert.deepEqual(before, ["Other", "Primary"]);

  for (const { label, headers } of refusedOrigins) {
    const created = await request(ctx.origin, collection, {
      method: "POST", cookie, headers,
      body: { name: "Refused", relaycastApiKey: "rk_refused", relaycastWorkspaceId: "rw_refused" },
    });
    assertRefused(created, `create, ${label}`);
    const updated = await request(ctx.origin, item, { method: "PUT", cookie, headers, body: { name: "Renamed" } });
    assertRefused(updated, `update, ${label}`);
  }
  assert.deepEqual(await names(), before, "refused cookie writes change no workspace");

  const allowed = { origin: ctx.origin };
  const created = await request(ctx.origin, collection, {
    method: "POST", cookie, headers: allowed,
    body: { name: "Via cookie", relaycastApiKey: "rk_cookie", relaycastWorkspaceId: "rw_cookie" },
  });
  assert.equal(created.status, 201, created.raw);
  const updated = await request(ctx.origin, item, { method: "PUT", cookie, headers: allowed, body: { name: "Renamed" } });
  assert.equal(updated.status, 200, updated.raw);
  assert.deepEqual(await names(), ["Other", "Renamed", "Via cookie"]);

  // Bearer callers send no Origin.
  const bearerCreated = await request(ctx.origin, `/api/v1/organizations/${ctx.orgId}/workspaces`, {
    method: "POST", token: BOOTSTRAP,
    body: { name: "Via bearer", relaycastApiKey: "rk_bearer", relaycastWorkspaceId: "rw_bearer" },
  });
  assert.equal(bearerCreated.status, 201, bearerCreated.raw);
  const bearerUpdated = await request(ctx.origin, `/api/v1/organizations/${ctx.orgId}/workspaces/${ctx.workspaceId}`, {
    method: "PUT", token: BOOTSTRAP, body: { name: "Primary" },
  });
  assert.equal(bearerUpdated.status, 200, bearerUpdated.raw);
  assert.deepEqual(await names(), ["Other", "Primary", "Via bearer", "Via cookie"]);
});

test("organization memberships: cookie add and remove need an allowed Origin; bearer callers are unaffected", async (t) => {
  const ctx = await copilotDesktopSetup(t);
  const cookie = await ctx.browserSession();
  const collection = `/cloud/api/v1/organizations/${ctx.orgId}/memberships`;
  const memberId = await ctx.addMember("kept@acme.test");
  const members = async () => (await ctx.database.query<{ user_id: string }>(
    "SELECT user_id FROM organization_memberships WHERE organization_id = $1 ORDER BY user_id", [ctx.orgId])).rows.map((row) => row.user_id);
  const before = await members();
  assert.equal(before.length, 2);

  for (const { label, headers } of refusedOrigins) {
    const added = await request(ctx.origin, collection, {
      method: "POST", cookie, headers, body: { email: "refused@acme.test", name: "Refused", role: "member" },
    });
    assertRefused(added, `add, ${label}`);
    const removed = await request(ctx.origin, `${collection}/${memberId}`, { method: "DELETE", cookie, headers });
    assertRefused(removed, `remove, ${label}`);
  }
  // A form-encoded body from a foreign origin is refused as well.
  const form = await request(ctx.origin, collection, {
    method: "POST", cookie, headers: { origin: FOREIGN },
    rawBody: "email=refused%40acme.test&name=Refused&role=member",
    contentType: "application/x-www-form-urlencoded",
  });
  assertRefused(form, "form-encoded add, foreign Origin");
  assert.deepEqual(await members(), before, "refused cookie writes change no membership");

  const allowed = { origin: ctx.origin };
  const added = await request(ctx.origin, collection, {
    method: "POST", cookie, headers: allowed, body: { email: "cookie@acme.test", name: "Cookie", role: "member" },
  });
  assert.equal(added.status, 200, added.raw);
  const removed = await request(ctx.origin, `${collection}/${added.body.userId}`, { method: "DELETE", cookie, headers: allowed });
  assert.equal(removed.status, 204, removed.raw);
  assert.deepEqual(await members(), before);

  // Bearer callers send no Origin.
  const bearerAdded = await request(ctx.origin, `/api/v1/organizations/${ctx.orgId}/memberships`, {
    method: "POST", token: BOOTSTRAP, body: { email: "bearer@acme.test", name: "Bearer", role: "member" },
  });
  assert.equal(bearerAdded.status, 200, bearerAdded.raw);
  const bearerRemoved = await request(ctx.origin, `/api/v1/organizations/${ctx.orgId}/memberships/${memberId}`, {
    method: "DELETE", token: BOOTSTRAP,
  });
  assert.equal(bearerRemoved.status, 204, bearerRemoved.raw);
  assert.deepEqual(await members(), [ctx.ownerId, bearerAdded.body.userId as string].sort());
});

test("workspace runtime: a cookie update needs an allowed Origin; bearer callers are unaffected", async (t) => {
  const ctx = await copilotDesktopSetup(t);
  const cookie = await ctx.browserSession();
  const path = `/cloud/api/v1/workspaces/${ctx.workspaceId}/runtime`;
  const runtime = async () => (await ctx.database.query<{ runtime_config: unknown }>(
    "SELECT runtime_config FROM workspaces WHERE id = $1", [ctx.workspaceId])).rows[0]!.runtime_config;
  const before = await runtime();

  for (const { label, headers } of refusedOrigins) {
    const updated = await request(ctx.origin, path, { method: "PUT", cookie, headers, body: { runtime: { image: "refused" } } });
    assertRefused(updated, `update, ${label}`);
  }
  assert.deepEqual(await runtime(), before, "refused cookie writes leave the runtime unchanged");

  const allowed = await request(ctx.origin, path, {
    method: "PUT", cookie, headers: { origin: ctx.origin }, body: { runtime: { image: "via-cookie" } },
  });
  assert.equal(allowed.status, 200, allowed.raw);
  assert.deepEqual(await runtime(), { image: "via-cookie" });

  const token = await ctx.deviceLogin();
  const bearer = await request(ctx.origin, `/api/v1/workspaces/${ctx.workspaceId}/runtime`, {
    method: "PUT", token, body: { runtime: { image: "via-bearer" } },
  });
  assert.equal(bearer.status, 200, bearer.raw);
  assert.deepEqual(await runtime(), { image: "via-bearer" });
});
