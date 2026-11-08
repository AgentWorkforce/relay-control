import assert from "node:assert/strict";
import test from "node:test";
import type { ChiefBackend } from "../src/chief/routes.js";
import { seedTenant, startControlPlane } from "./flows-helpers.js";

test("chief routes preserve tenant authorization, admin gates and browser CSRF checks", async (t) => {
  const calls: {
    operation: string;
    organizationId: string;
    workspaceId: string;
  }[] = [];
  const operation =
    (name: string) =>
    (context: { organizationId: string; workspaceId: string }) => {
      calls.push({ operation: name, ...context });
      return { chiefs: [], id: "chief-1" };
    };
  const backend: ChiefBackend = {
    list: operation("list"),
    repositories: operation("repositories"),
    get: operation("get"),
    create: operation("create"),
    scan: operation("scan"),
  };
  const app = await startControlPlane({}, backend);
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  const route = `/cloud/api/v1/workspaces/${tenant.workspaceId}/chiefs`;
  assert.equal((await app.api(route)).status, 401);
  assert.equal(
    (await app.api(route, { token: tenant.otherOwnerToken })).status,
    404,
  );
  assert.equal(
    (
      await app.api(route, {
        method: "POST",
        token: tenant.memberToken,
        body: {},
      })
    ).status,
    403,
  );
  assert.equal(
    (await app.api(`${route}/repositories`, { token: tenant.otherOwnerToken }))
      .status,
    404,
  );
  assert.equal(calls.length, 0);
  assert.equal(
    (await app.api(`${route}/repositories`, { token: tenant.ownerToken }))
      .status,
    200,
  );
  assert.equal(calls.at(-1)?.workspaceId, tenant.workspaceId);
  assert.equal(calls.at(-1)?.operation, "repositories");
  assert.equal(
    (await app.api(route, { token: tenant.memberToken })).status,
    200,
  );
  assert.equal(
    (
      await app.api(route, {
        method: "POST",
        token: tenant.ownerToken,
        body: { organizationId: "forged", workspaceId: "forged" },
      })
    ).status,
    202,
  );
  assert.equal(calls.at(-1)?.organizationId, tenant.organizationId);
  assert.equal(calls.at(-1)?.workspaceId, tenant.workspaceId);
  assert.equal(
    (
      await app.api(`${route}/chief-1/scan`, {
        method: "POST",
        headers: {
          cookie: `agent_relay_session=${tenant.ownerToken}`,
          origin: "https://attacker.example",
        },
        body: {},
      })
    ).status,
    403,
  );
  assert.equal(
    (
      await app.api(`${route}/chief-1/scan`, {
        method: "POST",
        headers: {
          cookie: `agent_relay_session=${tenant.ownerToken}`,
          origin: "https://control.selfhosted.company",
        },
        body: {},
      })
    ).status,
    202,
  );
  assert.equal(calls.at(-1)?.operation, "scan");
  assert.equal(
    (await app.api(route, { method: "DELETE", token: tenant.ownerToken }))
      .status,
    405,
  );
});
