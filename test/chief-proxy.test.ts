import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import test, { type TestContext } from "node:test";
import { loadChiefControlUrl, relayChiefControlBackend } from "../src/chief/proxy.js";
import { seedTenant, startControlPlane } from "./flows-helpers.js";

type Seen = { method: string; url: string; authorization?: string; body: string };

function upstream(t: TestContext, reply: (seen: Seen) => { status: number; body: unknown }) {
  const seen: Seen[] = [];
  const server: Server = createServer((request: IncomingMessage, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("end", () => {
      const entry = {
        method: request.method ?? "",
        url: request.url ?? "",
        authorization: request.headers.authorization,
        body: Buffer.concat(chunks).toString("utf8"),
      };
      seen.push(entry);
      const { status, body } = reply(entry);
      response.writeHead(status, { "content-type": "application/json" });
      response.end(JSON.stringify(body));
    });
  });
  t.after(() => server.close());
  return new Promise<{ url: string; seen: Seen[] }>((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({ url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen });
    });
  });
}

async function plane(t: TestContext, url: string, warnings: unknown[] = []) {
  const app = await startControlPlane({}, relayChiefControlBackend({
    url,
    warn: (message, fields) => warnings.push({ message, fields }),
  }));
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  return { app, tenant, route: `/cloud/api/v1/workspaces/${tenant.workspaceId}/chiefs` };
}

test("configured: routes reach relaychief-control with the caller's token, after the gates", async (t) => {
  const backend = await upstream(t, (seen) =>
    seen.method === "POST" ? { status: 202, body: { id: "chief-1" } } : { status: 200, body: { chiefs: [] } });
  const { app, tenant, route } = await plane(t, backend.url);

  // Refused here never reach the add-on.
  assert.equal((await app.api(route)).status, 401);
  assert.equal((await app.api(route, { token: tenant.otherOwnerToken })).status, 404);
  assert.equal((await app.api(route, { method: "POST", token: tenant.memberToken, body: {} })).status, 403);
  assert.equal((await app.api(`${route}/chief-1/scan`, {
    method: "POST",
    headers: { cookie: `agent_relay_session=${tenant.ownerToken}`, origin: "https://attacker.example" },
    body: {},
  })).status, 403);
  assert.equal(backend.seen.length, 0);

  const list = await app.api(route, { token: tenant.memberToken });
  assert.equal(list.status, 200);
  assert.deepEqual(list.body, { chiefs: [] });
  const upstreamPath = `/api/v1/workspaces/${tenant.workspaceId}/chiefs`;
  assert.deepEqual(backend.seen.at(-1), {
    method: "GET", url: upstreamPath, authorization: `Bearer ${tenant.memberToken}`, body: "",
  });

  assert.equal((await app.api(`${route}/repositories`, { token: tenant.ownerToken })).status, 200);
  assert.equal(backend.seen.at(-1)?.url, `${upstreamPath}/repositories`);
  assert.equal((await app.api(`${route}/chief%2F1`, { token: tenant.ownerToken })).status, 200);
  assert.equal(backend.seen.at(-1)?.url, `${upstreamPath}/chief%2F1`);

  const created = await app.api(route, { method: "POST", token: tenant.ownerToken, body: { requestId: "r1" } });
  assert.equal(created.status, 202);
  assert.deepEqual(created.body, { id: "chief-1" });
  assert.equal(backend.seen.at(-1)?.url, upstreamPath);
  assert.deepEqual(JSON.parse(backend.seen.at(-1)!.body), { requestId: "r1" });

  assert.equal((await app.api(`${route}/chief-1/scan`, { method: "POST", token: tenant.ownerToken, body: {} })).status, 202);
  assert.equal(backend.seen.at(-1)?.url, `${upstreamPath}/chief-1/scan`);

  // A browser session is forwarded as a bearer once CSRF has passed.
  await app.api(`${route}/chief-1/scan`, {
    method: "POST",
    headers: { cookie: `agent_relay_session=${tenant.ownerToken}`, origin: "https://control.selfhosted.company" },
    body: {},
  });
  assert.equal(backend.seen.at(-1)?.authorization, `Bearer ${tenant.ownerToken}`);

  // Dot segments cannot climb out of the chiefs collection.
  const count = backend.seen.length;
  assert.equal((await app.api(`${route}/%2e%2e`, { token: tenant.ownerToken })).status, 404);
  assert.equal(backend.seen.length, count);
});

test("configured: upstream failures map to bounded errors and reveal no diagnostics", async (t) => {
  let next: { status: number; body: unknown } = { status: 200, body: {} };
  const backend = await upstream(t, () => next);
  const warnings: unknown[] = [];
  const { app, tenant, route } = await plane(t, backend.url, warnings);

  next = { status: 409, body: { error: "project_already_configured", message: "internal detail" } };
  const conflict = await app.api(route, { method: "POST", token: tenant.ownerToken, body: {} });
  assert.equal(conflict.status, 409);
  assert.equal(conflict.body.error, "project_already_configured");
  assert.doesNotMatch(conflict.text, /internal detail/);

  next = { status: 404, body: { error: "BAD code <script>", message: "x" } };
  const missing = await app.api(`${route}/nope`, { token: tenant.ownerToken });
  assert.equal(missing.status, 404);
  assert.equal(missing.body.error, "chief_request_failed");

  for (const status of [401, 403, 500]) {
    next = { status, body: { error: "unauthorized", message: "secret detail" } };
    const failed = await app.api(route, { token: tenant.ownerToken });
    assert.equal(failed.status, 503);
    assert.deepEqual(failed.body, {
      error: "chief_unavailable",
      message: "Chief service is temporarily unavailable.",
    });
  }
  assert.deepEqual(warnings.at(-1), {
    message: "[selfhost-api] chief backend refused request",
    fields: { operation: "list", status: 500, error: "unauthorized" },
  });
  assert.doesNotMatch(JSON.stringify(warnings), new RegExp(tenant.ownerToken));
});

test("configured: an unreachable add-on is 503 and a redirect is not followed", async (t) => {
  const refused = await plane(t, "http://127.0.0.1:1");
  const down = await refused.app.api(refused.route, { token: refused.tenant.ownerToken });
  assert.equal(down.status, 503);
  assert.equal(down.body.error, "chief_unavailable");

  const elsewhere = await upstream(t, () => ({ status: 200, body: {} }));
  const redirecting = createServer((_request, response) => {
    response.writeHead(307, { location: `${elsewhere.url}/stolen` });
    response.end();
  });
  t.after(() => redirecting.close());
  await new Promise<void>((resolve) => redirecting.listen(0, "127.0.0.1", resolve));
  const { app, tenant, route } = await plane(t, `http://127.0.0.1:${(redirecting.address() as AddressInfo).port}`);
  assert.equal((await app.api(route, { token: tenant.ownerToken })).status, 503);
  assert.equal(elsewhere.seen.length, 0);
});

test("unconfigured: every Chief route keeps the setup 503", async (t) => {
  const app = await startControlPlane();
  t.after(() => app.stop());
  const tenant = await seedTenant(app.api);
  assert.equal(loadChiefControlUrl({}, { introspectSecret: null }), undefined);
  assert.equal(loadChiefControlUrl({ RELAYCHIEF_CONTROL_URL: "  " }, { introspectSecret: null }), undefined);
  const route = `/cloud/api/v1/workspaces/${tenant.workspaceId}/chiefs`;
  for (const [path, method] of [[route, "GET"], [`${route}/repositories`, "GET"], [route, "POST"], [`${route}/c/scan`, "POST"]] as const) {
    const answer = await app.api(path, {
      method,
      token: tenant.ownerToken,
      ...(method === "POST" ? { body: {} } : {}),
    });
    assert.equal(answer.status, 503);
    assert.deepEqual(answer.body, {
      error: "chief_unavailable",
      message: "Chief setup is not enabled on this installation.",
    });
  }
});

test("RELAYCHIEF_CONTROL_URL is a bare origin and needs the introspection secret", () => {
  const introspectSecret = "s".repeat(32);
  assert.equal(
    loadChiefControlUrl({ RELAYCHIEF_CONTROL_URL: "http://relaychief-control:3200/" }, { introspectSecret }),
    "http://relaychief-control:3200",
  );
  for (const bad of ["relaychief-control", "ftp://x", "http://u:p@x", "http://x/chief/v1", "http://x?a=1", "http://x#a"]) {
    assert.throws(() => loadChiefControlUrl({ RELAYCHIEF_CONTROL_URL: bad }, { introspectSecret }), /must be an http\(s\) origin/);
  }
  assert.throws(
    () => loadChiefControlUrl({ RELAYCHIEF_CONTROL_URL: "http://x:3200" }, { introspectSecret: null }),
    /requires RELAYCONTROL_INTROSPECT_SECRET/,
  );
});
