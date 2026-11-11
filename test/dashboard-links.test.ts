import assert from "node:assert/strict";
import { createServer, request as httpRequest } from "node:http";
import test from "node:test";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { dashboardLinkRedirect } from "../src/dashboard-links.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase } from "./support/harness.js";

// Agent Relay Desktop builds browser links as <site> + a Cloud dashboard path,
// with its site set to the public API origin. On a split-host install those
// links land here and are sent on to relay-webapp's routes.

const API_SITE = "https://api.proof.test";
const DASHBOARD_SITE = "https://proof.test";

function redirect(target: string, options: Partial<{ method: string; host: string; dashboardUrl: string; publicBaseUrl: string }> = {}) {
  return dashboardLinkRedirect({
    method: options.method ?? "GET",
    target,
    host: options.host ?? "api.proof.test",
    publicBaseUrl: options.publicBaseUrl ?? API_SITE,
    dashboardUrl: options.dashboardUrl ?? `${DASHBOARD_SITE}/`,
  });
}

test("Desktop's View on web link opens the session on the dashboard host", () => {
  assert.equal(
    redirect("/cloud/dashboard/sessions/01a1c8ca-e19f-7273-b7a6-df04b75694b7"),
    "https://proof.test/?session=01a1c8ca-e19f-7273-b7a6-df04b75694b7",
  );
  // A trailing slash and HEAD are handled the same way.
  assert.equal(
    redirect("/cloud/dashboard/sessions/abc/", { method: "HEAD" }),
    "https://proof.test/?session=abc",
  );
});

test("a session id is decoded once and re-encoded as a query value", () => {
  assert.equal(redirect("/cloud/dashboard/sessions/a%2Fb%20c%26d"), "https://proof.test/?session=a%2Fb+c%26d");
  assert.equal(redirect("/cloud/dashboard/sessions/%3Fx%3D1%23y"), "https://proof.test/?session=%3Fx%3D1%23y");
  // Undecodable, control characters or oversized: the dashboard root instead.
  assert.equal(redirect("/cloud/dashboard/sessions/%E0%A4%A"), "https://proof.test/");
  assert.equal(redirect("/cloud/dashboard/sessions/a%0Ab"), "https://proof.test/");
  assert.equal(redirect(`/cloud/dashboard/sessions/${"a".repeat(512)}`), `https://proof.test/?session=${"a".repeat(512)}`);
  assert.equal(redirect(`/cloud/dashboard/sessions/${"a".repeat(513)}`), "https://proof.test/");
});

test("a citation link keeps its source and drops an invalid one", () => {
  assert.equal(
    redirect("/dashboard/sessions/s-1?source=claude&workspace=ignored"),
    "https://proof.test/?session=s-1&source=claude",
  );
  // Any source the read routes accept is passed on, encoded.
  assert.equal(
    redirect("/dashboard/sessions/s-1?source=claude%2Bremote"),
    "https://proof.test/?session=s-1&source=claude%2Bremote",
  );
  assert.equal(redirect("/dashboard/sessions/s-1?source=a%0Ab"), "https://proof.test/?session=s-1");
  assert.equal(redirect(`/dashboard/sessions/s-1?source=${"a".repeat(513)}`), "https://proof.test/?session=s-1");
});

test("settings, downloads and other dashboard paths map to webapp routes", () => {
  assert.equal(redirect("/cloud/dashboard/settings"), "https://proof.test/#/settings/workspace");
  assert.equal(redirect("/cloud/dashboard/settings?reason=relaycast-capacity"), "https://proof.test/#/settings/workspace");
  // Amp's `/dashboard/settings#connections` (the fragment never reaches here).
  assert.equal(redirect("/dashboard/settings"), "https://proof.test/#/settings/connections");
  assert.equal(redirect("/cloud/dashboard/downloads"), "https://proof.test/downloads");
  for (const other of ["/cloud/dashboard", "/cloud/dashboard/", "/dashboard", "/cloud/dashboard/sessions", "/cloud/dashboard/billing/x"]) {
    assert.equal(redirect(other), "https://proof.test/", other);
  }
});

test("the dashboard base path is kept and its query and fragment are not", () => {
  assert.equal(
    redirect("/cloud/dashboard/sessions/s", { dashboardUrl: "https://proof.test/app?x=1" }),
    "https://proof.test/app/?session=s",
  );
  assert.equal(
    redirect("/cloud/dashboard/downloads", { dashboardUrl: "https://proof.test/app/" }),
    "https://proof.test/app/downloads",
  );
});

test("nothing is redirected on a shared host, on the dashboard host, off-path or for writes", () => {
  assert.equal(redirect("/cloud/dashboard/sessions/s", { dashboardUrl: `${API_SITE}/` }), null);
  assert.equal(redirect("/cloud/dashboard/sessions/s", { host: "proof.test" }), null);
  assert.equal(redirect("/cloud/dashboard/settings", { method: "POST" }), null);
  for (const path of ["/cloud/api/v1/me", "/dashboards", "/cloud/dashboardx/sessions/s", "/login", "/"]) {
    assert.equal(redirect(path), null, path);
  }
});

function raw(origin: string, path: string, host: string, method = "GET") {
  const target = new URL(origin);
  return new Promise<{ status: number; headers: Record<string, string | string[] | undefined> }>((resolve, reject) => {
    const req = httpRequest({ hostname: target.hostname, port: target.port, path, method, headers: { host } }, (res) => {
      res.resume();
      res.on("end", () => resolve({ status: res.statusCode ?? 0, headers: res.headers }));
    });
    req.on("error", reject);
    req.end();
  });
}

async function serve(t: test.TestContext, dashboardUrl: string) {
  const database = new PGliteDatabase();
  await migrate(database);
  const keyring = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: API_SITE,
    relaycastUrl: "http://relaycast.invalid",
    relaycastPublicUrl: "https://cast.proof.test",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.proof.test",
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: "https://history.proof.test", secret: "session-read-secret-".repeat(2) },
    bootstrapToken: "bootstrap-token-that-is-at-least-32-bytes",
    encryptionKeyring: keyring,
    internalServiceToken: null,
    oauthRedirectUrl: `${API_SITE}/api/v1/integrations/oauth/callback`,
    dashboardUrl,
    port: 0,
    host: "127.0.0.1",
  };
  const server = createServer();
  server.on("request", createApp({ config, store: new ControlPlaneStore(database, keyring, 0) }));
  const origin = await listen(server);
  t.after(async () => {
    await close(server);
    await database.close();
  });
  return origin;
}

test("Control answers a 302 that is never cached and sends no referrer", async (t) => {
  const origin = await serve(t, `${DASHBOARD_SITE}/`);
  const session = await raw(origin, "/cloud/dashboard/sessions/01a1c8ca-e19f-7273-b7a6-df04b75694b7", "api.proof.test");
  assert.equal(session.status, 302);
  assert.equal(session.headers.location, "https://proof.test/?session=01a1c8ca-e19f-7273-b7a6-df04b75694b7");
  assert.equal(session.headers["cache-control"], "no-store");
  assert.equal(session.headers["referrer-policy"], "no-referrer");
  // A forged Host never becomes the redirect target.
  const forged = await raw(origin, "/cloud/dashboard/settings", "evil.example");
  assert.equal(forged.status, 302);
  assert.equal(forged.headers.location, "https://proof.test/#/settings/workspace");
  assert.equal((await raw(origin, "/cloud/dashboard/settings", "api.proof.test", "POST")).status, 404);
});

test("a shared dashboard host keeps the existing 404", async (t) => {
  const origin = await serve(t, `${API_SITE}/`);
  const response = await raw(origin, "/cloud/dashboard/sessions/s", "api.proof.test");
  assert.equal(response.status, 404);
  assert.equal(response.headers.location, undefined);
});
