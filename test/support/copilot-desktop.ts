import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import type { TestContext } from "node:test";
import { createApp } from "../../src/app.js";
import type { SelfhostConfig } from "../../src/config.js";
import { migrate } from "../../src/migrations.js";
import { ControlPlaneStore } from "../../src/store.js";
import { close, listen, PGliteDatabase, request } from "./harness.js";
import { createRelaycastWorld, type RelaycastWorld } from "./relaycast-world.js";

/**
 * A self-host control plane on PGlite with an in-process Relaycast world, and
 * the real Desktop browser sign-in (consent screen + S256 redemption) that
 * yields a verified Desktop parent. Shared by the Copilot / desktop-MCP tests.
 */

export const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const VERIFIER = "desktop-verifier-0123456789abcdefghijklmnopqrstuvwxyz0123456789";
const CHALLENGE = createHash("sha256").update(VERIFIER).digest("base64url");

/** Relaycast served through the injected messaging fetch: the roster and the relay world. */
function relaycastFetch(roster: unknown[], world: RelaycastWorld): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    const headers = new Headers(init?.headers);
    const json = (status: number, body: unknown) => new Response(JSON.stringify(body), {
      status, headers: { "content-type": "application/json" },
    });
    if (url.pathname === "/v1/agents" && (init?.method ?? "GET") === "GET") return json(200, { ok: true, data: roster });
    if (url.pathname === "/v1/agents/presence") return json(200, { ok: true, data: [] });
    const body = typeof init?.body === "string" && init.body ? JSON.parse(init.body) as Record<string, any> : null;
    const handled = await world.handle(init?.method ?? "GET", url.pathname, url.searchParams,
      (headers.get("authorization") ?? "").replace(/^Bearer /, ""), body, headers.get("idempotency-key"));
    return handled ? json(handled.status, handled.body) : json(404, { ok: false, error: { code: "not_found" } });
  }) as typeof fetch;
}

export async function copilotDesktopSetup(t: TestContext, modules: Pick<Parameters<typeof createApp>[0], "capy"> = {}) {
  const database = new PGliteDatabase();
  await migrate(database);
  const roster: unknown[] = [];
  const world = createRelaycastWorld(roster);
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseUrl: "unused-in-test",
    publicBaseUrl: origin,
    relaycastUrl: "http://relaycast.internal",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayhistoryUrl: "http://relayhistory.invalid",
    relayhistoryPublicUrl: "https://history.selfhosted.test",
    sessionReadApi: { url: "http://relayhistory.invalid", publicUrl: "https://history.selfhosted.test", secret: "session-read-secret-".repeat(2) },
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: KEYRING,
    internalServiceToken: null,
    oauthRedirectUrl: `${origin}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${origin}/`,
    port: 0,
    host: "127.0.0.1",
  };
  const store = new ControlPlaneStore(database, KEYRING, 0);
  control.on("request", createApp({ config, store, messagingFetch: relaycastFetch(roster, world), ...modules }));
  t.after(async () => {
    await close(control);
    await database.close();
  });
  const org = await request(origin, "/api/v1/organizations", {
    method: "POST", token: BOOTSTRAP, body: { name: "Acme", ownerEmail: "owner@acme.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const orgId = org.body.id as string;
  const ownerId = org.body.owner.id as string;
  const workspace = await request(origin, `/api/v1/organizations/${orgId}/workspaces`, {
    method: "POST", token: BOOTSTRAP, body: { name: "Primary", relaycastApiKey: "rk_primary", relaycastWorkspaceId: "rw_primary" },
  });
  assert.equal(workspace.status, 201);
  const workspaceId = workspace.body.id as string;
  const otherWorkspace = await request(origin, `/api/v1/organizations/${orgId}/workspaces`, {
    method: "POST", token: BOOTSTRAP, body: { name: "Other", relaycastApiKey: "rk_other", relaycastWorkspaceId: "rw_other" },
  });
  assert.equal(otherWorkspace.status, 201);

  /** A device-flow token (an unverified sign-in that still carries cli:auth). */
  async function deviceLogin(userId = ownerId, inWorkspace = workspaceId): Promise<string> {
    const started = await request(origin, "/api/v1/auth/device/start", { method: "POST", body: { client_name: "copilot-test" } });
    assert.equal(started.status, 201);
    const approved = await request(origin, "/api/v1/auth/device/approve", {
      method: "POST", token: BOOTSTRAP,
      body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: inWorkspace },
    });
    assert.equal(approved.status, 200);
    const tokens = await request(origin, "/api/v1/auth/device/token", { method: "POST", body: { device_code: started.body.device_code } });
    assert.equal(tokens.status, 200);
    return tokens.body.access_token as string;
  }

  /** Signs a browser in through /login, approved by the bootstrap bearer. */
  async function browserSession(userId = ownerId): Promise<string> {
    const login = await fetch(`${origin}/login`);
    const code = (await login.text()).match(/<code>([A-Z0-9]{4}-[A-Z0-9]{4})<\/code>/)?.[1];
    assert(code);
    const deviceCookie = login.headers.get("set-cookie")!.split(";")[0]!;
    const approved = await request(origin, "/api/v1/auth/device/approve", {
      method: "POST", token: BOOTSTRAP, body: { action: "approve", user_code: code, user_id: userId, workspace_id: workspaceId },
    });
    assert.equal(approved.status, 200);
    const poll = await request(origin, "/login/poll", { method: "POST", cookie: deviceCookie });
    assert.equal(poll.status, 200);
    const session = poll.headers.get("set-cookie")?.match(/agent_relay_session=[^;]+/)?.[0];
    assert(session);
    return session;
  }

  /**
   * Desktop's browser sign-in. With `hostName`, the person approves "Agent
   * Relay Desktop on <host>" on the consent screen; without, the handoff is
   * issued at once. Returns the one-time handoff bearer and, after the S256
   * redemption, the renewable session (the parent).
   */
  async function desktopSignIn(options: { hostName?: string; userId?: string } = {}) {
    const session = await browserSession(options.userId);
    const params = new URLSearchParams({
      redirect_uri: "http://127.0.0.1:5123/callback/STATE1", state: "STATE1", client: "desktop",
      workspace_selection: "desktop", code_challenge: CHALLENGE, code_challenge_method: "S256",
      // Browser sessions carry the account scope and this fixture has two
      // workspaces, so name one (otherwise the sign-in shows the picker).
      workspace: workspaceId,
      ...(options.hostName ? { desktop_host_name: options.hostName } : {}),
    });
    let location: string | null;
    if (options.hostName) {
      const page = await fetch(`${origin}/cloud/api/v1/cli/login?${params}`, { redirect: "manual", headers: { cookie: session } });
      assert.equal(page.status, 200);
      const html = await page.text();
      const fields = Object.fromEntries([...html.matchAll(/name="([a-z_]+)" value="([^"]*)"/g)].map((m) => [m[1]!, m[2]!]));
      assert(fields.consent_token);
      const approved = await fetch(`${origin}/cloud/api/v1/cli/login`, {
        method: "POST", redirect: "manual",
        headers: { cookie: session, origin, "sec-fetch-site": "same-origin", "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ ...fields, decision: "approve" }).toString(),
      });
      assert.equal(approved.status, 303);
      location = approved.headers.get("location");
    } else {
      const handoff = await fetch(`${origin}/cloud/api/v1/cli/login?${params}`, { redirect: "manual", headers: { cookie: session } });
      assert.equal(handoff.status, 307);
      location = handoff.headers.get("location");
    }
    const handoffToken = new URL(location!).searchParams.get("access_token")!;
    assert.match(handoffToken, /^sh_at_/);
    const exchanged = await request(origin, "/cloud/api/v1/auth/desktop/session", {
      method: "POST", token: handoffToken, body: { codeVerifier: VERIFIER },
    });
    assert.equal(exchanged.status, 200);
    return { session, handoffToken, accessToken: exchanged.body.accessToken as string, refreshToken: exchanged.body.refreshToken as string };
  }

  /** Adds a second member of the organization. */
  async function addMember(email: string): Promise<string> {
    const added = await request(origin, `/api/v1/organizations/${orgId}/memberships`, {
      method: "POST", token: BOOTSTRAP, body: { email, name: email.split("@")[0], role: "member" },
    });
    assert.equal(added.status, 200, added.raw);
    return added.body.userId as string;
  }

  return {
    origin, config, database, store, world, roster, orgId, ownerId, workspaceId,
    otherWorkspaceId: otherWorkspace.body.id as string,
    deviceLogin, browserSession, desktopSignIn, addMember,
  };
}

/** The secret Agent Relay Desktop mints and saves before registering it. */
export const desktopSecret = () => `sh_at_${randomBytes(32).toString("base64url")}`;
export const installationId = () => randomUUID();

export const tokensPath = (workspaceId: string, tokenId?: string) =>
  `/api/v1/workspaces/${workspaceId}/mcp/shared-sessions-tokens${tokenId ? `/${tokenId}` : ""}`;
export const identitiesPath = (workspaceId: string) => `/api/v1/workspaces/${workspaceId}/messaging/desktop-identities`;
export const MCP_PATH = "/api/v1/mcp/shared-sessions";
