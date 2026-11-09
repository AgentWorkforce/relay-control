import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import { createApp } from "../src/app.js";
import {
  cloudPathForNext,
  ConsentTokens,
  isLoopbackRedirectUri,
  validateDesktopLogin,
} from "../src/auth/desktop-login.js";
import type { SelfhostConfig } from "../src/config.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const KEYRING = { active: { id: "test-key", key: Buffer.alloc(32, 7) } };
const VERIFIER = "desktop-verifier-0123456789abcdefghijklmnopqrstuvwxyz0123456789";
const CHALLENGE = createHash("sha256").update(VERIFIER).digest("base64url");

/** A stand-in Relaycast: node tokens and the workspace key's node reads. */
function fakeRelaycast(state: { nodes: Record<string, { id: string; name: string }>; workspaceKey: string; hidden: string[] }) {
  return createServer((req, res) => {
    const auth = req.headers.authorization?.replace(/^Bearer /, "") ?? "";
    const url = new URL(req.url ?? "/", "http://relaycast.test");
    const reply = (status: number, body: unknown) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(body));
    };
    if (url.pathname === "/v1/node/me") {
      const node = state.nodes[auth];
      return node ? reply(200, { ok: true, data: node }) : reply(401, { ok: false });
    }
    const byName = /^\/v1\/nodes\/([^/]+)$/.exec(url.pathname);
    if (byName) {
      if (auth !== state.workspaceKey) return reply(401, { ok: false });
      const name = decodeURIComponent(byName[1]!);
      const node = Object.values(state.nodes).find((n) => n.name === name);
      return node && !state.hidden.includes(name) ? reply(200, { ok: true, data: node }) : reply(404, { ok: false });
    }
    reply(404, { ok: false });
  });
}

async function setup(t: test.TestContext) {
  const database = new PGliteDatabase();
  await migrate(database);
  const relaycastState = {
    nodes: { nt_live_desktop_token_abc: { id: "node_desk", name: "sf-mini" } } as Record<string, { id: string; name: string }>,
    workspaceKey: "rk_primary",
    hidden: [] as string[],
  };
  const relaycast = fakeRelaycast(relaycastState);
  const relaycastUrl = await listen(relaycast);
  const control = createServer();
  const origin = await listen(control);
  const config: SelfhostConfig = {
    databaseUrl: "unused",
    publicBaseUrl: origin,
    relaycastUrl,
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
  control.on("request", createApp({ config, store }));
  t.after(async () => {
    await close(control);
    await close(relaycast);
    await database.close();
  });
  const org = await request(origin, "/api/v1/organizations", {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Acme", ownerEmail: "owner@acme.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const workspace = await request(origin, `/api/v1/organizations/${org.body.id}/workspaces`, {
    method: "POST",
    token: BOOTSTRAP,
    body: { name: "Primary", relaycastApiKey: "rk_primary", relaycastWorkspaceId: "rw_primary" },
  });
  assert.equal(workspace.status, 201);
  return {
    origin,
    relaycastState,
    orgId: org.body.id as string,
    ownerId: org.body.owner.id as string,
    workspaceId: workspace.body.id as string,
  };
}

/** Signs a browser in through /login, approved by the bootstrap bearer. */
async function browserSession(origin: string, ownerId: string, workspaceId: string): Promise<string> {
  const login = await fetch(`${origin}/login`);
  const code = (await login.text()).match(/<code>([A-Z0-9]{4}-[A-Z0-9]{4})<\/code>/)?.[1];
  assert(code);
  const deviceCookie = login.headers.get("set-cookie")!.split(";")[0]!;
  const approved = await request(origin, "/api/v1/auth/device/approve", {
    method: "POST",
    token: BOOTSTRAP,
    body: { action: "approve", user_code: code, user_id: ownerId, workspace_id: workspaceId },
  });
  assert.equal(approved.status, 200);
  const poll = await request(origin, "/login/poll", { method: "POST", cookie: deviceCookie });
  assert.equal(poll.status, 200);
  const session = poll.headers.get("set-cookie")?.match(/agent_relay_session=[^;]+/)?.[0];
  assert(session);
  return session;
}

/** The URL desktop-core browser_login.rs opens (reuse_browser_session=true). */
function loginPath(extra: Record<string, string> = {}): string {
  const params = new URLSearchParams({
    redirect_uri: "http://127.0.0.1:5123/callback/STATE1",
    state: "STATE1",
    client: "desktop",
    workspace_selection: "desktop",
    code_challenge: CHALLENGE,
    code_challenge_method: "S256",
    ...extra,
  });
  return `/cloud/api/v1/cli/login?${params}`;
}

function callbackParams(location: string | null): URLSearchParams {
  assert(location);
  const url = new URL(location);
  assert.equal(url.origin, "http://127.0.0.1:5123");
  assert.equal(url.pathname, "/callback/STATE1");
  return url.searchParams;
}

test("a signed-out browser is sent to /login and back; hosted's google/start also lands on /login", async (t) => {
  const { origin } = await setup(t);
  const unauthenticated = await fetch(`${origin}${loginPath()}`, { redirect: "manual" });
  assert.equal(unauthenticated.status, 302);
  const next = new URL(unauthenticated.headers.get("location")!, origin);
  assert.equal(next.pathname, "/login");
  assert.equal(new URL(next.searchParams.get("next")!, origin).pathname, "/cloud/api/v1/cli/login");

  const google = await fetch(
    `${origin}/cloud/api/auth/google/start?next=${encodeURIComponent("/api/v1/cli/login?state=STATE1&client=desktop")}`,
    { redirect: "manual" },
  );
  assert.equal(google.status, 302);
  const mapped = new URL(google.headers.get("location")!, origin);
  assert.equal(mapped.pathname, "/login");
  assert.equal(mapped.searchParams.get("next"), "/cloud/api/v1/cli/login?state=STATE1&client=desktop");
  const microsoft = await fetch(
    `${origin}/cloud/api/auth/microsoft/start?next=${encodeURIComponent("/api/v1/cli/login?redirect_uri=http%3A%2F%2F127.0.0.1%3A5123%2Fcallback%2FSTATE1&state=STATE1&client=desktop&workspace_selection=desktop&code_challenge=abc&code_challenge_method=S256")}`,
    { redirect: "manual" },
  );
  assert.equal(microsoft.status, 302);
  const inner = new URL(new URL(microsoft.headers.get("location")!, origin).searchParams.get("next")!, origin);
  assert.equal(inner.pathname, "/cloud/api/v1/cli/login");
  assert.equal(inner.searchParams.get("redirect_uri"), "http://127.0.0.1:5123/callback/STATE1");
  assert.equal(inner.searchParams.get("workspace_selection"), "desktop");
  assert.equal(inner.searchParams.get("code_challenge_method"), "S256");
  assert.equal(cloudPathForNext("https://evil.example/x"), "/");
  assert.equal(cloudPathForNext("//evil.example"), "/");
});

test("the browser flow hands the loopback listener a challenge-bound token that the verifier redeems once", async (t) => {
  const { origin, ownerId, workspaceId } = await setup(t);
  const session = await browserSession(origin, ownerId, workspaceId);

  // No desktop_host_name: issued at once (hosted issueHandoff), 307 to loopback.
  const handoff = await fetch(`${origin}${loginPath()}`, { redirect: "manual", headers: { cookie: session } });
  assert.equal(handoff.status, 307);
  assert.equal(handoff.headers.get("cache-control"), "no-store");
  const params = callbackParams(handoff.headers.get("location"));
  assert.equal(params.get("state"), "STATE1");
  assert.equal(params.get("api_url"), `${origin}/cloud`);
  assert.equal(params.get("refresh_token"), null);
  const accessToken = params.get("access_token")!;
  assert.match(accessToken, /^sh_at_/);
  const expiresAt = Date.parse(params.get("access_token_expires_at")!);
  assert(expiresAt - Date.now() <= 15 * 60_000 && expiresAt > Date.now());

  // The handoff bearer already works for the workspace exchange.
  const resolve = await request(origin, `/cloud/api/v1/workspaces/${workspaceId}/resolve`, { token: accessToken });
  assert.equal(resolve.status, 200);
  assert.equal(resolve.body.relaycastApiKey, "rk_primary");

  // Wrong verifier, then the right one, then a replay.
  const wrong = await request(origin, "/cloud/api/v1/auth/desktop/session", {
    method: "POST", token: accessToken, body: { codeVerifier: `${VERIFIER}x` },
  });
  assert.equal(wrong.status, 401);
  const exchanged = await request(origin, "/cloud/api/v1/auth/desktop/session", {
    method: "POST", token: accessToken, body: { codeVerifier: VERIFIER },
  });
  assert.equal(exchanged.status, 200);
  assert.equal(exchanged.body.tokenType, "Bearer");
  assert.equal(exchanged.body.apiUrl, `${origin}/cloud`);
  assert.match(exchanged.body.refreshToken, /^sh_rt_/);
  const replay = await request(origin, "/cloud/api/v1/auth/desktop/session", {
    method: "POST", token: accessToken, body: { codeVerifier: VERIFIER },
  });
  assert.equal(replay.status, 401);

  // The renewable session is a normal one: whoami and refresh work.
  const whoami = await request(origin, "/cloud/api/v1/auth/whoami", { token: exchanged.body.accessToken });
  assert.equal(whoami.status, 200);
  assert.equal(whoami.body.currentWorkspace.id, workspaceId);
  assert.equal(whoami.body.workspaceCount, 1);
  // The handoff carries desktop:workspaces: Desktop lists its workspaces here
  // instead of falling back to the browser picker (DG-001).
  const listed = await request(origin, "/cloud/api/v1/auth/desktop/workspaces", { token: exchanged.body.accessToken });
  assert.equal(listed.status, 200);
  assert.equal(listed.body.current_workspace_id, workspaceId);
  assert.deepEqual(listed.body.workspaces.map((workspace: { id: string }) => workspace.id), [workspaceId]);
  const refreshed = await request(origin, "/cloud/api/v1/auth/token/refresh", {
    method: "POST", body: { refreshToken: exchanged.body.refreshToken },
  });
  assert.equal(refreshed.status, 200);

  // A plain session token (no challenge) cannot be exchanged.
  const plain = await request(origin, "/cloud/api/v1/auth/desktop/session", {
    method: "POST", token: exchanged.body.accessToken, body: { codeVerifier: VERIFIER },
  });
  assert.equal(plain.status, 401);
});

test("a sign-in naming its host needs the person's approval on a same-origin consent screen", async (t) => {
  const { origin, ownerId, workspaceId } = await setup(t);
  const session = await browserSession(origin, ownerId, workspaceId);
  const page = await fetch(`${origin}${loginPath({ desktop_host_name: "sf-mini" })}`, {
    redirect: "manual", headers: { cookie: session },
  });
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.match(html, /Agent Relay Desktop on <strong>sf-mini<\/strong>/);
  assert.match(html, /<strong>Primary<\/strong>/);
  const consentToken = html.match(/name="consent_token" value="([^"]+)"/)?.[1];
  assert(consentToken);
  const fields = Object.fromEntries(
    [...html.matchAll(/name="([a-z_]+)" value="([^"]*)"/g)].map((m) => [m[1]!, m[2]!]),
  );
  const post = (overrides: Record<string, string>, headers: Record<string, string> = {}) =>
    fetch(`${origin}/cloud/api/v1/cli/login`, {
      method: "POST",
      redirect: "manual",
      headers: {
        cookie: session,
        origin,
        "sec-fetch-site": "same-origin",
        "content-type": "application/x-www-form-urlencoded",
        ...headers,
      },
      body: new URLSearchParams({ ...fields, decision: "approve", ...overrides }).toString(),
    });

  // Cross-origin, forged, and missing tokens are refused; nothing is issued.
  assert.equal((await post({}, { origin: "https://evil.example" })).status, 403);
  assert.equal((await post({ consent_token: "forged" })).status, 403);
  assert.equal((await post({ consent_token: consentToken, desktop_host_name: "other-host" })).status, 403);

  // A fresh screen's token approves once (the previous one was consumed by the forgery check).
  const again = await fetch(`${origin}${loginPath({ desktop_host_name: "sf-mini" })}`, {
    redirect: "manual", headers: { cookie: session },
  });
  const token2 = (await again.text()).match(/name="consent_token" value="([^"]+)"/)?.[1];
  assert(token2);
  const approved = await post({ consent_token: token2 });
  assert.equal(approved.status, 303);
  const params = callbackParams(approved.headers.get("location"));
  assert.match(params.get("access_token")!, /^sh_at_/);
  const replay = await post({ consent_token: token2 });
  assert.equal(replay.status, 403);

  // Deny issues nothing.
  const third = await fetch(`${origin}${loginPath({ desktop_host_name: "sf-mini" })}`, {
    redirect: "manual", headers: { cookie: session },
  });
  const token3 = (await third.text()).match(/name="consent_token" value="([^"]+)"/)?.[1];
  const denied = await post({ consent_token: token3!, decision: "deny" });
  assert.equal(denied.status, 200);
  assert.match(await denied.text(), /Sign-in denied/);
});

test("bad login requests are refused before any session work", async (t) => {
  const { origin, ownerId, workspaceId } = await setup(t);
  const session = await browserSession(origin, ownerId, workspaceId);
  const cases: Array<[string, Record<string, string>]> = [
    ["non-loopback redirect", { redirect_uri: "https://evil.example/callback" }],
    ["bad challenge", { code_challenge: "short" }],
    ["host without challenge", { code_challenge: "", code_challenge_method: "", desktop_host_name: "x" }],
  ];
  for (const [name, extra] of cases) {
    const url = new URL(`${origin}${loginPath()}`);
    for (const [key, value] of Object.entries(extra)) {
      if (value === "") url.searchParams.delete(key);
      else url.searchParams.set(key, value);
    }
    const response = await fetch(url, { redirect: "manual", headers: { cookie: session } });
    assert.equal(response.status, 400, name);
  }
  // Another workspace than the session's is refused, as in the device flow.
  const other = await fetch(`${origin}${loginPath({ workspace: "00000000-0000-0000-0000-000000000000" })}`, {
    redirect: "manual", headers: { cookie: session },
  });
  assert.equal(other.status, 403);
  // Outside /cloud there is no session cookie, so the person is sent to sign in.
  const bare = await fetch(`${origin}${loginPath().replace("/cloud", "")}`, {
    redirect: "manual", headers: { cookie: session },
  });
  assert.equal(bare.status, 302);

  assert.equal(isLoopbackRedirectUri("http://localhost:1234/cb"), true);
  assert.equal(isLoopbackRedirectUri("http://user@127.0.0.1/cb"), false);
  assert.equal(isLoopbackRedirectUri("http://127.0.0.1.evil.example/cb"), false);
  const login = validateDesktopLogin(new URLSearchParams({
    redirect_uri: "http://127.0.0.1:1/cb", client: "desktop",
  }));
  assert("codeChallenge" in login && login.codeChallenge === null);
  const tokens = new ConsentTokens(() => 0, 1_000);
  const attempt = { userId: "u", codeChallenge: "c", hostName: "h", workspaceId: "w", redirectUri: "r" };
  const issued = tokens.issue(attempt);
  assert.equal(tokens.consume(issued, { ...attempt, userId: "other" }), false);
  assert.equal(tokens.consume(issued, attempt), false, "consumed by the first attempt");
});

test("the Desktop claims its spawn node with a proven node token, idempotently, and can release it", async (t) => {
  const { origin, ownerId, workspaceId, relaycastState, orgId } = await setup(t);
  const session = await browserSession(origin, ownerId, workspaceId);
  const handoff = await fetch(`${origin}${loginPath()}`, { redirect: "manual", headers: { cookie: session } });
  const token = callbackParams(handoff.headers.get("location")).get("access_token")!;
  const claim = (body: unknown, method = "POST", bearer = token) =>
    request(origin, "/cloud/api/v1/fleet/nodes/claim", { method, token: bearer, body });

  assert.equal((await claim({ workspaceId, nodeToken: "bogus" })).status, 400);
  assert.equal((await claim({ workspaceId: "other", nodeToken: "nt_live_desktop_token_abc" })).status, 404);
  const unknown = await claim({ workspaceId, nodeToken: "nt_live_unknown_token_xyz" });
  assert.equal(unknown.status, 403);
  assert.equal(unknown.body.error, "node_claim_refused");

  const first = await claim({ workspaceId, nodeToken: "nt_live_desktop_token_abc" });
  assert.equal(first.status, 200);
  assert.deepEqual(first.body, { nodeId: "node_desk", claimed: true, owner: "you" });
  const second = await claim({ workspaceId, nodeToken: "nt_live_desktop_token_abc" });
  assert.deepEqual(second.body, { nodeId: "node_desk", claimed: false, owner: "you" });

  // Another member cannot take an owned node; the owner (or an org owner) releases it.
  const member = await request(origin, `/api/v1/organizations/${orgId}/memberships`, {
    method: "POST", token: BOOTSTRAP, body: { email: "member@acme.test", name: "Member", role: "member" },
  });
  assert.equal(member.status, 200);
  const memberSession = await browserSession(origin, member.body.userId ?? member.body.user?.id, workspaceId);
  const memberHandoff = await fetch(`${origin}${loginPath()}`, { redirect: "manual", headers: { cookie: memberSession } });
  const memberToken = callbackParams(memberHandoff.headers.get("location")).get("access_token")!;
  const taken = await claim({ workspaceId, nodeToken: "nt_live_desktop_token_abc" }, "POST", memberToken);
  assert.equal(taken.status, 409);
  const notYours = await claim({ workspaceId, nodeId: "node_desk" }, "DELETE", memberToken);
  assert.equal(notYours.status, 403);
  const released = await claim({ workspaceId, nodeId: "node_desk" }, "DELETE");
  assert.deepEqual(released.body, { released: true });
  const gone = await claim({ workspaceId, nodeId: "node_desk" }, "DELETE");
  assert.equal(gone.status, 404);
  // The member can claim it now that it is free; a node Relaycast does not know in this workspace is refused.
  const mine = await claim({ workspaceId, nodeToken: "nt_live_desktop_token_abc" }, "POST", memberToken);
  assert.equal(mine.body.claimed, true);
  relaycastState.nodes.nt_live_foreign_token_000 = { id: "node_far", name: "elsewhere" };
  relaycastState.hidden.push("elsewhere");
  const foreign = await claim({ workspaceId, nodeToken: "nt_live_foreign_token_000" });
  assert.equal(foreign.status, 403);
  // Relaycast unreachable or refusing the workspace key is a 502, never a hung request.
  relaycastState.workspaceKey = "rk_other_workspace";
  relaycastState.hidden.length = 0;
  const unconfirmed = await claim({ workspaceId, nodeToken: "nt_live_foreign_token_000" });
  assert.equal(unconfirmed.status, 502);
});

test("the bootstrap bearer replaces a workspace's Relaycast key after the relay behind it was reset", async (t) => {
  const { origin, ownerId, workspaceId, orgId } = await setup(t);
  const session = await browserSession(origin, ownerId, workspaceId);
  const handoff = await fetch(`${origin}${loginPath()}`, { redirect: "manual", headers: { cookie: session } });
  const token = callbackParams(handoff.headers.get("location")).get("access_token")!;

  const replaced = await request(origin, `/api/v1/organizations/${orgId}/workspaces/${workspaceId}`, {
    method: "PUT", token: BOOTSTRAP, body: { relaycastApiKey: "rk_reminted", relaycastWorkspaceId: "rw_new" },
  });
  assert.equal(replaced.status, 200);
  assert.equal(replaced.body.relaycastWorkspaceId, "rw_new");
  const resolve = await request(origin, `/cloud/api/v1/workspaces/${workspaceId}/resolve`, { token });
  assert.equal(resolve.body.relaycastApiKey, "rk_reminted");
  assert.equal(resolve.body.relaycastWorkspaceId, "rw_new");

  // Empty updates and unknown workspaces are refused; a member's own token is not enough.
  const empty = await request(origin, `/api/v1/organizations/${orgId}/workspaces/${workspaceId}`, {
    method: "PUT", token: BOOTSTRAP, body: {},
  });
  assert.equal(empty.status, 400);
  const missing = await request(origin, `/api/v1/organizations/${orgId}/workspaces/00000000-0000-0000-0000-000000000000`, {
    method: "PUT", token: BOOTSTRAP, body: { relaycastApiKey: "rk_x" },
  });
  assert.equal(missing.status, 404);
});
