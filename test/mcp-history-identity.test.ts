import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import type { SelfhostConfig } from "../src/config.js";
import { historyReader } from "../src/mcp/context.js";
import { forgetSessionReadTokens } from "../src/mcp/session-read-reader.js";
import type { Principal } from "../src/store.js";

const HISTORY = "https://history.example.com";
const READ_API = "https://read.example.com";
const PUBLIC = "https://read.public.example.com";
const SECRET = "service-secret-service-secret-service-secret";
const WORKSPACE_HEADER = "x-relayhistory-workspace-id";
const padded = (value: string) => value.replace(/[^A-Za-z0-9_-]/g, "_").padEnd(44, "x");

type Issue = { body: Record<string, string>; bearer: string | null; path: string };
type Read = { url: URL; bearer: string | null };
type Options = {
  ttlMs?: number;
  readStatus?: (url: URL, bearer: string | null) => number;
  attest?: (workspace: string) => string;
  issueStatus?: () => number;
};

function config(on = true) {
  return {
    relayhistoryUrl: HISTORY,
    sessionReadApi: { url: READ_API, publicUrl: PUBLIC, secret: SECRET },
    sessionReadMcpReads: on,
  } as SelfhostConfig;
}
const principal = (userId: string) => ({ userId }) as Principal;
const workspace = (id: string, organizationId: string) => ({ id, organizationId }) as never;

function fake(t: TestContext, options: Options = {}) {
  const issues: Issue[] = [];
  const reads: Read[] = [];
  const history: Read[] = [];
  let serial = 0;
  const original = globalThis.fetch;
  t.after(() => {
    globalThis.fetch = original;
  });
  globalThis.fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = new URL(String(input));
    const bearer = new Headers(init.headers).get("authorization");
    if (url.pathname.startsWith("/internal/v1/session-read/sessions")) {
      const body = JSON.parse(String(init.body)) as Record<string, string>;
      issues.push({ body, bearer, path: url.pathname });
      const status = options.issueStatus?.() ?? 200;
      if (status !== 200) return new Response("", { status });
      serial += 1;
      return Response.json({
        sessionId: `session-${serial}`,
        userId: body.userId,
        orgId: body.orgId,
        workspaceId: body.workspaceId,
        audience: body.audience,
        scopes: ["rth:read"],
        accessToken: `rth_at_read_${padded(`${body.userId}_${serial}`)}`,
        accessTokenExpiresAt: new Date(Date.now() + (options.ttlMs ?? 300_000)).toISOString(),
        refreshToken: `rth_rt_read_${padded(`${body.userId}_${serial}`)}`,
        refreshTokenExpiresAt: new Date(Date.now() + 86_400_000).toISOString(),
        tokenType: "Bearer",
      });
    }
    if (url.origin === HISTORY) {
      history.push({ url, bearer });
      if (url.pathname === "/v1/cli/login") {
        return Response.json({
          accessToken: "history-token",
          accessTokenExpiresAt: new Date(Date.now() + 300_000).toISOString(),
          refreshToken: "history-refresh",
          refreshTokenExpiresAt: new Date(Date.now() + 86_400_000).toISOString(),
          tokenType: "Bearer",
        });
      }
      return Response.json({ from: "history" }, { headers: { [WORKSPACE_HEADER]: url.searchParams.get("workspace") ?? "" } });
    }
    reads.push({ url, bearer });
    const status = options.readStatus?.(url, bearer) ?? 200;
    if (status !== 200) return new Response("", { status });
    const attested = options.attest?.(url.searchParams.get("workspace") ?? "") ?? url.searchParams.get("workspace") ?? "";
    return Response.json({ from: "read-api" }, { headers: { [WORKSPACE_HEADER]: attested } });
  }) as typeof fetch;
  return { issues, reads, history };
}

test("the setting off leaves MCP reads on the existing History path", async (t) => {
  const seen = fake(t);
  const cfg = config(false);
  const body = await historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a")("/v1/sessions");
  assert.deepEqual(body, { from: "history" });
  assert.equal(seen.issues.length, 0);
  assert.equal(seen.reads.length, 0);
});

test("each MCP read carries only the calling user's token, never a shared credential", async (t) => {
  const seen = fake(t);
  const cfg = config();
  t.after(() => forgetSessionReadTokens(cfg));

  await historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a")("/v1/sessions?limit=1");
  await historyReader(cfg, principal("user-b"), workspace("ws-b", "org-b"), "sh_at_user_b")("/v1/sessions?limit=1");

  assert.deepEqual(
    seen.issues.map(({ body }) => [body.userId, body.orgId, body.workspaceId, body.audience]),
    [["user-a", "org-a", "ws-a", PUBLIC], ["user-b", "org-b", "ws-b", PUBLIC]],
  );
  assert.deepEqual(
    seen.reads.map(({ bearer, url }) => [bearer?.includes("user-a_1") || bearer?.includes("user-b_2"), url.searchParams.get("workspace")]),
    [[true, "ws-a"], [true, "ws-b"]],
  );
  assert.ok(seen.reads[0]!.bearer!.includes("user-a") && seen.reads[1]!.bearer!.includes("user-b"));
  for (const read of seen.reads) {
    assert.match(read.bearer!, /^Bearer rth_at_read_/);
    assert.ok(!read.bearer!.includes(SECRET), "the service secret never reaches a read");
  }
  assert.equal(seen.history.length, 0);
});

test("the same person in another org gets a separate session", async (t) => {
  const seen = fake(t);
  const cfg = config();
  t.after(() => forgetSessionReadTokens(cfg));

  await historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a")("/v1/sessions");
  await historyReader(cfg, principal("user-a"), workspace("ws-c", "org-c"), "sh_at_user_a_c")("/v1/sessions");

  assert.deepEqual(seen.issues.map(({ body }) => [body.orgId, body.workspaceId]), [["org-a", "ws-a"], ["org-c", "ws-c"]]);
  assert.notEqual(seen.reads[0]!.bearer, seen.reads[1]!.bearer);
});

test("a tool path cannot widen the read to another workspace", async (t) => {
  const seen = fake(t);
  const cfg = config();
  t.after(() => forgetSessionReadTokens(cfg));

  await historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a")("/v1/sessions?workspace=ws-other");

  assert.deepEqual(seen.reads[0]!.url.searchParams.getAll("workspace"), ["ws-a"]);
  assert.deepEqual(seen.issues[0]!.body.workspaceId, "ws-a");
});

test("a response attesting another workspace never reaches the tool or falls back", async (t) => {
  const seen = fake(t, { attest: () => "ws-other" });
  const cfg = config();
  t.after(() => forgetSessionReadTokens(cfg));

  await assert.rejects(
    historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a")("/v1/sessions"),
    /not available yet/,
  );
  assert.equal(seen.history.length, 0);
});

test("a near-expiry token is refreshed once, sending only the held refresh token", async (t) => {
  const seen = fake(t, { ttlMs: 10_000 });
  const cfg = config();
  t.after(() => forgetSessionReadTokens(cfg));
  const read = historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a");

  await read("/v1/sessions");
  await read("/v1/sessions");

  assert.deepEqual(seen.issues.map(({ path }) => path), ["/internal/v1/session-read/sessions", "/internal/v1/session-read/sessions/refresh"]);
  assert.match(seen.issues[1]!.body.refreshToken!, /^rth_rt_read_user-a_1/);
  assert.equal(seen.issues[1]!.body.userId, "user-a");
});

test("a first page the read API can't serve falls back to History", async (t) => {
  const seen = fake(t, { readStatus: () => 501 });
  const cfg = config();
  t.after(() => forgetSessionReadTokens(cfg));

  const body = await historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a")("/v1/sessions");
  assert.deepEqual(body, { from: "history" });
  assert.equal(seen.reads.length, 1);
});

test("a read API cursor is never restarted on History", async (t) => {
  const seen = fake(t, { readStatus: () => 503 });
  const cfg = config();
  t.after(() => forgetSessionReadTokens(cfg));

  await assert.rejects(
    historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a")("/v1/sessions?cursor=b96l1:x"),
    /temporarily unavailable/,
  );
  assert.equal(seen.history.length, 0);
});

test("a failed issue on a first page falls back rather than reading", async (t) => {
  const seen = fake(t, { issueStatus: () => 503 });
  const cfg = config();
  t.after(() => forgetSessionReadTokens(cfg));

  const body = await historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a")("/v1/sessions");
  assert.deepEqual(body, { from: "history" });
  assert.equal(seen.reads.length, 0);
});

test("routes outside the read contract stay on History", async (t) => {
  const seen = fake(t);
  const cfg = config();
  t.after(() => forgetSessionReadTokens(cfg));

  const body = await historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a")("/v1/sessions/s-1/timing");
  assert.deepEqual(body, { from: "history" });
  assert.equal(seen.issues.length, 0);
});
