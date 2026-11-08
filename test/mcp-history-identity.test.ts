import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import type { SelfhostConfig } from "../src/config.js";
import { historyReader } from "../src/mcp/context.js";
import { forgetSessionReadTokens } from "../src/mcp/session-read-reader.js";
import type { Principal } from "../src/store.js";

const CONTROL = "https://control.example.com";
const HISTORY = "https://history.example.com";
const READ_API = "https://read.example.com";
const PUBLIC = "https://read.public.example.com";
const SECRET = "service-secret-service-secret-service-secret";
const WORKSPACE_HEADER = "x-relayhistory-workspace-id";
const originalFetch=globalThis.fetch;
const padded = (value: string) => value.replace(/[^A-Za-z0-9_-]/g, "_").padEnd(44, "x");

type Issue = { body: Record<string, string>; bearer: string | null; path: string };
type Read = { url: URL; bearer: string | null };
type Options = {
  ttlMs?: number;
  readStatus?: (url: URL, bearer: string | null) => number;
  attest?: (workspace: string) => string | null;
  readBody?: unknown;
  issueStatus?: (path:string) => number;
  reply?: (pair:Record<string,unknown>,path:string)=>Record<string,unknown>;
};

function config(on = true) {
  return {
    publicBaseUrl: CONTROL,
    relayhistoryUrl: HISTORY,
    sessionReadApi: { url: READ_API, publicUrl: PUBLIC, secret: SECRET },
    sessionReadMcpReads: on,
  } as SelfhostConfig;
}
const principal = (userId: string) => ({ userId,scopes:["rth:read"] }) as Principal;
const workspace = (id: string, organizationId: string) => ({ id, organizationId }) as never;

function fake(t: TestContext, options: Options = {}) {
  const issues: Issue[] = [];
  const reads: Read[] = [];
  const history: Read[] = [];
  let serial = 0;
  const families=new Map<string,string>();
  const original = originalFetch;
  t.after(() => {
    globalThis.fetch = original;
  });
  globalThis.fetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
    const url = new URL(String(input));
    const bearer = new Headers(init.headers).get("authorization");
    if (url.origin===CONTROL && /\/session-read\/(session|refresh)$/.test(url.pathname)) {
      const body = JSON.parse(String(init.body)) as Record<string, string>;
      issues.push({ body, bearer, path: url.pathname });
      const status = options.issueStatus?.(url.pathname) ?? 200;
      if (status !== 200) return new Response("", { status });
      serial += 1;
      const ws=decodeURIComponent(url.pathname.split("/")[4]!);
      const userId=ws==="ws-b"?"user-b":"user-a",orgId=`org-${ws.slice(3)}`;
      const refreshToken=`rth_rt_read_${padded(`${userId}_${serial}`)}`;
      const sessionId=body.refreshToken?families.get(body.refreshToken)!:`session-${serial}`;
      families.set(refreshToken,sessionId);
      const pair={baseUrl:PUBLIC,sessionId,userId,orgId,workspaceId:ws,audience:PUBLIC,scopes:["rth:read"],
        accessToken:`rth_at_read_${padded(`${userId}_${serial}`)}`,
        accessTokenExpiresAt:new Date(Date.now()+(options.ttlMs??300_000)).toISOString(),refreshToken,
        refreshTokenExpiresAt:new Date(Date.now()+86_400_000).toISOString(),tokenType:"Bearer"};
      return Response.json(options.reply?.(pair,url.pathname)??pair);
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
    const ws=url.searchParams.get("workspace")??"";
    const attested=options.attest?options.attest(ws):ws;
    return Response.json(options.readBody??{ from:"read-api" },{headers:attested===null?{}:{[WORKSPACE_HEADER]:attested}});
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
    seen.issues.map(({ path,bearer,body }) => [path,bearer,body]),
    [["/api/v1/workspaces/ws-a/session-read/session","Bearer sh_at_user_a",{label:"mcp"}],
     ["/api/v1/workspaces/ws-b/session-read/session","Bearer sh_at_user_b",{label:"mcp"}]],
  );
  assert.deepEqual(
    seen.reads.map(({ bearer, url }) => [bearer?.includes("user-a_1") || bearer?.includes("user-b_2"), url.searchParams.get("workspace")]),
    [[true, "ws-a"], [true, "ws-b"]],
  );
  assert.ok(seen.reads[0]!.bearer!.includes("user-a") && seen.reads[1]!.bearer!.includes("user-b"));
  for (const read of seen.reads) {
    assert.match(read.bearer!, /^Bearer rth_at_read_/);
    assert.ok(!read.bearer!.includes(SECRET), "the service secret never reaches a read");
    assert.equal(read.url.origin,PUBLIC);
  }
  assert.equal(seen.history.length, 0);
});

test("the same person in another org gets a separate session", async (t) => {
  const seen = fake(t);
  const cfg = config();
  t.after(() => forgetSessionReadTokens(cfg));

  await historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a")("/v1/sessions");
  await historyReader(cfg, principal("user-a"), workspace("ws-c", "org-c"), "sh_at_user_a_c")("/v1/sessions");

  assert.deepEqual(seen.issues.map(({ path }) => path),["/api/v1/workspaces/ws-a/session-read/session","/api/v1/workspaces/ws-c/session-read/session"]);
  assert.notEqual(seen.reads[0]!.bearer, seen.reads[1]!.bearer);
});

test("a tool path cannot widen the read to another workspace", async (t) => {
  const seen = fake(t);
  const cfg = config();
  t.after(() => forgetSessionReadTokens(cfg));

  await historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a")("/v1/sessions?workspace=ws-other");

  assert.deepEqual(seen.reads[0]!.url.searchParams.getAll("workspace"), ["ws-a"]);
  assert.equal(seen.issues[0]!.path,"/api/v1/workspaces/ws-a/session-read/session");
  assert.deepEqual(seen.issues[0]!.body,{label:"mcp"});
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

  assert.deepEqual(seen.issues.map(({ path }) => path), ["/api/v1/workspaces/ws-a/session-read/session", "/api/v1/workspaces/ws-a/session-read/refresh"]);
  assert.match(seen.issues[1]!.body.refreshToken!, /^rth_rt_read_user-a_1/);
  assert.equal(seen.issues[1]!.bearer,"Bearer sh_at_user_a");
  assert.deepEqual(Object.keys(seen.issues[1]!.body),["refreshToken"]);
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

test("a failed handoff cannot fall back to another reader", async (t) => {
  const seen = fake(t, { issueStatus: () => 503 });
  const cfg = config();
  t.after(() => forgetSessionReadTokens(cfg));

  await assert.rejects(historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a")("/v1/sessions"),/temporarily unavailable/);
  assert.equal(seen.reads.length,0);assert.equal(seen.history.length,0);
});

test("routes outside the read contract stay on History", async (t) => {
  const seen = fake(t);
  const cfg = config();
  t.after(() => forgetSessionReadTokens(cfg));

  const body = await historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a")("/v1/sessions/s-1/timing");
  assert.deepEqual(body, { from: "history" });
  assert.equal(seen.issues.length, 0);
});


test("MCP handoff never sends the internal secret or accepts broader credentials",async t=>{
  for(const change of [{accessToken:`rth_st_read_${padded("fake-service")}`},{accessToken:`sh_at_${padded("fake-user")}`},
    {refreshToken:`rth_st_read_${padded("fake-service")}`},{scopes:["rth:read","rth:sync"]},
    {baseUrl:"https://other.example.com"},{audience:"https://other.example.com"},
    {userId:"other-user"},{orgId:"other-org"},{workspaceId:"other-ws"}]) {
    const seen=fake(t,{reply:pair=>({...pair,...change})}),cfg=config();
    await assert.rejects(historyReader(cfg,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a")("/v1/sessions"));
    assert.equal(seen.reads.length,0);assert.equal(seen.history.length,0);
    assert.equal(seen.issues[0]!.bearer,"Bearer sh_at_user_a");
    assert.deepEqual(seen.issues[0]!.body,{label:"mcp"});
  }
});

test("privacy refusals never fall back to History on the first page",async t=>{
  for(const status of [403,404,503]) {
    const seen=fake(t,{readStatus:()=>status}),cfg=config();
    await assert.rejects(historyReader(cfg,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a")("/v1/sessions"));
    assert.equal(seen.history.length,0);assert.equal(seen.reads.length,1);
  }
});

test("an access401 refreshes through Control once; a refused refresh is never reminted",async t=>{
  const seen=fake(t,{readStatus:(_url,bearer)=>bearer?.includes("user-a_1")?401:200}),cfg=config();
  const read=historyReader(cfg,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a");
  assert.deepEqual(await read("/v1/sessions"),{from:"read-api"});
  assert.deepEqual(seen.issues.map(row=>row.path.split("/").at(-1)),["session","refresh"]);
  assert.equal(seen.history.length,0);
  const rejected=fake(t,{readStatus:()=>401,issueStatus:path=>path.endsWith("/refresh")?401:200}),other=config();
  const denied=historyReader(other,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a");
  await assert.rejects(denied("/v1/sessions"));await assert.rejects(denied("/v1/sessions"));
  assert.deepEqual(rejected.issues.map(row=>row.path.split("/").at(-1)),["session","refresh"]);
  assert.equal(rejected.history.length,0);
});

test("reader cursors retain their exact bytes and never switch to History",async t=>{
  const cursor="b96l1:opaque+/_=-",seen=fake(t),cfg=config();
  await historyReader(cfg,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a")(`/v1/sessions?cursor=${encodeURIComponent(cursor)}`);
  assert.equal(seen.reads[0]!.url.searchParams.get("cursor"),cursor);
  const before=seen.issues.length;
  for(const [other,path] of [[config(),"/v1/sessions?cursor=legacy-cursor"],
    [config(false),"/v1/sessions?cursor=b96l1:old"],[config(),"/v1/sessions/s-1/timing?cursor=b96l1:old"]] as const) {
    await assert.rejects(historyReader(other,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a")(path),/cursor has expired/);
  }
  assert.equal(seen.issues.length,before);assert.equal(seen.history.length,0);
});

test("session reads require rth:read and an exchanged Control user credential before any upstream call",async t=>{
  const seen=fake(t),cfg=config();
  for(const [who,token] of [[{...principal("user-a"),scopes:["cli:auth"]},"sh_at_user_a"],
    [{...principal("user-a"),pendingHandoff:true},"sh_at_user_a"],
    [principal("user-a"),`rth_st_read_${padded("fake-service")}`],[principal("user-a"),"mcp_at_fake"]] as const) {
    await assert.rejects(historyReader(cfg,who as Principal,workspace("ws-a","org-a"),token)("/v1/sessions"),/rth:read/);
  }
  assert.equal(seen.issues.length,0);assert.equal(seen.reads.length,0);assert.equal(seen.history.length,0);
});


test("missing attestation and malformed reader bodies never trigger another backend",async t=>{
  for(const options of [{attest:()=>null},{readBody:[]}]) {
    const seen=fake(t,options),cfg=config();
    await assert.rejects(historyReader(cfg,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a")("/v1/sessions"));
    assert.equal(seen.history.length,0);
  }
});

test("concurrent near-expiry reads share one rotating Control refresh",async t=>{
  const seen=fake(t,{ttlMs:10_000}),cfg=config();
  const read=historyReader(cfg,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a");
  await read("/v1/sessions");
  await Promise.all(Array.from({length:8},()=>read("/v1/sessions")));
  assert.equal(seen.issues.length,2);
  assert.equal(seen.issues[1]!.path.split("/").at(-1),"refresh");
  assert.equal(seen.history.length,0);
});

test("Control refresh must preserve the read session and rotate its refresh token",async t=>{
  for(const changed of [{sessionId:"wrong-family"},{refreshToken:`rth_rt_read_${padded("user-a_1")}`}]) {
    const seen=fake(t,{ttlMs:10_000,reply:(pair,path)=>path.endsWith("/refresh")?{...pair,...changed}:pair}),cfg=config();
    const read=historyReader(cfg,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a");
    await read("/v1/sessions");await assert.rejects(read("/v1/sessions"));
    assert.equal(seen.issues.length,2);assert.equal(seen.history.length,0);
  }
});
