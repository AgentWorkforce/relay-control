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
  errorReason?: string;
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
  const handoffs: Issue[] = [];
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
    if (url.origin === READ_API && url.pathname.startsWith("/internal/v1/session-read/sessions")) {
      // The dashboard path's read API handoff (service secret, never the caller token).
      const body = JSON.parse(String(init.body)) as Record<string, string>;
      handoffs.push({ body, bearer, path: url.pathname });
      serial += 1;
      return Response.json({
        sessionId: `dashboard-${serial}`,
        userId: body.userId,
        orgId: body.orgId,
        workspaceId: body.workspaceId,
        accessToken: `rth_at_read_${padded(`dashboard_${serial}`)}`,
        accessTokenExpiresAt: new Date(Date.now() + 300_000).toISOString(),
        refreshToken: `rth_rt_read_${padded(`dashboard_${serial}`)}`,
        refreshTokenExpiresAt: new Date(Date.now() + 86_400_000).toISOString(),
        tokenType: "Bearer",
        audience: PUBLIC,
        scopes: ["rth:read"],
      });
    }
    if (url.origin === HISTORY) {
      history.push({ url, bearer });
      return Response.json({ from: "history" }, { headers: { [WORKSPACE_HEADER]: url.searchParams.get("workspace") ?? "" } });
    }
    reads.push({ url, bearer });
    const status = options.readStatus?.(url, bearer) ?? 200;
    if (status !== 200) return Response.json({error:{code:"unsupported_by_backend",reason:options.errorReason??"unavailable"}},{status});
    const ws=url.searchParams.get("workspace")??"";
    const attested=options.attest?options.attest(ws):ws;
    return Response.json(options.readBody??{ from:"read-api" },{headers:attested===null?{}:{[WORKSPACE_HEADER]:attested}});
  }) as typeof fetch;
  return { issues, reads, history, handoffs };
}

test("the setting off leaves MCP reads on the existing History path", async (t) => {
  const seen = fake(t);
  const cfg = config(false);
  const body = await historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a")("/v1/sessions");
  assert.deepEqual(body, { from: "history" });
  assert.equal(seen.issues.length, 0);
  assert.equal(seen.reads.length, 0);
  assert.equal(seen.handoffs.length, 1);
  assert.equal(seen.handoffs[0]!.bearer, `Bearer ${SECRET}`);
  assert.ok(!JSON.stringify(seen.handoffs[0]!.body).includes("sh_at_user_a"), "the caller token never reaches the handoff");
  assert.match(seen.history[0]!.bearer!, /^Bearer rth_at_read_/);
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

test("every selected-reader501 stays unsupported with zero History calls regardless of reason",async t=>{
  for(const reason of ["unsupported_by_backend","first_page_inexact","privacy_refused","unknown",""]) {
    for(const suffix of ["","?cursor=b96l1:opaque"]) {
      const seen=fake(t,{readStatus:()=>501,errorReason:reason}),cfg=config();
      await assert.rejects(historyReader(cfg,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a")(`/v1/sessions${suffix}`),/unsupported_by_backend/);
      assert.equal(seen.reads.length,1);assert.equal(seen.history.length,0);
    }
  }
});

test("summary reads use the per-user reader and never fall back after refusal or missing attestation", async t => {
  const path="/v1/sessions/fake-session/summary?source=codex&kind=short&workspace=other";
  for(const status of [200,401,403,404,501,503]) {
    const seen=fake(t,{readStatus:()=>status}),cfg=config();
    const read=historyReader(cfg,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a");
    if(status===200) assert.deepEqual(await read(path),{from:"read-api"});
    else await assert.rejects(read(path));
    assert.ok(seen.reads.length>0);
    for(const request of seen.reads) {
      assert.equal(request.url.origin,PUBLIC);
      assert.equal(request.url.pathname,"/v1/sessions/fake-session/summary");
      assert.equal(request.url.searchParams.get("workspace"),"ws-a");
      assert.match(request.bearer!,/^Bearer rth_at_read_/);
    }
    assert.equal(seen.history.length,0);assert.equal(seen.handoffs.length,0);
  }
  const seen=fake(t,{attest:()=>null}),cfg=config();
  await assert.rejects(historyReader(cfg,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a")(path));
  assert.equal(seen.history.length,0);
});

test("a disabled recorded-summary opt-in never retries without the parameter or on History", async t => {
  const seen=fake(t,{readStatus:()=>501,errorReason:"param_includeShortSummary"}),cfg=config();
  await assert.rejects(historyReader(cfg,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a")(
    "/v1/sessions?includeShortSummary=recorded&limit=50"),/unsupported_by_backend/);
  assert.equal(seen.reads.length,1);
  assert.equal(seen.reads[0]!.url.searchParams.get("includeShortSummary"),"recorded");
  assert.equal(seen.reads[0]!.url.searchParams.get("workspace"),"ws-a");
  assert.equal(seen.history.length,0);assert.equal(seen.handoffs.length,0);
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
  await assert.rejects(denied("/v1/sessions"),/Reauthenticate/);await assert.rejects(denied("/v1/sessions"),/Reauthenticate/);
  assert.deepEqual(rejected.issues.map(row=>row.path.split("/").at(-1)),["session","refresh"]);
  assert.equal(rejected.history.length,0);
});

test("reader cursors retain their exact bytes and never switch to History",async t=>{
  const cursor="b96l1:opaque+/_=-",seen=fake(t),cfg=config();
  await historyReader(cfg,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a")(`/v1/sessions?cursor=${encodeURIComponent(cursor)}`);
  assert.equal(seen.reads[0]!.url.searchParams.get("cursor"),cursor);
  const before=seen.issues.length;
  await assert.rejects(historyReader(config(),principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a")("/v1/sessions?cursor=legacy-cursor"),/cursor has expired/);
  assert.equal(seen.issues.length,before);assert.equal(seen.history.length,0);
  // History is the read API too, so its cursors stay valid when a read is not selected.
  for(const [other,path] of [[config(false),"/v1/sessions?cursor=b96l1:old"],[config(),"/v1/sessions/s-1/timing?cursor=b96l1:old"]] as const) {
    assert.deepEqual(await historyReader(other,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a")(path),{from:"history"});
  }
  assert.deepEqual(seen.history.map(row=>row.url.searchParams.get("cursor")),["b96l1:old","b96l1:old"]);
  assert.equal(seen.issues.length,before);
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


test("refresh503 and timeout retain the same token/session for refresh retry without reminting",async t=>{
  for(const failure of ["503","timeout"]) {
    let unavailable=true;
    const sessionIds:string[]=[];
    const seen=fake(t,{ttlMs:10_000,issueStatus:path=>{
      if(path.endsWith("/refresh") && unavailable) {
        unavailable=false;
        if(failure==="timeout") throw new DOMException("synthetic timeout","TimeoutError");
        return 503;
      }
      return 200;
    },reply:pair=>{sessionIds.push(String(pair.sessionId));return pair;}}),cfg=config();
    const read=historyReader(cfg,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a");
    await read("/v1/sessions");
    await assert.rejects(read("/v1/sessions"),/temporarily unavailable/);
    assert.deepEqual(await read("/v1/sessions"),{from:"read-api"});
    assert.deepEqual(seen.issues.map(row=>row.path.split("/").at(-1)),["session","refresh","refresh"]);
    assert.equal(seen.issues[1]!.body.refreshToken,seen.issues[2]!.body.refreshToken);
    assert.deepEqual(sessionIds,["session-1","session-1"]);
    assert.equal(seen.history.length,0);
  }
});

test("an unavailable selected read retries on the same backend and cursor without new issuance",async t=>{
  let unavailable=true;
  const seen=fake(t,{readStatus:()=>unavailable?503:200}),cfg=config();
  const read=historyReader(cfg,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a");
  const path="/v1/sessions?cursor=b96l1:opaque";
  await assert.rejects(read(path),/temporarily unavailable/);unavailable=false;
  assert.deepEqual(await read(path),{from:"read-api"});
  assert.equal(seen.issues.length,1);assert.equal(seen.reads.length,2);
  assert.equal(seen.reads[0]!.url.toString(),seen.reads[1]!.url.toString());
  assert.equal(seen.reads[0]!.bearer,seen.reads[1]!.bearer);assert.equal(seen.history.length,0);
});
