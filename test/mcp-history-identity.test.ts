import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { loadSessionReadPointSummaryWorkspace, type SelfhostConfig } from "../src/config.js";
import { historyReader, type McpContext } from "../src/mcp/context.js";
import { buildReadAuditRecord } from "../src/mcp/read-audit.js";
import { describeCapabilities } from "../src/mcp/catalog.js";
import { forgetSessionReadTokens } from "../src/mcp/session-read-reader.js";
import { mcpReaderMarker } from "../src/session-read.js";
import type { Principal } from "../src/store.js";

const CONTROL = "https://control.example.com";
const HISTORY = "https://history.example.com";
const READ_API = "https://read.example.com";
const PUBLIC = "https://read.public.example.com";
const SECRET = "service-secret-service-secret-service-secret";
const WORKSPACE_HEADER = "x-relayhistory-workspace-id";
const originalFetch=globalThis.fetch;
const padded = (value: string) => value.replace(/[^A-Za-z0-9_-]/g, "_").padEnd(44, "x");

type Issue = { body: Record<string, string>; bearer: string | null; path: string; marker?: string | null };
type Read = { url: URL; bearer: string | null };
type Options = {
  ttlMs?: number;
  readStatus?: (url: URL, bearer: string | null) => number;
  attest?: (workspace: string) => string | null;
  readBody?: unknown;
  errorReason?: string;
  issueStatus?: (path:string) => number;
  reply?: (pair:Record<string,unknown>,path:string)=>Record<string,unknown>;
  /** Status the workspace (History) reader answers; 200 when absent. */
  historyStatus?: (url: URL) => number;
  /** The workspace header History attests; the queried workspace when absent. */
  historyAttest?: (workspace: string) => string | null;
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
const workspace = (id: string, organizationId: string, role = "member") => ({ id, organizationId, role }) as never;

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
      issues.push({ body, bearer, path: url.pathname, marker: new Headers(init.headers).get("x-relaycontrol-session-reader") });
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
      const status = options.historyStatus?.(url) ?? 200;
      if (status !== 200) return Response.json({error:{code:"unsupported_by_backend",reason:options.errorReason??"unavailable"}},{status});
      const queried = url.searchParams.get("workspace") ?? "";
      const attested = options.historyAttest ? options.historyAttest(queried) : queried;
      return Response.json({ from: "history" }, { headers: attested === null ? {} : { [WORKSPACE_HEADER]: attested } });
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
  assert.equal("reader_kind" in seen.handoffs[0]!.body, false, "without relaygate the mint body is unchanged");
  assert.match(seen.history[0]!.bearer!, /^Bearer rth_at_read_/);
});

test("behind relaygate the in-process MCP mint names the mcp reader kind", async (t) => {
  const seen = fake(t);
  const cfg = config(false);
  cfg.sessionReadApi.mintReaderKind = true;
  await historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a")("/v1/sessions");
  assert.equal(seen.handoffs.length, 1);
  assert.equal(seen.handoffs[0]!.body.reader_kind, "mcp");
  assert.equal("readerKind" in seen.handoffs[0]!.body, false);
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
  // The hop proves it is the MCP reader with the secret-derived marker, never the secret.
  assert.deepEqual(seen.issues.map(({ marker }) => marker), [mcpReaderMarker(SECRET), mcpReaderMarker(SECRET)]);
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

test("a role change issues a fresh read session instead of reusing the old role's token", async (t) => {
  const seen = fake(t);
  const cfg = config();
  t.after(() => forgetSessionReadTokens(cfg));

  await historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a", "member"), "sh_at_user_a")("/v1/sessions");
  await historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a", "member"), "sh_at_user_a")("/v1/sessions");
  await historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a", "admin"), "sh_at_user_a")("/v1/sessions");

  assert.equal(seen.issues.length, 2, "the same role reuses its session; a new role mints again");
  assert.equal(seen.reads[0]!.bearer, seen.reads[1]!.bearer);
  assert.notEqual(seen.reads[1]!.bearer, seen.reads[2]!.bearer);
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
  assert.equal(seen.issues[1]!.marker,mcpReaderMarker(SECRET));
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
  for (const kind of ["short", "long"]) {
    const path=`/v1/sessions/fake-session/summary?source=codex&kind=${kind}&workspace=other`;
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
        assert.equal(request.url.searchParams.get("source"),"codex");
        assert.equal(request.url.searchParams.get("kind"),kind);
        assert.match(request.bearer!,/^Bearer rth_at_read_/);
      }
      assert.equal(seen.history.length,0);assert.equal(seen.handoffs.length,0);
    }
    for (const attested of [null, "another-workspace"]) {
      const seen=fake(t,{attest:()=>attested}),cfg=config();
      await assert.rejects(historyReader(cfg,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a")(path));
      assert.equal(seen.history.length,0);
    }
  }
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

  const body = await historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a")("/v1/sessions/s-1/catalog");
  assert.deepEqual(body, { from: "history" });
  assert.equal(seen.issues.length, 0);
});

test("searchable MCP sessions use one reader for directory, exact-session and timing reads", async t => {
  const seen = fake(t), cfg = config();
  t.after(() => forgetSessionReadTokens(cfg));
  const read = historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a");

  for (const path of [
    "/v1/events?q=searchable",
    "/v1/sessions?includeShortSummary=recorded",
    "/v1/sessions/s-1/events?source=codex",
    "/v1/sessions/s-1/timing?source=codex",
  ]) await read(path);

  assert.deepEqual(seen.reads.map(row => row.url.pathname), [
    "/v1/events",
    "/v1/sessions",
    "/v1/sessions/s-1/events",
    "/v1/sessions/s-1/timing",
  ]);
  assert.equal(seen.history.length, 0);
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
  for(const [other,path] of [[config(false),"/v1/sessions?cursor=b96l1:old"],[config(),"/v1/sessions/s-1/catalog?cursor=b96l1:old"]] as const) {
    assert.deepEqual(await historyReader(other,principal("user-a"),workspace("ws-a","org-a"),"sh_at_user_a")(path),{from:"history"});
  }
  assert.deepEqual(seen.history.map(row=>row.url.searchParams.get("cursor")),["b96l1:old","b96l1:old"]);
  assert.equal(seen.issues.length,before);
});

test("session reads require rth:read and an exchanged Control user credential before any upstream call",async t=>{
  const seen=fake(t),cfg=config();
  for(const [who,token] of [[{...principal("user-a"),scopes:["cli:auth"]},"sh_at_user_a"],
    [{...principal("user-a"),pendingHandoff:true},"sh_at_user_a"],
    [principal("user-a"),`rth_st_read_${padded("fake-service")}`]] as const) {
    await assert.rejects(historyReader(cfg,who as Principal,workspace("ws-a","org-a"),token)("/v1/sessions"),/rth:read/);
  }
  assert.equal(seen.issues.length,0);assert.equal(seen.reads.length,0);assert.equal(seen.history.length,0);
});

const OAUTH_TOKEN=`mcp_at_${"O".repeat(43)}`;
const oauth=(scopes:string[],extra:Partial<Principal>={})=>({userId:"user-a",scopes,...extra}) as Principal;

test("an OAuth connection without relay:history is refused before any upstream call",async t=>{
  const seen=fake(t),cfg=config();
  // rth:read on an mcp_at_ principal is never a native path: that scope cannot reach an OAuth session.
  for(const who of [oauth(["relay:mcp"]),oauth(["relay:mcp","relay:agents"]),oauth(["relay:mcp","rth:read"])]) {
    await assert.rejects(historyReader(cfg,who,workspace("ws-a","org-a"),OAUTH_TOKEN)("/v1/sessions"),
      {message:"Session reads need the relay:history scope on this OAuth connection."});
  }
  // relay:history on any other credential shape grants nothing.
  for(const token of ["sh_at_user_a",`cld_at_${"G".repeat(43)}`,`rth_st_read_${padded("fake-service")}`]) {
    await assert.rejects(historyReader(cfg,oauth(["relay:mcp","relay:history"]),workspace("ws-a","org-a"),token)("/v1/sessions"),
      {message:"Session reads require an exchanged user session with rth:read."});
  }
  assert.equal(seen.issues.length+seen.reads.length+seen.history.length+seen.handoffs.length,0);
});

test("a pending handoff refuses an OAuth relay:history read before any upstream call",async t=>{
  const seen=fake(t),cfg=config();
  await assert.rejects(historyReader(cfg,oauth(["relay:mcp","relay:history"],{pendingHandoff:true}),workspace("ws-a","org-a"),OAUTH_TOKEN)("/v1/sessions"),
    {message:"Session reads require an exchanged user session with rth:read."});
  assert.equal(seen.issues.length+seen.reads.length+seen.history.length+seen.handoffs.length,0);
});

test("an OAuth relay:history read is minted server-side as an mcp reader and never forwards the OAuth token",async t=>{
  for(const on of [false,true]) for(const kind of [false,true]) {
    const seen=fake(t),cfg=config(on);
    cfg.sessionReadApi.mintReaderKind=kind;
    const who=oauth(["relay:mcp","relay:history"]);
    assert.deepEqual(await historyReader(cfg,who,workspace("ws-a","org-a"),OAUTH_TOKEN)("/v1/sessions"),{from:"history"});
    // Never the session-read hop, which would present the caller token to Control.
    assert.equal(seen.issues.length,0,`mode ${on}`);
    assert.equal(seen.handoffs.length,1);
    assert.equal(seen.handoffs[0]!.bearer,`Bearer ${SECRET}`);
    const minted=seen.handoffs[0]!.body;
    assert.deepEqual([minted.userId,minted.orgId,minted.workspaceId],["user-a","org-a","ws-a"]);
    if(kind) assert.equal(minted.reader_kind,"mcp");
    else assert.equal("reader_kind" in minted,false);
    assert.match(seen.history[0]!.bearer!,/^Bearer rth_at_read_/);
    assert.equal(JSON.stringify([seen.handoffs,seen.history,seen.reads,seen.issues]).includes(OAUTH_TOKEN),false);
    assert.deepEqual(who.scopes,["relay:mcp","relay:history"],"the OAuth principal never gains rth:read");
  }
});

test("capability discovery restricts OAuth session reads exactly when relay:history is missing",()=>{
  const reads=(authMode:"oauth"|"cli_login",scopes:string[])=>describeCapabilities({endpointUrl:"https://relay.example.test/mcp",
    authMode,scopes,workspaceId:"ws-a",role:"member",providers:[]}).groups.find(group=>group.id==="shared_session_reads")!;
  const restricted=reads("oauth",["relay:mcp","relay:agents"]) as {status:string;reason?:string;how_to_enable?:string};
  assert.equal(restricted.status,"restricted");
  assert.equal(restricted.reason,"This OAuth connection was not granted relay:history.");
  assert.match(restricted.how_to_enable!,/request the relay:history scope on the sessions resource/);
  assert.equal(reads("oauth",["relay:mcp","relay:history"]).status,"available");
  assert.equal(reads("cli_login",["rth:read"]).status,"available");
});

test("an OAuth session read is audited with auth_mode oauth and its client and grant ids",()=>{
  const context={workspace:{id:"ws-a",organizationId:"org-a"},principal:oauth(["relay:mcp","relay:history"]),
    authMode:"oauth",desktopCall:{required:false},relay:{sessionId:undefined},
    oauth:{access:{clientId:"mcpc_fake",grantId:"grant-fake"}}} as unknown as McpContext;
  const record=buildReadAuditRecord({context,toolName:"search_shared_sessions",args:{query:"fake"},
    result:{content:[{type:"text",text:"ok"}],structuredContent:{}} as never,startedAt:Date.now(),now:null});
  assert.equal(record.outcome,"ok");
  assert.deepEqual([record.identityKind,record.authMode,record.oauthClientId,record.oauthGrantId,record.callerUserId],
    ["oauth","oauth","mcpc_fake","grant-fake","user-a"]);
});

test("a Desktop provider grant (cld_at_, mcp:desktop) reads through the workspace reader in both modes",async t=>{
  const grant=`cld_at_${"G".repeat(43)}`;
  const desktop={...principal("user-a"),scopes:["rth:read","mcp:desktop"]} as Principal;
  for(const on of [false,true]) {
    const seen=fake(t),cfg=config(on);
    assert.deepEqual(await historyReader(cfg,desktop,workspace("ws-a","org-a"),grant)("/v1/sessions"),{from:"history"});
    // Never the session-read hop that would present the grant to Control.
    assert.equal(seen.issues.length,0);
    assert.equal(seen.handoffs.length,1);
    assert.equal(seen.handoffs[0]!.bearer,`Bearer ${SECRET}`);
    const minted=seen.handoffs[0]!.body;
    assert.deepEqual([minted.userId,minted.orgId,minted.workspaceId],["user-a","org-a","ws-a"]);
    assert.equal(JSON.stringify([seen.handoffs,seen.history,seen.reads]).includes(grant),false);
  }
  // The grant shape alone, or the scope without rth:read, is not enough.
  const seen=fake(t),cfg=config();
  for(const [who,token] of [[principal("user-a"),grant],
    [{...principal("user-a"),scopes:["mcp:desktop"]},grant],
    [desktop,"cld_at_short"],
    [{...desktop,pendingHandoff:true},grant]] as const) {
    await assert.rejects(historyReader(cfg,who as Principal,workspace("ws-a","org-a"),token)("/v1/sessions"),/rth:read/);
  }
  assert.equal(seen.issues.length+seen.reads.length+seen.history.length+seen.handoffs.length,0);
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

// The paths list_session_summaries and get_session_summary build, each with a
// caller workspace param the reader must replace.
const RECORDED_LIST = "/v1/sessions?limit=20&includeShortSummary=recorded&workspace=ws-other";
const POINT_SUMMARY = "/v1/sessions/s-1/summary?kind=short&source=codex&workspace=ws-other";

test("recorded list and point summary share one reader per workspace, with the setting on and off", async t => {
  for (const on of [true, false]) {
    const seen = fake(t), cfg = config(on);
    t.after(() => forgetSessionReadTokens(cfg));
    for (const [user, ws, org] of [["user-a", "ws-a", "org-a"], ["user-b", "ws-b", "org-b"]] as const) {
      const read = historyReader(cfg, principal(user), workspace(ws, org), `sh_at_${user.replace("-", "_")}`);
      const expected = on ? { from: "read-api" } : { from: "history" };
      assert.deepEqual(await read(RECORDED_LIST), expected);
      assert.deepEqual(await read(POINT_SUMMARY), expected);
    }
    // On selects the per-user read API for both tools; off sends both to History.
    const used = on ? seen.reads : seen.history;
    assert.equal((on ? seen.history : seen.reads).length, 0, `setting ${on}`);
    assert.deepEqual(used.map(({ url }) => [url.pathname, url.searchParams.getAll("workspace")]), [
      ["/v1/sessions", ["ws-a"]], ["/v1/sessions/s-1/summary", ["ws-a"]],
      ["/v1/sessions", ["ws-b"]], ["/v1/sessions/s-1/summary", ["ws-b"]],
    ]);
    // List and point for one person carry the same minted token.
    assert.equal(used[0]!.bearer, used[1]!.bearer);
    assert.equal(used[2]!.bearer, used[3]!.bearer);
    assert.notEqual(used[0]!.bearer, used[2]!.bearer);
    const minted = on ? seen.issues.map(({ path }) => path.split("/")[4]) : seen.handoffs.map(({ body }) => body.workspaceId);
    assert.deepEqual(minted, ["ws-a", "ws-b"]);
    assert.equal((on ? seen.handoffs : seen.issues).length, 0);
  }
});

test("with the setting off, a terminal point-summary status keeps its outcome and tries no other backend", async t => {
  for (const [status, outcome] of [[403, /temporarily unavailable/], [404, /temporarily unavailable/],
    [501, /unsupported_by_backend/], [503, /temporarily unavailable/]] as const) {
    const seen = fake(t, { historyStatus: () => status }), cfg = config(false);
    await assert.rejects(historyReader(cfg, principal("user-a"), workspace("ws-a", "org-a"), "sh_at_user_a")(POINT_SUMMARY), outcome);
    assert.equal(seen.history.length, 1, `status ${status}`);
    assert.equal(seen.history[0]!.url.pathname, "/v1/sessions/s-1/summary");
    assert.deepEqual(seen.history[0]!.url.searchParams.getAll("workspace"), ["ws-a"]);
    assert.equal(seen.reads.length + seen.issues.length, 0, "never the read API hop");
    assert.equal(seen.handoffs.length, 1);
  }
});

test("staff, Desktop and OAuth grants read list and point summary through the same workspace reader", async t => {
  const grants: Array<[string, Principal, string]> = [
    ["staff", principal("user-a"), `sh_sr_${"S".repeat(43)}`],
    ["desktop", { ...principal("user-a"), scopes: ["rth:read", "mcp:desktop"] } as Principal, `cld_at_${"G".repeat(43)}`],
    ["oauth", oauth(["relay:mcp", "relay:history"]), OAUTH_TOKEN],
  ];
  for (const on of [true, false]) for (const [name, who, token] of grants) {
    const seen = fake(t), cfg = config(on);
    const read = historyReader(cfg, who, workspace("ws-a", "org-a"), token);
    assert.deepEqual(await read(RECORDED_LIST), { from: "history" });
    assert.deepEqual(await read(POINT_SUMMARY), { from: "history" });
    assert.deepEqual(seen.history.map(({ url }) => [url.pathname, url.searchParams.getAll("workspace")]),
      [["/v1/sessions", ["ws-a"]], ["/v1/sessions/s-1/summary", ["ws-a"]]], `${name} setting ${on}`);
    assert.equal(seen.history[0]!.bearer, seen.history[1]!.bearer);
    assert.equal(seen.reads.length + seen.issues.length, 0, `${name} never takes the per-user hop`);
    assert.equal(seen.handoffs.length, 1);
    assert.equal(seen.handoffs[0]!.body.workspaceId, "ws-a");
    assert.equal(JSON.stringify([seen.handoffs, seen.history]).includes(token), false);
  }
});

// SESSION_READ_API_POINT_SUMMARY_WORKSPACE: one exact workspace's point
// summary reads through the per-user read API; nothing else moves.
const SELECTED = "00000000-0000-4000-8000-00000000000a";
const OTHER = "00000000-0000-4000-8000-00000000000b";
// The fake Control names the org `org-<workspace minus its first 3 chars>`.
const orgOf = (ws: string) => `org-${ws.slice(3)}`;
const LIST_FOR = (ws: string) => `/v1/sessions?limit=20&includeShortSummary=recorded&workspace=${ws}`;
const POINT_FOR = (ws: string) => `/v1/sessions/s-1/summary?kind=short&source=codex&workspace=${ws}`;
function selectedConfig(on: boolean, ...override: [selected: string | null | undefined] | []) {
  const cfg = config(on);
  // An explicit undefined stays undefined (unset); no argument selects SELECTED.
  cfg.sessionReadPointSummaryWorkspace = override.length ? override[0] : SELECTED;
  return cfg;
}
const nativeRead = (cfg: SelfhostConfig, ws: string) =>
  historyReader(cfg, principal("user-a"), workspace(ws, orgOf(ws)), "sh_at_user_a");

test("the point-summary workspace value selects exactly one complete UUID, or nobody", () => {
  const warnings: string[] = [];
  const load = (value?: string) => loadSessionReadPointSummaryWorkspace({ SESSION_READ_API_POINT_SUMMARY_WORKSPACE: value },
    message => warnings.push(message));
  assert.equal(load(SELECTED), SELECTED);
  assert.equal(load(`  ${SELECTED}\n`), SELECTED, "surrounding whitespace is trimmed");
  // Compared in lowercase, the form workspace ids are stored in.
  assert.equal(load(SELECTED.toUpperCase()), SELECTED);
  for (const value of [undefined, "", "   ", "*", "all", "true", "00000000-0000-4000-8000", "00000000",
    `${SELECTED},${OTHER}`, `${SELECTED} ${OTHER}`, `${SELECTED}*`, `{${SELECTED}}`, `${SELECTED}0`,
    SELECTED.replaceAll("-", ""), "ws-a", "0000000g-0000-4000-8000-00000000000a"]) {
    warnings.length = 0;
    assert.equal(load(value), null, `value ${JSON.stringify(value)}`);
    // Unset or blank stays silent; any other unusable value warns once, never echoing it.
    assert.equal(warnings.length, value?.trim() ? 1 : 0, `warnings for ${JSON.stringify(value)}`);
    if (value?.trim()) assert.equal(warnings[0]!.toLowerCase().includes(value.trim().toLowerCase()), false);
  }
  warnings.length = 0;
  assert.equal(load(SELECTED), SELECTED);
  assert.equal(warnings.length, 0, "a valid value is silent");
});

test("with the override unset, list and point summary keep one reader, with the setting on and off", async t => {
  for (const on of [true, false]) for (const selected of [undefined, null]) {
    const seen = fake(t), cfg = selectedConfig(on, selected);
    t.after(() => forgetSessionReadTokens(cfg));
    const read = nativeRead(cfg, SELECTED);
    const expected = on ? { from: "read-api" } : { from: "history" };
    assert.deepEqual(await read(LIST_FOR(OTHER)), expected);
    assert.deepEqual(await read(POINT_FOR(OTHER)), expected);
    const used = on ? seen.reads : seen.history;
    assert.equal((on ? seen.history : seen.reads).length, 0, `setting ${on}, override ${selected}`);
    assert.deepEqual(used.map(({ url }) => [url.pathname, url.searchParams.getAll("workspace")]),
      [["/v1/sessions", [SELECTED]], ["/v1/sessions/s-1/summary", [SELECTED]]]);
  }
});

test("the override sends only the selected workspace's point summary to the read API", async t => {
  const seen = fake(t), cfg = selectedConfig(false);
  t.after(() => forgetSessionReadTokens(cfg));
  // The caller's workspace parameter names the other workspace each time; only admission decides.
  const selected = nativeRead(cfg, SELECTED);
  assert.deepEqual(await selected(LIST_FOR(OTHER)), { from: "history" });
  assert.deepEqual(await selected(POINT_FOR(OTHER)), { from: "read-api" });
  const other = nativeRead(cfg, OTHER);
  assert.deepEqual(await other(LIST_FOR(SELECTED)), { from: "history" });
  assert.deepEqual(await other(POINT_FOR(SELECTED)), { from: "history" });

  assert.deepEqual(seen.reads.map(({ url }) => [url.pathname, url.searchParams.getAll("workspace")]),
    [["/v1/sessions/s-1/summary", [SELECTED]]]);
  assert.deepEqual(seen.issues.map(({ path }) => path), [`/api/v1/workspaces/${SELECTED}/session-read/session`]);
  assert.deepEqual(seen.history.map(({ url }) => [url.pathname, url.searchParams.getAll("workspace")]), [
    ["/v1/sessions", [SELECTED]], ["/v1/sessions", [OTHER]], ["/v1/sessions/s-1/summary", [OTHER]],
  ]);
});

test("the override moves no other route for the selected workspace", async t => {
  const seen = fake(t), cfg = selectedConfig(false);
  t.after(() => forgetSessionReadTokens(cfg));
  const read = nativeRead(cfg, SELECTED);
  const paths = ["/v1/sessions", "/v1/sessions/activity", "/v1/events?q=x", "/v1/sessions/s-1/events?source=codex",
    "/v1/sessions/s-1/turns?source=codex", "/v1/sessions/s-1/metadata?source=codex", "/v1/sessions/s-1/timing?source=codex",
    "/v1/relayfacts", "/v1/relayfacts/topic-1", "/v1/sessions/s-1/summary/extra", "/v1/sessions/summary"];
  for (const path of paths) assert.deepEqual(await read(path), { from: "history" }, path);
  assert.equal(seen.reads.length + seen.issues.length, 0);
  assert.equal(seen.history.length, paths.length);
});

test("with the setting on, the override changes nothing for either workspace", async t => {
  const seen = fake(t), cfg = selectedConfig(true);
  t.after(() => forgetSessionReadTokens(cfg));
  for (const ws of [SELECTED, OTHER]) {
    const read = nativeRead(cfg, ws);
    assert.deepEqual(await read(LIST_FOR(ws)), { from: "read-api" });
    assert.deepEqual(await read(POINT_FOR(ws)), { from: "read-api" });
  }
  assert.equal(seen.history.length, 0);
  assert.equal(seen.reads.length, 4);
});

test("staff, Desktop and OAuth grants keep the workspace reader under the override", async t => {
  const grants: Array<[string, Principal, string]> = [
    ["staff", principal("user-a"), `sh_sr_${"S".repeat(43)}`],
    ["desktop", { ...principal("user-a"), scopes: ["rth:read", "mcp:desktop"] } as Principal, `cld_at_${"G".repeat(43)}`],
    ["oauth", oauth(["relay:mcp", "relay:history"]), OAUTH_TOKEN],
  ];
  for (const on of [true, false]) for (const [name, who, token] of grants) {
    const seen = fake(t), cfg = selectedConfig(on);
    const read = historyReader(cfg, who, workspace(SELECTED, orgOf(SELECTED)), token);
    assert.deepEqual(await read(LIST_FOR(OTHER)), { from: "history" });
    assert.deepEqual(await read(POINT_FOR(OTHER)), { from: "history" });
    assert.deepEqual(seen.history.map(({ url }) => url.searchParams.getAll("workspace")), [[SELECTED], [SELECTED]]);
    assert.equal(seen.reads.length + seen.issues.length, 0, `${name} setting ${on} never takes the per-user hop`);
  }
});

test("a selected point summary refuses missing, empty or foreign attestation without leaking the body", async t => {
  const leaked = "fake-summary-text-that-must-not-leak";
  for (const attest of [() => null, () => "", () => OTHER]) {
    const seen = fake(t, { attest, readBody: { summary: { text: leaked } } }), cfg = selectedConfig(false);
    t.after(() => forgetSessionReadTokens(cfg));
    const error = await nativeRead(cfg, SELECTED)(POINT_FOR(OTHER)).then(() => null, (caught: Error) => caught);
    assert.ok(error, "the read is refused");
    assert.match(error.message, /not available yet/);
    assert.equal(JSON.stringify([error.message, error.stack, { ...error }]).includes(leaked), false);
    assert.equal(seen.reads.length, 1);
    assert.equal(seen.history.length + seen.handoffs.length, 0, "no other backend is tried");
  }
});

test("a malformed selected point-summary body fails closed with no other backend", async t => {
  for (const readBody of [[], "text", 42]) {
    const seen = fake(t, { readBody }), cfg = selectedConfig(false);
    t.after(() => forgetSessionReadTokens(cfg));
    await assert.rejects(nativeRead(cfg, SELECTED)(POINT_FOR(OTHER)), /temporarily unavailable/);
    assert.equal(seen.history.length + seen.handoffs.length, 0);
  }
});

test("a selected point summary keeps terminal 403/404/501 outcomes and tries no other backend", async t => {
  for (const [status, outcome] of [[403, /temporarily unavailable/], [404, /temporarily unavailable/],
    [501, /unsupported_by_backend/], [503, /temporarily unavailable/]] as const) {
    const seen = fake(t, { readStatus: () => status }), cfg = selectedConfig(false);
    t.after(() => forgetSessionReadTokens(cfg));
    await assert.rejects(nativeRead(cfg, SELECTED)(POINT_FOR(OTHER)), outcome);
    assert.equal(seen.reads.length, 1, `status ${status}`);
    assert.equal(seen.reads[0]!.url.pathname, "/v1/sessions/s-1/summary");
    assert.deepEqual(seen.reads[0]!.url.searchParams.getAll("workspace"), [SELECTED]);
    assert.equal(seen.history.length + seen.handoffs.length, 0, "never History");
  }
});

test("per-session events and turns still refuse mis-attestation on either reader under the override", async t => {
  for (const on of [false, true]) for (const attest of [() => null, () => "", () => OTHER]) {
    for (const path of ["/v1/sessions/s-1/events?source=codex", "/v1/sessions/s-1/turns?source=codex"]) {
      const seen = fake(t, on ? { attest } : { historyAttest: attest }), cfg = selectedConfig(on);
      t.after(() => forgetSessionReadTokens(cfg));
      await assert.rejects(nativeRead(cfg, SELECTED)(path), /not available yet/, `${path} setting ${on}`);
      assert.equal((on ? seen.reads : seen.history).length, 1);
      assert.equal((on ? seen.history : seen.reads).length, 0, "no other backend is tried");
    }
  }
});
