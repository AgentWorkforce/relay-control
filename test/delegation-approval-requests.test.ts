import assert from "node:assert/strict";
import test, { type TestContext } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { copilotDesktopSetup, MCP_PATH } from "./support/copilot-desktop.js";
import { request } from "./support/harness.js";

// One-tap Tier O approval requests (Cloud's twin, cloud#6704): a delegate asks
// its own owner; only the owner's decision in a human session mints.

type CallResult = Awaited<ReturnType<Client["callTool"]>>;
function structured(result: CallResult): Record<string, any> {
  assert.notEqual(result.isError, true, JSON.stringify(result.content));
  return result.structuredContent as Record<string, any>;
}
function toolError(result: CallResult): string {
  assert.equal(result.isError, true, JSON.stringify(result.content));
  return (result.content as Array<{ text: string }>)[0]!.text;
}

const MERGE = { class: "merge", target: "acme/web#7", conditions: [{ type: "ci_green" }] };

async function setup(t: TestContext) {
  const clock = { offsetMs: 0 };
  const env = await copilotDesktopSetup(t, { now: () => new Date(Date.now() + clock.offsetMs) });
  const desktop = await env.desktopSignIn({ hostName: "owner-box" });
  const base = `/api/v1/workspaces/${env.workspaceId}`;
  const browser = (path: string, method: string, body?: unknown, cookie = desktop.session, origin = env.origin) =>
    request(env.origin, `/cloud${base}${path}`, { method, cookie, ...(method === "GET" ? {} : { body: body ?? {} }), headers: { origin } });
  const enabled = await browser("/delegates/policy", "PUT", { delegation_enabled: true });
  assert.equal(enabled.status, 200, enabled.raw);
  const cliToken = await env.deviceLogin();
  const client = new Client({ name: "approval-requests-test", version: "1.0.0" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${env.origin}${MCP_PATH}`),
    { requestInit: { headers: { authorization: `Bearer ${cliToken}` } } }));
  t.after(() => client.close());
  const call = (name: string, args: Record<string, unknown>) => client.callTool({ name, arguments: args });
  const ask = async (args: Record<string, unknown>) => structured(await call("request_owner_approval", args));
  const approvals = async () => (await env.database.query<{ id: string; tier: string; owner_user_id: string; actions: unknown; single_use: boolean }>(
    "SELECT id, tier, owner_user_id::text AS owner_user_id, actions, single_use FROM delegation_approvals ORDER BY created_at")).rows;
  const events = async () => (await env.database.query<{ event: string; approval_id: string | null; request_id: string | null; actor_agent_id: string | null }>(
    `SELECT event, approval_id, data->>'request_id' AS request_id, actor_agent_id FROM delegation_audit_events
      WHERE event LIKE 'approval%' ORDER BY id`)).rows;
  return { env, clock, desktop, base, browser, cliToken, client, call, ask, approvals, events };
}

test("a delegate's request mints nothing; the owner's approve mints exactly its actions as Tier O, once", async (t) => {
  const f = await setup(t);
  // No identity yet: the request names the way to get one.
  assert.match(toolError(await f.call("request_owner_approval", { actions: [MERGE] })), /made as your own Agent Relay identity/);
  const joined = structured(await f.call("join_relay", { name: "owner-bot" }));
  const requester = f.env.world.agents.get(joined.name)!;

  const asked = await f.ask({ actions: [MERGE], note: "CI is green on #7", single_use: true });
  assert.equal(asked.status, "pending");
  assert.match(asked.request_id, /^apq_[A-Za-z0-9]{8,64}$/);
  const url = new URL(asked.approve_url);
  assert.equal(url.pathname, `/dashboard/approvals/${asked.request_id}`);
  assert.equal(url.searchParams.get("workspace"), f.env.workspaceId);
  assert.deepEqual(asked.requester, { agent_id: requester.id, name: "owner-bot" });
  assert.deepEqual(asked.actions, [MERGE]);
  assert.equal(asked.approval_id, null);
  assert.deepEqual(await f.approvals(), [], "a request grants nothing");
  assert.equal(structured(await f.call("get_owner_approval_request", { request_id: asked.request_id })).status, "pending");

  // The owner reads it in a human session; a plain CLI token is refused before any read.
  const path = `/delegates/approval-requests/${asked.request_id}`;
  const read = await f.browser(path, "GET");
  assert.equal(read.status, 200, read.raw);
  assert.equal(read.body.note, "CI is green on #7");
  assert.equal((await request(f.env.origin, `${f.base}${path}`, { token: f.cliToken })).status, 403);
  assert.equal((await request(f.env.origin, `${f.base}${path}`, { method: "POST", body: { decision: "approve" } })).status, 401);
  assert.equal((await f.browser(path, "POST", { decision: "approve" }, f.desktop.session, "https://evil.example")).status, 403);
  assert.equal((await f.browser(path, "POST", { decision: "maybe" })).status, 400);
  assert.deepEqual(await f.approvals(), []);

  const approved = await f.browser(path, "POST", { decision: "approve" });
  assert.equal(approved.status, 200, approved.raw);
  assert.equal(approved.body.status, "approved");
  const minted = await f.approvals();
  assert.equal(minted.length, 1);
  assert.deepEqual({ ...minted[0], id: undefined }, { id: undefined, tier: "O", owner_user_id: f.env.ownerId, actions: [MERGE], single_use: true });
  assert.equal(approved.body.approval_id, minted[0]!.id);

  const again = await f.browser(path, "POST", { decision: "approve" });
  assert.equal(again.status, 409, again.raw);
  assert.equal(again.body.code, "decided");
  assert.equal((await f.browser(path, "POST", { decision: "deny" })).status, 409);
  assert.equal((await f.approvals()).length, 1, "decided once");

  const polled = structured(await f.call("get_owner_approval_request", { request_id: asked.request_id }));
  assert.equal(polled.status, "approved");
  assert.equal(polled.approval_id, minted[0]!.id);
  assert.deepEqual(await f.events(), [
    { event: "approval_request.requested", approval_id: null, request_id: asked.request_id, actor_agent_id: requester.id },
    { event: "approval.minted", approval_id: minted[0]!.id, request_id: asked.request_id, actor_agent_id: null },
    { event: "approval_request.approved", approval_id: minted[0]!.id, request_id: asked.request_id, actor_agent_id: requester.id },
  ]);
});

test("only the owner sees or decides a request; deny always works and mints nothing", async (t) => {
  const f = await setup(t);
  await f.call("join_relay", { name: "owner-bot" });
  const asked = await f.ask({ actions: [MERGE] });
  const path = `/delegates/approval-requests/${asked.request_id}`;
  const memberId = await f.env.addMember("member@acme.test");
  const other = await f.env.browserSession(memberId);
  assert.equal((await f.browser(path, "GET", undefined, other)).status, 404);
  assert.equal((await f.browser(path, "POST", { decision: "approve" }, other)).status, 404);
  assert.equal((await f.browser("/delegates/approval-requests/apq_doesnotexist1", "GET")).status, 404);
  assert.equal((await f.browser("/delegates/approval-requests/not-an-id", "GET")).status, 404);

  // The policy is checked again at approve; denying still works.
  const narrowed = await f.browser("/delegates/policy", "PUT", { delegation_enabled: true, allowed_classes: ["pr_ops"] });
  assert.equal(narrowed.status, 200, narrowed.raw);
  const refused = await f.browser(path, "POST", { decision: "approve" });
  assert.equal(refused.status, 403, refused.raw);
  assert.equal(refused.body.code, "out_of_scope");
  const denied = await f.browser(path, "POST", { decision: "deny" });
  assert.equal(denied.status, 200, denied.raw);
  assert.equal(denied.body.status, "denied");
  assert.equal(denied.body.approval_id, null);
  assert.deepEqual(await f.approvals(), []);
  assert.equal(structured(await f.call("get_owner_approval_request", { request_id: asked.request_id })).status, "denied");
});

test("requests are validated field by field and against the policy before anything is recorded", async (t) => {
  const f = await setup(t);
  await f.call("join_relay", { name: "owner-bot" });
  const refused: Array<[Record<string, unknown>, RegExp]> = [
    [{ actions: [{ class: "merge", target: "acme/web" }] }, /^invalid_request: actions\[0\]: invalid target or conditions for this action\. Nothing was requested\.$/],
    [{ actions: [MERGE, MERGE] }, /^invalid_request: actions: one entry per class and target/],
    [{ actions: [{ class: "approve_everything", target: "acme/web#7" }] }, /^invalid_request: actions\[0\]\.class:/],
    [{ actions: [MERGE], expires_in_minutes: 1441 }, /^invalid_request: expires_in_minutes:/],
    [{ actions: [MERGE], note: "x".repeat(501) }, /^invalid_request: note:/],
    [{ actions: [{ class: "config_change", target: "chat-1:delegated_approvals_from=anyone" }] }, /^out_of_scope: Delegation settings themselves are never delegable/],
  ];
  for (const [args, message] of refused) assert.match(toolError(await f.call("request_owner_approval", args)), message, JSON.stringify(args));
  const narrowed = await f.browser("/delegates/policy", "PUT", { delegation_enabled: true, allowed_classes: ["pr_ops"] });
  assert.equal(narrowed.status, 200, narrowed.raw);
  assert.match(toolError(await f.call("request_owner_approval", { actions: [MERGE] })), /^out_of_scope: Policy does not allow delegating: merge/);
  const off = await f.browser("/delegates/policy", "PUT", { delegation_enabled: false });
  assert.equal(off.status, 200, off.raw);
  assert.match(toolError(await f.call("request_owner_approval", { actions: [MERGE] })), /^not_enabled:/);
  assert.equal((await f.env.database.query("SELECT 1 FROM delegation_approval_requests")).rows.length, 0);
  assert.match(toolError(await f.call("get_owner_approval_request", { request_id: "apq_doesnotexist1" })), /No approval request with that id/);
});

test("a pending request past its expiry is expired once, on read or decide, and answers 409 expired", async (t) => {
  const f = await setup(t);
  await f.call("join_relay", { name: "owner-bot" });
  const first = await f.ask({ actions: [MERGE], expires_in_minutes: 1 });
  const second = await f.ask({ actions: [{ class: "pr_ops", target: "acme/web#7:comment" }], expires_in_minutes: 1 });
  f.clock.offsetMs = 2 * 60_000;
  const read = await f.browser(`/delegates/approval-requests/${first.request_id}`, "GET");
  assert.equal(read.status, 200, read.raw);
  assert.equal(read.body.status, "expired");
  const decided = await f.browser(`/delegates/approval-requests/${second.request_id}`, "POST", { decision: "approve" });
  assert.equal(decided.status, 409, decided.raw);
  assert.equal(decided.body.code, "expired");
  assert.equal(decided.body.request.status, "expired");
  // Expired on read, it still answers expired when decided later, and is expired once.
  assert.equal((await f.browser(`/delegates/approval-requests/${first.request_id}`, "POST", { decision: "approve" })).body.code, "expired");
  assert.deepEqual(await f.approvals(), []);
  assert.equal((await f.events()).filter(row => row.event === "approval_request.expired").length, 2);
});

test("two racing approves mint once", async (t) => {
  const f = await setup(t);
  await f.call("join_relay", { name: "owner-bot" });
  const asked = await f.ask({ actions: [MERGE] });
  const path = `/delegates/approval-requests/${asked.request_id}`;
  const results = await Promise.all([f.browser(path, "POST", { decision: "approve" }), f.browser(path, "POST", { decision: "approve" })]);
  assert.deepEqual(results.map(result => result.status).sort(), [200, 409]);
  assert.equal((await f.approvals()).length, 1);
});

test("a request is read only by the identity that made it; as selects the caller's own participant", async (t) => {
  const f = await setup(t);
  await f.call("join_relay", { name: "owner-bot" });
  const asked = await f.ask({ actions: [MERGE] });
  // Another session of the same owner, with its own hosted participant.
  const other = new Client({ name: "approval-requests-other", version: "1.0.0" });
  await other.connect(new StreamableHTTPClientTransport(new URL(`${f.env.origin}${MCP_PATH}`),
    { requestInit: { headers: { authorization: `Bearer ${f.cliToken}` } } }));
  t.after(() => other.close());
  structured(await other.callTool({ name: "join_relay", arguments: { name: "second-bot" } }));
  assert.match(toolError(await other.callTool({ name: "get_owner_approval_request", arguments: { request_id: asked.request_id } })),
    /No approval request with that id was made by you/);
  // Naming its own participant by `as` still sees only that participant's requests.
  const mine = structured(await other.callTool({ name: "request_owner_approval", arguments: { actions: [MERGE], as: "second-bot" } }));
  assert.equal(mine.requester.name, "second-bot");
  assert.equal(structured(await other.callTool({ name: "get_owner_approval_request",
    arguments: { request_id: mine.request_id, as: "second-bot" } })).status, "pending");
  assert.match(toolError(await f.call("get_owner_approval_request", { request_id: mine.request_id })), /made by you/);
  // Another person's participant is never selectable.
  assert.equal((await other.callTool({ name: "request_owner_approval", arguments: { actions: [MERGE], as: "nobody-else" } })).isError, true);
});
