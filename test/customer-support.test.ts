import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { createServer } from "node:http";
import test from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { askCustomerSupport, sendCustomerSupport, CUSTOMER_SUPPORT_PATH, type CustomerSupportRequest } from "../src/mcp/customer-support.js";
import type { McpContext } from "../src/mcp/context.js";
import { copilotDesktopSetup, identitiesPath, MCP_PATH } from "./support/copilot-desktop.js";
import { close, listen, request } from "./support/harness.js";

const TOKEN = "dedicated-support-token-".repeat(2);
const input = { message: "Private setup question", request_id: "support-message-001" };
const minimal = () => ({ principal: { userId: randomUUID() }, workspace: { id: randomUUID(), organizationId: randomUUID() } }) as McpContext;

test("support input, retry identity, wait modes and revocation match the Cloud contract", async () => {
  const context = minimal();
  const sent: CustomerSupportRequest[] = [];
  let authorized = true;
  context.customerSupport = { origin: "https://control.test", authorize: async () => authorized,
    notifyTarget: async () => null, send: async body => { sent.push(body); return { kind: "pending", text: "working" }; } };
  for (const [mode, waitMs] of [[undefined, undefined], ["wait", undefined], ["hybrid", 4000], ["async", 0]] as const) {
    const result = await askCustomerSupport(context, { ...input, ...(mode ? { mode } : {}) });
    assert.equal(result.status, "pending");
    assert.equal(sent.at(-1)!.waitMs, waitMs);
    assert.equal(sent.at(-1)!.conversationId, sent[0]!.conversationId);
    assert.deepEqual(sent.at(-1)!.entitlements, ["selfhost"]);
  }
  for (const injected of [{ tenant: "other" }, { userId: randomUUID() }, { entitlements: [] }, { notify: { desktopAddress: "other@machine" } }]) {
    await assert.rejects(askCustomerSupport(context, { ...input, ...injected }));
  }
  context.customerSupport.send = async () => { authorized = false; return { kind: "reply", replies: ["PRIVATE_REPLY"] }; };
  assert.deepEqual(await askCustomerSupport(context, input), { status: "not_authorized" });
  assert.deepEqual(await askCustomerSupport(minimal(), input), { status: "unavailable" });
});

test("support transport refuses redirects and never forwards the service credential to them", async () => {
  let calls = 0;
  const context = minimal();
  const body: CustomerSupportRequest = { controlOrigin: "https://control.test", organizationId: context.workspace.organizationId,
    workspaceId: context.workspace.id, userId: context.principal.userId, conversationId: "a".repeat(32), requestId: input.request_id,
    message: input.message, entitlements: ["selfhost"] };
  const result = await sendCustomerSupport({ url: "https://support.test", token: TOKEN }, body, (async (url, init) => {
    calls++;
    assert.equal(String(url), `https://support.test${CUSTOMER_SUPPORT_PATH}`);
    assert.equal(init?.redirect, "manual");
    assert.equal(new Headers(init?.headers).get("authorization"), `Bearer ${TOKEN}`);
    return new Response(null, { status: 302, headers: { location: "https://untrusted.test" } });
  }) as typeof fetch);
  assert.deepEqual(result, { kind: "unavailable" });
  assert.equal(calls, 1);
});

test("real MCP calls, private history exclusion and Desktop reply wakes work without Cloud", async t => {
  const calls: CustomerSupportRequest[] = [];
  let beforeReply = async () => {};
  const backend = createServer(async (req, res) => {
    assert.equal(req.url, CUSTOMER_SUPPORT_PATH);
    assert.equal(req.headers.authorization, `Bearer ${TOKEN}`);
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    calls.push(JSON.parse(Buffer.concat(chunks).toString("utf8")) as CustomerSupportRequest);
    await beforeReply();
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ kind: "reply", replies: ["PRIVATE_SUPPORT_REPLY"] }));
  });
  const supportOrigin = await listen(backend);
  t.after(() => close(backend));
  const env = await copilotDesktopSetup(t);
  env.config.customerSupport = { url: supportOrigin, token: TOKEN };
  // Every member can use support; owner/admin status and staff enrollment are unnecessary.
  await env.database.query("UPDATE organization_memberships SET role = 'member' WHERE user_id = $1", [env.ownerId]);
  const token = await env.deviceLogin();
  const client = new Client({ name: "support-test", version: "1" });
  await client.connect(new StreamableHTTPClientTransport(new URL(`${env.origin}${MCP_PATH}`),
    { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
  t.after(() => client.close());
  const result = await client.callTool({ name: "ask_customer_support", arguments: { ...input, mode: "async" } });
  assert.notEqual(result.isError, true, "the registered support tool must dispatch through the HTTP client");
  assert.equal(calls.length, 1, "the Control support tool must send the request to the configured service");
  assert.deepEqual(result.structuredContent, { status: "reply", conversation_id: calls[0]!.conversationId, replies: ["PRIVATE_SUPPORT_REPLY"] });
  assert.equal(calls[0]!.workspaceId, env.workspaceId);
  assert.equal(calls[0]!.organizationId, env.orgId);
  assert.equal(calls[0]!.userId, env.ownerId);
  assert.equal(calls[0]!.waitMs, 0);
  assert.equal(calls[0]!.notify, undefined);
  assert(!JSON.stringify(calls).includes(token));
  const audit = await env.database.query("SELECT * FROM shared_session_read_audit");
  assert.equal(audit.rows.length, 0);
  const capabilities = (await client.callTool({ name: "describe_capabilities", arguments: {} })).structuredContent as any;
  assert.equal(capabilities.groups.find((group: any) => group.id === "customer_support").status, "available");

  const parent = await env.desktopSignIn();
  const ownerHash = createHash("sha256").update(env.ownerId).digest("hex");
  const chat = env.world.addAgent("support-desktop", { source: "relay-desktop", owner_hash: ownerHash });
  const desktopAddress = `${chat.name}@cloud-${chat.id}`;
  const sync = await request(env.origin, identitiesPath(env.workspaceId), { method: "PUT", token: parent.accessToken,
    body: { source_id: randomUUID(), identities: [{ name: chat.name, address: desktopAddress, agent_id: chat.id, token: chat.token }] } });
  assert.equal(sync.status, 200, sync.raw);
  assert.notEqual((await client.callTool({ name: "join_relay", arguments: { desktop_address: desktopAddress } })).isError, true);
  await client.callTool({ name: "ask_customer_support", arguments: input });
  assert.deepEqual(calls.at(-1)!.notify, { desktopAddress });
  const notice = { version: 1, organizationId: env.orgId, workspaceId: env.workspaceId, userId: env.ownerId,
    desktopAddress, conversationId: calls[0]!.conversationId, revision: 1, replyId: 2 };
  const noticePath = "/internal/v1/customer-support/reply-notice";
  assert.equal((await request(env.origin, noticePath, { method: "POST", body: notice })).status, 401);
  assert.equal((await request(env.origin, noticePath, { method: "POST", token: TOKEN, body: { ...notice, userId: randomUUID() } })).body.status, "not_authorized");
  const messagesBefore = env.world.messages.size;
  assert.equal((await request(env.origin, noticePath, { method: "POST", token: TOKEN, body: notice })).body.status, "sent");
  assert.equal((await request(env.origin, noticePath, { method: "POST", token: TOKEN, body: notice })).body.status, "sent");
  const notices = env.world.bodies.filter(call => call.path === "/v1/dm" && String(call.body?.text).includes("ask_customer_support"));
  assert.equal(notices.length, 2);
  assert.equal(env.world.messages.size, messagesBefore + 1, "duplicate notices create only one Relaycast message");
  assert.equal(notices[0]!.body!.address, desktopAddress);
  assert(!JSON.stringify(notices).includes("PRIVATE_SUPPORT_REPLY"));

  beforeReply = async () => { await env.database.query("DELETE FROM organization_memberships WHERE user_id = $1", [env.ownerId]); };
  const revoked = await client.callTool({ name: "ask_customer_support", arguments: { ...input, request_id: "revoke-during-call" } });
  assert.deepEqual(revoked.structuredContent, { status: "not_authorized" });
  assert.equal((await request(env.origin, noticePath, { method: "POST", token: TOKEN, body: notice })).body.status, "not_authorized");
});
