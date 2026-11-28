import assert from "node:assert/strict";
import test from "node:test";
import type { Database } from "../src/database.js";
import { createRelaycastClient } from "../src/messaging/relaycast.js";
import {
  sendAsSupport,
  SUPPORT_SENDER_NAME,
  SUPPORT_SENDER_PERSONA,
  supportSenderLockKey,
  supportSenderMetadata,
  supportSenderNames,
  SupportSenderError,
} from "../src/messaging/support-identity.js";
import { isListedRelayAgent } from "../src/mcp/team-activity.js";
import { createRelaycastWorld } from "./support/relaycast-world.js";

const WORKSPACE = "22222222-2222-4222-8222-222222222222";
const KEY = "rk_live_support_test";
const allow = async () => true;

function setup() {
  const world = createRelaycastWorld([]);
  const desktop = world.addAgent("claude-owner", { source: "relay-desktop" });
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const headers = new Headers(init?.headers);
    const result = await world.handle(init?.method ?? "GET", url.pathname, url.searchParams,
      (headers.get("authorization") ?? "").replace(/^Bearer /, ""),
      init?.body ? JSON.parse(String(init.body)) : null, headers.get("idempotency-key"));
    return Response.json(result?.body ?? { ok: false, error: { code: "not_found" } }, { status: result?.status ?? 404 });
  };
  const locks: string[] = [];
  const database = {
    transaction: async <T>(run: (tx: unknown) => Promise<T>) => run({
      query: async (_sql: string, params: unknown[]) => { locks.push(String(params[1])); return { rows: [] }; },
    }),
  } as unknown as Database;
  const relaycast = createRelaycastClient({ internalOrigin: "http://relaycast.test", fetchImpl });
  const input = { to: desktop.name, address: `${desktop.name}@cloud-${desktop.id}`,
    text: "Agent Relay support replied on your case.", idempotencyKey: "support-reply-0123456789abcdef0123456789abcdef01234567" };
  const deps = { database, relaycast, gateOnly: false };
  const workspace = { id: WORKSPACE, relaycastApiKey: KEY };
  const dms = () => world.bodies.filter(call => call.path === "/v1/dm");
  const senderOf = (text: string) => [...world.messages.values()].filter(m => m.text === text).map(m => m.agent_name);
  return { world, desktop, deps, workspace, input, locks, dms, senderOf };
}

test("registers the workspace's support sender on first use and DMs only the given Desktop address", async () => {
  const { world, deps, workspace, input, locks, dms, senderOf } = setup();
  assert.deepEqual(await sendAsSupport(deps, workspace, input, allow), { from: SUPPORT_SENDER_NAME });
  const agent = world.agents.get(SUPPORT_SENDER_NAME)!;
  assert.equal(agent.type, "agent");
  assert.deepEqual(agent.metadata, supportSenderMetadata(WORKSPACE));
  const register = world.bodies.find(call => call.method === "POST" && call.path === "/v1/agents")!;
  assert.equal(register.body!.persona, SUPPORT_SENDER_PERSONA);
  assert.deepEqual(dms().map(call => call.body!.address), [input.address]);
  assert.equal(dms()[0]!.body!.to, undefined, "exact address only, never a name lookup");
  assert.deepEqual(senderOf(input.text), [SUPPORT_SENDER_NAME], "never sent as the member");
  assert.deepEqual(locks, [supportSenderLockKey(WORKSPACE)]);
});

test("takes its own agent back through the audited takeover and a redelivery posts once", async () => {
  const { world, deps, workspace, input, senderOf } = setup();
  await sendAsSupport(deps, workspace, input, allow);
  await sendAsSupport(deps, workspace, input, allow);
  assert.equal(world.bodies.filter(call => call.path === `/v1/agents/${SUPPORT_SENDER_NAME}/takeover`).length, 1);
  assert.equal(world.bodies.filter(call => call.method === "POST" && call.path === "/v1/agents").length, 1);
  assert.deepEqual(senderOf(input.text), [SUPPORT_SENDER_NAME], "the same per-wake key deduplicates on the same sender");
});

test("leaves a foreign holder of the preferred name alone and sends from a stable fallback", async () => {
  const { world, deps, workspace, input, senderOf } = setup();
  const squatter = world.addAgent(SUPPORT_SENDER_NAME, { source: "mcp-hosted", workspace_id: WORKSPACE });
  const squatterToken = squatter.token;
  const [, fallback] = supportSenderNames(WORKSPACE);
  assert.deepEqual(await sendAsSupport(deps, workspace, input, allow), { from: fallback });
  assert.equal(world.agents.get(SUPPORT_SENDER_NAME)!.token, squatterToken, "the foreign holder is never taken over");
  assert.equal(world.bodies.some(call => call.path === `/v1/agents/${SUPPORT_SENDER_NAME}/takeover`), false);
  assert.deepEqual(senderOf(input.text), [fallback]);
  // Stable per workspace, distinct across workspaces, valid agent names.
  assert.deepEqual(supportSenderNames(WORKSPACE), supportSenderNames(WORKSPACE));
  assert.notEqual(supportSenderNames("99999999-9999-4999-8999-999999999999")[1], fallback);
  for (const name of supportSenderNames(WORKSPACE, true)) assert.match(name, /^control-agent-relay-support(-[0-9a-f]+)?$/);
});

test("keeps its owned fallback after the preferred name frees up", async () => {
  const { world, deps, workspace, input } = setup();
  const [, fallback] = supportSenderNames(WORKSPACE);
  world.addAgent(fallback!, supportSenderMetadata(WORKSPACE));
  assert.deepEqual(await sendAsSupport(deps, workspace, input, allow), { from: fallback });
  assert.equal(world.agents.has(SUPPORT_SENDER_NAME), false, "the free preferred name is not registered");
});

test("never adopts an agent another workspace or another source owns, and fails closed when all names are taken", async () => {
  for (const metadata of [{}, { source: "cloud-person", workspace_id: WORKSPACE }, supportSenderMetadata("99999999-9999-4999-8999-999999999999")]) {
    const { world, deps, workspace, input, dms } = setup();
    for (const name of supportSenderNames(WORKSPACE)) world.addAgent(name, metadata);
    await assert.rejects(sendAsSupport(deps, workspace, input, allow), SupportSenderError);
    assert.equal(world.bodies.some(call => call.path.endsWith("/takeover")), false);
    assert.equal(dms().length, 0);
  }
});

test("rechecks access after the lock and token, and sends nothing once it is revoked", async () => {
  const { world, deps, workspace, input, dms } = setup();
  let checkedAfterToken = false;
  const revoked = async () => {
    checkedAfterToken = world.agents.has(SUPPORT_SENDER_NAME);
    return false;
  };
  assert.equal(await sendAsSupport(deps, workspace, input, revoked), null);
  assert.equal(checkedAfterToken, true);
  assert.equal(dms().length, 0);
});

test("uses relaygate's reserved prefix on gate-only installs", async () => {
  const { world, deps, workspace, input } = setup();
  assert.deepEqual(await sendAsSupport({ ...deps, gateOnly: true }, workspace, input, allow), { from: `control-${SUPPORT_SENDER_NAME}` });
  assert.equal(world.agents.has(SUPPORT_SENDER_NAME), false);
});

test("is not listed as a messageable peer", () => {
  assert.equal(isListedRelayAgent({ metadata: supportSenderMetadata(WORKSPACE) }), false);
  assert.equal(isListedRelayAgent({ metadata: { source: "relay-desktop" } }), true);
});
