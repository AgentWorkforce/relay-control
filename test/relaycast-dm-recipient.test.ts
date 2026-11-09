import assert from "node:assert/strict";
import test from "node:test";
import { z } from "zod";
import { createRelaycastClient, RelaycastCallError } from "../src/messaging/relaycast.js";

// Relaycast's direct-message endpoint selects exactly one recipient. An address
// binds the machine too; it must never be downgraded to a same-name agent.
const directRecipient = z.object({
  to: z.string().min(1).optional(),
  address: z.string().min(1).optional(),
  text: z.string().min(1),
}).refine((body) => (body.to === undefined) !== (body.address === undefined));

function fixture(status = 201) {
  const calls: Array<{ url: string; body: unknown; authorization: string | null; key: string | null }> = [];
  const fetchImpl = (async (url, init) => {
    const headers = new Headers(init?.headers);
    const body = JSON.parse(String(init?.body));
    calls.push({ url: String(url), body, authorization: headers.get("authorization"), key: headers.get("idempotency-key") });
    if (!directRecipient.safeParse(body).success) {
      return Response.json({ ok: false, error: { code: "invalid_request" } }, { status: 400 });
    }
    if (status !== 201) return Response.json({ ok: false, error: { code: status === 401 ? "unauthorized" : "address_not_found" } }, { status });
    return Response.json({ ok: true, data: { conversation_id: "conversation-1", message: { id: "message-1", agent_name: "sender", text: body.text } } }, { status });
  }) as typeof fetch;
  return { calls, client: createRelaycastClient({ internalOrigin: "http://cast.internal.example", fetchImpl }) };
}

test("an exact machine address is the sole recipient and preserves actor and idempotency", async () => {
  const f = fixture();
  const sent = await f.client.sendDirectMessage({ token: "fixture-actor", to: "builder", address: "builder@machine-a", text: "one addressed message", idempotencyKey: "stable-message-key" });
  assert.equal(sent.message.id, "message-1");
  assert.deepEqual(f.calls, [{ url: "http://cast.internal.example/v1/dm", body: { address: "builder@machine-a", text: "one addressed message" }, authorization: "Bearer fixture-actor", key: "stable-message-key" }]);
});

test("a send by name retains its previous request", async () => {
  const f = fixture();
  await f.client.sendDirectMessage({ token: "fixture-actor", to: "builder", text: "one named message", idempotencyKey: "stable-name-key" });
  assert.deepEqual(f.calls[0]?.body, { to: "builder", text: "one named message" });
});

test("a rejected or invalid address never retries by name or changes caller credentials", async () => {
  for (const status of [401, 404]) {
    const f = fixture(status);
    await assert.rejects(f.client.sendDirectMessage({ token: "fixture-actor", to: "builder", address: "builder@other-machine", text: "refuse", idempotencyKey: "stable-refused-key" }), (error: unknown) => error instanceof RelaycastCallError && error.status === status && !error.outcomeUnknown);
    assert.equal(f.calls.length, 1);
    assert.deepEqual(f.calls[0]?.body, { address: "builder@other-machine", text: "refuse" });
    assert.equal(f.calls[0]?.authorization, "Bearer fixture-actor");
    assert.equal(f.calls[0]?.key, "stable-refused-key");
  }
  const f = fixture();
  await assert.rejects(f.client.sendDirectMessage({ token: "fixture-actor", to: "builder", address: "", text: "refuse", idempotencyKey: "stable-invalid-key" }), (error: unknown) => error instanceof RelaycastCallError && error.status === 400);
  assert.equal(f.calls.length, 1);
  assert.deepEqual(f.calls[0]?.body, { address: "", text: "refuse" });
});
