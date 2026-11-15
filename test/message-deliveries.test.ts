import assert from "node:assert/strict";
import test from "node:test";
import { createRelaycastClient, RelaycastCallError } from "../src/messaging/relaycast.js";

test("sender receipts use only the acting token and preserve acceptance, acknowledgement and explicit reads", async () => {
  for (const state of ["queued", "delivered", "consumed", "replied", "failed"]) {
    const client = createRelaycastClient({ internalOrigin: "https://cast.example.test", fetchImpl: async (url, init) => {
      assert.equal(String(url), "https://cast.example.test/v1/messages/123/deliveries");
      assert.equal(new Headers(init?.headers).get("authorization"), "Bearer acting-agent-token");
      return Response.json({ ok: true, data: { message_id: "123", deliveries: [{ id: "456", agent_id: "789", agent_name: "receiver",
        status: "delivered", state, accepted_at: state === "queued" ? null : "2026-11-14T00:00:00Z", read_at: null }] } });
    } });
    const [receipt] = (await client.getMessageDeliveries("acting-agent-token", "123"))!;
    assert.equal(receipt!.state, state);
    assert.equal(receipt!.read_at, null);
    if (state === "queued") assert.equal(receipt!.accepted_at, null);
  }
});

test("unsupported and invisible receipts remain unconfirmed; authorization and outages stay errors", async () => {
  for (const status of [404, 501, 401, 403, 503]) {
    const client = createRelaycastClient({ internalOrigin: "https://cast.example.test", fetchImpl: async () =>
      Response.json({ ok: false, error: { code: "not_found" } }, { status }) });
    if ([404, 501].includes(status)) assert.equal(await client.getMessageDeliveries("actor", "123"), null);
    else await assert.rejects(client.getMessageDeliveries("actor", "123"), RelaycastCallError);
  }
});

test("malformed or mismatched receipt data cannot produce a confirmation", async () => {
  for (const data of [{ message_id: "other", deliveries: [] }, { message_id: "123", deliveries: [{ id: "1", agent_id: "2", status: "acked", state: "read" }] }]) {
    const client = createRelaycastClient({ internalOrigin: "https://cast.example.test", fetchImpl: async () => Response.json({ ok: true, data }) });
    await assert.rejects(client.getMessageDeliveries("actor", "123"), RelaycastCallError);
  }
});
