import assert from "node:assert/strict";
import test from "node:test";
import { connectAndBind, factoryPath, queueRelayMessage, startFactoryEnv } from "./factory-helpers.js";

test("factory delivery receipt is readable by the binding owner only and never reconciles an unknown send", async (t) => {
  const env = await startFactoryEnv(t);
  const bound = await connectAndBind(env);
  queueRelayMessage(env.relay, bound.agent.name, { id: "m-ok", text: "one" });
  queueRelayMessage(env.relay, bound.agent.name, { id: "m-500", text: "two" });
  await env.module.worker.pollInbox();
  await env.module.worker.kickDelivery(bound.binding_id, "m-ok");
  env.factory.injectMode = "500";
  await env.module.worker.kickDelivery(bound.binding_id, "m-500");
  const path = (messageId: string) => factoryPath(env.workspaceId, `/bindings/${bound.binding_id}/deliveries/${messageId}`);

  const ok = await env.api(path("m-ok"), { token: env.ownerToken });
  assert.equal(ok.status, 200);
  assert.deepEqual(ok.body, { state: "delivered" });
  assert.equal(ok.headers.get("cache-control"), "no-store");
  const requestsBefore = env.factory.requests.length;
  assert.deepEqual((await env.api(path("m-500"), { token: env.ownerToken })).body, { state: "unknown", code: "factory_http_500" });
  assert.equal(env.factory.requests.length, requestsBefore, "a receipt read makes no provider call");

  const missing = await env.api(path("m-none"), { token: env.ownerToken });
  assert.deepEqual([missing.status, missing.body.error], [404, "delivery_not_found"]);
  // Another admin of the same workspace sees no such binding; members are refused at the gate.
  const admin = await env.api(path("m-ok"), { token: env.adminToken });
  assert.deepEqual([admin.status, admin.body.error], [404, "binding_not_found"]);
  assert.equal((await env.api(path("m-ok"), { token: env.memberToken })).status, 403);
  const elsewhere = await env.api(factoryPath(env.otherWorkspaceId, `/bindings/${bound.binding_id}/deliveries/m-ok`), { token: env.ownerOtherToken });
  assert.equal(elsewhere.status, 404);
});
