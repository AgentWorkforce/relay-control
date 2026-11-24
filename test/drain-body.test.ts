import assert from "node:assert/strict";
import { test } from "node:test";
import { drainBody } from "../src/drain-body.js";

function trackedResponse(status: number): { response: Response; cancelled: () => boolean } {
  let cancelled = false;
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode("secret-looking payload"));
    },
    cancel() {
      cancelled = true;
    },
  });
  return { response: new Response(body, { status }), cancelled: () => cancelled };
}

for (const status of [200, 204, 404, 500]) {
  test(`drainBody releases the body of a ${status} response`, async (t) => {
    const warn = t.mock.method(console, "warn", () => {});
    const { response, cancelled } = status === 204
      ? { response: new Response(null, { status }), cancelled: () => true }
      : trackedResponse(status);
    await drainBody(response, "test.status");
    assert.equal(cancelled(), true);
    assert.equal(warn.mock.callCount(), 0);
  });
}

test("drainBody marks a real body as consumed so it cannot linger", async () => {
  const response = new Response("hello", { status: 502 });
  await drainBody(response, "test.real");
  assert.equal(response.bodyUsed, true);
});

test("drainBody is a no-op on a null body and on an already-read body", async (t) => {
  const warn = t.mock.method(console, "warn", () => {});
  await drainBody(new Response(null, { status: 204 }), "test.null");
  const read = new Response("done");
  await read.text();
  await drainBody(read, "test.read");
  assert.equal(warn.mock.callCount(), 0);
});

test("drainBody never throws and logs only the label and error name on a failed cancel", async (t) => {
  const warn = t.mock.method(console, "warn", () => {});
  const failing = {
    bodyUsed: false,
    body: {
      cancel: () => Promise.reject(new TypeError("token=sk-should-not-appear")),
    },
  };
  await assert.doesNotReject(drainBody(failing, "test.failure"));
  assert.equal(warn.mock.callCount(), 1);
  const [message, fields] = warn.mock.calls[0]!.arguments as [string, Record<string, unknown>];
  assert.equal(message, "[drain-body] response body drain failed");
  assert.deepEqual(fields, { label: "test.failure", error: "TypeError" });
  assert.doesNotMatch(JSON.stringify(warn.mock.calls[0]!.arguments), /sk-should-not-appear/);
});

test("drainBody swallows a synchronous throw and a non-Error rejection", async (t) => {
  const warn = t.mock.method(console, "warn", () => {});
  const sync = { bodyUsed: false, body: { cancel: () => { throw new RangeError("boom"); } } };
  const odd = { bodyUsed: false, body: { cancel: () => Promise.reject("string reason") } };
  await assert.doesNotReject(drainBody(sync, "test.sync"));
  await assert.doesNotReject(drainBody(odd, "test.odd"));
  assert.deepEqual(warn.mock.calls.map((call) => call.arguments[1]), [
    { label: "test.sync", error: "RangeError" },
    { label: "test.odd", error: "string" },
  ]);
});
