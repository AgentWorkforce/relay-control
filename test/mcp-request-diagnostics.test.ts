import assert from "node:assert/strict";
import test from "node:test";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";
import { correlateMcpResponse, instrumentMcpTransport, withMcpDiagnosticContext } from "../src/mcp/request-diagnostics.js";

const FIRST = "00000000-0000-4000-8000-000000000001";
const SECOND = "00000000-0000-4000-8000-000000000002";

async function exchange(message: JSONRPCMessage) {
  let response: Response | undefined;
  const transport = { send: async (message: JSONRPCMessage) => { response = Response.json(message); } };
  instrumentMcpTransport(transport, "shared-sessions");
  await transport.send(message);
  return correlateMcpResponse(response!, "shared-sessions");
}

test("MCP diagnostics preserve protocol errors and correlate HTTP-200 replies", async t => {
  const log = t.mock.method(console, "error", () => {});
  await withMcpDiagnosticContext(FIRST, async () => {
    const response = await exchange({ jsonrpc: "2.0", id: "request", error: {
      code: -32602, message: "Invalid arguments", data: "existing detail",
    } });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-correlation-id"), FIRST);
    assert.deepEqual(await response.json(), { jsonrpc: "2.0", id: "request", error: {
      code: -32602, message: "Invalid arguments", data: { details: "existing detail", correlation_id: FIRST },
    } });
  });
  assert.deepEqual(log.mock.calls[0]?.arguments, ["[mcp] request failed", {
    endpoint: "shared-sessions", status: 200, correlationId: FIRST,
  }]);
});

test("MCP diagnostics retain handler-generated tool IDs without success-schema fields", async t => {
  t.mock.method(console, "error", () => {});
  await withMcpDiagnosticContext(FIRST, async () => {
    const response = await exchange({ jsonrpc: "2.0", id: 1, result: { isError: true,
      content: [{ type: "text", text: `Read failed\ncorrelation_id: ${SECOND}` }],
    } });
    assert.equal(response.headers.get("x-correlation-id"), SECOND);
    const body = await response.json() as any;
    assert.equal(body.result.content.length, 1);
    assert.equal(body.result.structuredContent, undefined);
  });
});

test("MCP diagnostics add useful correlated text to empty tool errors", async t => {
  t.mock.method(console, "error", () => {});
  await withMcpDiagnosticContext(FIRST, async () => {
    const body = await (await exchange({ jsonrpc: "2.0", id: 1, result: { isError: true, content: [] } })).json() as any;
    assert.deepEqual(body.result.content, [
      { type: "text", text: "The MCP tool failed. Please try again." },
      { type: "text", text: `correlation_id: ${FIRST}` },
    ]);
  });
});

test("MCP diagnostics leave successful transcript bodies unread", async t => {
  const body = JSON.stringify({ result: { content: "x".repeat(1024 * 1024) } });
  const original = new Response(body, { headers: { "content-type": "application/json" } });
  for (const method of ["text", "json", "arrayBuffer"] as const) {
    t.mock.method(original, method, async () => { throw Error("Successful body must not be decoded"); });
  }
  const response = await correlateMcpResponse(original, "shared-sessions", FIRST);
  assert.equal(original.bodyUsed, false);
  assert.equal(await response.text(), body);
});

test("MCP diagnostics keep concurrent request IDs separate", async t => {
  t.mock.method(console, "error", () => {});
  const responses = await Promise.all([FIRST, SECOND].map(id => withMcpDiagnosticContext(id, async () => {
    await new Promise(resolve => setTimeout(resolve, id === FIRST ? 5 : 0));
    return exchange({ jsonrpc: "2.0", id: 1, result: { isError: true, content: [{ type: "text", text: "Unavailable" }] } });
  })));
  assert.deepEqual(responses.map(response => response.headers.get("x-correlation-id")), [FIRST, SECOND]);
  for (const [index, response] of responses.entries()) {
    const body = await response.json() as any;
    assert.equal(body.result.content[1].text, `correlation_id: ${[FIRST, SECOND][index]}`);
  }
});

test("MCP diagnostics preserve OAuth challenges and repair empty HTTP failures", async t => {
  t.mock.method(console, "error", () => {});
  const refused = await correlateMcpResponse(Response.json({ jsonrpc: "2.0", id: null,
    error: { code: -32001, message: "Unauthorized" },
  }, { status: 401, headers: { "www-authenticate": 'Bearer error="invalid_token"' } }), "shared-sessions", FIRST);
  assert.equal(refused.status, 401);
  assert.equal(refused.headers.get("www-authenticate"), 'Bearer error="invalid_token"');
  const failure = await correlateMcpResponse(new Response("", { status: 503 }), "shared-sessions", FIRST);
  assert.equal(failure.status, 503);
  assert.match((await failure.json() as any).error.message, /HTTP 503/);
  assert.equal(failure.headers.get("x-correlation-id"), FIRST);
});
