import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import test from "node:test";
import { createRelaycastClient, RelaycastCallError } from "../src/messaging/relaycast.js";

type Client = ReturnType<typeof createRelaycastClient>;
const device = { id: "desktop-one", name: "Desktop one", kind: "desktop" as const };
const operations = [
  {
    name: "device-token mint", method: "POST", path: "/v1/agents/person/device-tokens", operation: "issue_device_token",
    invoke: (client: Client, signal?: AbortSignal) => client.issueDeviceToken("workspace-key", "person", {
      expectedAgentId: "person-id", device, ttlSeconds: 43_200,
    }, signal),
  },
  {
    name: "authenticated-agent probe", method: "GET", path: "/v1/agent", operation: "authenticated_agent",
    invoke: (client: Client, signal?: AbortSignal) => client.authenticatedAgent("device-token", signal),
  },
  {
    name: "workspace identity probe", method: "GET", path: "/v1/agents/person", operation: null,
    invoke: (client: Client, signal?: AbortSignal) => client.getAgent("workspace-key", "person", signal),
  },
] as const;

async function listen(server: Server): Promise<string> {
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert(address && typeof address === "object");
  return `http://127.0.0.1:${address.port}`;
}

async function close(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}

for (const operation of operations) {
  for (const phase of ["headers", "body"] as const) {
    test(`${operation.name}: abort cancels a real HTTP hang before ${phase === "headers" ? "headers" : "body completion"}`, { timeout: 5_000 }, async t => {
      let started!: () => void;
      const requestStarted = new Promise<void>(resolve => { started = resolve; });
      let disconnected!: () => void;
      const responseClosed = new Promise<void>(resolve => { disconnected = resolve; });
      const requests: Array<{ method: string | undefined; path: string | undefined; authorization: string | undefined }> = [];
      const server = createServer(async (request, response) => {
        for await (const _ of request) { /* Drain the real request; the response intentionally never finishes. */ }
        requests.push({ method: request.method, path: request.url, authorization: request.headers.authorization });
        response.once("close", disconnected);
        if (phase === "body") {
          response.writeHead(200, { "content-type": "application/json" });
          response.write('{"ok":true,"data":');
        }
        started();
      });
      const origin = await listen(server);
      t.after(() => close(server));
      let gotHeaders!: () => void;
      const headersReceived = new Promise<void>(resolve => { gotHeaders = resolve; });
      const fetchImpl: typeof fetch = async (input, init) => {
        const response = await fetch(input, init);
        gotHeaders();
        return response;
      };
      const client = createRelaycastClient({ internalOrigin: origin, fetchImpl });
      const controller = new AbortController();
      const pending = operation.invoke(client, controller.signal).then(
        () => { throw new Error("An unfinished upstream response must not succeed"); },
        (error: unknown) => error,
      );
      await requestStarted;
      if (phase === "body") await headersReceived;
      controller.abort(new DOMException("Caller deadline expired", "TimeoutError"));
      const error = await pending;
      assert(error instanceof RelaycastCallError);
      assert.equal(error.status, phase === "headers" ? 0 : 200);
      assert.equal(error.body, "");
      assert.equal(error.code, null);
      assert.equal(error.outcomeUnknown, true);
      assert.equal(error.operation, operation.operation);
      await responseClosed;
      assert.deepEqual(requests, [{ method: operation.method, path: operation.path,
        authorization: `Bearer ${operation.name === "authenticated-agent probe" ? "device-token" : "workspace-key"}` }]);
    });
  }
}

test("credential calls without a signal retain their successful HTTP contracts", async t => {
  const bodies: unknown[] = [];
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const raw = Buffer.concat(chunks).toString("utf8");
    if (raw) bodies.push(JSON.parse(raw));
    const data = request.method === "POST"
      ? { token: "issued-token", agent_id: "person-id", device, expires_at: "2026-11-26T00:00:00.000Z" }
      : { id: "person-id", name: "person", metadata: {}, channels: [] };
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true, data }));
  });
  const client = createRelaycastClient({ internalOrigin: await listen(server) });
  t.after(() => close(server));
  assert.deepEqual(await operations[0]!.invoke(client), {
    token: "issued-token", agentId: "person-id", device, expiresAt: "2026-11-26T00:00:00.000Z",
  });
  assert.equal((await operations[1]!.invoke(client))?.id, "person-id");
  assert.deepEqual(await operations[2]!.invoke(client), { id: "person-id", name: "person", metadata: {} });
  assert.deepEqual(bodies, [{ agent_id: "person-id", device, ttl_seconds: 43_200 }]);
});
