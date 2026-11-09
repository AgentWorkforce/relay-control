import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage } from "node:http";
import test, { type TestContext } from "node:test";
import { handleChiefRelay } from "../src/chief-relay.js";
import { loadConfig } from "../src/config.js";
import { close, listen, request } from "./support/harness.js";

const secret = "chief-relay-secret-at-least-32-bytes-long";
const chiefId = `chief-${"a".repeat(24)}`;
const workspaceId = randomUUID();

async function readBody(incoming: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of incoming) chunks.push(Buffer.from(chunk));
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

const RELAY_WORKSPACE = "245411583121604608";

async function setup(t: TestContext, options: { secret?: string | null; chief?: boolean; existing?: unknown; fail?: boolean; self?: unknown } = {}) {
  const calls: unknown[][] = [];
  const server = createServer((incoming, response) => {
    void handleChiefRelay(incoming, response, incoming.method ?? "GET", new URL(incoming.url!, "http://x").pathname, {
      secret: options.secret === undefined ? secret : options.secret,
      relaycast: {
        getAgent: async (...args) => {
          calls.push(["get", ...args]);
          if (options.fail) throw new Error("leaked-relaycast-detail");
          return (options.existing ?? null) as never;
        },
        registerHosted: async (...args) => { calls.push(["register", ...args]); return { id: "agent-new", name: chiefId, token: "token-new" }; },
        recoverHosted: async (...args) => { calls.push(["recover", ...args]); return { id: "agent-old", name: chiefId, token: "token-rotated" }; },
        authenticatedAgent: async (token) => {
          calls.push(["self", token]);
          return (options.self ?? { id: token === "token-new" ? "agent-new" : "agent-old", workspaceId: RELAY_WORKSPACE }) as never;
        },
      },
      relaycastBinding: async (id) => (id === workspaceId ? { relaycastWorkspaceId: workspaceId, relaycastApiKey: "workspace-key" } : null),
      requireChief: () => { if (options.chief === false) throw Object.assign(new Error("off"), { off: true }); },
      bearer: (r) => /^Bearer (.+)$/.exec(r.headers.authorization ?? "")?.[1] ?? null,
      requestObject: readBody,
      json: (r, status, body) => { r.writeHead(status, { "content-type": "application/json" }); r.end(JSON.stringify(body)); },
    }).then((handled) => { if (!handled) { response.writeHead(404); response.end("{}"); } })
      .catch(() => { response.writeHead(403); response.end("{}"); });
  });
  const origin = await listen(server);
  t.after(() => close(server));
  const post = (body: unknown = { chiefId }, token: string | undefined = secret, workspace: string = workspaceId) =>
    request(origin, `/internal/v1/chief/workspaces/${workspace}/relay-agents`, { method: "POST", ...(token ? { token } : {}), body });
  return { calls, post, origin };
}

test("the route does not exist without its secret", async (t) => {
  const env = await setup(t, { secret: null });
  assert.equal((await env.post()).status, 404);
  assert.deepEqual(env.calls, []);
});

test("only the secret reaches Relaycast, and only with chief selected", async (t) => {
  const env = await setup(t);
  assert.equal((await env.post({ chiefId }, "wrong")).status, 401);
  assert.equal((await env.post({ chiefId }, "")).status, 401);
  assert.deepEqual(env.calls, []);
  const off = await setup(t, { chief: false });
  assert.equal((await off.post()).status, 403);
  assert.deepEqual(off.calls, []);
});

test("a new chief is registered and never receives the workspace key", async (t) => {
  const env = await setup(t);
  const answer = await env.post();
  assert.equal(answer.status, 200, answer.raw);
  assert.deepEqual(answer.body, { agentId: "agent-new", agentName: chiefId, token: "token-new", relayWorkspaceId: RELAY_WORKSPACE });
  assert.equal(answer.raw.includes("workspace-key"), false);
  assert.equal((env.calls[1]![3] as { chief_id: string }).chief_id, chiefId);
});

test("a repeat call reissues the token of the chief's own agent", async (t) => {
  const env = await setup(t, { existing: { id: "agent-old", name: chiefId, metadata: { chief_id: chiefId } } });
  const answer = await env.post();
  assert.equal(answer.body.token, "token-rotated");
  assert.deepEqual(env.calls[1], ["recover", "workspace-key", chiefId, "agent-old", `chief:${chiefId}`]);
});

test("a Relay answer that cannot prove the workspace gives no credential", async (t) => {
  for (const self of [{ id: "agent-new", workspaceId: null }, { id: "someone-else", workspaceId: RELAY_WORKSPACE }]) {
    const env = await setup(t, { self });
    const answer = await env.post();
    assert.equal(answer.status, 502);
    assert.equal(answer.raw.includes("token-new"), false);
  }
});

test("an agent registered for anything else is refused, not taken over", async (t) => {
  const env = await setup(t, { existing: { id: "agent-other", name: chiefId, metadata: {} } });
  const answer = await env.post();
  assert.equal(answer.status, 409);
  assert.equal(answer.body.error, "relay_agent_conflict");
  assert.equal(env.calls.length, 1);
});

test("malformed requests and unknown workspaces stop before Relaycast", async (t) => {
  const env = await setup(t);
  assert.equal((await env.post({ chiefId: "not-a-chief" })).status, 400);
  assert.equal((await env.post({ chiefId, name: "override" })).status, 400);
  assert.equal((await env.post({ chiefId }, secret, "not-a-uuid")).status, 400);
  assert.equal((await env.post({ chiefId }, secret, randomUUID())).status, 404);
  assert.deepEqual(env.calls, []);
});

test("Relaycast failures carry no detail", async (t) => {
  const env = await setup(t, { fail: true });
  const answer = await env.post();
  assert.equal(answer.status, 502);
  assert.equal(answer.raw.includes("leaked-relaycast-detail"), false);
});

test("the secret is optional, long enough, and distinct from the broker secret", () => {
  const complete = {
    DATABASE_URL: "postgres://control:secret@postgres/control",
    SELFHOST_PUBLIC_URL: "https://control.internal.example",
    RELAYCAST_URL: "http://relaycast.relay.svc.cluster.local",
    RELAYCAST_PUBLIC_URL: "https://relaycast.selfhosted.company",
    RELAYHISTORY_BACKEND: "native",
    SESSION_READ_API_URL: "http://session-read.history.svc.cluster.local",
    SESSION_READ_API_PUBLIC_URL: "https://sessions.selfhosted.company",
    SESSION_READ_API_SECRET: "r".repeat(32),
    RELAYCONTROL_INTROSPECT_SECRET: "i".repeat(32),
    SELFHOST_BOOTSTRAP_TOKEN: "b".repeat(32),
    SELFHOST_ENCRYPTION_KEY_ID: "test-key",
    SELFHOST_ENCRYPTION_KEY: "00".repeat(32),
  };
  assert.equal(loadConfig(complete).chiefRelaySecret, null);
  assert.equal(loadConfig({ ...complete, RELAYCHIEF_CONTROL_RELAY_SECRET: secret }).chiefRelaySecret, secret);
  assert.throws(() => loadConfig({ ...complete, RELAYCHIEF_CONTROL_RELAY_SECRET: "short" }), /at least 32 bytes/);
  assert.throws(() => loadConfig({ ...complete, RELAYCHIEF_CONTROL_RELAY_SECRET: secret, RELAYFILE_CONTROL_BROKER_SECRET: secret }), /must differ/);
});
