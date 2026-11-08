// analytics lane: adapters against real HTTP(S) servers on 127.0.0.1.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer, request as httpsRequest } from "node:https";
import { join } from "node:path";
import test from "node:test";
import { loadAnalyticsConfig } from "../src/analytics/config.js";
import { projectEvent } from "../src/analytics/events.js";
import { createAnalyticsSink } from "../src/analytics/lifecycle.js";
import { parseRetryAfter } from "../src/analytics/retry.js";
import { classifyCollectorStatus, createCollectorSink } from "../src/analytics/sinks/collector.js";
import { createPosthogSink } from "../src/analytics/sinks/posthog.js";
import type { AnalyticsEnvelope } from "../src/analytics/types.js";
import { close, listen } from "./support/harness.js";

const TOKEN = "collector-producer-token-0001";
const TLS_DIR = join(import.meta.dirname, "fixtures/analytics-tls");
const TLS = {
  key: readFileSync(join(TLS_DIR, "throwaway-test-only.key")),
  cert: readFileSync(join(TLS_DIR, "throwaway-test-only.crt")),
};
/** Chains to TLS.cert (the trusted CA) but names only wrong-name.invalid, never 127.0.0.1 or localhost. */
const WRONG_NAME_TLS = {
  key: readFileSync(join(TLS_DIR, "throwaway-wrong-name.key")),
  cert: readFileSync(join(TLS_DIR, "throwaway-wrong-name.crt")),
};

type Received = { method?: string; url?: string; headers: IncomingMessage["headers"]; rawHeaders: string[]; body: string };

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

function recorder(respond: (response: ServerResponse) => void) {
  const received: Received[] = [];
  const handler = async (request: IncomingMessage, response: ServerResponse) => {
    received.push({
      method: request.method,
      url: request.url,
      headers: request.headers,
      rawHeaders: request.rawHeaders,
      body: await readBody(request),
    });
    respond(response);
  };
  return { received, handler };
}

function envelope(properties: Record<string, unknown> = {}): AnalyticsEnvelope {
  return projectEvent(
    { event: "service_started", properties: properties as never },
    { deploymentId: "dep_test_000001", traceId: "trace_test_0001", now: () => Date.parse("2026-11-08T12:00:00Z") },
  );
}

function signal(): AbortSignal {
  return new AbortController().signal;
}

test("collector receives POST /v1/events with one bearer header, the batch schema, and every envelope field", async () => {
  const { received, handler } = recorder((response) => response.writeHead(204).end());
  const server = createServer(handler);
  const url = await listen(server);
  try {
    // The configured URL is the complete endpoint; the sink appends nothing.
    const sink = createCollectorSink({ url: `${url}/v1/events`, token: TOKEN });
    const event = envelope({ component_version: "1.2.3", config_fingerprint: "abc123", secret_url: "https://x" });
    assert.deepEqual(await sink.send([event], signal()), { outcome: "accepted" });
    assert.equal(received.length, 1);
    const [request] = received;
    assert.equal(request!.method, "POST");
    assert.equal(request!.url, "/v1/events");
    assert.equal(request!.headers["content-type"], "application/json");
    assert.equal(request!.headers.authorization, `Bearer ${TOKEN}`);
    const authorizations = request!.rawHeaders.filter((_, index) => index % 2 === 0 && request!.rawHeaders[index]!.toLowerCase() === "authorization");
    assert.equal(authorizations.length, 1);
    const body = JSON.parse(request!.body);
    assert.deepEqual(Object.keys(body).sort(), ["events", "schema"]);
    assert.equal(body.schema, "agent-relay.analytics.batch/v1");
    assert.equal(body.events.length, 1);
    const wire = body.events[0];
    assert.deepEqual(Object.keys(wire).sort(), [
      "component", "deployment_id", "event", "event_id", "occurred_at", "properties", "trace_id", "version",
    ]);
    assert.equal(wire.version, 1);
    assert.match(wire.event_id, /^[0-9a-f-]{36}$/);
    assert.equal(wire.event_id, event.event_id);
    assert.equal(wire.occurred_at, "2026-11-08T12:00:00.000Z");
    assert.equal(wire.component, "relaycontrol");
    assert.equal(wire.deployment_id, "dep_test_000001");
    assert.equal(wire.event, "service_started");
    assert.equal(wire.trace_id, "trace_test_0001");
    assert.deepEqual(wire.properties, { component_version: "1.2.3", config_fingerprint: "abc123" });
    assert.doesNotMatch(request!.body, /secret_url|https:\/\/x/);
  } finally {
    await close(server);
  }
});

test("collector posts to the configured URL as-is and appends nothing", async () => {
  const { received, handler } = recorder((response) => response.writeHead(204).end());
  const server = createServer(handler);
  const url = await listen(server);
  try {
    const sink = createCollectorSink({ url: `${url}/ingest/v1/events`, token: TOKEN });
    assert.deepEqual(await sink.send([envelope()], signal()), { outcome: "accepted" });
    assert.deepEqual(received.map((request) => request.url), ["/ingest/v1/events"]);
  } finally {
    await close(server);
  }
});

test("collector treats 200 and 202 as protocol errors, never success", async () => {
  for (const status of [200, 202, 206]) {
    const server = createServer((_, response) => response.writeHead(status).end("{}"));
    const url = await listen(server);
    try {
      const result = await createCollectorSink({ url: `${url}/v1/events`, token: TOKEN }).send([envelope()], signal());
      assert.deepEqual(result, { outcome: "protocol", status });
    } finally {
      await close(server);
    }
  }
});

test("collector never follows a redirect or forwards the credential", async () => {
  const target = recorder((response) => response.writeHead(204).end());
  const targetServer = createServer(target.handler);
  const targetUrl = await listen(targetServer);
  const server = createServer((_, response) => {
    response.writeHead(302, { location: `${targetUrl}/v1/events` }).end();
  });
  const url = await listen(server);
  try {
    const result = await createCollectorSink({ url: `${url}/v1/events`, token: TOKEN }).send([envelope()], signal());
    assert.deepEqual(result, { outcome: "redirect", status: 302 });
    assert.equal(target.received.length, 0);
  } finally {
    await close(server);
    await close(targetServer);
  }
});

test("collector maps the contract's status table", async () => {
  const cases: Array<[number, Record<string, string>, unknown]> = [
    [400, {}, { outcome: "rejected", status: 400 }],
    [404, {}, { outcome: "rejected", status: 404 }],
    [422, {}, { outcome: "rejected", status: 422 }],
    [401, { "www-authenticate": "Bearer" }, { outcome: "auth", status: 401 }],
    [403, {}, { outcome: "auth", status: 403 }],
    [413, {}, { outcome: "oversize", status: 413 }],
    [408, {}, { outcome: "retry", reason: "timeout", status: 408 }],
    [429, { "retry-after": "2" }, { outcome: "retry", reason: "backpressure", status: 429, retryAfterMs: 2000 }],
    [503, { "retry-after": "120" }, { outcome: "retry", reason: "backpressure", status: 503, retryAfterMs: 30_000 }],
    [507, {}, { outcome: "retry", reason: "storage", status: 507, retryAfterMs: undefined }],
    [500, {}, { outcome: "retry", reason: "server", status: 500 }],
    [502, {}, { outcome: "retry", reason: "server", status: 502 }],
  ];
  let next = cases[0]!;
  const server = createServer((_, response) => response.writeHead(next[0], next[1]).end('{"error":"code"}'));
  const url = await listen(server);
  try {
    const sink = createCollectorSink({ url: `${url}/v1/events`, token: TOKEN });
    for (const entry of cases) {
      next = entry;
      assert.deepEqual(await sink.send([envelope()], signal()), entry[2], String(entry[0]));
    }
  } finally {
    await close(server);
  }
  assert.deepEqual(classifyCollectorStatus(301, null), { outcome: "redirect", status: 301 });
});

test("Retry-After accepts only unsigned decimal delta-seconds, capped at 30 s", async () => {
  assert.equal(parseRetryAfter("2"), 2000);
  assert.equal(parseRetryAfter(" 7 "), 7000);
  // Zero is a valid delay (the queue still counts the attempt).
  assert.equal(parseRetryAfter("0"), 0);
  // Oversized values are capped, including ones beyond Number precision.
  assert.equal(parseRetryAfter("31"), 30_000);
  assert.equal(parseRetryAfter("99999999999999999999999"), 30_000);
  // Malformed: ignored, so the queue uses its local backoff.
  for (const malformed of ["-1", "+5", "1.5", "1e2", "0x10", "soon", "5 s", "", null, undefined]) {
    assert.equal(parseRetryAfter(malformed), undefined, String(malformed));
  }
  // HTTP-date: ignored as well.
  assert.equal(parseRetryAfter("Sun, 08 Nov 2026 00:00:10 GMT"), undefined);
  assert.equal(parseRetryAfter(new Date(Date.now() + 10_000).toUTCString()), undefined);

  const server = createServer((_, response) => response.writeHead(503, { "retry-after": "Sun, 08 Nov 2026 00:00:10 GMT" }).end());
  const url = await listen(server);
  try {
    assert.deepEqual(
      await createCollectorSink({ url: `${url}/v1/events`, token: TOKEN }).send([envelope()], signal()),
      { outcome: "retry", reason: "backpressure", status: 503, retryAfterMs: undefined },
    );
  } finally {
    await close(server);
  }
});

test("collector connection loss and abort are retryable transport outcomes", async () => {
  const server = createServer();
  const url = await listen(server);
  await close(server);
  assert.deepEqual(
    await createCollectorSink({ url: `${url}/v1/events`, token: TOKEN }).send([envelope()], signal()),
    { outcome: "retry", reason: "transport" },
  );
  const hanging = createServer(() => undefined);
  const hangingUrl = await listen(hanging);
  try {
    const controller = new AbortController();
    const pending = createCollectorSink({ url: `${hangingUrl}/v1/events`, token: TOKEN }).send([envelope()], controller.signal);
    setTimeout(() => controller.abort(), 20);
    assert.deepEqual(await pending, { outcome: "retry", reason: "timeout" });
  } finally {
    await close(hanging);
  }
});

test("collector verifies TLS against the configured CA bundle and never disables verification", async () => {
  // Every send is bounded so no case can stall the suite.
  const bounded = () => AbortSignal.timeout(5000);
  const { received, handler } = recorder((response) => response.writeHead(204).end());
  const server = createHttpsServer(TLS, handler);
  const url = `${(await listen(server as never)).replace("http://", "https://")}/v1/events`;
  try {
    const config = loadAnalyticsConfig({
      SELFHOST_ANALYTICS_DESTINATION: "collector",
      SELFHOST_ANALYTICS_COLLECTOR_URL: url,
      SELFHOST_ANALYTICS_COLLECTOR_TOKEN: TOKEN,
      SELFHOST_ANALYTICS_COLLECTOR_CA_FILE: join(TLS_DIR, "throwaway-test-only.crt"),
      SELFHOST_ANALYTICS_DEPLOYMENT_ID: "dep_test_000001",
    });
    assert.deepEqual(await createAnalyticsSink(config).send([envelope()], bounded()), { outcome: "accepted" });
    assert.equal(received.length, 1);
    assert.equal(received[0]!.headers.authorization, `Bearer ${TOKEN}`);

    // Without the bundle the self-signed certificate is refused before any request.
    const untrusted = createCollectorSink({ url, token: TOKEN });
    assert.deepEqual(await untrusted.send([envelope()], bounded()), { outcome: "retry", reason: "transport" });
    assert.equal(received.length, 1);
  } finally {
    await close(server as never);
  }
});

test("collector keeps hostname verification on: a trusted certificate for another name is refused during the TLS handshake", async () => {
  const bounded = () => AbortSignal.timeout(5000);
  const { received, handler } = recorder((response) => response.writeHead(204).end());
  const server = createHttpsServer(WRONG_NAME_TLS, handler);
  // TLS evidence without secrets: only the key-log label is read, never the line itself.
  // SERVER_TRAFFIC_SECRET_0 means the server sent its certificate and Finished.
  let serverFlights = 0;
  let completed = 0;
  const aborted: Array<string | undefined> = [];
  server.on("keylog", (line: Buffer) => {
    if (line.subarray(0, 24).toString("latin1") === "SERVER_TRAFFIC_SECRET_0 ") serverFlights += 1;
  });
  server.on("secureConnection", () => { completed += 1; });
  server.on("tlsClientError", (error: NodeJS.ErrnoException) => { aborted.push(error.code); });
  const waitForAborts = async (count: number) => {
    const deadline = Date.now() + 5000;
    while (aborted.length < count && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 10));
  };
  // Dialled at 127.0.0.1, which the certificate deliberately does not name.
  const url = `${(await listen(server as never)).replace("http://", "https://")}/v1/events`;
  assert.match(url, /^https:\/\/127\.0\.0\.1:\d+\/v1\/events$/);
  try {
    // The chain is trusted, so the only failure left is the name.
    const code = await new Promise<string | undefined>((resolve) => {
      const probe = httpsRequest(url, { method: "POST", ca: TLS.cert, agent: false, signal: bounded() }, (response) => {
        response.resume();
        resolve(`unexpected HTTP ${response.statusCode}`);
      });
      probe.on("error", (error: NodeJS.ErrnoException) => resolve(error.code));
      probe.end();
    });
    assert.equal(code, "ERR_TLS_CERT_ALTNAME_INVALID");
    await waitForAborts(1);
    assert.equal(serverFlights, 1);

    const sink = createCollectorSink({ url, token: TOKEN, ca: TLS.cert.toString() });
    assert.deepEqual(await sink.send([envelope()], bounded()), { outcome: "retry", reason: "transport" });
    await waitForAborts(2);
    // The sink's connection also reached the server's certificate flight, then the client
    // abandoned the handshake: no session completed and no HTTP request was ever sent.
    assert.equal(serverFlights, 2);
    assert.equal(aborted.length, 2);
    assert.equal(completed, 0);
    assert.equal(received.length, 0);
  } finally {
    await close(server as never);
  }
});

test("posthog receives /batch/ with api_key, uuid = event_id, distinct_id = deployment_id", async () => {
  const { received, handler } = recorder((response) => response.writeHead(200, { "content-type": "application/json" }).end('{"status":1}'));
  const server = createServer(handler);
  const host = await listen(server);
  try {
    const sink = createPosthogSink({ host, projectKey: "phc_test_project_key" });
    const event = envelope({ component_version: "1.2.3", unlisted: "dropped" });
    // PostHog's own contract: any 2xx is success (the collector's 204 rule does not apply).
    assert.deepEqual(await sink.send([event], signal()), { outcome: "accepted" });
    const [request] = received;
    assert.equal(request!.url, "/batch/");
    assert.equal(request!.headers.authorization, undefined);
    const body = JSON.parse(request!.body);
    assert.equal(body.api_key, "phc_test_project_key");
    assert.equal(body.batch.length, 1);
    const [item] = body.batch;
    assert.equal(item.event, "service_started");
    assert.equal(item.uuid, event.event_id);
    assert.equal(item.timestamp, event.occurred_at);
    assert.equal(item.distinct_id, "dep_test_000001");
    assert.deepEqual(item.properties, {
      component_version: "1.2.3",
      component: "relaycontrol",
      trace_id: "trace_test_0001",
      $process_person_profile: false,
    });
  } finally {
    await close(server);
  }
  const redirecting = createServer((_, response) => response.writeHead(307, { location: "http://127.0.0.1:1/batch/" }).end());
  const redirectHost = await listen(redirecting);
  try {
    assert.deepEqual(
      await createPosthogSink({ host: redirectHost, projectKey: "k" }).send([envelope()], signal()),
      { outcome: "redirect", status: 307 },
    );
  } finally {
    await close(redirecting);
  }
});

test("sink factory selects only the configured destination", () => {
  assert.equal(createAnalyticsSink(loadAnalyticsConfig({})).name, "none");
  assert.equal(createAnalyticsSink(loadAnalyticsConfig({
    SELFHOST_ANALYTICS_DESTINATION: "posthog",
    SELFHOST_ANALYTICS_POSTHOG_HOST: "https://posthog.customer.example",
    SELFHOST_ANALYTICS_POSTHOG_PROJECT_KEY: "phc_test_project_key",
    SELFHOST_ANALYTICS_DEPLOYMENT_ID: "dep_test_000001",
  })).name, "posthog");
});
