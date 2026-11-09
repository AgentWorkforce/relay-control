import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { describeAnalyticsConfig, loadAnalyticsConfig } from "../src/analytics/config.js";
import { ANALYTICS_BATCH_OVERHEAD_BYTES, ANALYTICS_BATCH_SCHEMA } from "../src/analytics/types.js";

const TOKEN = "collector-producer-token-0001";
const collectorEnv = {
  SELFHOST_ANALYTICS_DESTINATION: "collector",
  SELFHOST_ANALYTICS_COLLECTOR_URL: "https://analytics-collector.relay.svc.cluster.local/v1/events",
  SELFHOST_ANALYTICS_COLLECTOR_TOKEN: TOKEN,
  SELFHOST_ANALYTICS_DEPLOYMENT_ID: "dep_test_000001",
};
const posthogEnv = {
  SELFHOST_ANALYTICS_DESTINATION: "posthog",
  SELFHOST_ANALYTICS_POSTHOG_HOST: "https://posthog.customer.example",
  SELFHOST_ANALYTICS_POSTHOG_PROJECT_KEY: "phc_test_project_key",
  SELFHOST_ANALYTICS_DEPLOYMENT_ID: "dep_test_000001",
};

test("analytics defaults to none and rejects unknown destinations", () => {
  const config = loadAnalyticsConfig({});
  assert.equal(config.destination, "none");
  assert.equal(config.deploymentId, null);
  assert.equal(config.collector, null);
  assert.equal(config.posthog, null);
  assert.equal(config.maxEventBytes, 4096);
  assert.equal(config.maxBatchEvents, 50);
  assert.equal(config.maxBatchBytes, 262_144);
  assert.equal(config.queueMaxEvents, 1000);
  assert.equal(config.queueMaxBytes, 1_048_576);
  assert.equal(config.requestTimeoutMs, 5000);
  assert.equal(config.maxAttempts, 4);
  assert.equal(config.flushIntervalMs, 5000);
  assert.equal(config.shutdownDeadlineMs, 3000);
  assert.deepEqual(config.gateway, { maxBodyBytes: 32_768, maxEvents: 20 });
  assert.throws(
    () => loadAnalyticsConfig({ SELFHOST_ANALYTICS_DESTINATION: "file" }),
    /DESTINATION must be none, collector, or posthog/,
  );
});

test("collector requires URL, token, and deployment id, with no installId fallback", () => {
  const config = loadAnalyticsConfig(collectorEnv);
  assert.equal(config.collector?.url, "https://analytics-collector.relay.svc.cluster.local/v1/events");
  assert.equal(config.collector?.token, TOKEN);
  assert.equal(config.deploymentId, "dep_test_000001");
  for (const name of ["SELFHOST_ANALYTICS_COLLECTOR_URL", "SELFHOST_ANALYTICS_COLLECTOR_TOKEN", "SELFHOST_ANALYTICS_DEPLOYMENT_ID"]) {
    const env: Record<string, string> = { ...collectorEnv };
    delete env[name];
    assert.throws(() => loadAnalyticsConfig(env), new RegExp(`${name}.*required`), name);
  }
  const withoutDeployment: Record<string, string> = {
    ...collectorEnv,
    SELFHOST_TELEMETRY_INSTALL_ID: "inst_testinstall01",
  };
  delete withoutDeployment.SELFHOST_ANALYTICS_DEPLOYMENT_ID;
  assert.throws(() => loadAnalyticsConfig(withoutDeployment), /DEPLOYMENT_ID is required/);
  assert.throws(
    () => loadAnalyticsConfig({ ...collectorEnv, SELFHOST_ANALYTICS_DEPLOYMENT_ID: "short" }),
    /DEPLOYMENT_ID must be/,
  );
});

test("collector token is opaque, single-sourced, and never a reused credential", () => {
  // No length minimum: the credential is opaque.
  assert.equal(loadAnalyticsConfig({ ...collectorEnv, SELFHOST_ANALYTICS_COLLECTOR_TOKEN: "t1" }).collector?.token, "t1");
  const directory = mkdtempSync(join(tmpdir(), "analytics-config-"));
  try {
    const file = join(directory, "token");
    writeFileSync(file, `${TOKEN}\n`);
    const fromFile: Record<string, string> = { ...collectorEnv, SELFHOST_ANALYTICS_COLLECTOR_TOKEN_FILE: file };
    delete fromFile.SELFHOST_ANALYTICS_COLLECTOR_TOKEN;
    assert.equal(loadAnalyticsConfig(fromFile).collector?.token, TOKEN);
    assert.throws(
      () => loadAnalyticsConfig({ ...collectorEnv, SELFHOST_ANALYTICS_COLLECTOR_TOKEN_FILE: file }),
      /mutually exclusive/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
  const malformed = "has space-in-token";
  assert.throws(
    () => loadAnalyticsConfig({ ...collectorEnv, SELFHOST_ANALYTICS_COLLECTOR_TOKEN: malformed }),
    (error: Error) => /visible ASCII/.test(error.message) && !error.message.includes(malformed),
  );
  const internal = "i".repeat(48);
  for (const [name, value, token] of [
    ["SELFHOST_INTERNAL_TOKEN", internal, internal],
    ["SELFHOST_BOOTSTRAP_TOKEN", "b".repeat(32), "b".repeat(32)],
    ["DATABASE_URL", "postgres://control:db-secret-1@postgres/control", "db-secret-1"],
    ["DATABASE_MIGRATIONS_URL", "postgres://owner:owner-secret@postgres/control", "postgres://owner:owner-secret@postgres/control"],
    ["SESSION_READ_API_SECRET", "session-read-api-secret-0001-0001", "session-read-api-secret-0001-0001"],
    ["RELAYCAST_INTERNAL_SECRET", "r".repeat(40), "r".repeat(40)],
    ["SELFHOST_ENCRYPTION_KEY", "ZW5jcnlwdGlvbi1rZXktbWF0ZXJpYWwtMzItYnl0ZXM=", "ZW5jcnlwdGlvbi1rZXktbWF0ZXJpYWwtMzItYnl0ZXM="],
    ["SELFHOST_ENCRYPTION_PREVIOUS_KEY", "cHJldmlvdXMta2V5LW1hdGVyaWFsLTMyLWJ5dGVzISE=", "cHJldmlvdXMta2V5LW1hdGVyaWFsLTMyLWJ5dGVzISE="],
    ["SELFHOST_TELEMETRY_INSTALL_KEY", "k".repeat(40), "k".repeat(40)],
    ["SELFHOST_OIDC_CLIENT_SECRET", "oidc-client-secret-test-0001", "oidc-client-secret-test-0001"],
    ["SELFHOST_SMTP_PASSWORD", "smtp-password-test-0001", "smtp-password-test-0001"],
    ["SELFHOST_OAUTH_GOOGLE_MAIL_CLIENT_SECRET", "oauth-client-secret-1", "oauth-client-secret-1"],
  ] as const) {
    assert.throws(
      () => loadAnalyticsConfig({ ...collectorEnv, [name]: value, SELFHOST_ANALYTICS_COLLECTOR_TOKEN: token }),
      (error: Error) => /dedicated analytics credential/.test(error.message) && !error.message.includes(token),
      name,
    );
  }
  // _FILE forms are read the same way the owning loader reads them.
  const secrets = mkdtempSync(join(tmpdir(), "analytics-secrets-"));
  try {
    for (const name of [
      "SELFHOST_TELEMETRY_INSTALL_KEY",
      "RELAYCAST_INTERNAL_SECRET",
      "SELFHOST_ENCRYPTION_KEY",
      "SELFHOST_OIDC_CLIENT_SECRET",
      "SELFHOST_SMTP_PASSWORD",
    ]) {
      const file = join(secrets, name);
      writeFileSync(file, "shared-secret-from-file\n");
      assert.throws(
        () => loadAnalyticsConfig({
          ...collectorEnv,
          [`${name}_FILE`]: file,
          SELFHOST_ANALYTICS_COLLECTOR_TOKEN: "shared-secret-from-file",
        }),
        (error: Error) => /dedicated analytics credential/.test(error.message)
          && !error.message.includes("shared-secret-from-file"),
        `${name}_FILE`,
      );
    }
  } finally {
    rmSync(secrets, { recursive: true, force: true });
  }
  // A distinct value alongside those secrets is accepted.
  assert.equal(
    loadAnalyticsConfig({
      ...collectorEnv,
      SELFHOST_TELEMETRY_INSTALL_KEY: "k".repeat(40),
      SELFHOST_OIDC_CLIENT_SECRET: "oidc-client-secret-test-0001",
      SELFHOST_SMTP_PASSWORD: "smtp-password-test-0001",
    }).collector?.token,
    TOKEN,
  );
});

test("the PostHog project key is never a reused credential", () => {
  const key = "phc_test_project_key";
  for (const name of [
    "SELFHOST_INTERNAL_TOKEN",
    "SELFHOST_BOOTSTRAP_TOKEN",
    "SESSION_READ_API_SECRET",
    "RELAYCAST_INTERNAL_SECRET",
    "SELFHOST_ENCRYPTION_KEY",
    "SELFHOST_TELEMETRY_INSTALL_KEY",
    "SELFHOST_OIDC_CLIENT_SECRET",
    "SELFHOST_SMTP_PASSWORD",
  ]) {
    assert.throws(
      () => loadAnalyticsConfig({ ...posthogEnv, [name]: key }),
      (error: Error) => /POSTHOG_PROJECT_KEY must be a dedicated analytics credential/.test(error.message)
        && !error.message.includes(key),
      name,
    );
  }
  // _FILE forms of the identity secrets are read the same way the identity loader reads them.
  const secrets = mkdtempSync(join(tmpdir(), "analytics-secrets-"));
  try {
    for (const name of ["SELFHOST_OIDC_CLIENT_SECRET", "SELFHOST_SMTP_PASSWORD"]) {
      const file = join(secrets, name);
      writeFileSync(file, `${key}\n`);
      assert.throws(
        () => loadAnalyticsConfig({ ...posthogEnv, [`${name}_FILE`]: file }),
        (error: Error) => /POSTHOG_PROJECT_KEY must be a dedicated analytics credential/.test(error.message)
          && !error.message.includes(key),
        `${name}_FILE`,
      );
    }
  } finally {
    rmSync(secrets, { recursive: true, force: true });
  }
  assert.equal(
    loadAnalyticsConfig({
      ...posthogEnv,
      SELFHOST_TELEMETRY_INSTALL_KEY: "k".repeat(40),
      SELFHOST_OIDC_CLIENT_SECRET: "oidc-client-secret-test-0001",
      SELFHOST_SMTP_PASSWORD: "smtp-password-test-0001",
    }).posthog?.projectKey,
    key,
  );
});

test("collector transport is verified https; http only in the development profile for cluster-local hosts", () => {
  for (const url of [
    "http://analytics-collector.relay.svc.cluster.local/v1/events",
    "http://127.0.0.1:8080/v1/events",
    "http://collector.example.com/v1/events",
  ]) {
    assert.throws(
      () => loadAnalyticsConfig({ ...collectorEnv, SELFHOST_ANALYTICS_COLLECTOR_URL: url }),
      /must use https unless SELFHOST_ANALYTICS_PROFILE is development/,
      url,
    );
  }
  const development = { ...collectorEnv, SELFHOST_ANALYTICS_PROFILE: "development" };
  for (const url of [
    "http://analytics-collector.relay.svc/v1/events",
    "http://analytics-collector.relay.svc.cluster.local:8080/v1/events",
    "http://127.0.0.1:8080/v1/events",
    "http://localhost:8080/v1/events",
    "http://[::1]:8080/v1/events",
  ]) {
    assert.equal(loadAnalyticsConfig({ ...development, SELFHOST_ANALYTICS_COLLECTOR_URL: url }).collector?.url, url);
  }
  for (const url of [
    "http://collector.example.com/v1/events",
    "http://10.0.0.5/v1/events",
    "http://svc.cluster.local/v1/events",
    "http://collector/v1/events",
  ]) {
    assert.throws(
      () => loadAnalyticsConfig({ ...development, SELFHOST_ANALYTICS_COLLECTOR_URL: url }),
      /http only for loopback/,
      url,
    );
  }
  assert.throws(
    () => loadAnalyticsConfig({ ...collectorEnv, SELFHOST_ANALYTICS_COLLECTOR_URL: "ftp://collector.relay.svc/v1/events" }),
    /COLLECTOR_URL must use https/,
  );
  assert.throws(
    () => loadAnalyticsConfig({ ...collectorEnv, SELFHOST_ANALYTICS_PROFILE: "insecure" }),
    /PROFILE must be production or development/,
  );
});

test("collector URL is the complete endpoint: absolute, with a path, no credentials, query or fragment", () => {
  for (const url of [
    "https://analytics-collector.relay.svc.cluster.local/v1/events",
    "https://collector.customer.example:8443/analytics/v1/events",
  ]) {
    const config = loadAnalyticsConfig({ ...collectorEnv, SELFHOST_ANALYTICS_COLLECTOR_URL: url });
    // Used as-is: nothing is appended or stripped.
    assert.equal(config.collector?.url, url);
    assert.equal(describeAnalyticsConfig(config).collectorUrl, url);
  }
  for (const [url, message] of [
    ["https://collector.relay.svc", /complete endpoint URL including its path/],
    ["https://collector.relay.svc/", /complete endpoint URL including its path/],
    ["/v1/events", /must be an absolute URL/],
    ["collector.relay.svc/v1/events", /must be an absolute URL/],
    ["https://user:pass@collector.relay.svc/v1/events", /credentials, a query, or a fragment/],
    ["https://user@collector.relay.svc/v1/events", /credentials, a query, or a fragment/],
    ["https://collector.relay.svc/v1/events?x=1", /credentials, a query, or a fragment/],
    ["https://collector.relay.svc/v1/events?", /credentials, a query, or a fragment/],
    ["https://collector.relay.svc/v1/events#f", /credentials, a query, or a fragment/],
    ["https://collector.relay.svc/v1/events#", /credentials, a query, or a fragment/],
  ] as const) {
    assert.throws(
      () => loadAnalyticsConfig({ ...collectorEnv, SELFHOST_ANALYTICS_COLLECTOR_URL: url }),
      (error: Error) => /SELFHOST_ANALYTICS_COLLECTOR_URL/.test(error.message) && message.test(error.message)
        && !error.message.includes("pass"),
      url,
    );
  }
});

test("delivery deadline is bounded and at least the request timeout", () => {
  assert.equal(loadAnalyticsConfig({}).deliveryDeadlineMs, 60_000);
  assert.equal(describeAnalyticsConfig(loadAnalyticsConfig(collectorEnv)).deliveryDeadlineMs, 60_000);
  assert.equal(loadAnalyticsConfig({ SELFHOST_ANALYTICS_DELIVERY_DEADLINE_MS: "600000" }).deliveryDeadlineMs, 600_000);
  assert.equal(
    loadAnalyticsConfig({
      SELFHOST_ANALYTICS_DELIVERY_DEADLINE_MS: "5000",
      SELFHOST_ANALYTICS_REQUEST_TIMEOUT_MS: "5000",
    }).deliveryDeadlineMs,
    5000,
  );
  assert.throws(
    () => loadAnalyticsConfig({
      SELFHOST_ANALYTICS_DELIVERY_DEADLINE_MS: "4999",
      SELFHOST_ANALYTICS_REQUEST_TIMEOUT_MS: "5000",
    }),
    /DELIVERY_DEADLINE_MS must be at least SELFHOST_ANALYTICS_REQUEST_TIMEOUT_MS/,
  );
  assert.throws(
    () => loadAnalyticsConfig({ SELFHOST_ANALYTICS_DELIVERY_DEADLINE_MS: "1000" }),
    /DELIVERY_DEADLINE_MS must be at least/,
  );
});

test("collector CA bundle is read from a file and requires https", () => {
  const ca = join(import.meta.dirname, "fixtures/analytics-tls/throwaway-test-only.crt");
  const config = loadAnalyticsConfig({ ...collectorEnv, SELFHOST_ANALYTICS_COLLECTOR_CA_FILE: ca });
  assert.equal(config.collector?.ca, readFileSync(ca, "utf8"));
  assert.throws(
    () => loadAnalyticsConfig({
      ...collectorEnv,
      SELFHOST_ANALYTICS_PROFILE: "development",
      SELFHOST_ANALYTICS_COLLECTOR_URL: "http://127.0.0.1:8080/v1/events",
      SELFHOST_ANALYTICS_COLLECTOR_CA_FILE: ca,
    }),
    /requires an https/,
  );
  const directory = mkdtempSync(join(tmpdir(), "analytics-ca-"));
  try {
    const bogus = join(directory, "ca.pem");
    writeFileSync(bogus, "not a certificate\n");
    assert.throws(
      () => loadAnalyticsConfig({ ...collectorEnv, SELFHOST_ANALYTICS_COLLECTOR_CA_FILE: bogus }),
      /PEM certificates/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("posthog is explicit-only and destinations never share settings", () => {
  const config = loadAnalyticsConfig(posthogEnv);
  assert.equal(config.posthog?.host, "https://posthog.customer.example");
  for (const name of ["SELFHOST_ANALYTICS_POSTHOG_HOST", "SELFHOST_ANALYTICS_POSTHOG_PROJECT_KEY", "SELFHOST_ANALYTICS_DEPLOYMENT_ID"]) {
    const env: Record<string, string> = { ...posthogEnv };
    delete env[name];
    assert.throws(() => loadAnalyticsConfig(env), new RegExp(`${name}.*required`), name);
  }
  assert.throws(
    () => loadAnalyticsConfig({ ...posthogEnv, SELFHOST_ANALYTICS_POSTHOG_HOST: "http://posthog.customer.example" }),
    /POSTHOG_HOST must use https/,
  );
  for (const destination of ["none", "collector"]) {
    const base = destination === "collector" ? collectorEnv : {};
    for (const stray of ["SELFHOST_ANALYTICS_POSTHOG_HOST", "SELFHOST_ANALYTICS_POSTHOG_PROJECT_KEY", "SELFHOST_ANALYTICS_POSTHOG_PROJECT_KEY_FILE"]) {
      assert.throws(
        () => loadAnalyticsConfig({ ...base, SELFHOST_ANALYTICS_DESTINATION: destination, [stray]: "x" }),
        new RegExp(`${stray} must not be set unless SELFHOST_ANALYTICS_DESTINATION is posthog`),
      );
    }
  }
  for (const destination of ["none", "posthog"]) {
    const base = destination === "posthog" ? posthogEnv : {};
    for (const stray of ["SELFHOST_ANALYTICS_COLLECTOR_URL", "SELFHOST_ANALYTICS_COLLECTOR_TOKEN", "SELFHOST_ANALYTICS_COLLECTOR_CA_FILE"]) {
      assert.throws(
        () => loadAnalyticsConfig({ ...base, SELFHOST_ANALYTICS_DESTINATION: destination, [stray]: "x" }),
        new RegExp(`${stray} must not be set unless SELFHOST_ANALYTICS_DESTINATION is collector`),
      );
    }
  }
});

test("no hosted analytics default appears in config or source", () => {
  for (const env of [{}, collectorEnv, posthogEnv]) {
    assert.doesNotMatch(JSON.stringify(loadAnalyticsConfig(env)), /agentrelay\.com|posthog\.com/i);
  }
  const root = join(import.meta.dirname, "../src/analytics");
  const files = readdirSync(root, { recursive: true, encoding: "utf8" }).filter((file) => file.endsWith(".ts"));
  assert.ok(files.length >= 8);
  for (const file of files) {
    assert.doesNotMatch(readFileSync(join(root, file), "utf8"), /i\.agentrelay\.com|posthog\.com/i, file);
  }
});

test("limits are bounded and ordered", () => {
  for (const [name, bad] of [
    ["MAX_EVENT_BYTES", "511"],
    ["MAX_EVENT_BYTES", "32769"],
    ["MAX_BATCH_EVENTS", "0"],
    ["MAX_BATCH_EVENTS", "501"],
    ["MAX_BATCH_BYTES", "4095"],
    ["QUEUE_MAX_EVENTS", "9"],
    ["QUEUE_MAX_BYTES", "16777217"],
    ["REQUEST_TIMEOUT_MS", "499"],
    ["MAX_ATTEMPTS", "11"],
    ["FLUSH_INTERVAL_MS", "60001"],
    ["SHUTDOWN_DEADLINE_MS", "8001"],
    ["SHUTDOWN_DEADLINE_MS", "1.5"],
    ["DELIVERY_DEADLINE_MS", "999"],
    ["DELIVERY_DEADLINE_MS", "600001"],
    ["DELIVERY_DEADLINE_MS", "6e4"],
    // Decimal digits only: forms Number() would accept are refused.
    ["MAX_BATCH_EVENTS", "0x10"],
    ["MAX_BATCH_EVENTS", "1e2"],
    ["MAX_ATTEMPTS", "+3"],
    ["FLUSH_INTERVAL_MS", "5000.0"],
    ["REQUEST_TIMEOUT_MS", "0b1111101000"],
    ["GATEWAY_MAX_BODY_BYTES", "1023"],
    ["GATEWAY_MAX_BODY_BYTES", "262145"],
    ["GATEWAY_MAX_BODY_BYTES", "32k"],
    ["GATEWAY_MAX_EVENTS", "0"],
    ["GATEWAY_MAX_EVENTS", "101"],
  ] as const) {
    assert.throws(
      () => loadAnalyticsConfig({ [`SELFHOST_ANALYTICS_${name}`]: bad }),
      new RegExp(`SELFHOST_ANALYTICS_${name} must be an integer`),
      `${name}=${bad}`,
    );
  }
  assert.equal(loadAnalyticsConfig({ SELFHOST_ANALYTICS_MAX_BATCH_EVENTS: "010" }).maxBatchEvents, 10);
  const gateway = loadAnalyticsConfig({
    SELFHOST_ANALYTICS_GATEWAY_MAX_BODY_BYTES: "4096",
    SELFHOST_ANALYTICS_GATEWAY_MAX_EVENTS: "5",
  });
  assert.deepEqual(gateway.gateway, { maxBodyBytes: 4096, maxEvents: 5 });
  assert.equal(describeAnalyticsConfig(gateway).gatewayMaxBodyBytes, 4096);
  assert.equal(describeAnalyticsConfig(gateway).gatewayMaxEvents, 5);
  assert.equal(
    ANALYTICS_BATCH_OVERHEAD_BYTES,
    Buffer.byteLength(JSON.stringify({ schema: ANALYTICS_BATCH_SCHEMA, events: [] })),
  );
  assert.throws(
    () => loadAnalyticsConfig({ SELFHOST_ANALYTICS_MAX_EVENT_BYTES: "8192", SELFHOST_ANALYTICS_MAX_BATCH_BYTES: "4096" }),
    /MAX_BATCH_BYTES must be at least SELFHOST_ANALYTICS_MAX_EVENT_BYTES \+ \d+ \(the batch envelope\)/,
  );
  // A max-size event alone plus the envelope would exceed MAX_BATCH_BYTES.
  assert.throws(
    () => loadAnalyticsConfig({ SELFHOST_ANALYTICS_MAX_EVENT_BYTES: "4096", SELFHOST_ANALYTICS_MAX_BATCH_BYTES: "4096" }),
    new RegExp(`so ${4096 + ANALYTICS_BATCH_OVERHEAD_BYTES} or more`),
  );
  assert.throws(
    () => loadAnalyticsConfig({ SELFHOST_ANALYTICS_MAX_BATCH_BYTES: "1048576", SELFHOST_ANALYTICS_QUEUE_MAX_BYTES: "65536" }),
    /must hold/,
  );
  const ok = loadAnalyticsConfig({
    SELFHOST_ANALYTICS_MAX_EVENT_BYTES: String(4096 - ANALYTICS_BATCH_OVERHEAD_BYTES),
    SELFHOST_ANALYTICS_MAX_BATCH_BYTES: "4096",
    SELFHOST_ANALYTICS_QUEUE_MAX_BYTES: "65536",
  });
  assert.equal(ok.maxBatchBytes, 4096);
  // The largest event the queue accepts, alone in a batch, fits the batch limit.
  const body = JSON.stringify({ schema: ANALYTICS_BATCH_SCHEMA, events: [{ pad: "x".repeat(ok.maxEventBytes - 10) }] });
  assert.equal(Buffer.byteLength(JSON.stringify({ pad: "x".repeat(ok.maxEventBytes - 10) })), ok.maxEventBytes);
  assert.ok(Buffer.byteLength(body) <= ok.maxBatchBytes);
});

test("describeAnalyticsConfig never exposes a token or key", () => {
  const collector = describeAnalyticsConfig(loadAnalyticsConfig(collectorEnv));
  assert.equal(collector.collectorTokenConfigured, true);
  assert.equal(collector.collectorUrl, collectorEnv.SELFHOST_ANALYTICS_COLLECTOR_URL);
  assert.doesNotMatch(JSON.stringify(collector), new RegExp(TOKEN));
  const posthog = describeAnalyticsConfig(loadAnalyticsConfig(posthogEnv));
  assert.equal(posthog.posthogKeyConfigured, true);
  assert.doesNotMatch(JSON.stringify(posthog), /phc_test_project_key/);
});
