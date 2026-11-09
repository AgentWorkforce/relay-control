import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  configFingerprint,
  loadConfig,
  loadDatabaseUrl,
  loadMigrationsDatabaseUrl,
  loadRuntimeDatabaseRole,
} from "../src/config.js";

const completeEnv = {
  DATABASE_URL: "postgres://control:secret@postgres/control",
  SELFHOST_PUBLIC_URL: "https://control.internal.example",
  RELAYCAST_URL: "http://relaycast.relay.svc.cluster.local",
  RELAYCAST_PUBLIC_URL: "https://relaycast.selfhosted.company",
  RELAYAUTH_URL: "http://relayauth.auth.svc.cluster.local",
  RELAYHISTORY_URL: "http://relayhistory.history.svc.cluster.local",
  RELAYHISTORY_PUBLIC_URL: "https://history.selfhosted.company",
  RELAYAUTH_API_KEY: "rak_test",
  SELFHOST_BOOTSTRAP_TOKEN: "b".repeat(32),
  SELFHOST_ENCRYPTION_KEY_ID: "test-key",
  SELFHOST_ENCRYPTION_KEY: "00".repeat(32),
};

test("session search @name parsing is default off and strictly boolean", () => {
  assert.equal(loadConfig(completeEnv).sessionSearchAgentTokens, false);
  assert.equal(loadConfig({ ...completeEnv, SESSION_SEARCH_AGENT_TOKENS: "true" }).sessionSearchAgentTokens, true);
  assert.throws(() => loadConfig({ ...completeEnv, SESSION_SEARCH_AGENT_TOKENS: "1" }), /SESSION_SEARCH_AGENT_TOKENS/);
});

test("the session erase API is default off and requires its full configuration", () => {
  assert.equal(loadConfig(completeEnv).sessionErasureApi, null);
  const eraser = {
    SESSION_ERASE_API_URL: "http://eraser.sessions.svc.cluster.local:8080",
    SESSION_ERASE_API_SECRET: "control-eraser-secret-".repeat(2),
  };
  assert.deepEqual(loadConfig({ ...completeEnv, ...eraser }).sessionErasureApi, {
    url: eraser.SESSION_ERASE_API_URL,
    secret: eraser.SESSION_ERASE_API_SECRET,
  });
  assert.throws(() => loadConfig({ ...completeEnv, SESSION_ERASE_API_URL: eraser.SESSION_ERASE_API_URL }), /SESSION_ERASE_API_SECRET/);
  assert.throws(() => loadConfig({ ...completeEnv, SESSION_ERASE_API_SECRET: eraser.SESSION_ERASE_API_SECRET }), /SESSION_ERASE_API_URL/);
  assert.throws(() => loadConfig({ ...completeEnv, ...eraser, SESSION_ERASE_API_SECRET: "short" }), /at least 32 bytes/);
});

test("the independent read API handoff is default off and requires its full configuration", () => {
  assert.equal(loadConfig(completeEnv).sessionReadApi, null);
  const reader = {
    SESSION_READ_API_URL: "http://reader.sessions.svc.cluster.local:8080",
    SESSION_READ_API_PUBLIC_URL: "https://sessions.selfhosted.company/",
    SESSION_READ_API_SECRET: "reader-control-secret-".repeat(2),
  };
  const config = loadConfig({ ...completeEnv, ...reader });
  assert.deepEqual(config.sessionReadApi, {
    url: reader.SESSION_READ_API_URL,
    publicUrl: "https://sessions.selfhosted.company",
    secret: reader.SESSION_READ_API_SECRET,
  });
  for (const key of Object.keys(reader)) {
    const partial = { ...reader };
    delete partial[key as keyof typeof partial];
    assert.throws(() => loadConfig({ ...completeEnv, ...partial }), /SESSION_READ_API_/);
  }
  assert.throws(() => loadConfig({ ...completeEnv, ...reader, SESSION_READ_API_SECRET: "short" }), /SECRET/);
  assert.throws(() => loadConfig({ ...completeEnv, ...reader, SESSION_READ_API_PUBLIC_URL: "http://reader.internal" }), /PUBLIC_URL/);
  assert.notEqual(configFingerprint(config), configFingerprint(loadConfig(completeEnv)));
  assert.equal(configFingerprint(config), configFingerprint({
    ...config, sessionReadApi: { ...config.sessionReadApi!, secret: "different-secret" },
  }), "fingerprint does not include credentials");
});

test("the read API handoff supports a mounted secret without accepting both secret forms", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "session-read-config-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const secretPath = join(directory, "secret");
  writeFileSync(secretPath, "reader-control-secret-".repeat(2), { mode: 0o600 });
  const env = {
    ...completeEnv,
    SESSION_READ_API_URL: "http://reader.sessions.svc.cluster.local:8080",
    SESSION_READ_API_PUBLIC_URL: "https://sessions.selfhosted.company",
    SESSION_READ_API_SECRET_FILE: secretPath,
  };
  assert.equal(loadConfig(env).sessionReadApi?.secret, "reader-control-secret-".repeat(2));
  assert.throws(() => loadConfig({ ...env, SESSION_READ_API_SECRET: "another-secret" }), /mutually exclusive/);
});

test("configuration has no hosted service defaults", () => {
  for (const required of [
    "SELFHOST_PUBLIC_URL",
    "RELAYCAST_URL",
    "RELAYCAST_PUBLIC_URL",
    "RELAYHISTORY_URL",
    "RELAYHISTORY_PUBLIC_URL",
  ]) {
    const env = { ...completeEnv };
    delete env[required as keyof typeof env];
    assert.throws(() => loadConfig(env), new RegExp(`${required} is required`));
  }

  const config = loadConfig(completeEnv);
  const serialized = JSON.stringify(config);
  assert.doesNotMatch(serialized, /agentrelay\.com|relaycast\.dev/i);
  assert.equal(config.relaycastUrl, completeEnv.RELAYCAST_URL);
  assert.equal(config.relaycastPublicUrl, completeEnv.RELAYCAST_PUBLIC_URL);
  assert.equal(config.relayhistoryUrl, completeEnv.RELAYHISTORY_URL);
  assert.equal(config.relayhistoryPublicUrl, completeEnv.RELAYHISTORY_PUBLIC_URL);
});

test("public client origins require bare HTTPS public DNS hosts", () => {
  assert.throws(
    () => loadConfig({
      ...completeEnv,
      RELAYCAST_PUBLIC_URL: "http://relaycast.selfhosted.company",
    }),
    /RELAYCAST_PUBLIC_URL must use https/,
  );
  for (const invalid of [
    "http://relaycast.selfhosted.company",
    "https://localhost",
    "https://relayhistory",
    "https://127.0.0.1",
    "https://[::1]",
    "https://history.svc.cluster.local",
    "https://history.internal",
    "https://history.office.lan",
    "https://history.example.com",
    "https://history.selfhosted.company.",
    "https://user:pass@history.selfhosted.company",
    "https://history.selfhosted.company/v1",
    "https://history.selfhosted.company?",
    "https://history.selfhosted.company#",
    "https://history.selfhosted.company?tenant=one",
    "https://history.selfhosted.company#fragment",
  ]) {
    assert.throws(
      () => loadConfig({ ...completeEnv, RELAYHISTORY_PUBLIC_URL: invalid }),
      /RELAYHISTORY_PUBLIC_URL/,
      invalid,
    );
  }
});

test("configuration fingerprint covers internal and public service origins", () => {
  const config = loadConfig(completeEnv);
  for (const [property, replacement] of [
    ["relaycastUrl", "http://relaycast.other.svc.cluster.local"],
    ["relaycastPublicUrl", "https://relaycast.other-company.com"],
    ["relayhistoryUrl", "http://relayhistory.other.svc.cluster.local"],
    ["relayhistoryPublicUrl", "https://history.other-company.com"],
  ] as const) {
    assert.notEqual(
      configFingerprint({ ...config, [property]: replacement }),
      configFingerprint(config),
      property,
    );
  }
});

test("RelayAuth is optional but both of its variables travel together", () => {
  const { RELAYAUTH_URL: _url, RELAYAUTH_API_KEY: _key, ...withoutRelayauth } = completeEnv;
  const config = loadConfig(withoutRelayauth);
  assert.equal(config.relayauthUrl, null);
  assert.equal(config.relayauthApiKey, null);
  assert.match(configFingerprint(config), /^[0-9a-f]{12}$/);
  assert.notEqual(configFingerprint(config), configFingerprint(loadConfig(completeEnv)));

  const withRelayauth = loadConfig(completeEnv);
  assert.equal(withRelayauth.relayauthUrl, completeEnv.RELAYAUTH_URL);
  assert.equal(withRelayauth.relayauthApiKey, completeEnv.RELAYAUTH_API_KEY);

  for (const only of [
    { ...withoutRelayauth, RELAYAUTH_URL: completeEnv.RELAYAUTH_URL },
    { ...withoutRelayauth, RELAYAUTH_API_KEY: completeEnv.RELAYAUTH_API_KEY },
  ]) {
    assert.throws(() => loadConfig(only), /RELAYAUTH_URL and RELAYAUTH_API_KEY must be set together/);
  }
  assert.throws(
    () => loadConfig({ ...completeEnv, RELAYAUTH_URL: "http://relayauth.svc/v1" }),
    /RELAYAUTH_URL must be an origin/,
  );
});

test("token introspection is off by default and validates its secret and audiences", () => {
  const config = loadConfig(completeEnv);
  assert.equal(config.introspectSecret, null);
  assert.deepEqual(config.introspectAudiences, [completeEnv.RELAYHISTORY_PUBLIC_URL]);

  const secret = "i".repeat(32);
  const enabled = loadConfig({
    ...completeEnv,
    RELAYCONTROL_INTROSPECT_SECRET: secret,
    SELFHOST_INTROSPECT_AUDIENCES: " https://history.selfhosted.company/ , http://relayfile.files.svc:8080 ",
  });
  assert.equal(enabled.introspectSecret, secret);
  assert.deepEqual(enabled.introspectAudiences, [
    "https://history.selfhosted.company",
    "http://relayfile.files.svc:8080",
  ]);
  assert.doesNotMatch(configFingerprint(enabled), new RegExp(secret));

  assert.throws(
    () => loadConfig({ ...completeEnv, RELAYCONTROL_INTROSPECT_SECRET: "short" }),
    /RELAYCONTROL_INTROSPECT_SECRET must be at least 32 bytes/,
  );
  for (const invalid of ["history", "ftp://history.example", "https://history.example/v1", "https://u:p@h.example", ","]) {
    assert.throws(
      () => loadConfig({ ...completeEnv, SELFHOST_INTROSPECT_AUDIENCES: invalid }),
      /SELFHOST_INTROSPECT_AUDIENCES/,
      invalid,
    );
  }
});

test("secret files and direct values cannot be combined", () => {
  assert.throws(
    () => loadConfig({
      ...completeEnv,
      DATABASE_URL_FILE: "/run/secrets/database-url",
    }),
    /mutually exclusive/,
  );
});

test("runtime and migration database credentials are separate file contracts", () => {
  const directory = mkdtempSync(join(tmpdir(), "selfhost-db-"));
  try {
    const runtime = join(directory, "runtime");
    const migrations = join(directory, "migrations");
    writeFileSync(runtime, "postgres://runtime:secret@postgres/control\n");
    writeFileSync(migrations, "postgres://owner:secret@postgres/control\n");
    assert.equal(
      loadDatabaseUrl({ DATABASE_URL_FILE: runtime }),
      "postgres://runtime:secret@postgres/control",
    );
    assert.equal(
      loadMigrationsDatabaseUrl({ DATABASE_MIGRATIONS_URL_FILE: migrations }),
      "postgres://owner:secret@postgres/control",
    );
    assert.throws(
      () => loadMigrationsDatabaseUrl({ DATABASE_URL_FILE: runtime }),
      /DATABASE_MIGRATIONS_URL is required/,
    );
    assert.throws(
      () => loadDatabaseUrl({ DATABASE_MIGRATIONS_URL_FILE: migrations }),
      /DATABASE_URL is required/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("runtime database role is explicit and cannot name the PUBLIC pseudo-role", () => {
  assert.equal(
    loadRuntimeDatabaseRole({ SELFHOST_RUNTIME_DATABASE_ROLE: "selfhost_runtime" }),
    "selfhost_runtime",
  );
  for (const role of [undefined, "", "PUBLIC", "public", "runtime-role", "a".repeat(64)]) {
    assert.throws(
      () => loadRuntimeDatabaseRole({ SELFHOST_RUNTIME_DATABASE_ROLE: role }),
      /SELFHOST_RUNTIME_DATABASE_ROLE/,
    );
  }
});


test("direct read Worker is dormant by default and requires introspection plus its explicit audience", () => {
  assert.equal(loadConfig(completeEnv).relayhistoryReadApiUrl, null);
  const reader = "https://session-reader.selfhosted.company";
  const env = { ...completeEnv, RELAYHISTORY_READ_API_URL: reader, RELAYCONTROL_INTROSPECT_SECRET: "i".repeat(32), SELFHOST_INTROSPECT_AUDIENCES: `${completeEnv.RELAYHISTORY_PUBLIC_URL},${reader}` };
  const configured = loadConfig(env);
  assert.equal(configured.relayhistoryReadApiUrl, reader);
  assert.equal(configured.relayhistoryUrl, completeEnv.RELAYHISTORY_URL);
  assert.throws(() => loadConfig({ ...env, RELAYCONTROL_INTROSPECT_SECRET: "" }), /RELAYHISTORY_READ_API_URL requires RELAYCONTROL_INTROSPECT_SECRET/);
  assert.throws(() => loadConfig({ ...env, SELFHOST_INTROSPECT_AUDIENCES: completeEnv.RELAYHISTORY_PUBLIC_URL }), /SELFHOST_INTROSPECT_AUDIENCES must include RELAYHISTORY_READ_API_URL/);
  for (const url of ["http://session-reader.selfhosted.company", "https://localhost", `${reader}/v1`, `${reader}?token=secret`, "https://user:secret@session-reader.selfhosted.company"]) {
    assert.throws(() => loadConfig({ ...env, RELAYHISTORY_READ_API_URL: url }), /RELAYHISTORY_READ_API_URL must/);
  }
  assert.notEqual(configFingerprint(configured), configFingerprint(loadConfig(completeEnv)));
});

test("native session-event reads are default-off and require the direct reader connection", () => {
  const reader = "https://session-reader.selfhosted.company";
  const env = { ...completeEnv, RELAYHISTORY_READ_API_URL: reader, RELAYCONTROL_INTROSPECT_SECRET: "i".repeat(32), SELFHOST_INTROSPECT_AUDIENCES: `${completeEnv.RELAYHISTORY_PUBLIC_URL},${reader}` };
  assert.equal(loadConfig(completeEnv).relayhistoryReadApiEvents, false);
  assert.equal(loadConfig(env).relayhistoryReadApiEvents, false);
  assert.equal(loadConfig({ ...env, RELAYHISTORY_READ_API_EVENTS: "false" }).relayhistoryReadApiEvents, false);
  const enabled = loadConfig({ ...env, RELAYHISTORY_READ_API_EVENTS: "true" });
  assert.equal(enabled.relayhistoryReadApiEvents, true);
  assert.notEqual(configFingerprint(enabled), configFingerprint(loadConfig(env)));
  assert.throws(() => loadConfig({ ...completeEnv, RELAYHISTORY_READ_API_EVENTS: "true" }), /requires RELAYHISTORY_READ_API_URL/);
  for (const invalid of ["1", "yes", "TRUE"]) {
    assert.throws(() => loadConfig({ ...env, RELAYHISTORY_READ_API_EVENTS: invalid }), /must be true or false/);
  }
});

test("the Flows broker secret is optional and must be long enough", () => {
  assert.equal(loadConfig(completeEnv).relayfileControlBrokerSecret, null);
  const secret = "s".repeat(32);
  assert.equal(loadConfig({ ...completeEnv, RELAYFILE_CONTROL_BROKER_SECRET: secret }).relayfileControlBrokerSecret, secret);
  assert.throws(() => loadConfig({ ...completeEnv, RELAYFILE_CONTROL_BROKER_SECRET: "short" }), /at least 32 bytes/);
});


test("native event search is a separate default-off connection with a strict switch", () => {
  const reader = "https://session-reader.selfhosted.company";
  const env = { ...completeEnv, RELAYHISTORY_READ_API_URL: reader, RELAYCONTROL_INTROSPECT_SECRET: "i".repeat(32), SELFHOST_INTROSPECT_AUDIENCES: `${completeEnv.RELAYHISTORY_PUBLIC_URL},${reader}` };
  assert.equal(loadConfig(completeEnv).relayhistoryReadApiSearch, false);
  assert.equal(loadConfig(env).relayhistoryReadApiSearch, false);
  assert.equal(loadConfig({ ...env, RELAYHISTORY_READ_API_EVENTS: "true" }).relayhistoryReadApiSearch, false);
  assert.equal(loadConfig({ ...env, RELAYHISTORY_READ_API_SEARCH: "false" }).relayhistoryReadApiSearch, false);
  const enabled = loadConfig({ ...env, RELAYHISTORY_READ_API_SEARCH: "true" });
  assert.equal(enabled.relayhistoryReadApiSearch, true);
  assert.equal(enabled.relayhistoryReadApiEvents, false);
  assert.notEqual(configFingerprint(enabled), configFingerprint(loadConfig(env)));
  assert.throws(() => loadConfig({ ...completeEnv, RELAYHISTORY_READ_API_SEARCH: "true" }), /requires RELAYHISTORY_READ_API_URL/);
  for (const invalid of ["1", "yes", "TRUE"]) assert.throws(() => loadConfig({ ...env, RELAYHISTORY_READ_API_SEARCH: invalid }), /must be true or false/);
});
