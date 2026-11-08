import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  configFingerprint,
  loadConfig,
  loadAllowedDatabaseSchemas,
  loadDatabaseSchema,
  loadDatabaseSchemaCutover,
  loadDatabaseUrl,
  loadMigrationsDatabaseUrl,
  loadRuntimeDatabaseRole,
  loadServerRuntimeDatabaseRole,
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

test("database schema defaults to public and accepts lower-case identifiers", () => {
  assert.equal(loadDatabaseSchema({}), "public");
  assert.equal(loadDatabaseSchema({ SELFHOST_DATABASE_SCHEMA: "  " }), "public");
  assert.equal(loadConfig(completeEnv).databaseSchema, "public");
  assert.equal(
    loadConfig({
      ...completeEnv,
      SELFHOST_DATABASE_SCHEMA: "relaycontrol",
      SELFHOST_RUNTIME_DATABASE_ROLE: "control_api_runtime",
    }).databaseSchema,
    "relaycontrol",
  );
  assert.equal(loadDatabaseSchema({ SELFHOST_DATABASE_SCHEMA: "_rc_2" }), "_rc_2");
  assert.equal(loadDatabaseSchema({ SELFHOST_DATABASE_SCHEMA: "a".repeat(63) }), "a".repeat(63));
});

test("the server requires its runtime role outside public and validates it", () => {
  // Legacy single-role install in public: unset keeps the old behaviour.
  assert.equal(loadConfig(completeEnv).runtimeDatabaseRole, null);
  assert.equal(loadServerRuntimeDatabaseRole({}), null);
  assert.equal(
    loadConfig({ ...completeEnv, SELFHOST_RUNTIME_DATABASE_ROLE: " control_api_runtime " })
      .runtimeDatabaseRole,
    "control_api_runtime",
  );
  assert.equal(
    loadConfig({
      ...completeEnv,
      SELFHOST_DATABASE_SCHEMA: "relaycontrol",
      SELFHOST_RUNTIME_DATABASE_ROLE: "control_api_runtime",
    }).runtimeDatabaseRole,
    "control_api_runtime",
  );
  for (const role of [undefined, "", "  "]) {
    assert.throws(
      () => loadConfig({
        ...completeEnv,
        SELFHOST_DATABASE_SCHEMA: "relaycontrol",
        SELFHOST_RUNTIME_DATABASE_ROLE: role,
      }),
      /^Error: SELFHOST_RUNTIME_DATABASE_ROLE is required when SELFHOST_DATABASE_SCHEMA is "relaycontrol"/,
    );
  }
  for (const role of ["PUBLIC", "runtime-role", "a".repeat(64)]) {
    for (const schema of ["public", "relaycontrol"]) {
      assert.throws(
        () => loadConfig({
          ...completeEnv,
          SELFHOST_DATABASE_SCHEMA: schema,
          SELFHOST_RUNTIME_DATABASE_ROLE: role,
        }),
        /SELFHOST_RUNTIME_DATABASE_ROLE must be a valid non-PUBLIC PostgreSQL role name/,
      );
    }
  }
});

test("database schema rejects system schemas and non-identifiers", () => {
  for (const value of [
    "pg_catalog",
    "information_schema",
    "pg_foo",
    "Relaycontrol",
    "relay-control",
    "1relay",
    "relay control",
    'relay"; DROP SCHEMA public; --',
    "a".repeat(64),
  ]) {
    assert.throws(
      () => loadDatabaseSchema({ SELFHOST_DATABASE_SCHEMA: value }),
      /SELFHOST_DATABASE_SCHEMA must/,
      value,
    );
    assert.throws(
      () => loadConfig({ ...completeEnv, SELFHOST_DATABASE_SCHEMA: value }),
      /SELFHOST_DATABASE_SCHEMA must/,
      value,
    );
  }
});

test("allowed extension schemas are a validated, de-duplicated comma list", () => {
  assert.deepEqual(loadAllowedDatabaseSchemas({}), []);
  assert.deepEqual(loadAllowedDatabaseSchemas({ SELFHOST_DATABASE_ALLOWED_SCHEMAS: " , " }), []);
  assert.deepEqual(
    loadAllowedDatabaseSchemas({ SELFHOST_DATABASE_ALLOWED_SCHEMAS: " extensions, postgis ,extensions," }),
    ["extensions", "postgis"],
  );
  for (const value of ["pg_catalog", "information_schema", "Ext", "ext-1", "ok,pg_toast"]) {
    assert.throws(
      () => loadAllowedDatabaseSchemas({ SELFHOST_DATABASE_ALLOWED_SCHEMAS: value }),
      /SELFHOST_DATABASE_ALLOWED_SCHEMAS entry/,
      value,
    );
  }
});

test("schema cutover is unset or fresh", () => {
  assert.equal(loadDatabaseSchemaCutover({}), undefined);
  assert.equal(loadDatabaseSchemaCutover({ SELFHOST_DATABASE_SCHEMA_CUTOVER: " " }), undefined);
  assert.equal(loadDatabaseSchemaCutover({ SELFHOST_DATABASE_SCHEMA_CUTOVER: "fresh" }), "fresh");
  for (const value of ["FRESH", "move", "true"]) {
    assert.throws(
      () => loadDatabaseSchemaCutover({ SELFHOST_DATABASE_SCHEMA_CUTOVER: value }),
      /SELFHOST_DATABASE_SCHEMA_CUTOVER must be unset or "fresh"/,
    );
  }
});
