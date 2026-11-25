import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  configFingerprint,
  loadConfig,
  loadDatabaseUrl,
  loadDefaultSharingMode,
  loadMigrationsDatabaseUrl,
  loadRuntimeDatabaseRole,
  loadSharingModeOverrideRoles,
} from "../src/config.js";

const completeEnv = {
  DATABASE_URL: "postgres://control:secret@postgres/control",
  SELFHOST_PUBLIC_URL: "https://control.internal.example",
  RELAYCAST_URL: "http://relaycast.relay.svc.cluster.local",
  RELAYCAST_PUBLIC_URL: "https://relaycast.selfhosted.company",
  SESSION_READ_API_URL: "http://reader.sessions.svc.cluster.local:8080",
  SESSION_READ_API_PUBLIC_URL: "https://history.selfhosted.company",
  SESSION_READ_API_SECRET: "reader-control-secret-".repeat(2),
  RELAYCONTROL_INTROSPECT_SECRET: "i".repeat(32),
  SELFHOST_BOOTSTRAP_TOKEN: "b".repeat(32),
  SELFHOST_ENCRYPTION_KEY_ID: "test-key",
  SELFHOST_ENCRYPTION_KEY: "00".repeat(32),
};

test("Cloud's dashboard workspace selector leaves both Control MCP reader modes unchanged", () => {
  for (const mode of ["true", "false"]) {
    const env = { ...completeEnv, SESSION_READ_API_MCP_READS: mode };
    const baseline = loadConfig(env);
    const selected = loadConfig({
      ...env,
      SESSIONS_READ_96BULLS_DASHBOARD_RECORDED_WORKSPACE: "11111111-2222-4333-8444-555555555555",
    });
    assert.equal(selected.sessionReadMcpReads, mode === "true");
    assert.deepEqual(selected.sessionReadApi, baseline.sessionReadApi);
    assert.equal(selected.relayhistoryUrl, baseline.relayhistoryUrl);
  }
});

test("customer support uses an optional complete dedicated service connection, never a customer allowlist", () => {
  assert.equal(loadConfig(completeEnv).customerSupport, null);
  const support = { SELFHOST_CUSTOMER_SUPPORT_URL: "https://support.example.test/", SELFHOST_CUSTOMER_SUPPORT_TOKEN: "s".repeat(32) };
  assert.deepEqual(loadConfig({ ...completeEnv, ...support }).customerSupport, { url: "https://support.example.test", token: "s".repeat(32) });
  assert.throws(() => loadConfig({ ...completeEnv, SELFHOST_CUSTOMER_SUPPORT_URL: support.SELFHOST_CUSTOMER_SUPPORT_URL }), /required together/);
  assert.throws(() => loadConfig({ ...completeEnv, ...support, SELFHOST_CUSTOMER_SUPPORT_TOKEN: "short" }), /at least 32/);
  assert.throws(() => loadConfig({ ...completeEnv, ...support, SELFHOST_CUSTOMER_SUPPORT_TOKEN: completeEnv.SELFHOST_BOOTSTRAP_TOKEN }), /dedicated/);
  assert.throws(() => loadConfig({ ...completeEnv, ...support, SELFHOST_CUSTOMER_SUPPORT_URL: "https://user:secret@support.test/path" }), /origin/);
  assert.throws(() => loadConfig({ ...completeEnv, ...support, SELFHOST_CUSTOMER_SUPPORT_URL: "http://support.remote.test" }), /HTTPS/);
  assert.equal(loadConfig({ ...completeEnv, ...support, SELFHOST_CUSTOMER_SUPPORT_URL: "http://127.0.0.1:3000" }).customerSupport?.url, "http://127.0.0.1:3000");
});

test("SELFHOST_RELAYGATE_PUBLIC_URL is optional and must be a public https origin", () => {
  assert.equal(loadConfig(completeEnv).relaygatePublicUrl, null);
  // reader_kind goes into the read-token mint body only behind relaygate.
  assert.equal(loadConfig(completeEnv).sessionReadApi.mintReaderKind, false);
  assert.equal(loadConfig({ ...completeEnv, SELFHOST_RELAYGATE_PUBLIC_URL: "https://cast.selfhosted.company" })
    .sessionReadApi.mintReaderKind, true);
  assert.equal(loadConfig({ ...completeEnv, SELFHOST_RELAYGATE_PUBLIC_URL: "  " }).relaygatePublicUrl, null);
  assert.equal(loadConfig({ ...completeEnv, SELFHOST_RELAYGATE_PUBLIC_URL: " https://cast.selfhosted.company/ " }).relaygatePublicUrl,
    "https://cast.selfhosted.company");
  for (const bad of ["http://cast.selfhosted.company", "https://cast.selfhosted.company/v1", "https://u:p@cast.selfhosted.company",
    "https://localhost", "https://10.0.0.1", "not a url"]) {
    assert.throws(() => loadConfig({ ...completeEnv, SELFHOST_RELAYGATE_PUBLIC_URL: bad }), /SELFHOST_RELAYGATE_PUBLIC_URL/, bad);
  }
});

test("SELFHOST_ROUTED_SITE_URL is optional and must be an https origin", () => {
  assert.equal(loadConfig(completeEnv).routedSiteOrigin, null);
  assert.equal(loadConfig({ ...completeEnv, SELFHOST_ROUTED_SITE_URL: "  " }).routedSiteOrigin, null);
  assert.equal(loadConfig({ ...completeEnv, SELFHOST_ROUTED_SITE_URL: "https://site.example.test" }).routedSiteOrigin,
    "https://site.example.test");
  assert.equal(loadConfig({ ...completeEnv, SELFHOST_ROUTED_SITE_URL: " https://Site.Example.Test/ " }).routedSiteOrigin,
    "https://site.example.test");
  for (const bad of ["http://site.example.test", "https://site.example.test/cloud", "https://site.example.test/?a=1",
    "https://site.example.test/#top", "https://u:p@site.example.test", "not a url"]) {
    assert.throws(() => loadConfig({ ...completeEnv, SELFHOST_ROUTED_SITE_URL: bad }),
      /SELFHOST_ROUTED_SITE_URL must be an https origin without credentials, path, query, or fragment/, bad);
  }
});

test("SELFHOST_EXTRA_SITES is optional and parses dashboard|API origin pairs", () => {
  const extra = (value: string) => loadConfig({ ...completeEnv, SELFHOST_EXTRA_SITES: value }).extraSites;
  assert.deepEqual(loadConfig(completeEnv).extraSites, []);
  assert.deepEqual(extra("  "), []);
  assert.deepEqual(extra("https://app.second.example.com|https://api.second.example.com"),
    [{ dashboardOrigin: "https://app.second.example.com", apiOrigin: "https://api.second.example.com" }]);
  assert.deepEqual(extra(" https://App.Second.Example.com/ | https://api.second.example.com ,\n https://app.third.example.com|https://api.third.example.com/ "), [
    { dashboardOrigin: "https://app.second.example.com", apiOrigin: "https://api.second.example.com" },
    { dashboardOrigin: "https://app.third.example.com", apiOrigin: "https://api.third.example.com" },
  ]);
  // A single-host site: both sides one origin, as the primary site allows.
  assert.deepEqual(extra("https://one.second.example.com|https://one.second.example.com"),
    [{ dashboardOrigin: "https://one.second.example.com", apiOrigin: "https://one.second.example.com" }]);
  assert.equal(extra(Array.from({ length: 8 }, (_, i) => `https://app${i}.example.com|https://api${i}.example.com`).join(","))?.length, 8);
});

test("SELFHOST_EXTRA_SITES rejects malformed entries without echoing them", () => {
  const load = (value: string, env: Record<string, string> = {}) =>
    () => loadConfig({ ...completeEnv, ...env, SELFHOST_EXTRA_SITES: value });
  const api = "https://api.second.example.com";
  for (const bad of ["http://app.second.example.com", "https://app.second.example.com/dashboard",
    "https://app.second.example.com/?a=1", "https://app.second.example.com/#top", "https://user:secret@app.second.example.com",
    "not a url"]) {
    assert.throws(load(`${bad}|${api}`),
      /SELFHOST_EXTRA_SITES entry 1 must name https origins without credentials, path, query, or fragment/, bad);
    assert.throws(load(`${api}|${bad}`), /SELFHOST_EXTRA_SITES entry 1 must name https origins/, bad);
    assert.throws(load(`${bad}|${api}`), (error: Error) => !error.message.includes("secret") && !error.message.includes("second"), bad);
  }
  assert.throws(load("https://app.second.example.com"), /SELFHOST_EXTRA_SITES entry 1 must be <dashboard origin>\|<API origin>/);
  assert.throws(load(`https://app.second.example.com|${api}|https://other.example.com`),
    /SELFHOST_EXTRA_SITES entry 1 must be <dashboard origin>\|<API origin>/);
  assert.throws(load(Array.from({ length: 9 }, (_, i) => `https://app${i}.example.com|https://api${i}.example.com`).join(",")),
    /SELFHOST_EXTRA_SITES allows at most 8 sites/);

  // A host belongs to one site only.
  const clash = /SELFHOST_EXTRA_SITES entry \d reuses host .*, which already belongs to another site/;
  assert.throws(load(`https://control.internal.example|${api}`), clash, "public URL host");
  assert.throws(load(`https://app.second.example.com|${api}`, { SELFHOST_DASHBOARD_URL: "https://app.second.example.com/dashboard/" }),
    clash, "dashboard URL host");
  assert.throws(load(`https://app.second.example.com|https://site.example.test`, { SELFHOST_ROUTED_SITE_URL: "https://site.example.test" }),
    clash, "routed site host");
  assert.throws(load(`https://app.second.example.com|${api}, https://app.third.example.com|${api}`),
    /SELFHOST_EXTRA_SITES entry 2 reuses host api\.second\.example\.com/, "another entry");
});

test("SELFHOST_DEFAULT_SHARING_MODE is optional and one of all, new or selected", () => {
  const unset = loadConfig(completeEnv);
  assert.equal(unset.defaultSharingMode, undefined);
  assert.equal(Object.hasOwn(unset, "defaultSharingMode"), false, "unset adds no key");
  for (const empty of ["", "   "]) {
    assert.equal(Object.hasOwn(loadConfig({ ...completeEnv, SELFHOST_DEFAULT_SHARING_MODE: empty }), "defaultSharingMode"), false);
    assert.equal(loadDefaultSharingMode({ SELFHOST_DEFAULT_SHARING_MODE: empty }), undefined);
  }
  for (const mode of ["all", "new", "selected"] as const) {
    assert.equal(loadConfig({ ...completeEnv, SELFHOST_DEFAULT_SHARING_MODE: mode }).defaultSharingMode, mode);
    assert.equal(loadDefaultSharingMode({ SELFHOST_DEFAULT_SHARING_MODE: ` ${mode} ` }), mode);
  }
  for (const bad of ["ALL", "none", "selected,all", "off"]) {
    assert.throws(() => loadConfig({ ...completeEnv, SELFHOST_DEFAULT_SHARING_MODE: bad }),
      /SELFHOST_DEFAULT_SHARING_MODE must be all, new or selected/, bad);
  }
});

test("SELFHOST_SHARING_MODE_OVERRIDE_ROLES is optional and lists only owner and admin", () => {
  const unset = loadConfig(completeEnv);
  assert.equal(Object.hasOwn(unset, "sharingModeOverrideRoles"), false, "unset adds no key");
  for (const empty of ["", "  ", ",", " , "]) {
    assert.equal(loadSharingModeOverrideRoles({ SELFHOST_SHARING_MODE_OVERRIDE_ROLES: empty }), undefined, empty);
  }
  assert.deepEqual(loadConfig({ ...completeEnv, SELFHOST_SHARING_MODE_OVERRIDE_ROLES: "owner" }).sharingModeOverrideRoles, ["owner"]);
  assert.deepEqual(loadSharingModeOverrideRoles({ SELFHOST_SHARING_MODE_OVERRIDE_ROLES: " owner , admin " }), ["owner", "admin"]);
  assert.deepEqual(loadSharingModeOverrideRoles({ SELFHOST_SHARING_MODE_OVERRIDE_ROLES: "admin,owner,admin,owner" }), ["admin", "owner"]);
  for (const bad of ["member", "owner,member", "Owner", "owner;admin", "root"]) {
    assert.throws(() => loadConfig({ ...completeEnv, SELFHOST_SHARING_MODE_OVERRIDE_ROLES: bad }),
      /SELFHOST_SHARING_MODE_OVERRIDE_ROLES must list only owner and\/or admin/, bad);
  }
});

test("SELFHOST_RELAY_NODE_SELF_MINT defaults on and is strictly boolean", () => {
  assert.equal(loadConfig(completeEnv).relayNodeSelfMint, true);
  for (const on of ["", "  ", "true", "1", "on", "TRUE"]) {
    assert.equal(loadConfig({ ...completeEnv, SELFHOST_RELAY_NODE_SELF_MINT: on }).relayNodeSelfMint, true, on);
  }
  for (const off of ["false", "0", "off", " Off "]) {
    assert.equal(loadConfig({ ...completeEnv, SELFHOST_RELAY_NODE_SELF_MINT: off }).relayNodeSelfMint, false, off);
  }
  for (const bad of ["yes", "no", "disabled", "2"]) {
    assert.throws(() => loadConfig({ ...completeEnv, SELFHOST_RELAY_NODE_SELF_MINT: bad }), /SELFHOST_RELAY_NODE_SELF_MINT/, bad);
  }
});

test("SELFHOST_ENROLLMENT_SELF_RENEWAL defaults on and is strictly boolean", () => {
  assert.equal(loadConfig(completeEnv).enrollmentSelfRenewal, true);
  for (const on of ["", "  ", "true", "1", "on", "TRUE"]) {
    assert.equal(loadConfig({ ...completeEnv, SELFHOST_ENROLLMENT_SELF_RENEWAL: on }).enrollmentSelfRenewal, true, on);
  }
  for (const off of ["false", "0", "off", " Off "]) {
    assert.equal(loadConfig({ ...completeEnv, SELFHOST_ENROLLMENT_SELF_RENEWAL: off }).enrollmentSelfRenewal, false, off);
  }
  for (const bad of ["yes", "no", "disabled", "2"]) {
    assert.throws(() => loadConfig({ ...completeEnv, SELFHOST_ENROLLMENT_SELF_RENEWAL: bad }), /SELFHOST_ENROLLMENT_SELF_RENEWAL/, bad);
  }
});

test("the image version is read from SELFHOST_IMAGE_VERSION and null from source", () => {
  assert.equal(loadConfig(completeEnv).imageVersion, null);
  assert.equal(loadConfig({ ...completeEnv, SELFHOST_IMAGE_VERSION: "  " }).imageVersion, null);
  assert.equal(loadConfig({ ...completeEnv, SELFHOST_IMAGE_VERSION: " 0.5.12 " }).imageVersion, "0.5.12");
});

test("session search @name parsing is default off and strictly boolean", () => {
  assert.equal(loadConfig(completeEnv).sessionSearchAgentTokens, false);
  assert.equal(loadConfig({ ...completeEnv, SESSION_SEARCH_AGENT_TOKENS: "true" }).sessionSearchAgentTokens, true);
  assert.throws(() => loadConfig({ ...completeEnv, SESSION_SEARCH_AGENT_TOKENS: "1" }), /SESSION_SEARCH_AGENT_TOKENS/);
});

test("SESSION_READ_MINT_INCLUDE_READER_KIND overrides the relaygate default and is strictly boolean", () => {
  const relaygate = { SELFHOST_RELAYGATE_PUBLIC_URL: "https://cast.selfhosted.company" };
  assert.equal(loadConfig(completeEnv).sessionReadApi.mintReaderKind, false);
  assert.equal(loadConfig({ ...completeEnv, SESSION_READ_MINT_INCLUDE_READER_KIND: "  " }).sessionReadApi.mintReaderKind, false);
  assert.equal(loadConfig({ ...completeEnv, ...relaygate }).sessionReadApi.mintReaderKind, true);
  assert.equal(loadConfig({ ...completeEnv, ...relaygate, SESSION_READ_MINT_INCLUDE_READER_KIND: "" }).sessionReadApi.mintReaderKind, true);
  assert.equal(loadConfig({ ...completeEnv, SESSION_READ_MINT_INCLUDE_READER_KIND: "true" }).sessionReadApi.mintReaderKind, true);
  assert.equal(loadConfig({ ...completeEnv, ...relaygate, SESSION_READ_MINT_INCLUDE_READER_KIND: "false" }).sessionReadApi.mintReaderKind, false);
  assert.throws(() => loadConfig({ ...completeEnv, SESSION_READ_MINT_INCLUDE_READER_KIND: "yes" }),
    /SESSION_READ_MINT_INCLUDE_READER_KIND must be true or false/);
});

test("the read API mint role is default off and strictly boolean", () => {
  assert.equal(loadConfig(completeEnv).sessionReadMintIncludeRole, false);
  assert.equal(loadConfig({ ...completeEnv, SESSION_READ_MINT_INCLUDE_ROLE: "false" }).sessionReadMintIncludeRole, false);
  assert.equal(loadConfig({ ...completeEnv, SESSION_READ_MINT_INCLUDE_ROLE: "true" }).sessionReadMintIncludeRole, true);
  assert.throws(() => loadConfig({ ...completeEnv, SESSION_READ_MINT_INCLUDE_ROLE: "1" }), /SESSION_READ_MINT_INCLUDE_ROLE/);
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

test("the read API handoff is required and must be fully configured", () => {
  const reader = {
    SESSION_READ_API_URL: "http://reader.sessions.svc.cluster.local:8080",
    SESSION_READ_API_PUBLIC_URL: "https://history.selfhosted.company/",
    SESSION_READ_API_SECRET: "reader-control-secret-".repeat(2),
  };
  const config = loadConfig({ ...completeEnv, ...reader });
  assert.deepEqual(config.sessionReadApi, {
    url: reader.SESSION_READ_API_URL,
    publicUrl: "https://history.selfhosted.company",
    secret: reader.SESSION_READ_API_SECRET,
    mintReaderKind: false,
  });
  // History is the read API: its URLs are the History URLs.
  assert.equal(config.relayhistoryUrl, reader.SESSION_READ_API_URL);
  assert.equal(config.relayhistoryPublicUrl, "https://history.selfhosted.company");
  const { SESSION_READ_API_URL: _url, SESSION_READ_API_PUBLIC_URL: _public, SESSION_READ_API_SECRET: _secret, ...withoutReader } = completeEnv;
  assert.throws(() => loadConfig(withoutReader), {
    message: "SESSION_READ_API_URL, SESSION_READ_API_PUBLIC_URL and SESSION_READ_API_SECRET are required",
  });
  for (const key of Object.keys(reader)) {
    const partial = { ...withoutReader, ...reader };
    delete partial[key as keyof typeof partial];
    assert.throws(() => loadConfig(partial), /SESSION_READ_API_/, key);
  }
  assert.throws(() => loadConfig({ ...completeEnv, ...reader, SESSION_READ_API_SECRET: "short" }), /SECRET/);
  assert.throws(() => loadConfig({ ...completeEnv, ...reader, SESSION_READ_API_PUBLIC_URL: "http://reader.internal" }), /PUBLIC_URL/);
  assert.notEqual(
    configFingerprint(config),
    configFingerprint(loadConfig({ ...completeEnv, SESSION_READ_API_URL: "http://other-reader.sessions.svc.cluster.local:8080" })),
  );
  assert.equal(configFingerprint(config), configFingerprint({
    ...config, sessionReadApi: { ...config.sessionReadApi, secret: "different-secret" },
  }), "fingerprint does not include credentials");
});

test("RELAYHISTORY_URL and RELAYHISTORY_PUBLIC_URL are accepted only as aliases of the read API", () => {
  const aliased = loadConfig({
    ...completeEnv,
    RELAYHISTORY_URL: completeEnv.SESSION_READ_API_URL,
    RELAYHISTORY_PUBLIC_URL: completeEnv.SESSION_READ_API_PUBLIC_URL,
  });
  assert.equal(aliased.relayhistoryUrl, completeEnv.SESSION_READ_API_URL);
  assert.equal(aliased.relayhistoryPublicUrl, completeEnv.SESSION_READ_API_PUBLIC_URL);
  assert.throws(
    () => loadConfig({ ...completeEnv, RELAYHISTORY_URL: "http://relayhistory.history.svc.cluster.local" }),
    { message: "RELAYHISTORY_URL must equal SESSION_READ_API_URL (or be unset)" },
  );
  assert.throws(
    () => loadConfig({ ...completeEnv, RELAYHISTORY_PUBLIC_URL: "https://other-history.selfhosted.company" }),
    { message: "RELAYHISTORY_PUBLIC_URL must equal SESSION_READ_API_PUBLIC_URL (or be unset)" },
  );
});

test("the read API handoff supports a mounted secret without accepting both secret forms", (t) => {
  const directory = mkdtempSync(join(tmpdir(), "session-read-config-"));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const secretPath = join(directory, "secret");
  writeFileSync(secretPath, "reader-control-secret-".repeat(2), { mode: 0o600 });
  const { SESSION_READ_API_SECRET: _inlineSecret, ...withoutInlineSecret } = completeEnv;
  const env = { ...withoutInlineSecret, SESSION_READ_API_SECRET_FILE: secretPath };
  assert.equal(loadConfig(env).sessionReadApi.secret, "reader-control-secret-".repeat(2));
  assert.throws(() => loadConfig({ ...env, SESSION_READ_API_SECRET: "another-secret" }), /mutually exclusive/);
});

test("configuration has no hosted service defaults", () => {
  for (const required of [
    "SELFHOST_PUBLIC_URL",
    "RELAYCAST_URL",
    "RELAYCAST_PUBLIC_URL",
    "SESSION_READ_API_URL",
    "SESSION_READ_API_PUBLIC_URL",
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
  assert.equal(config.relayhistoryUrl, completeEnv.SESSION_READ_API_URL);
  assert.equal(config.relayhistoryPublicUrl, completeEnv.SESSION_READ_API_PUBLIC_URL);
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
    for (const name of ["SESSION_READ_API_PUBLIC_URL", "RELAYHISTORY_PUBLIC_URL"]) {
      assert.throws(
        () => loadConfig({ ...completeEnv, [name]: invalid }),
        new RegExp(name),
        `${name}=${invalid}`,
      );
    }
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

test("startup refuses the removed RelayHistory and RelayAuth variables by name", () => {
  for (const backend of ["legacy", "maybe"]) {
    assert.throws(() => loadConfig({ ...completeEnv, RELAYHISTORY_BACKEND: backend }), {
      message: `RELAYHISTORY_BACKEND=${backend} is no longer supported: the standalone RelayHistory service and RelayAuth were removed; unset it or set native`,
    });
  }
  for (const [name, value] of [
    ["RELAYAUTH_URL", "http://relayauth.auth.svc.cluster.local"],
    ["RELAYAUTH_API_KEY", "rak_test"],
    ["RELAYAUTH_API_KEY_FILE", "/run/secrets/relayauth-api-key"],
  ] as const) {
    assert.throws(() => loadConfig({ ...completeEnv, [name]: value }), {
      message: `${name} is no longer supported: RelayAuth was removed from self-hosted installs; unset it`,
    }, name);
  }
  assert.throws(() => loadConfig({ ...completeEnv, RELAYHISTORY_READ_API_URL: "https://session-reader.selfhosted.company" }), {
    message: "RELAYHISTORY_READ_API_URL is no longer supported: the read API is configured only through SESSION_READ_API_URL, SESSION_READ_API_PUBLIC_URL and SESSION_READ_API_SECRET; unset it",
  });
  // Unset, empty and `native` start; empty removed variables count as unset.
  for (const backend of [undefined, "", "native"]) {
    assert.doesNotThrow(() => loadConfig({ ...completeEnv, RELAYHISTORY_BACKEND: backend }));
  }
  assert.doesNotThrow(() => loadConfig({ ...completeEnv, RELAYAUTH_URL: "", RELAYAUTH_API_KEY: " ", RELAYHISTORY_READ_API_URL: "" }));
});

test("token introspection is required and validates its secret and audiences", (t) => {
  const config = loadConfig(completeEnv);
  assert.equal(config.introspectSecret, completeEnv.RELAYCONTROL_INTROSPECT_SECRET);
  assert.deepEqual(config.introspectAudiences, []);
  assert.deepEqual(config.relayhistoryAudiences, [completeEnv.SESSION_READ_API_PUBLIC_URL]);
  assert.throws(() => loadConfig({ ...completeEnv, RELAYCONTROL_INTROSPECT_SECRET: "" }), {
    message: "RELAYCONTROL_INTROSPECT_SECRET is required: the sessions pipeline verifies every History token through introspection",
  });
  assert.deepEqual(
    loadConfig({ ...completeEnv, SELFHOST_INTROSPECT_AUDIENCES: "http://relayfile.files.svc:8080" }).introspectAudiences,
    ["http://relayfile.files.svc:8080"],
  );

  const secret = "j".repeat(32);
  const enabled = loadConfig({
    ...completeEnv,
    RELAYCONTROL_INTROSPECT_SECRET: secret,
    SELFHOST_INTROSPECT_AUDIENCES: " http://relayfile.files.svc:8080 ",
  });
  assert.equal(enabled.introspectSecret, secret);
  assert.deepEqual(enabled.introspectAudiences, [
    "http://relayfile.files.svc:8080",
  ]);
  const warnings: unknown[][] = [];
  t.mock.method(console, "warn", (...args: unknown[]) => warnings.push(args));
  const compatibleOverlap = loadConfig({
    ...completeEnv,
    SELFHOST_RELAYHISTORY_AUDIENCES:
      `${completeEnv.SESSION_READ_API_PUBLIC_URL},https://xn--bcher-kva.example`,
    SELFHOST_INTROSPECT_AUDIENCES:
      "https://HISTORY.SELFHOSTED.COMPANY.:0443,https://BÜCHER.example.:443,http://relayfile.files.svc:8080",
  });
  assert.deepEqual(compatibleOverlap.introspectAudiences, ["http://relayfile.files.svc:8080"]);
  assert.equal(warnings.length, 1);
  assert.match(String(warnings[0]![0]), /SELFHOST_INTROSPECT_AUDIENCES/);
  assert.match(String(warnings[0]![0]), /SELFHOST_RELAYHISTORY_AUDIENCES/);
  const importedHistory = loadConfig({
    ...completeEnv,
    SELFHOST_RELAYHISTORY_AUDIENCES:
      " https://history.selfhosted.company/ , https://BÜCHER.example.:0443 ",
  });
  assert.deepEqual(importedHistory.relayhistoryAudiences, [
    "https://history.selfhosted.company",
    "https://xn--bcher-kva.example",
  ]);
  assert.throws(
    () => loadConfig({
      ...completeEnv,
      SELFHOST_RELAYHISTORY_AUDIENCES: "https://history.customer.example",
    }),
    { message: "SELFHOST_RELAYHISTORY_AUDIENCES must include SESSION_READ_API_PUBLIC_URL" },
  );
  for (const invalid of ["http://history.customer.example", "ftp://history.example", "https://u:p@h.example"]) {
    assert.throws(
      () => loadConfig({ ...completeEnv, SELFHOST_RELAYHISTORY_AUDIENCES: invalid }),
      /SELFHOST_RELAYHISTORY_AUDIENCES/,
      invalid,
    );
  }
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

test("the introspection outage hold is default off and strictly bounded", () => {
  assert.equal(loadConfig(completeEnv).introspectOutageHoldMs, 0);
  const hold = (value: string) => loadConfig({ ...completeEnv, SELFHOST_INTROSPECT_OUTAGE_HOLD_MS: value });
  assert.equal(hold("").introspectOutageHoldMs, 0);
  assert.equal(hold("0").introspectOutageHoldMs, 0);
  assert.equal(hold("1000").introspectOutageHoldMs, 1_000);
  assert.equal(hold("60000").introspectOutageHoldMs, 60_000);
  assert.equal(hold("3600000").introspectOutageHoldMs, 3_600_000);
  for (const invalid of ["500", "999", "abc", "3600001", "-1", "1e4", "60000.5", "0x10", "60 000"]) {
    assert.throws(
      () => hold(invalid),
      (error: unknown) => error instanceof Error &&
        error.message.includes("SELFHOST_INTROSPECT_OUTAGE_HOLD_MS") &&
        !error.message.includes(invalid),
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


test("the Flows broker secret is optional and must be long enough", () => {
  assert.equal(loadConfig(completeEnv).relayfileControlBrokerSecret, null);
  const secret = "s".repeat(32);
  assert.equal(loadConfig({ ...completeEnv, RELAYFILE_CONTROL_BROKER_SECRET: secret }).relayfileControlBrokerSecret, secret);
  assert.throws(() => loadConfig({ ...completeEnv, RELAYFILE_CONTROL_BROKER_SECRET: "short" }), /at least 32 bytes/);
});
