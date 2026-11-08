/**
 * Draft contract tests for the Desktop feed (docs/desktop-feed.md).
 * Status: proposed, Cloud team decides, not yet confirmed.
 *
 * Nothing here exercises a server: there is no implementation. The tests pin
 * the contract instead: the JSON schemas, the OpenAPI operations and
 * responses, the canonicalisation and signature rule, and reference decision
 * functions for the credential, upload, publish, quota and transport rules,
 * each checked against the fixtures in test/fixtures/desktop-feed/ and
 * against the statuses the OpenAPI document declares.
 *
 * Keys are generated per run with generateKeyPairSync("ed25519"); no key and
 * no credential-shaped value is committed.
 */
import assert from "node:assert/strict";
import { createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import test from "node:test";
import { Ajv2020, type ValidateFunction } from "ajv/dist/2020.js";
import addFormatsModule from "ajv-formats";
import { parse as parseYaml } from "yaml";
import { canonicalBytes, canonicalize, JcsError } from "./support/jcs.js";
import { StrictJsonError, strictParse } from "./support/strict-json.js";

// ajv-formats ships CommonJS with a default export; under NodeNext the
// namespace object is what an ESM default import yields.
const addFormats = addFormatsModule as unknown as typeof addFormatsModule.default;

/* eslint-disable @typescript-eslint/no-explicit-any */
type Json = any;

const ROOT = new URL("../", import.meta.url);
const FIXTURES = new URL("test/fixtures/desktop-feed/", ROOT);
const readText = (url: URL): string => readFileSync(url, "utf8");
const fixture = (path: string): Json => JSON.parse(readText(new URL(path, FIXTURES)));
const fixtureText = (path: string): string => readText(new URL(path, FIXTURES));

const manifestSchema: Json = JSON.parse(readText(new URL("docs/specs/desktop-feed-manifest.schema.json", ROOT)));
const envelopeSchema: Json = JSON.parse(readText(new URL("docs/specs/desktop-feed-envelope.schema.json", ROOT)));
const spec: Json = parseYaml(readText(new URL("openapi.yaml", ROOT)));

const FEED_PREFIX = "/api/v1/desktop/feed";
const METHODS = ["get", "put", "post", "delete", "patch", "head", "options"] as const;
const READ_OPS = new Set([
  `get ${FEED_PREFIX}/manifest`,
  `get ${FEED_PREFIX}/releases`,
  `post ${FEED_PREFIX}/assets/{assetId}/download-url`,
  `get ${FEED_PREFIX}/assets/{assetId}`,
]);

// The install-token sample is built here, never stored in a fixture.
const SAMPLE_INSTALL_TOKEN = "sh_dfi_" + "0".repeat(43);

function strictAjv(): Ajv2020 {
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(ajv);
  return ajv;
}

const schemaAjv = strictAjv();
const validateManifest = schemaAjv.compile<Json>(manifestSchema);
const validateEnvelope = schemaAjv.compile<Json>(envelopeSchema);

// OpenAPI components carry `x-` keys, so they compile with strict off.
const OPENAPI_ID = "urn:relaycontrol:openapi";
const openapiAjv = new Ajv2020({ strict: false, allErrors: true });
addFormats(openapiAjv);
openapiAjv.addSchema({
  $id: OPENAPI_ID,
  components: {
    schemas: pick(spec.components.schemas),
    responses: pick(spec.components.responses),
  },
});

function pick(record: Record<string, Json>): Record<string, Json> {
  return Object.fromEntries(Object.entries(record).filter(([name]) => name.startsWith("DesktopFeed")));
}

function rebase(schema: Json): Json {
  if (Array.isArray(schema)) return schema.map(rebase);
  if (schema && typeof schema === "object") {
    return Object.fromEntries(
      Object.entries(schema).map(([key, value]) => [
        key,
        key === "$ref" && typeof value === "string" && value.startsWith("#/") ? `${OPENAPI_ID}${value}` : rebase(value),
      ]),
    );
  }
  return schema;
}

const componentValidators = new Map<string, ValidateFunction<Json>>();
function component(name: string): ValidateFunction<Json> {
  let fn = componentValidators.get(name);
  if (!fn) {
    fn = openapiAjv.compile<Json>({ $ref: `${OPENAPI_ID}#/components/schemas/${name}` });
    componentValidators.set(name, fn);
  }
  return fn;
}

function feedOperations(): Array<{ method: string; path: string; op: Json }> {
  const out: Array<{ method: string; path: string; op: Json }> = [];
  for (const [path, item] of Object.entries<Json>(spec.paths)) {
    if (!path.startsWith(FEED_PREFIX)) continue;
    for (const method of METHODS) if (item[method]) out.push({ method, path, op: item[method] });
  }
  return out;
}

function resolveResponse(response: Json): Json {
  if (response?.$ref) {
    const name = String(response.$ref).replace("#/components/responses/", "");
    return spec.components.responses[name];
  }
  return response;
}

function responseFor(opName: string, status: number): Json | undefined {
  const [method, path] = requestCases.operations[opName];
  const op = spec.paths[path]?.[method];
  assert.ok(op, `${opName} is documented`);
  const raw = op.responses[String(status)];
  return raw ? resolveResponse(raw) : undefined;
}

function responseValidator(opName: string, status: number): ValidateFunction | undefined {
  const response = responseFor(opName, status);
  const schema = response?.content?.["application/json"]?.schema;
  return schema ? openapiAjv.compile(rebase(schema)) : undefined;
}

/** Every error code a documented response of this operation may carry. */
function documentedErrors(opName: string, status: number): Set<string> {
  const codes = new Set<string>();
  const response = responseFor(opName, status);
  const walk = (node: Json): void => {
    if (Array.isArray(node)) return node.forEach(walk);
    if (!node || typeof node !== "object") return;
    if (node.$ref) {
      const target = String(node.$ref);
      if (target === "#/components/schemas/DesktopFeedError") return;
      walk(spec.components.schemas[target.replace("#/components/schemas/", "")]);
      return;
    }
    const error = node.properties?.error;
    if (error?.enum) error.enum.forEach((code: string) => codes.add(code));
    if (error?.const) codes.add(error.const);
    for (const key of ["allOf", "oneOf", "anyOf"]) if (node[key]) walk(node[key]);
  };
  walk(response?.content?.["application/json"]?.schema);
  return codes;
}

const feedState = fixture("feed-state.json");
const requestCases = fixture("request-cases.json");
const publisherCases = fixture("publisher-cases.json");
const manifestCases = fixture("manifest-cases.json");
const transportCases = fixture("transport-cases.json");
const apiBodies = fixture("api-bodies.json");

/* ------------------------------------------------------------------ JCS */

test("JCS: hand-computed canonical bytes", () => {
  // 1. Keys sorted, no whitespace.
  assert.equal(canonicalize({ b: 1, a: "x" }), '{"a":"x","b":1}');
  assert.equal(canonicalBytes({ b: 1, a: "x" }).toString("hex"), "7b2261223a2278222c2262223a317d");

  // 2. String escapes: the two-character forms, \u00xx in lower case for
  // other controls, and everything else raw UTF-8 (no escaping of "/", é, €).
  const escaped = { s: "\u0000\b\t\n\f\r\"\\/é€\u001f" };
  assert.equal(canonicalize(escaped), '{"s":"\\u0000\\b\\t\\n\\f\\r\\"\\\\/é€\\u001f"}');
  assert.equal(
    canonicalBytes(escaped).toString("hex"),
    "7b2273223a22" + "5c7530303030" + "5c62" + "5c74" + "5c6e" + "5c66" + "5c72" + "5c22" + "5c5c" + "2f" +
      "c3a9" + "e282ac" + "5c7530303166" + "227d",
  );

  // 3. Keys ordered by UTF-16 code units: U+1F600 (D83D DE00) sorts before
  // U+FB01, although its code point is larger. -0 is written 0.
  const ordered = { "ﬁ": 3, z: 1, "\u{1f600}": 2, a: [true, null, -0] };
  assert.equal(canonicalize(ordered), '{"a":[true,null,0],"z":1,"\u{1f600}":2,"ﬁ":3}');
  assert.equal(
    canonicalBytes(ordered).toString("hex"),
    "7b2261223a5b747275652c6e756c6c2c305d2c227a223a312c22" + "f09f9880" + "223a322c22" + "efac81" + "223a337d",
  );

  // 4. Nesting, empty containers and the largest safe integer.
  assert.equal(
    canonicalize([{ b: [], a: {} }, 9007199254740991, -1, "", false]),
    '[{"a":{},"b":[]},9007199254740991,-1,"",false]',
  );
});

test("JCS: refuses what the manifest never contains", () => {
  for (const bad of [1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53, "\ud800", { k: "x\udc00" }, undefined, new Date(0)]) {
    assert.throws(() => canonicalize(bad), JcsError, String(bad));
  }
});

/* ------------------------------------------------------ JSON schemas */

test("schemas: strict, self-contained, envelope copies the manifest definition", () => {
  for (const schema of [manifestSchema, envelopeSchema]) {
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema");
    assert.match(schema.$comment, /proposed/i);
    const refs = JSON.stringify(schema).match(/"\$ref":"([^"]+)"/g) ?? [];
    for (const ref of refs) assert.match(ref, /"#\/\$defs\//, `self-contained: ${ref}`);
  }
  const { $schema, $id, title, $comment, $defs, ...manifestBody } = manifestSchema;
  void $schema; void $id; void title; void $comment;
  assert.deepEqual(envelopeSchema.$defs.manifest, manifestBody, "envelope $defs.manifest equals the manifest schema");
  assert.deepEqual(envelopeSchema.$defs.asset, $defs.asset, "envelope $defs.asset equals the manifest schema");
});

test("schemas: OpenAPI components equal the JSON schemas", () => {
  const normalize = (node: Json): Json => {
    if (Array.isArray(node)) return node.map(normalize);
    if (node && typeof node === "object") {
      const out: Record<string, Json> = {};
      for (const [key, value] of Object.entries(node)) {
        if (key.startsWith("x-") || ["description", "$schema", "$id", "title", "$comment", "$defs"].includes(key)) continue;
        if (key === "$ref") {
          out[key] = String(value)
            .replace("#/components/schemas/DesktopFeedAsset", "#/$defs/asset")
            .replace("#/components/schemas/DesktopFeedManifest", "#/$defs/manifest");
          continue;
        }
        out[key] = normalize(value);
      }
      return out;
    }
    return node;
  };
  const schemas = spec.components.schemas;
  assert.deepEqual(normalize(schemas.DesktopFeedManifest), normalize(manifestSchema));
  assert.deepEqual(normalize(schemas.DesktopFeedAsset), normalize(manifestSchema.$defs.asset));
  assert.deepEqual(normalize(schemas.DesktopFeedEnvelope), normalize(envelopeSchema));
});

test("schemas: every manifest fixture has the expected schema result", () => {
  for (const entry of manifestCases.cases) {
    const ok = validateManifest(fixture(entry.file));
    assert.equal(ok, entry.schema === "valid", `${entry.file}: ${JSON.stringify(validateManifest.errors)}`);
  }
  for (const entry of manifestCases.envelopes) {
    const ok = validateEnvelope(fixture(entry.file));
    assert.equal(ok, entry.schema === "valid", `${entry.file}: ${JSON.stringify(validateEnvelope.errors)}`);
  }
  // Every fixture file is listed in a case.
  const listed = new Set([...manifestCases.cases, ...manifestCases.envelopes].map((entry: Json) => entry.file));
  for (const name of [
    "valid-stable", "valid-beta", "other-profile-stable", "invalid-unknown-schema", "invalid-beta-version-on-stable",
    "invalid-stable-version-on-beta", "invalid-sha256-uppercase", "invalid-sha256-short", "invalid-size-negative",
    "invalid-kind-unknown", "invalid-name-other-profile-prefix", "invalid-duplicate-asset-name", "invalid-no-assets",
  ]) {
    assert.ok(listed.has(`manifest/${name}.json`), name);
  }
});

/* ------------------------------------------- signature and client checks */

interface Compiled {
  profile: string;
  channel: "stable" | "beta";
  keyId: string;
  publicKey: KeyObject;
}

function signEnvelope(manifest: Json, privateKey: KeyObject, keyId: string): Json {
  const signature = sign(null, canonicalBytes(manifest), privateKey).toString("base64url");
  return { manifest, signature, key_id: keyId };
}

/**
 * The client's order of checks (source design, "Client order of checks"):
 * a strict I-JSON parse of the received text (duplicate names, lone
 * surrogates and non-RFC 8259 input are schema_invalid before any signature
 * check; DF-001), then key and signature over the canonical form of what was
 * received, then the schema, profile and channel, then the cross-field rules.
 */
function clientVerify(raw: string, compiled: Compiled): string {
  let envelope: Json;
  try {
    envelope = strictParse(raw);
  } catch (error) {
    assert.ok(error instanceof StrictJsonError);
    return "schema_invalid";
  }
  if (!envelope || typeof envelope !== "object" || typeof envelope.signature !== "string") return "schema_invalid";
  if (envelope.key_id !== compiled.keyId) return "key_id_refused";
  let bytes: Buffer;
  try {
    bytes = canonicalBytes(envelope.manifest);
  } catch {
    return "signature_invalid";
  }
  const signature = Buffer.from(envelope.signature, "base64url");
  if (signature.length !== 64 || !verify(null, bytes, compiled.publicKey, signature)) return "signature_invalid";
  if (!validateEnvelope(envelope)) return "schema_invalid";
  const manifest = envelope.manifest;
  if (manifest.profile !== compiled.profile) return "profile_mismatch";
  if (manifest.channel !== compiled.channel) return "channel_mismatch";
  const ids = new Set(manifest.assets.map((asset: Json) => asset.id));
  const names = new Set(manifest.assets.map((asset: Json) => asset.name));
  if (ids.size !== manifest.assets.length || names.size !== manifest.assets.length) return "duplicate_asset";
  return "accept";
}

function runtimeKey(): { privateKey: KeyObject; publicKey: KeyObject } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  // A build carries only the raw public key; rebuild it from the JWK x.
  const x = publicKey.export({ format: "jwk" }).x;
  assert.ok(x);
  return { privateKey, publicKey: createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x }, format: "jwk" }) };
}

test("signature: valid stable and beta envelopes verify; every manifest case gets its client result", () => {
  const key = runtimeKey();
  const keyId = feedState.profiles.x7k2q.key_id;
  for (const entry of manifestCases.cases) {
    const manifest = fixture(entry.file);
    let envelope: Json;
    try {
      envelope = signEnvelope(manifest, key.privateKey, keyId);
    } catch (error) {
      // A non-integer number cannot be canonicalised, so no conformant signer
      // can produce it; the schema refuses it too.
      assert.ok(error instanceof JcsError, entry.file);
      assert.equal(entry.client, "schema_invalid", entry.file);
      continue;
    }
    assert.ok(validateEnvelope(envelope) === (entry.schema === "valid"), entry.file);
    const channel = entry.request?.channel ?? manifest.channel ?? "stable";
    const compiled: Compiled = { profile: entry.request?.profile ?? "x7k2q", channel, keyId, publicKey: key.publicKey };
    assert.equal(clientVerify(JSON.stringify(envelope), compiled), entry.client, entry.file);
  }
});

test("signature: tampering, wrong key_id, another key, re-serialisation", () => {
  const key = runtimeKey();
  const other = runtimeKey();
  const keyId = "fk_x7k2q_2026a";
  const compiled: Compiled = { profile: "x7k2q", channel: "stable", keyId, publicKey: key.publicKey };
  const envelope = signEnvelope(fixture("manifest/valid-stable.json"), key.privateKey, keyId);
  const raw = JSON.stringify(envelope);
  assert.equal(clientVerify(raw, compiled), "accept");
  assert.equal(envelope.signature.length, 86);
  assert.match(envelope.signature, /^[A-Za-z0-9_-]{85}[AQgw]$/);

  // Whitespace and key order of the transport do not matter: the client
  // canonicalises what it received.
  assert.equal(clientVerify(JSON.stringify(envelope, null, 2), compiled), "accept");
  const reordered = { key_id: envelope.key_id, signature: envelope.signature, manifest: { ...envelope.manifest, assets: envelope.manifest.assets, schema: 1 } };
  assert.equal(clientVerify(JSON.stringify(reordered), compiled), "accept");
  assert.equal(clientVerify(` \r\n${JSON.stringify(reordered, null, "\t").replaceAll("\n", "\r\n")}\t\n`, compiled), "accept");
  // A duplicate name is refused before the signature check, although
  // JSON.parse would have returned the signed manifest (DF-001).
  const duplicated = raw.replace('"profile":"x7k2q"', '"profile":"a1b2c","profile":"x7k2q"');
  assert.notEqual(duplicated, raw);
  assert.deepEqual(JSON.parse(duplicated), envelope);
  assert.equal(clientVerify(duplicated, compiled), "schema_invalid");

  // One byte changed in the signed content.
  const tampered = raw.replace("2026-11-20T10:04:31Z", "2026-11-20T10:04:32Z");
  assert.notEqual(tampered, raw);
  assert.equal(clientVerify(tampered, compiled), "signature_invalid");
  const sizeTampered = raw.replace('"size":21311', '"size":21312');
  assert.notEqual(sizeTampered, raw);
  assert.equal(clientVerify(sizeTampered, compiled), "signature_invalid");

  // One bit changed in the signature.
  const sig = Buffer.from(envelope.signature, "base64url");
  sig[0] = (sig[0] ?? 0) ^ 1;
  assert.equal(clientVerify(JSON.stringify({ ...envelope, signature: sig.toString("base64url") }), compiled), "signature_invalid");

  // A key_id other than the compiled one is refused before verification.
  assert.equal(clientVerify(JSON.stringify({ ...envelope, key_id: "fk_x7k2q_2026b" }), compiled), "key_id_refused");
  // The right key_id signed by another key.
  const forged = signEnvelope(fixture("manifest/valid-stable.json"), other.privateKey, keyId);
  assert.equal(clientVerify(JSON.stringify(forged), compiled), "signature_invalid");
  // Another profile's correctly signed envelope.
  const otherProfile = signEnvelope(fixture("manifest/other-profile-stable.json"), key.privateKey, keyId);
  assert.equal(clientVerify(JSON.stringify(otherProfile), compiled), "profile_mismatch");
});

/**
 * Import (paths (a), (b), (c)): verify only, never sign. The server parses
 * the received request body (`{"envelope": ...}`, DesktopFeedImport) strictly
 * (a duplicate name at any depth, a lone surrogate or non-RFC 8259 input is
 * manifest_invalid; DF-001), checks schema, profile, key_id and signature,
 * then stores the envelope verbatim.
 */
function importDecision(rawBody: string, profile: string, keys: Map<string, KeyObject>, published: Set<string>): { status: number; error?: string } {
  let body: Json;
  try {
    body = strictParse(rawBody);
  } catch (error) {
    assert.ok(error instanceof StrictJsonError);
    return { status: 422, error: "manifest_invalid" };
  }
  const envelope = body?.envelope;
  if (!validateEnvelope(envelope)) return { status: 422, error: "manifest_invalid" };
  if (envelope.manifest.profile !== profile) return { status: 422, error: "profile_mismatch" };
  const publicKey = keys.get(envelope.key_id);
  if (!publicKey) return { status: 422, error: "key_id_unknown" };
  if (!verify(null, canonicalBytes(envelope.manifest), publicKey, Buffer.from(envelope.signature, "base64url"))) {
    return { status: 422, error: "signature_invalid" };
  }
  if (published.has(envelope.manifest.version)) return { status: 409, error: "version_exists" };
  return { status: 201 };
}

/** The import request body (DesktopFeedImport) around an envelope's raw text. */
const importBody = (envelopeText: string): string => `{"envelope":${envelopeText}}`;

test("import: verify and store, never sign", () => {
  const key = runtimeKey();
  const keys = new Map([["fk_x7k2q_2026a", key.publicKey]]);
  const good = signEnvelope(fixture("manifest/valid-stable.json"), key.privateKey, "fk_x7k2q_2026a");
  const check = (envelope: Json, published: string[] = []) =>
    importDecision(importBody(JSON.stringify(envelope)), "x7k2q", keys, new Set(published));
  const cases: Array<[Json, number, string | undefined, string[]?]> = [
    [good, 201, undefined],
    [good, 409, "version_exists", ["2026.11.9"]],
    [fixture("envelope/invalid-manifest-invalid.json"), 422, "manifest_invalid"],
    [signEnvelope(fixture("manifest/other-profile-stable.json"), key.privateKey, "fk_x7k2q_2026a"), 422, "profile_mismatch"],
    [{ ...good, key_id: "fk_x7k2q_2026b" }, 422, "key_id_unknown"],
    [{ ...good, manifest: { ...good.manifest, notes: "changed" } }, 422, "signature_invalid"],
  ];
  for (const [envelope, status, error, published] of cases) {
    assert.deepEqual(check(envelope, published), error ? { status, error } : { status });
    assert.ok(responseFor("import", status), `import documents ${status}`);
    if (error) assert.ok(documentedErrors("import", status).has(error), `${status} ${error}`);
  }
  assert.equal(spec.paths[`${FEED_PREFIX}/releases/import`].post.responses["503"], undefined, "import never needs a signer");
});

/* ------------------------------------- strict I-JSON acceptance (DF-001) */

const rawCases = fixture("raw/cases.json");

test("strict JSON: equals JSON.parse on every fixture file and both schemas", () => {
  const files = readdirSync(FIXTURES, { recursive: true, encoding: "utf8" })
    .filter((name) => name.endsWith(".json"))
    .sort();
  assert.ok(files.length > 40, `found ${files.length} fixture files`);
  const texts = files.map((name) => [name, fixtureText(name)] as const);
  for (const name of ["desktop-feed-manifest.schema.json", "desktop-feed-envelope.schema.json"]) {
    texts.push([name, readText(new URL(`docs/specs/${name}`, ROOT))]);
  }
  for (const [name, text] of texts) {
    if (name.startsWith("raw/") && name !== "raw/cases.json") continue; // raw templates: next tests
    assert.deepEqual(strictParse(text), JSON.parse(text), name);
  }
  // Escapes, surrogate pairs, numbers and "__proto__" agree with JSON.parse.
  for (const text of [
    '{"s":"\\u00e9\\ud83d\\ude00\\"\\\\\\/\\b\\f\\n\\r\\t","n":[0,-0,1e3,-1.5E-2,9007199254740993],"__proto__":{"x":null}}',
    ' [ true , false , null , { } , [ ] , "" ] ',
    '"\u{1f600}"',
  ]) {
    assert.deepEqual(strictParse(text), JSON.parse(text), text);
  }
});

test("strict JSON: refuses duplicates, lone surrogates and anything outside RFC 8259", () => {
  const refused: Array<[string, string, string]> = [
    ["duplicate at top level", '{"a":1,"a":1}', "duplicate_name"],
    ["duplicate nested", '{"a":[{"b":1,"c":2,"b":3}]}', "duplicate_name"],
    ["escaped-equivalent duplicate", '{"profile":"x","pro\\u0066ile":"x"}', "duplicate_name"],
    ["lone high surrogate escape", '{"s":"\\ud800"}', "lone_surrogate"],
    ["lone low surrogate escape", '["\\udc00x"]', "lone_surrogate"],
    ["lone surrogate in a name", '{"\\ud83d":1}', "lone_surrogate"],
    ["raw lone surrogate", '"\ud800"', "lone_surrogate"],
    ["trailing garbage", '{"a":1} x', "syntax"],
    ["second value", '{"a":1}{"a":1}', "syntax"],
    ["leading BOM", '﻿{"a":1}', "syntax"],
    ["trailing comma", '{"a":1,}', "syntax"],
    ["single quotes", "{'a':1}", "syntax"],
    ["leading zero", "[01]", "syntax"],
    ["bare fraction", "[.5]", "syntax"],
    ["unescaped control", '"a\tb"', "syntax"],
    ["bad escape", '"\\x41"', "syntax"],
    ["non-JSON whitespace", '{ "a":1}', "syntax"],
    ["empty", "", "syntax"],
  ];
  for (const [name, text, kind] of refused) {
    assert.throws(() => strictParse(text), (error: unknown) => error instanceof StrictJsonError && error.kind === kind, name);
  }
  // Duplicates are the gap: JSON.parse accepts them and keeps the last value.
  assert.deepEqual(JSON.parse('{"a":1,"a":2}'), { a: 2 });
});

test("raw envelopes (DF-001): client and import refuse duplicate names before verification", () => {
  const key = runtimeKey();
  const keyId = "fk_x7k2q_2026a";
  const signed = signEnvelope(fixture("manifest/valid-stable.json"), key.privateKey, keyId);
  const compiled: Compiled = { profile: "x7k2q", channel: "stable", keyId, publicKey: key.publicKey };
  const keys = new Map([[keyId, key.publicKey]]);
  const placeholder = JSON.stringify(rawCases.placeholder);

  const listed = new Set(rawCases.cases.map((entry: Json) => entry.file));
  for (const name of readdirSync(new URL("raw/", FIXTURES))) {
    if (name !== "cases.json") assert.ok(listed.has(`raw/${name}`), `raw/${name} is listed`);
  }
  for (const required of ["duplicate-profile", "duplicate-profile-escaped", "duplicate-manifest", "duplicate-key-id", "duplicate-asset-sha256", "valid-reordered-whitespace", "valid-pretty"]) {
    assert.ok(listed.has(`raw/${required}.json`), required);
  }

  for (const entry of rawCases.cases) {
    const template = fixtureText(entry.file);
    // The committed file carries the placeholder once and no signature.
    assert.equal(template.split(placeholder).length, 2, `${entry.file}: one placeholder`);
    assert.doesNotMatch(template, /[A-Za-z0-9_-]{85}[AQgw]/, `${entry.file}: no committed signature`);
    const text = template.replace(placeholder, JSON.stringify(signed.signature));

    // What a language-default parser sees: the valid, signed envelope.
    assert.deepEqual(JSON.parse(text), signed, `${entry.file}: JSON.parse keeps the last duplicate`);
    assert.ok(validateEnvelope(JSON.parse(text)), entry.file);

    if (entry.strict === "ok") assert.deepEqual(strictParse(text), signed, entry.file);
    else assert.throws(() => strictParse(text), (error: unknown) => error instanceof StrictJsonError && error.kind === entry.strict, entry.file);

    assert.equal(clientVerify(text, compiled), entry.client, `${entry.file}: client`);
    assert.ok(component("DesktopFeedImport")(JSON.parse(importBody(text))), entry.file);
    assert.deepEqual(importDecision(importBody(text), "x7k2q", keys, new Set()), entry.import, `${entry.file}: import`);
    if (entry.import.error) assert.ok(documentedErrors("import", entry.import.status).has(entry.import.error), entry.file);
  }

  // A duplicate "envelope" member in the import body itself.
  const goodText = JSON.stringify(signed);
  const otherText = JSON.stringify({ ...signed, key_id: "fk_x7k2q_2026b" });
  const duplicateBody = `{"envelope":${otherText},"envelope":${goodText}}`;
  assert.deepEqual(JSON.parse(duplicateBody), { envelope: signed });
  assert.deepEqual(importDecision(importBody(goodText), "x7k2q", keys, new Set()), { status: 201 });
  assert.deepEqual(importDecision(duplicateBody, "x7k2q", keys, new Set()), { status: 422, error: "manifest_invalid" });
});

/* ------------------------------------------------- request gate (precedence) */

interface Credential {
  kind: "workspaceBearer" | "installToken" | "browserSession" | "publisherToken";
  state?: "active" | "expired" | "revoked" | "unknown";
  workspace?: string;
  profile?: string;
}

const ACCEPTS: Record<string, Credential["kind"][]> = {
  manifest: ["workspaceBearer", "installToken", "browserSession"],
  releases: ["workspaceBearer", "installToken", "browserSession", "publisherToken"],
  download_url: ["workspaceBearer", "installToken", "browserSession"],
  asset: ["workspaceBearer", "installToken", "browserSession"],
  install_tokens_list: ["browserSession"],
  install_tokens_create: ["browserSession"],
  install_tokens_revoke: ["browserSession"],
  create_draft: ["publisherToken"],
  import: ["publisherToken"],
  upload: ["publisherToken"],
  publish: ["publisherToken"],
};

function publishedManifests(profile: string): Json[] {
  const channels = feedState.profiles[profile]?.channels ?? {};
  return Object.values<string | null>(channels).filter((path): path is string => !!path).map(fixture);
}

/**
 * Reference precedence: 429 at any step (modelled first); 400 mixed
 * credentials; 401 no or invalid credential; 403 wrong credential kind;
 * 403 csrf_rejected (cookie, unsafe method); 400 missing profile header;
 * 403 not_entitled; 400 invalid_request; then the resource: 404 no_release
 * (channel only), 403 not_entitled (asset), 501, 416.
 */
function gate(entry: Json): { status: number; error?: string } {
  const op: string = entry.op;
  const method: string = requestCases.operations[op][0];
  const credentials: Credential[] = entry.credentials;
  if (entry.rate_limited) return { status: 429, error: "rate_limited" };
  if (credentials.length > 1) return { status: 400, error: "mixed_credentials" };
  const credential = credentials[0];
  if (!credential || credential.state === "unknown") return { status: 401, error: "unauthenticated" };
  if (credential.state === "expired") return { status: 401, error: "token_expired" };
  if (credential.state === "revoked") return { status: 401, error: "token_revoked" };
  if (!ACCEPTS[op]?.includes(credential.kind)) return { status: 403, error: "wrong_credential" };
  if (op === "releases" && (credential.kind === "publisherToken") !== (entry.include_drafts === true)) {
    return { status: 403, error: "wrong_credential" };
  }
  if (credential.kind === "browserSession" && method !== "get" && entry.origin_ok === false) {
    return { status: 403, error: "csrf_rejected" };
  }
  const profileId: string | null = entry.profile;
  if (!profileId) return { status: 400, error: "profile_header_required" };
  const profile = feedState.profiles[profileId];
  const bound = (workspace?: string) => !!workspace && !!profile?.workspaces.includes(workspace);
  const entitled =
    !!profile &&
    (credential.kind === "publisherToken"
      ? credential.profile === profileId
      : credential.kind === "installToken"
        ? credential.profile === profileId && bound(credential.workspace)
        : bound(credential.workspace));
  if (!entitled) return { status: 403, error: "not_entitled" };
  const reader = credential.kind !== "publisherToken";
  if ((op === "manifest" || (op === "releases" && reader)) && !entry.channel) return { status: 400, error: "invalid_request" };

  switch (op) {
    case "manifest":
      return profile.channels[entry.channel] ? { status: 200 } : { status: 404, error: "no_release" };
    case "releases":
      if (!reader) return { status: 200 };
      return profile.channels[entry.channel] ? { status: 200 } : { status: 404, error: "no_release" };
    case "download_url":
    case "asset": {
      const manifest = publishedManifests(profileId).find((m) => m.assets.some((a: Json) => a.id === entry.asset));
      if (!manifest) return { status: 403, error: "not_entitled" };
      if (op === "download_url") {
        return feedState.object_storage && manifest.download_hosts.includes(feedState.object_storage_host)
          ? { status: 200 }
          : { status: 501, error: "no_object_storage" };
      }
      const asset = manifest.assets.find((a: Json) => a.id === entry.asset);
      const decision = rangeDecision(entry.range ?? null, asset.size, null);
      return decision.status === 416 ? { status: 416, error: "range_not_satisfiable" } : { status: decision.status };
    }
    case "install_tokens_list":
      return { status: 200 };
    case "install_tokens_create":
      return { status: 201 };
    case "install_tokens_revoke":
      return entry.token_id === "known" ? { status: 200 } : { status: 404, error: "install_token_not_found" };
    default:
      return { status: 0 }; // publisher operations: gate passed, see the publisher tests
  }
}

test("request gate: credential precedence, entitlement and resource rules", () => {
  for (const entry of requestCases.cases) {
    const got = gate(entry);
    assert.deepEqual(got, entry.expect, entry.name);
    const response = responseFor(entry.op, entry.expect.status);
    assert.ok(response, `${entry.name}: ${entry.op} documents ${entry.expect.status}`);
    if (entry.expect.error) {
      assert.ok(documentedErrors(entry.op, entry.expect.status).has(entry.expect.error), `${entry.name}: ${entry.expect.error} documented`);
      const validate = responseValidator(entry.op, entry.expect.status);
      assert.ok(validate, entry.name);
      const body = entry.expect.status === 429 ? { error: "rate_limited", retry_after_seconds: 30 } : { error: entry.expect.error };
      assert.ok(validate(body), `${entry.name}: ${JSON.stringify(validate.errors)}`);
    }
  }
  // Every operation appears in the cases at least once.
  const covered = new Set(requestCases.cases.map((entry: Json) => entry.op));
  for (const op of Object.keys(requestCases.operations)) assert.ok(covered.has(op), op);
});

test("request gate: an unknown or unbound profile is 403 even where the channel is empty", () => {
  for (const profile of ["zz0zz", "y9p3r", "q4m8z"]) {
    for (const channel of ["stable", "beta"]) {
      const got = gate({ op: "manifest", credentials: [{ kind: "workspaceBearer", workspace: "11111111-1111-4111-8111-111111111111" }], profile, channel });
      assert.deepEqual(got, { status: 403, error: "not_entitled" }, `${profile} ${channel}`);
    }
  }
});

/* ------------------------------------------------------------- publisher */

const draftCreateValidator = component("DesktopFeedDraftCreate");

function createDecision(body: Json, existing: string | undefined, assetPrefix: string, previous: Json): { status: number; error?: string } {
  if (!Array.isArray(body?.expected_assets) || body.expected_assets.length === 0) {
    return { status: 422, error: "expected_assets_required" };
  }
  if (!draftCreateValidator(body)) {
    const assetError = draftCreateValidator.errors?.some((e) => e.instancePath.startsWith("/expected_assets"));
    return { status: 422, error: assetError ? "invalid_asset" : "invalid_release" };
  }
  const names = new Set<string>();
  for (const asset of body.expected_assets) {
    if (names.has(asset.name)) return { status: 422, error: "invalid_asset" };
    names.add(asset.name);
    // Publish binding: every asset but the install script carries the
    // profile's asset prefix and this version.
    if (asset.kind !== "install-script" && !asset.name.startsWith(`${assetPrefix}-${body.version}-`)) {
      return { status: 422, error: "invalid_asset" };
    }
  }
  if (existing === "published") return { status: 409, error: "version_exists" };
  if (existing === "same_draft") {
    return canonicalize(body) === canonicalize(previous) ? { status: 200 } : { status: 409, error: "version_exists" };
  }
  return { status: 201 };
}

test("publisher: draft creation requires a complete, bound expected_assets", () => {
  const baseline = publisherCases.create[0].body;
  for (const entry of publisherCases.create) {
    const got = createDecision(entry.body, entry.existing, publisherCases.asset_prefix, baseline);
    assert.deepEqual(got, entry.expect, entry.name);
    assert.ok(responseFor("create_draft", entry.expect.status), `${entry.name}: documented`);
    if (entry.expect.error) assert.ok(documentedErrors("create_draft", entry.expect.status).has(entry.expect.error), entry.name);
  }
});

function uploadDecision(draft: Json, request: Json): { status: number; error?: string } {
  if (draft.state === "none") return { status: 404, error: "draft_not_found" };
  if (draft.state !== "draft") return { status: 409, error: "not_a_draft" };
  const declared = draft.expected.find((asset: Json) => asset.name === request.name);
  if (!declared) return { status: 422, error: "asset_not_declared" };
  const stored = draft.uploaded[request.name];
  if (stored) {
    return stored.sha256 === request.x_content_sha256 && stored.size === request.content_length
      ? { status: 200 }
      : { status: 409, error: "asset_conflict" };
  }
  if (request.content_length !== declared.size || request.x_content_sha256 !== declared.sha256) {
    return { status: 422, error: "asset_mismatch" };
  }
  if (request.received.size !== declared.size || request.received.sha256 !== declared.sha256) {
    return { status: 422, error: "asset_mismatch" };
  }
  return { status: 201 };
}

test("publisher: uploads must match a declared asset by name, size and sha256", () => {
  for (const entry of publisherCases.upload) {
    assert.deepEqual(uploadDecision(entry.draft, entry.request), entry.expect, entry.name);
    assert.ok(responseFor("upload", entry.expect.status), entry.name);
    if (entry.expect.error) assert.ok(documentedErrors("upload", entry.expect.status).has(entry.expect.error), entry.name);
  }
  const put = spec.paths[`${FEED_PREFIX}/releases/{version}/assets/{name}`].put;
  const headers = put.parameters.filter((p: Json) => p.in === "header" && p.required).map((p: Json) => p.name);
  assert.ok(headers.includes("X-Content-SHA256") && headers.includes("Content-Length"), "upload declares size and hash up front");
});

function publishDecision(entry: Json): Json {
  const draft = entry.draft;
  if (draft.state === "none") return { status: 404, error: "draft_not_found" };
  if (draft.state !== "draft") return { status: 409, error: "not_a_draft" };
  const missing: string[] = [];
  const mismatched: string[] = [];
  for (const asset of draft.expected) {
    const stored = draft.uploaded[asset.name];
    if (!stored) missing.push(asset.name);
    else if (stored.size !== asset.size || stored.sha256 !== asset.sha256) mismatched.push(asset.name);
  }
  if (missing.length || mismatched.length) return { status: 422, error: "assets_incomplete", missing, mismatched };
  if (entry.quota === "exceeded") return { status: 422, error: "quota_exceeded" };
  if (draft.origin === "import") return { status: 200, action: "store_verbatim" };
  if (entry.signer !== "available") return { status: 503, error: "signer_unavailable" };
  return { status: 200, action: "sign" };
}

test("publisher: publish verifies the declared set, then quota, then signs or stores", () => {
  for (const entry of publisherCases.publish) {
    const got = publishDecision(entry);
    assert.deepEqual(got, entry.expect, entry.name);
    assert.ok(responseFor("publish", got.status), entry.name);
    if (got.error) {
      assert.ok(documentedErrors("publish", got.status).has(got.error), entry.name);
      const validate = responseValidator("publish", got.status);
      assert.ok(validate);
      const body =
        got.error === "quota_exceeded"
          ? { error: got.error, quota_bytes: 20_000_000_000, used_bytes: 19_000_000_000, required_bytes: 2_000_000_000 }
          : got.error === "assets_incomplete"
            ? { error: got.error, missing: got.missing, mismatched: got.mismatched }
            : { error: got.error };
      assert.ok(validate(body), `${entry.name}: ${JSON.stringify(validate.errors)}`);
    }
  }
});

/**
 * Step 4 of publish (hosted drafts only): after the asset-set and quota
 * checks and before signing, refuse a manifest whose RFC 8785 canonical bytes
 * exceed the signer's declared limit. null means the signer declares none.
 */
function publishSizeDecision(manifest: Json, maxCanonicalBytes: number | null): Json {
  const length = canonicalBytes(manifest).length;
  if (maxCanonicalBytes !== null && length > maxCanonicalBytes) {
    return { status: 422, error: "manifest_too_large", canonical_bytes: length, max_canonical_bytes: maxCanonicalBytes };
  }
  return { status: 200, action: "sign" };
}

test("publish: signer byte limit refuses before signing", () => {
  const AWSKMS_RAW_LIMIT = 4096;
  const stable = fixture("manifest/valid-stable.json");
  // The figure docs/desktop-feed.md quotes for the 8-asset fixture.
  assert.equal(canonicalBytes(stable).length, 1962);
  assert.equal(stable.assets.length, 8);
  assert.deepEqual(publishSizeDecision(stable, AWSKMS_RAW_LIMIT), { status: 200, action: "sign" });

  // 64 unique ids and names: the schema's ceiling, still a valid manifest.
  const assets = Array.from({ length: 64 }, (_, i) => {
    const asset = stable.assets[i % stable.assets.length];
    return { ...asset, id: `${asset.id}x${i}`, name: asset.name.replace(/(\.[^.]+)$/, `-r${i}$1`) };
  });
  const large = { ...stable, assets };
  assert.ok(validateManifest(large), JSON.stringify(validateManifest.errors));
  assert.equal(new Set(assets.map((a) => a.id)).size, 64);
  assert.equal(new Set(assets.map((a) => a.name)).size, 64);
  const refused = publishSizeDecision(large, AWSKMS_RAW_LIMIT);
  assert.equal(refused.status, 422);
  assert.equal(refused.error, "manifest_too_large");
  assert.ok(refused.canonical_bytes > AWSKMS_RAW_LIMIT, String(refused.canonical_bytes));
  assert.equal(refused.max_canonical_bytes, AWSKMS_RAW_LIMIT);
  assert.deepEqual(publishSizeDecision(large, null), { status: 200, action: "sign" });

  const validate = responseValidator("publish", 422);
  assert.ok(validate);
  const { status: _status, ...body } = refused;
  const withMessage = { ...body, message: "Manifest too large for the signer." };
  assert.ok(validate(body), JSON.stringify(validate.errors));
  assert.ok(component("DesktopFeedManifestTooLarge")(withMessage));

  // Documented on publish 422 only; import never signs.
  assert.ok(spec.components.schemas.DesktopFeedErrorCode.enum.includes("manifest_too_large"));
  const where: string[] = [];
  for (const [name, [method, path]] of Object.entries<Json>(requestCases.operations)) {
    for (const status of Object.keys(spec.paths[path][method].responses)) {
      if (documentedErrors(name, Number(status)).has("manifest_too_large")) where.push(`${name} ${status}`);
    }
  }
  assert.deepEqual(where, ["publish 422"]);
  for (const status of Object.keys(spec.paths[`${FEED_PREFIX}/releases/import`].post.responses)) {
    assert.ok(!documentedErrors("import", Number(status)).has("manifest_too_large"), `import ${status}`);
  }

  // Publishers can check ahead: the limit is always present in the listing.
  const limits = spec.components.schemas.DesktopFeedLimits;
  assert.ok(limits.required.includes("max_canonical_bytes"));
  const validateLimits = component("DesktopFeedLimits");
  const base = { quota_bytes: 20_000_000_000, used_bytes: 0, retention: { stable: "all", beta_keep: 10 } };
  const [withLimit, withNull, withZero] = [AWSKMS_RAW_LIMIT, null, 0].map((max) => ({ ...base, max_canonical_bytes: max }));
  assert.ok(validateLimits(withLimit));
  assert.ok(validateLimits(withNull));
  assert.ok(!validateLimits(withZero));
  assert.ok(!validateLimits(base), "max_canonical_bytes is required");
});

function quotaCheck(state: Json, release: Json): Json {
  const published: Json[] = state.published;
  const stableBytes = published.filter((r) => r.channel === "stable").reduce((n, r) => n + r.bytes, 0);
  const betas = published.filter((r) => r.channel === "beta");
  let kept = betas;
  let pruned: string[] = [];
  if (release.channel === "beta") {
    // This beta takes one of the beta_keep slots; older betas beyond it go.
    const keep = Math.max(state.beta_keep - 1, 0);
    kept = betas.slice(Math.max(betas.length - keep, 0));
    pruned = betas.slice(0, Math.max(betas.length - keep, 0)).map((r) => r.version);
  }
  const draftBytes = state.drafts.reduce((n: number, d: Json) => n + d.bytes, 0);
  const used = stableBytes + kept.reduce((n: number, r: Json) => n + r.bytes, 0) + draftBytes;
  if (used + release.bytes > state.quota_bytes) return { ok: false, used_bytes: used, required_bytes: release.bytes };
  return release.channel === "beta" ? { ok: true, used_bytes: used, pruned } : { ok: true, used_bytes: used };
}

test("publisher: quota and retention are deterministic", () => {
  for (const entry of publisherCases.quota) {
    assert.deepEqual(quotaCheck(entry.state, entry.release), entry.expect, entry.name);
    if (!entry.expect.ok) {
      const body = {
        error: "quota_exceeded",
        message: "Profile quota exceeded.",
        quota_bytes: entry.state.quota_bytes,
        used_bytes: entry.expect.used_bytes,
        required_bytes: entry.expect.required_bytes,
      };
      assert.ok(component("DesktopFeedQuotaExceeded")(body), entry.name);
    }
  }
  // Stables are never pruned, whatever the pressure.
  for (const entry of publisherCases.quota) {
    for (const version of quotaCheck(entry.state, entry.release).pruned ?? []) {
      assert.ok(version.includes("-beta."), `${entry.name}: only betas are pruned`);
    }
  }
  for (const op of ["create_draft", "import", "publish"]) {
    assert.ok(documentedErrors(op, 422).has("quota_exceeded"), `${op} 422 quota_exceeded`);
    assert.equal(responseFor(op, 507), undefined, `${op} never uses 507`);
  }
});

/* ------------------------------------------------------------- transport */

function rangeDecision(range: string | null, size: number, ifRange: string | null): { status: number; contentRange?: string; length?: number } {
  if (!range || (ifRange !== null && ifRange !== "etag")) return { status: 200, length: size };
  const match = /^bytes=([0-9]*)-([0-9]*)$/.exec(range);
  if (!match) return { status: 416, contentRange: `bytes */${size}` };
  const [, startText = "", endText = ""] = match;
  let start: number;
  let end: number;
  if (startText === "") {
    const suffix = Number(endText);
    if (endText === "" || suffix === 0) return { status: 416, contentRange: `bytes */${size}` };
    start = Math.max(size - suffix, 0);
    end = size - 1;
  } else {
    start = Number(startText);
    end = endText === "" ? size - 1 : Math.min(Number(endText), size - 1);
    if (start >= size || start > end) return { status: 416, contentRange: `bytes */${size}` };
  }
  return { status: 206, contentRange: `bytes ${start}-${end}/${size}`, length: end - start + 1 };
}

test("transport: a single Range is 206, anything else unsatisfiable is 416", () => {
  for (const entry of transportCases.range) {
    const got = rangeDecision(entry.range, entry.size, entry.if_range ?? null);
    assert.equal(got.status, entry.expect.status, entry.name);
    if (entry.expect.content_range) assert.equal(got.contentRange, entry.expect.content_range, entry.name);
    if (entry.expect.content_length) assert.equal(got.length, entry.expect.content_length, entry.name);
    assert.ok(responseFor("asset", got.status), `${entry.name}: documented`);
  }
  const stream = spec.paths[`${FEED_PREFIX}/assets/{assetId}`].get;
  assert.ok(stream.responses["206"].headers["Content-Range"]);
  assert.ok(stream.responses["416"].headers["Content-Range"]);
  assert.ok(stream.responses["200"].headers["ETag"]);
  assert.equal(stream["x-desktop-feed-redirects"], "never");
});

function clientAcceptsUrl(url: string, site: string, downloadHosts: string[]): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:" || parsed.port !== "" || parsed.username !== "" || parsed.password !== "") return false;
  if (parsed.hostname === site) return parsed.pathname.startsWith(`${FEED_PREFIX}/assets/`);
  return downloadHosts.includes(parsed.hostname);
}

test("transport: the download host rule and no redirects", () => {
  for (const entry of transportCases.download_host) {
    assert.equal(clientAcceptsUrl(entry.url, entry.site, entry.download_hosts), entry.expect === "accept", entry.name);
  }
  for (const entry of transportCases.redirect) {
    const accepted = !(entry.status >= 300 && entry.status < 400);
    assert.equal(accepted, entry.expect === "accept", entry.name);
  }
  for (const { method, path, op } of feedOperations()) {
    for (const status of Object.keys(op.responses)) assert.ok(!status.startsWith("3"), `${method} ${path} documents no ${status}`);
  }
});

/* ------------------------------------------------------- response bodies */

test("response bodies: valid bodies match, invalid ones do not", () => {
  for (const entry of apiBodies.bodies) {
    const body = JSON.parse(JSON.stringify(entry.body).replaceAll("$RUNTIME_INSTALL_TOKEN", SAMPLE_INSTALL_TOKEN));
    const validate = responseFor(entry.op, entry.status) ? responseValidator(entry.op, entry.status) : undefined;
    const ok = validate ? validate(body) === true : false;
    assert.equal(ok, entry.valid, `${entry.name}: ${JSON.stringify(validate?.errors)}`);
  }
  assert.match(SAMPLE_INSTALL_TOKEN, new RegExp(spec.components.schemas.DesktopFeedInstallTokenIssued.properties.token.pattern));
});

/* ------------------------------------------------------- OpenAPI coverage */

test("coverage: every feed operation requires X-Agent-Relay-Profile and is marked proposed", () => {
  const operations = feedOperations();
  assert.equal(operations.length, 11);
  const profileParam = spec.components.parameters.DesktopFeedProfile;
  assert.equal(profileParam.name, "X-Agent-Relay-Profile");
  assert.equal(profileParam.in, "header");
  assert.equal(profileParam.required, true);
  for (const { method, path, op } of operations) {
    const label = `${method} ${path}`;
    const params = (op.parameters ?? []).map((p: Json) => (p.$ref ? spec.components.parameters[p.$ref.split("/").pop()] : p));
    assert.ok(params.some((p: Json) => p.name === "X-Agent-Relay-Profile" && p.in === "header" && p.required === true), `${label}: profile header`);
    assert.equal(op["x-status"], "proposed", label);
    assert.ok(op.tags.includes("Desktop feed (draft contract)"), label);
    assert.match(op.description, /Status: proposed, Cloud team decides, not yet confirmed/, label);
    assert.ok(op.responses["429"], `${label}: 429`);
    const rateLimited = resolveResponse(op.responses["429"]);
    assert.equal(rateLimited.headers["Retry-After"].required, true, `${label}: Retry-After`);
  }
});

test("coverage: read endpoints answer 403 not_entitled and never 404 for a profile", () => {
  const operations = feedOperations();
  const reads = operations.filter(({ op }) => op["x-desktop-feed-role"] === "read");
  assert.deepEqual(new Set(reads.map(({ method, path }) => `${method} ${path}`)), READ_OPS);
  const opName = (method: string, path: string): string =>
    Object.entries<Json>(requestCases.operations).find(([, [m, p]]) => m === method && p === path)![0];
  for (const { method, path, op } of reads) {
    const label = `${method} ${path}`;
    assert.ok(documentedErrors(opName(method, path), 403).has("not_entitled"), `${label}: 403 not_entitled`);
    const notFound = op.responses["404"];
    if (notFound) {
      const codes = documentedErrors(opName(method, path), 404);
      assert.deepEqual([...codes], ["no_release"], `${label}: 404 only for a channel with no release`);
      assert.ok(!/unknown profile|not bound/i.test(resolveResponse(notFound).description.replace(/Never used for an unknown or unbound profile\./, "")), label);
    }
  }
  // 404 no_release only on the two channel reads.
  const with404 = reads.filter(({ op }) => op.responses["404"]).map(({ method, path }) => `${method} ${path}`);
  assert.deepEqual(with404.sort(), [`get ${FEED_PREFIX}/manifest`, `get ${FEED_PREFIX}/releases`]);
  const downloadUrl = spec.paths[`${FEED_PREFIX}/assets/{assetId}/download-url`].post;
  assert.ok(documentedErrors("download_url", 501).has("no_object_storage"), downloadUrl.operationId);
});

test("coverage: credentials, security schemes and the error-code enum agree", () => {
  const schemeFor: Record<string, string> = {
    workspaceBearer: "bearerAuth",
    installToken: "installToken",
    browserSession: "cookieAuth",
    publisherToken: "publisherToken",
  };
  assert.ok(spec.components.securitySchemes.installToken);
  assert.ok(spec.components.securitySchemes.publisherToken);
  const enumCodes = new Set<string>(spec.components.schemas.DesktopFeedErrorCode.enum);
  const opNames = Object.entries<Json>(requestCases.operations);
  for (const { method, path, op } of feedOperations()) {
    const label = `${method} ${path}`;
    const kinds: string[] = op["x-desktop-feed-credentials"];
    const security = op.security.map((s: Json) => Object.keys(s)).flat().sort();
    assert.deepEqual(security, kinds.map((k) => schemeFor[k]).sort(), `${label}: security matches x-desktop-feed-credentials`);
    const role = op["x-desktop-feed-role"];
    if (role === "publisher") assert.deepEqual(kinds, ["publisherToken"], label);
    if (role === "read") assert.ok(!kinds.includes("publisherToken") || path.endsWith("/releases"), `${label}: publisher token is not a read credential`);
    const name = opNames.find(([, [m, p]]) => m === method && p === path)?.[0];
    assert.ok(name, label);
    for (const status of Object.keys(op.responses)) {
      for (const code of documentedErrors(name, Number(status))) assert.ok(enumCodes.has(code), `${label} ${status}: ${code} in enum`);
    }
  }
  // Every enum code is used by at least one operation.
  const used = new Set<string>();
  for (const [name, [method, path]] of opNames) {
    for (const status of Object.keys(spec.paths[path][method].responses)) documentedErrors(name, Number(status)).forEach((c) => used.add(c));
  }
  for (const code of enumCodes) assert.ok(used.has(code), `${code} is used`);
});

test("coverage: the signer is unresolved and there is no stored-key fallback", () => {
  const tag = spec.tags.find((t: Json) => t.name === "Desktop feed (draft contract)");
  assert.equal(tag["x-status"], "proposed");
  assert.equal(tag["x-signer-provider"]["x-status"], "unresolved");
  const publish = spec.paths[`${FEED_PREFIX}/releases/{version}/publish`].post;
  assert.equal(publish["x-signer-provider"]["x-status"], "unresolved");
  assert.match(spec.info.description, /Ed25519/);
  assert.match(spec.info.description, /RFC 8785/);
  const feedText = JSON.stringify([tag, ...feedOperations().map(({ op }) => op)]);
  // Postgres may be named only to say a key stored there is not accepted.
  const postgresSentences = feedText.replace(/\\n/g, " ").split(/\.\s/).filter((s) => /postgres/i.test(s));
  assert.ok(postgresSentences.length > 0);
  for (const sentence of postgresSentences) assert.match(sentence, /\bnot\b/, sentence);
  for (const { op } of feedOperations()) {
    for (const name of Object.keys(op["x-signer-provider"] ?? {})) assert.notEqual(name, "fallback");
  }
});
