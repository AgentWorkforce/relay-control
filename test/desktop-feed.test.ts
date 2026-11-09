// Desktop feed end to end: profile registration and binding, publisher
// tokens, draft -> upload -> publish, reads with a cli:auth bearer, the /cloud
// session cookie and an install token, every refusal branch, profile
// isolation, and the embedded schemas against docs/specs and openapi.yaml.
import assert from "node:assert/strict";
import { createHash, createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer, get as httpGet, type IncomingMessage } from "node:http";
import { PassThrough, Readable } from "node:stream";
import test, { type TestContext } from "node:test";
import { Ajv2020 } from "ajv/dist/2020.js";
import addFormatsModule from "ajv-formats";
import { parse as parseYaml } from "yaml";
import { ApiTokenStore } from "../src/admin/api-tokens.js";
import { createApp } from "../src/app.js";
import type { SelfhostConfig } from "../src/config.js";
import { canonicalBytes } from "../src/desktop-feed/canonical.js";
import { strictParse } from "../src/desktop-feed/strict-json.js";
import { DESKTOP_FEED_LIMITS, envelopeText, rangeDecision, type DesktopFeedLimits } from "../src/desktop-feed/routes.js";
import { DRAFT_CREATE_SCHEMA, ENVELOPE_SCHEMA, MANIFEST_SCHEMA } from "../src/desktop-feed/schemas.js";
import {
  AwsKmsDesktopFeedSigner,
  MemoryDesktopFeedSigner,
  publicKeyFromRaw,
  SignerUnavailableError,
  type DesktopFeedSigner,
} from "../src/desktop-feed/signer.js";
import { MemoryDesktopFeedStorage, type ByteRange, type DesktopFeedStorage } from "../src/desktop-feed/storage.js";
import { StaticAwsCredentialProvider } from "../src/aws/sigv4.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase } from "./support/harness.js";

const addFormats = addFormatsModule as unknown as typeof addFormatsModule.default;
const ROOT = new URL("../", import.meta.url);
const PUBLIC_ORIGIN = "https://control.internal.example";
const FEED = "/api/v1/desktop/feed";
type Json = any;

/* ------------------------------------------------------------ openapi */

const spec: Json = parseYaml(readFileSync(new URL("openapi.yaml", ROOT), "utf8"));
const OPENAPI_ID = "urn:relaycontrol:openapi";
const openapiAjv = new Ajv2020({ strict: false, allErrors: true });
addFormats(openapiAjv);
openapiAjv.addSchema({
  $id: OPENAPI_ID,
  components: {
    schemas: Object.fromEntries(Object.entries(spec.components.schemas as Record<string, Json>)
      .filter(([name]) => name.startsWith("DesktopFeed"))),
  },
});
const validators = new Map<string, ReturnType<typeof openapiAjv.compile>>();
function conforms(name: string, body: unknown): void {
  let validate = validators.get(name);
  if (!validate) {
    validate = openapiAjv.compile({ $ref: `${OPENAPI_ID}#/components/schemas/${name}` });
    validators.set(name, validate);
  }
  assert.ok(validate(body), `${name}: ${JSON.stringify(validate.errors)} for ${JSON.stringify(body)}`);
}
const ERROR_SCHEMA: Record<string, string> = {
  assets_incomplete: "DesktopFeedAssetsIncomplete",
  quota_exceeded: "DesktopFeedQuotaExceeded",
  manifest_too_large: "DesktopFeedManifestTooLarge",
  rate_limited: "DesktopFeedRateLimitedError",
};

/* ---------------------------------------------------- test doubles */

/** The memory signer with switches for the 503 and 422 manifest_too_large branches. */
class SwitchSigner implements DesktopFeedSigner {
  readonly kind = "memory" as const;
  readonly inner = new MemoryDesktopFeedSigner({ label: "dev" });
  down = false;
  max: number | null = null;
  keyId(profile: string) { return this.inner.keyId(profile); }
  async sign(profile: string, bytes: Buffer) {
    if (this.down) throw new SignerUnavailableError("signer down");
    return this.inner.sign(profile, bytes);
  }
  async publicKey(profile: string) { return this.inner.publicKey(profile); }
  maxCanonicalBytes() { return this.max; }
  unknownProfiles = new Set<string>();
  hasProfile(profile: string) { return !this.unknownProfiles.has(profile); }
}

/** Memory storage that can pretend to be an object store with a download host. */
class SwitchStorage implements DesktopFeedStorage {
  readonly kind = "memory" as const;
  readonly inner = new MemoryDesktopFeedStorage();
  host: string | null = null;
  /** When set, streams are handed out here and only finish when the test ends them. */
  held: PassThrough[] | null = null;
  put(key: string, body: Readable, size: number, sha256: string) { return this.inner.put(key, body, size, sha256); }
  async get(key: string, range?: ByteRange): Promise<Readable | null> {
    const stream = await this.inner.get(key, range);
    if (!stream || !this.held) return stream;
    const held = new PassThrough();
    held.write(Buffer.concat(await stream.toArray()));
    this.held.push(held);
    return held;
  }
  copy(sourceKey: string, destinationKey: string) { return this.inner.copy(sourceKey, destinationKey); }
  delete(key: string) { return this.inner.delete(key); }
  downloadHost() { return this.host; }
  async presignGet(key: string, expiresSeconds: number) {
    return this.host ? new URL(`https://${this.host}/${key}?X-Amz-Expires=${expiresSeconds}`) : null;
  }
}

/* ------------------------------------------------------------- setup */

type CallOptions = {
  method?: string;
  token?: string;
  cookie?: string;
  profile?: string;
  body?: unknown;
  raw?: string | Buffer;
  stream?: Readable;
  headers?: Record<string, string>;
};
type Reply = { status: number; text: string; json: Json; headers: Headers };

async function setup(
  t: TestContext,
  options: {
    feed?: boolean;
    limits?: Partial<DesktopFeedLimits>;
    signer?: DesktopFeedSigner;
    publisherTokenHashes?: Record<string, string[]>;
  } = {},
) {
  const database = new PGliteDatabase();
  await migrate(database);
  const config: SelfhostConfig = {
    databaseUrl: "unused-in-test",
    publicBaseUrl: PUBLIC_ORIGIN,
    relaycastUrl: "http://relaycast.internal",
    relaycastPublicUrl: "https://cast.selfhosted.example",
    relayhistoryUrl: "http://relayhistory.internal",
    relayhistoryPublicUrl: "https://history.selfhosted.test",
    sessionReadApi: { url: "http://relayhistory.internal", publicUrl: "https://history.selfhosted.test", secret: "session-read-secret-".repeat(2) },
    bootstrapToken: "bootstrap-token-that-is-at-least-32-bytes",
    encryptionKeyring: { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    internalServiceToken: "service-token-that-is-at-least-32-bytes",
    oauthRedirectUrl: `${PUBLIC_ORIGIN}/api/v1/integrations/oauth/callback`,
    dashboardUrl: `${PUBLIC_ORIGIN}/`,
    port: 3000,
    host: "127.0.0.1",
    desktopFeed: options.feed === false ? null : {
      signer: { kind: "memory", label: "dev" }, storage: { kind: "memory" }, publisherTokenHashes: options.publisherTokenHashes,
    },
  };
  const signer = new SwitchSigner();
  const storage = new SwitchStorage();
  let clock = new Date("2026-11-07T10:00:00.000Z");
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  const logs: Array<{ message: string; fields: Record<string, unknown> }> = [];
  const server = createServer(createApp({
    config, store, now: () => clock, desktopFeed: {
      signer: options.signer ?? signer, storage, limits: options.limits, log: (message, fields) => logs.push({ message, fields }),
    },
  }));
  const origin = await listen(server);
  t.after(async () => {
    await close(server);
    await database.close();
  });

  async function call(path: string, opts: CallOptions = {}): Promise<Reply> {
    const headers: Record<string, string> = { ...opts.headers };
    if (opts.token) headers.authorization = `Bearer ${opts.token}`;
    if (opts.cookie) headers.cookie = `agent_relay_session=${opts.cookie}`;
    if (opts.profile) headers["x-agent-relay-profile"] = opts.profile;
    let body: BodyInit | undefined;
    if (opts.stream) body = Readable.toWeb(opts.stream) as unknown as BodyInit;
    else if (opts.raw !== undefined) body = opts.raw as BodyInit;
    else if (opts.body !== undefined) {
      body = JSON.stringify(opts.body);
      headers["content-type"] ??= "application/json";
    }
    const response = await fetch(`${origin}${path}`, {
      method: opts.method ?? (body === undefined ? "GET" : "POST"),
      headers,
      body,
      ...(opts.stream ? { duplex: "half" } : {}),
    } as RequestInit);
    const text = Buffer.from(await response.arrayBuffer()).toString("utf8");
    let json: Json = null;
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
    // Every feed error body conforms to the OpenAPI error schemas.
    // Router-level replies (unknown route, body over the cap) keep the app's shared codes.
    if (response.status >= 400 && path.includes("/desktop/feed/") && json && typeof json.error === "string"
      && !["not_found", "payload_too_large", "internal"].includes(json.error)) {
      conforms(ERROR_SCHEMA[json.error] ?? "DesktopFeedError", json);
      assert.equal(response.headers.get("cache-control"), "no-store");
    }
    return { status: response.status, text, json, headers: response.headers };
  }
  const boot = config.bootstrapToken;
  const post = (path: string, body: unknown, token = boot) => call(path, { token, body });

  const org = await post("/api/v1/organizations", { name: "Tenant", ownerEmail: "owner@example.test", ownerName: "Owner" });
  assert.equal(org.status, 201);
  const orgId = org.json.id as string;
  const ownerId = org.json.owner.id as string;
  const w1 = await post(`/api/v1/organizations/${orgId}/workspaces`, {
    name: "Primary", relaycastWorkspaceId: "rc-first", relaycastApiKey: "rk_live_first",
  });
  assert.equal(w1.status, 201);
  const w2 = await post(`/api/v1/organizations/${orgId}/workspaces`, {
    name: "Other", relaycastWorkspaceId: "rc-other", relaycastApiKey: "rk_live_other",
  });
  assert.equal(w2.status, 201);
  const member = await post(`/api/v1/organizations/${orgId}/memberships`, { email: "member@example.test", name: "Member", role: "member" });
  assert.equal(member.status, 200);

  async function session(userId: string, workspaceId: string): Promise<string> {
    const started = await post("/api/v1/auth/device/start", { client_name: "feed-test" });
    assert.equal(started.status, 201);
    const approved = await post("/api/v1/auth/device/approve", {
      action: "approve", user_code: started.json.user_code, user_id: userId, workspace_id: workspaceId,
    });
    assert.equal(approved.status, 200);
    const tokens = await post("/api/v1/auth/device/token", { device_code: started.json.device_code });
    assert.equal(tokens.status, 200);
    return tokens.json.access_token as string;
  }

  return {
    origin, config, database, signer, storage, logs, call, post, orgId, ownerId,
    w1: w1.json.id as string,
    w2: w2.json.id as string,
    memberId: member.json.userId as string,
    session,
    setClock: (next: Date) => { clock = next; },
    clock: () => clock,
  };
}

type World = Awaited<ReturnType<typeof setup>>;

function sha(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

const BYTES = {
  dmg: Buffer.from("macOS arm64 disk image bytes"),
  appimage: Buffer.from("Linux x64 AppImage bytes!"),
  script: Buffer.from("#!/bin/sh\necho install\n"),
};

function declared(name: string, platform: string, arch: string, kind: string, bytes: Buffer, osFloor?: number) {
  return { name, platform, arch, ...(osFloor ? { os_floor: osFloor } : {}), kind, size: bytes.length, sha256: sha(bytes) };
}

function draftBody(prefix: string, version: string, channel = "stable") {
  return {
    version,
    channel,
    notes: `Release ${version}`,
    expected_assets: [
      declared(`${prefix}-${version}-arm64.dmg`, "macOS", "arm64", "image", BYTES.dmg, 13),
      declared(`${prefix}-${version}-x86_64.AppImage`, "Linux", "x64", "image", BYTES.appimage),
      declared("install.sh", "Linux", "x64", "install-script", BYTES.script),
    ],
  };
}

const BYTES_BY_INDEX = [BYTES.dmg, BYTES.appimage, BYTES.script];

/** Admin: create a profile, bind a workspace, mint a publisher token. */
async function provision(world: World, id: string, prefix: string, workspaceId: string, extra: Record<string, unknown> = {}) {
  const base = `/api/v1/organizations/${world.orgId}/desktop-feed/profiles`;
  const created = await world.post(base, { id, asset_prefix: prefix, ...extra });
  assert.equal(created.status, 201, created.text);
  const bound = await world.call(`${base}/${id}/workspaces/${workspaceId}`, { method: "PUT", token: world.config.bootstrapToken });
  assert.equal(bound.status, 200, bound.text);
  const minted = await world.post(`${base}/${id}/publisher-tokens`, { label: "ci" });
  assert.equal(minted.status, 201, minted.text);
  return { profile: created.json, publisher: minted.json.token as string };
}

/** Publisher: create the draft, upload every asset, publish. */
async function release(world: World, profile: string, publisher: string, prefix: string, version: string, channel = "stable", latest = true) {
  const body = draftBody(prefix, version, channel);
  const draft = await world.call(`${FEED}/releases`, { token: publisher, profile, body });
  assert.equal(draft.status, 201, draft.text);
  for (const [index, entry] of body.expected_assets.entries()) {
    const uploaded = await world.call(`${FEED}/releases/${version}/assets/${entry.name}`, {
      method: "PUT", token: publisher, profile, raw: BYTES_BY_INDEX[index]!, headers: { "x-content-sha256": entry.sha256 },
    });
    assert.equal(uploaded.status, 201, uploaded.text);
  }
  const published = await world.call(`${FEED}/releases/${version}/publish`, { token: publisher, profile, body: { latest } });
  assert.equal(published.status, 200, published.text);
  return published;
}

function verifyEnvelope(envelope: Json, rawPublicKey: string): boolean {
  const key = createPublicKey({
    key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), Buffer.from(rawPublicKey, "base64")]),
    format: "der",
    type: "spki",
  });
  return edVerify(null, canonicalBytes(envelope.manifest), key, Buffer.from(envelope.signature, "base64url"));
}

/* -------------------------------------------------------------- tests */

test("embedded schemas equal docs/specs and the OpenAPI draft-create component", () => {
  const read = (name: string) => JSON.parse(readFileSync(new URL(`docs/specs/${name}`, ROOT), "utf8"));
  assert.deepEqual(MANIFEST_SCHEMA, read("desktop-feed-manifest.schema.json"));
  assert.deepEqual(ENVELOPE_SCHEMA, read("desktop-feed-envelope.schema.json"));
  const strip = (value: Json): Json => Array.isArray(value)
    ? value.map(strip)
    : value && typeof value === "object"
      ? Object.fromEntries(Object.entries(value).filter(([key]) => !key.startsWith("x-")).map(([key, x]) => [key, strip(x)]))
      : value;
  const asset = strip(spec.components.schemas.DesktopFeedExpectedAsset);
  delete asset.description;
  const create = strip(spec.components.schemas.DesktopFeedDraftCreate);
  create.properties.expected_assets.items = asset;
  assert.deepEqual(DRAFT_CREATE_SCHEMA, {
    $schema: "https://json-schema.org/draft/2020-12/schema",
    $id: "urn:agent-relay:desktop-feed:draft-create:1",
    ...create,
  });
  // The manifest the OpenAPI document serves is the spec file.
  conforms("DesktopFeedManifest", JSON.parse(readFileSync(new URL("test/fixtures/desktop-feed/manifest/valid-stable.json", ROOT), "utf8")));
});

test("limits match docs/desktop-feed.md; range and envelope helpers", () => {
  assert.deepEqual(DESKTOP_FEED_LIMITS, {
    reads: { limit: 60, windowMs: 60_000 },
    downloadUrl: { limit: 30, windowMs: 60_000 },
    streamStarts: { limit: 30, windowMs: 60_000 },
    streamConcurrent: 4,
    publisher: { limit: 600, windowMs: 60_000 },
    installTokenMint: { limit: 10, windowMs: 3_600_000 },
    unauthenticated: { limit: 60, windowMs: 60_000 },
  });
  const etag = '"abc"';
  assert.deepEqual(rangeDecision(undefined, 10, undefined, etag), { status: 200 });
  assert.deepEqual(rangeDecision("bytes=2-4", 10, undefined, etag), { status: 206, range: { start: 2, end: 4 } });
  assert.deepEqual(rangeDecision("bytes=-3", 10, undefined, etag), { status: 206, range: { start: 7, end: 9 } });
  assert.deepEqual(rangeDecision("bytes=8-", 10, undefined, etag), { status: 206, range: { start: 8, end: 9 } });
  assert.deepEqual(rangeDecision("bytes=8-100", 10, undefined, etag), { status: 206, range: { start: 8, end: 9 } });
  assert.deepEqual(rangeDecision("bytes=10-", 10, undefined, etag), { status: 416 });
  assert.deepEqual(rangeDecision("bytes=5-2", 10, undefined, etag), { status: 416 });
  assert.deepEqual(rangeDecision("bytes=0-1,4-5", 10, undefined, etag), { status: 416 });
  assert.deepEqual(rangeDecision("bytes=2-4", 10, '"other"', etag), { status: 200 });
  assert.deepEqual(rangeDecision("bytes=2-4", 10, etag, etag), { status: 206, range: { start: 2, end: 4 } });
  assert.equal(envelopeText(' { "envelope" : {"a":[1,{"b":"}"}]} } '), '{"a":[1,{"b":"}"}]}');
});

test("feature off: every feed and feed-admin route is 404", async (t) => {
  const world = await setup(t, { feed: false });
  const manifest = await world.call(`${FEED}/manifest?channel=stable`, { token: world.config.bootstrapToken, profile: "acme" });
  assert.equal(manifest.status, 404);
  const admin = await world.post(`/api/v1/organizations/${world.orgId}/desktop-feed/profiles`, { id: "acme", asset_prefix: "Acme" });
  assert.equal(admin.status, 404);
});

test("profile admin: registration, binding, publisher tokens", async (t) => {
  const world = await setup(t);
  const base = `/api/v1/organizations/${world.orgId}/desktop-feed/profiles`;
  const ownerToken = await world.session(world.ownerId, world.w1);
  const memberToken = await world.session(world.memberId, world.w1);

  // Org admin (a user session) and bootstrap may register; a member may not.
  assert.equal((await world.post(base, { id: "acme", asset_prefix: "Acme" }, memberToken)).status, 403);
  const created = await world.post(base, { id: "acme", asset_prefix: "Acme" }, ownerToken);
  assert.equal(created.status, 201, created.text);
  assert.equal(created.json.quota_bytes, 20_000_000_000);
  assert.equal(created.json.beta_keep, 10);
  assert.equal(created.json.signing_key.key_id, "fk_acme_dev");
  assert.equal(Buffer.from(created.json.signing_key.public_key, "base64").length, 32);
  assert.equal((await world.post(base, { id: "acme", asset_prefix: "Acme" })).json.error, "profile_exists");
  for (const bad of [
    { id: "Acme", asset_prefix: "Acme" },
    { id: "zeta", asset_prefix: "-bad" },
    { id: "zeta", asset_prefix: "Z", quota_bytes: -1 },
    { id: "zeta", asset_prefix: "Z", beta_keep: 0 },
    { id: "zeta", asset_prefix: "Z", public_keys: [{ key_id: "fk_other_x", public_key: "A".repeat(43) + "=" }] },
    { id: "zeta", asset_prefix: "Z", extra: true },
  ]) {
    assert.equal((await world.post(base, bad)).status, 400, JSON.stringify(bad));
  }
  const listed = await world.call(base, { token: world.config.bootstrapToken });
  assert.deepEqual(listed.json.profiles.map((p: Json) => p.id), ["acme"]);
  assert.equal((await world.call(`${base}/nope`, { token: ownerToken })).json.error, "profile_not_found");

  // Binding: a workspace of this organization only.
  const unknownWorkspace = await world.call(`${base}/acme/workspaces/00000000-0000-4000-8000-000000000000`, {
    method: "PUT", token: world.config.bootstrapToken,
  });
  assert.equal(unknownWorkspace.json.error, "workspace_not_found");
  const bound = await world.call(`${base}/acme/workspaces/${world.w1}`, { method: "PUT", token: world.config.bootstrapToken });
  assert.deepEqual(bound.json.workspaces, [world.w1]);

  // Publisher tokens: shown once, stored hashed, two active at most.
  const first = await world.post(`${base}/acme/publisher-tokens`, { label: "ci-1" });
  assert.equal(first.status, 201);
  assert.match(first.json.token, /^sh_dfp_[A-Za-z0-9_-]{43}$/);
  assert.equal(first.json.token_prefix, first.json.token.slice(0, 11));
  assert.equal(first.headers.get("cache-control"), "no-store");
  const second = await world.post(`${base}/acme/publisher-tokens`, { label: "ci-2" });
  const third = await world.post(`${base}/acme/publisher-tokens`, { label: "ci-3" });
  const detail = await world.call(`${base}/acme`, { token: world.config.bootstrapToken });
  for (const minted of [first, second, third]) assert.ok(!detail.text.includes(minted.json.token));
  const statuses = Object.fromEntries(detail.json.publisher_tokens.map((row: Json) => [row.label, row.status]));
  assert.deepEqual(statuses, { "ci-1": "revoked", "ci-2": "active", "ci-3": "active" });
  const stored = await world.database.query<{ token_hash: string }>(
    "SELECT token_hash FROM desktop_feed_publisher_tokens WHERE id = $1", [third.json.id],
  );
  assert.equal(stored.rows[0]!.token_hash, sha(Buffer.from(third.json.token)));
  const firstUse = await world.call(`${FEED}/releases?include_drafts=true`, { token: first.json.token, profile: "acme" });
  assert.equal(firstUse.json.error, "token_revoked");
  const revoked = await world.call(`${base}/acme/publisher-tokens/${third.json.id}`, { method: "DELETE", token: world.config.bootstrapToken });
  assert.equal(revoked.json.status, "revoked");
  assert.equal((await world.call(`${FEED}/releases?include_drafts=true`, { token: third.json.token, profile: "acme" })).status, 401);
  // Revoking again is idempotent; an unknown id is 404.
  assert.equal((await world.call(`${base}/acme/publisher-tokens/${third.json.id}`, {
    method: "DELETE", token: world.config.bootstrapToken,
  })).json.status, "revoked");
  assert.equal((await world.call(`${base}/acme/publisher-tokens/00000000-0000-4000-8000-000000000000`, {
    method: "DELETE", token: world.config.bootstrapToken,
  })).json.error, "publisher_token_not_found");

  const unbound = await world.call(`${base}/acme/workspaces/${world.w1}`, { method: "DELETE", token: world.config.bootstrapToken });
  assert.deepEqual(unbound.json.workspaces, []);
  const audit = await world.database.query<{ action: string }>(
    "SELECT action FROM admin_audit_events WHERE action LIKE 'desktop_feed.%' ORDER BY created_at",
  );
  assert.ok(audit.rows.some((row) => row.action === "desktop_feed.profile_create"));
  assert.ok(audit.rows.some((row) => row.action === "desktop_feed.workspace_unbind"));
});

test("profile admin: cookie writes need an allowed Origin; members are refused every write", async (t) => {
  const world = await setup(t);
  const boot = world.config.bootstrapToken;
  const base = `/api/v1/organizations/${world.orgId}/desktop-feed/profiles`;
  const cloud = `/cloud${base}`;
  const owner = await world.session(world.ownerId, world.w1);
  const member = await world.session(world.memberId, world.w1);
  assert.equal((await world.post(base, { id: "acme", asset_prefix: "Acme" })).status, 201);
  assert.equal((await world.call(`${base}/acme/workspaces/${world.w1}`, { method: "PUT", token: boot })).status, 200);
  const mint = `${cloud}/acme/publisher-tokens`;
  const evil = "https://evil.example";

  // The /cloud session cookie of an org owner: no Origin, an evil Origin -> 403; the site's Origin -> 201.
  for (const headers of [{}, { origin: evil }] as Array<Record<string, string>>) {
    const refused = await world.call(mint, { cookie: owner, body: { label: "x" }, headers });
    assert.equal(refused.status, 403, refused.text);
    assert.equal(refused.json.error, "csrf_rejected");
  }
  const allowed = await world.call(mint, { cookie: owner, body: { label: "cookie" }, headers: { origin: PUBLIC_ORIGIN } });
  assert.equal(allowed.status, 201, allowed.text);
  // The cookie still reads without an Origin (GET is not checked).
  assert.equal((await world.call(`${cloud}/acme`, { cookie: owner })).status, 200);
  // A bearer is not CSRF-able: an evil Origin does not matter.
  const bearerMint = await world.call(`${base}/acme/publisher-tokens`, { token: owner, body: { label: "bearer" }, headers: { origin: evil } });
  assert.equal(bearerMint.status, 201, bearerMint.text);

  // DELETE binding over the cookie.
  const binding = `${cloud}/acme/workspaces/${world.w1}`;
  const json = { "content-type": "application/json" };
  const unbindEvil = await world.call(binding, { cookie: owner, method: "DELETE", headers: { ...json, origin: evil } });
  assert.equal(unbindEvil.status, 403, unbindEvil.text);
  assert.equal(unbindEvil.json.error, "csrf_rejected");
  const stillBound = await world.call(`${base}/acme`, { token: boot });
  assert.deepEqual(stillBound.json.workspaces, [world.w1]);
  const unbind = await world.call(binding, { cookie: owner, method: "DELETE", headers: { ...json, origin: PUBLIC_ORIGIN } });
  assert.equal(unbind.status, 200, unbind.text);
  assert.deepEqual(unbind.json.workspaces, []);

  // A plain member (bearer, so CSRF is not what refuses it) may not mint, bind or revoke.
  const forbidden = async (path: string, options: CallOptions) => {
    const reply = await world.call(path, { token: member, ...options });
    assert.equal(reply.status, 403, `${path}: ${reply.text}`);
    assert.equal(reply.json.error, "forbidden");
  };
  await forbidden(`${base}/acme/publisher-tokens`, { body: { label: "m" } });
  await forbidden(`${base}/acme/workspaces/${world.w1}`, { method: "PUT" });
  await forbidden(`${base}/acme/workspaces/${world.w1}`, { method: "DELETE" });
  await forbidden(`${base}/acme/publisher-tokens/${allowed.json.id}`, { method: "DELETE" });
  const detail = await world.call(`${base}/acme`, { token: boot });
  assert.deepEqual(detail.json.workspaces, []);
  const statuses = Object.fromEntries(detail.json.publisher_tokens.map((row: Json) => [row.label, row.status]));
  assert.deepEqual(statuses, { cookie: "active", bearer: "active" });
});

test("signer failure: a KMS error is 503 signer_unavailable and logged without the manifest", async (t) => {
  const kms = createServer((request, response) => {
    request.resume();
    request.on("end", () => {
      response.writeHead(400, { "content-type": "application/x-amz-json-1.1" });
      response.end(JSON.stringify({ __type: "com.amazonaws.kms#AccessDeniedException", message: "not allowed" }));
    });
  });
  const kmsOrigin = await listen(kms);
  t.after(() => close(kms));
  const signer = new AwsKmsDesktopFeedSigner({
    region: "eu-west-2",
    keyAliases: { acme: "alias/desktop-feed-acme" },
    label: "k1",
    credentials: new StaticAwsCredentialProvider({ accessKeyId: "AKIDFEEDTEST", secretAccessKey: "feed-test-secret" }),
    endpoint: `${kmsOrigin}/`,
  });
  const world = await setup(t, { signer });
  const { publisher } = await provision(world, "acme", "Acme", world.w1);
  const version = "2026.11.0";
  const body = draftBody("Acme", version);
  assert.equal((await world.call(`${FEED}/releases`, { token: publisher, profile: "acme", body })).status, 201);
  for (const [index, entry] of body.expected_assets.entries()) {
    const uploaded = await world.call(`${FEED}/releases/${version}/assets/${entry.name}`, {
      method: "PUT", token: publisher, profile: "acme", raw: BYTES_BY_INDEX[index]!, headers: { "x-content-sha256": entry.sha256 },
    });
    assert.equal(uploaded.status, 201, uploaded.text);
  }
  world.logs.length = 0;
  const published = await world.call(`${FEED}/releases/${version}/publish`, { token: publisher, profile: "acme", body: { latest: true } });
  assert.equal(published.status, 503, published.text);
  assert.equal(published.json.error, "signer_unavailable");
  const logged = JSON.stringify(world.logs);
  const signFailure = world.logs.find((entry) => entry.fields.operation === "sign");
  assert.ok(signFailure, logged);
  assert.equal(signFailure.message, "signer unavailable");
  assert.equal(signFailure.fields.error, "SignerUnavailableError");
  assert.match(String(signFailure.fields.message), /AccessDeniedException/);
  for (const secret of [`Release ${version}`, body.expected_assets[0]!.name, body.expected_assets[0]!.sha256, publisher]) {
    assert.ok(!logged.includes(secret), `log carries ${secret}: ${logged}`);
  }
});

test("publish and read: signed envelope, bearer, /cloud cookie, install token, assets", async (t) => {
  const world = await setup(t);
  const { profile, publisher } = await provision(world, "acme", "Acme", world.w1);
  const bearer = await world.session(world.ownerId, world.w1);
  const read = { token: bearer, profile: "acme" };

  // Nothing published yet.
  assert.equal((await world.call(`${FEED}/manifest?channel=stable`, read)).json.error, "no_release");
  assert.equal((await world.call(`${FEED}/releases?channel=stable`, read)).json.error, "no_release");

  // Draft: create is idempotent for the same body, 409 otherwise.
  const body = draftBody("Acme", "2026.11.0");
  const draft = await world.call(`${FEED}/releases`, { token: publisher, profile: "acme", body });
  assert.equal(draft.status, 201, draft.text);
  conforms("DesktopFeedDraft", draft.json);
  assert.equal(draft.json.expected_assets[0].id, null);
  assert.equal((await world.call(`${FEED}/releases`, { token: publisher, profile: "acme", body })).status, 200);
  const changed = await world.call(`${FEED}/releases`, { token: publisher, profile: "acme", body: { ...body, notes: "other" } });
  assert.equal(changed.json.error, "version_exists");

  // Publish before uploads: assets_incomplete.
  const early = await world.call(`${FEED}/releases/2026.11.0/publish`, { token: publisher, profile: "acme", body: {} });
  assert.equal(early.status, 422);
  assert.equal(early.json.error, "assets_incomplete");
  assert.equal(early.json.missing.length, 3);

  for (const [index, entry] of body.expected_assets.entries()) {
    const path = `${FEED}/releases/2026.11.0/assets/${entry.name}`;
    const put = { method: "PUT", token: publisher, profile: "acme", raw: BYTES_BY_INDEX[index]!, headers: { "x-content-sha256": entry.sha256 } };
    const uploaded = await world.call(path, put);
    assert.equal(uploaded.status, 201, uploaded.text);
    conforms("DesktopFeedUploaded", uploaded.json);
    const again = await world.call(path, put);
    assert.equal(again.status, 200);
    assert.equal(again.json.id, uploaded.json.id);
  }
  const drafts = await world.call(`${FEED}/releases?include_drafts=true`, { token: publisher, profile: "acme" });
  conforms("DesktopFeedPublisherVersionList", drafts.json);
  assert.deepEqual(drafts.json.versions.map((row: Json) => [row.version, row.state]), [["2026.11.0", "draft"]]);
  assert.equal(drafts.json.limits.used_bytes, BYTES.dmg.length + BYTES.appimage.length + BYTES.script.length);

  const published = await world.call(`${FEED}/releases/2026.11.0/publish`, { token: publisher, profile: "acme", body: { latest: true } });
  assert.equal(published.status, 200, published.text);
  const envelope = published.json;
  conforms("DesktopFeedEnvelope", envelope);
  assert.equal(envelope.key_id, "fk_acme_dev");
  assert.match(envelope.signature, /^[A-Za-z0-9_-]{86}$/);
  assert.deepEqual(envelope.manifest.download_hosts, []);
  assert.match(envelope.manifest.published_at, /^2026-11-07T10:00:00Z$/);
  // Verified with nothing but node:crypto and the public key the admin API exposes.
  assert.ok(verifyEnvelope(envelope, profile.signing_key.public_key));
  assert.equal((await world.call(`${FEED}/releases/2026.11.0/publish`, { token: publisher, profile: "acme", body: {} })).json.error, "not_a_draft");

  // Reads: the stored envelope byte for byte.
  const manifest = await world.call(`${FEED}/manifest?channel=stable`, read);
  assert.equal(manifest.status, 200);
  assert.equal(manifest.text, published.text);
  assert.equal(manifest.headers.get("cache-control"), "no-store");
  const releases = await world.call(`${FEED}/releases?channel=stable`, read);
  conforms("DesktopFeedReleaseList", releases.json);
  assert.equal(releases.json.next_page, null);
  assert.deepEqual(releases.json.releases, [envelope]);
  const cookieRead = await world.call(`/cloud${FEED}/manifest?channel=stable`, { cookie: bearer, profile: "acme" });
  assert.equal(cookieRead.status, 200);
  assert.equal(cookieRead.text, published.text);
  // The cookie counts only under /cloud/.
  assert.equal((await world.call(`${FEED}/manifest?channel=stable`, { cookie: bearer, profile: "acme" })).json.error, "unauthenticated");

  // Asset streaming with ranges.
  const dmg = envelope.manifest.assets.find((entry: Json) => entry.kind === "image" && entry.platform === "macOS");
  const whole = await world.call(`${FEED}/assets/${dmg.id}`, read);
  assert.equal(whole.status, 200);
  assert.equal(whole.text, BYTES.dmg.toString());
  assert.equal(whole.headers.get("etag"), `"${dmg.sha256}"`);
  assert.equal(whole.headers.get("accept-ranges"), "bytes");
  const part = await world.call(`${FEED}/assets/${dmg.id}`, { ...read, headers: { range: "bytes=0-4" } });
  assert.equal(part.status, 206);
  assert.equal(part.text, BYTES.dmg.subarray(0, 5).toString());
  assert.equal(part.headers.get("content-range"), `bytes 0-4/${BYTES.dmg.length}`);
  const beyond = await world.call(`${FEED}/assets/${dmg.id}`, { ...read, headers: { range: `bytes=${BYTES.dmg.length}-` } });
  assert.equal(beyond.status, 416);
  assert.equal(beyond.json.error, "range_not_satisfiable");
  assert.equal(beyond.headers.get("content-range"), `bytes */${BYTES.dmg.length}`);
  const cookieStream = await world.call(`/cloud${FEED}/assets/${dmg.id}`, { cookie: bearer, profile: "acme" });
  assert.equal(cookieStream.text, BYTES.dmg.toString());

  // No object storage host was signed: download-url is 501.
  const noStorage = await world.call(`${FEED}/assets/${dmg.id}/download-url`, { ...read, method: "POST" });
  assert.equal(noStorage.status, 501);
  assert.equal(noStorage.json.error, "no_object_storage");

  // A release published with a download host gets presigned URLs.
  world.storage.host = "feed-bucket.s3.eu-west-2.amazonaws.com";
  const hosted = await release(world, "acme", publisher, "Acme", "2026.11.1");
  assert.deepEqual(hosted.json.manifest.download_hosts, ["feed-bucket.s3.eu-west-2.amazonaws.com"]);
  const hostedAsset = hosted.json.manifest.assets[0];
  const url = await world.call(`${FEED}/assets/${hostedAsset.id}/download-url`, { ...read, method: "POST" });
  assert.equal(url.status, 200, url.text);
  conforms("DesktopFeedDownloadUrl", url.json);
  assert.equal(new URL(url.json.url).host, "feed-bucket.s3.eu-west-2.amazonaws.com");
  assert.equal(url.json.expires_at, "2026-11-07T10:05:00.000Z");
  // The older release signed no host, so it still streams only.
  assert.equal((await world.call(`${FEED}/assets/${dmg.id}/download-url`, { ...read, method: "POST" })).status, 501);
  world.storage.host = null;

  // latest:false leaves the stable pointer alone.
  await release(world, "acme", publisher, "Acme", "2026.11.2", "stable", false);
  assert.equal((await world.call(`${FEED}/manifest?channel=stable`, read)).json.manifest.version, "2026.11.1");

  // Install tokens: minted by the /cloud session, shown once.
  const cookie = { cookie: bearer, profile: "acme", headers: { origin: PUBLIC_ORIGIN } };
  const minted = await world.call(`/cloud${FEED}/install-tokens`, { ...cookie, body: { label: "laptop" } });
  assert.equal(minted.status, 201, minted.text);
  conforms("DesktopFeedInstallTokenIssued", minted.json);
  assert.match(minted.json.token, /^sh_dfi_[A-Za-z0-9_-]{43}$/);
  assert.equal(minted.json.expires_at, "2026-11-07T11:00:00.000Z");
  assert.ok(minted.json.command.includes(minted.json.token));
  const install = { token: minted.json.token as string, profile: "acme" };
  const viaInstall = await world.call(`${FEED}/manifest?channel=stable`, install);
  assert.equal(viaInstall.status, 200);
  assert.equal((await world.call(`${FEED}/assets/${dmg.id}`, install)).text, BYTES.dmg.toString());
  const list = await world.call(`/cloud${FEED}/install-tokens`, { cookie: bearer, profile: "acme" });
  assert.equal(list.status, 200);
  assert.equal(list.json.tokens.length, 1);
  conforms("DesktopFeedInstallTokenSummary", list.json.tokens[0]);
  assert.equal(list.json.tokens[0].status, "active");
  assert.ok(list.json.tokens[0].last_used_at);
  assert.ok(!list.text.includes(minted.json.token));
  const revoked = await world.call(`/cloud${FEED}/install-tokens/${minted.json.id}`, {
    ...cookie, method: "DELETE", headers: { ...cookie.headers, "content-type": "application/json" },
  });
  assert.equal(revoked.status, 200, revoked.text);
  assert.equal(revoked.json.status, "revoked");
  assert.equal((await world.call(`${FEED}/manifest?channel=stable`, install)).json.error, "token_revoked");

  // Expiry runs on the app clock.
  const short = await world.call(`/cloud${FEED}/install-tokens`, { ...cookie, body: {} });
  world.setClock(new Date("2026-11-07T11:00:01.000Z"));
  assert.equal((await world.call(`${FEED}/manifest?channel=stable`, { token: short.json.token, profile: "acme" })).json.error, "token_expired");

  // A token dies with its user's membership.
  const memberSession = await world.session(world.memberId, world.w1);
  const memberMint = await world.call(`/cloud${FEED}/install-tokens`, { cookie: memberSession, profile: "acme", headers: { origin: PUBLIC_ORIGIN }, body: {} });
  assert.equal(memberMint.status, 201);
  const memberInstall = { token: memberMint.json.token as string, profile: "acme" };
  assert.equal((await world.call(`${FEED}/manifest?channel=stable`, memberInstall)).status, 200);
  await world.database.query("DELETE FROM organization_memberships WHERE user_id = $1", [world.memberId]);
  assert.equal((await world.call(`${FEED}/manifest?channel=stable`, memberInstall)).json.error, "token_revoked");

  // Install tokens are stored hashed; no token value reaches an audit row.
  const hashes = await world.database.query<{ token_hash: string }>("SELECT token_hash FROM desktop_feed_install_tokens");
  assert.ok(hashes.rows.some((row) => row.token_hash === sha(Buffer.from(minted.json.token))));
  const audit = await world.database.query<{ row: string }>("SELECT row_to_json(e)::text AS row FROM desktop_feed_audit_events e");
  const adminAudit = await world.database.query<{ row: string }>("SELECT row_to_json(e)::text AS row FROM admin_audit_events e");
  for (const row of [...audit.rows, ...adminAudit.rows]) {
    assert.ok(!/sh_df[ip]_[A-Za-z0-9_-]{43}/.test(row.row), row.row);
  }
  const actions = new Set(audit.rows.map((row) => JSON.parse(row.row).action as string));
  for (const action of ["desktop_feed.manifest_read", "desktop_feed.publish", "desktop_feed.asset_upload", "desktop_feed.stream",
    "desktop_feed.install_token_create", "desktop_feed.install_token_revoke", "desktop_feed.denied", "desktop_feed.download_url_issue"]) {
    assert.ok(actions.has(action), action);
  }
});

test("beta channel: current moves on every publish, old betas pruned past beta_keep", async (t) => {
  const world = await setup(t);
  const { publisher } = await provision(world, "acme", "Acme", world.w1, { beta_keep: 2 });
  const bearer = await world.session(world.ownerId, world.w1);
  for (const n of [1, 2, 3]) await release(world, "acme", publisher, "Acme", `2026.11.0-beta.${n}`, "beta", false);
  const manifest = await world.call(`${FEED}/manifest?channel=beta`, { token: bearer, profile: "acme" });
  assert.equal(manifest.json.manifest.version, "2026.11.0-beta.3");
  const releases = await world.call(`${FEED}/releases?channel=beta`, { token: bearer, profile: "acme" });
  assert.deepEqual(releases.json.releases.map((entry: Json) => entry.manifest.version), ["2026.11.0-beta.3", "2026.11.0-beta.2"]);
  assert.ok(![...world.storage.inner.objects.keys()].some((key) => key.includes("beta.1")));
  assert.equal((await world.call(`${FEED}/manifest?channel=stable`, { token: bearer, profile: "acme" })).json.error, "no_release");
});

test("import: a release signed elsewhere is published unchanged", async (t) => {
  const world = await setup(t);
  const external = generateKeyPairSync("ed25519");
  const rawKey = external.publicKey.export({ format: "der", type: "spki" }).subarray(12).toString("base64");
  const { publisher } = await provision(world, "acme", "Acme", world.w1, {
    public_keys: [{ key_id: "fk_acme_ext", public_key: rawKey }],
  });
  const bearer = await world.session(world.ownerId, world.w1);
  const manifest = {
    schema: 1,
    profile: "acme",
    channel: "stable",
    version: "2026.10.4",
    published_at: "2026-10-30T08:00:00Z",
    notes: "Imported",
    download_hosts: [],
    assets: [{ id: "a_imported1", ...declared("Acme-2026.10.4-arm64.dmg", "macOS", "arm64", "image", BYTES.dmg, 13) }],
  };
  const sign = (value: Json) => edSign(null, canonicalBytes(value), external.privateKey).toString("base64url");
  const envelope = { manifest, signature: sign(manifest), key_id: "fk_acme_ext" };
  const importPath = `${FEED}/releases/import`;
  const pub = { token: publisher, profile: "acme" };
  const raw = (value: unknown) => ({ ...pub, raw: JSON.stringify(value), headers: { "content-type": "application/json" } });

  assert.equal((await world.call(importPath, { ...pub, raw: '{"envelope":{"a":1,"a":2}}', headers: { "content-type": "application/json" } })).json.error, "manifest_invalid");
  assert.equal((await world.call(importPath, raw({ envelope, extra: 1 }))).json.error, "manifest_invalid");
  assert.equal((await world.call(importPath, raw({ envelope: { ...envelope, signature: "x" } }))).json.error, "manifest_invalid");
  const otherProfile = { ...manifest, profile: "zeta" };
  assert.equal((await world.call(importPath, raw({ envelope: { manifest: otherProfile, signature: sign(otherProfile), key_id: "fk_acme_ext" } }))).json.error, "profile_mismatch");
  assert.equal((await world.call(importPath, raw({ envelope: { ...envelope, key_id: "fk_acme_gone" } }))).json.error, "key_id_unknown");
  assert.equal((await world.call(importPath, raw({ envelope: { ...envelope, manifest: { ...manifest, notes: "tampered" } } }))).json.error, "signature_invalid");

  // Key order and whitespace of the import body are kept byte for byte.
  const text = `{"envelope": {"key_id":"fk_acme_ext", "signature":"${envelope.signature}", "manifest":${JSON.stringify(manifest)}}}`;
  const imported = await world.call(importPath, { ...pub, raw: text, headers: { "content-type": "application/json" } });
  assert.equal(imported.status, 201, imported.text);
  assert.equal(imported.json.origin, "import");
  assert.equal(imported.json.expected_assets[0].id, "a_imported1");
  assert.equal((await world.call(importPath, raw({ envelope }))).json.error, "version_exists");
  const uploaded = await world.call(`${FEED}/releases/2026.10.4/assets/Acme-2026.10.4-arm64.dmg`, {
    ...pub, method: "PUT", raw: BYTES.dmg, headers: { "x-content-sha256": sha(BYTES.dmg) },
  });
  assert.equal(uploaded.json.id, "a_imported1");
  const published = await world.call(`${FEED}/releases/2026.10.4/publish`, { ...pub, body: { latest: true } });
  assert.equal(published.status, 200, published.text);
  assert.equal(published.text, `{"key_id":"fk_acme_ext", "signature":"${envelope.signature}", "manifest":${JSON.stringify(manifest)}}`);
  const read = await world.call(`${FEED}/manifest?channel=stable`, { token: bearer, profile: "acme" });
  assert.equal(read.text, published.text);
  assert.equal((await world.call(`${FEED}/assets/a_imported1`, { token: bearer, profile: "acme" })).text, BYTES.dmg.toString());
  // Asset ids are unique per profile.
  const reuse = { ...manifest, version: "2026.10.5", assets: [{ ...manifest.assets[0]!, name: "Acme-2026.10.5-arm64.dmg" }] };
  assert.equal((await world.call(importPath, raw({ envelope: { manifest: reuse, signature: sign(reuse), key_id: "fk_acme_ext" } }))).json.error, "manifest_invalid");
});

test("refusals: 400, 401, 403, 404, 409, 413, 422 and 503 branches, in precedence order", async (t) => {
  const world = await setup(t);
  const { publisher } = await provision(world, "acme", "Acme", world.w1, { quota_bytes: 200 });
  const bearer = await world.session(world.ownerId, world.w1);
  const pub = { token: publisher, profile: "acme" };
  const read = { token: bearer, profile: "acme" };
  const manifestPath = `${FEED}/manifest?channel=stable`;
  const code = async (path: string, options: CallOptions, status: number, error: string) => {
    const reply = await world.call(path, options);
    assert.equal(reply.status, status, `${path} ${JSON.stringify(options.headers ?? {})}: ${reply.text}`);
    assert.equal(reply.json?.error, error, reply.text);
    return reply;
  };

  // 404: unknown routes and methods.
  assert.equal((await world.call(`${FEED}/nothing`, read)).status, 404);
  assert.equal((await world.call(`${FEED}/manifest`, { ...read, method: "DELETE" })).status, 404);

  // 400 mixed credentials, then 401 before anything else.
  await code(`/cloud${manifestPath}`, { ...read, cookie: bearer }, 400, "mixed_credentials");
  const anonymous = await code(manifestPath, { profile: "acme" }, 401, "unauthenticated");
  assert.equal(anonymous.headers.get("www-authenticate"), "Bearer");
  await code(manifestPath, { token: "nope", profile: "nope" }, 401, "unauthenticated");
  await code(manifestPath, { token: `sh_dfi_${"x".repeat(43)}` }, 401, "unauthenticated");
  await code(manifestPath, { token: `sh_dfp_${"x".repeat(43)}` }, 401, "unauthenticated");
  await code(manifestPath, { token: `sh_wk_${"x".repeat(43)}` }, 401, "unauthenticated");

  // 403 wrong_credential: before the profile header is even looked at.
  const apiToken = await new ApiTokenStore(world.database).create({
    workspaceId: world.w1, organizationId: world.orgId, label: "deploy", purpose: "deployment",
    expiryDays: 30, neverExpires: false, actor: { kind: "user", userId: world.ownerId },
  });
  for (const token of [publisher, world.config.bootstrapToken, world.config.internalServiceToken!, apiToken.accessToken]) {
    await code(manifestPath, { token }, 403, "wrong_credential");
  }
  await code(`${FEED}/releases`, { token: bearer, profile: "acme", body: draftBody("Acme", "2026.11.0") }, 403, "wrong_credential");
  await code(`${FEED}/releases?channel=stable&include_drafts=true`, read, 403, "wrong_credential");
  await code(`${FEED}/releases?channel=stable`, pub, 403, "wrong_credential");
  await code(`${FEED}/install-tokens`, read, 403, "wrong_credential");
  // 403 csrf: a cookie write without an allowed Origin.
  await code(`/cloud${FEED}/install-tokens`, { cookie: bearer, profile: "acme", body: {} }, 403, "csrf_rejected");
  await code(`/cloud${FEED}/install-tokens`, {
    cookie: bearer, profile: "acme", body: {}, headers: { origin: "https://evil.example" },
  }, 403, "csrf_rejected");

  // 400 header, then 403 entitlement (never 404).
  await code(manifestPath, { token: bearer }, 400, "profile_header_required");
  await code(`${FEED}/releases`, { token: publisher, body: {} }, 400, "profile_header_required");
  for (const profile of ["zeta", "BAD!", "z".repeat(40)]) await code(manifestPath, { token: bearer, profile }, 403, "not_entitled");
  const unboundSession = await world.session(world.ownerId, world.w2);
  await code(manifestPath, { token: unboundSession, profile: "acme" }, 403, "not_entitled");
  await code(`${FEED}/assets/a_doesnotexist`, read, 403, "not_entitled");
  await code(`${FEED}/assets/a_doesnotexist/download-url`, { ...read, method: "POST" }, 403, "not_entitled");

  // 400 malformed parameters.
  await code(`${FEED}/manifest`, read, 400, "invalid_request");
  await code(`${FEED}/manifest?channel=nightly`, read, 400, "invalid_request");
  await code(`${FEED}/releases?channel=stable&page=0`, read, 400, "invalid_request");
  await code(`${FEED}/assets/not-an-id`, read, 400, "invalid_request");
  await code(`${FEED}/assets/%E0%A4%A`, read, 400, "invalid_request");
  await code(`/cloud${FEED}/install-tokens/not-a-uuid`, {
    cookie: bearer, profile: "acme", method: "DELETE", headers: { origin: PUBLIC_ORIGIN, "content-type": "application/json" },
  }, 400, "invalid_request");
  await code(`/cloud${FEED}/install-tokens`, {
    cookie: bearer, profile: "acme", body: { label: "x".repeat(129) }, headers: { origin: PUBLIC_ORIGIN },
  }, 400, "invalid_request");

  // 404 that never reveals another profile.
  await code(`/cloud${FEED}/install-tokens/00000000-0000-4000-8000-000000000000`, {
    cookie: bearer, profile: "acme", method: "DELETE", headers: { origin: PUBLIC_ORIGIN, "content-type": "application/json" },
  }, 404, "install_token_not_found");
  await code(`${FEED}/releases/2026.1.0/publish`, { ...pub, body: {} }, 404, "draft_not_found");
  await code(`${FEED}/releases/2026.1.0/assets/install.sh`, {
    ...pub, method: "PUT", raw: BYTES.script, headers: { "x-content-sha256": sha(BYTES.script) },
  }, 404, "draft_not_found");

  // 422 draft validation.
  const releasesPath = `${FEED}/releases`;
  const good = draftBody("Acme", "2026.11.0");
  await code(releasesPath, { ...pub, raw: "{not json", headers: { "content-type": "application/json" } }, 422, "invalid_release");
  await code(releasesPath, { ...pub, body: { ...good, expected_assets: [] } }, 422, "expected_assets_required");
  await code(releasesPath, { ...pub, body: { version: "2026.11.0", channel: "stable", notes: "" } }, 422, "expected_assets_required");
  await code(releasesPath, { ...pub, body: { ...good, version: "2026.13.0" } }, 422, "invalid_release");
  await code(releasesPath, { ...pub, body: { ...good, channel: "beta" } }, 422, "invalid_release");
  await code(releasesPath, { ...pub, body: { ...good, expected_assets: [{ ...good.expected_assets[0]!, sha256: "ABC" }] } }, 422, "invalid_asset");
  await code(releasesPath, { ...pub, body: { ...good, expected_assets: [good.expected_assets[0], good.expected_assets[0]] } }, 422, "invalid_asset");
  await code(releasesPath, { ...pub, body: { ...good, expected_assets: [{ ...good.expected_assets[0]!, name: "Other-2026.11.0-arm64.dmg" }] } }, 422, "invalid_asset");
  await code(releasesPath, {
    ...pub, body: { ...good, expected_assets: [good.expected_assets[1], { ...good.expected_assets[1]!, name: "Acme-2026.11.0-other.AppImage" }] },
  }, 422, "invalid_asset");
  // 413 over 1 MiB.
  await code(releasesPath, { ...pub, raw: JSON.stringify({ ...good, notes: "x".repeat(1_100_000) }), headers: { "content-type": "application/json" } }, 413, "payload_too_large");
  // 422 quota: the profile holds 200 bytes.
  const big = { ...good, expected_assets: [{ ...good.expected_assets[0]!, size: 201 }] };
  const quota = await code(releasesPath, { ...pub, body: big }, 422, "quota_exceeded");
  assert.deepEqual([quota.json.quota_bytes, quota.json.used_bytes, quota.json.required_bytes], [200, 0, 201]);

  // Uploads.
  assert.equal((await world.call(releasesPath, { ...pub, body: good })).status, 201);
  const upload = (name: string, bytes: Buffer, digest = sha(bytes), extra: Record<string, string> = {}) => ({
    ...pub, method: "PUT", raw: bytes, headers: { "x-content-sha256": digest, ...extra },
  });
  const dmgPath = `${releasesPath}/2026.11.0/assets/${good.expected_assets[0]!.name}`;
  await code(dmgPath, { ...pub, method: "PUT", raw: BYTES.dmg }, 400, "invalid_request");
  await code(dmgPath, upload("", BYTES.dmg, "NOT-HEX"), 400, "invalid_request");
  await code(dmgPath, {
    ...pub, method: "PUT", stream: Readable.from([BYTES.dmg]), headers: { "x-content-sha256": sha(BYTES.dmg) },
  }, 400, "invalid_request");
  await code(`${releasesPath}/2026.11.0/assets/Acme-2026.11.0-extra.zip`, upload("", BYTES.dmg), 422, "asset_not_declared");
  await code(dmgPath, upload("", BYTES.appimage), 422, "asset_mismatch");
  const sameLength = Buffer.alloc(BYTES.dmg.length, 0x41);
  await code(dmgPath, upload("", sameLength, sha(BYTES.dmg)), 422, "asset_mismatch");
  assert.equal((await world.call(dmgPath, upload("", BYTES.dmg))).status, 201);
  await code(dmgPath, upload("", sameLength), 409, "asset_conflict");
  for (const [index, entry] of good.expected_assets.entries()) {
    if (index === 0) continue;
    assert.equal((await world.call(`${releasesPath}/2026.11.0/assets/${entry.name}`, upload("", BYTES_BY_INDEX[index]!))).status, 201);
  }

  // Publish: body validation, then signer limits and availability.
  const publishPath = `${releasesPath}/2026.11.0/publish`;
  await code(publishPath, { ...pub, body: { latest: "yes" } }, 400, "invalid_request");
  await code(publishPath, { ...pub, body: { other: true } }, 400, "invalid_request");
  world.signer.max = 100;
  const tooLarge = await code(publishPath, { ...pub, body: {} }, 422, "manifest_too_large");
  assert.equal(tooLarge.json.max_canonical_bytes, 100);
  world.signer.max = null;
  world.signer.down = true;
  await code(publishPath, { ...pub, body: {} }, 503, "signer_unavailable");
  world.signer.down = false;
  assert.equal((await world.call(publishPath, { ...pub, body: { latest: true } })).status, 200);
  await code(publishPath, { ...pub, body: {} }, 409, "not_a_draft");
  await code(dmgPath, upload("", BYTES.dmg), 409, "not_a_draft");
  await code(releasesPath, { ...pub, body: good }, 409, "version_exists");

  // Denials are audited.
  const denied = await world.database.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM desktop_feed_audit_events WHERE action = 'desktop_feed.denied'",
  );
  assert.ok(denied.rows[0]!.n >= 15);
});

test("isolation: two profiles in one installation see nothing of each other", async (t) => {
  const world = await setup(t);
  const acme = await provision(world, "acme", "Acme", world.w1);
  const zeta = await provision(world, "zeta", "Zeta", world.w2);
  const acmeRelease = await release(world, "acme", acme.publisher, "Acme", "2026.11.0");
  const zetaRelease = await release(world, "zeta", zeta.publisher, "Zeta", "2026.11.0");
  const acmeReader = await world.session(world.ownerId, world.w1);
  const zetaReader = await world.session(world.ownerId, world.w2);
  const acmeAsset = acmeRelease.json.manifest.assets[0].id as string;
  const zetaAsset = zetaRelease.json.manifest.assets[0].id as string;
  assert.notEqual(acmeAsset, zetaAsset);
  assert.notEqual(acmeRelease.json.signature, zetaRelease.json.signature);
  assert.equal(zetaRelease.json.key_id, "fk_zeta_dev");

  const deny = async (token: string, profile: string, path: string, method = "GET") => {
    const reply = await world.call(path, { token, profile, method, ...(method === "POST" ? { body: {} } : {}) });
    assert.equal(reply.status, 403, `${profile} ${path}: ${reply.text}`);
    assert.ok(["not_entitled", "wrong_credential"].includes(reply.json.error));
  };
  // A reader bound to one profile cannot name the other.
  await deny(acmeReader, "zeta", `${FEED}/manifest?channel=stable`);
  await deny(zetaReader, "acme", `${FEED}/manifest?channel=stable`);
  // An asset id of the other profile is not_entitled, even under one's own header.
  await deny(acmeReader, "acme", `${FEED}/assets/${zetaAsset}`);
  await deny(zetaReader, "zeta", `${FEED}/assets/${acmeAsset}`);
  await deny(acmeReader, "acme", `${FEED}/assets/${zetaAsset}/download-url`, "POST");
  // A publisher token writes only its own profile.
  await deny(acme.publisher, "zeta", `${FEED}/releases?include_drafts=true`);
  await deny(acme.publisher, "zeta", `${FEED}/releases`, "POST");
  // Install tokens carry their profile.
  const minted = await world.call(`/cloud${FEED}/install-tokens`, {
    cookie: acmeReader, profile: "acme", body: {}, headers: { origin: PUBLIC_ORIGIN },
  });
  await deny(minted.json.token, "zeta", `${FEED}/manifest?channel=stable`);
  const own = await world.call(`${FEED}/manifest?channel=stable`, { token: zetaReader, profile: "zeta" });
  assert.equal(own.text, zetaRelease.text);
  // Admin: a profile of another org id is not found (single-org installs share one org, so check the org gate).
  const other = await world.call(`/api/v1/organizations/00000000-0000-4000-8000-000000000000/desktop-feed/profiles/acme`, {
    token: world.config.bootstrapToken,
  });
  assert.equal(other.status, 404);
});

test("rate limits: per credential, per IP when unauthenticated, install-token minting, stream concurrency", async (t) => {
  const world = await setup(t, {
    limits: {
      reads: { limit: 3, windowMs: 60_000 },
      downloadUrl: { limit: 2, windowMs: 60_000 },
      streamStarts: { limit: 2, windowMs: 60_000 },
      installTokenMint: { limit: 2, windowMs: 3_600_000 },
      unauthenticated: { limit: 2, windowMs: 60_000 },
      publisher: { limit: 40, windowMs: 60_000 },
    },
  });
  const { publisher } = await provision(world, "acme", "Acme", world.w1);
  const published = await release(world, "acme", publisher, "Acme", "2026.11.0");
  const asset = published.json.manifest.assets[0].id as string;
  const bearer = await world.session(world.ownerId, world.w1);
  const other = await world.session(world.ownerId, world.w1);
  const path = `${FEED}/manifest?channel=stable`;
  for (let i = 0; i < 3; i += 1) assert.equal((await world.call(path, { token: bearer, profile: "acme" })).status, 200);
  const limited = await world.call(path, { token: bearer, profile: "acme" });
  assert.equal(limited.status, 429);
  assert.equal(limited.json.error, "rate_limited");
  assert.ok(Number(limited.headers.get("retry-after")) >= 1);
  assert.equal(limited.json.retry_after_seconds, Number(limited.headers.get("retry-after")));
  // Another session has its own budget; the window resets on the app clock.
  assert.equal((await world.call(path, { token: other, profile: "acme" })).status, 200);
  world.setClock(new Date("2026-11-07T10:01:01.000Z"));
  assert.equal((await world.call(path, { token: bearer, profile: "acme" })).status, 200);

  // Unauthenticated requests spend a per-IP budget.
  assert.equal((await world.call(path, { profile: "acme" })).status, 401);
  assert.equal((await world.call(path, { token: "bogus", profile: "acme" })).status, 401);
  assert.equal((await world.call(path, { profile: "acme" })).status, 429);

  // download-url and stream have their own buckets.
  for (let i = 0; i < 2; i += 1) assert.equal((await world.call(`${FEED}/assets/${asset}/download-url`, { token: other, profile: "acme", method: "POST" })).status, 501);
  assert.equal((await world.call(`${FEED}/assets/${asset}/download-url`, { token: other, profile: "acme", method: "POST" })).status, 429);
  for (let i = 0; i < 2; i += 1) assert.equal((await world.call(`${FEED}/assets/${asset}`, { token: other, profile: "acme" })).status, 200);
  assert.equal((await world.call(`${FEED}/assets/${asset}`, { token: other, profile: "acme" })).status, 429);

  // Minting: per user per hour, across sessions.
  const mint = (session: string) => world.call(`/cloud${FEED}/install-tokens`, {
    cookie: session, profile: "acme", body: {}, headers: { origin: PUBLIC_ORIGIN },
  });
  assert.equal((await mint(bearer)).status, 201);
  assert.equal((await mint(other)).status, 201);
  assert.equal((await mint(bearer)).status, 429);
});

test("stream concurrency: at most four open streams per credential", async (t) => {
  const world = await setup(t);
  const { publisher } = await provision(world, "acme", "Acme", world.w1);
  const published = await release(world, "acme", publisher, "Acme", "2026.11.0");
  const asset = published.json.manifest.assets[0].id as string;
  const bearer = await world.session(world.ownerId, world.w1);
  const other = await world.session(world.ownerId, world.w1);
  // Plain node:http connections, so the held streams stay out of fetch's pool.
  const open = (token: string) => new Promise<IncomingMessage>((resolve, reject) => {
    httpGet(`${world.origin}${FEED}/assets/${asset}`, {
      agent: false, headers: { authorization: `Bearer ${token}`, "x-agent-relay-profile": "acme" },
    }, resolve).on("error", reject);
  });
  world.storage.held = [];
  const streams = await Promise.all([1, 2, 3, 4].map(() => open(bearer)));
  for (const response of streams) assert.equal(response.statusCode, 200);
  const fifth = await world.call(`${FEED}/assets/${asset}`, { token: bearer, profile: "acme" });
  assert.equal(fifth.status, 429);
  assert.equal(fifth.json.error, "rate_limited");
  // Another credential has its own four.
  const elsewhere = await open(other);
  assert.equal(elsewhere.statusCode, 200);
  // Finishing a stream frees its slot.
  const held = world.storage.held;
  world.storage.held = null;
  for (const stream of held) stream.end();
  await Promise.all([...streams, elsewhere].map((response) => response.resume().toArray()));
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.equal((await world.call(`${FEED}/assets/${asset}`, { token: bearer, profile: "acme" })).status, 200);
});

/* ------------------------------------ storage layout, KMS cap, entitlement */

/** Creates the draft and uploads every asset; `bytes` are per asset, in order. */
async function uploaded(world: World, profile: string, publisher: string, body: Json, bytes: Buffer[]) {
  const draft = await world.call(`${FEED}/releases`, { token: publisher, profile, body });
  assert.equal(draft.status, 201, draft.text);
  for (const [index, entry] of body.expected_assets.entries()) {
    const put = await world.call(`${FEED}/releases/${body.version}/assets/${entry.name}`, {
      method: "PUT", token: publisher, profile, raw: bytes[index]!, headers: { "x-content-sha256": entry.sha256 },
    });
    assert.equal(put.status, 201, put.text);
    assert.match(put.json.id, /^a_[0-9A-Za-z]{8}$/);
  }
}

test("storage: uploads land in drafts/, publish moves them to releases/ and mirrors manifests/", async (t) => {
  const world = await setup(t);
  const { publisher } = await provision(world, "acme", "Acme", world.w1);
  const objects = world.storage.inner.objects;
  const version = "2026.11.0";
  const body = draftBody("Acme", version);
  const name = body.expected_assets[0]!.name;
  await uploaded(world, "acme", publisher, body, BYTES_BY_INDEX);
  assert.ok(objects.has(`profiles/acme/drafts/${version}/${name}`));
  assert.ok(![...objects.keys()].some((key) => key.includes("/releases/")), "nothing is in releases/ before publish");

  const published = await world.call(`${FEED}/releases/${version}/publish`, { token: publisher, profile: "acme", body: { latest: true } });
  assert.equal(published.status, 200, published.text);
  assert.deepEqual(objects.get(`profiles/acme/releases/${version}/${name}`), BYTES.dmg);
  assert.ok(![...objects.keys()].some((key) => key.includes("/drafts/")), "drafts are removed after the commit");
  assert.equal(objects.get("profiles/acme/manifests/stable.json")!.toString("utf8"), published.text);
  assert.ok(!objects.has("profiles/acme/manifests/beta.json"));

  const token = await world.session(world.ownerId, world.w1);
  const streamed = await world.call(`${FEED}/assets/${published.json.manifest.assets[0].id}`, { token, profile: "acme" });
  assert.equal(streamed.status, 200);
  assert.equal(streamed.text, BYTES.dmg.toString("utf8"));

  const beta = draftBody("Acme", "2026.11.1-beta.1", "beta");
  await uploaded(world, "acme", publisher, beta, BYTES_BY_INDEX);
  const betaPublished = await world.call(`${FEED}/releases/2026.11.1-beta.1/publish`, { token: publisher, profile: "acme", body: {} });
  assert.equal(betaPublished.status, 200, betaPublished.text);
  assert.equal(objects.get("profiles/acme/manifests/beta.json")!.toString("utf8"), betaPublished.text);
});

test("publish: a failed copy leaves a draft that a rerun completes", async (t) => {
  const world = await setup(t);
  const { publisher } = await provision(world, "acme", "Acme", world.w1);
  const body = draftBody("Acme", "2026.11.0");
  await uploaded(world, "acme", publisher, body, BYTES_BY_INDEX);
  const copy = world.storage.inner.copy.bind(world.storage.inner);
  world.storage.inner.copy = async () => { throw new Error("copy down"); };
  const failed = await world.call(`${FEED}/releases/2026.11.0/publish`, { token: publisher, profile: "acme", body: { latest: true } });
  assert.ok(failed.status >= 500, failed.text);
  world.storage.inner.copy = copy;
  const listed = await world.call(`${FEED}/releases?include_drafts=true`, { token: publisher, profile: "acme" });
  assert.equal(listed.json.versions[0].state, "draft");
  const retried = await world.call(`${FEED}/releases/2026.11.0/publish`, { token: publisher, profile: "acme", body: { latest: true } });
  assert.equal(retried.status, 200, retried.text);
});

test("signer cap: an oversize manifest is refused at create with exact byte counts", async (t) => {
  const world = await setup(t);
  const { publisher } = await provision(world, "acme", "Acme", world.w1);
  const body = draftBody("Acme", "2026.11.0");
  world.signer.max = 300;
  const refused = await world.call(`${FEED}/releases`, { token: publisher, profile: "acme", body });
  assert.equal(refused.status, 422, refused.text);
  assert.equal(refused.json.error, "manifest_too_large");
  assert.equal(refused.json.max_canonical_bytes, 300);
  const size = refused.json.canonical_bytes as number;
  assert.ok(size > 300);
  assert.ok(refused.json.message.includes(String(size)) && refused.json.message.includes("300"), "the publisher prints only the message");
  const listed = await world.call(`${FEED}/releases?include_drafts=true`, { token: publisher, profile: "acme" });
  assert.deepEqual(listed.json.versions, [], "no draft was created");

  // The estimate is exact: the same manifest at exactly the cap signs.
  world.signer.max = size;
  await uploaded(world, "acme", publisher, body, BYTES_BY_INDEX);
  const published = await world.call(`${FEED}/releases/2026.11.0/publish`, { token: publisher, profile: "acme", body: { latest: true } });
  assert.equal(published.status, 200, published.text);
  assert.equal(canonicalBytes(published.json.manifest).length, size);
});

test("publisher tokens from env: stored hashed, scoped to their profile", async (t) => {
  const token = `sh_dfp_${"e".repeat(43)}`;
  const world = await setup(t, { publisherTokenHashes: { acme: [sha(Buffer.from(token))] } });
  await provision(world, "acme", "Acme", world.w1);
  await provision(world, "beta", "Beta", world.w2);
  const listed = await world.call(`${FEED}/releases?include_drafts=true`, { token, profile: "acme" });
  assert.equal(listed.status, 200, listed.text);
  const other = await world.call(`${FEED}/releases?include_drafts=true`, { token, profile: "beta" });
  assert.equal(other.status, 403);
  assert.equal(other.json.error, "not_entitled");
  const unknown = await world.call(`${FEED}/releases?include_drafts=true`, { token: `sh_dfp_${"f".repeat(43)}`, profile: "acme" });
  assert.equal(unknown.status, 401);
});

test("profiles: registering a profile needs a configured signing key", async (t) => {
  const world = await setup(t);
  world.signer.unknownProfiles.add("nokey");
  const refused = await world.post(`/api/v1/organizations/${world.orgId}/desktop-feed/profiles`, { id: "nokey", asset_prefix: "Nokey" });
  assert.equal(refused.status, 409, refused.text);
  assert.equal(refused.json.error, "signing_key_not_configured");
  await provision(world, "acme", "Acme", world.w1);
  await provision(world, "beta", "Beta", world.w2);
  const profiles = await world.call(`/api/v1/organizations/${world.orgId}/desktop-feed/profiles`, { token: world.config.bootstrapToken });
  assert.deepEqual(profiles.json.profiles.map((entry: Json) => entry.id), ["acme", "beta"], "one key per profile, several profiles");
});

test("desktop profiles: names the workspace's profiles for the downloads page", async (t) => {
  const world = await setup(t);
  const { publisher } = await provision(world, "acme", "Acme", world.w1);
  const path = "/api/v1/desktop/profiles";
  const bound = await world.session(world.ownerId, world.w1);
  const answered = await world.call(path, { token: bound });
  assert.equal(answered.status, 200, answered.text);
  assert.deepEqual(answered.json, { profiles: [{ id: "acme", asset_prefix: "Acme" }] });
  const viaCookie = await world.call(`/cloud${path}`, { cookie: bound });
  assert.deepEqual(viaCookie.json, answered.json);
  const unbound = await world.session(world.ownerId, world.w2);
  assert.deepEqual((await world.call(path, { token: unbound })).json, { profiles: [] });
  assert.equal((await world.call(path)).status, 401);
  assert.equal((await world.call(path, { token: publisher })).status, 403);
});

/* ------------------------------------------------- Desktop fixture replay */

for (const file of ["valid-stable", "valid-beta"]) {
  test(`Desktop fixtures: ${file} publishes to an envelope the client's rules accept`, async (t) => {
    const fixture: Json = JSON.parse(readFileSync(new URL(`test/fixtures/desktop-feed/manifest/${file}.json`, ROOT), "utf8"));
    const world = await setup(t);
    const prefix = fixture.assets.find((entry: Json) => entry.kind !== "install-script").name.split(`-${fixture.version}-`)[0];
    const { publisher } = await provision(world, fixture.profile, prefix, world.w1);
    const bytes = fixture.assets.map((entry: Json) => Buffer.from(`bytes of ${entry.name}`));
    const body = {
      version: fixture.version,
      channel: fixture.channel,
      notes: fixture.notes,
      expected_assets: fixture.assets.map((entry: Json, index: number) => {
        const { id: _id, ...declaredAsset } = entry;
        return { ...declaredAsset, size: bytes[index]!.length, sha256: sha(bytes[index]!) };
      }),
    };
    await uploaded(world, fixture.profile, publisher, body, bytes);
    const published = await world.call(`${FEED}/releases/${fixture.version}/publish`, {
      token: publisher, profile: fixture.profile, body: fixture.channel === "stable" ? { latest: true } : {},
    });
    assert.equal(published.status, 200, published.text);

    // The client's verify order, on the bytes as served.
    const reader = await world.session(world.ownerId, world.w1);
    const served = await world.call(`${FEED}/manifest?channel=${fixture.channel}`, {
      token: reader, profile: fixture.profile, headers: { "x-agent-relay-desktop": "1" },
    });
    assert.equal(served.status, 200, served.text);
    assert.equal(served.text, published.text, "served byte for byte");
    const envelope = strictParse(served.text) as Json;
    const ajv = new Ajv2020({ strict: true, allErrors: true });
    addFormats(ajv);
    const validate = ajv.compile(ENVELOPE_SCHEMA as Json);
    const candidate: Json = strictParse(served.text);
    assert.ok(validate(candidate), JSON.stringify(validate.errors));
    assert.deepEqual(Object.keys(envelope).sort(), ["key_id", "manifest", "signature"]);
    assert.match(envelope.key_id, new RegExp(`^fk_${fixture.profile}_[a-z0-9]{1,16}$`));
    assert.match(envelope.signature, /^[A-Za-z0-9_-]{85}[AQgw]$/);
    const key = publicKeyFromRaw(await world.signer.publicKey(fixture.profile));
    assert.ok(edVerify(null, canonicalBytes(envelope.manifest), key, Buffer.from(envelope.signature, "base64url")), "signature verifies");

    const manifest = envelope.manifest;
    assert.equal(manifest.profile, fixture.profile);
    assert.equal(manifest.channel, fixture.channel);
    assert.equal(manifest.version, fixture.version);
    assert.equal(manifest.notes, fixture.notes);
    const shape = (entry: Json) => [entry.name, entry.platform, entry.arch, entry.os_floor, entry.kind];
    assert.deepEqual(manifest.assets.map(shape), fixture.assets.map(shape));
    assert.equal(new Set(manifest.assets.map((entry: Json) => entry.id)).size, manifest.assets.length);
  });
}

test("signer cap: the cloud release fits under the KMS limit and the untrimmed one does not", async (t) => {
  const world = await setup(t);
  const { publisher } = await provision(world, "acme", "AgentRelay", world.w1, { quota_bytes: 1_000_000_000_000 });
  world.signer.max = 4096;
  world.storage.host = `${"b".repeat(63)}.s3.ap-southeast-3.amazonaws.com`;
  const version = "2026.12.12";
  const asset = (name: string, platform: string, arch: string, kind: string, osFloor?: number) => ({
    name, platform, arch, ...(osFloor ? { os_floor: osFloor } : {}), kind, size: 1_999_999_999, sha256: "a".repeat(64),
  });
  const packaged = (rest: string) => `AgentRelay-${version}-${rest}`;
  const cloud = ["arm64", "x64"].flatMap((arch) => [
    asset(packaged(`macOS15-${arch}.dmg`), "macOS", arch, "image", 15),
    asset(packaged(`Linux-${arch}.tar.gz`), "Linux", arch, "tarball"),
    asset(packaged(`Linux-${arch}.deb`), "Linux", arch, "deb"),
    asset(packaged(`Linux-${arch}-probe.tar.gz`), "Linux", arch, "probe"),
    asset(packaged(`Windows-${arch}.zip`), "Windows", arch, "zip"),
    asset(packaged(`Windows-${arch}-probe.zip`), "Windows", arch, "probe"),
    asset(packaged(`Windows-${arch}-Setup.exe`), "Windows", arch, "setup"),
  ]).concat([asset("install.sh", "Linux", "x64", "install-script"), asset("install.ps1", "Windows", "x64", "install-script")]);
  assert.equal(cloud.length, 16);
  const untrimmed = cloud.concat(["arm64", "x64"].flatMap((arch) => [
    asset(packaged(`macOS-${arch}.dmg`), "macOS", arch, "image"),
    asset(packaged(`macOS-${arch}-probe.tar.gz`), "macOS", arch, "probe"),
  ]));
  const create = (expected_assets: typeof cloud) => world.call(`${FEED}/releases`, {
    token: publisher, profile: "acme", body: { version, channel: "stable", notes: "n".repeat(300), expected_assets },
  });
  const refused = await create(untrimmed);
  assert.equal(refused.status, 422, refused.text);
  assert.equal(refused.json.error, "manifest_too_large");
  const created = await create(cloud);
  assert.equal(created.status, 201, created.text);
});

/* ---------------------------------------------------- review regressions */

test("credentials: an unexchanged Desktop handoff cannot read the feed", async (t) => {
  const world = await setup(t);
  await provision(world, "acme", "Acme", world.w1);
  const token = await world.session(world.ownerId, world.w1);
  assert.equal((await world.call(`${FEED}/manifest?channel=stable`, { token, profile: "acme" })).status, 404, "an exchanged session reaches the feed");
  await world.database.query(`UPDATE token_sessions SET desktop_exchange_challenge = 'pending', desktop_exchanged_at = NULL`);
  const refused = await world.call(`${FEED}/manifest?channel=stable`, { token, profile: "acme" });
  assert.equal(refused.status, 403, refused.text);
  assert.equal(refused.json.error, "wrong_credential");
  assert.equal((await world.call("/api/v1/desktop/profiles", { token })).status, 403);
});

test("audit: a failed audit after a commit does not fail the write, and reads still fail closed", async (t) => {
  const world = await setup(t);
  const { publisher } = await provision(world, "acme", "Acme", world.w1);
  const token = await world.session(world.ownerId, world.w1);
  const body = draftBody("Acme", "2026.11.0");
  await uploaded(world, "acme", publisher, body, BYTES_BY_INDEX);
  await world.database.query(`DROP TABLE admin_audit_events`);
  await world.database.query(`DROP TABLE desktop_feed_audit_events`);
  world.logs.length = 0;
  const published = await world.call(`${FEED}/releases/2026.11.0/publish`, { token: publisher, profile: "acme", body: { latest: true } });
  assert.equal(published.status, 200, published.text);
  assert.ok(world.logs.some((entry) => entry.message === "audit failed after commit" && entry.fields.action === "desktop_feed.publish"));
  const read = await world.call(`${FEED}/manifest?channel=stable`, { token, profile: "acme" });
  assert.equal(read.status, 500);
});

test("quota: concurrent drafts cannot reserve more than the quota", async (t) => {
  const world = await setup(t);
  const total = BYTES_BY_INDEX.reduce((sum, bytes) => sum + bytes.length, 0);
  const { publisher } = await provision(world, "acme", "Acme", world.w1, { quota_bytes: total + 1 });
  const results = await Promise.all(["2026.11.0", "2026.11.1"].map((version) =>
    world.call(`${FEED}/releases`, { token: publisher, profile: "acme", body: draftBody("Acme", version) })));
  assert.deepEqual(results.map((result) => result.status).sort(), [201, 422]);
  assert.ok(results.some((result) => result.json.error === "quota_exceeded"));
});

test("streams: a cancelled download destroys the upstream body", async (t) => {
  const world = await setup(t);
  const { publisher } = await provision(world, "acme", "Acme", world.w1);
  const token = await world.session(world.ownerId, world.w1);
  await uploaded(world, "acme", publisher, draftBody("Acme", "2026.11.0"), BYTES_BY_INDEX);
  const published = await world.call(`${FEED}/releases/2026.11.0/publish`, { token: publisher, profile: "acme", body: { latest: true } });
  const held: PassThrough[] = [];
  world.storage.held = held;
  const request = httpGet(`${world.origin}${FEED}/assets/${published.json.manifest.assets[0].id}`, {
    headers: { authorization: `Bearer ${token}`, "x-agent-relay-profile": "acme" },
  });
  request.on("error", () => undefined);
  await new Promise((resolve) => request.once("response", resolve));
  request.destroy();
  for (let attempt = 0; attempt < 200 && !held[0]?.destroyed; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(held[0]?.destroyed, true);
});

test("profiles: a registered key cannot shadow the site's signing key", async (t) => {
  const world = await setup(t);
  const refused = await world.post(`/api/v1/organizations/${world.orgId}/desktop-feed/profiles`, {
    id: "shadow", asset_prefix: "Shadow", public_keys: [{ key_id: "fk_shadow_dev", public_key: `${"A".repeat(43)}=` }],
  });
  assert.equal(refused.status, 400, refused.text);
  assert.match(refused.json.message, /signing key/);
});
