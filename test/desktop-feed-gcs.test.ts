// GCS object store and metadata-server credentials for the Desktop feed,
// against a fake local GCS XML API, metadata server and IAM Credentials.
import assert from "node:assert/strict";
import { createHash, createSign, createVerify, generateKeyPairSync } from "node:crypto";
import { createServer, type IncomingMessage } from "node:http";
import { Readable } from "node:stream";
import test, { type TestContext } from "node:test";
import { loadDesktopFeedConfig } from "../src/config.js";
import { GcpCredentialError, MetadataGcpCredentialProvider, type GcpCredentialProvider } from "../src/gcp/credentials.js";
import { GcsDesktopFeedStorage, StorageError } from "../src/desktop-feed/storage.js";
import { close, listen } from "./support/harness.js";

const NOW = new Date("2026-11-07T10:00:00.000Z");
const EMAIL = "relay-control@feed-test-project.iam.gserviceaccount.com";
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });

type Seen = { method: string; path: string; headers: IncomingMessage["headers"]; body: Buffer };

async function fakeServer(
  t: TestContext,
  reply: (seen: Seen) => { status: number; body?: string | Buffer; headers?: Record<string, string> },
) {
  const seen: Seen[] = [];
  const server = createServer(async (request, response) => {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const entry = { method: request.method!, path: request.url!, headers: request.headers, body: Buffer.concat(chunks) };
    seen.push(entry);
    const answer = reply(entry);
    response.writeHead(answer.status, answer.headers ?? {});
    response.end(answer.body ?? "");
  });
  const origin = await listen(server);
  t.after(() => close(server));
  return { origin, seen };
}

/** A credential provider whose signBlob is a local RSA key, so signatures can be verified. */
const FAKE_CREDENTIALS: GcpCredentialProvider & { signed: Buffer[] } = {
  signed: [],
  async accessToken() {
    return "ya29.feed-test-token";
  },
  async serviceAccountEmail() {
    return EMAIL;
  },
  async signBlob(payload: Buffer) {
    this.signed.push(payload);
    const signer = createSign("RSA-SHA256");
    signer.update(payload);
    return signer.sign(privateKey);
  },
};

test("GCS storage: streamed PUT, ranged GET, DELETE through the XML API with a Bearer token", async (t) => {
  const bytes = Buffer.from("desktop feed asset bytes");
  const sha = createHash("sha256").update(bytes).digest("hex");
  let putStatus = 200;
  const gcs = await fakeServer(t, (seen) => {
    if (seen.method === "PUT") return { status: putStatus };
    if (seen.method === "DELETE") return { status: seen.path.endsWith("/missing") ? 404 : 204 };
    if (seen.path.endsWith("/missing")) return { status: 404 };
    if (seen.headers.range) return { status: 206, body: bytes.subarray(2, 6) };
    return { status: 200, body: bytes };
  });
  assert.throws(() => new GcsDesktopFeedStorage({ bucket: "Bad_Bucket", prefix: "x" }), /GCS_BUCKET/);
  const storage = new GcsDesktopFeedStorage({
    bucket: "feed-bucket", prefix: "desktop-feed", credentials: FAKE_CREDENTIALS, endpoint: gcs.origin,
  });
  assert.equal(storage.kind, "gcs");
  assert.equal(storage.downloadHost(), "storage.googleapis.com");
  assert.equal(storage.url("profiles/acme/x").toString(), `${gcs.origin}/feed-bucket/desktop-feed/profiles/acme/x`);
  const key = "profiles/acme/releases/2026.11.0/Acme-2026.11.0-arm64.dmg";

  await storage.put(key, Readable.from([bytes.subarray(0, 5), bytes.subarray(5)]), bytes.length, sha);
  // Staged, verified, copied over the key, staging deleted.
  assert.deepEqual(gcs.seen.map((seen) => seen.method), ["PUT", "PUT", "DELETE"]);
  const put = gcs.seen[0]!;
  assert.equal(put.method, "PUT");
  const staging = put.path;
  assert.match(staging, new RegExp(`^/feed-bucket/desktop-feed/${key.replace(/\./g, "\\.")}\\.upload-[0-9a-f]{24}$`));
  assert.equal(gcs.seen[1]!.path, `/feed-bucket/desktop-feed/${key}`);
  assert.equal(gcs.seen[1]!.headers["x-goog-copy-source"], staging);
  assert.equal(gcs.seen[2]!.path, staging);
  assert.deepEqual(put.body, bytes);
  assert.equal(put.headers["content-length"], String(bytes.length));
  assert.equal(put.headers["content-type"], "application/octet-stream");
  assert.equal(put.headers.authorization, "Bearer ya29.feed-test-token");
  // Never a public ACL.
  assert.equal(put.headers["x-goog-acl"], undefined);

  const ranged = await storage.get(key, { start: 2, end: 5 });
  assert.ok(ranged);
  const chunks: Buffer[] = [];
  for await (const chunk of ranged) chunks.push(Buffer.from(chunk));
  assert.deepEqual(Buffer.concat(chunks), bytes.subarray(2, 6));
  const get = gcs.seen[3]!;
  assert.equal(get.method, "GET");
  assert.equal(get.headers.range, "bytes=2-5");
  assert.equal(get.headers.authorization, "Bearer ya29.feed-test-token");
  assert.equal(await storage.get("missing"), null);

  await storage.delete(key);
  assert.equal(gcs.seen.at(-1)!.method, "DELETE");
  assert.equal(gcs.seen.at(-1)!.path, `/feed-bucket/desktop-feed/${key}`);
  await storage.delete("missing");

  putStatus = 403;
  await assert.rejects(storage.put(key, Readable.from([bytes]), bytes.length, sha), StorageError);
  // A failed staging PUT is still cleaned up, and the key is never copied over.
  const [failedPut, cleanup] = gcs.seen.slice(-2);
  assert.equal(failedPut!.method, "PUT");
  assert.match(failedPut!.path, /\.upload-[0-9a-f]{24}$/);
  assert.equal(cleanup!.method, "DELETE");
  assert.equal(cleanup!.path, failedPut!.path);
});

test("GCS storage: an upload whose sha256 differs never touches the key", async (t) => {
  const gcs = await fakeServer(t, (seen) => ({ status: seen.method === "DELETE" ? 204 : 200 }));
  const storage = new GcsDesktopFeedStorage({
    bucket: "feed-bucket", prefix: "desktop-feed", credentials: FAKE_CREDENTIALS, endpoint: gcs.origin,
  });
  const bytes = Buffer.from("tampered bytes");
  const key = "profiles/acme/drafts/2026.11.0/a.dmg";
  await assert.rejects(storage.put(key, Readable.from([bytes]), bytes.length, "0".repeat(64)), /sha256/);
  // Only the staging object is written and deleted; the key is neither replaced nor removed.
  assert.deepEqual(gcs.seen.map((seen) => seen.method), ["PUT", "DELETE"]);
  assert.match(gcs.seen[0]!.path, /\.upload-[0-9a-f]{24}$/);
  assert.equal(gcs.seen[1]!.path, gcs.seen[0]!.path);
  assert.ok(gcs.seen.every((seen) => seen.path !== `/feed-bucket/desktop-feed/${key}`));
  assert.equal(gcs.seen[0]!.headers["x-goog-copy-source"], undefined);
});

test("GCS storage: copy is server-side and sees an error inside a 200", async (t) => {
  let answer = "<CopyObjectResult></CopyObjectResult>";
  const gcs = await fakeServer(t, () => ({ status: 200, body: answer }));
  const storage = new GcsDesktopFeedStorage({
    bucket: "feed-bucket", prefix: "desktop-feed", credentials: FAKE_CREDENTIALS, endpoint: gcs.origin,
  });
  const source = "profiles/acme/drafts/2026.11.0/Acme+x.dmg";
  const destination = "profiles/acme/releases/2026.11.0/Acme+x.dmg";
  await storage.copy(source, destination);
  const copy = gcs.seen[0]!;
  assert.equal(copy.method, "PUT");
  assert.equal(copy.path, "/feed-bucket/desktop-feed/profiles/acme/releases/2026.11.0/Acme%2Bx.dmg");
  assert.equal(copy.headers["x-goog-copy-source"], "/feed-bucket/desktop-feed/profiles/acme/drafts/2026.11.0/Acme%2Bx.dmg");
  assert.equal(copy.headers["content-length"], "0");
  assert.equal(copy.body.length, 0);
  answer = "<Error><Code>InternalError</Code></Error>";
  await assert.rejects(storage.copy(source, destination), StorageError);
});

test("GCS storage: V4 signed GET URL signed through signBlob", async () => {
  FAKE_CREDENTIALS.signed.length = 0;
  const storage = new GcsDesktopFeedStorage({ bucket: "feed-bucket", prefix: "desktop-feed", credentials: FAKE_CREDENTIALS });
  const key = "profiles/acme/releases/2026.11.0/Acme+x (1).dmg";
  const url = await storage.presignGet(key, 300, NOW);
  assert.equal(url.protocol, "https:");
  assert.equal(url.host, "storage.googleapis.com");
  assert.equal(url.pathname, "/feed-bucket/desktop-feed/profiles/acme/releases/2026.11.0/Acme%2Bx%20%281%29.dmg");
  assert.equal(url.searchParams.get("X-Goog-Algorithm"), "GOOG4-RSA-SHA256");
  assert.equal(url.searchParams.get("X-Goog-Credential"), `${EMAIL}/20261107/auto/storage/goog4_request`);
  assert.equal(url.searchParams.get("X-Goog-Date"), "20261107T100000Z");
  assert.equal(url.searchParams.get("X-Goog-Expires"), "300");
  assert.equal(url.searchParams.get("X-Goog-SignedHeaders"), "host");
  // The credential's @ and / are percent-encoded in the URL as in the canonical query.
  assert.match(url.search, /X-Goog-Credential=relay-control%40feed-test-project\.iam\.gserviceaccount\.com%2F20261107%2Fauto%2Fstorage%2Fgoog4_request&/);

  // Rebuild the string to sign independently and verify the signature.
  const canonicalQuery = url.search.slice(1).replace(/&X-Goog-Signature=[0-9a-f]+$/, "");
  const canonicalRequest = [
    "GET", url.pathname, canonicalQuery, "host:storage.googleapis.com", "", "host", "UNSIGNED-PAYLOAD",
  ].join("\n");
  const stringToSign = [
    "GOOG4-RSA-SHA256", "20261107T100000Z", "20261107/auto/storage/goog4_request",
    createHash("sha256").update(canonicalRequest).digest("hex"),
  ].join("\n");
  assert.equal(FAKE_CREDENTIALS.signed.length, 1);
  assert.equal(FAKE_CREDENTIALS.signed[0]!.toString(), stringToSign);
  const signature = url.searchParams.get("X-Goog-Signature")!;
  assert.match(signature, /^[0-9a-f]{512}$/);
  assert.ok(createVerify("RSA-SHA256").update(stringToSign).verify(publicKey, Buffer.from(signature, "hex")));
  // The query keys are in canonical (sorted) order with the signature last.
  assert.deepEqual([...url.searchParams.keys()], [
    "X-Goog-Algorithm", "X-Goog-Credential", "X-Goog-Date", "X-Goog-Expires", "X-Goog-SignedHeaders", "X-Goog-Signature",
  ]);
});

test("metadata credentials: Workload Identity token (cached), email and IAM signBlob", async (t) => {
  let clock = NOW.getTime();
  let tokenNumber = 0;
  let signStatus = 200;
  const server = await fakeServer(t, (seen) => {
    if (seen.path.startsWith("/computeMetadata/")) {
      if (seen.headers["metadata-flavor"] !== "Google") return { status: 403 };
      const headers = { "metadata-flavor": "Google" };
      if (seen.path.endsWith("/default/token")) {
        tokenNumber += 1;
        return { status: 200, headers, body: JSON.stringify({ access_token: `token-${tokenNumber}`, expires_in: 3600, token_type: "Bearer" }) };
      }
      if (seen.path.endsWith("/default/email")) return { status: 200, headers, body: EMAIL };
      return { status: 404, headers };
    }
    if (seen.path === `/v1/projects/-/serviceAccounts/${encodeURIComponent(EMAIL)}:signBlob` && seen.method === "POST") {
      if (signStatus !== 200) {
        return { status: signStatus, body: JSON.stringify({ error: { status: "PERMISSION_DENIED", message: "secret detail" } }) };
      }
      const payload = Buffer.from(JSON.parse(seen.body.toString()).payload, "base64");
      return { status: 200, body: JSON.stringify({ keyId: "k", signedBlob: Buffer.concat([Buffer.from("sig:"), payload]).toString("base64") }) };
    }
    return { status: 404 };
  });
  const host = new URL(server.origin).host;
  const credentials = new MetadataGcpCredentialProvider({
    env: { GCE_METADATA_HOST: host, GOOGLE_APPLICATION_CREDENTIALS: "/never/read.json" },
    iamOrigin: server.origin,
    now: () => clock,
  });
  const [first, second] = await Promise.all([credentials.accessToken(), credentials.accessToken()]);
  assert.equal(first, "token-1");
  assert.equal(second, "token-1");
  assert.equal(await credentials.accessToken(), "token-1");
  clock += 3_550_000; // within a minute of expiry
  assert.equal(await credentials.accessToken(), "token-2");
  assert.equal(await credentials.serviceAccountEmail(), EMAIL);
  assert.equal(await credentials.serviceAccountEmail(), EMAIL);
  assert.equal(server.seen.filter((seen) => seen.path.endsWith("/email")).length, 1);

  const signed = await credentials.signBlob(Buffer.from("to sign"));
  assert.equal(signed.toString(), "sig:to sign");
  const sign = server.seen.at(-1)!;
  assert.equal(sign.headers.authorization, "Bearer token-2");
  assert.deepEqual(JSON.parse(sign.body.toString()), { payload: Buffer.from("to sign").toString("base64") });

  signStatus = 403;
  await assert.rejects(credentials.signBlob(Buffer.from("x")), (error: unknown) => {
    assert.ok(error instanceof GcpCredentialError);
    assert.equal(error.message, "IAM Credentials signBlob failed: 403 PERMISSION_DENIED");
    return true;
  });
  // Metadata requests always carry Metadata-Flavor and no request reads a key file.
  for (const seen of server.seen.filter((entry) => entry.path.startsWith("/computeMetadata/"))) {
    assert.equal(seen.headers["metadata-flavor"], "Google");
  }
});

test("metadata credentials: an unreachable or non-Google metadata server is a clear error", async (t) => {
  const impostor = await fakeServer(t, () => ({ status: 200, body: JSON.stringify({ access_token: "x", expires_in: 3600 }) }));
  const credentials = new MetadataGcpCredentialProvider({ env: { GCE_METADATA_HOST: new URL(impostor.origin).host } });
  await assert.rejects(credentials.accessToken(), /metadata server answered 200/);
  const unreachable = new MetadataGcpCredentialProvider({
    env: {}, fetchImpl: async () => { throw new TypeError("fetch failed"); },
  });
  await assert.rejects(unreachable.accessToken(), /Workload Identity/);
  assert.throws(() => new MetadataGcpCredentialProvider({ env: { GCE_METADATA_HOST: "http://evil/" } }), /GCE_METADATA_HOST/);
});

test("feed config: gcs storage with bucket and prefix", () => {
  const gcs = (extra: Record<string, string>) => loadDesktopFeedConfig({
    SELFHOST_DESKTOP_FEED_SIGNER: "file",
    SELFHOST_DESKTOP_FEED_KEY_FILES: JSON.stringify({ acme: "/run/secrets/acme.pem" }),
    SELFHOST_DESKTOP_FEED_STORAGE: "gcs",
    ...extra,
  });
  assert.deepEqual(gcs({ SELFHOST_DESKTOP_FEED_GCS_BUCKET: "feed-bucket" }), {
    signer: { kind: "file", label: "f1", keyFiles: { acme: "/run/secrets/acme.pem" } },
    storage: { kind: "gcs", bucket: "feed-bucket", prefix: "desktop-feed" },
    publisherTokenHashes: {},
  });
  assert.deepEqual(gcs({ SELFHOST_DESKTOP_FEED_GCS_BUCKET: "feed.bucket_1", SELFHOST_DESKTOP_FEED_GCS_PREFIX: "/site/feed/" })?.storage, {
    kind: "gcs", bucket: "feed.bucket_1", prefix: "site/feed",
  });
  assert.throws(() => gcs({}), /SELFHOST_DESKTOP_FEED_GCS_BUCKET/);
  for (const bad of ["Feed", "-feed", "fe", "a..b", "feed/bucket"]) {
    assert.throws(() => gcs({ SELFHOST_DESKTOP_FEED_GCS_BUCKET: bad }), /GCS_BUCKET/, bad);
  }
  for (const bad of ["feed!", "a//b", "a/../b", "a b"]) {
    assert.throws(() => gcs({ SELFHOST_DESKTOP_FEED_GCS_BUCKET: "feed-bucket", SELFHOST_DESKTOP_FEED_GCS_PREFIX: bad }), /GCS_PREFIX/, bad);
  }
  assert.throws(() => loadDesktopFeedConfig({ SELFHOST_DESKTOP_FEED_SIGNER: "memory", SELFHOST_DESKTOP_FEED_STORAGE: "azure" }), /s3, gcs or memory/);
});
