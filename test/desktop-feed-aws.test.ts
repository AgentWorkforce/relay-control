// SigV4, AWS KMS signer and S3 object store for the Desktop feed, against
// published AWS signing vectors and a fake local HTTP server.
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as edSign } from "node:crypto";
import { createServer, type IncomingMessage } from "node:http";
import { Readable } from "node:stream";
import test, { type TestContext } from "node:test";
import { presignV4, signV4, StaticAwsCredentialProvider } from "../src/aws/sigv4.js";
import { loadDesktopFeedConfig } from "../src/config.js";
import {
  AWS_KMS_MAX_RAW_MESSAGE_BYTES,
  AwsKmsDesktopFeedSigner,
  rawPublicKeyFromSpki,
  SignerUnavailableError,
  verifyEd25519,
} from "../src/desktop-feed/signer.js";
import { S3DesktopFeedStorage, StorageError } from "../src/desktop-feed/storage.js";
import { close, listen } from "./support/harness.js";

const NOW = new Date("2026-11-07T10:00:00.000Z");
const CREDENTIALS = new StaticAwsCredentialProvider({
  accessKeyId: "AKIDFEEDTEST",
  secretAccessKey: "feed-test-secret",
  sessionToken: "feed-session-token",
});
const ALIASES = { acme: "alias/desktop-feed-acme", other: "alias/desktop-feed-other" };
const ALIASES_JSON = JSON.stringify(ALIASES);

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

test("signV4 and presignV4 reproduce the published AWS vectors", () => {
  // AWS SigV4 test suite, get-vanilla.
  const vanilla = signV4({
    method: "GET",
    url: new URL("https://example.amazonaws.com/"),
    region: "us-east-1",
    service: "service",
    body: "",
    credentials: { accessKeyId: "AKIDEXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" },
    now: new Date("2015-08-30T12:36:00Z"),
    contentSha256Header: false,
  });
  assert.equal(
    vanilla.authorization,
    "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
  );
  const s3Credentials = { accessKeyId: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" };
  // S3 docs, "Example: GET Object" with a Range header.
  const getObject = signV4({
    method: "GET",
    url: new URL("https://examplebucket.s3.amazonaws.com/test.txt"),
    region: "us-east-1",
    service: "s3",
    body: "",
    credentials: s3Credentials,
    now: new Date("2013-05-24T00:00:00Z"),
    extraHeaders: { range: "bytes=0-9" },
  });
  assert.equal(
    getObject.authorization,
    "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
  );
  // S3 docs, "Example: presigned URL".
  const presigned = presignV4({
    method: "GET",
    url: new URL("https://examplebucket.s3.amazonaws.com/test.txt"),
    region: "us-east-1",
    service: "s3",
    credentials: s3Credentials,
    now: new Date("2013-05-24T00:00:00Z"),
    expiresSeconds: 86400,
  });
  assert.equal(presigned.searchParams.get("X-Amz-Signature"), "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404");
});

test("AWS KMS signer: Sign and GetPublicKey over SigV4, one alias per profile", async (t) => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  let failNext = false;
  const kms = await fakeServer(t, (seen) => {
    if (failNext) return { status: 400, body: JSON.stringify({ __type: "com.amazonaws.kms#DisabledException" }) };
    const body = JSON.parse(seen.body.toString("utf8")) as Record<string, string>;
    if (seen.headers["x-amz-target"] === "TrentService.Sign") {
      return { status: 200, body: JSON.stringify({ Signature: edSign(null, Buffer.from(body.Message!, "base64"), privateKey).toString("base64") }) };
    }
    return { status: 200, body: JSON.stringify({ KeySpec: "ECC_NIST_EDWARDS25519", PublicKey: spki.toString("base64") }) };
  });
  assert.throws(() => new AwsKmsDesktopFeedSigner({ region: "eu-west-2", keyAliases: ALIASES, label: "Bad_Label" }), /label/);
  assert.throws(() => new AwsKmsDesktopFeedSigner({ region: "eu-west-2", keyAliases: { acme: "arn:aws:s3:::bucket" }, label: "k1" }), /alias/);
  assert.throws(() => new AwsKmsDesktopFeedSigner({ region: "eu-west-2", keyAliases: { acme: "alias/aws/s3" }, label: "k1" }), /alias/);
  const signer = new AwsKmsDesktopFeedSigner({
    region: "eu-west-2", keyAliases: ALIASES, label: "k1", credentials: CREDENTIALS, endpoint: `${kms.origin}/`, now: () => NOW,
  });
  assert.equal(signer.region, "eu-west-2");
  assert.equal(signer.keyId("acme"), "fk_acme_k1");
  assert.equal(signer.hasProfile("acme"), true);
  assert.equal(signer.hasProfile("nokey"), false);
  assert.equal(signer.maxCanonicalBytes(), AWS_KMS_MAX_RAW_MESSAGE_BYTES);
  assert.equal(AWS_KMS_MAX_RAW_MESSAGE_BYTES, 4096);

  const message = Buffer.from('{"schema":1}');
  const signed = await signer.sign("acme", message);
  assert.equal(signed.keyId, "fk_acme_k1");
  assert.match(signed.signature, /^[A-Za-z0-9_-]{86}$/);
  const raw = await signer.publicKey("acme");
  assert.equal(raw, rawPublicKeyFromSpki(spki));
  assert.equal(Buffer.from(raw, "base64").length, 32);
  assert.ok(verifyEd25519(raw, message, signed.signature));
  await signer.publicKey("acme");
  assert.equal(kms.seen.length, 2, "GetPublicKey is cached");

  const [signCall, keyCall] = kms.seen;
  assert.equal(signCall!.method, "POST");
  assert.equal(signCall!.path, "/");
  assert.equal(signCall!.headers["content-type"], "application/x-amz-json-1.1");
  assert.equal(signCall!.headers["x-amz-target"], "TrentService.Sign");
  assert.equal(signCall!.headers["x-amz-date"], "20261107T100000Z");
  assert.equal(signCall!.headers["x-amz-security-token"], "feed-session-token");
  assert.match(
    signCall!.headers.authorization!,
    /^AWS4-HMAC-SHA256 Credential=AKIDFEEDTEST\/20261107\/eu-west-2\/kms\/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=[0-9a-f]{64}$/,
  );
  assert.deepEqual(JSON.parse(signCall!.body.toString("utf8")), {
    KeyId: ALIASES.acme, Message: message.toString("base64"), MessageType: "RAW", SigningAlgorithm: "ED25519_SHA_512",
  });
  assert.equal(keyCall!.headers["x-amz-target"], "TrentService.GetPublicKey");
  assert.deepEqual(JSON.parse(keyCall!.body.toString("utf8")), { KeyId: ALIASES.acme });

  await assert.rejects(signer.sign("acme", Buffer.alloc(4097)), SignerUnavailableError);
  assert.equal(kms.seen.length, 2, "an oversized message never reaches KMS");
  await signer.sign("other", message);
  assert.equal(JSON.parse(kms.seen[2]!.body.toString("utf8")).KeyId, ALIASES.other, "each profile signs with its own key");
  await assert.rejects(signer.sign("nokey", message), SignerUnavailableError);
  await assert.rejects(signer.publicKey("nokey"), SignerUnavailableError);
  assert.equal(kms.seen.length, 3, "a profile without an alias never reaches KMS");
  failNext = true;
  await assert.rejects(signer.sign("acme", message), (error: Error) =>
    error instanceof SignerUnavailableError && /DisabledException/.test(error.message));
  const unreachable = new AwsKmsDesktopFeedSigner({
    region: "eu-west-2", keyAliases: ALIASES, label: "k1", credentials: CREDENTIALS, endpoint: "http://127.0.0.1:1/", now: () => NOW,
  });
  await assert.rejects(unreachable.publicKey("acme"), SignerUnavailableError);
});

test("S3 storage: streamed PUT, ranged GET, DELETE and presigned GET", async (t) => {
  const bytes = Buffer.from("desktop feed asset bytes");
  const sha = createHash("sha256").update(bytes).digest("hex");
  let putStatus = 200;
  const s3 = await fakeServer(t, (seen) => {
    if (seen.method === "PUT") return { status: putStatus };
    if (seen.method === "DELETE") return { status: 204 };
    if (seen.path.endsWith("/missing")) return { status: 404 };
    if (seen.headers.range) return { status: 206, body: bytes.subarray(2, 6) };
    return { status: 200, body: bytes };
  });
  assert.throws(() => new S3DesktopFeedStorage({ bucket: "Bad_Bucket", region: "eu-west-2", prefix: "x" }), /bucket/);
  const storage = new S3DesktopFeedStorage({
    bucket: "feed-bucket", region: "eu-west-2", prefix: "desktop-feed", credentials: CREDENTIALS,
    endpoint: s3.origin, now: () => NOW,
  });
  assert.equal(storage.downloadHost(), "feed-bucket.s3.eu-west-2.amazonaws.com");
  const key = "profiles/acme/releases/2026.11.0/Acme-2026.11.0-arm64.dmg";

  await storage.put(key, Readable.from([bytes.subarray(0, 5), bytes.subarray(5)]), bytes.length, sha);
  const put = s3.seen[0]!;
  assert.equal(put.method, "PUT");
  assert.equal(put.path, `/feed-bucket/desktop-feed/${key}`);
  assert.deepEqual(put.body, bytes);
  assert.equal(put.headers["content-length"], String(bytes.length));
  assert.equal(put.headers["x-amz-content-sha256"], sha);
  assert.equal(put.headers["x-amz-date"], "20261107T100000Z");
  assert.match(
    put.headers.authorization!,
    /^AWS4-HMAC-SHA256 Credential=AKIDFEEDTEST\/20261107\/eu-west-2\/s3\/aws4_request, SignedHeaders=content-length;content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token;x-amz-server-side-encryption, Signature=[0-9a-f]{64}$/,
  );
  assert.equal(put.headers["x-amz-server-side-encryption"], "AES256");

  const ranged = await storage.get(key, { start: 2, end: 5 });
  assert.ok(ranged);
  const chunks: Buffer[] = [];
  for await (const chunk of ranged) chunks.push(Buffer.from(chunk));
  assert.deepEqual(Buffer.concat(chunks), bytes.subarray(2, 6));
  const get = s3.seen[1]!;
  assert.equal(get.method, "GET");
  assert.equal(get.headers.range, "bytes=2-5");
  assert.equal(get.headers["x-amz-content-sha256"], createHash("sha256").update("").digest("hex"));
  assert.match(get.headers.authorization!, /SignedHeaders=host;range;x-amz-content-sha256;x-amz-date;x-amz-security-token,/);
  assert.equal(await storage.get("missing"), null);

  await storage.delete(key);
  assert.equal(s3.seen.at(-1)!.method, "DELETE");
  assert.equal(s3.seen.at(-1)!.path, `/feed-bucket/desktop-feed/${key}`);

  const url = await storage.presignGet(key, 300, NOW);
  assert.equal(url.protocol, "https:");
  assert.equal(url.host, "feed-bucket.s3.eu-west-2.amazonaws.com");
  assert.equal(url.pathname, `/desktop-feed/${key}`);
  assert.equal(url.searchParams.get("X-Amz-Expires"), "300");
  assert.equal(url.searchParams.get("X-Amz-Credential"), "AKIDFEEDTEST/20261107/eu-west-2/s3/aws4_request");
  assert.equal(url.searchParams.get("X-Amz-SignedHeaders"), "host");
  assert.equal(url.searchParams.get("X-Amz-Security-Token"), "feed-session-token");
  assert.match(url.searchParams.get("X-Amz-Signature")!, /^[0-9a-f]{64}$/);

  putStatus = 400;
  await assert.rejects(storage.put(key, Readable.from([bytes]), bytes.length, sha), StorageError);
});

test("feed config: off unless both signer and storage are set", () => {
  assert.equal(loadDesktopFeedConfig({}), null);
  assert.throws(() => loadDesktopFeedConfig({ SELFHOST_DESKTOP_FEED_SIGNER: "memory" }), /set together/);
  assert.throws(() => loadDesktopFeedConfig({
    SELFHOST_DESKTOP_FEED_SIGNER: "memory", SELFHOST_DESKTOP_FEED_STORAGE: "memory", NODE_ENV: "production",
  }), /not NODE_ENV=production/);
  assert.throws(() => loadDesktopFeedConfig({ SELFHOST_DESKTOP_FEED_STORAGE: "memory" }), /set together/);
  assert.deepEqual(loadDesktopFeedConfig({ SELFHOST_DESKTOP_FEED_SIGNER: "memory", SELFHOST_DESKTOP_FEED_STORAGE: "memory" }), {
    signer: { kind: "memory", label: "dev" }, storage: { kind: "memory" }, publisherTokenHashes: {},
  });
  const hash = "a".repeat(64);
  assert.deepEqual(loadDesktopFeedConfig({
    SELFHOST_DESKTOP_FEED_SIGNER: "awskms",
    SELFHOST_DESKTOP_FEED_KMS_REGION: "eu-west-2",
    SELFHOST_DESKTOP_FEED_KMS_KEY_ALIASES: ALIASES_JSON,
    SELFHOST_DESKTOP_FEED_STORAGE: "s3",
    SELFHOST_DESKTOP_FEED_S3_BUCKET: "feed-bucket",
    SELFHOST_DESKTOP_FEED_PUBLISHER_TOKEN_HASHES: JSON.stringify({ acme: [hash] }),
  }), {
    signer: { kind: "awskms", region: "eu-west-2", label: "k1", keyAliases: ALIASES },
    storage: { kind: "s3", bucket: "feed-bucket", region: "eu-west-2", prefix: "desktop-feed" },
    publisherTokenHashes: { acme: [hash] },
  });
  const kmsEnv = {
    SELFHOST_DESKTOP_FEED_SIGNER: "awskms", SELFHOST_DESKTOP_FEED_STORAGE: "memory", SELFHOST_DESKTOP_FEED_KMS_REGION: "eu-west-2",
  };
  assert.throws(() => loadDesktopFeedConfig(kmsEnv), /KMS_KEY_ALIASES/);
  assert.throws(() => loadDesktopFeedConfig({ ...kmsEnv, SELFHOST_DESKTOP_FEED_KMS_REGION: "", SELFHOST_DESKTOP_FEED_KMS_KEY_ALIASES: ALIASES_JSON }), /KMS_REGION/);
  assert.throws(() => loadDesktopFeedConfig({ ...kmsEnv, SELFHOST_DESKTOP_FEED_KMS_KEY_ALIASES: "{}" }), /at least one profile/);
  assert.throws(() => loadDesktopFeedConfig({ ...kmsEnv, SELFHOST_DESKTOP_FEED_KMS_KEY_ALIASES: JSON.stringify({ acme: "key/1234" }) }), /alias\/name/);
  assert.throws(() => loadDesktopFeedConfig({ ...kmsEnv, SELFHOST_DESKTOP_FEED_KMS_KEY_ALIASES: JSON.stringify({ "Bad-Id": "alias/x" }) }), /profile id/);
  assert.throws(() => loadDesktopFeedConfig({
    ...kmsEnv, SELFHOST_DESKTOP_FEED_KMS_KEY_ALIASES: ALIASES_JSON, SELFHOST_DESKTOP_FEED_KEY_LABEL: "Not Valid",
  }), /KEY_LABEL/);
  assert.throws(() => loadDesktopFeedConfig({
    ...kmsEnv, SELFHOST_DESKTOP_FEED_KMS_KEY_ALIASES: ALIASES_JSON, SELFHOST_DESKTOP_FEED_PUBLISHER_TOKEN_HASHES: JSON.stringify({ acme: ["plaintext"] }),
  }), /sha256/);
  assert.throws(() => loadDesktopFeedConfig({
    ...kmsEnv, SELFHOST_DESKTOP_FEED_KMS_KEY_ALIASES: ALIASES_JSON, SELFHOST_DESKTOP_FEED_STORAGE: "s3", SELFHOST_DESKTOP_FEED_S3_BUCKET: "dotted.bucket",
  }), /without dots/);
  assert.throws(() => loadDesktopFeedConfig({ SELFHOST_DESKTOP_FEED_SIGNER: "local", SELFHOST_DESKTOP_FEED_STORAGE: "memory" }), /awskms or memory/);
});

test("S3 storage: copy is server-side, encrypted, and sees an error inside a 200", async (t) => {
  let answer = "<CopyObjectResult></CopyObjectResult>";
  const s3 = await fakeServer(t, () => ({ status: 200, body: answer }));
  const storage = new S3DesktopFeedStorage({
    bucket: "feed-bucket", region: "eu-west-2", prefix: "desktop-feed", credentials: CREDENTIALS, endpoint: s3.origin, now: () => NOW,
  });
  const source = "profiles/acme/drafts/2026.11.0/Acme+x.dmg";
  const destination = "profiles/acme/releases/2026.11.0/Acme+x.dmg";
  await storage.copy(source, destination);
  const copy = s3.seen[0]!;
  assert.equal(copy.method, "PUT");
  assert.equal(copy.path, "/feed-bucket/desktop-feed/profiles/acme/releases/2026.11.0/Acme%2Bx.dmg");
  assert.equal(copy.headers["x-amz-copy-source"], "/feed-bucket/desktop-feed/profiles/acme/drafts/2026.11.0/Acme%2Bx.dmg");
  assert.equal(copy.headers["x-amz-server-side-encryption"], "AES256");
  assert.match(copy.headers.authorization!, /x-amz-copy-source;.*x-amz-server-side-encryption/);
  assert.equal(copy.body.length, 0);
  answer = "<Error><Code>InternalError</Code></Error>";
  await assert.rejects(storage.copy(source, destination), StorageError);
});

test("feed config: S3 prefix falls back to desktop-feed when empty and refuses characters SigV4 encodes differently", () => {
  const s3 = (prefix: string) => loadDesktopFeedConfig({
    SELFHOST_DESKTOP_FEED_SIGNER: "awskms",
    SELFHOST_DESKTOP_FEED_KMS_REGION: "eu-west-2",
    SELFHOST_DESKTOP_FEED_KMS_KEY_ALIASES: ALIASES_JSON,
    SELFHOST_DESKTOP_FEED_STORAGE: "s3",
    SELFHOST_DESKTOP_FEED_S3_BUCKET: "feed-bucket",
    SELFHOST_DESKTOP_FEED_S3_PREFIX: prefix,
  })?.storage;
  for (const empty of ["", "  ", "/", "//"]) {
    assert.deepEqual(s3(empty), { kind: "s3", bucket: "feed-bucket", region: "eu-west-2", prefix: "desktop-feed" }, JSON.stringify(empty));
  }
  assert.equal((s3("/site/feed.v1_a-b/") as { prefix: string }).prefix, "site/feed.v1_a-b");
  for (const bad of ["feed!", "feed*", "a/(b)", "it's", "a//b", "a/../b", "a b"]) {
    assert.throws(() => s3(bad), /S3_PREFIX/, bad);
  }
});
