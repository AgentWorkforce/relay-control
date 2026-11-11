import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { createApp } from "../src/app.js";
import { presignV4, StaticAwsCredentialProvider } from "../src/aws/sigv4.js";
import { AwsStsClient, StsError } from "../src/aws/sts.js";
import { loadHistoryUploadConfig, type HistoryUploadConfig, type SelfhostConfig } from "../src/config.js";
import { hashSecret } from "../src/crypto.js";
import {
  HistoryUploadCredentials,
  journalKey,
  JournalUnavailableError,
  layoutComponent,
  parseUploadCredentialsRequest,
  uploadInboxPrefix,
  S3PrivacyJournalReader,
  sessionPolicy,
  signWitness,
  UPLOAD_CONTRACT,
  uploadKeyValid,
  uploadUserHash,
  verifyWitness,
} from "../src/history-upload/credentials.js";
import { migrate } from "../src/migrations.js";
import { ControlPlaneStore } from "../src/store.js";
import { close, listen, PGliteDatabase, request } from "./support/harness.js";

// Every value here is a fake test fixture.
const BOOTSTRAP = "bootstrap-token-that-is-at-least-32-bytes";
const INTERNAL = "internal-service-token-at-least-32-bytes!";
const INTROSPECT_SECRET = "introspect-secret-that-is-at-least-32-bytes";
const READ_SECRET = "session-read-secret-that-is-at-least-32-b";
const ORIGIN = "https://history.selfhosted.company";
/** base64url of the 32 ASCII bytes "witness-test-key-0123456789abcde". */
const WITNESS_KEY = "d2l0bmVzcy10ZXN0LWtleS0wMTIzNDU2Nzg5YWJjZGU";
const WITNESS_KEY_BYTES = Buffer.from(WITNESS_KEY, "base64url");
const ROLE_ARN = "arn:aws:iam::123456789012:role/history-upload-test";
const KMS_ARN = "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555";
const BUCKET = "history-upload-test";
const STATIC_CREDS = { accessKeyId: "AKIDEXAMPLEFAKE", secretAccessKey: "fake-control-secret-key" };
const ASSUMED = { accessKeyId: "ASIAFAKEASSUMED", secretAccessKey: "fake-assumed-secret", sessionToken: "fake-assumed-session-token" };
const SHA_A = Buffer.alloc(32, 1).toString("base64");
const SHA_B = Buffer.alloc(32, 2).toString("base64");
const TENANT = { orgId: "org-a", workspaceId: "ws-a", userId: "user-1" };
const UPLOAD_SIGNED_HEADERS = "content-encoding;host;if-none-match;x-amz-checksum-sha256;x-amz-meta-relay-witness;x-amz-server-side-encryption;x-amz-server-side-encryption-aws-kms-key-id";

type Recorded = { method: string; path: string; headers: IncomingMessage["headers"]; body: string };

function stsXml(expiresAt: Date) {
  return `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleResult><Credentials>`
    + `<AccessKeyId>${ASSUMED.accessKeyId}</AccessKeyId><SecretAccessKey>${ASSUMED.secretAccessKey}</SecretAccessKey>`
    + `<SessionToken>${ASSUMED.sessionToken}</SessionToken><Expiration>${expiresAt.toISOString()}</Expiration>`
    + `</Credentials></AssumeRoleResult></AssumeRoleResponse>`;
}

/** One fake AWS origin: STS at POST /, S3 GET at /<bucket>/<key>. */
async function fakeAws(t: TestContext) {
  const state = {
    requests: [] as Recorded[],
    sts: { status: 200, body: null as string | null },
    journal: { status: 200, body: JSON.stringify({ v: 3, seq: 7, pending: [], ambiguous: [] }) },
    expiresAt: null as Date | null,
  };
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const path = new URL(req.url ?? "/", "http://x").pathname;
      const body = Buffer.concat(chunks).toString("utf8");
      state.requests.push({ method: req.method ?? "", path, headers: req.headers, body });
      if (req.method === "POST" && path === "/") {
        state.expiresAt = new Date(Math.floor(Date.now() / 1000) * 1000 + 3_600_000);
        res.writeHead(state.sts.status, { "content-type": "text/xml" });
        res.end(state.sts.body ?? stsXml(state.expiresAt));
        return;
      }
      if (req.method === "GET") {
        res.writeHead(state.journal.status, { "content-type": "application/json" });
        res.end(state.journal.body);
        return;
      }
      res.writeHead(500);
      res.end();
    });
  });
  const origin = await listen(server);
  t.after(() => close(server));
  return { origin, state };
}

function uploadConfig(overrides: Partial<HistoryUploadConfig> = {}): HistoryUploadConfig {
  return {
    mode: "allowlist", allowlist: [], bucket: BUCKET, region: "us-east-1", keyRoot: "96bulls",
    endpoint: null, internalEndpoint: null, roleArn: ROLE_ARN, kmsKeyArn: KMS_ARN, storeCredentials: null, witnessKey: WITNESS_KEY_BYTES, maxObjectBytes: 2_097_152, ...overrides,
  };
}

async function setup(t: TestContext, options: {
  /** A config, or one built from the fake AWS origin (for S3-compatible endpoints). */
  upload?: HistoryUploadConfig | null | ((awsOrigin: string) => HistoryUploadConfig);
  allowOwner?: boolean;
  /** Leave out the S3 endpoint hook so the journal read follows config.internalEndpoint. */
  omitS3Hook?: boolean;
  /** Leave out the credentials hook so URLs and the journal read are signed with config.storeCredentials. */
  omitCredentialsHook?: boolean;
  /** SELFHOST_CAPTURE_POLICY_UPLOADS; absent is report. */
  capturePolicyUploads?: "report" | "enforce";
} = {}) {
  const aws = await fakeAws(t);
  const database = new PGliteDatabase();
  await migrate(database);
  const upload = options.upload === undefined ? uploadConfig()
    : typeof options.upload === "function" ? options.upload(aws.origin) : options.upload;
  const config: SelfhostConfig = {
    databaseUrl: "unused-in-test",
    publicBaseUrl: "https://control.internal.example",
    relaycastUrl: "http://relaycast.internal",
    relaycastPublicUrl: "https://relaycast.selfhosted.test",
    relayhistoryUrl: "http://history.internal",
    relayhistoryPublicUrl: ORIGIN,
    sessionReadApi: { url: "http://history.internal", publicUrl: ORIGIN, secret: READ_SECRET },
    introspectSecret: INTROSPECT_SECRET,
    bootstrapToken: BOOTSTRAP,
    encryptionKeyring: { active: { id: "test-key", key: Buffer.alloc(32, 7) } },
    internalServiceToken: INTERNAL,
    oauthRedirectUrl: "https://control.internal.example/api/v1/integrations/oauth/callback",
    dashboardUrl: "https://control.internal.example/",
    port: 3000,
    host: "127.0.0.1",
    historyUpload: upload,
    ...(options.capturePolicyUploads ? { capturePolicyUploads: options.capturePolicyUploads } : {}),
  };
  const store = new ControlPlaneStore(database, config.encryptionKeyring, 0);
  const server = createServer(createApp({
    config,
    store,
    historyUpload: {
      ...(options.omitCredentialsHook ? {} : { credentials: new StaticAwsCredentialProvider(STATIC_CREDS) }),
      endpoints: options.omitS3Hook ? { sts: aws.origin } : { sts: aws.origin, s3: aws.origin },
    },
  }));
  const origin = await listen(server);
  t.after(async () => {
    await close(server);
    await database.close();
  });
  const org = await request(origin, "/api/v1/organizations", {
    method: "POST", token: BOOTSTRAP, body: { name: "Tenant", ownerEmail: "owner@example.test", ownerName: "Owner" },
  });
  assert.equal(org.status, 201);
  const created = await request(origin, `/api/v1/organizations/${org.body.id}/workspaces`, {
    method: "POST", token: BOOTSTRAP, body: { name: "alpha", relaycastApiKey: "rk_alpha" },
  });
  assert.equal(created.status, 201);
  const workspace = created.body.id as string;
  const userId = org.body.owner.id as string;
  // The allowlist is read per request, so the owner can be listed once its id exists.
  if (upload && options.allowOwner !== false) upload.allowlist.push(userId);
  const started = await request(origin, "/api/v1/auth/device/start", { method: "POST", body: { client_name: "upload-test" } });
  await request(origin, "/api/v1/auth/device/approve", {
    method: "POST", token: BOOTSTRAP,
    body: { action: "approve", user_code: started.body.user_code, user_id: userId, workspace_id: workspace },
  });
  const tokens = await request(origin, "/api/v1/auth/device/token", { method: "POST", body: { device_code: started.body.device_code } });
  assert.equal(tokens.status, 200);
  const tenant = { orgId: org.body.id as string, workspaceId: workspace, userId };
  return {
    origin, aws, database, workspace, userId, tenant, token: tokens.body.access_token as string,
    organizationId: org.body.id as string,
    path: `/api/v1/workspaces/${workspace}/relayhistory/upload-credentials`,
  };
}

const stsBody = { originId: "machine-1.claude", kind: "sts" };

// ---- pure helpers ----

test("layoutComponent keeps safe ids, maps unsafe characters and hashes long ids", () => {
  assert.equal(layoutComponent("ws-a.b_c"), "ws-a.b_c");
  assert.equal(layoutComponent("a/b:c"), "a_b_c");
  assert.equal(layoutComponent(".hidden"), "_hidden");
  const long = "x".repeat(200);
  const mapped = layoutComponent(long);
  assert.equal(mapped.length, 128);
  assert.match(mapped, /^x{119}-[0-9a-f]{8}$/);
});

test("user hash, journal key and upload inbox prefix match the pipeline vectors", () => {
  assert.equal(uploadUserHash(TENANT), "44185655a8bf362ce1034afe32f7ae4c");
  assert.equal(journalKey("96bulls", TENANT),
    "96bulls/.admission-inbox/org-a/v1/ws=ws-a/m=srv_44185655a8bf362ce1034afe32f7ae4c/privacy-journal.json");
  assert.equal(uploadInboxPrefix("96bulls", TENANT),
    "96bulls/.upload-inbox/org-a/v1/ws=ws-a/u=44185655a8bf362ce1034afe32f7ae4c/");
  const colon = { ...TENANT, workspaceId: "ws:b" };
  assert.match(uploadInboxPrefix("96bulls", colon), /^96bulls\/\.upload-inbox\/org-a\/v1\/ws=ws_b\/u=[0-9a-f]{32}\/$/);
});

test("sessionPolicy renders the exact policy", () => {
  assert.equal(
    sessionPolicy({ bucket: "b1", prefix: "96bulls/.upload-inbox/org-a/v1/ws=ws-a/u=44185655a8bf362ce1034afe32f7ae4c/", kmsKeyArn: KMS_ARN }),
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:AbortMultipartUpload"],'
    + '"Resource":"arn:aws:s3:::b1/96bulls/.upload-inbox/org-a/v1/ws=ws-a/u=44185655a8bf362ce1034afe32f7ae4c/*",'
    + '"Condition":{"StringEquals":{"s3:x-amz-server-side-encryption":"aws:kms","s3:x-amz-server-side-encryption-aws-kms-key-id":"'
    + KMS_ARN + '"},"Null":{"s3:if-none-match":"false"}}},{"Effect":"Allow","Action":"kms:GenerateDataKey","Resource":"'
    + KMS_ARN + '","Condition":{"StringLike":{"kms:EncryptionContext:aws:s3:arn":'
    + '"arn:aws:s3:::b1/96bulls/.upload-inbox/org-a/v1/ws=ws-a/u=44185655a8bf362ce1034afe32f7ae4c/*"}}}]}',
  );
  assert.equal(
    sessionPolicy({ bucket: "b2", prefix: "root/.upload-inbox/o/v1/ws=w/u=0/", kmsKeyArn: "k" }),
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:AbortMultipartUpload"],'
    + '"Resource":"arn:aws:s3:::b2/root/.upload-inbox/o/v1/ws=w/u=0/*",'
    + '"Condition":{"StringEquals":{"s3:x-amz-server-side-encryption":"aws:kms","s3:x-amz-server-side-encryption-aws-kms-key-id":"k"},'
    + '"Null":{"s3:if-none-match":"false"}}},{"Effect":"Allow","Action":"kms:GenerateDataKey","Resource":"k",'
    + '"Condition":{"StringLike":{"kms:EncryptionContext:aws:s3:arn":"arn:aws:s3:::b2/root/.upload-inbox/o/v1/ws=w/u=0/*"}}}]}',
  );
});

test("uploadKeyValid accepts relative keys and refuses traversal and bad segments", () => {
  for (const key of ["sessions/2026/abc.ndjson.zst", "a=1/b", `a/${"b".repeat(160)}`]) assert.equal(uploadKeyValid(key), true, key);
  for (const key of ["", "/a", "a//b", ".hidden", "a/../b", "a/./b", "a".repeat(513), `a/${"b".repeat(161)}`, "a b", ":a"]) {
    assert.equal(uploadKeyValid(key), false, JSON.stringify(key.slice(0, 20)));
  }
});

test("uploadKeyValid accepts the pipeline's o=/b=/d= key with a 128-char originId; originId follows the segment rule", () => {
  const originId = `desktop-${"m".repeat(120)}`;
  assert.equal(originId.length, 128);
  const hex = (value: string) => createHash("sha256").update(value).digest("hex").slice(0, 32);
  const key = `o=${originId}/b=${hex("batch-1")}/d=${hex("object bytes")}-w7.json.zst`;
  assert.equal(uploadKeyValid(key), true);
  assert.equal(uploadKeyValid("o=desktop:1/b=x/d=y-w1.json.zst"), false);
  assert.equal(parseUploadCredentialsRequest({ originId, kind: "sts" }).originId, originId);
  for (const bad of ["desktop:1", ".dot", "a".repeat(129), ""]) {
    assert.throws(() => parseUploadCredentialsRequest({ originId: bad, kind: "sts" }), /originId must match/);
  }
});

test("witness round-trips, refuses tampering and wrong keys, and matches the pinned vector", () => {
  const payload = { v: 1 as const, org: "org-a", ws: "ws-a", user: "user-1", seq: 3, exp: 1_800_000_000 };
  const token = signWitness(WITNESS_KEY_BYTES, payload);
  assert.equal(token,
    "v1.eyJ2IjoxLCJvcmciOiJvcmctYSIsIndzIjoid3MtYSIsInVzZXIiOiJ1c2VyLTEiLCJzZXEiOjMsImV4cCI6MTgwMDAwMDAwMH0.2uLZTDYatGcpZFcz89_6ck9yrNwigxlPUW4ng9-H33A");
  assert.deepEqual(verifyWitness(WITNESS_KEY_BYTES, token), payload);
  const [, body, mac] = token.split(".") as [string, string, string];
  const forged = Buffer.from(JSON.stringify({ ...payload, seq: 4 })).toString("base64url");
  assert.equal(verifyWitness(WITNESS_KEY_BYTES, `v1.${forged}.${mac}`), null);
  assert.equal(verifyWitness(WITNESS_KEY_BYTES, `v1.${body}.${mac.slice(0, -2)}AA`), null);
  assert.equal(verifyWitness(Buffer.from("another-witness-key-0123456789ab"), token), null);
  assert.equal(verifyWitness(WITNESS_KEY_BYTES, "not-a-witness"), null);
  assert.equal(verifyWitness(WITNESS_KEY_BYTES, `${body}.${mac}`), null);
  assert.equal(verifyWitness(WITNESS_KEY_BYTES, `v2.${body}.${mac}`), null);
});

// ---- config ----

function uploadEnv(extra: Record<string, string | undefined> = {}) {
  return {
    SELFHOST_HISTORY_UPLOAD_DIRECT: "allowlist",
    SELFHOST_HISTORY_UPLOAD_ALLOWLIST: " user-1, ,user-2 ",
    SELFHOST_HISTORY_UPLOAD_BUCKET: BUCKET,
    SELFHOST_HISTORY_UPLOAD_REGION: "us-east-1",
    SELFHOST_HISTORY_UPLOAD_ROLE_ARN: ROLE_ARN,
    SELFHOST_HISTORY_UPLOAD_KMS_KEY_ARN: KMS_ARN,
    SELFHOST_HISTORY_UPLOAD_WITNESS_KEY: WITNESS_KEY,
    ...extra,
  };
}

test("loadHistoryUploadConfig parses modes, requires every input and bounds the object size", () => {
  assert.equal(loadHistoryUploadConfig({}), null);
  assert.equal(loadHistoryUploadConfig({ SELFHOST_HISTORY_UPLOAD_DIRECT: "off" }), null);
  assert.throws(() => loadHistoryUploadConfig(uploadEnv({ SELFHOST_HISTORY_UPLOAD_DIRECT: "maybe" })), /SELFHOST_HISTORY_UPLOAD_DIRECT/);
  assert.throws(() => loadHistoryUploadConfig(uploadEnv({ SELFHOST_HISTORY_UPLOAD_ALLOWLIST: " , " })), /SELFHOST_HISTORY_UPLOAD_ALLOWLIST/);
  assert.deepEqual(loadHistoryUploadConfig(uploadEnv()), uploadConfig({ allowlist: ["user-1", "user-2"] }));
  const on = loadHistoryUploadConfig(uploadEnv({ SELFHOST_HISTORY_UPLOAD_DIRECT: "on" }));
  assert.equal(on?.mode, "on");
  assert.deepEqual(on?.allowlist, []);
  for (const name of ["SELFHOST_HISTORY_UPLOAD_BUCKET", "SELFHOST_HISTORY_UPLOAD_ROLE_ARN", "SELFHOST_HISTORY_UPLOAD_KMS_KEY_ARN", "SELFHOST_HISTORY_UPLOAD_WITNESS_KEY"]) {
    assert.throws(() => loadHistoryUploadConfig(uploadEnv({ [name]: undefined })), new RegExp(name));
  }
  for (const bad of ["c2hvcnQ", "short-fake-key", "not base64url at all, though longer than forty-four chars"]) {
    assert.throws(() => loadHistoryUploadConfig(uploadEnv({ SELFHOST_HISTORY_UPLOAD_WITNESS_KEY: bad })),
      (error: Error) => error.message === "SELFHOST_HISTORY_UPLOAD_WITNESS_KEY (or _FILE) must be base64url of at least 32 bytes"
        && !error.message.includes(bad));
  }
  assert.deepEqual(loadHistoryUploadConfig(uploadEnv({ SELFHOST_HISTORY_UPLOAD_WITNESS_KEY: `${WITNESS_KEY}=` }))?.witnessKey, WITNESS_KEY_BYTES);
  assert.throws(() => loadHistoryUploadConfig(uploadEnv({ SELFHOST_HISTORY_UPLOAD_MAX_OBJECT_BYTES: "1023" })), /MAX_OBJECT_BYTES/);
  assert.throws(() => loadHistoryUploadConfig(uploadEnv({ SELFHOST_HISTORY_UPLOAD_MAX_OBJECT_BYTES: "104857601" })), /MAX_OBJECT_BYTES/);
  assert.throws(() => loadHistoryUploadConfig(uploadEnv({ SELFHOST_HISTORY_UPLOAD_MAX_OBJECT_BYTES: "2e6" })), /MAX_OBJECT_BYTES/);
  assert.equal(loadHistoryUploadConfig(uploadEnv({ SELFHOST_HISTORY_UPLOAD_MAX_OBJECT_BYTES: "1024" }))?.maxObjectBytes, 1024);
  assert.equal(loadHistoryUploadConfig(uploadEnv({ SELFHOST_HISTORY_UPLOAD_MAX_OBJECT_BYTES: "104857600" }))?.maxObjectBytes, 104_857_600);
  const dir = mkdtempSync(join(tmpdir(), "history-upload-"));
  try {
    const file = join(dir, "witness");
    writeFileSync(file, `${WITNESS_KEY}\n`);
    const fromFile = loadHistoryUploadConfig(uploadEnv({ SELFHOST_HISTORY_UPLOAD_WITNESS_KEY: undefined, SELFHOST_HISTORY_UPLOAD_WITNESS_KEY_FILE: file }));
    assert.deepEqual(fromFile?.witnessKey, WITNESS_KEY_BYTES);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadHistoryUploadConfig: a public endpoint drops the role, makes KMS optional and needs issuer keys", () => {
  const storeKeys = { SELFHOST_HISTORY_UPLOAD_ACCESS_KEY_ID: "fake-store-access", SELFHOST_HISTORY_UPLOAD_SECRET_ACCESS_KEY: "fake-store-secret" };
  const s3 = (extra: Record<string, string | undefined> = {}) => uploadEnv({
    SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT: "https://store.example.test/s3/",
    SELFHOST_HISTORY_UPLOAD_ROLE_ARN: undefined,
    SELFHOST_HISTORY_UPLOAD_KMS_KEY_ARN: undefined,
    ...storeKeys,
    ...extra,
  });
  const parsed = loadHistoryUploadConfig(s3());
  assert.equal(parsed?.endpoint, "https://store.example.test/s3");
  assert.equal(parsed?.internalEndpoint, "https://store.example.test/s3");
  assert.equal(parsed?.roleArn, null);
  assert.equal(parsed?.kmsKeyArn, null);
  assert.deepEqual(parsed?.storeCredentials, { accessKeyId: "fake-store-access", secretAccessKey: "fake-store-secret" });
  assert.equal(loadHistoryUploadConfig(uploadEnv())?.storeCredentials, null);
  assert.equal(loadHistoryUploadConfig(s3({ SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT: "http://store:9000" }))?.endpoint, "http://store:9000");
  assert.equal(
    loadHistoryUploadConfig(s3({ SELFHOST_HISTORY_UPLOAD_INTERNAL_ENDPOINT: "http://store.cluster.local:9000/" }))?.internalEndpoint,
    "http://store.cluster.local:9000",
  );
  assert.equal(loadHistoryUploadConfig(s3({ SELFHOST_HISTORY_UPLOAD_KMS_KEY_ARN: "upload-key" }))?.kmsKeyArn, "upload-key");
  assert.equal(loadHistoryUploadConfig(s3({ SELFHOST_HISTORY_UPLOAD_KMS_KEY_ARN: KMS_ARN }))?.kmsKeyArn, KMS_ARN);
  assert.throws(() => loadHistoryUploadConfig(s3({ SELFHOST_HISTORY_UPLOAD_KMS_KEY_ARN: "upload key" })),
    /^Error: SELFHOST_HISTORY_UPLOAD_KMS_KEY_ARN must be a key id without whitespace$/);
  assert.throws(() => loadHistoryUploadConfig(s3({ SELFHOST_HISTORY_UPLOAD_ROLE_ARN: ROLE_ARN })),
    /^Error: SELFHOST_HISTORY_UPLOAD_ROLE_ARN is not supported with SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT/);
  assert.throws(() => loadHistoryUploadConfig(uploadEnv({ SELFHOST_HISTORY_UPLOAD_INTERNAL_ENDPOINT: "http://store:9000" })),
    /^Error: SELFHOST_HISTORY_UPLOAD_INTERNAL_ENDPOINT requires SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT$/);
  // Both issuer keys are required with a public endpoint, on any host (an AWS host gets no pass).
  for (const endpoint of ["https://store.example.test", "https://s3.us-east-1.amazonaws.com"]) {
    assert.throws(() => loadHistoryUploadConfig(s3({ SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT: endpoint, SELFHOST_HISTORY_UPLOAD_ACCESS_KEY_ID: undefined })),
      /^Error: SELFHOST_HISTORY_UPLOAD_ACCESS_KEY_ID \(or _FILE\) is required with SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT$/);
    assert.throws(() => loadHistoryUploadConfig(s3({ SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT: endpoint, SELFHOST_HISTORY_UPLOAD_SECRET_ACCESS_KEY: undefined })),
      /^Error: SELFHOST_HISTORY_UPLOAD_SECRET_ACCESS_KEY \(or _FILE\) is required with SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT$/);
  }
  // Ambient AWS keys do not stand in for the issuer keys.
  assert.throws(() => loadHistoryUploadConfig(s3({
    SELFHOST_HISTORY_UPLOAD_ACCESS_KEY_ID: undefined, SELFHOST_HISTORY_UPLOAD_SECRET_ACCESS_KEY: undefined,
    AWS_ACCESS_KEY_ID: "fake-ambient-access", AWS_SECRET_ACCESS_KEY: "fake-ambient-secret",
  })), /^Error: SELFHOST_HISTORY_UPLOAD_ACCESS_KEY_ID \(or _FILE\) is required/);
  // Without the public endpoint the issuer keys must be unset.
  const onlyWith = /^Error: SELFHOST_HISTORY_UPLOAD_ACCESS_KEY_ID and SELFHOST_HISTORY_UPLOAD_SECRET_ACCESS_KEY are only used with SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT$/;
  for (const extra of [
    { SELFHOST_HISTORY_UPLOAD_ACCESS_KEY_ID: "fake-store-access" },
    { SELFHOST_HISTORY_UPLOAD_SECRET_ACCESS_KEY: "fake-store-secret" },
    { SELFHOST_HISTORY_UPLOAD_SECRET_ACCESS_KEY_FILE: "/nonexistent/fake-secret" },
  ]) {
    assert.throws(() => loadHistoryUploadConfig(uploadEnv(extra)),
      (error: Error) => onlyWith.test(String(error)) && !error.message.includes("fake-store"));
  }
  // The _FILE form reads the key from a file.
  const dir = mkdtempSync(join(tmpdir(), "history-upload-store-"));
  try {
    const file = join(dir, "secret");
    writeFileSync(file, "fake-store-file-secret\n");
    const fromFile = loadHistoryUploadConfig(s3({ SELFHOST_HISTORY_UPLOAD_SECRET_ACCESS_KEY: undefined, SELFHOST_HISTORY_UPLOAD_SECRET_ACCESS_KEY_FILE: file }));
    assert.deepEqual(fromFile?.storeCredentials, { accessKeyId: "fake-store-access", secretAccessKey: "fake-store-file-secret" });
    assert.throws(() => loadHistoryUploadConfig(s3({ SELFHOST_HISTORY_UPLOAD_SECRET_ACCESS_KEY_FILE: file })),
      /^Error: SELFHOST_HISTORY_UPLOAD_SECRET_ACCESS_KEY and SELFHOST_HISTORY_UPLOAD_SECRET_ACCESS_KEY_FILE are mutually exclusive$/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  for (const [name, bad] of [
    ["SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT", "store.example.test"],
    ["SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT", "ftp://store.example.test"],
    ["SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT", "https://fake-user:fake-pass@store.example.test"],
    ["SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT", "https://store.example.test/?region=x"],
    ["SELFHOST_HISTORY_UPLOAD_PUBLIC_ENDPOINT", "https://store.example.test/#frag"],
    ["SELFHOST_HISTORY_UPLOAD_INTERNAL_ENDPOINT", "store:9000/path"],
    ["SELFHOST_HISTORY_UPLOAD_INTERNAL_ENDPOINT", "http://fake-user@store:9000"],
  ] as const) {
    assert.throws(() => loadHistoryUploadConfig(s3({ [name]: bad })),
      (error: Error) => error.message.startsWith(`${name} `) && !error.message.includes(bad), `${name}=${bad}`);
  }
});

// ---- STS client ----

test("AwsStsClient posts a signed AssumeRole form and parses the credentials", async (t) => {
  const aws = await fakeAws(t);
  const client = new AwsStsClient({ region: "us-east-1", credentials: new StaticAwsCredentialProvider(STATIC_CREDS), endpoint: aws.origin });
  const policy = sessionPolicy({ bucket: BUCKET, prefix: uploadInboxPrefix("96bulls", TENANT), kmsKeyArn: KMS_ARN });
  const input = { roleArn: ROLE_ARN, roleSessionName: "history-upload-test", sourceIdentity: "u_test", policy, durationSeconds: 3600 };
  const creds = await client.assumeRole(input);
  assert.deepEqual({ ...creds, expiresAt: creds.expiresAt.toISOString() }, { ...ASSUMED, expiresAt: aws.state.expiresAt!.toISOString() });
  const sent = aws.state.requests[0]!;
  assert.equal(sent.method, "POST");
  assert.equal(sent.path, "/");
  assert.match(String(sent.headers["content-type"]), /^application\/x-www-form-urlencoded/);
  assert.match(String(sent.headers.authorization), /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLEFAKE\/\d{8}\/us-east-1\/sts\/aws4_request/);
  const form = new URLSearchParams(sent.body);
  assert.equal(form.get("Action"), "AssumeRole");
  assert.equal(form.get("Version"), "2011-06-15");
  assert.equal(form.get("RoleArn"), ROLE_ARN);
  assert.equal(form.get("RoleSessionName"), "history-upload-test");
  assert.equal(form.get("SourceIdentity"), "u_test");
  assert.equal(form.get("DurationSeconds"), "3600");
  assert.equal(form.get("Policy"), policy);

  const leaks = (error: unknown) => {
    const text = `${(error as Error).message} ${(error as StsError).code}`;
    return text.includes(policy) || text.includes(STATIC_CREDS.secretAccessKey) || text.includes(ASSUMED.secretAccessKey);
  };
  aws.state.sts = { status: 403, body: `<ErrorResponse><Error><Code>AccessDenied</Code><Message>${policy}</Message></Error></ErrorResponse>` };
  await assert.rejects(client.assumeRole(input), (error) => error instanceof StsError && error.code === "AccessDenied" && error.status === 403 && !leaks(error));
  aws.state.sts = { status: 200, body: stsXml(new Date()).replace(/<SessionToken>[^<]*<\/SessionToken>/, "") };
  await assert.rejects(client.assumeRole(input), (error) => error instanceof StsError && error.code === "malformed_response" && !leaks(error));
});

// ---- presign ----

test("presignV4 signs the extra headers and is unchanged without them", () => {
  const vector = presignV4({
    method: "GET",
    url: new URL("https://examplebucket.s3.amazonaws.com/test.txt"),
    region: "us-east-1",
    service: "s3",
    credentials: { accessKeyId: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" },
    now: new Date("2013-05-24T00:00:00Z"),
    expiresSeconds: 86400,
  });
  assert.equal(vector.searchParams.get("X-Amz-SignedHeaders"), "host");
  assert.equal(vector.searchParams.get("X-Amz-Signature"), "aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404");
  const signed = presignV4({
    method: "PUT",
    url: new URL(`https://${BUCKET}.s3.us-east-1.amazonaws.com/k`),
    region: "us-east-1",
    service: "s3",
    credentials: STATIC_CREDS,
    now: new Date("2026-01-01T00:00:00Z"),
    expiresSeconds: 900,
    signedHeaders: {
      "X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id": KMS_ARN,
      "If-None-Match": "*",
      "x-amz-meta-relay-witness": "w",
      "x-amz-server-side-encryption": "aws:kms",
    },
  });
  assert.equal(signed.searchParams.get("X-Amz-SignedHeaders"),
    "host;if-none-match;x-amz-meta-relay-witness;x-amz-server-side-encryption;x-amz-server-side-encryption-aws-kms-key-id");
});

// ---- privacy journal ----

test("S3PrivacyJournalReader reads seq, treats 404 as empty and fails closed otherwise", async (t) => {
  const aws = await fakeAws(t);
  const reader = new S3PrivacyJournalReader({
    bucket: BUCKET, region: "us-east-1", credentials: new StaticAwsCredentialProvider(STATIC_CREDS), endpoint: aws.origin,
  });
  const key = journalKey("96bulls", TENANT);
  assert.equal(await reader.seq(key), 7);
  const sent = aws.state.requests[0]!;
  assert.equal(sent.method, "GET");
  assert.equal(sent.path.split("/").map(decodeURIComponent).join("/"), `/${BUCKET}/${key}`);
  assert.match(String(sent.headers.authorization), /^AWS4-HMAC-SHA256 Credential=AKIDEXAMPLEFAKE\/\d{8}\/us-east-1\/s3\/aws4_request/);
  aws.state.journal = { status: 404, body: "<Error><Code>NoSuchKey</Code></Error>" };
  assert.equal(await reader.seq(key), 0);
  aws.state.journal = { status: 200, body: "{}" };
  await assert.rejects(reader.seq(key), (error) => error instanceof JournalUnavailableError && error.code === "privacy_journal_invalid");
  aws.state.journal = { status: 500, body: "" };
  await assert.rejects(reader.seq(key), (error) => error instanceof JournalUnavailableError && error.code === "privacy_journal_unreadable");
});

// ---- route ----

test("route: sts issues prefix-scoped credentials with a witness over the journal seq", async (t) => {
  const env = await setup(t);
  const issued = await request(env.origin, env.path, { method: "POST", token: env.token, body: stsBody });
  assert.equal(issued.status, 200, issued.raw);
  assert.equal(issued.headers.get("cache-control"), "no-store");
  const prefix = uploadInboxPrefix("96bulls", env.tenant);
  const expiresAt = env.aws.state.expiresAt!;
  assert.equal(Object.keys(issued.body)[0], "contract");
  assert.equal(issued.body.contract, UPLOAD_CONTRACT);
  assert.equal(issued.body.contract, "relay-upload-inbox-v1");
  assert.deepEqual(Object.keys(issued.body).sort(), [
    "bucket", "contract", "credentials", "endpoint", "keyPrefix", "kind", "kmsKeyId", "maxObjectBytes", "refreshAfter", "region", "witness", "witnessSeq",
  ]);
  assert.equal(issued.body.kind, "sts");
  assert.equal(issued.body.bucket, BUCKET);
  assert.equal(issued.body.region, "us-east-1");
  assert.equal(issued.body.endpoint, null);
  assert.equal(issued.body.keyPrefix, prefix);
  assert.equal(issued.body.kmsKeyId, KMS_ARN);
  assert.equal(issued.body.maxObjectBytes, 2_097_152);
  assert.deepEqual(issued.body.credentials, { ...ASSUMED, expiresAt: expiresAt.toISOString() });
  assert.equal(issued.body.refreshAfter, new Date(expiresAt.getTime() - 600_000).toISOString());
  const witness = verifyWitness(WITNESS_KEY_BYTES, issued.body.witness);
  assert.deepEqual(witness, {
    v: 1, org: env.tenant.orgId, ws: env.workspace, user: env.userId, seq: 7, exp: Math.floor(expiresAt.getTime() / 1000),
  });
  assert.equal(issued.body.witnessSeq, 7);
  assert.equal(issued.body.witnessSeq, witness!.seq);

  const journalGet = env.aws.state.requests.find((r) => r.method === "GET")!;
  assert.equal(journalGet.path.split("/").map(decodeURIComponent).join("/"), `/${BUCKET}/${journalKey("96bulls", env.tenant)}`);
  const form = new URLSearchParams(env.aws.state.requests.find((r) => r.method === "POST")!.body);
  assert.equal(form.get("SourceIdentity"), `u_${uploadUserHash(env.tenant)}`);
  assert.equal(form.get("RoleSessionName"), `history-upload-${uploadUserHash(env.tenant)}`);
  assert.equal(form.get("DurationSeconds"), "3600");
  assert.equal(form.get("RoleArn"), ROLE_ARN);
  assert.equal(form.get("Policy"), sessionPolicy({ bucket: BUCKET, prefix, kmsKeyArn: KMS_ARN }));
});

test("route: presigned issues one signed PUT per key with the checksum and witness signed in", async (t) => {
  const env = await setup(t);
  const issued = await request(env.origin, env.path, {
    method: "POST", token: env.token,
    body: { originId: "machine-1", kind: "presigned", keys: [{ key: "s/1.zst", sha256: SHA_A }, { key: "s/2.zst", sha256: SHA_B }] },
  });
  const after = Date.now();
  assert.equal(issued.status, 200, issued.raw);
  assert.equal(Object.keys(issued.body)[0], "contract");
  assert.equal(issued.body.contract, "relay-upload-inbox-v1");
  assert.equal(issued.body.kind, "presigned");
  assert.equal("credentials" in issued.body, false);
  assert.equal(issued.body.witnessSeq, 7);
  assert.equal(verifyWitness(WITNESS_KEY_BYTES, issued.body.witness)?.seq, issued.body.witnessSeq);
  const prefix = uploadInboxPrefix("96bulls", env.tenant);
  assert.equal(issued.body.urls.length, 2);
  for (const [index, sha256] of [SHA_A, SHA_B].entries()) {
    const entry = issued.body.urls[index];
    assert.equal(entry.key, `s/${index + 1}.zst`);
    assert.ok(Date.parse(entry.expiresAt) <= after + 15 * 60_000);
    const url = new URL(entry.url);
    assert.equal(url.host, `${BUCKET}.s3.us-east-1.amazonaws.com`);
    assert.equal(url.pathname.split("/").map(decodeURIComponent).join("/"), `/${prefix}${entry.key}`);
    assert.equal(url.searchParams.get("X-Amz-SignedHeaders"), UPLOAD_SIGNED_HEADERS);
    assert.equal(url.searchParams.get("X-Amz-Security-Token"), ASSUMED.sessionToken);
    assert.match(url.searchParams.get("X-Amz-Credential")!, /^ASIAFAKEASSUMED\//);
    // Re-sign with this URL's own checksum: the signature covers it.
    const amzDate = url.searchParams.get("X-Amz-Date")!;
    const now = new Date(`${amzDate.slice(0, 4)}-${amzDate.slice(4, 6)}-${amzDate.slice(6, 8)}T${amzDate.slice(9, 11)}:${amzDate.slice(11, 13)}:${amzDate.slice(13, 15)}Z`);
    const resigned = presignV4({
      method: "PUT",
      url: new URL(`${url.origin}${url.pathname}`),
      region: "us-east-1",
      service: "s3",
      credentials: ASSUMED,
      now,
      expiresSeconds: Number(url.searchParams.get("X-Amz-Expires")),
      signedHeaders: {
        "content-encoding": "zstd",
        "if-none-match": "*",
        "x-amz-checksum-sha256": sha256,
        "x-amz-meta-relay-witness": issued.body.witness,
        "x-amz-server-side-encryption": "aws:kms",
        "x-amz-server-side-encryption-aws-kms-key-id": KMS_ARN,
      },
    });
    assert.equal(url.searchParams.get("X-Amz-Signature"), resigned.searchParams.get("X-Amz-Signature"));
  }
});

test("route: feature off answers 404 history_upload_direct_off for any method", async (t) => {
  const env = await setup(t, { upload: null });
  const post = await request(env.origin, env.path, { method: "POST", token: env.token, body: stsBody });
  assert.equal(post.status, 404);
  assert.equal(post.body.error, "history_upload_direct_off");
  const get = await request(env.origin, env.path, { token: env.token });
  assert.equal(get.status, 404);
  assert.equal(env.aws.state.requests.length, 0);
});

test("route: a caller not on the allowlist gets the same 404; mode on serves everyone", async (t) => {
  const listed = await setup(t, { allowOwner: false });
  listed.aws.state.requests.length = 0;
  const refused = await request(listed.origin, listed.path, { method: "POST", token: listed.token, body: stsBody });
  assert.equal(refused.status, 404);
  assert.equal(refused.body.error, "history_upload_direct_off");
  assert.equal(listed.aws.state.requests.length, 0);
  const open = await setup(t, { upload: uploadConfig({ mode: "on" }), allowOwner: false });
  const served = await request(open.origin, open.path, { method: "POST", token: open.token, body: stsBody });
  assert.equal(served.status, 200, served.raw);
});

test("route: the capture policy revision is reported by default and enforced with SELFHOST_CAPTURE_POLICY_UPLOADS=enforce", async (t) => {
  const HEADER = "X-Agent-Relay-Capture-Policy-Revision";
  for (const mode of ["report", "enforce"] as const) {
    const env = await setup(t, { capturePolicyUploads: mode });
    const ask = (revision?: string) => request(env.origin, env.path, {
      method: "POST", token: env.token, body: stsBody, ...(revision !== undefined ? { headers: { [HEADER]: revision } } : {}),
    });
    // No mandated setting: no revision is needed in either mode.
    assert.equal((await ask()).status, 200, mode);
    const policyPath = `/api/v1/organizations/${env.organizationId}/capture-policy`;
    assert.equal((await request(env.origin, policyPath, {
      method: "PUT", token: BOOTSTRAP, body: { settings: { sharing_mode: "all" } },
    })).status, 200);
    const warned: unknown[][] = [];
    t.mock.method(console, "warn", (...args: unknown[]) => { warned.push(args); });
    for (const revision of [undefined, "1", "0", "nope"]) {
      const answer = await ask(revision);
      if (mode === "enforce") {
        assert.equal(answer.status, 409, `${mode} ${revision}`);
        assert.equal(answer.body.error, "capture_policy_stale");
      } else {
        assert.equal(answer.status, 200, `${mode} ${revision}`);
      }
    }
    const logged = warned.filter(([message]) => message === "[selfhost-api] capture policy upload check").map(([, fields]) => fields);
    assert.deepEqual(logged.map((fields) => (fields as { outcome: string }).outcome), ["missing", "stale", "stale", "missing"]);
    assert.ok(logged.every((fields) => (fields as { mode: string; revision: number }).mode === mode && (fields as { revision: number }).revision === 2));
    // The current revision (or a newer one) passes, unlogged.
    warned.length = 0;
    assert.equal((await ask("2")).status, 200, mode);
    assert.equal((await ask("3")).status, 200, mode);
    assert.equal(warned.length, 0);
    t.mock.restoreAll();
  }
});

test("route: a browser cookie session under /cloud gets 403 forbidden", async (t) => {
  const env = await setup(t);
  const login = await fetch(`${env.origin}/login`);
  const code = (await login.text()).match(/<code>([A-Z0-9]{4}-[A-Z0-9]{4})<\/code>/)?.[1];
  assert(code);
  const deviceCookie = login.headers.get("set-cookie")!.split(";")[0]!;
  const approved = await request(env.origin, "/api/v1/auth/device/approve", {
    method: "POST", token: BOOTSTRAP, body: { action: "approve", user_code: code, user_id: env.userId, workspace_id: env.workspace },
  });
  assert.equal(approved.status, 200);
  const poll = await request(env.origin, "/login/poll", { method: "POST", cookie: deviceCookie });
  const session = poll.headers.get("set-cookie")?.match(/agent_relay_session=[^;]+/)?.[0];
  assert(session);
  const refused = await request(env.origin, `/cloud${env.path}`, { method: "POST", cookie: session, body: stsBody });
  assert.equal(refused.status, 403);
  assert.equal(refused.body.error, "forbidden");
});

test("route: a token without rth:sync gets 401 unauthorized", async (t) => {
  const env = await setup(t);
  await env.database.query("UPDATE token_sessions SET scopes = $2::text[] WHERE access_token_hash = $1", [hashSecret(env.token), ["cli:auth", "rth:read"]]);
  const refused = await request(env.origin, env.path, { method: "POST", token: env.token, body: stsBody });
  assert.equal(refused.status, 401);
  assert.equal(refused.body.error, "unauthorized");
});

test("route: an unexchanged sign-in handoff gets 403 handoff_not_exchanged", async (t) => {
  const env = await setup(t);
  await env.database.query("UPDATE token_sessions SET desktop_exchange_challenge = 'fake-challenge' WHERE access_token_hash = $1", [hashSecret(env.token)]);
  const refused = await request(env.origin, env.path, { method: "POST", token: env.token, body: stsBody });
  assert.equal(refused.status, 403);
  assert.equal(refused.body.error, "handoff_not_exchanged");
});

test("route: invalid bodies answer 400 invalid_request", async (t) => {
  const env = await setup(t);
  const tooMany = Array.from({ length: 65 }, (_, i) => ({ key: `k${i}`, sha256: SHA_A }));
  const bodies: unknown[] = [
    { kind: "sts" },
    { originId: "m", kind: "s3" },
    { originId: "m", kind: "presigned" },
    { originId: "m", kind: "presigned", keys: [{ key: "../x", sha256: SHA_A }] },
    { originId: "m", kind: "presigned", keys: tooMany },
    { originId: "m", kind: "presigned", keys: [{ key: "a" }] },
    { originId: "m", kind: "presigned", keys: [{ key: "a", sha256: Buffer.alloc(31, 1).toString("base64") }] },
    { originId: "m", kind: "presigned", keys: [{ key: "a", sha256: `${"*".repeat(43)}=` }] },
    { originId: "m", kind: "presigned", keys: ["a"] },
    { originId: "m", kind: "presigned", keys: [{ key: "a", sha256: SHA_A }, { key: "a", sha256: SHA_B }] },
  ];
  for (const body of bodies) {
    const refused = await request(env.origin, env.path, { method: "POST", token: env.token, body });
    assert.equal(refused.status, 400, JSON.stringify(body).slice(0, 80));
    assert.equal(refused.body.error, "invalid_request");
  }
});

test("route: journal and STS failures answer 503 so the client falls back", async (t) => {
  const env = await setup(t);
  env.aws.state.journal = { status: 500, body: "" };
  const journal = await request(env.origin, env.path, { method: "POST", token: env.token, body: stsBody });
  assert.equal(journal.status, 503);
  assert.equal(journal.body.error, "privacy_journal_unavailable");
  assert.equal(env.aws.state.requests.some((r) => r.method === "POST"), false);
  env.aws.state.journal = { status: 404, body: "" };
  env.aws.state.sts = { status: 403, body: "<ErrorResponse><Error><Code>AccessDenied</Code></Error></ErrorResponse>" };
  const sts = await request(env.origin, env.path, { method: "POST", token: env.token, body: stsBody });
  assert.equal(sts.status, 503);
  assert.equal(sts.body.error, "upload_credentials_unavailable");
});

test("route: the 13th request in a minute is rate limited", async (t) => {
  const env = await setup(t);
  for (let i = 0; i < 12; i += 1) {
    const ok = await request(env.origin, env.path, { method: "POST", token: env.token, body: stsBody });
    assert.equal(ok.status, 200, `request ${i + 1}`);
  }
  const limited = await request(env.origin, env.path, { method: "POST", token: env.token, body: stsBody });
  assert.equal(limited.status, 429);
  assert.equal(limited.body.error, "rate_limited");
  assert.ok(Number(limited.headers.get("retry-after")) > 0);
});

test("route: GET is 405 with allow POST, and session sync still returns the caller's token", async (t) => {
  const env = await setup(t);
  const get = await request(env.origin, env.path, { token: env.token });
  assert.equal(get.status, 405);
  assert.equal(get.headers.get("allow"), "POST");
  const sync = await request(env.origin, `/api/v1/workspaces/${env.workspace}/relayhistory/session`, {
    method: "POST", token: env.token, body: { mode: "sync" },
  });
  assert.equal(sync.status, 200, sync.raw);
  assert.equal(sync.body.accessToken, env.token);
});

// ---- route: S3-compatible endpoint ----

const STORE_CREDS = { accessKeyId: "fake-store-access", secretAccessKey: "fake-store-secret" };
const s3Compatible = (kmsKeyArn: string | null, storeCredentials = STATIC_CREDS) => (origin: string) =>
  uploadConfig({ endpoint: origin, internalEndpoint: origin, roleArn: null, kmsKeyArn, storeCredentials });

test("route: S3-compatible presigned without KMS signs path-style URLs with the store keys and no SSE headers", async (t) => {
  // No credentials hook: the store keys from config sign the journal read and the URLs.
  const env = await setup(t, { upload: s3Compatible(null, STORE_CREDS), omitS3Hook: true, omitCredentialsHook: true });
  const issued = await request(env.origin, env.path, {
    method: "POST", token: env.token,
    body: { originId: "machine-1", kind: "presigned", keys: [{ key: "s/1.zst", sha256: SHA_A }, { key: "s/2.zst", sha256: SHA_B }] },
  });
  assert.equal(issued.status, 200, issued.raw);
  assert.equal(issued.body.endpoint, env.aws.origin);
  assert.equal(issued.body.kmsKeyId, null);
  assert.equal(issued.body.witnessSeq, 7);
  // The journal was read through config.internalEndpoint, and no STS call was made.
  const journalGet = env.aws.state.requests.find((r) => r.method === "GET");
  assert.ok(journalGet);
  assert.ok(String(journalGet.headers.authorization).includes("Credential=fake-store-access/"));
  assert.equal(journalGet.path.split("/").map(decodeURIComponent).join("/"), `/${BUCKET}/${journalKey("96bulls", env.tenant)}`);
  assert.equal(env.aws.state.requests.some((r) => r.method === "POST"), false);
  const prefix = uploadInboxPrefix("96bulls", env.tenant);
  const witness = verifyWitness(WITNESS_KEY_BYTES, issued.body.witness);
  assert.ok(witness);
  assert.equal(witness.seq, 7);
  assert.equal(issued.body.urls.length, 2);
  for (const [index, sha256] of [SHA_A, SHA_B].entries()) {
    const entry = issued.body.urls[index];
    const url = new URL(entry.url);
    assert.equal(url.origin, env.aws.origin);
    assert.equal(url.pathname.split("/").map(decodeURIComponent).join("/"), `/${BUCKET}/${prefix}${entry.key}`);
    assert.equal(witness.exp, Math.floor(Date.parse(entry.expiresAt) / 1000));
    const signedHeaders = url.searchParams.get("X-Amz-SignedHeaders")!;
    assert.equal(signedHeaders, "content-encoding;host;if-none-match;x-amz-checksum-sha256;x-amz-meta-relay-witness");
    assert.equal(signedHeaders.includes("x-amz-server-side-encryption"), false);
    assert.ok(url.searchParams.get("X-Amz-Credential")!.startsWith("fake-store-access/"));
    assert.equal(url.searchParams.has("X-Amz-Security-Token"), false);
    assert.equal(Number(url.searchParams.get("X-Amz-Expires")), 900);
    const amzDate = url.searchParams.get("X-Amz-Date")!;
    const now = new Date(`${amzDate.slice(0, 4)}-${amzDate.slice(4, 6)}-${amzDate.slice(6, 8)}T${amzDate.slice(9, 11)}:${amzDate.slice(11, 13)}:${amzDate.slice(13, 15)}Z`);
    const resigned = presignV4({
      method: "PUT",
      url: new URL(`${url.origin}${url.pathname}`),
      region: "us-east-1",
      service: "s3",
      credentials: STORE_CREDS,
      now,
      expiresSeconds: 900,
      signedHeaders: {
        "content-encoding": "zstd",
        "if-none-match": "*",
        "x-amz-checksum-sha256": sha256,
        "x-amz-meta-relay-witness": issued.body.witness,
      },
    });
    assert.equal(url.searchParams.get("X-Amz-Signature"), resigned.searchParams.get("X-Amz-Signature"));
  }
});

test("route: S3-compatible presigned with a KMS key name signs both SSE headers", async (t) => {
  const env = await setup(t, { upload: s3Compatible("upload-key") });
  const issued = await request(env.origin, env.path, {
    method: "POST", token: env.token, body: { originId: "machine-1", kind: "presigned", keys: [{ key: "s/1.zst", sha256: SHA_A }] },
  });
  assert.equal(issued.status, 200, issued.raw);
  assert.equal(issued.body.kmsKeyId, "upload-key");
  assert.equal(issued.body.endpoint, env.aws.origin);
  const url = new URL(issued.body.urls[0].url);
  assert.equal(url.searchParams.get("X-Amz-SignedHeaders"), UPLOAD_SIGNED_HEADERS);
  assert.equal(env.aws.state.requests.some((r) => r.method === "POST"), false);
});

test("route: S3-compatible kind sts answers 501 unsupported_by_backend before any journal read", async (t) => {
  const env = await setup(t, { upload: s3Compatible(null), omitS3Hook: true });
  env.aws.state.requests.length = 0;
  const refused = await request(env.origin, env.path, { method: "POST", token: env.token, body: stsBody });
  assert.equal(refused.status, 501, refused.raw);
  assert.equal(refused.body.error, "unsupported_by_backend");
  assert.equal(env.aws.state.requests.length, 0);
});

test("route: S3-compatible credentials that cannot be loaded answer 503 upload_credentials_unavailable", async (t) => {
  const warnings: unknown[][] = [];
  t.mock.method(console, "warn", (...args: unknown[]) => warnings.push(args));
  const issuer = new HistoryUploadCredentials({
    config: uploadConfig({
      endpoint: "http://store.invalid", internalEndpoint: "http://store.invalid", roleArn: null, kmsKeyArn: null, storeCredentials: STATIC_CREDS,
    }),
    sts: { assumeRole: async () => assert.fail("no STS call with an endpoint") },
    journal: { seq: async () => 3 },
    credentials: { get: async () => { throw new Error("fake provider detail /secret/path"); } },
  });
  await assert.rejects(
    issuer.issue(TENANT, { originId: "m", kind: "presigned", keys: [{ key: "a", sha256: SHA_A }] }),
    (error: Error & { status?: number; code?: string }) => error.status === 503 && error.code === "upload_credentials_unavailable",
  );
  assert.deepEqual(warnings, [["[history-upload] credentials unavailable"]]);
});

// ---- relay-upload-inbox-v1 contract vectors (sessions pipeline decision 0004) ----

test("relay-upload-inbox-v1 contract vectors: user segment, journal key, prefix, key shape and witness", () => {
  // Synthetic ids from the pipeline's relay-upload-inbox-v1.vectors.json. The witness key is the
  // vectors' TEST ONLY key (bytes 0x00..0x1f) and must never be configured anywhere.
  const tenant = { orgId: "org-synthetic", workspaceId: "ws-synthetic", userId: "user-synthetic-a" };
  const uh = "5a3b60a76d453cbeead919bae088d3b5";
  const prefix = `96bulls/.upload-inbox/org-synthetic/v1/ws=ws-synthetic/u=${uh}/`;
  assert.equal(uploadUserHash(tenant), uh);
  assert.equal(journalKey("96bulls", tenant),
    `96bulls/.admission-inbox/org-synthetic/v1/ws=ws-synthetic/m=srv_${uh}/privacy-journal.json`);
  assert.equal(uploadInboxPrefix("96bulls", tenant), prefix);
  const relativeKey = "o=origin-synthetic/b=f671c6d71e203808d157b293a8f29b25/d=36d61817e86f05e696d3b4af66dbb3ff-w7.json.zst";
  assert.equal(uploadKeyValid(relativeKey), true);
  assert.equal(prefix + relativeKey,
    `96bulls/.upload-inbox/org-synthetic/v1/ws=ws-synthetic/u=${uh}/o=origin-synthetic/b=f671c6d71e203808d157b293a8f29b25/d=36d61817e86f05e696d3b4af66dbb3ff-w7.json.zst`);
  const testOnlyKey = Buffer.from("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "base64url");
  const payload = { v: 1 as const, org: "org-synthetic", ws: "ws-synthetic", user: "user-synthetic-a", seq: 7, exp: 1_794_355_200 };
  const token = "v1.eyJ2IjoxLCJvcmciOiJvcmctc3ludGhldGljIiwid3MiOiJ3cy1zeW50aGV0aWMiLCJ1c2VyIjoidXNlci1zeW50aGV0aWMtYSIsInNlcSI6NywiZXhwIjoxNzk0MzU1MjAwfQ.Q8WhA5OtmmCFKH3UPe85UnVBjjo_SQgGfDv-nDrRSO8";
  assert.equal(signWitness(testOnlyKey, payload), token);
  assert.deepEqual(verifyWitness(testOnlyKey, token), payload);
  // The vectors' bad-MAC refusal (last character changed).
  assert.equal(verifyWitness(testOnlyKey, token.slice(0, -1) + "A"), null);
});

test("relay-upload-inbox-v1 contract vectors: credentials.presignedSelfhost (S3-compatible endpoint with a path prefix, no KMS)", async () => {
  // The pipeline's credentials.presignedSelfhost vector: endpoint = origin plus an optional path
  // prefix, kmsKeyId null (clients send no SSE headers), presigned only. The vector's URL and
  // witness are placeholders, so the signed URL is pinned by origin, path and signed headers and
  // the witness by its payload; its exp is the URL expiry (Control's rule).
  const vector = {
    contract: "relay-upload-inbox-v1", kind: "presigned", bucket: "example-upload-bucket", region: "us-east-1",
    endpoint: "https://objects.example.test:9000/relayhistory",
    keyPrefix: "96bulls/.upload-inbox/org-synthetic/v1/ws=ws-synthetic/u=5a3b60a76d453cbeead919bae088d3b5/",
    kmsKeyId: null, maxObjectBytes: 2097152, refreshAfter: "2026-11-11T00:10:00Z", witnessSeq: 7,
  };
  const vectorUrl = {
    key: "o=origin-synthetic/b=f671c6d71e203808d157b293a8f29b25/d=36d61817e86f05e696d3b4af66dbb3ff-w7.json.zst",
    expiresAt: "2026-11-11T00:15:00Z",
  };
  const testOnlyKey = Buffer.from("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "base64url");
  const tenant = { orgId: "org-synthetic", workspaceId: "ws-synthetic", userId: "user-synthetic-a" };
  const issuer = new HistoryUploadCredentials({
    config: uploadConfig({
      bucket: vector.bucket, endpoint: vector.endpoint, internalEndpoint: vector.endpoint,
      roleArn: null, kmsKeyArn: null, storeCredentials: STORE_CREDS, witnessKey: testOnlyKey,
    }),
    sts: { assumeRole: async () => assert.fail("no STS call with an endpoint") },
    journal: { seq: async () => 7 },
    credentials: new StaticAwsCredentialProvider(STORE_CREDS),
    now: () => new Date("2026-11-11T00:00:00Z"),
  });
  await assert.rejects(
    issuer.issue(tenant, { originId: "origin-synthetic", kind: "sts" }),
    (error: Error & { status?: number; code?: string }) => error.status === 501 && error.code === "unsupported_by_backend",
  );
  const issued = await issuer.issue(tenant, { originId: "origin-synthetic", kind: "presigned", keys: [{ key: vectorUrl.key, sha256: SHA_A }] });
  assert.deepEqual(Object.keys(issued).sort(), [...Object.keys(vector), "urls", "witness"].sort());
  const { witness, urls, refreshAfter, ...common } = issued as { witness: string; urls: Array<{ key: string; url: string; expiresAt: string }>; refreshAfter: string } & Record<string, unknown>;
  const { refreshAfter: vectorRefreshAfter, ...vectorCommon } = vector;
  assert.deepEqual(common, vectorCommon);
  // Both are RFC 3339 instants; Control writes milliseconds, the vector does not.
  assert.equal(Date.parse(refreshAfter), Date.parse(vectorRefreshAfter));
  assert.equal(urls.length, 1);
  const entry = urls[0]!;
  assert.equal(entry.key, vectorUrl.key);
  assert.equal(Date.parse(entry.expiresAt), Date.parse(vectorUrl.expiresAt));
  const payload = verifyWitness(testOnlyKey, witness);
  assert.deepEqual(payload, { v: 1, org: tenant.orgId, ws: tenant.workspaceId, user: tenant.userId, seq: 7, exp: Math.floor(Date.parse(vectorUrl.expiresAt) / 1000) });
  const url = new URL(entry.url);
  assert.equal(url.origin, "https://objects.example.test:9000");
  assert.equal(url.pathname.split("/").map(decodeURIComponent).join("/"), `/relayhistory/${vector.bucket}/${vector.keyPrefix}${vectorUrl.key}`);
  assert.equal(url.searchParams.get("X-Amz-SignedHeaders"), "content-encoding;host;if-none-match;x-amz-checksum-sha256;x-amz-meta-relay-witness");
  assert.equal(url.searchParams.get("X-Amz-Expires"), "900");
  assert.equal(url.searchParams.has("X-Amz-Security-Token"), false);
});
