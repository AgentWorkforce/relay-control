// The default AWS credential chain (src/aws/sigv4.ts): static keys, container
// credentials (ECS, EKS Pod Identity), web identity (IRSA) and IMDSv2, with a
// fake fetch and temporary token files.
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { DefaultAwsCredentialProvider } from "../src/aws/sigv4.js";
import { credentialBackendFromEnv, S3ObjectBackend } from "../src/admin/credential-blobs.js";
import type { Database } from "../src/database.js";

const NOW = Date.parse("2026-11-10T10:00:00.000Z");
const SECRET = "container-secret-value";
const SESSION = "container-session-token";
const AUTH_TOKEN = "pod-identity-auth-token-1";

type Call = { url: string; method: string; headers: Record<string, string>; body?: string };

function fakeFetch(reply: (call: Call) => Response) {
  const calls: Call[] = [];
  const fetchImpl = async (url: string, init: RequestInit) => {
    const call: Call = {
      url,
      method: init.method ?? "GET",
      headers: Object.fromEntries(Object.entries((init.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v])),
      body: typeof init.body === "string" ? init.body : undefined,
    };
    calls.push(call);
    return reply(call);
  };
  return { calls, fetchImpl };
}

function containerReply(expiration: string, keyId = "ASIACONTAINER") {
  return () => Response.json({ AccessKeyId: keyId, SecretAccessKey: SECRET, Token: SESSION, Expiration: expiration });
}

async function tempDir(t: TestContext): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "rc-aws-creds-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

const POD_IDENTITY_URI = "http://169.254.170.23/v1/credentials";

test("container FULL_URI (EKS Pod Identity) sends the token file as Authorization", async (t) => {
  const dir = await tempDir(t);
  const tokenFile = join(dir, "eks-pod-identity-token");
  await writeFile(tokenFile, `${AUTH_TOKEN}\n`);
  const { calls, fetchImpl } = fakeFetch(containerReply("2026-11-10T16:00:00Z"));
  const provider = new DefaultAwsCredentialProvider(
    { AWS_CONTAINER_CREDENTIALS_FULL_URI: POD_IDENTITY_URI, AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE: tokenFile },
    fetchImpl,
    "http://imds.invalid",
    () => NOW,
  );
  assert.deepEqual(await provider.get(), { accessKeyId: "ASIACONTAINER", secretAccessKey: SECRET, sessionToken: SESSION });
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.url, POD_IDENTITY_URI);
  assert.equal(calls[0]!.method, "GET");
  assert.equal(calls[0]!.headers.authorization, AUTH_TOKEN);
  // Cached until five minutes before expiry.
  await provider.get();
  assert.equal(calls.length, 1, "cached credentials are reused");
});

test("container token file is re-read on every refresh (rotation)", async (t) => {
  const dir = await tempDir(t);
  const tokenFile = join(dir, "token");
  await writeFile(tokenFile, AUTH_TOKEN);
  let clock = NOW;
  // Expires 10 minutes out: inside the 5-minute refresh window after +6 minutes.
  const { calls, fetchImpl } = fakeFetch(() => Response.json({
    AccessKeyId: `ASIA${calls.length}`, SecretAccessKey: SECRET, Token: SESSION,
    Expiration: new Date(clock + 600_000).toISOString(),
  }));
  const provider = new DefaultAwsCredentialProvider(
    { AWS_CONTAINER_CREDENTIALS_FULL_URI: POD_IDENTITY_URI, AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE: tokenFile },
    fetchImpl,
    "http://imds.invalid",
    () => clock,
  );
  assert.equal((await provider.get()).accessKeyId, "ASIA1");
  await writeFile(tokenFile, "pod-identity-auth-token-2");
  clock += 360_000;
  assert.equal((await provider.get()).accessKeyId, "ASIA2");
  assert.deepEqual(calls.map((call) => call.headers.authorization), [AUTH_TOKEN, "pod-identity-auth-token-2"]);
});

test("concurrent callers share one container refresh", async () => {
  const { calls, fetchImpl } = fakeFetch(containerReply("2026-11-10T16:00:00Z"));
  const provider = new DefaultAwsCredentialProvider(
    { AWS_CONTAINER_CREDENTIALS_FULL_URI: POD_IDENTITY_URI, AWS_CONTAINER_AUTHORIZATION_TOKEN: "env-token" },
    fetchImpl, "http://imds.invalid", () => NOW,
  );
  await Promise.all([provider.get(), provider.get(), provider.get()]);
  assert.equal(calls.length, 1);
  assert.equal(calls[0]!.headers.authorization, "env-token", "AWS_CONTAINER_AUTHORIZATION_TOKEN is used without a token file");
});

test("container RELATIVE_URI (ECS) resolves against 169.254.170.2", async () => {
  const { calls, fetchImpl } = fakeFetch(containerReply("2026-11-10T16:00:00Z", "ASIAECS"));
  const provider = new DefaultAwsCredentialProvider(
    { AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: "/v2/credentials/abc-123" },
    fetchImpl, "http://imds.invalid", () => NOW,
  );
  assert.equal((await provider.get()).accessKeyId, "ASIAECS");
  assert.equal(calls[0]!.url, "http://169.254.170.2/v2/credentials/abc-123");
  assert.equal(calls[0]!.headers.authorization, undefined);
});

test("container FULL_URI on a disallowed host is refused without a request", async () => {
  for (const uri of ["http://169.254.169.254/latest/meta-data/", "http://evil.example.com/creds", "file:///etc/passwd", "not a url"]) {
    const { calls, fetchImpl } = fakeFetch(containerReply("2026-11-10T16:00:00Z"));
    const provider = new DefaultAwsCredentialProvider(
      { AWS_CONTAINER_CREDENTIALS_FULL_URI: uri, AWS_CONTAINER_AUTHORIZATION_TOKEN: AUTH_TOKEN },
      fetchImpl, "http://imds.invalid", () => NOW,
    );
    await assert.rejects(provider.get(), /AWS_CONTAINER_CREDENTIALS_FULL_URI/, uri);
    assert.equal(calls.length, 0, `${uri}: no request`);
  }
  for (const uri of ["http://127.0.0.1:8080/creds", "http://localhost/creds", "http://[::1]/creds", "http://[fd00:ec2::23]/v1/credentials", "https://creds.example.com/"]) {
    const { calls, fetchImpl } = fakeFetch(containerReply("2026-11-10T16:00:00Z"));
    const provider = new DefaultAwsCredentialProvider({ AWS_CONTAINER_CREDENTIALS_FULL_URI: uri }, fetchImpl, "http://imds.invalid", () => NOW);
    await provider.get();
    assert.equal(calls.length, 1, `${uri}: allowed`);
  }
});

test("static keys win over container, web identity and IMDS", async () => {
  const { calls, fetchImpl } = fakeFetch(() => {
    throw new Error("no request expected");
  });
  const provider = new DefaultAwsCredentialProvider(
    {
      AWS_ACCESS_KEY_ID: "AKIDSTATIC",
      AWS_SECRET_ACCESS_KEY: "static-secret",
      AWS_SESSION_TOKEN: "static-session",
      AWS_CONTAINER_CREDENTIALS_FULL_URI: POD_IDENTITY_URI,
      AWS_WEB_IDENTITY_TOKEN_FILE: "/nonexistent",
      AWS_ROLE_ARN: "arn:aws:iam::000000000000:role/example",
    },
    fetchImpl, "http://imds.invalid", () => NOW,
  );
  assert.deepEqual(await provider.get(), { accessKeyId: "AKIDSTATIC", secretAccessKey: "static-secret", sessionToken: "static-session" });
  assert.equal(calls.length, 0);
});

test("web identity (IRSA) calls regional STS AssumeRoleWithWebIdentity", async (t) => {
  const dir = await tempDir(t);
  const tokenFile = join(dir, "token");
  await writeFile(tokenFile, "irsa-jwt-token");
  const { calls, fetchImpl } = fakeFetch(() => new Response(
    `<AssumeRoleWithWebIdentityResponse><AssumeRoleWithWebIdentityResult><Credentials>
      <AccessKeyId>ASIAIRSA</AccessKeyId><SecretAccessKey>irsa-secret</SecretAccessKey>
      <SessionToken>irsa-session</SessionToken><Expiration>2026-11-10T11:00:00Z</Expiration>
    </Credentials></AssumeRoleWithWebIdentityResult></AssumeRoleWithWebIdentityResponse>`,
  ));
  const provider = new DefaultAwsCredentialProvider(
    { AWS_WEB_IDENTITY_TOKEN_FILE: tokenFile, AWS_ROLE_ARN: "arn:aws:iam::000000000000:role/example", AWS_REGION: "eu-west-1" },
    fetchImpl, "http://imds.invalid", () => NOW,
  );
  assert.deepEqual(await provider.get(), { accessKeyId: "ASIAIRSA", secretAccessKey: "irsa-secret", sessionToken: "irsa-session" });
  assert.equal(calls[0]!.url, "https://sts.eu-west-1.amazonaws.com/");
  assert.equal(calls[0]!.method, "POST");
  assert.equal(calls[0]!.headers.authorization, undefined, "AssumeRoleWithWebIdentity is unsigned");
  const params = new URLSearchParams(calls[0]!.body);
  assert.equal(params.get("Action"), "AssumeRoleWithWebIdentity");
  assert.equal(params.get("WebIdentityToken"), "irsa-jwt-token");
  assert.equal(params.get("RoleArn"), "arn:aws:iam::000000000000:role/example");
});

test("IMDSv2 fallback is unchanged", async () => {
  const { calls, fetchImpl } = fakeFetch((call) => {
    if (call.url.endsWith("/latest/api/token")) return new Response("imds-token");
    if (call.url.endsWith("/security-credentials/")) return new Response("node-role\n");
    return Response.json({ AccessKeyId: "ASIAIMDS", SecretAccessKey: "imds-secret", Token: "imds-session", Expiration: "2026-11-10T16:00:00Z" });
  });
  const provider = new DefaultAwsCredentialProvider({}, fetchImpl, "http://imds.test", () => NOW);
  assert.deepEqual(await provider.get(), { accessKeyId: "ASIAIMDS", secretAccessKey: "imds-secret", sessionToken: "imds-session" });
  assert.deepEqual(calls.map((call) => `${call.method} ${call.url}`), [
    "PUT http://imds.test/latest/api/token",
    "GET http://imds.test/latest/meta-data/iam/security-credentials/",
    "GET http://imds.test/latest/meta-data/iam/security-credentials/node-role",
  ]);
  assert.equal(calls[0]!.headers["x-aws-ec2-metadata-token-ttl-seconds"], "21600");
  assert.equal(calls[1]!.headers["x-aws-ec2-metadata-token"], "imds-token");
  await provider.get();
  assert.equal(calls.length, 3, "cached");
});

test("credential errors never contain tokens, secrets or response bodies", async (t) => {
  const dir = await tempDir(t);
  const tokenFile = join(dir, "token");
  await writeFile(tokenFile, AUTH_TOKEN);
  const leaks = [AUTH_TOKEN, SECRET, SESSION, "irsa-jwt-token", "body-secret"];
  const cases: Array<[string, Record<string, string>, () => Response]> = [
    ["container 403", { AWS_CONTAINER_CREDENTIALS_FULL_URI: POD_IDENTITY_URI, AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE: tokenFile },
      () => new Response(`denied ${AUTH_TOKEN} body-secret`, { status: 403 })],
    ["container incomplete", { AWS_CONTAINER_CREDENTIALS_FULL_URI: POD_IDENTITY_URI, AWS_CONTAINER_AUTHORIZATION_TOKEN: AUTH_TOKEN },
      () => Response.json({ AccessKeyId: "", SecretAccessKey: SECRET, Token: SESSION })],
    ["container not json", { AWS_CONTAINER_CREDENTIALS_FULL_URI: POD_IDENTITY_URI, AWS_CONTAINER_AUTHORIZATION_TOKEN: AUTH_TOKEN },
      () => new Response(`${SECRET} body-secret`)],
    ["container unreachable", { AWS_CONTAINER_CREDENTIALS_FULL_URI: POD_IDENTITY_URI, AWS_CONTAINER_AUTHORIZATION_TOKEN: AUTH_TOKEN },
      () => { throw new Error(`connect failed ${AUTH_TOKEN}`); }],
    ["container bad token file", { AWS_CONTAINER_CREDENTIALS_FULL_URI: POD_IDENTITY_URI, AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE: join(dir, "missing") },
      () => Response.json({})],
    ["sts refused", { AWS_WEB_IDENTITY_TOKEN_FILE: tokenFile, AWS_ROLE_ARN: "arn:aws:iam::000000000000:role/example" },
      () => new Response(`<ErrorResponse><Error><Code>${SECRET} body-secret</Code><Message>${AUTH_TOKEN}</Message></Error></ErrorResponse>`, { status: 400 })],
  ];
  for (const [name, env, reply] of cases) {
    const { fetchImpl } = fakeFetch(reply);
    const provider = new DefaultAwsCredentialProvider(env, fetchImpl, "http://imds.invalid", () => NOW);
    const error = await provider.get().then(() => null, (caught: unknown) => caught);
    assert(error instanceof Error, `${name}: rejects`);
    for (const leak of leaks) assert(!error.message.includes(leak), `${name}: message must not contain ${leak}`);
  }
});

test("credential-blobs s3 backend uses the shared chain when no static keys are set", async () => {
  const database = {} as Database;
  assert(credentialBackendFromEnv({ SELFHOST_CREDENTIAL_STORAGE: "s3", SELFHOST_CREDENTIAL_S3_BUCKET: "customer-bucket", AWS_REGION: "us-east-1" }, database) instanceof S3ObjectBackend);
  assert.throws(() => credentialBackendFromEnv({ SELFHOST_CREDENTIAL_STORAGE: "s3", SELFHOST_CREDENTIAL_S3_BUCKET: "customer-bucket" }, database), /region/);
  const { calls, fetchImpl } = fakeFetch((call) => call.url.startsWith("http://169.254.170.23")
    ? Response.json({ AccessKeyId: "ASIAPODID", SecretAccessKey: SECRET, Token: SESSION, Expiration: "2026-11-10T16:00:00Z" })
    : new Response("{}"));
  const backend = new S3ObjectBackend({
    bucket: "customer-bucket", region: "us-east-1", prefix: "creds",
    credentials: new DefaultAwsCredentialProvider({ AWS_CONTAINER_CREDENTIALS_FULL_URI: POD_IDENTITY_URI, AWS_CONTAINER_AUTHORIZATION_TOKEN: AUTH_TOKEN }, fetchImpl),
  }, fetchImpl);
  await backend.put("k", "{}");
  const put = calls.find((call) => call.method === "PUT")!;
  assert.match(put.headers.authorization ?? "", /^AWS4-HMAC-SHA256 Credential=ASIAPODID\//);
  assert.equal(put.headers["x-amz-security-token"], SESSION);
});
