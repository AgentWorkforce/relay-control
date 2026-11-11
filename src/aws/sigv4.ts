// AWS Signature Version 4 and credential resolution for the Desktop feed's S3
// object store and KMS signer (src/desktop-feed/). Hand-rolled on node:crypto so
// self-host carries no AWS SDK dependency.
import { createHash, createHmac } from "node:crypto";

export type AwsCredentials = { accessKeyId: string; secretAccessKey: string; sessionToken?: string };

export const sha256Hex = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const hmac = (key: string | Buffer, value: string) => createHmac("sha256", key).update(value).digest();

export function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

function amzDates(now: Date): { amzDate: string; date: string } {
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  return { amzDate, date: amzDate.slice(0, 8) };
}

function canonicalQuery(params: Iterable<[string, string]>): string {
  return [...params]
    .map(([k, v]) => [encodeRfc3986(k), encodeRfc3986(v)] as const)
    .sort(([a, av], [b, bv]) => (a < b ? -1 : a > b ? 1 : av < bv ? -1 : av > bv ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
}

function signature(secret: string, date: string, region: string, service: string, stringToSign: string): string {
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${secret}`, date), region), service), "aws4_request");
  return createHmac("sha256", signingKey).update(stringToSign).digest("hex");
}

/**
 * Header signing for a single-chunk payload. Returns every header to send
 * except host (fetch sets it from the URL). `body` may be a string or bytes;
 * `payloadHash` overrides the computed hash (for example UNSIGNED-PAYLOAD).
 */
export function signV4(input: {
  method: string;
  url: URL;
  region: string;
  service: string;
  body?: string | Buffer;
  payloadHash?: string;
  credentials: AwsCredentials;
  now: Date;
  extraHeaders?: Record<string, string>;
  /** S3 signs x-amz-content-sha256; other services (KMS) accept it but do not need it. */
  contentSha256Header?: boolean;
}): Record<string, string> {
  const { amzDate, date } = amzDates(input.now);
  const payloadHash = input.payloadHash ?? sha256Hex(input.body ?? "");
  const headers: Record<string, string> = {
    host: input.url.host,
    ...(input.contentSha256Header === false ? {} : { "x-amz-content-sha256": payloadHash }),
    "x-amz-date": amzDate,
    ...(input.credentials.sessionToken ? { "x-amz-security-token": input.credentials.sessionToken } : {}),
    ...Object.fromEntries(Object.entries(input.extraHeaders ?? {}).map(([k, v]) => [k.toLowerCase(), v])),
  };
  const names = Object.keys(headers).sort();
  const canonicalHeaders = names.map((name) => `${name}:${headers[name]!.trim()}\n`).join("");
  const signedHeaders = names.join(";");
  const canonicalRequest = [
    input.method,
    input.url.pathname,
    canonicalQuery(input.url.searchParams.entries()),
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");
  const scope = `${date}/${input.region}/${input.service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonicalRequest)].join("\n");
  const sig = signature(input.credentials.secretAccessKey, date, input.region, input.service, stringToSign);
  const { host: _host, ...rest } = headers;
  return {
    ...rest,
    authorization: `AWS4-HMAC-SHA256 Credential=${input.credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${sig}`,
  };
}

/**
 * Query-string presigning with UNSIGNED-PAYLOAD. `host` is always signed;
 * `signedHeaders` adds headers the client must then send with exactly these
 * values (names are lower-cased). Without it, host is the only signed header.
 */
export function presignV4(input: {
  method: string;
  url: URL;
  region: string;
  service: string;
  credentials: AwsCredentials;
  now: Date;
  expiresSeconds: number;
  signedHeaders?: Record<string, string>;
}): URL {
  const { amzDate, date } = amzDates(input.now);
  const scope = `${date}/${input.region}/${input.service}/aws4_request`;
  const url = new URL(input.url.toString());
  url.searchParams.set("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
  url.searchParams.set("X-Amz-Credential", `${input.credentials.accessKeyId}/${scope}`);
  url.searchParams.set("X-Amz-Date", amzDate);
  url.searchParams.set("X-Amz-Expires", String(input.expiresSeconds));
  if (input.credentials.sessionToken) url.searchParams.set("X-Amz-Security-Token", input.credentials.sessionToken);
  const headers: Record<string, string> = {
    ...Object.fromEntries(Object.entries(input.signedHeaders ?? {}).map(([k, v]) => [k.toLowerCase(), v.trim()])),
    host: url.host,
  };
  const names = Object.keys(headers).sort();
  const signedHeaders = names.join(";");
  url.searchParams.set("X-Amz-SignedHeaders", signedHeaders);
  const query = canonicalQuery(url.searchParams.entries());
  const canonicalHeaders = names.map((name) => `${name}:${headers[name]}\n`).join("");
  const canonicalRequest = [input.method, url.pathname, query, canonicalHeaders, signedHeaders, "UNSIGNED-PAYLOAD"].join("\n");
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonicalRequest)].join("\n");
  const sig = signature(input.credentials.secretAccessKey, date, input.region, input.service, stringToSign);
  url.search = `${query}&X-Amz-Signature=${sig}`;
  return url;
}

type Env = Record<string, string | undefined>;
type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export interface AwsCredentialProvider {
  get(): Promise<AwsCredentials>;
}

/**
 * Static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (+ AWS_SESSION_TOKEN) when
 * set, otherwise the EC2 instance role through IMDSv2. Instance-role
 * credentials are cached until five minutes before they expire. Credential
 * values are never logged or put into error messages.
 */
export class DefaultAwsCredentialProvider implements AwsCredentialProvider {
  #cached: { value: AwsCredentials; expiresAt: number } | null = null;
  constructor(
    private readonly env: Env = process.env,
    private readonly fetchImpl: FetchLike = (url, init) => fetch(url, init),
    private readonly imdsBase = "http://169.254.169.254",
    private readonly now: () => number = () => Date.now(),
  ) {}

  async get(): Promise<AwsCredentials> {
    const accessKeyId = this.env.AWS_ACCESS_KEY_ID?.trim();
    const secretAccessKey = this.env.AWS_SECRET_ACCESS_KEY?.trim();
    if (accessKeyId && secretAccessKey) {
      return { accessKeyId, secretAccessKey, sessionToken: this.env.AWS_SESSION_TOKEN?.trim() || undefined };
    }
    if (this.#cached && this.#cached.expiresAt > this.now() + 300_000) return this.#cached.value;
    const signal = AbortSignal.timeout(5_000);
    const tokenResponse = await this.fetchImpl(`${this.imdsBase}/latest/api/token`, {
      method: "PUT",
      headers: { "x-aws-ec2-metadata-token-ttl-seconds": "21600" },
      signal,
    });
    if (!tokenResponse.ok) throw new Error(`IMDSv2 token request failed: ${tokenResponse.status}`);
    const token = await tokenResponse.text();
    const headers = { "x-aws-ec2-metadata-token": token };
    const roleResponse = await this.fetchImpl(`${this.imdsBase}/latest/meta-data/iam/security-credentials/`, { headers, signal });
    if (!roleResponse.ok) throw new Error(`IMDSv2 role lookup failed: ${roleResponse.status}`);
    const role = (await roleResponse.text()).split("\n")[0]?.trim();
    if (!role) throw new Error("IMDSv2 reports no instance role");
    const credsResponse = await this.fetchImpl(
      `${this.imdsBase}/latest/meta-data/iam/security-credentials/${encodeURIComponent(role)}`,
      { headers, signal },
    );
    if (!credsResponse.ok) throw new Error(`IMDSv2 credential request failed: ${credsResponse.status}`);
    const body = await credsResponse.json() as {
      AccessKeyId?: string; SecretAccessKey?: string; Token?: string; Expiration?: string;
    };
    if (!body.AccessKeyId || !body.SecretAccessKey) throw new Error("IMDSv2 credential response is incomplete");
    const value = { accessKeyId: body.AccessKeyId, secretAccessKey: body.SecretAccessKey, sessionToken: body.Token };
    const expiresAt = body.Expiration ? Date.parse(body.Expiration) : this.now() + 900_000;
    this.#cached = { value, expiresAt: Number.isFinite(expiresAt) ? expiresAt : this.now() + 900_000 };
    return value;
  }
}

export class StaticAwsCredentialProvider implements AwsCredentialProvider {
  constructor(private readonly credentials: AwsCredentials) {}
  async get(): Promise<AwsCredentials> {
    return this.credentials;
  }
}
