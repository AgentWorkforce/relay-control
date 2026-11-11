// AWS Signature Version 4 and credential resolution for the Desktop feed's S3
// object store and KMS signer (src/desktop-feed/), STS and credential blobs. Hand-rolled on node:crypto so
// self-host carries no AWS SDK dependency.
import { createHash, createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";

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

type CachedCredentials = { value: AwsCredentials; expiresAt: number };
type ReadFileLike = (path: string) => Promise<string>;

/** Hosts an http:// AWS_CONTAINER_CREDENTIALS_FULL_URI may name (as the AWS SDKs allow). */
const CONTAINER_HTTP_HOSTS = new Set(["169.254.170.2", "169.254.170.23", "[fd00:ec2::23]", "localhost", "[::1]"]);
const CONTAINER_TIMEOUT_MS = 5_000;
const IMDS_TIMEOUT_MS = 5_000;
const STS_TIMEOUT_MS = 10_000;
/** AWS error codes are short identifiers; anything else is not echoed. */
const AWS_ERROR_CODE = /^[A-Za-z0-9._-]{1,64}$/;

function containerHostAllowed(url: URL): boolean {
  if (url.protocol === "https:") return true;
  if (url.protocol !== "http:") return false;
  return CONTAINER_HTTP_HOSTS.has(url.hostname) || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(url.hostname);
}

function xmlElement(xml: string, name: string): string | null {
  const match = new RegExp(`<${name}>([^<]*)</${name}>`).exec(xml);
  const value = match
    ? match[1]!.trim()
      .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, "\"").replace(/&apos;/g, "'").replace(/&amp;/g, "&")
    : "";
  return value || null;
}

/**
 * The standard AWS SDK credential chain, without the SDK:
 *
 * 1. static AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY (+ AWS_SESSION_TOKEN);
 * 2. container credentials: AWS_CONTAINER_CREDENTIALS_RELATIVE_URI against
 *    169.254.170.2 (ECS), or AWS_CONTAINER_CREDENTIALS_FULL_URI (EKS Pod
 *    Identity, http only to the link-local agent or loopback), authorised by
 *    AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE (re-read on every refresh, it
 *    rotates) or AWS_CONTAINER_AUTHORIZATION_TOKEN;
 * 3. web identity (EKS IRSA): AWS_WEB_IDENTITY_TOKEN_FILE + AWS_ROLE_ARN via
 *    STS AssumeRoleWithWebIdentity on the regional endpoint;
 * 4. the EC2 instance role through IMDSv2.
 *
 * Temporary credentials are cached until five minutes before they expire, and
 * concurrent refreshes share one request. Credential values, tokens and
 * response bodies are never logged or put into error messages.
 */
export class DefaultAwsCredentialProvider implements AwsCredentialProvider {
  #cached: CachedCredentials | null = null;
  #pending: Promise<AwsCredentials> | null = null;
  constructor(
    private readonly env: Env = process.env,
    private readonly fetchImpl: FetchLike = (url, init) => fetch(url, init),
    private readonly imdsBase = "http://169.254.169.254",
    private readonly now: () => number = () => Date.now(),
    private readonly readFileImpl: ReadFileLike = (path) => readFile(path, "utf8"),
    private readonly ecsBase = "http://169.254.170.2",
  ) {}

  async get(): Promise<AwsCredentials> {
    const accessKeyId = this.env.AWS_ACCESS_KEY_ID?.trim();
    const secretAccessKey = this.env.AWS_SECRET_ACCESS_KEY?.trim();
    if (accessKeyId && secretAccessKey) {
      return { accessKeyId, secretAccessKey, sessionToken: this.env.AWS_SESSION_TOKEN?.trim() || undefined };
    }
    if (this.#cached && this.#cached.expiresAt > this.now() + 300_000) return this.#cached.value;
    this.#pending ??= this.#refresh().finally(() => {
      this.#pending = null;
    });
    return this.#pending;
  }

  async #refresh(): Promise<AwsCredentials> {
    const relativeUri = this.env.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI?.trim();
    const fullUri = this.env.AWS_CONTAINER_CREDENTIALS_FULL_URI?.trim();
    const webIdentityTokenFile = this.env.AWS_WEB_IDENTITY_TOKEN_FILE?.trim();
    const roleArn = this.env.AWS_ROLE_ARN?.trim();
    const fresh = relativeUri || fullUri
      ? await this.#container(relativeUri, fullUri)
      : webIdentityTokenFile && roleArn
        ? await this.#webIdentity(webIdentityTokenFile, roleArn)
        : await this.#imds();
    this.#cached = fresh;
    return fresh.value;
  }

  #expiry(expiration: string | undefined | null): number {
    const parsed = expiration ? Date.parse(expiration) : Number.NaN;
    return Number.isFinite(parsed) ? parsed : this.now() + 900_000;
  }

  async #container(relativeUri: string | undefined, fullUri: string | undefined): Promise<CachedCredentials> {
    let url: URL;
    if (relativeUri) {
      if (!relativeUri.startsWith("/")) throw new Error("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI must start with /");
      url = new URL(`${this.ecsBase.replace(/\/+$/, "")}${relativeUri}`);
    } else {
      try {
        url = new URL(fullUri!);
      } catch {
        throw new Error("AWS_CONTAINER_CREDENTIALS_FULL_URI is not a URL");
      }
      if (!containerHostAllowed(url)) {
        throw new Error("AWS_CONTAINER_CREDENTIALS_FULL_URI must be https or http to loopback, 169.254.170.2, 169.254.170.23 or [fd00:ec2::23]");
      }
    }
    const headers: Record<string, string> = {};
    const tokenFile = this.env.AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE?.trim();
    let authorization: string | undefined;
    if (tokenFile) {
      try {
        authorization = (await this.readFileImpl(tokenFile)).trim();
      } catch {
        throw new Error("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE could not be read");
      }
    } else {
      authorization = this.env.AWS_CONTAINER_AUTHORIZATION_TOKEN?.trim() || undefined;
    }
    if (authorization !== undefined) {
      if (!authorization || /[\r\n]/.test(authorization)) throw new Error("container authorization token is empty or malformed");
      headers.authorization = authorization;
    }
    let response: Response;
    let body: { AccessKeyId?: string; SecretAccessKey?: string; Token?: string; Expiration?: string };
    try {
      response = await this.fetchImpl(url.toString(), { method: "GET", headers, signal: AbortSignal.timeout(CONTAINER_TIMEOUT_MS) });
    } catch {
      throw new Error("container credential endpoint could not be reached");
    }
    if (!response.ok) throw new Error(`container credential request failed: ${response.status}`);
    try {
      body = await response.json() as typeof body;
    } catch {
      throw new Error("container credential response is not JSON");
    }
    if (!body?.AccessKeyId || !body.SecretAccessKey) throw new Error("container credential response is incomplete");
    return {
      value: { accessKeyId: body.AccessKeyId, secretAccessKey: body.SecretAccessKey, sessionToken: body.Token || undefined },
      expiresAt: this.#expiry(body.Expiration),
    };
  }

  async #webIdentity(tokenFile: string, roleArn: string): Promise<CachedCredentials> {
    let token: string;
    try {
      token = (await this.readFileImpl(tokenFile)).trim();
    } catch {
      throw new Error("AWS_WEB_IDENTITY_TOKEN_FILE could not be read");
    }
    if (!token) throw new Error("AWS_WEB_IDENTITY_TOKEN_FILE is empty");
    const region = this.env.AWS_REGION?.trim() || this.env.AWS_DEFAULT_REGION?.trim();
    if (region && !/^[a-z0-9-]+$/.test(region)) throw new Error("AWS_REGION is not a region");
    const endpoint = region ? `https://sts.${region}.amazonaws.com/` : "https://sts.amazonaws.com/";
    const sessionName = this.env.AWS_ROLE_SESSION_NAME?.trim() || `relay-control-${this.now()}`;
    const params: Record<string, string> = {
      Action: "AssumeRoleWithWebIdentity",
      RoleArn: roleArn,
      RoleSessionName: sessionName,
      Version: "2011-06-15",
      WebIdentityToken: token,
    };
    const body = Object.keys(params).map((name) => `${encodeRfc3986(name)}=${encodeRfc3986(params[name]!)}`).join("&");
    let response: Response;
    let text: string;
    try {
      response = await this.fetchImpl(endpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded; charset=utf-8" },
        body,
        signal: AbortSignal.timeout(STS_TIMEOUT_MS),
      });
      text = await response.text();
    } catch {
      throw new Error("AssumeRoleWithWebIdentity request failed");
    }
    if (!response.ok) {
      const code = xmlElement(text, "Code");
      throw new Error(`AssumeRoleWithWebIdentity refused: ${code && AWS_ERROR_CODE.test(code) ? code : `http_${response.status}`}`);
    }
    const accessKeyId = xmlElement(text, "AccessKeyId");
    const secretAccessKey = xmlElement(text, "SecretAccessKey");
    const sessionToken = xmlElement(text, "SessionToken");
    if (!accessKeyId || !secretAccessKey || !sessionToken) throw new Error("AssumeRoleWithWebIdentity response is incomplete");
    return { value: { accessKeyId, secretAccessKey, sessionToken }, expiresAt: this.#expiry(xmlElement(text, "Expiration")) };
  }

  async #imds(): Promise<CachedCredentials> {
    const signal = AbortSignal.timeout(IMDS_TIMEOUT_MS);
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
    return {
      value: { accessKeyId: body.AccessKeyId, secretAccessKey: body.SecretAccessKey, sessionToken: body.Token },
      expiresAt: this.#expiry(body.Expiration),
    };
  }
}

export class StaticAwsCredentialProvider implements AwsCredentialProvider {
  constructor(private readonly credentials: AwsCredentials) {}
  async get(): Promise<AwsCredentials> {
    return this.credentials;
  }
}
