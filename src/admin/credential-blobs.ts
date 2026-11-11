// Encrypted credential blobs for subscription logins (Codex auth.json, Grok
// auth.json). Hosted keeps these as AES-256-GCM objects in an S3-shaped
// bucket (R2) under one static CredentialEncryptionKey. Self-host keeps the
// same object model and improves the key handling with envelope encryption:
//
// - every write draws a fresh 256-bit data key (DEK) and encrypts the blob
//   with it (AES-256-GCM, AAD binds the credential id and blob version);
// - the DEK is wrapped with the SELFHOST_ENCRYPTION_KEY keyring
//   (crypto.ts encryptSecret, `v2.<keyId>.…`), so key rotation keeps working
//   through the existing active/previous keyId mechanism;
// - the envelope JSON goes to the customer's object storage (GCS or S3) or,
//   when no bucket is configured, inline into Postgres.
//
// Plaintext never leaves this module except to the run-scoped materialisation
// read and the in-process refresher.
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from "node:crypto";
import type { Database, SqlExecutor } from "../database.js";
import { decryptSecret, encryptSecret, type EncryptionKeyring } from "../crypto.js";
import { DefaultAwsCredentialProvider, type AwsCredentialProvider } from "../aws/sigv4.js";

export type CredentialEnvelope = {
  v: 1;
  alg: "A256GCM";
  /** keyId of the keyring entry that wrapped the data key (also inside wrappedKey). */
  keyId: string;
  wrappedKey: string;
  iv: string;
  tag: string;
  ciphertext: string;
};

export class CredentialBlobError extends Error {
  constructor(readonly code: "missing" | "malformed" | "decrypt_failed" | "backend_failed", message: string) {
    super(message);
    this.name = "CredentialBlobError";
  }
}

function aad(credentialId: string, version: number): Buffer {
  return Buffer.from(`selfhost-cli-credential:v1:${credentialId}:${version}`, "utf8");
}

export function sealCredential(
  plaintext: string,
  keyring: EncryptionKeyring,
  credentialId: string,
  version: number,
): CredentialEnvelope {
  const dek = randomBytes(32);
  try {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", dek, iv);
    cipher.setAAD(aad(credentialId, version));
    const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
    return {
      v: 1,
      alg: "A256GCM",
      keyId: keyring.active.id,
      wrappedKey: encryptSecret(dek.toString("base64url"), keyring.active),
      iv: iv.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
      ciphertext: ciphertext.toString("base64url"),
    };
  } finally {
    dek.fill(0);
  }
}

export function openCredential(
  envelope: CredentialEnvelope,
  keyring: EncryptionKeyring,
  credentialId: string,
  version: number,
): string {
  if (envelope?.v !== 1 || envelope.alg !== "A256GCM") {
    throw new CredentialBlobError("malformed", "Unsupported credential envelope");
  }
  let dek: Buffer;
  try {
    dek = Buffer.from(decryptSecret(envelope.wrappedKey, keyring), "base64url");
  } catch {
    throw new CredentialBlobError("decrypt_failed", "Credential data key cannot be unwrapped with the configured keys");
  }
  try {
    const decipher = createDecipheriv("aes-256-gcm", dek, Buffer.from(envelope.iv, "base64url"));
    decipher.setAAD(aad(credentialId, version));
    decipher.setAuthTag(Buffer.from(envelope.tag, "base64url"));
    return Buffer.concat([
      decipher.update(Buffer.from(envelope.ciphertext, "base64url")),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    throw new CredentialBlobError("decrypt_failed", "Credential blob failed authentication");
  } finally {
    dek.fill(0);
  }
}

/** Where envelopes live. The Postgres row keeps only (backend, location, version). */
export interface CredentialObjectBackend {
  readonly kind: "postgres" | "gcs" | "s3";
  /** `executor` lets the Postgres backend join the caller's transaction; others ignore it. */
  put(key: string, body: string, executor?: SqlExecutor): Promise<void>;
  get(key: string, executor?: SqlExecutor): Promise<string | null>;
  delete(key: string, executor?: SqlExecutor): Promise<void>;
}

/** Fallback: envelopes inline in coding_agent_credential_blobs. */
export class PostgresObjectBackend implements CredentialObjectBackend {
  readonly kind = "postgres" as const;
  constructor(private readonly database: Database) {}
  async put(key: string, body: string, executor: SqlExecutor = this.database): Promise<void> {
    await executor.query(
      `INSERT INTO coding_agent_credential_blobs (object_key, envelope)
       VALUES ($1, $2)
       ON CONFLICT (object_key) DO UPDATE SET envelope = EXCLUDED.envelope, updated_at = now()`,
      [key, body],
    );
  }
  async get(key: string, executor: SqlExecutor = this.database): Promise<string | null> {
    const result = await executor.query<{ envelope: string }>(
      "SELECT envelope FROM coding_agent_credential_blobs WHERE object_key = $1",
      [key],
    );
    return result.rows[0]?.envelope ?? null;
  }
  async delete(key: string, executor: SqlExecutor = this.database): Promise<void> {
    await executor.query("DELETE FROM coding_agent_credential_blobs WHERE object_key = $1", [key]);
  }
}

type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/** GCS JSON API through the pod's Workload Identity (same as flows GcsBackend). */
export class GcsObjectBackend implements CredentialObjectBackend {
  readonly kind = "gcs" as const;
  #token: { value: string; expiresAt: number } | null = null;
  constructor(
    private readonly bucket: string,
    private readonly prefix: string,
    private readonly fetchImpl: FetchLike = (url, init) => fetch(url, init),
    private readonly tokenUrl =
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
  ) {
    if (!/^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$/.test(bucket)) {
      throw new Error("credential GCS bucket is not a valid bucket name");
    }
  }
  private async accessToken(): Promise<string> {
    if (this.#token && this.#token.expiresAt > Date.now() + 60_000) return this.#token.value;
    const response = await this.fetchImpl(this.tokenUrl, { headers: { "metadata-flavor": "Google" } });
    if (!response.ok) throw new CredentialBlobError("backend_failed", `GCS token request failed: ${response.status}`);
    const body = await response.json() as { access_token?: string; expires_in?: number };
    if (!body.access_token) throw new CredentialBlobError("backend_failed", "GCS token response missing access_token");
    this.#token = { value: body.access_token, expiresAt: Date.now() + (body.expires_in ?? 300) * 1_000 };
    return this.#token.value;
  }
  private name(key: string): string {
    return `${this.prefix.replace(/\/+$/, "")}/${key}`;
  }
  async put(key: string, body: string): Promise<void> {
    const url = `https://storage.googleapis.com/upload/storage/v1/b/${encodeURIComponent(this.bucket)}/o?uploadType=media&name=${encodeURIComponent(this.name(key))}`;
    const response = await this.fetchImpl(url, {
      method: "POST",
      headers: { authorization: `Bearer ${await this.accessToken()}`, "content-type": "application/json" },
      body,
    });
    if (!response.ok) throw new CredentialBlobError("backend_failed", `GCS upload failed: ${response.status}`);
  }
  async get(key: string): Promise<string | null> {
    const url = `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(this.bucket)}/o/${encodeURIComponent(this.name(key))}?alt=media`;
    const response = await this.fetchImpl(url, { headers: { authorization: `Bearer ${await this.accessToken()}` } });
    if (response.status === 404) return null;
    if (!response.ok) throw new CredentialBlobError("backend_failed", `GCS download failed: ${response.status}`);
    return response.text();
  }
  async delete(key: string): Promise<void> {
    const url = `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(this.bucket)}/o/${encodeURIComponent(this.name(key))}`;
    const response = await this.fetchImpl(url, {
      method: "DELETE",
      headers: { authorization: `Bearer ${await this.accessToken()}` },
    });
    if (!response.ok && response.status !== 404) {
      throw new CredentialBlobError("backend_failed", `GCS delete failed: ${response.status}`);
    }
  }
}

export type S3Credentials = { accessKeyId: string; secretAccessKey: string; sessionToken?: string };

/**
 * S3 (or any S3-compatible store: R2, MinIO) with AWS Signature V4, the
 * semantics hosted's R2 credential store uses. Credentials are either static
 * or an AwsCredentialProvider (from the environment: the shared AWS chain of
 * static keys, container/Pod Identity, web identity, then IMDSv2).
 */
export class S3ObjectBackend implements CredentialObjectBackend {
  readonly kind = "s3" as const;
  constructor(
    private readonly options: {
      bucket: string;
      region: string;
      prefix: string;
      endpoint?: string;
      credentials: S3Credentials | AwsCredentialProvider;
      forcePathStyle?: boolean;
    },
    private readonly fetchImpl: FetchLike = (url, init) => fetch(url, init),
    private readonly now: () => Date = () => new Date(),
  ) {
    if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(options.bucket)) {
      throw new Error("credential S3 bucket is not a valid bucket name");
    }
  }
  private url(key: string): URL {
    const objectKey = `${this.options.prefix.replace(/\/+$/, "")}/${key}`;
    const encoded = objectKey.split("/").map(encodeURIComponent).join("/");
    if (this.options.endpoint || this.options.forcePathStyle) {
      const base = (this.options.endpoint ?? `https://s3.${this.options.region}.amazonaws.com`).replace(/\/+$/, "");
      return new URL(`${base}/${this.options.bucket}/${encoded}`);
    }
    return new URL(`https://${this.options.bucket}.s3.${this.options.region}.amazonaws.com/${encoded}`);
  }
  private async request(method: "GET" | "PUT" | "DELETE", key: string, body?: string): Promise<Response> {
    const url = this.url(key);
    const source = this.options.credentials;
    let credentials: S3Credentials;
    try {
      credentials = "get" in source ? await source.get() : source;
    } catch (error) {
      // Provider messages carry no credential values.
      throw new CredentialBlobError("backend_failed", `S3 credentials unavailable: ${error instanceof Error ? error.message : "unknown error"}`);
    }
    const headers = signV4({
      method,
      url,
      region: this.options.region,
      service: "s3",
      body: body ?? "",
      credentials,
      now: this.now(),
      extraHeaders: body !== undefined ? { "content-type": "application/json" } : {},
    });
    return this.fetchImpl(url.toString(), { method, headers, body });
  }
  async put(key: string, body: string): Promise<void> {
    const response = await this.request("PUT", key, body);
    if (!response.ok) throw new CredentialBlobError("backend_failed", `S3 upload failed: ${response.status}`);
  }
  async get(key: string): Promise<string | null> {
    const response = await this.request("GET", key);
    if (response.status === 404) return null;
    if (!response.ok) throw new CredentialBlobError("backend_failed", `S3 download failed: ${response.status}`);
    return response.text();
  }
  async delete(key: string): Promise<void> {
    const response = await this.request("DELETE", key);
    if (!response.ok && response.status !== 404) {
      throw new CredentialBlobError("backend_failed", `S3 delete failed: ${response.status}`);
    }
  }
}

const sha256Hex = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const hmac = (key: string | Buffer, value: string) => createHmac("sha256", key).update(value).digest();

/** AWS Signature Version 4 header signing (single-chunk payload). */
export function signV4(input: {
  method: string;
  url: URL;
  region: string;
  service: string;
  body: string;
  credentials: S3Credentials;
  now: Date;
  extraHeaders?: Record<string, string>;
}): Record<string, string> {
  const amzDate = input.now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const date = amzDate.slice(0, 8);
  const payloadHash = sha256Hex(input.body);
  const headers: Record<string, string> = {
    host: input.url.host,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate,
    ...(input.credentials.sessionToken ? { "x-amz-security-token": input.credentials.sessionToken } : {}),
    ...Object.fromEntries(Object.entries(input.extraHeaders ?? {}).map(([k, v]) => [k.toLowerCase(), v])),
  };
  const names = Object.keys(headers).sort();
  const canonicalHeaders = names.map((name) => `${name}:${headers[name]!.trim()}\n`).join("");
  const signedHeaders = names.join(";");
  const query = [...input.url.searchParams.entries()]
    .map(([k, v]) => [encodeRfc3986(k), encodeRfc3986(v)])
    .sort(([a], [b]) => (a! < b! ? -1 : a! > b! ? 1 : 0))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
  const canonicalRequest = [
    input.method,
    input.url.pathname,
    query,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");
  const scope = `${date}/${input.region}/${input.service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonicalRequest)].join("\n");
  const signingKey = hmac(
    hmac(hmac(hmac(`AWS4${input.credentials.secretAccessKey}`, date), input.region), input.service),
    "aws4_request",
  );
  const signature = createHmac("sha256", signingKey).update(stringToSign).digest("hex");
  const { host: _host, ...rest } = headers;
  return {
    ...rest,
    authorization: `AWS4-HMAC-SHA256 Credential=${input.credentials.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
  };
}

function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

type Env = Record<string, string | undefined>;

/**
 * Backend selection. SELFHOST_CREDENTIAL_STORAGE=postgres|gcs|s3 wins; when it
 * is unset, credentials follow SELFHOST_FLOWS_STORAGE=gcs into the same bucket
 * (prefix coding-agent-credentials/), else Postgres.
 */
export function credentialBackendFromEnv(
  env: Env,
  database: Database,
  fetchImpl?: FetchLike,
): CredentialObjectBackend {
  const explicit = env.SELFHOST_CREDENTIAL_STORAGE?.trim();
  const kind = explicit || (env.SELFHOST_FLOWS_STORAGE?.trim() === "gcs" ? "gcs" : "postgres");
  const prefix = env.SELFHOST_CREDENTIAL_PREFIX?.trim() || "coding-agent-credentials";
  if (kind === "postgres") return new PostgresObjectBackend(database);
  if (kind === "gcs") {
    const bucket = env.SELFHOST_CREDENTIAL_GCS_BUCKET?.trim() || env.SELFHOST_FLOWS_GCS_BUCKET?.trim();
    if (!bucket) throw new Error("SELFHOST_CREDENTIAL_GCS_BUCKET (or SELFHOST_FLOWS_GCS_BUCKET) is required for gcs credential storage");
    return new GcsObjectBackend(bucket, prefix, fetchImpl);
  }
  if (kind === "s3") {
    const bucket = env.SELFHOST_CREDENTIAL_S3_BUCKET?.trim();
    const region = env.SELFHOST_CREDENTIAL_S3_REGION?.trim() || env.AWS_REGION?.trim();
    if (!bucket || !region) {
      throw new Error("s3 credential storage needs SELFHOST_CREDENTIAL_S3_BUCKET and a region (SELFHOST_CREDENTIAL_S3_REGION or AWS_REGION)");
    }
    const endpoint = env.SELFHOST_CREDENTIAL_S3_ENDPOINT?.trim() || undefined;
    const staticKeys = Boolean(env.AWS_ACCESS_KEY_ID?.trim() && env.AWS_SECRET_ACCESS_KEY?.trim());
    if (endpoint && !staticKeys) {
      // Ambient AWS role credentials must never be sent to a non-AWS store
      // (R2, MinIO); AWS VPC/PrivateLink endpoints may still use them.
      let host: string;
      try {
        host = new URL(endpoint).hostname.toLowerCase();
      } catch {
        throw new Error("SELFHOST_CREDENTIAL_S3_ENDPOINT is not a URL");
      }
      if (!(host === "amazonaws.com" || host.endsWith(".amazonaws.com"))) {
        throw new Error("a non-AWS SELFHOST_CREDENTIAL_S3_ENDPOINT needs AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY");
      }
    }
    return new S3ObjectBackend({
      bucket,
      region,
      prefix,
      endpoint,
      forcePathStyle: env.SELFHOST_CREDENTIAL_S3_FORCE_PATH_STYLE === "true",
      // Static AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY still win; otherwise the
      // ambient role (EKS Pod Identity, IRSA, ECS task role, EC2 instance role).
      credentials: new DefaultAwsCredentialProvider(env),
    }, fetchImpl);
  }
  throw new Error("SELFHOST_CREDENTIAL_STORAGE must be postgres, gcs or s3");
}

/** Object key per credential row and version (hosted: credentials/<user>/accounts/<rowId>/…). */
export function credentialObjectKey(workspaceId: string, credentialId: string, version: number): string {
  return `workspaces/${workspaceId}/accounts/${credentialId}/v${version}.json.enc`;
}

export class CredentialBlobStore {
  constructor(
    private readonly backend: CredentialObjectBackend,
    private readonly keyring: EncryptionKeyring,
  ) {}

  get kind(): CredentialObjectBackend["kind"] {
    return this.backend.kind;
  }

  async write(
    workspaceId: string,
    credentialId: string,
    version: number,
    plaintext: string,
    executor?: SqlExecutor,
  ): Promise<string> {
    const key = credentialObjectKey(workspaceId, credentialId, version);
    await this.backend.put(key, JSON.stringify(sealCredential(plaintext, this.keyring, credentialId, version)), executor);
    return key;
  }

  async read(location: string, credentialId: string, version: number, executor?: SqlExecutor): Promise<string> {
    const raw = await this.backend.get(location, executor);
    if (!raw) throw new CredentialBlobError("missing", "Credential blob is missing from storage");
    let envelope: CredentialEnvelope;
    try {
      envelope = JSON.parse(raw) as CredentialEnvelope;
    } catch {
      throw new CredentialBlobError("malformed", "Credential blob is not an envelope");
    }
    return openCredential(envelope, this.keyring, credentialId, version);
  }

  async remove(location: string): Promise<void> {
    await this.backend.delete(location);
  }
}
