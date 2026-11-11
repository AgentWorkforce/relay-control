// Direct-to-S3 session upload credentials (docs/sessions-read-api.md).
// POST .../relayhistory/upload-credentials hands a bearer client holding
// rth:sync either STS session credentials scoped to its own upload inbox prefix
// or presigned PUT URLs for keys it names, plus a signed privacy witness the
// pipeline consumer checks before it admits an object. Credential values, the
// witness key and witnesses are never logged.
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import type { HistoryUploadConfig } from "../config.js";
import {
  DefaultAwsCredentialProvider,
  encodeRfc3986,
  presignV4,
  sha256Hex,
  signV4,
  type AwsCredentialProvider,
} from "../aws/sigv4.js";
import { StsError, type StsClient } from "../aws/sts.js";

/**
 * Per-user upload inbox namespace (relay-upload-inbox-v1). Distinct from the
 * pipeline's `.admission-inbox` (privacy journals) and from the unrelated
 * non-dotted `upload-inbox/v1` root.
 */
export const UPLOAD_INBOX_NAMESPACE = ".upload-inbox";
/** The contract both credential responses name as their first field. */
export const UPLOAD_CONTRACT = "relay-upload-inbox-v1";
export const ADMISSION_INBOX_NAMESPACE = ".admission-inbox";
export const WITNESS_METADATA_KEY = "x-amz-meta-relay-witness";
/** Role chaining caps an assumed-role session at one hour. */
export const UPLOAD_SESSION_DURATION_SECONDS = 3600;
export const PRESIGNED_URL_MAX_MS = 15 * 60_000;
export const MAX_PRESIGNED_KEYS = 64;

export interface UploadTenant {
  orgId: string;
  workspaceId: string;
  userId: string;
}

/**
 * A source id (session, workspace, machine, harness) as a v1 layout key
 * component: `[A-Za-z0-9._-]{1,128}`, not starting with `.`. Ids over 128
 * chars keep 119 chars plus `-` and 8 hex of sha256(id); ids that fit are
 * unchanged.
 *
 * Vendored verbatim: relayhistory-pipeline src/shared/layout-component.ts @ 37f73b1406c13cb8cee272d0fa48c495344dcfc1
 */
export function layoutComponent(id: string): string {
  const safe = id.replace(/[^A-Za-z0-9._-]/g, "_").replace(/^\./, "_");
  if (safe.length <= 128) return safe;
  return `${safe.slice(0, 119)}-${createHash("sha256").update(id).digest("hex").slice(0, 8)}`;
}

/** relayhistory-pipeline src/session-ingest/writer.ts `SEGMENT` @ 37f73b1406c13cb8cee272d0fa48c495344dcfc1 */
const SEGMENT = /^[A-Za-z0-9._-]{1,128}$/;
const KEY_ROOT = /^[a-z0-9][a-z0-9-]{0,62}$/;

/**
 * The org id and key root must each be one key segment, as the pipeline's
 * writer requires (relayhistory-pipeline src/session-ingest/writer.ts
 * assertTenantSegment @ 37f73b1406c13cb8cee272d0fa48c495344dcfc1).
 */
export function assertTenantSegment(keyRoot: string, orgId: string): void {
  if (!SEGMENT.test(orgId) || orgId.startsWith(".") || !KEY_ROOT.test(keyRoot)) throw new Error("tenant_not_a_segment");
}

/**
 * The pipeline's admission user hash (async-admission.ts `userDir`), so one
 * user hash identifies the user across the admission inbox and the
 * upload inbox prefix.
 */
export function uploadUserHash(tenant: UploadTenant): string {
  return sha256Hex(JSON.stringify(["admission-user-v1", tenant.workspaceId, tenant.userId])).slice(0, 32);
}

/**
 * Per (org, workspace, user) privacy journal.
 * Pin: relayhistory-pipeline src/session-ingest/async-admission.ts journalKey @ 37f73b1406c13cb8cee272d0fa48c495344dcfc1
 */
export function journalKey(keyRoot: string, tenant: UploadTenant): string {
  return `${keyRoot}/${ADMISSION_INBOX_NAMESPACE}/${tenant.orgId}/v1/ws=${layoutComponent(tenant.workspaceId)}/m=srv_${uploadUserHash(tenant)}/privacy-journal.json`;
}

/** The only prefix a caller's credentials can write under (ends with `/`). */
export function uploadInboxPrefix(keyRoot: string, tenant: UploadTenant): string {
  return `${keyRoot}/${UPLOAD_INBOX_NAMESPACE}/${tenant.orgId}/v1/ws=${layoutComponent(tenant.workspaceId)}/u=${uploadUserHash(tenant)}/`;
}

/** STS SourceIdentity: the user hash, never the raw user id. */
export function sourceIdentity(tenant: UploadTenant): string {
  return `u_${uploadUserHash(tenant)}`;
}

/**
 * The inline session policy: create-only SSE-KMS PutObject (and multipart
 * abort) under the caller's prefix, and data keys for exactly those objects.
 */
export function sessionPolicy(input: { bucket: string; prefix: string; kmsKeyArn: string }): string {
  const objects = `arn:aws:s3:::${input.bucket}/${input.prefix}*`;
  return JSON.stringify({
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Action: ["s3:PutObject", "s3:AbortMultipartUpload"],
        Resource: objects,
        Condition: {
          StringEquals: {
            "s3:x-amz-server-side-encryption": "aws:kms",
            "s3:x-amz-server-side-encryption-aws-kms-key-id": input.kmsKeyArn,
          },
          Null: { "s3:if-none-match": "false" },
        },
      },
      {
        Effect: "Allow",
        Action: "kms:GenerateDataKey",
        Resource: input.kmsKeyArn,
        Condition: { StringLike: { "kms:EncryptionContext:aws:s3:arn": objects } },
      },
    ],
  });
}

/**
 * Control validates only this segment rule. The pipeline's layout under the
 * prefix (informative) is
 * `o=<originId>/b=<sha256hex(batchId)[:32]>/d=<sha256hex(objectBytes)[:32]>-w<witnessSeq>.json.zst`,
 * where originId is itself a segment (`[A-Za-z0-9._-]{1,128}`, not
 * dot-leading), so `o=<originId>` needs up to 130 characters, hence 160.
 */
const KEY_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._=-]{0,159}$/;

/** A relative object key under the prefix: 1..512 chars of non-empty, non-dot-leading segments. */
export function uploadKeyValid(key: string): boolean {
  return typeof key === "string" && key.length >= 1 && key.length <= 512
    && key.split("/").every((segment) => KEY_SEGMENT.test(segment));
}

// ---- privacy witness ----

export interface WitnessPayload {
  v: 1;
  org: string;
  ws: string;
  user: string;
  /** Privacy journal seq read when the credentials were issued. */
  seq: number;
  /** Epoch seconds. */
  exp: number;
}

const WITNESS_VERSION = "v1";
const WITNESS_DOMAIN = "relay-upload-witness-v1\n";
const b64url = (value: string | Buffer) => Buffer.from(value).toString("base64url");
const witnessMac = (key: Buffer, body: string) => createHmac("sha256", key).update(WITNESS_DOMAIN + body).digest();

/**
 * Decision 0004 (relay-upload-inbox-v1): `v1.<payloadB64url>.<macB64url>`,
 * where payloadB64url is unpadded base64url of the payload JSON in key order
 * `{ v, org, ws, user, seq, exp }` and mac is
 * HMAC-SHA256(key bytes, "relay-upload-witness-v1\n" + payloadB64url).
 * Opaque to clients.
 */
export function signWitness(key: Buffer, payload: WitnessPayload): string {
  const body = b64url(JSON.stringify({
    v: payload.v, org: payload.org, ws: payload.ws, user: payload.user, seq: payload.seq, exp: payload.exp,
  }));
  return `${WITNESS_VERSION}.${body}.${b64url(witnessMac(key, body))}`;
}

/** The payload when the version, MAC and shape are valid, otherwise null. Expiry is the consumer's check. */
export function verifyWitness(key: Buffer, token: string): WitnessPayload | null {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== WITNESS_VERSION || !parts[1] || !parts[2]) return null;
  const [, body, mac] = parts as [string, string, string];
  const expected = witnessMac(key, body);
  const given = Buffer.from(mac, "base64url");
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
  let value: unknown;
  try {
    value = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const v = value as Record<string, unknown>;
  if (Object.keys(v).sort().join(",") !== "exp,org,seq,user,v,ws") return null;
  if (v.v !== 1) return null;
  for (const field of ["org", "ws", "user"] as const) {
    if (typeof v[field] !== "string" || !v[field]) return null;
  }
  if (!Number.isSafeInteger(v.seq) || (v.seq as number) < 0) return null;
  if (!Number.isSafeInteger(v.exp) || (v.exp as number) <= 0) return null;
  return v as unknown as WitnessPayload;
}

// ---- privacy journal ----

export interface PrivacyJournalReader {
  /** The journal's seq (0 when the journal does not exist yet). */
  seq(key: string): Promise<number>;
}

export class JournalUnavailableError extends Error {
  constructor(message: string, readonly code: "privacy_journal_unreadable" | "privacy_journal_invalid") {
    super(message);
    this.name = "JournalUnavailableError";
  }
}

const JOURNAL_MAX_BYTES = 64 * 1024;
const JOURNAL_TIMEOUT_MS = 10_000;

async function limitedText(response: Response, maxBytes: number): Promise<string | null> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Reads the pipeline's privacy journal with a signed S3 GET. A missing
 * journal is the pipeline's empty journal (seq 0); anything unreadable or
 * invalid fails closed and is never read as seq 0.
 */
export class S3PrivacyJournalReader implements PrivacyJournalReader {
  constructor(
    private readonly options: {
      bucket: string;
      region: string;
      credentials?: AwsCredentialProvider;
      /** Override for tests (path-style requests to this origin). */
      endpoint?: string;
      fetchImpl?: typeof fetch;
      now?: () => Date;
    },
  ) {}

  #credentials: AwsCredentialProvider | null = null;

  /** Virtual-hosted URL in production; path style against an endpoint override. */
  url(key: string): URL {
    const encoded = key.split("/").map(encodeRfc3986).join("/");
    if (this.options.endpoint) {
      return new URL(`${this.options.endpoint.replace(/\/+$/, "")}/${this.options.bucket}/${encoded}`);
    }
    return new URL(`https://${this.options.bucket}.s3.${this.options.region}.amazonaws.com/${encoded}`);
  }

  async seq(key: string): Promise<number> {
    const url = this.url(key);
    let response: Response;
    let text: string | null;
    try {
      const credentials = await (this.#credentials ??= this.options.credentials ?? new DefaultAwsCredentialProvider()).get();
      const headers = signV4({
        method: "GET",
        url,
        region: this.options.region,
        service: "s3",
        body: "",
        credentials,
        now: this.options.now?.() ?? new Date(),
      });
      response = await (this.options.fetchImpl ?? fetch)(url.toString(), {
        method: "GET",
        headers,
        signal: AbortSignal.timeout(JOURNAL_TIMEOUT_MS),
      });
      if (response.status === 404) {
        await response.body?.cancel().catch(() => undefined);
        return 0;
      }
      if (response.status !== 200) {
        await response.body?.cancel().catch(() => undefined);
        throw new JournalUnavailableError("The privacy journal could not be read", "privacy_journal_unreadable");
      }
      text = await limitedText(response, JOURNAL_MAX_BYTES);
    } catch (error) {
      if (error instanceof JournalUnavailableError) throw error;
      throw new JournalUnavailableError("The privacy journal could not be read", "privacy_journal_unreadable");
    }
    let value: unknown;
    try {
      value = text === null ? null : JSON.parse(text);
    } catch {
      value = null;
    }
    // Minimal mirror of the pipeline's validJournal (async-admission.ts).
    const journal = value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
    if (
      !journal || journal.v !== 3 || !Number.isSafeInteger(journal.seq) || (journal.seq as number) < 0
      || !Array.isArray(journal.pending) || !Array.isArray(journal.ambiguous)
    ) {
      throw new JournalUnavailableError("The privacy journal is invalid", "privacy_journal_invalid");
    }
    return journal.seq as number;
  }
}

// ---- request and issuance ----

export class UploadCredentialsError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
    this.name = "UploadCredentialsError";
  }
}

export interface UploadKeyRequest {
  /** Object key relative to the caller's upload inbox prefix. */
  key: string;
  /** Base64 of the raw 32-byte SHA-256 of the object bytes as uploaded (zstd wire bytes). */
  sha256: string;
}

export interface UploadCredentialsRequest {
  originId: string;
  kind: "sts" | "presigned";
  keys?: UploadKeyRequest[];
}

const SHA256_BASE64 = /^[A-Za-z0-9+/]{43}=$/;

function keyEntryValid(entry: unknown): entry is UploadKeyRequest {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) return false;
  const { key, sha256 } = entry as Record<string, unknown>;
  return typeof key === "string" && uploadKeyValid(key)
    && typeof sha256 === "string" && SHA256_BASE64.test(sha256)
    && Buffer.from(sha256, "base64").length === 32;
}

/** originId becomes the `o=` key segment, so it follows the contract's segment rule. */
const originIdValid = (value: string) => SEGMENT.test(value) && !value.startsWith(".");

export function parseUploadCredentialsRequest(body: unknown): UploadCredentialsRequest {
  const invalid = (message: string) => new UploadCredentialsError(400, "invalid_request", message);
  if (!body || typeof body !== "object" || Array.isArray(body)) throw invalid("Body must be a JSON object");
  const { originId, kind, keys } = body as Record<string, unknown>;
  if (typeof originId !== "string" || !originIdValid(originId)) {
    throw invalid("originId must match ^[A-Za-z0-9._-]{1,128}$ and not start with '.'");
  }
  if (kind !== "sts" && kind !== "presigned") throw invalid("kind must be sts or presigned");
  if (keys !== undefined) {
    if (
      !Array.isArray(keys) || keys.length < 1 || keys.length > MAX_PRESIGNED_KEYS
      || !keys.every(keyEntryValid)
      || new Set(keys.map((entry) => entry.key)).size !== keys.length
    ) {
      throw invalid(`keys must be 1 to ${MAX_PRESIGNED_KEYS} objects with a unique relative key and a base64 sha256`);
    }
  }
  if (kind === "presigned" && keys === undefined) throw invalid("presigned requests must name keys");
  return { originId, kind, ...(keys !== undefined ? { keys: (keys as UploadKeyRequest[]).map(({ key, sha256 }) => ({ key, sha256 })) } : {}) };
}

export class HistoryUploadCredentials {
  constructor(
    private readonly options: {
      config: HistoryUploadConfig;
      sts: StsClient;
      journal: PrivacyJournalReader;
      now?: () => Date;
    },
  ) {}

  async issue(tenant: UploadTenant, request: UploadCredentialsRequest): Promise<Record<string, unknown>> {
    const { config, sts, journal } = this.options;
    try {
      assertTenantSegment(config.keyRoot, tenant.orgId);
    } catch {
      throw new UploadCredentialsError(400, "invalid_tenant", "The organization id cannot be used as an upload key segment");
    }
    let seq: number;
    try {
      seq = await journal.seq(journalKey(config.keyRoot, tenant));
    } catch (error) {
      if (!(error instanceof JournalUnavailableError)) throw error;
      console.warn("[history-upload] privacy journal unavailable", { code: error.code });
      throw new UploadCredentialsError(503, "privacy_journal_unavailable", "Upload credentials are unavailable; use the ingest edge");
    }
    const prefix = uploadInboxPrefix(config.keyRoot, tenant);
    const policy = sessionPolicy({ bucket: config.bucket, prefix, kmsKeyArn: config.kmsKeyArn });
    let creds;
    try {
      creds = await sts.assumeRole({
        roleArn: config.roleArn,
        roleSessionName: `history-upload-${uploadUserHash(tenant)}`,
        sourceIdentity: sourceIdentity(tenant),
        policy,
        durationSeconds: UPLOAD_SESSION_DURATION_SECONDS,
      });
    } catch (error) {
      if (!(error instanceof StsError)) throw error;
      console.warn("[history-upload] AssumeRole failed", { code: error.code });
      throw new UploadCredentialsError(503, "upload_credentials_unavailable", "Upload credentials are unavailable; use the ingest edge");
    }
    const witness = signWitness(config.witnessKey, {
      v: 1,
      org: tenant.orgId,
      ws: tenant.workspaceId,
      user: tenant.userId,
      seq,
      exp: Math.floor(creds.expiresAt.getTime() / 1000),
    });
    const now = this.options.now?.() ?? new Date();
    // witnessSeq is the seq inside the signed witness, readable by clients that treat the witness as opaque.
    const common = {
      bucket: config.bucket,
      region: config.region,
      endpoint: null,
      keyPrefix: prefix,
      kmsKeyId: config.kmsKeyArn,
    };
    if (request.kind === "sts") {
      return {
        contract: UPLOAD_CONTRACT,
        kind: "sts",
        ...common,
        credentials: {
          accessKeyId: creds.accessKeyId,
          secretAccessKey: creds.secretAccessKey,
          sessionToken: creds.sessionToken,
          expiresAt: creds.expiresAt.toISOString(),
        },
        witness,
        witnessSeq: seq,
        maxObjectBytes: config.maxObjectBytes,
        refreshAfter: new Date(Math.max(now.getTime() + 60_000, creds.expiresAt.getTime() - 10 * 60_000)).toISOString(),
      };
    }
    const urlLimit = Math.min(creds.expiresAt.getTime(), now.getTime() + PRESIGNED_URL_MAX_MS);
    const expiresSeconds = Math.max(1, Math.floor((urlLimit - now.getTime()) / 1000));
    const urlExpiresAt = new Date(now.getTime() + expiresSeconds * 1000);
    const baseHeaders = {
      "content-encoding": "zstd",
      "if-none-match": "*",
      [WITNESS_METADATA_KEY]: witness,
      "x-amz-server-side-encryption": "aws:kms",
      "x-amz-server-side-encryption-aws-kms-key-id": config.kmsKeyArn,
    };
    const urls = (request.keys ?? []).map(({ key, sha256 }) => ({
      key,
      url: presignV4({
        method: "PUT",
        url: new URL(`https://${config.bucket}.s3.${config.region}.amazonaws.com/${`${prefix}${key}`.split("/").map(encodeRfc3986).join("/")}`),
        region: config.region,
        service: "s3",
        credentials: { accessKeyId: creds.accessKeyId, secretAccessKey: creds.secretAccessKey, sessionToken: creds.sessionToken },
        now,
        expiresSeconds,
        signedHeaders: { ...baseHeaders, "x-amz-checksum-sha256": sha256 },
      }).toString(),
      expiresAt: urlExpiresAt.toISOString(),
    }));
    return {
      contract: UPLOAD_CONTRACT,
      kind: "presigned",
      ...common,
      witness,
      witnessSeq: seq,
      maxObjectBytes: config.maxObjectBytes,
      refreshAfter: new Date(Math.max(now.getTime() + 60_000, urlExpiresAt.getTime() - 5 * 60_000)).toISOString(),
      urls,
    };
  }
}
