// Desktop feed object storage: one private bucket (SSE-S3 on every write), with
// per-profile prefixes under <prefix>/profiles/<profile>/:
//   drafts/<version>/<name>     uploads of a release not yet published
//   releases/<version>/<name>   published assets, what downloads read
//   manifests/<channel>.json    a copy of the channel's current signed envelope
// There is deliberately no listing operation. Postgres is the source of truth
// for envelopes (desktop_feed_releases.envelope, served byte-for-byte);
// the manifests/ objects are a copy written after each publish commits.
import { createHash } from "node:crypto";
import { request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest } from "node:https";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { DefaultAwsCredentialProvider, presignV4, signV4, type AwsCredentialProvider } from "../aws/sigv4.js";

export type ByteRange = { start: number; end: number };

export class StorageError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = "StorageError";
  }
}

export interface DesktopFeedStorage {
  readonly kind: "memory" | "s3";
  /**
   * Store exactly `size` bytes whose sha256 is `sha256`. Rejects (and keeps
   * nothing) when the received bytes differ; the caller also checks.
   */
  put(key: string, body: Readable, size: number, sha256: string): Promise<void>;
  /** Copy one object within the store; repeating it is harmless. */
  copy(sourceKey: string, destinationKey: string): Promise<void>;
  /** The object's bytes (or the inclusive range), or null when missing. */
  get(key: string, range?: ByteRange): Promise<Readable | null>;
  delete(key: string): Promise<void>;
  /** The public host a signed URL points at, or null when this store cannot sign URLs. */
  downloadHost(): string | null;
  /** A signed GET URL for one object, or null when unsupported. */
  presignGet(key: string, expiresSeconds: number, now: Date): Promise<URL | null>;
}

const BUCKET = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;

/** Process memory; tests and local development. No signed URLs (download-url answers 501). */
export class MemoryDesktopFeedStorage implements DesktopFeedStorage {
  readonly kind = "memory" as const;
  readonly objects = new Map<string, Buffer>();
  async put(key: string, body: Readable, size: number, sha256: string): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const chunk of body) chunks.push(Buffer.from(chunk as Buffer));
    const bytes = Buffer.concat(chunks);
    if (bytes.length !== size || createHash("sha256").update(bytes).digest("hex") !== sha256) {
      throw new StorageError("object bytes do not match the declared size and sha256");
    }
    this.objects.set(key, bytes);
  }
  async copy(sourceKey: string, destinationKey: string): Promise<void> {
    const bytes = this.objects.get(sourceKey);
    if (!bytes) throw new StorageError("copy source is missing", 404);
    this.objects.set(destinationKey, bytes);
  }
  async get(key: string, range?: ByteRange): Promise<Readable | null> {
    const bytes = this.objects.get(key);
    if (!bytes) return null;
    return Readable.from([range ? bytes.subarray(range.start, range.end + 1) : bytes]);
  }
  async delete(key: string): Promise<void> {
    this.objects.delete(key);
  }
  downloadHost(): null {
    return null;
  }
  async presignGet(): Promise<null> {
    return null;
  }
}

/**
 * S3 with SigV4 (src/aws/sigv4.ts) and the instance role. Uploads stream
 * straight through: the request is signed with the declared sha256 as
 * x-amz-content-sha256, so S3 itself refuses bytes that do not match. Every
 * write asks for SSE-S3 (AES256).
 */
export class S3DesktopFeedStorage implements DesktopFeedStorage {
  readonly kind = "s3" as const;
  constructor(
    private readonly options: {
      bucket: string;
      region: string;
      prefix: string;
      credentials?: AwsCredentialProvider;
      /** Override for tests (path-style requests to this origin). */
      endpoint?: string;
      now?: () => Date;
    },
  ) {
    if (!BUCKET.test(options.bucket)) throw new Error("SELFHOST_DESKTOP_FEED_S3_BUCKET is not a valid bucket name");
    if (!/^[a-z0-9-]+$/.test(options.region)) throw new Error("SELFHOST_DESKTOP_FEED_S3_REGION is not a region");
  }
  #credentials: AwsCredentialProvider | null = null;
  private get credentials(): AwsCredentialProvider {
    this.#credentials ??= this.options.credentials ?? new DefaultAwsCredentialProvider();
    return this.#credentials;
  }
  private objectKey(key: string): string {
    const prefix = this.options.prefix.replace(/^\/+|\/+$/g, "");
    return prefix ? `${prefix}/${key}` : key;
  }
  /** Virtual-hosted URL in production; path style against an endpoint override. */
  url(key: string): URL {
    const encoded = this.objectKey(key).split("/").map(encodeURIComponent).join("/");
    if (this.options.endpoint) {
      return new URL(`${this.options.endpoint.replace(/\/+$/, "")}/${this.options.bucket}/${encoded}`);
    }
    return new URL(`https://${this.options.bucket}.s3.${this.options.region}.amazonaws.com/${encoded}`);
  }
  downloadHost(): string {
    return `${this.options.bucket}.s3.${this.options.region}.amazonaws.com`;
  }
  private async send(
    method: "GET" | "PUT" | "DELETE",
    key: string,
    options: { body?: Readable; size?: number; sha256?: string; range?: ByteRange; copySource?: string } = {},
  ): Promise<IncomingMessage> {
    const url = this.url(key);
    const extraHeaders: Record<string, string> = {};
    if (options.size !== undefined) {
      extraHeaders["content-length"] = String(options.size);
      extraHeaders["content-type"] = "application/octet-stream";
    }
    if (method === "PUT") extraHeaders["x-amz-server-side-encryption"] = "AES256";
    if (options.copySource) extraHeaders["x-amz-copy-source"] = options.copySource;
    if (options.range) extraHeaders.range = `bytes=${options.range.start}-${options.range.end}`;
    const headers = signV4({
      method,
      url,
      region: this.options.region,
      service: "s3",
      ...(options.sha256 ? { payloadHash: options.sha256 } : { body: "" }),
      credentials: await this.credentials.get(),
      now: this.options.now?.() ?? new Date(),
      extraHeaders,
    });
    const send = url.protocol === "https:" ? httpsRequest : httpRequest;
    return new Promise<IncomingMessage>((resolve, reject) => {
      const outgoing = send(url, { method, headers }, resolve);
      outgoing.setTimeout(120_000, () => outgoing.destroy(new StorageError("S3 request timed out")));
      outgoing.on("error", (error) => reject(error instanceof StorageError ? error : new StorageError("S3 request failed")));
      if (options.body) {
        pipeline(options.body, outgoing).catch((error) => {
          outgoing.destroy();
          reject(error instanceof StorageError ? error : new StorageError("upload stream failed"));
        });
      } else {
        outgoing.end();
      }
    });
  }
  async put(key: string, body: Readable, size: number, sha256: string): Promise<void> {
    const response = await this.send("PUT", key, { body, size, sha256 });
    response.resume();
    if (response.statusCode !== 200) throw new StorageError(`S3 upload failed: ${response.statusCode}`, response.statusCode);
  }
  async copy(sourceKey: string, destinationKey: string): Promise<void> {
    const encoded = this.objectKey(sourceKey).split("/").map(encodeURIComponent).join("/");
    const response = await this.send("PUT", destinationKey, { copySource: `/${this.options.bucket}/${encoded}` });
    // S3 can answer 200 and still fail a copy: the error is in the body.
    const chunks: Buffer[] = [];
    for await (const chunk of response) chunks.push(Buffer.from(chunk as Buffer));
    if (response.statusCode !== 200 || Buffer.concat(chunks).includes("<Error>")) {
      throw new StorageError(`S3 copy failed: ${response.statusCode}`, response.statusCode);
    }
  }
  async get(key: string, range?: ByteRange): Promise<Readable | null> {
    const response = await this.send("GET", key, { range });
    if (response.statusCode === 404) {
      response.resume();
      return null;
    }
    if (response.statusCode !== 200 && response.statusCode !== 206) {
      response.resume();
      throw new StorageError(`S3 download failed: ${response.statusCode}`, response.statusCode);
    }
    return response;
  }
  async delete(key: string): Promise<void> {
    const response = await this.send("DELETE", key);
    response.resume();
    if (response.statusCode !== 204 && response.statusCode !== 200 && response.statusCode !== 404) {
      throw new StorageError(`S3 delete failed: ${response.statusCode}`, response.statusCode);
    }
  }
  async presignGet(key: string, expiresSeconds: number, now: Date): Promise<URL> {
    // Signed URLs always use the public virtual-hosted https host, which is
    // what the manifest's download_hosts names.
    const encoded = this.objectKey(key).split("/").map(encodeURIComponent).join("/");
    return presignV4({
      method: "GET",
      url: new URL(`https://${this.downloadHost()}/${encoded}`),
      region: this.options.region,
      service: "s3",
      credentials: await this.credentials.get(),
      now,
      expiresSeconds,
    });
  }
}
