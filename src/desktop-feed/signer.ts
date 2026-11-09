// Desktop feed signers. The publish handler never sees key material: it asks
// the signer for a signature over the RFC 8785 canonical manifest bytes and
// for the declared canonical byte limit.
//
// - awskms: AWS KMS key spec ECC_NIST_EDWARDS25519, Sign with MessageType RAW
//   and SigningAlgorithm ED25519_SHA_512 (pure Ed25519, RFC 8032; never
//   ED25519_PH_SHA_512, which prehashes and would fail client verification).
//   RAW messages are capped at 4096 bytes by KMS, so maxCanonicalBytes() is
//   4096. One key per profile, addressed by alias. Credentials come from the
//   instance role (IMDSv2) or AWS_* env.
// - memory: a node:crypto key pair per profile, generated in process. Tests
//   and local development only; config refuses nothing else, but the key
//   dies with the process so nothing it signs survives a restart.
import { createPublicKey, generateKeyPairSync, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";
import { DefaultAwsCredentialProvider, signV4, type AwsCredentialProvider } from "../aws/sigv4.js";

export type DesktopFeedSignature = { signature: string; keyId: string };

export interface DesktopFeedSigner {
  readonly kind: "memory" | "awskms";
  /** `fk_<profile>_<label>`. */
  keyId(profile: string): string;
  /** Ed25519 over `bytes`, base64url without padding (86 characters). */
  sign(profile: string, bytes: Buffer): Promise<DesktopFeedSignature>;
  /** Raw 32-byte Ed25519 public key, standard base64 (DESKTOP_FEED_PUBLIC_KEY). */
  publicKey(profile: string): Promise<string>;
  /** Largest canonical manifest the signer accepts, or null for no declared limit. */
  maxCanonicalBytes(): number | null;
  /** Whether this signer holds a key for the profile. */
  hasProfile(profile: string): boolean;
}

/** The signer could not be reached or refused; publish answers 503 signer_unavailable. */
export class SignerUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignerUnavailableError";
  }
}

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Raw 32-byte key from an Ed25519 SubjectPublicKeyInfo DER, as base64. */
export function rawPublicKeyFromSpki(der: Buffer): string {
  if (der.length !== 44 || !der.subarray(0, 12).equals(SPKI_ED25519_PREFIX)) {
    throw new Error("public key is not an Ed25519 SubjectPublicKeyInfo");
  }
  return der.subarray(12).toString("base64");
}

/** KeyObject from the raw base64 form (what a build compiles in). */
export function publicKeyFromRaw(rawBase64: string): KeyObject {
  const raw = Buffer.from(rawBase64, "base64");
  if (raw.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  return createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: "der", type: "spki" });
}

export function verifyEd25519(rawPublicKey: string, bytes: Buffer, signatureB64url: string): boolean {
  const signature = Buffer.from(signatureB64url, "base64url");
  if (signature.length !== 64) return false;
  try {
    return edVerify(null, bytes, publicKeyFromRaw(rawPublicKey), signature);
  } catch {
    return false;
  }
}

export const KEY_LABEL_PATTERN = /^[a-z0-9]{1,16}$/;

export class MemoryDesktopFeedSigner implements DesktopFeedSigner {
  readonly kind = "memory" as const;
  readonly #keys = new Map<string, { privateKey: KeyObject; publicKey: KeyObject }>();
  constructor(private readonly options: { label?: string; maxCanonicalBytes?: number | null } = {}) {
    if (!KEY_LABEL_PATTERN.test(this.label)) throw new Error("memory signer key label must match ^[a-z0-9]{1,16}$");
  }
  private get label(): string {
    return this.options.label ?? "dev";
  }
  private pair(profile: string) {
    let pair = this.#keys.get(profile);
    if (!pair) {
      pair = generateKeyPairSync("ed25519");
      this.#keys.set(profile, pair);
    }
    return pair;
  }
  keyId(profile: string): string {
    return `fk_${profile}_${this.label}`;
  }
  async sign(profile: string, bytes: Buffer): Promise<DesktopFeedSignature> {
    const limit = this.maxCanonicalBytes();
    if (limit !== null && bytes.length > limit) throw new SignerUnavailableError("message exceeds the signer limit");
    return { signature: edSign(null, bytes, this.pair(profile).privateKey).toString("base64url"), keyId: this.keyId(profile) };
  }
  async publicKey(profile: string): Promise<string> {
    return rawPublicKeyFromSpki(this.pair(profile).publicKey.export({ format: "der", type: "spki" }));
  }
  maxCanonicalBytes(): number | null {
    return this.options.maxCanonicalBytes ?? null;
  }
  hasProfile(): boolean {
    return true;
  }
}

/** KMS Sign accepts at most 4096 bytes of RAW message. */
export const AWS_KMS_MAX_RAW_MESSAGE_BYTES = 4096;

/** A customer KMS alias; `alias/aws/...` names AWS-managed keys, which cannot sign. */
export const KMS_ALIAS_PATTERN = /^alias\/(?!aws\/)[A-Za-z0-9/_-]{1,250}$/;

type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

export class AwsKmsDesktopFeedSigner implements DesktopFeedSigner {
  readonly kind = "awskms" as const;
  readonly #region: string;
  readonly #aliases: Map<string, string>;
  readonly #publicKeys = new Map<string, string>();
  constructor(
    private readonly options: {
      region: string;
      /** Profile id to its KMS alias, one key per profile. */
      keyAliases: Record<string, string>;
      label: string;
      credentials?: AwsCredentialProvider;
      /** Override for tests; default https://kms.<region>.amazonaws.com. */
      endpoint?: string;
      fetchImpl?: FetchLike;
      now?: () => Date;
    },
  ) {
    if (!/^[a-z0-9-]+$/.test(options.region)) throw new Error("awskms region is not a region");
    if (!KEY_LABEL_PATTERN.test(options.label)) throw new Error("awskms key label must match ^[a-z0-9]{1,16}$");
    for (const alias of Object.values(options.keyAliases)) {
      if (!KMS_ALIAS_PATTERN.test(alias)) throw new Error("awskms key aliases must look like alias/name");
    }
    this.#region = options.region;
    this.#aliases = new Map(Object.entries(options.keyAliases));
  }
  get region(): string {
    return this.#region;
  }
  keyId(profile: string): string {
    return `fk_${profile}_${this.options.label}`;
  }
  maxCanonicalBytes(): number {
    return AWS_KMS_MAX_RAW_MESSAGE_BYTES;
  }
  hasProfile(profile: string): boolean {
    return this.#aliases.has(profile);
  }
  private keyAlias(profile: string): string {
    const alias = this.#aliases.get(profile);
    if (!alias) throw new SignerUnavailableError("no KMS key alias is configured for this profile");
    return alias;
  }
  private async call(target: "Sign" | "GetPublicKey", payload: Record<string, unknown>): Promise<Record<string, unknown>> {
    const url = new URL(this.options.endpoint ?? `https://kms.${this.#region}.amazonaws.com/`);
    const body = JSON.stringify(payload);
    let response: Response;
    try {
      const credentials = await (this.options.credentials ?? defaultCredentials()).get();
      const headers = signV4({
        method: "POST",
        url,
        region: this.#region,
        service: "kms",
        body,
        credentials,
        now: this.options.now?.() ?? new Date(),
        contentSha256Header: false,
        extraHeaders: { "content-type": "application/x-amz-json-1.1", "x-amz-target": `TrentService.${target}` },
      });
      response = await (this.options.fetchImpl ?? fetch)(url.toString(), {
        method: "POST",
        headers,
        body,
        signal: AbortSignal.timeout(10_000),
      });
    } catch {
      throw new SignerUnavailableError(`KMS ${target} could not be reached`);
    }
    if (!response.ok) {
      // The KMS error type is safe to surface; it never carries key material.
      const type = await response.json().then((b: { __type?: string }) => b.__type ?? "", () => "");
      throw new SignerUnavailableError(`KMS ${target} failed: ${response.status}${type ? ` ${type.split("#").pop()}` : ""}`);
    }
    return await response.json() as Record<string, unknown>;
  }
  async sign(profile: string, bytes: Buffer): Promise<DesktopFeedSignature> {
    if (bytes.length > AWS_KMS_MAX_RAW_MESSAGE_BYTES) {
      throw new SignerUnavailableError("message exceeds the KMS RAW limit");
    }
    const result = await this.call("Sign", {
      KeyId: this.keyAlias(profile),
      Message: bytes.toString("base64"),
      MessageType: "RAW",
      SigningAlgorithm: "ED25519_SHA_512",
    });
    const signature = typeof result.Signature === "string" ? Buffer.from(result.Signature, "base64") : null;
    if (!signature || signature.length !== 64) throw new SignerUnavailableError("KMS returned no Ed25519 signature");
    return { signature: signature.toString("base64url"), keyId: this.keyId(profile) };
  }
  async publicKey(profile: string): Promise<string> {
    const cached = this.#publicKeys.get(profile);
    if (cached) return cached;
    const result = await this.call("GetPublicKey", { KeyId: this.keyAlias(profile) });
    if (result.KeySpec !== undefined && result.KeySpec !== "ECC_NIST_EDWARDS25519") {
      throw new SignerUnavailableError("KMS key is not ECC_NIST_EDWARDS25519");
    }
    if (typeof result.PublicKey !== "string") throw new SignerUnavailableError("KMS returned no public key");
    let publicKey: string;
    try {
      publicKey = rawPublicKeyFromSpki(Buffer.from(result.PublicKey, "base64"));
    } catch {
      throw new SignerUnavailableError("KMS public key is not Ed25519");
    }
    this.#publicKeys.set(profile, publicKey);
    return publicKey;
  }
}

let sharedCredentials: AwsCredentialProvider | null = null;
export function defaultCredentials(): AwsCredentialProvider {
  sharedCredentials ??= new DefaultAwsCredentialProvider();
  return sharedCredentials;
}
