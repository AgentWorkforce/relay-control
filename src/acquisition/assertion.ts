import { createHash, createPublicKey, sign, type KeyObject } from "node:crypto";

/**
 * Issuing side of the acquisition control assertion codec (contract #314 §3).
 *
 * Ported from relayhistory-pipeline PR #331 (head f4919c6e),
 * src/session-ingest/acquisition-assertion.ts, which stays the verifier.
 * The wire spelling MUST stay identical to it: the per-operation field lists
 * and their order, the U+001F separator, the
 * "relayhistory-acquisition-assertion-<kind>-v1" prefix, the evidence and
 * request digests and the validation rules. test/acquisition-issuer.test.ts
 * verifies every issued envelope with a verbatim copy of the pipeline
 * verifier (test/support/pipeline-acquisition-assertion.ts).
 *
 * relaycontrol is the only issuer; the pipeline only verifies.
 */

export type AcquisitionOperation = "install" | "revoke" | "rebind";
export type AcquisitionOwnerKind = "cloud" | "native";
export type AcquisitionPayload = Readonly<Record<string, string>>;
export type AcquisitionEnvelope = { payload: Record<string, string>; signature: string };

export class AcquisitionAssertionError extends Error {
  constructor(readonly code: "invalid_request") {
    super("acquisition: " + code);
  }
}

const SEPARATOR = "\u001f";
const MAX_BIGINT = 9223372036854775807n;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HASH = /^[0-9a-f]{64}$/;
const COMMON = ["operationUuid", "orgId", "workspaceId", "source", "sessionId", "revision"] as const;
export const ACQUISITION_FIELDS: Readonly<Record<AcquisitionOperation, readonly string[]>> = {
  install: [...COMMON, "expectedRevision", "expectedOwnerEpoch", "expectedPredecessorGrantId",
    "ownerKind", "ownerUserId", "ownerOriginId", "bindingUuid", "installationId", "grantSha256", "expiresAt", "issuerKeyId"],
  revoke: [...COMMON, "targetGrantId", "targetOwnerEpoch", "targetOwnerKind", "targetBindingUuid",
    "targetInstallationId", "issuerKeyId"],
  rebind: [...COMMON, "targetGrantId", "targetOwnerEpoch", "ownerUserId", "installationId",
    "oldOriginId", "newOriginId", "issuerKeyId"],
};

function invalid(): never { throw new AcquisitionAssertionError("invalid_request"); }
function hash(bytes: Uint8Array | string): string { return createHash("sha256").update(bytes).digest("hex"); }

/** Snapshot a JSON object and refuse unknown/missing keys instead of silently dropping them. */
function exactObject(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
  const result = Object.fromEntries(Object.entries(value));
  if (Object.keys(result).sort().join(",") !== [...keys].sort().join(",")) invalid();
  return result;
}

/**
 * The pipeline's ingest_identifier rule: non-empty (unless `empty`), at most
 * 512 UTF-8 bytes, no control characters, no lone surrogates. No trimming or
 * case folding.
 */
export function isAcquisitionIdentifier(value: unknown, empty = false): value is string {
  if (typeof value !== "string" || (!empty && value === "") || Buffer.byteLength(value, "utf8") > 512 ||
      /[\u0000-\u001f\u007f]/.test(value)) return false;
  for (const character of value) {
    const point = character.codePointAt(0)!;
    if (point >= 0xd800 && point <= 0xdfff) return false;
  }
  return true;
}
function identifier(value: unknown, empty = false): string {
  if (!isAcquisitionIdentifier(value, empty)) invalid();
  return value;
}
export function isAcquisitionUuid(value: unknown): value is string {
  return typeof value === "string" && value.length === 36 && UUID.test(value);
}
function uuid(value: unknown, nullable = false): string {
  if (nullable && value === "") return "";
  if (!isAcquisitionUuid(value)) invalid();
  return value;
}
function decimal(value: unknown, zero = false): string {
  if (typeof value !== "string" || value !== value.trim() || !(zero ? /^(0|[1-9][0-9]{0,18})$/ : /^[1-9][0-9]{0,18}$/).test(value) ||
      BigInt(value) > MAX_BIGINT) invalid();
  return value;
}
function digest(value: unknown): string {
  if (typeof value !== "string" || value.length !== 64 || !HASH.test(value)) invalid();
  return value;
}
function ownerKind(value: unknown): AcquisitionOwnerKind {
  if (value !== "cloud" && value !== "native") invalid();
  return value;
}
function expiry(value: unknown): string {
  if (value === "") return "";
  if (typeof value !== "string" || !/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/.test(value) ||
      value.startsWith("0000-") || !Number.isFinite(Date.parse(value)) ||
      new Date(value).toISOString().replace(".000Z", "Z") !== value) invalid();
  return value;
}

/** Validate the unsigned assertion's exact wire spelling (the pipeline's acquisitionPayload). */
export function acquisitionPayload(kind: AcquisitionOperation, value: unknown): AcquisitionPayload {
  if (kind !== "install" && kind !== "revoke" && kind !== "rebind") invalid();
  const input = exactObject(value, ACQUISITION_FIELDS[kind]);
  const payload: Record<string, string> = {
    operationUuid: uuid(input.operationUuid), orgId: identifier(input.orgId),
    workspaceId: identifier(input.workspaceId, true), source: identifier(input.source),
    sessionId: identifier(input.sessionId), revision: decimal(input.revision),
    issuerKeyId: identifier(input.issuerKeyId),
  };
  if (kind === "install") {
    Object.assign(payload, {
      expectedRevision: decimal(input.expectedRevision, true), expectedOwnerEpoch: decimal(input.expectedOwnerEpoch, true),
      expectedPredecessorGrantId: uuid(input.expectedPredecessorGrantId, true), ownerKind: ownerKind(input.ownerKind),
      ownerUserId: identifier(input.ownerUserId), ownerOriginId: identifier(input.ownerOriginId),
      bindingUuid: uuid(input.bindingUuid, true), installationId: uuid(input.installationId, true),
      grantSha256: digest(input.grantSha256), expiresAt: expiry(input.expiresAt),
    });
    if ((payload.ownerKind === "cloud" && (!payload.bindingUuid || payload.installationId !== "")) ||
        (payload.ownerKind === "native" && (!payload.installationId || payload.bindingUuid !== ""))) invalid();
  } else if (kind === "revoke") {
    Object.assign(payload, {
      targetGrantId: uuid(input.targetGrantId), targetOwnerEpoch: decimal(input.targetOwnerEpoch),
      targetOwnerKind: ownerKind(input.targetOwnerKind), targetBindingUuid: uuid(input.targetBindingUuid, true),
      targetInstallationId: uuid(input.targetInstallationId, true),
    });
    if ((payload.targetOwnerKind === "cloud" && (!payload.targetBindingUuid || payload.targetInstallationId !== "")) ||
        (payload.targetOwnerKind === "native" && (!payload.targetInstallationId || payload.targetBindingUuid !== ""))) invalid();
  } else {
    Object.assign(payload, {
      targetGrantId: uuid(input.targetGrantId), targetOwnerEpoch: decimal(input.targetOwnerEpoch),
      ownerUserId: identifier(input.ownerUserId), installationId: uuid(input.installationId),
      oldOriginId: identifier(input.oldOriginId), newOriginId: identifier(input.newOriginId),
    });
  }
  return Object.freeze(payload);
}

/** The signed bytes: prefix and fields in contract order, joined by U+001F. */
export function acquisitionAssertionBytes(kind: AcquisitionOperation, value: unknown): Buffer {
  const payload = acquisitionPayload(kind, value);
  return Buffer.from(["relayhistory-acquisition-assertion-" + kind + "-v1",
    ...ACQUISITION_FIELDS[kind].map((key) => payload[key] ?? "")].join(SEPARATOR), "utf8");
}

/** The completed signed-envelope and SQL-request hashes in contract order. */
export function acquisitionAssertionDigests(
  assertion: Uint8Array,
  signature: Uint8Array,
): { evidenceSha256: string; requestSha256: string } {
  if (signature.byteLength !== 64) invalid();
  const evidenceSha256 = hash(Buffer.concat([assertion, Buffer.from(SEPARATOR), signature]));
  return {
    evidenceSha256,
    requestSha256: hash(["relayhistory-acquisition-request-v1", hash(assertion), evidenceSha256].join(SEPARATOR)),
  };
}

/**
 * Sign one validated unsigned assertion with the issuer's Ed25519 key:
 * `{payload: {fields..., evidenceSha256, requestSha256}, signature}` with the
 * raw 64-byte signature as unpadded base64url (86 characters), the shape the
 * pipeline's verifyAcquisitionAssertion takes.
 */
export function signAcquisitionAssertion(
  kind: AcquisitionOperation,
  unsigned: unknown,
  privateKey: KeyObject,
): AcquisitionEnvelope {
  const payload = acquisitionPayload(kind, unsigned);
  const assertion = acquisitionAssertionBytes(kind, payload);
  const signature = sign(null, assertion, privateKey);
  return {
    payload: { ...payload, ...acquisitionAssertionDigests(assertion, signature) },
    signature: signature.toString("base64url"),
  };
}

/** DER prefix of an Ed25519 SPKI public key (RFC 8410). */
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** The raw 32-byte Ed25519 public key, as the pipeline's ACQUISITION_PINNED_KEYS pins it. */
export function rawEd25519PublicKey(key: KeyObject): Buffer {
  const der = createPublicKey(key).export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(SPKI_ED25519_PREFIX.byteLength));
}

/** Strict base64 of exactly 32 bytes (the pipeline's strictBase64), or null. */
export function strictRawPublicKey(value: unknown): Buffer | null {
  if (typeof value !== "string") return null;
  const decoded = Buffer.from(value, "base64");
  if (decoded.byteLength !== 32 || decoded.toString("base64") !== value) return null;
  try {
    createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, decoded]), format: "der", type: "spki" });
  } catch {
    return null;
  }
  return decoded;
}
