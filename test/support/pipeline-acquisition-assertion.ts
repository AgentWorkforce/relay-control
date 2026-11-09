// VERBATIM COPY, do not edit. Source: relayhistory-pipeline PR #331, head
// f4919c6e, path src/session-ingest/acquisition-assertion.ts (the verifier the
// pipeline's ops routes run). The acquisition issuer tests verify every
// envelope relaycontrol issues with this exact code. Refresh it when the
// pipeline codec changes; a diff here is a wire contract change.
/** Canonical, independently authenticated acquisition control assertions (contract #314 §3). */
import {createHash, timingSafeEqual, verify, type KeyObject} from "node:crypto";

export type AcquisitionOperation = "install" | "revoke" | "rebind";
export type AcquisitionOwnerKind = "cloud" | "native";
export interface AcquisitionScope {
  orgId: string;
  workspaceId: string;
  source: string;
  sessionId: string;
}
export interface TrustedAcquisitionIssuer {
  ownerKind: AcquisitionOwnerKind;
  publicKey: KeyObject;
}
export interface VerifiedAcquisitionAssertion {
  kind: AcquisitionOperation;
  /** Detached, frozen SQL parameters; the signature is never passed through to SQL. */
  payload: Readonly<Record<string, string>>;
}
export class AcquisitionAssertionError extends Error {
  constructor(readonly code: "invalid_request" | "not_authorized") {
    super("acquisition: " + code);
  }
}

const SEPARATOR = "\u001f";
const MAX_BIGINT = 9223372036854775807n;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HASH = /^[0-9a-f]{64}$/;
const COMMON = ["operationUuid", "orgId", "workspaceId", "source", "sessionId", "revision"] as const;
const FIELDS: Record<AcquisitionOperation, readonly string[]> = {
  install: [...COMMON, "expectedRevision", "expectedOwnerEpoch", "expectedPredecessorGrantId",
    "ownerKind", "ownerUserId", "ownerOriginId", "bindingUuid", "installationId", "grantSha256", "expiresAt", "issuerKeyId"],
  revoke: [...COMMON, "targetGrantId", "targetOwnerEpoch", "targetOwnerKind", "targetBindingUuid",
    "targetInstallationId", "issuerKeyId"],
  rebind: [...COMMON, "targetGrantId", "targetOwnerEpoch", "ownerUserId", "installationId",
    "oldOriginId", "newOriginId", "issuerKeyId"],
};

function invalid(): never { throw new AcquisitionAssertionError("invalid_request"); }
function unauthorized(): never { throw new AcquisitionAssertionError("not_authorized"); }
function hash(bytes: Uint8Array | string): string { return createHash("sha256").update(bytes).digest("hex"); }

/** Snapshot a JSON object and refuse unknown/missing keys instead of silently dropping them. */
function exactObject(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
  const result = Object.fromEntries(Object.entries(value));
  if (Object.keys(result).sort().join(",") !== [...keys].sort().join(",")) invalid();
  return result;
}

/** Match ingest_identifier's UTF-8 boundary without trimming, case folding or lossy surrogates. */
function identifier(value: unknown, empty = false): string {
  if (typeof value !== "string" || (!empty && value === "") || Buffer.byteLength(value, "utf8") > 512 ||
      /[\u0000-\u001f\u007f]/.test(value)) invalid();
  for (const character of value) {
    const point = character.codePointAt(0)!;
    if (point >= 0xd800 && point <= 0xdfff) invalid();
  }
  return value;
}
function uuid(value: unknown, nullable = false): string {
  if (nullable && value === "") return "";
  if (typeof value !== "string" || value.length !== 36 || !UUID.test(value)) invalid();
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

/** Validate the unsigned assertion's exact wire spelling before any cryptographic operation. */
export function acquisitionPayload(kind: AcquisitionOperation, value: unknown): Readonly<Record<string, string>> {
  if (kind !== "install" && kind !== "revoke" && kind !== "rebind") invalid();
  const input = exactObject(value, FIELDS[kind]);
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

/** Encode A without its evidence, signature or request digest, avoiding a signature fixed point. */
export function acquisitionAssertionBytes(kind: AcquisitionOperation, value: unknown): Buffer {
  const payload = acquisitionPayload(kind, value);
  return Buffer.from(["relayhistory-acquisition-assertion-" + kind + "-v1",
    ...FIELDS[kind].map(key => payload[key] ?? "")].join(SEPARATOR), "utf8");
}

/** Compute the completed signed-envelope and SQL-request hashes in contract order. */
export function acquisitionAssertionDigests(assertion: Uint8Array, signature: Uint8Array): {evidenceSha256: string; requestSha256: string} {
  if (signature.byteLength !== 64) invalid();
  const evidenceSha256 = hash(Buffer.concat([assertion, Buffer.from(SEPARATOR), signature]));
  return {evidenceSha256, requestSha256: hash(["relayhistory-acquisition-request-v1", hash(assertion), evidenceSha256].join(SEPARATOR))};
}

/** Hash one session-scoped grant secret; no error or return value reveals G. */
export function acquisitionGrantDigest(scope: AcquisitionScope, grantId: string, grant: string): string {
  const parts = [identifier(scope.orgId), identifier(scope.workspaceId, true), identifier(scope.source), identifier(scope.sessionId)];
  if (typeof grant !== "string" || grant.length !== 68 || !/^rhg_[0-9a-f]{64}$/.test(grant)) invalid();
  return hash(["relayhistory-acquisition-grant-v1", ...parts, uuid(grantId), grant].join(SEPARATOR));
}

/** Verify only server-pinned issuers and a server-derived scope policy before producing SQL parameters. */
export function verifyAcquisitionAssertion(
  kind: AcquisitionOperation,
  value: unknown,
  issuers: ReadonlyMap<string, TrustedAcquisitionIssuer>,
  authorizeScope: (scope: AcquisitionScope, issuerKeyId: string) => boolean,
): VerifiedAcquisitionAssertion {
  const envelope = exactObject(value, ["payload", "signature"]);
  if (kind !== "install" && kind !== "revoke" && kind !== "rebind") invalid();
  const signed = exactObject(envelope.payload, [...FIELDS[kind], "evidenceSha256", "requestSha256"]);
  const {evidenceSha256, requestSha256, ...unsigned} = signed;
  const payload = acquisitionPayload(kind, unsigned);
  const issuerKeyId = payload.issuerKeyId!;
  const issuer = issuers.get(issuerKeyId);
  const declaredKind = kind === "install" ? payload.ownerKind : kind === "revoke" ? payload.targetOwnerKind : "native";
  if (!issuer || issuer.ownerKind !== declaredKind || issuer.publicKey.type !== "public" ||
      issuer.publicKey.asymmetricKeyType !== "ed25519") unauthorized();
  if (typeof envelope.signature !== "string" || envelope.signature.length !== 86 || !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature)) unauthorized();
  const signature = Buffer.from(envelope.signature, "base64url");
  if (signature.byteLength !== 64 || signature.toString("base64url") !== envelope.signature) unauthorized();
  const assertion = acquisitionAssertionBytes(kind, payload);
  if (!verify(null, assertion, issuer.publicKey, signature)) unauthorized();
  const expected = acquisitionAssertionDigests(assertion, signature);
  if (!timingSafeEqual(Buffer.from(digest(evidenceSha256), "hex"), Buffer.from(expected.evidenceSha256, "hex")) ||
      !timingSafeEqual(Buffer.from(digest(requestSha256), "hex"), Buffer.from(expected.requestSha256, "hex"))) unauthorized();
  try {
    if (authorizeScope({orgId: payload.orgId!, workspaceId: payload.workspaceId!, source: payload.source!, sessionId: payload.sessionId!}, issuerKeyId) !== true) unauthorized();
  } catch { unauthorized(); }
  return Object.freeze({kind, payload: Object.freeze({...payload, ...expected})});
}
