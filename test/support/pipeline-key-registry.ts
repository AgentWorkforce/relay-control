// COPY of relayhistory-pipeline PR #331, head f4919c6e,
// src/acquisition/key-registry.ts (parsePinnedKeys, ed25519PublicKey,
// rawPublicKey) with isIdentifier from src/acquisition/validation.ts inlined.
// Only the imports are adapted (this repo imports ".js" paths and has no
// validation.ts); the parsing logic is unchanged. The issuer tests parse the
// published keys with it, exactly as an operator's ACQUISITION_PINNED_KEYS is.
import { createPublicKey, type KeyObject } from "node:crypto";
import type { AcquisitionOwnerKind as OwnerKind, TrustedAcquisitionIssuer as IssuerKey } from "./pipeline-acquisition-assertion.js";
type IssuerRegistry = ReadonlyMap<string, IssuerKey>;

/** ingest_identifier: non-empty, <= 512 UTF-8 bytes, no control characters, no lone surrogates. */
export function isIdentifier(value: string): boolean {
  if (value.length === 0 || Buffer.byteLength(value, "utf8") > 512 || /[\u0000-\u001f\u007f]/.test(value)) return false;
  for (const ch of value) {
    const point = ch.codePointAt(0)!;
    if (point >= 0xd800 && point <= 0xdfff) return false;
  }
  return true;
}

/** DER prefix of an Ed25519 SPKI public key (RFC 8410). */
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export interface PinnedKeySpec {
  readonly issuerKeyId: string;
  readonly issuerClass: OwnerKind;
  readonly publicKeyBase64: string;
}

function strictBase64(value: string, bytes: number, name: string): Buffer {
  const decoded = Buffer.from(value, "base64");
  if (decoded.byteLength !== bytes || decoded.toString("base64") !== value) throw new Error(`96bulls: ${name} must be base64 of ${bytes} bytes`);
  return decoded;
}

export function ed25519PublicKey(raw: Uint8Array): KeyObject {
  return createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: "der", type: "spki" });
}

export function rawPublicKey(key: KeyObject): Buffer {
  const der = key.export({ format: "der", type: "spki" });
  return Buffer.from(der.subarray(SPKI_ED25519_PREFIX.byteLength));
}

/**
 * ACQUISITION_PINNED_KEYS: a JSON array of {issuerKeyId, issuerClass:"cloud", publicKeyBase64}.
 * Only cloud-class keys are accepted: there is no native issuer (relaycontrol is the sole
 * issuer), so a native-class entry refuses startup, as does any other class. Native Desktop
 * enrollment is a tracked gap (docs/acquisition-exchange.md, "Tracked gap: native receiver
 * contract"). Ids are unique, and so are public keys: one key pinned under two ids is refused.
 */
export function parsePinnedKeys(raw: string, name = "ACQUISITION_PINNED_KEYS"): IssuerRegistry {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`96bulls: ${name} must be a JSON array`);
  }
  if (!Array.isArray(parsed) || parsed.length === 0) throw new Error(`96bulls: ${name} must be a non-empty JSON array`);
  const registry = new Map<string, IssuerKey>();
  const publicKeys = new Set<string>();
  for (const entry of parsed) {
    if (entry === null || typeof entry !== "object" || Array.isArray(entry)) throw new Error(`96bulls: ${name} entries must be objects`);
    const keys = Object.keys(entry).sort().join(",");
    if (keys !== "issuerClass,issuerKeyId,publicKeyBase64") throw new Error(`96bulls: ${name} entries need exactly issuerKeyId, issuerClass, publicKeyBase64`);
    const { issuerKeyId, issuerClass, publicKeyBase64 } = entry as Record<string, unknown>;
    if (typeof issuerKeyId !== "string" || !isIdentifier(issuerKeyId)) throw new Error(`96bulls: ${name} has an invalid issuerKeyId`);
    if (issuerClass === "native")
      throw new Error(`96bulls: ${name} issuerClass must be cloud; native-class keys are refused (no native issuer; relaycontrol is the sole issuer)`);
    if (issuerClass !== "cloud") throw new Error(`96bulls: ${name} issuerClass must be cloud`);
    if (typeof publicKeyBase64 !== "string") throw new Error(`96bulls: ${name} publicKeyBase64 must be a string`);
    if (registry.has(issuerKeyId)) throw new Error(`96bulls: ${name} has a duplicate issuerKeyId`);
    const raw32 = strictBase64(publicKeyBase64, 32, name);
    const canonical = raw32.toString("hex");
    if (publicKeys.has(canonical)) throw new Error(`96bulls: ${name} pins the same public key under two issuerKeyIds`);
    publicKeys.add(canonical);
    registry.set(issuerKeyId, Object.freeze({ ownerKind: issuerClass, publicKey: ed25519PublicKey(raw32) }));
  }
  return registry;
}

/**
 * The subset of a registry with one issuer class (route groups accept only their own class).
 * parsePinnedKeys now admits cloud-class keys only, so for a parsed registry the "cloud" subset
 * is the whole registry; callers keep the filter as a defensive second check.
 */
export function registryOfClass(registry: IssuerRegistry, issuerClass: OwnerKind): IssuerRegistry {
  return new Map([...registry].filter(([, key]) => key.ownerKind === issuerClass));
}
