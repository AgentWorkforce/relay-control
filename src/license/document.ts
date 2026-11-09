import { createPublicKey, verify, type KeyObject } from "node:crypto";

/** Domain separation for licence signatures. */
export const LICENSE_SIGNATURE_PREFIX = "relaycontrol-license-v1\n";
const MAX_DOCUMENT_BYTES = 16 * 1024;
// DER SubjectPublicKeyInfo header for a raw 32-byte Ed25519 key (RFC 8410).
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RFC3339_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;

/** Verified claims. `features` holds the names as signed; the resolver decides what they grant. */
export type LicenseClaims = {
  licenseId: string;
  customer: string;
  issuedAt: string;
  expiresAt: string;
  features: string[];
  seats: number;
  notes: string | null;
};

export type LicenseVerification =
  | { ok: true; claims: LicenseClaims }
  | { ok: false; reason: string };

/** Base64 of a raw 32-byte Ed25519 public key, as a KeyObject. Throws when malformed. */
export function publicKeyFromBase64(value: string): KeyObject {
  const raw = Buffer.from(value.trim(), "base64");
  if (raw.length !== 32 || raw.toString("base64").replace(/=+$/, "") !== value.trim().replace(/=+$/, "")) {
    throw new Error("an Ed25519 public key must be base64 of exactly 32 bytes");
  }
  return createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

function base64url(segment: string): Buffer | null {
  if (!/^[A-Za-z0-9_-]+$/.test(segment)) return null;
  return Buffer.from(segment, "base64url");
}

function timestamp(value: unknown): number | null {
  if (typeof value !== "string" || !RFC3339_UTC.test(value)) return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

/**
 * `<base64url(payload JSON)>.<base64url(Ed25519 signature)>`, the signature
 * over the bytes `"relaycontrol-license-v1\n" + payload JSON`. The signature
 * is checked before any claim is read. Unknown claims are ignored.
 */
export function verifyLicenseDocument(document: string, publicKey: KeyObject | null): LicenseVerification {
  if (!publicKey) return { ok: false, reason: "no licence public key is compiled into this build" };
  const trimmed = document.trim();
  if (Buffer.byteLength(trimmed) > MAX_DOCUMENT_BYTES) return { ok: false, reason: "licence is too large" };
  const parts = trimmed.split(".");
  const payload = parts.length === 2 ? base64url(parts[0]!) : null;
  const signature = parts.length === 2 ? base64url(parts[1]!) : null;
  if (!payload || !signature || signature.length !== 64) {
    return { ok: false, reason: "licence is not <payload>.<signature> base64url" };
  }
  let signed = false;
  try {
    signed = verify(null, Buffer.concat([Buffer.from(LICENSE_SIGNATURE_PREFIX), payload]), publicKey, signature);
  } catch {
    signed = false;
  }
  if (!signed) return { ok: false, reason: "licence signature does not verify" };

  let claims: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(payload.toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
    claims = parsed as Record<string, unknown>;
  } catch {
    return { ok: false, reason: "licence payload is not a JSON object" };
  }
  const bad = (claim: string) => ({ ok: false as const, reason: `licence claim ${claim} is missing or malformed` });
  if (claims.v !== 1) return bad("v");
  if (typeof claims.license_id !== "string" || !UUID.test(claims.license_id)) return bad("license_id");
  if (typeof claims.customer !== "string" || !claims.customer.trim() || claims.customer.length > 200) {
    return bad("customer");
  }
  const issuedAt = timestamp(claims.issued_at);
  if (issuedAt === null) return bad("issued_at");
  const expiresAt = timestamp(claims.expires_at);
  if (expiresAt === null || expiresAt <= issuedAt) return bad("expires_at");
  const features = claims.features;
  if (!Array.isArray(features) || features.length > 64 || features.some((name) => typeof name !== "string")) {
    return bad("features");
  }
  if (typeof claims.seats !== "number" || !Number.isSafeInteger(claims.seats) || claims.seats < 1) {
    return bad("seats");
  }
  if (claims.notes !== undefined && claims.notes !== null && typeof claims.notes !== "string") return bad("notes");
  return {
    ok: true,
    claims: {
      licenseId: claims.license_id.toLowerCase(),
      customer: claims.customer.trim(),
      issuedAt: claims.issued_at as string,
      expiresAt: claims.expires_at as string,
      features: [...new Set(features as string[])],
      seats: claims.seats,
      notes: typeof claims.notes === "string" ? claims.notes : null,
    },
  };
}
