import { generateKeyPairSync, randomUUID, sign, type KeyObject } from "node:crypto";
import { LICENSE_SIGNATURE_PREFIX } from "../../src/license/document.js";
import { loadLicense } from "../../src/license/load.js";
import type { LoadedLicense } from "../../src/license/resolver.js";

// The override key is honoured only under NODE_ENV=test (node:test runs each file in its own process).
process.env.NODE_ENV = "test";

export type TestKeys = { privateKey: KeyObject; publicKeyBase64: string };

export function testKeys(): TestKeys {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  return { privateKey, publicKeyBase64: spki.subarray(spki.length - 32).toString("base64") };
}

export function licenseClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    license_id: randomUUID(),
    customer: "Acme Corp",
    issued_at: "2026-01-01T00:00:00Z",
    expires_at: "2099-01-01T00:00:00Z",
    features: ["flows", "relayfile"],
    seats: 25,
    ...overrides,
  };
}

/** `<base64url(payload)>.<base64url(Ed25519 over prefix + payload)>`. */
export function signLicense(privateKey: KeyObject, claims: Record<string, unknown>): string {
  const payload = Buffer.from(JSON.stringify(claims));
  const signature = sign(null, Buffer.concat([Buffer.from(LICENSE_SIGNATURE_PREFIX), payload]), privateKey);
  return `${payload.toString("base64url")}.${signature.toString("base64url")}`;
}

const quiet = () => {};

/** A loaded licence for app tests: signed with fresh keys, selection from `features`. */
export function testLicense(
  options: { features?: string; claims?: Record<string, unknown> | null } = {},
): LoadedLicense {
  const keys = testKeys();
  return loadLicense({
    SELFHOST_FEATURES: options.features ?? "flows,relayfile,chief",
    SELFHOST_LICENSE_PUBLIC_KEY_OVERRIDE: keys.publicKeyBase64,
    ...(options.claims === null ? {} : { SELFHOST_LICENSE: signLicense(keys.privateKey, licenseClaims(options.claims)) }),
  }, { log: quiet });
}
