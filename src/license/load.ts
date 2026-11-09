import { readFileSync } from "node:fs";
import type { KeyObject } from "node:crypto";
import { publicKeyFromBase64, verifyLicenseDocument } from "./document.js";
import { LICENSE_PUBLIC_KEY } from "./public-key.js";
import { FEATURES, licenseStatus, type Feature, type LoadedLicense } from "./resolver.js";

type Env = Record<string, string | undefined>;
type Log = (message: string, fields?: Record<string, unknown>) => void;

const defaultLog: Log = (message, fields) => console.log(`[selfhost-api] license: ${message}`, fields ?? {});

/**
 * SELFHOST_FEATURES: comma list of flows|relayfile|chief. Unset or empty
 * selects nothing; an unknown name is a startup configuration error.
 */
export function loadSelectedFeatures(env: Env): Record<Feature, boolean> {
  const selected = Object.fromEntries(FEATURES.map((f) => [f, false])) as Record<Feature, boolean>;
  for (const name of (env.SELFHOST_FEATURES ?? "").split(",").map((v) => v.trim().toLowerCase()).filter(Boolean)) {
    if (!(FEATURES as string[]).includes(name)) {
      throw new Error(`SELFHOST_FEATURES names unknown feature "${name}" (expected ${FEATURES.join(", ")})`);
    }
    selected[name as Feature] = true;
  }
  return selected;
}

/**
 * The trusted public key: the compiled constant, or
 * SELFHOST_LICENSE_PUBLIC_KEY_OVERRIDE (base64 raw 32 bytes) when, and only
 * when, process.env.NODE_ENV is "test". Nothing else supplies a key.
 */
function trustedPublicKey(env: Env, log: Log): KeyObject | null {
  const override = env.SELFHOST_LICENSE_PUBLIC_KEY_OVERRIDE?.trim();
  if (override) {
    if (process.env.NODE_ENV === "test") {
      try {
        return publicKeyFromBase64(override);
      } catch {
        log("SELFHOST_LICENSE_PUBLIC_KEY_OVERRIDE is not a base64 Ed25519 key; ignored");
        return null;
      }
    }
    log("SELFHOST_LICENSE_PUBLIC_KEY_OVERRIDE ignored (honoured only when NODE_ENV=test)");
  }
  return LICENSE_PUBLIC_KEY ? publicKeyFromBase64(LICENSE_PUBLIC_KEY) : null;
}

/**
 * Loads SELFHOST_FEATURES and SELFHOST_LICENSE / SELFHOST_LICENSE_FILE once
 * at startup. Only configuration mistakes throw (both licence sources set, an
 * unknown feature name); a bad, unreadable or expired licence is logged once
 * and the installation runs as core.
 */
export function loadLicense(env: Env = process.env, options: { log?: Log; now?: Date } = {}): LoadedLicense {
  const log = options.log ?? defaultLog;
  const selected = loadSelectedFeatures(env);
  const inline = env.SELFHOST_LICENSE?.trim();
  const file = env.SELFHOST_LICENSE_FILE?.trim();
  if (inline && file) throw new Error("SELFHOST_LICENSE and SELFHOST_LICENSE_FILE are mutually exclusive");

  const key = trustedPublicKey(env, log);
  let loaded: LoadedLicense = { supplied: false, claims: null, selected };
  let reason: string | null = null;
  if (inline || file) {
    let document: string | null = inline ?? null;
    if (!document) {
      try {
        document = readFileSync(file!, "utf8");
      } catch {
        reason = "SELFHOST_LICENSE_FILE could not be read";
      }
    }
    const verified = document === null ? null : verifyLicenseDocument(document, key);
    if (verified && !verified.ok) reason = verified.reason;
    loaded = { supplied: true, claims: verified?.ok ? verified.claims : null, selected };
  }
  const status = licenseStatus(loaded, options.now ?? new Date());
  log(status === "valid" || status === "absent" ? "loaded" : "not in effect; running as core", {
    status,
    ...(reason ? { reason } : {}),
    ...(loaded.claims ? { licenseId: loaded.claims.licenseId, expiresAt: loaded.claims.expiresAt } : {}),
    selected: FEATURES.filter((f) => selected[f]),
  });
  return loaded;
}
