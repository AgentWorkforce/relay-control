import type { LicenseClaims } from "./document.js";

/**
 * The feature class table. Paid features need a valid licence that names
 * them; optional core features (Chief) only need the operator to select
 * them. This is the only place a feature's class is decided.
 */
const FEATURE_CLASS = {
  flows: "paid",
  relayfile: "paid",
  chief: "optional",
} as const;

export type Feature = keyof typeof FEATURE_CLASS;
export type PaidFeature = { [F in Feature]: (typeof FEATURE_CLASS)[F] extends "paid" ? F : never }[Feature];
export const FEATURES = Object.keys(FEATURE_CLASS) as Feature[];
export const PAID_FEATURES = FEATURES.filter((f): f is PaidFeature => FEATURE_CLASS[f] === "paid");

export type LicenseStatus = "absent" | "invalid" | "expired" | "valid";

/** What startup loaded: the verified document (if any) and the operator's selection. */
export type LoadedLicense = {
  /** A licence was supplied (inline or file), whether or not it verified. */
  supplied: boolean;
  /** Claims of a document whose signature and claims verified; null otherwise. */
  claims: LicenseClaims | null;
  selected: Record<Feature, boolean>;
};

export type LicenseResolution = {
  status: LicenseStatus;
  /** Verified claims for a valid or expired licence; null for absent/invalid. */
  claims: LicenseClaims | null;
  selected: Record<Feature, boolean>;
  entitled: Record<PaidFeature, boolean>;
  capabilities: Record<Feature, boolean>;
};

export const CORE_LICENSE: LoadedLicense = {
  supplied: false,
  claims: null,
  selected: { flows: false, relayfile: false, chief: false },
};

export function licenseStatus(loaded: LoadedLicense, now: Date): LicenseStatus {
  if (!loaded.supplied) return "absent";
  if (!loaded.claims) return "invalid";
  return Date.parse(loaded.claims.expiresAt) <= now.getTime() ? "expired" : "valid";
}

/** capabilities[f] = selected[f] AND entitled[f] for paid f; selected[f] for optional f. */
export function resolveLicense(loaded: LoadedLicense, now: Date): LicenseResolution {
  const status = licenseStatus(loaded, now);
  const named = new Set(status === "valid" ? loaded.claims!.features : []);
  const entitled = Object.fromEntries(PAID_FEATURES.map((f) => [f, named.has(f)])) as Record<PaidFeature, boolean>;
  const capabilities = Object.fromEntries(FEATURES.map((f) => [
    f,
    loaded.selected[f] && (FEATURE_CLASS[f] !== "paid" || entitled[f as PaidFeature]),
  ])) as Record<Feature, boolean>;
  return {
    status,
    claims: status === "valid" || status === "expired" ? loaded.claims : null,
    selected: { ...loaded.selected },
    entitled,
    capabilities,
  };
}

const DISPLAY: Record<Feature, string> = { flows: "Flows", relayfile: "Relayfile", chief: "Chief" };

/** A 403 refusal for a feature route: `{ error, message, feature }`. */
export class FeatureRefusedError extends Error {
  readonly status = 403;
  constructor(
    readonly code: "feature_not_enabled" | "feature_not_licensed",
    readonly feature: Feature,
    message: string,
  ) {
    super(message);
  }
}

/**
 * Null when the feature may serve; otherwise the refusal. Not selected ->
 * feature_not_enabled; a selected paid feature without entitlement ->
 * feature_not_licensed. Optional features never answer not_licensed.
 */
export function featureRefusal(resolution: LicenseResolution, feature: Feature): FeatureRefusedError | null {
  if (resolution.capabilities[feature]) return null;
  if (!resolution.selected[feature]) {
    return new FeatureRefusedError(
      "feature_not_enabled",
      feature,
      `${DISPLAY[feature]} is not enabled on this installation.`,
    );
  }
  return new FeatureRefusedError(
    "feature_not_licensed",
    feature,
    `${DISPLAY[feature]} is not licensed on this installation.`,
  );
}

/** Throws the feature refusal unless `feature` is a capability at `now`. */
export function requireCapability(loaded: LoadedLicense, feature: Feature, now: Date = new Date()): void {
  const refusal = featureRefusal(resolveLicense(loaded, now), feature);
  if (refusal) throw refusal;
}

/**
 * Wraps a credential verifier owned by `feature` (the Flows worker hook the
 * admin runtime routes accept) so a verified credential is refused with the
 * feature code while the feature is not a capability. Unknown credentials
 * still fall through as null (401).
 */
export function gateCredentialVerifier<A extends unknown[], T>(
  verifier: (...args: A) => Promise<T | null>,
  loaded: LoadedLicense,
  feature: Feature,
): (...args: A) => Promise<T | null> {
  return async (...args) => {
    const verified = await verifier(...args);
    if (verified) requireCapability(loaded, feature);
    return verified;
  };
}
