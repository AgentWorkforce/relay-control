/**
 * Optional components an installation serves, chosen by the operator with
 * SELFHOST_FEATURES (comma list; unset or empty selects nothing). Read once
 * at startup. Everything else is core and always on.
 */
export const FEATURES = ["flows", "relayfile", "chief"] as const;
export type Feature = (typeof FEATURES)[number];
export type SelectedFeatures = Record<Feature, boolean>;

export const NO_FEATURES: SelectedFeatures = { flows: false, relayfile: false, chief: false };

/** An unknown name is a startup configuration error. */
export function loadSelectedFeatures(env: Record<string, string | undefined> = process.env): SelectedFeatures {
  const selected = { ...NO_FEATURES };
  for (const name of (env.SELFHOST_FEATURES ?? "").split(",").map((v) => v.trim().toLowerCase()).filter(Boolean)) {
    if (!(FEATURES as readonly string[]).includes(name)) {
      throw new Error(`SELFHOST_FEATURES names unknown feature "${name}" (expected ${FEATURES.join(", ")})`);
    }
    selected[name as Feature] = true;
  }
  return selected;
}

const DISPLAY: Record<Feature, string> = { flows: "Flows", relayfile: "Relayfile", chief: "Chief" };

/** A 403 refusal for a feature route: `{ error, message, feature }`. */
export class FeatureRefusedError extends Error {
  readonly status = 403;
  readonly code = "feature_not_enabled";
  constructor(readonly feature: Feature) {
    super(`${DISPLAY[feature]} is not enabled on this installation.`);
  }
}

/** Throws the feature refusal unless `feature` is selected. */
export function requireSelected(selected: SelectedFeatures, feature: Feature): void {
  if (!selected[feature]) throw new FeatureRefusedError(feature);
}

/**
 * Wraps a credential verifier owned by `feature` (the Flows worker hook the
 * admin runtime routes accept) so a verified credential is refused with the
 * feature code while the feature is off. Unknown credentials still fall
 * through as null (401).
 */
export function gateCredentialVerifier<A extends unknown[], T>(
  verifier: (...args: A) => Promise<T | null>,
  selected: SelectedFeatures,
  feature: Feature,
): (...args: A) => Promise<T | null> {
  return async (...args) => {
    const verified = await verifier(...args);
    if (verified) requireSelected(selected, feature);
    return verified;
  };
}
