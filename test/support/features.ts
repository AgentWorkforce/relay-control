import { loadSelectedFeatures, type SelectedFeatures } from "../../src/features.js";

/** Selection as SELFHOST_FEATURES would give it; every feature by default. */
export function testFeatures(list = "flows,relayfile,chief"): SelectedFeatures {
  return loadSelectedFeatures({ SELFHOST_FEATURES: list });
}
