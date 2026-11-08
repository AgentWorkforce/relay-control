/**
 * Entitlement for operator-control writes (capture policy PUT/DELETE; reads
 * are never gated so Desktop never fails closed).
 *
 * SELFHOST_OPERATOR_CONTROLS:
 * - `always` (default): entitled.
 * - `licence`: requires the licence feature `operator_controls`.
 * - `off`: not entitled.
 */
export type OperatorControlsMode = "always" | "licence" | "off";

export function operatorControlsMode(env: NodeJS.ProcessEnv = process.env): OperatorControlsMode {
  const raw = env.SELFHOST_OPERATOR_CONTROLS?.trim().toLowerCase();
  if (!raw || raw === "always") return "always";
  if (raw === "licence" || raw === "off") return raw;
  // An unrecognised value fails closed for writes.
  return "off";
}

export function operatorControlsEntitled(env: NodeJS.ProcessEnv = process.env): boolean {
  const mode = operatorControlsMode(env);
  if (mode === "always") return true;
  if (mode === "licence") {
    // TODO(feature-switch PR #37): evaluate the licence feature
    // `operator_controls` once the feature switch lands on main. Until then a
    // licence-gated installation is not entitled.
    return false;
  }
  return false;
}
