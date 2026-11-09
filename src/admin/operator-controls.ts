/**
 * Switch for operator-control writes (capture policy PUT/DELETE; reads are
 * never gated so Desktop never fails closed).
 *
 * SELFHOST_OPERATOR_CONTROLS: `always` (default) or `off`. An unrecognised
 * value fails closed for writes.
 */
export type OperatorControlsMode = "always" | "off";

export function operatorControlsMode(env: NodeJS.ProcessEnv = process.env): OperatorControlsMode {
  const raw = env.SELFHOST_OPERATOR_CONTROLS?.trim().toLowerCase();
  return !raw || raw === "always" ? "always" : "off";
}

export function operatorControlsEntitled(env: NodeJS.ProcessEnv = process.env): boolean {
  return operatorControlsMode(env) === "always";
}
