/**
 * Operator log fields for a refused native chat context. The response stays
 * generic ("Invalid native chat context."); the log carries a fixed code per
 * verifier message, looked up by exact message, so a future verifier message
 * with a value in it can never reach the log (it logs `unclassified`).
 */

/** Which verifier refused: the route sets it by call site, not by error class. */
export type NativeContextStage = "claude_attestation" | "copilot_attestation" | "desktop_context";

// Every fixed message of claude-attestation.ts, copilot-attestation.ts and
// desktop-call.ts (a test keeps this in step with those files). The codes are
// the same in both editions; several messages share one code on purpose.
const PROOF_REASONS = new Map<string, string>([
  ["proof is not a compact JWS", "malformed_proof"],
  ["invalid proof", "malformed_proof"],
  ["malformed segment", "malformed_segment"],
  ["unexpected header", "unexpected_header"],
  ["unexpected payload", "unexpected_payload"],
  ["provider mismatch", "provider_mismatch"],
  ["tool use mismatch", "tool_use_mismatch"],
  ["tool mismatch", "tool_mismatch"],
  ["arguments mismatch", "arguments_mismatch"],
  ["owner mismatch", "owner_mismatch"],
  ["call mismatch", "call_mismatch"],
  ["lifetime out of range", "invalid_lifetime"],
  ["invalid lifetime", "invalid_lifetime"],
  ["expired", "expired"],
  ["issued in the future", "issued_in_future"],
  ["malformed signature", "malformed_signature"],
  ["invalid signature", "malformed_signature"],
  ["unknown key", "unknown_key"],
  ["bad signature", "bad_signature"],
  ["replayed tool use", "replayed_proof"],
  ["replayed proof", "replayed_proof"],
  ["batched proof", "batched_proof"],
]);
const CONTEXT_REASONS = new Map<string, string>([
  ["Unsupported desktop identity headers.", "obsolete_identity_headers"],
  ["Unsupported native chat context.", "unsupported_context"],
  ["Conflicting native chat context.", "conflicting_context"],
  ["Invalid native chat context.", "invalid_context"],
]);

/** The fixed code for a refusal at this stage; never the raw message. */
export function nativeContextRefusalReason(stage: NativeContextStage, error: unknown): string {
  const reasons = stage === "desktop_context" ? CONTEXT_REASONS : PROOF_REASONS;
  return error instanceof Error ? reasons.get(error.message) ?? "unclassified" : "unclassified";
}

/** The response's `x-correlation-id`, when one was set; null otherwise. */
export function responseCorrelationId(response: { getHeader(name: string): unknown }): string | null {
  const id = response.getHeader("x-correlation-id");
  return typeof id === "string" && id !== "" ? id : null;
}
