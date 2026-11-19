/**
 * Operator log fields for a refused native chat context. The response stays
 * generic ("Invalid native chat context."); the log carries a fixed code per
 * verifier message, looked up by exact message, so a future verifier message
 * with a value in it can never reach the log (it logs `unclassified`).
 */

/** Which verifier refused: the route sets it by call site, not by error class. */
export type NativeContextStage = "claude_attestation" | "copilot_attestation" | "desktop_context";

// Every fixed message of claude-attestation.ts, copilot-attestation.ts and
// desktop-call.ts (a test keeps this in step with those files).
const REASONS = new Map<string, string>([
  // Claude Code / Cursor proofs.
  ["malformed segment", "malformed_segment"],
  ["proof is not a compact JWS", "proof_not_compact_jws"],
  ["unexpected header", "unexpected_header"],
  ["unexpected payload", "unexpected_payload"],
  ["provider mismatch", "provider_mismatch"],
  ["tool use mismatch", "tool_use_mismatch"],
  ["tool mismatch", "tool_mismatch"],
  ["arguments mismatch", "arguments_mismatch"],
  ["lifetime out of range", "lifetime_out_of_range"],
  ["expired", "expired"],
  ["issued in the future", "issued_in_the_future"],
  ["malformed signature", "malformed_signature"],
  ["unknown key", "unknown_key"],
  ["bad signature", "bad_signature"],
  ["replayed tool use", "replayed_tool_use"],
  ["batched proof", "batched_proof"],
  // Copilot proofs (shared messages above).
  ["invalid proof", "invalid_proof"],
  ["owner mismatch", "owner_mismatch"],
  ["call mismatch", "call_mismatch"],
  ["invalid lifetime", "invalid_lifetime"],
  ["invalid signature", "invalid_signature"],
  ["replayed proof", "replayed_proof"],
  // Desktop call context.
  ["Unsupported desktop identity headers.", "unsupported_identity_headers"],
  ["Unsupported native chat context.", "unsupported_context"],
  ["Conflicting native chat context.", "conflicting_context"],
  ["Invalid native chat context.", "invalid_context"],
]);

/** The fixed code for a refusal; never the raw message. */
export function nativeContextRefusalReason(error: unknown): string {
  return error instanceof Error ? REASONS.get(error.message) ?? "unclassified" : "unclassified";
}

/** The response's `x-correlation-id`, when one was set; null otherwise. */
export function responseCorrelationId(response: { getHeader(name: string): unknown }): string | null {
  const id = response.getHeader("x-correlation-id");
  return typeof id === "string" && id !== "" ? id : null;
}
