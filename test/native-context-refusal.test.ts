import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { nativeContextRefusalReason, responseCorrelationId } from "../src/mcp/native-context-refusal.js";

const SOURCES = [
  ["claude-attestation.ts", "claude_attestation"],
  ["copilot-attestation.ts", "copilot_attestation"],
  ["desktop-call.ts", "desktop_context"],
] as const;
const LITERAL = /\b(?:fail|new DesktopCallContextError)\("([^"\\]*)"\)/g;

test("every fixed verifier message maps to a snake_case code at its own stage (drift guard)", () => {
  let found = 0;
  for (const [file, stage] of SOURCES) {
    const source = readFileSync(new URL(`../src/mcp/${file}`, import.meta.url), "utf8");
    for (const match of source.matchAll(LITERAL)) {
      found++;
      const message = match[1]!;
      const code = nativeContextRefusalReason(stage, new Error(message));
      assert.notEqual(code, "unclassified", `unmapped ${stage} message: ${message}`);
      assert.match(code, /^[a-z][a-z0-9_]*$/, message);
    }
  }
  // A broken pattern must not pass by finding nothing.
  assert.ok(found > 20, `only ${found} verifier messages found`);
});

test("fixed spellings, including the messages that share one code", () => {
  const proofs: [string, string][] = [
    ["unknown key", "unknown_key"],
    ["tool use mismatch", "tool_use_mismatch"],
    ["expired", "expired"],
    ["replayed tool use", "replayed_proof"],
    ["replayed proof", "replayed_proof"],
    ["issued in the future", "issued_in_future"],
    ["proof is not a compact JWS", "malformed_proof"],
    ["invalid proof", "malformed_proof"],
    ["lifetime out of range", "invalid_lifetime"],
    ["invalid lifetime", "invalid_lifetime"],
    ["invalid signature", "malformed_signature"],
  ];
  for (const stage of ["claude_attestation", "copilot_attestation"] as const) {
    for (const [message, code] of proofs) assert.equal(nativeContextRefusalReason(stage, new Error(message)), code, message);
  }
  const contexts: [string, string][] = [
    ["Conflicting native chat context.", "conflicting_context"],
    ["Invalid native chat context.", "invalid_context"],
    ["Unsupported native chat context.", "unsupported_context"],
    ["Unsupported desktop identity headers.", "obsolete_identity_headers"],
  ];
  for (const [message, code] of contexts) assert.equal(nativeContextRefusalReason("desktop_context", new Error(message)), code, message);
});

test("anything not looked up by exact message at its stage is unclassified, never the raw message", () => {
  assert.equal(nativeContextRefusalReason("claude_attestation", new Error("something new")), "unclassified");
  assert.equal(nativeContextRefusalReason("claude_attestation", new Error("unknown key abc123")), "unclassified");
  assert.equal(nativeContextRefusalReason("claude_attestation", "unknown key"), "unclassified");
  assert.equal(nativeContextRefusalReason("copilot_attestation", null), "unclassified");
  assert.equal(nativeContextRefusalReason("desktop_context", undefined), "unclassified");
  // A message belongs to one stage only.
  assert.equal(nativeContextRefusalReason("desktop_context", new Error("unknown key")), "unclassified");
  assert.equal(nativeContextRefusalReason("claude_attestation", new Error("Invalid native chat context.")), "unclassified");
});

test("responseCorrelationId reads only a non-empty string header", () => {
  const response = (value: unknown) => ({ getHeader: (name: string) => name === "x-correlation-id" ? value : undefined });
  assert.equal(responseCorrelationId(response("corr-123")), "corr-123");
  assert.equal(responseCorrelationId(response(undefined)), null);
  assert.equal(responseCorrelationId(response("")), null);
  assert.equal(responseCorrelationId(response(42)), null);
  assert.equal(responseCorrelationId(response(["corr-123"])), null);
});
