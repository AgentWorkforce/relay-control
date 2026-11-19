import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { nativeContextRefusalReason, responseCorrelationId } from "../src/mcp/native-context-refusal.js";

const SOURCES = ["claude-attestation.ts", "copilot-attestation.ts", "desktop-call.ts"];
const LITERAL = /\b(?:fail|new DesktopCallContextError)\("([^"\\]*)"\)/g;

test("every fixed verifier message maps to a snake_case code (drift guard)", () => {
  const found: string[] = [];
  for (const file of SOURCES) {
    const source = readFileSync(new URL(`../src/mcp/${file}`, import.meta.url), "utf8");
    for (const match of source.matchAll(LITERAL)) found.push(match[1]!);
  }
  // A broken pattern must not pass by finding nothing.
  assert.ok(found.length > 20, `only ${found.length} verifier messages found`);
  for (const message of found) {
    const code = nativeContextRefusalReason(new Error(message));
    assert.notEqual(code, "unclassified", `unmapped verifier message: ${message}`);
    assert.match(code, /^[a-z][a-z0-9_]*$/, message);
  }
});

test("fixed spellings for the shortened and Desktop codes", () => {
  const cases: [string, string][] = [
    ["unknown key", "unknown_key"],
    ["tool use mismatch", "tool_use_mismatch"],
    ["expired", "expired"],
    ["replayed tool use", "replayed_tool_use"],
    ["issued in the future", "issued_in_the_future"],
    ["proof is not a compact JWS", "proof_not_compact_jws"],
    ["Conflicting native chat context.", "conflicting_context"],
    ["Invalid native chat context.", "invalid_context"],
    ["Unsupported native chat context.", "unsupported_context"],
    ["Unsupported desktop identity headers.", "unsupported_identity_headers"],
  ];
  for (const [message, code] of cases) assert.equal(nativeContextRefusalReason(new Error(message)), code, message);
});

test("anything not looked up by exact message is unclassified, never the raw message", () => {
  assert.equal(nativeContextRefusalReason(new Error("something new")), "unclassified");
  assert.equal(nativeContextRefusalReason(new Error("unknown key abc123")), "unclassified");
  assert.equal(nativeContextRefusalReason("unknown key"), "unclassified");
  assert.equal(nativeContextRefusalReason(null), "unclassified");
  assert.equal(nativeContextRefusalReason(undefined), "unclassified");
});

test("responseCorrelationId reads only a non-empty string header", () => {
  const response = (value: unknown) => ({ getHeader: (name: string) => name === "x-correlation-id" ? value : undefined });
  assert.equal(responseCorrelationId(response("corr-123")), "corr-123");
  assert.equal(responseCorrelationId(response(undefined)), null);
  assert.equal(responseCorrelationId(response("")), null);
  assert.equal(responseCorrelationId(response(42)), null);
  assert.equal(responseCorrelationId(response(["corr-123"])), null);
});
