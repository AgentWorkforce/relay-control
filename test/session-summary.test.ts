import assert from "node:assert/strict";
import test from "node:test";
import { recordedSummary, recordedSummaryResponse } from "../src/sessions/summary.js";

const ts = "2026-11-17T12:00:00.000Z";
const ready = (kind: "short" | "long", text = "Recorded summary") => ({
  summary: { status: "ready", kind, summary: text, model: "recorded-model", builtAt: ts, state: null },
});
const provenance = { source: "session_summary", kind: "long", generatedAt: ts, revision: 2, truncated: false };

test("recorded summary limits count Unicode code points for each requested kind", () => {
  for (const [kind, bound] of [["short", 320], ["long", 16_000]] as const) {
    for (const character of ["x", "😀"]) {
      const body = ready(kind, character.repeat(bound));
      assert.deepEqual(recordedSummaryResponse(body, kind)?.summary, body.summary);
      assert.equal(recordedSummaryResponse(ready(kind, character.repeat(bound + 1)), kind), null);
    }
    assert.equal(recordedSummaryResponse(ready(kind, "  "), kind), null);
  }
});

test("recorded summaries preserve the requested kind and never widen the dashboard short projection", () => {
  const short = ready("short"), long = ready("long");
  assert.deepEqual(recordedSummary(short), short.summary);
  assert.equal(recordedSummary(long), null);
  assert.equal(recordedSummaryResponse(short, "long"), null);
  assert.equal(recordedSummaryResponse(long, "short"), null);
  for (const kind of ["short", "long"] as const) {
    const body = { summary: { status: "empty", kind, state: null }, provenance: null };
    assert.deepEqual(recordedSummaryResponse(body, kind), body);
    assert.equal(recordedSummaryResponse(body, kind === "short" ? "long" : "short"), null);
  }
});

test("recorded envelope accepts optional provenance only when it describes a ready summary of the same kind", () => {
  const body = ready("long");
  assert.deepEqual(recordedSummaryResponse(body, "long"), body, "older Reader envelopes remain valid");
  assert.deepEqual(recordedSummaryResponse({ ...body, provenance: null }, "long"), { ...body, provenance: null });
  assert.deepEqual(recordedSummaryResponse({ ...body, provenance }, "long"), { ...body, provenance });
  for (const value of [
    { ...provenance, kind: "short" }, { ...provenance, source: "inferred" },
    { ...provenance, generatedAt: "yesterday" }, { ...provenance, revision: 1.5 },
    { ...provenance, truncated: "false" }, { ...provenance, extra: "unqualified" },
    { ...provenance, revision: undefined },
  ]) assert.equal(recordedSummaryResponse({ ...body, provenance: value }, "long"), null);
  assert.equal(recordedSummaryResponse({ summary: { status: "empty", kind: "long", state: null }, provenance }, "long"), null);
  assert.equal(recordedSummaryResponse({ summary: { status: "unsupported" }, provenance }, "long"), null);
});

test("ready summaries require bounded recorded model/time/state and never accept invented inner fields", () => {
  const body = ready("short");
  for (const summary of [
    { ...body.summary, model: undefined }, { ...body.summary, model: " " }, { ...body.summary, model: "m".repeat(129) },
    { ...body.summary, builtAt: undefined }, { ...body.summary, builtAt: "yesterday" },
    { ...body.summary, state: { state: "invented", classifiedAt: ts } },
    { ...body.summary, provenance }, { ...body.summary, title: "not a recorded summary" },
  ]) assert.equal(recordedSummaryResponse({ summary }), null);
  for (const body of [null, [], {}, { summary: null }, { summary: "Task title" }]) assert.equal(recordedSummaryResponse(body), null);
  const state = { state: "done", classifiedAt: ts };
  assert.deepEqual(recordedSummaryResponse({ summary: { ...body.summary, state } })?.summary, { ...body.summary, state });
});
