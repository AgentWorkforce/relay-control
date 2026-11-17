import { z } from "zod";

// Preserve recorded model provenance. A missing model or timestamp is not a
// ready summary, and a backend must never substitute configured defaults.
const recordedState = z.strictObject({
  state: z.enum(["active", "done", "abandoned", "unknown"]),
  classifiedAt: z.iso.datetime({ offset: true }),
}).nullable();
const nonBlank = z.string().min(1).refine((value) => value.trim().length > 0);
const kind = z.enum(["short", "long"]);
const summary = z.discriminatedUnion("status", [
  z.strictObject({
    status: z.literal("ready"),
    kind,
    summary: nonBlank.max(32_000),
    model: nonBlank.max(128),
    builtAt: z.iso.datetime({ offset: true }),
    state: recordedState,
  }),
  z.strictObject({ status: z.literal("empty"), kind, state: recordedState }),
  z.strictObject({ status: z.literal("unsupported") }),
]);

const response = z.strictObject({
  summary,
  provenance: z.strictObject({
    source: z.enum(["session_brief", "session_summary"]), kind,
    generatedAt: z.iso.datetime({ offset: true }), revision: z.number().int().nullable(),
    truncated: z.boolean(),
  }).nullable().optional(),
}).superRefine((body, ctx) => {
  if (body.summary.status === "ready" &&
      Array.from(body.summary.summary).length > (body.summary.kind === "short" ? 320 : 16_000)) {
    ctx.addIssue({ code: "custom", path: ["summary", "summary"], message: "Recorded summary exceeds its kind's limit" });
  }
  if (body.provenance && (body.summary.status !== "ready" || body.provenance.kind !== body.summary.kind)) {
    ctx.addIssue({ code: "custom", path: ["provenance"], message: "Provenance must describe the returned summary kind" });
  }
});

/** Validate the Reader envelope without substituting a different summary kind. */
export function recordedSummaryResponse(body: unknown, requestedKind: z.infer<typeof kind> = "short") {
  const parsed = response.safeParse(body);
  if (!parsed.success || (parsed.data.summary.status !== "unsupported" && parsed.data.summary.kind !== requestedKind)) return null;
  return parsed.data;
}

/** The dashboard's existing short-summary projection remains short-only. */
export function recordedSummary(body: Record<string, unknown>) {
  return recordedSummaryResponse(body)?.summary ?? null;
}
