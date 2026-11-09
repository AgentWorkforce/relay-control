import { z } from "zod";

// Preserve recorded model provenance. A missing model or timestamp is not a
// ready summary, and a backend must never substitute configured defaults.
const recordedState = z.strictObject({
  state: z.enum(["active", "done", "abandoned", "unknown"]),
  classifiedAt: z.iso.datetime({ offset: true }),
}).nullable();
const nonBlank = z.string().min(1).refine((value) => value.trim().length > 0);
const summary = z.discriminatedUnion("status", [
  z.strictObject({
    status: z.literal("ready"),
    kind: z.literal("short"),
    summary: nonBlank,
    model: nonBlank,
    builtAt: z.iso.datetime({ offset: true }),
    state: recordedState,
  }),
  z.strictObject({ status: z.literal("empty"), kind: z.literal("short"), state: recordedState }),
  z.strictObject({ status: z.literal("unsupported") }),
]);

export function recordedSummary(body: Record<string, unknown>) {
  const parsed = z.object({ summary }).safeParse(body);
  return parsed.success ? parsed.data.summary : null;
}
