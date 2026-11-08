// analytics lane: the disabled destination. The queue never calls it: with
// `none`, capture is only counted and nothing is queued, sent, or scheduled.
import type { AnalyticsSink } from "../types.js";

export const noneSink: AnalyticsSink = {
  name: "none",
  async send() {
    return { outcome: "accepted" };
  },
};
