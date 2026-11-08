// telemetry lane: drains the outbox to the hosted ingest over HTTPS with
// exponential backoff. Offline clusters simply accumulate pending rows.
import type { FetchLike } from "./collector.js";
import { INSTALL_HEADER, SIGNATURE_HEADER, signBody } from "./sign.js";
import type { OutboxRow, TelemetryStore } from "./store.js";

const MAX_ATTEMPTS = 40;
const MAX_AGE_MS = 14 * 24 * 60 * 60 * 1000;
const BASE_DELAY_SECONDS = 30;
const MAX_DELAY_SECONDS = 6 * 60 * 60;

export function backoffSeconds(attempts: number, random = Math.random): number {
  const exponential = Math.min(MAX_DELAY_SECONDS, BASE_DELAY_SECONDS * 2 ** Math.min(attempts, 20));
  // +/- 20% jitter so many installs do not retry in lockstep.
  return Math.max(BASE_DELAY_SECONDS, Math.round(exponential * (0.8 + random() * 0.4)));
}

export type SendOutcome = "sent" | "retry" | "dead";

export async function sendOne(input: {
  row: OutboxRow;
  endpoint: string;
  installId: string;
  installKey: string;
  userAgent: string;
  fetchImpl: FetchLike;
  store: TelemetryStore;
  now?: number;
}): Promise<SendOutcome> {
  const { row, store } = input;
  const now = input.now ?? Date.now();
  let failure: string;
  let permanent = false;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15_000);
    let response: Response;
    try {
      response = await input.fetchImpl(input.endpoint, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "user-agent": input.userAgent,
          [INSTALL_HEADER]: input.installId,
          [SIGNATURE_HEADER]: signBody(input.installKey, row.body, Math.floor(now / 1000)),
          "idempotency-key": row.id,
        },
        body: row.body,
        signal: controller.signal,
        redirect: "manual",
      });
    } finally {
      clearTimeout(timer);
    }
    await response.arrayBuffer().catch(() => undefined);
    // 409 = the ingest already has this report id (an earlier attempt landed).
    if (response.ok || response.status === 409) {
      await store.markSent(row.id);
      return "sent";
    }
    failure = `http_${response.status}`;
    // 400/413/422: the payload itself is rejected; retrying cannot help.
    permanent = response.status === 400 || response.status === 413 || response.status === 422;
  } catch (error) {
    failure = error instanceof Error && error.name === "AbortError" ? "timeout" : "network_error";
  }
  const tooOld = now - Date.parse(row.createdAt) > MAX_AGE_MS;
  const dead = permanent || tooOld || row.attempts + 1 >= MAX_ATTEMPTS;
  await store.markRetry(row.id, backoffSeconds(row.attempts), failure, dead);
  return dead ? "dead" : "retry";
}
