import { ampThreadId, AMP_CLI_VERSION, type AmpOperation } from "./provider.js";
import type { AmpTransportConfig } from "./config.js";

export type { AmpOperation } from "./provider.js";
export type AmpRuntime = (key: string, operation: AmpOperation) => Promise<unknown>;

/** `unknown` means Amp may have accepted the operation; such a send is never retried. */
export class AmpRuntimeError extends Error {
  constructor(readonly outcome: "rejected" | "unknown", readonly code: string) {
    super(code);
    this.name = "AmpRuntimeError";
  }
}

export const AMP_KEY = /^sgamp_[A-Za-z0-9_-]{16,512}$/;
const MAX_RESPONSE = 17 * 1024 * 1024;
const TIMEOUT_MS = 55_000;

async function responseText(response: Response): Promise<string> {
  if (!response.body) throw new Error("empty_response");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE) throw new Error("oversized_response");
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Client for the persistent Amp process service (hosted Cloud's runtime.ts).
 * It never provisions compute, installs packages, or retries a send whose
 * acceptance is uncertain. Self-host has no sandbox fallback.
 */
export function createAmpRuntime(config: AmpTransportConfig | null, fetchImpl: typeof fetch = fetch): AmpRuntime {
  return async (key, operation) => {
    if (!AMP_KEY.test(key)) throw new AmpRuntimeError("rejected", "amp_invalid_key");
    if (operation.kind !== "discover") {
      try {
        ampThreadId(operation.threadId);
      } catch {
        throw new AmpRuntimeError("rejected", "amp_invalid_thread");
      }
    }
    if (
      operation.kind === "inject" &&
      (!operation.text || operation.text.includes(String.fromCharCode(0)) || Buffer.byteLength(operation.text) > 64 * 1024)
    ) {
      throw new AmpRuntimeError("rejected", "amp_invalid_message");
    }
    let url: URL;
    try {
      if (!config) throw new Error();
      url = new URL(config.origin);
      if (
        url.protocol !== "https:" || url.username || url.password || url.search || url.hash ||
        url.pathname !== "/" || !config.token || config.token.length < 32 || config.token === "unset"
      ) {
        throw new Error();
      }
    } catch {
      throw new AmpRuntimeError("rejected", "amp_transport_not_configured");
    }
    url.pathname = "/v1/internal/amp/operation";
    try {
      const response = await fetchImpl(url, {
        method: "POST",
        redirect: "manual",
        headers: { authorization: `Bearer ${config.token}`, "content-type": "application/json" },
        body: JSON.stringify({ v: 1, cliVersion: AMP_CLI_VERSION, key, operation }),
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      const envelope = JSON.parse(await responseText(response)) as Record<string, unknown>;
      if (envelope.v !== 1 || envelope.cliVersion !== AMP_CLI_VERSION) throw new Error();
      if (response.ok && envelope.ok === true && Object.hasOwn(envelope, "value")) return envelope.value;
      if (envelope.ok === false && (envelope.outcome === "rejected" || envelope.outcome === "unknown")) {
        throw new AmpRuntimeError(envelope.outcome, "amp_command_failed");
      }
      throw new Error();
    } catch (error) {
      if (error instanceof AmpRuntimeError) throw error;
      throw new AmpRuntimeError(operation.kind === "inject" ? "unknown" : "rejected", "amp_runtime_unavailable");
    }
  };
}
