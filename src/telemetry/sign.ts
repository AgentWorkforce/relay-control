// telemetry lane: request signing shared with the hosted ingest.
//
//   x-relay-telemetry-install:   <installId>
//   x-relay-telemetry-signature: t=<unix seconds>,v1=<hex HMAC-SHA256(installKey, `${t}.${rawBody}`)>
//
// Same construction as relayhistory's self-host events bridge
// (cloud packages/web/lib/relayhistory-events/ingest.ts).
import { createHmac, timingSafeEqual } from "node:crypto";

export const INSTALL_HEADER = "x-relay-telemetry-install";
export const SIGNATURE_HEADER = "x-relay-telemetry-signature";
export const EXPORT_FORMAT = "agent-relay-telemetry-export/v1";

export function signBody(installKey: string, rawBody: string, timestampSeconds: number): string {
  const digest = createHmac("sha256", installKey)
    .update(`${timestampSeconds}.${rawBody}`)
    .digest("hex");
  return `t=${timestampSeconds},v1=${digest}`;
}

export function parseSignature(header: string): { timestamp: number; digest: string } | null {
  const parts = Object.fromEntries(
    header.split(",").map((part) => {
      const index = part.indexOf("=");
      return index > 0 ? [part.slice(0, index).trim(), part.slice(index + 1).trim()] : ["", ""];
    }),
  );
  const timestamp = Number(parts.t);
  if (!Number.isInteger(timestamp) || !/^[a-f0-9]{64}$/.test(parts.v1 ?? "")) return null;
  return { timestamp, digest: parts.v1! };
}

export function verifySignature(installKey: string, rawBody: string, header: string): boolean {
  const parsed = parseSignature(header);
  if (!parsed) return false;
  const expected = Buffer.from(signBody(installKey, rawBody, parsed.timestamp).split("v1=")[1]!, "hex");
  const actual = Buffer.from(parsed.digest, "hex");
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/**
 * Air-gapped export: one self-contained, signed envelope per report. An
 * operator carries the file out and POSTs it as-is (see docs/telemetry.md).
 */
export type ExportEnvelope = {
  format: typeof EXPORT_FORMAT;
  installId: string;
  signature: string;
  body: string;
};

export function exportEnvelope(installId: string, installKey: string, rawBody: string, now = Date.now()): ExportEnvelope {
  return {
    format: EXPORT_FORMAT,
    installId,
    signature: signBody(installKey, rawBody, Math.floor(now / 1000)),
    body: rawBody,
  };
}
