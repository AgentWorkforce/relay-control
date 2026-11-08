// telemetry lane: every outbound payload passes through here before it is
// stored in the outbox, previewed, exported, or sent.
//
// Layer 1 is the shared Technical Foul scrubber (technical-foul-scrub.ts),
// vendored byte-identical from sessions-pipeline PR #162 / relayhistory-cloud
// PR #269 (ruleset 3). Do not edit that file here: update it upstream, bump
// the ruleset, and re-vendor (test/telemetry-scrub.test.ts pins its sha256).
//
// Layer 2 is telemetry-specific: keys that name secrets or personal data are
// dropped to [REDACTED] whatever their value, and every string is
// length-bounded. Customer-written free text (issue reports) additionally has
// IPv4 addresses and UUIDs masked (scrubFreeText).
import { isSecretKeyName, scrubJson, scrubText } from "./technical-foul-scrub.js";

export const TELEMETRY_SCRUBBER_VERSION = "technical-foul-3+telemetry-1";
const REDACTED = "[REDACTED]";
const MAX_STRING = 2_000;

/** Keys whose values never leave the cluster, regardless of content. */
const PERSONAL_KEY = /(?:^|[_-])(?:e-?mail|user[_-]?name|full[_-]?name|display[_-]?name|first[_-]?name|last[_-]?name|phone|address|ip|ip[_-]?address|cookie|transcript|prompt|content|body|message[_-]?text|file[_-]?contents?)$/i;

const IPV4 = /(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])/g;
const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;

function camelWords(key: string): string {
  return key.replace(/([a-z0-9])([A-Z])/g, "$1_$2");
}

export function isBlockedKey(key: string): boolean {
  const normalized = camelWords(key);
  return isSecretKeyName(key) || isSecretKeyName(normalized) || PERSONAL_KEY.test(normalized);
}

function bounded(value: string): string {
  return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…[truncated]` : value;
}

/** Customer-written text (issue reports): also masks IPv4 addresses and UUIDs. */
export function scrubFreeText(value: string): string {
  return scrubText(bounded(value)).replace(IPV4, REDACTED).replace(UUID, REDACTED);
}

function layerTwo(value: unknown, allowKeys: ReadonlySet<string>): unknown {
  if (typeof value === "string") return scrubText(bounded(value));
  if (Array.isArray(value)) return value.map((item) => layerTwo(item, allowKeys));
  if (value && typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      output[key] = !allowKeys.has(key) && isBlockedKey(key) ? REDACTED : layerTwo(item, allowKeys);
    }
    return output;
  }
  return value;
}

function countRedactions(value: unknown): number {
  const text = JSON.stringify(value) ?? "";
  return text.split(REDACTED).length - 1;
}

/**
 * Keys emitted by the payload builder itself that would otherwise trip the
 * personal-data key rule (they carry no personal data: counts and hashes).
 */
const STRUCTURAL_KEYS = new Set<string>(["installId"]);

export type ScrubResult<T> = { value: T; redactions: number };

export function scrubPayload<T>(payload: T): ScrubResult<T> {
  const before = countRedactions(payload);
  // Layer 1 runs on keys and values; layer 2 then applies key policy.
  const scrubbed = layerTwo(scrubJson(payload), STRUCTURAL_KEYS) as T;
  return { value: scrubbed, redactions: Math.max(0, countRedactions(scrubbed) - before) };
}
