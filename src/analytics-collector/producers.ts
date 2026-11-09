// analytics collector: the producer registry. Each producer is registered with
// a name, the component and deployment_id it may write for, and a token file
// (a Secret mount). Tokens are read once at startup; only their SHA-256 digest
// is kept, in this module's closure. Lookups compare digests with
// timingSafeEqual against every registration, without an early exit.
import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { OPAQUE_ID } from "../analytics/events.js";

/** What the rest of the collector may know about a producer: never its token. */
export type Producer = {
  readonly name: string;
  readonly component: string;
  readonly deploymentId: string;
};

export type ProducerEntry = Producer & { token: string };

export interface ProducerRegistry {
  /** The producer whose token this is, or null. Constant-time per registration. */
  authenticate(token: string): Producer | null;
  list(): readonly Producer[];
  /** For startup logs: names, components and deployment ids; no tokens. */
  describe(): Array<{ name: string; component: string; deployment_id: string }>;
}

export const MAX_PRODUCERS = 256;
export const TOKEN_MIN_BYTES = 32;
export const TOKEN_MAX_BYTES = 512;
const PRODUCER_KEYS = new Set(["name", "component", "deployment_id", "token_file"]);
// Producer names appear in logs and as health keys.
const PRODUCER_NAME = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const COMPONENT = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
// Visible ASCII without spaces: a single bearer token.
const HEADER_TOKEN = /^[\x21-\x7e]+$/;

function digest(token: string): Buffer {
  return createHash("sha256").update(token, "utf8").digest();
}

/** Builds the registry. Errors name the producer (config, not secret), never a token. */
export function createProducerRegistry(entries: readonly ProducerEntry[]): ProducerRegistry {
  if (entries.length === 0) throw new Error("at least one producer must be registered");
  if (entries.length > MAX_PRODUCERS) throw new Error(`at most ${MAX_PRODUCERS} producers may be registered`);
  const names = new Set<string>();
  const authorities = new Set<string>();
  const registrations: Array<{ producer: Producer; digest: Buffer }> = [];
  for (const entry of entries) {
    if (!PRODUCER_NAME.test(entry.name)) {
      throw new Error("producer name must be 1-64 characters of a-z, 0-9, _, . or - starting with a letter or digit");
    }
    if (!COMPONENT.test(entry.component)) throw new Error(`producer ${entry.name}: component is not a valid component name`);
    if (!OPAQUE_ID.test(entry.deploymentId)) {
      throw new Error(`producer ${entry.name}: deployment_id is not an opaque identifier`);
    }
    const bytes = Buffer.byteLength(entry.token, "utf8");
    if (bytes < TOKEN_MIN_BYTES || bytes > TOKEN_MAX_BYTES || !HEADER_TOKEN.test(entry.token)) {
      throw new Error(
        `producer ${entry.name}: token must be ${TOKEN_MIN_BYTES} to ${TOKEN_MAX_BYTES} bytes of visible ASCII`,
      );
    }
    if (names.has(entry.name)) throw new Error(`producer ${entry.name}: duplicate producer name`);
    names.add(entry.name);
    const authority = `${entry.component}\u0000${entry.deploymentId}`;
    if (authorities.has(authority)) {
      throw new Error(`producer ${entry.name}: duplicate component and deployment_id registration`);
    }
    authorities.add(authority);
    const tokenDigest = digest(entry.token);
    if (registrations.some((registration) => timingSafeEqual(registration.digest, tokenDigest))) {
      throw new Error(`producer ${entry.name}: token is shared with another producer`);
    }
    registrations.push({
      producer: Object.freeze({ name: entry.name, component: entry.component, deploymentId: entry.deploymentId }),
      digest: tokenDigest,
    });
  }
  const producers = registrations.map((registration) => registration.producer);

  return {
    authenticate(token: string): Producer | null {
      const presented = digest(token);
      let found: Producer | null = null;
      // No early exit: every registration is compared.
      for (const registration of registrations) {
        if (timingSafeEqual(registration.digest, presented) && found === null) found = registration.producer;
      }
      return found;
    },
    list: () => producers,
    describe: () => producers.map((producer) => ({
      name: producer.name,
      component: producer.component,
      deployment_id: producer.deploymentId,
    })),
  };
}

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Reads ANALYTICS_COLLECTOR_PRODUCERS_FILE: a JSON array of
 * `{ name, component, deployment_id, token_file }`. Each token file is read
 * once and trimmed. Errors name the variable or the producer, never a value.
 */
export function loadProducers(file: string, variable = "ANALYTICS_COLLECTOR_PRODUCERS_FILE"): ProducerRegistry {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(file, "utf8"));
  } catch {
    throw new Error(`${variable} must name a readable JSON file`);
  }
  if (!Array.isArray(parsed)) throw new Error(`${variable} must contain a JSON array of producers`);
  if (parsed.length > MAX_PRODUCERS) throw new Error(`${variable} lists more than ${MAX_PRODUCERS} producers`);
  const entries: ProducerEntry[] = parsed.map((raw, index) => {
    if (!isObject(raw)) throw new Error(`${variable}: producer ${index} must be an object`);
    for (const key of Object.keys(raw)) {
      if (!PRODUCER_KEYS.has(key)) throw new Error(`${variable}: producer ${index} has an unknown key`);
    }
    for (const key of PRODUCER_KEYS) {
      if (typeof raw[key] !== "string" || !(raw[key] as string).trim()) {
        throw new Error(`${variable}: producer ${index} requires a non-empty string ${key}`);
      }
    }
    const name = (raw.name as string).trim();
    let token: string;
    try {
      token = readFileSync((raw.token_file as string).trim(), "utf8").trim();
    } catch {
      throw new Error(`${variable}: producer ${index} token_file is not readable`);
    }
    return {
      name,
      component: (raw.component as string).trim(),
      deploymentId: (raw.deployment_id as string).trim(),
      token,
    };
  });
  return createProducerRegistry(entries);
}
