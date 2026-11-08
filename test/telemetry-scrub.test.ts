/**
 * telemetry lane: the shared Technical Foul secret-scrubbing corpus
 * (sessions-pipeline PR #162 / relayhistory-cloud PR #269, ruleset 3), run
 * against the vendored scrubber and against the full telemetry payload path.
 * Ported from relayhistory-cloud test/scrub-secret-corpus.test.ts (vitest ->
 * node:test). Placeholders are filled with fresh random values each run, so no
 * secret-shaped value is stored in the repo.
 */
import assert from "node:assert/strict";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { scrubJson, scrubText } from "../src/telemetry/technical-foul-scrub.js";
import { scrubFreeText, scrubPayload, isBlockedKey } from "../src/telemetry/scrub.js";
import { issueSection, parseIssue } from "../src/telemetry/issues.js";

/** Keep identical to sessions-pipeline and relayhistory-cloud. */
const CORPUS_SHA256 = "4b0ffeaefe5ad955b66b64000107cffdb26cf2e609c245fe21e001efb8977524";
/** sha256 of technical-foul-scrub.ts = ruleset 3 upstream (do not edit locally). */
const SCRUB_RULESET_3_SHA256 = "d8c848480d99ac77eeef3c2bf1da900273bcb85631112ee691fc95508a1dd059";

const here = (path: string) => fileURLToPath(new URL(path, import.meta.url));
const corpusText = readFileSync(here("./fixtures/scrub-secret-corpus.json"), "utf8").replace(/\r\n/g, "\n");

type Part = [string, number | string];
type Generator = { prefix?: string; suffix?: string; parts: Part[] };
type Case = { id: string; input: string; expected: string };
const corpus = JSON.parse(corpusText) as { generators: Record<string, Generator>; secrets: string[]; cases: Case[] };

const CHARSETS: Record<string, string> = {
  alnum: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
  upper_alnum: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
  letters: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
  digits: "0123456789",
  hex: "0123456789abcdef",
  urlsafe: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
  b64: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
};

function randomFrom(charset: string, n: number): string {
  let out = "";
  while (out.length < n) {
    for (const b of randomBytes(n * 2)) {
      if (b < 256 - (256 % charset.length)) out += charset[b % charset.length];
      if (out.length === n) break;
    }
  }
  return out;
}

function generate(g: Generator): string {
  let body = "";
  for (const [kind, n] of g.parts) {
    if (kind === "lit") body += String(n);
    else if (kind === "uuid") body += randomUUID();
    else {
      const charset = CHARSETS[kind];
      if (!charset) throw new Error(`unknown charset ${kind}`);
      body += randomFrom(charset, Number(n));
    }
  }
  return `${g.prefix ?? ""}${body}${g.suffix ?? ""}`;
}

function instantiate(c: Case) {
  const values = new Map<string, string>();
  const fill = (s: string) =>
    s.replace(/\{\{([a-z0-9_]+)\}\}/g, (_m, name: string) => {
      const g = corpus.generators[name];
      if (!g) throw new Error(`${c.id}: unknown placeholder ${name}`);
      if (!values.has(name)) values.set(name, generate(g));
      return values.get(name)!;
    });
  const input = fill(c.input);
  const expected = fill(c.expected);
  const secrets = [...values].filter(([name]) => corpus.secrets.includes(name)).map(([, v]) => v);
  return { input, expected, secrets };
}

function fragments(secret: string): string[] {
  const out: string[] = [];
  for (const line of secret.split("\n")) {
    if (line.length < 12) continue;
    for (let i = 0; i + 12 <= line.length; i += 4) out.push(line.slice(i, i + 12));
  }
  return out;
}

test("corpus and vendored scrubber are the pinned upstream versions", () => {
  assert.equal(createHash("sha256").update(corpusText).digest("hex"), CORPUS_SHA256);
  const scrubSource = readFileSync(here("../src/telemetry/technical-foul-scrub.ts"));
  assert.equal(createHash("sha256").update(scrubSource).digest("hex"), SCRUB_RULESET_3_SHA256);
});

test("Technical Foul corpus: every case, five random rounds, no fragment survives", () => {
  assert.ok(corpus.cases.length >= 100);
  for (const c of corpus.cases) {
    for (let round = 0; round < 5; round++) {
      const { input, expected, secrets } = instantiate(c);
      const once = scrubText(input);
      assert.equal(once, expected, c.id);
      for (const secret of secrets) {
        for (const f of fragments(secret)) assert.equal(once.includes(f), false, `${c.id} leaked`);
      }
      assert.equal(scrubText(once), once, `${c.id} is not idempotent`);
    }
  }
});

test("corpus through the telemetry payload path: no secret survives scrubPayload", () => {
  for (const c of corpus.cases) {
    const { input, secrets } = instantiate(c);
    // Secrets can hide anywhere an error class, a deployment value, a support
    // bundle document, or an issue summary could carry them.
    const payload = {
      schema: "agent-relay.selfhost.telemetry/v1",
      deployment: { note: input },
      errors: [{ errorClass: input, route: `/api/v1/${input}` }],
      supportBundle: { documents: { "versions.json": { [input]: input, nested: [input] } } },
    };
    const out = JSON.stringify(scrubPayload(payload).value);
    for (const secret of secrets) {
      for (const f of fragments(secret)) assert.equal(out.includes(f), false, `${c.id} leaked via payload`);
    }
  }
});

test("corpus through the issue-report path (customer free text)", () => {
  for (const c of corpus.cases) {
    const { input, secrets } = instantiate(c);
    const issue = issueSection(parseIssue({ title: "t", summary: input.slice(0, 4000), observed: input.slice(0, 2000) }));
    const out = JSON.stringify(scrubPayload({ issue }).value);
    for (const secret of secrets) {
      for (const f of fragments(secret)) assert.equal(out.includes(f), false, `${c.id} leaked via issue`);
    }
  }
});

test("personal-data and secret keys are dropped regardless of value", () => {
  for (const key of ["email", "userEmail", "userName", "displayName", "password", "apiKey", "authToken",
    "prompt", "transcript", "content", "messageText", "fileContents", "ipAddress", "cookie"]) {
    assert.equal(isBlockedKey(key), true, key);
  }
  for (const key of ["installId", "component", "errorClass", "route", "status", "count", "fingerprint",
    "version", "workspace", "messages24h", "activeAgents24h", "requestsByArea", "reportId", "severity"]) {
    assert.equal(isBlockedKey(key), false, key);
  }
  const { value, redactions } = scrubPayload({
    deployment: { userEmail: "ops@customer.example", prompt: "summarize the incident", version: "1.2.3" },
  });
  assert.deepEqual(value, { deployment: { userEmail: "[REDACTED]", prompt: "[REDACTED]", version: "1.2.3" } });
  assert.equal(redactions, 2);
});

test("free text masks emails, IPs, UUIDs, and bounds length", () => {
  const out = scrubFreeText(
    `owner jane.doe@customer.example saw 10.12.0.7 fail for workspace 3f2c3a4e-1111-4222-8333-944445555666 ${"x".repeat(3000)}`,
  );
  assert.ok(!out.includes("jane.doe"));
  assert.ok(!out.includes("10.12.0.7"));
  assert.ok(!out.includes("3f2c3a4e"));
  assert.ok(out.endsWith("…[truncated]"));
});

test("structured payload values are not mangled", () => {
  const payload = {
    reportId: randomUUID(),
    generatedAt: new Date().toISOString(),
    errors: [{ fingerprint: "fp_0123456789abcdef", route: "/api/v1/workspaces/:id/sessions", status: 502 }],
    usage: { workspaceActivity: [{ workspace: "h_0123456789abcdef0123", requests: 42 }] },
    components: [{ name: "relaycast", version: "8.5.2", latencyMs: 12 }],
  };
  assert.deepEqual(scrubPayload(payload).value, payload);
  assert.deepEqual(scrubJson(payload), payload);
});
