import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { test } from "node:test";
import { scanSourceForUnreadBodies, type UnreadBodyFinding } from "./unread-fetch-body-scan.js";

// Reviewed exceptions. Each entry silences findings for one binding in one file; `count` is the
// number of findings it covers there. Add an entry only with a reason a reviewer can check, and
// prefer `await drainBody(response, "<label>")` from src/drain-body.ts instead. Stale entries fail.
type AllowlistEntry = { file: string; binding: string; count: number; reason: string };
const ALLOWLIST: AllowlistEntry[] = [
  {
    file: "src/flows/objects.ts",
    binding: "response",
    count: 1,
    reason:
      "Legacy src/flows run-object upload (GcsRunObjectStore.put). Flows belong to relayfile-control and AGENTS.md says not to change legacy src/flows by default; drain it there or delete it with the legacy module.",
  },
];

const SRC = new URL("../src/", import.meta.url);

function sourceFindings(): UnreadBodyFinding[] {
  const files = readdirSync(SRC, { recursive: true, encoding: "utf8" })
    .filter((file) => file.endsWith(".ts") && !file.endsWith(".d.ts") && !/\.test\.ts$/.test(file))
    .sort();
  assert.ok(files.length > 100, `only ${files.length} source files found; the scan root is wrong`);
  return files.flatMap((file) =>
    scanSourceForUnreadBodies(`src/${file}`, readFileSync(new URL(file, SRC), "utf8")),
  );
}

test("every fetch response under src/ has its body read or released on the success path", () => {
  const findings = sourceFindings();
  const unexplained: UnreadBodyFinding[] = [];
  const matched = new Map<AllowlistEntry, number>();
  for (const finding of findings) {
    const entry = ALLOWLIST.find((item) => item.file === finding.file && item.binding === finding.binding);
    if (entry) matched.set(entry, (matched.get(entry) ?? 0) + 1);
    else unexplained.push(finding);
  }
  assert.deepEqual(
    unexplained.map((finding) => `${finding.file}:${finding.line} ${finding.kind} ${finding.binding}: ${finding.text}`),
    [],
    "Read the body, or call `await drainBody(response, \"<label>\")` from src/drain-body.ts on the success path. " +
      "An unread body keeps the upstream request open and can hold the socket until GC.",
  );
  for (const entry of ALLOWLIST) {
    assert.ok(entry.reason.trim().length >= 20, `allowlist entry for ${entry.file} needs a real reason`);
    assert.equal(
      matched.get(entry) ?? 0,
      entry.count,
      `stale allowlist entry for ${entry.file} (${entry.binding}); update or remove it`,
    );
  }
});

test("the scan sees the repo's fetch call sites (a broken matcher must not pass by finding nothing)", () => {
  // Every awaited fetch-like call in this fixture is consumed, so a matcher that silently stopped
  // recognising them would return no findings here and also none on src/. Flip each one to unread
  // and require a finding, so the shapes used under src/ stay covered.
  const shapes = [
    "await fetch(url)",
    "await globalThis.fetch(url)",
    "await this.fetchImpl(url, {})",
    "await fetchImpl(url)",
    "await fetcher(url)",
    "await env.SERVICE.fetch(request)",
    "await timedFetch(url)",
  ];
  for (const call of shapes) {
    const findings = scanSourceForUnreadBodies("fixture.ts", `async function f() { const r = ${call}; if (!r.ok) throw new Error(); }`);
    assert.equal(findings.length, 1, call);
  }
});

function scan(body: string): UnreadBodyFinding[] {
  return scanSourceForUnreadBodies("fixture.ts", `import { drainBody } from "./drain-body.js";\n${body}`);
}

test("an unread success-path body is a finding", () => {
  const findings = scan(`
    export async function remove(url: string) {
      const response = await fetch(url, { method: "DELETE" });
      if (!response.ok) throw new Error(\`delete failed: \${response.status}\`);
    }`);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.binding, "response");
  assert.equal(findings[0]!.kind, "unread");
  assert.equal(findings[0]!.line, 4); // line 1 is the fixture import
});

test("drainBody on the success path satisfies the guard", () => {
  assert.deepEqual(
    scan(`
      export async function remove(url: string) {
        const response = await fetch(url, { method: "DELETE" });
        if (!response.ok) throw new Error("delete failed");
        await drainBody(response, "fixture.remove");
      }`),
    [],
  );
});

test("a comment that mentions consumption does not satisfy the guard", () => {
  const findings = scan(`
    export async function remove(url: string) {
      const response = await fetch(url, { method: "DELETE" });
      // response.text() is not needed here; drainBody(response, "x") later?
      /* return response; response.body?.cancel(); */
      if (!response.ok) throw new Error("delete failed");
    }`);
  assert.equal(findings.length, 1);
});

test("a string that mentions consumption does not satisfy the guard", () => {
  const findings = scan(`
    export async function remove(url: string) {
      const response = await fetch(url);
      const hint = "response.json() drainBody(response, 'x')";
      if (!response.ok) throw new Error(hint);
    }`);
  assert.equal(findings.length, 1);
});

test("consumption only inside if (!X.ok) does not count; the success path still leaks", () => {
  const findings = scan(`
    export async function post(url: string) {
      const response = await this.fetchImpl(url, { method: "POST" });
      if (!response.ok) {
        const detail = await response.text();
        throw new Error(detail);
      }
    }`);
  assert.equal(findings.length, 1);
  assert.deepEqual(
    scan(`
      export async function post(url: string) {
        const response = await this.fetchImpl(url, { method: "POST" });
        if (!response.ok) {
          await drainBody(response, "fixture.post.failure");
          throw new Error("failed");
        }
        return response.json();
      }`),
    [],
  );
});

test("each accepted form of consumption satisfies the guard", () => {
  const consumers = [
    "return response.json();",
    "const text = await response.text();",
    "await response.arrayBuffer();",
    "await response.blob();",
    "await response.formData();",
    "await response.body?.cancel();",
    "for await (const chunk of response.body!) void chunk;",
    "await drainBody(response, 'fixture');",
    "return response;",
    "return parse(response);",
    "return { response };",
    "const saved = response; return saved;",
  ];
  for (const consumer of consumers) {
    assert.deepEqual(
      scan(`async function f(url: string) { const response = await fetch(url); if (!response.ok) throw new Error(); ${consumer} }`),
      [],
      consumer,
    );
  }
});

test("a let binding assigned inside try is tracked like a const", () => {
  const leak = `
    async function f(url: string) {
      let response: Response;
      try {
        response = await fetchImpl(url);
      } catch {
        throw new Error("unreachable");
      }
      if (!response.ok && response.status !== 404) throw new Error(String(response.status));
    }`;
  assert.equal(scan(leak).length, 1);
  assert.deepEqual(scan(leak.replace(/\n    }$/, "\n      await drainBody(response, 'fixture');\n    }")), []);
});

test("discarded and metadata-only fetch results are findings", () => {
  assert.equal(scan("async function f(url: string) { await fetch(url, { method: 'POST' }); }")[0]?.kind, "discarded");
  assert.equal(scan("function f(url: string) { void fetch(url); }")[0]?.kind, "discarded");
  assert.equal(scan("async function f(url: string) { return (await fetch(url)).ok; }")[0]?.binding, "<.ok>");
  assert.deepEqual(scan("async function f(url: string) { return (await fetch(url)).json(); }"), []);
  assert.deepEqual(scan("async function f(url: string) { return await fetch(url); }"), []);
});

test("non-fetch calls and inline browser scripts in strings are ignored", () => {
  assert.deepEqual(scan("async function f() { const value = await fetchJson(url); const r = await load(url); }"), []);
  assert.deepEqual(
    scan("const page = `<script>async function poll(){const r=await fetch('/poll');}</script>`;"),
    [],
  );
});
