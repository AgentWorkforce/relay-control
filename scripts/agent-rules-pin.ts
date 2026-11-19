// Prints, or with --write updates, agent-rules/manifest.json sections_sha256.
// Run after editing a section, together with a version bump and a CHANGELOG
// entry (test/agent-rules.test.ts checks all three).
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { agentRulesDirectory, loadAgentRules } from "../src/agent-rules/bundle.js";

const directory = agentRulesDirectory();
const bundle = loadAgentRules(directory, { verifyDigest: false });
if (process.argv.includes("--write")) {
  const path = resolve(directory, "manifest.json");
  const manifest = JSON.parse(readFileSync(path, "utf8"));
  manifest.sections_sha256 = bundle.sectionsSha256;
  writeFileSync(path, JSON.stringify(manifest, null, 2) + "\n");
}
console.log(bundle.sectionsSha256);
