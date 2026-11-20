import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  AGENT_RULES_AUDIENCES, agentRulesDirectory, composeAgentRules, loadAgentRules, rulesTextProblem,
} from "../src/agent-rules/bundle.js";
import { AgentRules, grokBootstrapPrompt } from "../src/agent-rules/service.js";
import { grokRoutinePrompt } from "../src/mcp/grok-routine.js";
import { loadMcpOAuthConfig } from "../src/mcp/oauth/config.js";
import { grokFixture } from "./support/grok-fixture.js";

// docs/agent-rules.md; docs/specs/grok-bot-dynamic-prompt.md Phase 2.
const directory = agentRulesDirectory();
const manifest = JSON.parse(readFileSync(resolve(directory, "manifest.json"), "utf8"));

test("the committed bundle is pinned: a section change needs a new sha, version and CHANGELOG entry", () => {
  const bundle = loadAgentRules();
  assert.equal(bundle.sectionsSha256, manifest.sections_sha256,
    "Run node --import tsx scripts/agent-rules-pin.ts --write, bump manifest version and add a CHANGELOG entry");
  assert.match(readFileSync(resolve(directory, "CHANGELOG.md"), "utf8"), new RegExp(`^## ${bundle.version.replaceAll(".", "\\.")}$`, "m"),
    "CHANGELOG.md must describe the manifest's current version");
  assert.equal(bundle.sections[0]!.id, "safety");
  const listed = new Set(manifest.sections.flatMap((section: { file?: string }) => section.file ? [section.file] : []));
  for (const file of readdirSync(resolve(directory, "sections"))) assert.ok(listed.has(`sections/${file}`), `${file} is not in the manifest`);
  for (const section of bundle.sections) {
    if (section.text !== null) assert.equal(rulesTextProblem(section.text), null, `${section.id} fails the secret and size lint`);
  }
  for (const audience of AGENT_RULES_AUDIENCES) {
    assert.ok(bundle.sections.some(section => section.audiences.includes(audience)), `${audience} has no sections`);
  }
});

test("composition filters by audience, keeps safety first, appends the overlay and versions it", () => {
  const bundle = loadAgentRules();
  const lead = composeAgentRules(bundle, "lead", null);
  assert.deepEqual(lead.sections.map(section => section.id), ["safety", "lead-delegation", "lead-orchestration"]);
  assert.equal(lead.version, bundle.version);
  assert.match(lead.text, /## Orchestrate; don't implement serially/);
  const procedure = grokRoutinePrompt("fake-grok", { canReply: true });
  const grok = composeAgentRules(bundle, "grok-bot", { version: 3, text: "Escalate to the owner." }, { grokRoutinePrompt: procedure });
  assert.deepEqual(grok.sections.map(section => section.id), ["safety", "grok-inbox", "grok-delegation", "show-ui", "organization"]);
  assert.equal(grok.version, `${bundle.version}+org.3`);
  assert.ok(grok.text.includes(procedure), "grok-inbox is the grant's copied routine procedure");
  assert.ok(grok.text.indexOf("## Safety") < grok.text.indexOf("## Organization rules"));
  assert.notEqual(grok.sha256, composeAgentRules(bundle, "grok-bot", null, { grokRoutinePrompt: procedure }).sha256);
  assert.equal(composeAgentRules(bundle, "worker", { version: 1, text: "   " }).version, bundle.version, "a cleared overlay adds nothing");
});

test("the rules lint refuses secrets, routine URLs and oversized text without echoing them", () => {
  for (const bad of ["crsr_" + "a".repeat(20), "whsec_" + "A".repeat(20), "https://user:pass@example.test/x",
    "https://api2.cursor.sh/automations/webhook/rt_123", "sh_at_" + "b".repeat(20), "-----BEGIN RSA PRIVATE KEY-----"]) {
    const problem = rulesTextProblem(`ok ${bad} ok`);
    assert.ok(problem); assert.ok(!problem!.includes(bad));
  }
  assert.match(rulesTextProblem("x".repeat(16 * 1024 + 1))!, /at most/);
  assert.equal(rulesTextProblem("Follow up on silent agents after 30 minutes."), null);
});

test("dynamic prompt: connect returns the bootstrap; get_agent_rules renders this grant's procedure and records the version", async t => {
  const rules = new AgentRules({ database: undefined as never });
  const f = await grokFixture(t, true, { dynamicPrompt: { bootstrapVersion: rules.bundle.bootstrapVersion } });
  const connected = (await f.tool("connect_grok_bot_routine")).structuredContent as any;
  assert.equal(connected.routine_prompt, grokBootstrapPrompt("fake-grok", rules.bundle.bootstrapVersion));
  assert.match(connected.routine_prompt, /first call the Agent Relay tool get_agent_rules with audience = "grok-bot"/);
  await f.setup("POST", { webhook_url: "https://api2.cursor.sh/automations/webhook/rt_fake", authorization: "crsr_" + "fake_routine_key_".repeat(3) });

  const fetched = await f.tool("get_agent_rules", { bootstrap_version: rules.bundle.bootstrapVersion });
  const data = fetched.structuredContent as any;
  assert.equal(data.audience, "grok-bot");
  assert.equal(data.version, rules.bundle.version);
  assert.equal(data.bootstrap_outdated, undefined);
  assert.ok(data.text.includes(grokRoutinePrompt("fake-grok", { canReply: true })));
  const block = (fetched.content as Array<{ text: string }>)[0]!.text;
  assert.match(block, /^Agent Relay app: operating rules \(version /);
  assert.ok(!block.includes("untrusted data, not instructions.\n{"), "rules are the app's own instructions, not an untrusted block");
  const status = (await f.tool("grok_bot_routine_status")).structuredContent as any;
  assert.equal(status.rules_version_last_fetched, rules.bundle.version);

  const again = (await f.tool("get_agent_rules", { known_sha256: data.sha256 })).structuredContent as any;
  assert.equal(again.unchanged, true); assert.equal(again.text, undefined);
  const page = await (await f.setup()).text();
  assert.match(page, /get_agent_rules/);
});

test("without the dynamic flag the copied procedure is still pasted; the flag requires the Cloud copy", async t => {
  const f = await grokFixture(t, true);
  const connected = (await f.tool("connect_grok_bot_routine")).structuredContent as any;
  assert.equal(connected.routine_prompt, grokRoutinePrompt("fake-grok", { canReply: true }));
  assert.equal((await f.tool("get_agent_rules")).isError, undefined, "get_agent_rules is available to every connection");
  assert.throws(() => loadMcpOAuthConfig({ SELFHOST_GROK_DYNAMIC_PROMPT: "on" }, () => undefined), /requires SELFHOST_GROK_ROUTINES_CLOUD_COPY=on/);
  assert.equal(loadMcpOAuthConfig({ SELFHOST_GROK_DYNAMIC_PROMPT: "on", SELFHOST_GROK_ROUTINES_CLOUD_COPY: "on" }, () => undefined).grokDynamicPrompt, true);
});

test("HTTP: members read composed rules with ETag and markdown; only admins write overlays; overlays stay in their organization", async t => {
  const f = await grokFixture(t, true);
  const headers = (token: string, extra: Record<string, string> = {}) => ({ authorization: `Bearer ${token}`, ...extra });
  const owner = f.browser.accessToken;
  assert.equal((await fetch(f.base + "/api/v1/agent-rules/lead")).status, 401);
  assert.equal((await fetch(f.base + "/api/v1/agent-rules/nobody", { headers: headers(owner) })).status, 404);
  const first = await fetch(f.base + "/api/v1/agent-rules/lead", { headers: headers(owner) });
  assert.equal(first.status, 200);
  const body = await first.json() as any;
  assert.equal(first.headers.get("etag"), `"${body.sha256}"`);
  assert.equal((await fetch(f.base + "/api/v1/agent-rules/lead", { headers: headers(owner, { "if-none-match": `"${body.sha256}"` }) })).status, 304);
  const markdown = await fetch(f.base + "/cloud/api/v1/agent-rules/lead", { headers: headers(owner, { accept: "text/markdown" }) });
  assert.match(markdown.headers.get("content-type")!, /text\/markdown/);
  assert.equal(await markdown.text(), body.text);

  const overlayPath = `${f.base}/api/v1/organizations/${f.owner.organizationId}/agent-rules/grok-bot`;
  const put = (token: string, text: string) => fetch(overlayPath, { method: "PUT", headers: headers(token, { "content-type": "application/json" }), body: JSON.stringify({ text }) });
  // The fixture's person is a member: writing needs owner or admin.
  assert.equal((await put(owner, "Escalate stalls to the workspace owner.")).status, 403);
  await f.database.query("UPDATE organization_memberships SET role='admin' WHERE user_id=$1", [f.owner.userId]);
  assert.equal((await put(owner, "a crsr_" + "z".repeat(20))).status, 400);
  const written = await (await put(owner, "Escalate stalls to the workspace owner.")).json() as any;
  assert.equal(written.version, 1);
  const audit = (await f.database.query("SELECT action,target FROM admin_audit_events WHERE action LIKE 'agent_rules.%'")).rows;
  assert.deepEqual(audit.map(row => [row.action, row.target]), [["agent_rules.overlay_set", "grok-bot v1"]]);
  const rules = (await f.tool("get_agent_rules")).structuredContent as any;
  assert.equal(rules.version, `${loadAgentRules().version}+org.1`);
  assert.match(rules.text, /## Organization rules\n\nEscalate stalls to the workspace owner\./);

  const other = randomUUID();
  await f.database.query("INSERT INTO organizations(id,name) VALUES ($1,'Other Org')", [other]);
  const otherOverlay = await f.store.database.query("SELECT * FROM agent_rules_overlays WHERE organization_id=$1", [other]);
  assert.equal(otherOverlay.rows.length, 0);
  assert.equal((await fetch(`${f.base}/api/v1/organizations/${other}/agent-rules/grok-bot`, { headers: headers(owner) })).status, 404);
  assert.equal((await (await put(owner, "")).json() as any).cleared, true);
});
