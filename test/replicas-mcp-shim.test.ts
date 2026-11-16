import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { mcpInstall, REPLICA_MCP_FAILURE, REPLICA_MCP_READY, replicaMcpSource } from "../src/replicas/mcp.js";
import { helperInstall } from "../src/replicas/service.js";

const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");

// Real CLI captures: current Claude/Codex and Claude 2.1.0 from its official
// package. Only per-test name/path/scope/command values are substituted.
const harnessCaptures = JSON.parse(readFileSync(new URL("./fixtures/replicas/harness-cli.json", import.meta.url), "utf8"));

// The replica-side MCP server and its installer are vendored byte for byte
// from the hosted control plane (Cloud 905c888, mcp.ts sha256 c360e23e).
// A change here must be a deliberate re-vendor: update the hosted copy and
// these pins together.
test("vendored replica MCP shim matches the pinned hosted source", () => {
  assert.equal(sha256(replicaMcpSource), "1624e788afb02435b2e0bd9b18d84eda474ae318bba74ca218a4f5dd720913a8");
  assert.equal(sha256(mcpInstall("claude")), "d4a7a9a2c43d3b6335487034f7e1a05d4642e0bd7b43648ee738a631d460ddf1");
  assert.equal(sha256(mcpInstall("codex")), "254ae68fb8318fcee63faeb4dc78192aa78dad5987b916d853e0794847428fb8");
  assert.ok(replicaMcpSource.includes("stop retrying until binding access is restored"));
  assert.equal(REPLICA_MCP_READY, "agent-relay-mcp-ready-v1");
  assert.match(REPLICA_MCP_FAILURE, /^Agent Relay MCP provisioning failed\./);
});

const decode = (command: string) => {
  const payload = /b64decode\([^A-Za-z0-9+/=]*([A-Za-z0-9+/=]{20,})/.exec(command);
  assert.ok(payload);
  return JSON.parse(Buffer.from(payload[1]!, "base64").toString("utf8"));
};

test("the installer carries no credential and exposes exactly the three relay tools", () => {
  const id = "00000000-0000-4000-8000-000000000001";
  for (const harness of ["claude", "codex"]) {
    const command = mcpInstall(harness, [id]);
    assert.ok(command.startsWith("python3 -c '"));
    // The capability is read from the private credential file inside the replica, never embedded.
    assert.equal(/secret['"]?\s*:/.test(command), false);
    const decoded = decode(command);
    assert.deepEqual(Object.keys(decoded).sort(), ["harness", "legacy_names", "name", "source"]);
    assert.equal(decoded.harness, harness);
    assert.equal(decoded.name, "agent-relay-replica");
    assert.deepEqual(decoded.legacy_names, [`agent-relay-${id}`]);
    assert.equal(decoded.source, replicaMcpSource);
    assert.deepEqual(decode(mcpInstall(harness)).legacy_names, []);
  }
  for (const tool of ["list_relay_agents", "check_relay_inbox", "send_relay_message"]) assert.ok(replicaMcpSource.includes(tool));
});

/** A private HOME with a fake harness CLI; the installed Python MCP server and its handshake are real. */
function sandbox(t: TestContext, harness: string, capture = harness) {
  const home = mkdtempSync(join(tmpdir(), "replicas-mcp-"));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const bin = join(home, "bin");
  mkdirSync(bin);
  writeFileSync(join(bin, harness), `#!/usr/bin/env python3
import base64,json,pathlib,sys,time
captures=json.loads(base64.b64decode('${Buffer.from(JSON.stringify(harnessCaptures[capture])).toString("base64")}'))
p=pathlib.Path.home()/'registrations.json'
registry=json.loads(p.read_text()) if p.exists() else {}
operation=sys.argv[2]
if operation=='add':
 separator=sys.argv.index('--');name=sys.argv[separator-1]
 if name in registry: sys.exit(1)
 registry[name]={'type':'stdio','command':sys.argv[separator+1],'args':sys.argv[separator+2:],'scope':'user'}
elif operation=='get':
 name=sys.argv[3]
 if name not in registry:
  missing=captures['missing']
  sys.stdout.write(missing['stdout'].replace('{{name}}',name));sys.stderr.write(missing['stderr'].replace('{{name}}',name));sys.exit(missing['exit_code'])
 entry=registry[name]
 if entry.get('slow_get'): time.sleep(10)
 if entry.get('fail_get'): print('private-provider-output');sys.exit(1)
 captured=captures['owned' if entry['command']=='python3' else 'unrelated']['stdout']
 if '--json' in sys.argv:
  reply=json.loads(captured);reply['name']=name;reply['enabled']=entry.get('enabled',True)
  reply['transport'].update({key:entry[key] for key in ('type','command','args')})
  print(json.dumps(reply))
 else:
  scope='User config (available in all your projects)' if entry.get('scope')=='user' else 'Local config'
  print(captured.replace('{{name}}',name).replace('{{scope}}',scope).replace('{{command}}',entry['command']).replace('{{server_path}}',' '.join(entry['args'])))
elif operation=='remove':
 name=sys.argv[-1]
 if registry[name].get('fail_remove'): print('private-provider-output');sys.exit(1)
 del registry[name]
p.write_text(json.dumps(registry))
`, { mode: 0o700 });
  const env = { ...process.env, HOME: home, PATH: `${bin}:${process.env.PATH}` };
  execFileSync("sh", ["-c", helperInstall("http://127.0.0.1:1/messages", "test-private-capability")], { env });
  const registry = join(home, "registrations.json");
  const server = join(home, ".local/share/agent-relay-replicas/mcp.py");
  return { env, registry, server, read: () => JSON.parse(readFileSync(registry, "utf8")) };
}

test("the installer accepts the captured Claude 2.1.0 missing-entry response before adding the stable server", (t) => {
  const box = sandbox(t, "claude", "claude-2.1.0");
  assert.equal(execFileSync("sh", ["-c", mcpInstall("claude")], { env: box.env, encoding: "utf8" }).trim(), REPLICA_MCP_READY);
  assert.equal(box.read()["agent-relay-replica"].command, "python3");
});

test("the installer caps the legacy names at the eight it is given first", () => {
  const ids = Array.from({ length: 12 }, (_, i) => `id${i}`);
  assert.deepEqual(decode(mcpInstall("claude", ids)).legacy_names, ids.slice(0, 8).map((id) => `agent-relay-${id}`));
});

test("a disabled Codex stable registration is refused", (t) => {
  const box = sandbox(t, "codex");
  writeFileSync(box.registry, JSON.stringify({ "agent-relay-replica": { type: "stdio", command: "python3", args: [box.server], scope: "user", enabled: false } }));
  assert.throws(() => execFileSync("sh", ["-c", mcpInstall("codex")], { env: box.env, stdio: "pipe" }));
});

for (const harness of ["claude", "codex"]) {
  test(`${harness}: a foreign stable-name registration fails the install and is left untouched`, (t) => {
    const box = sandbox(t, harness);
    const registry = { "agent-relay-replica": { type: "stdio", command: "node", args: ["another-server.js"], scope: "user" } };
    writeFileSync(box.registry, JSON.stringify(registry));
    assert.throws(() => execFileSync("sh", ["-c", mcpInstall(harness)], { env: box.env, stdio: "pipe" }));
    assert.deepEqual(box.read(), registry);
  });

  test(`${harness}: only verified legacy launch entries are removed; unrelated entries stay`, (t) => {
    const box = sandbox(t, harness);
    const ids = ["00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000002", "00000000-0000-4000-8000-000000000003"];
    const owned = { type: "stdio", command: "python3", args: [box.server], scope: "user" };
    const registry: Record<string, unknown> = {
      [`agent-relay-${ids[0]}`]: owned,
      [`agent-relay-${ids[1]}`]: { ...owned, command: "node" },
      [`agent-relay-${ids[2]}`]: { ...owned, args: [`${box.server}.another-server`] },
      "agent-relay-unrecorded": owned,
    };
    writeFileSync(box.registry, JSON.stringify(registry));
    const command = mcpInstall(harness, ids);
    // Repeat-safe: a second run reuses the one stable entry.
    assert.equal(execFileSync("sh", ["-c", command], { env: box.env, encoding: "utf8" }).trim(), REPLICA_MCP_READY);
    assert.equal(execFileSync("sh", ["-c", command], { env: box.env, encoding: "utf8" }).trim(), REPLICA_MCP_READY);
    const remaining = box.read();
    assert.equal(remaining[`agent-relay-${ids[0]}`], undefined);
    for (const name of [`agent-relay-${ids[1]}`, `agent-relay-${ids[2]}`, "agent-relay-unrecorded"]) {
      assert.deepEqual(remaining[name], registry[name]);
    }
    assert.deepEqual(remaining["agent-relay-replica"], owned);
  });

  test(`${harness}: slow legacy lookups are bounded and keep the stable entry usable`, (t) => {
    const box = sandbox(t, harness);
    const ids = Array.from({ length: 40 }, (_, i) => String(i));
    const owned = { type: "stdio", command: "python3", args: [box.server], scope: "user", slow_get: true };
    writeFileSync(box.registry, JSON.stringify(Object.fromEntries(ids.map((id) => [`agent-relay-${id}`, owned]))));
    const started = Date.now();
    assert.equal(execFileSync("sh", ["-c", mcpInstall(harness, ids)], { env: box.env, encoding: "utf8", timeout: 15000 }).trim(), REPLICA_MCP_READY);
    assert.ok(Date.now() - started < 12000);
    const registry = box.read();
    assert.ok(registry["agent-relay-replica"]);
    assert.deepEqual(registry["agent-relay-0"], owned);
  });

  test(`${harness}: a failed legacy lookup is skipped without exposing CLI output`, (t) => {
    const box = sandbox(t, harness);
    writeFileSync(box.registry, JSON.stringify({ "agent-relay-old": { fail_get: true } }));
    assert.equal(execFileSync("sh", ["-c", mcpInstall(harness, ["old"])], { env: box.env, encoding: "utf8" }).trim(), REPLICA_MCP_READY);
  });

  test(`${harness}: a failed removal of a verified legacy entry fails without leaking CLI output`, (t) => {
    const box = sandbox(t, harness);
    const id = "00000000-0000-4000-8000-000000000001";
    writeFileSync(box.registry, JSON.stringify({ [`agent-relay-${id}`]: {
      type: "stdio", command: "python3", args: [box.server], scope: "user", fail_remove: true,
    } }));
    try {
      execFileSync("sh", ["-c", mcpInstall(harness, [id])], { env: box.env, stdio: "pipe" });
      assert.fail("the install should fail");
    } catch (error) {
      const result = error as { status: number; stdout: Buffer; stderr: Buffer };
      assert.equal(result.status, 1);
      assert.equal(String(result.stdout), "");
      assert.equal(String(result.stderr), "Agent Relay MCP provisioning failed\n");
    }
  });
}
