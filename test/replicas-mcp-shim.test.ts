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

// The replica-side MCP server and its installer are vendored byte for byte
// from the hosted control plane (Cloud 26235d9d4cf2, mcp.ts sha256 7f386084).
// A change here must be a deliberate re-vendor: update the hosted copy and
// these pins together.
test("vendored replica MCP shim matches the pinned hosted source", () => {
  assert.equal(sha256(replicaMcpSource), "ea66bfa7f279a4250aeba4deef07d1cc5b53081ccbbea1052081507cbef413e7");
  assert.equal(sha256(mcpInstall("claude")), "53a4068c8ae84e23ad8c86080180b5e2733a2468dae02febdda95f05efceb259");
  assert.equal(sha256(mcpInstall("codex")), "5aee7f4f88d3bd52271f9f5eeb892dd9a4ebc0b0700022b9186ad91b857b7d8f");
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
function sandbox(t: TestContext, harness: string) {
  const home = mkdtempSync(join(tmpdir(), "replicas-mcp-"));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const bin = join(home, "bin");
  mkdirSync(bin);
  writeFileSync(join(bin, harness), `#!/usr/bin/env python3
import json,pathlib,sys
p=pathlib.Path.home()/'registrations.json'
registry=json.loads(p.read_text()) if p.exists() else {}
operation=sys.argv[2]
if operation=='add':
 separator=sys.argv.index('--');name=sys.argv[separator-1]
 if name in registry: sys.exit(1)
 registry[name]={'type':'stdio','command':sys.argv[separator+1],'args':sys.argv[separator+2:],'scope':'user'}
elif operation=='get':
 name=sys.argv[3]
 if name not in registry: print('No MCP server named '+name,file=sys.stderr);sys.exit(1)
 entry=registry[name]
 if '--json' in sys.argv: print(json.dumps({'name':name,'transport':entry}))
 else: print('Scope: '+('User config' if entry.get('scope')=='user' else 'Local config')+'\\nType: '+entry['type']+'\\nCommand: '+entry['command']+'\\nArgs: '+' '.join(entry['args']))
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
