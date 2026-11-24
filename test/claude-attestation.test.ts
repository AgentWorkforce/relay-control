import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import {
  claudeAttestationFor, ClaudeAttestationError, CLAUDE_TOOL_USE_META, verifyClaudeAttestation, verifyClaudeHandoff,
  type ClaudeHandoffStore,
} from "../src/mcp/claude-attestation.js";
import { ATTESTATION_ARGUMENT, type AttestationStore } from "../src/mcp/copilot-attestation.js";
import { claudeSigner, toolUseId } from "./support/claude-signer.js";

// Cloud's Claude Code call attestation: Ed25519 JWS over chat (sid), source,
// tool-use id and tool; <=60 s; tool-use id spent once; stripped; counts only
// on desktop-managed calls.

function memoryStore(keys: Record<string, string>): AttestationStore & { spent: Set<string> } {
  const spent = new Set<string>();
  return {
    spent,
    async publicKey({ workspaceId, userId, sourceId, kid }) {
      return keys[`${workspaceId}/${userId}/${sourceId}/${kid}`] ?? null;
    },
    async spend({ workspaceId, userId, toolUseId }) {
      const key = `${workspaceId}/${userId}/${toolUseId}`;
      if (spent.has(key)) return false;
      spent.add(key);
      return true;
    },
  };
}

const auth = { workspaceId: "w1", userId: "u1" };
const desktopHeaders = new Headers({ "x-agent-relay-desktop": "1" });

async function fixture() {
  const signer = await claudeSigner();
  const src = randomUUID();
  const sid = randomUUID();
  const store = memoryStore({ [`${auth.workspaceId}/${auth.userId}/${src}/${signer.kid}`]: signer.publicKey });
  const call = async (overrides: Partial<Parameters<typeof signer.sign>[0]> & { signWith?: typeof signer; meta?: string } = {}) => {
    const { signWith, meta, ...claims } = overrides;
    const tuid = claims.tuid ?? toolUseId();
    const tool = "send_relay_message";
    const proof = await (signWith ?? signer).sign({ tool, src, sid, ...claims, tuid });
    return {
      jsonrpc: "2.0", id: 1, method: "tools/call",
      params: { name: tool, arguments: { to: "peer", text: "hi", [ATTESTATION_ARGUMENT]: proof }, _meta: { [CLAUDE_TOOL_USE_META]: meta ?? tuid } },
    };
  };
  return { signer, src, sid, store, call };
}

async function refused(promise: Promise<unknown>, reason: string) {
  await assert.rejects(promise, (error: unknown) => error instanceof ClaudeAttestationError && error.reason === reason);
}

test("a valid proof on a desktop-managed call verifies and is stripped from the arguments", async () => {
  const { src, sid, store, call } = await fixture();
  const body = await call();
  const result = await claudeAttestationFor(body, desktopHeaders, auth, store);
  assert.deepEqual(result, { nativeSession: { kind: "claude", id: sid }, sourceId: src });
  assert.deepEqual(body.params.arguments, { to: "peer", text: "hi" });
  // A child credential bound to provider "claude" is managed too.
  assert.ok(await claudeAttestationFor(await call(), new Headers(), { ...auth, desktopMcpProvider: "claude" }, store));
});

test("a proof signed by another key, or claiming the registered kid, is refused", async () => {
  const { signer, store, call } = await fixture();
  await refused(claudeAttestationFor(await call({ signWith: await claudeSigner() }), desktopHeaders, auth, store), "unknown key");
  await refused(claudeAttestationFor(await call({ signWith: await claudeSigner(), kid: signer.kid }), desktopHeaders, auth, store), "bad signature");
});

test("a proof checked against another account, workspace or source finds no key", async () => {
  const { store, call } = await fixture();
  await refused(claudeAttestationFor(await call(), desktopHeaders, { ...auth, userId: "u2" }, store), "unknown key");
  await refused(claudeAttestationFor(await call(), desktopHeaders, { ...auth, workspaceId: "w2" }, store), "unknown key");
  await refused(claudeAttestationFor(await call({ src: randomUUID() }), desktopHeaders, auth, store), "unknown key");
});

test("a proof bound to another tool use or tool is refused", async () => {
  const { store, call } = await fixture();
  await refused(claudeAttestationFor(await call({ meta: toolUseId() }), desktopHeaders, auth, store), "tool use mismatch");
  const noMeta = await call();
  delete (noMeta.params as { _meta?: unknown })._meta;
  await refused(claudeAttestationFor(noMeta, desktopHeaders, auth, store), "tool use mismatch");
  const renamed = await call();
  renamed.params.name = "post_relay_channel";
  await refused(claudeAttestationFor(renamed, desktopHeaders, auth, store), "tool mismatch");
});

test("expired, long-lived and future proofs are refused", async () => {
  const { store, call } = await fixture();
  const now = Math.floor(Date.now() / 1000);
  await refused(claudeAttestationFor(await call({ iat: now - 120, exp: now - 60 }), desktopHeaders, auth, store), "expired");
  await refused(claudeAttestationFor(await call({ iat: now, exp: now + 61 }), desktopHeaders, auth, store), "lifetime out of range");
  // Well past the 30 s allowance: the verifier reads the clock again, and a
  // proof only one second over would pass when a second boundary falls between.
  await refused(claudeAttestationFor(await call({ iat: now + 40, exp: now + 70 }), desktopHeaders, auth, store), "issued in the future");
});

test("a replayed tool use is refused", async () => {
  const { store, call } = await fixture();
  const tuid = toolUseId();
  assert.ok(await claudeAttestationFor(await call({ tuid }), desktopHeaders, auth, store));
  await refused(claudeAttestationFor(await call({ tuid }), desktopHeaders, auth, store), "replayed tool use");
});

test("malformed, forged and wrong-shape proofs are refused", async () => {
  const { store, call, signer, src, sid } = await fixture();
  const garbage = await call();
  garbage.params.arguments[ATTESTATION_ARGUMENT] = "not-a-proof";
  await refused(claudeAttestationFor(garbage, desktopHeaders, auth, store), "proof is not a compact JWS");
  const forgedBody = await call();
  const [head, payload] = String(forgedBody.params.arguments[ATTESTATION_ARGUMENT]).split(".");
  forgedBody.params.arguments[ATTESTATION_ARGUMENT] = `${head}.${payload}.${Buffer.alloc(64, 1).toString("base64url")}`;
  await refused(claudeAttestationFor(forgedBody, desktopHeaders, auth, store), "bad signature");
  await refused(claudeAttestationFor(await call({ kind: "copilot" }), desktopHeaders, auth, store), "unexpected payload");
  await refused(claudeAttestationFor(await call({ extra: { workspace: "w1" } }), desktopHeaders, auth, store), "unexpected payload");
  await refused(claudeAttestationFor(await call({ sid: sid.toUpperCase() }), desktopHeaders, auth, store), "unexpected payload");
  await refused(verifyClaudeAttestation({ proof: await signer.sign({ tool: "t", src, sid, tuid: "has:colon" }),
    ...auth, toolUseId: "has:colon", toolName: "t" }, store), "unexpected payload");
});

test("a proof on another provider's credential or in a batch is refused, and still stripped", async () => {
  const { store, call } = await fixture();
  const codex = await call();
  await refused(claudeAttestationFor(codex, new Headers(), { ...auth, desktopMcpProvider: "codex" }, store), "provider mismatch");
  assert.equal(ATTESTATION_ARGUMENT in codex.params.arguments, false);
  const batch = [await call()];
  await refused(claudeAttestationFor(batch, desktopHeaders, auth, store), "batched proof");
  assert.equal(ATTESTATION_ARGUMENT in batch[0]!.params.arguments, false);
});

test("outside desktop management a proof is stripped and ignored; no proof yields nothing", async () => {
  const { store, call } = await fixture();
  const plain = await call();
  assert.equal(await claudeAttestationFor(plain, new Headers(), auth, store), undefined);
  assert.equal(ATTESTATION_ARGUMENT in plain.params.arguments, false);
  assert.equal(store.spent.size, 0);
  const unproven = { method: "tools/call", params: { name: "send_relay_message", arguments: { text: "hi" } } };
  assert.equal(await claudeAttestationFor(unproven, desktopHeaders, auth, store), undefined);
});

test("an uppercase source id resolves to the lowercase source identity sync stored", async () => {
  const { src, sid, store, call } = await fixture();
  const result = await claudeAttestationFor(await call({ src: src.toUpperCase() }), desktopHeaders, auth, store);
  assert.deepEqual(result, { nativeSession: { kind: "claude", id: sid }, sourceId: src });
});

test("Cursor replay keys cannot collide across source/ticket pairs that share a `:` join", async () => {
  // Source `desk` + ticket `one:two` and source `desk:one` + ticket `two` are distinct calls.
  const signer = await claudeSigner();
  const sid = randomUUID();
  const store = memoryStore({
    [`${auth.workspaceId}/${auth.userId}/desk/${signer.kid}`]: signer.publicKey,
    [`${auth.workspaceId}/${auth.userId}/desk:one/${signer.kid}`]: signer.publicKey,
  });
  const args = { to: "peer", text: "hi" };
  for (const [src, tuid] of [["desk", "one:two"], ["desk:one", "two"]] as const) {
    const proof = await signer.sign({ kind: "cursor", tool: "send_relay_message", src, sid, tuid, extra: { args } });
    const result = await verifyClaudeAttestation({ proof, ...auth, toolUseId: undefined, toolName: "send_relay_message",
      args, provider: "cursor" }, store);
    assert.deepEqual(result, { nativeSession: { kind: "cursor", id: sid }, sourceId: src });
  }
  assert.equal(store.spent.size, 2);
});

// The handoff: Desktop posts the hook's proof ahead of the call (so the hook
// never rewrites input) and the route takes it by _meta claudecode/toolUseId.

function memoryHandoffs(): ClaudeHandoffStore & { rows: Map<string, string> } {
  const rows = new Map<string, string>();
  const key = (input: { workspaceId: string; userId: string; toolUseId: string }) =>
    `${input.workspaceId}/${input.userId}/${input.toolUseId}`;
  return {
    rows,
    async put(input) {
      const stored = rows.get(key(input));
      if (stored !== undefined) return stored === input.proof ? "exists" : "conflict";
      rows.set(key(input), input.proof);
      return "stored";
    },
    async take(input) {
      const stored = rows.get(key(input)) ?? null;
      rows.delete(key(input));
      return stored;
    },
  };
}

/** Hands a proof off for `tuid` and returns the unchanged call Claude Code then sends. */
async function handedOff(fixtureValue: Awaited<ReturnType<typeof fixture>>, handoffs: ClaudeHandoffStore,
  overrides: { tuid?: string; tool?: string; callTool?: string } = {}) {
  const { signer, src, sid, store } = fixtureValue;
  const tuid = overrides.tuid ?? toolUseId();
  const tool = overrides.tool ?? "send_relay_message";
  const proof = await signer.sign({ tool, src, sid, tuid });
  const verified = await verifyClaudeHandoff({ proof, ...auth }, store);
  assert.equal(verified.toolUseId, tuid);
  await handoffs.put({ ...auth, toolUseId: tuid, proof, expiresAt: verified.expiresAt });
  return {
    jsonrpc: "2.0", id: 1, method: "tools/call",
    params: { name: overrides.callTool ?? tool, arguments: { to: "peer", text: "hi" }, _meta: { [CLAUDE_TOOL_USE_META]: tuid } },
  };
}

test("a handed-off proof verifies the call with the matching claudecode/toolUseId; the call is unchanged", async () => {
  const value = await fixture();
  const handoffs = memoryHandoffs();
  const body = await handedOff(value, handoffs);
  const result = await claudeAttestationFor(body, desktopHeaders, auth, value.store, undefined, handoffs);
  assert.deepEqual(result, { nativeSession: { kind: "claude", id: value.sid }, sourceId: value.src });
  assert.deepEqual(body.params.arguments, { to: "peer", text: "hi" });
  assert.equal(handoffs.rows.size, 0, "the handoff was taken");
  assert.equal(value.store.spent.size, 1, "the tool use was spent");
  // A child credential bound to provider "claude" takes a handoff too.
  const child = await handedOff(value, handoffs);
  assert.ok(await claudeAttestationFor(child, new Headers(), { ...auth, desktopMcpProvider: "claude" }, value.store, undefined, handoffs));
});

test("a handed-off proof is used once: a repeat call has no attestation, a re-handed-off spent proof is refused", async () => {
  const value = await fixture();
  const handoffs = memoryHandoffs();
  const tuid = toolUseId();
  const body = await handedOff(value, handoffs, { tuid });
  assert.ok(await claudeAttestationFor(structuredClone(body), desktopHeaders, auth, value.store, undefined, handoffs));
  assert.equal(await claudeAttestationFor(structuredClone(body), desktopHeaders, auth, value.store, undefined, handoffs), undefined);
  await handedOff(value, handoffs, { tuid });
  await refused(claudeAttestationFor(body, desktopHeaders, auth, value.store, undefined, handoffs), "replayed tool use");
});

test("a handed-off proof for another tool is refused at the call", async () => {
  const value = await fixture();
  const handoffs = memoryHandoffs();
  const body = await handedOff(value, handoffs, { tool: "relay_status", callTool: "send_relay_message" });
  await refused(claudeAttestationFor(body, desktopHeaders, auth, value.store, undefined, handoffs), "tool mismatch");
});

test("Cursor and Copilot credentials, unmanaged calls, batches and malformed tool use ids never take a handoff", async () => {
  const value = await fixture();
  const handoffs = memoryHandoffs();
  const body = await handedOff(value, handoffs);
  for (const provider of ["cursor", "copilot"]) {
    assert.equal(await claudeAttestationFor(structuredClone(body), new Headers(), { ...auth, desktopMcpProvider: provider },
      value.store, undefined, handoffs), undefined, provider);
  }
  assert.equal(await claudeAttestationFor(structuredClone(body), new Headers(), auth, value.store, undefined, handoffs), undefined);
  assert.equal(await claudeAttestationFor([structuredClone(body)], desktopHeaders, auth, value.store, undefined, handoffs), undefined);
  const odd = structuredClone(body);
  (odd.params._meta as Record<string, unknown>)[CLAUDE_TOOL_USE_META] = "has:colon";
  assert.equal(await claudeAttestationFor(odd, desktopHeaders, auth, value.store, undefined, handoffs), undefined);
  for (const other of [null, "x", { method: "tools/list" }, { method: "tools/call" }, { method: "tools/call", params: { _meta: null } }]) {
    assert.equal(await claudeAttestationFor(other, desktopHeaders, auth, value.store, undefined, handoffs), undefined);
  }
  assert.equal(handoffs.rows.size, 1, "the handoff is still there");
  assert.equal(value.store.spent.size, 0);
});

test("an in-argument proof still wins when handoffs are available", async () => {
  const value = await fixture();
  const handoffs = memoryHandoffs();
  const body = await value.call();
  assert.ok(await claudeAttestationFor(body, desktopHeaders, auth, value.store, undefined, handoffs));
  assert.deepEqual(body.params.arguments, { to: "peer", text: "hi" });
});

test("a handoff is checked for format, kind, key, signature and lifetime, but not bound or spent", async () => {
  const { signer, src, sid, store } = await fixture();
  const tuid = toolUseId();
  const proof = await signer.sign({ tool: "send_relay_message", src, sid, tuid });
  const verified = await verifyClaudeHandoff({ proof, ...auth }, store);
  assert.equal(verified.toolUseId, tuid);
  assert.equal(store.spent.size, 0);
  await refused(verifyClaudeHandoff({ proof: await (await claudeSigner()).sign({ tool: "t", src, sid, tuid }), ...auth }, store), "unknown key");
  const [head, payload] = proof.split(".");
  await refused(verifyClaudeHandoff({ proof: `${head}.${payload}.${Buffer.alloc(64, 1).toString("base64url")}`, ...auth }, store), "bad signature");
  await refused(verifyClaudeHandoff({ proof: "not-a-proof", ...auth }, store), "proof is not a compact JWS");
  await refused(verifyClaudeHandoff({ proof: await signer.sign({ kind: "cursor", tool: "t", src, sid, tuid, extra: { args: {} } }), ...auth }, store),
    "provider mismatch");
  const now = Math.floor(Date.now() / 1000);
  await refused(verifyClaudeHandoff({ proof: await signer.sign({ tool: "t", src, sid, tuid, iat: now - 120, exp: now - 60 }), ...auth }, store), "expired");
  await refused(verifyClaudeHandoff({ proof, ...auth, userId: "u2" }, store), "unknown key");
});
