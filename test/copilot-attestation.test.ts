import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { randomUUID } from "node:crypto";
import test from "node:test";
import {
  ATTESTATION_ARGUMENT, attestationKeyId, copilotAttestationFor, CopilotAttestationError, decodeBase64Url,
  type AttestationStore,
} from "../src/mcp/copilot-attestation.js";
import { copilotSigner } from "./support/copilot-signer.js";

// Requirement (3): Ed25519 Copilot attestation over tool, args, user,
// workspace, source, sid and nonce; <=60 s; nonce spent once; stripped.

const fixture = JSON.parse(readFileSync(new URL("./fixtures/copilot-desktop-proof.json", import.meta.url), "utf8"));

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

function fixtureCall(args: Record<string, unknown> = fixture.args, proof: unknown = fixture.proof) {
  return { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "send_relay_message", arguments: { ...structuredClone(args), [ATTESTATION_ARGUMENT]: proof } } };
}

function fixtureStore() {
  const kid = attestationKeyId(decodeBase64Url(fixture.publicKey)!);
  return memoryStore({ [`${fixture.auth.workspaceId}/${fixture.auth.userId}/${fixture.sourceId}/${kid}`]: fixture.publicKey });
}

async function refused(promise: Promise<unknown>, reason: string) {
  await assert.rejects(promise, (error: unknown) => error instanceof CopilotAttestationError && error.reason === reason);
}

test("the Desktop-generated fixture proof verifies and is stripped from the arguments", async () => {
  const body = fixtureCall();
  const result = await copilotAttestationFor(body, fixture.auth, fixtureStore(), fixture.nowMs);
  assert.deepEqual(result, { nativeSession: { kind: "copilot", id: fixture.sessionId }, sourceId: fixture.sourceId });
  assert.equal(ATTESTATION_ARGUMENT in body.params.arguments, false);
  assert.deepEqual(body.params.arguments, fixture.args);
});

test("a proof checked against a different registered key is refused", async () => {
  const other = await copilotSigner();
  const kid = attestationKeyId(decodeBase64Url(fixture.publicKey)!);
  const store = memoryStore({ [`${fixture.auth.workspaceId}/${fixture.auth.userId}/${fixture.sourceId}/${kid}`]: other.publicKey });
  await refused(copilotAttestationFor(fixtureCall(), fixture.auth, store, fixture.nowMs), "unknown key");
  // A key registered under the proof's kid but by a different owner is never consulted.
  await refused(copilotAttestationFor(fixtureCall(), { ...fixture.auth, userId: "bob" }, fixtureStore(), fixture.nowMs), "owner mismatch");
});

test("a stale proof is refused once its 60 second lifetime has passed", async () => {
  await refused(copilotAttestationFor(fixtureCall(), fixture.auth, fixtureStore(), fixture.nowMs + 61_000), "invalid lifetime");
  const signer = await copilotSigner();
  const src = randomUUID();
  const store = memoryStore({ [`w/u/${src}/${signer.kid}`]: signer.publicKey });
  const now = Math.floor(Date.now() / 1000);
  const longLived = await signer.sign({ tool: "t", args: {}, user: "u", workspace: "w", src, sid: randomUUID(), iat: now, exp: now + 61 });
  await refused(copilotAttestationFor(
    { method: "tools/call", params: { name: "t", arguments: { [ATTESTATION_ARGUMENT]: longLived } } },
    { workspaceId: "w", userId: "u", desktopMcpProvider: "copilot" }, store), "invalid lifetime");
});

test("a replayed nonce is refused", async () => {
  const store = fixtureStore();
  assert.ok(await copilotAttestationFor(fixtureCall(), fixture.auth, store, fixture.nowMs));
  await refused(copilotAttestationFor(fixtureCall(), fixture.auth, store, fixture.nowMs), "replayed proof");
});

test("arguments or tool that differ from the signed call are refused", async () => {
  await refused(copilotAttestationFor(fixtureCall({ ...fixture.args, text: "something else" }), fixture.auth, fixtureStore(), fixture.nowMs), "call mismatch");
  const renamed = fixtureCall();
  renamed.params.name = "post_relay_channel";
  await refused(copilotAttestationFor(renamed, fixture.auth, fixtureStore(), fixture.nowMs), "call mismatch");
});

test("a proof for another workspace is refused", async () => {
  await refused(copilotAttestationFor(fixtureCall(), { ...fixture.auth, workspaceId: "elsewhere" }, fixtureStore(), fixture.nowMs), "owner mismatch");
});

test("a proof on a non-Copilot connection, a batch or a malformed proof is refused, and still stripped", async () => {
  const plain = fixtureCall();
  await refused(copilotAttestationFor(plain, { workspaceId: fixture.auth.workspaceId, userId: fixture.auth.userId }, fixtureStore(), fixture.nowMs), "provider mismatch");
  assert.equal(ATTESTATION_ARGUMENT in plain.params.arguments, false);
  const batch = [fixtureCall()];
  await refused(copilotAttestationFor(batch, fixture.auth, fixtureStore(), fixture.nowMs), "batched proof");
  assert.equal(ATTESTATION_ARGUMENT in batch[0]!.params.arguments, false);
  await refused(copilotAttestationFor(fixtureCall(fixture.args, "not-a-proof"), fixture.auth, fixtureStore(), fixture.nowMs), "invalid proof");
  // A forged signature over the genuine claims.
  const [head, payload] = (fixture.proof as string).split(".");
  const forged = `${head}.${payload}.${Buffer.alloc(64, 1).toString("base64url")}`;
  await refused(copilotAttestationFor(fixtureCall(fixture.args, forged), fixture.auth, fixtureStore(), fixture.nowMs), "bad signature");
});

test("a call without a proof yields no attestation (the route then refuses Copilot chat context)", async () => {
  const body = { method: "tools/call", params: { name: "send_relay_message", arguments: { text: "hi" } } };
  assert.equal(await copilotAttestationFor(body, fixture.auth, fixtureStore(), fixture.nowMs), undefined);
});
