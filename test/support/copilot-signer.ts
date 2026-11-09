import { randomBytes, randomUUID, webcrypto } from "node:crypto";
import { attestationKeyId } from "../../src/mcp/copilot-attestation.js";

/**
 * A disposable Desktop Copilot signer for tests: the same JWS shape the
 * Desktop PreToolUse hook produces (see test/fixtures/copilot-desktop-proof.json).
 */
export async function copilotSigner() {
  const pair = await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as webcrypto.CryptoKeyPair;
  const raw = new Uint8Array(await webcrypto.subtle.exportKey("raw", pair.publicKey));
  const publicKey = Buffer.from(raw).toString("base64url");
  const kid = attestationKeyId(raw);
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return {
    publicKey,
    kid,
    async sign(input: {
      tool: string; args: Record<string, unknown>; user: string; workspace: string; src: string; sid: string;
      nonce?: string; iat?: number; exp?: number; kid?: string;
    }): Promise<string> {
      const iat = input.iat ?? Math.floor(Date.now() / 1000);
      const head = encode({ alg: "EdDSA", kid: input.kid ?? kid, typ: "agent-relay-attest+jws" });
      const payload = encode({
        v: 1, kind: "copilot", sid: input.sid, src: input.src, workspace: input.workspace, user: input.user,
        nonce: input.nonce ?? randomBytes(16).toString("base64url"), tool: input.tool, args: input.args,
        iat, exp: input.exp ?? iat + 60,
      });
      const signature = await webcrypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, new TextEncoder().encode(`${head}.${payload}`));
      return `${head}.${payload}.${Buffer.from(signature).toString("base64url")}`;
    },
  };
}

export const newId = () => randomUUID();
