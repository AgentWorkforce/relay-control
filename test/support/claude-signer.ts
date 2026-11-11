import { randomBytes, webcrypto } from "node:crypto";
import { attestationKeyId } from "../../src/mcp/copilot-attestation.js";

/**
 * A disposable Desktop Claude Code signer for tests: the JWS the Desktop
 * PreToolUse hook produces (relay-desktop desktop-core/src/claude_attestation.rs):
 * header {alg, kid, typ}, payload {v, kind, sid, src, tuid, tool, iat, exp}.
 */
export async function claudeSigner() {
  const pair = await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]) as webcrypto.CryptoKeyPair;
  const raw = new Uint8Array(await webcrypto.subtle.exportKey("raw", pair.publicKey));
  const publicKey = Buffer.from(raw).toString("base64url");
  const kid = attestationKeyId(raw);
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return {
    publicKey,
    kid,
    async sign(input: {
      tool: string; src: string; sid: string; tuid: string;
      iat?: number; exp?: number; kid?: string; kind?: string; extra?: Record<string, unknown>;
    }): Promise<string> {
      const iat = input.iat ?? Math.floor(Date.now() / 1000);
      const head = encode({ alg: "EdDSA", kid: input.kid ?? kid, typ: "agent-relay-attest+jws" });
      const payload = encode({
        v: 1, kind: input.kind ?? "claude", sid: input.sid, src: input.src, tuid: input.tuid, tool: input.tool,
        iat, exp: input.exp ?? iat + 60, ...input.extra,
      });
      const signature = await webcrypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, new TextEncoder().encode(`${head}.${payload}`));
      return `${head}.${payload}.${Buffer.from(signature).toString("base64url")}`;
    },
  };
}

/** A Claude Code tool-use id (`toolu_` plus random base64url). */
export const toolUseId = () => `toolu_${randomBytes(12).toString("base64url")}`;
