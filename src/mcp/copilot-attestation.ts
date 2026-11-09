import { createHash, webcrypto } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import type { SqlExecutor } from "../database.js";

/**
 * Copilot tool-call attestation, ported verbatim from Cloud's
 * `packages/web/lib/mcp/copilot-attestation.ts` (and the shared helpers in
 * `claude-attestation.ts`).
 *
 * Copilot supplies no native chat or tool-use id in MCP metadata. Agent Relay
 * Desktop's trusted PreToolUse hook inserts `_agent_relay_attestation` after
 * the model chose the arguments: an Ed25519 JWS over the exact tool and
 * arguments, the user, workspace, Desktop source, verified native chat id and
 * a fresh nonce. The proof is stripped before dispatch, lives at most 60
 * seconds and its nonce is spent once. An MCP session id, API key or model
 * name is never proof of a chat.
 */

export const COPILOT_ATTESTATION_CAPABILITY = "com.agentrelay/copilot-session-attestation";
export const ATTESTATION_ARGUMENT = "_agent_relay_attestation";
export const ATTESTATION_TYPE = "agent-relay-attest+jws";

export class CopilotAttestationError extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = "CopilotAttestationError";
  }
}

export type AttestationStore = {
  /** The base64url raw Ed25519 key this owner's Desktop source registered under `kid`, or null. */
  publicKey(input: { workspaceId: string; userId: string; sourceId: string; kid: string }): Promise<string | null>;
  /** Records a proof nonce; false when it was already spent. */
  spend(input: { workspaceId: string; userId: string; toolUseId: string; expiresAt: Date }): Promise<boolean>;
};

export type CopilotAttestation = { nativeSession: { kind: "copilot"; id: string }; sourceId: string };

const BASE64URL = /^[A-Za-z0-9_-]+$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const fail = (reason: string): never => { throw new CopilotAttestationError(reason); };
const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/** Strict, canonical base64url (no padding); null for anything else. */
export function decodeBase64Url(value: string): Uint8Array | null {
  if (!BASE64URL.test(value)) return null;
  const bytes = Buffer.from(value, "base64url");
  return bytes.toString("base64url") === value ? new Uint8Array(bytes) : null;
}

/** base64url (no padding) of the first 16 bytes of SHA-256(raw public key). */
export function attestationKeyId(rawPublicKey: Uint8Array): string {
  return createHash("sha256").update(rawPublicKey).digest().subarray(0, 16).toString("base64url");
}

function decode(segment: string): Record<string, unknown> {
  const bytes = decodeBase64Url(segment);
  if (!bytes) return fail("malformed segment");
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return fail("malformed segment");
  }
  if (!object(value)) return fail("malformed segment");
  return value;
}

function exact(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every(key => Object.prototype.hasOwnProperty.call(value, key));
}

/**
 * Verifies and strips the proof of one tools/call. Returns undefined when the
 * call carries no proof (and is not a batch); throws CopilotAttestationError
 * for any proof that does not verify. The proof is removed from `body` in
 * every case, before anything else can read the arguments.
 */
export async function copilotAttestationFor(body: unknown, auth: {
  workspaceId: string;
  userId: string;
  desktopMcpProvider?: string;
}, store: AttestationStore, nowMs = Date.now()): Promise<CopilotAttestation | undefined> {
  if (Array.isArray(body)) {
    for (const item of body) {
      if (object(item) && object(item.params) && object(item.params.arguments)) delete item.params.arguments[ATTESTATION_ARGUMENT];
    }
    return fail("batched proof");
  }
  if (!object(body) || body.method !== "tools/call" || !object(body.params) || !object(body.params.arguments)) return undefined;
  const args = body.params.arguments;
  const proof = args[ATTESTATION_ARGUMENT];
  delete args[ATTESTATION_ARGUMENT];
  if (proof === undefined) return undefined;
  if (auth.desktopMcpProvider !== "copilot") return fail("provider mismatch");
  if (typeof proof !== "string" || proof.length > 96 * 1024) return fail("invalid proof");
  const parts = proof.split(".");
  if (parts.length !== 3) return fail("invalid proof");
  const [head, payload, sig] = parts as [string, string, string];
  const header = decode(head);
  const claims = decode(payload);
  if (!exact(header, ["alg", "kid", "typ"]) || header.alg !== "EdDSA" || header.typ !== ATTESTATION_TYPE ||
      typeof header.kid !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(header.kid)) return fail("unexpected header");
  if (!exact(claims, ["v", "kind", "sid", "src", "workspace", "user", "nonce", "tool", "args", "iat", "exp"]) ||
      claims.v !== 1 || claims.kind !== "copilot" ||
      typeof claims.sid !== "string" || !UUID.test(claims.sid) || typeof claims.src !== "string" || !UUID.test(claims.src) ||
      typeof claims.nonce !== "string" || !/^[A-Za-z0-9_-]{22}$/.test(claims.nonce) ||
      typeof claims.tool !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(claims.tool) ||
      !object(claims.args) || !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp)) return fail("unexpected payload");
  if (claims.workspace !== auth.workspaceId || claims.user !== auth.userId) return fail("owner mismatch");
  if (claims.tool !== body.params.name || !isDeepStrictEqual(claims.args, args)) return fail("call mismatch");
  const iat = claims.iat as number;
  const exp = claims.exp as number;
  const now = Math.floor(nowMs / 1000);
  if (iat < 0 || exp < iat || exp - iat > 60 || now > exp || iat > now + 30) return fail("invalid lifetime");
  const signature = decodeBase64Url(sig);
  if (!signature || signature.byteLength !== 64) return fail("invalid signature");
  const publicKey = await store.publicKey({ workspaceId: auth.workspaceId, userId: auth.userId, sourceId: claims.src, kid: header.kid });
  const raw = publicKey === null ? null : decodeBase64Url(publicKey);
  if (!raw || raw.byteLength !== 32 || attestationKeyId(raw) !== header.kid) return fail("unknown key");
  const key = await webcrypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
  if (!await webcrypto.subtle.verify({ name: "Ed25519" }, key, signature, new TextEncoder().encode(`${head}.${payload}`))) {
    return fail("bad signature");
  }
  if (!await store.spend({
    workspaceId: auth.workspaceId,
    userId: auth.userId,
    toolUseId: `copilot:${claims.src}:${claims.nonce}`,
    expiresAt: new Date((exp + 120) * 1000),
  })) return fail("replayed proof");
  return { nativeSession: { kind: "copilot", id: claims.sid }, sourceId: claims.src };
}

/**
 * The shared key and nonce store: desktop_attestation_keys and
 * mcp_attestation_tool_uses (migration 0020). Every replica reads
 * the same rows, so a nonce spent on one is spent on all.
 */
export function postgresAttestationStore(database: SqlExecutor): AttestationStore {
  return {
    async publicKey(input) {
      const result = await database.query<{ public_key: string }>(
        `SELECT public_key FROM desktop_attestation_keys
          WHERE workspace_id = $1 AND user_id = $2 AND source_id = $3 AND kid = $4`,
        [input.workspaceId, input.userId, input.sourceId, input.kid],
      );
      return result.rows[0]?.public_key ?? null;
    },
    async spend(input) {
      await database.query(
        `DELETE FROM mcp_attestation_tool_uses
          WHERE expires_at <= now() AND workspace_id = $1 AND user_id = $2`,
        [input.workspaceId, input.userId],
      );
      const result = await database.query<{ tool_use_id: string }>(
        `INSERT INTO mcp_attestation_tool_uses (workspace_id, user_id, tool_use_id, expires_at)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (workspace_id, user_id, tool_use_id) DO NOTHING
         RETURNING tool_use_id`,
        [input.workspaceId, input.userId, input.toolUseId, input.expiresAt],
      );
      return result.rows.length === 1;
    },
  };
}
