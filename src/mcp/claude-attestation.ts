import { webcrypto } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { normalizeDesktopSourceId } from "../desktop-source-id.js";
import {
  ATTESTATION_ARGUMENT, ATTESTATION_TYPE, attestationKeyId, decodeBase64Url, type AttestationStore,
} from "./copilot-attestation.js";

/**
 * Claude Code per-call chat identity, ported from Cloud's
 * `packages/web/lib/mcp/claude-attestation.ts`.
 *
 * Claude Code has no client-injected native chat field, so Agent Relay
 * Desktop's PreToolUse hook signs one per call: an Ed25519 JWS over the hook's
 * `session_id` (the chat), `tool_use_id`, the MCP tool name and the Desktop
 * source, with the key that source registered at identity sync. Claude Code
 * itself sends the same tool-use id as `params._meta["claudecode/toolUseId"]`,
 * which the model cannot set, so a proof binds to exactly one real tool call.
 * The proof is stripped before dispatch, lives at most 60 seconds and its
 * tool-use id is spent once. An MCP session id is never proof of a chat.
 *
 * Keys and spent ids share the Copilot store (desktop_attestation_keys and
 * mcp_attestation_tool_uses, migration 0020). Copilot nonces are stored as
 * `copilot:<src>:<nonce>`; a Claude tool-use id cannot contain `:`, so the two
 * never collide.
 *
 * Cursor chats use the same proof and path with `kind: "cursor"` (Cloud's
 * contract, docs/hosted-mcp-native-session-identity.md there). Cursor's
 * `beforeMCPExecution` hook can only allow or deny, so Agent Relay Desktop
 * points Cursor at its own stdio helper (`agent-relay-probe cursor-mcp`), which
 * attaches the proof and forwards the call. Cursor sends no per-call metadata
 * to check `tuid` against, so the hook's tool_use_id is only single-use, spent
 * as `cursor:<src>:<tuid>`, and the proof signs the exact forwarded `args`,
 * which must equal the call's arguments.
 */

export const CLAUDE_ATTESTATION_CAPABILITY = "com.agentrelay/claude-session-attestation";
export const CURSOR_ATTESTATION_CAPABILITY = "com.agentrelay/cursor-session-attestation";
export const CLAUDE_TOOL_USE_META = "claudecode/toolUseId";
export const CLAUDE_ATTESTATION_MAX_LIFETIME_SECONDS = 60;
export const CLAUDE_ATTESTATION_MAX_FUTURE_SKEW_SECONDS = 30;
/** Spent tool-use ids outlive their proof so instance clock skew cannot reopen them. */
export const CLAUDE_ATTESTATION_SPENT_RETENTION_SECONDS = 120;
/** A Cursor proof signs the forwarded arguments, so it may be as large as a Copilot proof. */
export const CURSOR_ATTESTATION_MAX_PROOF_BYTES = 96 * 1024;

export class ClaudeAttestationError extends Error {
  constructor(readonly reason: string) {
    super(reason);
    this.name = "ClaudeAttestationError";
  }
}

export type AttestedKind = "claude" | "cursor";
export type ClaudeAttestation = { nativeSession: { kind: AttestedKind; id: string }; sourceId: string };

const UUID_LOWER = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const KID = /^[A-Za-z0-9_-]{22}$/;
const TOOL_USE_ID = /^[A-Za-z0-9_-]{1,200}$/;
/** Cursor's per-call tool_use_id, issued to the proof by Desktop (it may contain `:`, so it is namespaced when spent). */
const CURSOR_TICKET = /^[A-Za-z0-9_.:-]{1,256}$/;
const CLAUDE_CLAIMS = ["v", "kind", "sid", "src", "tuid", "tool", "iat", "exp"];
const TOOL_NAME = /^[A-Za-z0-9_.-]{1,128}$/;

const fail = (reason: string): never => { throw new ClaudeAttestationError(reason); };
const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

function decodeJson(segment: string): Record<string, unknown> {
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

function hasExactKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every(key => Object.prototype.hasOwnProperty.call(value, key));
}

/**
 * Verifies one Claude Code or Cursor call proof. Every failure throws; success
 * yields the signed native chat and the Desktop source whose key signed it.
 * The tool-use id (Cursor: ticket) is spent only after the signature verifies.
 *
 * `provider` is the Desktop provider bound to the credential, when there is
 * one: the proof's kind must then equal it. `args` are the call's arguments
 * with the proof already removed; a Cursor proof's `args` must match them
 * exactly (JSON structural equality).
 */
export async function verifyClaudeAttestation(input: {
  proof: unknown;
  workspaceId: string;
  userId: string;
  toolUseId: unknown;
  toolName: unknown;
  args?: unknown;
  provider?: string;
  nowMs?: number;
}, store: AttestationStore): Promise<ClaudeAttestation> {
  if (typeof input.proof !== "string" || input.proof.length > CURSOR_ATTESTATION_MAX_PROOF_BYTES) {
    return fail("proof is not a compact JWS");
  }
  const parts = input.proof.split(".");
  if (parts.length !== 3) return fail("proof is not a compact JWS");
  const [headerSegment, payloadSegment, signatureSegment] = parts as [string, string, string];

  const header = decodeJson(headerSegment);
  if (!hasExactKeys(header, ["alg", "kid", "typ"]) || header.alg !== "EdDSA" ||
      header.typ !== ATTESTATION_TYPE || typeof header.kid !== "string" || !KID.test(header.kid)) {
    return fail("unexpected header");
  }
  const payload = decodeJson(payloadSegment);
  const kind = payload.kind;
  if (kind !== "claude" && kind !== "cursor") return fail("unexpected payload");
  // A credential bound to one provider only accepts that provider's proofs.
  if (input.provider !== undefined && input.provider !== kind) return fail("provider mismatch");
  // Claude's proof is small and never signs arguments; a Cursor proof always signs them.
  if (kind === "claude" && input.proof.length > 4096) return fail("proof is not a compact JWS");
  // A Cursor proof always signs the forwarded arguments: its ticket binds to nothing Cursor sends.
  const signsArgs = kind === "cursor";
  const claims = signsArgs ? [...CLAUDE_CLAIMS.slice(0, 6), "args", ...CLAUDE_CLAIMS.slice(6)] : CLAUDE_CLAIMS;
  if (!hasExactKeys(payload, claims) || payload.v !== 1 ||
      typeof payload.sid !== "string" || !UUID_LOWER.test(payload.sid) ||
      typeof payload.src !== "string" || payload.src.length < 1 || payload.src.length > 200 ||
      typeof payload.tuid !== "string" || !(kind === "claude" ? TOOL_USE_ID : CURSOR_TICKET).test(payload.tuid) ||
      (signsArgs && !object(payload.args)) ||
      typeof payload.tool !== "string" || !TOOL_NAME.test(payload.tool) ||
      !Number.isSafeInteger(payload.iat) || !Number.isSafeInteger(payload.exp)) {
    return fail("unexpected payload");
  }
  const { sid, tuid, tool } = payload as { sid: string; tuid: string; tool: string };
  const src = normalizeDesktopSourceId(payload.src as string);
  const iat = payload.iat as number;
  const exp = payload.exp as number;

  // Claude Code's own call metadata, not anything the model wrote. Cursor
  // sends none, so its ticket is only a single-use nonce.
  if (kind === "claude" && (typeof input.toolUseId !== "string" || tuid !== input.toolUseId)) return fail("tool use mismatch");
  if (typeof input.toolName !== "string" || tool !== input.toolName) return fail("tool mismatch");
  if (signsArgs && !isDeepStrictEqual(payload.args, input.args)) return fail("arguments mismatch");

  const now = Math.floor((input.nowMs ?? Date.now()) / 1000);
  if (exp < iat || exp - iat > CLAUDE_ATTESTATION_MAX_LIFETIME_SECONDS) return fail("lifetime out of range");
  if (now > exp) return fail("expired");
  if (iat > now + CLAUDE_ATTESTATION_MAX_FUTURE_SKEW_SECONDS) return fail("issued in the future");

  const signature = decodeBase64Url(signatureSegment);
  if (!signature || signature.byteLength !== 64) return fail("malformed signature");

  const encodedKey = await store.publicKey({
    workspaceId: input.workspaceId, userId: input.userId, sourceId: src, kid: header.kid as string,
  });
  const rawKey = encodedKey === null ? null : decodeBase64Url(encodedKey);
  if (!rawKey || rawKey.byteLength !== 32 || attestationKeyId(rawKey) !== header.kid) return fail("unknown key");

  const key = await webcrypto.subtle.importKey("raw", rawKey, { name: "Ed25519" }, false, ["verify"]);
  const signed = new TextEncoder().encode(`${headerSegment}.${payloadSegment}`);
  if (!await webcrypto.subtle.verify({ name: "Ed25519" }, key, signature, signed)) return fail("bad signature");

  const spent = await store.spend({
    workspaceId: input.workspaceId, userId: input.userId, toolUseId: kind === "claude" ? tuid : `cursor:${src}:${tuid}`,
    expiresAt: new Date((exp + CLAUDE_ATTESTATION_SPENT_RETENTION_SECONDS) * 1000),
  });
  if (!spent) return fail("replayed tool use");
  return { nativeSession: { kind, id: sid }, sourceId: src };
}

type ToolCallRequest = { method?: unknown; params?: { name?: unknown; arguments?: unknown; _meta?: Record<string, unknown> } };

function takeProof(message: unknown): { present: boolean; proof?: unknown } {
  const request = message as ToolCallRequest | null;
  if (!object(request) || request.method !== "tools/call") return { present: false };
  const args = request.params?.arguments;
  if (!object(args) || !Object.prototype.hasOwnProperty.call(args, ATTESTATION_ARGUMENT)) return { present: false };
  const proof = args[ATTESTATION_ARGUMENT];
  delete args[ATTESTATION_ARGUMENT];
  return { present: true, proof };
}

/**
 * Removes the proof from the parsed request in place, so no tool ever sees or
 * echoes it, then verifies it when this is a desktop-managed Claude Code or
 * Cursor call.
 * Returns no attestation when the request carries no proof, or carries one on
 * a call outside desktop management (stripped and ignored). Throws when a
 * proof fails, is batched, or arrives on a credential bound to another
 * provider.
 */
export async function claudeAttestationFor(body: unknown, headers: Headers, auth: {
  workspaceId: string;
  userId: string;
  desktopMcpProvider?: string;
}, store: AttestationStore, nowMs?: number): Promise<ClaudeAttestation | undefined> {
  if (Array.isArray(body)) {
    const present = body.map(takeProof).some(result => result.present);
    if (present) return fail("batched proof");
    return undefined;
  }
  const taken = takeProof(body);
  if (!taken.present) return undefined;
  const managed = auth.desktopMcpProvider !== undefined || headers.get("x-agent-relay-desktop") === "1";
  if (!managed) return undefined;
  const provider = auth.desktopMcpProvider;
  if (provider !== undefined && provider !== "claude" && provider !== "cursor") return fail("provider mismatch");
  const params = (body as ToolCallRequest).params;
  return verifyClaudeAttestation({
    proof: taken.proof, workspaceId: auth.workspaceId, userId: auth.userId,
    toolUseId: params?._meta?.[CLAUDE_TOOL_USE_META], toolName: params?.name, args: params?.arguments, provider, nowMs,
  }, store);
}
