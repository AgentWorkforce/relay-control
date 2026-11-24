import { webcrypto } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import type { SqlExecutor } from "../database.js";
import { normalizeDesktopSourceId } from "../desktop-source-id.js";
import { nativeContextRefusalReason } from "./native-context-refusal.js";
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
 * Claude Code's auto mode refuses any call whose input a hook rewrote, so
 * Desktop may instead hand the proof off ahead of the call (POST
 * .../messaging/desktop-identities/attestations, kept in
 * mcp_attestation_handoffs, migration 0097) and send the call unchanged; the
 * route takes it by the call's `claudecode/toolUseId`.
 *
 * Cursor chats use the same proof and path with `kind: "cursor"` (Cloud's
 * contract, docs/hosted-mcp-native-session-identity.md there). Cursor's
 * `beforeMCPExecution` hook can only allow or deny, so Agent Relay Desktop
 * points Cursor at its own stdio helper (`agent-relay-probe cursor-mcp`), which
 * attaches the proof and forwards the call. Cursor sends no per-call metadata
 * to check `tuid` against, so the hook's tool_use_id is only single-use, spent
 * once per source (`cursor:["<src>","<tuid>"]`), and the proof signs the exact forwarded `args`,
 * which must equal the call's arguments.
 */

export const CLAUDE_ATTESTATION_CAPABILITY = "com.agentrelay/claude-session-attestation";
export const CURSOR_ATTESTATION_CAPABILITY = "com.agentrelay/cursor-session-attestation";
export const CLAUDE_TOOL_USE_META = "claudecode/toolUseId";
export const CLAUDE_ATTESTATION_MAX_LIFETIME_SECONDS = 60;
export const CLAUDE_ATTESTATION_MAX_FUTURE_SKEW_SECONDS = 30;
/** Spent tool-use ids outlive their proof so instance clock skew cannot reopen them. */
export const CLAUDE_ATTESTATION_SPENT_RETENTION_SECONDS = 120;
/** A Claude proof never signs arguments; larger ones are refused. */
export const CLAUDE_ATTESTATION_MAX_PROOF_BYTES = 4096;
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
/** Cursor's per-call tool_use_id, issued to the proof by Desktop (it may contain `:`, so the spent key is a JSON tuple). */
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

type SignedProof = {
  kind: AttestedKind;
  sid: string;
  src: string;
  tuid: string;
  tool: string;
  args?: unknown;
  iat: number;
  exp: number;
  kid: string;
  signingInput: string;
  signature: string;
};

/** Format checks only: compact JWS, exact header, exact claims for its kind. */
function parseProof(proof: unknown, provider: string | undefined): SignedProof {
  if (typeof proof !== "string" || proof.length > CURSOR_ATTESTATION_MAX_PROOF_BYTES) {
    return fail("proof is not a compact JWS");
  }
  const parts = proof.split(".");
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
  if (provider !== undefined && provider !== kind) return fail("provider mismatch");
  // Claude's proof is small and never signs arguments; a Cursor proof always signs them.
  if (kind === "claude" && proof.length > CLAUDE_ATTESTATION_MAX_PROOF_BYTES) return fail("proof is not a compact JWS");
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
  return {
    kind, sid: payload.sid, src: normalizeDesktopSourceId(payload.src), tuid: payload.tuid, tool: payload.tool,
    ...(signsArgs ? { args: payload.args } : {}),
    iat: payload.iat as number, exp: payload.exp as number, kid: header.kid,
    signingInput: `${headerSegment}.${payloadSegment}`, signature: signatureSegment,
  };
}

/** Lifetime, expiry and the Ed25519 signature under the owner's registered key for the proof's source. */
async function checkSignature(proof: SignedProof, input: { workspaceId: string; userId: string; nowMs?: number },
  store: AttestationStore): Promise<void> {
  const now = Math.floor((input.nowMs ?? Date.now()) / 1000);
  if (proof.exp < proof.iat || proof.exp - proof.iat > CLAUDE_ATTESTATION_MAX_LIFETIME_SECONDS) return fail("lifetime out of range");
  if (now > proof.exp) return fail("expired");
  if (proof.iat > now + CLAUDE_ATTESTATION_MAX_FUTURE_SKEW_SECONDS) return fail("issued in the future");

  const signature = decodeBase64Url(proof.signature);
  if (!signature || signature.byteLength !== 64) return fail("malformed signature");

  const encodedKey = await store.publicKey({
    workspaceId: input.workspaceId, userId: input.userId, sourceId: proof.src, kid: proof.kid,
  });
  const rawKey = encodedKey === null ? null : decodeBase64Url(encodedKey);
  if (!rawKey || rawKey.byteLength !== 32 || attestationKeyId(rawKey) !== proof.kid) return fail("unknown key");

  const key = await webcrypto.subtle.importKey("raw", rawKey, { name: "Ed25519" }, false, ["verify"]);
  const signed = new TextEncoder().encode(proof.signingInput);
  if (!await webcrypto.subtle.verify({ name: "Ed25519" }, key, signature, signed)) return fail("bad signature");
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
  const proof = parseProof(input.proof, input.provider);
  const { kind, tuid, src } = proof;

  // Claude Code's own call metadata, not anything the model wrote. Cursor
  // sends none, so its ticket is only a single-use nonce.
  if (kind === "claude" && (typeof input.toolUseId !== "string" || tuid !== input.toolUseId)) return fail("tool use mismatch");
  if (typeof input.toolName !== "string" || proof.tool !== input.toolName) return fail("tool mismatch");
  if (kind === "cursor" && !isDeepStrictEqual(proof.args, input.args)) return fail("arguments mismatch");

  await checkSignature(proof, input, store);

  const spent = await store.spend({
    workspaceId: input.workspaceId, userId: input.userId, // Self-host source ids and Cursor tickets may both contain `:`, so the
    // Cursor key encodes the pair unambiguously (never `:`-free, unlike Claude's).
    toolUseId: kind === "claude" ? tuid : `cursor:${JSON.stringify([src, tuid])}`,
    expiresAt: new Date((proof.exp + CLAUDE_ATTESTATION_SPENT_RETENTION_SECONDS) * 1000),
  });
  if (!spent) return fail("replayed tool use");
  return { nativeSession: { kind, id: proof.sid }, sourceId: src };
}

/**
 * Checks a Claude Code proof handed off ahead of its call (POST
 * .../messaging/desktop-identities/attestations): the same format, lifetime,
 * key and signature checks as verifyClaudeAttestation, with no call binding
 * (there is no call yet) and no spend. Only `kind: "claude"` is accepted.
 * The call that later takes it runs verifyClaudeAttestation in full.
 */
export async function verifyClaudeHandoff(input: {
  proof: unknown;
  workspaceId: string;
  userId: string;
  nowMs?: number;
}, store: AttestationStore): Promise<{ toolUseId: string; expiresAt: Date }> {
  const proof = parseProof(input.proof, "claude");
  await checkSignature(proof, input, store);
  return { toolUseId: proof.tuid, expiresAt: new Date((proof.exp + CLAUDE_ATTESTATION_SPENT_RETENTION_SECONDS) * 1000) };
}

/**
 * Claude Code proofs handed off ahead of their call, keyed by the owner and
 * Claude's tool-use id (table mcp_attestation_handoffs, migration 0097).
 */
export type ClaudeHandoffStore = {
  /**
   * Stores a proof; "exists" when this exact proof is already stored,
   * "conflict" when another one is, "spent" when its tool use was already
   * spent by a call (nothing is stored then).
   */
  put(input: { workspaceId: string; userId: string; toolUseId: string; proof: string; expiresAt: Date }):
    Promise<"stored" | "exists" | "conflict" | "spent">;
  /** Reads and deletes the unexpired proof stored for this tool use, atomically; null when there is none. */
  take(input: { workspaceId: string; userId: string; toolUseId: string }): Promise<string | null>;
};

/** The handoff store on the primary database: a row the handoff wrote is visible to the call that follows it. */
export function postgresClaudeHandoffStore(database: SqlExecutor): ClaudeHandoffStore {
  return {
    async put(input) {
      // Opportunistic sweep, as the spent-tool-use store does.
      await database.query(
        `DELETE FROM mcp_attestation_handoffs
          WHERE expires_at <= now() AND workspace_id = $1 AND user_id = $2`,
        [input.workspaceId, input.userId],
      );
      // A proof for a tool use a call already spent can never verify again.
      const spent = await database.query(
        `SELECT 1 FROM mcp_attestation_tool_uses
          WHERE workspace_id = $1 AND user_id = $2 AND tool_use_id = $3 AND expires_at > now()`,
        [input.workspaceId, input.userId, input.toolUseId],
      );
      if (spent.rows.length > 0) return "spent";
      // A row taken between the insert and the read is inserted again.
      for (let attempt = 0; attempt < 2; attempt++) {
        const inserted = await database.query<{ tool_use_id: string }>(
          `INSERT INTO mcp_attestation_handoffs (workspace_id, user_id, tool_use_id, proof, expires_at)
           VALUES ($1, $2, $3, $4, $5)
           ON CONFLICT (workspace_id, user_id, tool_use_id) DO NOTHING
           RETURNING tool_use_id`,
          [input.workspaceId, input.userId, input.toolUseId, input.proof, input.expiresAt],
        );
        if (inserted.rows.length === 1) return "stored";
        const existing = await database.query<{ proof: string }>(
          `SELECT proof FROM mcp_attestation_handoffs WHERE workspace_id = $1 AND user_id = $2 AND tool_use_id = $3`,
          [input.workspaceId, input.userId, input.toolUseId],
        );
        const stored = existing.rows[0]?.proof;
        if (stored !== undefined) return stored === input.proof ? "exists" : "conflict";
      }
      return "conflict";
    },
    async take(input) {
      const result = await database.query<{ proof: string }>(
        `DELETE FROM mcp_attestation_handoffs
          WHERE workspace_id = $1 AND user_id = $2 AND tool_use_id = $3 AND expires_at > now()
          RETURNING proof`,
        [input.workspaceId, input.userId, input.toolUseId],
      );
      return result.rows[0]?.proof ?? null;
    },
  };
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
 * Operator log for the handoff take: outcome and a fixed reason code only,
 * never the proof, the tool-use id or key material.
 */
export type ClaudeHandoffLog = (message: string, fields: Record<string, unknown>) => void;
export const CLAUDE_HANDOFF_TAKE_LOG = "claude attestation handoff take";
const defaultHandoffLog: ClaudeHandoffLog = (message, fields) => console.warn(`[selfhost-mcp] ${message}`, fields);

/**
 * Removes the proof from the parsed request in place, so no tool ever sees or
 * echoes it, then verifies it when this is a desktop-managed Claude Code or
 * Cursor call.
 * Returns no attestation when the request carries no proof, or carries one on
 * a call outside desktop management (stripped and ignored). Throws when a
 * proof fails, is batched, or arrives on a credential bound to another
 * provider.
 *
 * With no proof in the arguments, a single desktop-managed `tools/call` on an
 * unbound or Claude credential (never Cursor or Copilot) that carries Claude
 * Code's `_meta["claudecode/toolUseId"]` takes the proof Desktop handed off
 * for that tool use, if any, and verifies it exactly as an in-argument proof
 * (tool, tool use, lifetime, spend). Nothing handed off is no attestation,
 * and neither is a store failure while taking it (logged; the call fails
 * closed). A store failure while verifying a proof still throws.
 */
export async function claudeAttestationFor(body: unknown, headers: Headers, auth: {
  workspaceId: string;
  userId: string;
  desktopMcpProvider?: string;
}, store: AttestationStore, nowMs?: number,
handoff?: { store: ClaudeHandoffStore; log?: ClaudeHandoffLog }): Promise<ClaudeAttestation | undefined> {
  if (Array.isArray(body)) {
    const present = body.map(takeProof).some(result => result.present);
    if (present) return fail("batched proof");
    return undefined;
  }
  const taken = takeProof(body);
  const managed = auth.desktopMcpProvider !== undefined || headers.get("x-agent-relay-desktop") === "1";
  if (!managed) return undefined;
  const provider = auth.desktopMcpProvider;
  if (!taken.present) {
    if (!handoff || (provider !== undefined && provider !== "claude")) return undefined;
    const request = body as ToolCallRequest | null;
    if (!object(request) || request.method !== "tools/call") return undefined;
    const params = request.params;
    const toolUseId = object(params) && object(params._meta) ? params._meta[CLAUDE_TOOL_USE_META] : undefined;
    if (typeof toolUseId !== "string" || !TOOL_USE_ID.test(toolUseId)) return undefined;
    const log = handoff.log ?? defaultHandoffLog;
    const owner = { workspace_id: auth.workspaceId, user_id: auth.userId, tool: typeof params?.name === "string" ? params.name : null };
    let proof: string | null;
    try {
      proof = await handoff.store.take({ workspaceId: auth.workspaceId, userId: auth.userId, toolUseId });
    } catch (error) {
      // A store failure here never fails the call: it proceeds with no
      // attestation, so actor tools fail closed with today's guidance.
      log(CLAUDE_HANDOFF_TAKE_LOG, { ...owner, outcome: "error", error: error instanceof Error ? error.name : "unknown" });
      return undefined;
    }
    if (proof === null) {
      log(CLAUDE_HANDOFF_TAKE_LOG, { ...owner, outcome: "miss" });
      return undefined;
    }
    try {
      const attested = await verifyClaudeAttestation({
        proof, workspaceId: auth.workspaceId, userId: auth.userId,
        toolUseId, toolName: params?.name, args: params?.arguments, provider: "claude", nowMs,
      }, store);
      log(CLAUDE_HANDOFF_TAKE_LOG, { ...owner, outcome: "hit" });
      return attested;
    } catch (error) {
      if (error instanceof ClaudeAttestationError) {
        log(CLAUDE_HANDOFF_TAKE_LOG, { ...owner, outcome: "verify_failed", reason: nativeContextRefusalReason("claude_attestation", error) });
      }
      throw error;
    }
  }
  if (provider !== undefined && provider !== "claude" && provider !== "cursor") return fail("provider mismatch");
  const params = (body as ToolCallRequest).params;
  return verifyClaudeAttestation({
    proof: taken.proof, workspaceId: auth.workspaceId, userId: auth.userId,
    toolUseId: params?._meta?.[CLAUDE_TOOL_USE_META], toolName: params?.name, args: params?.arguments, provider, nowMs,
  }, store);
}
