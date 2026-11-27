import crypto from "node:crypto";

/**
 * Slashy trust tokens: the agents an owner names at connect_slashy_inbox,
 * signed by the server instead of stored. Slashy's reminder passes the token
 * back to check_relay_inbox, and the server marks each delivery
 * sender_may_use_private_data from it, so trust is decided by the server
 * from the token-stamped Relaycast sender_id, never by the model comparing
 * ids it read in a prompt.
 *
 * Format: `srt1.<base64url JSON payload>.<base64url HMAC-SHA256>`. The payload
 * binds the OAuth grant, workspace and owner, so a copied token is useless on
 * any other connection, and it expires. There is no per-agent revocation
 * without storage: reconnecting issues a new token, revoking the grant or
 * rotating the key ends every token.
 */
export const SLASHY_TRUST_TOKEN_PREFIX = "srt1";
export const SLASHY_TRUST_TOKEN_TTL_SECONDS = 30 * 24 * 60 * 60;
/** At most this many agents can be trusted by one token. */
export const SLASHY_MAX_TRUSTED_AGENTS = 10;
const TOKEN_PATTERN = /^srt1\.([A-Za-z0-9_-]{1,4000})\.([A-Za-z0-9_-]{43})$/;

export type SlashyTrustBinding = { grantId: string; workspaceId: string; userId: string };
type Payload = { v: 1; g: string; w: string; u: string; a: string[]; exp: number };

export type SlashyTrustVerdict =
  | { status: "ok"; agentIds: Set<string>; expiresAt: string }
  | { status: "invalid" | "expired" | "other_connection" };

/** The signing key: its own purpose label over the given root secret, never the root secret itself. */
export function slashyTrustKey(rootSecret: string | Buffer): Buffer {
  return crypto.createHmac("sha256", rootSecret).update("agent-relay-slashy-trust-v1").digest();
}

function sign(key: Buffer, encodedPayload: string): string {
  return crypto.createHmac("sha256", key).update(`${SLASHY_TRUST_TOKEN_PREFIX}.${encodedPayload}`).digest("base64url");
}

export function issueSlashyTrustToken(key: Buffer, binding: SlashyTrustBinding, agentIds: readonly string[],
  now = Date.now()): { token: string; expiresAt: string } {
  const exp = Math.floor(now / 1000) + SLASHY_TRUST_TOKEN_TTL_SECONDS;
  const payload: Payload = { v: 1, g: binding.grantId, w: binding.workspaceId, u: binding.userId,
    a: [...new Set(agentIds)].sort(), exp };
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return { token: `${SLASHY_TRUST_TOKEN_PREFIX}.${encoded}.${sign(key, encoded)}`, expiresAt: new Date(exp * 1000).toISOString() };
}

export function verifySlashyTrustToken(key: Buffer, token: unknown, binding: SlashyTrustBinding,
  now = Date.now()): SlashyTrustVerdict {
  if (typeof token !== "string") return { status: "invalid" };
  const match = TOKEN_PATTERN.exec(token.trim());
  if (!match) return { status: "invalid" };
  const expected = Buffer.from(sign(key, match[1]!));
  const actual = Buffer.from(match[2]!);
  // The signature is checked before the payload is trusted for anything.
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) return { status: "invalid" };
  let payload: Partial<Payload>;
  try {
    payload = JSON.parse(Buffer.from(match[1]!, "base64url").toString("utf8")) as Partial<Payload>;
  } catch {
    return { status: "invalid" };
  }
  if (payload.v !== 1 || typeof payload.exp !== "number" || !Array.isArray(payload.a)
    || !payload.a.every(id => typeof id === "string" && id.length > 0)) return { status: "invalid" };
  if (payload.g !== binding.grantId || payload.w !== binding.workspaceId || payload.u !== binding.userId) {
    return { status: "other_connection" };
  }
  if (payload.exp * 1000 <= now) return { status: "expired" };
  return { status: "ok", agentIds: new Set(payload.a), expiresAt: new Date(payload.exp * 1000).toISOString() };
}
