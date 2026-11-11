/**
 * Desktop call context, ported from Cloud's
 * `packages/web/lib/mcp/desktop-call-context.ts`. Runtime context stays
 * outside model-visible tool arguments; a transport is not a chat.
 *
 * `provider` is the Desktop provider bound to the admitted credential (a
 * `mcp:desktop` child token), never a model argument or header. Any provider
 * makes the call managed: actor tools then need a verified native chat and
 * never fall back to a hosted participant. `attested` is a Claude or Copilot call proof
 * the route already verified (`claudeAttestationFor` / `copilotAttestationFor`).
 */
export type NativeSession = { kind: "codex" | "grok" | "pi" | "opencode" | "claude" | "copilot"; id: string };
/** `nativeSourceId` is set when a signed proof names the desktop source that must own the chat. */
export type DesktopCallContext = { required: boolean; nativeSession?: NativeSession; nativeSourceId?: string; provider?: string };
export const NATIVE_SESSION_CAPABILITY = "com.agentrelay/native-session-identity";

/** A native chat context this endpoint refuses (400 -32602). */
export class DesktopCallContextError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DesktopCallContextError";
  }
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Throws when the request carries identity context this endpoint refuses. */
export function desktopCallContext(body: unknown, headers: Headers, provider?: string,
  attested?: { nativeSession: NativeSession; sourceId: string }): DesktopCallContext {
  const required = provider !== undefined || headers.get("x-agent-relay-desktop") === "1";
  // No cached process-wide identity headers: they cannot distinguish chats.
  if (headers.has("x-agent-relay-session-kind") || headers.has("x-agent-relay-session-id")) {
    throw new DesktopCallContextError("Unsupported desktop identity headers.");
  }
  const managed = provider !== undefined ? { provider } : {};
  if (!required) return { required: false };
  const request = body as { method?: unknown; params?: { _meta?: { threadId?: unknown; "ai.opencode/sessionID"?: unknown } } } | null;
  if (request?.method !== "tools/call") return { required, ...managed };
  if (attested) {
    // A verified hook proof is the only native context this call may carry.
    if (provider !== undefined && provider !== attested.nativeSession.kind) throw new DesktopCallContextError("Unsupported native chat context.");
    if (headers.has("x-agent-relay-native-session-id") || request.params?._meta?.threadId !== undefined ||
        request.params?._meta?.["ai.opencode/sessionID"] !== undefined) {
      throw new DesktopCallContextError("Conflicting native chat context.");
    }
    return { required, ...managed, nativeSession: attested.nativeSession, nativeSourceId: attested.sourceId };
  }
  // These clients inject their current native ID at request time. The provider
  // comes from the authenticated grant, never from a model argument/header.
  const nativeHeader = headers.get("x-agent-relay-native-session-id");
  if (provider === "grok" || provider === "pi") {
    if (nativeHeader === null) return { required, ...managed };
    if (!UUID.test(nativeHeader)) throw new DesktopCallContextError("Invalid native chat context.");
    return { required, ...managed, nativeSession: { kind: provider, id: nativeHeader.toLowerCase() } };
  }
  if (nativeHeader !== null) throw new DesktopCallContextError("Unsupported native chat context.");
  if (provider === "opencode") {
    const id = request.params?._meta?.["ai.opencode/sessionID"];
    if (id === undefined) return { required, ...managed };
    if (typeof id !== "string" || !/^ses_[A-Za-z0-9]{4,128}$/.test(id)) throw new DesktopCallContextError("Invalid native chat context.");
    return { required, ...managed, nativeSession: { kind: "opencode", id } };
  }
  // Copilot (and any other provider) has no request-time native id: only a
  // verified proof names its chat.
  if (provider !== undefined && provider !== "codex") return { required, ...managed };
  // Codex injects its thread id from sess.thread_id, separately from arguments.
  const id = request.params?._meta?.threadId;
  if (id === undefined) return { required, ...managed };
  if (typeof id !== "string" || !UUID.test(id)) throw new DesktopCallContextError("Invalid native chat context.");
  return { required, ...managed, nativeSession: { kind: "codex", id: id.toLowerCase() } };
}
