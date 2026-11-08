/**
 * Desktop call context, ported from Cloud's
 * `packages/web/lib/mcp/desktop-call-context.ts` for credentials without a
 * desktop provider (self-host has no Desktop provider login or Claude/Copilot
 * attestation). Runtime context stays outside model-visible tool arguments.
 */
export type NativeSession = { kind: "codex"; id: string };
export type DesktopCallContext = { required: boolean; nativeSession?: NativeSession };
export const NATIVE_SESSION_CAPABILITY = "com.agentrelay/native-session-identity";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Throws when the request carries identity context this endpoint refuses. */
export function desktopCallContext(body: unknown, headers: Headers): DesktopCallContext {
  const required = headers.get("x-agent-relay-desktop") === "1";
  // No cached process-wide identity headers: they cannot distinguish chats.
  if (headers.has("x-agent-relay-session-kind") || headers.has("x-agent-relay-session-id")) {
    throw new Error("Unsupported desktop identity headers.");
  }
  if (!required) return { required: false };
  const request = body as { method?: unknown; params?: { _meta?: { threadId?: unknown } } } | null;
  if (request?.method !== "tools/call") return { required };
  // Only grant-bound providers (Grok, Pi) may send this header in Cloud.
  if (headers.get("x-agent-relay-native-session-id") !== null) throw new Error("Unsupported native chat context.");
  // Codex injects its thread id from sess.thread_id, separately from arguments.
  const id = request.params?._meta?.threadId;
  if (id === undefined) return { required };
  if (typeof id !== "string" || !UUID.test(id)) throw new Error("Invalid native chat context.");
  return { required, nativeSession: { kind: "codex", id: id.toLowerCase() } };
}
