/** Capy binding identities have separate custody from generic MCP participants.
 * Reserve the metadata domain even when its binding marker is malformed.
 * A name prefix alone does not reserve an ordinary hosted participant.
 */
export function isCapyBindingIdentity(metadata: Record<string, unknown>): boolean {
  return Object.hasOwn(metadata, "capy_binding_id") || metadata.created_by === "capy-binding";
}
