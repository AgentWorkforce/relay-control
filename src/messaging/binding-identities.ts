/** Provider bindings keep identity custody outside generic MCP participants.
 * Reserve their metadata domain even when a binding marker is malformed.
 * Name prefixes alone do not reserve an ordinary hosted participant.
 * New native provider registrations must be included before mounting them.
 */
export function isBindingOwnedIdentity(metadata: Record<string, unknown>): boolean {
  return ["capy_binding_id", "factory_binding_id", "amp_binding_id"].some(key => Object.hasOwn(metadata, key)) ||
    (metadata.created_by === "capy-binding" || metadata.created_by === "factory-binding" || metadata.created_by === "amp-binding");
}
