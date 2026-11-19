import type { Placement } from "./parse.js";

/**
 * Who may spawn where (the launch gate already requires an owner or admin):
 * - your own node (you claimed it): always;
 * - a teammate's claimed node: only when its spawn capabilities advertise
 *   `metadata.configured.teammates: true`; a missing flag means not allowed;
 * - an unclaimed desktop, or an unclaimed node that states no `node_kind`
 *   (older desktops omit it): nobody;
 * - an unclaimed broker (`node_kind: "broker"`): any owner or admin.
 *
 * Self-host has no Cloud sandboxes, so there is no `hosted` kind: a node
 * cannot open itself by carrying a sandbox tag here.
 */

export type SpawnNodeOwner = { userId: string; name: string | null };
export type Permission = { allowed: true; reason: "yours" | "teammates" | "shared" } |
  { allowed: false; reason: "owned_by_other" | "unclaimed_desktop" | "unclaimed_unidentified" };

export function permission(placement: Placement, owner: SpawnNodeOwner | undefined, userId: string): Permission {
  if (!owner) {
    if (placement.nodeKind === "desktop") return { allowed: false, reason: "unclaimed_desktop" };
    return placement.nodeKind === "broker" ? { allowed: true, reason: "shared" } : { allowed: false, reason: "unclaimed_unidentified" };
  }
  if (owner.userId === userId) return { allowed: true, reason: "yours" };
  return placement.teammates === true ? { allowed: true, reason: "teammates" } : { allowed: false, reason: "owned_by_other" };
}
