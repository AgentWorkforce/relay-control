import type { PlacementKind, PlacedTarget } from "./policy.js";
import type { Permission, SpawnNodeOwner } from "./permission.js";

/** Wording specific to this site ("this Agent Relay site", no Cloud sandboxes). */

export const TEAMMATES_SETTING = "Allow teammates to spawn here";
export const UNNAMED_OWNER = "a teammate";

export function ownerName(owner: SpawnNodeOwner): string {
  return owner.name?.trim() || UNNAMED_OWNER;
}
function opening(name: string): string {
  return name === UNNAMED_OWNER ? "A teammate" : name;
}

export function why(kind: PlacementKind, owner: SpawnNodeOwner | undefined, decision: Permission): string {
  const name = owner ? ownerName(owner) : "";
  const place = kind === "desktop" ? "computer" : "machine";
  switch (decision.reason) {
    case "yours": return `Your ${place}.`;
    case "teammates": return `${opening(name)}'s ${place}; they allow teammates to spawn here.`;
    case "shared": return "Shared workspace machine with no recorded owner; workspace owners and admins can spawn here.";
    case "owned_by_other": return kind === "desktop"
      ? `${opening(name)}'s computer. Not allowed: ${name} has not turned on "${TEAMMATES_SETTING}" in Agent Relay Desktop.`
      : `${opening(name)}'s ${place}. Not allowed: its owner has not allowed teammates to spawn here (teammates: true).`;
    case "unclaimed_desktop": return "Not allowed: this computer hasn't been claimed yet. Its owner claims it by signing in to this " +
      "Agent Relay site in Agent Relay Desktop.";
    case "unclaimed_unidentified": return "Not allowed: this machine hasn't been claimed and doesn't say whether it is a person's computer. " +
      "Its owner claims it by signing in to this Agent Relay site in Agent Relay Desktop.";
  }
}

export function notAllowedMessage(target: PlacedTarget): string {
  const owner = target.owner;
  if (!owner && target.kind !== "desktop") return `Node "${target.name}" hasn't been claimed yet and doesn't say whether it is a ` +
    "person's computer, so no one can spawn there. Its owner claims it by signing in to this Agent Relay site in Agent Relay Desktop " +
    "on that machine. Until then, choose one of the alternatives.";
  if (!owner) return `Node "${target.name}" is a computer that hasn't been claimed yet, so no one can spawn there. ` +
    "Its owner claims it by signing in to this Agent Relay site in Agent Relay Desktop on that computer. " +
    "Until then, choose one of the alternatives.";
  return target.kind === "desktop"
    ? `Node "${target.name}" is ${owner.name}'s computer. ${opening(owner.name)} has not allowed teammates to spawn there; ` +
      `they can turn on "${TEAMMATES_SETTING}" in Agent Relay Desktop.`
    : `Node "${target.name}" belongs to ${owner.name}. Only its owner can spawn there unless it advertises teammates: true.`;
}
