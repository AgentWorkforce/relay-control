import { z } from "zod";
import type { RosterAgent } from "../messaging/relaycast.js";

/**
 * Agent Relay A2A agent cards, mirrored from Cloud's hosted MCP: the card an
 * agent advertises is stored on its existing Relaycast agent record as
 * `metadata.skills` and `metadata.card`, and returned to agents in the A2A
 * AgentCard shape (camelCase, protocol 0.3.0) with an `x-agent-relay`
 * extension. Stored values are written by other agents, so every read is
 * bounded and shape-checked here; nothing stored is trusted as instructions.
 */

export const A2A_PROTOCOL_VERSION = "0.3.0";
export const DEFAULT_CARD_VERSION = "1";
const PROVIDER_URL = "https://agentrelay.com";

export const CARD_LIMITS = {
  skills: 20,
  skillName: 80,
  skillDescription: 500,
  examples: 5,
  example: 200,
  description: 1000,
  tags: 10,
  tag: 50,
  skillId: 64,
  version: 32,
  documentationUrl: 2048,
  /** Skill names list_relay_agents reports per agent. */
  listedSkills: 10,
} as const;

const KEBAB_CASE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

// ---------------------------------------------------------------------------
// set_relay_agent_card input (section-1 limits).

const tag = z.string().trim().min(1).max(CARD_LIMITS.tag);
const tags = z.array(tag).max(CARD_LIMITS.tags);

export const skillInputSchema = z.object({
  id: z.string().trim().min(1).max(CARD_LIMITS.skillId).regex(KEBAB_CASE)
    .describe("Kebab-case id, unique among your skills, e.g. review-pull-requests."),
  name: z.string().trim().min(1).max(CARD_LIMITS.skillName),
  description: z.string().trim().min(1).max(CARD_LIMITS.skillDescription)
    .describe("What this kind of work is and what you need to do it."),
  tags: tags.optional(),
  examples: z.array(z.string().trim().min(1).max(CARD_LIMITS.example)).max(CARD_LIMITS.examples).optional()
    .describe("Up to 5 short example requests a peer could send you for this skill."),
});

export const setCardInputSchema = {
  description: z.string().trim().min(1).max(CARD_LIMITS.description)
    .describe("Your purpose: what you do and why another agent should work with you."),
  skills: z.array(skillInputSchema).max(CARD_LIMITS.skills)
    .refine(skills => new Set(skills.map(skill => skill.id)).size === skills.length, { message: "Skill ids must be unique." })
    .describe("One skill per kind of work you take on, at most 20."),
  tags: tags.optional().describe("Up to 10 short tags for the whole agent."),
  documentation_url: z.string().trim().max(CARD_LIMITS.documentationUrl).url()
    .refine(value => value.startsWith("https://"), { message: "documentation_url must be an https URL." }).optional(),
  version: z.string().trim().min(1).max(CARD_LIMITS.version).optional()
    .describe("Your card's version; defaults to the current version, else 1."),
};

export type SetCardInput = {
  description: string;
  skills: Array<z.infer<typeof skillInputSchema>>;
  tags?: string[];
  documentation_url?: string;
  version?: string;
};

// ---------------------------------------------------------------------------
// Stored values (metadata.skills, metadata.card), read defensively.

export type CardSkill = { id: string; name: string; description: string; tags: string[]; examples?: string[] };
export type StoredCard = {
  description: string;
  documentation_url?: string;
  tags: string[];
  updated_at: string | null;
  version: string;
};

const record = (value: unknown): Record<string, unknown> | null =>
  value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
const bounded = (value: unknown, max: number): string | null =>
  typeof value === "string" && value.trim() ? value.trim().slice(0, max) : null;
const strings = (value: unknown, count: number, max: number): string[] =>
  Array.isArray(value) ? value.flatMap(item => bounded(item, max) ?? []).slice(0, count) : [];

/** Relaycast's skillIdFromName: a kebab-case id for a skill stored without one. */
export function skillIdFromName(name: string): string {
  return name.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "skill";
}

/**
 * The agent's declared skills, read as Relaycast's readDeclaredSkills does
 * (malformed entries skipped; a missing id derived from the name; a repeated
 * id suffixed -2, -3, ...), then bounded to the section-1 limits.
 */
export function storedSkills(metadata: Record<string, unknown>): CardSkill[] {
  if (!Array.isArray(metadata.skills)) return [];
  const used = new Set<string>();
  const skills: CardSkill[] = [];
  for (const item of metadata.skills) {
    if (skills.length >= CARD_LIMITS.skills) break;
    const raw = record(item);
    const name = bounded(raw?.name, CARD_LIMITS.skillName);
    if (!raw || !name) continue;
    const base = bounded(raw.id, CARD_LIMITS.skillId) ?? skillIdFromName(name);
    let id = base;
    for (let n = 2; used.has(id); n += 1) id = `${base}-${n}`;
    used.add(id);
    const examples = strings(raw.examples, CARD_LIMITS.examples, CARD_LIMITS.example);
    skills.push({ id, name, description: typeof raw.description === "string" ? raw.description.slice(0, CARD_LIMITS.skillDescription) : "",
      tags: strings(raw.tags, CARD_LIMITS.tags, CARD_LIMITS.tag), ...(examples.length ? { examples } : {}) });
  }
  return skills;
}

/** The agent's declared card, or null when it has none (a card needs a description). */
export function storedCard(metadata: Record<string, unknown>): StoredCard | null {
  const raw = record(metadata.card);
  const description = bounded(raw?.description, CARD_LIMITS.description);
  if (!raw || !description) return null;
  const documentation = bounded(raw.documentation_url, CARD_LIMITS.documentationUrl);
  return {
    description,
    ...(documentation?.startsWith("https://") ? { documentation_url: documentation } : {}),
    tags: strings(raw.tags, CARD_LIMITS.tags, CARD_LIMITS.tag),
    updated_at: bounded(raw.updated_at, 64),
    version: bounded(raw.version, CARD_LIMITS.version) ?? DEFAULT_CARD_VERSION,
  };
}

/** Relaycast's hasCard: the agent declared a card or at least one skill. */
export function hasCard(metadata: Record<string, unknown>): boolean {
  return storedCard(metadata) !== null || storedSkills(metadata).length > 0;
}

/** The two fields list_relay_agents adds per agent. */
export function cardSummary(metadata: Record<string, unknown>): { skills: string[]; has_card: boolean } {
  return { skills: storedSkills(metadata).slice(0, CARD_LIMITS.listedSkills).map(skill => skill.name),
    has_card: hasCard(metadata) };
}

/** The `metadata.skills` and `metadata.card` values set_relay_agent_card writes; no other key. */
export function cardMetadata(input: SetCardInput, existing: Record<string, unknown>, now: Date): { skills: CardSkill[]; card: Record<string, unknown> } {
  const skills = input.skills.map(skill => ({
    id: skill.id, name: skill.name, description: skill.description, tags: skill.tags ?? [],
    ...(skill.examples?.length ? { examples: skill.examples } : {}),
  }));
  const card = {
    description: input.description,
    ...(input.documentation_url ? { documentation_url: input.documentation_url } : {}),
    tags: input.tags ?? [],
    updated_at: now.toISOString(),
    version: input.version ?? storedCard(existing)?.version ?? DEFAULT_CARD_VERSION,
  };
  return { skills, card };
}

// ---------------------------------------------------------------------------
// The card returned to agents (contract section 2), field for field what
// Relaycast's buildAgentCard (GET /v1/agents/:name/card) returns:
// - description: metadata.card.description, else the persona, else
//   metadata.description, else "<name> on Agent Relay".
// - x-agent-relay.kind: metadata.kind, else the Relaycast agent type.
// - x-agent-relay.owner: metadata.owner_name, else metadata.owner; omitted when unset.
// - x-agent-relay.where: metadata.where, else the address's machine part; omitted when unset.
// - x-agent-relay.status: "offline" when Relaycast reports offline, else "live".
// - x-agent-relay.cardUpdatedAt: omitted without a card.

export function buildAgentCard(agent: RosterAgent, options: { organization: string; relaycastUrl: string }) {
  const metadata = agent.metadata;
  const card = storedCard(metadata);
  const skills = storedSkills(metadata);
  const description = card?.description ?? bounded(agent.persona, CARD_LIMITS.description)
    ?? bounded(metadata.description, CARD_LIMITS.description) ?? `${agent.name} on Agent Relay`;
  const at = agent.address?.indexOf("@") ?? -1;
  const machine = agent.address && at >= 0 ? agent.address.slice(at + 1) || null : null;
  const owner = bounded(metadata.owner_name, 200) ?? bounded(metadata.owner, 200);
  const where = bounded(metadata.where, 200) ?? machine;
  return {
    protocolVersion: A2A_PROTOCOL_VERSION,
    name: agent.name,
    description,
    url: `${options.relaycastUrl.replace(/\/+$/, "")}/a2a/rpc`,
    preferredTransport: "JSONRPC",
    version: card?.version ?? DEFAULT_CARD_VERSION,
    provider: { organization: options.organization, url: PROVIDER_URL },
    ...(card?.documentation_url ? { documentationUrl: card.documentation_url } : {}),
    capabilities: { streaming: false, pushNotifications: false },
    defaultInputModes: ["text/plain"],
    defaultOutputModes: ["text/plain"],
    skills,
    "x-agent-relay": {
      address: agent.address ?? agent.name,
      kind: bounded(metadata.kind, 40) ?? agent.kind,
      ...(owner ? { owner } : {}),
      ...(where ? { where } : {}),
      status: agent.status === "offline" ? "offline" : "live",
      tags: card?.tags ?? [],
      ...(card?.updated_at ? { cardUpdatedAt: card.updated_at } : {}),
      hasCard: card !== null || skills.length > 0,
    },
  };
}

export type AgentCard = ReturnType<typeof buildAgentCard>;
