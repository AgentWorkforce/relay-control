import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The versioned rules bundle (docs/agent-rules.md,
 * docs/specs/grok-bot-dynamic-prompt.md Phase 2). Base sections ship in the
 * image under agent-rules/ and apply to every tenant; an organization overlay
 * (agent_rules_overlays) is appended after them.
 */

export const AGENT_RULES_AUDIENCES = ["grok-bot", "lead", "worker"] as const;
export type AgentRulesAudience = (typeof AGENT_RULES_AUDIENCES)[number];
export const BUILTIN_SECTIONS = ["grok-routine-prompt"] as const;
type Builtin = (typeof BUILTIN_SECTIONS)[number];

type ManifestSection = { id: string; title: string; audiences: AgentRulesAudience[] } & ({ file: string } | { builtin: Builtin });
export type AgentRulesManifest = {
  version: string; bootstrap_version: number; sources?: Record<string, string>;
  sections: ManifestSection[]; sections_sha256: string;
};
export type LoadedSection = { id: string; title: string; audiences: AgentRulesAudience[]; text: string | null; builtin: Builtin | null };
export type AgentRulesBundle = { version: string; bootstrapVersion: number; sections: LoadedSection[]; sectionsSha256: string };

/** Values a builtin section is rendered from; a caller without them gets a generic rendering. */
export type BuiltinInputs = { grokRoutinePrompt?: string };

const VERSION = /^\d{4}\.\d{2}\.\d+$/;
const ID = /^[a-z][a-z0-9-]{0,63}$/;

export function agentRulesDirectory(): string {
  return resolve(dirname(fileURLToPath(import.meta.url)), "../../agent-rules");
}

export const sha256 = (value: string) => createHash("sha256").update(value).digest("hex");

/** sha256 over every base section's id and text, in manifest order: the CI pin that forces a version bump. */
export function sectionsDigest(sections: readonly Pick<LoadedSection, "id" | "text" | "builtin">[]): string {
  return sha256(JSON.stringify(sections.map(section => [section.id, section.builtin ?? section.text])));
}

/** Loads and validates the bundle once (at boot): the base cannot change within a deploy. */
export function loadAgentRules(directory = agentRulesDirectory(), options: { verifyDigest?: boolean } = {}): AgentRulesBundle {
  const manifest = JSON.parse(readFileSync(resolve(directory, "manifest.json"), "utf8")) as AgentRulesManifest;
  if (!VERSION.test(manifest.version)) throw new Error("agent-rules manifest version must be CalVer YYYY.MM.N");
  if (!Number.isSafeInteger(manifest.bootstrap_version) || manifest.bootstrap_version < 1) throw new Error("agent-rules bootstrap_version must be a positive integer");
  const ids = new Set<string>();
  const sections = manifest.sections.map((section): LoadedSection => {
    if (!ID.test(section.id) || ids.has(section.id)) throw new Error(`agent-rules section id ${section.id} is invalid or repeated`);
    ids.add(section.id);
    if (!section.audiences.length || section.audiences.some(audience => !AGENT_RULES_AUDIENCES.includes(audience))) {
      throw new Error(`agent-rules section ${section.id} has an unknown audience`);
    }
    if ("builtin" in section) {
      if (!BUILTIN_SECTIONS.includes(section.builtin)) throw new Error(`agent-rules section ${section.id} names an unknown builtin`);
      return { id: section.id, title: section.title, audiences: section.audiences, text: null, builtin: section.builtin };
    }
    const path = resolve(directory, section.file);
    if (!path.startsWith(resolve(directory) + "/")) throw new Error(`agent-rules section ${section.id} is outside the bundle`);
    return { id: section.id, title: section.title, audiences: section.audiences, text: readFileSync(path, "utf8").trim(), builtin: null };
  });
  if (sections[0]?.id !== "safety") throw new Error("agent-rules must start with the safety section");
  const digest = sectionsDigest(sections);
  if (options.verifyDigest !== false && digest !== manifest.sections_sha256) {
    throw new Error("agent-rules sections changed without updating manifest sections_sha256 and version");
  }
  return { version: manifest.version, bootstrapVersion: manifest.bootstrap_version, sections, sectionsSha256: digest };
}

/** The builtin grok-inbox text without a grant: the copied prompt with a placeholder name. */
function renderBuiltin(name: Builtin, inputs: BuiltinInputs): string {
  switch (name) {
    case "grok-routine-prompt":
      return inputs.grokRoutinePrompt
        ?? "Your routine's message-handling steps are returned when this connection calls get_agent_rules as its own Grok Bot connection.";
  }
}

export type ComposedRules = { audience: AgentRulesAudience; version: string; sha256: string; text: string;
  sections: Array<{ id: string; title: string }>; bootstrapVersion: number };

/**
 * Base sections for the audience in manifest order (safety always first), then
 * the organization overlay. An overlay adds rules; it cannot remove a base
 * section.
 */
export function composeAgentRules(bundle: AgentRulesBundle, audience: AgentRulesAudience,
  overlay: { version: number; text: string } | null, inputs: BuiltinInputs = {}): ComposedRules {
  const chosen = bundle.sections.filter(section => section.audiences.includes(audience));
  const parts = chosen.map(section => `## ${section.title}\n\n${section.builtin ? renderBuiltin(section.builtin, inputs) : section.text}`);
  const overlayText = overlay?.text.trim() ? overlay.text.trim() : null;
  if (overlayText) parts.push(`## Organization rules\n\n${overlayText}`);
  const version = overlayText ? `${bundle.version}+org.${overlay!.version}` : bundle.version;
  const text = `# Agent Relay operating rules\n\nVersion ${version}, audience ${audience}.\n\n${parts.join("\n\n")}\n`;
  return { audience, version, sha256: sha256(text), text, bootstrapVersion: bundle.bootstrapVersion,
    sections: [...chosen.map(section => ({ id: section.id, title: section.title })), ...(overlayText ? [{ id: "organization", title: "Organization rules" }] : [])] };
}

/** Patterns no rules text may contain: secrets and credential-bearing URLs. */
const SECRET_PATTERNS: readonly RegExp[] = [
  /crsr_[A-Za-z0-9_-]{8,}/, /whsec_[A-Za-z0-9+/=]{8,}/, /\b(?:sh_at|sh_wk|sh_fr|mcp_at|cld_at|rk_live|sk-ant)[_-][A-Za-z0-9_-]{8,}/,
  /https?:\/\/[^\s/@:]+:[^\s/@]+@/, /api2\.cursor\.sh\/automations\/webhook\/[A-Za-z0-9_-]+/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];

/** Returns the first rule a text breaks, never the matched value. */
export function rulesTextProblem(text: string, maxBytes = 16 * 1024): string | null {
  if (Buffer.byteLength(text, "utf8") > maxBytes) return `Rules text must be at most ${maxBytes} bytes.`;
  if (SECRET_PATTERNS.some(pattern => pattern.test(text))) return "Rules text must not contain secrets, credentials or routine webhook URLs.";
  return null;
}
