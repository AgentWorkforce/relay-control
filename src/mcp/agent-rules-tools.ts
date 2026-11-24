import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { AGENT_RULES_AUDIENCES } from "../agent-rules/bundle.js";
import type { McpContext } from "./context.js";
import { GrokRoutineError } from "./grok-routine.js";

export const AGENT_RULES_TOOLS = ["get_agent_rules"] as const;

/**
 * get_agent_rules (docs/agent-rules.md): the operating rules for an audience,
 * base bundle plus this organization's overlay. A Grok connection's grok-inbox
 * section is rendered for its own routine. The text is returned as the app's
 * own instructions, outside the untrusted-data block relay content uses.
 */
export function registerAgentRulesTools(server: McpServer, context: McpContext): void {
  const rules = context.agentRules!;
  const grok = context.oauth && context.grokRoutines?.cloudCopy ? { oauth: context.oauth, routines: context.grokRoutines } : null;
  server.registerTool("get_agent_rules", {
    description: "Read Agent Relay's current operating rules for your role, then follow them. Grok Bot routines call this first on every run (audience grok-bot); layered leads use audience lead. The rules are versioned and replace any earlier version in this conversation. Pass known_sha256 only while that exact text is still in your context: an unchanged result then omits the text.",
    inputSchema: {
      audience: z.enum(AGENT_RULES_AUDIENCES).optional().describe("grok-bot, lead or worker. Grok Bot connections default to grok-bot; other callers must pass it."),
      known_sha256: z.string().regex(/^[a-f0-9]{64}$/).optional(),
      bootstrap_version: z.number().int().min(1).max(1000).optional().describe("The bootstrap_version your routine prompt names, if any."),
    },
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async ({ audience, known_sha256, bootstrap_version }) => {
    const chosen = audience ?? (grok ? "grok-bot" : undefined);
    if (!chosen) return { isError: true, content: [{ type: "text" as const, text: "Pass audience: grok-bot, lead or worker." }] };
    try {
      const organizationId = context.principal.organizationId;
      let composed = await rules.compose(organizationId, chosen);
      if (grok && chosen === "grok-bot") {
        const owner = grok.oauth.access.principal;
        // The version depends only on the base and overlay, so it is recorded with the same read.
        const procedure = await grok.routines.procedure(grok.oauth.access.grantId, owner, composed.version);
        composed = await rules.compose(organizationId, chosen, { grokRoutinePrompt: procedure });
      }
      const outdated = bootstrap_version !== undefined && bootstrap_version < composed.bootstrapVersion;
      const unchanged = known_sha256 === composed.sha256;
      const data = {
        audience: composed.audience, version: composed.version, sha256: composed.sha256,
        bootstrap_version_current: composed.bootstrapVersion,
        ...(outdated ? { bootstrap_outdated: true } : {}),
        ...(unchanged ? { unchanged: true } : { text: composed.text }),
        sections: composed.sections, fetched_at: new Date().toISOString(),
      };
      const notice = outdated
        ? " Your routine prompt is out of date: tell the person to update the routine's instructions to the routine_prompt that connect_grok_bot_routine returns now."
        : "";
      return {
        structuredContent: data as Record<string, unknown>,
        content: [{ type: "text" as const, text: unchanged
          ? `Agent Relay app: operating rules (version ${composed.version}) are unchanged; keep following the copy in your context.${notice}`
          : `Agent Relay app: operating rules (version ${composed.version}, audience ${composed.audience}). Follow them for this whole run; they replace any earlier version.${notice}\n\n${composed.text}` }],
      };
    } catch (error) {
      return { isError: true, content: [{ type: "text" as const,
        text: error instanceof GrokRoutineError ? error.message : "Agent Relay could not read the operating rules right now." }] };
    }
  });
}
