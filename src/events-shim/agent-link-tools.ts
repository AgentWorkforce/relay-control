import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { McpContext } from "../mcp/context.js";
import { AgentLinkError, linkInboxToAgent, unlinkInboxFromAgent, type AgentLinkActor, type AgentLinkDeps } from "./agent-link.js";

/**
 * link_webhook_inbox and unlink_webhook_inbox (ported from hosted Cloud): the
 * creator of a webhook inbox links it to one of their bound cloud agents, so
 * each post reaches that agent as a relay DM and wakes it. The acting person
 * is the MCP connection's authenticated principal (OAuth and staff grants
 * never get these tools); no tool takes a user, workspace or role argument,
 * and the owner/admin role is re-read from Postgres on every call.
 */
export function registerWebhookInboxTools(server: McpServer, context: McpContext, deps: AgentLinkDeps): void {
  const actor: AgentLinkActor = {
    userId: context.principal.userId,
    workspaceId: context.workspace.id,
    organizationId: context.workspace.organizationId,
  };
  const run = async (work: () => Promise<unknown>) => {
    try {
      const data = await work();
      return { content: [{ type: "text" as const, text: JSON.stringify(data) }] };
    } catch (error) {
      return {
        isError: true,
        content: [{
          type: "text" as const,
          // A refusal says why; only unknown failures are generic.
          text: error instanceof AgentLinkError ? error.message : "The webhook inbox could not be linked. Try again in a minute.",
        }],
      };
    }
  };
  const inbox = z.string().min(1).max(512)
    .describe("The inbox's id, or its MCP URL (…/t/esm_…/mcp). It must be an inbox you created in this workspace.");
  server.registerTool("link_webhook_inbox", {
    title: "Link a webhook inbox to a bound agent",
    description:
      "Link a webhook inbox you created to one of your bound cloud agents (a Capy thread, Replica or Amp thread): each webhook post is then sent to that agent as a relay DM from the inbox's own identity, framed as untrusted webhook data, and wakes it. Replaces the inbox's current wake link; posts already waiting are sent too. Requires current owner/admin access.",
    inputSchema: { inbox, agent: z.string().min(1).max(129).describe("The bound agent's relay name, e.g. capy-01m6dvs5.") },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, ({ inbox: id, agent }) => run(() => linkInboxToAgent(deps, actor, { inbox: id, agent })));
  server.registerTool("unlink_webhook_inbox", {
    title: "Unlink a webhook inbox",
    description: "Stop sending a webhook inbox's posts to the cloud agent it is linked to. Posts then wait in the inbox.",
    inputSchema: { inbox },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  }, ({ inbox: id }) => run(() => unlinkInboxFromAgent(deps, actor, { inbox: id })));
}
