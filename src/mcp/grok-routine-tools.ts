import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { McpContext } from "./context.js";
import { GrokRoutineError } from "./grok-routine.js";
import { relayFailure, relayService } from "./relay-participants.js";
import { McpOAuthAccessRefused, McpOAuthActorRefused, McpOAuthAgentRetiring } from "./oauth/admission.js";

export function registerGrokRoutineTools(server: McpServer, context: McpContext): void {
  const run = async (fn: () => Promise<unknown>) => {
    try {
      await context.relay.database.transaction(tx => context.oauth!.lock(tx));
      const data = await fn();
      return { structuredContent: data as Record<string, unknown>, content: [{ type: "text" as const, text: JSON.stringify(data) }] };
    } catch (error) {
      if (error instanceof GrokRoutineError || error instanceof McpOAuthAccessRefused ||
          error instanceof McpOAuthActorRefused || error instanceof McpOAuthAgentRetiring) {
        return { isError: true, content: [{ type: "text" as const, text: error.message }] };
      }
      return relayFailure(error);
    }
  };
  const oauth = context.oauth!;
  const routines = context.grokRoutines!;
  const owner = oauth.access.principal;
  server.registerTool("connect_grok_bot_routine", {
    description: "Set up webhook wake-ups for this self-hosted Grok Bot connection after the person chooses them. Returns a secure setup_url and non-secret routine_prompt. Create a Grok routine with When a webhook fires, then have the person enter its Webhook URL and Authorization header on that page; never request the key in chat. Saved configuration is not proof of delivery: verify a real Relay message appears in the bot's chat.",
    inputSchema: { mode: z.literal("webhook").default("webhook"), name: z.string().max(128).optional() },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true },
  }, input => run(async () => {
    oauth.assertActor(input.name);
    await routines.status(oauth.access.grantId, owner);
    const joined = await relayService(context).join({ name: oauth.access.agentName });
    return { ...await routines.status(oauth.access.grantId, owner), inbox_address: joined.address, mode: "webhook" };
  }));
  server.registerTool("disconnect_grok_bot_routine", {
    description: "Stop webhook wake-ups and delete this Grok Bot connection's stored routine key. Also pause or delete the routine in Grok when the person asks to stop it.",
    inputSchema: { mode: z.literal("webhook").optional() },
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false },
  }, () => run(() => routines.disconnect(oauth.access.grantId, owner)));
  server.registerTool("grok_bot_routine_status", {
    description: "Read this connection's self-hosted webhook wake-up configuration and last delivery result, without secrets. webhook_accepted means Grok accepted the trigger; confirm the message appeared in the bot's chat before reporting end-to-end success.",
    inputSchema: {}, annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, () => run(() => routines.status(oauth.access.grantId, owner)));
}
