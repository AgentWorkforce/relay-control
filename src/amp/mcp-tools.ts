import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { McpContext } from "../mcp/context.js";
import { AmpError, bind, discover, unbind, type AmpActor, type AmpDeps } from "./service.js";

/**
 * list_amp_threads, bind_amp_thread and unbind_amp_thread, ported from
 * the hosted control plane's Amp MCP tools. The acting person is the MCP connection's
 * authenticated principal (admitted with cli:auth; agent and service tokens
 * are refused at admission). No tool takes a user, workspace or role
 * argument: model-supplied identity grants no authority, and the service
 * re-reads the owner/admin role from Postgres on every call.
 */
export function registerAmpTools(server: McpServer, context: McpContext, deps: AmpDeps): void {
  const actor: AmpActor = {
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
          text: error instanceof AmpError && error.code === "forbidden"
            ? "Only current owners and admins using a person connection can manage Amp."
            : error instanceof AmpError
              ? error.message
              : "Amp could not complete this operation. Check its connection in Settings.",
        }],
      };
    }
  };
  const annotations = { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true };
  server.registerTool("list_amp_threads", {
    title: "List Amp threads",
    description: "List up to 100 recent threads owned by the person whose Amp key is connected. Select a thread explicitly before sharing it with Relay.",
    inputSchema: {},
    annotations: { ...annotations, readOnlyHint: true },
  }, () => run(() => discover(deps, actor)));
  server.registerTool("bind_amp_thread", {
    title: "Bind an Amp thread",
    description: "Connect a selected Amp orb thread to Agent Relay for incoming messages. Requires the connected key owner. Replies use the returned identity or the scoped reply command in injected messages. Thread history upload to RelayHistory is inactive on self-hosted Agent Relay until a push-only history session can be issued.",
    inputSchema: { thread_id: z.string().min(1).max(160) },
    annotations,
  }, ({ thread_id }) => run(() => bind(deps, actor, thread_id)));
  server.registerTool("unbind_amp_thread", {
    title: "Unbind an Amp thread",
    description: "Disconnect an Amp thread from Relay; revokes injection and its scoped reply capability.",
    inputSchema: { binding_id: z.string().uuid() },
    annotations: { ...annotations, destructiveHint: true },
  }, ({ binding_id }) => run(() => unbind(deps, actor, binding_id)));
}
