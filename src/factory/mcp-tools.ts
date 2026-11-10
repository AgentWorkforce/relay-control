import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { McpContext } from "../mcp/context.js";
import { FactoryHttpError, type FactoryAccess, type FactoryService } from "./service.js";

/**
 * What the MCP server needs from the Factory module: the service (for the
 * three tools) and the send/read resolver hook. Present only when
 * SELFHOST_FACTORY_ENABLED is on.
 */
export type FactoryMcpDeps = {
  service: FactoryService;
  /** The hosted identity of the caller's own bound Factory agent `name`, else null. */
  agentFor: (workspaceId: string, userId: string, name: string) => Promise<{ name: string; token: string } | null>;
};

const MANAGER_REFUSAL = "Only current owners and admins using a person connection can manage Factory.";
const UNKNOWN_FAILURE = "Factory could not complete this operation. Check its connection in Settings.";

/**
 * list_factory_sessions, bind_factory_session and unbind_factory_session,
 * parallel to the Amp tools. The acting person is the MCP connection's
 * authenticated principal; no tool takes a user, workspace or role argument,
 * and the owner/admin role is re-read from Postgres on every call. The
 * service then enforces that only the person who connected Factory browses
 * or binds with its key.
 */
export function registerFactoryTools(server: McpServer, context: McpContext, deps: FactoryMcpDeps): void {
  const { service } = deps;
  const access: FactoryAccess = {
    principal: { userId: context.principal.userId },
    workspace: {
      id: context.workspace.id,
      organizationId: context.workspace.organizationId,
      relaycastApiKey: context.workspace.relaycastApiKey,
    },
  };
  const run = async (work: () => Promise<unknown>) => {
    try {
      if (!context.principal.scopes.includes("cli:auth")) throw new FactoryHttpError(403, "insufficient_scope", "Insufficient scope");
      await service.assertManager(access);
      const data = await work();
      return { content: [{ type: "text" as const, text: JSON.stringify(data) }] };
    } catch (error) {
      return {
        isError: true,
        content: [{
          type: "text" as const,
          // Service messages are fixed strings (design §3.1) and never carry keys or tokens.
          text: error instanceof FactoryHttpError && error.status === 403 && error.code !== "factory_not_owner"
            ? MANAGER_REFUSAL
            : error instanceof FactoryHttpError
              ? error.message
              : UNKNOWN_FAILURE,
        }],
      };
    }
  };
  const annotations = { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true };

  server.registerTool("list_factory_sessions", {
    title: "List Factory sessions",
    description: "List the connected key owner's computers and sessions. One active computer is selected automatically; provide computer_id if there are several. Select a session explicitly before sharing it with Relay.",
    inputSchema: { computer_id: z.string().min(1).max(256).optional() },
    annotations: { ...annotations, readOnlyHint: true },
  }, ({ computer_id }) => run(async () => {
    const { computers } = await service.computers(access);
    const { bindings } = await service.listBindings(access);
    const bound = bindings.filter((binding) => binding.state !== "retired");
    let selected = computer_id;
    if (!selected) {
      const active = computers.filter((computer) => computer.status === "active");
      if (computers.length === 1) selected = computers[0]!.id;
      else if (active.length === 1) selected = active[0]!.id;
    }
    if (!selected) {
      return {
        computers,
        selected_computer: null,
        sessions: [],
        bindings: bound,
        note: computers.length === 0
          ? "No Factory computers are available for the connected key."
          : "Several Factory computers are available. Call again with computer_id.",
      };
    }
    const listed = await service.sessions(access, selected);
    return { computers, selected_computer: selected, ...listed, bindings: bound };
  }));

  server.registerTool("bind_factory_session", {
    title: "Bind a Factory session",
    description: "Connect a selected Factory Droid session to Agent Relay for incoming messages. History waits until this workspace has reviewed acquisition ownership and publication support. Requires the connected key owner.",
    inputSchema: { session_id: z.string().min(1).max(160), computer_id: z.string().min(1).max(256).optional() },
    annotations,
  }, ({ session_id, computer_id }) => run(async () => {
    let computerId = computer_id;
    if (!computerId) {
      // The session's computer, from the owner's own computer list; ambiguity asks for computer_id.
      const { computers } = await service.computers(access);
      const active = computers.filter((computer) => computer.status === "active");
      const only = computers.length === 1 ? computers[0] : active.length === 1 ? active[0] : undefined;
      if (!only) throw new FactoryHttpError(422, "invalid_request", "Several Factory computers are available. Provide computer_id.");
      computerId = only.id;
    }
    return service.bind(access, { sessionId: session_id, computerId });
  }));

  server.registerTool("unbind_factory_session", {
    title: "Unbind a Factory session",
    description: "Disconnect a Factory session from Relay; revokes injection and its scoped reply capability. Preserves uploaded history.",
    inputSchema: { binding_id: z.string().uuid() },
    annotations: { ...annotations, destructiveHint: true },
  }, ({ binding_id }) => run(async () => {
    await service.unbind(access, binding_id);
    return { binding_id, unbound: true };
  }));
}
