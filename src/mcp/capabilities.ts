import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CAPABILITY_DISCOVERY_TOOL, describeCapabilities } from "./catalog.js";
import type { McpContext } from "./context.js";

/**
 * describe_capabilities, ported from Cloud's
 * `lib/mcp/capability-discovery-tool.ts`: this connection's endpoint, auth
 * mode, scopes, workspace role and every tool group, with the reason for each
 * one it cannot use. Read-only; the role was read at admission.
 */
export function registerCapabilityDiscovery(server: McpServer, context: McpContext): void {
  server.registerTool(CAPABILITY_DISCOVERY_TOOL, {
    title: "Describe this connection's capabilities",
    description: "Use when an expected Agent Relay capability is missing or an operation is refused. Returns this MCP connection's endpoint, authentication mode, granted scopes, current workspace role and tool groups; unavailable or restricted groups include the exact reason and enablement requirements. Read-only.",
    inputSchema: {},
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async () => {
    const report = describeCapabilities({
      endpointUrl: context.endpointUrl,
      authMode: context.authMode,
      scopes: context.principal.scopes,
      workspaceId: context.workspace.id,
      role: context.role,
      amp: Boolean(context.amp),
      factory: Boolean(context.factory),
      launch: Boolean(context.launch),
      providers: await context.providers(),
    });
    return {
      structuredContent: report as unknown as Record<string, unknown>,
      content: [{ type: "text" as const, text: JSON.stringify(report) }],
    };
  });
}
