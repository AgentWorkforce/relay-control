import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { CAPABILITY_DISCOVERY_TOOL, describeCapabilities } from "./catalog.js";
import type { McpContext } from "./context.js";
import { RelayToolError, relayService } from "./relay-participants.js";

const NATIVE_CHECK_RETRY_REASON = "Agent Relay could not check this chat's synced Desktop identity right now. Retry describe_capabilities.";
const NATIVE_CHECK_RETRY_GUIDANCE = "Retry shortly. If the check keeps failing, ask the operator to verify Relay and database health.";

/**
 * describe_capabilities, ported from Cloud's
 * `lib/mcp/capability-discovery-tool.ts`: this connection's endpoint, auth
 * mode, scopes, workspace role and every tool group, with the reason for each
 * one it cannot use. Read-only; the role was read at admission.
 */
export function registerCapabilityDiscovery(server: McpServer, context: McpContext,
  options: { nativeStatus?: () => Promise<unknown> } = {}): void {
  server.registerTool(CAPABILITY_DISCOVERY_TOOL, {
    title: "Describe this connection's capabilities",
    description: "Use when an expected Agent Relay capability is missing or an operation is refused. Returns this MCP connection's endpoint, authentication mode, granted scopes, current workspace role and tool groups; unavailable or restricted groups include the exact reason and enablement requirements. Read-only.",
    inputSchema: {},
    annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  }, async () => {
    const managed = !context.oauth && (context.desktopCall.required || context.desktopCall.provider !== undefined);
    let nativeAuthorityAvailable: boolean | undefined;
    let nativeAuthorityReason: string | undefined;
    let nativeAuthorityHowToEnable: string | undefined;
    // Staff read grants do not serve relay_messaging, so probing their native
    // identity would add a database and Relay round trip without changing the report.
    if (managed && context.authMode !== "staff_read_grant") {
      try {
        if (options.nativeStatus) await options.nativeStatus();
        else await relayService(context).status();
        nativeAuthorityAvailable = true;
      } catch (error) {
        nativeAuthorityAvailable = false;
        if (error instanceof RelayToolError) {
          nativeAuthorityReason = error.message;
          nativeAuthorityHowToEnable = "Follow the guidance in the refusal reason, then retry.";
        } else {
          nativeAuthorityReason = NATIVE_CHECK_RETRY_REASON;
          nativeAuthorityHowToEnable = NATIVE_CHECK_RETRY_GUIDANCE;
          console.warn("[selfhost-mcp] native identity capability check failed", {
            error: error instanceof Error ? error.name : "unknown",
          });
        }
      }
    }
    const report = describeCapabilities({
      endpointUrl: context.endpointUrl,
      authMode: context.authMode,
      scopes: context.principal.scopes,
      workspaceId: context.workspace.id,
      role: context.role,
      amp: Boolean(context.amp),
      factory: Boolean(context.factory),
      replicas: Boolean(context.replicas),
      webhookInbox: Boolean(context.webhookInbox),
      launch: Boolean(context.launch),
      capyPermits: Boolean(context.oauth && context.capyPermits),
      customerSupport: Boolean(context.customerSupport),
      grokRoutines: Boolean(context.grokRoutines),
      nativeAuthorityAvailable,
      nativeAuthorityReason,
      nativeAuthorityHowToEnable,
      providers: await context.providers(),
    });
    return {
      structuredContent: report as unknown as Record<string, unknown>,
      content: [{ type: "text" as const, text: JSON.stringify(report) }],
    };
  });
}
