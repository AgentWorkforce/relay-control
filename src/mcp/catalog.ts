import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ProviderStatus } from "../providers/registry.js";

/**
 * The shared-sessions MCP tool catalog, ported from Cloud's
 * `packages/web/lib/mcp/tool-catalog.ts`. Every group Cloud knows is listed,
 * in Cloud's reporting order, so describe_capabilities explains each one; the
 * self-host plan decides which groups this server registers. Registration goes
 * through `registerToolPlan`, so adding a group is one plan entry and one
 * registrar.
 */

export const MCP_FACADE = { facade: "shared-sessions", path: "/api/v1/mcp/shared-sessions", name: "Agent Relay Sessions" } as const;

const TOOL_TITLE_WORDS: Readonly<Record<string, string>> = {
  api: "API",
  capy: "Capy",
  grok: "Grok",
  mcp: "MCP",
  relay: "Relay",
  replicas: "Replicas",
  ui: "UI",
};

/**
 * Give every registered tool a human-readable title derived from its name.
 * An explicit title supplied by a registrar always wins.
 */
export function ensureToolTitles(server: McpServer): void {
  const registerTool = server.registerTool.bind(server) as (...args: unknown[]) => unknown;
  server.registerTool = ((name: string, config: unknown, ...rest: unknown[]) => {
    const words = name.split(/[._-]+/).filter(Boolean);
    const title = words.map((word, index) => TOOL_TITLE_WORDS[word]
      ?? (index === 0 ? `${word.charAt(0).toUpperCase()}${word.slice(1)}` : word)).join(" ");
    const titledConfig = config && typeof config === "object" && !Array.isArray(config)
      ? { title, ...config as Record<string, unknown> }
      : config;
    return registerTool(name, titledConfig, ...rest);
  }) as McpServer["registerTool"];
}

export const RELAY_TOOLS = ["list_relay_agents", "send_relay_message", "read_relay_conversation", "join_relay", "leave_relay",
  "relay_status", "check_relay_inbox", "list_relay_channels", "subscribe_relay_channel", "unsubscribe_relay_channel",
  "post_relay_channel", "read_relay_channel"] as const;
const RELAY_SPAWN_TOOLS = ["list_relay_spawn_targets", "spawn_relay_agent", "get_relay_spawn_status", "release_relay_agent"] as const;
const AMP_TOOLS = ["list_amp_threads", "bind_amp_thread", "unbind_amp_thread"] as const;
const FACTORY_TOOLS = ["list_factory_sessions", "bind_factory_session", "unbind_factory_session"] as const;
const REPLICAS_TOOLS = ["list_replicas_environments", "spawn_replica", "get_replica_spawn", "recover_replica_spawn",
  "bind_replica", "release_replica"] as const;
const CAPY_BINDING_TOOLS = ["bind_capy_thread", "unbind_capy_thread"] as const;
const CAPY_SPAWN_TOOLS = ["list_capy_projects", "spawn_capy_thread", "get_capy_thread_spawn"] as const;
export const SHARED_SESSION_READ_TOOLS = ["open_shared_sessions", "search_shared_sessions", "get_shared_session",
  "get_shared_session_context", "list_session_timings"] as const;
const SCREEN_TOOLS = ["show_ui", "show_ui_guide"] as const;
const EVENT_TOOLS = ["get_event", "get_recent_events", "connect_grok_bot_routine", "disconnect_grok_bot_routine",
  "connect_muse_polling", "disconnect_muse_polling",
  "answer_reply_question", "relay_events_status", "use_relay_identity"] as const;
const INBOX_APP_TOOLS = ["relay_inbox", "relay_inbox_tab", "relay_inbox_refresh", "relay_inbox_conversation"] as const;
const EVENTS_SETTINGS_TOOLS = ["settings.read", "settings.update"] as const;
const CONNECT_TOOLS = ["create_connect", "host_connect_agent", "join_connect", "connect_send", "connect_inbox", "connect_status",
  "extend_connect", "create_connect_observer", "list_connect_observers", "revoke_connect_observer", "end_connect"] as const;
export const CAPABILITY_DISCOVERY_TOOL = "describe_capabilities";

export type ToolGroupId =
  | "shared_session_reads" | "team_activity" | "relay_messaging" | "hosted_launch" | "replicas" | "amp" | "factory" | "capy_binding"
  | "customer_support" | "capy_launch" | "connect" | "events" | "relay_inbox_app" | "screens" | "events_settings" | "capability_discovery";

type GroupDefinition = {
  title: string;
  tools: readonly string[];
  /** Cloud serves the group only on its relay-events endpoint, which self-host does not run. */
  relayEventsOnly?: boolean;
};

/** Every group, in the order describe_capabilities reports them (Cloud's order). */
export const TOOL_GROUPS: Readonly<Record<ToolGroupId, GroupDefinition>> = {
  shared_session_reads: { title: "Shared session search and transcripts", tools: SHARED_SESSION_READ_TOOLS },
  team_activity: { title: "Workspace team activity", tools: ["list_team_activity"] },
  relay_messaging: { title: "Relay messaging and channels", tools: RELAY_TOOLS },
  customer_support: { title: "Private customer support", tools: ["ask_customer_support"] },
  hosted_launch: { title: "Agent launches", tools: RELAY_SPAWN_TOOLS },
  amp: { title: "Amp threads", tools: AMP_TOOLS },
  factory: { title: "Factory Droid sessions", tools: FACTORY_TOOLS },
  replicas: { title: "Replicas agents", tools: REPLICAS_TOOLS },
  capy_binding: { title: "Capy thread binding", tools: CAPY_BINDING_TOOLS },
  capy_launch: { title: "Capy thread launches", tools: CAPY_SPAWN_TOOLS },
  connect: { title: "Relay Connect rooms", tools: CONNECT_TOOLS },
  events: { title: "Agent Relay events and Grok Bot routines", tools: EVENT_TOOLS, relayEventsOnly: true },
  relay_inbox_app: { title: "Relay inbox app", tools: INBOX_APP_TOOLS, relayEventsOnly: true },
  screens: { title: "Live screens (show_ui)", tools: SCREEN_TOOLS },
  events_settings: { title: "Event handling settings", tools: EVENTS_SETTINGS_TOOLS, relayEventsOnly: true },
  capability_discovery: { title: "Capability discovery", tools: [CAPABILITY_DISCOVERY_TOOL] },
};

export type ToolPlanEntry = { group: ToolGroupId; tools: readonly string[] };

/** The self-host shared-sessions plan, in registration order. */
export function planToolGroups(options: { amp?: boolean; factory?: boolean; launch?: boolean } = {}): ToolPlanEntry[] {
  const groups: ToolGroupId[] = ["shared_session_reads", "team_activity", "relay_messaging"];
  // Launch tools exist only when SELFHOST_FEATURES selects launch; role and
  // connection kind are checked on every call.
  if (options.launch) groups.push("hosted_launch");
  // Amp tools exist only when SELFHOST_AMP_ENABLED is on.
  if (options.amp) groups.push("amp");
  // Factory tools exist only when SELFHOST_FACTORY_ENABLED is on.
  if (options.factory) groups.push("factory");
  groups.push("capability_discovery");
  return groups.map(group => ({ group, tools: TOOL_GROUPS[group].tools }));
}

export type ToolPlanRegistrars = { [G in ToolGroupId]?: (entry: ToolPlanEntry) => void };

/** Registers a plan through the server's registrars; a group without one is a programming error. */
export function registerToolPlan(plan: readonly ToolPlanEntry[], registrars: ToolPlanRegistrars): void {
  for (const planned of plan) {
    const register = registrars[planned.group];
    if (!register) throw new Error(`No MCP registrar for tool group ${planned.group}`);
    register(planned);
  }
}

/** The owner/admin refusal shared by describe_capabilities and every launch tool. */
export const LAUNCH_ROLE_REFUSAL = "Only current workspace owners and admins can manage agent launches. Call describe_capabilities for details.";

export type McpAuthMode = "session" | "cli_login" | "oauth";

const AUTH_MODE_LABELS: Readonly<Record<McpAuthMode, string>> = {
  session: "browser session",
  cli_login: "Agent Relay CLI login",
  oauth: "workspace-bound OAuth connection",
};

export type WorkspaceRole = "owner" | "admin" | "member" | "none" | null;

export type CapabilityGroup = {
  id: ToolGroupId;
  title: string;
  status: "available" | "restricted" | "unavailable";
  tools: string[];
  reason?: string;
  how_to_enable?: string;
};

export type CapabilityReport = {
  endpoint: { facade: typeof MCP_FACADE.facade; name: string; url: string };
  connection: { auth_mode: McpAuthMode; description: string; scopes: string[] };
  workspace: { workspace_id: string; role: Exclude<WorkspaceRole, null> | "unknown"; can_launch: boolean | null };
  groups: CapabilityGroup[];
  /** The provider catalog with this build's runtime state (src/providers/registry.ts). */
  providers: ProviderStatus[];
};

/**
 * What this connection can use and, for everything else, why not. Derived
 * from the same plan the server registered. Cloud's report also names its
 * relay-events endpoint (`other_endpoint`); self-host does not serve one, so
 * the field is omitted. `can_launch` is true only when the launch feature is
 * selected, this is a person connection (not OAuth) and the role read at
 * admission is owner or admin; each launch call checks again.
 */
export function describeCapabilities(input: {
  endpointUrl: string;
  authMode: McpAuthMode;
  scopes: readonly string[];
  workspaceId: string;
  role: WorkspaceRole;
  amp?: boolean;
  factory?: boolean;
  launch?: boolean;
  providers: ProviderStatus[];
}): CapabilityReport {
  const launchRole = input.role === "owner" || input.role === "admin";
  const canLaunch = Boolean(input.launch) && input.authMode !== "oauth" && launchRole;
  const planned = new Map(planToolGroups({ amp: input.amp, factory: input.factory, launch: input.launch && input.authMode !== "oauth" })
    .map(item => [item.group, item]));
  const groups = (Object.keys(TOOL_GROUPS) as ToolGroupId[]).map((id): CapabilityGroup => {
    const definition = TOOL_GROUPS[id];
    const base = { id, title: definition.title };
    const item = planned.get(id);
    if (item && id === "shared_session_reads" && input.authMode === "oauth") {
      return { ...base, status: "restricted", tools: [...item.tools],
        reason: "This OAuth connection does not grant transcript-history access.",
        how_to_enable: "Use an authorized native Agent Relay session for transcript reads." };
    }
    if (item && id === "hosted_launch" && !launchRole) {
      return { ...base, status: "restricted", tools: [...item.tools],
        reason: LAUNCH_ROLE_REFUSAL,
        how_to_enable: "Ask a workspace owner to make you an owner or admin." };
    }
    if (item) return { ...base, status: "available", tools: [...item.tools] };
    if (id === "hosted_launch" && input.launch && input.authMode === "oauth") {
      return { ...base, status: "unavailable", tools: [...definition.tools],
        reason: "Agent launches are not available through an OAuth MCP connection on this self-hosted site.",
        how_to_enable: "Connect with an Agent Relay CLI login or Agent Relay Desktop." };
    }
    if (id === "hosted_launch") {
      return { ...base, status: "unavailable", tools: [...definition.tools],
        reason: "Agent launches are not enabled on this self-hosted installation.",
        how_to_enable: "An operator adds launch to SELFHOST_FEATURES (chart selectedFeatures)." };
    }
    return { ...base, status: "unavailable", tools: [...definition.tools],
      reason: `${definition.title} are not part of the self-hosted Agent Relay edition.`,
      how_to_enable: "Use the hosted Agent Relay Cloud for these tools." };
  });
  return {
    endpoint: { facade: MCP_FACADE.facade, name: MCP_FACADE.name, url: input.endpointUrl },
    connection: { auth_mode: input.authMode, description: AUTH_MODE_LABELS[input.authMode], scopes: [...input.scopes] },
    workspace: { workspace_id: input.workspaceId, role: input.role ?? "unknown", can_launch: canLaunch },
    groups,
    providers: input.providers,
  };
}
