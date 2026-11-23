import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { ProviderStatus } from "../providers/registry.js";
import { GROK_EVENT_TOOLS, GROK_ROUTINE_TOOLS } from "./grok-routine.js";
import { MCP_HISTORY_SCOPE } from "./oauth/protocol.js";

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

export const RELAY_TOOLS = ["list_relay_agents", "get_relay_agent_card", "set_relay_agent_card", "send_relay_message", "get_relay_message_status", "read_relay_conversation", "join_relay", "leave_relay",
  "relay_status", "check_relay_inbox", "list_relay_channels", "subscribe_relay_channel", "unsubscribe_relay_channel",
  "post_relay_channel", "read_relay_channel"] as const;
/** Directory reads do not act as the managed chat, so they survive a missing synced Desktop identity. */
const RELAY_DIRECTORY_TOOLS = ["list_relay_agents", "get_relay_agent_card"] as const;
const RELAY_SPAWN_TOOLS = ["list_relay_spawn_targets", "spawn_relay_agent", "get_relay_spawn_status", "release_relay_agent"] as const;
const AMP_TOOLS = ["list_amp_threads", "bind_amp_thread", "unbind_amp_thread"] as const;
const WEBHOOK_INBOX_TOOLS = ["link_webhook_inbox", "unlink_webhook_inbox"] as const;
const FACTORY_TOOLS = ["list_factory_sessions", "bind_factory_session", "unbind_factory_session"] as const;
const REPLICAS_TOOLS = ["list_replicas_environments", "spawn_replica", "get_replica_spawn", "recover_replica_spawn",
  "bind_replica", "release_replica"] as const;
const CAPY_BINDING_TOOLS = ["bind_capy_thread", "unbind_capy_thread"] as const;
const CAPY_SPAWN_TOOLS = ["list_capy_projects", "spawn_capy_thread", "get_capy_thread_spawn"] as const;
export const SHARED_SESSION_READ_TOOLS = ["open_shared_sessions", "search_shared_sessions", "get_shared_session",
  "get_shared_session_context", "list_session_timings", "list_session_summaries", "get_session_summary"] as const;
/** Read-only proxies for the read API's /v1/relayfacts routes (relayfacts.ts). */
export const RELAYFACTS_TOOLS = ["relayfacts_list", "relayfacts_get"] as const;
const SCREEN_TOOLS = ["show_ui", "show_ui_guide"] as const;
const EVENT_TOOLS = ["get_event", "get_recent_events",
  "connect_muse_polling", "disconnect_muse_polling",
  "answer_reply_question", "relay_events_status", "use_relay_identity"] as const;
const INBOX_APP_TOOLS = ["relay_inbox", "relay_inbox_tab", "relay_inbox_refresh", "relay_inbox_conversation"] as const;
const EVENTS_SETTINGS_TOOLS = ["settings.read", "settings.update"] as const;
const CONNECT_TOOLS = ["create_connect", "host_connect_agent", "join_connect", "connect_send", "connect_inbox", "connect_status",
  "extend_connect", "create_connect_observer", "list_connect_observers", "revoke_connect_observer", "end_connect"] as const;
export const CAPABILITY_DISCOVERY_TOOL = "describe_capabilities";
/** Who may read one session, managed in relaygate (session-access.ts). */
export const SESSION_ACCESS_TOOLS = ["get_session_access", "set_session_access", "reset_session_access",
  "get_session_access_history"] as const;

export type ToolGroupId =
  | "shared_session_reads" | "team_activity" | "relayfacts" | "relay_messaging" | "hosted_launch" | "replicas" | "amp" | "factory" | "webhook_inbox" | "capy_binding"
  | "customer_support" | "capy_launch" | "connect" | "events" | "grok_routines" | "grok_events" | "relay_inbox_app" | "screens" | "events_settings"
  | "session_access" | "capability_discovery";

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
  relayfacts: { title: "Relayfacts topics", tools: RELAYFACTS_TOOLS },
  relay_messaging: { title: "Relay messaging and channels", tools: RELAY_TOOLS },
  customer_support: { title: "Private customer support", tools: ["ask_customer_support"] },
  hosted_launch: { title: "Agent launches", tools: RELAY_SPAWN_TOOLS },
  amp: { title: "Amp threads", tools: AMP_TOOLS },
  factory: { title: "Factory Droid sessions", tools: FACTORY_TOOLS },
  replicas: { title: "Replicas agents", tools: REPLICAS_TOOLS },
  webhook_inbox: { title: "Webhook inboxes for bound agents", tools: WEBHOOK_INBOX_TOOLS },
  capy_binding: { title: "Capy thread binding", tools: CAPY_BINDING_TOOLS },
  capy_launch: { title: "Capy thread launches", tools: CAPY_SPAWN_TOOLS },
  connect: { title: "Relay Connect rooms", tools: CONNECT_TOOLS },
  events: { title: "Agent Relay events", tools: EVENT_TOOLS, relayEventsOnly: true },
  grok_routines: { title: "Self-hosted Grok Bot webhook wake-ups", tools: GROK_ROUTINE_TOOLS },
  // SELFHOST_GROK_ROUTINES_CLOUD_COPY: the event reads Cloud's copied routine prompt calls.
  grok_events: { title: "Grok Bot routine events (Cloud copy)", tools: GROK_EVENT_TOOLS },
  relay_inbox_app: { title: "Relay inbox app", tools: INBOX_APP_TOOLS, relayEventsOnly: true },
  screens: { title: "Live screens (show_ui)", tools: SCREEN_TOOLS },
  events_settings: { title: "Event handling settings", tools: EVENTS_SETTINGS_TOOLS, relayEventsOnly: true },
  session_access: { title: "Session access management", tools: SESSION_ACCESS_TOOLS },
  capability_discovery: { title: "Capability discovery", tools: [CAPABILITY_DISCOVERY_TOOL] },
};

export type ToolPlanEntry = { group: ToolGroupId; tools: readonly string[] };

/** The self-host shared-sessions plan, in registration order. */
export function planToolGroups(options: { amp?: boolean; factory?: boolean; replicas?: boolean; webhookInbox?: boolean; launch?: boolean; capyPermits?: boolean; grokRoutines?: boolean; grokEvents?: boolean; sessionAccess?: boolean; staffReadGrant?: boolean; agentIdentity?: boolean } = {}): ToolPlanEntry[] {
  // A staff read grant (docs/staff-read-grants.md) reaches the shared-session
  // reads and capability discovery only, whatever else the server enables.
  if (options.staffReadGrant) {
    return (["shared_session_reads", "capability_discovery"] as const).map(group => ({ group, tools: TOOL_GROUPS[group].tools }));
  }
  // A workspace agent identity token (docs/identity.md) reaches Relay
  // messaging and capability discovery only, whatever else the server enables.
  if (options.agentIdentity) {
    return (["relay_messaging", "capability_discovery"] as const).map(group => ({ group, tools: TOOL_GROUPS[group].tools }));
  }
  const groups: ToolGroupId[] = ["shared_session_reads", "team_activity", "relayfacts", "relay_messaging", "customer_support"];
  // Launch tools exist only when SELFHOST_FEATURES selects launch; role and
  // connection kind are checked on every call.
  if (options.launch) groups.push("hosted_launch");
  // Amp tools exist only when SELFHOST_AMP_ENABLED is on.
  if (options.amp) groups.push("amp");
  // Factory tools exist only when SELFHOST_FACTORY_ENABLED is on.
  if (options.factory) groups.push("factory");
  // Replicas tools exist only when SELFHOST_REPLICAS_ENABLED is on.
  if (options.replicas) groups.push("replicas");
  // Webhook inbox links exist only while the events_shim feature is selected.
  if (options.webhookInbox) groups.push("webhook_inbox");
  if (options.capyPermits) groups.push("capy_binding");
  if (options.grokRoutines) groups.push("grok_routines");
  if (options.grokRoutines && options.grokEvents) groups.push("grok_events");
  // Session access tools exist only where the read API is relaygate and the
  // connection is a person's own session (src/sessions/access.ts).
  if (options.sessionAccess) groups.push("session_access");
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

export type McpAuthMode = "session" | "cli_login" | "oauth" | "staff_read_grant" | "agent_identity";

/** The only tools a staff read grant may list or call; the MCP route refuses every other call before a server is built. */
export const STAFF_READ_GRANT_TOOLS: readonly string[] = [...SHARED_SESSION_READ_TOOLS, CAPABILITY_DISCOVERY_TOOL];

/**
 * The only tools a workspace agent identity token may list or call: Relay
 * messaging and capability discovery. The MCP route refuses every other call
 * before a server is built, and the server registers nothing else for it.
 */
export const AGENT_IDENTITY_TOOLS: readonly string[] = [...RELAY_TOOLS, CAPABILITY_DISCOVERY_TOOL];

const AUTH_MODE_LABELS: Readonly<Record<McpAuthMode, string>> = {
  session: "browser session",
  cli_login: "Agent Relay CLI login",
  oauth: "workspace-bound OAuth connection",
  staff_read_grant: "staff read grant (read-only, sessions-only, pinned to one workspace)",
  agent_identity: "workspace agent identity token (Relay messaging only, as one named agent)",
};

export type WorkspaceRole = "owner" | "admin" | "member" | "none" | null;

export type CapabilityGroup = {
  id: ToolGroupId;
  title: string;
  status: "available" | "restricted" | "unavailable";
  tools: string[];
  /** Listed tools whose calls are refused while the rest of the group remains usable. */
  restricted_tools?: Array<{ name: string; reason: string }>;
  reason?: string;
  how_to_enable?: string;
  call_requirements?: string;
};

export type CapabilityReport = {
  endpoint: { facade: typeof MCP_FACADE.facade; name: string; url: string };
  connection: { auth_mode: McpAuthMode; description: string; scopes: string[] };
  workspace: {
    workspace_id: string; role: Exclude<WorkspaceRole, null> | "unknown"; can_launch: boolean | null;
    /** With launches on: the spawn memory policy mode (docs/specs/spawn-placement-memory.md). */
    spawn_memory_policy?: "off" | "observe" | "rank" | "enforce";
  };
  groups: CapabilityGroup[];
  /** The provider catalog with this build's runtime state (src/providers/registry.ts). */
  providers: ProviderStatus[];
};

/**
 * What this connection can use and, for everything else, why not. Derived
 * from the same plan the server registered. Cloud's report also names its
 * relay-events endpoint (`other_endpoint`); self-host does not serve one, so
 * the field is omitted. `can_launch` is true only when the launch feature is
 * selected and the consenting person's role read at
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
  replicas?: boolean;
  webhookInbox?: boolean;
  launch?: boolean;
  capyPermits?: boolean;
  customerSupport?: boolean;
  grokRoutines?: boolean;
  grokEvents?: boolean;
  /** Whether this connection was given the session access tools (see planToolGroups). */
  sessionAccess?: boolean;
  /** Whether a managed native call resolves to its synced Desktop identity. */
  nativeAuthorityAvailable?: boolean;
  /** Safe reason and remedy when the managed native identity cannot be used. */
  nativeAuthorityReason?: string;
  nativeAuthorityHowToEnable?: string;
  providers: ProviderStatus[];
}): CapabilityReport {
  const launchRole = input.role === "owner" || input.role === "admin";
  const canLaunch = Boolean(input.launch) && launchRole;
  const planned = new Map(planToolGroups({ amp: input.amp, factory: input.factory, replicas: input.replicas, webhookInbox: input.webhookInbox, launch: input.launch,
    capyPermits: input.capyPermits && input.authMode === "oauth", grokRoutines: input.grokRoutines, grokEvents: input.grokEvents, sessionAccess: input.sessionAccess,
    staffReadGrant: input.authMode === "staff_read_grant", agentIdentity: input.authMode === "agent_identity" })
    .map(item => [item.group, item]));
  const groups = (Object.keys(TOOL_GROUPS) as ToolGroupId[]).map((id): CapabilityGroup => {
    const definition = TOOL_GROUPS[id];
    const base = { id, title: definition.title };
    const item = planned.get(id);
    if (input.authMode === "staff_read_grant") {
      if (item) return { ...base, status: "available", tools: [...item.tools] };
      return { ...base, status: "unavailable", tools: [...definition.tools],
        reason: "This connection is a staff read grant: read-only access to one workspace's shared sessions and capability discovery, nothing else.",
        how_to_enable: "Use your own Agent Relay sign-in as a member of a workspace for these tools." };
    }
    if (input.authMode === "agent_identity") {
      if (item) return { ...base, status: "available", tools: [...item.tools], ...(id === "relay_messaging"
        ? { call_requirements: "Acts only as this token's named agent. join_relay takes no desktop_address and no other name; `as` may name only this agent." } : {}) };
      return { ...base, status: "unavailable", tools: [...definition.tools],
        reason: "This connection is a workspace agent identity token: Relay messaging as one named agent and capability discovery, nothing else.",
        how_to_enable: "Use a person's Agent Relay sign-in for these tools." };
    }
    if (id === "customer_support" && !input.customerSupport) return { ...base, status: "unavailable", tools: [...definition.tools],
      reason: "The customer support backend is not configured on this installation.",
      how_to_enable: "Configure SELFHOST_CUSTOMER_SUPPORT_URL and SELFHOST_CUSTOMER_SUPPORT_TOKEN for the support service." };
    // OAuth reads need the opt-in relay:history scope (never in the baseline
    // grant); with it the group is available as for a native session.
    if (item && (id === "shared_session_reads" || id === "relayfacts") && input.authMode === "oauth" && !input.scopes.includes(MCP_HISTORY_SCOPE)) {
      return { ...base, status: "restricted", tools: [...item.tools],
        reason: "This OAuth connection was not granted relay:history.",
        how_to_enable: "Reconnect and request the relay:history scope on the sessions resource; the consent page lists it as a separate line." };
    }
    if (item && id === "hosted_launch" && !launchRole) {
      return { ...base, status: "restricted", tools: [...item.tools],
        reason: LAUNCH_ROLE_REFUSAL,
        how_to_enable: "Ask a workspace owner to make you an owner or admin." };
    }
    if (item && id === "replicas" && !launchRole) {
      return { ...base, status: "restricted", tools: [...item.tools],
        reason: "Only current workspace owners and admins with a person connection can manage Replicas.",
        how_to_enable: "Ask a workspace owner to make you an owner or admin." };
    }
    if (item && id === "webhook_inbox" && !launchRole) {
      return { ...base, status: "restricted", tools: [...item.tools],
        reason: "Only current workspace owners and admins with a person connection can link webhook inboxes.",
        how_to_enable: "Ask a workspace owner to make you an owner or admin." };
    }
    if (id === "webhook_inbox" && !item) return { ...base, status: "unavailable", tools: [...definition.tools],
      reason: input.authMode === "oauth"
        ? "Webhook inbox links need a person connection; this OAuth connection acts only as its approved agent."
        : "Webhook inboxes are not enabled on this self-hosted installation.",
      how_to_enable: input.authMode === "oauth"
        ? "Use your own Agent Relay sign-in (a person connection) for these tools."
        : "An operator adds events_shim to SELFHOST_FEATURES (chart selectedFeatures)." };
    if (item && id === "relay_messaging" && input.nativeAuthorityAvailable === false) {
      const reason = input.nativeAuthorityReason ?? "Agent Relay could not verify this chat's synced Desktop identity.";
      return { ...base, status: "available", tools: [...item.tools],
        restricted_tools: item.tools.filter(name => !(RELAY_DIRECTORY_TOOLS as readonly string[]).includes(name))
          .map(name => ({ name, reason })),
        how_to_enable: input.nativeAuthorityHowToEnable ?? "Reconnect this chat from Agent Relay Desktop and wait for its identity to sync, then retry.",
        call_requirements: "Agent directory reads remain available. Acting as this managed chat requires its synced Desktop identity." };
    }
    if (item) return { ...base, status: "available", tools: [...item.tools], ...(id === "customer_support"
      ? { call_requirements: "Available to all signed-in customers. Current credentials and workspace membership are checked before sending and before returning an answer." } : {}) };
    if (id === "grok_events" && !item) return { ...base, status: "unavailable", tools: [...definition.tools],
      reason: "Grok Bot routine events serve Grok Bot connections only, on a server with SELFHOST_GROK_ROUTINES_CLOUD_COPY on.",
      how_to_enable: "Ask your operator to set SELFHOST_GROK_ROUTINES_CLOUD_COPY=on, then connect from Grok Bot." };
    if (id === "grok_routines") return { ...base, status: "unavailable", tools: [...definition.tools],
      reason: "Webhook wake-ups require a Grok Bot OAuth connection on this self-hosted server.",
      how_to_enable: "Connect Grok Bot to this server's /cloud/api/v1/mcp/shared-sessions endpoint, then call connect_grok_bot_routine." };
    if (id === "events") return { ...base, status: "unavailable", tools: [...definition.tools],
      reason: "The MCP Events endpoint is not available here. Self-hosted Grok Bot webhook wake-ups use the grok_routines group on this connection.",
      how_to_enable: "Use connect_grok_bot_routine from a Grok Bot OAuth connection to this server's /cloud/api/v1/mcp/shared-sessions endpoint." };
    if (id === "replicas") return { ...base, status: "unavailable", tools: [...definition.tools],
      reason: "Replicas agents are not enabled on this self-hosted installation.",
      how_to_enable: "An operator sets SELFHOST_REPLICAS_ENABLED=true and an owner or admin connects Replicas in Settings → Connections." };
    if (id === "hosted_launch") {
      return { ...base, status: "unavailable", tools: [...definition.tools],
        reason: "Agent launches are not enabled on this self-hosted installation.",
        how_to_enable: "An operator adds launch to SELFHOST_FEATURES (chart selectedFeatures)." };
    }
    if (id === "session_access") return { ...base, status: "unavailable", tools: [...definition.tools],
      reason: input.authMode === "oauth"
        ? "Session access management needs your own Agent Relay sign-in; an OAuth connection cannot use it."
        : "Session access management needs relaygate's sessions listener as this installation's session read API, and your own exchanged Agent Relay sign-in.",
      how_to_enable: "An operator points the session read API URL at relaygate's sessions listener, makes read token mints carry the reader kind (SESSION_READ_MINT_INCLUDE_READER_KIND=true, or unset with SELFHOST_RELAYGATE_PUBLIC_URL set) and sets SESSION_READ_API_MCP_READS=true; then connect with your own Agent Relay sign-in. relaygate still decides who is a session access administrator." };
    if (id === "connect") {
      // Connect rooms have no self-host implementation yet. The hosted edition
      // serves them; a public hosted invite is joined from Agent Relay Desktop,
      // which never goes through this server.
      return { ...base, status: "unavailable", tools: [...definition.tools],
        reason: "Relay Connect rooms are not available on this self-hosted installation.",
        how_to_enable: "There is no setting for this on the self-hosted server. Joining a public hosted Connect invite from Agent Relay Desktop is separate and does not use this server." };
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
