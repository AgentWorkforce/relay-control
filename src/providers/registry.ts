import { planToolGroups, type ToolGroupId } from "../mcp/catalog.js";

/**
 * The shared provider catalog: what each external agent provider is, how it
 * connects, where its history comes from and which MCP tool groups it owns.
 * Metadata only. Whether a provider is actually usable on this installation
 * is runtime state, reported as three separate booleans from
 * `ProviderProbes` (see `providerStatuses`), never folded into one.
 */

export type ProviderId = "amp" | "factory" | "copilot" | "capy" | "replicas" | "dot" | "grok-bot";
export type ProviderFamily = "remote_coding_agent" | "assistant_connector" | "local_app";
export type HistoryKind = "native_transcript_pull" | "redacted_mcp_activity" | "desktop_owned" | "none";

export type ProviderDescriptor = {
  id: ProviderId;
  product: string;
  family: ProviderFamily;
  transport: string;
  setup: "api_key" | "oauth_grant" | "desktop_roundtrip";
  history: {
    kind: HistoryKind;
    source: string | null;
    coverage: "event_triggered" | "continuous" | "passive_tail" | "n_a";
    notes?: string;
  };
  outbound: "relay:mcp" | "relay:events" | "none";
  /** MCP tool groups the provider requires (not necessarily owned exclusively). */
  mcpGroups: ToolGroupId[];
};

/** Deep-freezes one descriptor (its history and group list included). */
function freeze(descriptor: ProviderDescriptor): Readonly<ProviderDescriptor> {
  Object.freeze(descriptor.history);
  Object.freeze(descriptor.mcpGroups);
  return Object.freeze(descriptor);
}

/** Every provider, in reporting order. */
export const PROVIDERS: readonly Readonly<ProviderDescriptor>[] = Object.freeze([
  freeze({
    id: "amp",
    product: "Amp",
    family: "remote_coding_agent",
    transport: "Relaycast subscriptions to the relay-events webhook plus hosted inbox polling",
    setup: "api_key",
    history: {
      kind: "native_transcript_pull",
      source: "amp",
      coverage: "event_triggered",
      notes: "inactive until a push-only RelayHistory session issuer exists",
    },
    outbound: "relay:mcp",
    mcpGroups: ["amp"],
  }),
  freeze({
    id: "factory",
    product: "Factory",
    family: "remote_coding_agent",
    transport: "Factory session binding with a Relay agent",
    setup: "api_key",
    history: { kind: "native_transcript_pull", source: "droid", coverage: "event_triggered" },
    outbound: "relay:mcp",
    mcpGroups: ["factory"],
  }),
  freeze({
    id: "copilot",
    product: "GitHub Copilot",
    family: "local_app",
    transport: "Desktop MCP credential issuer roundtrip",
    setup: "desktop_roundtrip",
    history: { kind: "desktop_owned", source: null, coverage: "n_a" },
    outbound: "relay:mcp",
    mcpGroups: [],
  }),
  freeze({
    id: "capy",
    product: "Capy",
    family: "remote_coding_agent",
    transport: "API-key thread binding, relay-events and thread spawn",
    setup: "api_key",
    history: {
      kind: "native_transcript_pull",
      source: "capy",
      coverage: "event_triggered",
      notes: "no recurring history timer; final turns can lag until more Relay activity",
    },
    outbound: "relay:mcp",
    mcpGroups: ["capy_binding", "capy_launch"],
  }),
  freeze({
    id: "replicas",
    product: "Replicas",
    family: "remote_coding_agent",
    transport: "replicas.dev service client and tools (separate service, not the Grok Bot transcript store)",
    setup: "api_key",
    history: { kind: "native_transcript_pull", source: "replicas", coverage: "event_triggered" },
    outbound: "relay:mcp",
    mcpGroups: ["replicas"],
  }),
  freeze({
    id: "dot",
    product: "Dot",
    family: "assistant_connector",
    transport: "hosted MCP OAuth connector (connector kind chatgpt) with per-chat host-attached identities",
    setup: "oauth_grant",
    history: {
      kind: "redacted_mcp_activity",
      source: "chatgpt",
      coverage: "continuous",
      notes: "redacted MCP tool calls and results plus Relay messages grouped by grant and UTC day, not native transcripts",
    },
    outbound: "relay:mcp",
    mcpGroups: ["events"],
  }),
  freeze({
    id: "grok-bot",
    product: "Grok Bot",
    family: "assistant_connector",
    transport: "grok-bot routine webhook and polling through the events group",
    setup: "oauth_grant",
    history: {
      kind: "redacted_mcp_activity",
      source: "grok-bot",
      coverage: "continuous",
      notes: "plus a separate passive bounded local transcript-tail parser owned by RelayHistory",
    },
    outbound: "relay:mcp",
    mcpGroups: ["events"],
  }),
]);

export function providerDescriptor(id: string): Readonly<ProviderDescriptor> | undefined {
  return PROVIDERS.find(provider => provider.id === id);
}

/**
 * Runtime probes a build supplies for the provider modules it contains.
 * `implemented`: the provider module is present in this build.
 * `configured`: its configuration resolves.
 * `enabled`: the module is mounted and switched on.
 * A provider without a probe reports all three as false.
 */
export type ProviderProbe = {
  implemented: boolean;
  configured(): boolean | Promise<boolean>;
  enabled(): boolean | Promise<boolean>;
};
export type ProviderProbes = { readonly [P in ProviderId]?: ProviderProbe };

export type ProviderStatus = ProviderDescriptor & {
  implemented: boolean;
  configured: boolean;
  enabled: boolean;
  /** Every one of the provider's MCP groups is in this server's tool plan (false when it owns none). */
  mcpGroupsRegistered: boolean;
};

/** A probe that throws reports false for that state only. */
async function probeState(read: () => boolean | Promise<boolean>): Promise<boolean> {
  try {
    return (await read()) === true;
  } catch {
    return false;
  }
}

export async function providerStatuses(probes: ProviderProbes = {}): Promise<ProviderStatus[]> {
  const planned = new Set(planToolGroups().map(entry => entry.group));
  return Promise.all(PROVIDERS.map(async (provider): Promise<ProviderStatus> => {
    const probe = probes[provider.id];
    return {
      ...provider,
      history: { ...provider.history },
      mcpGroups: [...provider.mcpGroups],
      implemented: probe?.implemented === true,
      configured: probe ? await probeState(() => probe.configured()) : false,
      enabled: probe ? await probeState(() => probe.enabled()) : false,
      mcpGroupsRegistered: provider.mcpGroups.length > 0 && provider.mcpGroups.every(group => planned.has(group)),
    };
  }));
}
