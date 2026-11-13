export class RelaycastCallError extends Error {
  readonly code: string | null;
  /** True when the request may have been accepted and the outcome was not confirmed. */
  readonly outcomeUnknown: boolean;

  constructor(status: number, body: string, outcomeUnknown = false) {
    super(`Relaycast answered ${status}`);
    this.name = "RelaycastCallError";
    this.status = status;
    this.body = body;
    this.code = errorCode(body);
    this.outcomeUnknown = outcomeUnknown;
  }

  readonly status: number;
  readonly body: string;
  /** Which client operation failed (for safe diagnostics); null when unlabeled. */
  operation: string | null = null;
}

export type RegisteredAgent = { id: string; name: string; token: string };

export type HostedDelivery = {
  delivery_id: string;
  message_id: string;
  sender: string | null;
  sender_id: string | null;
  text: string;
  thread_id: string | null;
  conversation_id: string | null;
  reason: string | null;
  channel_id: string | null;
  created_at: string | null;
};

export type RelayChannel = { id: string; name: string; topic: string | null; memberCount: number; archived: boolean };

export type ChannelMessage = {
  id: string;
  sender: string | null;
  text: string;
  threadId: string | null;
  replyCount: number;
  createdAt: string | null;
};

export type PersonOwner = {
  cloudWorkspaceId: string;
  cloudUserId: string;
  displayName: string | null;
};

export type RemoteAgent = {
  id: string;
  name: string;
  metadata: Record<string, unknown>;
};

export type RosterAgent = RemoteAgent & {
  address: string | null;
  kind: string;
  persona: string | null;
  status: string | null;
  lastSeen: string | null;
};

export type PresenceRow = { agentId: string | null; agentName: string | null; status: string | null };

export type RegisteredHuman = {
  id: string;
  name: string;
  token: string;
};

export type DirectMessage = {
  id: string;
  sender: string;
  text: string;
  createdAt: string | null;
};

export type Conversation = {
  id: string;
  participants: string[];
};


/** A live fleet node as Relaycast's GET /v1/nodes reports it (see src/mcp/relay-spawn.ts). */
export type RelaySpawnTarget = {
  id: string;
  name: string;
  live: boolean;
  handlersLive: boolean;
  /** Only well-formed `spawn:<harness>` capabilities. */
  capabilities: string[];
  activeAgents: number;
  reservedAgents: number;
  /** 0 is Relaycast's unlimited sentinel. */
  maxAgents: number;
  stale: boolean;
  /** The raw node record, for the allowlisted placement reader. */
  raw: Record<string, unknown>;
};

/** A native spawn or release action invocation. */
export type RelaySpawnInvocation = {
  id: string;
  status: string;
  callerId: string | null;
  nodeId: string | null;
  name: string | null;
  spawned: boolean;
  ready: boolean;
  taskUnconfirmed: boolean;
  /** The upstream error code prefix only (never the free-text reason). */
  errorCode: string | null;
  /** A structured spawn refusal code, when Relaycast attached one. */
  errorDetailsCode: string | null;
};

/** `spawn:<harness id>`: lowercase letters, digits and hyphens, at most 32 characters. */
export const RELAY_HARNESS_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;
export function isRelayHarnessCapability(capability: string): boolean {
  return capability.startsWith("spawn:") && RELAY_HARNESS_ID_PATTERN.test(capability.slice("spawn:".length));
}

const INVOCATION_STATUSES = new Set(["pending", "dispatched", "running", "completed", "failed"]);

type FetchImpl = typeof fetch;

export function personMetadata(owner: PersonOwner): Record<string, unknown> {
  return {
    source: "cloud-person",
    role: "person",
    cloud_workspace_id: owner.cloudWorkspaceId,
    cloud_user_id: owner.cloudUserId,
  };
}

export function isOwnedBy(agent: RemoteAgent, owner: PersonOwner): boolean {
  return agent.metadata.source === "cloud-person"
    && agent.metadata.cloud_workspace_id === owner.cloudWorkspaceId
    && agent.metadata.cloud_user_id === owner.cloudUserId;
}

export function admissionRejected(error: RelaycastCallError): boolean {
  const body = error.body.toLowerCase();
  return body.includes("register_human") || body.includes("admission");
}

function errorCode(body: string): string | null {
  try {
    const parsed: unknown = body ? JSON.parse(body) : null;
    if (!parsed || typeof parsed !== "object") return null;
    const record = parsed as Record<string, unknown>;
    const error = record.error;
    if (typeof error === "string" && error) return error;
    if (error && typeof error === "object" && !Array.isArray(error)) {
      const code = (error as Record<string, unknown>).code;
      if (typeof code === "string" && code) return code;
    }
    return null;
  } catch {
    return null;
  }
}

function record(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function payload(parsed: unknown): unknown {
  const wrapper = record(parsed);
  if (wrapper && "data" in wrapper) return wrapper.data;
  return parsed;
}

/** Server-side Relaycast calls. Registration and revocation use the workspace key. */
export function createRelaycastClient(input: {
  internalOrigin: string;
  fetchImpl?: FetchImpl;
}) {
  const fetchImpl = input.fetchImpl ?? fetch;
  const origin = input.internalOrigin.replace(/\/+$/, "");

  async function call(
    method: string,
    path: string,
    token: string,
    body?: Record<string, unknown>,
    idempotencyKey?: string,
    allowNotFound = false,
  ): Promise<unknown> {
    let response: Response;
    try {
      response = await fetchImpl(`${origin}${path}`, {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          accept: "application/json",
          ...(body ? { "content-type": "application/json" } : {}),
          ...(idempotencyKey ? { "idempotency-key": idempotencyKey } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
    } catch {
      throw new RelaycastCallError(0, "", true);
    }
    const raw = await response.text();
    if (allowNotFound && response.status === 404) return null;
    if (!response.ok) {
      const unknown = response.status === 0 || response.status >= 500;
      throw new RelaycastCallError(response.status, raw, unknown);
    }
    if (!raw) return null;
    try {
      return payload(JSON.parse(raw) as unknown);
    } catch {
      throw new RelaycastCallError(response.status, "", true);
    }
  }

  /** Labels a failure with the operation that raised it; the error is otherwise unchanged. */
  async function labeled<T>(operation: string, work: () => Promise<T>): Promise<T> {
    try {
      return await work();
    } catch (error) {
      if (error instanceof RelaycastCallError && error.operation === null) error.operation = operation;
      throw error;
    }
  }

  function rosterFrom(value: unknown): RosterAgent | null {
    const agent = record(value);
    const id = text(agent?.id);
    const name = text(agent?.name);
    if (!agent || !id || !name) return null;
    return {
      id,
      name,
      metadata: record(agent.metadata) ?? {},
      address: text(agent.address),
      kind: text(agent.type) ?? "agent",
      persona: text(agent.persona),
      status: text(agent.status),
      lastSeen: text(agent.last_seen),
    };
  }

  function agentFrom(value: unknown): RemoteAgent {
    const data = record(value);
    const id = text(data?.id);
    const name = text(data?.name);
    if (!data || !id || !name) throw new RelaycastCallError(502, "", true);
    return { id, name, metadata: record(data.metadata) ?? {} };
  }

  function invocationFrom(value: unknown, write: boolean): RelaySpawnInvocation {
    const data = record(value);
    const output = record(data?.output);
    const id = text(data?.invocation_id) ?? text(data?.id);
    const status = text(data?.status);
    if (!id || !status || !INVOCATION_STATUSES.has(status)) throw new RelaycastCallError(502, "", write);
    const error = text(data?.error);
    const details = record(data?.error_details);
    const warning = output?.warning;
    return {
      id, status, callerId: text(data?.caller_id),
      nodeId: text(data?.dispatched_node_id) ?? text(data?.handler_node_id),
      name: text(output?.name), spawned: output?.spawned === true, ready: output?.ready === true,
      taskUnconfirmed: warning === "spawn_task_unconfirmed" || record(warning)?.code === "spawn_task_unconfirmed",
      // Free text can echo tokens: keep only a code-shaped prefix.
      errorCode: error ? (/^([a-z_]{1,64})(?::|$)/.exec(error)?.[1] ?? "spawn_failed") : null,
      errorDetailsCode: text(details?.code),
    };
  }

  return {
    async registerHuman(workspaceKey: string, name: string, owner: PersonOwner): Promise<RegisteredHuman> {
      const data = record(await call("POST", "/v1/agents", workspaceKey, {
        name,
        type: "human",
        auto_join_general: false,
        ...(owner.displayName ? { persona: owner.displayName } : {}),
        metadata: personMetadata(owner),
      }));
      const id = text(data?.id);
      const registeredName = text(data?.name) ?? name;
      const token = text(data?.token);
      if (!id || !token) throw new RelaycastCallError(502, "", true);
      return { id, name: registeredName, token };
    },

    async getAgent(workspaceKey: string, name: string): Promise<RemoteAgent | null> {
      const data = await call("GET", `/v1/agents/${encodeURIComponent(name)}`, workspaceKey, undefined, undefined, true);
      return data === null ? null : agentFrom(data);
    },

    async takeOver(workspaceKey: string, name: string, expectedAgentId: string, actor: string): Promise<string> {
      const data = record(await call("POST", `/v1/agents/${encodeURIComponent(name)}/takeover`, workspaceKey, {
        expected_agent_id: expectedAgentId,
        actor,
        reason: "Recover the person's own messaging identity",
        session_ref: `selfhost-messaging:${actor}`,
        node_id: "selfhost-control",
      }));
      const token = text(data?.token);
      if (!token || text(data?.agent_id) !== expectedAgentId) throw new RelaycastCallError(502, "", true);
      return token;
    },

    async revokeHuman(workspaceKey: string, name: string, expectedAgentId: string, actor: string): Promise<void> {
      await call("POST", `/v1/agents/${encodeURIComponent(name)}/revoke-token`, workspaceKey, {
        expected_agent_id: expectedAgentId,
        actor,
        reason: "Organization membership was removed",
        session_ref: `selfhost-revoke:${actor}`,
        node_id: "selfhost-control",
      }, undefined, true);
      await call("DELETE", `/v1/agents/${encodeURIComponent(name)}`, workspaceKey, undefined, undefined, true);
    },

    async sendDirectMessage(input: {
      token: string;
      to: string;
      /**
       * An exact machine address. When set it is sent instead of `to`:
       * Relaycast's POST /v1/dm takes exactly one of `to` (agent name) or
       * `address` (agent@machine) and refuses a body with both (400).
       */
      address?: string;
      text: string;
      idempotencyKey: string;
    }): Promise<{ conversationId: string; message: DirectMessage }> {
      const data = record(await labeled("send_dm", () => call(
        "POST",
        "/v1/dm",
        input.token,
        // Presence selects the exact-address contract, including invalid/empty addresses.
        input.address !== undefined
          ? { address: input.address, text: input.text }
          : { to: input.to, text: input.text },
        input.idempotencyKey,
      )));
      const message = record(data?.message);
      const conversationId = text(data?.conversation_id);
      const messageId = text(message?.id) ?? text(data?.id);
      const sender = text(message?.agent_name) ?? text(message?.sender);
      if (!conversationId || !messageId) throw new RelaycastCallError(200, "", true);
      return {
        conversationId,
        message: {
          id: messageId,
          sender: sender ?? "",
          text: text(message?.text) ?? input.text,
          createdAt: text(message?.created_at) ?? text(data?.created_at),
        },
      };
    },

    async listConversations(token: string): Promise<Conversation[]> {
      const data = await labeled("list_conversations", () => call("GET", "/v1/dm/conversations", token));
      if (!Array.isArray(data)) throw new RelaycastCallError(200, "", true);
      return data.flatMap((item) => {
        const conversation = record(item);
        const id = text(conversation?.id);
        const type = text(conversation?.type) ?? text(conversation?.dm_type);
        if (!conversation || !id || (type && type !== "1:1")) return [];
        const participants = (Array.isArray(conversation.participants) ? conversation.participants : [])
          .map((participant) => text(record(participant)?.agent_name) ?? text(participant))
          .filter((name): name is string => Boolean(name));
        return [{ id, participants }];
      });
    },

    async listMessages(
      token: string,
      conversationId: string,
      options: { limit?: number; before?: string } = {},
    ): Promise<{ messages: DirectMessage[]; hasEarlier: boolean }> {
      const limit = options.limit ?? 50;
      const query = new URLSearchParams({ limit: String(limit) });
      if (options.before) query.set("before", options.before);
      const data = await labeled("list_messages", () => call("GET", `/v1/dm/${encodeURIComponent(conversationId)}/messages?${query}`, token));
      if (!Array.isArray(data)) throw new RelaycastCallError(200, "", true);
      const messages = data.flatMap((item) => {
        const message = record(item);
        const id = text(message?.id);
        const sender = text(message?.agent_name);
        if (!message || !id || !sender) return [];
        return [{
          id,
          sender,
          text: typeof message.text === "string" ? message.text : "",
          createdAt: text(message.created_at),
        }];
      });
      messages.sort((left, right) => (left.createdAt ?? "").localeCompare(right.createdAt ?? "") || left.id.localeCompare(right.id));
      return { messages, hasEarlier: data.length >= limit };
    },

    async listDeliveries(token: string): Promise<Array<{ id: string; sender: string | null }>> {
      const data = await call("GET", "/v1/deliveries?limit=100", token);
      if (!Array.isArray(data)) return [];
      return data.flatMap((item) => {
        const delivery = record(item);
        const id = text(delivery?.id);
        const message = record(delivery?.message);
        return id ? [{ id, sender: text(message?.agent_name) }] : [];
      });
    },

    /** Idempotent for the owner (Relaycast engine/delivery.ts ackDelivery changed:false at ac38905); 404 = absent or not owned. */
    async acknowledgeDelivery(token: string, deliveryId: string): Promise<void> {
      await labeled("ack_delivery", () => call("POST", `/v1/deliveries/${encodeURIComponent(deliveryId)}/ack`, token, {}));
    },

    /** Workspace roster with the default metadata (ownership and declared sessions). */
    async listAgents(workspaceKey: string, status: "active" | "all", options: { includeStale?: boolean } = {}): Promise<RosterAgent[]> {
      const query = new URLSearchParams({ status, ...(options.includeStale ? { include_stale: "true" } : {}) });
      const data = await labeled("list_agents", () => call("GET", `/v1/agents?${query}`, workspaceKey));
      if (!Array.isArray(data)) throw new RelaycastCallError(200, "", true);
      return data.flatMap((item) => {
        const agent = rosterFrom(item);
        return agent ? [agent] : [];
      });
    },

    /** One agent by name with roster fields (address, status), or null. */
    async getRosterAgent(workspaceKey: string, name: string): Promise<RosterAgent | null> {
      const data = await labeled("get_agent", () =>
        call("GET", `/v1/agents/${encodeURIComponent(name)}`, workspaceKey, undefined, undefined, true));
      if (data === null) return null;
      const agent = rosterFrom(data);
      if (!agent) throw new RelaycastCallError(502, "", true);
      return agent;
    },

    /**
     * Sets top-level metadata keys on one agent. Relaycast's
     * `PATCH /v1/agents/:name` merges `metadata` into the stored metadata
     * (`{ ...existing, ...body.metadata }`), so keys not sent are preserved;
     * a key sent replaces that key's value. Returns the updated record.
     */
    async mergeAgentMetadata(workspaceKey: string, name: string, metadata: Record<string, unknown>): Promise<RosterAgent> {
      const data = await labeled("update_agent", () =>
        call("PATCH", `/v1/agents/${encodeURIComponent(name)}`, workspaceKey, { metadata }));
      const agent = rosterFrom(data);
      if (!agent) throw new RelaycastCallError(502, "", true);
      return agent;
    },

    /**
     * A hosted MCP participant (`type: agent`), ported from Cloud's
     * registerHosted. Self-host recovers an orphaned registration with
     * takeover instead of Cloud's recovery proof, so none is sent.
     */
    async registerHosted(workspaceKey: string, name: string, metadata: Record<string, unknown>): Promise<RegisteredAgent> {
      const data = record(await labeled("register_hosted", () => call("POST", "/v1/agents", workspaceKey, {
        name, type: "agent", auto_join_general: false, direct_machine_prefix: "cloud", metadata,
      })));
      const id = text(data?.id);
      const registered = text(data?.name);
      const token = text(data?.token);
      if (!id || registered !== name || !token) throw new RelaycastCallError(502, "", true);
      return { id, name, token };
    },

    /** Re-issues the token of an orphaned hosted participant this owner registered. */
    async recoverHosted(workspaceKey: string, name: string, expectedAgentId: string, actor: string): Promise<RegisteredAgent> {
      const data = record(await labeled("recover_hosted", () =>
        call("POST", `/v1/agents/${encodeURIComponent(name)}/takeover`, workspaceKey, {
          expected_agent_id: expectedAgentId,
          actor,
          reason: "Recover incomplete hosted MCP join",
          session_ref: `selfhost-hosted-mcp:${actor}`,
          node_id: "selfhost-control",
        })));
      const token = text(data?.token);
      if (!token || text(data?.agent_id) !== expectedAgentId) throw new RelaycastCallError(502, "", true);
      return { id: expectedAgentId, name, token };
    },

    /** Deletes exactly this agent id (never a successor that took the name). */
    async releaseHosted(workspaceKey: string, name: string, expectedAgentId: string): Promise<void> {
      for (const delayMs of [0, 25, 75, 150]) {
        if (delayMs > 0) await new Promise((resolve) => setTimeout(resolve, delayMs));
        const data = record(await labeled("release_hosted", () => call("POST", "/v1/agents/release-exact", workspaceKey, {
          name, expected_agent_id: expectedAgentId, delete_agent: true, reason: "Hosted MCP participant left",
        }, `hosted-mcp-leave:${expectedAgentId}`)));
        if (data?.status === "completed") return;
      }
      const pending = new RelaycastCallError(502, "", true);
      pending.operation = "release_hosted";
      throw pending;
    },

    /**
     * A workspace outbound event subscription signed with Standard Webhooks
     * (ported from Cloud's createSubscription). Relaycast POSTs matching events
     * to `url`; the `whsec_` secret is sent upstream and never echoed in errors.
     */
    async createSubscription(workspaceKey: string, input: {
      events: string[];
      url: string;
      secret: string;
      filter?: { mentions?: string; channel?: string };
    }): Promise<string> {
      const data = record(await labeled("create_subscription", () => call("POST", "/v1/subscriptions", workspaceKey, {
        events: input.events,
        url: input.url,
        secret: input.secret,
        signature_scheme: "standard-webhooks",
        ...(input.filter ? { filter: input.filter } : {}),
      })));
      const id = text(data?.id);
      if (!id) {
        const invalid = new RelaycastCallError(502, "", true);
        invalid.operation = "create_subscription";
        throw invalid;
      }
      return id;
    },

    /** Deletes an outbound subscription; an already-deleted one (404) is fine. */
    async deleteSubscription(workspaceKey: string, id: string): Promise<void> {
      await labeled("delete_subscription", () =>
        call("DELETE", `/v1/subscriptions/${encodeURIComponent(id)}`, workspaceKey, undefined, undefined, true));
    },

    /** The agent a token controls, with its channel memberships. */
    async authenticatedAgent(token: string): Promise<RosterAgent & { channels: Array<{ id: string; name: string }>; workspaceId: string | null }> {
      const data = await labeled("authenticated_agent", () => call("GET", "/v1/agent", token));
      const agent = rosterFrom(data);
      if (!agent) throw new RelaycastCallError(502, "", true);
      const channels = (Array.isArray(record(data)?.channels) ? record(data)!.channels as unknown[] : []).flatMap((item) => {
        const channel = record(item);
        const id = text(channel?.id);
        const name = text(channel?.name);
        return id && name ? [{ id, name }] : [];
      });
      return { ...agent, channels, workspaceId: text(record(data)?.workspace_id) };
    },

    async heartbeat(token: string): Promise<void> {
      await labeled("heartbeat", () => call("POST", "/v1/agents/heartbeat", token, {}));
    },

    /** Up to 100 unacknowledged deliveries for an agent token. */
    async readHostedInbox(token: string): Promise<HostedDelivery[]> {
      const data = await labeled("read_inbox", () => call("GET", "/v1/deliveries?limit=100", token));
      if (!Array.isArray(data)) throw new RelaycastCallError(200, "", true);
      return data.flatMap((item) => {
        const delivery = record(item);
        const message = record(delivery?.message);
        const id = text(delivery?.id);
        const messageId = text(message?.id);
        if (!id || !messageId) return [];
        return [{
          delivery_id: id,
          message_id: messageId,
          sender: text(message?.agent_name),
          sender_id: text(message?.agent_id),
          text: typeof message?.text === "string" ? message.text : "",
          thread_id: text(message?.thread_id),
          conversation_id: text(delivery?.conversation_id),
          reason: text(delivery?.reason),
          channel_id: text(delivery?.channel_id) ?? text(message?.channel_id),
          created_at: text(message?.created_at),
        }];
      });
    },

    /** Only call after verifying the parent belongs to the caller's DM. */
    async replyToMessage(input: { token: string; parentId: string; text: string; idempotencyKey: string }):
      Promise<{ conversationId: string; message: DirectMessage }> {
      const data = record(await labeled("reply_dm", () => call(
        "POST", `/v1/messages/${encodeURIComponent(input.parentId)}/replies`, input.token, { text: input.text }, input.idempotencyKey,
      )));
      const id = text(data?.id);
      const conversationId = text(data?.conversation_id);
      if (!id || !conversationId) throw new RelaycastCallError(200, "", true);
      return {
        conversationId,
        message: { id, sender: text(data?.agent_name) ?? "", text: text(data?.text) ?? input.text, createdAt: text(data?.created_at) },
      };
    },

    /** A message's author, thread and channel, read with an agent's token; null when unknown. */
    async getMessage(token: string, messageId: string):
      Promise<{ id: string; agentName: string | null; threadId: string | null; channelId: string | null } | null> {
      const data = record(await labeled("get_message", () =>
        call("GET", `/v1/messages/${encodeURIComponent(messageId)}`, token, undefined, undefined, true)));
      if (!data) return null;
      if (text(data.id) !== messageId) throw new RelaycastCallError(200, "", true);
      return { id: messageId, agentName: text(data.agent_name), threadId: text(data.thread_id), channelId: text(data.channel_id) };
    },

    async getMessageThreadId(token: string, messageId: string): Promise<string | null> {
      const data = record(await labeled("get_message", () => call("GET", `/v1/messages/${encodeURIComponent(messageId)}`, token)));
      if (text(data?.id) !== messageId) throw new RelaycastCallError(200, "", true);
      return text(data?.thread_id);
    },

    /** Workspace channels (workspace key). */
    async listChannels(workspaceKey: string): Promise<RelayChannel[]> {
      const data = await labeled("list_channels", () => call("GET", "/v1/channels", workspaceKey));
      if (!Array.isArray(data)) throw new RelaycastCallError(200, "", true);
      return data.flatMap((item) => {
        const channel = record(item);
        const id = text(channel?.id);
        const name = text(channel?.name);
        if (!channel || !id || !name) return [];
        return [{
          id, name, topic: text(channel.topic),
          memberCount: Number.isInteger(channel.member_count) ? channel.member_count as number : 0,
          archived: channel.is_archived === true,
        }];
      });
    },

    /** Creates a channel; Relaycast makes the token's agent its owner, so a member. */
    async createChannel(token: string, name: string): Promise<void> {
      const data = record(await labeled("create_channel", () => call("POST", "/v1/channels", token, { name })));
      if (text(data?.name) !== name) throw new RelaycastCallError(200, "", true);
    },

    /** Idempotent upstream: an existing member gets `already_member: true`. */
    async joinChannel(token: string, name: string): Promise<{ alreadyMember: boolean }> {
      const data = record(await labeled("join_channel", () =>
        call("POST", `/v1/channels/${encodeURIComponent(name)}/join`, token, {})));
      if (!data) throw new RelaycastCallError(200, "", true);
      return { alreadyMember: data.already_member === true };
    },

    async leaveChannel(token: string, name: string): Promise<void> {
      await labeled("leave_channel", () => call("POST", `/v1/channels/${encodeURIComponent(name)}/leave`, token, {}));
    },

    async postChannelMessage(input: { token: string; channel: string; text: string; idempotencyKey: string }):
      Promise<{ id: string; createdAt: string | null }> {
      const data = record(await labeled("post_channel", () => call(
        "POST", `/v1/channels/${encodeURIComponent(input.channel)}/messages`, input.token, { text: input.text }, input.idempotencyKey,
      )));
      const id = text(data?.id);
      if (!id) throw new RelaycastCallError(200, "", true);
      return { id, createdAt: text(data?.created_at) };
    },

    /** Only call after verifying the parent belongs to the channel. */
    async replyInChannelThread(input: { token: string; parentId: string; text: string; idempotencyKey: string }):
      Promise<{ id: string; channelId: string; threadId: string; createdAt: string | null }> {
      const data = record(await labeled("reply_channel", () => call(
        "POST", `/v1/messages/${encodeURIComponent(input.parentId)}/replies`, input.token, { text: input.text }, input.idempotencyKey,
      )));
      const id = text(data?.id);
      const channelId = text(data?.channel_id);
      const threadId = text(data?.thread_id);
      if (!id || !channelId || !threadId) throw new RelaycastCallError(200, "", true);
      return { id, channelId, threadId, createdAt: text(data?.created_at) };
    },

    /** Top-level posts, oldest first. Read with the workspace key: callers enforce membership. */
    async listChannelMessages(workspaceKey: string, channel: string, options: { limit: number; before?: string }):
      Promise<{ messages: ChannelMessage[]; hasEarlier: boolean }> {
      const query = new URLSearchParams({ limit: String(options.limit) });
      if (options.before) query.set("before", options.before);
      const data = await labeled("read_channel", () =>
        call("GET", `/v1/channels/${encodeURIComponent(channel)}/messages?${query}`, workspaceKey));
      if (!Array.isArray(data)) throw new RelaycastCallError(200, "", true);
      const messages = data.flatMap((item): ChannelMessage[] => {
        const message = record(item);
        const id = text(message?.id);
        if (!message || !id) return [];
        return [{
          id, sender: text(message.agent_name), text: typeof message.text === "string" ? message.text : "",
          threadId: text(message.thread_id),
          replyCount: Number.isInteger(message.reply_count) ? message.reply_count as number : 0,
          createdAt: text(message.created_at),
        }];
      });
      // Snowflake ids: a shorter decimal string is an earlier message.
      messages.sort((left, right) => left.id.length - right.id.length || left.id.localeCompare(right.id));
      return { messages, hasEarlier: data.length >= options.limit };
    },

    /**
     * Fleet nodes visible to this workspace key, online only by default. The
     * key belongs to one Relaycast workspace, so a node enrolled in another
     * workspace or another installation is never listed.
     */
    async listSpawnTargets(workspaceKey: string, options: { includeOffline?: boolean } = {}): Promise<RelaySpawnTarget[]> {
      const data = await labeled("list_spawn_targets", () =>
        call("GET", options.includeOffline ? "/v1/nodes?limit=100" : "/v1/nodes?status=online&limit=100", workspaceKey));
      if (!Array.isArray(data)) throw new RelaycastCallError(502, "", true);
      return data.flatMap((value): RelaySpawnTarget[] => {
        const node = record(value);
        const id = text(node?.id);
        const name = text(node?.name);
        if (!node || !id || !name || !Array.isArray(node.capabilities) || !Number.isInteger(node.active_agents)
          || !Number.isInteger(node.max_agents) || (node.max_agents as number) < 0 || (node.active_agents as number) < 0) return [];
        // An absent count means no reservations; a malformed one means capacity is unknown.
        const reserved = node.reserved_agents ?? 0;
        const reservedValid = Number.isInteger(reserved) && (reserved as number) >= 0;
        const capabilities = [...new Set((node.capabilities as unknown[])
          .map(item => typeof item === "string" ? item : text(record(item)?.name))
          .filter((item): item is string => typeof item === "string" && isRelayHarnessCapability(item)))];
        return [{
          id, name, live: node.live === true, handlersLive: node.handlers_live === true, capabilities,
          activeAgents: node.active_agents as number, reservedAgents: reservedValid ? reserved as number : 0,
          maxAgents: node.max_agents as number,
          stale: node.live !== true || node.active_agents_stale === true || !reservedValid,
          raw: node,
        }];
      });
    },

    /** Sends one native spawn as the hosted actor (agent token); never retried. */
    async spawnRelayAgent(token: string, input: { name: string; cli: string; task: string; target_node: string; worker_cwd?: string },
      idempotencyKey: string): Promise<RelaySpawnInvocation> {
      const data = await labeled("spawn_agent", () => call("POST", "/v1/actions/spawn/invoke", token,
        { input: { ...input, verify_ready: true } }, idempotencyKey));
      return invocationFrom(data, true);
    },

    async getRelayInvocation(token: string, action: "spawn" | "release", id: string): Promise<RelaySpawnInvocation> {
      const data = await labeled("spawn_status", () =>
        call("GET", `/v1/actions/${action}/invocations/${encodeURIComponent(id)}`, token));
      return invocationFrom(data, false);
    },

    /** Exact release of one immutable worker identity, as the actor that launched it. */
    async releaseSpawnedAgent(token: string, name: string, expectedAgentId: string, idempotencyKey: string):
      Promise<{ id: string | null; status: string }> {
      const data = record(await labeled("release_spawned_agent", () => call("POST", "/v1/agents/release-exact", token, {
        name, expected_agent_id: expectedAgentId, delete_agent: true, reason: "Released by the owning MCP connection",
      }, idempotencyKey)));
      if (data?.status === "completed") return { id: text(data.invocation_id) ?? text(data.id), status: "completed" };
      const invocation = invocationFrom(data, true);
      return { id: invocation.id, status: invocation.status };
    },

    /** The roster entry for a name, with its origin node (spawn readiness checks). */
    async getSpawnedAgent(workspaceKey: string, name: string): Promise<(RosterAgent & { originNodeId: string | null }) | null> {
      const data = await labeled("get_spawned_agent", () =>
        call("GET", `/v1/agents/${encodeURIComponent(name)}`, workspaceKey, undefined, undefined, true));
      if (data === null) return null;
      const agent = rosterFrom(data);
      if (!agent) throw new RelaycastCallError(502, "", true);
      return { ...agent, originNodeId: text(record(data)?.origin_node_id) };
    },

    /** Fresh presence from expiring broker keys, independent of roster status. */
    async listPresence(workspaceKey: string): Promise<PresenceRow[]> {
      const data = await labeled("list_presence", () => call("GET", "/v1/agents/presence", workspaceKey));
      if (!Array.isArray(data)) throw new RelaycastCallError(200, "", true);
      return data.flatMap((item) => {
        const row = record(item);
        const agentId = text(row?.agent_id);
        const agentName = text(row?.agent_name);
        if (!agentId && !agentName) return [];
        return [{ agentId, agentName, status: text(row?.status) }];
      });
    },
  };
}

export type RelaycastClient = ReturnType<typeof createRelaycastClient>;
