/**
 * A small stateful Relaycast for the relay_messaging MCP tests: agents and
 * their tokens, 1:1 DMs, deliveries, threaded replies, channels and outbound
 * event subscriptions. It answers
 * only the endpoints the self-host Relaycast client calls, with the response
 * shapes that client parses. Workspace keys start with `rk_`; anything else
 * is an agent token.
 */

type Agent = { id: string; name: string; type: string; metadata: Record<string, unknown>; token: string; status: string };
type Message = {
  id: string; agent_name: string; agent_id: string; text: string; created_at: string;
  conversation_id: string | null; channel_id: string | null; thread_id: string | null;
};
/** Acknowledged rows are kept, owner-scoped, as Relaycast does; only unacknowledged ones are pending. */
type Delivery = { id: string; agent: string; message: Message; reason: string; acked: boolean };
type Channel = { id: string; name: string; topic: string | null; members: Set<string>; archived: boolean };
/** An outbound webhook subscription, with the workspace key that created it. */
type Subscription = {
  id: string; events: string[]; url: string; secret: string; signature_scheme: string;
  filter: Record<string, unknown> | null; workspaceKey: string;
};

export type RelaycastWorld = ReturnType<typeof createRelaycastWorld>;

export function createRelaycastWorld(roster: unknown[]) {
  let sequence = 1000;
  const next = () => String(++sequence);
  const agents = new Map<string, Agent>();
  const conversations: Array<{ id: string; participants: [string, string] }> = [];
  const messages = new Map<string, Message>();
  const deliveries: Delivery[] = [];
  const channels = new Map<string, Channel>();
  const subscriptions = new Map<string, Subscription>();
  const idempotent = new Map<string, unknown>();
  /** Every request body, for assertions about what was sent upstream. */
  const bodies: Array<{ method: string; path: string; body: Record<string, any> | null }> = [];
  /**
   * Injected failures keyed by `METHOD path`. `after` applies the request
   * first and then fails the response (a lost response); otherwise the
   * request fails before it has any effect.
   */
  const failures = new Map<string, Array<{ status: number; code: string; after: boolean }>>();
  /** Fleet nodes per workspace key (GET /v1/nodes), raw as Relaycast serves them. */
  const nodes = new Map<string, Array<Record<string, any>>>();
  /** Native spawn/release invocations. `spawnOutcome` decides how the next spawn completes. */
  const invocations = new Map<string, Record<string, any>>();
  const spawnOutcome = { mode: "ready" as "ready" | "pending" | "failed" | "rejected" };
  /** How the next agent-token exact release ends: stop the worker, or fail and leave it running. */
  const releaseOutcome = { mode: "completed" as "completed" | "failed" };

  const rosterEntry = (agent: Agent) => ({
    id: agent.id, name: agent.name, type: agent.type, metadata: agent.metadata,
    address: `${agent.name}@cloud-${agent.id}`, status: agent.status, last_seen: new Date().toISOString(),
  });
  function syncRoster(): void {
    roster.splice(0, roster.length, ...[...agents.values()].map(rosterEntry));
  }
  function addAgent(name: string, metadata: Record<string, unknown> = {}): Agent {
    const agent = { id: `ag_${next()}`, name, type: "agent", metadata, token: `at_${name}_${next()}`, status: "online" };
    agents.set(name, agent);
    syncRoster();
    return agent;
  }
  const byToken = (token: string) => [...agents.values()].find(agent => agent.token === token) ?? null;
  function message(sender: Agent, text: string, place: { conversation_id?: string; channel_id?: string; thread_id?: string }): Message {
    const created = {
      id: next(), agent_name: sender.name, agent_id: sender.id, text, created_at: new Date(Date.UTC(2026, 10, 7, 0, 0, sequence)).toISOString(),
      conversation_id: place.conversation_id ?? null, channel_id: place.channel_id ?? null, thread_id: place.thread_id ?? null,
    };
    messages.set(created.id, created);
    return created;
  }
  function deliver(to: string, created: Message, reason: string): void {
    if (agents.has(to)) deliveries.push({ id: `dl_${next()}`, agent: to, message: created, reason, acked: false });
  }
  function directMessage(sender: Agent, to: string, text: string) {
    let conversation = conversations.find(item => item.participants.includes(sender.name) && item.participants.includes(to));
    if (!conversation) {
      conversation = { id: `conv_${next()}`, participants: [sender.name, to] };
      conversations.push(conversation);
    }
    const created = message(sender, text, { conversation_id: conversation.id });
    deliver(to, created, "dm");
    return { conversation_id: conversation.id, message: { id: created.id, agent_name: sender.name, text, created_at: created.created_at } };
  }

  async function handle(method: string, path: string, query: URLSearchParams, bearer: string, body: Record<string, any> | null,
    idempotencyKey: string | null): Promise<{ status: number; body: unknown } | null> {
    bodies.push({ method, path, body });
    const queued = failures.get(`${method} ${path}`);
    const failure = queued?.shift();
    if (queued && queued.length === 0) failures.delete(`${method} ${path}`);
    if (failure && !failure.after) return { status: failure.status, body: { ok: false, error: { code: failure.code } } };
    const result = await route(method, path, query, bearer, body, idempotencyKey);
    return failure ? { status: failure.status, body: { ok: false, error: { code: failure.code } } } : result;
  }

  async function route(method: string, path: string, query: URLSearchParams, bearer: string, body: Record<string, any> | null,
    idempotencyKey: string | null): Promise<{ status: number; body: unknown } | null> {
    const ok = (data: unknown, status = 200) => ({ status, body: { ok: true, data } });
    const fail = (status: number, code: string) => ({ status, body: { ok: false, error: { code } } });
    const workspace = bearer.startsWith("rk_");
    const caller = workspace ? null : byToken(bearer);
    if (!workspace && !caller) return fail(401, "unauthorized");
    const once = (result: { status: number; body: unknown }) => {
      if (idempotencyKey) idempotent.set(`${caller?.id ?? "ws"}:${idempotencyKey}`, result);
      return result;
    };
    if (idempotencyKey && idempotent.has(`${caller?.id ?? "ws"}:${idempotencyKey}`)) {
      return idempotent.get(`${caller?.id ?? "ws"}:${idempotencyKey}`) as { status: number; body: unknown };
    }
    let match: RegExpExecArray | null;

    if (method === "POST" && path === "/v1/agents" && workspace) {
      if (agents.has(body!.name)) return fail(409, "agent_already_exists");
      const agent = addAgent(body!.name, body!.metadata ?? {});
      agent.type = body!.type;
      return ok({ id: agent.id, name: agent.name, token: agent.token }, 201);
    }
    if (method === "GET" && path === "/v1/nodes" && workspace) {
      const listed = (nodes.get(bearer) ?? []).filter(node => query.get("status") !== "online" || node.live === true);
      return ok(listed);
    }
    if (method === "POST" && path === "/v1/actions/spawn/invoke" && caller) {
      const input = body!.input as Record<string, any>;
      if (spawnOutcome.mode === "rejected") return fail(409, "spawn_capacity_exceeded");
      const node = [...nodes.values()].flat().find(item => item.name === input.target_node);
      if (!node) return fail(404, "spawn_target_unavailable");
      const id = `inv_${next()}`;
      const invocation: Record<string, any> = { id, status: "running", caller_id: caller.id, dispatched_node_id: node.id, input };
      if (spawnOutcome.mode === "ready") {
        const worker = addAgent(input.name, { fleet: { invocation_id: id, node_id: node.id } });
        invocation.status = "completed";
        invocation.output = { name: worker.name, spawned: true, ready: true };
      } else if (spawnOutcome.mode === "failed") {
        invocation.status = "failed";
        invocation.error = "spawn_failed: harness exited (token at_secret)";
      }
      invocations.set(id, invocation);
      return once(ok({ invocation_id: id, status: invocation.status === "completed" ? "dispatched" : invocation.status }, 202));
    }
    if ((match = /^\/v1\/actions\/(spawn|release)\/invocations\/([^/]+)$/.exec(path)) && method === "GET" && caller) {
      const invocation = invocations.get(decodeURIComponent(match[2]!));
      if (!invocation || invocation.caller_id !== caller.id) return fail(404, "not_found");
      return ok(invocation);
    }
    if (method === "POST" && path === "/v1/agents/release-exact" && caller) {
      const agent = agents.get(body!.name);
      if (!agent) return fail(404, "agent_not_found");
      if (agent.id !== body!.expected_agent_id) return fail(409, "agent_identity_conflict");
      const id = `inv_${next()}`;
      if (releaseOutcome.mode === "failed") {
        invocations.set(id, { id, status: "failed", caller_id: caller.id, error: "release_failed: broker unreachable" });
        return once(ok({ invocation_id: id, status: "pending" }));
      }
      agents.delete(agent.name);
      syncRoster();
      invocations.set(id, { id, status: "completed", caller_id: caller.id });
      return once(ok({ invocation_id: id, status: "pending" }));
    }
    if (method === "POST" && path === "/v1/agents/release-exact" && workspace) {
      const agent = agents.get(body!.name);
      if (!agent) return fail(404, "agent_not_found");
      if (agent.id !== body!.expected_agent_id) return fail(409, "agent_identity_conflict");
      agents.delete(agent.name);
      syncRoster();
      return once(ok({ status: "completed" }));
    }
    if (method === "POST" && path === "/v1/subscriptions" && workspace) {
      const subscription = {
        id: `sub_${next()}`, events: body!.events, url: body!.url, secret: body!.secret,
        signature_scheme: body!.signature_scheme, filter: body!.filter ?? null, workspaceKey: bearer,
      };
      subscriptions.set(subscription.id, subscription);
      return ok({ id: subscription.id, events: subscription.events, url: subscription.url }, 201);
    }
    if ((match = /^\/v1\/subscriptions\/([^/]+)$/.exec(path)) && method === "DELETE" && workspace) {
      const id = decodeURIComponent(match[1]!);
      if (!subscriptions.has(id)) return fail(404, "subscription_not_found");
      subscriptions.delete(id);
      return ok({ deleted: true });
    }
    if (method === "POST" && path === "/v1/agents/heartbeat" && caller) return ok({});
    if ((match = /^\/v1\/agents\/([^/]+)\/takeover$/.exec(path)) && method === "POST" && workspace) {
      const agent = agents.get(decodeURIComponent(match[1]!));
      if (!agent || agent.id !== body!.expected_agent_id) return fail(409, "agent_identity_conflict");
      agent.token = `at_${agent.name}_${next()}`;
      return ok({ agent_id: agent.id, token: agent.token });
    }
    if ((match = /^\/v1\/agents\/([^/]+)$/.exec(path)) && method === "GET" && workspace) {
      const agent = agents.get(decodeURIComponent(match[1]!));
      return agent ? ok(rosterEntry(agent)) : fail(404, "agent_not_found");
    }
    if (method === "GET" && path === "/v1/agent" && caller) {
      return ok({ ...rosterEntry(caller), channels: [...channels.values()]
        .filter(channel => channel.members.has(caller.name)).map(channel => ({ id: channel.id, name: channel.name })) });
    }
    if (method === "POST" && path === "/v1/dm" && caller) {
      // Relaycast's POST /v1/dm takes exactly one of `to` (agent name) or
      // `address` (agent@machine) and refuses anything else with 400.
      if ((body?.to === undefined) === (body?.address === undefined)) {
        return { status: 400, body: { ok: false, error: { code: "invalid_request",
          message: 'exactly one of "to" (agent name) or "address" (agent@machine) is required' } } };
      }
      let to: string = body!.to;
      if (body!.address !== undefined) {
        const address = String(body!.address);
        const at = address.lastIndexOf("@");
        const agent = at > 0 ? agents.get(address.slice(0, at)) : undefined;
        if (!agent || rosterEntry(agent).address !== address) return fail(404, "address_not_found");
        to = agent.name;
      }
      if (!agents.has(to)) return fail(404, "agent_not_found");
      return once(ok(directMessage(caller, to, body!.text), 201));
    }
    if (method === "GET" && path === "/v1/dm/conversations" && caller) {
      return ok(conversations.filter(item => item.participants.includes(caller.name)).map(item => ({
        id: item.id, type: "1:1", participants: item.participants.map(agent_name => ({ agent_name })) })));
    }
    if ((match = /^\/v1\/dm\/([^/]+)\/messages$/.exec(path)) && method === "GET" && caller) {
      const conversation = conversations.find(item => item.id === match![1] && item.participants.includes(caller.name));
      if (!conversation) return fail(404, "not_found");
      const before = query.get("before");
      const limit = Number(query.get("limit") ?? 50);
      const rows = [...messages.values()].filter(row => row.conversation_id === conversation.id && (!before || BigInt(row.id) < BigInt(before)));
      return ok(rows.slice(-limit).reverse());
    }
    if (method === "GET" && path === "/v1/deliveries" && caller) {
      return ok(deliveries.filter(row => row.agent === caller.name && !row.acked).map(row => ({
        id: row.id, conversation_id: row.message.conversation_id, reason: row.reason, channel_id: row.message.channel_id, message: row.message })));
    }
    if ((match = /^\/v1\/deliveries\/([^/]+)\/ack$/.exec(path)) && method === "POST" && caller) {
      // Relaycast ackDelivery (engine/delivery.ts at ac38905): a repeat ack by
      // the owner succeeds with changed:false; 404 means absent or not owned.
      const row = deliveries.find(item => item.id === match![1] && item.agent === caller.name);
      if (!row) return fail(404, "not_found");
      const changed = !row.acked;
      row.acked = true;
      return ok({ id: row.id, acknowledged: true, changed });
    }
    if ((match = /^\/v1\/messages\/([^/]+)$/.exec(path)) && method === "GET" && caller) {
      const found = messages.get(match[1]!);
      return found ? ok(found) : fail(404, "not_found");
    }
    if ((match = /^\/v1\/messages\/([^/]+)\/replies$/.exec(path)) && method === "POST" && caller) {
      const parent = messages.get(match[1]!);
      if (!parent) return fail(404, "not_found");
      const created = message(caller, body!.text, { conversation_id: parent.conversation_id ?? undefined,
        channel_id: parent.channel_id ?? undefined, thread_id: parent.id });
      if (parent.conversation_id) {
        const conversation = conversations.find(item => item.id === parent.conversation_id)!;
        deliver(conversation.participants.find(name => name !== caller.name)!, created, "dm");
      } else {
        for (const member of channels.get([...channels.values()].find(row => row.id === parent.channel_id)!.name)!.members) {
          if (member !== caller.name) deliver(member, created, "thread-reply");
        }
      }
      return once(ok(created, 201));
    }
    if (method === "GET" && path === "/v1/channels" && workspace) {
      return ok([...channels.values()].map(channel => ({ id: channel.id, name: channel.name, topic: channel.topic,
        member_count: channel.members.size, is_archived: channel.archived })));
    }
    if (method === "POST" && path === "/v1/channels" && caller) {
      if (channels.has(body!.name)) return fail(409, "channel_already_exists");
      const channel = { id: `ch_${next()}`, name: body!.name, topic: null, members: new Set([caller.name]), archived: false };
      channels.set(channel.name, channel);
      return ok({ id: channel.id, name: channel.name }, 201);
    }
    if ((match = /^\/v1\/channels\/([^/]+)\/(join|leave)$/.exec(path)) && method === "POST" && caller) {
      const channel = channels.get(decodeURIComponent(match[1]!));
      if (!channel) return fail(404, "channel_not_found");
      if (match[2] === "leave") {
        channel.members.delete(caller.name);
        return ok({ left: true });
      }
      const already = channel.members.has(caller.name);
      channel.members.add(caller.name);
      return ok({ already_member: already });
    }
    if ((match = /^\/v1\/channels\/([^/]+)\/messages$/.exec(path))) {
      const channel = channels.get(decodeURIComponent(match[1]!));
      if (!channel) return fail(404, "channel_not_found");
      if (method === "POST" && caller) {
        if (!channel.members.has(caller.name)) return fail(403, "forbidden");
        const created = message(caller, body!.text, { channel_id: channel.id });
        for (const member of channel.members) if (member !== caller.name) deliver(member, created, "message");
        return once(ok({ id: created.id, created_at: created.created_at }, 201));
      }
      if (method === "GET" && workspace) {
        const before = query.get("before");
        const limit = Number(query.get("limit") ?? 50);
        const rows = [...messages.values()].filter(row => row.channel_id === channel.id && !row.thread_id
          && (!before || BigInt(row.id) < BigInt(before)));
        return ok(rows.slice(-limit).reverse().map(row => ({ ...row,
          reply_count: [...messages.values()].filter(reply => reply.thread_id === row.id).length })));
      }
    }
    return null;
  }

  return {
    agents, conversations, messages, deliveries, channels, subscriptions, bodies, handle, addAgent,
    nodes, invocations, spawnOutcome, releaseOutcome,
    /** An agent's unacknowledged deliveries. */
    pending(agent: string) {
      return deliveries.filter(row => row.agent === agent && !row.acked);
    },
    /** Fails the next request to `METHOD path`; with `after`, only once the request has taken effect. */
    failNext(method: string, path: string, status: number, options: { code?: string; after?: boolean } = {}) {
      const key = `${method} ${path}`;
      failures.set(key, [...failures.get(key) ?? [], { status, code: options.code ?? "unavailable", after: options.after ?? false }]);
    },
    /** Re-issues an agent's token in place (as a takeover elsewhere would), keeping its id and metadata. */
    rotateToken(name: string): string {
      const agent = agents.get(name)!;
      agent.token = `at_${agent.name}_${next()}`;
      return agent.token;
    },
    /** A peer agent sends a DM (to a hosted participant, say). */
    sendAs(from: string, to: string, text: string) {
      return directMessage(agents.get(from)!, to, text);
    },
    /** A peer agent creates or joins a channel and optionally posts to it. */
    channelAs(from: string, name: string, text?: string) {
      let channel = channels.get(name);
      if (!channel) {
        channel = { id: `ch_${next()}`, name, topic: null, members: new Set<string>(), archived: false };
        channels.set(name, channel);
      }
      channel.members.add(from);
      if (text === undefined) return null;
      const created = message(agents.get(from)!, text, { channel_id: channel.id });
      for (const member of channel.members) if (member !== from) deliver(member, created, "message");
      return created;
    },
  };
}
