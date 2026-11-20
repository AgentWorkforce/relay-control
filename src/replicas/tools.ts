import { z } from "zod";
import { hash, inboundDelivery, ReplicasError, type ReplicasDeps, type ResolvedBinding } from "./service.js";

/**
 * The replica-side Agent Relay tools (list_relay_agents, check_relay_inbox,
 * send_relay_message), independent of transport. Each handler takes a
 * binding already authenticated and re-checked under the revocation lock
 * (service.withCapability) and returns a plain result. The capability RPC
 * route is one caller; any later replica transport calls the same handlers.
 * None of them grants session, admin, spawn or channel-management scope.
 * The list and inbox results carry `inbound_delivery`: whether Relay
 * messages are also pushed into the replica's chat. check_relay_inbox works
 * either way, and shows a pushed message until it is acknowledged.
 */
export const outgoingInput = z.object({
  to: z.string().min(1).max(256).nullable().optional(),
  reply_to: z.string().regex(/^[0-9]{1,32}$/).nullable().optional(),
  text: z.string().min(1).max(20_000),
  request_id: z.string().uuid(),
}).strict().refine((value) => Boolean(value.to) !== Boolean(value.reply_to));

const inboxInput = z.object({ acknowledge: z.array(z.string().min(1).max(256)).max(100).default([]) }).strict();

const capabilityReadInput = z.discriminatedUnion("action", [
  z.object({ action: z.literal("list_relay_agents") }).strict(),
  z.object({ action: z.literal("check_relay_inbox"), acknowledge: z.array(z.string().min(1).max(256)).max(100).default([]) }).strict(),
]);

export async function listRelayAgents(deps: ReplicasDeps, binding: ResolvedBinding) {
  const agents = await deps.relaycast.listAgents(binding.relay.key, "all");
  return {
    agent: binding.row.agent_name,
    agents: agents.map((agent) => ({ name: agent.name, address: agent.address, kind: agent.kind, status: agent.status })),
    inbound_delivery: inboundDelivery(binding.row),
  };
}

export async function checkRelayInbox(deps: ReplicasDeps, binding: ResolvedBinding, raw: unknown) {
  const parsed = inboxInput.safeParse(raw ?? {});
  if (!parsed.success) throw new ReplicasError("Unsupported binding action or arguments.");
  for (const deliveryId of parsed.data.acknowledge) await deps.relaycast.acknowledgeDelivery(binding.token, deliveryId);
  return { agent: binding.row.agent_name, messages: await deps.relaycast.readHostedInbox(binding.token),
    inbound_delivery: inboundDelivery(binding.row) };
}

export async function sendRelayMessage(deps: ReplicasDeps, binding: ResolvedBinding, raw: unknown) {
  const parsed = outgoingInput.safeParse(raw);
  if (!parsed.success) throw new ReplicasError("Supply a recipient or reply parent, text and a request UUID.");
  const data = parsed.data;
  const { token } = binding;
  // The same request id always maps to the same Relay idempotency key, so a retried send is one message.
  const idempotencyKey = `replicas-${hash(`${binding.row.id}:${data.request_id}`)}`;
  if (!data.reply_to) {
    return deps.relaycast.sendDirectMessage({ token, to: data.to!,
      ...(data.to!.includes("@") ? { address: data.to! } : {}), text: data.text, idempotencyKey });
  }
  const parent = await deps.relaycast.getMessage(token, data.reply_to);
  if (!parent) throw new ReplicasError("Reply parent is not visible to this agent.", 403);
  const self = await deps.relaycast.authenticatedAgent(token);
  if (parent.channelId && self.channels.some((channel) => channel.id === parent.channelId)) {
    return deps.relaycast.replyInChannelThread({ token, parentId: data.reply_to, text: data.text, idempotencyKey });
  }
  // A DM parent is proved through the calling token's own DM history, not a workspace-wide lookup.
  const before = `${BigInt(data.reply_to) + 1n}`;
  for (const conversation of await deps.relaycast.listConversations(token)) {
    const page = await deps.relaycast.listMessages(token, conversation.id, { limit: 1, before });
    if (page.messages.some((message) => message.id === data.reply_to)) {
      return deps.relaycast.replyToMessage({ token, parentId: data.reply_to, text: data.text, idempotencyKey });
    }
  }
  throw new ReplicasError("Reply parent is not in this agent's DMs or joined channels.", 403);
}

/** The capability RPC body: `{action}` reads, anything else is a send (the helper script's shape). */
export async function capabilityCall(deps: ReplicasDeps, binding: ResolvedBinding, body: unknown) {
  if (body && typeof body === "object" && "action" in body) {
    const read = capabilityReadInput.safeParse(body);
    if (!read.success) throw new ReplicasError("Unsupported binding action or arguments.");
    if (read.data.action === "list_relay_agents") return listRelayAgents(deps, binding);
    return checkRelayInbox(deps, binding, { acknowledge: read.data.acknowledge });
  }
  return sendRelayMessage(deps, binding, body);
}
