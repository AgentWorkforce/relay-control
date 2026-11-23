// Which relay channel posts become relay.channel_message events, and which of
// those wake a routine. Copied from Agent Relay Cloud's MCP Events module
// (channel-wake.ts) with its policy fixed at Cloud's default ("mentions"):
// self-host stores no per-connection channel wake setting.
//
// A bot in a channel sees every post, but a routine run per post would be
// noisy and, with other agents in the channel, could loop. So a post is kept
// and wakes only when it is addressed to the bot, and every loop guard fails
// closed:
//
// - the bot's own posts never wake it;
// - another agent (anything not verified as a `human`) wakes it only with an
//   @mention, never with a plain post or a thread reply;
// - a thread, and a channel, wake it at most a few times per window, and an
//   agent at most twice per thread (a hop cap for agent-to-bot ping-pong).

/** How a channel delivery is addressed to the bot. */
export type ChannelAddress = "mention" | "bot-thread" | "post";
/** Cloud's sender kinds (Relaycast agent types); null when no record says. An unknown kind counts as an agent. */
export type ChannelSenderKind = "human" | "agent" | null;

/** Window over which the wake caps below are counted. */
export const CHANNEL_WAKE_WINDOW_MS = 10 * 60 * 1000;
/** Wake-ups per thread (a top-level post and its replies) per window. */
export const MAX_THREAD_WAKES = 6;
/** Wake-ups by agent posts per thread per window: the hop cap. */
export const MAX_AGENT_THREAD_WAKES = 2;
/** Wake-ups per channel per window. */
export const MAX_CHANNEL_WAKES = 20;
/**
 * A channel delivery whose thread could not be checked (a failed Relaycast read) is retried until the message is
 * this old, then treated as an ordinary reply: acknowledged, never saved, never a wake.
 */
export const CHANNEL_RETRY_WINDOW_MS = 10 * 60 * 1000;

/**
 * Cloud's channelWakeAllows under the "mentions" policy: an @mention by anyone, or a person's reply in a thread
 * the bot is part of. Self-host saves a channel post only when this holds, so an agent's unmentioned post reaches
 * nobody's events.
 */
export function channelWakeAllows(addressed: ChannelAddress, senderKind: string | null | undefined): boolean {
  if (addressed === "mention") return true;
  if (senderKind !== "human") return false;
  return addressed === "bot-thread";
}

/** The cap a new wake-up would exceed, given this window's counts; null when it may wake. */
export function channelWakeCap(counts: { channel: number; thread: number; agentThread: number }, senderKind: string | null | undefined) {
  if (counts.channel >= MAX_CHANNEL_WAKES) return "channel";
  if (counts.thread >= MAX_THREAD_WAKES) return "thread";
  if (senderKind !== "human" && counts.agentThread >= MAX_AGENT_THREAD_WAKES) return "agent-hops";
  return null;
}

/** Cloud's channelRetryExpired: past the retry window, or without a timestamp (it could never wake a routine). */
export function channelRetryExpired(message: { created_at: string | null }, now: Date): boolean {
  const createdAt = message.created_at ? Date.parse(message.created_at) : Number.NaN;
  return Number.isNaN(createdAt) || now.getTime() - createdAt > CHANNEL_RETRY_WINDOW_MS;
}
