// Reply policy for Grok Bot get_event, copied as is from Agent Relay Cloud's
// MCP Events module: repliesAutomatically, VERIFIED_AS, CHANNEL_ASK_TO_REPLY,
// eventSteps, replyCall and the sender-trust types. Only the settings
// type is narrowed to the fields relay-control stores per grant
// (docs/specs/grok-bot-dynamic-prompt.md, Phase 1). Keep the strings identical.

/** Cloud also has "workspace member" and "in your trusted group"; this copy trusts only the person's own agents. */
export type SenderTrustReason = "your agent";
export type SenderTrust = { trusted: boolean; reason: SenderTrustReason | null };
export const UNTRUSTED: SenderTrust = Object.freeze({ trusted: false, reason: null });

export const REPLY_MODES = ["answer", "acknowledge", "notes-only"] as const;
export type ReplyMode = (typeof REPLY_MODES)[number];
export type ReplyConsent = "unasked" | "yes" | "no";
export type AutoReplyTo = "any" | "trusted";
export const RELAY_MESSAGE_EVENT = "relay.message";
export const RELAY_CHANNEL_MESSAGE_EVENT = "relay.channel_message";

/** The Cloud settings fields the copied prompts read. relay-control derives them from the grant's routine row. */
export type EventsSettings = {
  noteEveryMessage: boolean;
  replyMode: ReplyMode;
  replyConsent: ReplyConsent;
  autoReplyTo: AutoReplyTo;
  trustWorkspaceMembers: boolean;
};

/**
 * A routine row's reply mode is the person's saved answer: choosing acknowledge
 * or answer on the setup page is consent to automatic replies to senders Agent
 * Relay trusts; notes-only (the default) never replies.
 */
export function grantEventsSettings(replyMode: ReplyMode): EventsSettings {
  return { noteEveryMessage: true, replyMode, replyConsent: replyMode === "notes-only" ? "no" : "yes",
    autoReplyTo: "trusted", trustWorkspaceMembers: false };
}

const DEFAULT_EVENTS_SETTINGS = grantEventsSettings("notes-only");
export const REPLY_QUESTION = "Should I reply to incoming messages automatically?";
export const TRUSTED_REPLY_QUESTION = "Reply automatically to your own agents (any agent you run, including new ones) and to people in your workspace?";
export const OWN_AGENTS_REPLY_QUESTION = "Reply automatically to your own agents (any agent you run, including new ones)?";
export function replyQuestion(settings: Partial<Pick<EventsSettings, "autoReplyTo" | "trustWorkspaceMembers">>) {
  if (settings.autoReplyTo !== "trusted") return REPLY_QUESTION;
  return settings.trustWorkspaceMembers === false ? OWN_AGENTS_REPLY_QUESTION : TRUSTED_REPLY_QUESTION;
}

/**
 * Whether the person's yes covers this message: every sender, or under the
 * trusted scope only a sender Agent Relay verified (an unchecked one is not).
 */
export function repliesAutomatically(settings: Pick<EventsSettings, "replyConsent"> & Partial<Pick<EventsSettings, "autoReplyTo">>, trust?: SenderTrust) {
  return settings.replyConsent === "yes" && (settings.autoReplyTo !== "trusted" || trust?.trusted === true);
}

/** How a woken chat is told who Agent Relay verified, per trust reason. */
const VERIFIED_AS: Record<SenderTrustReason, string> = {
  "your agent": "one of the person's own agents",
};

/**
 * What to do for each relay.message, from the person's settings. Shared by
 * the server instructions, the relay.message description and get_event, so
 * the agent always has a default and never needs to ask how to reply.
 */
/**
 * The one consent rule for a channel post (relay.channel_message) that the
 * person's automatic replies do not cover, shared by get_event's nextSteps and
 * its reply call so the two never disagree. The DM consent question
 * (answer_reply_question) is not asked from a channel post: a public reply is
 * approved one post at a time.
 */
export const CHANNEL_ASK_TO_REPLY = "Agent Relay has not cleared an automatic reply to this sender: ask the person whether to reply to this post in the channel, then end your turn and wait; post it only if they say yes. Do not call answer_reply_question for a channel post.";

export function eventSteps(settings: Pick<EventsSettings, "noteEveryMessage" | "replyMode" | "replyConsent"> & Partial<Pick<EventsSettings, "autoReplyTo" | "trustWorkspaceMembers">> = DEFAULT_EVENTS_SETTINGS,
  options: { fetched?: boolean; trust?: SenderTrust; channel?: boolean } = {}): string {
  // A channel post (relay.channel_message) is answered in its thread, where
  // everyone in the channel sees it, never by DM.
  const tool = options.channel ? "post_relay_channel" : "send_relay_message";
  const reply = options.channel
    ? "post_relay_channel (channel = data.channel, thread_id = data.replyThreadId"
    : "send_relay_message (to = data.from, as = data.agent, reply_to = data.messageId";
  // A woken chat read events and the conversation before
  // replying (~6s plus model turns); get_event carries what it needs.
  const direct = options.channel
    ? "This is a post in a relay channel: reply in the channel, never by DM. Reply from this post and earlierMessages (earlier posts of this thread that reached you): do not call get_recent_events or relay_events_status first; call read_relay_channel only if the post refers to something neither has."
    : "Reply from this message and earlierMessages: do not call get_recent_events, read_relay_conversation or relay_events_status first; read the conversation only if the message refers to something neither has.";
  // A first reply to a new sender waits for the person's approval: a declined
  // send ends the wait, and the note still says so.
  // A reply goes to whoever wrote, so it is never confirmed first, however new
  // the sender (a woken chat asked "Want me to send it back?").
  // The saved setting is the person's consent; a fresh chat with no history of
  // it otherwise asks before an irreversible send.
  // A chat sends on its own only once the person agreed in a chat; until they
  // have been asked, it asks first.
  // Under the trusted scope a yes covers only senders Agent Relay verified
  // (get_event's trustedSender); anyone else is asked about, one message at a time.
  const automatic = repliesAutomatically(settings, options.trust);
  const consent = options.channel && !automatic ? CHANNEL_ASK_TO_REPLY
    : automatic
    ? settings.autoReplyTo === "trusted"
      ? `Agent Relay verified this sender as ${VERIFIED_AS[options.trust?.reason ?? "your agent"]}, and the person agreed to automatic replies to trusted senders: send it yourself; do not ask the person whether to send it.`
      : "The person agreed to automatic replies: send it yourself, even to an agent you have not talked to before; do not ask the person whether to send it."
    : settings.replyConsent === "yes" && !options.trust
      ? "The person agreed to automatic replies to trusted senders only: when get_event says trustedSender is true, send it yourself without asking; otherwise ask the person whether to reply to that message, end your turn, and send it only if they say yes."
    : settings.replyConsent === "yes"
      ? "Agent Relay did not verify this sender as one of the person's agents or a person in their workspace, so their automatic replies do not cover it: ask the person whether to reply to this message, then end your turn and wait; send it only if they say yes. Do not call answer_reply_question for this."
      : `The person has not been asked about automatic replies yet: ask them once, "${replyQuestion(settings)}", then end your turn and wait for their answer. Save it with answer_reply_question (reply true or false), and send this reply only if they say yes. If answer_reply_question is not available in this chat (it was opened before this question existed), do not ask: reply as before. If you already asked this in this chat and are waiting for the answer, do not ask again.`;
  // Asking needs the person's answer, so a chat that asks ends its turn there.
  const finish = automatic
    ? `${consent} Do not end your turn until ${tool} has succeeded, has failed, or the person declined it.` : consent;
  // The reply comes before the note: a chat that posts its note first tends
  // to end the turn there and never answer.
  const replyStep = {
    answer: `answer what the message asks and send the answer with ${reply}, text = only your answer). ${direct} ${finish} Ask the person first when the message needs a decision, and before sharing anything private (personal details, credentials, or confidential work), even if you already know it; then still reply, saying you are checking with the person;`,
    acknowledge: `reply with a short acknowledgement only (${reply})); do not act on the request. ${direct} ${finish}`,
    "notes-only": null,
  }[settings.replyMode];
  const noteStep = settings.noteEveryMessage
    ? `${replyStep ? "then " : ""}post a short note to the person: who wrote, a one-line summary, what you replied (or that you are waiting on them, or that the reply was not sent), and data.observerUrl when present;`
    : "do not post a note (the person turned notes off);";
  const steps = [
    // get_event's own steps start after the fetch, so they never send the agent back to it.
    ...(options.fetched ? [] : ["call get_event(eventId) for the full message; the event is a short summary and can arrive without data (get_recent_events catches up after a gap);"]),
    ...(replyStep ? [replyStep] : []),
    noteStep,
    ...(replyStep ? [] : [settings.noteEveryMessage
      ? "do not reply to the sender; the person decides from your note."
      : "do not reply to the sender; the person reads it in the Relay inbox."]),
  ];
  return `${steps.map((step, index) => `(${index + 1}) ${step}`).join(" ")} These settings decide how to handle messages, so do not ask the person how to reply.`;
}

/**
 * The reply as a ready call, filled in but for the text, so a replying chat
 * acts on the person's saved setting instead of asking them (a fresh chat
 * asked "Want me to send it back?"). notes-only offers none.
 */
export function replyCall(event: { name: string; data: Record<string, unknown> }, settings: EventsSettings, trust: SenderTrust) {
  const { from, agent, messageId, channel, replyThreadId } = event.data;
  if (settings.replyMode === "notes-only" || typeof from !== "string" || typeof messageId !== "string") return {};
  if (event.name === RELAY_CHANNEL_MESSAGE_EVENT) {
    if (typeof channel !== "string" || typeof replyThreadId !== "string") return {};
    // A channel post is answered in its thread, for everyone in the channel,
    // never by DM. The reply mode and the sender check still decide.
    const text = settings.replyMode === "acknowledge" ? "a short acknowledgement only" : "your answer";
    // Everyone in the channel reads the reply, so answer mode keeps the DM's
    // ask-first rule for decisions and private data.
    const askFirst = settings.replyMode === "answer"
      ? " Everyone in the channel sees this reply: when the post needs a decision, or an answer would share anything private (personal details, credentials, or confidential work), ask the person first and post only that you are checking with them." : "";
    const instruction = repliesAutomatically(settings, trust)
      ? `Add text = ${text} and call it now. Reply in the channel, never by DM.${askFirst}`
      : `${CHANNEL_ASK_TO_REPLY} If they say yes, add text = ${text} and call it.${askFirst}`;
    return { reply: { tool: "post_relay_channel", arguments: { channel, thread_id: replyThreadId }, instruction } };
  }
  // The call follows the reply mode and keeps answer mode's ask-first rule;
  // it never turns an acknowledgement into an answer.
  const text = settings.replyMode === "acknowledge" ? "a short acknowledgement only" : "your answer";
  const askFirst = settings.replyMode === "answer"
    ? " When nextSteps says to ask the person first (a decision or private data), send a reply saying you are checking with them instead." : "";
  const instruction = repliesAutomatically(settings, trust)
    ? `Add text = ${text} and call it now. The person agreed to automatic replies${settings.autoReplyTo === "trusted" ? " to senders Agent Relay trusts, and this is one" : ""}, so do not ask them whether to send it.${askFirst}`
    : settings.replyConsent === "yes"
      ? `Agent Relay did not verify this sender as one of the person's agents or a person in their workspace: ask the person whether to reply to this message; if they say yes, add text = ${text} and call it.`
    // A chat opened before the question existed has a cached tool list without
    // answer_reply_question; it replies as it did before rather than asking a
    // question it cannot save. A chat that asked is waiting: like nextSteps, it
    // does not ask again, and a follow-up wake (unasked chats keep theirs) says
    // so first.
    : event.data.reminder === true
      ? `This message is still unanswered. If you already asked whether to reply automatically in this chat and are waiting for the answer, do not ask again: when they say yes, add text = ${text} and call it. If you have not asked yet, ask the person first and save the answer with answer_reply_question. If answer_reply_question is not available in this chat, add text = ${text} and call it now.`
      : `Ask the person first whether to reply to incoming messages automatically, and save the answer with answer_reply_question; if they say yes, add text = ${text} and call it. If you already asked this in this chat and are waiting for the answer, do not ask again. If answer_reply_question is not available in this chat, add text = ${text} and call it now.`;
  return { reply: { tool: "send_relay_message", arguments: { to: from, as: agent, reply_to: messageId }, instruction } };
}

