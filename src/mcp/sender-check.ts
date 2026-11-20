// Copied verbatim from Agent Relay Cloud's MCP Events module.
/**
 * How get_event's app block states Agent Relay's sender check ("Sender check:
 * trustedSender true (your agent)."). Prompts that gate replies on it quote
 * this, so the two cannot drift apart. Dependency-free: browser code (the
 * Grok routine setup) builds those prompts.
 */
export const SENDER_CHECK = "Sender check: trustedSender";

/**
 * How get_event's app block states the person's reply setting ("Reply
 * setting: replyMode notes-only."), next to the sender check, so a model that
 * reads only text (an unattended routine) sees it.
 */
export const REPLY_SETTING = "Reply setting: replyMode";
