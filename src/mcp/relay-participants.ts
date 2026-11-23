import { isBindingOwnedIdentity } from "../messaging/binding-identities.js";
import { createHash, randomUUID } from "node:crypto";
import { agentIdentityOwnerRef } from "../admin/api-tokens.js";
import { recordAudit } from "../admin/audit.js";
import { decryptSecret, encryptSecret } from "../crypto.js";
import type { SqlExecutor } from "../database.js";
import { RelaycastCallError, type RosterAgent } from "../messaging/relaycast.js";
import {
  bindDesktopSession, DesktopIdentityUnavailable, DESKTOP_IDENTITY_MESSAGES, findDesktopIdentityByAddress,
  findDesktopIdentityByName, findDesktopIdentityBySession, linkedDesktopIdentity, unbindDesktopSession, verifyDesktopIdentity,
  type DesktopIdentityRow, type LinkedDesktopIdentity,
} from "../messaging/desktop-identities.js";
import type { McpContext, McpMember } from "./context.js";
import { isListedRelayAgent, rosterAgent, ROSTER_TIMEOUT_MS, withinRelayRead } from "./team-activity.js";
import { buildAgentCard, cardMetadata, cardSummary, recipientCard, type SetCardInput } from "./relay-agent-cards.js";
import { loadRelayAgentOwners, relayAgentOwnerTarget } from "./relay-agent-owners.js";
import { McpOAuthAccessRefused, McpOAuthActorRefused } from "./oauth/admission.js";
import { admissionConnectorKind, connectorKind, usedRedirectUrisSql } from "./oauth/connector-kind.js";
import { LAUNCH_ROLE_REFUSAL } from "./catalog.js";
import { RECEIPT_GUIDANCE } from "../messaging/delivery-status.js";
import { MCP_OAUTH_RETIRING_MESSAGE, McpOAuthAgentRetiring, retiringIdentity } from "./oauth/retirement.js";
import {
  CursorIdentityError, cursorCloudParticipantName, cursorIdentityNonces, cursorMintCommand, verifyCursorIdentityToken,
} from "./cursor-oidc.js";
import { postgresAttestationStore } from "./copilot-attestation.js";
import { enrolHostedAtGate, freshAtGate, HostedGateRefused, type GateEnrolment } from "./hosted-gate.js";
import { underOwnerLock } from "./owner-lock-deadline.js";
import type { RelayHostedClient } from "./relay-hosted-credentials.js";

/**
 * Hosted relay participants and the Relaycast operations behind the
 * relay_messaging tools, ported from Cloud's `lib/mcp/relay-service.ts`.
 *
 * A participant is a Relaycast `agent` registered for one owner (workspace +
 * user) and bound to an MCP session by the session id's hash, or used by name
 * (`as`). The server keeps no state between requests: every call looks the
 * participant up again, verifies that the remote agent still carries this
 * owner's metadata, and serializes join/leave per owner with a Postgres
 * advisory lock.
 *
 * Managed calls: a request admitted with a `mcp:desktop` provider credential,
 * or the Desktop app bearer marked `X-Agent-Relay-Desktop: 1`, acts only as
 * the Desktop identity synced for its verified native chat (a Codex threadId,
 * or a Claude Code / Copilot chat named by a verified attestation). No
 * verified chat, or no matching synced identity, means the actor tools are
 * unavailable; they never fall back to a hosted participant.
 * Other native MCP sessions may link to one of the owner's synced Desktop
 * identities with join_relay desktop_address (a row in
 * desktop_relay_session_bindings keyed by the session hash). A linked
 * session acts as that identity unless `as` names a hosted participant, so
 * DMs and channel posts reach the Desktop natively; an unlinked session acts
 * as its hosted participant. OAuth grants act only as their approved agent
 * and never link. An explicitly injected Capy resolver permits only native,
 * unmanaged sends as an owned binding; it creates no participant alias.
 * Person sends (`as_person`) and events inboxes are not part of self-host;
 * launches (SELFHOST_FEATURES launch) go through
 * withSpawnActor and src/mcp/relay-spawn.ts.
 */

export class RelayToolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RelayToolError";
  }
}

export const ownerHash = (id: string) => createHash("sha256").update(id).digest("hex");

/** Whether a workspace agent identity holds `name` in this workspace (case-blind). */
export async function agentIdentityHoldsName(executor: SqlExecutor, workspaceId: string, name: string): Promise<boolean> {
  const result = await executor.query(
    "SELECT 1 FROM agent_identities WHERE workspace_id = $1 AND lower(agent_name) = lower($2) LIMIT 1",
    [workspaceId, name],
  );
  return result.rows.length > 0;
}

export const HOSTED_SOURCE = "cloud-hosted-mcp";
/** Card kinds (metadata.kind), as Cloud's hosted MCP writes them. */
export const HOSTED_KIND = "hosted";
export const DESKTOP_KIND = "relay-desktop";
const AS_PERSON_UNAVAILABLE =
  "as_person is not available on this self-hosted site. Omit it to act as this MCP session's hosted participant.";
const ownerEnrichmentFailed = (operation: "list_relay_agents" | "get_relay_agent_card", error: unknown) => {
  console.warn("[selfhost-mcp] owner enrichment failed", {
    operation, error: error instanceof Error ? error.name : "unknown",
  });
};
const inboxSenderEnrichmentFailed = (error: unknown) => {
  console.warn("[selfhost-mcp] inbox sender enrichment failed", {
    operation: "check_relay_inbox", error: error instanceof Error ? error.name : "unknown",
  });
};
const relayStatusAddressEnrichmentFailed = (error: unknown) => {
  console.warn("[selfhost-mcp] relay status address enrichment failed", {
    operation: "relay_status", error: error instanceof Error ? error.name : "unknown",
  });
};
const sessionEnrichmentFailed = (error: unknown) => {
  console.warn("[selfhost-mcp] session enrichment failed", {
    operation: "list_relay_agents", error: error instanceof Error ? error.name : "unknown",
  });
};

/** Contract section 4, verbatim (shared with Cloud's hosted MCP). */
export const RELAY_AGENT_CARD_GUIDANCE = "Before delegating to a peer, read its card with get_relay_agent_card to see what it does and what to send it. Keep your own card current with set_relay_agent_card: a description of your purpose and one skill per kind of work you take on, with example requests.";
/**
 * Said plainly so a Desktop-managed chat (Claude Code, Cursor, Codex, ...) does
 * not go looking for a socket or a separate login before it sends. As Cloud.
 */
export const DESKTOP_CHAT_RELAY_GUIDANCE =
  "Once Agent Relay Desktop has registered this chat on this computer, you can send and read relay messages with these tools as the chat's own agent: send_relay_message, post_relay_channel, check_relay_inbox, read_relay_conversation and relay_status act as that chat, with no socket or extra login.";

export const RELAY_COORDINATION_GUIDANCE = "DM a specific agent by default. Use channels only to coordinate a larger swarm or broadcast to many agents, and subscribe only to channels you need. Reply to a channel post in that channel with post_relay_channel (thread_id for its thread), not by DM, unless the reply is private. At task start, check list_relay_agents and DM peers whose work your task affects, without waiting to be asked. "
  + RELAY_AGENT_CARD_GUIDANCE;
export const HOSTED_REPLY_GUIDANCE = "replies arrive in check_relay_inbox; poll it";
export const FACTORY_REPLY_GUIDANCE = "Replies to this Factory agent are delivered into its Droid session by the Factory worker; check_relay_inbox does not serve Factory agents. Read the conversation with read_relay_conversation as=<this agent>.";
export const CAPY_REPLY_GUIDANCE = "Replies are addressed to the bound Capy thread. This receipt does not confirm delivery or reading.";
export const DESKTOP_REPLY_GUIDANCE = "replies will be injected into your session by Agent Relay Desktop";
export const MANAGED_AS_REFUSED = "This managed chat can only act as its verified desktop identity.";
export const MANAGED_JOIN_REFUSED = "This chat can only use its verified desktop identity.";
/** Cloud's DESKTOP_RELAY_GUIDANCE without the web-session sentence: self-host has no web sessions. */
export const DESKTOP_RELAY_GUIDANCE = "If this session receives Agent Relay messages with a `[reply: curl --unix-socket …]` hint or has a desktop address from GET /whoami, call join_relay with desktop_address first; DMs and subscribed channel posts are then injected.";
export const UNLINKED_CHANNEL_GUIDANCE = "This MCP session is not linked to Agent Relay Desktop, so channel posts would not reach your local session. Call join_relay with desktop_address (from GET /whoami on the relay socket, or an injected Agent Relay message), then retry. To use this MCP session's hosted inbox instead (posts arrive in check_relay_inbox; poll it), pass hosted: true.";
export const DESKTOP_NOT_SYNCED = "That desktop identity is not synced to your account in this workspace. Is Agent Relay Desktop running and signed in?";
/** Desktop syncs the direct name@machine address; relay-node's whoami may show an alias instead. */
const desktopAliasHint = (direct: string) =>
  `That address is not the synced one. desktop_address is the direct name@machine address Agent Relay Desktop syncs, not an alias; use desktop_address "${direct}".`;
const DESKTOP_LINK_FIELDS = "desktop_address cannot be combined with name or description.";
const DESKTOP_LINK_NEEDS_SESSION = "Initialize MCP to receive Mcp-Session-Id before linking a desktop identity.";
const DESKTOP_LINK_OAUTH = "This connection acts only as the agent approved for it and cannot link a desktop identity. Use a native MCP session (one that keeps Mcp-Session-Id) to call join_relay with desktop_address.";
const DESKTOP_INBOX_GUIDANCE = "Replies are injected into your session by Agent Relay Desktop; check_relay_inbox is not used for this linked identity.";
const INBOX_SENDER_LOOKUP_TIMEOUT_MS = 1_000;
const RELAY_STATUS_LOOKUP_TIMEOUT_MS = 1_000;
const CHANNEL_REPLY_GUIDANCE = "Reply to a post in this channel with post_relay_channel channel=<name> thread_id=<message_id>. Use send_relay_message only when the reply is private.";
const RESERVED_CHANNEL_PREFIX = "agent-events-";
const CHANNEL_NAME = /^[a-z0-9][a-z0-9_-]{0,79}$/;
const CHANNEL_DELIVERY_REASONS: ReadonlySet<string> = new Set(["message", "mention", "thread-reply"]);
const isChannelDelivery = (delivery: { reason?: string | null }) =>
  Boolean(delivery.reason && CHANNEL_DELIVERY_REASONS.has(delivery.reason));

export function normalizeChannelName(channel: string): string {
  const name = channel.trim().replace(/^#/, "").toLowerCase();
  if (!CHANNEL_NAME.test(name) || name.startsWith(RESERVED_CHANNEL_PREFIX)) {
    throw new RelayToolError("Channel names are lowercase letters, digits, hyphens and underscores (a leading # is optional). Use list_relay_channels.");
  }
  return name;
}
const channelReplyHint = (channel: string, threadId: string) => `post_relay_channel channel=${channel} thread_id=${threadId}`;
const hostedChannelDelivery = (channel: string) => `Posts in #${channel} will arrive in check_relay_inbox; poll it.`;
const desktopChannelDelivery = (channel: string) => `Posts in #${channel} will be injected into this session by Agent Relay Desktop.`;

function automaticParticipantName(user: { name: string; email: string }, sessionHash: string): string {
  const label = user.name.trim() || user.email.split("@")[0] || "agent";
  const slug = label.normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase()
    .replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "agent";
  return `${slug.slice(0, 35).replace(/-+$/g, "")}-mcp-${sessionHash.slice(0, 8)}`;
}

// ---------------------------------------------------------------------------
// Store: hosted_relay_participants (migration 0012).

export type ParticipantRow = {
  id: string;
  workspaceId: string;
  /**
   * The owner's id: a person's user id, or a workspace agent identity's id
   * when `agentIdentity` is true (hosted_relay_participants.agent_identity_id).
   */
  userId: string;
  agentIdentity: boolean;
  relayWorkspaceId: string;
  sessionHash: string | null;
  agentName: string;
  agentRemoteId: string;
  tokenCiphertext: string;
  /**
   * relaygate's agent id when the participant enrolled through relaygate
   * (gate-only installs; the token is then an rg_ token), else null.
   */
  relaygateAgentId: string | null;
  /**
   * Gate-only installs: the hosted clients (connector kinds) relaygate
   * enrolled this participant for. Another kind enrols at relaygate before
   * it may use the participant, so relaygate's policy decides it too.
   */
  admittedClients: string[];
};

/** `owned`: an agent identity's one participant (unique per workspace, migration 0086). */
type Selector = { name: string } | { sessionHash: string } | { agentRemoteId: string } | { owned: true };

/**
 * Who owns a participant row: a person (user_id) or a workspace agent
 * identity (agent_identity_id). Exactly one is set on every row (migration 0086).
 */
type Owner = { userId: string; agentIdentity: boolean };

const COLUMNS = `p.id, p.workspace_id, p.user_id, p.agent_identity_id, p.relaycast_workspace_id, p.session_hash, p.agent_name, p.agent_remote_id, p.token_ciphertext, p.relaygate_agent_id, p.admitted_clients`;

function rowFrom(row: Record<string, unknown>): ParticipantRow {
  return {
    id: String(row.id),
    workspaceId: String(row.workspace_id),
    userId: String(row.user_id ?? row.agent_identity_id),
    agentIdentity: row.user_id == null && row.agent_identity_id != null,
    relayWorkspaceId: String(row.relaycast_workspace_id),
    sessionHash: typeof row.session_hash === "string" ? row.session_hash : null,
    agentName: String(row.agent_name),
    agentRemoteId: String(row.agent_remote_id),
    tokenCiphertext: String(row.token_ciphertext),
    relaygateAgentId: typeof row.relaygate_agent_id === "string" ? row.relaygate_agent_id : null,
    admittedClients: Array.isArray(row.admitted_clients) ? row.admitted_clients.map(String) : [],
  };
}

/**
 * Only the owner's own rows are ever visible: workspace and owner are always
 * in the predicate, and a person's rows and an agent identity's rows never
 * match each other's owner column.
 */
async function findParticipant(executor: SqlExecutor, workspaceId: string, owner: Owner, organizationId: string, selector: Selector) {
  const ownerColumn = owner.agentIdentity ? "agent_identity_id" : "user_id";
  if ("owned" in selector && !owner.agentIdentity) return null;
  const [column, value] = "name" in selector ? ["agent_name", selector.name]
    : "agentRemoteId" in selector ? ["agent_remote_id", selector.agentRemoteId]
      : "owned" in selector ? [ownerColumn, owner.userId] : ["session_hash", selector.sessionHash];
  const result = await executor.query(
    `SELECT ${COLUMNS} FROM hosted_relay_participants p
      JOIN workspaces w ON w.id=p.workspace_id
      WHERE p.workspace_id = $1 AND p.${ownerColumn} = $2 AND w.organization_id=$3 AND p.${column} = $4`,
    [workspaceId, owner.userId, organizationId, value],
  );
  return result.rows[0] ? rowFrom(result.rows[0]) : null;
}

async function insertParticipant(executor: SqlExecutor, row: Omit<ParticipantRow, "id">): Promise<void> {
  await executor.query(
    `INSERT INTO hosted_relay_participants
       (id, workspace_id, user_id, agent_identity_id, relaycast_workspace_id, session_hash, agent_name, agent_remote_id, token_ciphertext,
        relaygate_agent_id, admitted_clients)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::text[])`,
    [randomUUID(), row.workspaceId, row.agentIdentity ? null : row.userId, row.agentIdentity ? row.userId : null,
      row.relayWorkspaceId, row.sessionHash, row.agentName, row.agentRemoteId, row.tokenCiphertext,
      row.relaygateAgentId, row.admittedClients],
  );
}

async function updateParticipant(executor: SqlExecutor, id: string,
  fields: { sessionHash?: string; agentName?: string; tokenCiphertext?: string; relaygateAgentId?: string; admittedClients?: string[] }) {
  await executor.query(
    `UPDATE hosted_relay_participants
        SET session_hash = COALESCE($2, session_hash), agent_name = COALESCE($3, agent_name),
            token_ciphertext = COALESCE($4, token_ciphertext), relaygate_agent_id = COALESCE($5, relaygate_agent_id),
            admitted_clients = COALESCE($6::text[], admitted_clients), updated_at = now()
      WHERE id = $1`,
    [id, fields.sessionHash ?? null, fields.agentName ?? null, fields.tokenCiphertext ?? null, fields.relaygateAgentId ?? null,
      fields.admittedClients ?? null],
  );
}

async function removeParticipant(executor: SqlExecutor, id: string): Promise<void> {
  await executor.query("DELETE FROM hosted_relay_participants WHERE id = $1", [id]);
}

// ---------------------------------------------------------------------------
// Failures.

const SAFE_DIAGNOSTIC_CODES: ReadonlySet<string> = new Set([
  "agent_already_exists", "agent_not_found", "not_found", "unauthorized", "forbidden", "rate_limited",
  "agent_identity_conflict", "address_not_found", "ambiguous_address", "delivery_rejected",
  "channel_not_found", "channel_already_exists", "channel_archived",
  "idempotency_key_reused", "dm_conversation_id_collision", "internal_error", "database_overloaded",
  "idempotency_unavailable", "handler_unavailable", "node_dispatch_unavailable", "mailbox_full",
  "event_delivery_retryable_failure", "rate_limit_exceeded", "plan_limit_exceeded",
  "invalid_request", "invalid_json",
]);

export type RelayToolOperation = "send" | "join" | "leave";

/** The allow-listed diagnostic for an upstream failure; null for anything else. */
function safeDiagnostic(error: unknown) {
  const upstream = error instanceof RelaycastCallError ? error : null;
  return upstream ? {
    operation: upstream.operation ?? "relaycast",
    status: upstream.status === 0 ? null : upstream.status,
    code: upstream.code === null ? "none" : SAFE_DIAGNOSTIC_CODES.has(upstream.code) ? upstream.code : "unlisted_code",
  } : null;
}

/**
 * Every failure becomes a public tool error, ported from Cloud's
 * relayFailure. The diagnostic names only the operation, the HTTP status
 * and an allow-listed error code: upstream bodies can echo credentials, so
 * no other upstream text reaches the log or the caller.
 */
export function relayFailure(error: unknown, operation?: RelayToolOperation) {
  const upstream = error instanceof RelaycastCallError ? error : null;
  const diagnostic = safeDiagnostic(error);
  if (diagnostic) console.error("[selfhost-mcp] relay operation failed", diagnostic);
  else if (!(error instanceof RelayToolError)) {
    console.error("[selfhost-mcp] relay tool failed", { error: error instanceof Error ? error.name : "unknown" });
  }
  const registrationConflict = upstream?.status === 409 && upstream.code === "agent_already_exists"
    && upstream.operation === "register_hosted";
  const message = error instanceof RelayToolError ? error.message
    : registrationConflict ? "That relay name is already taken. Choose another name."
    : upstream?.status === 404 ? "The relay agent or address is no longer available. Refresh list_relay_agents."
    : operation === "leave" ? "Leaving the hosted relay participant failed. It is safe to retry leave_relay."
    : "Relay operation failed. If a send was attempted, its outcome may be unknown. Retry only with the same supplied idempotency_key; if you omitted it and received no receipt, check the conversation before retrying.";
  const diagnosticText = diagnostic
    ? ` Upstream diagnostic: operation=${diagnostic.operation} status=${diagnostic.status ?? "none"} code=${diagnostic.code}.`
    : "";
  return { isError: true as const, content: [{ type: "text" as const, text: message + diagnosticText }] };
}

// ---------------------------------------------------------------------------
// The per-request relay service.

/** `desktop` marks a synced Agent Relay Desktop identity; its deliveries are injected, not polled. */
/**
 * `gated` marks a hosted participant enrolled through relaygate (gate-only
 * installs): its token is an rg_ token, and every call it makes, reads
 * included, goes through relaygate.
 */
type Identity = { name: string; token: string; desktop?: boolean; gated?: boolean; factory?: boolean; capy?: boolean; capyGrant?: boolean };
type DesktopActor = LinkedDesktopIdentity & { desktop: true };
/**
 * `remotePresent` and the ownership checks come from the token or, when
 * Relaycast rejects it, from the workspace-key roster; `tokenUsable` says
 * whether Relaycast accepted the stored token itself.
 */
type Hosted = Identity & { row: ParticipantRow; remotePresent: boolean; tokenUsable: boolean };
type ParticipantOptions = {
  /** A missing `as` participant returns null instead of throwing. */
  allowMissing?: boolean;
  /** A participant whose remote agent is gone is returned (for leave). */
  allowGone?: boolean;
  /** A participant whose token Relaycast rejects is returned (for join's recovery and leave). */
  allowRejected?: boolean;
  /** The caller binds this MCP session to the selected row (native join); requires `executor` under the owner lock. */
  bind?: boolean;
  executor?: SqlExecutor;
  /** The owner's launcher (withSpawnActor only): on gate-only installs it is never a messaging identity. */
  internal?: boolean;
  /** A Cursor cloud agent run of this OAuth grant (cursor_cloud_runs): never the grant's pinned agent. */
  run?: boolean;
};
/** The hosted participant every agent launch of one owner is sent as (src/mcp/relay-spawn.ts). */
export type SpawnActor = {
  id: string; name: string; token: string; relaycastWorkspaceId: string;
  /**
   * The verified desktop identity that asked for the launch; the node treats
   * its DMs as native input. Absent for OAuth and unlinked hosted sessions.
   */
  requester?: { agentId: string; name: string };
};
/** The owner's launcher name: never derived from a display name. */
export const launcherName = (userId: string) => `launcher-${ownerHash(userId).slice(0, 16)}`;
const ACTIVE_LAUNCHES = "This participant still owns agent launches that have not been released. Release them with release_relay_agent first.";

/** Whether a hosted actor still owns a launch that is not terminal; its token is needed to release it. */
export async function hasActiveLaunches(executor: SqlExecutor, workspaceId: string, actorId: string): Promise<boolean> {
  const result = await executor.query(
    `SELECT 1 FROM relay_spawns WHERE workspace_id = $1 AND actor_id = $2 AND state NOT IN ('failed', 'released') LIMIT 1`,
    [workspaceId, actorId],
  );
  return result.rows.length > 0;
}

const UNKNOWN_CARD_AGENT = "Unknown agent name or stale machine address in this workspace. Use list_relay_agents.";
const CARD_NEEDS_IDENTITY = "This MCP session has no relay identity to publish a card for. Call join_relay with desktop_address (from GET /whoami on the relay socket) to publish your Agent Relay Desktop identity's card, or join_relay to use a hosted participant, then retry.";
const CARD_IDENTITY_CHANGED = "Your relay identity is no longer available or changed. Call relay_status, join_relay again if needed, then retry.";
/** joinLocked found nothing to join on a gate-only install: enrol at relaygate outside the lock, then retry. */
const NEEDS_GATE_ENROLMENT = Symbol("needs-gate-enrolment");
/** A Cursor cloud agent run's participant name (cursorCloudParticipantName). */
const CURSOR_RUN_NAME = /^cursor-cloud-[0-9a-f]{10}$/;
const CURSOR_RUN_RETIRING = "This Cursor cloud agent run's earlier connection was disconnected and its relay agent is being released. Retry join_relay in a minute.";
const CURSOR_TOKEN_ELSEWHERE = "cursor_identity_token is only for Cursor cloud agents connected through this server's OAuth (added at cursor.com/agents).";
const NO_PARTICIPANT_MESSAGE = "No hosted participant with that name is owned by you in this workspace.";
const NAME_TAKEN = "That relay name is already taken. Choose another name.";
/** Gate-only installs: reads go through relaygate as the caller's own relay identity, so one is needed first. */
export const GATE_JOIN_FIRST = "This install routes relay traffic through relaygate, which answers as your relay identity. Call join_relay first (or join_relay with desktop_address to use your Agent Relay Desktop identity), then retry.";
export const GATE_RENEW_FAILED = "relaygate did not accept this hosted participant's token, and renewing it failed. Retry; if it keeps failing, ask your operator whether relaygate's policy still allows hosted participants.";
const gateNotAdmitted = (client: RelayHostedClient) =>
  `This hosted participant is not enrolled at relaygate for hosted ${client} clients. Retry; if it keeps failing, ask your operator whether relaygate's policy allows hosted ${client} participants.`;
export const GATE_OAUTH_LAUNCH_REFUSED = "Launching agents from a hosted connector is not available on this install: relaygate does not proxy launches. Launch from Agent Relay Desktop or a native MCP session.";
const rejectedToken = (name: string) => new RelayToolError(
  `The relay token for participant ${name} was rejected by Relaycast. Call join_relay with name=${name} to recover it, or leave_relay to remove it.`);
type ChannelInput = { as?: string; as_person?: boolean; hosted?: boolean };
const AGENT_IDENTITY_UNAVAILABLE = "This workspace agent identity token did not resolve to an agent identity. Mint a new token.";
const AGENT_IDENTITY_NO_LAUNCH = "A workspace agent identity token cannot launch or release agents.";
const AGENT_IDENTITY_GATE = "Workspace agent identity tokens cannot use Relay on this install: relaygate enrols hosted participants for a person only.";
const agentIdentityOnly = (name: string) =>
  `This workspace agent identity token acts only as the relay agent ${name}. Omit \`as\`, or pass as=${name}.`;
const agentIdentityJoinOnly = (name: string) =>
  `This workspace agent identity token joins only as ${name}. Call join_relay without desktop_address, cursor_identity_token or another name.`;

function createRelayService(context: McpContext) {
  const { database, keyring, client, sessionId, gateClient: gate } = context.relay;
  /**
   * The client for calls made with an identity's own token. On gate-only
   * installs Desktop identities and hosted participants hold rg_ tokens only
   * relaygate accepts, so those calls go through relaygate.
   */
  const clientFor = (identity: { desktop?: boolean; gated?: boolean }) => (identity.desktop || identity.gated) && gate ? gate : client;
  /**
   * Directory reads (roster, names, channels, channel history) for an
   * identity: a gated hosted participant reads through relaygate with its own
   * token, so relaygate's policy filters what it sees; everyone else reads
   * with the workspace key as before.
   */
  const directory = (identity?: Identity | null) => identity?.gated && gate
    ? { via: gate, credential: identity.token } : { via: client, credential: key };
  type Directory = ReturnType<typeof directory>;
  const workspaceId = context.workspace.id;
  const organizationId = context.workspace.organizationId;
  const executor = database;
  const oauth = context.oauth;
  /**
   * A workspace agent identity token (authMode "agent_identity"): the Relay
   * tools act only as this identity's one hosted participant, selected by the
   * identity and never by the MCP session, so every token of the identity
   * reaches the same Relay agent.
   */
  const agent = context.authMode === "agent_identity" ? context.agentIdentity ?? null : null;
  /** Fails closed: an agent-identity context without its identity never falls back to the principal. */
  const agentMissing = context.authMode === "agent_identity" && !agent;
  const userId = agent ? agent.id : context.principal.userId;
  const ownerKey: Owner = { userId, agentIdentity: agent !== null };
  const key = context.workspace.relaycastApiKey;
  const relayWorkspaceId = context.workspace.relaycastWorkspaceId;
  const sessionHash = !oauth && !agent && sessionId ? ownerHash(sessionId) : null;
  // An agent identity's owner marker is in its own namespace, so it can never
  // equal a person's (ownerHash of a user id).
  const actorRef = agent ? agentIdentityOwnerRef(agent.id) : userId;
  const owner = ownerHash(actorRef);
  const ownerName = agent ? null : (typeof context.principal.name === "string" ? context.principal.name.trim().slice(0, 200) : "") || null;
  const desktopCall = context.desktopCall;
  /**
   * A desktop-managed call (a Desktop-provider credential, or the app bearer
   * with X-Agent-Relay-Desktop: 1, as Cloud): only the verified native chat's
   * identity may act, and a missing or unverified chat fails closed. OAuth
   * grants are never managed: they act only as their approved agent.
   */
  const managed = !oauth && (desktopCall.required || desktopCall.provider !== undefined);
  const linkedKind = (identity: Identity) => identity.desktop ? "desktop" as const : "hosted" as const;
  const channelDelivery = (identity: Identity, channel: string) =>
    identity.desktop ? desktopChannelDelivery(channel) : hostedChannelDelivery(channel);
  let linked: Promise<DesktopActor> | undefined;

  /** The synced Desktop identity of this call's verified native chat; throws when there is none. */
  function desktop() {
    linked ??= (async () => {
      if (!desktopCall.nativeSession) {
        throw new RelayToolError(desktopCall.provider === "cursor" ? DESKTOP_IDENTITY_MESSAGES.cursorUnverified : DESKTOP_IDENTITY_MESSAGES.unverified);
      }
      try {
        return { ...await linkedDesktopIdentity({
          database, keyring, client, ...(gate ? { gate } : {}), relaycastApiKey: key,
          workspaceId, userId, relaycastWorkspaceId: relayWorkspaceId,
          nativeSession: desktopCall.nativeSession, sourceId: desktopCall.nativeSourceId,
        }), desktop: true as const };
      } catch (error) {
        if (error instanceof DesktopIdentityUnavailable) throw new RelayToolError(error.message);
        throw error;
      }
    })();
    return linked;
  }

  /** Re-checks a stored identity with Relaycast; failures become tool errors. */
  async function verifiedDesktop(row: DesktopIdentityRow): Promise<DesktopActor> {
    try {
      return { ...await verifyDesktopIdentity({ keyring, client, ...(gate ? { gate } : {}), relaycastApiKey: key,
        userId, relaycastWorkspaceId: relayWorkspaceId, row }),
        desktop: true as const };
    } catch (error) {
      if (error instanceof DesktopIdentityUnavailable) throw new RelayToolError(error.message);
      throw error;
    }
  }

  /**
   * The Desktop identity this native MCP session linked with join_relay
   * desktop_address, verified again on every call; null when it has none.
   * Managed and OAuth calls never use a session link.
   */
  async function linkedDesktop(query: SqlExecutor = executor): Promise<DesktopActor | null> {
    if (managed || oauth || !sessionHash) return null;
    const row = await findDesktopIdentityBySession(query, workspaceId, userId, sessionHash);
    return row ? verifiedDesktop(row) : null;
  }

  /** Managed calls cannot choose another actor. */
  async function managedActorOnly(as?: string, alternate = false) {
    if (managed && (as || alternate)) {
      await desktop();
      throw new RelayToolError(MANAGED_AS_REFUSED);
    }
  }

  /**
   * Serializes join and leave for this owner in Postgres; every store access inside uses `tx`.
   * Once the locks are held, Relaycast and relaygate calls inside share ownerLockFetch's budget,
   * so a stalled upstream cannot hold the locks; waiting for the locks does not count.
   */
  function withOwnerLock<T>(run: (tx: SqlExecutor) => Promise<T>): Promise<T> {
    return database.transaction(async (tx) => {
      if (oauth) await oauth.lock(tx);
      await tx.query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))",
        ["selfhost-hosted-mcp", `${workspaceId}:${userId}`]);
      return underOwnerLock(() => run(tx));
    });
  }

  /** Callers hold the owner lock; `tx` is the transaction that would write the binding. */
  async function refuseRetiring(tx: SqlExecutor, agentRemoteId: string, agentName: string): Promise<void> {
    if (await retiringIdentity(tx, { organizationId, workspaceId, userId, agentRemoteId, agentName })) {
      throw new RelayToolError(MCP_OAUTH_RETIRING_MESSAGE);
    }
  }

  function ownsRemote(remote: { metadata: Record<string, unknown> }): boolean {
    return !isBindingOwnedIdentity(remote.metadata) && remote.metadata.source === HOSTED_SOURCE && remote.metadata.cloud_workspace_id === workspaceId
      && remote.metadata.owner_hash === owner;
  }

  /**
   * The remote agent behind a row and whether its stored token still works.
   * When Relaycast rejects the token, the workspace-key roster answers for
   * existence, ownership and cleanup only: the token is not usable.
   */
  async function hostedRemote(row: ParticipantRow, token: string): Promise<{ remote: RosterAgent | null; tokenUsable: boolean }> {
    try {
      const remote = await client.authenticatedAgent(token);
      return { remote: remote.status === "released" ? null : remote, tokenUsable: true };
    } catch (error) {
      if (!(error instanceof RelaycastCallError) || error.status !== 401) throw error;
      const remote = oauth
        ? (await client.listAgents(key, "all", { includeStale: true })).find(agent=>agent.id===row.agentRemoteId) ?? null
        : await client.getRosterAgent(key, row.agentName);
      return { remote, tokenUsable: false };
    }
  }

  /**
   * The hosted MCP client relaygate's policy matches this caller's
   * participants on: the grant's admission kind, from the redirect URIs its
   * authorization codes were delivered to, so a client that only registers a
   * provider's callback beside its own enrols as "mcp". Callers inside a
   * transaction pass it.
   */
  let clientKind: Promise<RelayHostedClient> | undefined;
  function hostedClient(query: SqlExecutor = executor): Promise<RelayHostedClient> {
    clientKind ??= (async () => {
      if (!oauth) return "mcp" as const;
      const row = (await query.query<{ client_name: string | null; redirect_uris: string[]; used: string[] }>(
        `SELECT c.client_name, c.redirect_uris, ${usedRedirectUrisSql("$2::uuid", "c.client_id")} AS used
           FROM mcp_oauth_clients c WHERE c.client_id = $1`, [oauth.access.clientId, oauth.access.grantId])).rows[0];
      return row ? admissionConnectorKind({ clientName: row.client_name, redirectUris: row.redirect_uris ?? [] }, row.used ?? []) : "mcp" as const;
    })();
    return clientKind;
  }

  /** Enrols `name` for this owner at relaygate; refusals become tool errors naming what the operator must change. */
  async function enrolAtGate(name: string): Promise<GateEnrolment> {
    try {
      return await enrolHostedAtGate({ database, gate: gate! }, {
        workspaceId, organizationId, userId, agentName: name, client: await hostedClient() });
    } catch (error) {
      if (error instanceof HostedGateRefused) throw new RelayToolError(error.message);
      throw error;
    }
  }

  /**
   * A gated participant's live state at relaygate: whoami must name the
   * stored relaygate agent and this owner, and the upstream agent behind it
   * must be the stored Relaycast agent. "rejected" means relaygate no longer
   * accepts the token (it expires after 24 hours).
   */
  async function gateState(row: ParticipantRow, token: string):
    Promise<{ state: "ok"; remote: RosterAgent } | { state: "rejected" } | { state: "changed" }> {
    let who;
    try {
      who = await gate!.whoami(token);
    } catch (error) {
      if (error instanceof RelaycastCallError && error.status === 401) return { state: "rejected" };
      throw error;
    }
    if (who.agentId !== row.relaygateAgentId || (who.userId !== null && who.userId !== userId)) return { state: "changed" };
    const remote = await gate!.authenticatedAgent(token);
    return remote.id === row.agentRemoteId && remote.status !== "released" ? { state: "ok", remote } : { state: "changed" };
  }

  /** Whether `name` is one of this OAuth grant's Cursor cloud agent runs (cursor_cloud_runs). */
  async function ownRun(name: string | undefined, query: SqlExecutor = executor): Promise<boolean> {
    if (!oauth || !context.cursorCloud || !name || !CURSOR_RUN_NAME.test(name)) return false;
    return (await query.query(
      "SELECT 1 FROM cursor_cloud_runs WHERE grant_id = $1 AND agent_name = $2 AND user_id = $3 AND workspace_id = $4",
      [oauth.access.grantId, name, userId, workspaceId])).rows.length > 0;
  }

  /**
   * The release fence of a Cursor cloud agent run: a run row of a revoked
   * grant stays until the OAuth teardown worker has released the
   * participant, so nothing may reattach it meanwhile.
   */
  async function cursorRunRetiring(tx: SqlExecutor, name: string): Promise<boolean> {
    if (!CURSOR_RUN_NAME.test(name)) return false;
    return (await tx.query(`SELECT 1 FROM cursor_cloud_runs r JOIN mcp_oauth_grants g ON g.id = r.grant_id
      WHERE r.workspace_id = $1 AND r.user_id = $2 AND r.agent_name = $3 AND g.revoked_at IS NOT NULL LIMIT 1`,
    [workspaceId, userId, name])).rows.length > 0;
  }

  /** SELFHOST_CURSOR_CLOUD_RUN_IDENTITY=required: a cursor-cloud grant acts only as a verified run. */
  async function runRequired(query: SqlExecutor = executor): Promise<boolean> {
    return Boolean(oauth && context.cursorCloud?.config.runIdentity === "required") && await hostedClient(query) === "cursor-cloud";
  }

  /** How a Cursor cloud agent mints the token join_relay takes; null for any other connection. */
  async function cursorIdentityGuidance(query: SqlExecutor = executor) {
    const cc = context.cursorCloud;
    if (!oauth || !cc || await hostedClient(query) !== "cursor-cloud") return null;
    const nonce = cursorIdentityNonces(cc.nonceSecret, oauth.access.grantId).current;
    return { audience: cc.audience, nonce, mint_command: cursorMintCommand(cc.audience, nonce),
      next_step: "Run mint_command in this cloud agent's shell, then call join_relay with cursor_identity_token set to the returned token. Use the name it returns as `as` on every relay tool call." };
  }

  async function cursorRunRequiredError(query: SqlExecutor = executor): Promise<RelayToolError> {
    const guidance = await cursorIdentityGuidance(query);
    return new RelayToolError(`This Cursor connection acts only as a verified cloud agent run. ${guidance
      ? `Mint an identity token with: ${guidance.mint_command} then call join_relay with cursor_identity_token, and pass the returned name as \`as\`.`
      : "Call join_relay with cursor_identity_token."}`);
  }

  /** The row participant() would select for `as` (or this session), read without the owner lock. */
  async function selectedRow(as?: string): Promise<ParticipantRow | null> {
    if (agent) return findParticipant(executor, workspaceId, ownerKey, organizationId, { owned: true });
    if (await ownRun(as)) return findParticipant(executor, workspaceId, ownerKey, organizationId, { name: as! });
    const approvedId = oauth?.access.agentRemoteId;
    const name = oauth && !approvedId ? oauth.access.agentName : as;
    const selector: Selector | null = approvedId ? { agentRemoteId: approvedId }
      : name ? { name } : sessionHash ? { sessionHash } : null;
    return selector ? findParticipant(executor, workspaceId, ownerKey, organizationId, selector) : null;
  }

  /**
   * Gate-only installs, before any owner-locked work: makes the selected row
   * usable at relaygate for this caller's hosted client. A gated row whose
   * rg_ token relaygate rejects (it expires after 24 hours) enrols again, and
   * the same owner gets the same relaygate agent back. A gated row relaygate
   * has not admitted this hosted client for enrols again as it, so
   * relaygate's policy decides that client too: a refusal leaves the row and
   * its token as they were. A row registered in Relaycast directly before this
   * install enforced relaygate for hosted participants is enrolled through
   * relaygate once, after its upstream agent is confirmed as this owner's
   * with the workspace roster (a one-time control-plane check, never the
   * participant's traffic), so the enrolment only takes over the agent the
   * row already is. relaygate introspects the credential with this service,
   * so no transaction is open while it enrols; the result is written under
   * the owner lock only if the row is unchanged. Throws when relaygate
   * refuses, naming what its policy is missing.
   */
  async function refreshGated(as?: string): Promise<void> {
    if (!gate) return;
    const row = await selectedRow(as);
    if (!row || row.relayWorkspaceId !== relayWorkspaceId || row.agentName === launcherName(userId)) return;
    const kind = await hostedClient();
    let rejected = true;
    if (row.relaygateAgentId !== null) {
      const state = (await gateState(row, decryptSecret(row.tokenCiphertext, keyring))).state;
      if (state === "changed" || (state === "ok" && row.admittedClients.includes(kind))) return;
      rejected = state === "rejected";
    }
    // relaygate takes an upstream agent of this name over when it enrols one it already knows. Ask only while that
    // agent is still this row's: a replaced or renamed one is never handed to relaygate. A pre-gate row must also
    // still be this owner's; a gated row's agent was registered by relaygate and carries no owner marker.
    const upstream = await client.getRosterAgent(key, row.agentName);
    if (!upstream || upstream.status === "released" || upstream.id !== row.agentRemoteId
        || (row.relaygateAgentId === null && !ownsRemote(upstream))) return;
    const enrolled = await enrolAtGate(row.agentName);
    if (enrolled.relaycastAgentId !== row.agentRemoteId) {
      // The agent this row was is gone: never adopt another. Release only an agent relaygate registered itself for
      // this enrolment; a name it took over is someone's live agent, and releasing it would delete that agent.
      if (freshAtGate(enrolled)) await gate.releaseOwnAgent(enrolled.token).catch(() => {});
      return;
    }
    // The same upstream agent. relaygate may answer with a new relaygate agent for it (it re-created its own
    // record); the row adopts that one with the token, as long as nothing changed the row meanwhile.
    const admittedClients = rejected ? [kind] : [...new Set([...row.admittedClients, kind])];
    await withOwnerLock(async (tx) => {
      const current = await findParticipant(tx, workspaceId, ownerKey, organizationId, { agentRemoteId: row.agentRemoteId });
      if (!current || current.id !== row.id || current.tokenCiphertext !== row.tokenCiphertext
          || current.relaygateAgentId !== row.relaygateAgentId) return;
      await updateParticipant(tx, row.id, {
        tokenCiphertext: encryptSecret(enrolled.token, keyring.active), relaygateAgentId: enrolled.relaygateAgentId, admittedClients });
    });
  }

  /**
   * participant() on a gate-only install. Never enrols (refreshGated did,
   * before the lock), and refuses a row relaygate has not admitted this
   * caller's hosted client for. A row relaygate does not accept is returned only to
   * `allowRejected` callers, for cleanup: its upstream agent is then
   * released with the workspace key, as for any participant whose token no
   * one can use.
   */
  async function gatedParticipant(row: ParticipantRow, requested: string | undefined, options: ParticipantOptions): Promise<Hosted | null> {
    const { allowGone = false, allowRejected = false, executor: query = executor } = options;
    const token = decryptSecret(row.tokenCiphertext, keyring);
    const checked = row.relaygateAgentId === null ? null : await gateState(row, token);
    if (checked?.state === "changed" && !allowGone) {
      throw new RelayToolError("The hosted participant is no longer available. Its relay identity changed.");
    }
    let remote: RosterAgent | null = checked?.state === "ok" ? checked.remote : null;
    const usable = remote !== null;
    if (usable) {
      const kind = await hostedClient(query);
      if (!row.admittedClients.includes(kind)) throw new RelayToolError(gateNotAdmitted(kind));
    }
    if (!usable && checked?.state !== "changed") {
      if (!allowRejected) throw new RelayToolError(GATE_RENEW_FAILED);
      const upstream = await client.getRosterAgent(key, row.agentName);
      remote = upstream && upstream.id === row.agentRemoteId && upstream.status !== "released" && ownsRemote(upstream) ? upstream : null;
    }
    let name = row.agentName;
    if (usable && remote && remote.name !== row.agentName) {
      await updateParticipant(query, row.id, { agentName: remote.name });
      name = remote.name;
    }
    if (oauth && !options.run) {
      oauth.assertActor(requested, name);
      if (usable) await oauth.pin(query, { workspaceId, userId, agentName: name, agentRemoteId: row.agentRemoteId });
    }
    return { row: { ...row, agentName: name }, token, name, gated: usable,
      remotePresent: remote !== null, tokenUsable: usable };
  }

  /**
   * The owner's participant selected by `as`, else by this MCP session.
   * Verifies the remote agent is still the one this owner registered, and
   * refuses a rejected token unless `allowRejected`.
   */
  async function participant(as?: string, options: ParticipantOptions = {}): Promise<Hosted | null> {
    if (agentMissing) throw new RelayToolError(AGENT_IDENTITY_UNAVAILABLE);
    if (agent) {
      // An agent identity acts only as its own participant: `as` may only name it.
      if (gate) throw new RelayToolError(AGENT_IDENTITY_GATE);
      if (as !== undefined && as.trim().toLowerCase() !== agent.name.toLowerCase()) throw new RelayToolError(agentIdentityOnly(agent.name));
      as = undefined;
    }
    // Gate-only installs renew or migrate the row at relaygate before any lock is taken.
    if (gate && !options.executor && !options.internal) await refreshGated(as);
    if (oauth && !options.executor) return withOwnerLock(tx=>participant(as,{...options,executor:tx}));
    const { allowMissing = false, allowGone = false, allowRejected = false, executor: query = executor } = options;
    const requested = as;
    const run = options.run || await ownRun(as, query);
    if (oauth && !run && await runRequired(query)) throw await cursorRunRequiredError(query);
    const approvedId = run ? undefined : oauth?.access.agentRemoteId;
    if (oauth && !run && !approvedId) { oauth.assertActor(as); as = oauth.access.agentName; }
    const selector: Selector | null = agent ? { owned: true } : approvedId ? { agentRemoteId: approvedId }
      : as ? { name: as } : sessionHash ? { sessionHash } : null;
    const row = selector ? await findParticipant(query, workspaceId, ownerKey, organizationId, selector) : null;
    if (!row) {
      if (approvedId && !allowGone) throw new RelayToolError("The approved agent is no longer available. Reconnect the app to choose an agent.");
      if (as && !allowMissing && !(oauth && !requested) && !approvedId) throw new RelayToolError(NO_PARTICIPANT_MESSAGE);
      return null;
    }
    if (row.relayWorkspaceId !== relayWorkspaceId) {
      throw new RelayToolError("The participant does not belong to you in this workspace's relay.");
    }
    // Retirement fence, before any Relaycast call: an unpinned OAuth grant
    // would pin this row's agent, and a native join would bind its session.
    if (((oauth && !run && !approvedId) || (options.bind && !row.sessionHash)) && options.executor) {
      await refuseRetiring(query, row.agentRemoteId, row.agentName);
    }
    if (gate) {
      // The owner's launcher stays a Relaycast identity (relaygate does not proxy launches; each launch is
      // checked at relaygate's /v1/check instead), so it never messages on a gate-only install.
      if (row.agentName === launcherName(userId) && !options.internal) throw new RelayToolError(NO_PARTICIPANT_MESSAGE);
      if (row.agentName !== launcherName(userId)) return gatedParticipant(row, requested, { ...options, run });
    }
    const token = decryptSecret(row.tokenCiphertext, keyring);
    const { remote, tokenUsable } = await hostedRemote(row, token);
    if ((!remote && !allowGone) || (remote && (remote.id !== row.agentRemoteId || !ownsRemote(remote)))) {
      throw new RelayToolError("The hosted participant is no longer available. Its relay identity changed.");
    }
    let name = row.agentName;
    if (remote && remote.name !== row.agentName) {
      await updateParticipant(query, row.id, { agentName: remote.name });
      name = remote.name;
    }
    if (oauth && !run) {
      oauth.assertActor(requested, name);
      if (remote) await oauth.pin(query, { workspaceId, userId, agentName: name, agentRemoteId: row.agentRemoteId });
    }
    if (!tokenUsable && !allowRejected) throw rejectedToken(name);
    return { row: { ...row, agentName: name }, token, name, remotePresent: remote !== null, tokenUsable };
  }

  async function touchPresence(identity: Identity): Promise<void> {
    try {
      await clientFor(identity).heartbeat(identity.token);
    } catch {
      // Presence is best effort; the call itself proceeds.
    }
  }

  async function listedAgents(status: "active" | "all", includeStale = false, dir: Directory = directory()) {
    return (await withinRelayRead(
      signal => dir.via.listAgents(dir.credential, status, { includeStale, signal }),
      ROSTER_TIMEOUT_MS,
    )).filter(isListedRelayAgent);
  }

  const syncedSessionKinds = new Set(["codex", "grok", "pi", "opencode", "claude", "copilot", "cursor"]);
  const syncedSessionId = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
  type SyncedDesktopSessions = {
    sessions: Map<string, { sessionId: string; sessionKind: string }>;
    ambiguous: Set<string>;
  };
  async function syncedDesktopSessions(agents: readonly RosterAgent[]) {
    const targets = agents.map(agent => relayAgentOwnerTarget(agent, Boolean(gate)));
    const candidates = new Map(targets.map((target, index) => [`${target.lookupId}\0${target.name}`, agents[index]!]));
    const ids = [...new Set(targets.map(target => target.lookupId))];
    if (!ids.length) return { sessions: new Map(), ambiguous: new Set() } satisfies SyncedDesktopSessions;
    const rows = await executor.query<{ agent_name: string; agent_remote_id: string; native_session_kind: string; native_session_id: string }>(
      `SELECT agent_name, agent_remote_id, native_session_kind, native_session_id
         FROM desktop_relay_identities
        WHERE workspace_id = $1 AND agent_remote_id = ANY($2::text[])
          AND relaycast_workspace_id = $3
          AND native_session_kind IS NOT NULL AND native_session_id IS NOT NULL`,
      [workspaceId, ids, relayWorkspaceId],
    );
    const sessions = new Map<string, { sessionId: string; sessionKind: string }>();
    const matched = new Set<string>();
    const ambiguous = new Set<string>();
    for (const row of rows.rows) {
      const agent = candidates.get(`${row.agent_remote_id}\0${row.agent_name}`);
      if (!agent) continue;
      if (matched.has(agent.id)) {
        sessions.delete(agent.id);
        ambiguous.add(agent.id);
        continue;
      }
      matched.add(agent.id);
      const kind = row.native_session_kind.trim();
      if (syncedSessionKinds.has(kind) && syncedSessionId.test(row.native_session_id)) {
        sessions.set(agent.id, { sessionId: row.native_session_id, sessionKind: kind });
      }
    }
    return { sessions, ambiguous };
  }

  async function roster(status: "live" | "all" | "offline", people: readonly McpMember[], includeStale = false, dir: Directory = directory()) {
    const listed = await listedAgents(status === "live" ? "active" : "all", includeStale, dir);
    const [owners, synced] = await Promise.all([
      loadRelayAgentOwners(database, workspaceId, relayWorkspaceId, listed, people, Boolean(gate))
        .catch(error => { ownerEnrichmentFailed("list_relay_agents", error); return undefined; }),
      syncedDesktopSessions(listed).then(result => ({ ...result, failed: false as const })).catch(error => {
        sessionEnrichmentFailed(error);
        return { sessions: new Map<string, { sessionId: string; sessionKind: string }>(),
          ambiguous: new Set<string>(), failed: true as const };
      }),
    ]);
    return listed
      .map(agent => {
        const row = rosterAgent(agent, people, userId, workspaceId, owners?.get(agent.id));
        const session = row.session_attribution ? null : synced.sessions.get(agent.id);
        const unavailableReason = row.session_attribution || session ? null
          : synced.failed ? "enrichment_failed" as const
            : synced.ambiguous.has(agent.id) ? "ambiguous_sync" as const : null;
        return { ...row,
          ...(session ? { session_id: session.sessionId, session_kind: session.sessionKind, session_attribution: "synced" as const } : {}),
          session_unavailable_reason: unavailableReason,
          ...cardSummary(agent.metadata, agent) };
      })
      .filter(agent => status === "all" || (status === "live" ? agent.online : !agent.online));
  }

  async function addressFor(name: string, bestEffort = false, dir: Directory = directory()): Promise<string | null> {
    try {
      // Bounded lookup: one name, never the whole roster.
      const agent = await dir.via.findAgentByName(dir.credential, name);
      return agent && isListedRelayAgent(agent) ? agent.address : null;
    } catch (error) {
      if (bestEffort) return null;
      throw error;
    }
  }

  /** A name or `name@machine` address, resolved by name without listing the roster. */
  async function explicitAgent(target: string, dir: Directory = directory()): Promise<RosterAgent | null> {
    const separator = target.lastIndexOf("@");
    const name = separator < 0 ? target : target.slice(0, separator);
    if (!name) return null;
    const agent = await dir.via.findAgentByName(dir.credential, name) ?? await dir.via.getRosterAgent(dir.credential, name);
    return agent?.name === name && (separator < 0 || agent.address === target) ? agent : null;
  }

  async function recipient(to: string, people: readonly McpMember[], dir: Directory = directory()) {
    const agent = await explicitAgent(to, dir);
    if (!agent || agent.status === "released" || agent.metadata.source === "cloud-persona-deploy"
        || agent.metadata.source === "cloud-persona") {
      throw new RelayToolError("Unknown agent name or stale machine address in this workspace. Use list_relay_agents.");
    }
    return { ...rosterAgent(agent, people, userId, workspaceId), card: recipientCard(agent.metadata) };
  }

  async function conversation(token: string, name: string, peer: string, via = client) {
    return (await via.listConversations(token))
      .find(item => item.participants.length === 2 && item.participants.includes(name) && item.participants.includes(peer));
  }

  /**
   * A person's (or an OAuth grant's) participant may not take a name a
   * workspace agent identity holds, in any letter case. The owner's internal
   * launcher and an agent identity's own join are exempt. Run in the
   * transaction that writes the participant row, before any Relaycast call.
   */
  async function refuseAgentIdentityName(tx: SqlExecutor, name: string, options: { internal?: boolean } = {}): Promise<void> {
    if (agent || options.internal) return;
    if (await agentIdentityHoldsName(tx, workspaceId, name)) throw new RelayToolError(NAME_TAKEN);
  }

  /**
   * Callers hold the owner lock. On a gate-only install every participant but
   * the owner's launcher (`internal`) enrols through relaygate.
   */
  async function registerParticipant(tx: SqlExecutor, name: string, boundSession: string | null, objective: string,
    options: { internal?: boolean; enrolled?: GateEnrolment; run?: boolean } = {}) {
    if (gate && !options.internal) {
      // Gate-only installs enrol at relaygate before the owner lock (prepareGateRegistration).
      if (!options.enrolled || options.enrolled.name !== name) throw new Error("gate registration needs a prepared enrolment");
      return registerAtGate(tx, options.enrolled, boundSession, options.run);
    }
    await refuseAgentIdentityName(tx, name, options);
    const remote = await client.getAgent(key, name);
    if (remote && !ownsRemote(remote)) throw new RelayToolError(NAME_TAKEN);
    // Recovering an owned agent binds it again; its release may be in flight.
    if (remote) await refuseRetiring(tx, remote.id, remote.name);
    // An owned agent without a row is an interrupted join: recover its token.
    const registered = remote
      ? await client.recoverHosted(key, name, remote.id, actorRef)
      : await client.registerHosted(key, name, {
        source: HOSTED_SOURCE, cloud_workspace_id: workspaceId, owner_hash: owner, objective,
        // Agent card fields (x-agent-relay kind and owner).
        kind: HOSTED_KIND, ...(ownerName ? { owner_name: ownerName } : {}),
        ...(oauth ? { created_by: "mcp-oauth" } : agent ? { created_by: "agent-identity" } : {}),
      });
    try {
      await insertParticipant(tx, {
        workspaceId, userId, agentIdentity: ownerKey.agentIdentity, relayWorkspaceId, sessionHash: boundSession,
        agentName: registered.name, agentRemoteId: registered.id,
        tokenCiphertext: encryptSecret(registered.token, keyring.active), relaygateAgentId: null, admittedClients: [],
      });
      if (oauth && !options.run) await oauth.pin(tx, { workspaceId, userId, agentName: registered.name, agentRemoteId: registered.id });
    } catch (error) {
      if (!remote) await client.releaseHosted(key, registered.name, registered.id).catch(() => {});
      throw error;
    }
    return registered;
  }

  /**
   * Gate-only installs, before the owner lock: relaygate enrols the name for
   * this owner (refusing it, with the rule to add, when its policy has none
   * for this hosted client). relaygate introspects the credential with this
   * service, so no transaction may be open meanwhile. The owner metadata
   * Relaycast registration used to carry is merged through relaygate: OAuth
   * teardown and the roster read it. Ownership itself is decided by
   * relaygate's whoami, never by it.
   *
   * relaygate reserves a name for its first enroller only, and takes over an
   * upstream agent of that name that it did not register. So the name is
   * checked with the workspace roster first, as registerParticipant does: an
   * agent another owner (or a binding) holds is refused before any credential
   * is minted. relaygate's answer is checked again: the agent must be the one
   * checked, this owner's, or one relaygate registered itself for this
   * enrolment. Anything else is refused and never released (that would
   * delete the other owner's agent).
   */
  async function prepareGateRegistration(name: string, objective: string): Promise<GateEnrolment> {
    // Early refusal before relaygate mints anything; registerAtGate checks again in the row's transaction.
    await refuseAgentIdentityName(executor, name);
    const checked = await client.getRosterAgent(key, name);
    const held = checked && checked.status !== "released" ? checked : null;
    if (held && !ownsRemote(held)) throw new RelayToolError(NAME_TAKEN);
    // An owned agent without a row is an interrupted join: relaygate enrols the same agent again.
    const enrolled = await enrolAtGate(name);
    const ours = held ? enrolled.relaycastAgentId === held.id
      : !isBindingOwnedIdentity(enrolled.metadata) && (ownsRemote(enrolled) || freshAtGate(enrolled));
    if (!ours) {
      if (freshAtGate(enrolled)) await gate!.releaseOwnAgent(enrolled.token).catch(() => {});
      throw new RelayToolError(NAME_TAKEN);
    }
    try {
      await gate!.mergeOwnAgentMetadata(enrolled.token, {
        source: HOSTED_SOURCE, cloud_workspace_id: workspaceId, owner_hash: owner, objective,
        kind: await hostedKind(), hosted_client: await hostedClient(), ...(ownerName ? { owner_name: ownerName } : {}),
        ...(oauth ? { created_by: "mcp-oauth" } : {}),
      });
    } catch (error) {
      await gate!.releaseOwnAgent(enrolled.token).catch(() => {});
      throw error;
    }
    return enrolled;
  }

  /** registerParticipant on a gate-only install, under the owner lock: the row keeps relaygate's rg_ token. */
  async function registerAtGate(tx: SqlExecutor, enrolled: GateEnrolment, boundSession: string | null, run = false) {
    try {
      await refuseAgentIdentityName(tx, enrolled.name);
      // The same owner may get an agent back whose release is in flight.
      await refuseRetiring(tx, enrolled.relaycastAgentId, enrolled.name);
      await insertParticipant(tx, {
        workspaceId, userId, agentIdentity: ownerKey.agentIdentity, relayWorkspaceId, sessionHash: boundSession,
        agentName: enrolled.name, agentRemoteId: enrolled.relaycastAgentId,
        tokenCiphertext: encryptSecret(enrolled.token, keyring.active), relaygateAgentId: enrolled.relaygateAgentId,
        admittedClients: [await hostedClient(tx)],
      });
      if (oauth && !run) await oauth.pin(tx, { workspaceId, userId, agentName: enrolled.name, agentRemoteId: enrolled.relaycastAgentId });
    } catch (error) {
      // Never leave a retiring agent's release to race a new binding: only a fresh one is released here.
      if (!(error instanceof RelayToolError && error.message === MCP_OAUTH_RETIRING_MESSAGE)) {
        await gate!.releaseOwnAgent(enrolled.token).catch(() => {});
      }
      throw error;
    }
    return { id: enrolled.relaycastAgentId, name: enrolled.name, token: enrolled.token };
  }

  /** Releases a participant's agent: through relaygate (its own token) when gated, else with the workspace key. */
  async function releaseRemote(hosted: Hosted): Promise<void> {
    if (!hosted.remotePresent) return;
    if (hosted.gated) {
      await gate!.releaseOwnAgent(hosted.token);
      return;
    }
    try {
      await client.releaseHosted(key, hosted.name, hosted.row.agentRemoteId);
    } catch (error) {
      // A concurrent remote deletion also completes the release.
      if (!(error instanceof RelaycastCallError) || error.status !== 404 || await client.getAgent(key, hosted.name)) throw error;
    }
  }

  /**
   * Re-issues the token of an existing participant whose stored token
   * Relaycast rejects. Callers hold the owner lock, and `participant` has
   * already verified that the roster agent is this row's id and carries this
   * owner's metadata, so a foreign owner or a successor identity never gets
   * here. Takeover is bound to the row's agent id, and the replacement token
   * is persisted on `tx` before join reports success. If persisting fails
   * after the takeover, the error propagates and the transaction rolls back:
   * the stored token stays rejected, and the next join_relay repeats this
   * same recovery.
   */
  async function recoverToken(tx: SqlExecutor, existing: Hosted): Promise<string> {
    let recovered;
    try {
      recovered = await client.recoverHosted(key, existing.name, existing.row.agentRemoteId, actorRef);
    } catch (error) {
      const diagnostic = safeDiagnostic(error);
      if (diagnostic) console.error("[selfhost-mcp] relay operation failed", diagnostic);
      throw new RelayToolError(`Relaycast rejected the stored token for participant ${existing.name}, and recovering it failed. No replacement token was stored; the relay outcome may be unknown. Retry join_relay with name=${existing.name}, or call leave_relay to remove it.`);
    }
    if (recovered.id !== existing.row.agentRemoteId) {
      throw new RelayToolError("The hosted participant is no longer available. Its relay identity changed.");
    }
    await updateParticipant(tx, existing.row.id, { tokenCiphertext: encryptSecret(recovered.token, keyring.active) });
    return recovered.token;
  }

  async function join(input: { name?: string; description?: string; desktop_address?: string; cursor_identity_token?: string }) {
    if (agentMissing) throw new RelayToolError(AGENT_IDENTITY_UNAVAILABLE);
    if (agent) {
      // An agent identity joins only as itself, as a hosted participant.
      if (input.cursor_identity_token !== undefined || input.desktop_address
          || (input.name !== undefined && input.name.trim().toLowerCase() !== agent.name.toLowerCase())) {
        throw new RelayToolError(agentIdentityJoinOnly(agent.name));
      }
      if (gate) throw new RelayToolError(AGENT_IDENTITY_GATE);
    }
    if (input.cursor_identity_token !== undefined) {
      if (input.name || input.desktop_address) throw new RelayToolError("cursor_identity_token cannot be combined with name or desktop_address: the run's name is fixed.");
      return joinCursorRun(input.cursor_identity_token, input.description);
    }
    if (managed) {
      const identity = await desktop();
      if (input.name || input.description || (input.desktop_address && input.desktop_address !== identity.address)) {
        throw new RelayToolError(MANAGED_JOIN_REFUSED);
      }
      return { joined: true, linked: "desktop" as const, name: identity.name, address: identity.address,
        already_joined: true, reply_guidance: DESKTOP_REPLY_GUIDANCE };
    }
    if (input.desktop_address) return joinDesktop(input.desktop_address.trim(), input);
    if (oauth && !oauth.access.agentRemoteId) oauth.assertActor(input.name);
    if (!sessionHash && !input.name && !oauth && !agent) {
      throw new RelayToolError("Initialize MCP to receive Mcp-Session-Id, or pass an explicit name and use as on later calls.");
    }
    const requestedName = agent ? agent.name : oauth?.access.agentName ?? input.name ?? automaticParticipantName(context.principal, sessionHash!);
    const ownerLabel = agent ? agent.name : context.principal.name.trim() || context.principal.email || userId;
    const objective = input.description ?? (agent ? `Workspace agent identity ${agent.name}`
      : `Hosted MCP inbox participant acting for ${ownerLabel}`);
    if (gate) {
      // Gate-only installs: the launcher name is the owner's launcher, never a messaging participant.
      if (requestedName === launcherName(userId)) throw new RelayToolError("That relay name is reserved. Choose another name.");
      // Renew or migrate an existing participant at relaygate before taking the owner lock.
      await refreshGated();
      await refreshGated(requestedName);
    }
    let prepared: GateEnrolment | undefined;
    for (;;) {
      const outcome = await joinLocked(input, requestedName, objective, prepared);
      if (outcome !== NEEDS_GATE_ENROLMENT) return outcome;
      // No participant yet: enrol at relaygate with no lock held, then join again under the lock.
      prepared = await prepareGateRegistration(requestedName, objective);
    }
  }

  async function joinLocked(input: { name?: string; description?: string }, requestedName: string, objective: string,
    prepared: GateEnrolment | undefined) {
    const joined = await withOwnerLock(async (tx) => {
      const bound = await participant(undefined, { allowRejected: true, executor: tx });
      if (oauth && bound) oauth.assertActor(input.name, bound.name);
      if (bound && input.name && bound.name !== input.name && !oauth && !agent) {
        throw new RelayToolError("This MCP session is already joined. Leave before choosing another name.");
      }
      let existing = bound ?? await participant(requestedName, {
        allowMissing: true, allowRejected: true, executor: tx, bind: Boolean(sessionHash) });
      if (existing && await cursorRunRetiring(tx, existing.row.agentName)) throw new RelayToolError(CURSOR_RUN_RETIRING);
      if (existing) {
        if (sessionHash && existing.row.sessionHash && existing.row.sessionHash !== sessionHash) {
          throw new RelayToolError("That participant is bound to another MCP session. Use as to act as it without changing its binding, or choose a new name.");
        }
        if (gate && prepared && existing.row.agentName !== launcherName(userId)) existing = await settlePrepared(tx, existing, prepared);
        // A gated participant is renewed only at relaygate (refreshGated), never by a Relaycast takeover.
        if (gate && existing.row.agentName !== launcherName(userId) && !existing.tokenUsable) throw new RelayToolError(GATE_RENEW_FAILED);
        const token = existing.tokenUsable ? existing.token : await recoverToken(tx, existing);
        if (sessionHash && !existing.row.sessionHash) await updateParticipant(tx, existing.row.id, { sessionHash });
        await unlinkDesktop(tx);
        return { name: existing.name, token, gated: existing.gated, alreadyJoined: true, recovered: !existing.tokenUsable };
      }
      if (gate && !prepared) return NEEDS_GATE_ENROLMENT;
      const registered = await registerParticipant(tx, requestedName, sessionHash, objective, { enrolled: prepared });
      // Joining a hosted participant replaces this session's desktop link.
      await unlinkDesktop(tx);
      return { name: registered.name, token: registered.token, gated: Boolean(gate), alreadyJoined: false, recovered: false };
    });
    if (joined === NEEDS_GATE_ENROLMENT) return joined;
    await touchPresence(joined);
    return { joined: true, linked: "hosted" as const, name: joined.name, address: await addressFor(joined.name, true, directory(joined)),
      already_joined: joined.alreadyJoined, recovered: joined.recovered, reply_guidance: HOSTED_REPLY_GUIDANCE, desktop_relay_guidance: DESKTOP_RELAY_GUIDANCE };
  }

  /**
   * joinLocked found a participant after this join enrolled at relaygate: a
   * concurrent join of this owner wrote it meanwhile. relaygate gives the same
   * owner and name the same agent and revokes its earlier tokens, so the
   * prepared enrolment is usually the row's own agent, whose stored token it
   * just revoked: the row adopts the prepared token. Otherwise the prepared
   * agent is released only when relaygate registered it itself and no row of
   * this owner holds its name or upstream agent, since releasing deletes the
   * upstream agent by name. In every other case nothing is done: the agent
   * belongs to a row, and a rejected token renews at relaygate on the next
   * call. Callers hold the owner lock.
   */
  async function settlePrepared(tx: SqlExecutor, existing: Hosted, prepared: GateEnrolment): Promise<Hosted> {
    if (existing.row.relaygateAgentId === prepared.relaygateAgentId && existing.row.agentRemoteId === prepared.relaycastAgentId) {
      if (existing.tokenUsable) return existing;
      await updateParticipant(tx, existing.row.id, {
        tokenCiphertext: encryptSecret(prepared.token, keyring.active), admittedClients: [await hostedClient(tx)] });
      return { ...existing, token: prepared.token, gated: true, remotePresent: true, tokenUsable: true };
    }
    const held = await findParticipant(tx, workspaceId, ownerKey, organizationId, { name: prepared.name })
      ?? await findParticipant(tx, workspaceId, ownerKey, organizationId, { agentRemoteId: prepared.relaycastAgentId });
    if (!held && freshAtGate(prepared)) await gate!.releaseOwnAgent(prepared.token).catch(() => {});
    return existing;
  }

  /**
   * join_relay cursor_identity_token: a Cursor cloud agent run joins as its
   * own participant (docs/cursor-cloud-agents.md). The token is a
   * Cursor-signed OIDC JWT minted in the run's VM for this install's audience
   * and this grant's nonce (./cursor-oidc.ts); the Cursor account behind it
   * must be linked to the grant's user. The participant's name is fixed by
   * the run, it is recorded as the grant's run (never pinned as the grant's
   * approved agent), and later calls select it with `as`. On a gate-only
   * install it enrols at relaygate as cursor-cloud like any hosted
   * participant.
   */
  async function joinCursorRun(token: string, description?: string) {
    const cc = context.cursorCloud;
    if (!oauth || !cc || await hostedClient() !== "cursor-cloud") throw new RelayToolError(CURSOR_TOKEN_ELSEWHERE);
    const grantId = oauth.access.grantId;
    const store = postgresAttestationStore(database);
    let identity;
    try {
      identity = await verifyCursorIdentityToken(token, {
        audience: cc.audience, nonces: cursorIdentityNonces(cc.nonceSecret, grantId).accepted, jwks: cc.jwks,
        allowSelfHosted: cc.config.allowSelfHosted,
        // Spent ids share the attestation store; the prefix keeps them apart from desktop proofs.
        spend: (jti, expiresAt) => store.spend({ workspaceId, userId, toolUseId: `cursor-oidc:${jti}`, expiresAt }),
      });
    } catch (error) {
      if (!(error instanceof CursorIdentityError)) throw error;
      const guidance = await cursorIdentityGuidance();
      throw new RelayToolError(`The Cursor identity token was refused (${error.reason}). Mint a fresh one with: ${guidance!.mint_command}`);
    }
    const decision = await withOwnerLock(tx => cc.links.decide(tx,
      { userId, organizationId, workspaceId, email: context.principal.email ?? null }, identity, cc.config.trustedTeams));
    if (!decision.linked) {
      throw new RelayToolError("conflict" in decision
        ? "That Cursor account is linked to another person in this workspace. Connect Cursor with your own Agent Relay account."
        : `Before this Cursor cloud agent can join as you, open ${decision.confirmUrl} signed in to Agent Relay as yourself and confirm the Cursor account (the link works once, for 15 minutes). Then mint a fresh token and call join_relay again.`);
    }
    const name = cursorCloudParticipantName(identity.cloudAgentId);
    const ownerLabel = context.principal.name.trim() || context.principal.email || userId;
    const objective = description ?? `Cursor cloud agent run acting for ${ownerLabel}${identity.repoUrl ? ` on ${identity.repoUrl}` : ""}`;
    const recordRun = (tx: SqlExecutor) => tx.query(
      `INSERT INTO cursor_cloud_runs (grant_id, cloud_agent_id, workspace_id, user_id, agent_name)
       VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`, [grantId, identity.cloudAgentId, workspaceId, userId, name]);
    if (gate && await findParticipant(executor, workspaceId, ownerKey, organizationId, { name })) {
      // An earlier join of this run: renew it at relaygate before the lock, as every gated participant is. The
      // release fence is checked in the same transaction that records the run, so a run being released is never
      // re-recorded.
      await withOwnerLock(async (tx) => {
        if (await cursorRunRetiring(tx, name)) throw new RelayToolError(CURSOR_RUN_RETIRING);
        await recordRun(tx);
      });
      await refreshGated(name);
    }
    let prepared: GateEnrolment | undefined;
    for (;;) {
      const joined = await withOwnerLock(async (tx) => {
        if (await findParticipant(tx, workspaceId, ownerKey, organizationId, { name })) {
          if (await cursorRunRetiring(tx, name)) throw new RelayToolError(CURSOR_RUN_RETIRING);
          await recordRun(tx);
          let existing = (await participant(name, { executor: tx, run: true, allowRejected: !gate }))!;
          if (gate && prepared) existing = await settlePrepared(tx, existing, prepared);
          if (gate && !existing.tokenUsable) throw new RelayToolError(GATE_RENEW_FAILED);
          const token = existing.tokenUsable ? existing.token : await recoverToken(tx, existing);
          return { name, token, gated: existing.gated, alreadyJoined: true };
        }
        if (gate && !prepared) return NEEDS_GATE_ENROLMENT;
        const registered = await registerParticipant(tx, name, null, objective, { enrolled: prepared, run: true });
        await recordRun(tx);
        return { name: registered.name, token: registered.token, gated: Boolean(gate), alreadyJoined: false };
      });
      if (joined !== NEEDS_GATE_ENROLMENT) {
        await touchPresence(joined);
        await recordAudit(database, { organizationId, workspaceId, actor: { kind: "user", userId },
          action: "cursor_cloud.run.joined", target: `${name} grant=${grantId} subject=${identity.subject}` });
        return { joined: true, linked: "hosted" as const, name: joined.name, address: await addressFor(joined.name, true, directory(joined)),
          already_joined: joined.alreadyJoined, cursor_cloud_run: true,
          reply_guidance: `Pass as="${joined.name}" on every relay tool call from this cloud agent run. ${HOSTED_REPLY_GUIDANCE} with as="${joined.name}".` };
      }
      prepared = await prepareGateRegistration(name, objective);
    }
  }

  /** Callers hold the owner lock. */
  async function unlinkDesktop(tx: SqlExecutor): Promise<void> {
    if (sessionHash && !oauth) await unbindDesktopSession(tx, { workspaceId, userId, sessionHash });
  }

  /**
   * join_relay desktop_address: link this native MCP session to one of the
   * owner's synced Desktop identities, ported from Cloud's joinUncached. The
   * session's hosted participant, if any, is released once the link is
   * written; a failed release removes the link again.
   */
  async function joinDesktop(address: string, input: { name?: string; description?: string }) {
    if (input.name || input.description) throw new RelayToolError(DESKTOP_LINK_FIELDS);
    if (oauth) throw new RelayToolError(DESKTOP_LINK_OAUTH);
    if (!sessionHash) throw new RelayToolError(DESKTOP_LINK_NEEDS_SESSION);
    const linkedSession = sessionHash;
    const owned = { workspaceId, userId, sessionHash: linkedSession };
    // Gate-only installs: renew this session's participant at relaygate first, so linking releases it through relaygate.
    await refreshGated().catch(() => {});
    const joined = await withOwnerLock(async (tx) => {
      const row = await findDesktopIdentityByAddress(tx, workspaceId, userId, address);
      if (!row) {
        const at = address.lastIndexOf("@");
        const named = at > 0 ? await findDesktopIdentityByName(tx, workspaceId, userId, address.slice(0, at)) : null;
        throw new RelayToolError(named ? desktopAliasHint(named.address) : DESKTOP_NOT_SYNCED);
      }
      const identity = await verifiedDesktop(row);
      const current = await findDesktopIdentityBySession(tx, workspaceId, userId, linkedSession);
      const bind = async () => {
        try {
          await bindDesktopSession(tx, { ...owned, identityId: row.id });
        } catch (error) {
          if (error instanceof DesktopIdentityUnavailable) throw new RelayToolError(error.message);
          throw error;
        }
      };
      if (current?.id === row.id) {
        // A repeat join is fresh proof the tools are loaded: re-binding moves
        // linked_at past a desktop re-registration of this agent.
        await bind();
        return { identity, alreadyJoined: true };
      }
      const hosted = await participant(undefined, { allowGone: true, allowRejected: true, executor: tx });
      if (hosted && await hasActiveLaunches(tx, workspaceId, hosted.row.agentRemoteId)) throw new RelayToolError(ACTIVE_LAUNCHES);
      await bind();
      try {
        if (hosted) {
          await releaseRemote(hosted);
          await removeParticipant(tx, hosted.row.id);
        }
      } catch (error) {
        await unbindDesktopSession(tx, owned);
        throw error;
      }
      return { identity, alreadyJoined: false };
    });
    return { joined: true, linked: "desktop" as const, name: joined.identity.name, address: joined.identity.address,
      already_joined: joined.alreadyJoined, reply_guidance: DESKTOP_REPLY_GUIDANCE };
  }

  /** Whether `as` may fall back to the Factory hook: native, unmanaged calls naming an agent, with Factory on. */
  const factoryFallback = (as: string | undefined): as is string => Boolean(as && !managed && !oauth && context.factory);

  /**
   * The caller's own bound Factory agent named `as`, else the original
   * missing-participant error. Factory agents are hosted by the Factory
   * service's bindings, not participant rows, so `participant()` never finds
   * them; no participant row is created and nothing auto-joins.
   */
  async function factoryActor(as: string): Promise<Identity> {
    const found = await context.factory!.agentFor(workspaceId, userId, as);
    if (!found) throw new RelayToolError(NO_PARTICIPANT_MESSAGE);
    return { name: found.name, token: found.token, factory: true };
  }

  const capyFallback = (as: string | undefined): as is string => Boolean(
    as?.startsWith("capy-") && !managed && !oauth && context.capy);

  async function capyActor(as: string, grant = false): Promise<Identity | null> {
    if (grant && (!oauth || oauth.access.principal.userId!==userId ||
      oauth.access.principal.organizationId!==organizationId || oauth.access.principal.workspaceId!==workspaceId ||
      context.principal.organizationId!==organizationId || context.principal.workspaceId!==workspaceId)) {
      throw new RelayToolError(NO_PARTICIPANT_MESSAGE);
    }
    const found = grant ? await context.capyPermits!.agentForGrant(oauth!,as)
      : await context.capy!.agentFor(workspaceId, userId, as);
    if (!found && grant) return null; // No permit: retain the original persona/assertActor path.
    if (!found || found.name !== as || !found.token) throw new RelayToolError(NO_PARTICIPANT_MESSAGE);
    // agentFor resolves current custody. The recipient was resolved using this
    // request's admitted route: never mix it with a newly rebound workspace.
    const route = (await database.query<{ relaycast_workspace_id: string | null; relaycast_api_key_ciphertext: string | null }>(
      "SELECT relaycast_workspace_id,relaycast_api_key_ciphertext FROM workspaces WHERE id=$1 AND organization_id=$2",
      [workspaceId,organizationId])).rows[0];
    if (!route || !route.relaycast_api_key_ciphertext || route.relaycast_workspace_id !== relayWorkspaceId ||
        decryptSecret(route.relaycast_api_key_ciphertext,keyring) !== key) throw new RelayToolError(NO_PARTICIPANT_MESSAGE);
    return { name: found.name, token: found.token, capy: true, ...(grant ? { capyGrant:true } : {}) };
  }

  /** Native provider identities never become participant rows. Only send opts into Capy. */
  async function hostedActor<T>(as: string | undefined, fn: (identity: Identity) => Promise<T>,
    options: { factory?: boolean; capy?: boolean } = {}): Promise<T> {
    const viaCapy = options.capy === true && capyFallback(as);
    const viaFactory = !viaCapy && options.factory === true && factoryFallback(as);
    if (managed) {
      await managedActorOnly(as);
      return fn(await desktop());
    }
    if (options.capy && as?.startsWith("capy-") && oauth && context.capyPermits && as!==oauth.access.agentName) {
      const permitted = await capyActor(as,true);
      if (permitted) return fn(permitted);
    }
    if (!as) {
      const linkedIdentity = await linkedDesktop();
      if (linkedIdentity) return fn(linkedIdentity);
    }
    let hosted = await participant(as, { allowMissing: Boolean(oauth) || viaFactory || viaCapy });
    if (!hosted && viaCapy) return fn((await capyActor(as))!);
    if (!hosted && viaFactory) return fn(await factoryActor(as));
    if (!hosted) {
      await join({});
      hosted = await participant();
    }
    if (!hosted) throw new RelayToolError("Could not create a hosted participant for this MCP session. Call join_relay, then retry.");
    await touchPresence(hosted);
    return fn(hosted);
  }

  /**
   * The identity channel tools act as: the linked Desktop identity unless
   * `as` names a hosted participant, else a hosted participant chosen by
   * `as`, `hosted: true`, or the one this session already joined; auto-joined
   * only when `create`. Unchosen, `unlinked` decides: "error" throws, "none"
   * acts as nobody.
   */
  async function channelActor<T>(input: ChannelInput, create: boolean, fn: (identity: Identity) => Promise<T>,
    unlinked: "error" | "none" = "error"): Promise<T | null> {
    if (input.as_person && input.as) throw new RelayToolError("Choose either as_person or as, not both.");
    if (input.hosted && (input.as_person || input.as)) throw new RelayToolError("Choose one of hosted, as or as_person.");
    if (managed) {
      await managedActorOnly(input.as, Boolean(input.hosted || input.as_person));
      return fn(await desktop());
    }
    if (input.as_person) throw new RelayToolError(AS_PERSON_UNAVAILABLE);
    if (!input.as) {
      // As in Cloud, a link wins over hosted: true; linking released this session's hosted participant.
      const linkedIdentity = await linkedDesktop();
      if (linkedIdentity) return fn(linkedIdentity);
      const chosen = oauth || agent || input.hosted || (sessionHash && await findParticipant(executor, workspaceId, ownerKey, organizationId, { sessionHash }));
      if (!chosen) {
        if (unlinked === "none") return null;
        throw new RelayToolError(UNLINKED_CHANNEL_GUIDANCE);
      }
    }
    if (create) return hostedActor(input.as, fn);
    const hosted = await participant(input.as);
    if (!hosted) return null;
    await touchPresence(hosted);
    return fn(hosted);
  }

  async function membership(identity: Identity, channel: string) {
    return (await clientFor(identity).authenticatedAgent(identity.token)).channels.find(row => row.name === channel) ?? null;
  }

  function notSubscribed(channel: string): never {
    throw new RelayToolError(`You are not subscribed to #${channel}. Call subscribe_relay_channel first.`);
  }

  const cardOptions = { organization: context.workspace.name, relaycastUrl: context.relay.relaycastPublicUrl };

  type CardIdentity = { name: string; agentId: string; linked: "desktop" | "hosted"; kind: string; gated?: { token: string } };

  /** The identity set_relay_agent_card writes: the caller's own, chosen as relay_status reports it. */
  async function ownCardIdentity(as?: string): Promise<CardIdentity> {
    if (managed) {
      await managedActorOnly(as);
      const identity = await desktop();
      return { name: identity.name, agentId: identity.agentId, linked: "desktop", kind: DESKTOP_KIND };
    }
    const linkedIdentity = as ? null : await linkedDesktop();
    if (linkedIdentity) return { name: linkedIdentity.name, agentId: linkedIdentity.agentId, linked: "desktop", kind: DESKTOP_KIND };
    // `as` selects the caller's own participant, e.g. a Cursor cloud agent run (never someone else's).
    const hosted = await participant(as);
    if (!hosted) throw new RelayToolError(CARD_NEEDS_IDENTITY);
    return { name: hosted.name, agentId: hosted.row.agentRemoteId, linked: "hosted", kind: await hostedKind(),
      ...(hosted.gated ? { gated: { token: hosted.token } } : {}) };
  }

  /**
   * A hosted participant's card kind: an OAuth grant's connector kind
   * (grok-bot, chatgpt, muse) from its registered redirect URIs, else "hosted".
   */
  async function hostedKind(): Promise<string> {
    if (!oauth) return HOSTED_KIND;
    const client = (await executor.query<{ client_name: string | null; redirect_uris: string[] }>(
      "SELECT client_name, redirect_uris FROM mcp_oauth_clients WHERE client_id = $1", [oauth.access.clientId])).rows[0];
    const kind = client ? connectorKind({ clientName: client.client_name, redirectUris: client.redirect_uris ?? [] }) : "mcp";
    return kind === "mcp" ? HOSTED_KIND : kind;
  }

  /**
   * The owner's launcher participant, created on first use. Every launch is
   * sent as it, never as a person, a Desktop identity or another session's
   * participant, so leaving or relinking a chat cannot strand a launch. A
   * managed (Desktop provider) chat or a session linked to a Desktop identity
   * must still prove that identity, or it launches nothing.
   */
  async function withSpawnActor<T>(fn: (actor: SpawnActor) => Promise<T>): Promise<T> {
    // A workspace agent identity never launches agents (its tool fence refuses the launch tools too).
    if (agent || agentMissing) throw new RelayToolError(AGENT_IDENTITY_NO_LAUNCH);
    if (oauth) {
      // A gated participant's rg_ token can't invoke launches: relaygate does not proxy them.
      if (gate) throw new RelayToolError(GATE_OAUTH_LAUNCH_REFUSED);
      // The grant's approved participant is the launcher; never borrow the
      // person's native launcher or another client's identity.
      await withOwnerLock(async () => {
        if (!["owner", "admin"].includes(oauth.access.principal.role ?? "")) throw new RelayToolError(LAUNCH_ROLE_REFUSAL);
      });
      return hostedActor(undefined, async identity => {
        const current = await participant();
        if (!current || current.token !== identity.token) throw new RelayToolError(NO_PARTICIPANT_MESSAGE);
        if (!["owner", "admin"].includes(oauth.access.principal.role ?? "")) throw new RelayToolError(LAUNCH_ROLE_REFUSAL);
        return fn({ id: current.row.agentRemoteId, name: current.name, token: current.token, relaycastWorkspaceId: relayWorkspaceId });
      });
    }
    let requester: SpawnActor["requester"];
    if (managed) {
      const desktopIdentity = await desktop();
      requester = { agentId: desktopIdentity.agentId, name: desktopIdentity.name };
    } else if (sessionHash) {
      const linkedRow = await findDesktopIdentityBySession(executor, workspaceId, userId, sessionHash);
      if (linkedRow) {
        const desktopIdentity = await verifiedDesktop(linkedRow);
        requester = { agentId: desktopIdentity.agentId, name: desktopIdentity.name };
      }
    }
    const name = launcherName(userId);
    const actor = await withOwnerLock(async (tx) => {
      let hosted = await participant(name, { allowMissing: true, allowRejected: true, executor: tx, internal: true });
      if (!hosted) {
        await registerParticipant(tx, name, null, "Launches agents for its owner through MCP", { internal: true });
        hosted = await participant(name, { executor: tx, internal: true });
        if (!hosted) throw new RelayToolError("Could not create the launcher participant. Retry.");
      }
      const token = hosted.tokenUsable ? hosted.token : await recoverToken(tx, hosted);
      return { id: hosted.row.agentRemoteId, name: hosted.name, token, relaycastWorkspaceId: relayWorkspaceId,
        ...(requester ? { requester } : {}) };
    });
    return fn(actor);
  }

  /**
   * The directory a tool with no acting identity of its own reads (the
   * roster, a card): the workspace key, except on a gate-only install where a
   * caller that is not a Desktop identity reads through relaygate as its
   * hosted participant, and must have joined first.
   */
  async function callerDirectory(as?: string): Promise<Directory> {
    if (managed) await managedActorOnly(as);
    if (!gate || managed || (!as && await linkedDesktop())) return directory();
    const hosted = await participant(as);
    if (!hosted) throw new RelayToolError(GATE_JOIN_FIRST);
    return directory(hosted);
  }

  /** read_relay_conversation once the reading identity and the peer's name are known. */
  async function readConversation(hosted: Identity, peerName: string, input: { before?: string; limit: number }) {
    const via = clientFor(hosted);
    // relaygate does not proxy heartbeats; Desktop keeps its own presence.
    if (via === client) await touchPresence(hosted);
    const conv = await conversation(hosted.token, hosted.name, peerName, via);
    if (!conv) return { you: hosted.name, conversation_id: null, messages: [], earlier: null };
    const page = await via.listMessages(hosted.token, conv.id, { before: input.before, limit: input.limit });
    const messages = [];
    // The DM listing omits thread_id; enrich only authorized ids, five at a time.
    for (let index = 0; index < page.messages.length; index += 5) {
      messages.push(...await Promise.all(page.messages.slice(index, index + 5).map(async message => ({
        message_id: message.id, sender: message.sender, text: message.text, created_at: message.createdAt,
        thread_id: await via.getMessageThreadId(hosted.token, message.id), mine: message.sender === hosted.name,
      }))));
    }
    return { you: hosted.name, conversation_id: conv.id, messages,
      earlier: page.hasEarlier ? page.messages[0]?.id ?? null : null };
  }

  return {
    withSpawnActor,

    async list(input: { status: "live" | "all" | "offline"; person?: string; query?: string; include_stale?: boolean; limit?: number; as?: string }) {
      const query = input.query?.toLowerCase();
      const person = input.person?.toLowerCase();
      const agents = await roster(input.status, await context.members(), input.include_stale, await callerDirectory(input.as));
      const matching = agents.filter(agent =>
        (!person || (person === "me" ? agent.is_mine
          : agent.owner?.user_id.toLowerCase() === person || agent.owner?.name.toLowerCase().includes(person))) &&
        (!query || [agent.name, agent.address, agent.description, agent.where].some(value => value?.toLowerCase().includes(query))));
      const listed = matching.slice(0, input.limit ?? 100);
      return { workspace_id: workspaceId, agents: listed, total_matching: matching.length,
        truncated: matching.length > listed.length };
    },

    join,

    /** get_relay_agent_card: any listed agent in this workspace, by name or exact machine address. Read-only. */
    async getCard(input: { agent: string; as?: string }) {
      const agent = await explicitAgent(input.agent.trim(), await callerDirectory(input.as));
      if (!agent || agent.status === "released" || !isListedRelayAgent(agent)) throw new RelayToolError(UNKNOWN_CARD_AGENT);
      const owners = await Promise.resolve().then(async () =>
        loadRelayAgentOwners(database, workspaceId, relayWorkspaceId, [agent], await context.members(), Boolean(gate)))
        .catch(error => { ownerEnrichmentFailed("get_relay_agent_card", error); return undefined; });
      return buildAgentCard(agent, cardOptions, owners?.get(agent.id));
    },

    /**
     * set_relay_agent_card: the caller's own identity only, never a target it
     * names. A managed chat's verified desktop identity, else this session's
     * desktop link, else its joined hosted participant (an OAuth grant's
     * approved agent). Nothing is created: a session with no identity is told
     * to join first. Only `skills`, `card`, `kind` and `owner_name` are sent;
     * Relaycast merges them into the stored metadata, so every other key is
     * preserved.
     */
    async setCard(input: SetCardInput & { as?: string }) {
      const own = await ownCardIdentity(input.as);
      if (own.gated) {
        // A gated participant writes its own card through relaygate (which merges it upstream).
        const current = await gate!.authenticatedAgent(own.gated.token);
        if (current.id !== own.agentId || current.status === "released") throw new RelayToolError(CARD_IDENTITY_CHANGED);
        await gate!.mergeOwnAgentMetadata(own.gated.token, {
          ...cardMetadata(input, current.metadata, new Date()), kind: own.kind, ...(ownerName ? { owner_name: ownerName } : {}) });
        const updated = await gate!.authenticatedAgent(own.gated.token);
        if (updated.id !== own.agentId) throw new RelayToolError(CARD_IDENTITY_CHANGED);
        return { updated: true, linked: own.linked, name: updated.name,
          card: buildAgentCard(updated, cardOptions, agent ? undefined : context.principal) };
      }
      const current = await client.getRosterAgent(key, own.name);
      if (!current || current.id !== own.agentId || current.status === "released") throw new RelayToolError(CARD_IDENTITY_CHANGED);
      // Only these keys are sent; Relaycast merges them, keeping every other key.
      // Bound to the checked id: a name re-registered since is never written.
      const updated = await client.mergeAgentMetadata(key, own.name, {
        ...cardMetadata(input, current.metadata, new Date()), kind: own.kind, ...(ownerName ? { owner_name: ownerName } : {}) }, own.agentId)
        .catch((error: unknown) => {
          if (error instanceof RelaycastCallError && error.status === 409) throw new RelayToolError(CARD_IDENTITY_CHANGED);
          throw error;
        });
      if (updated.id !== own.agentId) throw new RelayToolError(CARD_IDENTITY_CHANGED);
      return { updated: true, linked: own.linked, name: updated.name,
        card: buildAgentCard(updated, cardOptions, agent ? undefined : context.principal) };
    },

    async leave(as?: string) {
      if (managed) {
        await managedActorOnly(as);
        await desktop();
        return { joined: false, desktop_agent_unchanged: true, native_chat_identity_retained: true };
      }
      // A run this connection already left (or never had): leaving again is a no-op, not a run-identity refusal.
      if (oauth && as && CURSOR_RUN_NAME.test(as) && context.cursorCloud && !await ownRun(as)) return { joined: false, already_left: true };
      // Gate-only installs: renew at relaygate first so the release goes through it; a refusal still lets it leave.
      await refreshGated(as).catch(() => {});
      return withOwnerLock(async (tx) => {
        if (!as && sessionHash && !oauth && await findDesktopIdentityBySession(tx, workspaceId, userId, sessionHash)) {
          // Unlinking leaves the Desktop's own agent running.
          await unlinkDesktop(tx);
          return { joined: false, linked: null, already_left: false, desktop_agent_unchanged: true };
        }
        // Release uses the workspace key (or, gated, a token re-enrolled at relaygate), so a rejected token can still leave.
        const hosted = await participant(as, { allowGone: true, allowRejected: true, executor: tx });
        if (!hosted) return { joined: false, already_left: true };
        // A Cursor cloud agent run may be shared: other connections' runs, or a native session bound to it. Leaving then
        // detaches only this caller (its run record, or its session binding); the last user releases the participant.
        if (CURSOR_RUN_NAME.test(hosted.name)) {
          const mine = oauth ? oauth.access.grantId : null;
          const others = await tx.query(`SELECT 1 FROM cursor_cloud_runs r JOIN mcp_oauth_grants g ON g.id = r.grant_id
            WHERE r.workspace_id = $1 AND r.user_id = $2 AND r.agent_name = $3 AND g.revoked_at IS NULL
              AND ($4::uuid IS NULL OR r.grant_id <> $4::uuid) LIMIT 1`, [workspaceId, userId, hosted.name, mine]);
          const boundElsewhere = oauth !== undefined && hosted.row.sessionHash !== null;
          if (others.rows.length || boundElsewhere) {
            if (mine) await tx.query("DELETE FROM cursor_cloud_runs WHERE grant_id = $1 AND agent_name = $2", [mine, hosted.name]);
            else await tx.query("UPDATE hosted_relay_participants SET session_hash = NULL, updated_at = now() WHERE id = $1", [hosted.row.id]);
            return { joined: false, already_left: false, kept_for_other_connections: true };
          }
        }
        if (oauth && hosted.row.sessionHash) {
          throw new RelayToolError("A native MCP session still uses this agent. Leave from that session instead.");
        }
        if (oauth && await oauth.claimedByOther(tx, { agentName: hosted.name, agentRemoteId: hosted.row.agentRemoteId })) {
          throw new RelayToolError("Another active connection still uses this agent. Disconnect it before leaving.");
        }
        if (await hasActiveLaunches(tx, workspaceId, hosted.row.agentRemoteId)) throw new RelayToolError(ACTIVE_LAUNCHES);
        await releaseRemote(hosted);
        await removeParticipant(tx, hosted.row.id);
        // A Cursor cloud agent run that leaves is no longer any grant's run.
        if (CURSOR_RUN_NAME.test(hosted.name)) {
          await tx.query("DELETE FROM cursor_cloud_runs WHERE workspace_id = $1 AND user_id = $2 AND agent_name = $3", [workspaceId, userId, hosted.name]);
        }
        return { joined: false, already_left: false };
      });
    },

    async status(as?: string) {
      if (managed) {
        await managedActorOnly(as);
        const identity = await desktop();
        return { joined: true, linked: "desktop" as const, name: identity.name, address: identity.address,
          unread_count: null, guidance: DESKTOP_REPLY_GUIDANCE };
      }
      const linkedIdentity = as ? null : await linkedDesktop();
      if (linkedIdentity) {
        return { joined: true, linked: "desktop" as const, name: linkedIdentity.name, address: linkedIdentity.address,
          unread_count: null, guidance: DESKTOP_REPLY_GUIDANCE };
      }
      // A Cursor cloud agent learns here how to join as its own run.
      const cursor = await cursorIdentityGuidance();
      if (cursor && !as && await runRequired()) {
        return { joined: false, name: null, address: null, unread_count: 0, cursor_identity: cursor, guidance: cursor.next_step };
      }
      const hosted = await participant(as);
      if (!hosted) return { joined: false, name: null, address: null, unread_count: 0,
        ...(cursor ? { cursor_identity: cursor } : {}),
        guidance: "Send a message with send_relay_message to auto-join this MCP session, or call join_relay first." };
      await touchPresence(hosted);
      const dir = directory(hosted);
      const [agents, inbox] = await Promise.all([
        withinRelayRead(
          signal => dir.via.findAgentsByNames(dir.credential, [hosted.name], { signal }),
          RELAY_STATUS_LOOKUP_TIMEOUT_MS,
        ).catch(error => { relayStatusAddressEnrichmentFailed(error); return []; }),
        clientFor(hosted).readHostedInbox(hosted.token),
      ]);
      const address = agents.find(agent => agent.name === hosted.name && isListedRelayAgent(agent))?.address ?? null;
      return { joined: true, linked: "hosted" as const, name: hosted.name, address,
        unread_count: inbox.length, unread_count_is_lower_bound: inbox.length === 100,
        ...(cursor && !await ownRun(as) ? { cursor_identity: cursor } : {}) };
    },

    async inbox(as: string | undefined, acknowledge: string[]) {
      if (managed) {
        await managedActorOnly(as);
        const identity = await desktop();
        return { linked: "desktop" as const, name: identity.name, address: identity.address, messages: [],
          polling_needed: false, guidance: DESKTOP_INBOX_GUIDANCE };
      }
      const linkedIdentity = as ? null : await linkedDesktop();
      if (linkedIdentity) {
        return { linked: "desktop" as const, name: linkedIdentity.name, address: linkedIdentity.address, messages: [],
          polling_needed: false, guidance: DESKTOP_INBOX_GUIDANCE };
      }
      const hosted = await participant(as);
      if (!hosted) throw new RelayToolError("No hosted participant is bound to this MCP session. Send a message with send_relay_message to auto-join, or call join_relay first.");
      await touchPresence(hosted);
      // Required inbox and conversation reads finish before acknowledgement.
      // Sender-address enrichment is optional and bounded: failure is logged
      // and returned as a null address without failing the delivery read.
      const via = clientFor(hosted);
      const dir = directory(hosted);
      const [messages, conversations] = await Promise.all([
        via.readHostedInbox(hosted.token), via.listConversations(hosted.token),
      ]);
      // Sender addresses come from one bounded lookup of the senders' names.
      const senders = [...new Set(messages.flatMap(message => message.sender ? [message.sender] : []))];
      const agents = senders.length ? (await dir.via.findAgentsByNames(dir.credential, senders, {
        signal: AbortSignal.timeout(INBOX_SENDER_LOOKUP_TIMEOUT_MS),
      }).catch(error => { inboxSenderEnrichmentFailed(error); return []; })).filter(isListedRelayAgent) : [];
      const addresses = new Map(agents.map(agent => [agent.name, agent.address]));
      const channelNames = new Map<string, string>();
      if (messages.some(isChannelDelivery)) {
        for (const row of (await via.authenticatedAgent(hosted.token)).channels) channelNames.set(row.id, row.name);
        if (messages.some(message => isChannelDelivery(message) && message.channel_id && !channelNames.has(message.channel_id))) {
          for (const row of await dir.via.listChannels(dir.credential)) channelNames.set(row.id, row.name);
        }
      }
      const enriched = messages.map(message => {
        const base = { ...message, sender_address: message.sender ? addresses.get(message.sender) ?? null : null };
        if (isChannelDelivery(message)) {
          const channel = message.channel_id ? channelNames.get(message.channel_id) ?? null : null;
          const root = message.thread_id ?? message.message_id;
          return { ...base, kind: "channel" as const, channel, conversation_id: null,
            reply_hint: channel
              ? `Reply in the channel with ${channelReplyHint(channel, root)}; use send_relay_message only for a private reply.`
              : `Reply in the channel with post_relay_channel thread_id=${root}; use send_relay_message only for a private reply.` };
        }
        return { ...base, kind: "dm" as const,
          conversation_id: message.conversation_id ?? conversations.find(item => item.participants.length === 2 &&
            item.participants.includes(hosted.name) && Boolean(message.sender && item.participants.includes(message.sender)))?.id ?? null };
      });
      // Relaycast ack is idempotent for the owner (engine/delivery.ts ackDelivery
      // returns changed:false for an already-acked delivery at ac38905); 404 means
      // absent or not owned by this participant and stays an error. A retry of a
      // partly failed batch therefore resumes cleanly.
      const requested = [...new Set(acknowledge)];
      for (const id of requested) await via.acknowledgeDelivery(hosted.token, id);
      const acknowledged = new Set(requested);
      return { name: hosted.name, messages: enriched.filter(message => !acknowledged.has(message.delivery_id)),
        acknowledged: requested, has_more: messages.length === 100 };
    },

    async send(input: { to: string; text: string; reply_to?: string; as?: string; as_person?: boolean; idempotency_key?: string },
      serverIdempotencyKey: string = randomUUID()) {
      if (input.as_person && input.as) throw new RelayToolError("Choose either as_person or as, not both.");
      await managedActorOnly(input.as, Boolean(input.as_person));
      if (input.as_person) throw new RelayToolError(AS_PERSON_UNAVAILABLE);
      // The recipient is validated before any identity is joined, so an
      // unknown recipient never leaves a participant behind. On a gate-only
      // install it is resolved through relaygate as the sending identity, so
      // it can only be an agent relaygate lets that identity see.
      const people = await context.members();
      const early = gate ? null : await recipient(input.to, people);
      return hostedActor(input.as, async (identity) => {
        const peer = early ?? await recipient(input.to, people, directory(identity));
        if (identity.name === peer.name) throw new RelayToolError("Choose another agent as the recipient.");
        const responseIdempotencyKey = input.idempotency_key ?? serverIdempotencyKey;
        const idempotencyKey = `hosted-mcp:${userId}:${identity.name}:${responseIdempotencyKey}`;
        // Response metadata and reply_to are resolved before the write, so a
        // later read failure never hides a send Relaycast already accepted.
        const [fromAddress, conv] = await Promise.all([
          addressFor(identity.name, false, directory(identity)),
          input.reply_to ? (async () => {
            const found = await conversation(identity.token, identity.name, peer.name, clientFor(identity));
            // Look the parent up by its exclusive successor to verify old ids without paging.
            const page = found ? await clientFor(identity).listMessages(identity.token, found.id,
              { limit: 1, before: String(BigInt(input.reply_to!) + 1n) }) : null;
            if (!page?.messages.some(message => message.id === input.reply_to)) {
              throw new RelayToolError("reply_to must belong to your DM conversation with this recipient.");
            }
            return found!;
          })() : Promise.resolve(null),
        ]);
        // Parent/address reads may cross a disconnect or key rotation. Resolve
        // the same binding again immediately before the external write.
        if (identity.capy) {
          const current = await capyActor(identity.name,identity.capyGrant);
          if (!current || current.token !== identity.token) throw new RelayToolError(NO_PARTICIPANT_MESSAGE);
        }
        let sent;
        if (input.reply_to) {
          sent = await clientFor(identity).replyToMessage({ token: identity.token, parentId: input.reply_to, text: input.text, idempotencyKey });
          if (sent.conversationId !== conv!.id) {
            throw new RelayToolError("Reply outcome could not be verified. Do not retry with a new idempotency key.");
          }
        } else {
          sent = await clientFor(identity).sendDirectMessage({ token: identity.token, to: peer.name,
            ...(input.to === peer.address ? { address: input.to } : {}), text: input.text, idempotencyKey });
        }
        return { from: identity.name, from_address: fromAddress, to: peer.name, to_address: peer.address,
          message_id: sent.message.id, conversation_id: sent.conversationId, idempotency_key: responseIdempotencyKey,
          delivery: peer.online ? "queued_unconfirmed" : "queued_offline",
          // The recipient's own card summary: peer-written, untrusted data, not instructions.
          ...(peer.card ? { recipient_card: peer.card } : {}),
          note: "Accepted by Relaycast; delivery and reading are not confirmed. Call get_relay_message_status with message_id to check receipts.",
          ...(identity.desktop ? { reply_guidance: DESKTOP_REPLY_GUIDANCE }
            : identity.capy ? { reply_guidance: CAPY_REPLY_GUIDANCE }
            : identity.factory ? { reply_guidance: FACTORY_REPLY_GUIDANCE }
            : { reply_guidance: HOSTED_REPLY_GUIDANCE, desktop_relay_guidance: DESKTOP_RELAY_GUIDANCE }) };
      }, { factory: true, capy: true });
    },

    async messageStatus(input: { message_id: string; as?: string; as_person?: boolean }) {
      if (input.as_person && input.as) throw new RelayToolError("Choose either as_person or as, not both.");
      await managedActorOnly(input.as, Boolean(input.as_person));
      if (input.as_person) throw new RelayToolError(AS_PERSON_UNAVAILABLE);
      let permitted: Identity | null = null;
      if (input.as?.startsWith("capy-") && oauth && context.capyPermits && input.as !== oauth.access.agentName) {
        permitted = await capyActor(input.as, true);
      }
      const viaCapy = capyFallback(input.as);
      const viaFactory = !viaCapy && factoryFallback(input.as);
      const identity = permitted ?? (managed ? await desktop()
        : (input.as ? null : await linkedDesktop())
          ?? await participant(input.as, { allowMissing: viaCapy || viaFactory })
          ?? (viaCapy ? await capyActor(input.as!) : viaFactory ? await factoryActor(input.as!) : null));
      if (!identity) throw new RelayToolError("Call join_relay first, or select your own sending participant with as.");
      const deliveries = await clientFor(identity).getMessageDeliveries(identity.token, input.message_id);
      return { message_id: input.message_id, you: identity.name, confirmation: deliveries === null ? "unavailable" : "available",
        deliveries: deliveries ?? [], note: deliveries === null
          ? "Delivery is unconfirmed: this engine does not expose receipts, or this message is not visible as your own outgoing message. Do not resend solely because confirmation is unavailable."
          : RECEIPT_GUIDANCE };
    },

    async read(input: { agent: string; as?: string; before?: string; limit: number }) {
      // Names resolve within the actor's own DMs; only a machine address needs a lookup.
      const peerName = input.agent.includes("@") && !gate ? (await explicitAgent(input.agent))?.name : input.agent;
      if (!peerName) throw new RelayToolError("Unknown or stale machine address in this workspace.");
      await managedActorOnly(input.as);
      const hosted: Identity | null = managed ? await desktop()
        : (input.as ? null : await linkedDesktop())
          ?? await participant(input.as, { allowMissing: factoryFallback(input.as) })
          ?? (factoryFallback(input.as) ? await factoryActor(input.as) : null);
      if (!hosted) return { you: null, conversation_id: null, messages: [], earlier: null };
      // Gate-only installs resolve a machine address as the reading identity, through relaygate when gated.
      if (gate && input.agent.includes("@")) {
        const resolved = (await explicitAgent(input.agent, directory(hosted)))?.name;
        if (!resolved) throw new RelayToolError("Unknown or stale machine address in this workspace.");
        return readConversation(hosted, resolved, input);
      }
      return readConversation(hosted, peerName, input);
    },

    async listChannels(input: ChannelInput) {
      let acted = false;
      let actor: Identity | null = null;
      const mine = await channelActor(input, false, async (identity) => {
        acted = true;
        actor = identity;
        return { you: identity.name, linked: linkedKind(identity),
          ids: new Set((await clientFor(identity).authenticatedAgent(identity.token)).channels.map(row => row.id)) };
      }, "none");
      // Gate-only installs: a gated participant lists through relaygate; nobody lists without an identity.
      if (gate && !actor) throw new RelayToolError(GATE_JOIN_FIRST);
      const dir = directory(actor);
      const channels = await dir.via.listChannels(dir.credential);
      const unlinked = !managed && !acted && !input.as && !input.hosted &&
        !(sessionHash && await findParticipant(executor, workspaceId, ownerKey, organizationId, { sessionHash }));
      return { you: mine?.you ?? null, linked: mine?.linked ?? null,
        ...(unlinked ? { note: UNLINKED_CHANNEL_GUIDANCE } : {}),
        channels: channels.filter(channel => !channel.archived && !channel.name.startsWith(RESERVED_CHANNEL_PREFIX)).map(channel => ({
          name: channel.name, topic: channel.topic, member_count: channel.memberCount, subscribed: mine?.ids.has(channel.id) ?? false })),
        guidance: RELAY_COORDINATION_GUIDANCE };
    },

    async subscribeChannel(input: ChannelInput & { channel: string; create?: boolean }) {
      const channel = normalizeChannelName(input.channel);
      return (await channelActor(input, true, async (identity) => {
        let created = false;
        let alreadySubscribed = false;
        try {
          alreadySubscribed = (await clientFor(identity).joinChannel(identity.token, channel)).alreadyMember;
        } catch (error) {
          if (!(error instanceof RelaycastCallError) || error.status !== 404) throw error;
          if (!input.create) throw new RelayToolError(`No channel #${channel} exists. Use list_relay_channels, or pass create: true to start it.`);
          try {
            // The creator becomes the channel's owner, which is membership.
            await clientFor(identity).createChannel(identity.token, channel);
            created = true;
          } catch (createError) {
            // Someone created it first: join theirs.
            if (!(createError instanceof RelaycastCallError) || createError.status !== 409) throw createError;
            alreadySubscribed = (await clientFor(identity).joinChannel(identity.token, channel)).alreadyMember;
          }
        }
        return { subscribed: true, channel, you: identity.name, linked: linkedKind(identity), created,
          already_subscribed: alreadySubscribed, delivery: channelDelivery(identity, channel), reply_guidance: CHANNEL_REPLY_GUIDANCE };
      }))!;
    },

    async unsubscribeChannel(input: ChannelInput & { channel: string }) {
      const channel = normalizeChannelName(input.channel);
      return await channelActor(input, false, async (identity) => {
        if (!await membership(identity, channel)) return { subscribed: false, channel, you: identity.name, already_unsubscribed: true };
        await clientFor(identity).leaveChannel(identity.token, channel);
        return { subscribed: false, channel, you: identity.name, already_unsubscribed: false };
      }) ?? { subscribed: false, channel, you: null, already_unsubscribed: true };
    },

    async postChannel(input: ChannelInput & { channel: string; text: string; thread_id?: string; idempotency_key?: string },
      serverIdempotencyKey: string = randomUUID()) {
      const channel = normalizeChannelName(input.channel);
      // Posting requires a subscription, so no identity is created here.
      return (await channelActor(input, false, async (identity) => {
        const member = await membership(identity, channel);
        if (!member) notSubscribed(channel);
        const responseIdempotencyKey = input.idempotency_key ?? serverIdempotencyKey;
        const idempotencyKey = `hosted-mcp-channel:${userId}:${identity.name}:${responseIdempotencyKey}`;
        let messageId: string;
        let threadId: string | null = null;
        if (input.thread_id) {
          const parent = await clientFor(identity).getMessage(identity.token, input.thread_id);
          if (!parent || parent.channelId !== member.id) throw new RelayToolError(`thread_id must be a message in #${channel}. Use read_relay_channel.`);
          const reply = await clientFor(identity).replyInChannelThread({ token: identity.token, parentId: input.thread_id, text: input.text, idempotencyKey });
          if (reply.channelId !== member.id) throw new RelayToolError("Reply outcome could not be verified. Do not retry with a new idempotency key.");
          messageId = reply.id;
          threadId = reply.threadId;
        } else {
          messageId = (await clientFor(identity).postChannelMessage({ token: identity.token, channel, text: input.text, idempotencyKey })).id;
        }
        return { from: identity.name, channel, linked: linkedKind(identity), message_id: messageId, thread_id: threadId,
          idempotency_key: responseIdempotencyKey,
          note: "Accepted by Relaycast and delivered to the channel's subscribers; reading is not confirmed.",
          reply_guidance: `${channelDelivery(identity, channel)} Continue this thread with ${channelReplyHint(channel, threadId ?? messageId)}.` };
      })) ?? notSubscribed(channel);
    },

    async readChannel(input: ChannelInput & { channel: string; before?: string; limit: number }) {
      const channel = normalizeChannelName(input.channel);
      return (await channelActor(input, false, async (identity) => {
        // History is read with the workspace key (a gated participant: through relaygate, which checks read
        // itself), so membership is checked here.
        if (!await membership(identity, channel)) notSubscribed(channel);
        const dir = directory(identity);
        const page = await dir.via.listChannelMessages(dir.credential, channel, { before: input.before, limit: input.limit });
        return { you: identity.name, channel,
          messages: page.messages.map(message => ({ message_id: message.id, sender: message.sender, text: message.text,
            created_at: message.createdAt, thread_id: message.threadId, reply_count: message.replyCount, mine: message.sender === identity.name })),
          earlier: page.hasEarlier ? page.messages[0]?.id ?? null : null,
          reply_guidance: CHANNEL_REPLY_GUIDANCE };
      })) ?? notSubscribed(channel);
    },
  };
}

/** Native calls retain their flow; OAuth tools recheck the exact live bearer before acting. */
export function relayService(context: McpContext) {
  const service = createRelayService(context);
  if (!context.oauth) return service;
  const fenced = {} as typeof service;
  for (const name of Object.keys(service) as Array<keyof typeof service>) {
    const call = async (...args: unknown[]) => {
      try {
        await context.relay.database.transaction(tx=>context.oauth!.lock(tx));
        // Join/pin commits before sending. A lost send response therefore
        // retains the identity for idempotent retry and revocation cleanup.
        const method = service[name] as (...values: unknown[]) => Promise<unknown>;
        return await method(...args);
      } catch (error) {
        if (error instanceof McpOAuthAccessRefused || error instanceof McpOAuthActorRefused || error instanceof McpOAuthAgentRetiring) {
          throw new RelayToolError(error.message);
        }
        throw error;
      }
    };
    Object.defineProperty(fenced,name,{value:call,enumerable:true});
  }
  return fenced;
}
