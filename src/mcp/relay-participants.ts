import { createHash, randomUUID } from "node:crypto";
import { decryptSecret, encryptSecret } from "../crypto.js";
import type { SqlExecutor } from "../database.js";
import { RelaycastCallError, type RosterAgent } from "../messaging/relaycast.js";
import { DesktopIdentityUnavailable, DESKTOP_IDENTITY_MESSAGES, linkedDesktopIdentity } from "../messaging/desktop-identities.js";
import type { McpContext, McpMember } from "./context.js";
import { isListedRelayAgent, rosterAgent } from "./team-activity.js";
import { McpOAuthAccessRefused, McpOAuthActorRefused } from "./oauth/admission.js";
import { MCP_OAUTH_RETIRING_MESSAGE, McpOAuthAgentRetiring, retiringIdentity } from "./oauth/retirement.js";

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
 * Managed (Desktop provider) calls: a request admitted with a `mcp:desktop`
 * provider credential acts only as the Desktop identity synced for its
 * verified native chat (a Copilot chat named by a verified attestation). No
 * verified chat, or no matching synced identity, means the actor tools are
 * unavailable; they never fall back to a hosted participant.
 * Other callers act as hosted participants; their native session context is
 * not an identity here. Person sends (`as_person`), OAuth grants, events
 * inboxes, launches and Capy are not part of self-host.
 */

export class RelayToolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RelayToolError";
  }
}

export const ownerHash = (id: string) => createHash("sha256").update(id).digest("hex");

export const HOSTED_SOURCE = "cloud-hosted-mcp";
export const DESKTOP_ADDRESS_UNAVAILABLE =
  "Desktop-linked identity is not yet available on this self-hosted site; call join_relay with name instead.";
const AS_PERSON_UNAVAILABLE =
  "as_person is not available on this self-hosted site. Omit it to act as this MCP session's hosted participant.";

export const RELAY_COORDINATION_GUIDANCE = "DM a specific agent by default. Use channels only to coordinate a larger swarm or broadcast to many agents, and subscribe only to channels you need. Reply to a channel post in that channel with post_relay_channel (thread_id for its thread), not by DM, unless the reply is private. At task start, check list_relay_agents and DM peers whose work your task affects, without waiting to be asked.";
export const HOSTED_REPLY_GUIDANCE = "replies arrive in check_relay_inbox; poll it";
export const DESKTOP_REPLY_GUIDANCE = "replies will be injected into your session by Agent Relay Desktop";
export const MANAGED_AS_REFUSED = "This managed chat can only act as its verified desktop identity.";
export const MANAGED_JOIN_REFUSED = "This chat can only use its verified desktop identity.";
/** Cloud's DESKTOP_RELAY_GUIDANCE, adapted: self-host cannot link a desktop identity yet. */
export const DESKTOP_RELAY_GUIDANCE = "This self-hosted site does not link Agent Relay Desktop identities yet: this MCP session messages as its hosted participant, and replies arrive in check_relay_inbox.";
/** Cloud's UNLINKED_CHANNEL_GUIDANCE without the desktop link, which self-host does not offer. */
export const UNLINKED_CHANNEL_GUIDANCE = "This MCP session has not joined Agent Relay, so it has no identity for channels. To use this MCP session's hosted inbox (posts arrive in check_relay_inbox; poll it), pass hosted: true, or call join_relay first.";
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
// Store: selfhost_hosted_relay_participants (migration 0012).

export type ParticipantRow = {
  id: string;
  workspaceId: string;
  userId: string;
  relayWorkspaceId: string;
  sessionHash: string | null;
  agentName: string;
  agentRemoteId: string;
  tokenCiphertext: string;
};

type Selector = { name: string } | { sessionHash: string } | { agentRemoteId: string };

const COLUMNS = `p.id, p.workspace_id, p.user_id, p.relaycast_workspace_id, p.session_hash, p.agent_name, p.agent_remote_id, p.token_ciphertext`;

function rowFrom(row: Record<string, unknown>): ParticipantRow {
  return {
    id: String(row.id),
    workspaceId: String(row.workspace_id),
    userId: String(row.user_id),
    relayWorkspaceId: String(row.relaycast_workspace_id),
    sessionHash: typeof row.session_hash === "string" ? row.session_hash : null,
    agentName: String(row.agent_name),
    agentRemoteId: String(row.agent_remote_id),
    tokenCiphertext: String(row.token_ciphertext),
  };
}

/** Only the owner's own rows are ever visible: workspace and user are always in the predicate. */
async function findParticipant(executor: SqlExecutor, workspaceId: string, userId: string, organizationId: string, selector: Selector) {
  const [column, value] = "name" in selector ? ["agent_name", selector.name]
    : "agentRemoteId" in selector ? ["agent_remote_id", selector.agentRemoteId] : ["session_hash", selector.sessionHash];
  const result = await executor.query(
    `SELECT ${COLUMNS} FROM selfhost_hosted_relay_participants p
      JOIN selfhost_workspaces w ON w.id=p.workspace_id
      WHERE p.workspace_id = $1 AND p.user_id = $2 AND w.organization_id=$3 AND p.${column} = $4`,
    [workspaceId, userId, organizationId, value],
  );
  return result.rows[0] ? rowFrom(result.rows[0]) : null;
}

async function insertParticipant(executor: SqlExecutor, row: Omit<ParticipantRow, "id">): Promise<void> {
  await executor.query(
    `INSERT INTO selfhost_hosted_relay_participants
       (id, workspace_id, user_id, relaycast_workspace_id, session_hash, agent_name, agent_remote_id, token_ciphertext)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [randomUUID(), row.workspaceId, row.userId, row.relayWorkspaceId, row.sessionHash, row.agentName, row.agentRemoteId, row.tokenCiphertext],
  );
}

async function updateParticipant(executor: SqlExecutor, id: string,
  fields: { sessionHash?: string; agentName?: string; tokenCiphertext?: string }) {
  await executor.query(
    `UPDATE selfhost_hosted_relay_participants
        SET session_hash = COALESCE($2, session_hash), agent_name = COALESCE($3, agent_name),
            token_ciphertext = COALESCE($4, token_ciphertext), updated_at = now()
      WHERE id = $1`,
    [id, fields.sessionHash ?? null, fields.agentName ?? null, fields.tokenCiphertext ?? null],
  );
}

async function removeParticipant(executor: SqlExecutor, id: string): Promise<void> {
  await executor.query("DELETE FROM selfhost_hosted_relay_participants WHERE id = $1", [id]);
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

type Identity = { name: string; token: string };
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
};
const rejectedToken = (name: string) => new RelayToolError(
  `The relay token for participant ${name} was rejected by Relaycast. Call join_relay with name=${name} to recover it, or leave_relay to remove it.`);
type ChannelInput = { as?: string; as_person?: boolean; hosted?: boolean };

function createRelayService(context: McpContext) {
  const { database, keyring, client, sessionId } = context.relay;
  const workspaceId = context.workspace.id;
  const organizationId = context.workspace.organizationId;
  const executor = database;
  const oauth = context.oauth;
  const userId = context.principal.userId;
  const key = context.workspace.relaycastApiKey;
  const relayWorkspaceId = context.workspace.relaycastWorkspaceId;
  const sessionHash = !oauth && sessionId ? ownerHash(sessionId) : null;
  const owner = ownerHash(userId);
  const desktopCall = context.desktopCall;
  /** A Desktop-provider credential: only the verified native chat's identity may act. */
  const managed = desktopCall.provider !== undefined;
  const linkedKind = managed ? "desktop" as const : "hosted" as const;
  const channelDelivery = managed ? desktopChannelDelivery : hostedChannelDelivery;
  let linked: Promise<{ name: string; address: string; token: string }> | undefined;

  /** The synced Desktop identity of this call's verified native chat; throws when there is none. */
  function desktop() {
    linked ??= (async () => {
      if (!desktopCall.nativeSession) throw new RelayToolError(DESKTOP_IDENTITY_MESSAGES.unverified);
      try {
        return await linkedDesktopIdentity({
          database, keyring, client, workspaceId, userId, relaycastWorkspaceId: relayWorkspaceId,
          nativeSession: desktopCall.nativeSession, sourceId: desktopCall.nativeSourceId,
        });
      } catch (error) {
        if (error instanceof DesktopIdentityUnavailable) throw new RelayToolError(error.message);
        throw error;
      }
    })();
    return linked;
  }

  /** Managed calls cannot choose another actor. */
  async function managedActorOnly(as?: string, alternate = false) {
    if (managed && (as || alternate)) {
      await desktop();
      throw new RelayToolError(MANAGED_AS_REFUSED);
    }
  }

  /** Serializes join and leave for this owner in Postgres; every store access inside uses `tx`. */
  function withOwnerLock<T>(run: (tx: SqlExecutor) => Promise<T>): Promise<T> {
    return database.transaction(async (tx) => {
      if (oauth) await oauth.lock(tx);
      await tx.query("SELECT pg_advisory_xact_lock(hashtext($1), hashtext($2))",
        ["selfhost-hosted-mcp", `${workspaceId}:${userId}`]);
      return run(tx);
    });
  }

  /** Callers hold the owner lock; `tx` is the transaction that would write the binding. */
  async function refuseRetiring(tx: SqlExecutor, agentRemoteId: string, agentName: string): Promise<void> {
    if (await retiringIdentity(tx, { organizationId, workspaceId, userId, agentRemoteId, agentName })) {
      throw new RelayToolError(MCP_OAUTH_RETIRING_MESSAGE);
    }
  }

  function ownsRemote(remote: { metadata: Record<string, unknown> }): boolean {
    return remote.metadata.source === HOSTED_SOURCE && remote.metadata.cloud_workspace_id === workspaceId
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
   * The owner's participant selected by `as`, else by this MCP session.
   * Verifies the remote agent is still the one this owner registered, and
   * refuses a rejected token unless `allowRejected`.
   */
  async function participant(as?: string, options: ParticipantOptions = {}): Promise<Hosted | null> {
    if (oauth && !options.executor) return withOwnerLock(tx=>participant(as,{...options,executor:tx}));
    const { allowMissing = false, allowGone = false, allowRejected = false, executor: query = executor } = options;
    const requested = as;
    const approvedId = oauth?.access.agentRemoteId;
    if (oauth && !approvedId) { oauth.assertActor(as); as = oauth.access.agentName; }
    const selector: Selector | null = approvedId ? { agentRemoteId: approvedId }
      : as ? { name: as } : sessionHash ? { sessionHash } : null;
    const row = selector ? await findParticipant(query, workspaceId, userId, organizationId, selector) : null;
    if (!row) {
      if (approvedId && !allowGone) throw new RelayToolError("The approved agent is no longer available. Reconnect the app to choose an agent.");
      if (as && !allowMissing && !(oauth && !requested) && !approvedId) throw new RelayToolError("No hosted participant with that name is owned by you in this workspace.");
      return null;
    }
    if (row.relayWorkspaceId !== relayWorkspaceId) {
      throw new RelayToolError("The participant does not belong to you in this workspace's relay.");
    }
    // Retirement fence, before any Relaycast call: an unpinned OAuth grant
    // would pin this row's agent, and a native join would bind its session.
    if (((oauth && !approvedId) || (options.bind && !row.sessionHash)) && options.executor) {
      await refuseRetiring(query, row.agentRemoteId, row.agentName);
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
    if (oauth) {
      oauth.assertActor(requested, name);
      if (remote) await oauth.pin(query, { workspaceId, userId, agentName: name, agentRemoteId: row.agentRemoteId });
    }
    if (!tokenUsable && !allowRejected) throw rejectedToken(name);
    return { row: { ...row, agentName: name }, token, name, remotePresent: remote !== null, tokenUsable };
  }

  async function touchPresence(token: string): Promise<void> {
    try {
      await client.heartbeat(token);
    } catch {
      // Presence is best effort; the call itself proceeds.
    }
  }

  async function listedAgents(status: "active" | "all", includeStale = false) {
    return (await client.listAgents(key, status, { includeStale })).filter(isListedRelayAgent);
  }

  async function roster(status: "live" | "all" | "offline", people: readonly McpMember[], includeStale = false) {
    return (await listedAgents(status === "live" ? "active" : "all", includeStale))
      .map(agent => rosterAgent(agent, people, userId, workspaceId))
      .filter(agent => status === "all" || (status === "live" ? agent.online : !agent.online));
  }

  async function addressFor(name: string, bestEffort = false): Promise<string | null> {
    try {
      return (await listedAgents("all")).find(agent => agent.name === name)?.address ?? null;
    } catch (error) {
      if (bestEffort) return null;
      throw error;
    }
  }

  async function explicitAgent(target: string): Promise<RosterAgent | null> {
    const separator = target.lastIndexOf("@");
    const recent = (await client.listAgents(key, "all"))
      .find(agent => separator < 0 ? agent.name === target : agent.address === target);
    if (recent) return recent;
    const name = separator < 0 ? target : target.slice(0, separator);
    if (!name) return null;
    const agent = await client.getRosterAgent(key, name);
    return agent?.name === name && (separator < 0 || agent.address === target) ? agent : null;
  }

  async function recipient(to: string, people: readonly McpMember[]) {
    const agent = await explicitAgent(to);
    if (!agent || agent.status === "released" || agent.metadata.source === "cloud-persona-deploy"
        || agent.metadata.source === "cloud-persona") {
      throw new RelayToolError("Unknown agent name or stale machine address in this workspace. Use list_relay_agents.");
    }
    return rosterAgent(agent, people, userId, workspaceId);
  }

  async function conversation(token: string, name: string, peer: string) {
    return (await client.listConversations(token))
      .find(item => item.participants.length === 2 && item.participants.includes(name) && item.participants.includes(peer));
  }

  /** Callers hold the owner lock. */
  async function registerParticipant(tx: SqlExecutor, name: string, boundSession: string | null, objective: string) {
    const remote = await client.getAgent(key, name);
    if (remote && !ownsRemote(remote)) throw new RelayToolError("That relay name is already taken. Choose another name.");
    // Recovering an owned agent binds it again; its release may be in flight.
    if (remote) await refuseRetiring(tx, remote.id, remote.name);
    // An owned agent without a row is an interrupted join: recover its token.
    const registered = remote
      ? await client.recoverHosted(key, name, remote.id, userId)
      : await client.registerHosted(key, name, {
        source: HOSTED_SOURCE, cloud_workspace_id: workspaceId, owner_hash: owner, objective,
        ...(oauth ? { created_by: "mcp-oauth" } : {}),
      });
    try {
      await insertParticipant(tx, {
        workspaceId, userId, relayWorkspaceId, sessionHash: boundSession,
        agentName: registered.name, agentRemoteId: registered.id,
        tokenCiphertext: encryptSecret(registered.token, keyring.active),
      });
      if (oauth) await oauth.pin(tx, { workspaceId, userId, agentName: registered.name, agentRemoteId: registered.id });
    } catch (error) {
      if (!remote) await client.releaseHosted(key, registered.name, registered.id).catch(() => {});
      throw error;
    }
    return registered;
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
      recovered = await client.recoverHosted(key, existing.name, existing.row.agentRemoteId, userId);
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

  async function join(input: { name?: string; description?: string; desktop_address?: string }) {
    if (managed) {
      const identity = await desktop();
      if (input.name || input.description || (input.desktop_address && input.desktop_address !== identity.address)) {
        throw new RelayToolError(MANAGED_JOIN_REFUSED);
      }
      return { joined: true, linked: "desktop" as const, name: identity.name, address: identity.address,
        already_joined: true, reply_guidance: DESKTOP_REPLY_GUIDANCE };
    }
    if (input.desktop_address) throw new RelayToolError(DESKTOP_ADDRESS_UNAVAILABLE);
    if (oauth && !oauth.access.agentRemoteId) oauth.assertActor(input.name);
    if (!sessionHash && !input.name && !oauth) {
      throw new RelayToolError("Initialize MCP to receive Mcp-Session-Id, or pass an explicit name and use as on later calls.");
    }
    const joined = await withOwnerLock(async (tx) => {
      const bound = await participant(undefined, { allowRejected: true, executor: tx });
      if (oauth && bound) oauth.assertActor(input.name, bound.name);
      if (bound && input.name && bound.name !== input.name && !oauth) {
        throw new RelayToolError("This MCP session is already joined. Leave before choosing another name.");
      }
      const requestedName = oauth?.access.agentName ?? input.name ?? automaticParticipantName(context.principal, sessionHash!);
      const existing = bound ?? await participant(requestedName, {
        allowMissing: true, allowRejected: true, executor: tx, bind: Boolean(sessionHash) });
      if (existing) {
        if (sessionHash && existing.row.sessionHash && existing.row.sessionHash !== sessionHash) {
          throw new RelayToolError("That participant is bound to another MCP session. Use as to act as it without changing its binding, or choose a new name.");
        }
        const token = existing.tokenUsable ? existing.token : await recoverToken(tx, existing);
        if (sessionHash && !existing.row.sessionHash) await updateParticipant(tx, existing.row.id, { sessionHash });
        return { name: existing.name, token, alreadyJoined: true, recovered: !existing.tokenUsable };
      }
      const ownerLabel = context.principal.name.trim() || context.principal.email || userId;
      const registered = await registerParticipant(tx, requestedName, sessionHash,
        input.description ?? `Hosted MCP inbox participant acting for ${ownerLabel}`);
      return { name: registered.name, token: registered.token, alreadyJoined: false, recovered: false };
    });
    await touchPresence(joined.token);
    return { joined: true, linked: "hosted" as const, name: joined.name, address: await addressFor(joined.name, true),
      already_joined: joined.alreadyJoined, recovered: joined.recovered, reply_guidance: HOSTED_REPLY_GUIDANCE, desktop_relay_guidance: DESKTOP_RELAY_GUIDANCE };
  }

  /** The participant `as` names, else this session's, auto-joining this session when it has none. */
  async function hostedActor<T>(as: string | undefined, fn: (identity: Identity) => Promise<T>): Promise<T> {
    if (managed) {
      await managedActorOnly(as);
      return fn(await desktop());
    }
    let hosted = await participant(as, { allowMissing: Boolean(oauth) });
    if (!hosted) {
      await join({});
      hosted = await participant();
    }
    if (!hosted) throw new RelayToolError("Could not create a hosted participant for this MCP session. Call join_relay, then retry.");
    await touchPresence(hosted.token);
    return fn(hosted);
  }

  /**
   * The identity channel tools act as: a hosted participant chosen by `as`,
   * `hosted: true`, or the one this session already joined; auto-joined only
   * when `create`. Unchosen, `unlinked` decides: "error" throws, "none" acts
   * as nobody.
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
      const chosen = oauth || input.hosted || (sessionHash && await findParticipant(executor, workspaceId, userId, organizationId, { sessionHash }));
      if (!chosen) {
        if (unlinked === "none") return null;
        throw new RelayToolError(UNLINKED_CHANNEL_GUIDANCE);
      }
    }
    if (create) return hostedActor(input.as, fn);
    const hosted = await participant(input.as);
    if (!hosted) return null;
    await touchPresence(hosted.token);
    return fn(hosted);
  }

  async function membership(token: string, channel: string) {
    return (await client.authenticatedAgent(token)).channels.find(row => row.name === channel) ?? null;
  }

  function notSubscribed(channel: string): never {
    throw new RelayToolError(`You are not subscribed to #${channel}. Call subscribe_relay_channel first.`);
  }

  return {
    async list(input: { status: "live" | "all" | "offline"; person?: string; query?: string; include_stale?: boolean }) {
      const query = input.query?.toLowerCase();
      const person = input.person?.toLowerCase();
      const agents = await roster(input.status, await context.members(), input.include_stale);
      return { workspace_id: workspaceId, agents: agents.filter(agent =>
        (!person || (person === "me" ? agent.is_mine
          : agent.owner?.user_id.toLowerCase() === person || agent.owner?.name.toLowerCase().includes(person))) &&
        (!query || [agent.name, agent.address, agent.description, agent.where].some(value => value?.toLowerCase().includes(query)))) };
    },

    join,

    async leave(as?: string) {
      if (managed) {
        await managedActorOnly(as);
        await desktop();
        return { joined: false, desktop_agent_unchanged: true, native_chat_identity_retained: true };
      }
      return withOwnerLock(async (tx) => {
        // Release uses the workspace key, so a rejected token can still leave.
        const hosted = await participant(as, { allowGone: true, allowRejected: true, executor: tx });
        if (!hosted) return { joined: false, already_left: true };
        if (oauth && hosted.row.sessionHash) {
          throw new RelayToolError("A native MCP session still uses this agent. Leave from that session instead.");
        }
        if (oauth && await oauth.claimedByOther(tx, { agentName: hosted.name, agentRemoteId: hosted.row.agentRemoteId })) {
          throw new RelayToolError("Another active connection still uses this agent. Disconnect it before leaving.");
        }
        if (hosted.remotePresent) {
          try {
            await client.releaseHosted(key, hosted.name, hosted.row.agentRemoteId);
          } catch (error) {
            // A concurrent remote deletion also completes leave.
            if (!(error instanceof RelaycastCallError) || error.status !== 404 || await client.getAgent(key, hosted.name)) throw error;
          }
        }
        await removeParticipant(tx, hosted.row.id);
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
      const hosted = await participant(as);
      if (!hosted) return { joined: false, name: null, address: null, unread_count: 0,
        guidance: "Send a message with send_relay_message to auto-join this MCP session, or call join_relay first." };
      await touchPresence(hosted.token);
      const [address, inbox] = await Promise.all([addressFor(hosted.name), client.readHostedInbox(hosted.token)]);
      return { joined: true, linked: "hosted" as const, name: hosted.name, address,
        unread_count: inbox.length, unread_count_is_lower_bound: inbox.length === 100 };
    },

    async inbox(as: string | undefined, acknowledge: string[]) {
      if (managed) {
        await managedActorOnly(as);
        const identity = await desktop();
        return { linked: "desktop" as const, name: identity.name, address: identity.address, messages: [],
          polling_needed: false,
          guidance: "Replies are injected into your session by Agent Relay Desktop; check_relay_inbox is not used for this linked identity." };
      }
      const hosted = await participant(as);
      if (!hosted) throw new RelayToolError("No hosted participant is bound to this MCP session. Send a message with send_relay_message to auto-join, or call join_relay first.");
      await touchPresence(hosted.token);
      // Every fallible read finishes before any acknowledgement, so a failed
      // enrichment leaves the deliveries pending for a retry.
      const [messages, agents, conversations] = await Promise.all([
        client.readHostedInbox(hosted.token), listedAgents("all"), client.listConversations(hosted.token),
      ]);
      const addresses = new Map(agents.map(agent => [agent.name, agent.address]));
      const channelNames = new Map<string, string>();
      if (messages.some(isChannelDelivery)) {
        for (const row of (await client.authenticatedAgent(hosted.token)).channels) channelNames.set(row.id, row.name);
        if (messages.some(message => isChannelDelivery(message) && message.channel_id && !channelNames.has(message.channel_id))) {
          for (const row of await client.listChannels(key)) channelNames.set(row.id, row.name);
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
      for (const id of requested) await client.acknowledgeDelivery(hosted.token, id);
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
      // unknown recipient never leaves a participant behind.
      const peer = await recipient(input.to, await context.members());
      return hostedActor(input.as, async (identity) => {
        if (identity.name === peer.name) throw new RelayToolError("Choose another agent as the recipient.");
        const responseIdempotencyKey = input.idempotency_key ?? serverIdempotencyKey;
        const idempotencyKey = `hosted-mcp:${userId}:${identity.name}:${responseIdempotencyKey}`;
        // Response metadata and reply_to are resolved before the write, so a
        // later read failure never hides a send Relaycast already accepted.
        const [fromAddress, conv] = await Promise.all([
          addressFor(identity.name),
          input.reply_to ? (async () => {
            const found = await conversation(identity.token, identity.name, peer.name);
            // Look the parent up by its exclusive successor to verify old ids without paging.
            const page = found ? await client.listMessages(identity.token, found.id,
              { limit: 1, before: String(BigInt(input.reply_to!) + 1n) }) : null;
            if (!page?.messages.some(message => message.id === input.reply_to)) {
              throw new RelayToolError("reply_to must belong to your DM conversation with this recipient.");
            }
            return found!;
          })() : Promise.resolve(null),
        ]);
        let sent;
        if (input.reply_to) {
          sent = await client.replyToMessage({ token: identity.token, parentId: input.reply_to, text: input.text, idempotencyKey });
          if (sent.conversationId !== conv!.id) {
            throw new RelayToolError("Reply outcome could not be verified. Do not retry with a new idempotency key.");
          }
        } else {
          sent = await client.sendDirectMessage({ token: identity.token, to: peer.name,
            ...(input.to === peer.address ? { address: input.to } : {}), text: input.text, idempotencyKey });
        }
        return { from: identity.name, from_address: fromAddress, to: peer.name, to_address: peer.address,
          message_id: sent.message.id, conversation_id: sent.conversationId, idempotency_key: responseIdempotencyKey,
          delivery: peer.online ? "queued_unconfirmed" : "queued_offline",
          note: "Accepted by Relaycast; delivery and reading are not confirmed.",
          ...(managed ? { reply_guidance: DESKTOP_REPLY_GUIDANCE }
            : { reply_guidance: HOSTED_REPLY_GUIDANCE, desktop_relay_guidance: DESKTOP_RELAY_GUIDANCE }) };
      });
    },

    async read(input: { agent: string; as?: string; before?: string; limit: number }) {
      // Names resolve within the actor's own DMs; only a machine address needs a lookup.
      const peerName = input.agent.includes("@") ? (await explicitAgent(input.agent))?.name : input.agent;
      if (!peerName) throw new RelayToolError("Unknown or stale machine address in this workspace.");
      await managedActorOnly(input.as);
      const hosted: Identity | null = managed ? await desktop() : await participant(input.as);
      if (!hosted) return { you: null, conversation_id: null, messages: [], earlier: null };
      await touchPresence(hosted.token);
      const conv = await conversation(hosted.token, hosted.name, peerName);
      if (!conv) return { you: hosted.name, conversation_id: null, messages: [], earlier: null };
      const page = await client.listMessages(hosted.token, conv.id, { before: input.before, limit: input.limit });
      const messages = [];
      // The DM listing omits thread_id; enrich only authorized ids, five at a time.
      for (let index = 0; index < page.messages.length; index += 5) {
        messages.push(...await Promise.all(page.messages.slice(index, index + 5).map(async message => ({
          message_id: message.id, sender: message.sender, text: message.text, created_at: message.createdAt,
          thread_id: await client.getMessageThreadId(hosted.token, message.id), mine: message.sender === hosted.name,
        }))));
      }
      return { you: hosted.name, conversation_id: conv.id, messages,
        earlier: page.hasEarlier ? page.messages[0]?.id ?? null : null };
    },

    async listChannels(input: ChannelInput) {
      let acted = false;
      const [channels, mine] = await Promise.all([client.listChannels(key), channelActor(input, false, async (identity) => {
        acted = true;
        return { you: identity.name, ids: new Set((await client.authenticatedAgent(identity.token)).channels.map(row => row.id)) };
      }, "none")]);
      const unlinked = !managed && !acted && !input.as && !input.hosted &&
        !(sessionHash && await findParticipant(executor, workspaceId, userId, organizationId, { sessionHash }));
      return { you: mine?.you ?? null, linked: mine ? linkedKind : null,
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
          alreadySubscribed = (await client.joinChannel(identity.token, channel)).alreadyMember;
        } catch (error) {
          if (!(error instanceof RelaycastCallError) || error.status !== 404) throw error;
          if (!input.create) throw new RelayToolError(`No channel #${channel} exists. Use list_relay_channels, or pass create: true to start it.`);
          try {
            // The creator becomes the channel's owner, which is membership.
            await client.createChannel(identity.token, channel);
            created = true;
          } catch (createError) {
            // Someone created it first: join theirs.
            if (!(createError instanceof RelaycastCallError) || createError.status !== 409) throw createError;
            alreadySubscribed = (await client.joinChannel(identity.token, channel)).alreadyMember;
          }
        }
        return { subscribed: true, channel, you: identity.name, linked: linkedKind, created,
          already_subscribed: alreadySubscribed, delivery: channelDelivery(channel), reply_guidance: CHANNEL_REPLY_GUIDANCE };
      }))!;
    },

    async unsubscribeChannel(input: ChannelInput & { channel: string }) {
      const channel = normalizeChannelName(input.channel);
      return await channelActor(input, false, async (identity) => {
        if (!await membership(identity.token, channel)) return { subscribed: false, channel, you: identity.name, already_unsubscribed: true };
        await client.leaveChannel(identity.token, channel);
        return { subscribed: false, channel, you: identity.name, already_unsubscribed: false };
      }) ?? { subscribed: false, channel, you: null, already_unsubscribed: true };
    },

    async postChannel(input: ChannelInput & { channel: string; text: string; thread_id?: string; idempotency_key?: string },
      serverIdempotencyKey: string = randomUUID()) {
      const channel = normalizeChannelName(input.channel);
      // Posting requires a subscription, so no identity is created here.
      return (await channelActor(input, false, async (identity) => {
        const member = await membership(identity.token, channel);
        if (!member) notSubscribed(channel);
        const responseIdempotencyKey = input.idempotency_key ?? serverIdempotencyKey;
        const idempotencyKey = `hosted-mcp-channel:${userId}:${identity.name}:${responseIdempotencyKey}`;
        let messageId: string;
        let threadId: string | null = null;
        if (input.thread_id) {
          const parent = await client.getMessage(identity.token, input.thread_id);
          if (!parent || parent.channelId !== member.id) throw new RelayToolError(`thread_id must be a message in #${channel}. Use read_relay_channel.`);
          const reply = await client.replyInChannelThread({ token: identity.token, parentId: input.thread_id, text: input.text, idempotencyKey });
          if (reply.channelId !== member.id) throw new RelayToolError("Reply outcome could not be verified. Do not retry with a new idempotency key.");
          messageId = reply.id;
          threadId = reply.threadId;
        } else {
          messageId = (await client.postChannelMessage({ token: identity.token, channel, text: input.text, idempotencyKey })).id;
        }
        return { from: identity.name, channel, linked: linkedKind, message_id: messageId, thread_id: threadId,
          idempotency_key: responseIdempotencyKey,
          note: "Accepted by Relaycast and delivered to the channel's subscribers; reading is not confirmed.",
          reply_guidance: `${channelDelivery(channel)} Continue this thread with ${channelReplyHint(channel, threadId ?? messageId)}.` };
      })) ?? notSubscribed(channel);
    },

    async readChannel(input: ChannelInput & { channel: string; before?: string; limit: number }) {
      const channel = normalizeChannelName(input.channel);
      return (await channelActor(input, false, async (identity) => {
        // History is read with the workspace key, so membership is checked here.
        if (!await membership(identity.token, channel)) notSubscribed(channel);
        const page = await client.listChannelMessages(key, channel, { before: input.before, limit: input.limit });
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
