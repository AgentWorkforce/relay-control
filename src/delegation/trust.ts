import type { SqlExecutor } from "../database.js";
import { connectorKind, type ConnectorKind } from "../mcp/oauth/connector-kind.js";

/**
 * Delegation roles bind the kinds in roles.ts CONNECTOR_KINDS. A Slashy grant
 * keeps the generic "mcp" connector kind it had before Slashy was classified,
 * so existing connector:mcp bindings still cover it (as in Cloud).
 */
function delegationConnectorKind(kind: ConnectorKind): Exclude<ConnectorKind, "slashy"> {
  return kind === "slashy" ? "mcp" : kind;
}
import { sha256Hex } from "./scope.js";

/**
 * The set-once trust rule's ownership chain, as Cloud's lib/delegation/trust.ts
 * (#owner-decisions 251238934511685632, 251241083284656128, 251242695516778496).
 *
 * An agent is covered by its owner's rule only through stored ownership
 * records, never by a name:
 * - a ROOT is an agent the owner connected: a completed, unreleased claim
 *   (one-time code plus the agent's own Relaycast token), or a live MCP OAuth
 *   grant of the owner pinned to the agent's immutable id
 *   (`mcp_oauth_grants.agent_remote_id`, with a live session), joined to the
 *   owner's hosted participant for that id;
 * - a HOP is a Control launch (`relay_spawns`) of the owner whose launching
 *   actor is itself covered, in state `ready`. relay-control records no
 *   owner-verified ready audit like Cloud's; a launch reaches `ready` only after
 *   its invocation's caller and node were matched to the journaled actor and
 *   node and the worker was correlated (src/mcp/relay-spawn.ts), so `ready` is
 *   the proof here.
 * Every node must have exactly one Control binding. Sub-agents a worker starts
 * through its node's own broker leave no Control record and are not covered.
 */
export type TrustPath = {
  root: { kind: "claim"; claim_id: string; agent_id: string; created_at: string } |
    { kind: "connector"; oauth_grant_id: string; connector: string; agent_id: string; created_at: string };
  hops: Array<{ spawn_id: string; actor_id: string; worker_id: string; created_at: string }>;
};

/** How far a chain is walked from an agent back to its root. */
export const MAX_TRUST_DEPTH = 8;

/** The owner's hosted launcher acts for their desktop chats; it is never a connected assistant. */
export const launcherName = (userId: string) => `launcher-${sha256Hex(userId).slice(0, 16)}`;

type SpawnRow = { id: string; userId: string; workspaceId: string; actorId: string; workerId: string | null; agentName: string;
  state: string; createdAt: Date };

/**
 * A proven chain, and the agent's current Relaycast name. The name only finds
 * the agent for the live check, which then compares the immutable id; it never
 * decides coverage.
 */
export type TrustProof = { path: TrustPath; name: string };

export type TrustReader = {
  /** Live completed claims holding this agent id (any owner). */
  claims(workspaceId: string, relaycastWorkspaceId: string, agentId: string): Promise<Array<{ id: string; ownerUserId: string;
    workspaceId: string; completedAt: Date; agentName: string }>>;
  /** The owner's live OAuth grants pinned to this agent id, each joined to the owner's hosted participant for it. */
  connectors(workspaceId: string, relaycastWorkspaceId: string, ownerUserId: string, agentId: string): Promise<Array<{
    grantId: string; clientName: string | null; redirectUris: string[]; participantName: string;
    /** When the hosted participant was created. */
    createdAt: Date;
    /** When the OAuth grant was created: a reconnect makes a new grant, so coverage never predates it. */
    grantCreatedAt: Date }>>;
  /** Hosted participants holding this agent id (any owner, at most 2), for uniqueness. */
  participants(workspaceId: string, relaycastWorkspaceId: string, agentId: string): Promise<Array<{ userId: string | null;
    workspaceId: string }>>;
  /** Launches whose worker is this agent id, terminal ones included (at most 2). */
  spawns(workspaceId: string, relaycastWorkspaceId: string, agentId: string): Promise<SpawnRow[]>;
  /** Desktop and person identities holding this agent id: either makes the agent ambiguous for the rule. */
  otherBindings(workspaceId: string, relaycastWorkspaceId: string, agentId: string): Promise<number>;
};

const at = (value: Date | string) => value instanceof Date ? value : new Date(value);

/**
 * The stored records, read on `executor`. Uniqueness counts look across the
 * whole Relaycast workspace (as anyBinding does), ownership rows are scoped to
 * the Control workspace.
 *
 * With `lock` (inside the caller's transaction), every row the chain stands on
 * is share-locked until it ends: the claim and its binding, the OAuth grant,
 * its live sessions and the participant, each launch, and each participant
 * holding the id. A claim release, connector revoke or launch release that
 * commits after the read waits for that transaction; one that committed
 * before it is seen.
 */
export function sqlTrustReader(executor: SqlExecutor, lock = false): TrustReader {
  const share = (of?: string) => lock ? ` FOR SHARE${of ? ` OF ${of}` : ""}` : "";
  return {
    claims: async (_workspaceId, relaycastWorkspaceId, agentId) => (await executor.query<{ id: string; user_id: string;
      workspace_id: string; consumed_at: Date | string; agent_name: string }>(
      `SELECT c.id, b.user_id::text, b.workspace_id::text, c.consumed_at, b.agent_name
         FROM delegation_agent_bindings b JOIN delegation_claims c ON c.id = b.claim_id
        WHERE b.relaycast_workspace_id = $1 AND b.agent_id = $2 AND c.consumed_at IS NOT NULL AND c.released_at IS NULL
        ORDER BY c.id LIMIT 2${share("b, c")}`, [relaycastWorkspaceId, agentId])).rows.map(row => ({ id: row.id, ownerUserId: row.user_id,
      workspaceId: row.workspace_id, completedAt: at(row.consumed_at), agentName: row.agent_name })),
    connectors: async (workspaceId, relaycastWorkspaceId, ownerUserId, agentId) => {
      const rows = (await executor.query<{ id: string;
      client_name: string | null; redirect_uris: string[] | null; agent_name: string; created_at: Date | string;
      grant_created_at: Date | string }>(
      `SELECT g.id::text, COALESCE(c.client_name, g.client_name) AS client_name, c.redirect_uris, p.agent_name, p.created_at,
              g.created_at AS grant_created_at
         FROM mcp_oauth_grants g
         JOIN hosted_relay_participants p ON p.workspace_id = g.workspace_id AND p.user_id = g.user_id
          AND p.relaycast_workspace_id = $2 AND p.agent_remote_id = $4
         LEFT JOIN mcp_oauth_clients c ON c.client_id = g.client_id
        WHERE g.workspace_id = $1 AND g.user_id = $3 AND g.agent_remote_id = $4 AND g.revoked_at IS NULL
          -- A live grant has a live session: unrevoked and still refreshable.
          AND EXISTS (SELECT 1 FROM mcp_oauth_sessions s WHERE s.grant_id = g.id AND s.revoked_at IS NULL
                        AND s.refresh_token_expires_at > now())
        ORDER BY g.created_at, g.id LIMIT 20${share("g, p")}`, [workspaceId, relaycastWorkspaceId, ownerUserId, agentId])).rows;
      // The live sessions the grants stand on, share-locked too (a revoke updates them).
      if (lock && rows.length) {
        await executor.query(
          `SELECT 1 FROM mcp_oauth_sessions WHERE grant_id = ANY($1::uuid[]) AND revoked_at IS NULL
              AND refresh_token_expires_at > now() ORDER BY id FOR SHARE`, [rows.map(row => row.id)]);
      }
      return rows.map(row => ({
        grantId: row.id, clientName: row.client_name, redirectUris: row.redirect_uris ?? [], participantName: row.agent_name,
        createdAt: at(row.created_at), grantCreatedAt: at(row.grant_created_at) }));
    },
    participants: async (_workspaceId, relaycastWorkspaceId, agentId) => (await executor.query<{ user_id: string | null;
      workspace_id: string }>(
      `SELECT user_id::text, workspace_id::text FROM hosted_relay_participants
        WHERE relaycast_workspace_id = $1 AND agent_remote_id = $2 ORDER BY id LIMIT 2${share()}`, [relaycastWorkspaceId, agentId])).rows
      .map(row => ({ userId: row.user_id, workspaceId: row.workspace_id })),
    spawns: async (_workspaceId, relaycastWorkspaceId, agentId) => (await executor.query<{ id: string; user_id: string;
      workspace_id: string; actor_id: string; worker_id: string | null; agent_name: string; state: string;
      created_at: Date | string }>(
      `SELECT id::text, user_id::text, workspace_id::text, actor_id, worker_id, agent_name, state, created_at
         FROM relay_spawns WHERE relaycast_workspace_id = $1 AND worker_id = $2 ORDER BY id LIMIT 2${share()}`,
      [relaycastWorkspaceId, agentId]))
      .rows.map(row => ({ id: row.id, userId: row.user_id, workspaceId: row.workspace_id, actorId: row.actor_id,
        workerId: row.worker_id, agentName: row.agent_name, state: row.state, createdAt: at(row.created_at) })),
    otherBindings: async (_workspaceId, relaycastWorkspaceId, agentId) => (await executor.query(
      `SELECT 1 FROM desktop_relay_identities WHERE relaycast_workspace_id = $1 AND agent_remote_id = $2
       UNION ALL SELECT 1 FROM person_identities WHERE relaycast_workspace_id = $1 AND agent_remote_id = $2
       LIMIT 2`, [relaycastWorkspaceId, agentId])).rows.length,
  };
}

type WalkInput = { workspaceId: string; relaycastWorkspaceId: string; ownerUserId: string; agentId: string };

/**
 * The root an agent is for this owner, or null. Exactly one binding: a claim
 * and no participant, or one participant and no claim. Two participants (of
 * one owner or two) holding the id are ambiguous, never decided by row order.
 */
async function rootOf(reader: TrustReader, input: WalkInput): Promise<{ root: TrustPath["root"]; name: string } | null> {
  const [claims, connectors, participants] = await Promise.all([
    reader.claims(input.workspaceId, input.relaycastWorkspaceId, input.agentId),
    reader.connectors(input.workspaceId, input.relaycastWorkspaceId, input.ownerUserId, input.agentId),
    reader.participants(input.workspaceId, input.relaycastWorkspaceId, input.agentId),
  ]);
  if (claims.length === 1 && participants.length === 0) {
    const [claim] = claims as [typeof claims[number]];
    return claim.ownerUserId === input.ownerUserId && claim.workspaceId === input.workspaceId && claim.agentName
      ? { name: claim.agentName, root: { kind: "claim", claim_id: claim.id, agent_id: input.agentId,
        created_at: claim.completedAt.toISOString() } } : null;
  }
  if (claims.length !== 0 || participants.length !== 1) return null;
  const [participant] = participants as [typeof participants[number]];
  if (participant.userId !== input.ownerUserId || participant.workspaceId !== input.workspaceId) return null;
  const owned = connectors.filter(row => row.participantName !== launcherName(input.ownerUserId));
  const first = owned[0];
  if (!first) return null;
  // Proven no earlier than both the participant and the live grant: a message
  // the agent sent while its connector was revoked predates a reconnect.
  const provenAt = new Date(Math.max(first.createdAt.getTime(), first.grantCreatedAt.getTime()));
  return { name: first.participantName, root: { kind: "connector", oauth_grant_id: first.grantId, agent_id: input.agentId,
    created_at: provenAt.toISOString(),
    connector: delegationConnectorKind(connectorKind({ clientName: first.clientName, redirectUris: first.redirectUris })) } };
}

/**
 * The ownership chain from one of the owner's roots down to `agentId`, read
 * now, or null when the agent is not covered: no root, a launch by someone
 * else or by an uncovered actor, a launch not ready, a second binding
 * anywhere, a cycle, or a chain deeper than MAX_TRUST_DEPTH. A read error
 * throws (an outage is never "not covered" for good).
 */
export async function resolveTrustPath(reader: TrustReader, input: WalkInput): Promise<TrustProof | null> {
  const hops: TrustPath["hops"] = [];
  let name: string | null = null;
  const seen = new Set<string>();
  let agentId = input.agentId;
  for (let depth = 0; depth <= MAX_TRUST_DEPTH; depth += 1) {
    if (seen.has(agentId)) return null;
    seen.add(agentId);
    const [spawns, others] = await Promise.all([
      reader.spawns(input.workspaceId, input.relaycastWorkspaceId, agentId),
      reader.otherBindings(input.workspaceId, input.relaycastWorkspaceId, agentId),
    ]);
    if (others > 0) return null;
    if (!spawns.length) {
      const found = await rootOf(reader, { ...input, agentId });
      return found ? { path: { root: found.root, hops: hops.reverse() }, name: name ?? found.name } : null;
    }
    // A launched worker: exactly one launch row (terminal rows included, so a reused id never transfers ownership).
    if (spawns.length !== 1) return null;
    const [spawn] = spawns as [SpawnRow];
    if (spawn.userId !== input.ownerUserId || spawn.workspaceId !== input.workspaceId || spawn.state !== "ready" ||
        spawn.workerId !== agentId) return null;
    // A launched worker is never also a root (no claim, no participant for its id).
    const [claims, participants] = await Promise.all([
      reader.claims(input.workspaceId, input.relaycastWorkspaceId, agentId),
      reader.participants(input.workspaceId, input.relaycastWorkspaceId, agentId),
    ]);
    if (claims.length || participants.length) return null;
    name ??= spawn.agentName;
    hops.push({ spawn_id: spawn.id, actor_id: spawn.actorId, worker_id: agentId, created_at: spawn.createdAt.toISOString() });
    agentId = spawn.actorId;
  }
  return null;
}

/** The agents of a chain from its root down to the covered agent itself. */
export function trustPathAgents(path: TrustPath): string[] {
  return [path.root.agent_id, ...path.hops.map(hop => hop.worker_id)];
}

/** The latest moment any record in the chain came to exist: messages sent before it predate the proof. */
export function trustPathProvenAt(path: TrustPath): Date {
  return new Date(Math.max(Date.parse(path.root.created_at), ...path.hops.map(hop => Date.parse(hop.created_at))));
}

/** Where the recipient sits relative to the sender in the owner's trust tree. */
export type TrustRelation = "self" | "ancestor" | "descendant" | "sibling" | "unrelated";

/**
 * `ancestor`: the sender launched (directly or not) the recipient. `descendant`:
 * the recipient launched the sender. `sibling`: same root, neither above the
 * other. `unrelated`: the recipient is not in the sender's tree.
 */
export function trustRelation(sender: TrustPath, recipientAgentId: string, recipient: TrustPath | null): TrustRelation {
  const senderAgents = trustPathAgents(sender);
  const senderId = senderAgents.at(-1)!;
  if (senderId === recipientAgentId) return "self";
  if (senderAgents.includes(recipientAgentId)) return "descendant";
  if (!recipient) return "unrelated";
  const recipientAgents = trustPathAgents(recipient);
  if (recipientAgents.includes(senderId)) return "ancestor";
  return recipientAgents[0] === senderAgents[0] ? "sibling" : "unrelated";
}

/**
 * Which relations a rule-backed approval may cross. Khaliq's final answer
 * (#owner-decisions 251242695516778496): "allow everything, including a bot
 * approving its own requests". Flipping this one value to `down_tree_only`
 * restores the earlier answer (ancestor to descendant only, or outside the tree).
 */
export type TrustRelationMode = "allow_all" | "down_tree_only";
export const TRUST_RELATION_MODE: TrustRelationMode = "allow_all";

/** The one predicate deciding whether a rule-backed approval may pass between these two agents. */
export function trustRelationAllowed(relation: TrustRelation, mode: TrustRelationMode = TRUST_RELATION_MODE): boolean {
  if (mode === "allow_all") return true;
  return relation === "ancestor" || relation === "unrelated";
}

/**
 * What a chain proves with: the root's own record (its claim or OAuth grant)
 * and every launch, in order (as Cloud's trustPathFingerprint). Two proofs with
 * the same fingerprint stand on the same records. A system grant keeps the
 * fingerprint it was created on; a chain that now proves through other records
 * (a claim released and reclaimed, a connector revoked and reconnected, a
 * worker launched again under the id) is a new coverage, never a continuation.
 */
export function trustPathFingerprint(path: TrustPath): string {
  const root = path.root.kind === "claim" ? `claim:${path.root.claim_id}` : `connector:${path.root.oauth_grant_id}`;
  return [root, path.root.agent_id, ...path.hops.map(hop => `${hop.spawn_id}>${hop.worker_id}`)].join("|");
}
