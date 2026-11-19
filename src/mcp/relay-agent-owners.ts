import type { SqlExecutor } from "../database.js";
import { relaygateAgentId } from "../messaging/desktop-identities.js";
import type { RosterAgent } from "../messaging/relaycast.js";
import type { McpMember } from "./context.js";

type OwnerCandidate = {
  agent_id: string | null;
  agent_name: string | null;
  source: "desktop" | "hosted" | "spawn";
  user_id: string;
  verified: boolean;
};

export type RelayAgentOwnerTarget = { agentId: string; lookupId: string; name: string };

/**
 * Desktop stores relaygate's id on gate-only installs while the roster carries
 * the upstream Relaycast id. The exact name is part of the join so an agent
 * cannot claim another Desktop row by writing its relaygate metadata field.
 * This is also the shared id mapping used by synced-session roster enrichment.
 */
export function relayAgentOwnerTarget(
  agent: Pick<RosterAgent, "id" | "name" | "metadata">,
  gateOnly: boolean,
): RelayAgentOwnerTarget {
  return { agentId: agent.id, lookupId: gateOnly ? relaygateAgentId(agent.metadata) ?? agent.id : agent.id, name: agent.name };
}

/**
 * Resolve display ownership from Control's own identity journals. Relaycast
 * metadata is agent-written and is only a legacy fallback. Any duplicate
 * binding makes an id ambiguous rather than silently transferring ownership.
 */
export async function loadRelayAgentOwners(executor: SqlExecutor, workspaceId: string,
  relaycastWorkspaceId: string, agents: ReadonlyArray<Pick<RosterAgent, "id" | "name" | "metadata">>,
  members: readonly McpMember[], gateOnly = false) {
  if (!agents.length) return new Map<string, McpMember>();
  const targets = agents.map(agent => relayAgentOwnerTarget(agent, gateOnly));
  const rosterIds = [...new Set(targets.map(target => target.agentId))];
  const desktopIds = [...new Set(targets.map(target => target.lookupId))];
  const desktopTargets = new Map(targets.map(target => [`${target.lookupId}\0${target.name}`, target.agentId]));
  // Control sets ready only after checking the invocation caller, target node,
  // and correlated registration. This is display data, never authorization.
  const rows = (await executor.query<OwnerCandidate>(
    `SELECT agent_remote_id AS agent_id, agent_name, 'desktop'::text AS source, user_id, true AS verified
       FROM desktop_relay_identities
      WHERE workspace_id = $1 AND relaycast_workspace_id = $2 AND agent_remote_id = ANY($3::text[])
     UNION ALL
     SELECT agent_remote_id AS agent_id, NULL::text AS agent_name, 'hosted'::text AS source, user_id, true AS verified
       FROM hosted_relay_participants
      WHERE workspace_id = $1 AND relaycast_workspace_id = $2 AND agent_remote_id = ANY($4::text[])
     UNION ALL
     SELECT worker_id AS agent_id, NULL::text AS agent_name, 'spawn'::text AS source, user_id, state = 'ready' AS verified
       FROM relay_spawns
      WHERE workspace_id = $1 AND relaycast_workspace_id = $2
        AND worker_id IS NOT NULL AND worker_id = ANY($4::text[])`,
    [workspaceId, relaycastWorkspaceId, desktopIds, rosterIds],
  )).rows;
  const memberById = new Map(members.map(member => [member.userId, member]));
  const seen = new Set<string>();
  const owners = new Map<string, McpMember>();
  for (const row of rows) {
    if (!row.agent_id) continue;
    const agentId = row.source === "desktop" && row.agent_name
      ? desktopTargets.get(`${row.agent_id}\0${row.agent_name}`) : row.agent_id;
    if (!agentId) continue;
    if (seen.has(agentId)) {
      owners.delete(agentId);
      continue;
    }
    seen.add(agentId);
    const member = memberById.get(row.user_id);
    // Non-ready rows still participate in ambiguity.
    if (row.verified && member) owners.set(agentId, member);
  }
  return owners;
}
