import type { SqlExecutor } from "../database.js";
import type { McpMember } from "./context.js";

type OwnerCandidate = { agent_id: string | null; user_id: string; verified: boolean };

/**
 * Resolve display ownership from Control's own identity journals. Relaycast
 * metadata is agent-written and is only a legacy fallback. Any duplicate
 * binding makes an id ambiguous rather than silently transferring ownership.
 */
export async function loadRelayAgentOwners(executor: SqlExecutor, workspaceId: string,
  relaycastWorkspaceId: string, agentIds: string[], members: readonly McpMember[]) {
  if (!agentIds.length) return new Map<string, McpMember>();
  const rows = (await executor.query<OwnerCandidate>(
    `SELECT agent_remote_id AS agent_id, user_id, true AS verified
       FROM desktop_relay_identities
      WHERE workspace_id = $1 AND relaycast_workspace_id = $2 AND agent_remote_id = ANY($3::text[])
     UNION ALL
     SELECT agent_remote_id AS agent_id, user_id, true AS verified
       FROM hosted_relay_participants
      WHERE workspace_id = $1 AND relaycast_workspace_id = $2 AND agent_remote_id = ANY($3::text[])
     UNION ALL
     SELECT worker_id AS agent_id, user_id, state = 'ready' AS verified
       FROM relay_spawns
      WHERE workspace_id = $1 AND relaycast_workspace_id = $2
        AND worker_id IS NOT NULL AND worker_id = ANY($3::text[])`,
    [workspaceId, relaycastWorkspaceId, agentIds],
  )).rows;
  const memberById = new Map(members.map(member => [member.userId, member]));
  const seen = new Set<string>();
  const owners = new Map<string, McpMember>();
  for (const row of rows) {
    if (!row.agent_id) continue;
    if (seen.has(row.agent_id)) {
      owners.delete(row.agent_id);
      continue;
    }
    seen.add(row.agent_id);
    const member = memberById.get(row.user_id);
    if (row.verified && member) owners.set(row.agent_id, member);
  }
  return owners;
}
