import type { Database } from "../database.js";
import { RelaycastCallError, type RelaycastClient } from "../messaging/relaycast.js";
import { relayHostedCredentials, type RelayHostedClient } from "./relay-hosted-credentials.js";

/**
 * Hosted participants on gate-only installs (SELFHOST_RELAYGATE_PUBLIC_URL;
 * docs/identity.md, "Hosted participants on gate-only installs").
 *
 * relaygate is the only public way into Relaycast there, and its policy
 * decides each agent's group. A hosted MCP participant used to be registered
 * in Relaycast with the workspace key and to message with a Relaycast token,
 * around relaygate. Now it enrols at relaygate's POST /v1/register with a
 * single-use hosted credential (`sh_ht_`, ./relay-hosted-credentials.ts) and
 * holds only an rg_ token, so every call it makes goes through relaygate.
 *
 * relaygate fails closed: a hosted credential matches only controlPrincipals
 * rules that name the hosted kind, so an install without such a rule refuses
 * the participant, and the error names the rule to add.
 */
export class HostedGateRefused extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HostedGateRefused";
  }
}

export const hostedGateNoRule = (client: RelayHostedClient) =>
  `This install's relaygate policy does not allow hosted ${client} participants. Ask your operator to add a controlPrincipals rule with "kinds": ["hosted"] and "clients": ["${client}"] (see "Hosted participants" in relaygate's docs/contract.md).`;

function refusal(error: unknown, input: { agentName: string; client: RelayHostedClient }): Error {
  if (!(error instanceof RelaycastCallError)) return error instanceof Error ? error : new Error("relaygate enrolment failed");
  if (error.status === 0 || error.status >= 500) {
    return new HostedGateRefused("relaygate is unavailable, so this hosted participant could not enrol. Retry shortly.");
  }
  if (error.status === 409) return new HostedGateRefused("That relay name is already taken. Choose another name.");
  if (error.status === 403 && error.code === "relaygate_name_scope") {
    return new HostedGateRefused(`relaygate's policy does not allow the name ${input.agentName} for hosted ${input.client} participants. Choose a name its rule allows.`);
  }
  if (error.status === 403) return new HostedGateRefused(hostedGateNoRule(input.client));
  if (error.status === 401) {
    return new HostedGateRefused("relaygate could not verify this install's hosted participant credential. Check relaygate's relay-control introspection settings.");
  }
  return new HostedGateRefused("relaygate refused this hosted participant.");
}

export type GateEnrolment = {
  /** relaygate's agent id. */
  relaygateAgentId: string;
  /** The upstream Relaycast agent id (what pins, retirement and launches key on). */
  relaycastAgentId: string;
  name: string;
  /** An rg_ token; only relaygate accepts it. */
  token: string;
  /**
   * The upstream agent's metadata as relaygate left it. relaygate stamps a
   * name it registers itself with `relaygate.agent_id`; a name it took over
   * keeps the metadata it had.
   */
  metadata: Record<string, unknown>;
};

/** Whether relaygate registered the upstream agent itself for this enrolment, so it carries no other owner's metadata. */
export function freshAtGate(enrolled: Pick<GateEnrolment, "relaygateAgentId" | "metadata">): boolean {
  const stamp = enrolled.metadata.relaygate;
  return enrolled.metadata.source === undefined && typeof stamp === "object" && stamp !== null
    && (stamp as Record<string, unknown>).agent_id === enrolled.relaygateAgentId;
}

/**
 * Enrols (or, for the same owner and name, recovers) one hosted participant
 * at relaygate. Throws HostedGateRefused with an operator-facing reason when
 * relaygate refuses.
 */
export async function enrolHostedAtGate(
  deps: { database: Database; gate: RelaycastClient },
  input: { workspaceId: string; organizationId: string; userId: string; agentName: string; client: RelayHostedClient },
): Promise<GateEnrolment> {
  const { token: credential } = await relayHostedCredentials(deps.database).issue(input);
  let enrolled;
  try {
    enrolled = await deps.gate.registerAtGate(credential, input.agentName);
  } catch (error) {
    throw refusal(error, input);
  }
  // relaygate names the Control user it enrolled the agent for; any other user is not this owner.
  if (enrolled.userId !== null && enrolled.userId !== input.userId) {
    await deps.gate.releaseOwnAgent(enrolled.token).catch(() => {});
    throw new HostedGateRefused("relaygate enrolled this participant for another user. Nothing was joined.");
  }
  const upstream = await deps.gate.authenticatedAgent(enrolled.token);
  if (upstream.name !== input.agentName) throw new HostedGateRefused("relaygate enrolled a different agent name. Nothing was joined.");
  return { relaygateAgentId: enrolled.agentId, relaycastAgentId: upstream.id, name: upstream.name, token: enrolled.token,
    metadata: upstream.metadata };
}
