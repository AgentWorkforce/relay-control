import { createHash } from "node:crypto";
import type { Database, SqlExecutor } from "../database.js";
import { GATE_ONLY_PERSON_IDENTITY_NAME_PREFIX, withLock } from "./identity.js";
import { RelaycastCallError, type createRelaycastClient, type RemoteAgent } from "./relaycast.js";

/**
 * The workspace's own Agent Relay Support sender: the identity a "support
 * replied" notice comes from, so it reads as Agent Relay telling the person,
 * not as the person messaging themselves from whichever machine their person
 * identity last connected on. Parity with Cloud
 * (AgentWorkforce/cloud packages/web/lib/customer-support/support-identity.ts).
 *
 * One per relay workspace, registered by this server with ownership metadata
 * naming the workspace. Its token is never stored: each send obtains one under
 * a per-workspace lock, registering on first use and otherwise through
 * Relaycast's audited owner takeover. Nothing else holds that token, so the
 * takeover revokes nothing in use, and the lock stops two notices revoking
 * each other's token mid-send. A same-named agent this server did not register
 * is never taken over; a stable fallback name is used instead.
 */
export const SUPPORT_SENDER_NAME = "agent-relay-support";
export const SUPPORT_SENDER_PERSONA = "Agent Relay Support";
export const SUPPORT_SENDER_SOURCE = "control-support-notice";

type Relaycast = ReturnType<typeof createRelaycastClient>;

export class SupportSenderError extends Error {
  readonly name = "SupportSenderError";
  constructor(readonly code: "foreign_identity", message: string) {
    super(message);
  }
}

export function supportSenderMetadata(workspaceId: string): Record<string, unknown> {
  return { source: SUPPORT_SENDER_SOURCE, role: "support", workspace_id: workspaceId };
}

export function isSupportSenderOwnedBy(agent: Pick<RemoteAgent, "metadata">, workspaceId: string): boolean {
  return agent.metadata.source === SUPPORT_SENDER_SOURCE && agent.metadata.workspace_id === workspaceId;
}

/**
 * Names the sender may use, preferred first. Any workspace agent (a hosted
 * `join_relay` participant, a Desktop session) can already hold the preferred
 * name, so fall back to names that are stable per workspace: retries and later
 * notices land on the same agent, which keeps Relaycast's agent-scoped
 * idempotency keys deduplicating. Gate-only installs use the prefix relaygate
 * reserves, so a Desktop-enrolled name never collides with one.
 */
export function supportSenderNames(workspaceId: string, gateOnly = false): string[] {
  const base = `${gateOnly ? GATE_ONLY_PERSON_IDENTITY_NAME_PREFIX : ""}${SUPPORT_SENDER_NAME}`;
  const digest = createHash("sha256").update(`${SUPPORT_SENDER_NAME}:${workspaceId}`).digest("hex");
  return [base, `${base}-${digest.slice(0, 6)}`, `${base}-${digest.slice(6, 18)}`];
}

export function supportSenderLockKey(workspaceId: string): string {
  return `${workspaceId}:${SUPPORT_SENDER_NAME}`;
}

function nameTaken(error: unknown): boolean {
  return error instanceof RelaycastCallError && (error.status === 409 || error.code === "agent_already_exists");
}

const ACTOR = (workspaceId: string) => `selfhost-workspace:${workspaceId}`;

async function takeBack(relaycast: Relaycast, workspaceKey: string, workspaceId: string, remote: RemoteAgent) {
  const token = await relaycast.takeOver(workspaceKey, remote.name, remote.id, ACTOR(workspaceId));
  return { name: remote.name, token };
}

async function acquireToken(relaycast: Relaycast, workspaceKey: string, workspaceId: string, gateOnly: boolean) {
  const names = supportSenderNames(workspaceId, gateOnly);
  const found = await Promise.all(names.map(name => relaycast.getAgent(workspaceKey, name)));
  // An identity this server already owns wins over registering a now-free
  // preferred name, so the sender never changes once chosen.
  const owned = found.find(remote => remote && isSupportSenderOwnedBy(remote, workspaceId));
  if (owned) return takeBack(relaycast, workspaceKey, workspaceId, owned);
  for (const [index, name] of names.entries()) {
    if (found[index]) continue; // Someone else's: never taken over.
    try {
      const registered = await relaycast.registerSystemAgent(workspaceKey, {
        name, persona: SUPPORT_SENDER_PERSONA, metadata: supportSenderMetadata(workspaceId),
      });
      return { name: registered.name, token: registered.token };
    } catch (error) {
      if (!nameTaken(error)) throw error;
    }
    // Registered concurrently: ours only if its ownership says so.
    const raced = await relaycast.getAgent(workspaceKey, name);
    if (raced && isSupportSenderOwnedBy(raced, workspaceId)) return takeBack(relaycast, workspaceKey, workspaceId, raced);
  }
  throw new SupportSenderError("foreign_identity",
    "Every Agent Relay Support sender name in this workspace belongs to an agent Agent Relay did not create.");
}

/**
 * Sends one DM as the workspace's Agent Relay Support identity. `authorized`
 * runs last, inside the lock, after token acquisition and immediately before
 * the send, so access revoked during either never gets a DM; null then. It is
 * given the lock's transaction: query through it, never a second connection.
 */
export async function sendAsSupport(
  deps: { database: Database; relaycast: Relaycast; gateOnly: boolean },
  workspace: { id: string; relaycastApiKey: string },
  input: { to: string; address: string; text: string; idempotencyKey: string },
  authorized: (tx: SqlExecutor) => Promise<boolean>,
): Promise<{ from: string } | null> {
  return withLock(deps.database, supportSenderLockKey(workspace.id), async (tx) => {
    const sender = await acquireToken(deps.relaycast, workspace.relaycastApiKey, workspace.id, deps.gateOnly);
    if (!(await authorized(tx))) return null;
    await deps.relaycast.sendDirectMessage({ token: sender.token, ...input });
    return { from: sender.name };
  });
}
