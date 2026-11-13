import { sha256Hex } from "@agent-relay/events-shim";
import { decryptSecret, encryptSecret, type EncryptionKeyring } from "../crypto.js";
import type { Database } from "../database.js";

const DAY_MS = 24 * 60 * 60 * 1000;

/** How long an inbox's temporary Agent Relay workspace lives without activity (the inbox's own idle expiry). */
export const TEMP_WORKSPACE_SECONDS = 7 * 24 * 60 * 60;

/** Activity pushes the deadline back once it is nearer than this: at most about once a day. */
const EXTEND_WHEN_LEFT_MS = 6 * DAY_MS;

/** A stored workspace this close to its deadline is replaced rather than handed out. */
const REISSUE_WHEN_LEFT_MS = 60 * 60 * 1000;

const TOKEN = /^esm_[A-Za-z0-9_-]{16,128}$/;

export type TempWorkspaceDeps = {
  database: Database;
  keyring: EncryptionKeyring;
  /** Relaycast's internal origin (RELAYCAST_URL). */
  relaycastUrl: string;
  /** RELAYCAST_INTERNAL_SECRET; without it no temporary workspace is made. */
  internalSecret: string | null;
  fetchImpl?: typeof fetch;
  now?: () => Date;
};

export type TempWorkspace = {
  workspaceId: string;
  workspaceKey: string;
  expiresAt: string;
};

/** Relaycast refused or could not be reached; the route answers 503 with retry-after. */
export class TempWorkspaceError extends Error {
  constructor(message: string, readonly configured = true) {
    super(message);
    this.name = "TempWorkspaceError";
  }
}

type Row = {
  id: string;
  relay_workspace_id: string | null;
  relay_workspace_key_ciphertext: string | null;
  relay_workspace_expires_at: Date | string | null;
};

const at = (value: Date | string) => (value instanceof Date ? value : new Date(value));

function call(deps: TempWorkspaceDeps): typeof fetch {
  return (input, init) => (deps.fetchImpl ? deps.fetchImpl(input, init) : globalThis.fetch(input, init));
}

/**
 * The inbox's temporary Agent Relay workspace, made on first use through
 * Relaycast's internal admin API with a {@link TEMP_WORKSPACE_SECONDS}
 * deadline. events-shim runs its standalone core on it when the machine's
 * Agent Relay is not signed in to this control plane. Asking for it is use of
 * the inbox: its last use is refreshed and a deadline under 6 days away moves back.
 *
 * @param mcpToken - The inbox's MCP token (from its MCP URL): the capability.
 * @returns The workspace, or null when there is no such inbox.
 */
export async function inboxTempWorkspace(deps: TempWorkspaceDeps, mcpToken: string): Promise<TempWorkspace | null> {
  if (!TOKEN.test(mcpToken)) return null;
  const now = (deps.now ?? (() => new Date()))();
  const mcpTokenHash = await sha256Hex(mcpToken);
  const found = await deps.database.query<Row>(
    `UPDATE events_shims SET last_used_at = $2 WHERE mcp_token_hash = $1
     RETURNING id, relay_workspace_id, relay_workspace_key_ciphertext, relay_workspace_expires_at`,
    [mcpTokenHash, now],
  );
  const row = found.rows[0];
  if (!row) return null;
  if (!deps.internalSecret) throw new TempWorkspaceError("RELAYCAST_INTERNAL_SECRET is not set", false);
  if (row.relay_workspace_id && row.relay_workspace_key_ciphertext && row.relay_workspace_expires_at) {
    const expiresAt = at(row.relay_workspace_expires_at);
    if (expiresAt.getTime() - now.getTime() > REISSUE_WHEN_LEFT_MS) {
      return {
        workspaceId: row.relay_workspace_id,
        workspaceKey: decryptSecret(row.relay_workspace_key_ciphertext, deps.keyring),
        expiresAt: (await keepAlive(deps, row.id, row.relay_workspace_id, expiresAt, now))?.toISOString()
          ?? expiresAt.toISOString(),
      };
    }
  }

  const minted = await createTempWorkspace(deps, row.id);
  // The row is replaced only while it still holds what was read: of two first
  // calls at once, the first stored wins and the other hands out that one
  // (its own workspace is deleted).
  const stored = await deps.database.query(
    `UPDATE events_shims
        SET relay_workspace_id = $2, relay_workspace_key_ciphertext = $3, relay_workspace_expires_at = $4
      WHERE id = $1 AND relay_workspace_id IS NOT DISTINCT FROM $5
      RETURNING id`,
    [row.id, minted.workspaceId, encryptSecret(minted.workspaceKey, deps.keyring.active), new Date(minted.expiresAt), row.relay_workspace_id],
  );
  if (stored.rows.length > 0) return minted;
  await removeWorkspace(deps, minted.workspaceId);
  return inboxTempWorkspace(deps, mcpToken);
}

/**
 * Activity on an inbox (a post, an agent's MCP call) keeps its temporary
 * workspace alive: once its deadline is under 6 days away it moves back to
 * {@link TEMP_WORKSPACE_SECONDS} from now. Best effort: never throws.
 *
 * @param by - The inbox, by the sha256 of its MCP or webhook token.
 */
export async function keepTempWorkspaceAlive(
  deps: TempWorkspaceDeps,
  by: { mcpTokenHash: string } | { hookTokenHash: string },
): Promise<void> {
  try {
    const now = (deps.now ?? (() => new Date()))();
    const found = await deps.database.query<Row>(
      `SELECT id, relay_workspace_id, relay_workspace_key_ciphertext, relay_workspace_expires_at
         FROM events_shims
        WHERE ${"mcpTokenHash" in by ? "mcp_token_hash" : "hook_token_hash"} = $1
          AND relay_workspace_expires_at > $2 AND relay_workspace_expires_at <= $3`,
      ["mcpTokenHash" in by ? by.mcpTokenHash : by.hookTokenHash, now, new Date(now.getTime() + EXTEND_WHEN_LEFT_MS)],
    );
    const row = found.rows[0];
    if (row?.relay_workspace_id && row.relay_workspace_expires_at) {
      await keepAlive(deps, row.id, row.relay_workspace_id, at(row.relay_workspace_expires_at), now);
    }
  } catch {
    /* Best effort: the next activity tries again. */
  }
}

/** Moves a deadline under 6 days away back to 7 days from now; returns the new deadline, or null when not moved. */
async function keepAlive(deps: TempWorkspaceDeps, shimId: string, workspaceId: string, expiresAt: Date, now: Date): Promise<Date | null> {
  if (!deps.internalSecret || expiresAt.getTime() - now.getTime() > EXTEND_WHEN_LEFT_MS) return null;
  const moved = await setExpiry(deps, workspaceId, TEMP_WORKSPACE_SECONDS).catch(() => null);
  if (!moved) return null;
  await deps.database.query(
    "UPDATE events_shims SET relay_workspace_expires_at = $3 WHERE id = $1 AND relay_workspace_id = $2",
    [shimId, workspaceId, moved],
  );
  return moved;
}

async function createTempWorkspace(deps: TempWorkspaceDeps, shimId: string): Promise<TempWorkspace> {
  const base = deps.relaycastUrl.replace(/\/+$/, "");
  let response: Response;
  try {
    response = await call(deps)(`${base}/internal/workspaces`, {
      method: "POST",
      headers: admin(deps),
      body: JSON.stringify({ name: `webhooks-${shimId.slice(0, 8)}` }),
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    throw new TempWorkspaceError("Relaycast is unreachable");
  }
  const body = await response.json().catch(() => null) as { data?: { workspace_id?: unknown; api_key?: unknown } } | null;
  const workspaceId = body?.data?.workspace_id;
  const workspaceKey = body?.data?.api_key;
  // Never echo the body: it can carry a key.
  if ((response.status !== 201 && response.status !== 200) || typeof workspaceId !== "string" || typeof workspaceKey !== "string") {
    throw new TempWorkspaceError(`Relaycast refused the workspace (HTTP ${response.status})`);
  }
  // The internal create makes a permanent workspace: without a deadline it is not handed out.
  const expiresAt = await setExpiry(deps, workspaceId, TEMP_WORKSPACE_SECONDS).catch(() => null);
  if (!expiresAt) {
    await removeWorkspace(deps, workspaceId);
    throw new TempWorkspaceError("Relaycast cannot set a workspace expiry (it needs POST /internal/workspaces/:id/expiry)");
  }
  return { workspaceId, workspaceKey, expiresAt: expiresAt.toISOString() };
}

async function setExpiry(deps: TempWorkspaceDeps, workspaceId: string, seconds: number): Promise<Date | null> {
  const response = await call(deps)(
    `${deps.relaycastUrl.replace(/\/+$/, "")}/internal/workspaces/${encodeURIComponent(workspaceId)}/expiry`,
    { method: "POST", headers: admin(deps), body: JSON.stringify({ expires_in_seconds: seconds }), signal: AbortSignal.timeout(10_000) },
  );
  const body = await response.json().catch(() => null) as { ok?: boolean; data?: { expires_at?: unknown } } | null;
  return response.ok && body?.ok && typeof body.data?.expires_at === "string" ? new Date(body.data.expires_at) : null;
}

async function removeWorkspace(deps: TempWorkspaceDeps, workspaceId: string): Promise<void> {
  await call(deps)(`${deps.relaycastUrl.replace(/\/+$/, "")}/internal/workspaces/${encodeURIComponent(workspaceId)}`, {
    method: "DELETE",
    headers: admin(deps),
    signal: AbortSignal.timeout(30_000),
  }).catch(() => undefined);
}

function admin(deps: TempWorkspaceDeps): Record<string, string> {
  return {
    authorization: `Bearer ${deps.internalSecret ?? ""}`,
    "content-type": "application/json",
    accept: "application/json",
  };
}
