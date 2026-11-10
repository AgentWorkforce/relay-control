import { createHash } from "node:crypto";
import { decryptSecret, encryptSecret, type EncryptionKeyring } from "../crypto.js";
import type { Database, SqlExecutor } from "../database.js";
import { recordAudit } from "../admin/audit.js";

/** Connection checks ported from Cloud main 8865fe718, not generic API-key storage.
 * Fixed provider origins, no redirects, no provider bodies/errors in public replies.
 * Connecting a key does not assert that Relay binding/history are implemented.
 */
export const REMOTE_AGENT_PROVIDERS = [
  { id: "capy", product: "Capy", docsUrl: "https://capy.ai" },
  { id: "replicas", product: "Replicas", docsUrl: "https://replicas.dev" },
  { id: "devin", product: "Devin", docsUrl: "https://app.devin.ai" },
  { id: "cursor-cloud", product: "Cursor Cloud", docsUrl: "https://cursor.com/dashboard" },
] as const;
export type RemoteAgentId = typeof REMOTE_AGENT_PROVIDERS[number]["id"];
export const isRemoteAgentId = (value: string): value is RemoteAgentId =>
  REMOTE_AGENT_PROVIDERS.some(provider => provider.id === value);
export type ConnectionActor = { userId: string; workspaceId: string; organizationId: string };
export type RemoteConnection = {
  keyHint: string;
  providerAccount: string | null;
  validatedAt: string;
};
export class RemoteAgentError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}
type ConnectionRow = {
  provider: RemoteAgentId;
  key_hint: string;
  provider_account: string | null;
  validated_at: Date | string;
};
const view = (row: ConnectionRow): RemoteConnection => ({
  keyHint: row.key_hint,
  providerAccount: row.provider_account,
  validatedAt: new Date(row.validated_at).toISOString(),
});

const MAX_PROVIDER_RESPONSE_BYTES = 64 * 1024;
const invalidProviderResponse = () => new RemoteAgentError(
  502, "invalid_provider_response", "The provider returned an unsupported response.",
);

/** Bound decoded response bytes and every stream read by the existing operation deadline. */
async function providerJson(response: Response, signal: AbortSignal): Promise<unknown> {
  if (!response.body) throw invalidProviderResponse();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    for (;;) {
      let onAbort!: () => void;
      const aborted = new Promise<never>((_resolve, reject) => {
        onAbort = () => reject(signal.reason);
        signal.addEventListener("abort", onAbort, { once: true });
      });
      let chunk: ReadableStreamReadResult<Uint8Array>;
      try {
        signal.throwIfAborted();
        chunk = await Promise.race([reader.read(), aborted]);
      } finally {
        signal.removeEventListener("abort", onAbort);
      }
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      if (bytes > MAX_PROVIDER_RESPONSE_BYTES) throw invalidProviderResponse();
      chunks.push(chunk.value);
    }
    signal.throwIfAborted();
    try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
    catch { throw invalidProviderResponse(); }
  } finally {
    // An uncooperative upstream cancellation must not extend the deadline.
    void reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

export class RemoteAgentConnections {
  constructor(
    readonly database: Database,
    readonly keyring: EncryptionKeyring,
    readonly fetchImpl: typeof fetch = fetch,
  ) {}

  async list(workspaceId: string) {
    const { rows } = await this.database.query<ConnectionRow>(
      "SELECT provider, key_hint, provider_account, validated_at FROM remote_agent_connections WHERE workspace_id = $1",
      [workspaceId],
    );
    return REMOTE_AGENT_PROVIDERS.map(provider => ({
      ...provider,
      connection: rows.find(row => row.provider === provider.id)
        ? view(rows.find(row => row.provider === provider.id)!) : null,
      capabilities: { connectionManagement: true, relayBinding: false, historySync: false },
    }));
  }

  // Recheck under the organization lock used by member removal, including
  // AFTER a slow provider check. URL workspace ids never grant authority.
  private async authorized<T>(actor: ConnectionActor, run: (tx: SqlExecutor) => Promise<T>): Promise<T> {
    return this.database.transaction(async tx => {
      await tx.query("SELECT id FROM organizations WHERE id = $1 FOR SHARE", [actor.organizationId]);
      await tx.query("SELECT pg_advisory_xact_lock(hashtext('remote-agent-connections'), hashtext($1))", [actor.workspaceId]);
      const access = await tx.query<{ role: string }>(
        `SELECT m.role FROM workspaces w JOIN organization_memberships m
           ON m.organization_id = w.organization_id AND m.user_id = $3
          WHERE w.id = $1 AND w.organization_id = $2 FOR SHARE OF m`,
        [actor.workspaceId, actor.organizationId, actor.userId],
      );
      if (!access.rows.some(row => row.role === "owner" || row.role === "admin")) {
        throw new RemoteAgentError(403, "forbidden", "Only current owners and admins can manage provider connections.");
      }
      return run(tx);
    });
  }

  async connect(actor: ConnectionActor, provider: RemoteAgentId, input: Record<string, unknown>): Promise<RemoteConnection> {
    const prior = await this.authorized(actor, async tx => {
      const existing = await tx.query<{ key_ciphertext: string }>(
        "SELECT key_ciphertext FROM remote_agent_connections WHERE workspace_id=$1 AND provider=$2", [actor.workspaceId, provider],
      );
      return existing.rows[0]?.key_ciphertext ?? null;
    });
    const raw = typeof input.key === "string" ? input.key.trim().replace(/^Bearer\s+/i, "") : "";
    const grammar = provider === "capy" ? /^capy_[A-Za-z0-9_-]{16,256}$/
      : provider === "devin" ? /^[A-Za-z0-9_-]{16,256}$/
      : provider === "cursor-cloud" ? /^[!-~]{16,512}$/ : /^[A-Za-z0-9_.-]{16,512}$/;
    if (!grammar.test(raw)) throw new RemoteAgentError(400, "invalid_key", "Paste a complete provider API key.");
    const org = typeof input.orgId === "string" ? input.orgId.trim() : "";
    if (provider === "devin" && !/^[A-Za-z0-9][A-Za-z0-9_-]{2,127}$/.test(org)) {
      throw new RemoteAgentError(400, "invalid_organization", "Enter your Cognition organization ID.");
    }
    const signal = AbortSignal.timeout(15_000);
    const check = async (url: string, init: RequestInit = {}) => {
      try {
        const response = await this.fetchImpl(url, {
          ...init, signal, redirect: "error", cache: "no-store",
          headers: { authorization: `Bearer ${raw}`, accept: "application/json",
            ...(provider === "replicas" ? { "X-Replicas-Api-Version": "2026-10-07" } : {}),
            ...(init.body ? { "content-type": "application/json" } : {}) },
        });
        if (!response.ok) throw new Error("provider_refused");
        const body: unknown = await providerJson(response, signal);
        if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("invalid_provider_response");
        return body as Record<string, unknown>;
      } catch (error) {
        if (error instanceof RemoteAgentError) throw error;
        throw new RemoteAgentError(502, "credential_check_failed", "The provider could not validate this key. Check its permissions and try again.");
      }
    };
    let account: string | null = null;
    if (provider === "capy") {
      const result = await check("https://api.capy.ai/api/v1/projects");
      if (!Array.isArray(result.items)) throw new RemoteAgentError(502, "invalid_provider_response", "Capy returned an unsupported project list.");
    } else if (provider === "replicas") {
      const result = await check("https://api.replicas.dev/v1/whoami");
      const organization = result.organization as { id?: unknown } | null;
      if (typeof organization?.id !== "string" || !organization.id || organization.id.length > 128) {
        throw new RemoteAgentError(502, "invalid_provider_response", "Replicas did not confirm the key's organization.");
      }
      account = organization.id;
    } else if (provider === "devin") {
      const base = `https://api.devin.ai/v3/organizations/${encodeURIComponent(org)}`;
      const result = await check(`${base}/sessions?first=1`);
      if (!Array.isArray(result.items)) throw new RemoteAgentError(502, "invalid_provider_response", "Devin returned an unsupported session list.");
      // Hosted Cloud's zero-session scope probe: prove ManageOrgSessions
      // without writing into a real session. Read-only keys cannot connect.
      let response: Response;
      try {
        response = await this.fetchImpl(`${base}/sessions/devin-00000000000000000000000000000000/messages`, {
          method: "POST", signal, redirect: "error", cache: "no-store",
          headers: { authorization: `Bearer ${raw}`, "content-type": "application/json" },
          body: JSON.stringify({ message: "agent relay connection check" }),
        });
      } catch {
        throw new RemoteAgentError(502, "credential_check_failed", "Devin could not confirm the key's session-management permission.");
      }
      if (response.status !== 404 && !response.ok) throw new RemoteAgentError(502, "credential_check_failed", "Devin could not confirm the key's session-management permission.");
      // The status is sufficient; cleanup must not extend the validation deadline.
      void response.body?.cancel().catch(() => undefined);
      account = org;
    } else {
      const result = await check("https://api.cursor.com/v1/me");
      if (typeof result.apiKeyName !== "string" || !result.apiKeyName || result.apiKeyName.length > 255
        || typeof result.createdAt !== "string" || !result.createdAt || result.createdAt.length > 128
        || (result.userId !== undefined && (!Number.isSafeInteger(result.userId) || (result.userId as number) < 0))) {
        throw new RemoteAgentError(502, "invalid_provider_response", "Cursor did not confirm the key's identity.");
      }
      account = createHash("sha256").update(JSON.stringify([
        "cursor-cloud-principal:v1", typeof result.userId === "number" ? "user" : "service_account",
        result.userId ?? null, result.apiKeyName, result.createdAt,
      ])).digest("hex");
    }
    return this.authorized(actor, async tx => {
      const existing = await tx.query<{ provider_account: string | null; key_ciphertext: string }>(
        "SELECT provider_account,key_ciphertext FROM remote_agent_connections WHERE workspace_id=$1 AND provider=$2 FOR UPDATE",
        [actor.workspaceId, provider],
      );
      if ((existing.rows[0]?.key_ciphertext ?? null) !== prior) {
        throw new RemoteAgentError(409, "connection_changed", "This connection changed while the provider was being checked. Refresh settings and try again.");
      }
      if (existing.rows[0] && existing.rows[0].provider_account !== account) {
        throw new RemoteAgentError(409, "provider_account_changed", "Disconnect this provider before connecting a different account.");
      }
      const saved = await tx.query<ConnectionRow>(
        `INSERT INTO remote_agent_connections(workspace_id,provider,key_ciphertext,key_hint,provider_account,created_by_user_id)
          VALUES($1,$2,$3,$4,$5,$6)
          ON CONFLICT(workspace_id,provider) DO UPDATE SET key_ciphertext=EXCLUDED.key_ciphertext,
            key_hint=EXCLUDED.key_hint,provider_account=EXCLUDED.provider_account,
            created_by_user_id=EXCLUDED.created_by_user_id,validated_at=now()
          RETURNING provider,key_hint,provider_account,validated_at`,
        [actor.workspaceId, provider, encryptSecret(raw, this.keyring.active), `…${raw.slice(-4)}`, account, actor.userId],
      );
      await recordAudit(tx, { workspaceId: actor.workspaceId, organizationId: actor.organizationId,
        actor: { kind: "user", userId: actor.userId }, action: "remote_agent.connect", target: provider });
      return view(saved.rows[0]!);
    });
  }

  async disconnect(actor: ConnectionActor, provider: RemoteAgentId): Promise<void> {
    await this.authorized(actor, async tx => {
      await tx.query("DELETE FROM remote_agent_connections WHERE workspace_id=$1 AND provider=$2", [actor.workspaceId, provider]);
      await recordAudit(tx, { workspaceId: actor.workspaceId, organizationId: actor.organizationId,
        actor: { kind: "user", userId: actor.userId }, action: "remote_agent.disconnect", target: provider });
    });
  }

  /** Server-side only. No route ever returns keys or encrypted envelopes. */
  async keyFor(workspaceId: string, provider: RemoteAgentId): Promise<string | null> {
    const result = await this.database.query<{ key_ciphertext: string }>(
      "SELECT key_ciphertext FROM remote_agent_connections WHERE workspace_id=$1 AND provider=$2", [workspaceId, provider],
    );
    return result.rows[0] ? decryptSecret(result.rows[0].key_ciphertext, this.keyring) : null;
  }
}
