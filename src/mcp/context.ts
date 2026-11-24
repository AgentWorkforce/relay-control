import type { CursorCloudDeps } from "./cursor-cloud.js";
import type { MemoryPolicy } from "@agent-relay/spawn-placement";
import type { CapyBindings } from "../capy/bindings.js";
import type { AmpDeps } from "../amp/service.js";
import type { ReplicasDeps } from "../replicas/service.js";
import type { AgentLinkDeps } from "../events-shim/agent-link.js";
import type { FactoryMcpDeps } from "../factory/mcp-tools.js";
import type { SelfhostConfig } from "../config.js";
import { ReadCursorExpiredError, UpstreamError } from "../relayhistory.js";
import { readWorkspaceHistory } from "../sessions/history.js";
import { accessViaSessionRead, readViaSessionRead } from "./session-read-reader.js";
import type { AccessDeps } from "../sessions/access.js";
import { DESKTOP_MCP_SCOPE, DESKTOP_MCP_TOKEN } from "../auth/desktop-mcp-credentials.js";
import { mcpReaderMarker } from "../session-read.js";
import { MCP_HISTORY_SCOPE } from "./oauth/protocol.js";
import type { EncryptionKeyring } from "../crypto.js";
import type { Database, SqlExecutor } from "../database.js";
import type { RelaycastClient, RosterAgent, PresenceRow } from "../messaging/relaycast.js";
import type { ProviderStatus } from "../providers/registry.js";
import type { Principal } from "../store.js";
import type { McpAuthMode, WorkspaceRole } from "./catalog.js";
import type { DesktopCallContext } from "./desktop-call.js";
import type { McpOAuthConnection } from "./oauth/admission.js";
import type { CustomerSupportConnection } from "./customer-support.js";
import type { GrokRoutines } from "./grok-routines.js";
import type { AgentRules } from "../agent-rules/service.js";
import type { RelayLaunchCheck } from "./relay-launch-check.js";

export type McpWorkspace = {
  id: string;
  organizationId: string;
  name: string;
  relaycastWorkspaceId: string;
  relaycastApiKey: string;
  role: Principal["role"];
};

export type McpMember = { userId: string; email: string; name: string | null };

/** Everything one MCP request's tools may use. Built after admission. */
export type McpContext = {
  principal: Principal;
  workspace: McpWorkspace;
  authMode: McpAuthMode;
  role: WorkspaceRole;
  /** Site origin citations link to (the dashboard or public origin the request arrived on). */
  origin: string;
  /** The URL this request was served at. */
  endpointUrl: string;
  desktopCall: DesktopCallContext;
  /** Present only after the MCP-only OAuth resolver admits its exact resource. */
  oauth?: McpOAuthConnection;
  /**
   * Present only when a workspace agent identity token was admitted
   * (authMode "agent_identity"): the identity the Relay tools act as. The
   * principal's userId is then this identity's id, never a person's.
   */
  agentIdentity?: { id: string; name: string };
  grokRoutines?: GrokRoutines;
  /** The rules source for get_agent_rules (docs/agent-rules.md); absent for staff read grants. */
  agentRules?: AgentRules;
  /** Cursor cloud agent runs (./cursor-cloud.ts); present only for OAuth contexts when the feature is on. */
  cursorCloud?: CursorCloudDeps;
  customerSupport?: CustomerSupportConnection;
  /** GET a workspace-scoped RelayHistory path (with its query); throws SharedSessionsToolError. */
  readHistory: (path: string, options?: { timeoutMessage?: string }) => Promise<unknown>;
  /**
   * Set only when session reads follow per-session access (the reader-kind
   * mint setting): list_team_activity then shows a roster session binding
   * only once `readHistory` proved the session readable ("probe"), or shows
   * none ("none") for a caller `readHistory` would refuse. Absent, bindings
   * are shown as declared.
   */
  sessionBindings?: "probe" | "none";
  /** Read `@name` tokens in search text as agent filters. */
  agentTokens?: boolean;
  members: () => Promise<McpMember[]>;
  /** The provider catalog with this build's runtime state, for describe_capabilities. */
  providers: () => Promise<ProviderStatus[]>;
  relaycast: {
    /** `signal`, when given, aborts the read (list_team_activity bounds it). */
    listAgents: (status: "active" | "all", options?: { signal?: AbortSignal }) => Promise<RosterAgent[]>;
    listPresence: (options?: { signal?: AbortSignal }) => Promise<PresenceRow[]>;
  };
  /** relay_messaging: the participant store, its key envelope, and the Relaycast client. */
  relay: {
    database: Database;
    keyring: EncryptionKeyring;
    client: RelaycastClient;
    /** The Mcp-Session-Id header, when the client sent one. */
    sessionId: string | undefined;
    /** Relaycast's public base URL; agent cards name `<it>/a2a/rpc` as their A2A endpoint. */
    relaycastPublicUrl: string;
    /**
     * SELFHOST_RELAYGATE_PUBLIC_URL, when set (a gate-only install): agent
     * launches then mint a one-time relay launch credential.
     */
    relaygatePublicUrl?: string;
    /** Gate-only installs only: relaygate's pre-spawn POST /v1/check (./relay-launch-check.ts). */
    launchCheck?: RelayLaunchCheck;
    /** The spawn memory policy (docs/specs/spawn-placement-memory.md); absent means the defaults in observe. */
    spawnMemoryPolicy?: MemoryPolicy;
    /**
     * Gate-only installs: the Relaycast client bound to relaygate's origin;
     * desktop identities hold rg_ tokens that only relaygate accepts.
     */
    gateClient?: RelaycastClient;
  };
  /** Amp control (SELFHOST_AMP_ENABLED); absent when the feature is off. */
  amp?: AmpDeps;
  /** Replicas agents (SELFHOST_REPLICAS_ENABLED); absent when the feature is off. */
  replicas?: ReplicasDeps;
  /** Webhook inbox links to bound agents (events_shim feature, person connections only); absent otherwise. */
  webhookInbox?: AgentLinkDeps;
  /** Agent launch tools (SELFHOST_FEATURES launch); false or absent when the feature is off. */
  launch?: boolean;
  /** Factory sessions (SELFHOST_FACTORY_ENABLED); absent when the feature is off. */
  factory?: FactoryMcpDeps;
  /**
   * Session access management (./session-access.ts), bound to this person.
   * Present only on a relaygate read path (sessionAccessConfigured) for a
   * person's own exchanged session with rth:read; see sessionAccessDeps.
   */
  sessionAccess?: AccessDeps;
  /** Internal native send resolver; absent until a complete Capy module is mounted. */
  capy?: Pick<CapyBindings, "agentFor">;
  /** Explicit exact-grant reply permits; never the native resolver or a persona pin. */
  capyPermits?: Pick<CapyBindings, "bindGrant" | "unbindGrant" | "agentForGrant">;
  /** Where shared-session read calls are audited (src/mcp/read-audit.ts); absent writes nothing. */
  readAudit?: {
    database: SqlExecutor;
    now?: () => Date;
    /** JSON-RPC request ids whose read a tool handler recorded (validation failures are recorded after). */
    handled?: Set<string>;
  };
};

export class SharedSessionsToolError extends Error {
  constructor(readonly publicMessage: string) {
    super(publicMessage);
    this.name = "SharedSessionsToolError";
  }
}

/** The read API answered 501 for this view; `reason` is its code (see unsupportedReason). */
export class BackendUnsupportedError extends SharedSessionsToolError {
  constructor(readonly reason: string) {
    super("The selected backend does not support this view (unsupported_by_backend).");
    this.name = "BackendUnsupportedError";
  }
}

export const UNAVAILABLE_MESSAGE = "Shared session history is temporarily unavailable. Please try again.";
const ATTESTATION_MESSAGE =
  "Workspace-scoped shared session history is not available yet. Please try again later.";

function historyReadGrant(principal: Principal, callerToken: string) {
  // A staff read grant (sh_sr_) was admitted by its own fence and pinned to
  // this workspace; RelayHistory introspects it at Control like sh_at_.
  const staffGrant = callerToken.startsWith("sh_sr_");
  // A Desktop provider grant (cld_at_, mcp:desktop) was admitted by
  // DesktopMcpCredentials.resolve, which re-checks its lease, verified
  // parent and membership on every request. It authenticates nowhere else,
  // so it reads through the workspace reader, never the session-read hop.
  const desktopGrant = DESKTOP_MCP_TOKEN.test(callerToken) && principal.scopes.includes(DESKTOP_MCP_SCOPE);
  // An OAuth connection reads only with the opt-in relay:history scope its
  // person approved as a separate consent line; relay:mcp alone never does.
  const oauthToken = callerToken.startsWith("mcp_at_");
  const oauthGrant = oauthToken && principal.scopes.includes(MCP_HISTORY_SCOPE);
  const nativeGrant = principal.scopes.includes("rth:read") && (callerToken.startsWith("sh_at_") || staffGrant || desktopGrant);
  return { staffGrant, desktopGrant, oauthToken, oauthGrant, nativeGrant };
}

/**
 * True when historyReader would read for this caller at all: every such read
 * carries a read token for this person (its own, or one minted for it).
 */
export function historyReadable(principal: Principal, callerToken: string): boolean {
  const { oauthGrant, nativeGrant } = historyReadGrant(principal, callerToken);
  return !principal.pendingHandoff && (nativeGrant || oauthGrant);
}

/**
 * Reads through the dashboard's workspace-scoped reader: a History
 * `rth:read` session minted for exactly this {user, organization, workspace}
 * or the caller token for an explicitly configured direct list/turns reader,
 * `workspace=` forced on every query, and the response's workspace
 * attestation header required. Failures become public tool messages only.
 *
 * Who may read: an exchanged user session (`sh_at_`) or a staff or Desktop
 * grant, each with `rth:read`; or an OAuth connection (`mcp_at_`) whose
 * admitted scopes include the opt-in `relay:history`. Admission narrows those
 * scopes to the live grant on every request, so revoking the connection or
 * dropping the scope from its grant ends reads. An OAuth read is minted
 * server-side (reader kind mcp) through the workspace reader in both read API
 * modes; the OAuth token is never forwarded and never gains `rth:read`.
 */
export function historyReader(
  config: SelfhostConfig,
  principal: Principal,
  workspace: McpWorkspace,
  callerToken: string,
) {
  const identity = {
    userId: principal.userId,
    organizationId: workspace.organizationId,
    workspaceId: workspace.id,
    role: workspace.role,
    callerToken,
    // Every MCP read is on the person's behalf, in both read modes.
    readerKind: "mcp" as const,
  };
  // Proves the flagged mode's hop to the public session-read route is this
  // reader (see readerKindOf). Derived from the secret; never logged.
  const marker = mcpReaderMarker(config.sessionReadApi.secret);
  return async (path: string, options: { timeoutMessage?: string } = {}): Promise<unknown> => {
    // MCP admission authenticates the person; content reads additionally need
    // the issue-time read scope. Neither a handoff nor a service credential
    // may be promoted by the reader's Control handoff.
    const { staffGrant, desktopGrant, oauthToken, oauthGrant } = historyReadGrant(principal, callerToken);
    // A pending handoff is refused at OAuth admission too; checked here again.
    if (!historyReadable(principal, callerToken)) {
      throw new SharedSessionsToolError(oauthToken && !principal.pendingHandoff
        ? "Session reads need the relay:history scope on this OAuth connection."
        : "Session reads require an exchanged user session with rth:read.");
    }
    const url = new URL(path, "https://relayhistory.invalid");
    try {
      // The per-user session-read route is a dashboard route that refuses a
      // grant (staff or Desktop provider) by shape, so a grant always reads
      // through the workspace reader. So does OAuth: that hop presents the
      // caller token to Control, and an mcp_at_ token must never leave here.
      const result = (staffGrant || desktopGrant || oauthGrant ? null : await readViaSessionRead(config, identity, url.pathname, url.searchParams, marker))
        ?? await readWorkspaceHistory(config, identity, url.pathname, url.searchParams);
      if (result.status === "unsupported") {
        throw new BackendUnsupportedError(result.reason);
      }
      if (result.status !== "ok") throw new SharedSessionsToolError(UNAVAILABLE_MESSAGE);
      return result.body;
    } catch (error) {
      if (error instanceof SharedSessionsToolError) throw error;
      if (error instanceof ReadCursorExpiredError) throw new SharedSessionsToolError(error.message);
      if (error instanceof UpstreamError) {
        if (error.status === 401) {
          throw new SharedSessionsToolError("Reader credentials were refused. Reauthenticate before reading again.");
        }
        if (error.message === "RelayHistory did not attest the workspace") {
          console.error("[selfhost-mcp] History workspace attestation failed");
          throw new SharedSessionsToolError(ATTESTATION_MESSAGE);
        }
        if (options.timeoutMessage && error.status === 504) throw new SharedSessionsToolError(options.timeoutMessage);
        console.error("[selfhost-mcp] History read failed", { stage: error.stage, upstreamStatus: error.status ?? null });
      }
      throw new SharedSessionsToolError(UNAVAILABLE_MESSAGE);
    }
  };
}

/**
 * Session access calls as this person: the per-person session-read hop
 * (reader kind `mcp`), never the workspace reader, a service token or the
 * caller's own token upstream. The MCP route offers this only to an exchanged
 * user session (`sh_at_`) with rth:read and no pending handoff; an OAuth
 * connection, a Desktop provider credential, a staff read grant and an agent
 * identity never get it.
 */
export function sessionAccessDeps(
  config: SelfhostConfig,
  principal: Principal,
  workspace: McpWorkspace,
  callerToken: string,
  members: () => Promise<McpMember[]>,
): AccessDeps {
  const identity = {
    userId: principal.userId,
    organizationId: workspace.organizationId,
    workspaceId: workspace.id,
    role: workspace.role,
    callerToken,
    readerKind: "mcp" as const,
  };
  const marker = mcpReaderMarker(config.sessionReadApi.secret);
  return { send: request => accessViaSessionRead(config, identity, request, marker), members };
}

export function toolError(error: unknown, options: { correlationId?: string } = {}) {
  const message = error instanceof SharedSessionsToolError ? error.publicMessage : UNAVAILABLE_MESSAGE;
  return {
    isError: true,
    content: [{ type: "text" as const, text: options.correlationId
      ? `${message}\ncorrelation_id: ${options.correlationId}` : message }],
  };
}

/** `<origin>/dashboard/sessions/<id>?source=<source>`, the dashboard's session page. */
export function sessionCitation(origin: string, sessionId: string, source?: string): string {
  const url = new URL(`/dashboard/sessions/${encodeURIComponent(sessionId)}`, origin);
  if (source) url.searchParams.set("source", source);
  return url.toString();
}
