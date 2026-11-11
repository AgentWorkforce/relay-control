import type { AmpDeps } from "../amp/service.js";
import type { FactoryMcpDeps } from "../factory/mcp-tools.js";
import type { SelfhostConfig } from "../config.js";
import { ReadCursorExpiredError, UpstreamError } from "../relayhistory.js";
import { readWorkspaceHistory } from "../sessions/history.js";
import { readViaSessionRead } from "./session-read-reader.js";
import type { EncryptionKeyring } from "../crypto.js";
import type { Database, SqlExecutor } from "../database.js";
import type { RelaycastClient, RosterAgent, PresenceRow } from "../messaging/relaycast.js";
import type { ProviderStatus } from "../providers/registry.js";
import type { Principal } from "../store.js";
import type { McpAuthMode, WorkspaceRole } from "./catalog.js";
import type { DesktopCallContext } from "./desktop-call.js";
import type { McpOAuthConnection } from "./oauth/admission.js";

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
  /** GET a workspace-scoped RelayHistory path (with its query); throws SharedSessionsToolError. */
  readHistory: (path: string, options?: { timeoutMessage?: string }) => Promise<unknown>;
  /** Read `@name` tokens in search text as agent filters. */
  agentTokens?: boolean;
  members: () => Promise<McpMember[]>;
  /** The provider catalog with this build's runtime state, for describe_capabilities. */
  providers: () => Promise<ProviderStatus[]>;
  relaycast: {
    listAgents: (status: "active" | "all") => Promise<RosterAgent[]>;
    listPresence: () => Promise<PresenceRow[]>;
  };
  /** relay_messaging: the participant store, its key envelope, and the Relaycast client. */
  relay: {
    database: Database;
    keyring: EncryptionKeyring;
    client: RelaycastClient;
    /** The Mcp-Session-Id header, when the client sent one. */
    sessionId: string | undefined;
  };
  /** Amp control (SELFHOST_AMP_ENABLED); absent when the feature is off. */
  amp?: AmpDeps;
  /** Agent launch tools (SELFHOST_FEATURES launch); false or absent when the feature is off. */
  launch?: boolean;
  /** Factory sessions (SELFHOST_FACTORY_ENABLED); absent when the feature is off. */
  factory?: FactoryMcpDeps;
  /** Where shared-session read calls are audited (src/mcp/read-audit.ts); absent writes nothing. */
  readAudit?: { database: SqlExecutor; now?: () => Date };
};

export class SharedSessionsToolError extends Error {
  constructor(readonly publicMessage: string) {
    super(publicMessage);
    this.name = "SharedSessionsToolError";
  }
}

export const UNAVAILABLE_MESSAGE = "Shared session history is temporarily unavailable. Please try again.";
const ATTESTATION_MESSAGE =
  "Workspace-scoped shared session history is not available yet. Please try again later.";

/**
 * Reads through the dashboard's workspace-scoped reader: a History
 * `rth:read` session minted for exactly this {user, organization, workspace}
 * or the caller token for an explicitly configured direct list/turns reader,
 * `workspace=` forced on every query, and the response's workspace
 * attestation header required. Failures become public tool messages only.
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
    callerToken,
  };
  return async (path: string, options: { timeoutMessage?: string } = {}): Promise<unknown> => {
    // MCP admission authenticates the person; content reads additionally need
    // the issue-time read scope. Neither a handoff nor a service credential
    // may be promoted by the reader's Control handoff.
    if (!principal.scopes.includes("rth:read") || principal.pendingHandoff || !callerToken.startsWith("sh_at_")) {
      throw new SharedSessionsToolError("Session reads require an exchanged user session with rth:read.");
    }
    const url = new URL(path, "https://relayhistory.invalid");
    try {
      const result = await readViaSessionRead(config, identity, url.pathname, url.searchParams)
        ?? await readWorkspaceHistory(config, identity, url.pathname, url.searchParams);
      if (result.status === "unsupported") {
        throw new SharedSessionsToolError("The selected backend does not support this view (unsupported_by_backend).");
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
