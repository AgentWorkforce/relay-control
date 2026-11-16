import { STATUS_CODES, type IncomingMessage } from "node:http";
import type { Duplex } from "node:stream";
import { WebSocket, WebSocketServer, type RawData } from "ws";
import type { ApiTokenStore, RelayNodePrincipal } from "../admin/api-tokens.js";
import { recordAudit } from "../admin/audit.js";
import type { Database } from "../database.js";
import type { RelayLaunchCredentials } from "../mcp/relay-launch-credentials.js";
import type { RelayNodeCredentials } from "./credentials.js";

/**
 * Relay node socket bridge for gate-only installs (SELFHOST_RELAYGATE_PUBLIC_URL
 * set; docs/relay-node-credential.md, "Gate-only installs").
 *
 * A relay node that enrolled through the /relay-node/v1 broker never holds its
 * Relaycast node token: Control does. The node opens GET /relay-node/v1/ws with
 * its `relay-node` workspace API token as a Bearer header; Control opens
 * Relaycast's node socket with the stored node token and relays frames in both
 * directions unchanged, except:
 *
 * - Relaycast -> node `action.invoke` for a `spawn:` action whose invocation
 *   is a launch journaled in relay_spawns for this node: the launch's one-time
 *   credential is added as `input.launch_credential`.
 * - Relaycast -> node `deliver` frames are dropped: launched agents read their
 *   messages through relaygate, not through the node.
 *
 * Upgrade refusals: 404 (not gate-only, or another path), 401 (no live
 * relay-node token), 403 (node not enrolled through this Control, or its
 * stored token unreadable: re-enrol), 429 (rate limited), 503 (bridge full).
 *
 * Frames and the URLs and headers of both sockets carry credentials: never
 * log them.
 */
export const RELAY_NODE_SOCKET_PATH = "/relay-node/v1/ws";
export const RELAY_NODE_SOCKET_MAX_PAYLOAD = 4 * 1024 * 1024;
/** Client frames held while the upstream socket opens. */
export const RELAY_NODE_SOCKET_MAX_PENDING = 100;
export const RELAY_NODE_HEARTBEAT_THROTTLE_MS = 30_000;
const UPSTREAM_HANDSHAKE_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_CONNECTIONS = 1_000;
/** How long a spawn invocation waits for its launch row to record the invocation id. */
const DEFAULT_SPAWN_LOOKUP_WAIT_MS = 2_000;
const SPAWN_LOOKUP_POLL_MS = 100;

export type RelayNodeSocketDeps = {
  apiTokens: Pick<ApiTokenStore, "authenticateRelayNode">;
  nodeCredentials: Pick<RelayNodeCredentials, "find" | "heartbeat">;
  launchCredentials: Pick<RelayLaunchCredentials, "sealedFor">;
  relaycastUrl: string;
  database: Database;
  /** False when the token is over its rate limit. */
  rateLimit?: (key: string) => boolean;
  /** Internal failures only; never frames, URLs or tokens. */
  log?: (message: string, fields: Record<string, unknown>) => void;
  maxConnections?: number;
  spawnLookupWaitMs?: number;
  now?: () => number;
};

export type RelayNodeSocketBridge = {
  handleUpgrade(request: IncomingMessage, socket: Duplex, head: Buffer): void;
  close(): void;
};

/** Answers an upgrade request with a plain HTTP status and ends the socket. */
export function refuseUpgrade(socket: Duplex, status: number): void {
  if (socket.destroyed) return;
  const reason = STATUS_CODES[status] ?? "Error";
  socket.end(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`);
}

/** Close codes a peer may send: 1005/1006/1015 and unknown codes become 1011. */
export function sanitizeCloseCode(code: number): number {
  const valid = (code >= 1000 && code <= 1014 && code !== 1004 && code !== 1005 && code !== 1006)
    || (code >= 3000 && code <= 4999);
  return valid ? code : 1011;
}

function bearer(request: IncomingMessage): string | null {
  const header = request.headers.authorization;
  if (typeof header !== "string") return null;
  const match = /^Bearer\s+(\S+)\s*$/i.exec(header);
  return match ? match[1]! : null;
}

function upstreamUrl(relaycastUrl: string, token: string): string {
  const url = new URL(`${relaycastUrl.replace(/\/+$/, "")}/v1/node/ws`);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  url.searchParams.set("token", token);
  return url.toString();
}

function frameObject(data: RawData, isBinary: boolean): Record<string, unknown> | null {
  if (isBinary) return null;
  try {
    const parsed: unknown = JSON.parse(Buffer.isBuffer(data) ? data.toString("utf8") : Buffer.concat(
      Array.isArray(data) ? data : [Buffer.from(data)]).toString("utf8"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export function createRelayNodeSocketBridge(deps: RelayNodeSocketDeps): RelayNodeSocketBridge {
  const wss = new WebSocketServer({ noServer: true, maxPayload: RELAY_NODE_SOCKET_MAX_PAYLOAD });
  const now = deps.now ?? Date.now;
  const maxConnections = deps.maxConnections ?? DEFAULT_MAX_CONNECTIONS;
  const spawnLookupWaitMs = deps.spawnLookupWaitMs ?? DEFAULT_SPAWN_LOOKUP_WAIT_MS;
  const live = new Set<{ client: WebSocket; upstream: WebSocket }>();
  let pendingUpgrades = 0;
  let closed = false;

  const audit = (principal: RelayNodePrincipal, action: string, target: string) =>
    recordAudit(deps.database, {
      organizationId: principal.organizationId,
      workspaceId: principal.workspaceId,
      actor: { kind: "service", subject: `relay-node:${principal.tokenId}` },
      action,
      target,
    }).catch((error: unknown) => deps.log?.("relay node socket audit failed", {
      action, error: error instanceof Error ? error.name : "unknown",
    }));

  /** The launch journaled for this invocation on this node, if any. */
  async function launchFor(principal: RelayNodePrincipal, invocationId: string): Promise<string | null> {
    const find = async () => (await deps.database.query<{ id: string }>(
      `SELECT s.id FROM relay_spawns s
         JOIN relay_launch_credentials c ON c.spawn_id = s.id
        WHERE s.workspace_id = $1 AND s.invocation_id = $2 AND c.node_name = $3`,
      [principal.workspaceId, invocationId, principal.nodeName],
    )).rows[0]?.id ?? null;
    let found = await find();
    if (found) return found;
    // Relaycast can dispatch the invocation before Control records its id on
    // the launch row. Wait briefly, only while such a launch is in flight.
    const deadline = now() + spawnLookupWaitMs;
    while (!found && now() < deadline) {
      const inFlight = await deps.database.query(
        `SELECT 1 FROM relay_spawns s
           JOIN relay_launch_credentials c ON c.spawn_id = s.id
          WHERE s.workspace_id = $1 AND s.state = 'reserved' AND s.invocation_id IS NULL
            AND c.node_name = $2 AND c.redeemed_at IS NULL AND c.expires_at > now()
          LIMIT 1`,
        [principal.workspaceId, principal.nodeName],
      );
      if (inFlight.rows.length === 0) return null;
      await sleep(SPAWN_LOOKUP_POLL_MS);
      found = await find();
    }
    return found;
  }

  /** Relaycast -> node: the frame to forward, or null to drop it. */
  async function toNode(principal: RelayNodePrincipal, data: RawData, isBinary: boolean): Promise<string | RawData | null> {
    const frame = frameObject(data, isBinary);
    if (!frame) return data;
    if (frame.type === "deliver") return null;
    if (frame.type !== "action.invoke" || typeof frame.invocation_id !== "string"
      || typeof frame.action !== "string" || !frame.action.startsWith("spawn:")) return data;
    const spawnId = await launchFor(principal, frame.invocation_id);
    if (!spawnId) return data;
    const credential = await deps.launchCredentials.sealedFor(spawnId);
    if (!credential) return data;
    const input = frame.input && typeof frame.input === "object" && !Array.isArray(frame.input)
      ? frame.input as Record<string, unknown> : {};
    void audit(principal, "relay_node.launch_credential.attached", `node=${principal.nodeName} spawn=${spawnId}`);
    return JSON.stringify({ ...frame, input: { ...input, launch_credential: credential } });
  }

  function bridge(client: WebSocket, principal: RelayNodePrincipal, token: string): void {
    const upstream = new WebSocket(upstreamUrl(deps.relaycastUrl, token), {
      maxPayload: RELAY_NODE_SOCKET_MAX_PAYLOAD,
      handshakeTimeout: UPSTREAM_HANDSHAKE_TIMEOUT_MS,
      followRedirects: false,
    });
    const entry = { client, upstream };
    live.add(entry);
    void audit(principal, "relay_node.socket.opened", `node=${principal.nodeName}`);
    const pending: Array<{ data: RawData; isBinary: boolean }> = [];
    let lastHeartbeat = -Infinity;
    let ended = false;
    let toNodeChain: Promise<void> = Promise.resolve();

    const end = (code: number, reason?: Buffer) => {
      if (ended) return;
      ended = true;
      live.delete(entry);
      const safe = sanitizeCloseCode(code);
      const text = reason && reason.length <= 123 ? reason.toString("utf8") : undefined;
      for (const side of [client, upstream]) {
        if (side.readyState === WebSocket.OPEN) side.close(safe, text);
        else if (side.readyState === WebSocket.CONNECTING) side.terminate();
      }
      void audit(principal, "relay_node.socket.closed", `node=${principal.nodeName} code=${safe}`);
    };

    client.on("message", (data, isBinary) => {
      if (ended) return;
      const frame = frameObject(data, isBinary);
      if (frame && (frame.type === "node.heartbeat" || frame.type === "node.register")
        && now() - lastHeartbeat >= RELAY_NODE_HEARTBEAT_THROTTLE_MS) {
        lastHeartbeat = now();
        deps.nodeCredentials.heartbeat(principal).catch((error: unknown) =>
          deps.log?.("relay node heartbeat update failed", { error: error instanceof Error ? error.name : "unknown" }));
      }
      if (upstream.readyState === WebSocket.OPEN) {
        upstream.send(data, { binary: isBinary });
        return;
      }
      if (pending.length >= RELAY_NODE_SOCKET_MAX_PENDING) {
        end(1013);
        return;
      }
      pending.push({ data, isBinary });
    });
    upstream.on("open", () => {
      for (const frame of pending.splice(0)) upstream.send(frame.data, { binary: frame.isBinary });
    });
    upstream.on("message", (data, isBinary) => {
      toNodeChain = toNodeChain.then(async () => {
        if (ended) return;
        let forward: string | RawData | null;
        try {
          forward = await toNode(principal, data, isBinary);
        } catch (error) {
          // A failed lookup never edits the frame; it still reaches the node.
          deps.log?.("relay node launch credential lookup failed", { error: error instanceof Error ? error.name : "unknown" });
          forward = data;
        }
        if (forward === null || ended || client.readyState !== WebSocket.OPEN) return;
        client.send(forward, { binary: typeof forward === "string" ? false : isBinary });
      });
    });
    client.on("close", (code, reason) => end(code, reason));
    upstream.on("close", (code, reason) => {
      // Let frames already received from Relaycast reach the node first.
      void toNodeChain.then(() => end(code, reason));
    });
    client.on("error", () => end(1011));
    upstream.on("error", () => end(1011));
  }

  async function upgrade(request: IncomingMessage, socket: Duplex, head: Buffer): Promise<void> {
    const token = bearer(request);
    const principal = token ? await deps.apiTokens.authenticateRelayNode(token) : null;
    if (!principal) return refuseUpgrade(socket, 401);
    if (deps.rateLimit && !deps.rateLimit(`relay-node:${principal.tokenId}`)) return refuseUpgrade(socket, 429);
    if (live.size + pendingUpgrades > maxConnections) return refuseUpgrade(socket, 503);
    const stored = await deps.nodeCredentials.find({ workspaceId: principal.workspaceId, nodeName: principal.nodeName });
    if (!stored || !stored.token) return refuseUpgrade(socket, 403);
    if (closed || socket.destroyed) return refuseUpgrade(socket, 503);
    const nodeToken = stored.token;
    wss.handleUpgrade(request, socket, head, (client) => bridge(client, principal, nodeToken));
  }

  return {
    handleUpgrade(request, socket, head) {
      // Errors on a socket being answered must not crash the process.
      const ignore = () => undefined;
      socket.on("error", ignore);
      let path: string;
      try {
        path = new URL(request.url ?? "/", "http://relay-node.invalid").pathname;
      } catch {
        path = "";
      }
      if (closed || path !== RELAY_NODE_SOCKET_PATH || request.method !== "GET") {
        refuseUpgrade(socket, 404);
        return;
      }
      pendingUpgrades += 1;
      upgrade(request, socket, head)
        .catch((error: unknown) => {
          deps.log?.("relay node socket upgrade failed", { error: error instanceof Error ? error.name : "unknown" });
          refuseUpgrade(socket, 503);
        })
        .finally(() => { pendingUpgrades -= 1; });
    },
    close() {
      closed = true;
      for (const entry of [...live]) {
        entry.client.terminate();
        entry.upstream.terminate();
      }
      live.clear();
      wss.close();
    },
  };
}
