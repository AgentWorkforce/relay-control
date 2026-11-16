import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import type { McpContext } from "../mcp/context.js";
import {
  bindReplica,
  listEnvironments,
  recoverReplica,
  releaseReplica,
  replicaStatus,
  ReplicasError,
  spawnInput,
  spawnReplica,
  type ReplicasActor,
  type ReplicasDeps,
} from "./service.js";

/**
 * The person-side Replicas tools, ported from the hosted control plane. The
 * acting person is the MCP connection's authenticated principal (admitted
 * with cli:auth; agent and service tokens are refused at admission). No tool
 * takes a user, workspace or role argument, and the service re-reads the
 * owner/admin role from Postgres on every call.
 */
export function registerReplicasTools(server: McpServer, context: McpContext, deps: ReplicasDeps): void {
  const actor: ReplicasActor = {
    userId: context.principal.userId,
    workspaceId: context.workspace.id,
    organizationId: context.workspace.organizationId,
  };
  async function run(work: () => Promise<unknown>) {
    try {
      const data = await work();
      return { ...(data && typeof data === "object" && "provisioning_error" in data ? { isError: true } : {}),
        content: [{ type: "text" as const, text: JSON.stringify(data) }], structuredContent: data as Record<string, unknown> };
    } catch (error) {
      return { isError: true, content: [{ type: "text" as const, text: error instanceof ReplicasError ? error.message
        : "Replicas operation failed or access was refused. Keep the same request id and check its status." }] };
    }
  }
  const annotations = { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: true };
  server.registerTool("list_replicas_environments", { description: "List environments this workspace's connected Replicas account can use. Requires current owner/admin access.",
    inputSchema: {}, annotations: { ...annotations, readOnlyHint: true } },
    () => run(() => listEnvironments(deps, actor)));
  server.registerTool("spawn_replica", { description: "Start a Replicas agent in an environment. Control binds its relay identity, installs its scoped Agent Relay MCP and reply helper and sends the task. The result includes spawn_id; subsequent status reads continue preparation until status is bound. client_request_id makes equivalent retries idempotent, while a new request id represents a new launch. Provider credentials stay in Control.",
    inputSchema: spawnInput.shape, annotations: { ...annotations, destructiveHint: true } },
    (input) => run(() => spawnReplica(deps, actor, input)));
  server.registerTool("get_replica_spawn", { description: "Continue preparation and return the state of a Replicas launch. This operation may install the scoped Agent Relay MCP and reply helper, register the relay agent and dispatch the task. Provisioning failures return a structured provisioning_error. A bound result includes binding.agent. Unknown create or task outcomes remain associated with the original launch.",
    inputSchema: { spawn_id: z.string().uuid() }, annotations: { ...annotations, destructiveHint: true } },
    ({ spawn_id }) => run(() => replicaStatus(deps, actor, spawn_id)));
  server.registerTool("recover_replica_spawn", { description: "Recover an unconfirmed create or task send without replaying it. The existing replica UUID is verified against the launch marker in its original chat; recovery remains attached to the original launch id and may continue setup through dispatch of its original task.",
    inputSchema: { spawn_id: z.string().uuid(), replica_id: z.string().uuid(),
      revive: z.boolean().optional().describe("Owner/admin only: re-admit a released environment-level identity (its workspace_identity token is refused until revived). The next admitted call enrols it again.") },
    annotations: { ...annotations, destructiveHint: true } },
    ({ spawn_id, replica_id, revive }) => run(() => recoverReplica(deps, actor, spawn_id, replica_id, { revive: revive === true })));
  server.registerTool("bind_replica", { description: "Connect an existing Replicas chat to Relay without creating a replica. The operation stops when another bridge already owns the chat. Requires current workspace owner or admin access. A pending result retains a spawn_id for later status reads.",
    inputSchema: { replica_id: z.string().uuid(), chat_id: z.string().uuid() }, annotations },
    (input) => run(() => bindReplica(deps, actor, input)));
  server.registerTool("release_replica", { description: "Disconnect a spawned Replicas agent from Relay and sleep its compute. The repeat-safe operation revokes MCP and reply capability and removes subscriptions while preserving the replica and its history.",
    inputSchema: { spawn_id: z.string().uuid() }, annotations: { ...annotations, destructiveHint: true } },
    ({ spawn_id }) => run(() => releaseReplica(deps, actor, spawn_id)));
}
