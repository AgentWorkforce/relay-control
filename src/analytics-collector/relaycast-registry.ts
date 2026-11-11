// Relaycast #636 producer projection at 25eee4e0. Only native workspace
// observations and installation-scoped exception classifications are admitted.
import type { EventSpec, PropertySpec } from "../analytics/events.js";

/** The decimal 64-bit workspace id that Relaycast credentials carry. */
export function isRelaycastWorkspaceId(value: string): boolean {
  return /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= (1n << 64n) - 1n;
}

const RELAYCAST_ID = { type: "relaycast_id" } as const;
const COUNT = { type: "integer", min: 0, max: Number.MAX_SAFE_INTEGER } as const;
const NUMBER = { type: "nonnegative_number" } as const;
const FLAG = { type: "boolean" } as const;
const values = (values: readonly string[]): PropertySpec => ({ type: "enum", values });

const FACTS = {
  agent_id: RELAYCAST_ID,
  audit_id: RELAYCAST_ID,
  channel_id: RELAYCAST_ID,
  message_id: RELAYCAST_ID,
  parent_message_id: RELAYCAST_ID,
  file_id: RELAYCAST_ID,
  conversation_id: RELAYCAST_ID,
  invocation_id: RELAYCAST_ID,
  subscription_id: RELAYCAST_ID,
  webhook_id: RELAYCAST_ID,
  grace_seconds: COUNT,
  size_bytes: COUNT,
  query_length: COUNT,
  result_count: COUNT,
  duration_ms: COUNT,
  participant_count: COUNT,
  event_count: COUNT,
  skill_count: COUNT,
  tag_count: COUNT,
  score: NUMBER,
  success: FLAG,
  fallback: FLAG,
  changed_name: FLAG,
  changed_system_prompt: FLAG,
  changed_metadata: FLAG,
  changed_status: FLAG,
  changed_persona: FLAG,
  has_attachments: FLAG,
  has_from_filter: FLAG,
  has_channel_filter: FLAG,
  stream_mode: values(["on", "off", "default", "enabled", "disabled", "other"]),
  operation: values(["set", "reset", "other"]),
  session_scope: values(["workspace", "node", "other"]),
  created_via: values(["api", "internal", "bootstrap", "other"]),
  deleted_via: values(["api", "internal", "retention", "other"]),
  agent_type: values(["agent", "human", "system", "other"]),
  message_kind: values(["channel_message", "thread_reply", "other"]),
} satisfies Record<string, PropertySpec>;

const ORIGIN = {
  actor_type: values(["human", "agent", "system"]),
  origin_app: values([
    "agent-relay-cli", "agent-relay-broker", "agent-relay-cloud", "pear", "relaycast-cli",
    "relaycast-mcp", "unknown", "other",
  ]),
  origin_actor_type: values(["agent", "user", "system", "node", "ci", "unknown", "other"]),
  origin_client: values([
    "@relaycast/sdk", "@relaycast/sdk-ts", "@relaycast/sdk-rust", "@relaycast/sdk-swift",
    "@relaycast/mcp", "@relaycast/cli", "@relaycast/react", "@relaycast/openclaw", "@relaycast/a2a",
    "agent-relay-cli", "agent-relay-broker", "unknown", "other",
  ]),
};

const OBSERVATIONS: Record<string, readonly (keyof typeof FACTS)[]> = {
  "workspace.created": ["created_via"],
  "workspace.updated": ["changed_name", "changed_system_prompt", "changed_metadata"],
  "workspace.deleted": ["deleted_via"],
  "workspace.stream.updated": ["stream_mode"],
  "workspace.key.rotated": ["grace_seconds"],
  "agent.registered": ["agent_id", "agent_type"],
  "agent.updated": ["changed_status", "changed_persona", "changed_metadata"],
  "legacy.identity.claimed": [],
  "agent.deleted": [],
  "agent.token.rotated": [],
  "agent.identity.taken.over": ["agent_id", "audit_id"],
  "agent.token.revoked": ["agent_id", "audit_id"],
  "channel.created": ["channel_id"],
  "channel.updated": ["channel_id"],
  "channel.topic.updated": ["channel_id"],
  "channel.archived": [],
  "channel.joined": ["agent_id"],
  "channel.left": ["agent_id"],
  "channel.invited": [],
  "channel.muted": ["agent_id"],
  "channel.unmuted": ["agent_id"],
  "message.created": ["channel_id", "message_id", "has_attachments", "message_kind"],
  "thread.reply.created": ["message_id", "parent_message_id"],
  "file.upload.requested": ["file_id", "size_bytes"],
  "file.upload.completed": ["file_id", "size_bytes"],
  "dm.sent": ["conversation_id", "message_id"],
  "group.dm.created": ["conversation_id", "participant_count"],
  "group.dm.message.sent": ["conversation_id", "message_id"],
  "group.dm.participant.added": ["conversation_id"],
  "group.dm.participant.removed": ["conversation_id", "agent_id"],
  "reaction.added": ["message_id"],
  "reaction.removed": ["message_id"],
  "search.executed": ["query_length", "result_count", "has_from_filter", "has_channel_filter"],
  "command.registered": [],
  "command.deleted": [],
  "command.invoked": ["invocation_id"],
  "subscription.created": ["subscription_id", "event_count"],
  "subscription.deleted": ["subscription_id"],
  "inbound.webhook.created": ["webhook_id"],
  "inbound.webhook.deleted": ["webhook_id"],
  "inbound.webhook.triggered": ["webhook_id"],
  "message.read.marked": ["message_id", "agent_id"],
  "presence.heartbeat": ["agent_id"],
  "presence.disconnected": ["agent_id"],
  "system.prompt.updated": ["operation"],
  "ws.session.started": ["session_scope"],
  "ws.session.ended": ["session_scope", "duration_ms"],
  "action.registered": [],
  "action.deleted": [],
  "action.invoked": ["invocation_id"],
  "directory.agent.created": ["skill_count"],
  "directory.agent.updated": [],
  "directory.agent.deleted": [],
  "directory.rating.upserted": ["score"],
  "directory.search.executed": ["query_length", "result_count", "tag_count"],
  "route.resolved": ["fallback", "score"],
  "route.feedback.recorded": ["success"],
  "routing.config.updated": [],
  "relayfile.inbound.delivered": [],
};

const EXCEPTION: EventSpec = {
  scope: "installation",
  properties: {
    error_name: values([
      "Error", "TypeError", "RangeError", "SyntaxError", "ReferenceError", "EvalError", "URIError",
      "AggregateError", "DOMException", "AdmissionDeniedError", "ConfigError",
      "D1WriteRetryExhaustedError", "ExternalIoOutsideMaintenance", "WorkspaceDeliveryCapacityError",
      "WorkspaceIdNotSnowflakeError", "SqliteError", "DrizzleError", "DrizzleQueryError",
      "unregistered", "NonError:null", "NonError:undefined", "NonError:string", "NonError:number",
      "NonError:bigint", "NonError:boolean", "NonError:symbol", "NonError:object", "NonError:function",
    ]),
    error_code: values([
      "internal_error", "delivery_failed", "webhook_agent_provision_failed", "workspace_id_collision",
      "a2a_agent_card_fetch_failed", "a2a_invalid_response", "a2a_jsonrpc_error",
      "a2a_redirect_forbidden", "a2a_transport_unavailable", "a2a_legacy_replay_unavailable",
      "action_deleted", "agent_host_unavailable", "database_overloaded",
      "event_delivery_fetch_required", "event_delivery_retryable_failure",
      "file_storage_delete_partial", "file_storage_delete_unsupported", "handler_unavailable",
      "idempotency_unavailable", "mailbox_full", "node_dispatch_unavailable",
      "relayfile_inbound_unavailable", "spawn_target_unavailable",
      "workspace_create_idempotency_unavailable", "workspace_storage_unavailable", "SQLITE_ERROR",
      "SQLITE_BUSY", "SQLITE_LOCKED", "SQLITE_FULL", "SQLITE_IOERR", "SQLITE_CORRUPT",
      "SQLITE_READONLY", "SQLITE_CANTOPEN", "SQLITE_CONSTRAINT", "SQLITE_CONSTRAINT_UNIQUE",
      "SQLITE_CONSTRAINT_PRIMARYKEY", "SQLITE_CONSTRAINT_FOREIGNKEY", "SQLITE_CONSTRAINT_NOTNULL",
      "SQLITE_CONSTRAINT_CHECK", "ECONNREFUSED", "ECONNRESET", "ETIMEDOUT", "EPIPE", "ENOSPC", "EACCES",
      "ENOENT", "EMFILE",
    ]),
    operation: values([
      "node.event_queue", "node.event_queue.poll", "node.event_queue.deliver",
      "node.event_queue.retention_prune", "node.maintenance", "node.maintenance.node_delivery",
      "node.maintenance.delivery_expiry", "actor.maintenance", "inbox.get", "deliveries.list",
      "workspace.delete", "invocations.sweep", "backfill.mention_fts",
    ]),
  },
};

export const RELAYCAST_COLLECTOR_REGISTRY: Readonly<Record<string, EventSpec>> = {
  ...Object.fromEntries(Object.entries(OBSERVATIONS).map(([name, fields]) => [name, {
    scope: "native_workspace",
    properties: { ...ORIGIN, ...Object.fromEntries(fields.map((field) => [field, FACTS[field]])) },
  } satisfies EventSpec])),
  exception: EXCEPTION,
};
