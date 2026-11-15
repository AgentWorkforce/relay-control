/** Sender-scoped Relaycast receipts. Raw status is not proof of acceptance. */
export type DeliveryState = "queued" | "delivered" | "consumed" | "replied" | "failed";
export type MessageDelivery = {
  id: string; agent_id: string; agent_name: string | null; status: string; state: DeliveryState;
  created_at: string | null; delivered_at: string | null; accepted_at: string | null;
  acked_at: string | null; replied_at: string | null; reply_message_id: string | null;
  dead_lettered_at: string | null; error: string | null; read_at: string | null;
};
export const RECEIPT_GUIDANCE = "delivered means recipient software accepted it; consumed means acknowledged, not human reading or understanding. replied requires an explicitly correlated reply. read_at is an explicit read receipt only. An empty list does not confirm delivery.";
export function parseMessageDeliveries(value: unknown, messageId: string): MessageDelivery[] {
  const data = value as { message_id?: unknown; deliveries?: unknown } | null;
  if (data?.message_id !== messageId || !Array.isArray(data.deliveries)) throw new Error("Invalid delivery receipt response");
  const nullable = (v: unknown) => typeof v === "string" ? v : null;
  return data.deliveries.map(value => {
    if (!value || typeof value !== "object") throw new Error("Invalid delivery receipt");
    const row = value as Record<string, unknown>;
    if (typeof row.id !== "string" || typeof row.agent_id !== "string" || typeof row.status !== "string"
      || !["queued", "delivered", "consumed", "replied", "failed"].includes(String(row.state))) throw new Error("Invalid delivery receipt");
    return { id: row.id, agent_id: row.agent_id, agent_name: nullable(row.agent_name), status: row.status, state: row.state as DeliveryState,
      created_at: nullable(row.created_at), delivered_at: nullable(row.delivered_at), accepted_at: nullable(row.accepted_at),
      acked_at: nullable(row.acked_at), replied_at: nullable(row.replied_at), reply_message_id: nullable(row.reply_message_id),
      dead_lettered_at: nullable(row.dead_lettered_at), error: nullable(row.error), read_at: nullable(row.read_at) };
  });
}
