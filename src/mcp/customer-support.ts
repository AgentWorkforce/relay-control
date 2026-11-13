import { createHash } from "node:crypto";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { McpContext } from "./context.js";

export const CUSTOMER_SUPPORT_PATH = "/api/v1/agents/agent-relay/support/control";
export const CustomerSupportInput = z.object({
  message: z.string().max(12_000).describe("Your support question. Empty only when continuing a pending conversation."),
  request_id: z.string().regex(/^[A-Za-z0-9_-]{8,64}$/).describe("Stable unique ID for this message; reuse on retry."),
  conversation_id: z.string().regex(/^[0-9a-f]{32}$/).optional().describe("Returned by the first call; reuse for this case."),
  mode: z.enum(["wait", "hybrid", "async"]).optional().describe("wait (default, up to 25 seconds), hybrid (up to 4 seconds), or async (returns pending at once)."),
}).strict().refine(input => Boolean(input.message.trim()) || Boolean(input.conversation_id), "A new case needs a message");

export type CustomerSupportRequest = {
  controlOrigin: string; organizationId: string; workspaceId: string; userId: string;
  conversationId: string; requestId: string; message: string;
  entitlements: ["selfhost"];
  waitMs?: number;
  notify?: { desktopAddress: string };
};
export type CustomerSupportConnection = {
  /** Revalidates the credential and current membership, including after a long wait. */
  authorize(): Promise<boolean>;
  send(input: CustomerSupportRequest): Promise<unknown>;
  origin: string;
  notifyTarget(): Promise<string | null>;
};

const Reply = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("reply"), replies: z.array(z.string().max(100_000)).max(100) }).strict(),
  z.object({ kind: z.literal("pending"), text: z.string().max(1000) }).strict(),
  z.object({ kind: z.enum(["unauthorized", "unavailable", "rate_limited", "invalid_request"]) }).strict(),
]);

/** Bounded response reads share the request timeout; no upstream bodies or credentials reach errors. */
export async function sendCustomerSupport(config: { url: string; token: string }, input: CustomerSupportRequest,
  fetchImpl: typeof fetch = globalThis.fetch): Promise<unknown> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 30_000);
  try {
    const response = await fetchImpl(new URL(CUSTOMER_SUPPORT_PATH, config.url), {
      method: "POST", redirect: "manual", signal: controller.signal,
      headers: { authorization: `Bearer ${config.token}`, "content-type": "application/json" }, body: JSON.stringify(input),
    });
    if (!response.ok) {
      await response.body?.cancel();
      return { kind: response.status === 401 || response.status === 403 ? "unauthorized"
        : response.status === 429 ? "rate_limited" : "unavailable" };
    }
    const reader = response.body?.getReader();
    if (!reader) return { kind: "unavailable" };
    let bytes = 0;
    const chunks: Uint8Array[] = [];
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.byteLength;
      if (bytes > 10_500_000) { await reader.cancel(); return { kind: "unavailable" }; }
      chunks.push(part.value);
    }
    return Reply.parse(JSON.parse(Buffer.concat(chunks).toString("utf8")));
  } finally { clearTimeout(timer); }
}

export async function askCustomerSupport(context: Pick<McpContext, "principal" | "workspace" | "customerSupport">, raw: unknown) {
  const input = CustomerSupportInput.parse(raw);
  const support = context.customerSupport;
  if (!support) return { status: "unavailable" as const };
  if (!await support.authorize()) return { status: "not_authorized" as const };
  const conversationId = input.conversation_id ?? createHash("sha256")
    .update(JSON.stringify(["support-case-v1", context.workspace.organizationId, context.workspace.id, context.principal.userId, input.request_id]))
    .digest("hex").slice(0, 32);
  const desktopAddress = await support.notifyTarget().catch(() => null);
  const result = Reply.parse(await support.send({ controlOrigin: support.origin,
    organizationId: context.workspace.organizationId, workspaceId: context.workspace.id, userId: context.principal.userId,
    conversationId, requestId: input.request_id, message: input.message,
    // Self-host docs are open to every current member, matching Cloud's open entitlement mode.
    entitlements: ["selfhost"],
    ...(input.mode === "async" ? { waitMs: 0 } : input.mode === "hybrid" ? { waitMs: 4000 } : {}),
    ...(desktopAddress ? { notify: { desktopAddress } } : {}),
  }));
  if (!await support.authorize()) return { status: "not_authorized" as const };
  if (result.kind === "reply") return { status: "reply" as const, conversation_id: conversationId, replies: result.replies };
  if (result.kind === "pending") return { status: "pending" as const, conversation_id: conversationId,
    next: desktopAddress
      ? "Agent Relay will message this session when the reply is ready. Call ask_customer_support with this conversation_id and an empty message to receive it. This result is not an answer or an escalation receipt."
      : "Call ask_customer_support with this conversation_id and an empty message to receive the pending reply. Retry with mode wait to hold for the reply. This result is not an answer or an escalation receipt." };
  return { status: result.kind, conversation_id: conversationId };
}

export function registerCustomerSupportTool(server: McpServer, context: McpContext): void {
  server.registerTool("ask_customer_support", {
    title: "Ask your private customer support agent",
    description: "Send a private support question about Agent Relay setup or your account. Available to all signed-in customers with current workspace membership. Company context, account health and escalation are available only when configured for your workspace. Access and recipients come from the authenticated connection, never tool input. Replies return as tool results. Continue pending cases with the same conversation_id and an empty message. A linked Desktop session is messaged when a reply is ready. Support questions and answers are excluded from shared session history.",
    inputSchema: CustomerSupportInput,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: true },
  }, async input => {
    try {
      const data = await askCustomerSupport(context, input);
      return { structuredContent: data, content: [{ type: "text" as const, text: JSON.stringify(data) }] };
    } catch {
      console.warn("[customer-support] tool_failed", { stage: "support_call", status: 503 });
      return { isError: true, content: [{ type: "text" as const,
        text: "Customer support is unavailable. Retry with the same request_id and conversation_id; no escalation is confirmed." }] };
    }
  });
}
