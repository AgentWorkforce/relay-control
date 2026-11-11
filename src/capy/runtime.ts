import { z } from "zod";

/** Native transport port of Cloud 902c95ea1 packages/web/lib/capy/client.ts.
 * This is server-only I/O, not an authorization boundary. The binding service
 * must resolve the current person's workspace/credential before calling it.
 * It starts no worker and does not advertise a live Capy runtime.
 */
const ORIGIN = "https://api.capy.ai/api/v1";
const TIMEOUT_MS = 15_000;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
export const DEFAULT_CAPY_MODEL = "anthropic/claude-sonnet-5-5";

export class CapyRuntimeError extends Error {
  constructor(
    readonly outcome: "rejected" | "unknown",
    readonly code: string,
    readonly status = 0,
    readonly retryAfterSeconds: number | null = null,
  ) { super(code); this.name = "CapyRuntimeError"; }
}

const identifier = z.string().min(1).max(128).regex(/^[^\p{Cc}\p{Cf}]+$/u);
const threadId = z.string().regex(/^jam_[A-Za-z0-9]{6,64}$/);
const stableKey = z.string().regex(/^[A-Za-z0-9._:-]{1,128}$/);
const cursor = z.string().min(1).max(4096).nullable();
const model = z.object({ modelId: identifier });
const thread = z.object({ id: threadId, title: z.string().nullable(), status: identifier });
const pagination = z.object({ limit: z.number().int().min(1).max(100), cursor });
const projects = z.object({
  items: z.array(z.object({ id: identifier, name: z.string().max(4096) })).max(100),
  nextCursor: cursor,
  hasMore: z.boolean(),
}).refine(value => !value.hasMore || value.nextCursor !== null);
const ack = z.object({ id: identifier, deduped: z.boolean() });
const text = z.string().min(1).refine(value => value.trim().length > 0 && Buffer.byteLength(value) <= 64 * 1024);
const createInput = z.object({ requestId: stableKey, projectId: identifier,
  message: z.string().trim().min(1).max(20_000), model: model.optional(),
  pullRequestAuthor: z.enum(["user", "capy"]).optional() }).strict();
const sendInput = z.object({ text, clientKey: stableKey,
  delivery: z.enum(["steer", "queue", "interrupt"]), model: model.optional() }).strict();
const message = z.object({
  id: identifier, source: z.enum(["user", "assistant", "tool"]), text: z.string().optional(),
  tool: z.string().optional(), callId: z.string().optional(), model: z.string().optional(),
  calls: z.array(z.object({ tool: z.string(), durationMs: z.union([z.number().finite(), z.string()]) })).optional(),
  authorName: z.string().optional(), createdAt: z.string().optional(),
  attachments: z.array(z.object({ file: z.object({ fileId: z.string(), name: z.string(),
    mediaType: z.string(), sizeBytes: z.union([z.number().finite(), z.string()]) }) })).optional(),
});
const messages = z.object({ items: z.array(message).max(100), cursor });
export type CapyMessage = z.infer<typeof message>;
export type CapyCreateInput = z.infer<typeof createInput>;
export type CapySendInput = z.infer<typeof sendInput>;

function input<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.safeParse(value);
  if (!parsed.success) throw new CapyRuntimeError("rejected", "capy_invalid_input");
  return parsed.data;
}

/** A fetch implementation or body can ignore abort; the caller's wait still ends. */
async function bounded<T>(work: () => Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted();
  let onAbort!: () => void;
  const aborted = new Promise<never>((_resolve, reject) => {
    onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try { return await Promise.race([work(), aborted]); }
  finally { signal.removeEventListener("abort", onAbort); }
}

export function createCapyRuntime(options: { fetchImpl?: typeof fetch; timeoutMs?: number } = {}) {
  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMs = input(z.number().int().min(1).max(TIMEOUT_MS), options.timeoutMs ?? TIMEOUT_MS);

  function operation(key: string) {
    input(z.string().regex(/^capy_[A-Za-z0-9_-]{16,256}$/), key);
    const signal = AbortSignal.timeout(timeoutMs);
    let remainingBytes = MAX_RESPONSE_BYTES;

    async function json(response: Response): Promise<unknown> {
      if (!response.body) throw new Error("invalid_body");
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      try {
        for (;;) {
          const chunk = await bounded(() => reader.read(), signal);
          if (chunk.done) break;
          remainingBytes -= chunk.value.byteLength;
          if (remainingBytes < 0) throw new Error("invalid_body");
          chunks.push(chunk.value);
        }
        return JSON.parse(Buffer.concat(chunks).toString("utf8"));
      } finally {
        // Cancellation is best effort and never owns the operation deadline.
        void reader.cancel().catch(() => undefined);
        reader.releaseLock();
      }
    }

    return async <T>(path: string, schema: z.ZodType<T>, body?: Record<string, unknown>): Promise<T> => {
      const write = body !== undefined;
      // Already expired before dispatch: no provider write was attempted.
      if (signal.aborted) throw new CapyRuntimeError("rejected", "capy_deadline");
      try {
        const response = await bounded(() => fetchImpl(`${ORIGIN}${path}`, {
          method: write ? "POST" : "GET", redirect: "error", cache: "no-store", signal,
          headers: { authorization: `Bearer ${key}`, accept: "application/json",
            ...(write ? { "content-type": "application/json" } : {}) },
          ...(write ? { body: JSON.stringify(body) } : {}),
        }).then(response => {
          // Also release a response from a transport which ignored cancellation
          // and resolved only after the caller's deadline had already elapsed.
          if (signal.aborted) void response.body?.cancel().catch(() => undefined);
          return response;
        }), signal);
        // Bound the body even for failures: provider errors are never propagated.
        let decoded: unknown;
        try { decoded = await json(response); }
        catch {
          if (signal.aborted) throw new CapyRuntimeError(write ? "unknown" : "rejected", "capy_deadline");
          if (response.ok) throw new CapyRuntimeError(write ? "unknown" : "rejected", "capy_invalid_response", response.status);
          // Empty, HTML or oversized error bodies do not erase a definitive
          // HTTP rejection. They supply no model/retry hint, so use status only.
          decoded = {};
        }
        if (!response.ok) {
          const error = decoded && typeof decoded === "object" && !Array.isArray(decoded)
            ? decoded as Record<string, unknown> : {};
          const tag = error._tag ?? error.code;
          const missingModel = response.status === 400 && (tag === "model_not_selected" ||
            (typeof tag === "string" && tag.length <= 80 && tag.startsWith("ModelSelection")));
          const retry = response.status === 429 && typeof error.retryAfterSeconds === "number" && Number.isFinite(error.retryAfterSeconds)
            ? Math.max(0, Math.min(3600, Math.ceil(error.retryAfterSeconds))) : null;
          throw new CapyRuntimeError(write && response.status >= 500 ? "unknown" : "rejected",
            missingModel ? "capy_model_not_selected" : `capy_http_${response.status}`, response.status, retry);
        }
        const parsed = schema.safeParse(decoded);
        if (!parsed.success) throw new CapyRuntimeError(write ? "unknown" : "rejected", "capy_invalid_response", response.status);
        return parsed.data;
      } catch (error) {
        if (error instanceof CapyRuntimeError) throw error;
        throw new CapyRuntimeError(write ? "unknown" : "rejected", signal.aborted ? "capy_deadline" : "capy_transport_unavailable");
      }
    };
  }

  async function withModelFallback<T>(key: string, path: string, schema: z.ZodType<T>, body: Record<string, unknown>) {
    const call = operation(key);
    try { return await call(path, schema, body); }
    catch (error) {
      // A missing-model 400 is a definitive rejection, not an uncertain write.
      // Reuse the operation deadline and requestId/clientKey for the one retry.
      if (body.model || !(error instanceof CapyRuntimeError) || error.code !== "capy_model_not_selected") throw error;
      return call(path, schema, { ...body, model: { modelId: DEFAULT_CAPY_MODEL } });
    }
  }

  return {
    async listProjects(key: string, raw: { limit: number; cursor: string | null }) {
      const page = input(pagination, raw);
      const query = new URLSearchParams({ limit: String(page.limit), ...(page.cursor ? { cursor: page.cursor } : {}) });
      return operation(key)(`/projects?${query}`, projects);
    },
    async getThread(key: string, rawThreadId: string) {
      const id = input(threadId, rawThreadId);
      return operation(key)(`/threads/${encodeURIComponent(id)}`, thread);
    },
    async createThread(key: string, raw: CapyCreateInput) {
      const body = input(createInput, raw);
      return withModelFallback(key, "/threads", thread, { ...body, visibility: "org" });
    },
    async sendMessage(key: string, rawThreadId: string, raw: CapySendInput) {
      const id = input(threadId, rawThreadId);
      const body = input(sendInput, raw);
      return withModelFallback(key, `/threads/${encodeURIComponent(id)}/message`, ack, body);
    },
    async listMessages(key: string, rawThreadId: string, raw: { after: string | null; limit: number }) {
      const id = input(threadId, rawThreadId);
      const page = input(z.object({ after: cursor, limit: pagination.shape.limit }), raw);
      const query = new URLSearchParams({ limit: String(page.limit), ...(page.after ? { after: page.after } : {}) });
      return operation(key)(`/threads/${encodeURIComponent(id)}/messages?${query}`, messages);
    },
  };
}
export type CapyRuntime = ReturnType<typeof createCapyRuntime>;
