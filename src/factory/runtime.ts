/**
 * Factory provider transport, ported from Cloud 6168 `runtime.ts`: no
 * provisioning, no redirects, no retries of a write. Errors carry a stable
 * code and whether the write may have happened (`unknown`).
 */

export type FactoryComputer = { id: string; name: string; status: string };
export type FactorySessionRow = { id: string; title: string; computerId: string };
export type FactorySessionMeta = {
  sessionId: string;
  computerId: string;
  updatedAt: number;
  messageCount: number;
};
export type FactoryInjectAck = { messageId: string; status: string };

export class FactoryRuntimeError extends Error {
  constructor(
    readonly outcome: "rejected" | "unknown",
    readonly code: string,
    readonly retryable = outcome === "rejected" &&
      ["factory_http_429", "factory_transport_unavailable", "factory_operation_deadline"].includes(code),
  ) {
    super(code);
    this.name = "FactoryRuntimeError";
  }
}

/** The per-request window, the whole operation, and the response budget (Cloud limits). */
export const FACTORY_REQUEST_TIMEOUT_MS = 30_000;
export const FACTORY_OPERATION_TIMEOUT_MS = 55_000;
const MAX_BYTES = 16 * 1024 * 1024;
const MAX_PAGES = 100;
export const MAX_INJECT_BYTES = 64 * 1024;
export const FACTORY_ID = /^[A-Za-z0-9_-]{1,256}$/;
export const REACHABILITY_WARNING =
  "The Factory key is valid, but this computer is not reachable. Keep Factory Remote Control running on that computer, then choose sessions again.";
const UNREACHABLE_CODES = [
  "factory_transport_unavailable",
  "factory_operation_deadline",
  "factory_http_502",
  "factory_http_503",
  "factory_http_504",
];

export function validFactoryKey(key: string): boolean {
  return key.length >= 16 && key.length <= 2048 && !/[\s\x00-\x1f\x7f]/.test(key);
}

type Budget = { bytes: number };

async function readJson(response: Response, budget: Budget): Promise<unknown> {
  if (!response.body) throw new Error("factory_empty_response");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      budget.bytes += value.byteLength;
      if (budget.bytes > MAX_BYTES) throw new Error("factory_response_too_large");
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("factory_invalid_response");
  return value as Record<string, unknown>;
}

function factoryId(value: unknown, code: string): string {
  if (typeof value !== "string" || !FACTORY_ID.test(value)) throw new FactoryRuntimeError("rejected", code);
  return value;
}

function pageCursor(value: unknown): string | null {
  const page = object(value);
  if (typeof page.hasMore !== "boolean" || !(page.nextCursor === null || typeof page.nextCursor === "string")) {
    throw new FactoryRuntimeError("rejected", "factory_invalid_pagination");
  }
  if (page.hasMore && (typeof page.nextCursor !== "string" || !page.nextCursor || page.nextCursor.length > 4096)) {
    throw new FactoryRuntimeError("rejected", "factory_invalid_cursor");
  }
  return page.hasMore ? page.nextCursor as string : null;
}

export function createFactoryRuntime(input: { apiUrl: string; fetchImpl?: typeof fetch }) {
  const fetcher = input.fetchImpl ?? fetch;
  const origin = input.apiUrl.replace(/\/+$/, "");

  function operation(key: string) {
    if (!validFactoryKey(key)) throw new FactoryRuntimeError("rejected", "factory_invalid_key");
    const budget: Budget = { bytes: 0 };
    const deadline = Date.now() + FACTORY_OPERATION_TIMEOUT_MS;
    return async (path: string, query: Record<string, string | null> = {}, body?: unknown) => {
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new FactoryRuntimeError("rejected", "factory_operation_deadline");
      const url = new URL(`${origin}${path}`);
      for (const [name, value] of Object.entries(query)) if (value !== null) url.searchParams.set(name, value);
      let response: Response;
      try {
        response = await fetcher(url, {
          method: body === undefined ? "GET" : "POST",
          redirect: "manual",
          cache: "no-store",
          signal: AbortSignal.timeout(Math.min(FACTORY_REQUEST_TIMEOUT_MS, remaining)),
          headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        });
      } catch {
        // A POST that failed in transport may have been accepted.
        throw new FactoryRuntimeError(body === undefined ? "rejected" : "unknown", "factory_transport_unavailable");
      }
      if (!response.ok) {
        await response.body?.cancel().catch(() => undefined);
        // Only a definite client rejection says the write did not happen.
        const definite = [400, 401, 403, 404, 409, 422, 429].includes(response.status);
        throw new FactoryRuntimeError(
          body === undefined || definite ? "rejected" : "unknown",
          `factory_http_${response.status}`,
        );
      }
      try {
        return object(await readJson(response, budget));
      } catch {
        throw new FactoryRuntimeError(body === undefined ? "rejected" : "unknown", "factory_invalid_response");
      }
    };
  }

  async function sessionMeta(
    request: ReturnType<typeof operation>,
    sessionId: string,
    computerId: string,
  ): Promise<FactorySessionMeta> {
    factoryId(sessionId, "factory_invalid_session");
    const session = await request(`/api/v0/sessions/${encodeURIComponent(sessionId)}`, { computerId });
    if (session.sessionId !== sessionId) throw new FactoryRuntimeError("rejected", "factory_session_mismatch");
    if (
      !Number.isSafeInteger(session.updatedAt) || Number(session.updatedAt) < 0 ||
      !Number.isSafeInteger(session.messageCount) || Number(session.messageCount) < 0
    ) {
      throw new FactoryRuntimeError("rejected", "factory_session_metadata_invalid");
    }
    const reported = factoryId(session.computerId, "factory_invalid_computer");
    if (reported !== computerId) throw new FactoryRuntimeError("rejected", "factory_computer_changed");
    return {
      sessionId,
      computerId: reported,
      updatedAt: Number(session.updatedAt),
      messageCount: Number(session.messageCount),
    };
  }

  return {
    /** The key check: the computers listed for the key's owner. */
    async listComputers(key: string): Promise<FactoryComputer[]> {
      const request = operation(key);
      const raw = await request("/api/v0/computers", {
        includeProvisioningSteps: "false",
        includeUnlisted: "false",
      });
      if (!Array.isArray(raw.computers) || raw.computers.length > 1000) {
        throw new FactoryRuntimeError("rejected", "factory_invalid_computers");
      }
      const computers = raw.computers.map((value) => {
        let row: Record<string, unknown>;
        try {
          row = object(value);
        } catch {
          throw new FactoryRuntimeError("rejected", "factory_invalid_computer");
        }
        const id = factoryId(row.id, "factory_invalid_computer");
        if (typeof row.name !== "string" || !["active", "provisioning", "error"].includes(String(row.status))) {
          throw new FactoryRuntimeError("rejected", "factory_invalid_computer");
        }
        return { id, name: row.name.slice(0, 200), status: String(row.status) };
      });
      if (new Set(computers.map((row) => row.id)).size !== computers.length) {
        throw new FactoryRuntimeError("rejected", "factory_invalid_computers");
      }
      return computers;
    },

    /** Sessions on one computer; an unreachable computer yields a warning, not an error. */
    async listSessions(key: string, computerId: string): Promise<{ sessions: FactorySessionRow[]; warning?: string }> {
      const request = operation(key);
      factoryId(computerId, "factory_invalid_computer");
      const rows: unknown[] = [];
      const cursors = new Set<string>();
      let cursor: string | null = null;
      try {
        for (let page = 0; ; page++) {
          if (page >= MAX_PAGES) throw new FactoryRuntimeError("rejected", "factory_page_limit");
          const raw = await request("/api/v0/sessions", { limit: "100", cursor, computerId });
          if (!Array.isArray(raw.sessions)) throw new FactoryRuntimeError("rejected", "factory_invalid_page");
          rows.push(...raw.sessions);
          cursor = pageCursor(raw.pagination);
          if (!cursor) break;
          if (cursors.has(cursor) || raw.sessions.length === 0) {
            throw new FactoryRuntimeError("rejected", "factory_pagination_incomplete");
          }
          cursors.add(cursor);
        }
      } catch (error) {
        // Computer metadata can be active while its Remote Control daemon is
        // disconnected. Keep the valid key without claiming reachability.
        if (error instanceof FactoryRuntimeError && UNREACHABLE_CODES.includes(error.code)) {
          return { sessions: [], warning: REACHABILITY_WARNING };
        }
        throw error;
      }
      return {
        sessions: rows.map((value) => {
          let row: Record<string, unknown>;
          try {
            row = object(value);
          } catch {
            throw new FactoryRuntimeError("rejected", "factory_invalid_page");
          }
          if (factoryId(row.computerId, "factory_invalid_computer") !== computerId) {
            throw new FactoryRuntimeError("rejected", "factory_computer_changed");
          }
          const id = factoryId(row.sessionId, "factory_invalid_session");
          return { id, title: typeof row.title === "string" ? row.title.slice(0, 200) : id, computerId };
        }),
      };
    },

    /** Session metadata, pinned to the computer it must be on. */
    async getSession(key: string, sessionId: string, computerId: string): Promise<FactorySessionMeta> {
      return sessionMeta(operation(key), sessionId, computerId);
    },

    /**
     * Posts one message into a session. `beforeWrite` re-enters the caller's
     * fence immediately before the POST; it throwing means nothing was sent.
     */
    async inject(
      key: string,
      target: { sessionId: string; computerId: string; text: string },
      beforeWrite: () => Promise<void>,
    ): Promise<FactoryInjectAck> {
      const request = operation(key);
      if (!target.text || Buffer.byteLength(target.text) > MAX_INJECT_BYTES || target.text.includes("\0")) {
        throw new FactoryRuntimeError("rejected", "factory_invalid_message");
      }
      await sessionMeta(request, target.sessionId, target.computerId);
      await beforeWrite();
      const result = await request(
        `/api/v0/sessions/${encodeURIComponent(target.sessionId)}/messages`,
        {},
        { text: target.text, computerId: target.computerId },
      );
      if (
        typeof result.messageId !== "string" || !result.messageId || result.messageId.length > 256 ||
        !["idle", "pending", "running"].includes(String(result.status))
      ) {
        throw new FactoryRuntimeError("unknown", "factory_message_ack_invalid");
      }
      return { messageId: result.messageId, status: String(result.status) };
    },
  };
}

export type FactoryRuntime = ReturnType<typeof createFactoryRuntime>;
