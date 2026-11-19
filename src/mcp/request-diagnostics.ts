import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";

type ObjectValue = Record<string, unknown>;
const object = (value: unknown): ObjectValue | undefined =>
  value !== null && typeof value === "object" && !Array.isArray(value) ? value as ObjectValue : undefined;
const CORRELATION = /(?:^|\n)correlation_id: ([0-9a-f-]{36})(?:\n|$)/;
type DiagnosticContext = { correlationId: string };
// Next may load the route and server from separate chunks. They must share
// the storage instance, while AsyncLocalStorage isolates concurrent requests.
const contextKey = Symbol.for("agentrelay.mcp.request-diagnostics.v1");
const globals = globalThis as typeof globalThis & { [key: symbol]: AsyncLocalStorage<DiagnosticContext> | undefined };
const context = globals[contextKey] ?? (globals[contextKey] = new AsyncLocalStorage<DiagnosticContext>());
const currentId = () => context.getStore()?.correlationId ?? randomUUID();

export function withMcpDiagnosticContext<T>(correlationId: string, work: () => T): T {
  return context.run({ correlationId }, work);
}

/** Annotate errors before serialization; never parse successful transcript payloads. */
export function correlateMcpMessage<T>(message: T, endpoint: string, correlationId: string = currentId(), status = 200): T {
  const envelope = object(message);
  const error = object(envelope?.error);
  const result = object(envelope?.result);
  if (result?.isError === true) {
    const content = Array.isArray(result.content) ? result.content : [];
    if (!content.some(part => typeof object(part)?.text === "string" && String(object(part)?.text).trim())) {
      content.push({ type: "text", text: "The MCP tool failed. Please try again." });
    }
    const existing = content.flatMap(part => {
      const text = object(part)?.text;
      return typeof text === "string" ? CORRELATION.exec(text)?.[1] ?? [] : [];
    })[0];
    correlationId = existing ?? correlationId;
    if (!existing) result.content = [...content, { type: "text", text: `correlation_id: ${correlationId}` }];
  } else if (error) {
    error.message = typeof error.message === "string" && error.message.trim()
      ? error.message : "The MCP request failed. Please try again.";
    const details = object(error.data) ?? (error.data === undefined ? {} : { details: error.data });
    error.data = { ...details, correlation_id: correlationId };
  } else {
    return message;
  }
  const active = context.getStore();
  if (active) active.correlationId = correlationId;
  // Never log request bodies, headers, exception messages or upstream bodies.
  console.error("[mcp] request failed", { endpoint, status, correlationId });
  return message;
}

/** SDK errors can use HTTP 200. Inspect the message, not the serialized body. */
export function instrumentMcpTransport(transport: Pick<Transport, "send">, endpoint: string): void {
  const send = transport.send.bind(transport);
  transport.send = (message, options) => send(correlateMcpMessage(message, endpoint), options);
}

/** Only HTTP failures need decoding; successful bodies pass through untouched. */
export async function correlateMcpResponse(response: Response, endpoint: string, correlationId: string = currentId()): Promise<Response> {
  const headers = new Headers(response.headers);
  headers.set("X-Correlation-Id", correlationId);
  if (response.status < 400) {
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  }
  let body: string | undefined;
  let logged = false;
  if (headers.get("content-type")?.includes("application/json")) {
    try {
      const envelope = object(await response.json());
      if (envelope) {
        if (object(envelope.error)) {
          correlateMcpMessage(envelope, endpoint, correlationId, response.status);
          logged = true;
        } else {
          // Preserve non-RPC refusal contracts (for example an edition's 404).
          envelope.correlation_id = correlationId;
        }
        body = JSON.stringify(envelope);
      }
    } catch { /* Empty or malformed HTTP errors get the safe fallback below. */ }
  }
  if (body === undefined) {
    // Never forward an upstream HTML error containing internal URLs.
    headers.set("content-type", "application/json");
    body = JSON.stringify({ jsonrpc: "2.0", id: null, error: {
      code: -32603,
      message: `The MCP service returned HTTP ${response.status}. Please try again.\ncorrelation_id: ${correlationId}`,
      data: { correlation_id: correlationId },
    } });
  }
  if (!logged) console.error("[mcp] request failed", { endpoint, status: response.status, correlationId });
  headers.set("Cache-Control", "no-store");
  headers.delete("content-length");
  return new Response(body, { status: response.status, statusText: response.statusText, headers });
}

