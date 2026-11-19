import { randomUUID } from "node:crypto";

type ObjectValue = Record<string, unknown>;
const object = (value: unknown): ObjectValue | undefined =>
  value !== null && typeof value === "object" && !Array.isArray(value) ? value as ObjectValue : undefined;
const CORRELATION = /(?:^|\n)correlation_id: ([0-9a-f-]{36})(?:\n|$)/;

/** Correlate protocol and tool errors without changing successful tool schemas. */
export async function correlateMcpResponse(response: Response, endpoint: string, correlationId: string = randomUUID()): Promise<Response> {
  const headers = new Headers(response.headers);
  let body: string | undefined;
  let failed = response.status >= 400;
  if (headers.get("content-type")?.includes("application/json")) {
    body = await response.text();
    let envelope: ObjectValue | undefined;
    try { envelope = object(JSON.parse(body)); }
    catch { if (!failed) throw new Error("Invalid MCP response JSON"); }
    const error = object(envelope?.error);
    const result = object(envelope?.result);
    if (result?.isError === true) {
      failed = true;
      const content = Array.isArray(result.content) ? result.content : [];
      if (!content.some(part => typeof object(part)?.text === "string" && String(object(part)?.text).trim())) {
        content.push({ type: "text", text: "The MCP tool failed. Please try again." });
      }
      const existing = content.flatMap(part => {
        const text = object(part)?.text;
        return typeof text === "string" ? CORRELATION.exec(text)?.[1] ?? [] : [];
      })[0];
      correlationId = existing ?? correlationId;
      if (!existing) {
        result.content = [...content, { type: "text", text: `correlation_id: ${correlationId}` }];
      }
      body = JSON.stringify(envelope);
    } else if (error) {
      failed = true;
      const message = typeof error.message === "string" && error.message.trim()
        ? error.message : "The MCP request failed. Please try again.";
      error.message = message;
      error.data = { ...object(error.data), correlation_id: correlationId };
      body = JSON.stringify(envelope);
    } else if (failed && envelope) {
      // Preserve non-RPC refusal contracts (for example an edition's 404).
      envelope.correlation_id = correlationId;
      body = JSON.stringify(envelope);
    } else if (failed) {
      body = undefined;
    }
  }
  if (failed && body === undefined) {
    // A proxy/adapter can return an empty failure. Never forward its raw body
    // (which may contain an internal URL); keep the status and a useful error.
    headers.set("content-type", "application/json");
    body = JSON.stringify({ jsonrpc: "2.0", id: null, error: {
      code: -32603,
      message: `The MCP service returned HTTP ${response.status}. Please try again.\ncorrelation_id: ${correlationId}`,
      data: { correlation_id: correlationId },
    } });
  }
  headers.set("X-Correlation-Id", correlationId);
  if (failed) {
    // Never log request bodies, headers, exception messages or upstream bodies.
    console.error("[mcp] request failed", { endpoint, status: response.status, correlationId });
    headers.set("Cache-Control", "no-store");
  }
  if (body !== undefined) headers.delete("content-length");
  return new Response(body ?? response.body, { status: response.status, statusText: response.statusText, headers });
}

