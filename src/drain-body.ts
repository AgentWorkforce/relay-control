// Release a fetch response body the caller does not need.
//
// An unread body keeps the upstream request open, and in Node (undici) it can hold the socket
// until the response is garbage collected. Call this on every path that discards a response
// without reading it. It never throws: a failed cancel is logged with the label and the error
// name only, never the body or any header.
export type DrainableResponse = { readonly body: { cancel(reason?: unknown): Promise<void> } | null; readonly bodyUsed: boolean };

export async function drainBody(response: DrainableResponse, label: string): Promise<void> {
  const body = response.body;
  if (!body || response.bodyUsed) return;
  try {
    await body.cancel();
  } catch (error) {
    console.warn("[drain-body] response body drain failed", {
      label,
      error: error instanceof Error ? error.name : typeof error,
    });
  }
}
