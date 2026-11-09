/**
 * Errors shared by the History read paths. History is served only by the
 * sessions pipeline (read API and ingest edge); the standalone RelayHistory
 * service and RelayAuth were removed.
 */
export class UpstreamError extends Error {
  constructor(
    /** `exchange`: the read API credential handoff; `read`: a session read. */
    readonly stage: "exchange" | "read",
    readonly status?: number,
    message = `Session read API ${stage} failed`,
    readonly retryable = false,
  ) {
    super(message);
  }
}

/** A backend-specific cursor cannot continue after rollback or credential transport changes. */
export class ReadCursorExpiredError extends Error {
  constructor() {
    super("This session cursor has expired. Restart from the first page.");
    this.name = "ReadCursorExpiredError";
  }
}
