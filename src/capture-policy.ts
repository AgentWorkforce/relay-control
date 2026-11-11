import type { Database } from "./database.js";
import { recordAudit, type AuditActor } from "./admin/audit.js";

/**
 * Operator capture policy (docs/capture-policy.md). Only keys present in
 * `settings` are enforced; an absent key means the member chooses. Nothing is
 * ever defaulted here.
 */
export type CaptureSettings = {
  sharing_mode?: "all" | "new" | "selected";
  upload_control?: "operator" | "user";
  oops_window_seconds?: number;
  user_retroactive_delete?: boolean;
};

export type CapturePolicy = {
  version: 1;
  revision: number;
  settings: CaptureSettings;
  /**
   * When `sharing_mode` last became `new` (ISO 8601). Present only while it
   * is `new`; the sessions pipeline refuses a session that started earlier.
   */
  sharing_mode_since?: string;
};

type CapturePolicyRow = { revision: number | string; settings: unknown; sharing_mode_since?: Date | string | null };

export const UNSET_CAPTURE_POLICY: CapturePolicy = Object.freeze({
  version: 1,
  revision: 1,
  settings: Object.freeze({}),
}) as CapturePolicy;

export class CapturePolicyError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

const ENUMS: Record<string, readonly string[]> = {
  sharing_mode: ["all", "new", "selected"],
  upload_control: ["operator", "user"],
};
const MAX_OOPS_WINDOW_SECONDS = 86_400;

function invalid(message: string): CapturePolicyError {
  return new CapturePolicyError(400, "invalid_policy", message);
}

/** Validates a full settings object (unknown keys, enums, ranges). */
export function parseCaptureSettings(value: unknown): CaptureSettings {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw invalid("settings must be a JSON object");
  }
  const settings: CaptureSettings = {};
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    if (key === "sharing_mode" || key === "upload_control") {
      if (typeof entry !== "string" || !ENUMS[key]!.includes(entry)) {
        throw invalid(`${key} must be one of ${ENUMS[key]!.join(", ")}`);
      }
      (settings as Record<string, unknown>)[key] = entry;
    } else if (key === "oops_window_seconds") {
      if (typeof entry !== "number" || !Number.isInteger(entry) || entry < 0 || entry > MAX_OOPS_WINDOW_SECONDS) {
        throw invalid(`oops_window_seconds must be an integer from 0 to ${MAX_OOPS_WINDOW_SECONDS}`);
      }
      settings.oops_window_seconds = entry;
    } else if (key === "user_retroactive_delete") {
      if (typeof entry !== "boolean") throw invalid("user_retroactive_delete must be a boolean");
      settings.user_retroactive_delete = entry;
    } else {
      throw invalid(`Unknown capture policy key: ${key.slice(0, 64)}`);
    }
  }
  return settings;
}

/** `If-Match: 7` or `If-Match: "7"`; undefined when absent. */
export function parseIfMatch(header: string | string[] | undefined): number | undefined {
  if (header === undefined) return undefined;
  const raw = (Array.isArray(header) ? header[0] ?? "" : header).trim();
  const match = /^"?([1-9][0-9]{0,8})"?$/.exec(raw);
  if (!match) throw new CapturePolicyError(400, "invalid_request", "If-Match must be a policy revision number");
  return Number(match[1]);
}

/**
 * The served policy for a stored row (absent: unset). Shared with token
 * introspection, which joins the row onto the token session.
 */
export function capturePolicyFromRow(row: CapturePolicyRow | null | undefined): CapturePolicy {
  if (!row || row.revision === null || row.revision === undefined) return { ...UNSET_CAPTURE_POLICY, settings: {} };
  const settings = row.settings && typeof row.settings === "object" && !Array.isArray(row.settings)
    ? row.settings as CaptureSettings
    : {};
  const since = settings.sharing_mode === "new" && row.sharing_mode_since
    ? new Date(row.sharing_mode_since).toISOString()
    : undefined;
  return {
    version: 1,
    revision: Number(row.revision),
    settings: projectSettings(settings),
    ...(since ? { sharing_mode_since: since } : {}),
  };
}

/** Default oops window (15 min) served when the operator mandates upload. */
export const DEFAULT_OOPS_WINDOW_SECONDS = 900;

/**
 * Served settings: stored settings plus `oops_window_seconds: 900` when
 * `upload_control` is `operator` and no window was set. Storage is untouched.
 */
export function projectSettings(settings: CaptureSettings): CaptureSettings {
  if (settings.upload_control === "operator" && settings.oops_window_seconds === undefined) {
    return { ...settings, oops_window_seconds: DEFAULT_OOPS_WINDOW_SECONDS };
  }
  return settings;
}

export async function readCapturePolicy(database: Database, organizationId: string): Promise<CapturePolicy> {
  const result = await database.query<CapturePolicyRow>(
    "SELECT revision, settings, sharing_mode_since FROM capture_policies WHERE organization_id = $1",
    [organizationId],
  );
  return capturePolicyFromRow(result.rows[0]);
}

/**
 * Replaces (or, with `settings` empty and action cleared, resets) the policy
 * in one transaction. Revision is previous + 1; an absent row counts as the
 * unset revision 1, so the first write is revision 2.
 */
export async function writeCapturePolicy(database: Database, input: {
  organizationId: string;
  settings: CaptureSettings;
  expectedRevision?: number;
  actor: AuditActor;
  action: "capture_policy.set" | "capture_policy.cleared";
}): Promise<CapturePolicy> {
  return database.transaction(async (tx) => {
    // Serializes writers per organization, including the first insert.
    await tx.query("SELECT id FROM organizations WHERE id = $1 FOR UPDATE", [input.organizationId]);
    const current = capturePolicyFromRow((await tx.query<CapturePolicyRow>(
      "SELECT revision, settings, sharing_mode_since FROM capture_policies WHERE organization_id = $1",
      [input.organizationId],
    )).rows[0]);
    if (input.expectedRevision !== undefined && input.expectedRevision !== current.revision) {
      throw new CapturePolicyError(409, "revision_mismatch",
        `Capture policy is at revision ${current.revision}, not ${input.expectedRevision}`);
    }
    const revision = current.revision + 1;
    const userId = input.actor.kind === "user" ? input.actor.userId : null;
    // sharing_mode_since: kept while sharing_mode stays `new`, set when it
    // becomes `new`, cleared otherwise. clock_timestamp(), not now(): now() is
    // the transaction start, before the organization lock wait above, so it
    // could predate the moment `new` takes effect and admit older sessions.
    const written = await tx.query<{ sharing_mode_since: Date | string | null }>(
      `INSERT INTO capture_policies (organization_id, revision, settings, set_by_user_id, updated_at, sharing_mode_since)
       VALUES ($1, $2, $3::jsonb, $4, now(), CASE WHEN $3::jsonb->>'sharing_mode' = 'new' THEN clock_timestamp() END)
       ON CONFLICT (organization_id) DO UPDATE
         SET revision = EXCLUDED.revision, settings = EXCLUDED.settings,
             set_by_user_id = EXCLUDED.set_by_user_id, updated_at = now(),
             sharing_mode_since = CASE
               WHEN EXCLUDED.settings->>'sharing_mode' IS DISTINCT FROM 'new' THEN NULL
               WHEN capture_policies.settings->>'sharing_mode' = 'new'
                 THEN COALESCE(capture_policies.sharing_mode_since, clock_timestamp())
               ELSE clock_timestamp()
             END
       RETURNING sharing_mode_since`,
      [input.organizationId, revision, JSON.stringify(input.settings), userId],
    );
    // The audit row names the keys, never their values.
    const keys = Object.keys(input.settings).sort();
    await recordAudit(tx, {
      organizationId: input.organizationId,
      actor: input.actor,
      action: input.action,
      target: `${input.organizationId} revision=${revision}${keys.length ? ` keys=${keys.join(",")}` : ""}`,
    });
    return capturePolicyFromRow({ revision, settings: input.settings, sharing_mode_since: written.rows[0]?.sharing_mode_since ?? null });
  });
}

/**
 * The header Agent Relay Desktop sends with each upload and each
 * direct-upload credentials ask: the policy revision it applies.
 */
export const CAPTURE_POLICY_REVISION_HEADER = "x-agent-relay-capture-policy-revision";

/** SELFHOST_CAPTURE_POLICY_UPLOADS: log a stale upload (`report`) or refuse it (`enforce`). */
export type CapturePolicyUploadsMode = "report" | "enforce";

/**
 * How an upload's applied revision compares with the organization's policy.
 * `unset`: no setting is mandated, so no revision is needed. `missing`: the
 * header is absent or not a revision. `stale`: older than the current one.
 */
export function uploadPolicyVerdict(
  policy: CapturePolicy,
  header: string | string[] | undefined,
): "current" | "unset" | "missing" | "stale" {
  if (Object.keys(policy.settings).length === 0) return "unset";
  const raw = (Array.isArray(header) ? header[0] ?? "" : header ?? "").trim();
  if (!/^[1-9][0-9]{0,9}$/.test(raw)) return "missing";
  return Number(raw) < policy.revision ? "stale" : "current";
}
