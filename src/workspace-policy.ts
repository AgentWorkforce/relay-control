import type { Database, SqlExecutor } from "./database.js";
import { recordAudit, type AuditActor } from "./admin/audit.js";
import {
  CapturePolicyError,
  parseCaptureSettings,
  projectSettings,
  type CaptureSettings,
} from "./capture-policy.js";

/**
 * Workspace policy v2 (docs/workspace-policy.md): one versioned document
 * served to Agent Relay Desktop beside the capture policy. Each section has
 * two tiers: `locked` values the person cannot change, `defaults` initial
 * values the person may change. An absent key leaves the client's own
 * behaviour unchanged. Nothing is ever defaulted here.
 *
 * Storage is the organization's capture_policies row (migration 0072): the
 * capture section is the existing `settings` (lock-only), the other sections
 * are `workspace_settings`. `revision` here is `workspace_revision`, which
 * advances on every write; the capture revision advances only when the
 * capture settings change, because Desktop uploads are checked against it.
 */

export type PolicyValue = boolean | number | string | string[];
export type PolicyTier = Record<string, PolicyValue>;
export type PolicySection = { locked: PolicyTier; defaults: PolicyTier };
/** Capture keys are always locked; `defaults` is always empty. */
export type CaptureSection = { locked: CaptureSettings; defaults: Record<string, never> };

export type WorkspaceSections = {
  capture: CaptureSection;
  spawn: PolicySection;
  join: PolicySection;
  delivery: PolicySection;
  analytics: PolicySection;
};

/** The non-capture sections, as stored in `workspace_settings`. */
export type StoredWorkspaceSections = Pick<WorkspaceSections, "spawn" | "join" | "delivery" | "analytics">;

export type WorkspacePolicy = {
  version: 2;
  revision: number;
  managed: boolean;
  consent: string[];
  sections: WorkspaceSections;
};

/** A validated PUT body: every section present (absent ones empty). */
export type WorkspacePolicyInput = {
  sections: WorkspaceSections;
  consent: string[];
};

type WorkspacePolicyRow = {
  revision: number | string | null;
  settings: unknown;
  sharing_mode_since?: Date | string | null;
  workspace_settings: unknown;
  workspace_revision: number | string | null;
  consent: string[] | null;
};

export const SECTION_NAMES = ["capture", "spawn", "join", "delivery", "analytics"] as const;
type SectionName = (typeof SECTION_NAMES)[number];
type StoredSectionName = Exclude<SectionName, "capture">;
const STORED_SECTIONS: readonly StoredSectionName[] = ["spawn", "join", "delivery", "analytics"];

/**
 * Keys a person must consent to before an operator value applies on their
 * computer. `consent` may name only these.
 */
export const PERSON_ONLY_KEYS: readonly string[] = Object.freeze([
  "accept_spawns",
  "spawn_allow_teammates",
  "spawn_full_access_claude",
  "spawn_full_access_codex",
  "spawn_native_input",
  "spawn_requester_approvals",
  "spawn_repositories",
]);

/** Billing per harness, as Agent Relay Desktop stores it. */
export const SPAWN_BILLING_VALUES = ["subscription", "api", "unspecified"] as const;
export const INBOUND_DEFAULT_VALUES = ["deliver", "hold"] as const;
export const SPAWN_MAX_AGENTS_MAX = 32;
const MAX_LIST_ENTRIES = 200;
const MAX_LIST_ENTRY_LENGTH = 200;
const REPOSITORY = /^[A-Za-z0-9_.-]{1,100}\/(?:[A-Za-z0-9_.-]{1,100}|\*)$/;

function invalid(message: string): CapturePolicyError {
  return new CapturePolicyError(400, "invalid_policy", message);
}

const name64 = (value: string) => value.slice(0, 64);

type Validator = (key: string, value: unknown) => PolicyValue;

const bool: Validator = (key, value) => {
  if (typeof value !== "boolean") throw invalid(`${key} must be a boolean`);
  return value;
};

const integer = (min: number, max: number): Validator => (key, value) => {
  if (typeof value !== "number" || !Number.isInteger(value) || value < min || value > max) {
    throw invalid(`${key} must be an integer from ${min} to ${max}`);
  }
  return value;
};

const oneOf = (values: readonly string[]): Validator => (key, value) => {
  if (typeof value !== "string" || !values.includes(value)) {
    throw invalid(`${key} must be one of ${values.join(", ")}`);
  }
  return value;
};

const stringList: Validator = (key, value) => {
  if (!Array.isArray(value) || value.length > MAX_LIST_ENTRIES) {
    throw invalid(`${key} must be an array of at most ${MAX_LIST_ENTRIES} strings`);
  }
  for (const entry of value) {
    if (typeof entry !== "string" || entry.length < 1 || entry.length > MAX_LIST_ENTRY_LENGTH) {
      throw invalid(`${key} entries must be strings of 1 to ${MAX_LIST_ENTRY_LENGTH} characters`);
    }
  }
  return [...value] as string[];
};

/**
 * `owner/name`, or `owner/*` for every repository under an owner; lower-cased so matching is
 * stable and duplicates after lower-casing collapse. A client matches locally and reports only the
 * matched `owner/name`.
 */
const repositoryList: Validator = (key, value) => {
  if (!Array.isArray(value) || value.length > MAX_LIST_ENTRIES) {
    throw invalid(`${key} must be an array of at most ${MAX_LIST_ENTRIES} repositories`);
  }
  const repositories: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string" || !REPOSITORY.test(entry)) {
      throw invalid(`${key} entries must be owner/name repositories or owner/* for a whole owner`);
    }
    const lower = entry.toLowerCase();
    if (!repositories.includes(lower)) repositories.push(lower);
  }
  return repositories;
};

/** The allowlist (docs/workspace-policy.md). Capture keys are validated by parseCaptureSettings. */
const ALLOWLIST: Record<StoredSectionName, Record<string, Validator>> = {
  spawn: {
    accept_spawns: bool,
    spawn_allow_teammates: bool,
    spawn_max_agents: integer(1, SPAWN_MAX_AGENTS_MAX),
    spawn_native_input: bool,
    spawn_requester_approvals: bool,
    spawn_repositories: stringList,
    spawn_full_access_claude: bool,
    spawn_full_access_codex: bool,
    spawn_billing_claude: oneOf(SPAWN_BILLING_VALUES),
    spawn_billing_codex: oneOf(SPAWN_BILLING_VALUES),
  },
  join: {
    auto_join_general: bool,
    auto_join_repositories: repositoryList,
    trust_workspace_members: bool,
  },
  delivery: {
    inbound_default: oneOf(INBOUND_DEFAULT_VALUES),
    trusted_relay_senders: stringList,
  },
  analytics: {
    analytics_enabled: bool,
  },
};

const emptySection = (): PolicySection => ({ locked: {}, defaults: {} });

function emptyStoredSections(): StoredWorkspaceSections {
  return { spawn: emptySection(), join: emptySection(), delivery: emptySection(), analytics: emptySection() };
}

export const UNSET_WORKSPACE_POLICY: WorkspacePolicy = Object.freeze({
  version: 2,
  revision: 1,
  managed: false,
  consent: Object.freeze([]) as unknown as string[],
  sections: Object.freeze({ capture: { locked: {}, defaults: {} }, ...emptyStoredSections() }),
}) as WorkspacePolicy;

function isObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function parseTier(section: StoredSectionName, tier: "locked" | "defaults", value: unknown): PolicyTier {
  if (value === undefined) return {};
  if (!isObject(value)) throw invalid(`${section}.${tier} must be a JSON object`);
  const parsed: PolicyTier = {};
  for (const [key, entry] of Object.entries(value)) {
    if (section === "delivery" && key === "admin_senders") {
      throw invalid("admin_senders is computed by the server");
    }
    const validate = Object.hasOwn(ALLOWLIST[section], key) ? ALLOWLIST[section][key] : undefined;
    if (!validate) throw invalid(`Unknown ${section} policy key: ${name64(key)}`);
    parsed[key] = validate(key, entry);
  }
  return parsed;
}

function sectionTiers(name: SectionName, value: unknown): { locked: unknown; defaults: unknown } {
  if (!isObject(value)) throw invalid(`${name} must be a JSON object`);
  for (const key of Object.keys(value)) {
    if (key !== "locked" && key !== "defaults") {
      throw invalid(`Unknown ${name} policy tier: ${name64(key)}`);
    }
  }
  return { locked: value.locked, defaults: value.defaults };
}

/** Validates a PUT body `{sections, consent?}` (unknown fields, sections, keys, values). */
export function parseWorkspacePolicyInput(body: Record<string, unknown>): WorkspacePolicyInput {
  const extra = Object.keys(body).filter((key) => key !== "sections" && key !== "consent");
  if (extra.length > 0) throw invalid(`Unknown field: ${name64(extra[0]!)}`);
  const given = body.sections;
  if (!isObject(given)) throw invalid("sections must be a JSON object");
  for (const key of Object.keys(given)) {
    if (!(SECTION_NAMES as readonly string[]).includes(key)) {
      throw invalid(`Unknown policy section: ${name64(key)}`);
    }
  }

  let capture: CaptureSettings = {};
  if (given.capture !== undefined) {
    const tiers = sectionTiers("capture", given.capture);
    if (tiers.defaults !== undefined) {
      if (!isObject(tiers.defaults)) throw invalid("capture.defaults must be a JSON object");
      const key = Object.keys(tiers.defaults)[0];
      if (key !== undefined) throw invalid(`${name64(key)}: capture keys are always locked`);
    }
    if (tiers.locked !== undefined) capture = parseCaptureSettings(tiers.locked);
  }

  const sections = emptyStoredSections();
  for (const name of STORED_SECTIONS) {
    if (given[name] === undefined) continue;
    const tiers = sectionTiers(name, given[name]);
    const locked = parseTier(name, "locked", tiers.locked);
    const defaults = parseTier(name, "defaults", tiers.defaults);
    const both = Object.keys(locked).find((key) => Object.hasOwn(defaults, key));
    if (both !== undefined) throw invalid(`${both} may be locked or a default, not both`);
    sections[name] = { locked, defaults };
  }

  return {
    sections: { capture: { locked: capture, defaults: {} }, ...sections },
    consent: parseConsent(body.consent),
  };
}

function parseConsent(value: unknown): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw invalid("consent must be an array of key names");
  for (const entry of value) {
    if (typeof entry !== "string" || !PERSON_ONLY_KEYS.includes(entry)) {
      throw invalid(`consent may name only person-only keys, not ${name64(String(entry))}`);
    }
  }
  return [...new Set(value as string[])].sort();
}

/** A stored tier as written; anything malformed reads as empty. */
function storedTier(value: unknown): PolicyTier {
  return isObject(value) ? { ...(value as PolicyTier) } : {};
}

function storedSections(value: unknown): StoredWorkspaceSections {
  const sections = emptyStoredSections();
  if (!isObject(value)) return sections;
  for (const name of STORED_SECTIONS) {
    const section = value[name];
    if (!isObject(section)) continue;
    sections[name] = { locked: storedTier(section.locked), defaults: storedTier(section.defaults) };
  }
  return sections;
}

function storedCapture(value: unknown): CaptureSettings {
  return isObject(value) ? value as CaptureSettings : {};
}

/** Whether delivery sets `inbound_default` in either tier: only then are admin senders served. */
function deliveryNamesInbound(sections: StoredWorkspaceSections): boolean {
  return Object.hasOwn(sections.delivery.locked, "inbound_default")
    || Object.hasOwn(sections.delivery.defaults, "inbound_default");
}

/**
 * The served document for a stored row (absent: unset). `adminSenders` is
 * given only on a workspace read (access/me); it is served in
 * `delivery.locked.admin_senders` while delivery sets `inbound_default`.
 */
export function workspacePolicyFromRow(
  row: WorkspacePolicyRow | null | undefined,
  adminSenders?: string[],
): WorkspacePolicy {
  const sections = storedSections(row?.workspace_settings);
  if (adminSenders !== undefined && deliveryNamesInbound(sections)) {
    sections.delivery.locked = { admin_senders: [...adminSenders], ...sections.delivery.locked };
  }
  const stored = row?.workspace_revision;
  const consent = row?.consent;
  return {
    version: 2,
    revision: stored === null || stored === undefined ? 1 : Number(stored),
    // Always false until enrollment-key consent lands (the key will decide it).
    managed: false,
    consent: Array.isArray(consent) ? [...consent].sort() : [],
    sections: {
      capture: { locked: projectSettings(storedCapture(row?.settings)), defaults: {} },
      ...sections,
    },
  };
}

const ROW_COLUMNS = "revision, settings, sharing_mode_since, workspace_settings, workspace_revision, consent";

/**
 * `agent_name` and `address` of every Desktop relay identity synced into the
 * workspace by an organization owner or admin, sorted and deduplicated.
 */
async function adminSendersFor(executor: SqlExecutor, organizationId: string, workspaceId: string): Promise<string[]> {
  const result = await executor.query<{ agent_name: string; address: string }>(
    `SELECT d.agent_name, d.address
       FROM desktop_relay_identities d
       JOIN organization_memberships m
         ON m.organization_id = d.organization_id AND m.user_id = d.user_id
      WHERE d.workspace_id = $1 AND d.organization_id = $2 AND m.role IN ('owner', 'admin')`,
    [workspaceId, organizationId],
  );
  return [...new Set(result.rows.flatMap((row) => [row.agent_name, row.address]))].sort();
}

/**
 * The served workspace policy. With `workspaceId` (access/me) admin senders
 * are resolved for that workspace; the organization route omits them.
 */
export async function readWorkspacePolicy(
  database: Database,
  organizationId: string,
  options: { workspaceId?: string } = {},
): Promise<WorkspacePolicy> {
  const row = (await database.query<WorkspacePolicyRow>(
    `SELECT ${ROW_COLUMNS} FROM capture_policies WHERE organization_id = $1`,
    [organizationId],
  )).rows[0];
  if (options.workspaceId === undefined) return workspacePolicyFromRow(row);
  const stored = storedSections(row?.workspace_settings);
  const senders = deliveryNamesInbound(stored)
    ? await adminSendersFor(database, organizationId, options.workspaceId)
    : [];
  return workspacePolicyFromRow(row, senders);
}

/** Order-independent comparison of two capture settings objects. */
function sameCapture(left: CaptureSettings, right: CaptureSettings): boolean {
  const canonical = (settings: CaptureSettings) =>
    JSON.stringify(Object.entries(settings).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
  return canonical(left) === canonical(right);
}

/** Audit key names (`section.key`, `consent.key`), sorted; never values. */
function auditKeys(input: WorkspacePolicyInput): string[] {
  const keys = Object.keys(input.sections.capture.locked).map((key) => `capture.${key}`);
  for (const name of STORED_SECTIONS) {
    const section = input.sections[name];
    for (const key of [...Object.keys(section.locked), ...Object.keys(section.defaults)]) keys.push(`${name}.${key}`);
  }
  for (const key of input.consent) keys.push(`consent.${key}`);
  return keys.sort();
}

/**
 * Replaces (or, with everything empty and action cleared, resets) the
 * workspace policy in one transaction. `workspace_revision` is previous + 1
 * on every write; the capture `revision` (and `sharing_mode_since`) moves
 * only when the capture settings differ from the stored ones. An absent row
 * counts as revision 1 for both, so the first write of either is 2.
 */
export async function writeWorkspacePolicy(database: Database, input: {
  organizationId: string;
  sections: WorkspaceSections;
  consent: string[];
  expectedRevision?: number;
  actor: AuditActor;
  action: "workspace_policy.set" | "workspace_policy.cleared";
}): Promise<WorkspacePolicy> {
  return database.transaction(async (tx) => {
    // Serializes writers per organization (both routes), including the first insert.
    await tx.query("SELECT id FROM organizations WHERE id = $1 FOR UPDATE", [input.organizationId]);
    const row = (await tx.query<WorkspacePolicyRow>(
      `SELECT ${ROW_COLUMNS} FROM capture_policies WHERE organization_id = $1`,
      [input.organizationId],
    )).rows[0];
    const current = workspacePolicyFromRow(row);
    if (input.expectedRevision !== undefined && input.expectedRevision !== current.revision) {
      throw new CapturePolicyError(409, "revision_mismatch",
        `Workspace policy is at revision ${current.revision}, not ${input.expectedRevision}`);
    }
    const workspaceRevision = current.revision + 1;
    const storedSettings = storedCapture(row?.settings);
    const storedRevision = row?.revision;
    const captureRevision = storedRevision === null || storedRevision === undefined ? 1 : Number(storedRevision);
    const capture = input.sections.capture.locked;
    const captureChanged = !sameCapture(storedSettings, capture);
    // Unchanged capture settings are written back exactly as stored, at the same revision.
    const settings = captureChanged ? capture : storedSettings;
    const { spawn, join, delivery, analytics } = input.sections;
    const workspaceSettings: StoredWorkspaceSections = { spawn, join, delivery, analytics };
    const revision = captureChanged ? captureRevision + 1 : captureRevision;
    const userId = input.actor.kind === "user" ? input.actor.userId : null;
    // sharing_mode_since follows writeCapturePolicy (src/capture-policy.ts);
    // with the settings unchanged the same rule keeps the stored time.
    const written = await tx.query<{ sharing_mode_since: Date | string | null }>(
      `INSERT INTO capture_policies
         (organization_id, revision, settings, set_by_user_id, updated_at, sharing_mode_since,
          workspace_settings, workspace_revision, consent)
       VALUES ($1, $2, $3::jsonb, $4, now(), CASE WHEN $3::jsonb->>'sharing_mode' = 'new' THEN clock_timestamp() END,
               $5::jsonb, $6, $7::text[])
       ON CONFLICT (organization_id) DO UPDATE
         SET revision = EXCLUDED.revision, settings = EXCLUDED.settings,
             set_by_user_id = EXCLUDED.set_by_user_id, updated_at = now(),
             workspace_settings = EXCLUDED.workspace_settings,
             workspace_revision = EXCLUDED.workspace_revision,
             consent = EXCLUDED.consent,
             sharing_mode_since = CASE
               WHEN EXCLUDED.settings->>'sharing_mode' IS DISTINCT FROM 'new' THEN NULL
               WHEN capture_policies.settings->>'sharing_mode' = 'new'
                 THEN COALESCE(capture_policies.sharing_mode_since, clock_timestamp())
               ELSE clock_timestamp()
             END
       RETURNING sharing_mode_since`,
      [
        input.organizationId,
        revision,
        JSON.stringify(settings),
        userId,
        JSON.stringify(workspaceSettings),
        workspaceRevision,
        input.consent,
      ],
    );
    // The audit row names the keys, never their values.
    const keys = auditKeys(input);
    await recordAudit(tx, {
      organizationId: input.organizationId,
      actor: input.actor,
      action: input.action,
      target: `${input.organizationId} revision=${workspaceRevision}${keys.length ? ` keys=${keys.join(",")}` : ""}`,
    });
    return workspacePolicyFromRow({
      revision,
      settings,
      sharing_mode_since: written.rows[0]?.sharing_mode_since ?? null,
      workspace_settings: workspaceSettings,
      workspace_revision: workspaceRevision,
      consent: input.consent,
    });
  });
}
