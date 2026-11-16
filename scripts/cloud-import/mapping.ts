// Cloud (hosted, schema `public`) -> relay-control identity import: the
// mapping contract. The importer reads its source rows through exactly these
// queries, and the verifier (../cloud-import-verify) projects the same
// queries, so a skip rule cannot drift between the two.
//
// Every source query returns one row per candidate source row plus a
// `skip_reason` column: NULL means "import", any other value is a stable,
// documented reason that the importer counts in its JSON ledger. Rows are
// never dropped without a reason, except rows outside the selected
// organisations, which are not candidates at all.
//
// The rules here are reviewed configuration. Bump MAPPING_REVISION whenever a
// rule, a projection or a target column changes.

export const MAPPING_REVISION = "cloud-identity-2026-11-15.3";

/** Lowest Control migration the import is written against. */
export const REQUIRED_MIGRATION = "0051_grok_bot_routines.sql";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type ImportScope = {
  /** Cloud organisation ids to import. `null` imports every organisation. */
  orgIds: readonly string[] | null;
};

export function assertScope(scope: ImportScope): void {
  if (scope.orgIds === null) return;
  if (scope.orgIds.length === 0) throw new Error("org scope must name at least one organization");
  for (const id of scope.orgIds) {
    if (!UUID.test(id)) throw new Error("org scope ids must be UUIDs");
  }
}

/** Literal uuid[] for the scope. Ids are validated UUIDs, so inlining is safe. */
function orgArray(scope: ImportScope): string {
  assertScope(scope);
  return scope.orgIds === null
    ? "NULL::uuid[]"
    : `ARRAY[${scope.orgIds.map((id) => `'${id.toLowerCase()}'`).join(", ")}]::uuid[]`;
}

// Control's normalizeEmailAddress (src/identity/config.ts), in SQL.
const validEmail = (expression: string) =>
  `(${expression} IS NOT NULL AND length(${expression}) <= 320 AND ${expression} ~ '^[^@[:space:]<>()",;:]+@[^@[:space:]<>()",;:]+\\.[^@[:space:]<>()",;:]+$')`;
const normEmail = (expression: string) => `lower(btrim(${expression}))`;
const ROLE_RANK = (expression: string) =>
  `(CASE ${expression} WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 WHEN 'member' THEN 2 ELSE 3 END)`;
const RW_FORMAT = "'^rw_[0-9a-f]{8}$'";
// 0056 workspaces_relayhistory_origin_format. Cloud stores a bare https
// origin; it is lowercased and stripped of a trailing slash. A value that
// still does not fit is dropped (NULL = Control default) and flagged.
const ORIGIN_FORMAT = "'^https?://([[:alnum:].-]+|\\[[0-9A-Fa-f:.]+\\])(:[0-9]{1,5})?$'";
const ORIGIN = (expression: string) => `lower(rtrim(btrim(${expression}), '/'))`;

/**
 * Shared CTEs. Order matters: later CTEs read earlier ones.
 *
 * - Emails: lower(btrim(primary_email)) when valid, otherwise the user's
 *   best auth_identities email (verified first, then oldest). Users with no
 *   valid email cannot sign in to Control and are skipped.
 * - Duplicate emails (O4): the oldest user (created_at, then id) survives;
 *   every other Cloud user with that email maps onto the survivor. Rows that
 *   reference a merged user are rewritten to the survivor, then de-duplicated
 *   on the target's unique keys.
 * - Memberships: only status 'active' with role owner|admin|member. After a
 *   merge, the highest role wins.
 * - Workspaces need a live Relaycast binding (rw_ -> relay_workspaces with a
 *   provider id and a non-empty key). A workspace whose delete has started is
 *   skipped.
 */
function ctes(scope: ImportScope): string {
  const orgs = orgArray(scope);
  const scoped = scope.orgIds === null ? "false" : "true";
  return `
scope_orgs AS (
  SELECT o.id FROM public.organizations o
   WHERE ${orgs} IS NULL OR o.id = ANY(${orgs})
),
ident_email AS (
  SELECT DISTINCT ON (a.user_id) a.user_id, ${normEmail("a.email")} AS email
    FROM public.auth_identities a
   WHERE ${validEmail(normEmail("a.email"))}
   ORDER BY a.user_id, a.email_verified DESC, a.created_at, a.id
),
cloud_users AS (
  SELECT u.id, u.name, u.created_at, u.updated_at, u.last_organization_id, u.last_workspace_id,
         COALESCE(
           CASE WHEN ${validEmail(normEmail("u.primary_email"))} THEN ${normEmail("u.primary_email")} END,
           ie.email
         ) AS email
    FROM public.users u
    LEFT JOIN ident_email ie ON ie.user_id = u.id
),
user_map AS (
  SELECT cu.id AS cloud_user_id,
         first_value(cu.id) OVER (PARTITION BY cu.email ORDER BY cu.created_at, cu.id) AS user_id
    FROM cloud_users cu
   WHERE cu.email IS NOT NULL
),
member_rows AS (
  SELECT m.organization_id, um.user_id, m.user_id AS cloud_user_id, m.role, m.created_at, m.updated_at,
         CASE
           WHEN um.user_id IS NULL THEN 'user_not_imported'
           WHEN m.status <> 'active' THEN 'inactive_membership'
           WHEN ${ROLE_RANK("m.role")} = 3 THEN 'unsupported_role'
           WHEN row_number() OVER (
             PARTITION BY m.organization_id, um.user_id
             ORDER BY (m.status <> 'active'), ${ROLE_RANK("m.role")}, m.created_at, m.user_id
           ) > 1 THEN 'merged_duplicate_membership'
         END AS skip_reason
    FROM public.organization_memberships m
    JOIN scope_orgs s ON s.id = m.organization_id
    LEFT JOIN user_map um ON um.cloud_user_id = m.user_id
),
imported_members AS (
  SELECT organization_id, user_id FROM member_rows WHERE skip_reason IS NULL
),
workspace_rows AS (
  SELECT w.id, w.organization_id, w.name,
         rw.relaycast_workspace_id,
         rw.relaycast_api_key,
         w.default_runtime AS runtime_config,
         CASE WHEN w.relay_workspace_id ~ ${RW_FORMAT} THEN w.relay_workspace_id END AS cloud_relay_workspace_id,
         w.slug,
         CASE WHEN ${ORIGIN("w.relayhistory_origin")} ~ ${ORIGIN_FORMAT}
              THEN ${ORIGIN("w.relayhistory_origin")} END AS relayhistory_origin,
         (w.relayhistory_origin IS NOT NULL AND ${ORIGIN("w.relayhistory_origin")} !~ ${ORIGIN_FORMAT}) AS origin_invalid,
         rw.relaycast_api_key_generation,
         (w.relayhistory_dashboard_url IS NOT NULL) AS has_dashboard_url,
         w.created_at, w.updated_at,
         CASE
           WHEN w.deletion_requested_at IS NOT NULL THEN 'workspace_being_deleted'
           WHEN w.relay_workspace_id IS NULL THEN 'no_relay_workspace'
           WHEN rw.id IS NULL THEN 'relay_workspace_missing'
           WHEN rw.relaycast_workspace_id IS NULL OR rw.relaycast_workspace_id = '' THEN 'no_relaycast_binding'
           WHEN rw.relaycast_api_key IS NULL OR rw.relaycast_api_key = '' THEN 'no_relaycast_key'
           WHEN row_number() OVER (
             PARTITION BY w.relay_workspace_id
             ORDER BY (w.deletion_requested_at IS NOT NULL), w.created_at, w.id
           ) > 1 THEN 'duplicate_rw_binding'
           WHEN row_number() OVER (
             PARTITION BY w.organization_id, rw.relaycast_workspace_id
             ORDER BY (w.deletion_requested_at IS NOT NULL), w.created_at, w.id
           ) > 1 THEN 'duplicate_relaycast_binding'
         END AS skip_reason
    FROM public.workspaces w
    JOIN scope_orgs s ON s.id = w.organization_id
    LEFT JOIN public.relay_workspaces rw ON rw.id = w.relay_workspace_id
),
imported_workspaces AS (
  SELECT id, organization_id, relaycast_workspace_id, cloud_relay_workspace_id
    FROM workspace_rows WHERE skip_reason IS NULL
),
user_rows AS (
  SELECT cu.id, cu.email,
         COALESCE(NULLIF(btrim(cu.name), ''), cu.email) AS name,
         cu.created_at, cu.updated_at,
         CASE WHEN EXISTS (
           SELECT 1 FROM imported_members im
            WHERE im.user_id = cu.id AND im.organization_id = cu.last_organization_id
         ) THEN cu.last_organization_id END AS last_organization_id,
         CASE WHEN EXISTS (
           SELECT 1 FROM imported_workspaces iw
             JOIN imported_members im ON im.organization_id = iw.organization_id AND im.user_id = cu.id
            WHERE iw.id = cu.last_workspace_id
         ) THEN cu.last_workspace_id END AS last_workspace_id,
         CASE
           WHEN cu.email IS NULL THEN 'no_valid_email'
           WHEN um.user_id <> cu.id THEN 'merged_into_survivor'
           WHEN ${scoped} AND NOT EXISTS (SELECT 1 FROM imported_members im WHERE im.user_id = cu.id)
             THEN 'outside_org_scope'
         END AS skip_reason
    FROM cloud_users cu
    LEFT JOIN user_map um ON um.cloud_user_id = cu.id
),
imported_users AS (
  SELECT id FROM user_rows WHERE skip_reason IS NULL
),
github_rows AS (
  -- #146 import contract: the default (name IS NULL) Cloud GitHub connection
  -- becomes a github_app connection anchored on its installation. Cloud keys
  -- workspace_integrations by rw_ (older rows by the app workspace UUID).
  SELECT wi.id, iw.id AS workspace_id, iw.organization_id, wi.installation_id,
         iu.id AS created_by_user_id, wi.created_at, wi.updated_at,
         CASE
           WHEN iw.id IS NULL THEN 'workspace_not_imported'
           WHEN wi.name IS NOT NULL THEN 'named_connection_needs_policy'
           WHEN wi.installation_id IS NULL OR wi.installation_id !~ '^[1-9][0-9]{0,19}$' THEN 'invalid_installation_id'
           WHEN first_value(iw.organization_id) OVER (
             PARTITION BY wi.installation_id, (wi.name IS NULL), (iw.id IS NOT NULL)
             ORDER BY wi.created_at, wi.id
           ) <> iw.organization_id THEN 'installation_claimed_by_other_org'
         END AS skip_reason
    FROM public.workspace_integrations wi
    -- A workspace being deleted may still hold the same rw_; never match it.
    JOIN public.workspaces w
      ON (w.relay_workspace_id = wi.workspace_id AND w.deletion_requested_at IS NULL)
      OR w.id::text = wi.workspace_id
    JOIN scope_orgs s ON s.id = w.organization_id
    LEFT JOIN imported_workspaces iw ON iw.id = w.id
    LEFT JOIN user_map um ON um.cloud_user_id = wi.created_by_user_id
    LEFT JOIN imported_users iu ON iu.id = um.user_id
   WHERE wi.provider = 'github'
)`;
}

/** Candidate rows per target table, in dependency order. */
export const SOURCE_TABLES = [
  "users",
  "organizations",
  "organization_memberships",
  "workspaces",
  "organization_invitations",
  "person_identities",
  "hosted_relay_participants",
  "desktop_relay_identities",
  "fleet_node_owners",
  "coding_agent_credentials",
  "github_app_installations",
  "github_app_connections",
] as const;
export type ImportTable = (typeof SOURCE_TABLES)[number];

/** Organisation-scoped tables are imported in one target transaction per org. */
export const ORG_TABLES: readonly ImportTable[] = SOURCE_TABLES.filter((t) => t !== "users");

function selects(): Record<ImportTable, string> {
  return {
    users: `
SELECT id, email, name, created_at, updated_at, last_organization_id, last_workspace_id,
       NULL::uuid AS organization_id, skip_reason
  FROM user_rows`,
    organizations: `
SELECT o.id, o.id AS organization_id, o.name, o.slug, o.created_at, o.updated_at, NULL::text AS skip_reason
  FROM public.organizations o JOIN scope_orgs s ON s.id = o.id`,
    organization_memberships: `
SELECT organization_id, user_id, cloud_user_id, role, created_at, updated_at, skip_reason
  FROM member_rows`,
    workspaces: `
SELECT id, organization_id, name, relaycast_workspace_id, relaycast_api_key AS secret_plaintext,
       runtime_config, cloud_relay_workspace_id, slug, relayhistory_origin, relaycast_api_key_generation,
       has_dashboard_url, origin_invalid, created_at, updated_at, skip_reason
  FROM workspace_rows`,
    organization_invitations: `
SELECT i.id, i.organization_id, ${normEmail("i.email")} AS email, i.role,
       iu.id AS invited_by_user_id, i.expires_at, i.created_at, i.updated_at,
       CASE
         WHEN i.accepted_at IS NOT NULL THEN 'accepted'
         WHEN i.canceled_at IS NOT NULL THEN 'canceled'
         WHEN NOT ${validEmail(normEmail("i.email"))} THEN 'invalid_email'
         WHEN ${ROLE_RANK("i.role")} = 3 THEN 'unsupported_role'
         WHEN EXISTS (
           SELECT 1 FROM imported_members im JOIN user_rows ur ON ur.id = im.user_id
            WHERE im.organization_id = i.organization_id AND ur.email = ${normEmail("i.email")}
         ) THEN 'already_member'
         WHEN row_number() OVER (
           PARTITION BY i.organization_id, ${normEmail("i.email")}
           ORDER BY (i.accepted_at IS NOT NULL OR i.canceled_at IS NOT NULL), i.created_at DESC, i.id DESC
         ) > 1 THEN 'superseded_open_invite'
       END AS skip_reason
  FROM public.organization_invites i
  JOIN scope_orgs s ON s.id = i.organization_id
  LEFT JOIN user_map um ON um.cloud_user_id = i.invited_by_user_id
  LEFT JOIN imported_users iu ON iu.id = um.user_id`,
    person_identities: `
SELECT p.id, p.workspace_id, w.organization_id, iu.id AS user_id, iw.relaycast_workspace_id,
       p.agent_name, p.agent_remote_id, p.token_envelope AS secret_envelope, p.created_at,
       CASE
         WHEN iw.id IS NULL THEN 'workspace_not_imported'
         WHEN iu.id IS NULL THEN 'user_not_imported'
         WHEN p.relay_workspace_id IS DISTINCT FROM w.relay_workspace_id THEN 'stale_relay_workspace'
         WHEN row_number() OVER (
           PARTITION BY p.workspace_id, iu.id ORDER BY p.updated_at DESC, p.id
         ) > 1 THEN 'duplicate_after_merge'
       END AS skip_reason
  FROM public.workspace_person_identities p
  JOIN public.workspaces w ON w.id = p.workspace_id
  JOIN scope_orgs s ON s.id = w.organization_id
  LEFT JOIN imported_workspaces iw ON iw.id = p.workspace_id
  LEFT JOIN user_map um ON um.cloud_user_id = p.user_id
  LEFT JOIN imported_users iu ON iu.id = um.user_id`,
    hosted_relay_participants: `
SELECT h.id, h.workspace_id, w.organization_id, iu.id AS user_id, iw.relaycast_workspace_id,
       h.session_hash, h.agent_name, h.agent_remote_id, h.token_envelope AS secret_envelope,
       h.created_at, h.created_at AS updated_at,
       CASE
         WHEN iw.id IS NULL THEN 'workspace_not_imported'
         WHEN iu.id IS NULL THEN 'user_not_imported'
         WHEN h.relay_workspace_id IS DISTINCT FROM w.relay_workspace_id THEN 'stale_relay_workspace'
         WHEN row_number() OVER (
           PARTITION BY h.workspace_id, iu.id, h.agent_name ORDER BY h.created_at DESC, h.id
         ) > 1 THEN 'duplicate_after_merge'
         WHEN h.session_hash IS NOT NULL AND row_number() OVER (
           PARTITION BY h.workspace_id, iu.id, h.session_hash ORDER BY h.created_at DESC, h.id
         ) > 1 THEN 'duplicate_after_merge'
       END AS skip_reason
  FROM public.hosted_relay_participants h
  JOIN public.workspaces w ON w.id = h.workspace_id
  JOIN scope_orgs s ON s.id = w.organization_id
  LEFT JOIN imported_workspaces iw ON iw.id = h.workspace_id
  LEFT JOIN user_map um ON um.cloud_user_id = h.user_id
  LEFT JOIN imported_users iu ON iu.id = um.user_id`,
    desktop_relay_identities: `
SELECT d.id, d.workspace_id, w.organization_id, iu.id AS user_id, iw.relaycast_workspace_id,
       -- #152: lowercase UUID-shaped ids, keep opaque ids byte for byte.
       CASE WHEN d.source_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            THEN lower(d.source_id) ELSE d.source_id END AS source_id,
       (d.source_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') AS source_id_is_uuid,
       d.agent_name, d.agent_remote_id, d.address,
       CASE WHEN d.native_session_kind IS NOT NULL AND d.native_session_id IS NOT NULL THEN d.native_session_kind END AS native_session_kind,
       CASE WHEN d.native_session_kind IS NOT NULL AND d.native_session_id IS NOT NULL THEN d.native_session_id END AS native_session_id,
       d.token_envelope AS secret_envelope, d.created_at, d.updated_at,
       CASE
         WHEN iw.id IS NULL THEN 'workspace_not_imported'
         WHEN iu.id IS NULL THEN 'user_not_imported'
         WHEN NOT EXISTS (
           SELECT 1 FROM imported_members im WHERE im.organization_id = w.organization_id AND im.user_id = iu.id
         ) THEN 'not_a_member'
         WHEN d.relay_workspace_id IS DISTINCT FROM w.relay_workspace_id THEN 'stale_relay_workspace'
         WHEN row_number() OVER (
           PARTITION BY d.workspace_id, iu.id,
             CASE WHEN d.source_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN lower(d.source_id) ELSE d.source_id END,
             d.agent_remote_id ORDER BY d.updated_at DESC, d.id
         ) > 1 THEN 'duplicate_after_merge'
       END AS skip_reason
  FROM public.desktop_relay_identities d
  JOIN public.workspaces w ON w.id = d.workspace_id
  JOIN scope_orgs s ON s.id = w.organization_id
  LEFT JOIN imported_workspaces iw ON iw.id = d.workspace_id
  LEFT JOIN user_map um ON um.cloud_user_id = d.user_id
  LEFT JOIN imported_users iu ON iu.id = um.user_id`,
    fleet_node_owners: `
SELECT f.id, f.workspace_id, w.organization_id, iu.id AS user_id, iw.relaycast_workspace_id,
       f.node_id, NULL::text AS node_name, f.created_at,
       CASE
         WHEN iw.id IS NULL THEN 'workspace_not_imported'
         WHEN iu.id IS NULL THEN 'user_not_imported'
         WHEN NOT EXISTS (
           SELECT 1 FROM imported_members im WHERE im.organization_id = w.organization_id AND im.user_id = iu.id
         ) THEN 'not_a_member'
         WHEN f.relay_workspace_id IS DISTINCT FROM w.relay_workspace_id THEN 'stale_relay_workspace'
       END AS skip_reason
  FROM public.fleet_node_owners f
  JOIN public.workspaces w ON w.id = f.workspace_id
  JOIN scope_orgs s ON s.id = w.organization_id
  LEFT JOIN imported_workspaces iw ON iw.id = f.workspace_id
  LEFT JOIN user_map um ON um.cloud_user_id = f.user_id
  LEFT JOIN imported_users iu ON iu.id = um.user_id`,
    // Cloud keeps every coding-agent secret in its credential store (S3),
    // not in the database. Only relay_managed rows carry no secret, so only
    // they are imported (0058 contract): credential fields stay NULL and
    // harness_active is forced off. Control allows one active credential per
    // (workspace, provider); Cloud allows one per user, so extra active rows
    // are demoted (flagged) to the newest one.
    github_app_installations: `
SELECT DISTINCT ON (installation_id) installation_id, organization_id, NULL::text AS skip_reason
  FROM github_rows WHERE skip_reason IS NULL
 ORDER BY installation_id, created_at, id`,
    github_app_connections: `
SELECT id, workspace_id, 'github'::text AS provider, 'github_app'::text AS auth_mode, 'ready'::text AS status,
       'bearer'::text AS token_type, ARRAY[]::text[] AS scopes, '{}'::jsonb AS metadata,
       created_by_user_id, created_by_user_id AS updated_by_user_id,
       installation_id, organization_id, organization_id AS github_app_organization_id,
       'empty-credentials'::text AS secret_plaintext,
       created_at, updated_at, skip_reason
  FROM github_rows`,
    coding_agent_credentials: `
SELECT p.id, iw.organization_id, p.workspace_id, iu.id AS created_by_user_id,
       p.model_provider, p.harness, p.auth_type, p.display_name, p.label, p.account_email,
       (p.is_active AND row_number() OVER (
          PARTITION BY p.workspace_id, p.model_provider, p.is_active, (p.auth_type = 'relay_managed')
          ORDER BY p.updated_at DESC, p.id
        ) = 1) AS is_active,
       (p.is_active AND row_number() OVER (
          PARTITION BY p.workspace_id, p.model_provider, p.is_active, (p.auth_type = 'relay_managed')
          ORDER BY p.updated_at DESC, p.id
        ) > 1) AS active_demoted,
       false AS harness_active,
       p.status, p.last_error, p.last_authenticated_at, p.last_used_at, p.created_at, p.updated_at,
       CASE
         WHEN iw.id IS NULL THEN 'workspace_not_imported'
         WHEN p.auth_type <> 'relay_managed' THEN 'secret_in_cloud_credential_store'
         WHEN p.model_provider NOT IN ('anthropic', 'openai', 'openrouter', 'xai', 'google') THEN 'unsupported_model_provider'
         WHEN p.status NOT IN ('connected', 'error', 'refresh_failed') THEN 'unsupported_status'
       END AS skip_reason
  FROM public.provider_credentials p
  JOIN public.workspaces w ON w.id = p.workspace_id
  JOIN scope_orgs s ON s.id = w.organization_id
  LEFT JOIN imported_workspaces iw ON iw.id = p.workspace_id
  LEFT JOIN user_map um ON um.cloud_user_id = p.user_id
  LEFT JOIN imported_users iu ON iu.id = um.user_id`,
  };
}

/** The source query for one table: every candidate row with its skip_reason. */
export function sourceQuery(table: ImportTable, scope: ImportScope): string {
  return `WITH ${ctes(scope)}\n${selects()[table]}`;
}

/**
 * How a candidate row becomes a target row.
 * - `columns`: target column <- source field (same name unless mapped).
 * - `optional`: target columns written only when the target has them
 *   (columns added by migrations after REQUIRED_MIGRATION).
 * - `secret`: the source field holding plaintext or a Cloud envelope, and the
 *   target ciphertext column it is re-encrypted into under Control's keyring.
 * - `insertOnly`: written on insert, never overwritten by a re-run.
 */
export type TargetSpec = {
  table: string;
  primaryKey: readonly string[];
  columns: readonly string[];
  optional?: readonly string[];
  secret?: { source: "secret_plaintext" | "secret_envelope"; target: string };
  /** Invites: a fresh sh_inv_ token hash, generated on insert only. */
  inviteTokenHash?: string;
  insertOnly?: readonly string[];
  /** Row key expression for the ledger (default id). */
  key?: string;
  /**
   * A table added by a later migration: when the target lacks it (or any of
   * its columns), rows are skipped with this importer reason instead of the
   * whole run being refused.
   */
  gate?: string;
  /** The secret is a constant, not a source value. */
  secretConstant?: string;
};

export const TARGETS: Record<ImportTable, TargetSpec> = {
  github_app_installations: {
    table: "github_app_installations",
    primaryKey: ["installation_id"],
    columns: ["installation_id", "organization_id"],
    // Never move a claim between organizations: a conflicting claim makes the
    // connection's composite FK fail, which fails that organization visibly.
    insertOnly: ["organization_id"],
    key: "installation_id",
    gate: "target_lacks_github_app",
  },
  github_app_connections: {
    table: "integration_connections",
    primaryKey: ["id"],
    columns: ["id", "workspace_id", "provider", "auth_mode", "status", "token_type", "scopes", "metadata", "created_by_user_id", "updated_by_user_id", "installation_id", "github_app_organization_id", "created_at", "updated_at"],
    secret: { source: "secret_plaintext", target: "credentials_ciphertext" },
    secretConstant: "{}",
    gate: "target_lacks_github_app",
  },
  coding_agent_credentials: {
    table: "coding_agent_credentials",
    primaryKey: ["id"],
    columns: ["id", "organization_id", "workspace_id", "created_by_user_id", "model_provider", "harness", "auth_type", "display_name", "label", "account_email", "is_active", "harness_active", "status", "last_error", "last_authenticated_at", "last_used_at", "created_at", "updated_at"],
  },
  users: {
    table: "users",
    primaryKey: ["id"],
    // last_* are written after every organisation is in (FKs), see importer.
    columns: ["id", "email", "name", "created_at", "updated_at"],
  },
  organizations: {
    table: "organizations",
    primaryKey: ["id"],
    columns: ["id", "name", "created_at", "updated_at"],
    optional: ["slug"], // 0056
  },
  organization_memberships: {
    table: "organization_memberships",
    primaryKey: ["organization_id", "user_id"],
    columns: ["organization_id", "user_id", "role", "created_at", "updated_at"],
  },
  workspaces: {
    table: "workspaces",
    primaryKey: ["id"],
    columns: ["id", "organization_id", "name", "relaycast_workspace_id", "runtime_config", "created_at", "updated_at"],
    // 0053: cloud_relay_workspace_id. 0056: slug, relayhistory_origin,
    // relaycast_api_key_generation. Cloud's relayhistory_dashboard_url has no
    // Control column; rows that set it are counted as a warning.
    optional: ["cloud_relay_workspace_id", "slug", "relayhistory_origin", "relaycast_api_key_generation"],
    secret: { source: "secret_plaintext", target: "relaycast_api_key_ciphertext" },
  },
  organization_invitations: {
    table: "organization_invitations",
    primaryKey: ["id"],
    columns: ["id", "organization_id", "email", "role", "invited_by_user_id", "expires_at", "created_at", "updated_at"],
    inviteTokenHash: "token_hash",
    insertOnly: ["token_hash"],
  },
  person_identities: {
    table: "person_identities",
    primaryKey: ["id"],
    columns: ["id", "workspace_id", "user_id", "relaycast_workspace_id", "agent_name", "agent_remote_id", "created_at"],
    secret: { source: "secret_envelope", target: "token_ciphertext" },
  },
  hosted_relay_participants: {
    table: "hosted_relay_participants",
    primaryKey: ["id"],
    columns: ["id", "workspace_id", "user_id", "relaycast_workspace_id", "session_hash", "agent_name", "agent_remote_id", "created_at", "updated_at"],
    secret: { source: "secret_envelope", target: "token_ciphertext" },
  },
  desktop_relay_identities: {
    table: "desktop_relay_identities",
    primaryKey: ["id"],
    columns: ["id", "workspace_id", "organization_id", "user_id", "relaycast_workspace_id", "source_id", "agent_name", "agent_remote_id", "address", "native_session_kind", "native_session_id", "created_at", "updated_at"],
    secret: { source: "secret_envelope", target: "token_ciphertext" },
  },
  fleet_node_owners: {
    table: "fleet_node_owners",
    primaryKey: ["id"],
    // Cloud has no node name. 0057 makes node_name nullable and it is left
    // NULL; on an older target (NOT NULL) the node id stands in.
    columns: ["id", "workspace_id", "organization_id", "relaycast_workspace_id", "node_id", "node_name", "user_id", "created_at"],
  },
};

/** Importer-side skips (decided after the query, recorded in the ledger). */
// coding_agent_credentials: "target_lacks_relay_managed" before 0058.
export const IMPORTER_SKIP_REASONS = [
  "cloud_decrypt_failed",
  // desktop_relay_identities.source_id is uuid before 0057.
  "source_id_not_uuid",
  "target_lacks_relay_managed",
  "target_lacks_github_app",
  "target_email_conflict",
] as const;

// ---------------------------------------------------------------------------
// Verifier contract (consumed by scripts/cloud-import-verify).

export type ComparisonSpec = {
  name: string;
  sourceSql: string;
  targetSql: string;
  /** True when both projections also expose __workspace (workspace id text). */
  workspaceScoped?: boolean;
};

/**
 * Like-for-like projections over the imported scope. Ciphertext and token
 * hashes are never compared (they are randomized); see encryptedSamples.
 * Timestamps are compared as UTC microsecond text, JSON as jsonb text.
 */
const ts = (column: string) => `to_char(${column} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US')`;

type Projection = { key: string; org: string; workspace?: string; columns: Record<string, string> };

const PROJECTIONS: Record<ImportTable, Projection> = {
  github_app_installations: {
    key: "installation_id", org: "organization_id::text",
    columns: { installation_id: "installation_id", organization_id: "organization_id::text" },
  },
  github_app_connections: {
    key: "id::text", org: "github_app_organization_id::text", workspace: "workspace_id::text",
    columns: { id: "id::text", workspace_id: "workspace_id::text", provider: "provider", auth_mode: "auth_mode", status: "status", token_type: "token_type", installation_id: "installation_id", github_app_organization_id: "github_app_organization_id::text", created_by_user_id: "created_by_user_id::text", created_at: ts("created_at") },
  },
  coding_agent_credentials: {
    key: "id::text", org: "organization_id::text", workspace: "workspace_id::text",
    columns: { id: "id::text", organization_id: "organization_id::text", workspace_id: "workspace_id::text", created_by_user_id: "created_by_user_id::text", model_provider: "model_provider", harness: "harness", auth_type: "auth_type", display_name: "display_name", label: "label", account_email: "account_email", is_active: "is_active", harness_active: "harness_active", status: "status", last_error: "last_error", last_authenticated_at: ts("last_authenticated_at"), last_used_at: ts("last_used_at"), created_at: ts("created_at") },
  },
  users: {
    key: "id::text", org: "NULL::text",
    columns: { id: "id::text", email: "email", name: "name", created_at: ts("created_at"), updated_at: ts("updated_at"), last_organization_id: "last_organization_id::text", last_workspace_id: "last_workspace_id::text" },
  },
  organizations: {
    key: "id::text", org: "id::text",
    columns: { id: "id::text", name: "name", slug: "slug", created_at: ts("created_at"), updated_at: ts("updated_at") },
  },
  organization_memberships: {
    key: "organization_id::text || ':' || user_id::text", org: "organization_id::text",
    columns: { organization_id: "organization_id::text", user_id: "user_id::text", role: "role", created_at: ts("created_at"), updated_at: ts("updated_at") },
  },
  workspaces: {
    key: "id::text", org: "organization_id::text", workspace: "id::text",
    columns: { id: "id::text", organization_id: "organization_id::text", name: "name", relaycast_workspace_id: "relaycast_workspace_id", cloud_relay_workspace_id: "cloud_relay_workspace_id", slug: "slug", relayhistory_origin: "relayhistory_origin", relaycast_api_key_generation: "relaycast_api_key_generation", runtime_config: "runtime_config::jsonb::text", created_at: ts("created_at"), updated_at: ts("updated_at") },
  },
  organization_invitations: {
    key: "id::text", org: "organization_id::text",
    columns: { id: "id::text", organization_id: "organization_id::text", email: "email", role: "role", invited_by_user_id: "invited_by_user_id::text", expires_at: ts("expires_at"), created_at: ts("created_at") },
  },
  person_identities: {
    key: "id::text", org: "organization_id::text", workspace: "workspace_id::text",
    columns: { id: "id::text", workspace_id: "workspace_id::text", user_id: "user_id::text", relaycast_workspace_id: "relaycast_workspace_id", agent_name: "agent_name", agent_remote_id: "agent_remote_id", created_at: ts("created_at") },
  },
  hosted_relay_participants: {
    key: "id::text", org: "organization_id::text", workspace: "workspace_id::text",
    columns: { id: "id::text", workspace_id: "workspace_id::text", user_id: "user_id::text", relaycast_workspace_id: "relaycast_workspace_id", session_hash: "session_hash", agent_name: "agent_name", agent_remote_id: "agent_remote_id", created_at: ts("created_at") },
  },
  desktop_relay_identities: {
    key: "id::text", org: "organization_id::text", workspace: "workspace_id::text",
    columns: { id: "id::text", workspace_id: "workspace_id::text", organization_id: "organization_id::text", user_id: "user_id::text", relaycast_workspace_id: "relaycast_workspace_id", source_id: "source_id::text", agent_name: "agent_name", agent_remote_id: "agent_remote_id", address: "address", native_session_kind: "native_session_kind", native_session_id: "native_session_id", created_at: ts("created_at") },
  },
  fleet_node_owners: {
    key: "id::text", org: "organization_id::text", workspace: "workspace_id::text",
    columns: { id: "id::text", workspace_id: "workspace_id::text", organization_id: "organization_id::text", relaycast_workspace_id: "relaycast_workspace_id", node_id: "node_id", node_name: "COALESCE(node_name, node_id)", user_id: "user_id::text", created_at: ts("created_at") },
  },
};

/** Target rows in scope. Tables without organization_id join their workspace. */
function targetScope(table: ImportTable, scope: ImportScope): { from: string; org: string } {
  const orgs = orgArray(scope);
  const filter = (column: string) => scope.orgIds === null ? "" : ` WHERE ${column} = ANY(${orgs})`;
  switch (table) {
    case "users":
      return {
        from: scope.orgIds === null
          ? "public.users t"
          : `public.users t WHERE EXISTS (SELECT 1 FROM public.organization_memberships m WHERE m.user_id = t.id AND m.organization_id = ANY(${orgs}))`,
        org: "NULL::text",
      };
    case "organizations":
      return { from: `public.organizations t${filter("t.id")}`, org: "id::text" };
    case "person_identities":
    case "hosted_relay_participants":
      return {
        from: `(SELECT x.*, w.organization_id FROM public.${table} x JOIN public.workspaces w ON w.id = x.workspace_id) t${filter("t.organization_id")}`,
        org: "organization_id::text",
      };
    case "github_app_connections":
      return {
        from: `(SELECT * FROM public.integration_connections WHERE auth_mode = 'github_app') t${filter("t.github_app_organization_id")}`,
        org: "github_app_organization_id::text",
      };
    default:
      return { from: `public.${TARGETS[table].table} t${filter("t.organization_id")}`, org: "organization_id::text" };
  }
}

/**
 * Comparisons for the verifier. `targetHasColumns` lists optional target
 * columns that exist (so a pre-0053 target is compared without them).
 */
export function verifierComparisons(
  scope: ImportScope,
  targetHasColumns: ReadonlySet<string> = new Set(["workspaces.cloud_relay_workspace_id"]),
  /** Gated tables (TargetSpec.gate) to include; default all. */
  gatedTablesPresent: ReadonlySet<ImportTable> | null = null,
): ComparisonSpec[] {
  return SOURCE_TABLES.filter((table) => !TARGETS[table].gate || gatedTablesPresent === null || gatedTablesPresent.has(table)).map((table) => {
    const projection = PROJECTIONS[table];
    const names = Object.keys(projection.columns).filter((column) =>
      !(TARGETS[table].optional ?? []).includes(column) || targetHasColumns.has(`${table}.${column}`));
    const list = names.map((name) => `${projection.columns[name]} AS ${name}`).join(", ");
    const target = targetScope(table, scope);
    const workspace = projection.workspace ? `, ${projection.workspace} AS __workspace` : "";
    return {
      name: table,
      sourceSql: `WITH ${ctes(scope)}, src AS (${selects()[table]})\nSELECT ${list}, ${projection.key} AS __key, ${projection.org} AS __org${workspace} FROM src WHERE skip_reason IS NULL`,
      targetSql: `SELECT ${list}, ${projection.key} AS __key, ${target.org} AS __org${workspace} FROM ${target.from}`,
      ...(projection.workspace ? { workspaceScoped: true } : {}),
    };
  });
}

/** Every relation the import writes, for the verifier's FK/unique scans. */
export const TARGET_RELATIONS = SOURCE_TABLES.map((table) => `public.${TARGETS[table].table}`);

/** Encrypted columns the verifier decrypts with Control's keyring. */
export function encryptedSamples(limit = 200, scope: ImportScope = { orgIds: null }): { name: string; sql: string; minimum: number; limit: number }[] {
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000) throw new Error("limit must be 1..1000");
  return SOURCE_TABLES.flatMap((table) => {
    const secret = TARGETS[table].secret;
    if (!secret) return [];
    const target = targetScope(table, scope);
    return [{
      name: `${table}.${secret.target}`,
      sql: `SELECT ${secret.target} AS ciphertext FROM ${target.from} ORDER BY ${TARGETS[table].key ?? "id"} LIMIT ${limit}`,
      minimum: 1,
      limit,
    }];
  });
}
