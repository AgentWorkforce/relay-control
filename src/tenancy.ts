import type { SqlExecutor } from "./database.js";

/**
 * Design G: one installation serves one organisation (`single`, the default
 * and today's behaviour) or many (`multi`, hosted). A request-time gate, not a
 * schema constraint (migration 0014).
 */
export type TenancyMode = "single" | "multi";

export type TenancyConfig = {
  mode: TenancyMode;
  /**
   * Multi mode: a first sign-in with no invite, membership or auto-join
   * creates a personal organisation (false: 403 no_organization). The
   * installation settings column overrides it when not NULL.
   */
  personalOrgOnSignIn: boolean;
  /**
   * Multi mode: any signed-in user may POST /api/v1/organizations (false:
   * bootstrap bearer only). The installation settings column overrides it.
   */
  selfServeOrganizations: boolean;
};

export const SINGLE_TENANCY: TenancyConfig = {
  mode: "single",
  personalOrgOnSignIn: false,
  selfServeOrganizations: false,
};

/**
 * The multi-mode defaults, used when the env var is unset. Change them by
 * editing these constants or by setting SELFHOST_PERSONAL_ORG_ON_SIGNIN /
 * SELFHOST_SELF_SERVE_ORGANIZATIONS. Single mode ignores both.
 */
export const DEFAULT_PERSONAL_ORG_ON_SIGNIN = true;
export const DEFAULT_SELF_SERVE_ORGANIZATIONS = true;

type Env = Record<string, string | undefined>;

function optionalFlag(env: Env, name: string, fallback: boolean): boolean {
  const value = env[name]?.trim().toLowerCase();
  if (!value) return fallback;
  if (value === "true" || value === "1" || value === "yes") return true;
  if (value === "false" || value === "0" || value === "no") return false;
  throw new Error(`${name} must be true or false`);
}

export function loadTenancyConfig(env: Env = process.env): TenancyConfig {
  const raw = env.SELFHOST_TENANCY?.trim().toLowerCase() || "single";
  if (raw !== "single" && raw !== "multi") {
    throw new Error(`SELFHOST_TENANCY must be single or multi, got ${JSON.stringify(env.SELFHOST_TENANCY)}`);
  }
  // Single mode ignores the multi-mode flags entirely.
  if (raw === "single") return SINGLE_TENANCY;
  return {
    mode: "multi",
    personalOrgOnSignIn: optionalFlag(env, "SELFHOST_PERSONAL_ORG_ON_SIGNIN", DEFAULT_PERSONAL_ORG_ON_SIGNIN),
    selfServeOrganizations: optionalFlag(env, "SELFHOST_SELF_SERVE_ORGANIZATIONS", DEFAULT_SELF_SERVE_ORGANIZATIONS),
  };
}

/**
 * Advisory lock order for every writer that touches users, memberships or
 * organizations (DG-005, operator review of PR #24). Within one transaction:
 *   1. lockIdentity(email): hashtext('email:' || normalised email), before
 *      the user row is upserted (a new user has no id yet);
 *   2. lockUser(user id): hashtext('user:' || id), once the row exists;
 *   3. lockOrganization(organization id): hashtext('org:' || id), in id
 *      order, when joining or changing an organization's memberships;
 *   4. ORGANIZATION_CREATE_LOCK (1947182642), last, only when creating an
 *      organization that must be unique (single mode, the bootstrap one).
 * No path takes a lock from an earlier step after a later one.
 */
export const ORGANIZATION_CREATE_LOCK = 1947182642;

export async function lockIdentity(tx: SqlExecutor, normalizedEmail: string): Promise<void> {
  await tx.query("SELECT pg_advisory_xact_lock(hashtext('email:' || $1::text))", [normalizedEmail]);
}

export async function lockUser(tx: SqlExecutor, userId: string): Promise<void> {
  await tx.query("SELECT pg_advisory_xact_lock(hashtext('user:' || $1::text))", [userId]);
}

export async function lockOrganization(tx: SqlExecutor, organizationId: string): Promise<void> {
  await tx.query("SELECT pg_advisory_xact_lock(hashtext('org:' || $1::text))", [organizationId]);
}

export async function lockOrganizationCreate(tx: SqlExecutor): Promise<void> {
  await tx.query(`SELECT pg_advisory_xact_lock(${ORGANIZATION_CREATE_LOCK})`);
}
