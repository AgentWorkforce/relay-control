import { randomUUID } from "node:crypto";
import type { Database, SqlExecutor } from "../database.js";
import { encryptSecret, hashSecret, opaqueToken, type EncryptionKeyring } from "../crypto.js";
import { recordAudit, type AuditActor } from "../admin/audit.js";
import type { IssuedTokens } from "../store.js";
import { asciiDomain, emailDomain, normalizeEmailAddress, type BootstrapConfig } from "./config.js";
import {
  lockIdentity,
  lockOrganization,
  lockOrganizationCreate,
  lockUser,
  SINGLE_TENANCY,
  type TenancyConfig,
} from "../tenancy.js";
import type { RelaycastProvisioner } from "./bootstrap.js";

export type Role = "owner" | "admin" | "member";
const ROLE_RANK: Record<Role, number> = { member: 0, admin: 1, owner: 2 };
const EMAIL_LOGIN_TTL_MS = 15 * 60 * 1_000;
const BOOTSTRAP_ACTOR: AuditActor = { kind: "service", subject: "installation-bootstrap" };
/** Serializes bootstrap and sign-in joins against createOrganization's lock. */

export class IdentityError extends Error {
  constructor(readonly status: number, readonly code: string, message: string) {
    super(message);
  }
}

export type Invitation = {
  id: string;
  email: string;
  role: Role;
  status: "pending" | "accepted" | "revoked" | "expired";
  invitedBy: { id: string; name: string; email: string } | null;
  createdAt: string;
  expiresAt: string;
  acceptedAt: string | null;
  revokedAt: string | null;
};

type InvitationRow = {
  id: string;
  organization_id: string;
  email: string;
  role: Role;
  token_hash: string;
  invited_by_user_id: string | null;
  inviter_name: string | null;
  inviter_email: string | null;
  expires_at: Date | string;
  accepted_at: Date | string | null;
  accepted_by_user_id: string | null;
  revoked_at: Date | string | null;
  created_at: Date | string;
};

function iso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

/** Validated lowercase IDNA-ascii domain; 400 when it is not a domain. */
export function normalizeDomain(value: string): string {
  const domain = asciiDomain(value);
  if (!domain) throw new IdentityError(400, "invalid_request", `${JSON.stringify(value)} is not a valid email domain`);
  return domain;
}

function cleanName(value: string): string {
  return value.replace(/[\p{C}]/gu, " ").trim().slice(0, 120);
}

/**
 * Whether a COMMIT rejection is the server's own report that the transaction
 * aborted: a SQLSTATE in class 40 (transaction_rollback, e.g. 40001
 * serialization_failure, 40P01 deadlock_detected) or class 23
 * (integrity_constraint_violation, from deferred constraints checked at
 * COMMIT). 40003 statement_completion_unknown is excluded: it says the
 * outcome is unknown. Every other rejection leaves the outcome unknown.
 */
function isDefiniteAbort(error: unknown): boolean {
  const code = typeof error === "object" && error !== null ? (error as { code?: unknown }).code : undefined;
  if (typeof code !== "string" || !/^[0-9A-Z]{5}$/.test(code)) return false;
  if (code === "40003") return false;
  return code.startsWith("40") || code.startsWith("23");
}

const INVITATION_SELECT = `SELECT i.id, i.organization_id, i.email, i.role, i.token_hash, i.invited_by_user_id,
       u.name AS inviter_name, u.email AS inviter_email, i.expires_at, i.accepted_at,
       i.accepted_by_user_id, i.revoked_at, i.created_at
  FROM organization_invitations i
  LEFT JOIN users u ON u.id = i.invited_by_user_id`;

export type SignInResult = {
  userId: string;
  email: string;
  organizationId: string;
  workspaceId: string;
  joined: { role: Role; via: "invite" | "auto_join" | "personal" | "admin_email" } | null;
  tokens: IssuedTokens;
};

export type SignInMethod = "oidc" | "email" | "password";

type SignInInput = {
  /**
   * Runs inside the transaction that issues the session, after the user row
   * exists; throwing rolls the whole sign-in back (password set-up uses it
   * to spend its token and write the credential atomically).
   */
  onSignedIn?: (tx: SqlExecutor, userId: string) => Promise<void>;
  name: string | null;
  inviteTokenHash: string | null;
  method: SignInMethod;
  /**
   * Whether the identity provider asserted the address verified. Email links
   * are verified by construction; OIDC is verified only when the id_token
   * says email_verified: true. Multi mode joins operator-assigned domains
   * only for verified addresses; single mode keeps the pre-0014 rule (an
   * id_token without the claim, e.g. Entra ID, still auto-joins). Omitted
   * means verified.
   */
  emailVerified?: boolean;
};

/** What one sign-in has learned and changed so far (single transaction). */
type SignInContext = {
  email: string;
  name: string | null;
  inviteTokenHash: string | null;
  method: SignInMethod;
  /** The address is verified for domain auto-join (see signIn). */
  emailVerified: boolean;
  /** The address was positively verified (email link, password, OIDC email_verified: true). */
  addressVerified: boolean;
  userId: string | null;
  /** The person's memberships, updated as the sign-in joins organizations. */
  roles: Map<string, Role>;
  joined: SignInResult["joined"];
  /** The organization most recently joined by this sign-in. */
  lastJoined: string | null;
  role(organizationId: string): Role | null;
};

export class IdentityStore {
  constructor(
    private readonly database: Database,
    private readonly keyring: EncryptionKeyring,
    private readonly options: {
      inviteTtlMs: number;
      autoJoinDomains: string[];
      issueSession: (tx: SqlExecutor, input: { userId: string; organizationId: string; workspaceId: string; label: string }) => Promise<IssuedTokens>;
      now?: () => number;
      /** SELFHOST_TENANCY (default single). */
      tenancy?: TenancyConfig;
      /** Creates the Relaycast workspace of a personal or self-serve organization (multi mode). */
      provisioner?: RelaycastProvisioner | null;
      /**
       * SELFHOST_ADMIN_EMAILS (without the boot-time SELFHOST_BOOTSTRAP_ADMIN_EMAIL
       * owner): on a verified sign-in the first becomes owner of the bootstrap
       * organization when it has none, the rest admin, once each.
       */
      adminEmails?: string[];
    },
  ) {}

  get adminEmails(): readonly string[] {
    return this.options.adminEmails ?? [];
  }

  get tenancy(): TenancyConfig {
    return this.options.tenancy ?? SINGLE_TENANCY;
  }

  get provisioner(): RelaycastProvisioner | null {
    return this.options.provisioner ?? null;
  }

  // ---- installation settings (multi-mode kill switches) ------------------------

  /**
   * The installation's runtime switches: a non-NULL column overrides the
   * environment default; NULL follows it. Read on every request, so a PATCH
   * takes effect immediately without a restart.
   */
  async installationSettings(executor: SqlExecutor = this.database): Promise<{
    tenancy: TenancyConfig["mode"];
    personalOrgSignupEnabled: boolean | null;
    selfServeOrganizationsEnabled: boolean | null;
    effective: { personalOrgOnSignIn: boolean; selfServeOrganizations: boolean };
  }> {
    const result = await executor.query<{ personal_org_signup_enabled: boolean | null; self_serve_organizations_enabled: boolean | null }>(
      "SELECT personal_org_signup_enabled, self_serve_organizations_enabled FROM installation_bootstrap WHERE installation_slot = 1",
    );
    const personal = result.rows[0]?.personal_org_signup_enabled ?? null;
    const selfServe = result.rows[0]?.self_serve_organizations_enabled ?? null;
    const multi = this.tenancy.mode === "multi";
    return {
      tenancy: this.tenancy.mode,
      personalOrgSignupEnabled: personal,
      selfServeOrganizationsEnabled: selfServe,
      effective: {
        // Single mode has neither: there is exactly one organization.
        personalOrgOnSignIn: multi && (personal ?? this.tenancy.personalOrgOnSignIn),
        selfServeOrganizations: multi && (selfServe ?? this.tenancy.selfServeOrganizations),
      },
    };
  }

  /** PATCH semantics: an omitted field is unchanged; null clears the override. */
  async updateInstallationSettings(input: {
    personalOrgSignupEnabled?: boolean | null;
    selfServeOrganizationsEnabled?: boolean | null;
  }): Promise<Awaited<ReturnType<IdentityStore["installationSettings"]>>> {
    return this.database.transaction(async (tx) => {
      await tx.query(
        `INSERT INTO installation_bootstrap (installation_slot) VALUES (1)
         ON CONFLICT (installation_slot) DO NOTHING`,
      );
      await tx.query(
        `UPDATE installation_bootstrap
            SET personal_org_signup_enabled = CASE WHEN $1::boolean THEN $2::boolean ELSE personal_org_signup_enabled END,
                self_serve_organizations_enabled = CASE WHEN $3::boolean THEN $4::boolean ELSE self_serve_organizations_enabled END,
                updated_at = now()
          WHERE installation_slot = 1`,
        [
          input.personalOrgSignupEnabled !== undefined,
          input.personalOrgSignupEnabled ?? null,
          input.selfServeOrganizationsEnabled !== undefined,
          input.selfServeOrganizationsEnabled ?? null,
        ],
      );
      return this.installationSettings(tx);
    });
  }

  private async personalOrgOnSignInEnabled(executor: SqlExecutor = this.database): Promise<boolean> {
    return (await this.installationSettings(executor)).effective.personalOrgOnSignIn;
  }

  /**
   * Multi mode, self-serve POST /api/v1/organizations: a signed-in person
   * creates an organization (owner) with a "Default" workspace. The Relaycast
   * workspace is provisioned outside the transaction and released when the
   * transaction does not use it. Lock order: email, then user; no
   * organization-creation lock (multi mode has no singleton).
   */
  async createOrganizationForUser(input: { userId: string; email: string; name: string }): Promise<{
    id: string;
    name: string;
    owner: { id: string; email: string };
    workspace: { id: string; name: string };
  }> {
    if (this.tenancy.mode !== "multi") throw new IdentityError(403, "forbidden", "Bootstrap token required");
    const name = cleanName(input.name);
    if (!name) throw new IdentityError(400, "invalid_request", "name is required");
    const provisioner = this.options.provisioner;
    if (!provisioner) {
      throw new IdentityError(503, "not_ready", "This installation can't create organizations yet (RELAYCAST_INTERNAL_SECRET is not set).");
    }
    if (!(await this.installationSettings()).effective.selfServeOrganizations) {
      throw new IdentityError(403, "self_serve_disabled", "Creating organizations is turned off on this installation. Ask the operator.");
    }
    const relaycast = await provisioner.create(name).catch((error: unknown) => {
      throw new IdentityError(503, "not_ready", `Agent Relay couldn't create the workspace yet. Try again in a minute. (${error instanceof Error ? error.message : String(error)})`);
    });
    // `bodyCompleted` separates a rollback before COMMIT (the workspace is
    // unused: release it) from a transaction that failed after its body ran,
    // whose COMMIT may have landed (released only on a proven abort).
    let bodyCompleted = false;
    try {
      return await this.database.transaction(async (tx) => {
        bodyCompleted = false;
        await lockIdentity(tx, input.email);
        await lockUser(tx, input.userId);
        // Rechecked under the locks: the switch may have been turned off and
        // the person removed meanwhile.
        if (!(await this.installationSettings(tx)).effective.selfServeOrganizations) {
          throw new IdentityError(403, "self_serve_disabled", "Creating organizations is turned off on this installation. Ask the operator.");
        }
        const user = await tx.query<{ id: string }>("SELECT id FROM users WHERE id = $1 AND email = $2", [input.userId, input.email]);
        if (!user.rows[0]) throw new IdentityError(401, "unauthorized", "Sign in again.");
        const id = randomUUID();
        const workspaceId = randomUUID();
        await tx.query("INSERT INTO organizations (id, name) VALUES ($1, $2)", [id, name]);
        await tx.query(
          "INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, 'owner')",
          [id, input.userId],
        );
        await tx.query(
          `INSERT INTO workspaces
             (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
           VALUES ($1, $2, 'Default', $3, $4)`,
          [workspaceId, id, relaycast.id, encryptSecret(relaycast.apiKey, this.keyring.active)],
        );
        await recordAudit(tx, {
          organizationId: id,
          actor: { kind: "user", userId: input.userId },
          action: "organization.self_serve_create",
          target: name,
        });
        const created = { id, name, owner: { id: input.userId, email: input.email }, workspace: { id: workspaceId, name: "Default" } };
        bodyCompleted = true;
        return created;
      });
    } catch (error) {
      if (!bodyCompleted) await provisioner.remove(relaycast.id);
      else await this.reconcileUnknownCommit(provisioner, relaycast.id, error);
      throw error;
    }
  }

  /**
   * The transaction that bound `relaycastWorkspaceId` rejected after its body
   * completed, so the rejection came from COMMIT (or from beyond it) and the
   * commit may have landed. Only a server-reported abort proves it did not:
   * a SQLSTATE in class 40 (transaction rollback: serialization failure,
   * deadlock) or class 23 (a deferred constraint violated at COMMIT). Then the
   * workspace is unused: release it (the caller rethrows the original error).
   *
   * Anything else (no SQLSTATE, a connection-class 08 error, 57P0x shutdown,
   * XX internal, a timeout, 40003 statement_completion_unknown) is an unknown
   * outcome: keep the workspace and throw an error naming it for operator
   * reconciliation. There is deliberately no "is the binding there?" read:
   * a COMMIT can still be in flight on a dying connection, and a fresh MVCC
   * snapshot taken meanwhile sees no row, yet the binding becomes visible
   * once that pending committer finishes. Absence is never proof of abort, so
   * it never drives deletion.
   */
  private async reconcileUnknownCommit(
    provisioner: RelaycastProvisioner,
    relaycastWorkspaceId: string,
    error: unknown,
  ): Promise<void> {
    if (isDefiniteAbort(error)) {
      await provisioner.remove(relaycastWorkspaceId);
      return;
    }
    const reason = error instanceof Error ? error.message : String(error);
    throw new Error(
      `The transaction outcome is unknown (${reason}); Relaycast workspace ${relaycastWorkspaceId} was retained for operator reconciliation`,
      { cause: error },
    );
  }

  /** The bootstrap (operator) organization, when the bootstrap has run. */
  async bootstrapOrganizationId(): Promise<string | null> {
    const result = await this.database.query<{ organization_id: string | null }>(
      "SELECT organization_id FROM installation_bootstrap WHERE installation_slot = 1",
    );
    return result.rows[0]?.organization_id ?? null;
  }

  // ---- operator-assigned auto-join domains ---------------------------------

  /** Domains whose verified addresses auto-join the organization. */
  async listDomains(organizationId: string): Promise<string[]> {
    const result = await this.database.query<{ domain: string }>(
      "SELECT domain FROM organization_domains WHERE organization_id = $1 ORDER BY domain",
      [organizationId],
    );
    return result.rows.map((row) => row.domain);
  }

  /**
   * Assigns a domain to an organization. Operator-only (the route checks the
   * bootstrap bearer). A domain belongs to at most one organization: a
   * competing assignment is 409; re-assigning to the same one is a no-op.
   */
  async assignDomain(input: { organizationId: string; domain: string; actor: AuditActor }): Promise<{ domain: string; created: boolean }> {
    const domain = normalizeDomain(input.domain);
    return this.database.transaction(async (tx) => {
      const organization = await tx.query("SELECT 1 FROM organizations WHERE id = $1", [input.organizationId]);
      if (!organization.rows[0]) throw new IdentityError(404, "organization_not_found", "Organization not found");
      const inserted = await tx.query<{ organization_id: string }>(
        `INSERT INTO organization_domains (domain, organization_id) VALUES ($1, $2)
         ON CONFLICT (domain) DO NOTHING RETURNING organization_id`,
        [domain, input.organizationId],
      );
      if (!inserted.rows[0]) {
        const owner = await tx.query<{ organization_id: string }>(
          "SELECT organization_id FROM organization_domains WHERE domain = $1",
          [domain],
        );
        if (owner.rows[0]?.organization_id === input.organizationId) return { domain, created: false };
        throw new IdentityError(409, "domain_assigned", "That domain is assigned to another organization");
      }
      await recordAudit(tx, {
        organizationId: input.organizationId,
        actor: input.actor,
        action: "organization.domain_assign",
        target: domain,
      });
      return { domain, created: true };
    });
  }

  async removeDomain(input: { organizationId: string; domain: string; actor: AuditActor }): Promise<boolean> {
    const domain = normalizeDomain(input.domain);
    return this.database.transaction(async (tx) => {
      const removed = await tx.query(
        "DELETE FROM organization_domains WHERE domain = $1 AND organization_id = $2 RETURNING domain",
        [domain, input.organizationId],
      );
      if (!removed.rows[0]) return false;
      await recordAudit(tx, {
        organizationId: input.organizationId,
        actor: input.actor,
        action: "organization.domain_remove",
        target: domain,
      });
      return true;
    });
  }

  private now(): number {
    return this.options.now?.() ?? Date.now();
  }

  // ---- first-boot bootstrap -------------------------------------------------

  /**
   * Creates the installation's organization with the admin as owner, or, when
   * it already exists, makes a newly configured admin email an owner once.
   * Idempotent: the admin email it acted on is recorded, so a later demotion
   * or removal by another owner is not undone by a restart.
   *
   * Single mode: does nothing while more than one organization exists
   * (readiness reports tenancy_mismatch), and otherwise makes the bootstrap
   * organization's domain rows equal SELFHOST_AUTO_JOIN_DOMAINS on every
   * pass, clearing them when the env is absent or empty (DG-004).
   *
   * Lock order (see src/tenancy.ts): the admin's email lock, then the
   * organization's lock when it exists, else the creation lock.
   */
  async ensureOrganization(bootstrap: BootstrapConfig): Promise<{
    organizationId: string;
    created: boolean;
    adminGranted: boolean;
  } | { organizationId: null; skipped: "tenancy_mismatch"; organizations: number }> {
    return this.database.transaction(async (tx) => {
      if (bootstrap.adminEmail) await lockIdentity(tx, bootstrap.adminEmail);
      const findOrganization = async (): Promise<string | undefined | "mismatch"> => {
        if (this.tenancy.mode === "single") {
          const orgs = await tx.query<{ id: string }>("SELECT id FROM organizations ORDER BY created_at LIMIT 2");
          if (orgs.rows.length > 1) return "mismatch";
          return orgs.rows[0]?.id;
        }
        // Multi mode: the bootstrap organization is the one the bootstrap
        // state names (an upgraded single installation's state already names
        // its organization). Nothing else is adopted: the only organization
        // of a fresh multi installation may be someone's personal one.
        const state = await tx.query<{ organization_id: string | null }>(
          "SELECT organization_id FROM installation_bootstrap WHERE installation_slot = 1",
        );
        const named = state.rows[0]?.organization_id ?? null;
        if (!named) return undefined;
        const found = await tx.query<{ id: string }>("SELECT id FROM organizations WHERE id = $1", [named]);
        return found.rows[0]?.id;
      };
      const mismatch = async () => {
        const count = await tx.query<{ n: number }>("SELECT count(*)::int AS n FROM organizations");
        return { organizationId: null, skipped: "tenancy_mismatch" as const, organizations: count.rows[0]!.n };
      };
      let found = await findOrganization();
      if (found === "mismatch") return mismatch();
      let organizationId: string | undefined = found;
      if (organizationId) {
        await lockOrganization(tx, organizationId);
      } else {
        // Last in the lock order; re-read under it so concurrent bootstrap
        // passes (and a bootstrap-bearer createOrganization in single mode)
        // create one organization.
        await lockOrganizationCreate(tx);
        found = await findOrganization();
        if (found === "mismatch") return mismatch();
        organizationId = found;
      }
      const state = await tx.query<{ admin_email: string | null }>(
        "SELECT admin_email FROM installation_bootstrap WHERE installation_slot = 1",
      );
      let created = false;
      if (!organizationId) {
        organizationId = randomUUID();
        await tx.query("INSERT INTO organizations (id, name) VALUES ($1, $2)", [organizationId, bootstrap.organizationName]);
        created = true;
        await recordAudit(tx, { organizationId, actor: BOOTSTRAP_ACTOR, action: "organization.bootstrap", target: bootstrap.organizationName });
      }
      let adminGranted = false;
      if (bootstrap.adminEmail && (created || state.rows[0]?.admin_email !== bootstrap.adminEmail)) {
        const user = await this.upsertUser(tx, bootstrap.adminEmail, bootstrap.adminName, false);
        const existing = await tx.query<{ role: Role }>(
          "SELECT role FROM organization_memberships WHERE organization_id = $1 AND user_id = $2",
          [organizationId, user.id],
        );
        if (existing.rows[0]?.role !== "owner") {
          await tx.query(
            `INSERT INTO organization_memberships (organization_id, user_id, role)
             VALUES ($1, $2, 'owner')
             ON CONFLICT (organization_id, user_id) DO UPDATE SET role = 'owner', updated_at = now()`,
            [organizationId, user.id],
          );
          adminGranted = true;
          await recordAudit(tx, { organizationId, actor: BOOTSTRAP_ACTOR, action: "membership.bootstrap_owner", target: bootstrap.adminEmail });
        }
      }
      await tx.query(
        `INSERT INTO installation_bootstrap (installation_slot, organization_id, admin_email, admin_granted_at)
         VALUES (1, $1, $2, CASE WHEN $3::boolean THEN now() ELSE NULL END)
         ON CONFLICT (installation_slot) DO UPDATE
           SET organization_id = EXCLUDED.organization_id,
               admin_email = COALESCE(EXCLUDED.admin_email, installation_bootstrap.admin_email),
               admin_granted_at = COALESCE(EXCLUDED.admin_granted_at, installation_bootstrap.admin_granted_at),
               updated_at = now()`,
        [organizationId, bootstrap.adminEmail, adminGranted],
      );
      // Single mode: SELFHOST_AUTO_JOIN_DOMAINS (absent or empty = none) is
      // the authority, so every pass makes the rows equal it (DG-004).
      if (this.tenancy.mode === "single") await this.syncEnvDomains(tx, organizationId);
      return { organizationId, created, adminGranted };
    });
  }

  private async syncEnvDomains(tx: SqlExecutor, organizationId: string): Promise<void> {
    const domains = [...new Set(this.options.autoJoinDomains.map(normalizeDomain))];
    const removed = await tx.query<{ domain: string }>(
      "DELETE FROM organization_domains WHERE NOT (domain = ANY($1::text[])) RETURNING domain",
      [domains],
    );
    const added = await tx.query<{ domain: string }>(
      `INSERT INTO organization_domains (domain, organization_id)
       SELECT unnest($2::text[]), $1
       ON CONFLICT (domain) DO UPDATE SET organization_id = EXCLUDED.organization_id
         WHERE organization_domains.organization_id <> EXCLUDED.organization_id
       RETURNING domain`,
      [organizationId, domains],
    );
    if (removed.rows.length > 0 || added.rows.length > 0) {
      await recordAudit(tx, {
        organizationId,
        actor: BOOTSTRAP_ACTOR,
        action: "organization.domains_env_sync",
        target: `added=${added.rows.map((row) => row.domain).sort().join(",")} removed=${removed.rows.map((row) => row.domain).sort().join(",")}`,
      });
    }
  }

  async workspaceCount(organizationId: string): Promise<number> {
    const result = await this.database.query<{ count: string }>(
      "SELECT count(*)::text AS count FROM workspaces WHERE organization_id = $1",
      [organizationId],
    );
    return Number(result.rows[0]?.count ?? "0");
  }

  /**
   * Stores the provisioned default workspace unless one appeared meanwhile
   * (then the caller deletes the Relaycast workspace it just created).
   */
  async insertBootstrapWorkspace(input: {
    organizationId: string;
    name: string;
    relaycastWorkspaceId: string;
    relaycastApiKey: string;
  }): Promise<{ id: string } | null> {
    return this.database.transaction(async (tx) => {
      await lockOrganizationCreate(tx);
      const existing = await tx.query<{ id: string }>(
        "SELECT id FROM workspaces WHERE organization_id = $1 LIMIT 1",
        [input.organizationId],
      );
      if (existing.rows[0]) return null;
      const id = randomUUID();
      await tx.query(
        `INSERT INTO workspaces
           (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
         VALUES ($1, $2, $3, $4, $5)`,
        [id, input.organizationId, input.name, input.relaycastWorkspaceId, encryptSecret(input.relaycastApiKey, this.keyring.active)],
      );
      await tx.query(
        "UPDATE installation_bootstrap SET workspace_id = $1, updated_at = now() WHERE installation_slot = 1",
        [id],
      );
      await recordAudit(tx, {
        organizationId: input.organizationId,
        workspaceId: id,
        actor: BOOTSTRAP_ACTOR,
        action: "workspace.bootstrap",
        target: `${input.name} (relaycast ${input.relaycastWorkspaceId})`,
      });
      return { id };
    });
  }

  // ---- invitations ----------------------------------------------------------

  private toInvitation(row: InvitationRow): Invitation {
    const expired = new Date(row.expires_at).getTime() <= this.now();
    return {
      id: row.id,
      email: row.email,
      role: row.role,
      status: row.revoked_at ? "revoked" : row.accepted_at ? "accepted" : expired ? "expired" : "pending",
      invitedBy: row.invited_by_user_id
        ? { id: row.invited_by_user_id, name: row.inviter_name ?? "", email: row.inviter_email ?? "" }
        : null,
      createdAt: iso(row.created_at),
      expiresAt: iso(row.expires_at),
      acceptedAt: row.accepted_at ? iso(row.accepted_at) : null,
      revokedAt: row.revoked_at ? iso(row.revoked_at) : null,
    };
  }

  /** Open invites (pending or expired, not yet accepted or revoked), newest first. */
  async listInvitations(organizationId: string): Promise<Invitation[]> {
    const result = await this.database.query<InvitationRow>(
      `${INVITATION_SELECT}
        WHERE i.organization_id = $1 AND i.accepted_at IS NULL AND i.revoked_at IS NULL
        ORDER BY i.created_at DESC`,
      [organizationId],
    );
    return result.rows.map((row) => this.toInvitation(row));
  }

  /**
   * Creates an invite and returns its token once. An open invite for the same
   * email is replaced (hosted Cloud's rule). Only owners may invite owners.
   */
  async createInvitation(input: {
    organizationId: string;
    email: string;
    role: Role;
    actor: { kind: "user"; userId: string; role: Role } | { kind: "bootstrap" };
  }): Promise<{ invitation: Invitation; token: string }> {
    const email = normalizeEmailAddress(input.email);
    if (!email) throw new IdentityError(400, "invalid_request", "Enter a valid email address.");
    if (!(input.role in ROLE_RANK)) throw new IdentityError(400, "invalid_request", "role must be owner, admin, or member");
    if (input.actor.kind === "user" && input.role === "owner" && input.actor.role !== "owner") {
      throw new IdentityError(403, "forbidden", "Only an owner can invite another owner.");
    }
    const token = opaqueToken("sh_inv_");
    const id = randomUUID();
    const expiresAt = new Date(this.now() + this.options.inviteTtlMs);
    const actorUserId = input.actor.kind === "user" ? input.actor.userId : null;
    await this.database.transaction(async (tx) => {
      await tx.query("SELECT id FROM organizations WHERE id = $1 FOR UPDATE", [input.organizationId]);
      const member = await tx.query<{ user_id: string }>(
        `SELECT m.user_id FROM organization_memberships m
           JOIN users u ON u.id = m.user_id
          WHERE m.organization_id = $1 AND u.email = $2`,
        [input.organizationId, email],
      );
      if (member.rows[0]) throw new IdentityError(409, "already_member", "That person is already a member of this organization.");
      const replaced = await tx.query<{ id: string }>(
        `UPDATE organization_invitations
            SET revoked_at = now(), revoked_by_user_id = $3, updated_at = now()
          WHERE organization_id = $1 AND email = $2 AND accepted_at IS NULL AND revoked_at IS NULL
          RETURNING id`,
        [input.organizationId, email, actorUserId],
      );
      await tx.query(
        `INSERT INTO organization_invitations
           (id, organization_id, email, role, token_hash, invited_by_user_id, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [id, input.organizationId, email, input.role, hashSecret(token), actorUserId, expiresAt],
      );
      await recordAudit(tx, {
        organizationId: input.organizationId,
        actor: input.actor.kind === "user" ? { kind: "user", userId: input.actor.userId } : { kind: "bootstrap" },
        action: "invitation.create",
        target: `${id} ${email} role=${input.role}${replaced.rows.length ? ` replaces=${replaced.rows.map((r) => r.id).join(",")}` : ""}`,
      });
    });
    const invitation = await this.invitationById(input.organizationId, id);
    return { invitation: invitation!, token };
  }

  async invitationById(organizationId: string, id: string): Promise<Invitation | null> {
    if (!/^[0-9a-f-]{36}$/i.test(id)) return null;
    const result = await this.database.query<InvitationRow>(
      `${INVITATION_SELECT} WHERE i.organization_id = $1 AND i.id = $2`,
      [organizationId, id],
    );
    return result.rows[0] ? this.toInvitation(result.rows[0]) : null;
  }

  private async openInvitationForUpdate(tx: SqlExecutor, organizationId: string, id: string, actorRole: Role | null): Promise<InvitationRow> {
    if (!/^[0-9a-f-]{36}$/i.test(id)) throw new IdentityError(404, "invitation_not_found", "Invitation not found");
    const result = await tx.query<InvitationRow>(
      `${INVITATION_SELECT} WHERE i.organization_id = $1 AND i.id = $2 FOR UPDATE OF i`,
      [organizationId, id],
    );
    const row = result.rows[0];
    if (!row) throw new IdentityError(404, "invitation_not_found", "Invitation not found");
    if (row.accepted_at) throw new IdentityError(409, "invitation_accepted", "Invite has already been accepted");
    if (row.revoked_at) throw new IdentityError(409, "invitation_revoked", "Invite has been canceled");
    if (actorRole !== null && row.role === "owner" && actorRole !== "owner") {
      throw new IdentityError(403, "forbidden", "Only an owner can manage an owner invite.");
    }
    return row;
  }

  async revokeInvitation(input: { organizationId: string; id: string; actor: { kind: "user"; userId: string; role: Role } | { kind: "bootstrap" } }): Promise<void> {
    await this.database.transaction(async (tx) => {
      const row = await this.openInvitationForUpdate(tx, input.organizationId, input.id, input.actor.kind === "user" ? input.actor.role : null);
      await tx.query(
        `UPDATE organization_invitations
            SET revoked_at = now(), revoked_by_user_id = $2, updated_at = now() WHERE id = $1`,
        [row.id, input.actor.kind === "user" ? input.actor.userId : null],
      );
      await recordAudit(tx, {
        organizationId: input.organizationId,
        actor: input.actor.kind === "user" ? { kind: "user", userId: input.actor.userId } : { kind: "bootstrap" },
        action: "invitation.revoke",
        target: `${row.id} ${row.email}`,
      });
    });
  }

  /**
   * Issues a fresh link for an open invite: the old link stops working and
   * the expiry restarts. Used for "Copy link" and "Resend".
   */
  async rotateInvitation(input: { organizationId: string; id: string; actor: { kind: "user"; userId: string; role: Role } | { kind: "bootstrap" } }): Promise<{ invitation: Invitation; token: string }> {
    const token = opaqueToken("sh_inv_");
    await this.database.transaction(async (tx) => {
      const row = await this.openInvitationForUpdate(tx, input.organizationId, input.id, input.actor.kind === "user" ? input.actor.role : null);
      await tx.query(
        `UPDATE organization_invitations
            SET token_hash = $2, expires_at = $3, updated_at = now() WHERE id = $1`,
        [row.id, hashSecret(token), new Date(this.now() + this.options.inviteTtlMs)],
      );
      await recordAudit(tx, {
        organizationId: input.organizationId,
        actor: input.actor.kind === "user" ? { kind: "user", userId: input.actor.userId } : { kind: "bootstrap" },
        action: "invitation.rotate",
        target: `${row.id} ${row.email}`,
      });
    });
    return { invitation: (await this.invitationById(input.organizationId, input.id))!, token };
  }

  /** What the sign-in page shows for an invite link. Never reveals other invites. */
  async describeInvitation(token: string): Promise<{
    organizationName: string;
    email: string;
    role: Role;
    inviterName: string | null;
    status: Invitation["status"];
    expiresAt: string;
  } | null> {
    if (!/^sh_inv_[A-Za-z0-9_-]{20,}$/.test(token)) return null;
    const result = await this.database.query<InvitationRow & { organization_name: string }>(
      `SELECT i.*, u.name AS inviter_name, u.email AS inviter_email, o.name AS organization_name
         FROM organization_invitations i
         JOIN organizations o ON o.id = i.organization_id
         LEFT JOIN users u ON u.id = i.invited_by_user_id
        WHERE i.token_hash = $1`,
      [hashSecret(token)],
    );
    const row = result.rows[0];
    if (!row) return null;
    const view = this.toInvitation(row);
    return {
      organizationName: row.organization_name,
      email: view.email,
      role: view.role,
      inviterName: row.inviter_name,
      status: view.status,
      expiresAt: view.expiresAt,
    };
  }

  // ---- sign-in ----------------------------------------------------------------

  /**
   * Resolves a verified email to an organization membership and issues a
   * browser session.
   *
   * Single mode (one organization), in one transaction:
   *   1. an existing member signs in;
   *   2. otherwise the invite they followed (email must match), or any open
   *      invite for that email (hosted Cloud's auto-accept), makes them a member;
   *   3. otherwise an auto-join domain (SELFHOST_AUTO_JOIN_DOMAINS or the
   *      operator-assigned organization_domains rows) joins them;
   *   4. otherwise sign-in is refused.
   *
   * Multi mode picks the organization (invitation > membership > domain >
   * personal > 403):
   *   1. the invite they followed selects its organization; otherwise open
   *      invites for the email are accepted (landing in the last accepted);
   *   2. otherwise an existing membership (users.last_organization_id when
   *      still a member, else the newest);
   *   3. otherwise the organization the operator assigned the (verified)
   *      email's domain to, as member;
   *   4. otherwise a personal organization "<name>'s Workspace" with a
   *      "Default" workspace, when enabled (else 403 no_organization).
   * The workspace is users.last_workspace_id when it is in that organization,
   * else its oldest.
   *
   * Lock order (DG-005, src/tenancy.ts): the email lock, then the user lock
   * once the row exists, then hashtext('org:' || organization id) for each
   * organization joined, in id order. The organization-creation lock
   * (1947182642) is never taken in a sign-in transaction.
   */
  async signIn(input: SignInInput & {
    email: string;
    /** Multi mode: runs before a personal organization is provisioned (rate limit). */
    beforePersonalOrganization?: () => void;
  }): Promise<SignInResult> {
    const email = normalizeEmailAddress(input.email);
    if (!email) throw new IdentityError(400, "email_invalid", "That email address is not valid.");
    if (this.tenancy.mode === "single") {
      return this.database.transaction(async (tx) => {
        const org = await tx.query<{ id: string; name: string }>("SELECT id, name FROM organizations ORDER BY created_at LIMIT 2");
        if (org.rows.length !== 1) {
          throw new IdentityError(503, "not_ready", "This Agent Relay installation is not set up yet. Ask your administrator to configure its organization.");
        }
        const organization = org.rows[0]!;
        await lockIdentity(tx, email);
        await lockOrganization(tx, organization.id);
        const context = await this.signInContext(tx, email, input);
        await this.acceptInvites(tx, context, organization.id);
        await this.grantAdminEmail(tx, context, organization.id);
        if (context.role(organization.id) === null) await this.autoJoin(tx, context, organization.id);
        if (context.role(organization.id) === null) {
          throw new IdentityError(403, "not_invited", `${email} doesn't have access to ${organization.name}. Ask an owner or admin to invite you.`);
        }
        return this.finishSignIn(tx, context, organization.id, input.method, input.onSignedIn);
      });
    }

    const provisioner = this.options.provisioner;
    const selected = await this.database.transaction(async (tx) => {
      const resolved = await this.selectOrganization(tx, email, input);
      if (resolved.kind === "organization") return this.finishSignIn(tx, resolved.context, resolved.organizationId, input.method, input.onSignedIn);
      // Refusals roll back, so a refused address leaves no user row.
      if (!await this.personalOrgOnSignInEnabled(tx)) {
        throw new IdentityError(403, "no_organization", `${email} isn't a member of any organization here. Ask an owner or admin to invite you.`);
      }
      if (!provisioner) {
        throw new IdentityError(503, "not_ready", "This installation can't create personal organizations yet (RELAYCAST_INTERNAL_SECRET is not set). Ask your administrator to invite you.");
      }
      return null;
    });
    if (selected) return selected;

    // A personal organization: provision its Relaycast workspace outside any
    // transaction (it can take a while), then re-run the selection under the
    // same per-user lock and create it only if still nothing matched.
    if (!provisioner) throw new Error("unreachable: provisioner checked above");
    input.beforePersonalOrganization?.();
    const existingName = await this.database.query<{ name: string }>("SELECT name FROM users WHERE email = $1", [email]);
    const displayName = cleanName(input.name ?? existingName.rows[0]?.name ?? "") || email.slice(0, email.indexOf("@"));
    const organizationName = `${displayName}'s Workspace`.slice(0, 120);
    const relaycast = await provisioner.create(organizationName).catch((error: unknown) => {
      throw new IdentityError(503, "not_ready", `Agent Relay couldn't create your workspace yet. Try again in a minute. (${error instanceof Error ? error.message : String(error)})`);
    });
    // `inserted` marks that the transaction placed the workspace;
    // `bodyCompleted` that the body ran to the end, so a later rejection may
    // hide a COMMIT that landed (see reconcileUnknownCommit).
    let inserted = false;
    let bodyCompleted = false;
    let signedIn: SignInResult;
    try {
      signedIn = await this.database.transaction(async (tx) => {
        inserted = false;
        bodyCompleted = false;
        const resolved = await this.selectOrganization(tx, email, input);
        if (resolved.kind === "organization") {
          const result = await this.finishSignIn(tx, resolved.context, resolved.organizationId, input.method, input.onSignedIn);
          bodyCompleted = true;
          return result;
        }
        if (!await this.personalOrgOnSignInEnabled(tx)) {
          throw new IdentityError(403, "no_organization", `${email} isn't a member of any organization here. Ask an owner or admin to invite you.`);
        }
        const context = resolved.context;
        const user = { id: context.userId! };
        const organizationId = randomUUID();
        const workspaceId = randomUUID();
        await tx.query("INSERT INTO organizations (id, name) VALUES ($1, $2)", [organizationId, organizationName]);
        await tx.query(
          "INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, 'owner')",
          [organizationId, user.id],
        );
        await tx.query(
          `INSERT INTO workspaces
             (id, organization_id, name, relaycast_workspace_id, relaycast_api_key_ciphertext)
           VALUES ($1, $2, 'Default', $3, $4)`,
          [workspaceId, organizationId, relaycast.id, encryptSecret(relaycast.apiKey, this.keyring.active)],
        );
        inserted = true;
        context.roles.set(organizationId, "owner");
        context.joined = { role: "owner", via: "personal" };
        context.lastJoined = organizationId;
        await recordAudit(tx, {
          organizationId,
          actor: { kind: "user", userId: user.id },
          action: "organization.personal_create",
          target: `${organizationName} via=${input.method}`,
        });
        const result = await this.finishSignIn(tx, context, organizationId, input.method, input.onSignedIn);
        bodyCompleted = true;
        return result;
      });
    } catch (error) {
      // Rolled back before COMMIT, or the body never bound the workspace:
      // it is unused. Otherwise release only on a proven abort.
      if (!bodyCompleted || !inserted) await provisioner.remove(relaycast.id);
      else await this.reconcileUnknownCommit(provisioner, relaycast.id, error);
      throw error;
    }
    // Another sign-in or invite resolved the person meanwhile: release the
    // unused Relaycast workspace.
    if (!inserted) await provisioner.remove(relaycast.id);
    return signedIn;
  }

  /** Multi mode: the organization a sign-in lands in, under a per-email lock. */
  private async selectOrganization(
    tx: SqlExecutor,
    email: string,
    input: SignInInput,
  ): Promise<{ kind: "organization"; organizationId: string; context: SignInContext } | { kind: "personal"; context: SignInContext }> {
    // The email lock comes first (a new person has no user id yet), then the
    // user row and its lock; the caller rolls back when sign-in is refused.
    await lockIdentity(tx, email);
    const user = await this.upsertUser(tx, email, input.name ?? email.slice(0, email.indexOf("@")), input.name !== null);
    await lockUser(tx, user.id);
    const context = await this.signInContext(tx, email, input);
    if (input.inviteTokenHash) {
      const found = await tx.query<{ organization_id: string }>(
        "SELECT organization_id FROM organization_invitations WHERE token_hash = $1",
        [input.inviteTokenHash],
      );
      const organizationId = found.rows[0]?.organization_id;
      if (!organizationId) throw new IdentityError(404, "invite_invalid", "This invite link is not valid. Ask for a new invite.");
      await lockOrganization(tx, organizationId);
      await this.acceptInvites(tx, context, organizationId);
      return { kind: "organization", organizationId, context };
    }
    const open = await tx.query<{ organization_id: string }>(
      `SELECT DISTINCT organization_id FROM organization_invitations
        WHERE email = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > $2
        ORDER BY organization_id`,
      [email, new Date(this.now())],
    );
    const invited = new Set(open.rows.map((row) => row.organization_id));
    const adminOrganization = context.addressVerified && this.adminEmails.includes(email)
      ? await this.bootstrapOrganizationIdIn(tx)
      : null;
    // Locks in organization id order, so concurrent sign-ins cannot deadlock.
    for (const organizationId of [...new Set([...invited, ...(adminOrganization ? [adminOrganization] : [])])].sort()) {
      await lockOrganization(tx, organizationId);
      if (invited.has(organizationId)) await this.acceptInvites(tx, context, organizationId);
      if (organizationId === adminOrganization) await this.grantAdminEmail(tx, context, organizationId);
    }
    if (context.lastJoined) return { kind: "organization", organizationId: context.lastJoined, context };
    const memberships = await tx.query<{ organization_id: string }>(
      `SELECT m.organization_id
         FROM organization_memberships m
         JOIN users u ON u.id = m.user_id
        WHERE m.user_id = $1
        ORDER BY (m.organization_id = u.last_organization_id) DESC NULLS LAST, m.created_at DESC, m.organization_id`,
      [user.id],
    );
    if (memberships.rows[0]) return { kind: "organization", organizationId: memberships.rows[0].organization_id, context };
    const domainOrganization = await this.domainOrganization(tx, context);
    if (domainOrganization) {
      await lockOrganization(tx, domainOrganization);
      await this.autoJoin(tx, context, domainOrganization);
      if (context.role(domainOrganization) !== null) return { kind: "organization", organizationId: domainOrganization, context };
    }
    return { kind: "personal", context };
  }

  /** The organization the operator assigned the email's domain to, if the address qualifies. */
  private async domainOrganization(tx: SqlExecutor, context: SignInContext): Promise<string | null> {
    if (this.tenancy.mode === "multi" && !context.emailVerified) return null;
    const domain = asciiDomain(emailDomain(context.email));
    if (!domain) return null;
    const result = await tx.query<{ organization_id: string }>(
      "SELECT organization_id FROM organization_domains WHERE domain = $1",
      [domain],
    );
    return result.rows[0]?.organization_id ?? null;
  }

  private async signInContext(
    tx: SqlExecutor,
    email: string,
    input: SignInInput,
  ): Promise<SignInContext> {
    const existingUser = await tx.query<{ id: string }>("SELECT id FROM users WHERE email = $1", [email]);
    const userId = existingUser.rows[0]?.id ?? null;
    const roles = new Map<string, Role>();
    if (userId) {
      const memberships = await tx.query<{ organization_id: string; role: Role }>(
        "SELECT organization_id, role FROM organization_memberships WHERE user_id = $1",
        [userId],
      );
      for (const row of memberships.rows) roles.set(row.organization_id, row.role);
    }
    return {
      email,
      name: input.name,
      inviteTokenHash: input.inviteTokenHash,
      method: input.method,
      emailVerified: input.emailVerified !== false,
      addressVerified: input.emailVerified === true,
      userId,
      roles,
      joined: null,
      lastJoined: null,
      role: (organizationId: string) => roles.get(organizationId) ?? null,
    };
  }

  /**
   * Accepts the invite the person followed (scoped to organizationId) and
   * any open invite for their email there. Caller holds the org lock.
   */
  private async acceptInvites(tx: SqlExecutor, context: SignInContext, organizationId: string): Promise<void> {
    const { email } = context;
    const accept = async (invite: InvitationRow) => {
      const user = await this.upsertUser(tx, email, context.name ?? email.slice(0, email.indexOf("@")), context.name !== null);
      context.userId = user.id;
      if (context.role(organizationId) === null) {
        await tx.query(
          `INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, $3)
           ON CONFLICT (organization_id, user_id) DO NOTHING`,
          [organizationId, user.id, invite.role],
        );
        const role = await tx.query<{ role: Role }>(
          "SELECT role FROM organization_memberships WHERE organization_id = $1 AND user_id = $2",
          [organizationId, user.id],
        );
        context.roles.set(organizationId, role.rows[0]!.role);
        context.joined = { role: role.rows[0]!.role, via: "invite" };
        context.lastJoined = organizationId;
      }
      await tx.query(
        `UPDATE organization_invitations
            SET accepted_at = now(), accepted_by_user_id = $2, updated_at = now() WHERE id = $1`,
        [invite.id, user.id],
      );
      await recordAudit(tx, {
        organizationId,
        actor: { kind: "user", userId: user.id },
        action: "invitation.accept",
        target: `${invite.id} ${email} role=${invite.role} via=${context.method}`,
      });
    };
    if (context.inviteTokenHash) {
      const found = await tx.query<InvitationRow>(
        `${INVITATION_SELECT} WHERE i.token_hash = $1 AND i.organization_id = $2 FOR UPDATE OF i`,
        [context.inviteTokenHash, organizationId],
      );
      const invite = found.rows[0];
      if (!invite) throw new IdentityError(404, "invite_invalid", "This invite link is not valid. Ask for a new invite.");
      if (invite.revoked_at) throw new IdentityError(410, "invite_revoked", "Invite has been canceled. Ask for a new invite.");
      if (invite.accepted_at) {
        if (!(context.role(organizationId) !== null && invite.accepted_by_user_id === context.userId)) {
          throw new IdentityError(410, "invite_accepted", "Invite has already been accepted.");
        }
      } else if (new Date(invite.expires_at).getTime() <= this.now()) {
        throw new IdentityError(410, "invite_expired", "Invite has expired. Ask for a new invite.");
      } else if (invite.email !== email) {
        throw new IdentityError(403, "invite_email_mismatch", `This invite was sent to ${invite.email}. You signed in as ${email}. Sign in with the invited account.`);
      } else {
        await accept(invite);
      }
    }
    if (context.role(organizationId) === null) {
      const open = await tx.query<InvitationRow>(
        `${INVITATION_SELECT}
          WHERE i.organization_id = $1 AND i.email = $2 AND i.accepted_at IS NULL
            AND i.revoked_at IS NULL AND i.expires_at > $3
          ORDER BY i.created_at DESC LIMIT 1 FOR UPDATE OF i`,
        [organizationId, email, new Date(this.now())],
      );
      if (open.rows[0]) await accept(open.rows[0]);
    }
  }

  /**
   * SELFHOST_ADMIN_EMAILS: on the address's first verified sign-in, makes it
   * owner when the organization has no owner yet (so the first listed admin
   * to verify owns the installation) and admin otherwise. Recorded once per
   * address, so a later demotion sticks. Never lowers a role. Caller holds
   * the identity and organization locks, which serialize the owner choice.
   */
  private async grantAdminEmail(tx: SqlExecutor, context: SignInContext, organizationId: string): Promise<void> {
    const { email } = context;
    if (!context.addressVerified || !this.adminEmails.includes(email)) return;
    const granted = await tx.query("SELECT 1 AS found FROM admin_email_grants WHERE email = $1", [email]);
    if (granted.rows[0]) return;
    const owners = await tx.query<{ n: number }>(
      "SELECT count(*)::int AS n FROM organization_memberships WHERE organization_id = $1 AND role = 'owner'",
      [organizationId],
    );
    const role: Role = owners.rows[0]!.n === 0 ? "owner" : "admin";
    const user = await this.upsertUser(tx, email, context.name ?? email.slice(0, email.indexOf("@")), context.name !== null);
    context.userId = user.id;
    const current = context.role(organizationId);
    if (current === null || ROLE_RANK[current] < ROLE_RANK[role]) {
      await tx.query(
        `INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, $3)
         ON CONFLICT (organization_id, user_id) DO UPDATE SET role = EXCLUDED.role, updated_at = now()`,
        [organizationId, user.id, role],
      );
      context.roles.set(organizationId, role);
      if (current === null) {
        context.joined = { role, via: "admin_email" };
        context.lastJoined = organizationId;
      }
      await recordAudit(tx, {
        organizationId,
        actor: { kind: "user", userId: user.id },
        action: role === "owner" ? "membership.admin_email_owner" : "membership.admin_email_admin",
        target: `${email} via=${context.method}`,
      });
    }
    await tx.query(
      "INSERT INTO admin_email_grants (email, organization_id, role) VALUES ($1, $2, $3) ON CONFLICT (email) DO NOTHING",
      [email, organizationId, role],
    );
  }

  private async bootstrapOrganizationIdIn(tx: SqlExecutor): Promise<string | null> {
    const state = await tx.query<{ organization_id: string | null }>(
      "SELECT organization_id FROM installation_bootstrap WHERE installation_slot = 1",
    );
    return state.rows[0]?.organization_id ?? null;
  }

  /** Joins as member when the email's domain is an auto-join domain of the org. Caller holds the org lock. */
  private async autoJoin(tx: SqlExecutor, context: SignInContext, organizationId: string): Promise<void> {
    const { email } = context;
    const domain = asciiDomain(emailDomain(email));
    if (!domain) return;
    let matches = await this.domainOrganization(tx, context) === organizationId;
    // Single mode: SELFHOST_AUTO_JOIN_DOMAINS also applies before the first
    // bootstrap pass copies it into organization_domains.
    if (!matches && this.tenancy.mode === "single") matches = this.options.autoJoinDomains.includes(domain);
    if (!matches) return;
    const user = await this.upsertUser(tx, email, context.name ?? email.slice(0, email.indexOf("@")), context.name !== null);
    context.userId = user.id;
    const inserted = await tx.query<{ role: Role }>(
      `INSERT INTO organization_memberships (organization_id, user_id, role) VALUES ($1, $2, 'member')
       ON CONFLICT (organization_id, user_id) DO NOTHING RETURNING role`,
      [organizationId, user.id],
    );
    const role = await tx.query<{ role: Role }>(
      "SELECT role FROM organization_memberships WHERE organization_id = $1 AND user_id = $2",
      [organizationId, user.id],
    );
    context.roles.set(organizationId, role.rows[0]!.role);
    if (!inserted.rows[0]) return;
    context.joined = { role: "member", via: "auto_join" };
    context.lastJoined = organizationId;
    await recordAudit(tx, {
      organizationId,
      actor: { kind: "user", userId: user.id },
      action: "membership.auto_join",
      target: `${email} domain=${domain} via=${context.method}`,
    });
  }

  /** Picks the workspace, remembers the selection and issues the session. */
  private async finishSignIn(
    tx: SqlExecutor,
    context: SignInContext,
    organizationId: string,
    method: SignInMethod,
    onSignedIn?: (tx: SqlExecutor, userId: string) => Promise<void>,
  ): Promise<SignInResult> {
    const userId = context.userId;
    if (userId === null || context.role(organizationId) === null) {
      throw new IdentityError(403, "not_invited", `${context.email} doesn't have access to this organization. Ask an owner or admin to invite you.`);
    }
    if (context.name && !context.joined) {
      await tx.query("UPDATE users SET name = $2, updated_at = now() WHERE id = $1 AND name <> $2", [userId, cleanName(context.name) || context.email]);
    }
    const workspace = await tx.query<{ id: string }>(
      `SELECT w.id FROM workspaces w
         LEFT JOIN users u ON u.id = $2 AND u.last_workspace_id = w.id
        WHERE w.organization_id = $1
        ORDER BY (u.id IS NOT NULL) DESC, w.created_at, w.id LIMIT 1`,
      [organizationId, userId],
    );
    if (!workspace.rows[0]) {
      throw new IdentityError(503, "not_ready", "Agent Relay is still creating this installation's workspace. Try again in a minute.");
    }
    const workspaceId = workspace.rows[0].id;
    await tx.query(
      "UPDATE users SET last_organization_id = $2, last_workspace_id = $3 WHERE id = $1",
      [userId, organizationId, workspaceId],
    );
    const tokens = await this.options.issueSession(tx, {
      userId,
      organizationId,
      workspaceId,
      label: method === "oidc" ? "Browser sign-in (SSO)" : method === "password" ? "Browser sign-in (password)" : "Browser sign-in (email link)",
    });
    if (onSignedIn) await onSignedIn(tx, userId);
    const joined = context.lastJoined === organizationId ? context.joined : null;
    return { userId, email: context.email, organizationId, workspaceId, joined, tokens };
  }

  /**
   * Whether an email may receive a sign-in link: a member, someone with an
   * open invite, or an auto-join domain. The caller answers the same either
   * way so addresses cannot be enumerated.
   */
  async createEmailLogin(input: { email: string; inviteToken: string | null; next: string }): Promise<string | null> {
    const email = normalizeEmailAddress(input.email);
    if (!email) return null;
    const inviteTokenHash = input.inviteToken ? hashSecret(input.inviteToken) : null;
    const eligible = await this.database.query<{ ok: boolean }>(
      `SELECT EXISTS (
         SELECT 1 FROM organization_memberships m JOIN users u ON u.id = m.user_id WHERE u.email = $1
       ) OR EXISTS (
         SELECT 1 FROM organization_invitations
          WHERE email = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > $2
       ) AS ok`,
      [email, new Date(this.now())],
    );
    // Multi mode: any address may sign in (it may land in a personal
    // organization); the route rate-limits per address and per IP.
    if (this.tenancy.mode === "single" && !eligible.rows[0]?.ok && !this.adminEmails.includes(email) &&
      !await this.autoJoinEligible(email)) return null;
    const token = opaqueToken("sh_el_");
    await this.database.query(
      `INSERT INTO email_login_tokens (id, email, token_hash, invite_token_hash, next_path, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [randomUUID(), email, hashSecret(token), inviteTokenHash, input.next, new Date(this.now() + EMAIL_LOGIN_TTL_MS)],
    );
    return token;
  }

  /**
   * Whether an address may register a password: an existing member, an open
   * invite to it, an auto-join domain, or an admin email. Unlike email links,
   * multi mode does not open password registration to every address.
   */
  async passwordRegistrationEligible(email: string): Promise<boolean> {
    if (this.adminEmails.includes(email)) return true;
    const eligible = await this.database.query<{ ok: boolean }>(
      `SELECT EXISTS (
         SELECT 1 FROM organization_memberships m JOIN users u ON u.id = m.user_id WHERE u.email = $1
       ) OR EXISTS (
         SELECT 1 FROM organization_invitations
          WHERE email = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > $2
       ) AS ok`,
      [email, new Date(this.now())],
    );
    if (eligible.rows[0]?.ok) return true;
    return this.autoJoinEligible(email);
  }

  private async autoJoinEligible(email: string): Promise<boolean> {
    const domain = asciiDomain(emailDomain(email));
    if (!domain) return false;
    if (this.options.autoJoinDomains.includes(domain)) return true;
    const result = await this.database.query<{ ok: boolean }>(
      "SELECT EXISTS (SELECT 1 FROM organization_domains WHERE domain = $1) AS ok",
      [domain],
    );
    return result.rows[0]?.ok === true;
  }

  /** Redeems an email sign-in link once. */
  async consumeEmailLogin(token: string): Promise<{ email: string; inviteTokenHash: string | null; next: string } | null> {
    if (!/^sh_el_[A-Za-z0-9_-]{20,}$/.test(token)) return null;
    const result = await this.database.query<{ email: string; invite_token_hash: string | null; next_path: string | null }>(
      `UPDATE email_login_tokens SET consumed_at = now()
        WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2
        RETURNING email, invite_token_hash, next_path`,
      [hashSecret(token), new Date(this.now())],
    );
    const row = result.rows[0];
    return row ? { email: row.email, inviteTokenHash: row.invite_token_hash, next: row.next_path ?? "/" } : null;
  }

  async peekEmailLogin(token: string): Promise<string | null> {
    if (!/^sh_el_[A-Za-z0-9_-]{20,}$/.test(token)) return null;
    const result = await this.database.query<{ email: string }>(
      "SELECT email FROM email_login_tokens WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2",
      [hashSecret(token), new Date(this.now())],
    );
    return result.rows[0]?.email ?? null;
  }

  // ---- membership management ---------------------------------------------------

  async audit(input: { organizationId: string; actor: AuditActor; action: string; target: string }): Promise<void> {
    await recordAudit(this.database, input);
  }

  async organizationName(organizationId: string): Promise<string | null> {
    const result = await this.database.query<{ name: string }>("SELECT name FROM organizations WHERE id = $1", [organizationId]);
    return result.rows[0]?.name ?? null;
  }

  async userSummary(userId: string): Promise<{ name: string; email: string } | null> {
    const result = await this.database.query<{ name: string; email: string }>("SELECT name, email FROM users WHERE id = $1", [userId]);
    return result.rows[0] ?? null;
  }

  private async upsertUser(tx: SqlExecutor, email: string, name: string, overwriteName: boolean): Promise<{ id: string }> {
    const cleaned = cleanName(name) || email;
    const result = await tx.query<{ id: string }>(
      `INSERT INTO users (id, email, name) VALUES ($1, $2, $3)
       ON CONFLICT (email) DO UPDATE
         SET name = CASE WHEN $4::boolean THEN EXCLUDED.name ELSE users.name END,
             updated_at = now()
       RETURNING id`,
      [randomUUID(), email, cleaned, overwriteName],
    );
    return result.rows[0]!;
  }
}

export function roleAtLeast(role: Role, minimum: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[minimum];
}
