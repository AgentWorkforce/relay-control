import { randomUUID } from "node:crypto";
import type { Database, SqlExecutor } from "../../database.js";
import { hashSecret, opaqueToken } from "../../crypto.js";
import { recordAudit, type AuditActor } from "../../admin/audit.js";
import type { StoredPassword } from "./hashing.js";

/**
 * Postgres state for email + password sign-in (migration 0029): credentials,
 * pending registrations, reset tokens and the lockout counters. Tokens are
 * stored only as SHA-256 hashes; passwords only as argon2id PHC strings.
 */

/** A pending registration's verification link lives this long. */
export const REGISTRATION_TTL_MS = 60 * 60 * 1_000;
/** A password reset link lives this long (requirement: at most 30 minutes). */
export const RESET_TTL_MS = 30 * 60 * 1_000;

export type LockoutRule = { free: number };
export const LOCKOUT = {
  /** Failures allowed per account before backoff starts. */
  account: { free: 5 } as LockoutRule,
  /** Failures allowed per client IP before backoff starts. */
  ip: { free: 30 } as LockoutRule,
  /** First lock; each further failure doubles it. */
  baseMs: 30 * 1_000,
  /** Longest single lock. */
  capMs: 15 * 60 * 1_000,
  /** A subject with no failure for this long starts over. */
  windowMs: 60 * 60 * 1_000,
};

const REGISTRATION_TOKEN = /^sh_pv_[A-Za-z0-9_-]{20,200}$/;
const RESET_TOKEN = /^sh_pr_[A-Za-z0-9_-]{20,200}$/;

export function lockDelayMs(failures: number, free: number): number {
  if (failures <= free) return 0;
  const exponent = Math.min(failures - free - 1, 30);
  return Math.min(LOCKOUT.capMs, LOCKOUT.baseMs * 2 ** exponent);
}

export function accountSubject(email: string): string {
  return `account:${email}`;
}

export function ipSubject(ip: string): string {
  return `ip:${ip.slice(0, 64)}`;
}

export class PasswordStore {
  constructor(
    private readonly database: Database,
    private readonly options: { now?: () => number } = {},
  ) {}

  private now(): number {
    return this.options.now?.() ?? Date.now();
  }

  get executor(): SqlExecutor {
    return this.database;
  }

  // ---- credentials -------------------------------------------------------------

  async credentialByEmail(email: string): Promise<{ userId: string; hash: string; pepperVersion: number | null } | null> {
    const result = await this.database.query<{ user_id: string; password_hash: string; pepper_version: number | null }>(
      `SELECT c.user_id, c.password_hash, c.pepper_version
         FROM selfhost_password_credentials c JOIN selfhost_users u ON u.id = c.user_id
        WHERE u.email = $1`,
      [email],
    );
    const row = result.rows[0];
    return row ? { userId: row.user_id, hash: row.password_hash, pepperVersion: row.pepper_version } : null;
  }

  async upsertCredential(executor: SqlExecutor, userId: string, stored: StoredPassword): Promise<void> {
    await executor.query(
      `INSERT INTO selfhost_password_credentials (user_id, password_hash, pepper_version, params)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id) DO UPDATE
         SET password_hash = EXCLUDED.password_hash, pepper_version = EXCLUDED.pepper_version,
             params = EXCLUDED.params, updated_at = now()`,
      [userId, stored.hash, stored.pepperVersion, stored.params],
    );
  }

  /** Replaces the hash only if it is still the one that was verified. */
  async rehash(userId: string, previousHash: string, stored: StoredPassword): Promise<boolean> {
    const result = await this.database.query<{ user_id: string }>(
      `UPDATE selfhost_password_credentials
          SET password_hash = $3, pepper_version = $4, params = $5, updated_at = now()
        WHERE user_id = $1 AND password_hash = $2
        RETURNING user_id`,
      [userId, previousHash, stored.hash, stored.pepperVersion, stored.params],
    );
    return result.rows.length === 1;
  }

  // ---- lockout -----------------------------------------------------------------

  /** Whether any of the subjects is inside a lock right now. */
  async locked(subjects: string[]): Promise<boolean> {
    const result = await this.database.query<{ locked: boolean }>(
      "SELECT EXISTS (SELECT 1 FROM selfhost_login_attempts WHERE subject = ANY($1::text[]) AND locked_until > $2) AS locked",
      [subjects, new Date(this.now())],
    );
    return result.rows[0]?.locked === true;
  }

  /**
   * Counts one failure. Returns the new lock end when this failure started
   * (or extended) a lock, else null.
   */
  async recordFailure(subject: string, rule: LockoutRule): Promise<Date | null> {
    const now = new Date(this.now());
    return this.database.transaction(async (tx) => {
      await tx.query(
        `INSERT INTO selfhost_login_attempts (subject, failures, first_failure_at, last_failure_at)
         VALUES ($1, 0, $2, $2) ON CONFLICT (subject) DO NOTHING`,
        [subject, now],
      );
      const row = (await tx.query<{ failures: number; last_failure_at: Date | string }>(
        "SELECT failures, last_failure_at FROM selfhost_login_attempts WHERE subject = $1 FOR UPDATE",
        [subject],
      )).rows[0]!;
      const idle = now.getTime() - new Date(row.last_failure_at).getTime() > LOCKOUT.windowMs;
      const failures = (idle ? 0 : row.failures) + 1;
      const delay = lockDelayMs(failures, rule.free);
      const lockedUntil = delay > 0 ? new Date(now.getTime() + delay) : null;
      await tx.query(
        `UPDATE selfhost_login_attempts
            SET failures = $2, last_failure_at = $3, locked_until = $4,
                first_failure_at = CASE WHEN $5::boolean THEN $3 ELSE first_failure_at END
          WHERE subject = $1`,
        [subject, failures, now, lockedUntil, idle || failures === 1],
      );
      return lockedUntil;
    });
  }

  async clearSubject(executor: SqlExecutor, subject: string): Promise<void> {
    await executor.query("DELETE FROM selfhost_login_attempts WHERE subject = $1", [subject]);
  }

  // ---- registration --------------------------------------------------------------

  /** Stores a pending registration and returns its single-use token. */
  async createRegistration(input: { email: string; stored: StoredPassword; inviteTokenHash: string | null }): Promise<string> {
    const token = opaqueToken("sh_pv_");
    await this.database.transaction(async (tx) => {
      // Only the newest link for an address works.
      await tx.query(
        "UPDATE selfhost_password_registrations SET consumed_at = now() WHERE email = $1 AND consumed_at IS NULL",
        [input.email],
      );
      await tx.query(
        `INSERT INTO selfhost_password_registrations
           (id, email, token_hash, password_hash, pepper_version, params, invite_token_hash, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [randomUUID(), input.email, hashSecret(token), input.stored.hash, input.stored.pepperVersion,
          input.stored.params, input.inviteTokenHash, new Date(this.now() + REGISTRATION_TTL_MS)],
      );
    });
    return token;
  }

  /** Redeems a registration link once. */
  async consumeRegistration(token: string): Promise<{ email: string; stored: StoredPassword; inviteTokenHash: string | null } | null> {
    if (!REGISTRATION_TOKEN.test(token)) return null;
    const result = await this.database.query<{
      email: string; password_hash: string; pepper_version: number | null; params: string; invite_token_hash: string | null;
    }>(
      `UPDATE selfhost_password_registrations SET consumed_at = now()
        WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2
        RETURNING email, password_hash, pepper_version, params, invite_token_hash`,
      [hashSecret(token), new Date(this.now())],
    );
    const row = result.rows[0];
    if (!row) return null;
    return {
      email: row.email,
      stored: { hash: row.password_hash, pepperVersion: row.pepper_version, params: row.params },
      inviteTokenHash: row.invite_token_hash,
    };
  }

  // ---- reset ---------------------------------------------------------------------

  /** A reset token for an address that has a password, else null. */
  async createReset(email: string): Promise<{ token: string; userId: string } | null> {
    return this.database.transaction(async (tx) => {
      const found = await tx.query<{ user_id: string }>(
        `SELECT c.user_id FROM selfhost_password_credentials c JOIN selfhost_users u ON u.id = c.user_id
          WHERE u.email = $1 FOR UPDATE OF c`,
        [email],
      );
      const userId = found.rows[0]?.user_id;
      if (!userId) return null;
      // Only the newest link works.
      await tx.query("UPDATE selfhost_password_reset_tokens SET used_at = now() WHERE user_id = $1 AND used_at IS NULL", [userId]);
      const token = opaqueToken("sh_pr_");
      await tx.query(
        "INSERT INTO selfhost_password_reset_tokens (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)",
        [randomUUID(), userId, hashSecret(token), new Date(this.now() + RESET_TTL_MS)],
      );
      return { token, userId };
    });
  }

  /** The owner of a live reset token, without spending it. */
  async peekReset(token: string): Promise<{ userId: string; email: string } | null> {
    if (!RESET_TOKEN.test(token)) return null;
    const result = await this.database.query<{ user_id: string; email: string }>(
      `SELECT r.user_id, u.email FROM selfhost_password_reset_tokens r JOIN selfhost_users u ON u.id = r.user_id
        WHERE r.token_hash = $1 AND r.used_at IS NULL AND r.expires_at > $2`,
      [hashSecret(token), new Date(this.now())],
    );
    const row = result.rows[0];
    return row ? { userId: row.user_id, email: row.email } : null;
  }

  /**
   * Spends the token and sets the new password in one transaction; `revoke`
   * runs in the same transaction to end every session of the person.
   */
  async completeReset(
    token: string,
    stored: StoredPassword,
    revoke: (tx: SqlExecutor, userId: string) => Promise<void>,
  ): Promise<{ userId: string; email: string } | null> {
    if (!RESET_TOKEN.test(token)) return null;
    return this.database.transaction(async (tx) => {
      const spent = await tx.query<{ user_id: string }>(
        `UPDATE selfhost_password_reset_tokens SET used_at = now()
          WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2
          RETURNING user_id`,
        [hashSecret(token), new Date(this.now())],
      );
      const userId = spent.rows[0]?.user_id;
      if (!userId) return null;
      const user = (await tx.query<{ email: string }>("SELECT email FROM selfhost_users WHERE id = $1", [userId])).rows[0]!;
      await this.upsertCredential(tx, userId, stored);
      await revoke(tx, userId);
      // Every other outstanding link for the person stops working too.
      await tx.query("UPDATE selfhost_password_reset_tokens SET used_at = now() WHERE user_id = $1 AND used_at IS NULL", [userId]);
      await tx.query("UPDATE selfhost_password_registrations SET consumed_at = now() WHERE email = $1 AND consumed_at IS NULL", [user.email]);
      await tx.query("UPDATE selfhost_email_login_tokens SET consumed_at = now() WHERE email = $1 AND consumed_at IS NULL", [user.email]);
      await this.clearSubject(tx, accountSubject(user.email));
      return { userId, email: user.email };
    });
  }

  // ---- audit ---------------------------------------------------------------------

  /** The organization a person's audit events belong to: their last, else the bootstrap one. */
  async auditOrganization(userId: string | null): Promise<string | null> {
    const result = await this.database.query<{ organization_id: string | null }>(
      `SELECT COALESCE(
         (SELECT last_organization_id FROM selfhost_users WHERE id = $1::uuid),
         (SELECT organization_id FROM selfhost_installation_bootstrap WHERE installation_slot = 1)
       ) AS organization_id`,
      [userId],
    );
    return result.rows[0]?.organization_id ?? null;
  }

  /** Never pass a password, pepper or token in `target`. */
  async audit(input: { userId: string | null; action: string; target: string }): Promise<void> {
    const actor: AuditActor = input.userId ? { kind: "user", userId: input.userId } : { kind: "service", subject: "password-signin" };
    await recordAudit(this.database, {
      organizationId: await this.auditOrganization(input.userId),
      actor,
      action: input.action,
      target: input.target,
    });
  }
}
