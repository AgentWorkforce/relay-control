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
/** A set-password token (minted by verify) lives this long: at most 15 minutes. */
export const SETUP_TTL_MS = 15 * 60 * 1_000;
/** Retention: login attempt rows idle this long are deleted. */
export const ATTEMPT_RETENTION_MS = 24 * 60 * 60 * 1_000;
/** Retention: spent or expired registration, set-password and reset tokens older than this are deleted. */
export const TOKEN_RETENTION_MS = 7 * 24 * 60 * 60 * 1_000;

export type LockoutRule = { free: number };
export const LOCKOUT = {
  /** Attempts allowed per account before backoff starts. */
  account: { free: 5 } as LockoutRule,
  /** Attempts allowed per client IP before backoff starts. */
  ip: { free: 30 } as LockoutRule,
  /** First lock; each further attempt doubles it. */
  baseMs: 30 * 1_000,
  /** Longest single lock. */
  capMs: 15 * 60 * 1_000,
  /** A subject with no attempt for this long starts over. */
  windowMs: 60 * 60 * 1_000,
};

const REGISTRATION_TOKEN = /^sh_pv_[A-Za-z0-9_-]{20,200}$/;
const RESET_TOKEN = /^sh_pr_[A-Za-z0-9_-]{20,200}$/;
const SETUP_TOKEN = /^sh_ps_[A-Za-z0-9_-]{20,200}$/;

/** Thrown inside the set-password transaction to roll it back. */
export class SetupRefused extends Error {
  constructor(readonly reason: "token_invalid" | "password_already_set") {
    super(reason);
  }
}

/**
 * The lock that follows the `attempts`-th attempt: none while attempts stay
 * below the free allowance, then base, doubling, capped. The attempt that
 * uses the last free slot starts the first lock, so a subject gets exactly
 * `free` attempts before it must wait.
 */
export function lockDelayMs(attempts: number, free: number): number {
  if (attempts < free) return 0;
  const exponent = Math.min(attempts - free, 30);
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

  /**
   * Reserves one attempt for every subject before the password is checked,
   * in one transaction that row-locks them (in a fixed order). If any subject
   * is inside a lock nothing is counted and the attempt is refused; otherwise
   * each counter goes up and may start the next lock. Concurrent attempts
   * serialize on the rows, so a parallel burst gets no more than the free
   * allowance. The row locks are not held across the argon2id check.
   */
  async reserveAttempt(rules: Array<{ subject: string; rule: LockoutRule }>): Promise<
    { allowed: false } | { allowed: true; locks: Array<{ subject: string; until: Date }> }
  > {
    const now = new Date(this.now());
    const ordered = [...rules].sort((a, b) => a.subject.localeCompare(b.subject));
    return this.database.transaction(async (tx) => {
      const rows: Array<{ subject: string; rule: LockoutRule; failures: number; idle: boolean }> = [];
      for (const { subject, rule } of ordered) {
        await tx.query(
          `INSERT INTO selfhost_login_attempts (subject, failures, first_failure_at, last_failure_at)
           VALUES ($1, 0, $2, $2) ON CONFLICT (subject) DO NOTHING`,
          [subject, now],
        );
        const row = (await tx.query<{ failures: number; last_failure_at: Date | string; locked_until: Date | string | null }>(
          "SELECT failures, last_failure_at, locked_until FROM selfhost_login_attempts WHERE subject = $1 FOR UPDATE",
          [subject],
        )).rows[0]!;
        if (row.locked_until && new Date(row.locked_until).getTime() > now.getTime()) return { allowed: false as const };
        const idle = now.getTime() - new Date(row.last_failure_at).getTime() > LOCKOUT.windowMs;
        rows.push({ subject, rule, failures: idle ? 0 : row.failures, idle });
      }
      const locks: Array<{ subject: string; until: Date }> = [];
      for (const row of rows) {
        const attempts = row.failures + 1;
        const delay = lockDelayMs(attempts, row.rule.free);
        const lockedUntil = delay > 0 ? new Date(now.getTime() + delay) : null;
        if (lockedUntil) locks.push({ subject: row.subject, until: lockedUntil });
        await tx.query(
          `UPDATE selfhost_login_attempts
              SET failures = $2, last_failure_at = $3, locked_until = $4,
                  first_failure_at = CASE WHEN $5::boolean THEN $3 ELSE first_failure_at END
            WHERE subject = $1`,
          [row.subject, attempts, now, lockedUntil, row.idle || attempts === 1],
        );
      }
      return { allowed: true as const, locks };
    });
  }

  /**
   * Gives back one reserved attempt after a success (the IP subject; the
   * account row is cleared instead). A lock the reservation started is
   * lifted when the remaining count is back inside the free allowance.
   */
  async refundAttempt(subject: string, rule: LockoutRule): Promise<void> {
    await this.database.query(
      `UPDATE selfhost_login_attempts
          SET failures = GREATEST(failures - 1, 0),
              locked_until = CASE WHEN GREATEST(failures - 1, 0) < $2 THEN NULL ELSE locked_until END
        WHERE subject = $1`,
      [subject, rule.free],
    );
  }

  async clearSubject(executor: SqlExecutor, subject: string): Promise<void> {
    await executor.query("DELETE FROM selfhost_login_attempts WHERE subject = $1", [subject]);
  }

  // ---- registration --------------------------------------------------------------

  /** Stores a pending registration (no password) and returns its single-use token. */
  async createRegistration(input: { email: string; inviteTokenHash: string | null }): Promise<string> {
    const token = opaqueToken("sh_pv_");
    await this.database.transaction(async (tx) => {
      // Only the newest link for an address works.
      await tx.query(
        "UPDATE selfhost_password_registrations SET consumed_at = now() WHERE email = $1 AND consumed_at IS NULL",
        [input.email],
      );
      await tx.query(
        `INSERT INTO selfhost_password_registrations (id, email, token_hash, invite_token_hash, expires_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [randomUUID(), input.email, hashSecret(token), input.inviteTokenHash, new Date(this.now() + REGISTRATION_TTL_MS)],
      );
    });
    return token;
  }

  /**
   * Redeems a verification link once and, in the same transaction, mints the
   * set-password token for the proven address. Null for an unknown, spent or
   * expired link; "password_already_set" when the address already has a
   * password (the link is spent, no token is minted).
   */
  async verifyRegistration(token: string): Promise<
    { email: string; setupToken: string; expiresAt: Date } | { email: string; refused: "password_already_set" } | null
  > {
    if (!REGISTRATION_TOKEN.test(token)) return null;
    const now = this.now();
    return this.database.transaction(async (tx) => {
      const spent = await tx.query<{ email: string; invite_token_hash: string | null }>(
        `UPDATE selfhost_password_registrations SET consumed_at = now()
          WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2
          RETURNING email, invite_token_hash`,
        [hashSecret(token), new Date(now)],
      );
      const row = spent.rows[0];
      if (!row) return null;
      const existing = await tx.query(
        `SELECT 1 FROM selfhost_password_credentials c JOIN selfhost_users u ON u.id = c.user_id WHERE u.email = $1`,
        [row.email],
      );
      if (existing.rows.length) return { email: row.email, refused: "password_already_set" as const };
      await tx.query(
        "UPDATE selfhost_password_setup_tokens SET consumed_at = now() WHERE email = $1 AND consumed_at IS NULL",
        [row.email],
      );
      const setupToken = opaqueToken("sh_ps_");
      const expiresAt = new Date(now + SETUP_TTL_MS);
      await tx.query(
        `INSERT INTO selfhost_password_setup_tokens (id, email, token_hash, invite_token_hash, expires_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [randomUUID(), row.email, hashSecret(setupToken), row.invite_token_hash, expiresAt],
      );
      return { email: row.email, setupToken, expiresAt };
    });
  }

  /** The address and invite of a live set-password token, without spending it. */
  async peekSetup(token: string): Promise<{ email: string; inviteTokenHash: string | null } | null> {
    if (!SETUP_TOKEN.test(token)) return null;
    const result = await this.database.query<{ email: string; invite_token_hash: string | null }>(
      `SELECT email, invite_token_hash FROM selfhost_password_setup_tokens
        WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2`,
      [hashSecret(token), new Date(this.now())],
    );
    const row = result.rows[0];
    return row ? { email: row.email, inviteTokenHash: row.invite_token_hash } : null;
  }

  /**
   * Inside the sign-in transaction: spends the set-password token and writes
   * the first credential. Throws SetupRefused (rolling the whole sign-in
   * back) if the token is no longer live or the person already has a
   * password.
   */
  async redeemSetup(tx: SqlExecutor, token: string, userId: string, stored: StoredPassword): Promise<void> {
    const spent = await tx.query(
      `UPDATE selfhost_password_setup_tokens SET consumed_at = now()
        WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2
        RETURNING id`,
      [hashSecret(token), new Date(this.now())],
    );
    if (!spent.rows.length) throw new SetupRefused("token_invalid");
    if (!await this.insertFirstCredential(tx, userId, stored)) throw new SetupRefused("password_already_set");
  }

  /** Writes a credential only if the person has none. False if one exists. */
  async insertFirstCredential(executor: SqlExecutor, userId: string, stored: StoredPassword): Promise<boolean> {
    const inserted = await executor.query(
      `INSERT INTO selfhost_password_credentials (user_id, password_hash, pepper_version, params)
       VALUES ($1, $2, $3, $4) ON CONFLICT (user_id) DO NOTHING RETURNING user_id`,
      [userId, stored.hash, stored.pepperVersion, stored.params],
    );
    return inserted.rows.length === 1;
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
      await tx.query("UPDATE selfhost_password_setup_tokens SET consumed_at = now() WHERE email = $1 AND consumed_at IS NULL", [user.email]);
      await tx.query("UPDATE selfhost_email_login_tokens SET consumed_at = now() WHERE email = $1 AND consumed_at IS NULL", [user.email]);
      await this.clearSubject(tx, accountSubject(user.email));
      return { userId, email: user.email };
    });
  }

  // ---- retention -----------------------------------------------------------------

  /**
   * Deletes login attempt rows idle for 24 hours (none of them is still
   * locked: the longest lock is 15 minutes) and registration, set-password
   * and reset tokens that were spent or expired more than 7 days ago.
   */
  async sweep(): Promise<{ attempts: number; registrations: number; setups: number; resets: number }> {
    const now = this.now();
    const attemptCutoff = new Date(now - ATTEMPT_RETENTION_MS);
    const tokenCutoff = new Date(now - TOKEN_RETENTION_MS);
    const attempts = await this.database.query(
      "DELETE FROM selfhost_login_attempts WHERE last_failure_at < $1 AND (locked_until IS NULL OR locked_until < $1) RETURNING subject",
      [attemptCutoff],
    );
    const registrations = await this.database.query(
      "DELETE FROM selfhost_password_registrations WHERE COALESCE(consumed_at, expires_at) < $1 RETURNING id",
      [tokenCutoff],
    );
    const setups = await this.database.query(
      "DELETE FROM selfhost_password_setup_tokens WHERE COALESCE(consumed_at, expires_at) < $1 RETURNING id",
      [tokenCutoff],
    );
    const resets = await this.database.query(
      "DELETE FROM selfhost_password_reset_tokens WHERE COALESCE(used_at, expires_at) < $1 RETURNING id",
      [tokenCutoff],
    );
    return { attempts: attempts.rows.length, registrations: registrations.rows.length, setups: setups.rows.length, resets: resets.rows.length };
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
