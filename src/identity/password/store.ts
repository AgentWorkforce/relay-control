import { randomUUID } from "node:crypto";
import type { Database, SqlExecutor } from "../../database.js";
import { hashSecret, opaqueToken } from "../../crypto.js";
import { recordAudit, type AuditActor } from "../../admin/audit.js";
import { lockIdentity } from "../../tenancy.js";
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
/** A setup key works for at most this long after it is recorded. */
export const SETUP_KEY_TTL_MS = 24 * 60 * 60 * 1_000;
/** A temporary password's default lifetime (POST .../temporary-password may shorten or extend it). */
export const TEMPORARY_PASSWORD_TTL_MS = 72 * 60 * 60 * 1_000;
/** The longest lifetime a temporary password may be given. */
export const TEMPORARY_PASSWORD_MAX_TTL_MS = 7 * 24 * 60 * 60 * 1_000;
/** Retention: login attempt rows idle this long are deleted. */
export const ATTEMPT_RETENTION_MS = 24 * 60 * 60 * 1_000;
/** Retention: spent or expired registration, set-password and reset tokens older than this are deleted. */
export const TOKEN_RETENTION_MS = 7 * 24 * 60 * 60 * 1_000;

/**
 * "backoff": `free` attempts, then each further attempt locks the subject
 * for base doubling to the cap. "threshold": `limit` attempts within the
 * window lock the subject once for `lockMs`, and the count starts over.
 */
export type LockoutRule =
  | { kind: "backoff"; free: number }
  | { kind: "threshold"; limit: number; lockMs: number };

export const LOCKOUT = {
  /**
   * Per account and client key ("account-key:"): what one client can do to
   * one account. A remote client that guesses only locks itself out.
   */
  accountKey: { kind: "backoff", free: 5 } satisfies LockoutRule,
  /**
   * Per account across every client ("account:"): a distributed guess
   * (many addresses) locks the account for 15 minutes after 50 attempts in
   * an hour, and the owner is emailed (at most once a day).
   */
  account: { kind: "threshold", limit: 50, lockMs: 15 * 60 * 1_000 } satisfies LockoutRule,
  /** Per client key across every account ("ip:"): a spray from one client. */
  ip: { kind: "backoff", free: 30 } satisfies LockoutRule,
  /** First backoff lock; each further attempt doubles it. */
  baseMs: 30 * 1_000,
  /** Longest single backoff lock. */
  capMs: 15 * 60 * 1_000,
  /** A backoff subject idle this long, or a threshold count this old, starts over. */
  windowMs: 60 * 60 * 1_000,
};

/** A lockout notice email goes to an account owner at most this often. */
export const LOCKOUT_NOTICE_INTERVAL_MS = 24 * 60 * 60 * 1_000;

const REGISTRATION_TOKEN = /^sh_pv_[A-Za-z0-9_-]{20,200}$/;
const RESET_TOKEN = /^sh_pr_[A-Za-z0-9_-]{20,200}$/;
const SETUP_TOKEN = /^sh_ps_[A-Za-z0-9_-]{20,200}$/;

/** Thrown inside the sign-in transaction when the verified password was changed meanwhile. */
export class CredentialChanged extends Error {
  constructor() {
    super("credential_changed");
  }
}

/** Thrown inside the setup-key or temporary-password transaction to roll it back. */
export class OneTimeRefused extends Error {
  constructor(readonly reason: "spent" | "password_already_set" | "not_a_member" | "already_signed_in" | "other_organization") {
    super(reason);
  }
}

export type LiveSetupKey = { id: string; keyHash: string; source: "configured" | "minted"; expiresAt: Date };
export type LiveTemporaryPassword = {
  id: string;
  organizationId: string;
  hash: string;
  pepperVersion: number | null;
  expiresAt: Date;
};

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

/** `clientKey` is limiterKey(clientIp(request)). */
export function accountKeySubject(email: string, clientKey: string): string {
  return `${accountKeyPrefix(email)}${clientKey.slice(0, 64)}`;
}

function accountKeyPrefix(email: string): string {
  return `account-key:${email}|`;
}

/** `clientKey` is limiterKey(clientIp(request)). */
export function ipSubject(clientKey: string): string {
  return `ip:${clientKey.slice(0, 64)}`;
}

export type Lock = { subject: string; until: Date };

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
         FROM password_credentials c JOIN users u ON u.id = c.user_id
        WHERE u.email = $1`,
      [email],
    );
    const row = result.rows[0];
    return row ? { userId: row.user_id, hash: row.password_hash, pepperVersion: row.pepper_version } : null;
  }

  async upsertCredential(executor: SqlExecutor, userId: string, stored: StoredPassword): Promise<void> {
    await executor.query(
      `INSERT INTO password_credentials (user_id, password_hash, pepper_version, params)
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
      `UPDATE password_credentials
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
   * is inside a lock the transaction rolls back, so nothing is counted and no
   * row is created (a locked flood of new addresses cannot grow the table),
   * and the attempt is refused; otherwise each counter goes up and may start
   * (or, for backoff, extend) a lock, returned in `locks`. Concurrent
   * attempts serialize on the rows, so a parallel burst gets no more than
   * the allowance. The row locks are not held across the argon2id check.
   */
  async reserveAttempt(rules: Array<{ subject: string; rule: LockoutRule }>): Promise<
    { allowed: false } | { allowed: true; locks: Lock[] }
  > {
    const now = new Date(this.now());
    const ordered = [...rules].sort((a, b) => a.subject.localeCompare(b.subject));
    return this.database.transaction(async (tx) => {
      // Locked existing rows first, without inserting anything.
      const existing = await tx.query<{ locked_until: Date | string | null }>(
        "SELECT locked_until FROM login_attempts WHERE subject = ANY($1::text[]) ORDER BY subject FOR UPDATE",
        [ordered.map((entry) => entry.subject)],
      );
      if (existing.rows.some((row) => row.locked_until && new Date(row.locked_until).getTime() > now.getTime())) {
        return { allowed: false as const };
      }
      const rows: Array<{ subject: string; rule: LockoutRule; failures: number; restart: boolean }> = [];
      for (const { subject, rule } of ordered) {
        await tx.query(
          `INSERT INTO login_attempts (subject, failures, first_failure_at, last_failure_at)
           VALUES ($1, 0, $2, $2) ON CONFLICT (subject) DO NOTHING`,
          [subject, now],
        );
        const row = (await tx.query<{ failures: number; first_failure_at: Date | string; last_failure_at: Date | string; locked_until: Date | string | null }>(
          "SELECT failures, first_failure_at, last_failure_at, locked_until FROM login_attempts WHERE subject = $1 FOR UPDATE",
          [subject],
        )).rows[0]!;
        if (row.locked_until && new Date(row.locked_until).getTime() > now.getTime()) return { allowed: false as const };
        // Backoff forgets a subject idle for a window; a threshold counts
        // the attempts made within a window of the first one.
        const since = rule.kind === "backoff" ? row.last_failure_at : row.first_failure_at;
        const restart = row.failures === 0 || now.getTime() - new Date(since).getTime() > LOCKOUT.windowMs;
        rows.push({ subject, rule, failures: restart ? 0 : row.failures, restart });
      }
      const locks: Lock[] = [];
      for (const row of rows) {
        let attempts = row.failures + 1;
        let restart = row.restart;
        let lockedUntil: Date | null = null;
        if (row.rule.kind === "backoff") {
          const delay = lockDelayMs(attempts, row.rule.free);
          if (delay > 0) lockedUntil = new Date(now.getTime() + delay);
        } else if (attempts >= row.rule.limit) {
          // One lock, then the count starts over: attempts refused during
          // the lock count nothing, so keeping the account locked takes
          // another full allowance after it ends, not one attempt.
          lockedUntil = new Date(now.getTime() + row.rule.lockMs);
          attempts = 0;
          restart = true;
        }
        if (lockedUntil) locks.push({ subject: row.subject, until: lockedUntil });
        await tx.query(
          `UPDATE login_attempts
              SET failures = $2, last_failure_at = $3, locked_until = $4,
                  first_failure_at = CASE WHEN $5::boolean THEN $3 ELSE first_failure_at END
            WHERE subject = $1`,
          [row.subject, attempts, now, lockedUntil, restart],
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
  async refundAttempt(subject: string, rule: { free: number }): Promise<void> {
    await this.database.query(
      `UPDATE login_attempts
          SET failures = GREATEST(failures - 1, 0),
              locked_until = CASE WHEN GREATEST(failures - 1, 0) < $2 THEN NULL ELSE locked_until END
        WHERE subject = $1`,
      [subject, rule.free],
    );
  }

  /**
   * Gives back every attempt one reservation counted, when the attempt was
   * never checked (every argon2id slot was taken after the reservation).
   * Backoff subjects use refundAttempt, which also lifts a lock the
   * reservation started; threshold subjects are only decremented.
   */
  async refundAttempts(rules: Array<{ subject: string; rule: LockoutRule }>): Promise<void> {
    for (const { subject, rule } of rules) {
      if (rule.kind === "backoff") {
        await this.refundAttempt(subject, rule);
      } else {
        await this.database.query(
          "UPDATE login_attempts SET failures = GREATEST(failures - 1, 0) WHERE subject = $1",
          [subject],
        );
      }
    }
  }

  async clearSubject(executor: SqlExecutor, subject: string): Promise<void> {
    await executor.query("DELETE FROM login_attempts WHERE subject = $1", [subject]);
  }

  /** Clears the account's lockout: its "account:" row and every "account-key:" row. */
  async clearAccount(executor: SqlExecutor, email: string): Promise<void> {
    const prefix = accountKeyPrefix(email);
    await executor.query(
      "DELETE FROM login_attempts WHERE subject = $1 OR left(subject, $3) = $2",
      [accountSubject(email), prefix, prefix.length],
    );
  }

  /**
   * Claims the once-a-day lockout notice for the account behind `email`.
   * The user id when the notice should be sent now, else null (no password,
   * or a notice went out within 24 hours).
   */
  async claimLockoutNotice(email: string): Promise<string | null> {
    const now = this.now();
    const result = await this.database.query<{ user_id: string }>(
      `UPDATE password_credentials c SET lockout_notice_at = $2
         FROM users u
        WHERE u.id = c.user_id AND u.email = $1
          AND (c.lockout_notice_at IS NULL OR c.lockout_notice_at <= $3)
        RETURNING c.user_id`,
      [email, new Date(now), new Date(now - LOCKOUT_NOTICE_INTERVAL_MS)],
    );
    return result.rows[0]?.user_id ?? null;
  }

  /**
   * Inside the sign-in transaction (which holds the identity lock): throws
   * CredentialChanged unless the person's password hash is still the one
   * that was verified. A reset that committed after the verify is caught
   * here, and the sign-in (and its session) rolls back.
   */
  async assertCredentialUnchanged(tx: SqlExecutor, userId: string, verifiedHash: string): Promise<void> {
    const current = await tx.query<{ password_hash: string }>(
      "SELECT password_hash FROM password_credentials WHERE user_id = $1",
      [userId],
    );
    if (current.rows[0]?.password_hash !== verifiedHash) throw new CredentialChanged();
  }

  // ---- registration --------------------------------------------------------------

  /**
   * Stores a pending registration (no password) and returns its single-use
   * token. Older links for the address stay valid until they expire or one
   * of them is used: a new request (which anyone can make) must not cancel
   * the link the owner is about to click.
   */
  async createRegistration(input: { email: string; inviteTokenHash: string | null }): Promise<string> {
    const token = opaqueToken("sh_pv_");
    await this.database.query(
      `INSERT INTO password_registrations (id, email, token_hash, invite_token_hash, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [randomUUID(), input.email, hashSecret(token), input.inviteTokenHash, new Date(this.now() + REGISTRATION_TTL_MS)],
    );
    return token;
  }

  /** The address of a live verification link, without spending it. */
  async peekRegistration(token: string): Promise<{ email: string } | null> {
    if (!REGISTRATION_TOKEN.test(token)) return null;
    const result = await this.database.query<{ email: string }>(
      `SELECT email FROM password_registrations
        WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2`,
      [hashSecret(token), new Date(this.now())],
    );
    const row = result.rows[0];
    return row ? { email: row.email } : null;
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
        `UPDATE password_registrations SET consumed_at = now()
          WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2
          RETURNING email, invite_token_hash`,
        [hashSecret(token), new Date(now)],
      );
      const row = spent.rows[0];
      if (!row) return null;
      const existing = await tx.query(
        `SELECT 1 FROM password_credentials c JOIN users u ON u.id = c.user_id WHERE u.email = $1`,
        [row.email],
      );
      if (existing.rows.length) return { email: row.email, refused: "password_already_set" as const };
      // A link was used: every other outstanding link and set-password
      // token for the address stops working.
      await tx.query(
        "UPDATE password_registrations SET consumed_at = now() WHERE email = $1 AND consumed_at IS NULL",
        [row.email],
      );
      await tx.query(
        "UPDATE password_setup_tokens SET consumed_at = now() WHERE email = $1 AND consumed_at IS NULL",
        [row.email],
      );
      const setupToken = opaqueToken("sh_ps_");
      const expiresAt = new Date(now + SETUP_TTL_MS);
      await tx.query(
        `INSERT INTO password_setup_tokens (id, email, token_hash, invite_token_hash, expires_at)
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
      `SELECT email, invite_token_hash FROM password_setup_tokens
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
    const spent = await tx.query<{ email: string }>(
      `UPDATE password_setup_tokens SET consumed_at = now()
        WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > $2
        RETURNING email`,
      [hashSecret(token), new Date(this.now())],
    );
    const email = spent.rows[0]?.email;
    if (!email) throw new SetupRefused("token_invalid");
    if (!await this.insertFirstCredential(tx, userId, stored)) throw new SetupRefused("password_already_set");
    // The password is set: no other outstanding link for the address works.
    await tx.query("UPDATE password_registrations SET consumed_at = now() WHERE email = $1 AND consumed_at IS NULL", [email]);
    await tx.query("UPDATE password_setup_tokens SET consumed_at = now() WHERE email = $1 AND consumed_at IS NULL", [email]);
  }

  /** Writes a credential only if the person has none. False if one exists. */
  async insertFirstCredential(executor: SqlExecutor, userId: string, stored: StoredPassword): Promise<boolean> {
    const inserted = await executor.query(
      `INSERT INTO password_credentials (user_id, password_hash, pepper_version, params)
       VALUES ($1, $2, $3, $4) ON CONFLICT (user_id) DO NOTHING RETURNING user_id`,
      [userId, stored.hash, stored.pepperVersion, stored.params],
    );
    return inserted.rows.length === 1;
  }

  // ---- reset ---------------------------------------------------------------------

  /**
   * A reset token for an address that has a password, else null. Older
   * links stay valid until they expire or a reset completes, so a request
   * made by someone else cannot cancel the owner's link.
   */
  async createReset(email: string): Promise<{ token: string; userId: string } | null> {
    return this.database.transaction(async (tx) => {
      const found = await tx.query<{ user_id: string }>(
        `SELECT c.user_id FROM password_credentials c JOIN users u ON u.id = c.user_id
          WHERE u.email = $1 FOR UPDATE OF c`,
        [email],
      );
      const userId = found.rows[0]?.user_id;
      if (!userId) return null;
      const token = opaqueToken("sh_pr_");
      await tx.query(
        "INSERT INTO password_reset_tokens (id, user_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)",
        [randomUUID(), userId, hashSecret(token), new Date(this.now() + RESET_TTL_MS)],
      );
      return { token, userId };
    });
  }

  /** The owner of a live reset token, without spending it. */
  async peekReset(token: string): Promise<{ userId: string; email: string } | null> {
    if (!RESET_TOKEN.test(token)) return null;
    const result = await this.database.query<{ user_id: string; email: string }>(
      `SELECT r.user_id, u.email FROM password_reset_tokens r JOIN users u ON u.id = r.user_id
        WHERE r.token_hash = $1 AND r.used_at IS NULL AND r.expires_at > $2`,
      [hashSecret(token), new Date(this.now())],
    );
    const row = result.rows[0];
    return row ? { userId: row.user_id, email: row.email } : null;
  }

  /**
   * Spends the token and sets the new password in one transaction; `revoke`
   * runs in the same transaction to end every session of the person.
   *
   * The identity lock (lockIdentity, the same advisory lock every sign-in
   * holds for its whole transaction) is taken before the token is spent and
   * before anything is revoked. That ordering is what makes the revocation
   * complete, so no reset_started_at marker compared with session
   * created_at is needed:
   *
   * - a sign-in that took the identity lock first commits its session
   *   before this transaction gets the lock, and the revocation (a later
   *   statement, so a later snapshot) sees and revokes it;
   * - a sign-in that asks for the lock after this one has it waits until the
   *   reset commits, and a password sign-in then re-reads the credential
   *   inside its transaction (assertCredentialUnchanged) and rolls back,
   *   because the hash it verified is gone. Other methods it could use
   *   (email links, set-password tokens) are voided below in the same
   *   transaction.
   *
   * So no session created against the old password survives the reset.
   */
  async completeReset(
    token: string,
    stored: StoredPassword,
    revoke: (tx: SqlExecutor, userId: string) => Promise<void>,
  ): Promise<{ userId: string; email: string } | null> {
    if (!RESET_TOKEN.test(token)) return null;
    const tokenHash = hashSecret(token);
    return this.database.transaction(async (tx) => {
      const owner = (await tx.query<{ email: string }>(
        `SELECT u.email FROM password_reset_tokens r JOIN users u ON u.id = r.user_id
          WHERE r.token_hash = $1 AND r.used_at IS NULL AND r.expires_at > $2`,
        [tokenHash, new Date(this.now())],
      )).rows[0];
      if (!owner) return null;
      await lockIdentity(tx, owner.email);
      const spent = await tx.query<{ user_id: string }>(
        `UPDATE password_reset_tokens SET used_at = now()
          WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2
          RETURNING user_id`,
        [tokenHash, new Date(this.now())],
      );
      const userId = spent.rows[0]?.user_id;
      if (!userId) return null;
      const user = (await tx.query<{ email: string }>("SELECT email FROM users WHERE id = $1", [userId])).rows[0]!;
      await this.upsertCredential(tx, userId, stored);
      await revoke(tx, userId);
      // Every other outstanding link for the person stops working too.
      await tx.query("UPDATE password_reset_tokens SET used_at = now() WHERE user_id = $1 AND used_at IS NULL", [userId]);
      await tx.query("UPDATE password_registrations SET consumed_at = now() WHERE email = $1 AND consumed_at IS NULL", [user.email]);
      await tx.query("UPDATE password_setup_tokens SET consumed_at = now() WHERE email = $1 AND consumed_at IS NULL", [user.email]);
      await tx.query("UPDATE email_login_tokens SET consumed_at = now() WHERE email = $1 AND consumed_at IS NULL", [user.email]);
      // A temporary password set before the reset must not undo it.
      await tx.query("UPDATE temporary_passwords SET revoked_at = now() WHERE email = $1 AND used_at IS NULL AND revoked_at IS NULL", [user.email]);
      await this.clearAccount(tx, user.email);
      return { userId, email: user.email };
    });
  }

  // ---- setup key (first admin) -----------------------------------------------------

  /**
   * Records a configured key (SELFHOST_SETUP_KEY) the first time the server
   * sees it; the 24 hours start then. A key seen before keeps its row (and
   * its expiry, use or revocation), so a restart never renews it.
   */
  async recordConfiguredSetupKey(email: string, keyHash: string): Promise<void> {
    await this.database.query(
      `INSERT INTO setup_keys (id, email, key_hash, source, expires_at)
       VALUES ($1, $2, $3, 'configured', $4) ON CONFLICT (key_hash) DO NOTHING`,
      [randomUUID(), email, keyHash, new Date(this.now() + SETUP_KEY_TTL_MS)],
    );
  }

  /** Mints a key for `email`, revoking every earlier live one. Returns it once. */
  async mintSetupKey(email: string): Promise<{ key: string; expiresAt: Date }> {
    const key = opaqueToken("sh_sk_");
    const expiresAt = new Date(this.now() + SETUP_KEY_TTL_MS);
    await this.database.transaction(async (tx) => {
      // Serializes concurrent mints (and redemptions) for the address.
      await lockIdentity(tx, email);
      await tx.query("UPDATE setup_keys SET revoked_at = now() WHERE email = $1 AND used_at IS NULL AND revoked_at IS NULL", [email]);
      await tx.query(
        "INSERT INTO setup_keys (id, email, key_hash, source, expires_at) VALUES ($1, $2, $3, 'minted', $4)",
        [randomUUID(), email, hashSecret(key), expiresAt],
      );
    });
    return { key, expiresAt };
  }

  /** Live (unused, unrevoked, unexpired) keys for the address, newest first. */
  async liveSetupKeys(email: string): Promise<LiveSetupKey[]> {
    const result = await this.database.query<{ id: string; key_hash: string; source: "configured" | "minted"; expires_at: Date | string }>(
      `SELECT id, key_hash, source, expires_at FROM setup_keys
        WHERE email = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $2
        ORDER BY created_at DESC`,
      [email, new Date(this.now())],
    );
    return result.rows.map((row) => ({ id: row.id, keyHash: row.key_hash, source: row.source, expiresAt: new Date(row.expires_at) }));
  }

  /**
   * Whether `email` has never finished a sign-in here and has no password:
   * the only time a setup key is offered or accepted.
   */
  async neverSignedIn(email: string): Promise<boolean> {
    const result = await this.database.query<{ signed_in: boolean }>(
      `SELECT EXISTS (
         SELECT 1 FROM users u
          WHERE u.email = $1
            AND (u.last_organization_id IS NOT NULL
                 OR EXISTS (SELECT 1 FROM password_credentials c WHERE c.user_id = u.id)
                 OR EXISTS (SELECT 1 FROM token_sessions s WHERE s.user_id = u.id))
       ) AS signed_in`,
      [email],
    );
    return result.rows[0]?.signed_in !== true;
  }

  /** Revokes every live key for the address (the admin signed in another way). */
  async revokeSetupKeys(email: string): Promise<number> {
    const result = await this.database.query(
      "UPDATE setup_keys SET revoked_at = now() WHERE email = $1 AND used_at IS NULL AND revoked_at IS NULL RETURNING id",
      [email],
    );
    return result.rows.length;
  }

  /**
   * Inside the sign-in transaction: spends the key and writes the admin's
   * first password. Throws OneTimeRefused (rolling the sign-in back) when
   * the key is no longer live or a password exists.
   */
  async redeemSetupKey(tx: SqlExecutor, keyId: string, userId: string, stored: StoredPassword): Promise<void> {
    const spent = await tx.query<{ email: string }>(
      `UPDATE setup_keys SET used_at = now()
        WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $2
        RETURNING email`,
      [keyId, new Date(this.now())],
    );
    const email = spent.rows[0]?.email;
    if (!email) throw new OneTimeRefused("spent");
    // Under the identity lock the sign-in holds: the session this sign-in
    // just issued must be the person's only one ever, so a sign-in by any
    // other method that committed after the key was checked wins.
    const sessions = await tx.query<{ n: number }>("SELECT count(*)::int AS n FROM token_sessions WHERE user_id = $1", [userId]);
    if (sessions.rows[0]!.n > 1) throw new OneTimeRefused("already_signed_in");
    if (!await this.insertFirstCredential(tx, userId, stored)) throw new OneTimeRefused("password_already_set");
    await tx.query("UPDATE setup_keys SET revoked_at = now() WHERE email = $1 AND used_at IS NULL AND revoked_at IS NULL", [email]);
  }

  // ---- temporary passwords ------------------------------------------------------------

  /**
   * Stores a temporary password for `email` in `organizationId`, revoking
   * any earlier live one for the address.
   */
  async createTemporaryPassword(input: {
    organizationId: string;
    email: string;
    stored: StoredPassword;
    createdByUserId: string | null;
    ttlMs: number;
  }): Promise<{ id: string; expiresAt: Date }> {
    const id = randomUUID();
    const expiresAt = new Date(this.now() + input.ttlMs);
    await this.database.transaction(async (tx) => {
      // Serializes concurrent setters for the address (one live row each).
      await lockIdentity(tx, input.email);
      await tx.query(
        "UPDATE temporary_passwords SET revoked_at = now() WHERE email = $1 AND used_at IS NULL AND revoked_at IS NULL",
        [input.email],
      );
      await tx.query(
        `INSERT INTO temporary_passwords
           (id, organization_id, email, password_hash, pepper_version, params, created_by_user_id, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [id, input.organizationId, input.email, input.stored.hash, input.stored.pepperVersion, input.stored.params, input.createdByUserId, expiresAt],
      );
    });
    return { id, expiresAt };
  }

  async liveTemporaryPassword(email: string): Promise<LiveTemporaryPassword | null> {
    const result = await this.database.query<{ id: string; organization_id: string; password_hash: string; pepper_version: number | null; expires_at: Date | string }>(
      `SELECT id, organization_id, password_hash, pepper_version, expires_at FROM temporary_passwords
        WHERE email = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $2`,
      [email, new Date(this.now())],
    );
    const row = result.rows[0];
    return row
      ? { id: row.id, organizationId: row.organization_id, hash: row.password_hash, pepperVersion: row.pepper_version, expiresAt: new Date(row.expires_at) }
      : null;
  }

  /** Revokes the live temporary password of an address in an organization (invite canceled). */
  async revokeTemporaryPasswords(organizationId: string, email: string): Promise<number> {
    const result = await this.database.query(
      `UPDATE temporary_passwords SET revoked_at = now()
        WHERE organization_id = $1 AND email = $2 AND used_at IS NULL AND revoked_at IS NULL RETURNING id`,
      [organizationId, email],
    );
    return result.rows.length;
  }

  /**
   * Inside the sign-in transaction: spends the temporary password and writes
   * the person's new password. Throws OneTimeRefused (rolling the sign-in
   * back) when it is no longer live or the person is not a member of the
   * organization that set it.
   */
  async redeemTemporaryPassword(tx: SqlExecutor, id: string, userId: string, stored: StoredPassword): Promise<void> {
    const spent = await tx.query<{ organization_id: string; email: string }>(
      `UPDATE temporary_passwords SET used_at = now()
        WHERE id = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $2
        RETURNING organization_id, email`,
      [id, new Date(this.now())],
    );
    const row = spent.rows[0];
    if (!row) throw new OneTimeRefused("spent");
    const member = await tx.query(
      "SELECT 1 FROM organization_memberships WHERE organization_id = $1 AND user_id = $2",
      [row.organization_id, userId],
    );
    if (!member.rows.length) throw new OneTimeRefused("not_a_member");
    // Checked again here, after this sign-in accepted any open invites: a
    // password one organization set must not reach another organization
    // the person belongs to (or was invited to) as well.
    const other = await tx.query(
      "SELECT 1 FROM organization_memberships WHERE user_id = $1 AND organization_id <> $2 LIMIT 1",
      [userId, row.organization_id],
    );
    if (other.rows.length) throw new OneTimeRefused("other_organization");
    await this.upsertCredential(tx, userId, stored);
    await this.clearAccount(tx, row.email);
  }

  // ---- retention -----------------------------------------------------------------

  /**
   * Deletes login attempt rows idle for 24 hours (none of them is still
   * locked: every lock is at most 15 minutes) and registration, set-password
   * and reset tokens that were spent or expired more than 7 days ago.
   */
  async sweep(): Promise<{ attempts: number; registrations: number; setups: number; resets: number; setupKeys: number; temporaryPasswords: number }> {
    const now = this.now();
    const attemptCutoff = new Date(now - ATTEMPT_RETENTION_MS);
    const tokenCutoff = new Date(now - TOKEN_RETENTION_MS);
    const attempts = await this.database.query(
      "DELETE FROM login_attempts WHERE last_failure_at < $1 AND (locked_until IS NULL OR locked_until < $1) RETURNING subject",
      [attemptCutoff],
    );
    const registrations = await this.database.query(
      "DELETE FROM password_registrations WHERE COALESCE(consumed_at, expires_at) < $1 RETURNING id",
      [tokenCutoff],
    );
    const setups = await this.database.query(
      "DELETE FROM password_setup_tokens WHERE COALESCE(consumed_at, expires_at) < $1 RETURNING id",
      [tokenCutoff],
    );
    const resets = await this.database.query(
      "DELETE FROM password_reset_tokens WHERE COALESCE(used_at, expires_at) < $1 RETURNING id",
      [tokenCutoff],
    );
    // A configured setup key keeps its row: deleting it would let the same
    // SELFHOST_SETUP_KEY be recorded again, with a fresh 24 hours.
    const setupKeys = await this.database.query(
      "DELETE FROM setup_keys WHERE source = 'minted' AND COALESCE(used_at, revoked_at, expires_at) < $1 RETURNING id",
      [tokenCutoff],
    );
    const temporaryPasswords = await this.database.query(
      "DELETE FROM temporary_passwords WHERE COALESCE(used_at, revoked_at, expires_at) < $1 RETURNING id",
      [tokenCutoff],
    );
    return {
      attempts: attempts.rows.length,
      registrations: registrations.rows.length,
      setups: setups.rows.length,
      resets: resets.rows.length,
      setupKeys: setupKeys.rows.length,
      temporaryPasswords: temporaryPasswords.rows.length,
    };
  }

  // ---- audit ---------------------------------------------------------------------

  /** The organization a person's audit events belong to: their last, else the bootstrap one. */
  async auditOrganization(userId: string | null): Promise<string | null> {
    const result = await this.database.query<{ organization_id: string | null }>(
      `SELECT COALESCE(
         (SELECT last_organization_id FROM users WHERE id = $1::uuid),
         (SELECT organization_id FROM installation_bootstrap WHERE installation_slot = 1)
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
