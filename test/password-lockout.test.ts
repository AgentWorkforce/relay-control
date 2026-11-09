import assert from "node:assert/strict";
import test from "node:test";
import { HashSlots, PasswordHasher, type VerifyOutcome } from "../src/identity/password/hashing.js";
import { LOCKOUT } from "../src/identity/password/store.js";
import {
  API,
  auditActions,
  call,
  type Ctx,
  linkToken,
  login,
  PASSWORD,
  passwordConfig,
  registerVerified,
  session,
  sessionCookie,
  setup,
  verifyLink,
} from "./support/password.js";

/*
 * Password sign-in: reset races, the argon2id slot cap, the account-wide
 * lock, audit volume under a locked flood, mail buckets and the link pages.
 * (Kept apart from password-hardening.test.ts so each file stays inside the
 * test memory guard.)
 */

// ---- reset races, argon2id capacity and the account-wide lock ----------------------------

/** A hasher whose verify can be held after it finished, to straddle a reset. */
class GatedHasher extends PasswordHasher {
  gate: Promise<void> | null = null;
  entered: (() => void) | null = null;

  override async verify(password: string, stored: { hash: string; pepperVersion: number | null }): Promise<VerifyOutcome> {
    const outcome = await super.verify(password, stored);
    const gate = this.gate;
    if (gate) {
      this.gate = null;
      this.entered?.();
      await gate;
    }
    return outcome;
  }
}

const liveSessions = async (ctx: Ctx, email: string) => Number((await ctx.database.query<{ n: number }>(
  `SELECT count(*)::int AS n FROM selfhost_token_sessions s JOIN selfhost_users u ON u.id = s.user_id
    WHERE u.email = $1 AND s.revoked_at IS NULL`, [email])).rows[0]!.n);

test("reset race: a sign-in whose verify straddles a reset answers 401 and leaves no live session", async (t) => {
  const hasher = new GatedHasher(passwordConfig());
  const ctx = await setup(t, { passwordHasher: hasher });
  await registerVerified(ctx, "race@acme.test");
  await call(ctx.origin, `${API}/reset`, { json: { email: "race@acme.test" } });
  await ctx.identity.idle();
  const token = linkToken(ctx.mailer.sent.at(-1)!, "/login/password/reset");

  // The old password verifies, then the request is held before its session is issued.
  let release!: () => void;
  hasher.gate = new Promise<void>((resolve) => { release = resolve; });
  const entered = new Promise<void>((resolve) => { hasher.entered = resolve; });
  const pending = login(ctx, "race@acme.test", PASSWORD);
  await entered;
  const done = await call(ctx.origin, `${API}/reset/complete`, { json: { token, password: "a brand new long passphrase" }, ip: "198.51.100.9" });
  assert.equal(done.status, 200, done.text);
  assert.equal(await liveSessions(ctx, "race@acme.test"), 0);
  release();

  const raced = await pending;
  const wrong = await login(ctx, "race@acme.test", "certainly not the password", "198.51.100.10");
  assert.equal(raced.status, 401);
  assert.equal(raced.text, wrong.text, "byte-identical to any failed sign-in");
  assert.equal(raced.cookies.agent_relay_session, undefined);
  assert.equal(await liveSessions(ctx, "race@acme.test"), 0, "the session issued with the old password was rolled back");
  assert.ok((await auditActions(ctx)).some((e) => e.action === "login.password.failure" && e.target!.includes("reason=credential_changed")));
  assert.equal((await login(ctx, "race@acme.test", "a brand new long passphrase", "198.51.100.11")).status, 200);
});

test("argon2id slots: when every slot is busy, password routes answer 429 at once without hashing or counting", async (t) => {
  const slots = new HashSlots(1);
  const ctx = await setup(t, { passwordHasher: new PasswordHasher(passwordConfig(), { slots }) });
  await registerVerified(ctx, "busy@acme.test");
  const setupToken = (await call(ctx.origin, `${API}/verify`, { json: { token: await verifyLink(ctx, "busy2@acme.test") } })).body.setupToken;
  await call(ctx.origin, `${API}/reset`, { json: { email: "busy@acme.test" } });
  await ctx.identity.idle();
  const resetToken = linkToken(ctx.mailer.sent.at(-1)!, "/login/password/reset");
  const attemptsBefore = await ctx.database.query("SELECT subject FROM selfhost_login_attempts");
  const auditBefore = (await auditActions(ctx)).length;

  const hold = slots.tryAcquire()!;
  assert.equal(slots.tryAcquire(), null, "the only slot is taken");
  const started = Date.now();
  const refused = await login(ctx, "busy@acme.test", PASSWORD);
  assert.equal(refused.status, 429);
  assert.equal(refused.body.error, "rate_limited");
  const set = await call(ctx.origin, `${API}/set`, { json: { token: setupToken, password: PASSWORD } });
  assert.equal(set.status, 429, set.text);
  assert.equal(set.body.error, "rate_limited");
  const reset = await call(ctx.origin, `${API}/reset/complete`, { json: { token: resetToken, password: "a brand new long passphrase" } });
  assert.equal(reset.status, 429, reset.text);
  assert.ok(Date.now() - started < 5_000, "refused at once, not queued");
  assert.deepEqual((await ctx.database.query("SELECT subject FROM selfhost_login_attempts")).rows, attemptsBefore.rows, "a refused sign-in counts nothing");
  assert.equal((await auditActions(ctx)).length, auditBefore, "and writes no audit row");
  await assert.rejects(new PasswordHasher(passwordConfig(), { slots }).hash(PASSWORD), /capacity/);

  hold();
  assert.equal((await login(ctx, "busy@acme.test", PASSWORD)).status, 200);
  assert.equal((await call(ctx.origin, `${API}/set`, { json: { token: setupToken, password: PASSWORD } })).status, 200, "the token was not spent by the refusal");
  assert.equal((await call(ctx.origin, `${API}/reset/complete`, { json: { token: resetToken, password: "a brand new long passphrase" } })).status, 200);
});

test("lockout: 50 failures in an hour from many clients lock the account for 15 minutes and mail the owner once a day", async (t) => {
  const ctx = await setup(t);
  await registerVerified(ctx, "target@acme.test");
  const locked = (e: { action: string; target: string | null }) => e.action === "login.lockout" && e.target!.includes("scope=account ");
  const notices = () => ctx.mailer.sent.filter((m) => m.to === "target@acme.test" && /Too many failed sign-ins/.test(m.subject));
  const round = async (net: string) => {
    for (let i = 1; i <= LOCKOUT.account.limit; i += 1) {
      assert.equal((await login(ctx, "target@acme.test", "a wrong passphrase", `${net}.${i}`)).status, 401);
    }
    await ctx.identity.idle();
  };

  await round("198.51.100");
  assert.equal((await login(ctx, "target@acme.test", PASSWORD, "203.0.113.200")).status, 401, "locked for every client, even with the right password");
  assert.equal((await auditActions(ctx)).filter(locked).length, 1, "one login.lockout row");
  assert.equal(notices().length, 1, "the owner is mailed");
  assert.match(notices()[0]!.text, /\/login\/password\/reset/);

  ctx.clock.now += LOCKOUT.account.lockMs + 1_000;
  assert.equal((await login(ctx, "target@acme.test", PASSWORD, "203.0.113.200")).status, 200, "the lock ends after 15 minutes");
  const left = (await ctx.database.query<{ subject: string }>("SELECT subject FROM selfhost_login_attempts WHERE subject LIKE '%target@acme.test%'")).rows.map((r) => r.subject);
  assert.ok(!left.includes("account:target@acme.test"), "a success clears the account-wide counter");
  assert.ok(!left.includes("account-key:target@acme.test|203.0.113.200"), "and its own client's counter");
  assert.equal(left.length, LOCKOUT.account.limit, "other clients' counters are theirs to wait out");

  await round("192.0.2");
  assert.equal((await auditActions(ctx)).filter(locked).length, 2, "locked again");
  assert.equal(notices().length, 1, "but not mailed again within a day");

  ctx.clock.now += 24 * 60 * 60 * 1_000;
  await round("203.0.113");
  assert.equal(notices().length, 2, "a day later the owner is mailed again");
});

test("lockout: a locked flood of 50 attempts adds at most one audit row", async (t) => {
  const ctx = await setup(t);
  await registerVerified(ctx, "flood@acme.test");
  for (let i = 0; i < LOCKOUT.accountKey.free; i += 1) await login(ctx, "flood@acme.test", "a wrong passphrase");
  const before = (await auditActions(ctx)).length;
  for (let i = 0; i < 50; i += 1) assert.equal((await login(ctx, "flood@acme.test", "a wrong passphrase")).status, 401);
  assert.ok((await auditActions(ctx)).length - before <= 1);
});

test("mail limits: registration and reset mail have separate buckets", async (t) => {
  const ctx = await setup(t);
  await registerVerified(ctx, "mail@acme.test");
  const sentTo = () => ctx.mailer.sent.filter((m) => m.to === "mail@acme.test").length;
  const start = sentTo();
  for (let i = 0; i < 4; i += 1) await call(ctx.origin, `${API}/register`, { json: { email: "mail@acme.test" } });
  await ctx.identity.idle();
  assert.equal(sentTo() - start, 2, "3 registration mails per address (the first went with registerVerified)");
  for (let i = 0; i < 4; i += 1) assert.equal((await call(ctx.origin, `${API}/reset`, { json: { email: "mail@acme.test" } })).status, 202);
  await ctx.identity.idle();
  assert.equal(sentTo() - start, 5, "reset mail is not spent by registrations, and has its own 3");
});

// ---- the link pages ------------------------------------------------------------------------

test("link pages: the fragment token is posted same-origin from /login/password/verify and /login/password/reset", async (t) => {
  const ctx = await setup(t);
  const verifyPage = await call(ctx.origin, "/login/password/verify");
  assert.equal(verifyPage.status, 200);
  assert.match(verifyPage.text, /<form id="set" method="post" action="\/login\/password\/verify" hidden>/);
  assert.match(verifyPage.text, /location\.hash/);
  assert.match(verifyPage.text, /history\.replaceState/);

  const token = await verifyLink(ctx, "page@acme.test");
  const crossSite = await call(ctx.origin, "/login/password/verify", { form: { token, password: PASSWORD }, originHeader: "https://evil.example" });
  assert.equal(crossSite.status, 403);
  const weak = await call(ctx.origin, "/login/password/verify", { form: { token, password: "short" } });
  assert.equal(weak.status, 400);
  assert.match(weak.text, new RegExp(`name="token" id="token" value="${token}"`), "the form comes back with the link still usable");
  const set = await call(ctx.origin, "/login/password/verify", { form: { token, password: PASSWORD } });
  assert.equal(set.status, 303, set.text);
  assert.equal(set.location, "/");
  assert.equal((await session(ctx, sessionCookie(set))).status, 200);
  await ctx.identity.idle();
  assert.ok(ctx.mailer.sent.some((m) => m.to === "page@acme.test" && /password was added/i.test(m.subject)));
  const again = await call(ctx.origin, "/login/password/verify", { form: { token, password: PASSWORD } });
  assert.equal(again.status, 410, "the link works once");

  const resetPage = await call(ctx.origin, "/login/password/reset");
  assert.equal(resetPage.status, 200);
  assert.match(resetPage.text, /<form id="none" method="post" action="\/login\/password\/reset">/);
  const requested = await call(ctx.origin, "/login/password/reset", { form: { email: "page@acme.test" } });
  assert.equal(requested.status, 200);
  assert.match(requested.text, /Check your email/);
  await ctx.identity.idle();
  const resetToken = linkToken(ctx.mailer.sent.at(-1)!, "/login/password/reset");
  const changed = await call(ctx.origin, "/login/password/reset", { form: { token: resetToken, password: "a brand new long passphrase" } });
  assert.equal(changed.status, 200, changed.text);
  assert.match(changed.text, /Password changed/);
  assert.equal((await session(ctx, sessionCookie(set))).status, 401, "the reset signed the browser out");
  await ctx.identity.idle();
  assert.ok(ctx.mailer.sent.some((m) => m.to === "page@acme.test" && /password was changed/i.test(m.subject)));
  assert.equal((await login(ctx, "page@acme.test", "a brand new long passphrase")).status, 200);
});
