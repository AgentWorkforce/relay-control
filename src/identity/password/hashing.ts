import { createHmac, randomBytes } from "node:crypto";
import { hash as argon2Hash, verify as argon2Verify, type Options } from "@node-rs/argon2";
import type { Argon2Params, PasswordConfig, PasswordPepper } from "../config.js";

/**
 * Password hashing: argon2id with a random 16-byte salt per hash, stored as
 * the library's PHC string ($argon2id$v=19$m=..,t=..,p=..$salt$hash), which
 * carries the salt and parameters. With a pepper file the password is first
 * HMAC-SHA256'd with the current pepper (base64 of the MAC is hashed); the pepper version is stored next to
 * the hash (never the pepper). Nothing here logs or returns password material.
 */

const ARGON2ID = 2; // Algorithm.Argon2id (a const enum in the package typings)

export type StoredPassword = {
  hash: string;
  /** Null when the hash was made without a pepper. */
  pepperVersion: number | null;
  /** "m=<KiB>,t=<passes>,p=<lanes>", for operators reading the table. */
  params: string;
};

export type VerifyOutcome = { ok: boolean; needsRehash: boolean };

export function paramsLabel(params: Argon2Params): string {
  return `m=${params.memoryCost},t=${params.timeCost},p=${params.parallelism}`;
}

/** The m/t/p a PHC string was made with, or null when it is not argon2id. */
export function parsePhcParams(phc: string): Argon2Params | null {
  const match = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(phc);
  if (!match) return null;
  return { memoryCost: Number(match[1]), timeCost: Number(match[2]), parallelism: Number(match[3]) };
}

/** Thrown when every argon2id slot is busy; the caller answers 429 without hashing. */
export class HasherBusy extends Error {
  constructor() {
    super("password hashing is at capacity");
  }
}

/** A counting semaphore that never queues: a caller gets a slot or is refused. */
export class HashSlots {
  private used = 0;

  constructor(readonly max: number) {}

  get available(): number {
    return this.max - this.used;
  }

  /** A release function, or null when every slot is taken. */
  tryAcquire(): (() => void) | null {
    if (this.used >= this.max) return null;
    this.used += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.used -= 1;
    };
  }
}

/** Concurrent argon2id hashes and verifies allowed per process. */
export const MAX_CONCURRENT_HASHES = 8;
/**
 * Shared by every hasher in the process: argon2id work runs on the libuv
 * pool, and a flood beyond this answers 429 at once instead of queueing
 * memory-hard work behind it.
 */
const PROCESS_HASH_SLOTS = new HashSlots(MAX_CONCURRENT_HASHES);

export class PasswordHasher {
  private readonly options: Options;
  private readonly peppers: Map<number, Buffer>;
  /** A real hash at the current parameters, verified for unknown accounts. */
  private dummy: Promise<string> | null = null;
  private readonly slots: HashSlots;

  constructor(
    private readonly config: Pick<PasswordConfig, "argon2" | "peppers" | "currentPepperVersion">,
    options: { slots?: HashSlots } = {},
  ) {
    this.slots = options.slots ?? PROCESS_HASH_SLOTS;
    this.options = {
      algorithm: ARGON2ID,
      memoryCost: config.argon2.memoryCost,
      timeCost: config.argon2.timeCost,
      parallelism: config.argon2.parallelism,
    };
    this.peppers = new Map(config.peppers.map((pepper: PasswordPepper) => [pepper.version, pepper.secret]));
  }

  /** False when every argon2id slot is busy (a cheap pre-check; the call itself still decides). */
  get hasCapacity(): boolean {
    return this.slots.available > 0;
  }

  /** Runs argon2id work in a slot, or throws HasherBusy at once when none is free. */
  private async slot<T>(work: () => Promise<T>): Promise<T> {
    const release = this.slots.tryAcquire();
    if (!release) throw new HasherBusy();
    try {
      return await work();
    } finally {
      release();
    }
  }

  get params(): Argon2Params {
    return { ...this.config.argon2 };
  }

  get currentPepperVersion(): number | null {
    return this.config.currentPepperVersion;
  }

  private input(password: string, pepperVersion: number | null): Buffer | null {
    const utf8 = Buffer.from(password.normalize("NFC"), "utf8");
    if (pepperVersion === null) return utf8;
    const pepper = this.peppers.get(pepperVersion);
    if (!pepper) return null;
    // Base64 text, not the raw digest: @node-rs/argon2 does not round-trip
    // arbitrary binary input between hash() and verify().
    return Buffer.from(createHmac("sha256", pepper).update(utf8).digest("base64"), "utf8");
  }

  async hash(password: string): Promise<StoredPassword> {
    const version = this.config.currentPepperVersion;
    const input = this.input(password, version)!;
    return {
      hash: await this.slot(() => argon2Hash(input, { ...this.options, salt: randomBytes(16) })),
      pepperVersion: version,
      params: paramsLabel(this.config.argon2),
    };
  }

  /**
   * Constant-time verify (the library compares digests in constant time).
   * needsRehash is set on success when the stored parameters or pepper
   * version differ from the current ones. A hash whose pepper version is no
   * longer configured cannot verify; a dummy verify keeps the timing.
   * Throws HasherBusy when every slot is taken.
   */
  async verify(password: string, stored: { hash: string; pepperVersion: number | null }): Promise<VerifyOutcome> {
    const input = this.input(password, stored.pepperVersion);
    if (input === null) {
      await this.dummyVerify(password);
      return { ok: false, needsRehash: false };
    }
    const ok = await this.slot(async () => {
      try {
        return await argon2Verify(stored.hash, input);
      } catch {
        return false;
      }
    });
    if (!ok) return { ok: false, needsRehash: false };
    const params = parsePhcParams(stored.hash);
    const current = this.config.argon2;
    const needsRehash = stored.pepperVersion !== this.config.currentPepperVersion || params === null ||
      params.memoryCost !== current.memoryCost || params.timeCost !== current.timeCost ||
      params.parallelism !== current.parallelism;
    return { ok: true, needsRehash };
  }

  /**
   * Spends one verify at the current parameters, for accounts without a
   * password. Takes a slot like a real verify (HasherBusy when none is free),
   * so an unknown address is refused under load exactly like a known one.
   */
  async dummyVerify(password: string): Promise<void> {
    // The one-off dummy hash is made outside the slots (once per process).
    this.dummy ??= argon2Hash(randomBytes(32), { ...this.options, salt: randomBytes(16) });
    const dummy = await this.dummy;
    const input = this.input(password, this.config.currentPepperVersion) ?? Buffer.from(password, "utf8");
    await this.slot(async () => {
      try {
        await argon2Verify(dummy, input);
      } catch {
        // The outcome is irrelevant; only the time spent matters.
      }
    });
  }
}
