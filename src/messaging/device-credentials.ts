import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { decryptSecret, encryptSecret } from "../crypto.js";
import type { SqlExecutor } from "../database.js";
import type { Principal } from "../store.js";
import { MessagingHttpError } from "./http.js";
import {
  client,
  isMember,
  personLockKey,
  recoverPersonIdentity,
  slug,
  withLock,
  type MessagingDeps,
  type PersonAccess,
  type PersonIdentity,
} from "./identity.js";
import { RelaycastCallError, type DeviceTokenDevice } from "./relaycast.js";

/** Lifetime asked for every device token; Relaycast accepts 60..2592000 seconds. */
export const DEVICE_TOKEN_TTL_SECONDS = 12 * 60 * 60;
/** A stored device token this close to its expiry is re-minted instead of served. */
export const DEVICE_TOKEN_RENEW_MARGIN_MS = 60 * 60 * 1000;
/** A client report of a refused token forces at most one mint per device in this window. */
export const FORCED_MINT_INTERVAL_SECONDS = 30;
/** Upstream device-token revocations attempted per sweep. */
const SWEEP_BATCH = 10;
const MAX_DEVICE_NAME_UNITS = 80;
const MAX_DEVICE_ID_SLUG = 32;
/** Relaycast's device id rule. */
const DEVICE_ID = /^[a-z0-9-]{1,64}$/;
/** Device ids Relaycast reserves for its own bookkeeping. */
const RESERVED_DEVICE_IDS = new Set(["unknown", "direct"]);

/** The browser session's device. It is bound to no sign-in session. */
export const WEB_DEVICE: DeviceTokenDevice = { id: "web", name: "web", kind: "web" };

export type DeviceCredential =
  | { kind: "device"; identity: PersonIdentity; device: DeviceTokenDevice; token: string; expiresAt: Date }
  /** Relaycast has no device-token route: the person's shared token, without a device. */
  | { kind: "shared"; identity: PersonIdentity };

type DeviceRow = {
  id: string;
  device_name: string;
  session_id: string | null;
  relaycast_workspace_id: string;
  agent_name: string;
  agent_remote_id: string;
  token_ciphertext: string;
  expires_at: Date | string;
  revoked_at: Date | string | null;
  /** Whole seconds until a forced mint is allowed again, by the database clock; 0 or less when it is allowed. */
  forced_mint_wait: number;
};

/** A device token with the device as Relaycast recorded it (its cleaned name). */
type StoredToken = { token: string; expiresAt: Date; device: DeviceTokenDevice };

/** Bound on the upstream device-token revokes a sign-out waits for. */
export const SIGN_OUT_REVOKE_TIMEOUT_MS = 5_000;

const REFUSED_TOKEN_SHA256 = /^[0-9a-f]{64}$/;

/** 429 for a forced mint inside FORCED_MINT_INTERVAL_SECONDS; the route sends Retry-After. */
export class DeviceMintRateLimited extends MessagingHttpError {
  constructor(readonly retryAfterSeconds: number) {
    super(429, "rate_limited", "A new credential was issued for this device moments ago. Try again shortly.");
    this.name = "DeviceMintRateLimited";
  }
}

function deviceRevoked(): MessagingHttpError {
  return new MessagingHttpError(403, "device_revoked", "This device's messaging credential was revoked. Sign in again.");
}

/**
 * The optional credential request body, read the same way as the hosted
 * route so one client works against both: no body, or a JSON object whose
 * optional `refusedTokenSha256` is the 64 lowercase hex SHA-256 of the token
 * the client saw refused (absent or null: no report). Other keys are ignored;
 * the device never comes from the body. Invalid JSON, a non-object body or a
 * malformed hash is 400 invalid_request.
 */
export function parseCredentialRequest(raw: string): { refusedTokenSha256: string | null } {
  if (!raw.trim()) return { refusedTokenSha256: null };
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new MessagingHttpError(400, "invalid_request", "Body must be valid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new MessagingHttpError(400, "invalid_request", "Body must be a JSON object");
  }
  const value = (parsed as Record<string, unknown>).refusedTokenSha256;
  if (value === undefined || value === null) return { refusedTokenSha256: null };
  if (typeof value !== "string" || !REFUSED_TOKEN_SHA256.test(value)) {
    throw new MessagingHttpError(
      400,
      "invalid_request",
      "refusedTokenSha256 must be the 64 lowercase hex SHA-256 of the refused token",
    );
  }
  return { refusedTokenSha256: value };
}

/** Constant-time comparison of sha256(token) with a reported hex digest. */
function tokenHashMatches(token: string, reportedSha256: string): boolean {
  const actual = Buffer.from(createHash("sha256").update(token).digest("hex"), "utf8");
  const reported = Buffer.from(reportedSha256, "utf8");
  return actual.length === reported.length && timingSafeEqual(actual, reported);
}

export function isValidDeviceId(id: string): boolean {
  return DEVICE_ID.test(id) && !RESERVED_DEVICE_IDS.has(id);
}

/**
 * The display name of a sign-in's device: the host name recorded on the
 * session row with control and bidirectional formatting characters removed,
 * cut to at most 80 UTF-16 units on a grapheme boundary. Empty falls back to
 * the kind.
 */
export function deviceName(hostName: string | null | undefined, kind: DeviceTokenDevice["kind"]): string {
  const cleaned = (hostName ?? "").replace(/[\p{Cc}\u202A-\u202E\u2066-\u2069]/gu, "").trim();
  let cut = "";
  for (const { segment } of new Intl.Segmenter(undefined, { granularity: "grapheme" }).segment(cleaned)) {
    if (cut.length + segment.length > MAX_DEVICE_NAME_UNITS) break;
    cut += segment;
  }
  return cut.trim() || kind;
}

/**
 * `<slug of the name, or the kind>-<first 8 hex of sha256(sign-in id)>`. The
 * hash suffix keeps two sign-ins on hosts with the same name apart and keeps
 * the id off Relaycast's reserved ids.
 */
export function deviceId(name: string, kind: DeviceTokenDevice["kind"], signInId: string): string {
  const base = slug(name).slice(0, MAX_DEVICE_ID_SLUG).replace(/-+$/, "") || kind;
  const id = `${base}-${createHash("sha256").update(signInId).digest("hex").slice(0, 8)}`;
  if (!isValidDeviceId(id)) throw new Error("derived device id is outside Relaycast's device id rule");
  return id;
}

/**
 * The device a messaging credential request speaks for, derived from the
 * server-side session only. A cookie request is the web device; a bearer is
 * its own sign-in's device, bound to that session row.
 */
export function personDevice(
  principal: Pick<Principal, "sessionId" | "desktopHostName">,
  viaCookie: boolean,
): { device: DeviceTokenDevice; signInId: string | null } {
  if (viaCookie) return { device: WEB_DEVICE, signInId: null };
  const kind = principal.desktopHostName ? "desktop" : "cli";
  const name = deviceName(principal.desktopHostName, kind);
  return { device: { id: deviceId(name, kind, principal.sessionId), name, kind }, signInId: principal.sessionId };
}

/** Stored expiry: the earlier of Relaycast's expiry and the TTL asked for. */
export function deviceTokenExpiry(upstream: string | null, now: Date, ttlSeconds = DEVICE_TOKEN_TTL_SECONDS): Date {
  const asked = new Date(now.getTime() + ttlSeconds * 1000);
  if (upstream === null) return asked;
  const reported = new Date(upstream);
  if (Number.isNaN(reported.getTime())) return asked;
  return reported.getTime() < asked.getTime() ? reported : asked;
}

function errorMessage(body: string): string | null {
  try {
    const parsed: unknown = body ? JSON.parse(body) : null;
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const outer = parsed as Record<string, unknown>;
    const nested = outer.error;
    if (nested && typeof nested === "object" && !Array.isArray(nested)) {
      const message = (nested as Record<string, unknown>).message;
      return typeof message === "string" ? message : null;
    }
    return typeof outer.message === "string" ? outer.message : null;
  } catch {
    return null;
  }
}

/**
 * True only when Relaycast plainly has no device-token route (a release
 * before device tokens): the mint answered 404 with code `not_found` and the
 * message `Route not found`, and a workspace-key lookup still finds the
 * person's agent under the expected id. Any other answer, a lookup failure, or
 * a missing or replaced agent is not a missing route.
 */
export async function isMissingDeviceTokenRoute(
  error: unknown,
  findAgent: () => Promise<{ id: string } | null>,
  expectedAgentId: string,
): Promise<boolean> {
  if (!(error instanceof RelaycastCallError)) return false;
  if (error.status !== 404 || error.code !== "not_found" || errorMessage(error.body) !== "Route not found") return false;
  try {
    const agent = await findAgent();
    return agent !== null && agent.id === expectedAgentId;
  } catch {
    return false;
  }
}

/** Mint refusals that mean the person agent itself is gone or was replaced. */
function isIdentityRefusal(error: unknown): boolean {
  return error instanceof RelaycastCallError
    && ((error.status === 404 && error.code === "agent_not_found")
      || (error.status === 409 && error.code === "agent_identity_conflict"));
}

function nowOf(deps: MessagingDeps): Date {
  return deps.now?.() ?? new Date();
}

async function readDeviceRow(executor: SqlExecutor, access: PersonAccess, deviceIdValue: string): Promise<DeviceRow | null> {
  const result = await executor.query<DeviceRow>(
    `SELECT id, device_name, session_id, relaycast_workspace_id, agent_name, agent_remote_id, token_ciphertext, expires_at, revoked_at,
            CEIL(EXTRACT(EPOCH FROM minted_at + interval '${FORCED_MINT_INTERVAL_SECONDS} seconds' - now()))::int
              AS forced_mint_wait
       FROM person_device_credentials
      WHERE workspace_id = $1 AND user_id = $2 AND device_id = $3`,
    [access.workspaceId, access.user.userId, deviceIdValue],
  );
  return result.rows[0] ?? null;
}

function usableRow(
  row: DeviceRow | null,
  identity: PersonIdentity,
  device: DeviceTokenDevice,
  signInId: string | null,
  now: Date,
  deps: MessagingDeps,
): StoredToken | null {
  if (!row || row.revoked_at !== null) return null;
  if (row.relaycast_workspace_id !== identity.relaycastWorkspaceId) return null;
  if (row.agent_remote_id !== identity.agentId || row.agent_name !== identity.name) return null;
  if (row.session_id !== signInId) return null;
  const expiresAt = new Date(row.expires_at);
  if (expiresAt.getTime() - now.getTime() <= DEVICE_TOKEN_RENEW_MARGIN_MS) return null;
  return {
    token: decryptSecret(row.token_ciphertext, deps.keyring),
    expiresAt,
    device: { ...device, name: row.device_name },
  };
}

/**
 * Whether a stored token may be served. A refusal (401/403) or a token that
 * now acts as another agent is dropped. An unreachable or failing Relaycast
 * did not refuse it, so it is served: callers only probe rows outside the
 * renew margin, which are unexpired. Nothing is cached between requests.
 * `device_token_forbidden` says the route does not take device tokens at
 * all, not that this token was refused, so it is an error and never a reason
 * to mint again.
 */
async function probeServes(deps: MessagingDeps, token: string, identity: PersonIdentity): Promise<boolean> {
  try {
    const agent = await client(deps).authenticatedAgent(token);
    return agent.id === identity.agentId;
  } catch (error) {
    if (error instanceof RelaycastCallError && error.status === 403 && error.code === "device_token_forbidden") {
      throw new MessagingHttpError(502, "upstream_unavailable", "The relay is not reachable right now. Try again shortly.");
    }
    return !(error instanceof RelaycastCallError && (error.status === 401 || error.status === 403));
  }
}

/**
 * Locks the sign-in's session row FOR SHARE before the device row is written,
 * the order a sign-out takes them in (session row, then its device rows). A
 * concurrent sign-out then waits for this transaction and its device-row
 * revoke sees the row stored here. False when the session row is gone:
 * removing a membership deletes the person's session rows, and that can
 * commit while the Relaycast mint is in flight.
 */
async function lockSession(tx: SqlExecutor, signInId: string): Promise<boolean> {
  const result = await tx.query("SELECT 1 FROM token_sessions WHERE id = $1 FOR SHARE", [signInId]);
  return result.rows.length === 1;
}

async function sessionLive(tx: SqlExecutor, signInId: string): Promise<boolean> {
  const result = await tx.query(
    `SELECT 1 FROM token_sessions
      WHERE id = $1 AND revoked_at IS NULL AND refresh_token_expires_at > now()
      FOR SHARE`,
    [signInId],
  );
  return result.rows.length === 1;
}

async function storeRow(
  tx: SqlExecutor,
  deps: MessagingDeps,
  input: {
    access: PersonAccess;
    identity: PersonIdentity;
    device: DeviceTokenDevice;
    signInId: string | null;
    token: string;
    expiresAt: Date;
    /** Saves the row already revoked, pending the upstream revoke. */
    revoked: boolean;
  },
): Promise<string> {
  const stored = await tx.query<{ id: string }>(
    `INSERT INTO person_device_credentials
       (id, workspace_id, user_id, device_id, device_name, device_kind, session_id, relaycast_workspace_id,
        agent_name, agent_remote_id, token_ciphertext, expires_at, minted_at, revoked_at, upstream_revoked_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now(), CASE WHEN $13::boolean THEN now() END, NULL)
     ON CONFLICT (workspace_id, user_id, device_id) DO UPDATE
       SET device_name = EXCLUDED.device_name,
           device_kind = EXCLUDED.device_kind,
           session_id = EXCLUDED.session_id,
           relaycast_workspace_id = EXCLUDED.relaycast_workspace_id,
           agent_name = EXCLUDED.agent_name,
           agent_remote_id = EXCLUDED.agent_remote_id,
           token_ciphertext = EXCLUDED.token_ciphertext,
           expires_at = EXCLUDED.expires_at,
           minted_at = now(),
           revoked_at = EXCLUDED.revoked_at,
           upstream_revoked_at = NULL,
           updated_at = now()
     RETURNING id`,
    [
      randomUUID(),
      input.access.workspaceId,
      input.access.user.userId,
      input.device.id,
      input.device.name,
      input.device.kind,
      input.signInId,
      input.identity.relaycastWorkspaceId,
      input.identity.name,
      input.identity.agentId,
      encryptSecret(input.token, deps.keyring.active),
      input.expiresAt,
      input.revoked,
    ],
  );
  return stored.rows[0]!.id;
}

type MintOutcome =
  | { kind: "served"; stored: StoredToken }
  | { kind: "rate_limited"; retryAfterSeconds: number }
  | { kind: "device_revoked" }
  | { kind: "refused"; status: 401 | 403; rowId: string };

/** A row revoked while its own sign-in still authenticates: the device was revoked, not the sign-in. */
function revokedForSignIn(row: DeviceRow | null, signInId: string | null): boolean {
  return row !== null && row.revoked_at !== null && signInId !== null && row.session_id === signInId;
}

/**
 * Mints under the person lock (personLockKey), the lock the person identity's
 * registration, takeover, recovery and member revocation take, so a mint
 * never interleaves with a recovery that expires or a removal that revokes
 * device rows. Like the identity code, the Relaycast call runs inside it.
 * Locks are taken in the order person lock, session row, device row; a
 * sign-out takes session row, then device rows.
 *
 * `forced` is a client report of the refused stored token `droppedToken`:
 * it re-mints at most once per FORCED_MINT_INTERVAL_SECONDS per device, by
 * the row's minted_at against the database clock.
 */
async function mintUnderLock(
  deps: MessagingDeps,
  access: PersonAccess,
  identity: PersonIdentity,
  device: DeviceTokenDevice,
  signInId: string | null,
  droppedToken: string | null,
  forced: boolean,
): Promise<StoredToken> {
  const relaycast = client(deps);
  const outcome = await withLock<MintOutcome>(
    deps.database,
    personLockKey(access.workspaceId, access.user.userId),
    async (tx) => {
      const row = await readDeviceRow(tx, access, device.id);
      if (revokedForSignIn(row, signInId)) return { kind: "device_revoked" };
      // Another request may have minted while this one waited for the lock.
      const again = usableRow(row, identity, device, signInId, nowOf(deps), deps);
      if (again && again.token !== droppedToken) return { kind: "served", stored: again };
      if (forced && again && row && row.forced_mint_wait > 0) {
        return { kind: "rate_limited", retryAfterSeconds: row.forced_mint_wait };
      }
      const issued = await relaycast.issueDeviceToken(access.relaycastApiKey, identity.name, {
        expectedAgentId: identity.agentId,
        device,
        ttlSeconds: DEVICE_TOKEN_TTL_SECONDS,
      });
      const stored: StoredToken = {
        token: issued.token,
        expiresAt: deviceTokenExpiry(issued.expiresAt, nowOf(deps)),
        device: issued.device,
      };
      if (deps.beforeDeviceSave) await deps.beforeDeviceSave(tx);
      // A refused token stays recorded, revoked and with no session, so the
      // sweep retries the upstream revoke if the immediate one fails.
      const recordRevoked = () => storeRow(tx, deps, { access, identity, signInId: null, revoked: true, ...stored });
      if (signInId && !(await lockSession(tx, signInId))) {
        return { kind: "refused", status: 401, rowId: await recordRevoked() };
      }
      const rowId = await storeRow(tx, deps, { access, identity, signInId, revoked: false, ...stored });
      if (deps.afterDeviceMint) await deps.afterDeviceMint(tx);
      // Checked after the save: a sign-out or member removal that commits
      // before this point is seen here, one that comes later waits for this
      // transaction and revokes or deletes the saved row.
      const refusal = signInId && !(await sessionLive(tx, signInId))
        ? 401 as const
        : !(await isMember(tx, access.organizationId, access.user.userId)) ? 403 as const : null;
      if (refusal === null) return { kind: "served", stored };
      const revoked = await tx.query<{ id: string }>(
        "UPDATE person_device_credentials SET revoked_at = now(), updated_at = now() WHERE id = $1 RETURNING id",
        [rowId],
      );
      // A deleted session row takes its device rows with it.
      return { kind: "refused", status: refusal, rowId: revoked.rows[0]?.id ?? await recordRevoked() };
    },
  );
  if (outcome.kind === "served") return outcome.stored;
  if (outcome.kind === "rate_limited") throw new DeviceMintRateLimited(outcome.retryAfterSeconds);
  if (outcome.kind === "device_revoked") throw deviceRevoked();
  try {
    await relaycast.revokeDeviceToken(access.relaycastApiKey, identity.name, device.id);
    await deps.database.query(
      `UPDATE person_device_credentials SET upstream_revoked_at = now(), updated_at = now()
        WHERE id = $1 AND revoked_at IS NOT NULL AND upstream_revoked_at IS NULL`,
      [outcome.rowId],
    );
  } catch {
    // The revoked row stays pending for sweepDeviceRevocations.
  }
  if (outcome.status === 401) {
    throw new MessagingHttpError(401, "unauthorized", "The sign-in ended before the credential was issued");
  }
  throw new MessagingHttpError(403, "forbidden", "Organization membership ended before the credential was issued");
}

/**
 * This device's own Relaycast token for the person agent `identity`: the
 * stored one while it is usable and not refused upstream, otherwise a fresh
 * mint bound to the sign-in session. The shared person token comes back only
 * when Relaycast has no device-token route (isMissingDeviceTokenRoute).
 *
 * `options.refusedTokenSha256` is the client's report of a refused token. When
 * it matches the stored token (constant-time) that token is dropped without a
 * probe and re-minted, at most once per FORCED_MINT_INTERVAL_SECONDS per
 * device (DeviceMintRateLimited inside it). A hash that does not match takes
 * the normal path. A device row revoked while its sign-in still authenticates
 * answers 403 device_revoked.
 */
export async function ensureDeviceCredential(
  deps: MessagingDeps,
  access: PersonAccess,
  identity: PersonIdentity,
  device: DeviceTokenDevice,
  signInId: string | null,
  options: { refusedTokenSha256?: string | null } = {},
): Promise<DeviceCredential> {
  if (!isValidDeviceId(device.id)) throw new Error("device id is outside Relaycast's device id rule");
  let current = identity;
  let droppedToken: string | null = null;
  let forced = false;
  const row = await readDeviceRow(deps.database, access, device.id);
  if (revokedForSignIn(row, signInId)) throw deviceRevoked();
  const stored = usableRow(row, current, device, signInId, nowOf(deps), deps);
  if (stored) {
    forced = options.refusedTokenSha256 ? tokenHashMatches(stored.token, options.refusedTokenSha256) : false;
    if (!forced && await probeServes(deps, stored.token, current)) {
      return { kind: "device", identity: current, ...stored };
    }
    droppedToken = stored.token;
  }
  let recovered = false;
  for (;;) {
    try {
      const minted = await mintUnderLock(deps, access, current, device, signInId, droppedToken, forced);
      return { kind: "device", identity: current, ...minted };
    } catch (error) {
      if (!(error instanceof RelaycastCallError)) throw error;
      if (!recovered && isIdentityRefusal(error)) {
        recovered = true;
        try {
          current = await recoverPersonIdentity(deps, access, current);
        } catch (recoveryError) {
          if (recoveryError instanceof RelaycastCallError) {
            throw new MessagingHttpError(502, "upstream_unavailable", "The relay is not reachable right now. Try again shortly.");
          }
          throw recoveryError;
        }
        continue;
      }
      const agentName = current.name;
      const missingRoute = await isMissingDeviceTokenRoute(
        error,
        () => client(deps).getAgent(access.relaycastApiKey, agentName),
        current.agentId,
      );
      if (missingRoute) {
        (deps.warn ?? defaultWarn)("messaging device credential fallback: Relaycast has no device-token route", {
          workspaceId: access.workspaceId,
          deviceKind: device.kind,
        });
        return { kind: "shared", identity: current };
      }
      throw new MessagingHttpError(502, "upstream_unavailable", "The relay is not reachable right now. Try again shortly.");
    }
  }
}

function defaultWarn(message: string, fields: Record<string, string>): void {
  console.warn(`[selfhost-api] ${message}`, fields);
}

/**
 * Sends the upstream revoke for device rows revoked locally (ended sign-ins,
 * refused mints) that Relaycast has not confirmed yet. Bounded per call; a
 * failed row is retried on a later call after the others. `options.signal`
 * bounds the upstream calls; an aborted call leaves its row pending like any
 * other failure.
 */
export async function sweepDeviceRevocations(
  deps: MessagingDeps,
  organizationId?: string,
  options: { signal?: AbortSignal } = {},
): Promise<void> {
  const rows = await deps.database.query<{
    id: string;
    workspace_id: string;
    user_id: string;
    device_id: string;
    agent_name: string;
    row_relaycast_workspace_id: string;
    relaycast_workspace_id: string;
    relaycast_api_key_ciphertext: string;
  }>(
    `SELECT device.id, device.workspace_id, device.user_id, device.device_id, device.agent_name,
            device.relaycast_workspace_id AS row_relaycast_workspace_id,
            workspace.relaycast_workspace_id, workspace.relaycast_api_key_ciphertext
       FROM person_device_credentials device
       JOIN workspaces workspace ON workspace.id = device.workspace_id
      WHERE device.revoked_at IS NOT NULL AND device.upstream_revoked_at IS NULL
        AND workspace.relaycast_api_key_ciphertext IS NOT NULL
        AND ($1::uuid IS NULL OR workspace.organization_id = $1)
      ORDER BY device.updated_at
      LIMIT ${SWEEP_BATCH}`,
    [organizationId ?? null],
  );
  if (rows.rows.length === 0) return;
  const relaycast = client(deps);
  for (const row of rows.rows) {
    if (options.signal?.aborted) return;
    try {
      await withLock(deps.database, personLockKey(row.workspace_id, row.user_id), async (tx) => {
        // A mint may have replaced the row with a live token since it was read.
        const pending = await tx.query(
          `SELECT 1 FROM person_device_credentials
            WHERE id = $1 AND revoked_at IS NOT NULL AND upstream_revoked_at IS NULL`,
          [row.id],
        );
        if (pending.rows.length === 0) return;
        // The workspace key only reaches the workspace's current Relaycast
        // workspace; a token minted on an earlier one runs out at its expiry.
        if (row.row_relaycast_workspace_id === row.relaycast_workspace_id) {
          await relaycast.revokeDeviceToken(
            decryptSecret(row.relaycast_api_key_ciphertext, deps.keyring),
            row.agent_name,
            row.device_id,
            options.signal,
          );
        }
        await tx.query(
          "UPDATE person_device_credentials SET upstream_revoked_at = now(), updated_at = now() WHERE id = $1",
          [row.id],
        );
      });
    } catch {
      // Moves the row behind the others; it stays pending for a later sweep.
      await deps.database.query(
        "UPDATE person_device_credentials SET updated_at = now() WHERE id = $1 AND upstream_revoked_at IS NULL",
        [row.id],
      ).catch(() => undefined);
    }
  }
}
