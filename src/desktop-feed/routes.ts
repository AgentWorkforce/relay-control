// Desktop feed routes (docs/desktop-feed.md, openapi /api/v1/desktop/feed/*)
// plus the organization-admin endpoints that register profiles, bind
// workspaces and mint publisher tokens.
import type { IncomingMessage, ServerResponse } from "node:http";
import { createHash, randomInt } from "node:crypto";
import { Readable, Transform } from "node:stream";
import { Ajv2020 } from "ajv/dist/2020.js";
import addFormatsModule from "ajv-formats";
import type { SelfhostConfig } from "../config.js";
import { hashSecret, opaqueToken, secureEqual } from "../crypto.js";
import type { SqlExecutor } from "../database.js";
import type { ControlPlaneStore, Principal } from "../store.js";
import { ApiTokenStore } from "../admin/api-tokens.js";
import { recordAudit, type AuditActor } from "../admin/audit.js";
import { clientIp, cookieRequestAllowed, limiterKey, RateLimiter } from "../auth/device-approval.js";
import { canonicalBytes, canonicalize } from "./canonical.js";
import { strictParse } from "./strict-json.js";
import { DRAFT_CREATE_SCHEMA, ENVELOPE_SCHEMA } from "./schemas.js";
import { verifyEd25519, type DesktopFeedSigner } from "./signer.js";
import type { ByteRange, DesktopFeedStorage } from "./storage.js";
import type {
  AssetRow,
  Channel,
  DeclaredAsset,
  DesktopFeedStore,
  InstallTokenRow,
  ProfileRow,
  PublisherTokenRow,
  ReleaseRow,
} from "./store.js";

const addFormats = addFormatsModule as unknown as typeof addFormatsModule.default;

export const FEED_PREFIX = "/api/v1/desktop/feed";
export const FEED_PROFILES_PATH = "/api/v1/desktop/profiles";
export const SESSION_COOKIE = "agent_relay_session";
const PROFILE_HEADER = "x-agent-relay-profile";
const PROFILE_PATTERN = /^[a-z0-9]{1,32}$/;
const VERSION_PATTERN = /^[0-9]{4}\.(?:[1-9]|1[0-2])\.(?:0|[1-9][0-9]*)(?:-beta\.(?:0|[1-9][0-9]*))?$/;
const NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_+-]*(?:\.[A-Za-z0-9_+-]+)*$/;
const ASSET_ID_PATTERN = /^a_[0-9A-Za-z]{1,64}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const ASSET_PREFIX_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_+-]{0,63}$/;
const INSTALL_TOKEN_PREFIX = "sh_dfi_";
const PUBLISHER_TOKEN_PREFIX = "sh_dfp_";
const JSON_LIMIT = 1024 * 1024;
const READ_PAGE = 20;
const PUBLISHER_PAGE = 50;
const DOWNLOAD_URL_SECONDS = 300;
const INSTALL_TOKEN_SECONDS = 3600;
const ACTIVE_PUBLISHER_TOKENS = 2;
const DEFAULT_QUOTA_BYTES = 20_000_000_000;
const DEFAULT_BETA_KEEP = 10;
const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const ASSET_ID_CHARS = 8;
// Same length as a real timestamp, for sizing the manifest before publish.
const PLACEHOLDER_PUBLISHED_AT = "2000-01-01T00:00:00Z";

/**
 * Short on purpose: ids are signed into the manifest under the KMS 4096-byte
 * cap, and are not secrets (every lookup is scoped to an entitled profile).
 */
function newAssetId(): string {
  return `a_${Array.from({ length: ASSET_ID_CHARS }, () => BASE62[randomInt(BASE62.length)]).join("")}`;
}

export type RateRule = { limit: number; windowMs: number };
export type DesktopFeedLimits = {
  reads: RateRule;
  downloadUrl: RateRule;
  streamStarts: RateRule;
  streamConcurrent: number;
  publisher: RateRule;
  installTokenMint: RateRule;
  unauthenticated: RateRule;
};

/** docs/desktop-feed.md, Rate limits. */
export const DESKTOP_FEED_LIMITS: DesktopFeedLimits = {
  reads: { limit: 60, windowMs: 60_000 },
  downloadUrl: { limit: 30, windowMs: 60_000 },
  streamStarts: { limit: 30, windowMs: 60_000 },
  streamConcurrent: 4,
  publisher: { limit: 600, windowMs: 60_000 },
  installTokenMint: { limit: 10, windowMs: 3_600_000 },
  unauthenticated: { limit: 60, windowMs: 60_000 },
};

type Kind = "workspaceBearer" | "installToken" | "browserSession" | "publisherToken";
type Op =
  | "manifest" | "releases" | "create" | "import" | "upload" | "publish"
  | "download_url" | "stream" | "install_tokens_list" | "install_tokens_create" | "install_tokens_revoke";

const ACCEPTS: Record<Op, readonly Kind[]> = {
  manifest: ["workspaceBearer", "installToken", "browserSession"],
  releases: ["workspaceBearer", "installToken", "browserSession", "publisherToken"],
  create: ["publisherToken"],
  import: ["publisherToken"],
  upload: ["publisherToken"],
  publish: ["publisherToken"],
  download_url: ["workspaceBearer", "installToken", "browserSession"],
  stream: ["workspaceBearer", "installToken", "browserSession"],
  install_tokens_list: ["browserSession"],
  install_tokens_create: ["browserSession"],
  install_tokens_revoke: ["browserSession"],
};

const ACTIONS: Record<Op, string> = {
  manifest: "desktop_feed.manifest_read",
  releases: "desktop_feed.releases_read",
  create: "desktop_feed.draft_create",
  import: "desktop_feed.import",
  upload: "desktop_feed.asset_upload",
  publish: "desktop_feed.publish",
  download_url: "desktop_feed.download_url_issue",
  stream: "desktop_feed.stream",
  install_tokens_list: "desktop_feed.install_token_list",
  install_tokens_create: "desktop_feed.install_token_create",
  install_tokens_revoke: "desktop_feed.install_token_revoke",
};

const READ_OPS = new Set<Op>(["manifest", "releases", "download_url", "stream"]);

type Credential =
  | { kind: "workspaceBearer" | "browserSession"; principal: Principal; rateKey: string }
  | { kind: "installToken"; token: InstallTokenRow; rateKey: string }
  | { kind: "publisherToken"; token: PublisherTokenRow; rateKey: string }
  /** A valid credential no feed operation accepts (sh_wk_, bootstrap, service, no cli:auth). */
  | { kind: "other"; rateKey: string };

type ErrorExtra = Record<string, unknown>;

export class FeedError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly extra: ErrorExtra = {},
    readonly headers: Record<string, string> = {},
  ) {
    super(message);
  }
}

type Reply =
  | { status: number; json: unknown; headers?: Record<string, string> }
  | { status: number; text: string; headers?: Record<string, string> }
  | { status: number; stream: Readable; headers: Record<string, string>; release: () => void };

type HttpErrorFactory = (status: number, code: string, message: string) => Error;
type OrganizationAuth = { kind: "bootstrap" } | { kind: "user"; principal: Principal };

export type DesktopFeedHandlerInput = {
  config: SelfhostConfig;
  controlStore: ControlPlaneStore;
  store: DesktopFeedStore;
  signer: DesktopFeedSigner;
  storage: DesktopFeedStorage;
  browserOrigins: readonly string[];
  /** Publisher tokens configured in env: sha256 of the token, by profile. */
  publisherTokenHashes?: Record<string, readonly string[]>;
  now?: () => Date;
  limits?: Partial<DesktopFeedLimits>;
  organizationAccess: (request: IncomingMessage, organizationId: string, admin?: boolean) => Promise<OrganizationAuth>;
  requestObject: (request: IncomingMessage) => Promise<Record<string, unknown>>;
  json: (response: ServerResponse, status: number, body: unknown, noStore?: boolean) => void;
  httpError: HttpErrorFactory;
  /** Server-side warnings (signer and storage failures). Defaults to console.warn. */
  log?: (message: string, fields: Record<string, unknown>) => void;
};

/** The error's name and message only; never a payload. */
function errorFields(error: unknown): Record<string, unknown> {
  return error instanceof Error
    ? { error: error.name, message: error.message }
    : { error: typeof error, message: String(error) };
}

function bearerToken(request: IncomingMessage): string | null {
  const header = request.headers.authorization;
  if (!header) return null;
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match?.[1]?.trim() || null;
}

function cookieValue(request: IncomingMessage, name: string): string | null {
  for (const part of (request.headers.cookie ?? "").split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0 || part.slice(0, separator).trim() !== name) continue;
    try {
      return decodeURIComponent(part.slice(separator + 1).trim()) || null;
    } catch {
      return null;
    }
  }
  return null;
}

function decodeSegment(value: string): string | null {
  try {
    return decodeURIComponent(value);
  } catch {
    return null;
  }
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

/** Whole-second RFC 3339 UTC, as the manifest schema requires. */
export function wholeSecondIso(date: Date): string {
  return `${date.toISOString().slice(0, 19)}Z`;
}

/** docs/desktop-feed.md, Range rules. */
export function rangeDecision(
  range: string | undefined,
  size: number,
  ifRange: string | undefined,
  etag: string,
): { status: 200 } | { status: 206; range: ByteRange } | { status: 416 } {
  if (!range || (ifRange !== undefined && ifRange !== etag)) return { status: 200 };
  const match = /^bytes=([0-9]*)-([0-9]*)$/.exec(range.trim());
  if (!match) return { status: 416 };
  const [, first = "", last = ""] = match;
  if (first === "") {
    if (last === "") return { status: 416 };
    const suffix = Number(last);
    if (!Number.isSafeInteger(suffix) || suffix === 0) return { status: 416 };
    return { status: 206, range: { start: Math.max(0, size - suffix), end: size - 1 } };
  }
  const start = Number(first);
  const end = last === "" ? size - 1 : Math.min(Number(last), size - 1);
  if (!Number.isSafeInteger(start) || start >= size || (last !== "" && Number(last) < start)) return { status: 416 };
  return { status: 206, range: { start, end } };
}

/** The `envelope` member's exact text from a body already strict-parsed to `{"envelope": {...}}`. */
export function envelopeText(rawBody: string): string | null {
  const match = /^[ \t\n\r]*\{[ \t\n\r]*"(?:[^"\\]|\\.)*"[ \t\n\r]*:[ \t\n\r]*([\s\S]*?)[ \t\n\r]*\}[ \t\n\r]*$/.exec(rawBody);
  return match?.[1] ?? null;
}

type FeedOperation = { op: Op; params: string[] };

function matchOperation(path: string, method: string): FeedOperation | null {
  if (!path.startsWith(`${FEED_PREFIX}/`)) return null;
  const rest = path.slice(FEED_PREFIX.length);
  if (rest === "/manifest") return method === "GET" ? { op: "manifest", params: [] } : null;
  if (rest === "/releases") {
    if (method === "GET") return { op: "releases", params: [] };
    if (method === "POST") return { op: "create", params: [] };
    return null;
  }
  if (rest === "/releases/import") return method === "POST" ? { op: "import", params: [] } : null;
  if (rest === "/install-tokens") {
    if (method === "GET") return { op: "install_tokens_list", params: [] };
    if (method === "POST") return { op: "install_tokens_create", params: [] };
    return null;
  }
  let match = /^\/releases\/([^/]+)\/assets\/([^/]+)$/.exec(rest);
  if (match) return method === "PUT" ? { op: "upload", params: [match[1]!, match[2]!] } : null;
  match = /^\/releases\/([^/]+)\/publish$/.exec(rest);
  if (match) return method === "POST" ? { op: "publish", params: [match[1]!] } : null;
  match = /^\/assets\/([^/]+)\/download-url$/.exec(rest);
  if (match) return method === "POST" ? { op: "download_url", params: [match[1]!] } : null;
  match = /^\/assets\/([^/]+)$/.exec(rest);
  if (match) return method === "GET" ? { op: "stream", params: [match[1]!] } : null;
  match = /^\/install-tokens\/([^/]+)$/.exec(rest);
  if (match) return method === "DELETE" ? { op: "install_tokens_revoke", params: [match[1]!] } : null;
  return null;
}

function installTokenSummary(row: InstallTokenRow, now: Date) {
  return {
    id: row.id,
    label: row.label,
    token_prefix: row.tokenPrefix,
    profile: row.profileId,
    workspace_id: row.workspaceId,
    created_at: row.createdAt,
    expires_at: row.expiresAt,
    revoked_at: row.revokedAt,
    last_used_at: row.lastUsedAt,
    status: row.revokedAt ? "revoked" : new Date(row.expiresAt).getTime() <= now.getTime() ? "expired" : "active",
  };
}

function publisherTokenSummary(row: PublisherTokenRow) {
  return {
    id: row.id,
    label: row.label,
    token_prefix: row.tokenPrefix,
    created_at: row.createdAt,
    revoked_at: row.revokedAt,
    last_used_at: row.lastUsedAt,
    status: row.revokedAt ? "revoked" : "active",
  };
}

function draftBody(release: ReleaseRow, assets: AssetRow[]) {
  return {
    version: release.version,
    channel: release.channel,
    state: "draft" as const,
    origin: release.origin,
    notes: release.notes,
    created_at: release.createdAt,
    expected_assets: assets.map((entry) => ({
      name: entry.name,
      platform: entry.platform,
      arch: entry.arch,
      ...(entry.osFloor !== null ? { os_floor: entry.osFloor } : {}),
      kind: entry.kind,
      size: entry.size,
      sha256: entry.sha256,
      uploaded: entry.uploadedAt !== null,
      id: entry.assetId,
    })),
  };
}

export function createDesktopFeedHandler(input: DesktopFeedHandlerInput) {
  const { config, controlStore, store, signer, storage } = input;
  const now = input.now ?? (() => new Date());
  const log = input.log ?? ((message, fields) => console.warn(`[selfhost-api] desktop feed: ${message}`, fields));
  const signerFailed = (operation: string, profile: string, error: unknown) =>
    log("signer unavailable", { operation, profile, signer: signer.kind, ...errorFields(error) });
  const storageFailed = (operation: string, key: string, error: unknown) =>
    log("storage failed", { operation, key, storage: storage.kind, ...errorFields(error) });
  const limits: DesktopFeedLimits = { ...DESKTOP_FEED_LIMITS, ...input.limits };
  const limiter = new RateLimiter(() => now().getTime());
  const streams = new Map<string, number>();
  const apiTokens = new ApiTokenStore(controlStore.database);
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(ajv);
  const validateDraft = ajv.compile(DRAFT_CREATE_SCHEMA as unknown as Record<string, unknown>);
  const validateEnvelope = ajv.compile(ENVELOPE_SCHEMA as unknown as Record<string, unknown>);
  const envPublisherTokens = new Map(Object.entries(input.publisherTokenHashes ?? {})
    .flatMap(([profileId, hashes]) => hashes.map((hash) => [hash, profileId] as const)));

  /* ------------------------------------------------------------ helpers */

  function rate(key: string, rule: RateRule): void {
    const result = limiter.consume(key, rule.limit, rule.windowMs);
    if (!result.allowed) throw rateLimited(result.retryAfterSeconds);
  }

  function rateLimited(seconds: number): FeedError {
    const retry = Math.max(1, Math.ceil(seconds));
    return new FeedError(429, "rate_limited", "Too many requests", { retry_after_seconds: retry }, { "retry-after": String(retry) });
  }

  async function readText(request: IncomingMessage): Promise<string> {
    const declared = Number(request.headers["content-length"] ?? 0);
    if (Number.isFinite(declared) && declared > JSON_LIMIT) {
      throw new FeedError(413, "payload_too_large", "Body exceeds 1 MiB");
    }
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of request) {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buffer.length;
      if (size > JSON_LIMIT) throw new FeedError(413, "payload_too_large", "Body exceeds 1 MiB");
      chunks.push(buffer);
    }
    return Buffer.concat(chunks).toString("utf8");
  }

  /** Steps 1 and 2 of the check precedence; 401s also spend the per-IP budget. */
  async function resolveCredential(request: IncomingMessage, rawPath: string, ip: string): Promise<Credential> {
    const headerToken = bearerToken(request);
    const cookieToken = rawPath.startsWith("/cloud/") ? cookieValue(request, SESSION_COOKIE) : null;
    if (headerToken && cookieToken) {
      throw new FeedError(400, "mixed_credentials", "Send exactly one credential");
    }
    const unauthorized = (code: string, message: string): FeedError => {
      const result = limiter.consume(`df:unauth:${limiterKey(ip)}`, limits.unauthenticated.limit, limits.unauthenticated.windowMs);
      if (!result.allowed) return rateLimited(result.retryAfterSeconds);
      return new FeedError(401, code, message, {}, { "www-authenticate": "Bearer" });
    };
    const token = headerToken ?? cookieToken;
    if (!token) throw unauthorized("unauthenticated", "Authentication required");
    const at = now();
    if (headerToken?.startsWith(INSTALL_TOKEN_PREFIX)) {
      const row = await store.installTokenByHash(hashSecret(headerToken));
      if (!row) throw unauthorized("unauthenticated", "Unknown token");
      if (row.revokedAt) throw unauthorized("token_revoked", "Token revoked");
      if (new Date(row.expiresAt).getTime() <= at.getTime()) throw unauthorized("token_expired", "Token expired");
      // The token dies with the user's membership.
      if (!await store.isMember(row.workspaceId, row.userId)) throw unauthorized("token_revoked", "Token revoked");
      await store.touchInstallToken(row.id, at);
      return { kind: "installToken", token: row, rateKey: `it:${row.id}` };
    }
    if (headerToken?.startsWith(PUBLISHER_TOKEN_PREFIX)) {
      const tokenHash = hashSecret(headerToken);
      const envProfile = envPublisherTokens.get(tokenHash);
      if (envProfile) {
        const id = `env-${tokenHash.slice(0, 12)}`;
        return {
          kind: "publisherToken",
          token: {
            id, profileId: envProfile, label: "env", tokenPrefix: headerToken.slice(0, 11),
            createdAt: new Date(0).toISOString(), revokedAt: null, lastUsedAt: null,
          },
          rateKey: `pt:${id}`,
        };
      }
      const row = await store.publisherTokenByHash(tokenHash);
      if (!row) throw unauthorized("unauthenticated", "Unknown token");
      if (row.revokedAt) throw unauthorized("token_revoked", "Token revoked");
      await store.touchPublisherToken(row.id, at);
      return { kind: "publisherToken", token: row, rateKey: `pt:${row.id}` };
    }
    if (headerToken) {
      const other = { kind: "other" as const, rateKey: `o:${hashSecret(headerToken).slice(0, 24)}` };
      if (config.internalServiceToken && secureEqual(headerToken, config.internalServiceToken)) return other;
      if (secureEqual(headerToken, config.bootstrapToken)) return other;
      if (headerToken.startsWith("sh_wk_")) {
        if (await apiTokens.authenticate(headerToken)) return other;
        throw unauthorized("unauthenticated", "Unknown token");
      }
    }
    const principal = await controlStore.authenticateAccessToken(token);
    if (!principal) throw unauthorized("unauthenticated", "Unknown or expired session");
    if (!principal.scopes.includes("cli:auth") || principal.pendingHandoff) {
      return { kind: "other", rateKey: `s:${principal.sessionId}` };
    }
    return { kind: headerToken ? "workspaceBearer" : "browserSession", principal, rateKey: `s:${principal.sessionId}` };
  }

  function rateRule(op: Op, credential: Credential): { bucket: string; rule: RateRule } {
    if (credential.kind === "publisherToken") return { bucket: "publisher", rule: limits.publisher };
    if (op === "download_url") return { bucket: "download_url", rule: limits.downloadUrl };
    if (op === "stream") return { bucket: "stream", rule: limits.streamStarts };
    if (op === "create" || op === "import" || op === "upload" || op === "publish") {
      return { bucket: "publisher", rule: limits.publisher };
    }
    return { bucket: "reads", rule: limits.reads };
  }

  async function entitled(credential: Credential, profileId: string): Promise<ProfileRow | null> {
    if (!PROFILE_PATTERN.test(profileId)) return null;
    const profile = await store.profile(profileId);
    if (!profile) return null;
    switch (credential.kind) {
      case "publisherToken":
        return credential.token.profileId === profileId ? profile : null;
      case "installToken":
        return credential.token.profileId === profileId && await store.isBound(profileId, credential.token.workspaceId)
          ? profile
          : null;
      case "workspaceBearer":
      case "browserSession":
        return await store.isBound(profileId, credential.principal.workspaceId) ? profile : null;
      default:
        return null;
    }
  }

  /** Keys an import or import draft may verify against: registered keys plus the signer's own. */
  async function verificationKey(profileId: string, keyId: string): Promise<string | null> {
    const registered = await store.publicKeys(profileId);
    const key = registered.get(keyId);
    if (key) return key;
    if (keyId === signer.keyId(profileId)) {
      try {
        return await signer.publicKey(profileId);
      } catch (error) {
        signerFailed("publicKey", profileId, error);
        return null;
      }
    }
    return null;
  }

  async function quotaCheck(
    profile: ProfileRow,
    channel: Channel,
    required: number,
    excludeReleaseId: string | null,
    executor: SqlExecutor = store.database,
  ): Promise<void> {
    const usage = await store.usage(profile.id, executor);
    const keptBetas = channel === "beta"
      ? usage.betas.slice(Math.max(0, usage.betas.length - (profile.betaKeep - 1)))
      : usage.betas;
    const betaBytes = channel === "beta" && profile.betaKeep - 1 <= 0
      ? 0
      : keptBetas.reduce((total, entry) => total + entry.bytes, 0);
    const draftBytes = usage.drafts
      .filter((entry) => entry.id !== excludeReleaseId)
      .reduce((total, entry) => total + entry.bytes, 0);
    const used = usage.stableBytes + betaBytes + draftBytes;
    if (used + required > profile.quotaBytes) {
      throw new FeedError(422, "quota_exceeded", "The profile's storage quota would be exceeded", {
        quota_bytes: profile.quotaBytes,
        used_bytes: used,
        required_bytes: required,
      });
    }
  }

  async function currentUsage(profile: ProfileRow): Promise<number> {
    const usage = await store.usage(profile.id);
    return usage.stableBytes
      + usage.betas.reduce((total, entry) => total + entry.bytes, 0)
      + usage.drafts.reduce((total, entry) => total + entry.bytes, 0);
  }

  function serviceActor(credential: Credential): AuditActor {
    if (credential.kind === "publisherToken") return { kind: "service", subject: `desktop-feed:publisher:${credential.token.id}` };
    if (credential.kind === "installToken") return { kind: "service", subject: `desktop-feed:user:${credential.token.userId}` };
    if (credential.kind === "workspaceBearer" || credential.kind === "browserSession") {
      return { kind: "service", subject: `desktop-feed:user:${credential.principal.userId}` };
    }
    return { kind: "service", subject: "desktop-feed:unknown" };
  }

  /** The write already committed: a failed audit is logged, not reported as a failed write. */
  async function auditCommitted(entry: Parameters<typeof recordAudit>[1]): Promise<void> {
    try {
      await recordAudit(store.database, entry);
    } catch (error) {
      log("audit failed after commit", { action: entry.action, ...errorFields(error) });
    }
  }

  async function mirror(profile: ProfileRow, credential: Credential, action: string, workspaceId: string | null = null): Promise<void> {
    await auditCommitted({
      organizationId: profile.organizationId,
      workspaceId,
      actor: serviceActor(credential),
      action,
      target: `profile/${profile.id}`,
    });
  }

  /* --------------------------------------------------------- operations */

  type Context = {
    request: IncomingMessage;
    url: URL;
    credential: Credential;
    profile: ProfileRow;
    params: string[];
    audit: { channel?: string | null; version?: string | null; assetId?: string | null; detail?: Record<string, unknown> };
    markBodyRead: () => void;
  };

  function readerChannel(url: URL): Channel {
    const channel = url.searchParams.get("channel");
    if (channel !== "stable" && channel !== "beta") throw new FeedError(400, "invalid_request", "channel must be stable or beta");
    return channel;
  }

  function pageParam(url: URL): number {
    const raw = url.searchParams.get("page");
    if (raw === null) return 1;
    if (!/^[1-9][0-9]{0,8}$/.test(raw)) throw new FeedError(400, "invalid_request", "page must be a positive integer");
    return Number(raw);
  }

  async function manifest(ctx: Context): Promise<Reply> {
    const channel = readerChannel(ctx.url);
    ctx.audit.channel = channel;
    const current = await store.currentEnvelope(ctx.profile.id, channel);
    if (!current) throw new FeedError(404, "no_release", "No release on this channel yet");
    ctx.audit.version = current.version;
    return { status: 200, text: current.envelope };
  }

  async function releases(ctx: Context): Promise<Reply> {
    const includeDrafts = ctx.url.searchParams.get("include_drafts");
    if (includeDrafts !== null && includeDrafts !== "true" && includeDrafts !== "false") {
      throw new FeedError(400, "invalid_request", "include_drafts must be true or false");
    }
    if (ctx.credential.kind === "publisherToken") {
      const rawChannel = ctx.url.searchParams.get("channel");
      if (rawChannel !== null && rawChannel !== "stable" && rawChannel !== "beta") {
        throw new FeedError(400, "invalid_request", "channel must be stable or beta");
      }
      const page = pageParam(ctx.url);
      const rows = await store.versions(ctx.profile.id, rawChannel as Channel | null, (page - 1) * PUBLISHER_PAGE, PUBLISHER_PAGE + 1);
      const more = rows.length > PUBLISHER_PAGE;
      return {
        status: 200,
        json: {
          versions: rows.slice(0, PUBLISHER_PAGE).map((row) => ({
            version: row.version,
            channel: row.channel,
            state: row.state,
            origin: row.origin,
            published_at: row.publishedAt,
            current: row.current,
          })),
          next_page: more ? page + 1 : null,
          limits: {
            quota_bytes: ctx.profile.quotaBytes,
            used_bytes: await currentUsage(ctx.profile),
            max_canonical_bytes: signer.maxCanonicalBytes(),
            retention: { stable: "all", beta_keep: ctx.profile.betaKeep },
          },
        },
      };
    }
    const channel = readerChannel(ctx.url);
    ctx.audit.channel = channel;
    const page = pageParam(ctx.url);
    if (await store.publishedCount(ctx.profile.id, channel) === 0) {
      throw new FeedError(404, "no_release", "No release on this channel yet");
    }
    const texts = await store.publishedEnvelopes(ctx.profile.id, channel, (page - 1) * READ_PAGE, READ_PAGE + 1);
    const more = texts.length > READ_PAGE;
    return {
      status: 200,
      text: `{"releases":[${texts.slice(0, READ_PAGE).join(",")}],"next_page":${more ? page + 1 : "null"}}`,
    };
  }

  /** The manifest of a release; ids and the timestamp may be placeholders of the real length. */
  function manifestBody(
    profileId: string,
    release: { channel: Channel; version: string; notes: string },
    publishedAt: string,
    assets: Array<{ id: string; name: string; platform: string; arch: string; osFloor: number | null; kind: string; size: number; sha256: string }>,
  ) {
    const host = storage.downloadHost();
    return {
      schema: 1,
      profile: profileId,
      channel: release.channel,
      version: release.version,
      published_at: publishedAt,
      notes: release.notes,
      download_hosts: host ? [host] : [],
      assets: assets.map((entry) => ({
        id: entry.id,
        name: entry.name,
        platform: entry.platform,
        arch: entry.arch,
        ...(entry.osFloor !== null ? { os_floor: entry.osFloor } : {}),
        kind: entry.kind,
        size: entry.size,
        sha256: entry.sha256,
      })),
    };
  }

  function refuseOversize(bytes: number): void {
    const max = signer.maxCanonicalBytes();
    if (max !== null && bytes > max) {
      throw new FeedError(
        422,
        "manifest_too_large",
        `The signed manifest would be ${bytes} bytes and this signer accepts at most ${max}; declare fewer assets or shorten the notes`,
        { canonical_bytes: bytes, max_canonical_bytes: max },
      );
    }
  }

  async function create(ctx: Context): Promise<Reply> {
    const raw = await readText(ctx.request);
    ctx.markBodyRead();
    let body: unknown;
    try {
      body = JSON.parse(raw);
    } catch {
      throw new FeedError(422, "invalid_release", "Body must be a JSON object");
    }
    if (!isPlainObject(body) || !Array.isArray(body.expected_assets) || body.expected_assets.length === 0) {
      throw new FeedError(422, "expected_assets_required", "expected_assets must list every asset of the release");
    }
    if (!validateDraft(body)) {
      const assetError = validateDraft.errors?.some((entry) => entry.instancePath.startsWith("/expected_assets"));
      throw assetError
        ? new FeedError(422, "invalid_asset", "An expected asset fails the asset rules")
        : new FeedError(422, "invalid_release", "The release fails the version, channel or notes rules");
    }
    const draft = body as { version: string; channel: Channel; notes: string; expected_assets: DeclaredAsset[] };
    ctx.audit.channel = draft.channel;
    ctx.audit.version = draft.version;
    const names = new Set<string>();
    const tuples = new Set<string>();
    for (const entry of draft.expected_assets) {
      if (names.has(entry.name)) throw new FeedError(422, "invalid_asset", "Asset names repeat");
      names.add(entry.name);
      const tuple = `${entry.platform}/${entry.arch}/${entry.kind}/${entry.os_floor ?? ""}`;
      if (tuples.has(tuple)) throw new FeedError(422, "invalid_asset", "Asset platform/arch/kind/os_floor tuples repeat");
      tuples.add(tuple);
      if (entry.kind !== "install-script" && !entry.name.startsWith(`${ctx.profile.assetPrefix}-${draft.version}-`)) {
        throw new FeedError(422, "invalid_asset", "Asset names must start with the profile's asset prefix and the version");
      }
    }
    const canonical = canonicalize(body);
    const existing = await store.release(ctx.profile.id, draft.version);
    if (existing) {
      if (existing.state === "draft" && existing.createBody !== null && existing.createBody === canonical) {
        return { status: 200, json: draftBody(existing, await store.assets(existing.id)) };
      }
      throw new FeedError(409, "version_exists", "This version already exists");
    }
    // Refuse before CI uploads gigabytes: the size is already fully determined.
    refuseOversize(canonicalBytes(manifestBody(
      ctx.profile.id,
      draft,
      PLACEHOLDER_PUBLISHED_AT,
      draft.expected_assets.map((entry) => ({
        id: `a_${"0".repeat(ASSET_ID_CHARS)}`, name: entry.name, platform: entry.platform, arch: entry.arch,
        osFloor: entry.os_floor ?? null, kind: entry.kind, size: entry.size, sha256: entry.sha256,
      })),
    )).length);
    const required = draft.expected_assets.reduce((total, entry) => total + entry.size, 0);
    const created = await store.createDraft({
      reserve: (tx) => quotaCheck(ctx.profile, draft.channel, required, null, tx),
      profileId: ctx.profile.id,
      version: draft.version,
      channel: draft.channel,
      origin: "publish",
      notes: draft.notes,
      createBody: canonical,
      envelope: null,
      assets: draft.expected_assets,
      now: now(),
    });
    if (!created) throw new FeedError(409, "version_exists", "This version already exists");
    return { status: 201, json: draftBody(created, await store.assets(created.id)) };
  }

  async function importRelease(ctx: Context): Promise<Reply> {
    const raw = await readText(ctx.request);
    ctx.markBodyRead();
    const invalid = (message: string) => new FeedError(422, "manifest_invalid", message);
    let body: unknown;
    try {
      body = strictParse(raw);
    } catch {
      throw invalid("The body is not strict I-JSON");
    }
    if (!isPlainObject(body) || Object.keys(body).length !== 1 || !("envelope" in body)) {
      throw invalid("The body must be {\"envelope\": ...}");
    }
    if (!validateEnvelope(body.envelope)) throw invalid("The envelope fails the envelope schema");
    const text = envelopeText(raw);
    if (text === null) throw invalid("The envelope could not be read");
    const envelope = body.envelope as {
      manifest: { profile: string; channel: Channel; version: string; notes: string; assets: Array<DeclaredAsset & { id: string }> };
      signature: string;
      key_id: string;
    };
    const signed = envelope.manifest;
    ctx.audit.channel = signed.channel;
    ctx.audit.version = signed.version;
    const ids = new Set(signed.assets.map((entry) => entry.id));
    const names = new Set(signed.assets.map((entry) => entry.name));
    if (ids.size !== signed.assets.length || names.size !== signed.assets.length) throw invalid("Asset ids or names repeat");
    if (signed.profile !== ctx.profile.id) throw new FeedError(422, "profile_mismatch", "manifest.profile is not this profile");
    const key = await verificationKey(ctx.profile.id, envelope.key_id);
    if (!key) throw new FeedError(422, "key_id_unknown", "key_id is not a registered key of this profile");
    if (!verifyEd25519(key, canonicalBytes(signed), envelope.signature)) {
      throw new FeedError(422, "signature_invalid", "The signature does not verify");
    }
    if (await store.release(ctx.profile.id, signed.version)) throw new FeedError(409, "version_exists", "This version already exists");
    if (await store.assetIdsInUse(ctx.profile.id, [...ids])) throw invalid("An asset id is already used in this profile");
    const required = signed.assets.reduce((total, entry) => total + entry.size, 0);
    const created = await store.createDraft({
      reserve: (tx) => quotaCheck(ctx.profile, signed.channel, required, null, tx),
      profileId: ctx.profile.id,
      version: signed.version,
      channel: signed.channel,
      origin: "import",
      notes: signed.notes,
      createBody: null,
      envelope: text,
      assets: signed.assets,
      now: now(),
    });
    if (!created) throw new FeedError(409, "version_exists", "This version already exists");
    await mirror(ctx.profile, ctx.credential, "desktop_feed.import");
    return { status: 201, json: draftBody(created, await store.assets(created.id)) };
  }

  async function upload(ctx: Context): Promise<Reply> {
    const version = decodeSegment(ctx.params[0]!);
    const name = decodeSegment(ctx.params[1]!);
    if (!version || !VERSION_PATTERN.test(version)) throw new FeedError(400, "invalid_request", "Invalid version");
    if (!name || name.length > 255 || !NAME_PATTERN.test(name)) throw new FeedError(400, "invalid_request", "Invalid asset name");
    ctx.audit.version = version;
    const sha256 = ctx.request.headers["x-content-sha256"];
    const lengthHeader = ctx.request.headers["content-length"];
    if (typeof sha256 !== "string" || !SHA256_PATTERN.test(sha256)) {
      throw new FeedError(400, "invalid_request", "X-Content-SHA256 must be a lower-case sha256");
    }
    if (typeof lengthHeader !== "string" || !/^[1-9][0-9]*$/.test(lengthHeader) || !Number.isSafeInteger(Number(lengthHeader))) {
      throw new FeedError(400, "invalid_request", "Content-Length is required");
    }
    const size = Number(lengthHeader);
    const release = await store.release(ctx.profile.id, version);
    if (!release) throw new FeedError(404, "draft_not_found", "No draft of this version");
    ctx.audit.channel = release.channel;
    if (release.state !== "draft") throw new FeedError(409, "not_a_draft", "This version is already published");
    const assets = await store.assets(release.id);
    const declared = assets.find((entry) => entry.name === name);
    if (!declared) throw new FeedError(422, "asset_not_declared", "The draft does not declare this asset");
    const uploadedReply = (entry: AssetRow): Reply => {
      if (entry.uploadedSha256 === sha256 && entry.uploadedSize === size) {
        ctx.audit.assetId = entry.assetId;
        return { status: 200, json: { id: entry.assetId, name: entry.name, size: entry.uploadedSize, sha256: entry.uploadedSha256 } };
      }
      throw new FeedError(409, "asset_conflict", "This asset was uploaded with other bytes");
    };
    if (declared.uploadedAt) return uploadedReply(declared);
    if (size !== declared.size || sha256 !== declared.sha256) {
      throw new FeedError(422, "asset_mismatch", "Size or sha256 differs from the declaration");
    }
    const storageKey = `profiles/${ctx.profile.id}/drafts/${version}/${name}`;
    const hash = createHash("sha256");
    let received = 0;
    const counter = new Transform({
      transform(chunk: Buffer, _encoding, callback) {
        received += chunk.length;
        if (received > size) {
          callback(new Error("body longer than Content-Length"));
          return;
        }
        hash.update(chunk);
        callback(null, chunk);
      },
    });
    ctx.markBodyRead();
    ctx.request.on("error", (error) => counter.destroy(error));
    ctx.request.on("aborted", () => counter.destroy(new Error("upload aborted")));
    ctx.request.pipe(counter);
    let failure: unknown = null;
    try {
      await storage.put(storageKey, counter, size, sha256);
    } catch (error) {
      failure = error;
    }
    const digest = hash.digest("hex");
    if (received !== size || digest !== sha256) {
      if (!failure) await storage.delete(storageKey).catch(() => undefined);
      throw new FeedError(422, "asset_mismatch", "The received bytes differ from the declaration");
    }
    if (failure) {
      storageFailed("put", storageKey, failure);
      throw failure;
    }
    const assetId = declared.assetId ?? newAssetId();
    const recorded = await store.recordUpload({
      releaseId: release.id, name, assetId, size, sha256, storageKey, now: now(),
    });
    if (!recorded) {
      const current = (await store.assets(release.id)).find((entry) => entry.name === name);
      if (!current) throw new FeedError(404, "draft_not_found", "No draft of this version");
      return uploadedReply(current);
    }
    ctx.audit.assetId = assetId;
    return { status: 201, json: { id: assetId, name, size, sha256 } };
  }

  async function publish(ctx: Context): Promise<Reply> {
    const version = decodeSegment(ctx.params[0]!);
    if (!version || !VERSION_PATTERN.test(version)) throw new FeedError(400, "invalid_request", "Invalid version");
    ctx.audit.version = version;
    const raw = await readText(ctx.request);
    ctx.markBodyRead();
    let latest = false;
    if (raw.trim()) {
      let body: unknown;
      try {
        body = JSON.parse(raw);
      } catch {
        throw new FeedError(400, "invalid_request", "Body must be a JSON object");
      }
      if (!isPlainObject(body) || Object.keys(body).some((key) => key !== "latest")
        || (body.latest !== undefined && typeof body.latest !== "boolean")) {
        throw new FeedError(400, "invalid_request", "Body may only carry latest (boolean)");
      }
      latest = body.latest === true;
    }
    const release = await store.release(ctx.profile.id, version);
    if (!release) throw new FeedError(404, "draft_not_found", "No draft of this version");
    ctx.audit.channel = release.channel;
    if (release.state !== "draft") throw new FeedError(409, "not_a_draft", "This version is already published");
    const assets = await store.assets(release.id);
    const missing: string[] = [];
    const mismatched: string[] = [];
    for (const entry of assets) {
      if (!entry.uploadedAt) missing.push(entry.name);
      else if (entry.uploadedSize !== entry.size || entry.uploadedSha256 !== entry.sha256) mismatched.push(entry.name);
    }
    if (missing.length || mismatched.length) {
      throw new FeedError(422, "assets_incomplete", "Every declared asset must be uploaded first", { missing, mismatched });
    }
    await quotaCheck(ctx.profile, release.channel, release.declaredBytes, release.id);
    let text: string;
    let publishedAt: string;
    if (release.origin === "import") {
      const stored = JSON.parse(release.envelope ?? "null") as { manifest: { published_at: string }; signature: string; key_id: string } | null;
      const key = stored ? await verificationKey(ctx.profile.id, stored.key_id) : null;
      if (!stored || !key || !verifyEd25519(key, canonicalBytes(stored.manifest), stored.signature)) {
        throw new FeedError(422, "signature_invalid", "The imported envelope no longer verifies");
      }
      text = release.envelope!;
      publishedAt = stored.manifest.published_at;
    } else {
      publishedAt = wholeSecondIso(now());
      const manifest = manifestBody(ctx.profile.id, release, publishedAt, assets.map((entry) => ({ ...entry, id: entry.assetId! })));
      const bytes = canonicalBytes(manifest);
      refuseOversize(bytes.length);
      const unavailable = () => new FeedError(503, "signer_unavailable", "The signer is unavailable; the draft stays a draft");
      let signature: { signature: string; keyId: string };
      let publicKey: string;
      try {
        signature = await signer.sign(ctx.profile.id, bytes);
        publicKey = await signer.publicKey(ctx.profile.id);
      } catch (error) {
        signerFailed("sign", ctx.profile.id, error);
        throw unavailable();
      }
      if (!verifyEd25519(publicKey, bytes, signature.signature)) {
        log("signer unavailable", {
          operation: "verify", profile: ctx.profile.id, signer: signer.kind,
          error: "SignatureMismatch", message: "the signer's signature does not verify against its public key",
        });
        throw unavailable();
      }
      text = JSON.stringify({ manifest, signature: signature.signature, key_id: signature.keyId });
    }
    // Copy before the commit: a failed copy leaves a draft that a rerun resumes.
    const releasePrefix = `profiles/${ctx.profile.id}/releases/${version}`;
    for (const entry of assets) {
      const key = `${releasePrefix}/${entry.name}`;
      try {
        await storage.copy(entry.storageKey!, key);
      } catch (error) {
        storageFailed("copy", key, error);
        throw error;
      }
    }
    const moveCurrent = release.channel === "beta" || latest;
    const result = await store.publish({
      releaseId: release.id,
      profileId: ctx.profile.id,
      channel: release.channel,
      envelope: text,
      publishedAt,
      moveCurrent,
      betaKeep: ctx.profile.betaKeep,
      releasePrefix,
    });
    if (!result) throw new FeedError(409, "not_a_draft", "This version is already published");
    await mirror(ctx.profile, ctx.credential, "desktop_feed.publish");
    // The release is committed; what follows is cleanup, and failing it must
    // not report a failed publish. Postgres still serves the envelope.
    for (const entry of assets) {
      await storage.delete(entry.storageKey!).catch((error) => storageFailed("delete", entry.storageKey!, error));
    }
    if (moveCurrent) {
      const key = `profiles/${ctx.profile.id}/manifests/${release.channel}.json`;
      const bytes = Buffer.from(text, "utf8");
      await storage.put(key, Readable.from([bytes]), bytes.length, createHash("sha256").update(bytes).digest("hex"))
        .catch((error) => storageFailed("put", key, error));
    }
    for (const pruned of result.pruned) {
      for (const key of pruned.storageKeys) await storage.delete(key).catch(() => undefined);
      await store.audit({
        organizationId: ctx.profile.organizationId,
        workspaceId: null,
        actorKind: "publisher_token",
        actorId: ctx.credential.kind === "publisherToken" ? ctx.credential.token.id : null,
        action: "desktop_feed.beta_prune",
        profile: ctx.profile.id,
        channel: "beta",
        version: pruned.version,
        assetId: null,
        clientIp: clientIp(ctx.request),
        status: 200,
      }).catch((error) => log("audit failed after commit", { action: "desktop_feed.beta_prune", ...errorFields(error) }));
      await mirror(ctx.profile, ctx.credential, "desktop_feed.beta_prune");
    }
    return { status: 200, text };
  }

  async function publishedAssetFor(ctx: Context) {
    const assetId = decodeSegment(ctx.params[0]!);
    if (!assetId || !ASSET_ID_PATTERN.test(assetId)) throw new FeedError(400, "invalid_request", "Invalid asset id");
    ctx.audit.assetId = assetId;
    const found = await store.publishedAsset(ctx.profile.id, assetId);
    if (!found || !found.storageKey) throw new FeedError(403, "not_entitled", "Not entitled to this asset");
    ctx.audit.channel = found.channel;
    ctx.audit.version = found.version;
    return found;
  }

  async function downloadUrl(ctx: Context): Promise<Reply> {
    const found = await publishedAssetFor(ctx);
    const host = storage.downloadHost();
    const signedHosts = (JSON.parse(found.envelope) as { manifest: { download_hosts: string[] } }).manifest.download_hosts;
    const noStorage = () => new FeedError(501, "no_object_storage", "This deployment streams assets; use GET /assets/{assetId}");
    if (!host || !signedHosts.includes(host)) throw noStorage();
    const issued = now();
    const url = await storage.presignGet(found.storageKey!, DOWNLOAD_URL_SECONDS, issued);
    if (!url) throw noStorage();
    return {
      status: 200,
      json: { url: url.toString(), expires_at: new Date(issued.getTime() + DOWNLOAD_URL_SECONDS * 1000).toISOString() },
    };
  }

  async function stream(ctx: Context): Promise<Reply> {
    const found = await publishedAssetFor(ctx);
    const etag = `"${found.sha256}"`;
    const rangeHeader = ctx.request.headers.range;
    const ifRange = ctx.request.headers["if-range"];
    const decision = rangeDecision(rangeHeader, found.size, typeof ifRange === "string" ? ifRange : undefined, etag);
    if (decision.status === 416) {
      throw new FeedError(416, "range_not_satisfiable", "Range not satisfiable", {}, { "content-range": `bytes */${found.size}` });
    }
    const key = ctx.credential.rateKey;
    const active = streams.get(key) ?? 0;
    if (active >= limits.streamConcurrent) throw rateLimited(1);
    streams.set(key, active + 1);
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      const count = (streams.get(key) ?? 1) - 1;
      if (count <= 0) streams.delete(key);
      else streams.set(key, count);
    };
    try {
      const body = await storage.get(found.storageKey!, decision.status === 206 ? decision.range : undefined);
      if (!body) throw new Error("desktop feed object missing from storage");
      const headers: Record<string, string> = {
        "content-type": "application/octet-stream",
        "accept-ranges": "bytes",
        etag,
      };
      if (decision.status === 206) {
        headers["content-range"] = `bytes ${decision.range.start}-${decision.range.end}/${found.size}`;
        headers["content-length"] = String(decision.range.end - decision.range.start + 1);
      } else {
        headers["content-length"] = String(found.size);
      }
      return { status: decision.status, stream: body, headers, release };
    } catch (error) {
      release();
      storageFailed("get", found.storageKey!, error);
      throw error;
    }
  }

  function sessionPrincipal(ctx: Context): Principal {
    if (ctx.credential.kind !== "browserSession") throw new FeedError(403, "wrong_credential", "Browser session required");
    return ctx.credential.principal;
  }

  async function installTokensList(ctx: Context): Promise<Reply> {
    const principal = sessionPrincipal(ctx);
    const rows = await store.installTokens(principal.userId, principal.workspaceId, ctx.profile.id);
    const at = now();
    return { status: 200, json: { tokens: rows.map((row) => installTokenSummary(row, at)) } };
  }

  async function installTokensCreate(ctx: Context): Promise<Reply> {
    const principal = sessionPrincipal(ctx);
    const raw = await readText(ctx.request);
    ctx.markBodyRead();
    let label: string | null = null;
    if (raw.trim()) {
      let body: unknown;
      try {
        body = JSON.parse(raw);
      } catch {
        throw new FeedError(400, "invalid_request", "Body must be a JSON object");
      }
      if (!isPlainObject(body) || Object.keys(body).some((key) => key !== "label")
        || (body.label !== undefined && (typeof body.label !== "string" || body.label.length > 128))) {
        throw new FeedError(400, "invalid_request", "Body may only carry label (string, at most 128 characters)");
      }
      label = (body.label as string | undefined) ?? null;
    }
    rate(`df:mint:${principal.userId}`, limits.installTokenMint);
    const token = opaqueToken(INSTALL_TOKEN_PREFIX);
    const at = now();
    const row = await store.createInstallToken({
      tokenHash: hashSecret(token),
      tokenPrefix: token.slice(0, 11),
      userId: principal.userId,
      workspaceId: principal.workspaceId,
      profileId: ctx.profile.id,
      label,
      now: at,
      expiresAt: new Date(at.getTime() + INSTALL_TOKEN_SECONDS * 1000),
    });
    await mirror(ctx.profile, ctx.credential, "desktop_feed.install_token_create", principal.workspaceId);
    return {
      status: 201,
      json: {
        id: row.id,
        token,
        label: row.label,
        profile: row.profileId,
        workspace_id: row.workspaceId,
        created_at: row.createdAt,
        expires_at: row.expiresAt,
        command: `AGENT_RELAY_INSTALL_TOKEN=${token} bash install.sh`,
      },
    };
  }

  async function installTokensRevoke(ctx: Context): Promise<Reply> {
    const principal = sessionPrincipal(ctx);
    const id = decodeSegment(ctx.params[0]!);
    if (!id || !UUID_PATTERN.test(id)) throw new FeedError(400, "invalid_request", "Invalid token id");
    const row = await store.revokeInstallToken({
      id, userId: principal.userId, workspaceId: principal.workspaceId, profileId: ctx.profile.id, now: now(),
    });
    if (!row) throw new FeedError(404, "install_token_not_found", "Install token not found");
    await mirror(ctx.profile, ctx.credential, "desktop_feed.install_token_revoke", principal.workspaceId);
    return { status: 200, json: installTokenSummary(row, now()) };
  }

  const OPERATIONS: Record<Op, (ctx: Context) => Promise<Reply>> = {
    manifest,
    releases,
    create,
    import: importRelease,
    upload,
    publish,
    download_url: downloadUrl,
    stream,
    install_tokens_list: installTokensList,
    install_tokens_create: installTokensCreate,
    install_tokens_revoke: installTokensRevoke,
  };

  /* -------------------------------------------------------------- feed */

  async function feed(request: IncomingMessage, response: ServerResponse, operation: FeedOperation, method: string): Promise<void> {
    const url = new URL(request.url ?? "/", config.publicBaseUrl);
    const rawPath = url.pathname;
    const ip = clientIp(request);
    const { op } = operation;
    let credential: Credential | null = null;
    let profile: ProfileRow | null = null;
    const headerProfile = request.headers[PROFILE_HEADER];
    const profileHeader = typeof headerProfile === "string" ? headerProfile.trim() : "";
    const audit: Context["audit"] = {};
    let bodyRead = false;
    let reply: Reply;
    try {
      credential = await resolveCredential(request, rawPath, ip);
      const { bucket, rule } = rateRule(op, credential);
      rate(`df:${bucket}:${credential.rateKey}`, rule);
      if (credential.kind === "other" || !ACCEPTS[op].includes(credential.kind)) {
        throw new FeedError(403, "wrong_credential", "This credential is not accepted here");
      }
      if (op === "releases" && (credential.kind === "publisherToken") !== (url.searchParams.get("include_drafts") === "true")) {
        throw new FeedError(403, "wrong_credential", "This credential is not accepted here");
      }
      if (credential.kind === "browserSession" && method !== "GET" && !cookieRequestAllowed(request, input.browserOrigins)) {
        throw new FeedError(403, "csrf_rejected", "Cross-origin browser requests are forbidden");
      }
      if (!profileHeader) throw new FeedError(400, "profile_header_required", "X-Agent-Relay-Profile is required");
      profile = await entitled(credential, profileHeader);
      if (!profile) throw new FeedError(403, "not_entitled", "Not entitled to this profile");
      reply = await OPERATIONS[op]({
        request, url, credential, profile, params: operation.params, audit, markBodyRead: () => { bodyRead = true; },
      });
    } catch (error) {
      if (!(error instanceof FeedError)) throw error;
      reply = {
        status: error.status,
        json: { error: error.code, message: error.message, ...error.extra },
        headers: error.headers,
      };
    }

    const success = reply.status >= 200 && reply.status < 300;
    const denied = reply.status === 401 || reply.status === 403;
    if (denied || READ_OPS.has(op) || success) {
      try {
        await store.audit(auditEvent(denied ? "desktop_feed.denied" : ACTIONS[op], reply.status));
      } catch (error) {
        if (success && !READ_OPS.has(op)) {
          // The write committed; a retry would get 409 or lose a one-time token.
          log("audit failed after commit", { action: ACTIONS[op], ...errorFields(error) });
        } else {
          if ("release" in reply) reply.release();
          throw error;
        }
      }
    }

    function auditEvent(action: string, status: number) {
      const principal = credential && (credential.kind === "workspaceBearer" || credential.kind === "browserSession")
        ? credential.principal
        : null;
      return {
        organizationId: principal?.organizationId ?? profile?.organizationId ?? null,
        workspaceId: principal?.workspaceId ?? (credential?.kind === "installToken" ? credential.token.workspaceId : null),
        actorKind: principal
          ? "user" as const
          : credential?.kind === "installToken"
            ? "install_token" as const
            : credential?.kind === "publisherToken"
              ? "publisher_token" as const
              : "anonymous" as const,
        actorId: principal?.userId
          ?? (credential?.kind === "installToken" || credential?.kind === "publisherToken" ? credential.token.id : null),
        action,
        profile: profile?.id ?? (PROFILE_PATTERN.test(profileHeader) ? profileHeader : null),
        channel: audit.channel ?? null,
        version: audit.version ?? null,
        assetId: audit.assetId ?? null,
        clientIp: ip,
        status,
        detail: {
          operation: op,
          ...(denied && "json" in reply ? { error: (reply.json as { error?: string }).error } : {}),
          ...audit.detail,
        },
      };
    }

    // A refused request whose body was never read: drain a small one, close
    // the connection after a large one rather than reading it.
    if (!bodyRead && !request.complete) {
      const length = Number(request.headers["content-length"] ?? 0);
      if (Number.isFinite(length) && length <= JSON_LIMIT && !request.headers["transfer-encoding"]) request.resume();
      else response.setHeader("connection", "close");
    }

    if ("stream" in reply) {
      const body = reply.stream;
      const { release } = reply;
      response.once("close", () => {
        release();
        body.destroy();
      });
      response.writeHead(reply.status, { ...reply.headers });
      body.once("error", () => response.destroy());
      body.pipe(response);
      return;
    }
    const headers: Record<string, string> = {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...reply.headers,
    };
    response.writeHead(reply.status, headers);
    response.end("text" in reply ? reply.text : JSON.stringify(reply.json));
  }

  /* ------------------------------------------------------------- admin */

  const ADMIN_PATTERN = /^\/api\/v1\/organizations\/([^/]+)\/desktop-feed\/profiles(?:\/([^/]+)(?:\/(workspaces|publisher-tokens)(?:\/([^/]+))?)?)?$/;

  function adminActor(auth: OrganizationAuth): AuditActor {
    return auth.kind === "bootstrap" ? { kind: "bootstrap" } : { kind: "user", userId: auth.principal.userId };
  }

  function bad(message: string): Error {
    return input.httpError(400, "invalid_request", message);
  }

  async function profileDetail(profile: ProfileRow) {
    const keys = await store.publicKeys(profile.id);
    let signingKey: { key_id: string; public_key: string } | null = null;
    try {
      signingKey = { key_id: signer.keyId(profile.id), public_key: await signer.publicKey(profile.id) };
    } catch (error) {
      signerFailed("publicKey", profile.id, error);
      signingKey = null;
    }
    return {
      id: profile.id,
      organization_id: profile.organizationId,
      asset_prefix: profile.assetPrefix,
      quota_bytes: profile.quotaBytes,
      beta_keep: profile.betaKeep,
      created_at: profile.createdAt,
      public_keys: [...keys].map(([keyId, publicKey]) => ({ key_id: keyId, public_key: publicKey })),
      signing_key: signingKey,
      workspaces: await store.bindings(profile.id),
      publisher_tokens: (await store.publisherTokens(profile.id)).map(publisherTokenSummary),
    };
  }

  async function admin(request: IncomingMessage, response: ServerResponse, match: RegExpExecArray, method: string): Promise<boolean> {
    const [, rawOrg, rawProfile, sub, rawSubId] = match;
    const organizationId = decodeSegment(rawOrg!);
    if (!organizationId || !UUID_PATTERN.test(organizationId)) {
      throw input.httpError(404, "organization_not_found", "Organization not found");
    }
    const routeKnown =
      (!rawProfile && (method === "GET" || method === "POST"))
      || (rawProfile && !sub && method === "GET")
      || (sub === "workspaces" && rawSubId && (method === "PUT" || method === "DELETE"))
      || (sub === "publisher-tokens" && !rawSubId && method === "POST")
      || (sub === "publisher-tokens" && rawSubId && method === "DELETE");
    if (!routeKnown) return false;
    // The /cloud session cookie reaches these routes too; a bearer is not CSRF-able.
    if (method !== "GET" && !bearerToken(request) && !cookieRequestAllowed(request, input.browserOrigins)) {
      throw input.httpError(403, "csrf_rejected", "Cross-origin browser requests are forbidden");
    }
    const auth = await input.organizationAccess(request, organizationId, true);
    const actor = adminActor(auth);

    if (!rawProfile) {
      if (method === "GET") {
        const profiles = await store.profilesForOrganization(organizationId);
        input.json(response, 200, { profiles: await Promise.all(profiles.map(profileDetail)) }, true);
        return true;
      }
      const body = await input.requestObject(request);
      const allowed = new Set(["id", "asset_prefix", "quota_bytes", "beta_keep", "public_keys"]);
      if (Object.keys(body).some((key) => !allowed.has(key))) throw bad("Unknown field");
      const id = body.id;
      if (typeof id !== "string" || !PROFILE_PATTERN.test(id)) throw bad("id must match ^[a-z0-9]{1,32}$");
      if (typeof body.asset_prefix !== "string" || !ASSET_PREFIX_PATTERN.test(body.asset_prefix)) {
        throw bad("asset_prefix must match ^[A-Za-z0-9][A-Za-z0-9_+-]{0,63}$");
      }
      const quota = body.quota_bytes ?? DEFAULT_QUOTA_BYTES;
      if (typeof quota !== "number" || !Number.isSafeInteger(quota) || quota < 0) throw bad("quota_bytes must be a non-negative integer");
      const betaKeep = body.beta_keep ?? DEFAULT_BETA_KEEP;
      if (typeof betaKeep !== "number" || !Number.isSafeInteger(betaKeep) || betaKeep < 1 || betaKeep > 1000) {
        throw bad("beta_keep must be an integer from 1 to 1000");
      }
      const rawKeys = body.public_keys ?? [];
      if (!Array.isArray(rawKeys) || rawKeys.length > 8) throw bad("public_keys must be an array of at most 8 keys");
      const keyIdPattern = new RegExp(`^fk_${id}_[a-z0-9]{1,16}$`);
      const publicKeys = rawKeys.map((entry: unknown) => {
        if (!isPlainObject(entry) || typeof entry.key_id !== "string" || typeof entry.public_key !== "string"
          || Object.keys(entry).some((key) => key !== "key_id" && key !== "public_key")) {
          throw bad("public_keys entries are {key_id, public_key}");
        }
        if (!keyIdPattern.test(entry.key_id)) throw bad("key_id must be fk_<profile>_<label>");
        if (!/^[A-Za-z0-9+/]{43}=$/.test(entry.public_key) || Buffer.from(entry.public_key, "base64").length !== 32) {
          throw bad("public_key must be the base64 of a raw 32-byte Ed25519 key");
        }
        return { keyId: entry.key_id, publicKey: entry.public_key };
      });
      if (new Set(publicKeys.map((entry) => entry.keyId)).size !== publicKeys.length) throw bad("key_id values repeat");
      if (publicKeys.some((entry) => entry.keyId === signer.keyId(id))) throw bad("key_id is this site's signing key");
      if (!signer.hasProfile(id)) {
        throw input.httpError(409, "signing_key_not_configured", "No KMS key alias is configured for this profile id");
      }
      const result = await store.createProfile({
        id, organizationId, assetPrefix: body.asset_prefix, quotaBytes: quota, betaKeep, publicKeys,
      });
      if ("refused" in result) throw input.httpError(409, "profile_exists", "A profile with this id already exists");
      const created = result.created;
      await auditCommitted({ organizationId, actor, action: "desktop_feed.profile_create", target: `profile/${id}` });
      input.json(response, 201, await profileDetail(created), true);
      return true;
    }

    const profileId = decodeSegment(rawProfile);
    const profile = profileId && PROFILE_PATTERN.test(profileId) ? await store.profile(profileId) : null;
    if (!profile || profile.organizationId !== organizationId) {
      throw input.httpError(404, "profile_not_found", "Desktop feed profile not found");
    }
    const target = `profile/${profile.id}`;
    if (!sub) {
      input.json(response, 200, await profileDetail(profile), true);
      return true;
    }
    const subId = decodeSegment(rawSubId ?? "");
    if (sub === "workspaces") {
      if (!subId || !UUID_PATTERN.test(subId) || !await store.workspaceInOrganization(subId, organizationId)) {
        throw input.httpError(404, "workspace_not_found", "Workspace not found");
      }
      if (method === "PUT") {
        await store.bind(profile.id, subId);
        await auditCommitted({ organizationId, workspaceId: subId, actor, action: "desktop_feed.workspace_bind", target });
      } else {
        await store.unbind(profile.id, subId);
        await auditCommitted({ organizationId, workspaceId: subId, actor, action: "desktop_feed.workspace_unbind", target });
      }
      input.json(response, 200, { profile: profile.id, workspaces: await store.bindings(profile.id) }, true);
      return true;
    }
    if (method === "POST") {
      const body = await input.requestObject(request);
      if (Object.keys(body).some((key) => key !== "label")
        || (body.label !== undefined && (typeof body.label !== "string" || body.label.length > 128))) {
        throw bad("Body may only carry label (string, at most 128 characters)");
      }
      const token = opaqueToken(PUBLISHER_TOKEN_PREFIX);
      const row = await store.createPublisherToken({
        profileId: profile.id,
        tokenHash: hashSecret(token),
        tokenPrefix: token.slice(0, 11),
        label: (body.label as string | undefined) ?? null,
        now: now(),
        keep: ACTIVE_PUBLISHER_TOKENS,
      });
      await auditCommitted({ organizationId, actor, action: "desktop_feed.publisher_token_create", target });
      input.json(response, 201, { ...publisherTokenSummary(row), profile: profile.id, token }, true);
      return true;
    }
    if (!subId || !UUID_PATTERN.test(subId)) throw input.httpError(404, "publisher_token_not_found", "Publisher token not found");
    const revoked = await store.revokePublisherToken(profile.id, subId, now());
    if (!revoked) throw input.httpError(404, "publisher_token_not_found", "Publisher token not found");
    await auditCommitted({ organizationId, actor, action: "desktop_feed.publisher_token_revoke", target });
    input.json(response, 200, publisherTokenSummary(revoked), true);
    return true;
  }

  /**
   * The profiles the signed-in workspace may read, so the downloads page can
   * name one in X-Agent-Relay-Profile. An unentitled workspace gets an empty list.
   */
  async function feedProfiles(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const url = new URL(request.url ?? "/", config.publicBaseUrl);
    const ip = clientIp(request);
    let reply: { status: number; body: unknown; headers?: Record<string, string> };
    try {
      const credential = await resolveCredential(request, url.pathname, ip);
      rate(`df:reads:${credential.rateKey}`, limits.reads);
      if (credential.kind !== "workspaceBearer" && credential.kind !== "browserSession") {
        throw new FeedError(403, "wrong_credential", "This credential is not accepted here");
      }
      const profiles = await store.profilesForWorkspace(credential.principal.workspaceId);
      reply = { status: 200, body: { profiles: profiles.map((row) => ({ id: row.id, asset_prefix: row.assetPrefix })) } };
    } catch (error) {
      if (!(error instanceof FeedError)) throw error;
      reply = { status: error.status, body: { error: error.code, message: error.message, ...error.extra }, headers: error.headers };
    }
    response.writeHead(reply.status, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      ...reply.headers,
    });
    response.end(JSON.stringify(reply.body));
  }

  /** Handles a desktop feed or feed-admin route; false when the path is not one. */
  return async function handle(request: IncomingMessage, response: ServerResponse, path: string, method: string): Promise<boolean> {
    if (path === FEED_PROFILES_PATH && method === "GET") {
      await feedProfiles(request, response);
      return true;
    }
    const operation = matchOperation(path, method);
    if (operation) {
      await feed(request, response, operation, method);
      return true;
    }
    const adminMatch = ADMIN_PATTERN.exec(path);
    if (adminMatch) return admin(request, response, adminMatch, method);
    return false;
  };
}
