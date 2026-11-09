// Postgres access for the desktop feed (migrations/0020_desktop_feed.sql).
// Token values never reach this layer: callers pass hashSecret(token).
import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import type { Database, SqlExecutor } from "../database.js";

export type Channel = "stable" | "beta";

export type ProfileRow = {
  id: string;
  organizationId: string;
  assetPrefix: string;
  quotaBytes: number;
  betaKeep: number;
  createdAt: string;
};

export type PublisherTokenRow = {
  id: string;
  profileId: string;
  label: string | null;
  tokenPrefix: string;
  createdAt: string;
  revokedAt: string | null;
  lastUsedAt: string | null;
};

export type InstallTokenRow = {
  id: string;
  userId: string;
  workspaceId: string;
  profileId: string;
  label: string | null;
  tokenPrefix: string;
  createdAt: string;
  expiresAt: string;
  revokedAt: string | null;
  lastUsedAt: string | null;
};

export type ReleaseRow = {
  id: string;
  profileId: string;
  version: string;
  channel: Channel;
  state: "draft" | "published";
  origin: "publish" | "import";
  notes: string;
  createBody: string | null;
  envelope: string | null;
  declaredBytes: number;
  publishedAt: string | null;
  publishSeq: number | null;
  createdAt: string;
};

export type AssetRow = {
  releaseId: string;
  position: number;
  name: string;
  platform: string;
  arch: string;
  osFloor: number | null;
  kind: string;
  size: number;
  sha256: string;
  assetId: string | null;
  uploadedSize: number | null;
  uploadedSha256: string | null;
  storageKey: string | null;
  uploadedAt: string | null;
};

export type DeclaredAsset = {
  name: string;
  platform: string;
  arch: string;
  os_floor?: number;
  kind: string;
  size: number;
  sha256: string;
  id?: string;
};

export type AuditInput = {
  organizationId: string | null;
  workspaceId: string | null;
  actorKind: "user" | "install_token" | "publisher_token" | "service" | "anonymous";
  actorId: string | null;
  action: string;
  profile: string | null;
  channel: string | null;
  version: string | null;
  assetId: string | null;
  clientIp: string | null;
  status: number;
  detail?: Record<string, unknown>;
};

type Row = Record<string, unknown>;

const iso = (value: unknown): string => new Date(value as string | Date).toISOString();
const isoOrNull = (value: unknown): string | null => value === null || value === undefined ? null : iso(value);
const num = (value: unknown): number => Number(value);

function profile(row: Row): ProfileRow {
  return {
    id: row.id as string,
    organizationId: row.organization_id as string,
    assetPrefix: row.asset_prefix as string,
    quotaBytes: num(row.quota_bytes),
    betaKeep: num(row.beta_keep),
    createdAt: iso(row.created_at),
  };
}

function publisherToken(row: Row): PublisherTokenRow {
  return {
    id: row.id as string,
    profileId: row.profile_id as string,
    label: (row.label as string | null) ?? null,
    tokenPrefix: row.token_prefix as string,
    createdAt: iso(row.created_at),
    revokedAt: isoOrNull(row.revoked_at),
    lastUsedAt: isoOrNull(row.last_used_at),
  };
}

function installToken(row: Row): InstallTokenRow {
  return {
    id: row.id as string,
    userId: row.user_id as string,
    workspaceId: row.workspace_id as string,
    profileId: row.profile_id as string,
    label: (row.label as string | null) ?? null,
    tokenPrefix: row.token_prefix as string,
    createdAt: iso(row.created_at),
    expiresAt: iso(row.expires_at),
    revokedAt: isoOrNull(row.revoked_at),
    lastUsedAt: isoOrNull(row.last_used_at),
  };
}

function release(row: Row): ReleaseRow {
  return {
    id: row.id as string,
    profileId: row.profile_id as string,
    version: row.version as string,
    channel: row.channel as Channel,
    state: row.state as ReleaseRow["state"],
    origin: row.origin as ReleaseRow["origin"],
    notes: row.notes as string,
    createBody: (row.create_body as string | null) ?? null,
    envelope: (row.envelope as string | null) ?? null,
    declaredBytes: num(row.declared_bytes),
    publishedAt: isoOrNull(row.published_at),
    publishSeq: row.publish_seq === null || row.publish_seq === undefined ? null : num(row.publish_seq),
    createdAt: iso(row.created_at),
  };
}

function asset(row: Row): AssetRow {
  return {
    releaseId: row.release_id as string,
    position: num(row.position),
    name: row.name as string,
    platform: row.platform as string,
    arch: row.arch as string,
    osFloor: row.os_floor === null || row.os_floor === undefined ? null : num(row.os_floor),
    kind: row.kind as string,
    size: num(row.size),
    sha256: row.sha256 as string,
    assetId: (row.asset_id as string | null) ?? null,
    uploadedSize: row.uploaded_size === null || row.uploaded_size === undefined ? null : num(row.uploaded_size),
    uploadedSha256: (row.uploaded_sha256 as string | null) ?? null,
    storageKey: (row.storage_key as string | null) ?? null,
    uploadedAt: isoOrNull(row.uploaded_at),
  };
}

const RELEASE_COLUMNS = `id, profile_id, version, channel, state, origin, notes, create_body, envelope,
  declared_bytes, published_at, publish_seq, created_at`;

export class DesktopFeedStore {
  constructor(readonly database: Database) {}

  /* ------------------------------------------------------------ profiles */

  async profile(id: string, executor: SqlExecutor = this.database): Promise<ProfileRow | null> {
    const result = await executor.query(`SELECT * FROM selfhost_desktop_feed_profiles WHERE id = $1`, [id]);
    return result.rows[0] ? profile(result.rows[0]) : null;
  }

  async profilesForOrganization(organizationId: string): Promise<ProfileRow[]> {
    const result = await this.database.query(
      `SELECT * FROM selfhost_desktop_feed_profiles WHERE organization_id = $1 ORDER BY id`,
      [organizationId],
    );
    return result.rows.map(profile);
  }

  async createProfile(input: {
    id: string;
    organizationId: string;
    assetPrefix: string;
    quotaBytes: number;
    betaKeep: number;
    publicKeys: Array<{ keyId: string; publicKey: string }>;
  }): Promise<{ created: ProfileRow } | { refused: "exists" }> {
    return this.database.transaction(async (tx) => {
      const inserted = await tx.query(
        `INSERT INTO selfhost_desktop_feed_profiles (id, organization_id, asset_prefix, quota_bytes, beta_keep)
         VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING RETURNING *`,
        [input.id, input.organizationId, input.assetPrefix, input.quotaBytes, input.betaKeep],
      );
      if (!inserted.rows[0]) return { refused: "exists" as const };
      for (const key of input.publicKeys) {
        await tx.query(
          `INSERT INTO selfhost_desktop_feed_profile_keys (profile_id, key_id, public_key) VALUES ($1, $2, $3)`,
          [input.id, key.keyId, key.publicKey],
        );
      }
      return { created: profile(inserted.rows[0]) };
    });
  }

  async publicKeys(profileId: string): Promise<Map<string, string>> {
    const result = await this.database.query<{ key_id: string; public_key: string }>(
      `SELECT key_id, public_key FROM selfhost_desktop_feed_profile_keys WHERE profile_id = $1`,
      [profileId],
    );
    return new Map(result.rows.map((row) => [row.key_id, row.public_key]));
  }

  /** The profiles a workspace may read, for the downloads page. */
  async profilesForWorkspace(workspaceId: string): Promise<ProfileRow[]> {
    const result = await this.database.query(
      `SELECT p.* FROM selfhost_desktop_feed_profiles p
         JOIN selfhost_desktop_feed_workspace_bindings b ON b.profile_id = p.id
        WHERE b.workspace_id = $1 ORDER BY p.id`,
      [workspaceId],
    );
    return result.rows.map(profile);
  }

  async bindings(profileId: string): Promise<string[]> {
    const result = await this.database.query<{ workspace_id: string }>(
      `SELECT workspace_id FROM selfhost_desktop_feed_workspace_bindings WHERE profile_id = $1 ORDER BY created_at, workspace_id`,
      [profileId],
    );
    return result.rows.map((row) => row.workspace_id);
  }

  async isBound(profileId: string, workspaceId: string): Promise<boolean> {
    const result = await this.database.query(
      `SELECT 1 FROM selfhost_desktop_feed_workspace_bindings WHERE profile_id = $1 AND workspace_id = $2`,
      [profileId, workspaceId],
    );
    return result.rows.length > 0;
  }

  async workspaceInOrganization(workspaceId: string, organizationId: string): Promise<boolean> {
    const result = await this.database.query(
      `SELECT 1 FROM selfhost_workspaces WHERE id = $1 AND organization_id = $2`,
      [workspaceId, organizationId],
    );
    return result.rows.length > 0;
  }

  async bind(profileId: string, workspaceId: string): Promise<void> {
    await this.database.query(
      `INSERT INTO selfhost_desktop_feed_workspace_bindings (profile_id, workspace_id) VALUES ($1, $2)
       ON CONFLICT DO NOTHING`,
      [profileId, workspaceId],
    );
  }

  async unbind(profileId: string, workspaceId: string): Promise<boolean> {
    const result = await this.database.query(
      `DELETE FROM selfhost_desktop_feed_workspace_bindings WHERE profile_id = $1 AND workspace_id = $2 RETURNING profile_id`,
      [profileId, workspaceId],
    );
    return result.rows.length > 0;
  }

  /** The user still belongs to the workspace's organization (install tokens die with the user). */
  async isMember(workspaceId: string, userId: string): Promise<boolean> {
    const result = await this.database.query(
      `SELECT 1 FROM selfhost_workspaces w
         JOIN selfhost_organization_memberships m ON m.organization_id = w.organization_id AND m.user_id = $2
        WHERE w.id = $1`,
      [workspaceId, userId],
    );
    return result.rows.length > 0;
  }

  /* ------------------------------------------------------ publisher tokens */

  /** Inserts a token and revokes all but the newest `keep` active ones (rotation). */
  async createPublisherToken(input: {
    profileId: string;
    tokenHash: string;
    tokenPrefix: string;
    label: string | null;
    now: Date;
    keep: number;
  }): Promise<PublisherTokenRow> {
    return this.database.transaction(async (tx) => {
      // Concurrent mints for one profile serialize here, so at most `keep` stay active.
      await tx.query(`SELECT id FROM selfhost_desktop_feed_profiles WHERE id = $1 FOR UPDATE`, [input.profileId]);
      const id = randomUUID();
      const inserted = await tx.query(
        `INSERT INTO selfhost_desktop_feed_publisher_tokens (id, profile_id, token_hash, token_prefix, label, created_at)
         VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
        [id, input.profileId, input.tokenHash, input.tokenPrefix, input.label, input.now.toISOString()],
      );
      await tx.query(
        `UPDATE selfhost_desktop_feed_publisher_tokens SET revoked_at = $3
          WHERE profile_id = $1 AND revoked_at IS NULL AND id NOT IN (
            SELECT id FROM selfhost_desktop_feed_publisher_tokens
             WHERE profile_id = $1 AND revoked_at IS NULL
             ORDER BY id = $4 DESC, created_at DESC, seq DESC LIMIT $2)`,
        [input.profileId, input.keep, input.now.toISOString(), id],
      );
      return publisherToken(inserted.rows[0]!);
    });
  }

  async publisherTokens(profileId: string): Promise<PublisherTokenRow[]> {
    const result = await this.database.query(
      `SELECT * FROM selfhost_desktop_feed_publisher_tokens WHERE profile_id = $1 ORDER BY created_at DESC, seq DESC`,
      [profileId],
    );
    return result.rows.map(publisherToken);
  }

  async revokePublisherToken(profileId: string, id: string, now: Date): Promise<PublisherTokenRow | null> {
    const result = await this.database.query(
      `UPDATE selfhost_desktop_feed_publisher_tokens SET revoked_at = COALESCE(revoked_at, $3)
        WHERE profile_id = $1 AND id = $2 RETURNING *`,
      [profileId, id, now.toISOString()],
    );
    return result.rows[0] ? publisherToken(result.rows[0]) : null;
  }

  async publisherTokenByHash(tokenHash: string): Promise<PublisherTokenRow | null> {
    const result = await this.database.query(
      `SELECT * FROM selfhost_desktop_feed_publisher_tokens WHERE token_hash = $1`,
      [tokenHash],
    );
    return result.rows[0] ? publisherToken(result.rows[0]) : null;
  }

  async touchPublisherToken(id: string, now: Date): Promise<void> {
    await this.database.query(
      `UPDATE selfhost_desktop_feed_publisher_tokens SET last_used_at = $2 WHERE id = $1`,
      [id, now.toISOString()],
    );
  }

  /* -------------------------------------------------------- install tokens */

  async createInstallToken(input: {
    tokenHash: string;
    tokenPrefix: string;
    userId: string;
    workspaceId: string;
    profileId: string;
    label: string | null;
    now: Date;
    expiresAt: Date;
  }): Promise<InstallTokenRow> {
    const result = await this.database.query(
      `INSERT INTO selfhost_desktop_feed_install_tokens
         (id, token_hash, token_prefix, user_id, workspace_id, profile_id, label, created_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [randomUUID(), input.tokenHash, input.tokenPrefix, input.userId, input.workspaceId, input.profileId,
        input.label, input.now.toISOString(), input.expiresAt.toISOString()],
    );
    return installToken(result.rows[0]!);
  }

  async installTokenByHash(tokenHash: string): Promise<InstallTokenRow | null> {
    const result = await this.database.query(
      `SELECT * FROM selfhost_desktop_feed_install_tokens WHERE token_hash = $1`,
      [tokenHash],
    );
    return result.rows[0] ? installToken(result.rows[0]) : null;
  }

  async installTokens(userId: string, workspaceId: string, profileId: string): Promise<InstallTokenRow[]> {
    const result = await this.database.query(
      `SELECT * FROM selfhost_desktop_feed_install_tokens
        WHERE user_id = $1 AND workspace_id = $2 AND profile_id = $3
        ORDER BY created_at DESC, id LIMIT 200`,
      [userId, workspaceId, profileId],
    );
    return result.rows.map(installToken);
  }

  async revokeInstallToken(input: {
    id: string;
    userId: string;
    workspaceId: string;
    profileId: string;
    now: Date;
  }): Promise<InstallTokenRow | null> {
    const result = await this.database.query(
      `UPDATE selfhost_desktop_feed_install_tokens SET revoked_at = COALESCE(revoked_at, $5)
        WHERE id = $1 AND user_id = $2 AND workspace_id = $3 AND profile_id = $4 RETURNING *`,
      [input.id, input.userId, input.workspaceId, input.profileId, input.now.toISOString()],
    );
    return result.rows[0] ? installToken(result.rows[0]) : null;
  }

  async touchInstallToken(id: string, now: Date): Promise<void> {
    await this.database.query(
      `UPDATE selfhost_desktop_feed_install_tokens SET last_used_at = $2 WHERE id = $1`,
      [id, now.toISOString()],
    );
  }

  /* -------------------------------------------------------------- releases */

  async release(profileId: string, version: string, executor: SqlExecutor = this.database): Promise<ReleaseRow | null> {
    const result = await executor.query(
      `SELECT ${RELEASE_COLUMNS} FROM selfhost_desktop_feed_releases WHERE profile_id = $1 AND version = $2`,
      [profileId, version],
    );
    return result.rows[0] ? release(result.rows[0]) : null;
  }

  async assets(releaseId: string, executor: SqlExecutor = this.database): Promise<AssetRow[]> {
    const result = await executor.query(
      `SELECT * FROM selfhost_desktop_feed_assets WHERE release_id = $1 ORDER BY position`,
      [releaseId],
    );
    return result.rows.map(asset);
  }

  /** Inserts a draft and its declared assets; null when the version already exists. */
  async createDraft(input: {
    profileId: string;
    version: string;
    channel: Channel;
    origin: "publish" | "import";
    notes: string;
    createBody: string | null;
    envelope: string | null;
    assets: DeclaredAsset[];
    now: Date;
  }): Promise<ReleaseRow | null> {
    return this.database.transaction(async (tx) => {
      const declared = input.assets.reduce((total, entry) => total + entry.size, 0);
      const inserted = await tx.query(
        `INSERT INTO selfhost_desktop_feed_releases
           (id, profile_id, version, channel, state, origin, notes, create_body, envelope, declared_bytes, created_at)
         VALUES ($1, $2, $3, $4, 'draft', $5, $6, $7, $8, $9, $10)
         ON CONFLICT (profile_id, version) DO NOTHING
         RETURNING ${RELEASE_COLUMNS}`,
        [randomUUID(), input.profileId, input.version, input.channel, input.origin, input.notes,
          input.createBody, input.envelope, declared, input.now.toISOString()],
      );
      const row = inserted.rows[0];
      if (!row) return null;
      for (const [position, entry] of input.assets.entries()) {
        await tx.query(
          `INSERT INTO selfhost_desktop_feed_assets
             (release_id, profile_id, position, name, platform, arch, os_floor, kind, size, sha256, asset_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
          [row.id, input.profileId, position, entry.name, entry.platform, entry.arch, entry.os_floor ?? null,
            entry.kind, entry.size, entry.sha256, entry.id ?? null],
        );
      }
      return release(row);
    });
  }

  /** An asset id already used in the profile (import keeps the signed ids). */
  async assetIdsInUse(profileId: string, ids: string[]): Promise<boolean> {
    if (ids.length === 0) return false;
    const result = await this.database.query(
      `SELECT 1 FROM selfhost_desktop_feed_assets WHERE profile_id = $1 AND asset_id = ANY($2::text[]) LIMIT 1`,
      [profileId, ids],
    );
    return result.rows.length > 0;
  }

  /** Records an upload; false when the name was uploaded concurrently. */
  async recordUpload(input: {
    releaseId: string;
    name: string;
    assetId: string;
    size: number;
    sha256: string;
    storageKey: string;
    now: Date;
  }): Promise<boolean> {
    const result = await this.database.query(
      `UPDATE selfhost_desktop_feed_assets
          SET asset_id = COALESCE(asset_id, $3), uploaded_size = $4, uploaded_sha256 = $5, storage_key = $6, uploaded_at = $7
        WHERE release_id = $1 AND name = $2 AND uploaded_at IS NULL
        RETURNING asset_id`,
      [input.releaseId, input.name, input.assetId, input.size, input.sha256, input.storageKey, input.now.toISOString()],
    );
    return result.rows.length > 0;
  }

  /** Bytes for the quota: published releases and open drafts of the profile. */
  async usage(profileId: string): Promise<{
    stableBytes: number;
    betas: Array<{ version: string; bytes: number }>;
    drafts: Array<{ id: string; bytes: number }>;
  }> {
    const result = await this.database.query<{ id: string; version: string; channel: Channel; state: string; declared_bytes: unknown }>(
      `SELECT id, version, channel, state, declared_bytes FROM selfhost_desktop_feed_releases
        WHERE profile_id = $1 ORDER BY publish_seq ASC NULLS LAST, created_at ASC`,
      [profileId],
    );
    let stableBytes = 0;
    const betas: Array<{ version: string; bytes: number }> = [];
    const drafts: Array<{ id: string; bytes: number }> = [];
    for (const row of result.rows) {
      const bytes = num(row.declared_bytes);
      if (row.state === "draft") drafts.push({ id: row.id, bytes });
      else if (row.channel === "stable") stableBytes += bytes;
      else betas.push({ version: row.version, bytes });
    }
    return { stableBytes, betas, drafts };
  }

  /**
   * Marks the draft published, moves the channel's current release when
   * asked, points its assets at their release objects (`releasePrefix`/name),
   * and prunes betas beyond `betaKeep` (beta publishes only). Returns null when
   * the release is no longer a draft, else the pruned releases' storage keys so
   * the caller can delete the objects.
   */
  async publish(input: {
    releaseId: string;
    profileId: string;
    channel: Channel;
    envelope: string;
    publishedAt: string;
    moveCurrent: boolean;
    betaKeep: number;
    releasePrefix: string;
  }): Promise<{ pruned: Array<{ version: string; storageKeys: string[] }> } | null> {
    return this.database.transaction(async (tx) => {
      const updated = await tx.query(
        `UPDATE selfhost_desktop_feed_releases
            SET state = 'published', envelope = $2, published_at = $3,
                publish_seq = nextval('selfhost_desktop_feed_publish_seq')
          WHERE id = $1 AND state = 'draft' RETURNING id`,
        [input.releaseId, input.envelope, input.publishedAt],
      );
      if (!updated.rows[0]) return null;
      await tx.query(
        `UPDATE selfhost_desktop_feed_assets SET storage_key = $2 || '/' || name WHERE release_id = $1`,
        [input.releaseId, input.releasePrefix],
      );
      if (input.moveCurrent) {
        await tx.query(
          `INSERT INTO selfhost_desktop_feed_current (profile_id, channel, release_id) VALUES ($1, $2, $3)
           ON CONFLICT (profile_id, channel) DO UPDATE SET release_id = EXCLUDED.release_id`,
          [input.profileId, input.channel, input.releaseId],
        );
      }
      const pruned: Array<{ version: string; storageKeys: string[] }> = [];
      if (input.channel === "beta") {
        const old = await tx.query<{ id: string; version: string }>(
          `SELECT id, version FROM selfhost_desktop_feed_releases
            WHERE profile_id = $1 AND channel = 'beta' AND state = 'published'
            ORDER BY publish_seq DESC OFFSET $2`,
          [input.profileId, input.betaKeep],
        );
        for (const row of old.rows) {
          const keys = await tx.query<{ storage_key: string | null }>(
            `SELECT storage_key FROM selfhost_desktop_feed_assets WHERE release_id = $1`,
            [row.id],
          );
          await tx.query(`DELETE FROM selfhost_desktop_feed_releases WHERE id = $1`, [row.id]);
          pruned.push({
            version: row.version,
            storageKeys: keys.rows.map((entry) => entry.storage_key).filter((key): key is string => !!key),
          });
        }
      }
      return { pruned };
    });
  }

  async currentEnvelope(profileId: string, channel: Channel): Promise<{ envelope: string; version: string } | null> {
    const result = await this.database.query<{ envelope: string; version: string }>(
      `SELECT r.envelope, r.version FROM selfhost_desktop_feed_current c
         JOIN selfhost_desktop_feed_releases r ON r.id = c.release_id
        WHERE c.profile_id = $1 AND c.channel = $2 AND r.state = 'published'`,
      [profileId, channel],
    );
    return result.rows[0] ?? null;
  }

  async publishedCount(profileId: string, channel: Channel): Promise<number> {
    const result = await this.database.query<{ count: unknown }>(
      `SELECT count(*) AS count FROM selfhost_desktop_feed_releases
        WHERE profile_id = $1 AND channel = $2 AND state = 'published'`,
      [profileId, channel],
    );
    return num(result.rows[0]?.count ?? 0);
  }

  /** Published envelopes, newest publish first; one extra row signals another page. */
  async publishedEnvelopes(profileId: string, channel: Channel, offset: number, limit: number): Promise<string[]> {
    const result = await this.database.query<{ envelope: string }>(
      `SELECT envelope FROM selfhost_desktop_feed_releases
        WHERE profile_id = $1 AND channel = $2 AND state = 'published'
        ORDER BY publish_seq DESC LIMIT $3 OFFSET $4`,
      [profileId, channel, limit, offset],
    );
    return result.rows.map((row) => row.envelope);
  }

  async versions(profileId: string, channel: Channel | null, offset: number, limit: number): Promise<Array<{
    version: string;
    channel: Channel;
    state: "draft" | "published";
    origin: "publish" | "import";
    publishedAt: string | null;
    current: boolean;
  }>> {
    const result = await this.database.query<Row>(
      `SELECT r.version, r.channel, r.state, r.origin, r.published_at,
              (c.release_id IS NOT NULL) AS current
         FROM selfhost_desktop_feed_releases r
         LEFT JOIN selfhost_desktop_feed_current c ON c.release_id = r.id
        WHERE r.profile_id = $1 AND ($2::text IS NULL OR r.channel = $2)
        ORDER BY r.created_at DESC, r.version DESC LIMIT $3 OFFSET $4`,
      [profileId, channel, limit, offset],
    );
    return result.rows.map((row) => ({
      version: row.version as string,
      channel: row.channel as Channel,
      state: row.state as "draft" | "published",
      origin: row.origin as "publish" | "import",
      publishedAt: isoOrNull(row.published_at),
      current: row.current === true,
    }));
  }

  /** A published asset of the profile, with its release's envelope; null otherwise. */
  async publishedAsset(profileId: string, assetId: string): Promise<(AssetRow & { envelope: string; version: string; channel: Channel }) | null> {
    const result = await this.database.query<Row>(
      `SELECT a.*, r.envelope, r.version, r.channel FROM selfhost_desktop_feed_assets a
         JOIN selfhost_desktop_feed_releases r ON r.id = a.release_id
        WHERE a.profile_id = $1 AND a.asset_id = $2 AND r.state = 'published'`,
      [profileId, assetId],
    );
    const row = result.rows[0];
    if (!row) return null;
    return { ...asset(row), envelope: row.envelope as string, version: row.version as string, channel: row.channel as Channel };
  }

  /* ----------------------------------------------------------------- audit */

  async audit(input: AuditInput): Promise<void> {
    await this.database.query(
      `INSERT INTO selfhost_desktop_feed_audit_events
         (id, organization_id, workspace_id, actor_kind, actor_id, action, profile, channel, version, asset_id,
          client_ip, status, detail)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::inet, $12, $13::jsonb)`,
      [randomUUID(), input.organizationId, input.workspaceId, input.actorKind, input.actorId, input.action,
        input.profile, input.channel, input.version, input.assetId,
        input.clientIp && isIP(input.clientIp) ? input.clientIp : null, input.status,
        JSON.stringify(input.detail ?? {})],
    );
  }
}
