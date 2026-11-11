// Desktop downloads from a public GitHub releases repository
// (docs/desktop-feed.md, "GitHub releases source"). Off unless
// SELFHOST_DESKTOP_RELEASES_REPO is set; then GET /api/v1/desktop/releases
// serves the latest release in the downloads card's manifest shape.
//
// Bounds: Control calls only https://api.github.com/repos/<owner>/<repo>/releases
// (the list, and each checksum sidecar through its API asset URL, whose one
// redirect may go only to a *.githubusercontent.com host). No token. Every
// response is size-capped and the whole read has a deadline. Results are
// cached for five minutes. Any upstream failure is `release: null`, never 5xx.
//
// Integrity, not authenticity: a sidecar `.sha256` comes from the same
// release as the file it describes, so it detects corruption, not a hostile
// publisher. The signed Desktop feed remains the authenticated source.

export const RELEASES_REPO = /^[A-Za-z0-9-]+\/[A-Za-z0-9._-]+$/;
const API = "https://api.github.com";
const CACHE_MS = 5 * 60_000;
const DEADLINE_MS = 8_000;
const MAX_LIST_BYTES = 2 * 1024 * 1024;
const MAX_SIDECAR_BYTES = 1024;
const MAX_ASSETS = 64;
const SIDECAR_CONCURRENCY = 6;
const SIDECAR_HOST = /^(?:[a-z0-9-]+\.)*githubusercontent\.com$/;
const SHA256 = /^[0-9a-f]{64}$/;

export type ReleaseAsset = {
  id: string;
  name: string;
  platform: "macOS" | "Windows" | "Linux";
  arch: "arm64" | "x64";
  os_floor?: number;
  kind: "image" | "setup" | "zip" | "deb" | "tarball" | "probe";
  size: number;
  sha256: string;
  url: string;
};

export type DesktopReleases = {
  source: { kind: "github"; repo: string; releasesUrl: string };
  release: null | {
    version: string;
    tag: string;
    prerelease: boolean;
    published_at: string;
    assets: ReleaseAsset[];
  };
};

/** Validates SELFHOST_DESKTOP_RELEASES_REPO; unset or empty is null. */
export function loadDesktopReleasesRepo(env: Record<string, string | undefined>): string | null {
  const raw = env.SELFHOST_DESKTOP_RELEASES_REPO?.trim();
  if (!raw) return null;
  if (!RELEASES_REPO.test(raw) || raw.split("/").some((part) => part === "." || part === "..")) {
    throw new Error("SELFHOST_DESKTOP_RELEASES_REPO must be owner/repository");
  }
  return raw;
}

/**
 * Maps a release asset name to the card's fields, or null when it is not a
 * Desktop installer: `Desktop-<profile>-<version>-<OS>-<arch>[-probe|-Setup].<ext>`.
 */
export function describeAsset(name: string): Omit<ReleaseAsset, "id" | "name" | "size" | "sha256" | "url"> | null {
  const match = /-(macOS(\d{2})?|Linux|Windows)-(arm64|x64)(-probe|-Setup)?\.(dmg|deb|tar\.gz|exe|zip)$/.exec(name);
  if (!match || !name.startsWith("Desktop-")) return null;
  const [, os, floor, arch, suffix, ext] = match;
  const platform = (os!.startsWith("macOS") ? "macOS" : os) as ReleaseAsset["platform"];
  const kind: ReleaseAsset["kind"] | null = suffix === "-probe"
    ? (ext === "tar.gz" || ext === "zip" ? "probe" : null)
    : platform === "macOS" ? (ext === "dmg" ? "image" : null)
    : platform === "Windows" ? (ext === "exe" && suffix === "-Setup" ? "setup" : ext === "zip" ? "zip" : null)
    : ext === "deb" ? "deb" : ext === "tar.gz" ? "tarball" : null;
  if (!kind) return null;
  return { platform, arch: arch as ReleaseAsset["arch"], kind, ...(floor ? { os_floor: Number(floor) } : {}) };
}

/** Only a direct release download of this repository may reach the browser. */
export function allowedDownloadUrl(repo: string, value: unknown): string | null {
  if (typeof value !== "string") return null;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username || url.password || url.port || url.search || url.hash) return null;
  if (url.hostname !== "github.com" && url.hostname !== "objects.githubusercontent.com") return null;
  // GitHub treats owner/repository case-insensitively; its URLs use the
  // canonical spelling, which may differ from the configured one.
  const prefix = `/${repo}/releases/download/`;
  if (url.pathname.slice(0, prefix.length).toLowerCase() !== prefix.toLowerCase()) return null;
  return url.toString();
}

class Deadline extends Error {}

async function boundedText(response: Response, limit: number): Promise<string> {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > limit) {
    await response.body?.cancel().catch(() => {});
    throw new Error("too large");
  }
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) {
      await reader.cancel().catch(() => {});
      throw new Error("too large");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

type ApiAsset = {
  id: number; name: string; size: number; url: string; browser_download_url: string;
  digest?: string | null; updated_at?: string;
};
type ApiRelease = { tag_name: string; draft: boolean; prerelease: boolean; published_at: string | null; assets: ApiAsset[] };

function isApiRelease(value: unknown): value is ApiRelease {
  const row = value as ApiRelease | null;
  return !!row && typeof row === "object" && typeof row.tag_name === "string" && typeof row.draft === "boolean" &&
    typeof row.prerelease === "boolean" && Array.isArray(row.assets);
}

/** A sidecar could not be read (transport, status, size): the release is unavailable, not smaller. */
class SidecarUnavailable extends Error {}

export class GitHubDesktopReleases {
  #cache: { expiresAt: number; value: DesktopReleases } | null = null;
  #inflight: Promise<DesktopReleases> | null = null;
  /** The last complete answer, served again when a refresh fails (stale beats empty). */
  #lastGood: DesktopReleases | null = null;
  /** The release list's ETag: a 304 reply does not count against GitHub's unauthenticated quota. */
  #etag: string | null = null;
  /**
   * Verified sidecar digests by `<asset id>:<asset updated_at>`: a re-upload
   * changes both, so an unchanged asset is never re-read. Bounded.
   */
  readonly #digests = new Map<string, string>();

  constructor(
    readonly repo: string,
    private readonly fetchImpl: typeof fetch = globalThis.fetch,
    private readonly now: () => number = Date.now,
  ) {}

  private empty(): DesktopReleases {
    return { source: { kind: "github", repo: this.repo, releasesUrl: `https://github.com/${this.repo}/releases` }, release: null };
  }

  async latest(): Promise<DesktopReleases> {
    if (this.#cache && this.#cache.expiresAt > this.now()) return this.#cache.value;
    this.#inflight ??= this.load().finally(() => {
      this.#inflight = null;
    });
    return this.#inflight;
  }

  private async load(): Promise<DesktopReleases> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(new Deadline()), DEADLINE_MS);
    let value: DesktopReleases;
    try {
      value = await this.read(controller.signal);
      if (value.release) this.#lastGood = value;
    } catch {
      // An outage (or the quota) serves the last complete answer, else null.
      value = this.#lastGood ?? this.empty();
    } finally {
      clearTimeout(timer);
    }
    // Failures are cached too, so an outage costs one call per five minutes.
    this.#cache = { expiresAt: this.now() + CACHE_MS, value };
    return value;
  }

  private async api(path: string, signal: AbortSignal, accept: string, etag?: string | null): Promise<Response> {
    const url = new URL(`${API}/repos/${this.repo}/releases${path}`);
    if (url.origin !== API || !url.pathname.startsWith(`/repos/${this.repo}/releases`)) throw new Error("bad path");
    return this.fetchImpl(url, {
      redirect: "manual",
      signal,
      headers: {
        accept,
        "user-agent": "agent-relay-selfhost",
        "x-github-api-version": "2022-11-28",
        ...(etag ? { "if-none-match": etag } : {}),
      },
    });
  }

  private async read(signal: AbortSignal): Promise<DesktopReleases> {
    const list = await this.api("?per_page=10", signal, "application/vnd.github+json", this.#lastGood ? this.#etag : null);
    if (list.status === 304 && this.#lastGood) {
      await list.body?.cancel().catch(() => {});
      return this.#lastGood;
    }
    if (list.status !== 200) {
      await list.body?.cancel().catch(() => {});
      throw new Error(`list ${list.status}`);
    }
    const etag = list.headers.get("etag");
    const releases: unknown = JSON.parse(await boundedText(list, MAX_LIST_BYTES));
    if (!Array.isArray(releases)) throw new Error("list shape");
    // Newest first; drafts are never public, but skip them defensively.
    const release = releases.find((row): row is ApiRelease => isApiRelease(row) && !row.draft);
    if (!release) return this.empty();
    const byName = new Map(release.assets.slice(0, MAX_ASSETS * 2).map((asset) => [asset.name, asset]));
    const candidates = [...byName.values()].flatMap((asset) => {
      const described = describeAsset(asset.name);
      const url = allowedDownloadUrl(this.repo, asset.browser_download_url);
      const sidecar = byName.get(`${asset.name}.sha256`);
      return described && url && sidecar && Number.isSafeInteger(asset.size) && asset.size > 0
        ? [{ asset, described, url, sidecar }] : [];
    }).slice(0, MAX_ASSETS);
    const assets: ReleaseAsset[] = [];
    let next = 0;
    await Promise.all(Array.from({ length: Math.min(SIDECAR_CONCURRENCY, candidates.length) }, async () => {
      while (next < candidates.length) {
        const { asset, described, url, sidecar } = candidates[next++]!;
        const key = `${sidecar.id}:${sidecar.updated_at ?? ""}`;
        let sha256 = this.#digests.get(key) ?? null;
        if (!sha256) {
          // Throws SidecarUnavailable on any read failure: the whole release is
          // then unavailable rather than silently missing installers.
          sha256 = await this.sidecar(sidecar, asset.name, signal);
          if (sha256) {
            if (this.#digests.size >= MAX_ASSETS * 4) this.#digests.clear();
            this.#digests.set(key, sha256);
          }
        }
        if (!sha256) continue;
        // GitHub's own digest, when present, must agree with the sidecar.
        if (typeof asset.digest === "string" && asset.digest.startsWith("sha256:") && asset.digest.slice(7) !== sha256) continue;
        assets.push({ id: asset.name, name: asset.name, ...described, size: asset.size, sha256, url });
      }
    }));
    assets.sort((a, b) => a.name.localeCompare(b.name));
    this.#etag = etag;
    return {
      source: this.empty().source,
      release: {
        version: release.tag_name.replace(/^v/, ""),
        tag: release.tag_name,
        prerelease: release.prerelease,
        published_at: release.published_at ?? "",
        assets,
      },
    };
  }

  /** The 64-hex digest from `<name>.sha256` (`<hex>  <name>` or just `<hex>`). */
  /**
   * The digest, or null when the sidecar's content does not verify this asset
   * (that asset is dropped). Throws SidecarUnavailable when it cannot be read.
   */
  private async sidecar(sidecar: ApiAsset, name: string, signal: AbortSignal): Promise<string | null> {
    if (!Number.isSafeInteger(sidecar.id) || sidecar.size > MAX_SIDECAR_BYTES) return null;
    let text: string;
    try {
      const first = await this.api(`/assets/${sidecar.id}`, signal, "application/octet-stream");
      let response = first;
      if (first.status === 301 || first.status === 302 || first.status === 307 || first.status === 308) {
        await first.body?.cancel().catch(() => {});
        const location = first.headers.get("location");
        const target = location ? new URL(location, API) : null;
        // An off-host redirect is a refusal of this asset, not an outage.
        if (!target || target.protocol !== "https:" || !SIDECAR_HOST.test(target.hostname)) return null;
        response = await this.fetchImpl(target, { redirect: "error", signal, headers: { "user-agent": "agent-relay-selfhost" } });
      }
      if (response.status !== 200) {
        await response.body?.cancel().catch(() => {});
        throw new SidecarUnavailable(`sidecar ${response.status}`);
      }
      text = (await boundedText(response, MAX_SIDECAR_BYTES)).trim();
    } catch (error) {
      if (error instanceof SidecarUnavailable) throw error;
      throw new SidecarUnavailable(error instanceof Error ? error.message : "sidecar");
    }
    const [digest, file] = text.split(/\s+/);
    const hex = digest?.toLowerCase() ?? "";
    if (!SHA256.test(hex)) return null;
    if (file && file.replace(/^\*/, "") !== name) return null;
    return hex;
  }
}
