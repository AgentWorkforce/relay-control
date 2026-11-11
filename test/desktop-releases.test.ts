import assert from "node:assert/strict";
import test from "node:test";
import {
  allowedDownloadUrl,
  describeAsset,
  GitHubDesktopReleases,
  loadDesktopReleasesRepo,
} from "../src/desktop-releases.js";

const REPO = "AgentWorkforce/relay-desktop-kind-releases";
const TAG = "v2026.11.1-beta.6";
const hex = (seed: string) => seed.repeat(64).slice(0, 64);

test("SELFHOST_DESKTOP_RELEASES_REPO: owner/repository only", () => {
  assert.equal(loadDesktopReleasesRepo({}), null);
  assert.equal(loadDesktopReleasesRepo({ SELFHOST_DESKTOP_RELEASES_REPO: " " }), null);
  assert.equal(loadDesktopReleasesRepo({ SELFHOST_DESKTOP_RELEASES_REPO: REPO }), REPO);
  for (const bad of ["owner", "owner/repo/x", "https://github.com/o/r", "o/..", "o r/x", "o/r?x", "../r"]) {
    assert.throws(() => loadDesktopReleasesRepo({ SELFHOST_DESKTOP_RELEASES_REPO: bad }), /owner\/repository/, bad);
  }
});

test("asset names map to the card's platform, arch, kind and macOS floor", () => {
  const name = (rest: string) => `Desktop-q7m2k9-2026.11.1-beta.6-${rest}`;
  assert.deepEqual(describeAsset(name("macOS-arm64.dmg")), { platform: "macOS", arch: "arm64", kind: "image" });
  assert.deepEqual(describeAsset(name("macOS15-x64.dmg")), { platform: "macOS", arch: "x64", kind: "image", os_floor: 15 });
  assert.deepEqual(describeAsset(name("Windows-arm64-Setup.exe")), { platform: "Windows", arch: "arm64", kind: "setup" });
  assert.deepEqual(describeAsset(name("Windows-x64.zip")), { platform: "Windows", arch: "x64", kind: "zip" });
  assert.deepEqual(describeAsset(name("Linux-x64.deb")), { platform: "Linux", arch: "x64", kind: "deb" });
  assert.deepEqual(describeAsset(name("Linux-arm64.tar.gz")), { platform: "Linux", arch: "arm64", kind: "tarball" });
  assert.deepEqual(describeAsset(name("Linux-x64-probe.tar.gz")), { platform: "Linux", arch: "x64", kind: "probe" });
  assert.deepEqual(describeAsset(name("Windows-arm64-probe.zip")), { platform: "Windows", arch: "arm64", kind: "probe" });
  for (const other of [name("Linux-x64.deb.sha256"), name("macOS-arm64.zip"), name("Windows-x64.exe"), "notes.txt", "Other-macOS-arm64.dmg"]) {
    assert.equal(describeAsset(other), null, other);
  }
});

test("only this repository's release downloads on GitHub hosts reach the browser", () => {
  const good = `https://github.com/${REPO}/releases/download/${TAG}/a.dmg`;
  assert.equal(allowedDownloadUrl(REPO, good), good);
  assert.equal(allowedDownloadUrl(REPO, `https://objects.githubusercontent.com/${REPO}/releases/download/${TAG}/a.dmg`),
    `https://objects.githubusercontent.com/${REPO}/releases/download/${TAG}/a.dmg`);
  for (const bad of [
    `http://github.com/${REPO}/releases/download/${TAG}/a.dmg`,
    `https://evil.example/${REPO}/releases/download/${TAG}/a.dmg`,
    `https://github.com/other/repo/releases/download/${TAG}/a.dmg`,
    `https://github.com/${REPO}/archive/a.dmg`,
    `https://github.com:8443/${REPO}/releases/download/${TAG}/a.dmg`,
    `https://user@github.com/${REPO}/releases/download/${TAG}/a.dmg`,
    `https://github.com/${REPO}/releases/download/${TAG}/a.dmg?x=1`,
    42,
  ]) {
    assert.equal(allowedDownloadUrl(REPO, bad), null, String(bad));
  }
});

type Fake = { calls: string[]; fetch: typeof fetch };

function fakeGitHub(options: {
  assets?: Array<{ name: string; size?: number; digest?: string; browser?: string }>;
  sidecars?: Record<string, string>;
  redirectHost?: string;
  listStatus?: number;
  releases?: unknown[];
} = {}): Fake {
  const calls: string[] = [];
  const assets = (options.assets ?? []).map((asset, index) => ({
    id: index + 1,
    name: asset.name,
    size: asset.size ?? (asset.name.endsWith(".sha256") ? 120 : 1000),
    url: `https://api.github.com/repos/${REPO}/releases/assets/${index + 1}`,
    browser_download_url: asset.browser ?? `https://github.com/${REPO}/releases/download/${TAG}/${asset.name}`,
    ...(asset.digest ? { digest: asset.digest } : {}),
  }));
  const releases = options.releases ?? [
    { tag_name: "v9.9.9-draft", draft: true, prerelease: false, published_at: null, assets: [] },
    { tag_name: TAG, draft: false, prerelease: true, published_at: "2026-11-11T19:21:31Z", assets },
  ];
  const fetchImpl = (async (input: string | URL) => {
    const url = new URL(String(input));
    calls.push(url.toString());
    if (url.origin === "https://api.github.com" && url.pathname === `/repos/${REPO}/releases`) {
      return new Response(JSON.stringify(releases), { status: options.listStatus ?? 200 });
    }
    const asset = /\/assets\/(\d+)$/.exec(url.pathname);
    if (url.origin === "https://api.github.com" && asset) {
      const id = Number(asset[1]);
      return new Response(null, {
        status: 302,
        headers: { location: `https://${options.redirectHost ?? "objects.githubusercontent.com"}/blob/${id}` },
      });
    }
    const blob = /^\/blob\/(\d+)$/.exec(url.pathname);
    if (blob) {
      const name = assets[Number(blob[1]) - 1]!.name;
      const body = options.sidecars?.[name];
      return body === undefined ? new Response("missing", { status: 404 }) : new Response(body, { status: 200 });
    }
    return new Response("unexpected", { status: 500 });
  }) as typeof fetch;
  return { calls, fetch: fetchImpl };
}

const DMG = "Desktop-q7m2k9-2026.11.1-beta.6-macOS-arm64.dmg";
const DEB = "Desktop-q7m2k9-2026.11.1-beta.6-Linux-x64.deb";
const EXE = "Desktop-q7m2k9-2026.11.1-beta.6-Windows-x64-Setup.exe";

test("latest release: mapped installers with sidecar checksums, newest non-draft, prerelease kept", async () => {
  const github = fakeGitHub({
    assets: [
      { name: DMG }, { name: `${DMG}.sha256` },
      { name: DEB, digest: `sha256:${hex("b")}` }, { name: `${DEB}.sha256` },
      { name: EXE }, // no sidecar: dropped
      { name: "notes.txt" },
    ],
    sidecars: { [`${DMG}.sha256`]: `${hex("a")}  ${DMG}\n`, [`${DEB}.sha256`]: `${hex("b")}\n` },
  });
  const releases = new GitHubDesktopReleases(REPO, github.fetch);
  const result = await releases.latest();
  assert.deepEqual(result.source, { kind: "github", repo: REPO, releasesUrl: `https://github.com/${REPO}/releases` });
  assert.equal(result.release?.version, "2026.11.1-beta.6");
  assert.equal(result.release?.tag, TAG);
  assert.equal(result.release?.prerelease, true);
  assert.deepEqual(result.release?.assets, [
    { id: DEB, name: DEB, platform: "Linux", arch: "x64", kind: "deb", size: 1000, sha256: hex("b"),
      url: `https://github.com/${REPO}/releases/download/${TAG}/${DEB}` },
    { id: DMG, name: DMG, platform: "macOS", arch: "arm64", kind: "image", size: 1000, sha256: hex("a"),
      url: `https://github.com/${REPO}/releases/download/${TAG}/${DMG}` },
  ]);
  // Only the API list, API asset URLs and the githubusercontent redirect targets.
  for (const call of github.calls) {
    const host = new URL(call).hostname;
    assert.ok(host === "api.github.com" || host.endsWith("githubusercontent.com"), call);
    if (host === "api.github.com") assert.ok(new URL(call).pathname.startsWith(`/repos/${REPO}/releases`), call);
  }
  // Cached: a second read makes no call.
  const before = github.calls.length;
  await releases.latest();
  assert.equal(github.calls.length, before);
});

test("checksum mismatches, foreign download URLs and off-host redirects drop the asset", async () => {
  const mismatch = fakeGitHub({
    assets: [{ name: DMG, digest: `sha256:${hex("c")}` }, { name: `${DMG}.sha256` }],
    sidecars: { [`${DMG}.sha256`]: hex("a") },
  });
  assert.deepEqual((await new GitHubDesktopReleases(REPO, mismatch.fetch).latest()).release?.assets, []);
  const wrongFile = fakeGitHub({
    assets: [{ name: DMG }, { name: `${DMG}.sha256` }],
    sidecars: { [`${DMG}.sha256`]: `${hex("a")}  other.dmg` },
  });
  assert.deepEqual((await new GitHubDesktopReleases(REPO, wrongFile.fetch).latest()).release?.assets, []);
  const foreign = fakeGitHub({
    assets: [{ name: DMG, browser: `https://evil.example/${REPO}/releases/download/${TAG}/${DMG}` }, { name: `${DMG}.sha256` }],
    sidecars: { [`${DMG}.sha256`]: hex("a") },
  });
  assert.deepEqual((await new GitHubDesktopReleases(REPO, foreign.fetch).latest()).release?.assets, []);
  const offHost = fakeGitHub({
    assets: [{ name: DMG }, { name: `${DMG}.sha256` }],
    sidecars: { [`${DMG}.sha256`]: hex("a") },
    redirectHost: "evil.example",
  });
  assert.deepEqual((await new GitHubDesktopReleases(REPO, offHost.fetch).latest()).release?.assets, []);
  assert.ok(offHost.calls.every((call) => !call.includes("evil.example")));
});

test("an upstream failure is release null (cached), never an error", async () => {
  const down = fakeGitHub({ listStatus: 503 });
  let now = 1_000;
  const releases = new GitHubDesktopReleases(REPO, down.fetch, () => now);
  assert.equal((await releases.latest()).release, null);
  assert.equal(down.calls.length, 1);
  await releases.latest();
  assert.equal(down.calls.length, 1);
  now += 5 * 60_000 + 1;
  await releases.latest();
  assert.equal(down.calls.length, 2);
  const throwing = new GitHubDesktopReleases(REPO, (async () => { throw new Error("offline"); }) as typeof fetch);
  assert.equal((await throwing.latest()).release, null);
  const empty = fakeGitHub({ releases: [] });
  assert.equal((await new GitHubDesktopReleases(REPO, empty.fetch).latest()).release, null);
});
