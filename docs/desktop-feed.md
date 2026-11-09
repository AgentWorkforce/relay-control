# Desktop feed

Status: implemented in relaycontrol (approved 2026-11-07; the rules marked
from the doc and proposed below are both approved). Deviations from the
contract are listed under "Implementation" and in `openapi.yaml`.

The feed is a relaycontrol-only service: one profile per installation, signed
with an AWS KMS Ed25519 key and stored in a private S3 bucket under a
per-profile prefix. It is off (every feed route answers 404) unless both
`SELFHOST_DESKTOP_FEED_SIGNER` and `SELFHOST_DESKTOP_FEED_STORAGE` are set.
This document began as the contract that translates the relay-desktop design
`docs/enterprise-distribution.md` at `21e61026` (the "source design" below)
into:

| Artifact | Path |
|---|---|
| OpenAPI operations, schemas, responses and security schemes (tag "Desktop feed") | `openapi.yaml`, paths under `/api/v1/desktop/feed/` |
| Manifest schema (JSON Schema 2020-12, strict, self-contained) | `docs/specs/desktop-feed-manifest.schema.json` |
| Envelope schema (embeds an identical copy of the manifest schema) | `docs/specs/desktop-feed-envelope.schema.json` |
| Fixtures | `test/fixtures/desktop-feed/` |
| Contract tests and reference decision functions | `test/desktop-feed-contract.test.ts` |
| Implementation | `src/desktop-feed/`, `src/aws/sigv4.ts`, `migrations/0013_desktop_feed.sql` |
| End-to-end and AWS signing tests | `test/desktop-feed.test.ts`, `test/desktop-feed-aws.test.ts` |
| RFC 8785 canonicaliser | `src/desktop-feed/canonical.ts` (re-exported by `test/support/jcs.ts`) |
| Strict I-JSON parser (duplicate names, lone surrogates) | `src/desktop-feed/strict-json.ts` (re-exported by `test/support/strict-json.ts`) |

## Implementation

### Configuration

| Variable | Meaning |
|---|---|
| `SELFHOST_DESKTOP_FEED_SIGNER` | `awskms` (deployed sites) or `memory` (tests and development: a throwaway key per process, refused when `NODE_ENV=production`). Must be set together with `_STORAGE`; setting only one is a startup error |
| `SELFHOST_DESKTOP_FEED_STORAGE` | `s3` (deployed sites) or `memory` (tests and development, refused when `NODE_ENV=production`) |
| `SELFHOST_DESKTOP_FEED_KMS_REGION` | `awskms`: region of the keys; default `AWS_REGION` |
| `SELFHOST_DESKTOP_FEED_KMS_KEY_ALIASES` | `awskms`: JSON object of profile id to KMS alias, one key per profile, for example `{"x7k2q":"alias/desktop-feed-x7k2q"}`. Each key has spec `ECC_NIST_EDWARDS25519`, usage `SIGN_VERIFY`. Calls are `Sign` with `MessageType=RAW`, `SigningAlgorithm=ED25519_SHA_512`, and `GetPublicKey` (cached) |
| `SELFHOST_DESKTOP_FEED_KEY_LABEL` | The `<label>` in `key_id` `fk_<profile>_<label>`. Default `k1` for `awskms` and `dev` for `memory` |
| `SELFHOST_DESKTOP_FEED_PUBLISHER_TOKEN_HASHES` | Optional JSON object of profile id to an array of token sha256 hex digests, for CI tokens (`sh_dfp_...`) provisioned outside the admin routes. Only the hash is configured; removing an entry and restarting revokes the token |
| `SELFHOST_DESKTOP_FEED_S3_BUCKET` | `s3`: private bucket name, without dots (TLS on the virtual-hosted host). Its virtual-hosted host `<bucket>.s3.<region>.amazonaws.com` is signed into `download_hosts` |
| `SELFHOST_DESKTOP_FEED_S3_REGION` | `s3`: bucket region; default `AWS_REGION`, then `SELFHOST_DESKTOP_FEED_KMS_REGION` |
| `SELFHOST_DESKTOP_FEED_S3_PREFIX` | `s3`: key prefix, default `desktop-feed` (also when set empty or to `/`). Segments of `[A-Za-z0-9._-]` separated by `/`; `.` and `..` segments and any other character are a startup error |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` | Optional static credentials. Unset: the EC2 instance role through IMDSv2, cached until five minutes before expiry |

The role needs `kms:Sign` and `kms:GetPublicKey` on each profile's key, and
`s3:PutObject`, `s3:GetObject` and `s3:DeleteObject` on
`<prefix>/profiles/*`. Requests are SigV4 (`src/aws/sigv4.ts`). Every S3 write
asks for SSE-S3 (`AES256`); block public access on the bucket.

Objects live under `<prefix>/profiles/<profile>/`: `drafts/<version>/<name>`
until publish, `releases/<version>/<name>` once published, and
`manifests/<channel>.json`, a copy of the channel's current envelope written
after the commit. Postgres stays the source of truth and serves the envelope
byte for byte.

KMS caps a `RAW` message at 4096 bytes. `POST /releases` computes the exact
canonical size and answers 422 `manifest_too_large` with `canonical_bytes` and
`max_canonical_bytes` before anything is uploaded, and publish checks again.
A cloud profile's release is trimmed to fit: 16 assets (the floored macOS
images, the Linux tarballs and debs, the Windows zips and setups, the Linux and
Windows probe bundles the headless installers use, `install.sh`, `install.ps1`)
with signed notes of about 300 bytes, a short summary that links to the full
notes. The publisher enforces the asset set and the notes budget; this server
enforces only the total, so the set can change without a server release. Asset
ids are `a_` plus 8
base62 characters for the same reason; they are not secrets, since every lookup
is scoped to an entitled profile.

`GET /api/v1/desktop/profiles` (session credential, no profile header) lists
the profiles the current workspace may read, so the downloads page can name
one.

### Source layout

| File | Role |
|---|---|
| `src/desktop-feed/routes.ts` | Feed and admin routes, credential resolution, precedence, rate limits, audit |
| `src/desktop-feed/store.ts` | Postgres access (profiles, bindings, tokens, releases, assets, audit) |
| `src/desktop-feed/signer.ts` | `AwsKmsDesktopFeedSigner`, `MemoryDesktopFeedSigner` |
| `src/desktop-feed/storage.ts` | `S3DesktopFeedStorage` (streamed PUT, ranged GET, presigned GET), `MemoryDesktopFeedStorage` |
| `src/desktop-feed/schemas.ts` | The manifest, envelope and draft-create schemas, kept equal to `docs/specs/` and `openapi.yaml` by `test/desktop-feed.test.ts` |
| `src/desktop-feed/canonical.ts`, `strict-json.ts` | RFC 8785 and strict I-JSON |
| `migrations/0013_desktop_feed.sql` | `selfhost_desktop_feed_*` tables |

### Profile administration

Profiles, workspace bindings and publisher tokens are managed through admin
routes (bootstrap token, or an organization owner or admin). The `/cloud`
session cookie is accepted, so a non-GET admin request without a bearer
token must pass the existing browser-origin check or it answers 403
`csrf_rejected`:

| Route | Effect |
|---|---|
| `GET /api/v1/organizations/{org}/desktop-feed/profiles` | List profiles with bindings, keys and publisher-token summaries |
| `POST /api/v1/organizations/{org}/desktop-feed/profiles` | Register `{id, asset_prefix, quota_bytes?, beta_keep?, public_keys?}`; `public_keys` are extra keys accepted on import. 201 with `signing_key {key_id, public_key}` (base64 of the raw 32-byte Ed25519 key) |
| `GET .../profiles/{id}` | One profile |
| `PUT` / `DELETE .../profiles/{id}/workspaces/{workspaceId}` | Bind or unbind a workspace of the organization |
| `POST .../profiles/{id}/publisher-tokens` | Mint `{label?}`; the `sh_dfp_` value is returned once (201) and stored as a SHA-256 hash. Two tokens stay active; minting a third revokes the oldest |
| `DELETE .../profiles/{id}/publisher-tokens/{tokenId}` | Revoke (idempotent) |

### Deviations from the contract

1. **Admin routes exist.** The draft left profile registry, binding and
   publisher-token issue to an admin tool; they are the routes above. They
   are not in `openapi.yaml`.
2. **One KMS key per profile.** Keys are addressed by alias; registering a
   profile with no configured alias is 409 `signing_key_not_configured`.
3. **Self-host signs.** The contract said self-hosted deployments only import.
   The approved shape signs on this site with KMS; the private key never
   leaves KMS, and a key in Postgres is still not accepted. Import works as
   drafted.
4. **Storage keys** are `<prefix>/profiles/<profile>/{drafts,releases}/<version>/<name>`
   and `<prefix>/profiles/<profile>/manifests/<channel>.json`, rather than
   `desktop-feed/<profile>/<version>/<name>`: one prefix per profile.
5. **Envelopes are stored verbatim in Postgres** (the release row), not in the
   object store; only assets go to S3.
6. **`download_hosts`** of a hosted publish is filled in by the server from
   the storage backend (empty for `memory`); imports keep the signed list.
   `download-url` is 501 `no_object_storage` when the storage has no host,
   the host is not in the release's `download_hosts`, or presigning fails.
7. **413 `payload_too_large`** (the app-wide code, not in
   `DesktopFeedErrorCode`) answers a JSON body over 1 MiB on draft create,
   import, publish and install-token create. Those operations keep
   `x-status: proposed` in `openapi.yaml`.
8. **Malformed JSON** on draft create is 422 `invalid_release`, on import 422
   `manifest_invalid` (the status matrix names no code for it).
9. **Install-token list and revoke** count against the read bucket (60 per
   minute); the limits table names no bucket for them.
10. **A user no longer in the organization** makes their install tokens 401
    `token_revoked`.
11. **Mixed credentials:** every token kind uses `Authorization`, so the only
    detectable mix is a bearer plus the `/cloud` session cookie.
12. **All feed responses** carry `Cache-Control: no-store`, not only the
    manifest.
13. **Not implemented:** `gcpkms`, `gcs` and `postgres-lo` backends, the audit
    retention prune and the `desktop_feed.denied` burst alert, the mirror
    token (path (b)) and `relayctl desktop-feed` commands.

## Contract

Every rule below is marked **from the doc** (stated in the source design) or
**proposed** (filled in here). Both kinds are approved and implemented. In
`openapi.yaml`, `x-status: proposed` remains only on the operations listed in
deviation 7 above, and the signer provider is `awskms`.

The source design writes paths as `{site}/cloud/api/v1/desktop/feed/...`. This
document uses `/api/v1/desktop/feed/...` like the rest of `openapi.yaml`.
Publisher and install-script callers use the same API base without the
`/cloud` mount, and only the browser session needs `/cloud` (see the
credential matrix).

## Isolation

- **From the doc.** Every feed request carries `X-Agent-Relay-Profile: <id>`,
  the compiled profile id. Cloud answers members of bound workspaces only.
  Storage is per-profile prefixes in a private bucket with no listing, and
  each profile has its own signing key.
- **From the doc.** 403, never 404. A profile not bound to the caller's
  workspace and a profile id the server does not know both answer
  `403 {"error":"not_entitled"}`. 404 `no_release` is reserved for a channel
  of an *entitled* profile with no release yet.
- **Proposed.** The header is required on every operation, including
  publisher and install-token operations. A missing header is 400
  `profile_header_required`. The tests check this for all 11 operations.
- **Proposed.** Asset ids are looked up only within the header's profile.
  An asset id that is unknown, belongs to a draft, or belongs to another
  profile answers 403 `not_entitled`, never 404. This keeps another profile's
  ids from being probed.
- **Proposed.** Entitlement is checked before request validation and before
  any resource lookup. An unentitled caller therefore learns nothing,
  including whether a channel is empty or a query is malformed.
- **Proposed.** Publish binding (below) ties every stored object to
  `profiles/<profile_id>/releases/<version>/<name>` with a single-segment
  name, so a publisher token for one profile cannot write under another
  profile's prefix.

Check precedence, the same for every operation (proposed). A 429 may
interrupt at any step.

1. More than one credential: 400 `mixed_credentials`.
2. No credential, or an unknown one: 401 `unauthenticated`. Expired install
   token: 401 `token_expired`. Revoked token: 401 `token_revoked`.
3. Credential kind not accepted here: 403 `wrong_credential`.
4. Cookie on an unsafe method that fails the existing browser-origin check:
   403 `csrf_rejected`.
5. Header missing: 400 `profile_header_required`.
6. Not entitled to the header's profile: 403 `not_entitled`.
7. Request validation: 400 `invalid_request`. Publisher bodies use 422
   instead.
8. Resource checks:
   - 404 `no_release` (channel reads only).
   - 403 `not_entitled` (asset ids).
   - 404 `draft_not_found` / 409 (publisher).
   - 501 `no_object_storage`.
   - 416 `range_not_satisfiable`.

## Status matrix

| Status | Code(s) | Where | Origin |
|---|---|---|---|
| 200 / 201 | | every operation | from the doc |
| 206 | | asset stream with a single `Range` | from the doc |
| 400 | `mixed_credentials`, `profile_header_required`, `invalid_request` | every operation | proposed |
| 401 | `unauthenticated`, `token_expired`, `token_revoked` | every operation | 401 from the doc; codes proposed |
| 403 | `not_entitled` | reads: unbound or unknown profile, or an asset not in the profile. Publisher: header names another or unknown profile | from the doc (reads); proposed (publisher) |
| 403 | `wrong_credential` | a credential kind the operation does not accept | proposed |
| 403 | `csrf_rejected` | cookie on an unsafe method, failing the existing origin check | proposed (reuses the existing code) |
| 404 | `no_release` | manifest and read listing only: an entitled profile's channel has no published release | from the doc |
| 404 | `draft_not_found`, `install_token_not_found` | upload or publish to a version with no draft; revoking an unknown token | proposed |
| 409 | `version_exists`, `not_a_draft`, `asset_conflict` | create, import, upload, publish | from the doc (409s); codes proposed |
| 416 | `range_not_satisfiable` | stream | proposed |
| 422 | `invalid_release`, `expected_assets_required`, `invalid_asset`, `asset_not_declared`, `asset_mismatch`, `assets_incomplete`, `quota_exceeded`, `manifest_too_large`, `manifest_invalid`, `profile_mismatch`, `key_id_unknown`, `signature_invalid` | publisher operations (`manifest_too_large`: hosted publish only) | 422s from the doc; codes, `quota_exceeded` and `manifest_too_large` proposed |
| 429 | `rate_limited`, header `Retry-After` (required) | every operation | from the doc (429, rate limits on every endpoint); body proposed |
| 501 | `no_object_storage` | `download-url` | from the doc |
| 503 | `signer_unavailable` | hosted publish only; import never signs | proposed |
| 3xx | none | no feed operation defines a redirect | proposed |

Error bodies keep the API's existing shape, `{"error": code, "message"?}`
(`HttpError` in `src/app.ts`), with `additionalProperties: false`. Four
codes carry extra fields:

- `assets_incomplete` has `missing` and `mismatched`.
- `quota_exceeded` has `quota_bytes`, `used_bytes` and `required_bytes`.
- `manifest_too_large` has `canonical_bytes` and `max_canonical_bytes`.
- `rate_limited` has `retry_after_seconds`.

`DesktopFeedErrorCode` lists all 31 codes. The tests check that every code is
used by some response and that every response's codes are in the enum.

## Credential matrix and the mixed-credential rule

| Operation | Workspace bearer | Install token | Browser session (`/cloud` only) | Publisher token |
|---|---|---|---|---|
| `GET /manifest` | yes | yes | yes | 403 `wrong_credential` |
| `GET /releases` (read, `include_drafts` absent or false) | yes | yes | yes | 403 `wrong_credential` |
| `GET /releases?include_drafts=true` (version listing) | 403 | 403 | 403 | yes |
| `POST /assets/{id}/download-url` | yes | yes | yes, plus origin check | 403 |
| `GET /assets/{id}` | yes | yes | yes | 403 |
| `POST /releases`, `POST /releases/import`, `PUT .../assets/{name}`, `POST .../publish` | 403 | 403 | 403 | yes |
| `GET`/`POST /install-tokens`, `DELETE /install-tokens/{id}` | 403 | 403 | yes, plus origin check on POST and DELETE | 403 |

- **From the doc.** Reads accept a workspace bearer (the desktop-core
  session) or an install token. The downloads page uses the browser session.
  The publisher token "can read nothing else" except the version listing. The
  install token is "accepted by the read endpoints only".
- **Proposed.** A request with more than one credential is refused with 400
  `mixed_credentials`, never merged. Examples are a bearer plus the session
  cookie, or an install token plus a bearer. This deliberately departs from
  `authenticate()` in `src/app.ts`, where the bearer wins over the cookie.
  For a feed the two credentials can name different workspaces, and picking
  one silently would make entitlement depend on header order. The check runs
  before validity, so an expired token sent next to a valid one is still
  400.
- **Proposed.** Install tokens use the `installToken` scheme: `Authorization:
  Bearer sh_dfi_...`. Publisher tokens use `publisherToken`: `Authorization:
  Bearer sh_dfp_...`. Both are opaque tokens from `opaqueToken(prefix)` and
  are stored only as `hashSecret` (`src/crypto.ts`), like `sh_wk_` workspace
  tokens. The prefix lets the server pick the credential kind before any
  lookup.
- **Proposed.** `x-desktop-feed-credentials` on each operation lists the
  accepted kinds. The tests check that it equals the operation's `security`
  list.

## Install token and publisher token lifecycle

### Install token

- **From the doc.** Minted on the downloads page behind the browser session.
  Scope is feed read for that profile only, lifetime 1 hour, revocable from
  the same page. Revoked together with the user.
- **Proposed.**
  - `POST /install-tokens` returns the token once, along with `profile`,
    `workspace_id`, `expires_at` (created + 1 h) and the command
    `AGENT_RELAY_INSTALL_TOKEN=<token> bash install.sh`.
  - `GET /install-tokens` lists the caller's own tokens for the header's
    profile. Each entry shows `token_prefix` (first 11 characters) and
    `status` (`active`, `expired` or `revoked`) and never the token.
  - `DELETE /install-tokens/{id}` revokes a token. An unknown id, or another
    user's token, is 404 `install_token_not_found`.
  - A token is bound to the user, the workspace and the profile. It stops
    working when the user is removed, when the workspace loses its binding
    (403 `not_entitled`), at expiry (401 `token_expired`) and at revocation
    (401 `token_revoked`).
  - The fixtures cover the expired and revoked bodies.
- **Procedures to be provided by the admin tool.** These are bulk revocation
  for a user or workspace, a listing across users for an admin, and cleanup
  of expired rows. No endpoint is drafted for them.

### Publisher token

- **From the doc.** One per profile. Write-only on that profile's feed plus
  the version listing. Rotatable. Never a workspace user's token. Stored as
  the `desktop-<id>` environment secret `DESKTOP_FEED_PUBLISHER_TOKEN`. The
  registry keeps `publisher_token_hash`.
- **Proposed.** During rotation a profile may hold two token hashes at once
  (current and next), so CI can switch without a gap. A publisher token whose
  profile differs from the header is 403 `not_entitled`.
- **Procedures to be provided by the admin tool.** These are issue, rotate,
  revoke, and issuing an on-prem deployment's publisher token for path (a).
  The contract defines how the token is used, not how it is issued. No
  issuing endpoint is drafted.

## Open question 2: which workspace counts

**Proposal: the signed-in workspace only.** The feed is answered when the
workspace the credential is signed in to is bound to the profile. Another of
the user's workspaces being bound does not count.

Reasoning:

- Every credential already names one workspace. The workspace bearer's
  principal carries `workspaceId`, an install token is minted inside one
  workspace, and the browser session has a current workspace. "Any of the
  user's workspaces" would need a membership scan on every read, including
  every update poll.
- The source design's isolation rule is "Cloud only answers members of bound
  workspaces". Answering through an unrelated workspace would let one
  workspace's session read a feed on the strength of a membership the app
  cannot see. The user would then lose updates silently when that other
  membership ends.
- It matches the app's 403 message ("This workspace is not entitled..."). The
  fix it suggests, switching workspace, is something the user can act on.
- Audit records name the workspace that was actually used.

Cost: a user in several workspaces must sign the app in to a bound one. The
downloads page shows the profile of the current workspace only.

## Open question 4: freeze protection

**Proposal: not in Phase 0. The client relies on `published_at` plus its
no-downgrade rule. A countersigned freshness statement is a follow-up.**

- Publish-time signing cannot detect a replayed older manifest. The source
  design bounds the risk with TLS to the built-in site and the audit log. The
  client already refuses a version that is not newer than the installed one,
  and `version`, `channel` and `profile` are signed, so a replay can only
  freeze a device, never downgrade it.
- `published_at` is signed and set by the signer. A client may surface "no
  update since <date>" and may refuse a manifest whose `published_at` is
  older than the one it last accepted. That is a monotonic check that needs
  no online key.
- A countersigned freshness statement (a short-lived signature over the
  current manifest's digest) needs an online signing key with high
  availability. The signer provider is still unresolved (below), so the
  contract leaves room without committing. A future `freshness` field would
  go in a new envelope `schema` version, and the current schemas reject
  unknown fields. Decides: Cloud team.

## Open question 6: retention and quota

**Proposal (numbers):**

- Every stable release is kept.
- The last **10** published betas are kept.
- Each profile has a quota of **20 GB** (20,000,000,000 bytes, decimal).

**Proposal (deterministic rule):**

| Rule | Origin |
|---|---|
| Retention keeps every stable and the last N betas | from the doc |
| N = 10, quota 20 GB | proposed |
| Stables are never deleted automatically, whatever the quota pressure | proposed (follows "every stable") |
| Betas are pruned only when a beta is published. After it publishes, the newest 10 betas by publish order are kept and older ones (envelope and assets) are deleted. Nothing is pruned on a timer, on a stable publish or on a quota check | proposed |
| Usage = bytes of retained published releases + declared bytes of every open draft | proposed |
| Quota is checked at draft creation and at import (reserving the declared total, before any upload) and again at publish. The projection subtracts the betas this release's publish would prune (betas only) | proposed |
| Over quota: the request is refused with **422 `quota_exceeded`** and `quota_bytes`, `used_bytes` and `required_bytes`. Nothing is deleted to make room. The fix is an admin action: delete a draft, delete an old stable, or raise the quota | proposed |
| Publish order: complete asset set (422 `assets_incomplete`), then quota, then the signer's canonical byte limit (hosted only, 422 `manifest_too_large`), then sign (or store an import verbatim), then mark published, then prune betas | proposed |

**Why 422 and not 507.** The refusal is a policy decision about this request
against this profile's allowance. The server is not short of storage.

- 507 Insufficient Storage comes from WebDAV (RFC 4918) and describes the
  server being unable to store the representation.
- A 5xx tells CI and HTTP clients to retry. Retrying a quota refusal can never
  succeed without an admin action, and auto-retry would hammer the endpoint.
- 422 keeps the refusal with the other "your release cannot be accepted"
  answers, and the publish job already fails on 4xx.

The tests (`publisher: quota and retention are deterministic`) check that 507
is not documented on any publisher operation.

The listing shows quota, retention and the signer's byte limit. `GET
/releases?include_drafts=true` with the publisher token returns `limits:
{quota_bytes, used_bytes, max_canonical_bytes, retention: {stable: "all",
beta_keep: 10}}`, so the publish job can report headroom before uploading.
`max_canonical_bytes` (`DesktopFeedLimits`, proposed) is always present: the
configured signer's declared limit on the RFC 8785 canonical bytes of the
manifest (4096 for `awskms`), or null when the signer declares none. The job
can canonicalise its manifest and compare before creating the draft.

## Publish binding

- **From the doc.** The publisher call sequence is: `POST /releases`
  (`{version, channel, notes}`), then `PUT .../assets/{name}` with
  `X-Content-SHA256` and `Content-Length`, then `POST .../publish` (`{latest:
  true}` for stable). Publish signs only after every declared asset has been
  uploaded.
- **Proposed: `expected_assets`.** The source design says publish fails
  "unless every asset the draft declared has been uploaded", but its create
  body declares nothing. The draft therefore declares its complete asset set
  up front:
  - `expected_assets` is required and non-empty, with at most 64 entries and
    unique names.
  - Each entry has `name`, `platform`, `arch`, `os_floor`?, `kind`, `size`
    and `sha256`, using the same rules as the manifest asset.
  - A missing or empty list is 422 `expected_assets_required`.
  - A client-supplied `id` is 422 `invalid_asset`. Ids are assigned by the
    server.
  - The asset set is never inferred at publish.
- **Proposed: name binding.** Every asset except the `install-script` must be
  named `<asset_prefix>-<version>-...`, where `asset_prefix` comes from the
  profile registry (proposed registry field; `Desktop-x7k2q` in the
  fixtures). Another profile's prefix, another version or a path is 422
  `invalid_asset`. Names are a single segment
  (`^[A-Za-z0-9][A-Za-z0-9_+-]*(?:\.[A-Za-z0-9_+-]+)*$`), so `..` and `/`
  cannot occur.
- **Proposed: upload checks, in order.**
  1. The draft exists (404 `draft_not_found`) and is still a draft (409
     `not_a_draft`).
  2. The name is declared (422 `asset_not_declared`).
  3. The name has not already been uploaded. Identical bytes are 200 with no
     change; different bytes are 409 `asset_conflict`.
  4. `Content-Length` and `X-Content-SHA256` equal the declared values,
     checked before reading the body (422 `asset_mismatch`).
  5. The received bytes match (422 `asset_mismatch`; the stored object is
     discarded).
- **Proposed: idempotent create.** Re-posting an identical body for an open
  draft returns 200 with the draft. Any other body for an existing version is
  409 `version_exists`. A failed CI job can retry from the start.
- **Proposed: publish.** The checks run in this order:
  1. Draft checks (404 `draft_not_found`, 409 `not_a_draft`).
  2. Asset set: every declared asset must be present and still match (422
     `assets_incomplete` with `missing` and `mismatched`).
  3. Quota (422 `quota_exceeded`).
  4. Canonical size (hosted draft only). If the signer declares a limit
     (`maxCanonicalBytes()`, see "Proposed defaults") and
     `canonicalBytes(manifest).length` exceeds it, publish answers **422
     `manifest_too_large`** with `canonical_bytes` and
     `max_canonical_bytes`. Nothing is signed, the draft stays a draft and
     nothing is deleted. The fix is to shorten `notes`, split assets across
     releases, or use a signer without the limit.
  5. Signing: the hosted feed signs (503 `signer_unavailable` if the signer
     cannot be reached; the release stays a draft), or an import draft is
     stored verbatim. Import never signs, so it never answers
     `manifest_too_large`.
  For stable, `latest: true` makes the release the channel's current one. The
  current beta is always the most recently published beta.
- **Not drafted.** There is no draft deletion. An abandoned draft keeps its
  quota reservation until an admin deletes it, so an admin-tool procedure is
  needed.

## Signature and canonicalisation

From the doc:

- Ed25519 (RFC 8032) signs the UTF-8 bytes of the `manifest` object
  canonicalised with JCS (RFC 8785).
- `key_id` selects the public key. A build carries one key and refuses any
  other `key_id`.
- The client canonicalises what it received, not a re-serialisation of parsed
  types.
- The client's order of checks: signature, then profile, channel and schema,
  then version, then asset selection and name, then the download host, then
  size and sha256.

Proposed:

- **Signature encoding.** base64url without padding, 86 characters
  (`^[A-Za-z0-9_-]{85}[AQgw]$`; 64 bytes are 512 bits and 85 characters
  carry 510, so the last character carries two data bits and four zero
  padding bits). `key_id` is `fk_<profile>_<label>`
  (`^fk_[a-z0-9]{1,32}_[a-z0-9]{1,16}$`).
- **Strict I-JSON acceptance** (from RFC 8785; proposed for this contract).
  Every consumer of a received envelope (the Swift client, the Rust GTK
  client and probe, the install scripts' OpenSSL path, and the server's
  import endpoint) MUST reject an envelope whose JSON text contains a
  duplicate member name at any depth (names compared after escape decoding,
  so `"profile"` and `"pro\u0066ile"` are duplicates), a lone surrogate, or
  anything outside the RFC 8259 grammar (including a leading byte order
  mark), BEFORE canonicalising or verifying it. The client reports this as
  schema-invalid and import as 422 `manifest_invalid`. RFC 8785 section 3.1
  requires JCS input to be I-JSON (RFC 7493), which forbids duplicate names
  and lone surrogates. Language-default parsers do not enforce this:
  JSON.parse and Foundation `JSONSerialization` keep one of the duplicates
  (JSON.parse the last), and serde_json into a `Value` or a map is
  last-wins (only a derived struct rejects a duplicate field, and not inside
  nested `Value`s). A document with a duplicate therefore canonicalises to the
  bytes of whichever value survived, and a correct signature over one
  reading verifies a text that other parsers read differently. Each consumer
  needs a duplicate-detecting parse of the raw text; a shell path cannot
  rely on `jq`, which is last-wins too.
- **Integers only.** The manifest contains only strings, safe integers
  (`size` ≤ 2^53−1, `schema`, `os_floor`), booleans, arrays and objects. JCS
  number formatting therefore never depends on ES float printing.
  `test/support/jcs.ts` refuses non-integers, non-finite numbers, lone
  surrogates and non-plain objects.
- **Envelope storage.** The envelope is stored and served byte-for-byte as
  produced at publish or import. The server never re-serialises it.
- **Cross-field rules.** A schema cannot express these, so clients and
  import must check them:
  - asset ids and names are unique;
  - `manifest.profile` equals the compiled or header profile;
  - `key_id` names that profile;
  - the version is newer than the installed one;
  - `published_at` is not older than the last accepted one (open question 4
    proposal).

The tests sign at runtime with `generateKeyPairSync("ed25519")` and rebuild
the public key from its JWK `x`, as a build would from
`DESKTOP_FEED_PUBLIC_KEY`. They check that:

- the stable and beta envelopes verify;
- pretty-printing, key reordering and extra whitespace (tabs, CRLF) still
  verify;
- a duplicate member name at any depth (outer `manifest` or `key_id`,
  `manifest.profile` including an escaped spelling of the name, a field
  inside one `assets[]` object) is refused as schema-invalid by the client
  and as 422 `manifest_invalid` by import, before the signature check,
  although JSON.parse of the same text yields the valid signed envelope.
  These cases are raw texts in `test/fixtures/desktop-feed/raw/`, read as
  text, with a `$SIGNATURE` placeholder filled at run time;
- a one-byte change, a flipped signature bit and another key fail;
- another `key_id` is refused before verification;
- each invalid fixture reaches its expected client result.

The canonicaliser is checked against four hand-computed byte strings,
including UTF-16 key ordering (U+1F600 sorts before U+FB01). The strict
parser is checked to equal JSON.parse on every fixture file and both
schemas, and to refuse top-level, nested and escaped-equivalent duplicates,
lone surrogates, trailing characters, a leading BOM and other non-RFC 8259
input.

## Transport rules

All proposed unless marked.

- **TLS only.** A signed URL must be `https`, have no explicit port and no
  userinfo, and its host must equal an entry of the signed `download_hosts`
  exactly (from the doc), not by suffix. A streamed URL is the site itself
  under `/api/v1/desktop/feed/assets/`.
- **No redirects.** No feed operation defines a 3xx (tested). The client
  follows no redirect from the stream or from a signed URL. The stream
  endpoint is `x-desktop-feed-redirects: never`.
- **Signed URLs.** One object, `GET` only, 5 minutes, checked only when the
  request starts (from the doc). 501 `no_object_storage` when the deployment
  streams only: no object store, the manifest's `download_hosts` is empty, or
  the deployment's store host is not in it. The client then streams.
- **Range.** A single `bytes=` range is 206 with `Content-Range`. Open-ended
  and suffix ranges are allowed, and an end past the size is clamped. Multiple
  ranges, a start at or past the size, a start after the end, and `bytes=-0`
  are 416 with `Content-Range: bytes */<size>`. `ETag` is the quoted asset
  sha256. A stale `If-Range` returns 200 with the whole body.
- **Caching.** The manifest is `Cache-Control: no-store`.
- **Rate limits (proposed numbers).** Every operation documents 429 with a
  required `Retry-After`. Limits per credential, keyed as `RateLimiter` and
  `clientIp` in `src/auth/device-approval.ts` key theirs:

  | Operation | Limit |
  |---|---|
  | Manifest and listing reads | 60 per minute |
  | `download-url` | 30 per minute |
  | Stream | 4 concurrent, 30 starts per minute |
  | Publisher operations | 600 per minute |
  | Install-token minting | 10 per hour per user |
  | Unauthenticated requests | 60 per minute per IP |

  A burst of 403s is also an alert condition (from the doc).

## Signing ownership and on-prem paths

- **From the doc.** The hosted publish endpoint is the only signer, with one
  Ed25519 key per profile, held in KMS. A customer-hosted or on-prem
  relaycontrol and any mirror only store and serve signed envelopes verbatim
  and hold no private key.
- **Unresolved: signer provider.** The design says "KMS", but no provider has
  been confirmed for this deployment. `openapi.yaml` marks it `x-signer-provider:
  {x-status: unresolved}` on the tag and on the publish operation. The
  contract fixes only the observable behaviour:
  - the signature format;
  - `key_id`;
  - 503 `signer_unavailable`;
  - the signer's declared canonical byte limit and 422 `manifest_too_large`;
  - signing happens after the asset-set check, the quota check and the
    canonical size check.
- **An alternative not accepted: a private key stored in Postgres.** Keeping
  the Ed25519 private key in the application database (encrypted or not), as
  a fallback when no KMS is configured, is not accepted. It would put the key
  that is the only security floor on Linux and Windows within reach of any
  database read, backup or SQL injection. It would also let on-prem
  deployments sign, against open question 5's decision. Without a signer, a
  deployment can import but cannot publish (503 `signer_unavailable`).

On-prem paths: every path ends in the same verify-and-store call. It never
signs.

| Path | How a release arrives | Verify-and-store call |
|---|---|---|
| (a) Direct | Our publish job publishes to the hosted feed (signs), then uses the customer-issued publisher token on the customer's site | `POST /releases/import` with the hosted envelope (verifies schema, profile, `key_id`, signature; opens an import draft whose `expected_assets` are `manifest.assets`, ids kept), then `PUT .../assets/{name}` for each asset, then `POST .../publish`, which stores the envelope verbatim |
| (b) Mirror | `relayctl desktop-feed sync` on the customer's deployment reads our hosted feed with a mirror token | The same three calls, made locally by `sync` with the deployment's own publisher token |
| (c) Air-gapped | `relayctl desktop-feed export` writes a bundle (envelope + assets), it is carried in, and `relayctl desktop-feed import` loads it | The same three calls, made by `relayctl desktop-feed import` |

Import errors: 422 `manifest_invalid`, `profile_mismatch`, `key_id_unknown` or
`signature_invalid`; 409 `version_exists`; quota 422 `quota_exceeded`.
Import has no 503 because it never needs a signer (tested).

Gaps found while drafting:

- **`download_hosts` on-prem.** An imported envelope's `download_hosts` was
  signed by the hosted feed, so it names the hosted object store. An on-prem
  deployment cannot add its own store host without breaking the signature.
  Unless the customer's store host is in the signed list, on-prem
  `download-url` answers 501 and clients stream. To change this, the hosted
  signer would need each profile's on-prem store hosts at signing time
  (registry field), and the Cloud team decides.
- **Mirror token (path (b)).** The doc names it but does not define it: its
  scope (read envelopes and assets for one profile, every channel, without a
  workspace binding), issuance and audit. No operation is drafted for it.
- **Streamed-only storage.** The existing Postgres blob backend
  (`src/flows/objects.ts`) caps inline objects at 8 MiB. Installers are far
  larger, so a deployment without GCS or S3 needs a large-object or
  filesystem backend for the stream. The backend is unresolved.

## Audit

From the doc:

- Every manifest read, list read, URL issue, stream and publish is recorded,
  with the workspace, the user or install token, the profile, the asset, the
  time and the client address.
- Publish and bursts of 403 raise an alert.

Proposed: write these through `recordAudit` in `src/admin/audit.ts` with these
action names:

- `desktop_feed.manifest_read`
- `desktop_feed.releases_read`
- `desktop_feed.download_url_issue`
- `desktop_feed.stream`
- `desktop_feed.draft_create`
- `desktop_feed.asset_upload`
- `desktop_feed.publish`
- `desktop_feed.import`
- `desktop_feed.beta_prune`
- `desktop_feed.install_token_create`
- `desktop_feed.install_token_revoke`
- `desktop_feed.denied` (403 and 401 refusals, which feed the burst alert)

`recordAudit` today cannot record all of the doc's fields:

- **Missing columns.** `selfhost_admin_audit_events` has `organization_id`,
  `workspace_id`, `actor_kind`, `actor_id`, `action` and `target`. It has no
  column for the profile, the asset or the client address.
- **Missing actor kinds.** `AuditActor` allows only `user`, `service` and
  `bootstrap`, with no kind for an install token or a publisher token.

The contract does not choose between widening that table (a migration) and
adding a feed-specific audit table. Until one is chosen, `target` can carry
`profile/<id>/asset/<asset_id>`, which is still not enough for the client
address. Token values are never written; only token ids are.

## Proposed defaults (not decided)

The operator asked for defaults so the open implementation choices have a
concrete starting point. The signer below is decided; everything else here is
**proposed**, and nothing is deployed on the strength of this section.

### Signer

- **Interface.** One `DesktopFeedSigner` with `sign(profile, bytes) ->
  {signature, key_id}`, `publicKey(profile)` and `maxCanonicalBytes(): number
  | null` (the largest canonical manifest the signer can sign; null means no
  declared limit). The publish handler never sees key material. It compares
  the canonical bytes with `maxCanonicalBytes()` before calling `sign` (422
  `manifest_too_large`) and reports the value as `max_canonical_bytes` in
  `DesktopFeedLimits`. Selected by `SELFHOST_DESKTOP_FEED_SIGNER`.
- **Decided: `awskms`, one non-exportable key per profile.** Key spec
  `ECC_NIST_EDWARDS25519`, signing algorithm `ED25519_SHA_512` with
  `MessageType: RAW` (never `ED25519_PH_SHA_512`, which prehashes and is not
  RFC 8032 pure Ed25519, so client verification would fail). No key material
  is ever in the process, Postgres, logs or audit. `maxCanonicalBytes()` is
  4096, and there is no prehash workaround, so a cloud profile's manifest is
  trimmed to fit (see Configuration).
- **No file or environment key provider is proposed for any deployed site.**
  Local development and the contract tests use a throwaway run-time key pair,
  as `test/desktop-feed-contract.test.ts` does today.
- **Not accepted, unchanged.** A private key stored in Postgres (see "Signing
  ownership and on-prem paths").
- **No signer configured.** Import works, publish answers 503
  `signer_unavailable` (already in the contract).

### Storage

- **Feed assets never use the inline Postgres blob table.** `MAX_OBJECT_BYTES`
  in `src/flows/objects.ts` is 8 MiB; installers are hundreds of MiB.
- **Backend selected by `SELFHOST_DESKTOP_FEED_STORAGE`:** `s3` (SigV4 against
  an S3-compatible bucket with the instance or pod role; the non-production
  default on the AWS box), `gcs` (the hosted default; reuse the existing GCS
  JSON-API client), `postgres-lo` (PostgreSQL large objects, streamed in
  chunks; for self-host deployments with no object store, which then answer
  501 `no_object_storage` on `download-url` and serve the stream route).
- **Keys.** `desktop-feed/<profile>/<version>/<asset name>`, written once; a
  draft's uploads go to the same key, so an abandoned draft leaves no orphan
  on publish, and `beta_prune` deletes the keys it removes.
- **Signed `download_hosts`.** For `s3` and `gcs` the publishing job must put
  the bucket's public host in the signed manifest; otherwise `download-url`
  answers 501 and clients stream (the on-prem gap above stays open).

### Audit

- **A feed-specific table, `selfhost_desktop_feed_audit_events`,** rather than
  widening `selfhost_admin_audit_events`. Columns: `id`, `occurred_at`,
  `organization_id`, `workspace_id` (nullable for publisher actions),
  `actor_kind` (`user`, `install_token`, `publisher_token`, `service`),
  `actor_id`, `action` (the `desktop_feed.*` names above), `profile`,
  `channel`, `version`, `asset_id` (nullable), `client_ip` (inet, nullable),
  `status` (HTTP status), `detail` (jsonb, never token values).
- **Why not widen.** The admin table is read by the admin audit page and its
  shape is shared with other features; the feed adds three columns and two
  actor kinds that mean nothing elsewhere, and its read volume (every manifest
  fetch) would swamp the admin log.
- **Mirror the admin-visible actions.** `publish`, `import`,
  `install_token_create`, `install_token_revoke` and `beta_prune` are also
  written through `recordAudit` with actor kind `service` and `target`
  `profile/<id>` so they appear on the existing admin page.
- **Burst alert.** A count of `desktop_feed.denied` per workspace per 5
  minutes above a configured threshold; the alert sink is whatever the
  deployment already uses, not drafted here.
- **Retention.** Read events kept 30 days, write events kept as long as the
  release exists plus 1 year; a daily prune, proposed, not scheduled.

### Still open after these defaults

The scope choice (hosted Cloud plus relaycontrol, relaycontrol only, or draft
only), open questions 2, 4 and 6, the mirror token, the on-prem
`download_hosts` gap, and the `gcpkms` data limit for `EC_SIGN_ED25519`
(to be measured; `maxCanonicalBytes()` stays null until then). None of them
is answered by a default.

## What the original draft did not do

The list below described the draft before implementation. The server code,
routes, migrations, registry, storage backends, KMS integration and admin
endpoints now exist (see "Implementation"); the remaining items still hold.

- No server code, routes, migrations, registry table, storage backend, KMS
  integration or `relayctl` commands.
- No keys, tokens or buckets. The tests generate an Ed25519 keypair in memory
  per run. The only token-shaped value (`sh_dfi_` + 43 zeros) is built at
  runtime.
- No downloads page. The page needs to know its profile id. The proposal is
  that the dashboard account payload exposes the bound profile(s) of the
  current workspace, which is not drafted.
- No admin endpoints for the profile registry, workspace binding, publisher
  token issue or rotation, draft deletion, quota changes, or install-token
  bulk revocation. These are left to the admin tool.
- No mirror token or sync protocol for path (b).
- No freshness countersignature (open question 4), no next-key support (open
  question 3), and no Windows first-install verifier (open question 1).
- No limit on `beta.N`. The source design does not bound it, so the pattern
  accepts any non-negative integer.
- No parser for any consumer. The strict I-JSON rule names what each
  consumer must refuse; choosing a duplicate-detecting parser for Swift,
  Rust and the install scripts is left to those projects.
  `test/support/strict-json.ts` is a test reference, not a library to ship.
- The OpenAPI document does not express the cross-field rules, the strict
  I-JSON rule (it states it in prose only), the check precedence, the quota arithmetic or the Range arithmetic. Those are in this
  document and in the reference functions in
  `test/desktop-feed-contract.test.ts`.
