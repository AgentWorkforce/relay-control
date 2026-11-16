# GitHub App installation credentials

Cloud's `workspace_integrations.installation_id` identifies the existing GitHub
App installation. Its Nango APP access token lasts an hour and is not an OAuth
user refresh token. The replacement keeps that installation and mints tokens
directly using **the same GitHub App registration** that Cloud/Nango uses.

An operator supplies `SELFHOST_GITHUB_APP_ID` (the numeric App ID) and
`SELFHOST_GITHUB_APP_PRIVATE_KEY_FILE` (a mounted secret PEM). The existing
`SELFHOST_GITHUB_APP_PRIVATE_KEY` direct-secret alternative is also supported;
direct and file settings are mutually exclusive. Partial configuration or an
invalid RSA key fails startup with a fixed message. Config retains a parsed key
object, not the PEM text. Never print the config or private key. This change
does not provision, retrieve, rotate, or copy any deployed secret.

When configured, the GitHub provider catalog reports `authMode: APP`. Existing
OAuth rows continue to work with their OAuth refresh mechanism. New OAuth
connects for GitHub are disabled in App mode. Installing/relinking a new App
installation is a separate setup flow; this change supports existing imported
installations without a reconnect.

## Import contract

Apply `0054_github_app_connections.sql` before importing. The trusted identity
importer maps the **default** Cloud GitHub connection (`name IS NULL`) into the
mapped relay-control workspace. Use `ConnectionStore.importGithubAppConnection`
with `workspaceId`, `organizationId`, `installationId` from that Cloud row's
`installation_id`, optional account labels, and the import's service audit
actor. It persists `auth_mode = 'github_app'`, `provider = 'github'`, a validated
decimal `installation_id`, and an encrypted empty credential object. First
runtime use mints a token. No Nango access/refresh token or App JWT is imported.
The method is a trusted in-process seam, not an HTTP endpoint: the importer
must verify the source workspace mapping before calling it.

For a SQL-based importer the equivalent columns on `integration_connections`
are `auth_mode = 'github_app'`, `installation_id = <source installation_id>`,
`credentials_ciphertext = encryptSecret('{}', targetKeyring.active)`,
`access_token_expires_at = NULL`, `refresh_token_expires_at = NULL`,
`token_type = 'bearer'`, `status = 'ready'`. Keep existing identity, audit and
tenant mapping rules. A GitHub row with a missing/invalid installation ID must
be reported for repair, never guessed from account IDs or repository names.
Named Cloud connections need an explicit selection policy: this store still
supports one default connection per workspace/provider.

## Runtime behavior

The existing authorized internal token route and runtime environment injection
use the workspace's persisted installation ID. Under the existing row lock,
relay-control creates a short-lived RS256 App JWT and posts to the fixed GitHub
`/app/installations/{id}/access_tokens` endpoint. Redirects are refused and the
request times out after 15 seconds. The token retains the installation's
granted repositories and permissions; this is the canonical workspace
integration credential, not a repository-scoped run credential.

Tokens are cached encrypted in Postgres across restarts and instances, reused
until two minutes before expiry, and minted again on expiry or `forceRefresh`.
Disconnect removes the connection/cache. Public connection records include
`installationId` and `refreshable`, never tokens. GitHub response bodies,
transport errors, JWTs and signing keys never enter error messages or audits.
HTTP 429/5xx, rate limits, malformed answers and network failures produce 503;
authorization/installation refusals produce 409. A later request can recover
by minting again without reconnecting. Unconfigured signing returns 503 and
never falls back to a stale imported OAuth token.

Protocol references: [App JWTs](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)
and [installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app).

Focused verification (no live GitHub calls or production credentials):

```sh
npm ci --no-audit --no-fund
node --import tsx --test --test-concurrency=1 test/github-app.test.ts test/admin.test.ts test/migrations.test.ts
npm run typecheck
npm run build
```
