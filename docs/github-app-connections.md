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

The GitHub provider retains its OAuth connect flow, including callbacks started
before the signing key was configured and reconnects for existing OAuth rows.
The catalog reports `authMode: OAUTH2` and `supportedAuthModes: [OAUTH2, APP]`.
Its `configured`, `configuredBy`, and `oauthApp` fields describe OAuth setup;
`githubAppConfigured` independently describes App signing readiness, and
`githubAppSetup: import` means App bindings use the trusted import seam rather
than the interactive OAuth flow. Each persisted connection's `auth_mode`
selects OAuth user refresh or App installation minting. Installing/relinking a
new App installation is a separate setup flow.

## Import contract

Apply `0054_github_app_connections.sql` before importing. The trusted identity
importer maps the **default** Cloud GitHub connection (`name IS NULL`) into the
mapped relay-control workspace. Use `ConnectionStore.importGithubAppConnection`
with `workspaceId`, `organizationId`, `installationId` from that Cloud row's
`installation_id`, optional account labels, and the import's service audit
actor. It persists `auth_mode = 'github_app'`, `provider = 'github'`, a validated
decimal `installation_id`, `github_app_organization_id`, and an encrypted empty credential object. First
runtime use mints a token. No Nango access/refresh token or App JWT is imported.
The method verifies the target workspace's organization inside the import
transaction. A unique `github_app_installations.installation_id` claims the
installation for one organization. Multiple workspaces in that organization
may share it; a claim by another organization fails, including concurrent
imports. Composite foreign keys enforce both installation and workspace
ownership on direct writes too. Claims remain bound to their organization
after disconnect; moving an installation between organizations requires an
explicit operator-controlled ownership migration. The method is a trusted
in-process seam, not an HTTP endpoint: the importer must still verify the
source workspace mapping before calling it.

For a SQL-based importer the equivalent columns on `integration_connections`
are `auth_mode = 'github_app'`, `installation_id = <source installation_id>`,
`github_app_organization_id = <mapped organization_id>`,
`credentials_ciphertext = encryptSecret('{}', targetKeyring.active)`,
`access_token_expires_at = NULL`, `refresh_token_expires_at = NULL`,
`token_type = 'bearer'`, `status = 'ready'`. In the same transaction, first
claim the installation in `github_app_installations` with its mapped
organization, refusing an existing claim owned by any other organization.
Clear `github_app_refresh_id` and `github_app_refresh_until` when replacing a
connection. Keep existing identity, audit and tenant mapping rules.
A GitHub row with a missing/invalid installation ID must
be reported for repair, never guessed from account IDs or repository names.
Named Cloud connections need an explicit selection policy: this store still
supports one default connection per workspace/provider.

### Manually unbind an installation

The first import binds an installation to its organization. Disconnecting its
last workspace does **not** remove that claim; deleting the organization
removes it by cascade. To correct a mis-mapped import without deleting the
organization, an operator must explicitly remove the old claim:

1. Pause imports for the installation and verify its current organization and
   the intended destination mapping.
2. Disconnect every App connection for that installation in the old
   organization through the normal workspace integration API. This removes
   the cached credentials and fences pending refreshes. Unbinding does not
   revoke tokens already handed to consumers: revoke those tokens or wait
   for their GitHub expiry before transferring ownership across organizations.
3. With separately authorized database maintenance access, set the psql
   variables `installation_id` and `previous_organization_id` to the verified
   identifiers, then run this guarded deletion:

   ```sql
   DELETE FROM github_app_installations
   WHERE installation_id = :'installation_id'
     AND organization_id = :'previous_organization_id'::uuid
   RETURNING installation_id;
   ```

   Exactly one row should be returned. Zero rows means the expected claim was
   absent or its owner differed; recheck the mapping rather than removing the
   organization guard. The foreign key refuses deletion while a connection
   still references the claim. Keep that constraint enabled and do not use
   cascading deletion to bypass it.
4. Re-run `ConnectionStore.importGithubAppConnection` with the verified
   destination organization/workspace mapping, then resume imports. The new
   claim is created by the normal tenant checks; do not copy the old token
   cache. This operation does not uninstall the GitHub App.

## Runtime behavior

The existing authorized internal token route and runtime environment injection
use the workspace's persisted installation ID. A short row-lock transaction
claims a 30-second refresh lease, then commits. Outside any database transaction,
relay-control creates a short-lived RS256 App JWT and posts to the fixed GitHub
`/app/installations/{id}/access_tokens` endpoint. Redirects are refused and the
request times out after 15 seconds. A second short transaction publishes the
token only if the connection still owns that lease. Reconnect and disconnect
invalidate the claim; a late mint cannot resurrect or overwrite the connection.
A crashed refresher's lease expires and can be reclaimed.

The token covers **every repository and permission granted to the installation**,
including repositories the workspace has not used. Workspace authorization
does not narrow that repository or permission scope. This is the canonical
workspace integration credential, not a repository-scoped run credential.

Tokens are cached encrypted in Postgres across restarts and instances, reused
until two minutes before expiry, and minted again on expiry or `forceRefresh`.
Cache expiry is the earlier of GitHub's advertised expiry and one hour after
receipt on the local clock, so a server clock behind GitHub does not reject a
valid token for exceeding the local one-hour window.
Disconnect removes the connection/cache. Public connection records include
`installationId` and `refreshable`, never tokens. GitHub response bodies,
transport errors, JWTs and signing keys never enter error messages or audits.
HTTP 429/5xx, rate limits, malformed answers and network failures produce 503;
authorization/installation refusals produce 409. On a retryable mint failure,
an unexpired cached token stays usable and `last_error` records a fixed code
without changing its ready status. Expired tokens are never returned as a
fallback. While another instance holds a refresh lease, readers use a still-valid
cache or receive 503 `github_app_refresh_in_progress` and can retry shortly.
A later request can recover
by minting again without reconnecting. Unconfigured signing returns 503 and
never falls back to a stale imported OAuth token.

## Migration and rollback

Migration 0054 uses only schema objects present through 0051; 0053 is reserved
for the identity import. Any changes to shared tables or constraints must be
coordinated before those migrations are deployed together.
The migration runner tracks names and checksums, sorts pending files lexically,
and does not check for numeric gaps. If 0053 is shipped later, an upgraded
database applies it after its already-applied 0054; fresh installs apply the
files in lexical order. Keep those migrations independent or deploy them
together before importing. Mount the existing App's signing key before the
import so the new rows can mint on first use.

An older binary cannot use `github_app` rows. Rollback must first restore the
previous connection representation from a verified export or remove the imported
App connections; restoring the older auth-mode CHECK while App rows remain
will fail. Preserve the ownership registry when preserving imported connections.

Protocol references: [App JWTs](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app)
and [installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app).

Focused verification (no live GitHub calls or production credentials):

```sh
npm ci --no-audit --no-fund
node --import tsx --test --test-concurrency=1 test/github-app.test.ts test/admin.test.ts test/migrations.test.ts
npm run typecheck
npm run build
```
