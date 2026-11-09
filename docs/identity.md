# Sign-in, first-boot bootstrap and invites

By default (`SELFHOST_TENANCY=single`) a self-hosted installation has one
organization. With `SELFHOST_TENANCY=multi` one installation serves many
organizations; see [Tenancy](#tenancy). This page covers how the
organization is created, how people sign in, and how owners and admins invite
teammates.

## First boot

| Variable | Meaning |
|---|---|
| `SELFHOST_BOOTSTRAP_ORG_NAME` | Organization name (set together with the admin email) |
| `SELFHOST_BOOTSTRAP_ADMIN_EMAIL` | The first owner |
| `SELFHOST_BOOTSTRAP_ADMIN_NAME` | Optional display name until their first sign-in (default: the email's local part) |
| `SELFHOST_BOOTSTRAP_WORKSPACE_NAME` | Optional, default `Default` |
| `RELAYCAST_INTERNAL_SECRET[_FILE]` | Relaycast's internal admin secret (same value as Relaycast's `RELAYCAST_INTERNAL_SECRET`) |

On every start the API runs one idempotent pass in the background:

1. No organization yet: it creates the organization, with the admin email as
   its owner. If the organization already exists (for example, it was created
   by hand), its name and data are left alone. The configured admin email is
   made an owner once. The bootstrap records which email it acted on, so if
   another owner later demotes or removes that person, a restart does not
   undo it.
2. The organization has no workspace yet: it calls Relaycast's
   `POST /internal/workspaces`. This is the same call used to rebind the
   proof's `Default` workspace by hand. The new workspace's key is encrypted
   with `SELFHOST_ENCRYPTION_KEY` and stored as the `Default` workspace.
   - On a durable-actors Relaycast the key is an `ar_ws_` key.
   - On the SQLite image it is an `rk_live_` key.

   If a workspace appears while the call is in flight, the Relaycast
   workspace the API just created is deleted.
3. While Relaycast is starting or unreachable, the pass retries with a
   backoff from 5 s to 60 s. The API keeps serving meanwhile, and the
   break-glass path below works.

Events are logged as `[selfhost-api] bootstrap: ...` and recorded in the audit
table:
- `organization.bootstrap`
- `membership.bootstrap_owner`
- `workspace.bootstrap`

## Sign-in methods

`GET /login` on the dashboard origin offers each configured method. It also
always has a collapsed **Operator sign-in** device code, which is the
break-glass path.

### OpenID Connect (recommended)

| Variable | Meaning |
|---|---|
| `SELFHOST_OIDC_ISSUER` | Issuer URL. Discovery is read from `<issuer>/.well-known/openid-configuration` |
| `SELFHOST_OIDC_CLIENT_ID` | OAuth client ID |
| `SELFHOST_OIDC_CLIENT_SECRET[_FILE]` | Client secret. Mount it from a Secret |
| `SELFHOST_OIDC_ALLOWED_DOMAINS` | Optional. Email domains allowed to sign in. Everyone else is refused |
| `SELFHOST_OIDC_DISPLAY_NAME` | Button label, shown as "Continue with <name>" |
| `SELFHOST_OIDC_SCOPES` | Default `openid email profile` |
| `SELFHOST_OIDC_REDIRECT_URL` | Optional fixed redirect URI. The default is `<site>/login/oidc/callback`, where the site is the dashboard origin, or the API origin when sign-in starts there |
| `SELFHOST_OIDC_ALLOW_HTTP_ISSUER` | Test only: accept an `http://` issuer (for example an in-cluster Dex) |

The flow is the authorization-code flow with PKCE (S256), `state` and
`nonce`.
- The attempt is kept in an encrypted, HttpOnly cookie scoped to `/login/oidc`
  that lasts 10 minutes.
- The code is exchanged with `client_secret_basic`, or with
  `client_secret_post` when the provider advertises only that.
- The `id_token` must pass all of these checks:
  - its signature verifies against the provider's JWKS (RS/PS/ES algorithms
    only, never `none` or HS*);
  - `iss` and `aud`/`azp` match;
  - `exp`, `iat` and `nonce` are valid;
  - it carries an `email` claim;
  - `email_verified` is not `false`.

Register this redirect URI with the provider:
`https://<dashboard host>/login/oidc/callback`.

**Google Workspace**
1. Open Google Cloud console → APIs & Services → OAuth consent screen and pick
   "Internal".
2. Open Credentials → Create credentials → OAuth client ID, with type "Web
   application".
3. Set the authorized redirect URI to
   `https://<dashboard host>/login/oidc/callback`.
4. Set these variables:
   - issuer: `https://accounts.google.com`
   - `SELFHOST_OIDC_ALLOWED_DOMAINS`: your domain. With exactly one domain,
     Google preselects it through `hd`.

**Okta**
1. Create an OIDC "Web Application" app integration with grant type
   Authorization Code.
2. Use issuer `https://<org>.okta.com/oauth2/default` (or your custom
   authorization server).

**Microsoft Entra ID**
1. Create an app registration with a Web redirect URI.
2. Use issuer `https://login.microsoftonline.com/<tenant-id>/v2.0`.
3. Add the optional `email` claim to the ID token. Entra omits
   `email_verified`, and the email comes from your directory.

### Email sign-in links (optional)

Set the SMTP variables below and `SELFHOST_EMAIL_LOGIN=true`. A person enters
their email address and receives a single-use link that expires after
15 minutes.
- Only members, people with an open invite, and auto-join domains get mail.
- The page gives the same answer for every address, so addresses can't be
  enumerated.
- Opening the link shows a "Continue" button that signs the person in with a
  same-origin POST. This keeps mail scanners that prefetch links from using up
  the token.

| Variable | Meaning |
|---|---|
| `SELFHOST_SMTP_HOST` / `SELFHOST_SMTP_PORT` | SMTP server. The default port is 587 |
| `SELFHOST_SMTP_SECURITY` | `starttls` (the default), `tls` (the default for port 465), or `none` |
| `SELFHOST_SMTP_USERNAME` / `SELFHOST_SMTP_PASSWORD[_FILE]` | Optional, set together |
| `SELFHOST_EMAIL_FROM` | For example `Agent Relay <relay@example.com>` |

SMTP alone, without `SELFHOST_EMAIL_LOGIN`, is used to email invites.

### Break-glass: the bootstrap bearer

`SELFHOST_BOOTSTRAP_TOKEN` can still:
- approve a `/login` device code for any member (`POST /api/v1/auth/device/approve`
  with `user_id` and `workspace_id`);
- create invitations and manage memberships.

Keep it in the Secret and use it only when no sign-in method works.

The bootstrap bearer is an installation-wide operator credential in both
modes: it reaches every organization. With `SELFHOST_TENANCY=multi` every use
against an organization route is written to `selfhost_admin_audit_events`
(action `bootstrap.access`, actor `bootstrap`, target `METHOD path`).

**Rotating it.** The token is read at startup and compared on each request;
nothing derived from it is stored. To rotate: write a new value of at least
32 bytes to the Secret, restart (roll) every API replica, and confirm the old
value gets `401` while the new one gets `200` on
`GET /api/v1/installation/settings`. Sessions, device tokens and Desktop
tokens are unaffected. Rotate after anyone who held it leaves, and whenever
the `bootstrap.access` audit rows show use you can't account for.

### Tokens other services verify

Every sign-in method ends in the same `sh_at_` access token. In a RelayAuth-free
install RelayHistory (and relayfile) accept that token directly and verify it
through `POST /internal/v1/auth/introspect`, authenticated with
`RELAYCONTROL_INTROSPECT_SECRET`. The answer comes from the live token
session, so removing a member, revoking a session or refreshing the token
takes effect on the service's next check; refresh, bootstrap and worker
tokens, and every workspace API token other than a relayfile agent or
acquisition operator token (below), are always reported as `wrong-kind` (an
`sh_wk_` that matches no token is `unknown`). See
[RelayAuth and RelayHistory](../README.md#relayauth-and-relayhistory).
`GET /readyz` lists the accepted audiences (`introspection.audiences`, empty
while introspection is disabled), so a scheme or port mismatch shows up there
instead of as a runtime 401.
The self-hosted sessions backend, the RelayHistory read API container, is
such a service: it introspects the forwarded `sh_at_` token with
`READ_API_ORIGIN` as `aud` and grants only `rth:read`. See
[docs/sessions-read-api.md](sessions-read-api.md).

The `workspace` in the request is optional. A token session is bound to
exactly one workspace, so a service that only has the bearer (the Desktop
upload edge) omits it (or sends null) and takes the `workspace` in the answer
as authoritative. When it is sent it must be a non-empty string equal to the
session's workspace, else the answer is inactive with `workspace`; an empty
string or any other type is a 400. `aud` is always required.

A service that writes on behalf of a computer also sends the caller's claimed
`machine` (the Relaycast node id the Desktop claimed through
`POST /api/v1/fleet/nodes/claim`). Once the token itself is active,
relaycontrol checks that node's claims: claimed by the token's user in the
token's workspace answers active with `machine_id` set to it; otherwise the
answer is inactive with `machine_not_owned` (another person's claim in this
workspace), `machine_workspace_mismatch` (no claim in this workspace, but one
in another) or `machine_unclaimed` (no claim). Releasing the claim takes
effect on the next check. Without `machine` the answer carries
`machine_id: null` and History treats the caller as read-only. History takes
the machine id only from this answer, never from its own caller.

#### Relayfile agent tokens

An agent that talks to relayfile presents a workspace API token of purpose
`relayfile-agent`. A workspace owner or admin mints it with
`POST /api/v1/workspaces/{id}/deployment-api-tokens`
`{label, purpose: "relayfile-agent", agent_name, aud, expiryDays? | neverExpires?}`;
the `sh_wk_` value is shown once. `agent_name` follows the node id pattern
(`[A-Za-z0-9._:-]`, 1-200) and is unique among the workspace's non-revoked
relayfile-agent tokens (409 otherwise; revoke the old one first). `aud` must
normalize to one of the accepted introspection audiences, so minting is a 400
while introspection is disabled. Scopes are fixed: `fs:read`, `fs:write`,
`sync:read`, `sync:trigger`, never admin scopes.

Introspecting such a token answers with `principal_type: "agent"`, `sub` and
`token_id` set to the token id, `email: null`, `agent_name`, `machine_id: null`,
the token's workspace, organization and scopes, `aud` (the stored audience),
`iat` (mint time) and `exp`. `exp` is the token's own expiry when it has one;
a token that never expires gets `now + 3600` recomputed on every call, so a
caller may cache an answer for at most an hour and revocation takes effect on
its next check. Inactive reasons: an `sh_wk_` with no such token is
`unknown`; any other `sh_wk_` token is `wrong-kind`;
then `revoked`, `expired`, `audience` (the request `aud` must normalize to the
token's stored `aud`), `workspace` (same rule as for users), and any `machine`
is `machine_not_owned`, since an agent token is not a computer.

#### Acquisition operator tokens

An operator service (Backend, Cloud) that drives session acquisition in
RelayHistory presents a workspace API token of purpose `acquisition-operator`.
Only a workspace owner or admin mints or revokes one, with their own user
token, through the same routes as every workspace API token:
`POST /api/v1/workspaces/{id}/deployment-api-tokens`
`{label, purpose: "acquisition-operator", aud, expiryDays? | neverExpires?}`,
`GET` on the same path, and `DELETE .../deployment-api-tokens/{tokenId}`. Like
every `/api/v1` route they are also served at `/cloud/api/v1`. There is no
internal or service-token mint path: a workspace API token, the internal
service token or the bootstrap token is a 401 there. The `sh_wk_` value is
shown once. `aud` is required and must normalize to one of the accepted
introspection audiences (so minting is a 400 while introspection is
disabled); `agent_name` is a 400. The scope is fixed to `acquisition:operate`
(a `scope` or `scopes` field is a 400 for every purpose). The token may never
expire (`neverExpires: true`) or expire after `expiryDays` (1-365, default
90). A workspace may hold several at once.

Introspecting one answers like a relayfile agent token except
`principal_type: "service"`, `agent_name: null` and
`scopes: ["acquisition:operate"]`; the inactive reasons are the same
(`revoked`, `expired`, `audience`, `workspace`, and any `machine` is
`machine_not_owned`).

#### Desktop session scopes

Sessions issued to the Desktop (and CLI) through the device flow, and the
Desktop browser handoff (`/cloud/api/v1/cli/login`) and its exchange
(`POST /cloud/api/v1/auth/desktop/session`), carry `cli:auth`, `rth:read`,
`rth:sync` and `rth:acquire` (Desktop handoff sessions also carry
`desktop:workspaces`). Dashboard browser sessions (the `/login` page, SSO and
email-link sign-in) carry `cli:auth`, `rth:read`, `rth:sync` and `account`,
never `rth:acquire`. A
refresh keeps the session's scopes, so a session issued before `rth:acquire`
existed gains it only at the next sign-in. Introspection returns the scopes
verbatim.

## Who may sign in

**Single mode (the default).** A verified email signs in when one of these is
true:
1. it already belongs to a member;
2. it followed an invite link sent to that same email;
3. it has any open invite (invites are accepted automatically at sign-in,
   as in hosted Cloud);
4. its domain is in `SELFHOST_AUTO_JOIN_DOMAINS`, in which case it joins as
   `member`.

Everyone else sees "<email> doesn't have access to <org>. Ask an owner or
admin to invite you." A session is bound to the organization's first
workspace.

`SELFHOST_AUTO_JOIN_DOMAINS` is the only authority for auto-join in single
mode, including when it is absent or empty. On every bootstrap pass (each
start) the bootstrap organization's rows in `selfhost_organization_domains`
are made equal to the normalized list (lowercase, IDNA ASCII, a leading `@`
dropped): missing rows are inserted, extra rows deleted, and all rows are
cleared when the variable is absent or empty, which means no auto-join, as
before 0014. A change takes effect on the next restart. The domain routes
answer `409 domains_managed_by_env` to `PUT` and `DELETE` in single mode.

**Multi mode.** The organization a sign-in lands in is chosen in this order:
1. the invite the person followed, then every other open invite for the
   email (each is accepted; the session lands in the last one accepted);
2. otherwise an existing membership: the remembered organization
   (`selfhost_users.last_organization_id`) when still a member, else the
   newest;
3. otherwise the organization the operator assigned the email's domain to,
   as `member`, and only for a verified email (see [Domains](#domains));
4. otherwise a personal organization named "<name>'s Workspace" with a
   `Default` workspace, when personal organizations are on; else
   `403 no_organization`.

The workspace is the remembered one (`last_workspace_id`) when it is in that
organization, else the organization's oldest. A refused sign-in rolls back
and leaves no user row. Personal and self-serve organizations need
`RELAYCAST_INTERNAL_SECRET` to create their Relaycast workspace; without it
they answer `503 not_ready`.

## Invites

Owners and admins invite people by email from Settings → Members. The API
calls are below. They take a dashboard session (a same-origin JSON request)
or the bootstrap bearer.

| Call | Purpose |
|---|---|
| `GET /api/v1/organizations/{org}/invitations` | Open invites, without their links |
| `POST /api/v1/organizations/{org}/invitations` `{email, role}` | Creates an invite. Returns `{invitation, inviteUrl, emailDelivery: sent\|failed\|not_configured}` |
| `POST /api/v1/organizations/{org}/invitations/{id}/link` `{send?}` | Issues a new link (the old link stops working and the expiry restarts). Optionally re-emails it |
| `DELETE /api/v1/organizations/{org}/invitations/{id}` | Revokes an invite |
| `GET /api/v1/auth/methods` | Which sign-in methods and invite delivery are configured (for the dashboard) |

How invites behave:
- The link is `<dashboard>/login?invite=sh_inv_...`. Only its SHA-256 is
  stored, so the link is shown once. Use "new link" to copy it again.
- Links are single use and expire after `SELFHOST_INVITE_TTL_HOURS`
  (default 7 days).
- A new invite for the same email replaces the open one.
- Inviting an existing member is refused.
- The invitee must sign in with the invited email.
- When SMTP is configured, the invite is emailed. The link is returned
  either way.

Audit actions:
- `invitation.create`
- `invitation.rotate`
- `invitation.revoke`
- `invitation.accept`
- `membership.auto_join`
- `membership.update`
- `membership.remove`

## Roles

| Role | Can |
|---|---|
| `owner` | Everything, including granting or removing `owner` |
| `admin` | Invite `admin`/`member`, change and remove admins and members, manage workspace settings |
| `member` | Use the workspace and view settings and members |

The last owner cannot be demoted or removed.

## Tenancy

| Variable | Meaning |
|---|---|
| `SELFHOST_TENANCY` | `single` (the default) or `multi`. Validated at startup and logged once |
| `SELFHOST_PERSONAL_ORG_ON_SIGNIN` | Multi mode only. A first sign-in with no invite, membership or domain creates a personal organization. Default `true` |
| `SELFHOST_SELF_SERVE_ORGANIZATIONS` | Multi mode only. Any person signed in to the dashboard (the browser account session) may `POST /api/v1/organizations` and owns the result. Default `true` |

The two `true` values are the multi-mode defaults; change them by editing
the constants `DEFAULT_PERSONAL_ORG_ON_SIGNIN` and
`DEFAULT_SELF_SERVE_ORGANIZATIONS` in `src/tenancy.ts` or by setting the env
flag. Single mode ignores both flags.

Multi mode refuses to start with `SELFHOST_AUTO_JOIN_DOMAINS` set (assign
domains per organization instead) and requires `SELFHOST_BOOTSTRAP_ORG_NAME`
and `SELFHOST_BOOTSTRAP_ADMIN_EMAIL`. The bootstrap organization is the
operator's; the bootstrap pass adopts only the organization recorded in
`selfhost_installation_bootstrap`, never "the only organization".

### Readiness

`GET /readyz` checks the database and the migrations and, in single mode,
that at most one organization exists. With more than one it answers not
ready with reason `tenancy_mismatch` ("SELFHOST_TENANCY=single but N
organisations exist"). The
check runs before any bootstrap work: while mismatched the bootstrap pass
does nothing (it does not sync domains or grant owners). Nothing is deleted.
Either switch to `multi` or consolidate the organizations by hand.

### Installation settings (kill switches)

`GET|PATCH /api/v1/installation/settings`, bootstrap bearer only:

```json
{ "personalOrgSignupEnabled": false, "selfServeOrganizationsEnabled": null }
```

A non-null value overrides the env flag; `null` follows it again; an omitted
field is unchanged. The response includes the stored values and
`effective: {personalOrgOnSignIn, selfServeOrganizations}`. The values are
read on every request, so a change applies to the next sign-in or
`POST /api/v1/organizations` without a restart. Each change is audited as
`installation.settings`. In single mode both effective values are `false`.

### Domains

In multi mode the installation operator assigns auto-join domains per
organization:

| Call | Who |
|---|---|
| `GET /api/v1/organizations/{org}/domains` | Any member, or the bootstrap bearer |
| `PUT /api/v1/organizations/{org}/domains/{domain}` | Bootstrap bearer only. `201` assigned, `200` already assigned here, `409 domain_assigned` when another organization holds it |
| `DELETE /api/v1/organizations/{org}/domains/{domain}` | Bootstrap bearer only. `204`, or `404 domain_not_found` |

Owners and admins get `403`: assigning a domain lets every address at it join
the organization, which only the operator can vouch for. A domain belongs to
at most one organization (it is the table's primary key). Only a verified
email auto-joins: an OIDC `id_token` with `email_verified: true` (a provider
that omits the claim signs in but never auto-joins), or an email sign-in link
(the link proves the mailbox). An invite or an existing membership always
wins over a domain. Audit actions: `organization.domain_assign`,
`organization.domain_remove`.

### Organizations and workspaces

`POST /api/v1/organizations` `{name}` with the browser account session (the
`/cloud` cookie, scope `account`; multi mode, when self-serve is on) creates
an organization the caller owns, with a `Default` workspace. CLI, Desktop
and pre-upgrade credentials get `403 reauthentication_required`. The bootstrap bearer keeps the operator form
`{name, ownerEmail, ownerName}` in both modes. Rate limits apply per user and
per IP.

Every token, cookie and session is bound to one user, organization and
workspace. The transport (bearer header or the `/cloud` cookie) never confers
authority: an organization route checks the caller's membership in the path
organization and answers `404` otherwise. Reaching another workspace takes a
capability scope:

| Route | Needs | Does |
|---|---|---|
| `GET /cloud/api/auth/session` | `account` | The person, the current organization and workspace, and every organization and workspace they belong to |
| `POST /cloud/api/auth/workspace` `{workspaceId}` | `account`, same-origin cookie | Replaces the session with one bound to that workspace (a new cookie), revokes the old access and refresh tokens, remembers the choice |
| `GET /api/v1/auth/desktop/workspaces` | `desktop:workspaces` (bearer) | The person's workspaces across organizations |
| `POST /api/v1/auth/desktop/workspaces` `{workspaceId}` | `desktop:workspaces` (bearer) | A new Desktop access/refresh pair bound to that workspace, in the same token family |
| `/api/v1/cli/login` picker | `account` | Lists every member workspace; a session without `account` stays bound to its own workspace |
| `POST /api/v1/auth/device/approve` | `account` (or the bootstrap bearer) | Approves for any workspace the person belongs to; other credentials approve for their own workspace only |

Membership is checked live on every request and mint, so removing a person
from an organization takes effect on their next request.

### Scope mint matrix

Scopes are fixed when a credential is issued and stored on its session row.
They are additive: `account`, `desktop:workspaces` and `rth:acquire` are added to the
existing set; nothing is removed. Refresh keeps a session's scopes and never
adds one.

| Credential | Issued by | Scopes |
|---|---|---|
| Browser session (cookie under `/cloud`) | `/login/oidc/callback`, `/login/email/verify`, `POST /login/poll` for a `/login` device code, `POST /cloud/api/auth/workspace` | `cli:auth rth:read rth:sync account` |
| Desktop session | `/api/v1/cli/login` handoff exchanged at `/api/v1/auth/desktop/session`, `POST /api/v1/auth/desktop/workspaces` | `cli:auth rth:read rth:sync rth:acquire desktop:workspaces` |
| Device / CLI token | `POST /api/v1/auth/device/token` | `cli:auth rth:read rth:sync rth:acquire` |
| Refreshed token | `POST /api/v1/auth/token/refresh` | Unchanged from the session it refreshes |
| MCP, workspace API, worker and service tokens | Their own routes | Never `account` or `desktop:workspaces` |

`/login` starts its device code with the reserved client name
`relay-dashboard`. Only that code, redeemed by `POST /login/poll` as the
browser cookie, becomes an `account` session; `POST /api/v1/auth/device/start`
refuses the name with `400` (also after surrounding and invisible characters
are cleaned from it), and the same code redeemed at
`/api/v1/auth/device/token` gets the device scopes.

A credential issued before this release has the device scopes only. It keeps
working on every resource route, bound to its workspace; the account and
Desktop workspace routes answer `403 reauthentication_required`, and the
dashboard's `GET /cloud/api/auth/session` answers `401`
`{authenticated: false, reason: "reauthentication_required"}` so the
dashboard signs in again. Signing in again issues a session with the new
scope.

A Desktop handoff token (from `/api/v1/cli/login`) is good only for its
verifier exchange: until then the Desktop workspace routes answer
`403 handoff_not_exchanged` and the account routes refuse it.

### Lock order

Every writer that touches users, memberships or organizations takes
transaction-scoped advisory locks in one order (`src/tenancy.ts`):

1. the email: `hashtext('email:' || normalized email)`, before the user row
   is upserted (a new person has no id yet);
2. the user: `hashtext('user:' || user id)`, once the row exists;
3. each organization joined or changed: `hashtext('org:' || organization id)`,
   in id order;
4. the organization-creation lock `1947182642`, last, only when creating an
   organization that must be unique (single mode, and the bootstrap
   organization).

No path takes an earlier lock after a later one. Sign-in, invite acceptance,
domain auto-join, personal and self-serve organizations, membership changes
and the bootstrap pass all follow it.

PGlite runs one transaction at a time, so the in-process tests prove the
logic, not the locking. The two-connection race (the same identity racing
first sign-in, organization creation and the bootstrap) runs against a real
PostgreSQL only when you opt in:

```sh
createdb relaycontrol_race
TEST_DATABASE_URL=postgres://localhost/relaycontrol_race \
  node --import tsx --test test/tenancy-postgres.test.ts
```

Without `TEST_DATABASE_URL` the test is reported as skipped. Point it only at
an empty throwaway database: the test migrates it, refuses to run if any
organization exists, and leaves its rows behind (drop the database
afterwards).

### Telemetry

With `SELFHOST_TENANCY=multi` an organization admin's telemetry view
(`/api/v1/organizations/{org}/telemetry`, `/preview`, `/export`) covers only
the issue reports filed in that organization. Digests, error reports,
snapshots (`?snapshot=1`) and hypothetical previews (`?level=`) are
installation-wide and answer `403 installation_scope` to anyone but the
bootstrap bearer. An organization export signs its reports without marking
them exported; delivery stays with the operator. See
[telemetry.md](telemetry.md).

### Rolling back migration 0014

Migrations run forward only. Going back to an image older than 0014 is
supported only while **exactly one organization** exists; the old image
enforces that. With the old image stopped, run this as the migration owner:

```sql
BEGIN;
DO $$
BEGIN
  IF (SELECT count(*) FROM selfhost_organizations) <> 1 THEN
    RAISE EXCEPTION 'rollback of 0014 requires exactly one organization';
  END IF;
END
$$;
-- telemetry organization column
DROP INDEX IF EXISTS selfhost_telemetry_outbox_organization_idx;
ALTER TABLE selfhost_telemetry_outbox DROP COLUMN IF EXISTS organization_id;
-- domains, selections, kill switches, single-organization constraint
ALTER TABLE selfhost_installation_bootstrap
  DROP COLUMN IF EXISTS personal_org_signup_enabled,
  DROP COLUMN IF EXISTS self_serve_organizations_enabled;
DROP TABLE IF EXISTS selfhost_organization_domains;
ALTER TABLE selfhost_users
  DROP COLUMN IF EXISTS last_organization_id,
  DROP COLUMN IF EXISTS last_workspace_id;
ALTER TABLE selfhost_organizations
  ADD COLUMN installation_slot smallint NOT NULL DEFAULT 1,
  ADD CONSTRAINT selfhost_organizations_single_slot CHECK (installation_slot = 1);
CREATE UNIQUE INDEX selfhost_organizations_singleton_idx
  ON selfhost_organizations (installation_slot);
CREATE UNIQUE INDEX selfhost_single_organization_idx
  ON selfhost_organizations ((true));
DELETE FROM selfhost_schema_migrations
 WHERE name = '0014_multi_tenant.sql';
COMMIT;
```

What is lost: the operator-assigned domains (in single mode they are a copy
of `SELFHOST_AUTO_JOIN_DOMAINS`, which the old image reads directly), the
remembered selections, the kill-switch overrides, and the organization
attribution of queued issue reports. Sessions issued with `account` or
`desktop:workspaces` keep working on the old image, which ignores scopes it
does not know. Upgrading again re-applies the migration.
