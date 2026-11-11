# Sign-in, first-boot bootstrap and invites

By default (`SELFHOST_TENANCY=single`) a self-hosted installation has one
organization. With `SELFHOST_TENANCY=multi` one installation serves many
organizations; see [Tenancy](#tenancy). This page covers how the
organization is created, how people sign in, and how owners and admins invite
teammates.

## First boot

| Variable | Meaning |
|---|---|
| `SELFHOST_BOOTSTRAP_ORG_NAME` | Organization name (set together with `SELFHOST_BOOTSTRAP_ADMIN_EMAIL` or `SELFHOST_ADMIN_EMAILS`) |
| `SELFHOST_BOOTSTRAP_ADMIN_EMAIL` | The first owner |
| `SELFHOST_ADMIN_EMAILS` | Optional comma list of admin addresses. The first listed address to sign in with a verified email becomes owner if the organization has none; the others become admins. Each grant is applied once, so a later demotion sticks. `SELFHOST_BOOTSTRAP_ADMIN_EMAIL` is an alias for a listed address that is made owner at first boot |
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
| `SELFHOST_OIDC_TRUST_MISSING_EMAIL_VERIFIED_ISSUER` | Optional. Treats an `id_token` with no `email_verified` claim as verified, which matters for domain auto-join in multi mode. Must equal `SELFHOST_OIDC_ISSUER`. See [Providers that omit `email_verified`](#providers-that-omit-email_verified) |

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
   authorization server). The `email` scope, requested by default, puts both
   `email` and `email_verified` in the `id_token`.
3. Assign the people who should sign in to the app. Okta refuses anyone who
   is not assigned.

**Microsoft Entra ID**
1. Create an app registration with a Web redirect URI, for accounts in this
   organizational directory only.
2. Use issuer `https://login.microsoftonline.com/<tenant-id>/v2.0`, with the
   directory (tenant) ID. The shared `common` and `organizations` issuers
   are refused at sign-in: their discovery document names no single issuer.
3. Add the optional `email` claim to the ID token. Entra omits
   `email_verified`; see below. `preferred_username` and `upn` are never used
   in place of `email`, so a person with no email on their directory record
   is refused.

#### Providers that omit `email_verified`

Microsoft Entra ID sends no `email_verified` claim. An explicit `false` is
always refused. When the claim is missing:

| Path | Single mode | Multi mode |
|---|---|---|
| Bootstrap owner | Signs in as owner | Signs in as owner |
| Existing member | Signs in | Signs in |
| Invite (link or open invite) | Signs in with the invited role | Signs in with the invited role |
| Domain auto-join | Joins as `member` | Does not join: personal organization when those are on, else `403 no_organization` |

Single mode needs no setting. To let a provider's accounts auto-join assigned
domains in multi mode, set
`SELFHOST_OIDC_TRUST_MISSING_EMAIL_VERIFIED_ISSUER` to the exact value of
`SELFHOST_OIDC_ISSUER`. Startup fails when it differs, or when it names a
shared Microsoft issuer (`common`, `organizations`, `consumers`).

Use it only when the people who can set an email address in that directory
are people you trust with membership of the organization. Microsoft documents
the `email` claim as mutable, so anyone able to edit a directory user's email
could use it to take on that address here.

### Microsoft accounts (Outlook.com, Hotmail and Entra ID)

A second, Microsoft-specific provider for people who sign in with a personal
Microsoft account (Outlook.com, Hotmail, Live) or a work or school account in
any Entra ID tenant. It uses the same authorization code + PKCE flow as the
generic provider, at `/login/microsoft/start` and `/login/microsoft/callback`,
and shows a "Continue with Microsoft" button.

| Variable | Meaning |
|---|---|
| `SELFHOST_MICROSOFT_CLIENT_ID` | Application (client) ID of the app registration |
| `SELFHOST_MICROSOFT_CLIENT_SECRET[_FILE]` | Client secret value. Set together with the client ID; one without the other refuses to start. Mount it from a Secret |
| `SELFHOST_MICROSOFT_TENANT` | Optional. `common` (default: work or school and personal accounts), `consumers` (personal accounts only), `organizations` (work or school accounts only), or one tenant ID as a lowercase UUID. Anything else refuses to start |
| `SELFHOST_MICROSOFT_REDIRECT_URL` | Optional fixed redirect URI. It must be `<origin>/login/microsoft/callback`. The default is `<site>/login/microsoft/callback`, as for the generic provider |

The issuer is `https://login.microsoftonline.com/<tenant>/v2.0`, the scopes are
`openid email profile` and the button label is "Microsoft". None of these can be
changed. There is no domain allow-list for this provider: who may join is
decided by invites, `SELFHOST_ADMIN_EMAILS` and `SELFHOST_AUTO_JOIN_DOMAINS`
(see [Who may sign in](#who-may-sign-in)).

#### Register the app

In the Microsoft Entra admin center, under App registrations, choose New
registration:

1. **Supported account types:** "Accounts in any organizational directory and
   personal Microsoft accounts" for `common`. Choose "Personal Microsoft
   accounts only" for `consumers`, "Accounts in any organizational directory"
   for `organizations`, or "Accounts in this organizational directory only"
   for a single tenant ID.
2. **Redirect URI:** platform Web, `https://<dashboard host>/login/microsoft/callback`.
3. Under Certificates & secrets, create a client secret. Set its value as
   `SELFHOST_MICROSOFT_CLIENT_SECRET` and the application (client) ID as
   `SELFHOST_MICROSOFT_CLIENT_ID`.
4. Under Token configuration, choose Add optional claim, token type ID, and add
   `email` and `xms_edov`.

#### Which email addresses count as verified

Every token must carry a tenant ID (`tid`), and its issuer must be
`https://login.microsoftonline.com/<tid>/v2.0`. With a single tenant ID, or with
`consumers`, the token must also come from that tenant. The `email` claim is
required.

- **Personal accounts** (Outlook.com, Hotmail, Live): Microsoft verifies the
  address, so it is accepted.
- **Work or school accounts:** accepted only when the token carries
  `xms_edov` set to true, which means the tenant has verified the address's
  domain. Add the optional claim in step 4.
- Anything else is refused: "Your Microsoft account's email address isn't
  verified." Nothing is created and no session is issued.

#### Beside SELFHOST_OIDC_*

Both providers can be configured at once. The login page then shows "Continue
with <name>" for the generic provider first and "Continue with Microsoft"
below it. `GET /api/v1/auth/login-config` and `GET /api/v1/auth/methods`
publish `microsoft: { displayName }` (or `null`) beside `oidc`. When
Microsoft is configured, Agent Relay Desktop's "Continue with Microsoft" opens
`/login/microsoft/start`; otherwise it, and Desktop's Google start, open the
`/login` chooser, which lists every configured provider, even when
`SELFHOST_OIDC_*` is set. A signed-out bounce never forces one provider.

#### Invites

An invite to a personal address such as `x@outlook.com` is redeemed through
"Continue with Microsoft" on the invite link, and the invite's address is sent
as the sign-in hint. Signing in with a different account is refused with "This
invite was sent to x@outlook.com. You signed in as <address>. Sign in with the
invited account.", and the way back keeps the invite. Audit rows record
`via=microsoft`.

#### Troubleshooting

| What you see | Likely cause |
|---|---|
| `AADSTS50011` | The redirect URI registered on the app isn't exactly `https://<dashboard host>/login/microsoft/callback` |
| "Your Microsoft account's email address isn't verified" | A work or school account without `xms_edov`: the optional claim is missing from the app registration, or the address's domain isn't verified in that tenant |
| "did not share an email address" | No optional `email` claim, or no email on the directory user |
| "id_token issuer does not match" | The account belongs to a tenant that `SELFHOST_MICROSOFT_TENANT` excludes |
| "Discovery issuer does not match the Microsoft tenant" | `SELFHOST_MICROSOFT_TENANT` names a tenant that Microsoft doesn't publish |
| "The identity provider refused the sign-in (invalid_client)" | Wrong or expired client secret |

### Test your SSO before go-live

Run this after configuring the provider and before announcing sign-in. Use a
private browser window for each person, so an earlier session can't answer
for the next one.

1. Check that the issuer is exact. The `issuer` printed must equal
   `SELFHOST_OIDC_ISSUER`, without a trailing slash difference:

   ```sh
   curl -s "$SELFHOST_OIDC_ISSUER/.well-known/openid-configuration" | jq -r .issuer
   ```

2. Prepare test accounts at the provider:
   - **Okta:** in the app's Assignments tab, assign the bootstrap admin, one
     person at an auto-join domain, and one invited person. Use an issuer
     from Security → API → Authorization Servers. If your org has no custom
     authorization server, use `https://<org>.okta.com`.
   - **Entra ID:** on each test user, confirm the Email field is filled in.
     In the app registration, under Token configuration, confirm the optional
     `email` claim is listed for ID tokens. Under API permissions, confirm
     `openid`, `email` and `profile`, and grant admin consent if your tenant
     requires it.

3. Open `https://<dashboard host>/login` and choose "Continue with
   <name>". Check each of these:

   | Sign in as | Expected |
   |---|---|
   | `SELFHOST_BOOTSTRAP_ADMIN_EMAIL` | Lands in the organization as owner |
   | Someone at an auto-join domain, not yet a member | Joins as `member` (multi mode with Entra: see above) |
   | Someone invited, using the invite link | Joins with the invited role |
   | The same person a second time | Signs in with no new membership |
   | Someone outside `SELFHOST_OIDC_ALLOWED_DOMAINS` | Refused: "Accounts from <domain> can't sign in here" |
| Microsoft: someone invited, choosing "Continue with Microsoft" with a different account | Refused: "This invite was sent to ... Sign in with the invited account." No membership |

4. In the Agent Relay Desktop app, sign in to this installation. The browser
   opens `/login`; after sign-in it returns to the app, signed in to the
   workspace.

5. If something fails:

   | What you see | Likely cause |
   |---|---|
   | "Discovery issuer does not match" | `SELFHOST_OIDC_ISSUER` differs from the `issuer` in step 1, or names `common`/`organizations` |
   | Entra `AADSTS50011`, or Okta's redirect URI error | The redirect URI registered with the provider isn't exactly `https://<dashboard host>/login/oidc/callback` |
   | "did not share an email address" | Entra: no optional `email` claim, or no email on the directory user |
   | "You cancelled the sign-in" on Okta, with no cancel | The person is not assigned to the app (Okta answers `access_denied`) |
   | Entra `AADSTS50105` | The app requires assignment and the person isn't assigned |
   | "The identity provider refused the sign-in (invalid_client)" | Wrong or expired client secret |
   | "doesn't have access to <org>" | Not a member, not invited, and the domain is not in `SELFHOST_AUTO_JOIN_DOMAINS` |

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

### Email and password (optional)

Turn it on with `SELFHOST_SIGNIN_METHODS`, a comma list of `email_link` and
`password`. When the variable is unset the old behaviour holds:
`SELFHOST_EMAIL_LOGIN=true` means `email_link` alone. Password sign-in needs
SMTP, because every password starts from a verified email address. A method
that is not listed answers `404 {"error":"signin_method_disabled"}` on all of
its routes. That covers `/api/v1/auth/password/*` and `/login/password` for
`password`, and `/login/email` and `/login/email/verify` for `email_link`.

| Variable | Meaning |
|---|---|
| `SELFHOST_SIGNIN_METHODS` | `email_link`, `password`, or both. The default is `email_link` when `SELFHOST_EMAIL_LOGIN=true`, otherwise none |
| `SELFHOST_LOGIN_LOGO_URL` | Optional customer logo for the sign-in pages, shown under the Agent Relay lockup. Must be an absolute `https` URL without credentials. It is drawn 22px tall through an `<img>`, so script inside an SVG does not run |
| `SELFHOST_LOGIN_ORG_NAME` | Optional name shown beside that logo. The default is `SELFHOST_BOOTSTRAP_ORG_NAME`. Public through `login-config`, and only while a logo is set |
| `SELFHOST_PASSWORD_PEPPER_FILE` | Optional file of versioned peppers, one `v<version>:<secret>` per line (for example `v1:...`, `v2:...`). Each secret is at least 32 bytes. The highest version hashes new passwords. See [Pepper file](#pepper-file) for the required permissions |
| `SELFHOST_PASSWORD_ARGON2_MEMORY_KIB` / `_TIME_COST` / `_PARALLELISM` | Optional. These can only raise argon2id above the baseline of 19456 KiB, 2 passes and 1 lane. A lower value refuses to start |
| `SELFHOST_PASSWORD_HIBP` | `off` (the default) or `on`: also refuse passwords found in Have I Been Pwned |
| `SELFHOST_TRUSTED_PROXIES` | Number of reverse proxies in front of the server that append to `X-Forwarded-For`, `0` to `99`. **Required when `password` is enabled: set it explicitly, even to `0`.** Unset or empty refuses to start. Use `1` only behind a single proxy that appends to `X-Forwarded-For` (such as the Helm chart's ingress) with direct pod or Service access restricted; use `0` when clients connect directly. See [Client address](#client-address) |

#### Login config

`GET /api/v1/auth/login-config` is public and returns only what a sign-in page
needs:

```json
{
  "methods": ["email_link", "password"],
  "oidc": { "displayName": "Okta" },
  "logo_url": "https://cdn.example.com/logo.svg",
  "org_name": "Example Corp",
  "allowed_domain_hint": true,
  "password_policy": { "min_length": 12, "max_length": 128 }
}
```

`allowed_domain_hint` is a boolean that says whether auto-join or OIDC
domains are configured. The domains themselves are never returned. Neither are
secrets, peppers or SMTP settings.

#### Flows

Every API route is `POST` with a JSON body. Requests must send a JSON content type
and an `Origin` that matches `SELFHOST_PUBLIC_URL` or the dashboard origin.
Anything else answers `403 csrf_rejected`. Unknown body fields are refused.
Native clients (Desktop, CLI or scripts) that call these routes directly must
also send an `Origin` header equal to one of those two origins. Without
`Origin`, only a request with `Sec-Fetch-Site: same-origin` is accepted.
Browsers send that header themselves. Any other request without `Origin` is
refused.

A password is never chosen before the address is proven. Registration takes
three steps: register, verify and set.

1. **Register.** `POST /api/v1/auth/password/register {email, invite?}`
   - There is no password in the body. `invite` is the token from an invite
     link (at most 256 characters). It is carried into the verification link.
   - The answer is always `202 {"status":"verification_sent"}` for a
     well-formed request, whatever the address.
   - Mail goes only to an address that may join: a configured admin email, an
     existing member, an open invite, or an auto-join domain. That address
     receives a single-use link to
     `<site>/login/password/verify#token=...`, valid for 1 hour. `<site>` is
     the configured origin the request arrived on (`SELFHOST_PUBLIC_URL` or
     the `SELFHOST_DASHBOARD_URL` origin), as for email sign-in links; this
     server serves the page. The
     token sits in the URL fragment, so it never reaches server logs, proxies
     or a `Referer` header. The page's script reads it, clears it from the
     address bar and posts it same-origin with the chosen password
     (`POST /login/password/verify`, form fields `token` and `password`). On
     success the page redirects with `303` to `/` and the session cookie set.
   - A newer request does not cancel older links, so a delayed message still
     works. Using any link voids every other pending link for that address.
   - An address that already has a password receives a pointer to the reset
     page instead.
2. **Verify.** `POST /api/v1/auth/password/verify {token}`
   - Spends the link and answers
     `200 {"status":"verified","email":...,"setupToken":"sh_ps_...","expiresAt":...}`.
   - The set-password token is single-use and valid for 15 minutes. Only its
     SHA-256 hash is stored. Nothing else is written at this step: no account,
     no credential and no session.
   - A used, expired or unknown link answers `410 token_invalid`. If the
     address got a password meanwhile, the answer is `409 password_already_set`.
3. **Set the password.** `POST /api/v1/auth/password/set {token, password}`
   - Checks the password policy (below) against the verified address.
   - Spends the set-password token, creates or joins the account and writes
     the credential in one transaction. Either all of it happens or none of it.
   - Answers `200` with the session cookie and
     `{userId, email, organizationId, workspaceId}`. Membership follows the
     usual sign-in rules for a verified address (invites, auto-join, admin
     emails).
   - A used, expired or unknown token answers `410 token_invalid`. An address
     that already has a password answers `409 password_already_set`.
   - A `token` is always required. Someone who already has an account (from
     OIDC or an email link) adds a password through the same register,
     verify and set steps, which prove control of the mailbox. There is no
     way to add a password from a signed-in session.
   - Once the password is set, a "password added" notice is mailed to the
     address, with a pointer to the reset page.
4. **Sign in.** `POST /api/v1/auth/password/login {email, password}`
   - Answers `200` with the session cookie and the same body as set.
   - Every failure is `401 {"error":"invalid_credentials","message":"Incorrect email or password."}`.
     An unknown address, a wrong password, a locked account or IP, and a
     malformed address all look the same.
   - The `/login` page has a matching email and password form, which posts to
     `POST /login/password` (same-origin form; `email`, `password`, `next`,
     `invite`). On success it redirects with `303` to `next` (a local path;
     anything else becomes `/`). On failure it redirects back to
     `/login?error=invalid_credentials`. This form is what lets CLI login and
     Desktop browser login, which both land on `/login`, work when `password`
     is the only method. With `password` enabled the page also links to the
     dashboard's forgot-password and register pages on the
     `SELFHOST_DASHBOARD_URL` origin, carrying `next` and `invite`. The
     emailed link itself does not carry them.
5. **Request a reset.** `POST /api/v1/auth/password/reset {email}`
   - Always `202 {"status":"reset_requested"}`, for every address.
   - An address with a password receives a link to
     `<site>/login/password/reset#token=...` (the same `<site>` as above). The link is single-use and
     valid for 30 minutes. As with registration the token is in the fragment;
     the page posts it same-origin with the new password
     (`POST /login/password/reset`). Without a token the page offers a form
     to request a new link.
   - The token is stored only as a SHA-256 hash. A newer request does not
     cancel older tokens; completing a reset voids all of them.
6. **Complete a reset.** `POST /api/v1/auth/password/reset/complete {token, password}`
   - Checks the policy against the account's email, then sets the new password.
   - In the same transaction it:
     - revokes every browser, CLI and Desktop session of that person
       (`revoked_reason = password_reset`) and every MCP OAuth grant;
     - deletes the person's Desktop relay identities (the Relaycast agent
       tokens Desktop synced), so this server's MCP endpoint stops acting as
       those agents. The tokens themselves are not revoked at Relaycast: a
       copy still works against Relaycast directly until Desktop replaces it.
       Desktop syncs its identities again after the person signs in;
     - expires approved device authorizations that have not been collected yet
       (the polling client then gets `expired_token`);
     - voids unredeemed MCP authorization codes;
     - cancels outstanding reset, registration, set-password and email sign-in
       tokens;
     - clears the account's lockout (every counter for that address).
   - Answers
     `200 {"status":"password_reset","revoked":{"sessions":n,"mcpGrants":n,"desktopRelayIdentities":n,"deviceAuthorizations":n,"mcpCodes":n}}`
     and clears the session cookie. The person then signs in again.
   - A "password changed" notice is mailed to the address afterwards.
   - Not touched: person messaging identities (the person's human agent in
     each workspace, used for direct messages) and workspace API keys. API
     keys belong to the workspace rather than to the person. Rotate them
     separately if needed.
   - A reset takes the address's identity lock first, the same lock a sign-in
     holds while it issues a session. A sign-in whose verify started before the
     reset re-reads the credential under that lock and fails with the usual
     `401` if the hash changed, so it can never leave a live session behind.

Registration mail and reset mail have separate buckets: each allows 3 messages
per address and 10 per IP every 10 minutes. Above the limit the answer stays
the same `202` and no mail is sent. Verify, set and reset-complete accept 30
attempts per IP every 5 minutes, and password sign-in 60 per IP per minute
(`429 rate_limited`).

At most 8 argon2id hashes or verifies run at once in each replica. When all 8
are busy, sign-in, set and reset-complete answer `429 rate_limited` at once
instead of queueing. A sign-in refused this way is not counted as a failure:
when the slots fill after the attempt was reserved against the lockout
counters, the reservation is given back before the `429`.

#### Error codes

| Status | `error` | When |
|---|---|---|
| 400 | `invalid_request` | The body is not the expected JSON object |
| 400 | `email_invalid` | Register with an address that is not an email |
| 400 | `password_too_short` / `password_too_long` | Fewer than 12 or more than 128 characters |
| 400 | `password_common` | On the bundled common-password list |
| 400 | `password_contains_email` | Contains the address's local part |
| 400 | `password_breached` | Found by the HIBP check (only when `SELFHOST_PASSWORD_HIBP=on`) |
| 401 | `invalid_credentials` | Any failed sign-in |
| 403 | `csrf_rejected` | Wrong content type, or a missing or foreign `Origin` |
| 404 | `signin_method_disabled` | The method is not in `SELFHOST_SIGNIN_METHODS` |
| 405 | `method_not_allowed` | Not `POST` |
| 409 | `password_already_set` | Verify or set for an address that already has a password |
| 410 | `token_invalid` | A used, expired or unknown verify, set-password or reset token |
| 429 | `rate_limited` | Too many sign-in, verify, set or reset-complete attempts from one IP, or all argon2id slots are busy |

#### Password policy

- Between 12 and 128 characters, counted as Unicode code points after NFC
  normalisation. There are no composition rules.
- Not on the bundled list of the 10,000 most common passwords (SecLists, MIT,
  see `NOTICE`). The check ignores case and a short trailing run of digits or
  symbols, so `Sunshine2024!` counts as common.
- Does not contain the email's local part, when that is 3 characters or more.
- With `SELFHOST_PASSWORD_HIBP=on`, it is also not in Have I Been Pwned. Only
  the first 5 hex characters of the SHA-1 leave the server (k-anonymity range
  API, with padding). If HIBP cannot be reached within 3 seconds the check
  fails open: the password is accepted and a `password.hibp.unavailable`
  audit event is recorded.

#### Hashing

- Passwords are hashed with argon2id, at least m=19456 KiB, t=2, p=1 (the
  OWASP baseline), with a 16-byte random salt.
- The hash is stored as a PHC string together with its parameters and pepper
  version. The pepper itself is never stored.
- With a pepper file, the password is first HMAC-SHA256'd with the current
  pepper.
- On a successful sign-in the password is re-hashed if the parameters were
  raised or the pepper version changed. Keep an old version in the file until
  its hashes have been re-hashed, because a removed version can no longer
  verify.
- The library is `@node-rs/argon2`. It ships prebuilt native binaries for
  every platform we build on, so the image's `npm ci --ignore-scripts` needs no
  compiler or install script. It wraps the reference RustCrypto argon2
  implementation, and its verify compares in constant time.
- An unknown account still spends one argon2id verify against a dummy hash,
  so its response time matches a wrong password. A locked attempt answers
  without any argon2id work.
- At most 8 hashes or verifies run at once per replica; above that the
  request answers `429 rate_limited` without waiting.

#### Pepper file

The pepper file is a secret, so the server refuses to start unless only its
own user can read it:

- It must be a regular file (not a directory or device).
- It must be owned by the user the server runs as.
- It must have no group or other permission bits. Use `chmod 600` (or `400`).
  A mode such as `644`, `640` or `604` refuses to start.

Every line is `v<version>:<secret>`, and each secret is at least 32 bytes.
Blank lines and `#` comments are ignored. To rotate, add a higher version and
keep the old line until its hashes have been re-hashed on sign-in. When the
file comes from a mounted secret, make sure the mounted file ends up owned by
the server's user with mode `0400` or `0600`. A root-owned or group-readable
mount refuses to start.

On Kubernetes a Secret volume is owned by root, with group bits from
`fsGroup`, so the file check fails when the file is mounted directly. Either
copy it in an init container into an `emptyDir` with mode `0400`, owned by the
server's uid, and point `SELFHOST_PASSWORD_PEPPER_FILE` at the copy, or use a
projected volume whose ownership and `defaultMode` give the server's uid sole
read access.

#### Client address

Rate limits, lockouts and audit records use one client address. By default
(`SELFHOST_TRUSTED_PROXIES=0`) it is the TCP peer address, and
`X-Forwarded-For` and `X-Real-IP` are ignored, because any client can send them.

Behind reverse proxies, set `SELFHOST_TRUSTED_PROXIES` to the number of proxies
that append to `X-Forwarded-For`. Use `1` only for a single proxy that appends to the
header (for example the Helm chart's ingress) and only when direct access to the
pod or Service that bypasses that proxy is restricted; any other proxy chain
needs its actual hop count. The client address is then the Nth entry from the right, the one
the outermost trusted proxy appended. Entries further left are client-supplied
and never trusted. With `password` enabled the variable must be set
explicitly, even to `0`; unset or empty refuses to start and names the
variable. Use `0` when clients connect directly.
Setting the number higher than the real proxy count lets
clients pick their own address. Setting it lower makes every request share the
proxy's address. The chosen entry is reduced to a bare IP (brackets, a port
and an IPv4-mapped `::ffff:` prefix are dropped); an entry that is not an IP
falls back to the TCP peer address.

The same address is used for the device-flow and Desktop limits. For
per-IP limits and the IP lockout, an IPv6 address is bucketed by its /64
prefix, because one host usually holds a whole /64. Audit records keep the
full address.

With `SELFHOST_TRUSTED_PROXIES=0` the IP lockout, like every per-IP limit,
always uses the TCP peer address, whether or not the request carries
`X-Forwarded-For`; a forged header cannot move a client to another counter.
When a request does carry the header, the server logs one warning per
process: the header was seen with 0 trusted hops, per-IP limits use the
socket address, and `SELFHOST_TRUSTED_PROXIES` should be set if a proxy is in
front.

**Upgrade note.** Earlier builds took the leftmost `X-Forwarded-For` entry, then
`X-Real-IP`. Deployments behind a proxy must now set
`SELFHOST_TRUSTED_PROXIES` to the number of proxy hops (`1` only for a single
proxy that appends to the header, with direct pod or Service access restricted); with the default
`0` every client shares the proxy's address for per-IP limits. With
`password` enabled the variable must now be set explicitly (even to `0`), or
the server refuses to start. `X-Real-IP` is no longer read.

#### Lockout

Failed sign-ins are counted in Postgres (`login_attempts`) under
three subjects. The account is the normalized email, also for addresses with
no account; the client is the client address (IPv6 by /64).

| Subject | Limit | Then |
|---|---|---|
| Account and client | 5 free failures | Locked for 30 s, doubling with each further failure, capped at 15 minutes |
| Account, from every client | 50 failures in a rolling hour | Locked for 15 minutes |
| Client, across every account | 30 free failures | Same backoff as the first row |

- The short lock is per account and client, so a guesser elsewhere cannot
  lock the owner out with a handful of attempts. The account-wide limit
  stops a guess spread over many addresses.
- When the account-wide lock engages, the owner is mailed a notice ("Too many
  failed sign-ins"), at most once every 24 hours.

- An attempt is reserved in Postgres before any argon2id work starts, in a
  single row-locked update. Parallel requests cannot all slip in before the
  first failure is recorded. Once the free failures are used, each lock window
  admits exactly one attempt, however many requests arrive at once.
- A counter starts over after 1 hour without failures.
- While a lock lasts, even the right password gets the same `401`. Attempts
  refused during a lock are not counted and do not extend it.
- A successful sign-in clears the account-wide counter and its own account
  and client counter, and gives back the client attempt it reserved. Other
  clients' counters for the account stay. A completed reset clears every
  counter for the account.
- A locked or refused attempt writes no audit row. One `login.lockout` row is
  written when a lock engages or escalates.

**Limiter and lockout.** There are two layers, and they do different jobs:

- The lockout above is shared by every replica, because it lives in Postgres.
  It is the guessing defence.
- The `429 rate_limited` limits on verify, set and reset-complete, and the mail
  limits on register and reset, are in-memory and per replica. With N replicas
  a client can get up to N times those numbers. They protect the server from
  load, not the account.

**Lock trade-off.** The reservation holds a row lock on the subject's counter
only for the short update, not during the argon2id work. The argon2id hash runs
after the reservation commits. This keeps a slow hash from blocking other
sign-ins on the same account or IP. The cost is that a reserved attempt counts
even if the request later fails for another reason, such as a client
disconnect or a server error. Holding the lock through the hash would avoid
that, but it would serialise every sign-in from one IP (a shared NAT or proxy)
behind argon2id.

#### Retention

An hourly sweep in each replica deletes:

- login attempt counters with no activity for 24 hours (well past the 1-hour
  reset);
- registration links, set-password tokens and reset tokens that were spent
  or expired more than 7 days ago.

Credentials and the audit log are not swept.

#### Audit events

All of these are recorded in `admin_audit_events`. Targets carry the
address and a reason, never a password, hash or token.
- `login.password.success`, with `rehashed=true` when the hash was upgraded
- `login.password.failure`, with reason `wrong_password`, `unknown_account`,
  `invalid_email` or `credential_changed` (a reset landed during the verify).
  Attempts refused by a lock are not recorded.
- `login.lockout`, with scope `account_key`, `account` or `ip`, once each time
  a lock engages or escalates
- `password.registration.verified`
- `password.registration.completed`
- `password.reset.requested`
- `password.reset.completed`, with revocation counts (including
  `desktop_relay_identities_deleted`)
- `password.hibp.unavailable`

#### Limitations

- A password can only be added through a mailed link, never from a
  signed-in session. Sessions carry no sign-in time, so a session path could
  not check recency, and a stolen session cookie could have been turned into
  a durable password. Someone with mailbox access can still add a password to
  an existing account; the "password added" notice goes to that same mailbox.
  SSO-only installations should leave `password` out of
  `SELFHOST_SIGNIN_METHODS`.
- A hash made with older (weaker) argon2id parameters or an older pepper
  version still verifies at its stored cost until the person's next
  successful sign-in re-hashes it. Raising the parameters does not upgrade
  hashes of people who do not sign in. A reset always hashes with the current
  parameters.
- The per-IP `429` limits and the argon2id slot cap are per replica.

Migration `0029_password_signin.sql` adds the credential, pending
registration, set-password token, reset token, login attempt and admin email
grant tables.

### Break-glass: the bootstrap bearer

`SELFHOST_BOOTSTRAP_TOKEN` can still:
- approve a `/login` device code for any member (`POST /api/v1/auth/device/approve`
  with `user_id` and `workspace_id`);
- create invitations and manage memberships.

Keep it in the Secret and use it only when no sign-in method works.

The bootstrap bearer is an installation-wide operator credential in both
modes: it reaches every organization. With `SELFHOST_TENANCY=multi` every use
against an organization route is written to `admin_audit_events`
(action `bootstrap.access`, actor `bootstrap`, target `METHOD path`).

**Rotating it.** The token is read at startup and compared on each request;
nothing derived from it is stored. To rotate: write a new value of at least
32 bytes to the Secret, restart (roll) every API replica, and confirm the old
value gets `401` while the new one gets `200` on
`GET /api/v1/installation/settings`. Sessions, device tokens and Desktop
tokens are unaffected. Rotate after anyone who held it leaves, and whenever
the `bootstrap.access` audit rows show use you can't account for.

### Tokens other services verify

Every sign-in method ends in the same `sh_at_` access token. The sessions
pipeline ingest edge (and relayfile) accept that token directly and verify it
through `POST /internal/v1/auth/introspect`, authenticated with
`RELAYCONTROL_INTROSPECT_SECRET`. The answer comes from the live token
session, so removing a member, revoking a session or refreshing the token
takes effect on the service's next check; refresh, bootstrap and worker
tokens, and every workspace API token other than a relayfile agent or
acquisition operator token (below), are always reported as `wrong-kind` (an
`sh_wk_` that matches no token is `unknown`). See
[RelayHistory (sessions pipeline)](../README.md#relayhistory-sessions-pipeline).
`GET /readyz` lists the accepted audiences (`introspection.audiences`, empty
while introspection is disabled), so a scheme or port mismatch shows up there
instead of as a runtime 401.
Flows workers carry another kind: an opaque per-run `sh_fr_` Relayfile
credential minted through the Flows credential broker. It introspects as
principal `agent` (`agent_name` `flows-run-<runId>`) with only the run's
`relayfile:fs:*` path scopes, for the worker Relayfile origin alone, and is
revoked when the run ends. See
[docs/flows-relayfile-credential.md](flows-relayfile-credential.md).
The sessions pipeline ingest edge is such a service: it introspects the
upload credential (the caller's own `sh_at_` token, handed back by
`POST .../relayhistory/session` with `mode: "sync"`) with the public History
origin as `aud` on every upload. History reads do not use it: the read API
issues its own read tokens through Control's handoff. See
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

#### Database outage hold

The ingest edge has no positive cache, so without help every Desktop upload
stops the moment Control's database stops answering, even for tokens Control
verified seconds earlier. `SELFHOST_INTROSPECT_OUTAGE_HOLD_MS` closes that gap
for Desktop user tokens. It is off by default (unset or `0`); otherwise it is
an integer from 1000 to 3600000 milliseconds, and any other value refuses
startup. `GET /readyz` shows the value in effect as
`introspection.outageHoldMs`.

While the database answers nothing changes: every introspection runs the
query, and the hold is never consulted. Each active answer for an `sh_at_`
token is remembered in memory, keyed by the token hash (never the token),
with the time of the check; an `unknown`, `revoked` or `expired` answer
removes it. At most 10000 tokens are remembered per process, least recently
used first out. When the query then fails with a connection-class database
error (connection refused, reset or timed out, DNS failure, pool connect
timeout, connection terminated, SQLSTATE class `08`, `57P01`-`57P03`,
`53300`), and only then, the remembered answer for that token is served if it
is at most the hold old and the token has not expired. Held answers stop one
second before the hold or the token would run out, so a verifier never reads
a held `exp` as already passed. Any other error, a
token with no remembered answer, or a stale one still fails with 500 as
before, so the edge keeps answering 503. The hold is per process: each
replica remembers only the tokens it verified itself.

The verifier sees the normal active answer plus `held: true`, with `exp`
clamped to the earlier of the token's expiry and the end of the hold. The
audience and `workspace` checks still run against the request. A request that
sends `machine` is never held: machine ownership needs the node-claims query,
so it still fails with 500. `sh_wk_` and `sh_fr_` tokens are never held.

The bound this accepts: a revocation, membership removal or workspace removal
that happened after the token's last successful introspection and before the
outage is not visible until the hold runs out or the database returns. The
Desktop uploads, and so introspects, continuously, so for an active Desktop
that window is the gap since its last upload. Each held answer is logged as
`[selfhost-api] token introspection held` with `token_id`, `aud`,
`workspace`, `age_ms` (time since the last successful check) and `cause` (the
error's errno or SQLSTATE); the token is never logged.

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

#### Relay node tokens

A relay node host presents a workspace API token of purpose `relay-node`,
minted through the same routes with
`{label, purpose: "relay-node", nodeName, expiryDays?}` (scopes fixed to
`relay:workspace:read`, `relay:nodes:read`, `relay:nodes:enroll`,
`relay:agents:read`; expires within 365 days; several per `nodeName`). It is
accepted only by the `/relay-node/v1` broker; every other workspace API token
gate treats it as no credential and introspection answers `wrong-kind`. See
[relay-node-credential.md](relay-node-credential.md).

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

**Single mode (the default).** An email the provider did not mark unverified
signs in when one of these is true:
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
start) the bootstrap organization's rows in `organization_domains`
are made equal to the normalized list (lowercase, IDNA ASCII, a leading `@`
dropped): missing rows are inserted, extra rows deleted, and all rows are
cleared when the variable is absent or empty, which means no auto-join, as
before 0014. A change takes effect on the next restart. The domain routes
answer `409 domains_managed_by_env` to `PUT` and `DELETE` in single mode.

**Multi mode.** The organization a sign-in lands in is chosen in this order:
1. the invite the person followed, then every other open invite for the
   email (each is accepted; the session lands in the last one accepted);
2. otherwise an existing membership: the remembered organization
   (`users.last_organization_id`) when still a member, else the
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
`installation_bootstrap`, never "the only organization".

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
that omits the claim signs in but does not auto-join, unless you name its
issuer; see [Providers that omit `email_verified`](#providers-that-omit-email_verified)),
or an email sign-in link (the link proves the mailbox). An invite or an existing membership always
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

Hosted MCP OAuth connectors (`mcp_at_`/`mcp_rt_`) are on by default and work only
at their granted MCP resource; see [mcp-oauth.md](mcp-oauth.md).

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
  IF (SELECT count(*) FROM organizations) <> 1 THEN
    RAISE EXCEPTION 'rollback of 0014 requires exactly one organization';
  END IF;
END
$$;
-- telemetry organization column
DROP INDEX IF EXISTS telemetry_outbox_organization_idx;
ALTER TABLE telemetry_outbox DROP COLUMN IF EXISTS organization_id;
-- domains, selections, kill switches, single-organization constraint
ALTER TABLE installation_bootstrap
  DROP COLUMN IF EXISTS personal_org_signup_enabled,
  DROP COLUMN IF EXISTS self_serve_organizations_enabled;
DROP TABLE IF EXISTS organization_domains;
ALTER TABLE users
  DROP COLUMN IF EXISTS last_organization_id,
  DROP COLUMN IF EXISTS last_workspace_id;
ALTER TABLE organizations
  ADD COLUMN installation_slot smallint NOT NULL DEFAULT 1,
  ADD CONSTRAINT organizations_single_slot CHECK (installation_slot = 1);
CREATE UNIQUE INDEX organizations_singleton_idx
  ON organizations (installation_slot);
CREATE UNIQUE INDEX single_organization_idx
  ON organizations ((true));
DELETE FROM control_schema_migrations
 WHERE name = '0014_multi_tenant.sql';
COMMIT;
```

What is lost: the operator-assigned domains (in single mode they are a copy
of `SELFHOST_AUTO_JOIN_DOMAINS`, which the old image reads directly), the
remembered selections, the kill-switch overrides, and the organization
attribution of queued issue reports. Sessions issued with `account` or
`desktop:workspaces` keep working on the old image, which ignores scopes it
does not know. Upgrading again re-applies the migration.
