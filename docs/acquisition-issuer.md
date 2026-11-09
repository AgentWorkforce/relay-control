# Acquisition assertion issuer (dormant, cloud class)

relaycontrol can sign the acquisition assertions that the RelayHistory pipeline's acquisition
service verifies (relayhistory-pipeline PR #331, `docs/acquisition-exchange.md`). The pipeline
is verify-only: it holds no private key and accepts envelopes signed by a `cloud`-class key
pinned in its `ACQUISITION_PINNED_KEYS`. This issuer is that key's holder for a self-hosted
install.

It is **off by default**. With `SELFHOST_ACQUISITION_ISSUER_ENABLED` unset or `false`, no other
issuer variable is read, and every `/api/v1/acquisition/*` route (and its `/cloud` alias)
answers `404 {"error":{"code":"not_found"}}`, the same as an unknown route.

It stores nothing durable. There is no migration. Each issued envelope writes one audit event
(`acquisition.assertion.issued`, target `<kind> <operationUuid> key <issuerKeyId>`, plus
`reserved-revoke <uuid>` when one was minted). Signatures and digests are never logged.

## Configuration

| Variable | Meaning |
| --- | --- |
| `SELFHOST_ACQUISITION_ISSUER_ENABLED` | `true` turns the issuer on. Empty or `false` (the default) leaves it off. Anything else refuses startup. |
| `SELFHOST_ACQUISITION_ORIGIN` | Required when enabled. The acquisition service's public origin, the same value as the pipeline's `ACQUISITION_ORIGIN`. It must be a bare http(s) origin and must also be listed in `SELFHOST_INTROSPECT_AUDIENCES`. |
| `SELFHOST_ACQUISITION_ISSUER_KEY_ID` | Required when enabled. The `issuerKeyId` stamped into every payload and published with the key: 1-512 characters, no control characters. |
| `SELFHOST_ACQUISITION_ISSUER_PRIVATE_KEY` | Required when enabled (`_FILE` supported). An unencrypted PKCS#8 PEM Ed25519 private key. |
| `SELFHOST_ACQUISITION_ISSUER_PREVIOUS_PUBLIC_KEYS` | Optional. A JSON array of `{issuerKeyId, publicKeyBase64}` (raw 32-byte Ed25519, standard base64). These are published after the active key during a rotation. Ids and keys must be unique, including against the active key. |

Enabling the issuer also requires `RELAYCONTROL_INTROSPECT_SECRET`, because callers are
verified through the introspection internals.

Startup fails closed. A missing or invalid variable stops the server with a message that names
the variable and never contains its value.

### Generating a key

```sh
umask 077
openssl genpkey -algorithm ed25519 -out acquisition-issuer.pem
# Raw 32-byte public key, standard base64, for ACQUISITION_PINNED_KEYS:
openssl pkey -in acquisition-issuer.pem -pubout -outform DER | tail -c 32 | base64
```

Store the PEM in the deployment's secret store and mount it as
`SELFHOST_ACQUISITION_ISSUER_PRIVATE_KEY_FILE`. Do not paste it into a shell history or a
ticket. The public key may be printed.

### Pinning into the pipeline

Once the issuer is enabled, `GET /api/v1/acquisition/issuer-keys` returns the exact value for
the pipeline's `ACQUISITION_PINNED_KEYS`:

```sh
curl -fsS "$SELFHOST_PUBLIC_URL/api/v1/acquisition/issuer-keys" | jq -c .keys
# [{"issuerKeyId":"relaycontrol-acq-2026-11","issuerClass":"cloud","publicKeyBase64":"..."}]
```

You can also set it from the openssl output above with
`[{"issuerKeyId":"<SELFHOST_ACQUISITION_ISSUER_KEY_ID>","issuerClass":"cloud","publicKeyBase64":"<base64>"}]`.

Two things must also be in place:

- **Audience.** List the same origin in `SELFHOST_INTROSPECT_AUDIENCES`. Startup refuses if it
  is missing. Without it, neither this issuer nor the pipeline's ops routes can introspect a
  token minted for that audience.
- **Rotation.**
  1. Generate a new key and pin both old and new in `ACQUISITION_PINNED_KEYS`.
  2. Switch `SELFHOST_ACQUISITION_ISSUER_KEY_ID` and `SELFHOST_ACQUISITION_ISSUER_PRIVATE_KEY`
     to the new key, and keep the old public key in
     `SELFHOST_ACQUISITION_ISSUER_PREVIOUS_PUBLIC_KEYS`.
  3. Once no envelope signed by the old key can still be in flight (including reserved
     revokes), remove the old key from both places.

## Routes

All responses are `Cache-Control: no-store`. Errors use the pipeline shape
`{"error":{"code":"..."}}`. The routes are also served under `/cloud`.

| Route | Auth | Result |
| --- | --- | --- |
| `GET /api/v1/acquisition/issuer-keys` | none | `{"keys":[{issuerKeyId, issuerClass:"cloud", publicKeyBase64}]}`, active key first |
| `POST /api/v1/acquisition/assertions/install` | operator or Desktop user | Signed install envelope, plus an optional reserved revoke |
| `POST /api/v1/acquisition/assertions/revoke` | operator only | Signed revoke envelope |
| `POST /api/v1/acquisition/assertions/rebind` | operator or Desktop user | Always `409 native_receiver_contract_pending` |

Request body: the unsigned pipeline payload for that kind, where every field is a string, every
field is required and no unknown keys are allowed. On top of that:

- `aud` is required and must equal `SELFHOST_ACQUISITION_ORIGIN`.
- `issuerKeyId` is optional. If present, it must be the active key id; the issuer always stamps
  its own.
- On install only, `reserveRevoke: true` with
  `reservedRevoke: {revision, targetGrantId, targetOwnerEpoch, operationUuid?}`. This returns a
  second envelope, `revokeEnvelope`, that revokes this install:
  - The org, workspace, source, session, `targetOwnerKind`, `targetBindingUuid` and
    `targetInstallationId` are copied from the install.
  - `operationUuid` defaults to a fresh random UUID and must differ from the install's.

Response: `{kind, issuerKeyId, issuedAt, envelope:{payload, signature}, revokeEnvelope?}`. The
`payload` contains the request fields plus `issuerKeyId`, `evidenceSha256` and `requestSha256`,
computed with the pipeline's codec, and the signature is base64url Ed25519. Forward the
envelope verbatim to the pipeline's `/v1/acquisition/ops/*`.

Errors:

| Status | Code | When |
| --- | --- | --- |
| 404 | `not_found` | Issuer disabled, or an unknown kind |
| 405 | `method_not_allowed` | Wrong method (with `Allow`) |
| 401 | `unauthorized` | Missing, unknown or inactive (revoked or expired) bearer, including an `sh_wk_` with no such token and a string that is not a recognised token kind; a real token of another kind, audience or workspace is 403 |
| 403 | `not_authorized` | Any principal other than the two below; token or body `aud` other than the origin; `orgId`/`workspaceId` outside the caller's workspace; a Desktop user issuing for another `ownerUserId`, or issuing a revoke |
| 400 | `invalid_request` | Bad JSON; missing, unknown or invalid field; `ownerKind`/`targetOwnerKind` other than `cloud` (so `native` is 400); a foreign `issuerKeyId`; a malformed reserved revoke |
| 409 | `native_receiver_contract_pending` | `rebind`, for an authorized caller |

## Scopes and callers

Callers are verified through the same internals as `POST /internal/v1/auth/introspect`, with
`aud = SELFHOST_ACQUISITION_ORIGIN`:

- **Acquisition operator.** A workspace API token (`sh_wk_`) of purpose `acquisition-operator`.
  It carries scope `acquisition:operate`, and its stored aud must equal the origin (see
  [identity.md](identity.md#acquisition-operator-tokens)). This is the same token the pipeline
  ops routes accept. The token can issue for its own org and workspace only.
- **Desktop user.** A user access token (`sh_at_`) carrying `rth:acquire`, meaning a
  Desktop-issued session (see [identity.md](identity.md#desktop-session-scopes)).
  - It can only issue an install whose `ownerUserId` is the caller, in the session's org and
    workspace, while the caller is still a member.
  - Browser handoff tokens and pending handoffs are refused.
  - Like introspection, this needs a single-organization install.
- A missing or inactive bearer is `401 unauthorized`. Everything else is `403 not_authorized`: dashboard browser sessions (scope `account`), other
  workspace token purposes, the internal service token, the bootstrap token, and worker or run
  tokens.

## Native receiver contract (tracked gap)

Only `cloud`-class assertions are issued here. Native (Desktop-owned) acquisition has no
receiver yet:

- **Issuing owner:** relay-control. This issuer is where native
  issuance will be added.
- **Receiver:** a dedicated verification class and scope in relayhistory-pipeline. That is a
  follow-up there. Its source target is the pipeline ops listener from PR #331, which today
  verifies cloud class only and refuses native-class pinned keys at startup.
- **Until then:**
  - `ownerKind: "native"` (install) and `targetOwnerKind: "native"` (revoke) are `400` here.
  - `rebind`, which is native-only in the codec, is `409 native_receiver_contract_pending`
    here, and `403` at the pipeline's `ops/rebind`.
- **Pipeline signing:** nobody restores it. The pipeline stays verify-only, and cloud-class
  keys are never trusted for native.
