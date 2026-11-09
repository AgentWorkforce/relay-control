# Flows run Relayfile credential (self-host)

Status: design note, 2026-11-09. Owners: relay-control issuer and introspection
(layered-control); relayfile-control dispatch and verification
(layered-relayfile); worker acceptance (relayflows-node-spawn, see §7);
Relayfile dual-mode prefix routing (layered-relayfile, see §5).

## 1. Problem

A Flows worker mounts the run's Relayfile paths with the `relayfileToken` in
its assignment payload. Cloud fills it with a RelayAuth path-scoped `relay_pa_`
token. Self-host has no RelayAuth, so both Flows stores hand workers
`relayfileToken: ""` and native Flows-to-File cannot work. The only self-host
Relayfile credential today is the owner-minted workspace API token
(`sh_wk_`, purpose `relayfile-agent`), which is workspace-wide and long-lived.
Workers must never receive one.

## 2. Credential

- **Shape:** opaque bearer `sh_fr_<random>` (same generator as other
  relay-control tokens), stored as a sha256 hash with its 10-char prefix.
  No JWT, no refresh token. Nothing about it is derivable offline.
- **Binding:** exactly one active credential per run. Issuing again for the
  same run revokes the previous one (redelivery, retry).
- **Scope = the run's paths.** The caller passes `mountPaths` (Cloud
  semantics: the run root first, provider roots after). relay-control emits
  the scopes the worker and Relayfile already understand, mirroring Cloud's
  `relayAuthTokenPathsForMountPaths`: for each root `p`,
  `relayfile:fs:read:p`, `relayfile:fs:read:p/*` and, unless `readOnly`,
  `relayfile:fs:write:p`, `relayfile:fs:write:p/*`. No `fs:*`, `sync:*`,
  `manage` or `*` scopes ever.
- **Path rules (refused with 400 `invalid_mount_paths`):** 1 to 16 paths,
  each absolute, normalized (no `.`/`..` segments, no trailing slash, no `*`,
  no control characters, max 512 chars); the first path must be
  `/workflows/runs/<runId>` for this run or `/workflows/schedules/<id>`.
- **Audience:** the normalized origin of the Relayfile URL handed to workers
  (`SELFHOST_FLOWS_WORKER_RELAYFILE_URL`). It must be one of relay-control's
  accepted introspection audiences (`SELFHOST_INTROSPECT_AUDIENCES`);
  otherwise issuing fails 409 `relayfile_audience_not_accepted` and the
  message names both settings.
- **TTL = the run.** `expiresAt = issuedAt + SELFHOST_FLOWS_RELAYFILE_CREDENTIAL_TTL_MS`
  (default 12 h, min 5 min, max 24 h) as a hard horizon; the real end of life
  is revocation when the run ends (§4). Workers see `relayfileTokenExpiresAt`
  and treat expiry as terminal (no rotation on self-host).

## 3. Issue route (relay-control, Flows credential broker)

`POST /internal/v1/flows/credentials/relayfile` behind the existing broker
bearer (`RELAYFILE_CONTROL_BROKER_SECRET`; unset = 404 like its siblings).

Request `{ workspaceId: uuid, runId: uuid, mountPaths: string[], readOnly?: boolean, aud?: string }`.
`aud`, when sent, is the audience the caller expects; it must normalize to the
origin of `SELFHOST_FLOWS_WORKER_RELAYFILE_URL`.

200 `{ credentialId, relayfileToken, relayfileTokenExpiresAt, relayfileMountPaths, scopes, aud }`.
`credentialId` is the credential's id, equal to the `sub`/`token_id` that
introspection returns for the token.
The token appears only in this response body (never logged, never audited
in clear; the audit row records credential id, run id, paths and expiry).

Refusals (JSON `{error, message}`): 400 `invalid_request` /
`invalid_mount_paths`; 404 `relayfile_not_configured` when relay-control has
no worker Relayfile URL or no introspection secret (so the data plane could
not verify anything); 409 `relayfile_audience_not_accepted` when the worker
Relayfile origin is not an accepted introspection audience, or when a
requested `aud` does not match that origin (each with its own message).

## 4. Revocation

- The in-process Flows store revokes the run's Relayfile credential in the
  same transaction that completes, fails or cancels its local run. Local
  assignment issuance locks the matching workspace/run row in its mint
  transaction and refuses terminal runs, so an assignment racing completion
  cannot leave a late credential active. This local check does not apply to
  broker issuance: externally stored runs need no `workflow_runs` row here.
- `POST /internal/v1/flows/credentials/revoke` `{ runId }` (existing route,
  already called by relayfile-control's run-end outbox) now also revokes the
  run's Relayfile credential. relayfile-control needs no new call for this.
  It is idempotent: a run that never had a Relayfile credential (or whose
  credential is already revoked) still answers 200 `{ revoked: true }`.
- Re-issue for the same run revokes the earlier credential.
- Revoked or expired credentials introspect inactive (`revoked` / `expired`).
  Relayfile caches positive verdicts for at most 60 s, so revocation is
  visible within a minute.
- Rows are kept for audit; a housekeeping delete after 7 days past expiry
  is optional.

## 5. Verification route (what Relayfile sees)

Relayfile already verifies self-host bearers through
`POST /internal/v1/auth/introspect` on relay-control. `sh_fr_` tokens are
answered there, next to `sh_at_` and `sh_wk_`:

- active: `{ active: true, sub: <credential id>, token_id: <credential id>,
  principal_type: "agent", agent_name: "flows-run-<runId>", email: null,
  machine_id: null, org, workspace, scopes: <stored scopes>, aud, iat, exp }`.
- inactive reasons: `unknown`, `revoked`, `expired`, `audience` (request
  `aud` differs from the stored one), `workspace` (request workspace differs),
  `machine_not_owned` (a machine was asked about), `wrong-kind` never applies.
- `agent_name` fits Relayfile's agent-name pattern, so ACL `agent:` rules and
  audit lines can name a run.

Relayfile's `introspection` auth mode forwards every bearer and needs no
change. Its `dual` mode routes by prefix (`sh_at_`, `sh_wk_`) and must learn
`sh_fr_` (layered-relayfile); until then dual-mode installs refuse the
credential with 401.

## 6. relayfile-control dispatch (layered-relayfile)

At assignment, compute the run's mount roots the way Cloud does (run root
plus provider roots) and call §3. On 200 put `relayfileToken`,
`relayfileTokenExpiresAt` and `relayfileMountPaths` in the payload (Cloud
field names, no refresh fields). On any refusal or broker error, **omit**
`relayfileToken` (never `""`), append a run event
`run.relayfile_credential_unavailable` with the error code, and let the run
proceed; the worker then refuses Flows-to-File with that reason instead of
mounting nothing silently. relay-control's own legacy Flows store does the
same through the in-process issuer until that store is removed.

## 7. Worker acceptance (relayflows-node-spawn)

The worker launcher's scoped-workflow path accepts only `relay_pa_` tokens
with mount paths. It must also accept `sh_fr_` when
`metadata.controlPlane === "relaycontrol"`, derive scopes from
`relayfileMountPaths` exactly as above, treat a missing `relayfileToken` as
"Relayfile unavailable: <reason>" (clear failure of file steps, not a mount
of nothing), and never fall back to a workspace token.

## 8. Tests and proof

relay-control: broker route (issue, refusals, re-issue revokes, revoke on run
end), introspection answers for active/revoked/expired/wrong-aud/wrong-workspace,
no token in logs or audit, legacy store payload omits `relayfileToken` when
unconfigured. relayfile-control: payload carries the credential on 200 and
omits it with the run event otherwise. Kind proof: a Flows-to-File run writes
under `/workflows/runs/<runId>` and is refused outside it.
