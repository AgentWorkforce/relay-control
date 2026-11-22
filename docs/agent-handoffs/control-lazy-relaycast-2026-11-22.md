# Control lazy Relaycast binding — restart handoff

Checkpointed on 2026-11-22 for the linuyc machine reset.

## 1. Owned work

The owned slice was lazy Relaycast binding in `AgentWorkforce/relay-control`,
including coordination of the required engine-side idempotent workspace-create
contract in `AgentWorkforce/relaycast`. The Control implementation is complete
and merged. No new work is in progress.

## 2. Pull requests and branches

- `AgentWorkforce/relay-control` PR
  [#169](https://github.com/AgentWorkforce/relay-control/pull/169) merged as
  `ad90ad7cd38a081c4e3bc5afd8c892c5270d8270`. Its reviewed PR head was
  `c69215c28d8951914bcf72ff69ec9ecdc34c4f7d`; the remote feature branch has
  been deleted.
- Required companion `AgentWorkforce/relaycast` PR
  [#687](https://github.com/AgentWorkforce/relaycast/pull/687) remains open and
  draft on `batch/20261116-0601` at
  `cf887cfff2e101810e5768e0f43d9d9b5608cb73`. Its CI was green when this
  checkpoint was written.
- This handoff is stored on branch
  `checkpoint/control-lazy-relaycast-reset-20261122`, based on relay-control
  main `6e201e2850b7b2bcadfe41091d29ba8d305173d8`.

## 3. Mid-run state

Nothing from this slice is running: no migration, build, deploy, test, database
operation, or other long job. The machine is safe to interrupt. No credentials
or secret values are needed to recover this work.

The final Control validation before merge passed:

- manifest readers: 9/9
- isolated manifest harness: 81/81
- focused lazy-binding suite: 16/16
- real PostgreSQL focused suite: 33/33 with zero skips
- TypeScript typecheck

## 4. Decisions still required from Khaliq

Khaliq's direct approval is required before merging Relaycast PR #687 and
publishing its npm/engine release. Activation also requires the separately
approved deployment and bootstrap configuration. Until the companion contract
is deployed and advertised, Control's lazy binding intentionally fails closed.

## 5. Resume procedure

1. Start a new Agent Relay session and identify it as the Control lazy
   Relaycast binding slice.
2. Read this file and re-check the current state and head of Relaycast PR #687.
3. Treat relay-control PR #169 as complete; do not reopen or recreate its
   implementation unless a post-merge defect is reported.
4. Route Neon-exit coordination to `neon-exit-lead-2`; new PR links also go to
   `neonexitgrok`.
5. Do not merge, release, deploy, change secrets/IAM, write production data,
   apply DDL/migrations, or flip traffic without the required direct approval.

