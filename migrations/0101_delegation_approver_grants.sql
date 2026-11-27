-- Granted approvers, the self-hosted twin of Cloud's 0457_delegation_approver_grants
-- (cloud#6709): an owner-made delegation grant of kind 'approver' lets one
-- exact Relay identity (agent id and address) approve within its scopes on its
-- own. Redeem reports it as an approver; hard-limit classes need an explicit
-- scope.
--
-- Additive (expand): three plain ADD COLUMNs, nullable with constant
-- defaults, no NOT NULL and no CHECK. A null or 'delegate' kind reads as a
-- delegate, so every existing grant is exactly what it was, and the previous
-- build never reads these columns. That an approver is pinned to an address,
-- has at least one GitHub login and is never rule-backed is enforced by the
-- only code that writes one (POST delegates).
ALTER TABLE delegation_grants ADD COLUMN IF NOT EXISTS kind text DEFAULT 'delegate';
ALTER TABLE delegation_grants ADD COLUMN IF NOT EXISTS delegate_address text;
ALTER TABLE delegation_grants ADD COLUMN IF NOT EXISTS approver_github_logins text[] DEFAULT '{}'::text[];
