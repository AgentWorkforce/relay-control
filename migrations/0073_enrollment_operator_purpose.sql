-- Enrollment operator tokens (docs/identity.md, "Desktop enrollment keys"):
-- an owner or admin mints one `sh_wk_` token of purpose `enrollment-operator`
-- (scope enrollment:mint) for an MDM script or an admin terminal, which then
-- mints, lists and revokes its own desktop-enrollment keys without a device
-- sign-in. Like desktop-enrollment it is bound to no agent and no audience,
-- so agent_name and aud stay NULL (the catch-all branch of
-- api_token_agent_binding already says so for any other purpose).
ALTER TABLE workspace_api_tokens DROP CONSTRAINT api_token_purpose;
ALTER TABLE workspace_api_tokens ADD CONSTRAINT api_token_purpose CHECK (purpose IN ('agent-runtime','workflow','deployment','relayfile-agent','acquisition-operator','relay-node','desktop-enrollment','enrollment-operator'));

-- minted_by_token_id: the enrollment-operator token that minted a
-- desktop-enrollment key; NULL for a key an owner or admin minted with a
-- user session, and for every other purpose. created_by_user_id is already
-- nullable (ON DELETE SET NULL since 0003), so a token-minted key keeps it
-- NULL and records the minting token here instead; no constraint is relaxed.
-- SET NULL on delete: the key outlives the row of the token that minted it.
ALTER TABLE workspace_api_tokens
  ADD COLUMN minted_by_token_id uuid REFERENCES workspace_api_tokens(id) ON DELETE SET NULL,
  ADD CONSTRAINT api_token_minted_by_token CHECK (
    minted_by_token_id IS NULL OR purpose = 'desktop-enrollment');

CREATE INDEX workspace_api_tokens_minted_by_token
  ON workspace_api_tokens (minted_by_token_id) WHERE minted_by_token_id IS NOT NULL;

-- Audit rows written by a workspace API token (actor_id is the token id).
ALTER TABLE admin_audit_events DROP CONSTRAINT admin_audit_actor_kind;
ALTER TABLE admin_audit_events ADD CONSTRAINT admin_audit_actor_kind
  CHECK (actor_kind IN ('user', 'service', 'bootstrap', 'token'));
