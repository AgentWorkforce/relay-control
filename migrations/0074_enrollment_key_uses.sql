-- Per-person desktop enrollment keys (docs/identity.md, "Desktop enrollment
-- keys"): one `sh_ek_` key may now sign in up to `max_uses` machines of its
-- bound member, and may carry the member's admin policy consent.
--
-- max_uses: how many exchanges the key allows; 1 (the default) is the
--   single-use key of migration 0050. use_count: exchanges so far. The key is
--   spent once use_count reaches max_uses; exchanged_at, exchanged_session_id
--   and exchanged_host_name (0050) then record the LAST exchange, and before
--   that the latest one.
-- policy_consent: 'admin' when the minting admin consented, on the member's
--   behalf, to the workspace policy's person-only keys; every session the key
--   provisions is then a managed session (docs/workspace-policy.md, "managed").
-- Like 0050's enrollment-only columns, a token of any other purpose keeps the
-- neutral values (max_uses 1, policy_consent NULL).
ALTER TABLE workspace_api_tokens
  ADD COLUMN max_uses integer NOT NULL DEFAULT 1 CONSTRAINT api_token_max_uses CHECK (max_uses BETWEEN 1 AND 500),
  ADD COLUMN use_count integer NOT NULL DEFAULT 0 CONSTRAINT api_token_use_count CHECK (use_count >= 0),
  ADD COLUMN policy_consent text CONSTRAINT api_token_policy_consent CHECK (policy_consent IS NULL OR policy_consent = 'admin'),
  ADD CONSTRAINT api_token_enrollment_uses CHECK (
    purpose = 'desktop-enrollment'
    OR (max_uses = 1 AND policy_consent IS NULL));

-- Existing spent single-use keys count their one exchange.
UPDATE workspace_api_tokens SET use_count = 1
 WHERE purpose = 'desktop-enrollment' AND exchanged_at IS NOT NULL;
