-- Factory acquisition enrollment (docs/factory-sessions.md). When
-- SELFHOST_ACQUISITION_ORIGIN is set, a Factory connect mints one
-- `acquisition-operator` workspace API token whose aud is that origin, so the
-- acquisition service can verify the workspace through introspection. The
-- plaintext token is kept only as an encrypted envelope (same format as the
-- Factory key envelope), with its 10-char prefix for support.
--
-- Lifecycle: enrolled -> draining (disconnect, member removal, workspace
-- deletion, rotation) -> revoked (reconciler or an explicit admin revoke).
-- Draining keeps the token active so outstanding acquisition obligations can
-- still complete. Rows are kept after revocation for audit.
--
-- The workspace and token foreign keys cascade, like workspace_api_tokens
-- itself: a retained revoked row must never block workspace deletion.
CREATE TABLE IF NOT EXISTS factory_acquisition_operators (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL,
  organization_id uuid NOT NULL,
  acquisition_origin text NOT NULL,
  token_id uuid NOT NULL REFERENCES workspace_api_tokens(id) ON DELETE CASCADE,
  token_envelope text NOT NULL,
  token_prefix text NOT NULL,
  control_origin text NOT NULL,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  state text NOT NULL CHECK (state IN ('enrolled', 'draining', 'revoked')),
  reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  drain_started_at timestamptz,
  revoked_at timestamptz,
  stranded_count integer NOT NULL DEFAULT 0,
  FOREIGN KEY (workspace_id, organization_id)
    REFERENCES workspaces(id, organization_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS factory_acquisition_operators_enrolled_unique
  ON factory_acquisition_operators (workspace_id, acquisition_origin)
  WHERE state = 'enrolled';

CREATE INDEX IF NOT EXISTS factory_acquisition_operators_draining_idx
  ON factory_acquisition_operators (drain_started_at)
  WHERE state = 'draining';
