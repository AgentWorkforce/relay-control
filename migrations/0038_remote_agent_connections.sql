-- Provider keys belong to Control, never to the static webapp or Cloud.
CREATE TABLE remote_agent_connections (
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  provider text NOT NULL CHECK (provider IN ('capy', 'replicas', 'devin', 'cursor-cloud')),
  key_ciphertext text NOT NULL,
  key_hint text NOT NULL,
  provider_account text,
  created_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
  validated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, provider)
);
