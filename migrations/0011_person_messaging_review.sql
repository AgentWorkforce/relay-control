-- Review repairs: bind each identity to a Relaycast workspace, claim sends
-- before dispatch, and keep a revocation queue that does not store tokens.

ALTER TABLE selfhost_person_identities
  ADD COLUMN relaycast_workspace_id text;

UPDATE selfhost_person_identities AS identity
   SET relaycast_workspace_id = workspace.relaycast_workspace_id
  FROM selfhost_workspaces AS workspace
 WHERE workspace.id = identity.workspace_id
   AND identity.relaycast_workspace_id IS NULL;

ALTER TABLE selfhost_person_identities
  ALTER COLUMN relaycast_workspace_id SET NOT NULL;

ALTER TABLE selfhost_person_messages
  ADD COLUMN relaycast_workspace_id text,
  ADD COLUMN fingerprint text,
  ADD COLUMN status text NOT NULL DEFAULT 'accepted',
  ADD COLUMN terminal_code text;

UPDATE selfhost_person_messages AS message
   SET relaycast_workspace_id = workspace.relaycast_workspace_id,
       fingerprint = COALESCE(message.fingerprint, 'legacy')
  FROM selfhost_workspaces AS workspace
 WHERE workspace.id = message.workspace_id
   AND message.relaycast_workspace_id IS NULL;

ALTER TABLE selfhost_person_messages
  ALTER COLUMN relaycast_workspace_id SET NOT NULL,
  ALTER COLUMN fingerprint SET NOT NULL;

ALTER TABLE selfhost_person_messages
  ADD CONSTRAINT selfhost_person_messages_status_check
  CHECK (status IN ('pending', 'accepted', 'uncertain', 'retryable', 'rejected'));

DO $$
DECLARE
  constraint_name text;
BEGIN
  SELECT con.conname INTO constraint_name
    FROM pg_constraint con
    JOIN pg_class rel ON rel.oid = con.conrelid
   WHERE rel.relname = 'selfhost_person_messages'
     AND con.contype = 'u'
     AND pg_get_constraintdef(con.oid) LIKE '%client_message_id%';
  IF constraint_name IS NOT NULL THEN
    EXECUTE format('ALTER TABLE selfhost_person_messages DROP CONSTRAINT %I', constraint_name);
  END IF;
END $$;

ALTER TABLE selfhost_person_messages
  ADD CONSTRAINT selfhost_person_messages_binding_client_message_key
  UNIQUE (workspace_id, user_id, relaycast_workspace_id, client_message_id);

CREATE TABLE IF NOT EXISTS selfhost_person_revocations (
  id uuid PRIMARY KEY,
  workspace_id uuid NOT NULL REFERENCES selfhost_workspaces(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES selfhost_users(id) ON DELETE CASCADE,
  relaycast_workspace_id text NOT NULL,
  agent_name text NOT NULL,
  agent_remote_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (workspace_id, user_id, agent_remote_id)
);
