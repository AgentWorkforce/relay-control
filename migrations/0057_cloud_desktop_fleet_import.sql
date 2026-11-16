-- Cloud Desktop source IDs are opaque text, not necessarily UUIDs. Keep both
-- tables on the same type because their composite keys join on source_id.
ALTER TABLE desktop_relay_identities
  ALTER COLUMN source_id TYPE text USING source_id::text;

ALTER TABLE desktop_attestation_keys
  ALTER COLUMN source_id TYPE text USING source_id::text;

-- Cloud proves node ownership but does not persist a node display name.
ALTER TABLE fleet_node_owners
  ALTER COLUMN node_name DROP NOT NULL;
