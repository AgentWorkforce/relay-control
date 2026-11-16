-- Cloud identity import ledger (scripts/cloud-import). One row per target
-- row the importer wrote, per organization, written in the importer's
-- per-org transaction. A re-run reconciles only against this table, so it
-- can never delete a row the import did not write; an organization present
-- without ledger rows is Control's own and the importer refuses it.
--
-- Importer-only state: OWNER_ONLY_TABLES in src/control-tables.ts keeps it
-- out of the runtime role's grants, so only the owner role (the importer)
-- can read or write it. IF NOT EXISTS: a scratch target may already hold it
-- from the importer's --init-ledger (same DDL).
CREATE TABLE IF NOT EXISTS cloud_import_ledger (
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  table_name text NOT NULL,
  row_key text NOT NULL,
  mapping_revision text NOT NULL,
  imported_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, table_name, row_key)
);
