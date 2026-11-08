DO $$
DECLARE
  organization_count bigint;
BEGIN
  SELECT count(*) INTO organization_count FROM selfhost_organizations;
  IF organization_count > 1 THEN
    RAISE EXCEPTION
      'Self-hosted installation contains % organizations; exactly zero or one is required',
      organization_count
      USING HINT =
        'Consolidate the organizations and their workspaces before retrying. This migration never deletes organization data.';
  END IF;
END
$$;

ALTER TABLE selfhost_organizations
  ADD COLUMN installation_slot smallint NOT NULL DEFAULT 1,
  ADD CONSTRAINT selfhost_organizations_single_slot
    CHECK (installation_slot = 1);

CREATE UNIQUE INDEX selfhost_organizations_singleton_idx
  ON selfhost_organizations (installation_slot);
DO $$
DECLARE
  organization_count bigint;
BEGIN
  SELECT count(*) INTO organization_count FROM selfhost_organizations;
  IF organization_count > 1 THEN
    RAISE EXCEPTION
      'self-hosted installations support exactly one organization; found % organizations',
      organization_count
      USING ERRCODE = '23514';
  END IF;
END
$$;

-- The expression is identical for every row, so PostgreSQL enforces the
-- installation-wide singleton even for writes that bypass the API.
CREATE UNIQUE INDEX selfhost_single_organization_idx
  ON selfhost_organizations ((true));

ALTER TABLE selfhost_device_authorizations
  ADD CONSTRAINT selfhost_device_approved_membership
  FOREIGN KEY (organization_id, approved_by_user_id)
  REFERENCES selfhost_organization_memberships (organization_id, user_id)
  ON DELETE CASCADE;
