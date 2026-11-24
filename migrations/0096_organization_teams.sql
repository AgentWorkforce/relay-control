-- Organization teams (docs/teams.md, behind SELFHOST_FEATURES=teams): flat,
-- organization-level groups of members maintained in the dashboard. A person
-- has at most one current team per organization. Assignments have a start and
-- an end; moving a person closes the current row and opens a new one, so past
-- windows stay answerable. The `organization_` prefix keeps these apart from
-- the hosted product's agent `teams`.
CREATE TABLE IF NOT EXISTS organization_teams (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
  archived_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (id, organization_id)
);
-- A name is unique among the organization's live teams, whatever its case.
-- Archiving frees it.
CREATE UNIQUE INDEX IF NOT EXISTS organization_teams_name
  ON organization_teams (organization_id, lower(name)) WHERE archived_at IS NULL;

-- No foreign key to organization_memberships: removing a member closes the
-- open row in the same transaction and keeps the closed ones. Rows go with the
-- user or the organization (through the team). The store closes and opens rows
-- under the membership row lock, so one person's intervals in one organization
-- never overlap.
CREATE TABLE IF NOT EXISTS organization_team_assignments (
  id uuid PRIMARY KEY,
  organization_id uuid NOT NULL,
  team_id uuid NOT NULL,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  starts_at timestamptz NOT NULL,
  -- Null: the current assignment.
  ends_at timestamptz,
  source text NOT NULL DEFAULT 'manual' CHECK (source IN ('manual')),
  FOREIGN KEY (team_id, organization_id) REFERENCES organization_teams (id, organization_id) ON DELETE CASCADE,
  CHECK (ends_at IS NULL OR ends_at > starts_at)
);
-- One current team per person and organization.
CREATE UNIQUE INDEX IF NOT EXISTS organization_team_assignments_current
  ON organization_team_assignments (organization_id, user_id) WHERE ends_at IS NULL;
CREATE INDEX IF NOT EXISTS organization_team_assignments_team
  ON organization_team_assignments (team_id, starts_at);
-- A person's history in an organization, and the user deletion cascade.
CREATE INDEX IF NOT EXISTS organization_team_assignments_user
  ON organization_team_assignments (user_id, organization_id);
