-- Usage page, People drill-down (owner-only, behind SELFHOST_FEATURES=usage_people,
-- independent of `usage`). Unlike the v1 counters this table is keyed by the
-- real user id: owners see per-member counts. Nothing is written while the
-- feature is off. Rows go with the user or the organization.

CREATE TABLE IF NOT EXISTS usage_people_daily (
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  day date NOT NULL,
  searches bigint NOT NULL DEFAULT 0,
  last_active_at timestamptz,
  PRIMARY KEY (organization_id, user_id, day)
);
