-- Follow-up guards for imported Cloud identity metadata. Customer History
-- origins receive user bearer tokens, so only HTTPS is accepted away from
-- loopback and one origin cannot be assigned across tenant workspaces.
ALTER TABLE workspaces
  DROP CONSTRAINT workspaces_relayhistory_origin_format,
  ADD CONSTRAINT workspaces_relayhistory_origin_format
    CHECK (
      relayhistory_origin IS NULL
      OR relayhistory_origin ~ '^https://([[:alnum:].-]+|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?$'
      OR relayhistory_origin ~ '^http://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]{1,5})?$'
    );

CREATE UNIQUE INDEX workspaces_relayhistory_origin_unique
  ON workspaces (lower(relayhistory_origin))
  WHERE relayhistory_origin IS NOT NULL;

-- Cloud slugs are case-insensitive. Keep the original index names so schema
-- checks and operator diagnostics continue to identify the same contracts.
DROP INDEX organizations_slug_unique;
CREATE UNIQUE INDEX organizations_slug_unique
  ON organizations (lower(slug));

DROP INDEX workspaces_org_slug_unique;
CREATE UNIQUE INDEX workspaces_org_slug_unique
  ON workspaces (organization_id, lower(slug));
