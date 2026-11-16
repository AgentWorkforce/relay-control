-- Cloud identity import compatibility. Nullable slugs preserve existing
-- Control rows without manufacturing Cloud identities; PostgreSQL unique
-- indexes permit multiple NULLs while protecting imported non-NULL slugs.
ALTER TABLE organizations
  ADD COLUMN slug text;

CREATE UNIQUE INDEX organizations_slug_unique
  ON organizations (slug);

ALTER TABLE workspaces
  ADD COLUMN slug text,
  ADD COLUMN relayhistory_origin text,
  ADD COLUMN relaycast_api_key_generation integer NOT NULL DEFAULT 1,
  ADD CONSTRAINT workspaces_relayhistory_origin_format
    CHECK (
      relayhistory_origin IS NULL
      OR relayhistory_origin ~ '^https?://([[:alnum:].-]+|\[[0-9A-Fa-f:.]+\])(:[0-9]{1,5})?$'
    ),
  ADD CONSTRAINT workspaces_relaycast_api_key_generation_positive
    CHECK (relaycast_api_key_generation >= 1);

CREATE UNIQUE INDEX workspaces_org_slug_unique
  ON workspaces (organization_id, slug);
