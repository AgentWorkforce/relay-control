-- Canonical customer History origins. The importer uses the matching Node URL
-- helper; this function keeps direct SQL imports inside the same contract.
CREATE FUNCTION relayhistory_origin_is_canonical(origin text)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
  parts text[];
  scheme_name text;
  authority text;
  hostname text;
  port_text text;
  port_number integer;
  canonical_host text;
  address inet;
  label text;
BEGIN
  parts := regexp_match(origin, '^(https?)://(.+)$');
  IF parts IS NULL THEN RETURN false; END IF;
  scheme_name := parts[1];
  authority := parts[2];

  IF left(authority, 1) = '[' THEN
    parts := regexp_match(authority, '^\[([0-9a-f:.]+)\](:([0-9]+))?$');
    IF parts IS NULL THEN RETURN false; END IF;
    BEGIN
      address := parts[1]::inet;
    EXCEPTION WHEN OTHERS THEN
      RETURN false;
    END;
    IF family(address) <> 6 THEN RETURN false; END IF;
    canonical_host := '[' || host(address) || ']';
    IF canonical_host LIKE '[::ffff:%' THEN RETURN false; END IF;
    port_text := parts[3];
  ELSE
    parts := regexp_match(authority, '^([a-z0-9][a-z0-9.-]*[a-z0-9]|[a-z0-9])(:([0-9]+))?$');
    IF parts IS NULL THEN RETURN false; END IF;
    hostname := parts[1];
    port_text := parts[3];
    IF hostname ~ '^[0-9.]+$' THEN
      BEGIN
        address := hostname::inet;
      EXCEPTION WHEN OTHERS THEN
        RETURN false;
      END;
      IF family(address) <> 4 THEN RETURN false; END IF;
      canonical_host := host(address);
    ELSE
      -- WHATWG treats a hostname whose last label is decimal or 0x-hex as
      -- IPv4. Refuse it here unless the whole host took the canonical inet
      -- branch above, so 0x7f.1 cannot coexist with 127.0.0.1.
      IF split_part(hostname, '.', array_length(string_to_array(hostname, '.'), 1))
        ~ '^([0-9]+|0x[0-9a-f]*)$' THEN
        RETURN false;
      END IF;
      FOREACH label IN ARRAY string_to_array(hostname, '.') LOOP
        IF label !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$' THEN RETURN false; END IF;
      END LOOP;
      canonical_host := hostname;
    END IF;
  END IF;

  IF port_text IS NOT NULL THEN
    IF port_text !~ '^[1-9][0-9]{0,4}$' THEN RETURN false; END IF;
    port_number := port_text::integer;
    IF port_number > 65535 THEN RETURN false; END IF;
    IF (scheme_name = 'https' AND port_number = 443)
      OR (scheme_name = 'http' AND port_number = 80) THEN
      RETURN false;
    END IF;
  END IF;
  IF scheme_name = 'http' AND canonical_host NOT IN ('localhost', '127.0.0.1', '[::1]') THEN
    RETURN false;
  END IF;
  RETURN origin = scheme_name || '://' || canonical_host ||
    CASE WHEN port_text IS NULL THEN '' ELSE ':' || port_number::text END;
END
$$;

-- Fail before replacing any constraint/index and name the rows an operator
-- must repair. The migration transaction rolls this function back too when a
-- preflight fails. scripts/preflight-0062-cloud-identity-security.sql reports
-- every finding before an upgrade is attempted.
DO $$
DECLARE
  bad_ids text;
BEGIN
  SELECT string_agg(id::text, ', ' ORDER BY id) INTO bad_ids
    FROM (SELECT id FROM workspaces
           WHERE relayhistory_origin IS NOT NULL
             AND NOT relayhistory_origin_is_canonical(relayhistory_origin)
           ORDER BY id LIMIT 20) invalid_origins;
  IF bad_ids IS NOT NULL THEN
    RAISE EXCEPTION '0062 preflight: non-canonical relayhistory_origin on workspace ids: %', bad_ids
      USING HINT = 'Set the value to NULL or the canonical HTTPS origin (HTTP only on localhost/127.0.0.1/[::1]); run scripts/preflight-0062-cloud-identity-security.sql and retry.';
  END IF;

  SELECT string_agg(id::text, ', ' ORDER BY id) INTO bad_ids
    FROM (
      SELECT w.id FROM workspaces w
      JOIN (SELECT relayhistory_origin FROM workspaces
             WHERE relayhistory_origin IS NOT NULL
             GROUP BY relayhistory_origin HAVING count(*) > 1) duplicates
        USING (relayhistory_origin)
      ORDER BY w.id LIMIT 20
    ) duplicate_origins;
  IF bad_ids IS NOT NULL THEN
    RAISE EXCEPTION '0062 preflight: duplicate relayhistory_origin on workspace ids: %', bad_ids
      USING HINT = 'Assign each canonical History origin to one workspace or set extra values to NULL; run the 0062 preflight script and retry.';
  END IF;

  SELECT string_agg(id::text, ', ' ORDER BY id) INTO bad_ids
    FROM (
      SELECT o.id FROM organizations o
      JOIN (SELECT lower(slug) AS slug_key FROM organizations
             WHERE slug IS NOT NULL GROUP BY lower(slug) HAVING count(*) > 1) duplicates
        ON lower(o.slug) = duplicates.slug_key
      ORDER BY o.id LIMIT 20
    ) duplicate_organization_slugs;
  IF bad_ids IS NOT NULL THEN
    RAISE EXCEPTION '0062 preflight: case-insensitive slug collision on organization ids: %', bad_ids
      USING HINT = 'Rename or NULL colliding organization slugs; run the 0062 preflight script and retry.';
  END IF;

  SELECT string_agg(id::text, ', ' ORDER BY id) INTO bad_ids
    FROM (
      SELECT w.id FROM workspaces w
      JOIN (SELECT organization_id, lower(slug) AS slug_key FROM workspaces
             WHERE slug IS NOT NULL GROUP BY organization_id, lower(slug) HAVING count(*) > 1) duplicates
        ON w.organization_id = duplicates.organization_id AND lower(w.slug) = duplicates.slug_key
      ORDER BY w.id LIMIT 20
    ) duplicate_workspace_slugs;
  IF bad_ids IS NOT NULL THEN
    RAISE EXCEPTION '0062 preflight: case-insensitive slug collision on workspace ids: %', bad_ids
      USING HINT = 'Rename or NULL colliding workspace slugs within each organization; run the 0062 preflight script and retry.';
  END IF;
END
$$;

ALTER TABLE workspaces
  DROP CONSTRAINT workspaces_relayhistory_origin_format,
  ADD CONSTRAINT workspaces_relayhistory_origin_format
    CHECK (relayhistory_origin IS NULL OR relayhistory_origin_is_canonical(relayhistory_origin));

CREATE UNIQUE INDEX workspaces_relayhistory_origin_unique
  ON workspaces (relayhistory_origin)
  WHERE relayhistory_origin IS NOT NULL;

-- Cloud slugs are case-insensitive. Keep the original index names so schema
-- checks and operator diagnostics continue to identify the same contracts.
DROP INDEX organizations_slug_unique;
CREATE UNIQUE INDEX organizations_slug_unique
  ON organizations (lower(slug));

DROP INDEX workspaces_org_slug_unique;
CREATE UNIQUE INDEX workspaces_org_slug_unique
  ON workspaces (organization_id, lower(slug));
