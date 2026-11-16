-- Run read-only against the Control database before deploying migration 0062.
-- The desired result is zero rows from every SELECT. Repair the named ids,
-- re-run this script, then deploy. Do not modify rows automatically.

-- Invalid/non-canonical origins. Store new URL(value).origin after removing a
-- DNS trailing dot; use HTTPS except localhost, 127.0.0.1 or [::1].
SELECT id AS workspace_id, organization_id, relayhistory_origin,
       'Set NULL or store the canonical HTTPS origin; IDNs must be lowercase punycode and default ports omitted.' AS remediation
  FROM workspaces
 WHERE relayhistory_origin IS NOT NULL
   AND NOT (
     (
       relayhistory_origin ~ '^https://([a-z0-9][a-z0-9.-]*[a-z0-9]|[a-z0-9]|\[[0-9a-f:.]+\])(:[1-9][0-9]{0,4})?$'
       AND relayhistory_origin !~ ':443$'
       AND coalesce(substring(relayhistory_origin FROM ':([0-9]+)$')::integer <= 65535, true)
     ) OR (
       relayhistory_origin ~ '^http://(localhost|127\.0\.0\.1|\[::1\])(:[1-9][0-9]{0,4})?$'
       AND relayhistory_origin !~ ':80$'
       AND coalesce(substring(relayhistory_origin FROM ':([0-9]+)$')::integer <= 65535, true)
     )
   )
 ORDER BY organization_id, id;

-- One canonical History destination may belong to only one workspace.
SELECT w.id AS workspace_id, w.organization_id, w.relayhistory_origin,
       'Assign this origin to one workspace; set every extra row to NULL or its correct destination.' AS remediation
  FROM workspaces w
  JOIN (SELECT relayhistory_origin FROM workspaces
         WHERE relayhistory_origin IS NOT NULL
         GROUP BY relayhistory_origin HAVING count(*) > 1) duplicates
    USING (relayhistory_origin)
 ORDER BY w.relayhistory_origin, w.organization_id, w.id;

-- Cloud organization slugs are globally case-insensitive.
SELECT o.id AS organization_id, o.slug,
       'Rename or NULL one of the colliding organization slugs.' AS remediation
  FROM organizations o
  JOIN (SELECT lower(slug) AS slug_key FROM organizations
         WHERE slug IS NOT NULL GROUP BY lower(slug) HAVING count(*) > 1) duplicates
    ON lower(o.slug) = duplicates.slug_key
 ORDER BY lower(o.slug), o.id;

-- Cloud workspace slugs are case-insensitive within an organization.
SELECT w.id AS workspace_id, w.organization_id, w.slug,
       'Rename or NULL one of the colliding workspace slugs in this organization.' AS remediation
  FROM workspaces w
  JOIN (SELECT organization_id, lower(slug) AS slug_key FROM workspaces
         WHERE slug IS NOT NULL GROUP BY organization_id, lower(slug) HAVING count(*) > 1) duplicates
    ON w.organization_id = duplicates.organization_id AND lower(w.slug) = duplicates.slug_key
 ORDER BY w.organization_id, lower(w.slug), w.id;
