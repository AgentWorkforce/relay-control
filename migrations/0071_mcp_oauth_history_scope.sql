-- Opt-in OAuth scope relay:history for shared-session reads on the person's
-- behalf (never part of the baseline grant). The scope checks on grants,
-- authorization codes and sessions were inline column constraints with
-- generated names, so each is located by its definition before it is replaced.
DO $$
DECLARE
  t text;
  c text;
BEGIN
  FOREACH t IN ARRAY ARRAY['mcp_oauth_grants', 'mcp_oauth_authorization_codes', 'mcp_oauth_sessions'] LOOP
    FOR c IN
      SELECT con.conname FROM pg_constraint con
      WHERE con.conrelid = t::regclass AND con.contype = 'c'
        AND pg_get_constraintdef(con.oid) LIKE '%relay:agents%'
    LOOP
      EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', t, c);
    END LOOP;
    EXECUTE format(
      'ALTER TABLE %I ADD CONSTRAINT %I CHECK (cardinality(scopes) > 0 AND scopes <@ ARRAY[''relay:mcp'',''relay:events'',''relay:agents'',''relay:history'',''openid'']::text[])',
      t, t || '_scopes_check');
  END LOOP;
END $$;
