-- Where an account was created, set by Control for its own sign-ups (the
-- identity import's carry of hosted Cloud values lands in a follow-up). Nullable: most accounts have no attributed
-- source. The set is exactly the values hosted Cloud holds (teams, flows,
-- desktop) plus mcp, an MCP connector's OAuth consent (ChatGPT's Agent Relay
-- app and any other MCP OAuth client). Set once, at user creation; never
-- overwritten by a later sign-in.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS signup_source text,
  ADD CONSTRAINT users_signup_source_known
    CHECK (signup_source IS NULL OR signup_source IN ('teams', 'flows', 'desktop', 'mcp'));
