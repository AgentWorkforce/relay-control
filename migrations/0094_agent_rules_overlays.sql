-- Organization overlays for the agent rules bundle (docs/agent-rules.md).
-- Append-only: the newest version per (organization, audience) is active, and
-- an empty text clears it. Base rules live in the image (agent-rules/).
CREATE TABLE agent_rules_overlays (
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  audience text NOT NULL CHECK (audience IN ('grok-bot', 'lead', 'worker')),
  version integer NOT NULL CHECK (version >= 1),
  text text NOT NULL CHECK (octet_length(text) <= 16384),
  updated_by uuid REFERENCES users(id) ON DELETE SET NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, audience, version)
);

-- Which rules version a Grok routine last read, so operators can see which
-- bots are on which rules and which still run a pasted (pre-bootstrap) prompt.
ALTER TABLE grok_bot_routines ADD COLUMN rules_version_last_fetched text;
