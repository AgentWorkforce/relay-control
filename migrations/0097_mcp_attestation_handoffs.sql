-- Claude Code proofs handed off ahead of their call. Claude Code's auto mode
-- refuses a call whose input a hook rewrote, so Agent Relay Desktop posts the
-- hook's proof to POST .../messaging/desktop-identities/attestations and sends
-- the call unchanged; the MCP route takes (reads and deletes) the row by the
-- call's `_meta["claudecode/toolUseId"]` and verifies it as an in-argument
-- proof. Rows outlive the proof (exp + 120 s) and are pruned after expires_at.
-- token_family_id is the depositing session's token family (it survives
-- refresh): only a call on the same family takes the row, so the tool-use id
-- alone redeems nothing. A NULL family never matches.
CREATE TABLE IF NOT EXISTS mcp_attestation_handoffs (
  workspace_id uuid NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tool_use_id text NOT NULL,
  proof text NOT NULL CHECK (char_length(proof) <= 4096),
  expires_at timestamptz NOT NULL,
  token_family_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (workspace_id, user_id, tool_use_id)
);

CREATE INDEX IF NOT EXISTS mcp_attestation_handoffs_expiry_idx
  ON mcp_attestation_handoffs (expires_at);
