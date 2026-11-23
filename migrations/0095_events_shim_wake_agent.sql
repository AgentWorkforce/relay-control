-- The Agent Relay agent name an inbox's wake link wakes (@agent-relay/events-shim
-- WakeTarget.agent, from link_relay_wake's `agent` or the bound agent of an agent link).
-- Shown as linked_agent / replaced_agent / wake_agent so an agent can tell whether the
-- link is its own. Null for links made before this column or without a name.
ALTER TABLE events_shims ADD COLUMN IF NOT EXISTS wake_agent text;
