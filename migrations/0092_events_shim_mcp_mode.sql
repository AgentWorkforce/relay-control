-- MCP Events (SEP-3415) webhook deliveries (@agent-relay/events-shim 18.13.0): posts to
-- /h/<token>/mcp are stored with mode 'mcp'. The 0047 CHECK listed only the first five
-- modes, so an mcp delivery failed its insert. Widen it; existing rows all pass.
ALTER TABLE events_shim_events DROP CONSTRAINT IF EXISTS events_shim_events_mode_check;
ALTER TABLE events_shim_events ADD CONSTRAINT events_shim_events_mode_check
  CHECK (mode IN ('open','github','stripe','linear','bearer','mcp'));
