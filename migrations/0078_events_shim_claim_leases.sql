-- Events shim claim leases (docs/events-shim.md, @agent-relay/events-shim ackPending/releasePending): a
-- wait_for_webhook claim made with auto_ack: false keeps its posts 'pending' with delivered_at set to the claim
-- time and claim_token set to the claim's token. Only that token can acknowledge (mark read) or release them;
-- once delivered_at is older than the lease, the posts are claimable again. NULL for every other post.
ALTER TABLE events_shim_events ADD COLUMN claim_token text;
