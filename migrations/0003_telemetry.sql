-- telemetry lane: aggregate-only usage/error telemetry and its outbox.
-- No message content, transcripts, prompts, file contents, secrets, emails,
-- or user names are stored here: only counters, scrubbed error metadata, and
-- scrubbed outbound payloads.

-- Singleton: the per-install salt used to hash identifiers. It never leaves
-- the cluster.
CREATE TABLE IF NOT EXISTS selfhost_telemetry_state (
  id smallint PRIMARY KEY DEFAULT 1,
  salt text NOT NULL,
  window_started_at timestamptz NOT NULL DEFAULT now(),
  last_digest_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT selfhost_telemetry_state_singleton CHECK (id = 1)
);

-- Counters accumulated since the last digest (moved into the outbox on digest).
CREATE TABLE IF NOT EXISTS selfhost_telemetry_counters (
  area text NOT NULL,
  metric text NOT NULL,
  value bigint NOT NULL DEFAULT 0,
  PRIMARY KEY (area, metric)
);

-- Error aggregates since the last digest.
CREATE TABLE IF NOT EXISTS selfhost_telemetry_errors (
  fingerprint text NOT NULL,
  component text NOT NULL,
  route text NOT NULL,
  status integer NOT NULL,
  error_class text NOT NULL,
  count bigint NOT NULL,
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL,
  PRIMARY KEY (fingerprint, component, route, status, error_class)
);

-- Long-lived per-fingerprint index: first seen ever, last burst report.
CREATE TABLE IF NOT EXISTS selfhost_telemetry_error_index (
  fingerprint text NOT NULL,
  component text NOT NULL,
  first_seen timestamptz NOT NULL DEFAULT now(),
  last_seen timestamptz NOT NULL DEFAULT now(),
  last_burst_reported_at timestamptz,
  PRIMARY KEY (fingerprint, component)
);

-- Durable outbox: offline clusters buffer here and send later; air-gapped
-- installs export from here.
CREATE TABLE IF NOT EXISTS selfhost_telemetry_outbox (
  id uuid PRIMARY KEY,
  kind text NOT NULL,
  body text NOT NULL,
  status text NOT NULL DEFAULT 'pending',
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  sent_at timestamptz,
  CONSTRAINT selfhost_telemetry_outbox_kind
    CHECK (kind IN ('digest', 'error_burst', 'issue_report')),
  CONSTRAINT selfhost_telemetry_outbox_status
    CHECK (status IN ('pending', 'sent', 'exported', 'dead'))
);

CREATE INDEX IF NOT EXISTS selfhost_telemetry_outbox_due_idx
  ON selfhost_telemetry_outbox (next_attempt_at)
  WHERE status = 'pending';
