-- =============================================================================
-- TIXIFY-VR Security Engine — security-owned schema
-- =============================================================================
-- Person 2 / Security Engineer. Raw SQL, no ORM.
--
-- OWNERSHIP RULE
--   These five tables are the ONLY tables this project creates. Person 1 owns
--   users, events, venues, seats, inventory, reservations, bookings, payments
--   and tickets; this schema neither creates, alters, nor joins into them.
--
--   Person 1 entity ids (user_id, event_id, booking_id, ticket_id) appear below
--   as PLAIN COLUMNS WITH NO FOREIGN KEY, deliberately. A foreign key would
--   create exactly the schema coupling this project is designed to avoid: it
--   would block Person 1 from renaming a table, changing a key type, or moving
--   an id to a different representation without breaking our migrations, and it
--   would make the security engine impossible to deploy or test independently.
--
--   Referential integrity across that boundary is enforced in the application
--   layer, through the TicketRepository / EventRepository ports, where the
--   authoritative schema actually lives.
--
--   Within THIS schema, foreign keys are used freely — the tables here are ours
--   and we can guarantee their integrity.
--
-- POSTGRES VERSION: 13+ (uses generated columns and identity columns)
-- =============================================================================

BEGIN;

-- =============================================================================
-- 1. security_events
-- =============================================================================
-- Normalized security telemetry. High volume, append-only, queried by the
-- dashboard. Kept separate from audit_logs because the retention, volume and
-- access patterns differ: events are numerous and short-lived, audit rows are
-- fewer and must survive much longer.
-- =============================================================================
CREATE TABLE IF NOT EXISTS security_events (
  id              BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_type      TEXT        NOT NULL,
  severity        TEXT        NOT NULL DEFAULT 'LOW',

  -- Identity. user_id is nullable because many events (an unauthenticated flood,
  -- a queue bypass) have no authenticated actor.
  user_id         TEXT        NULL,

  -- Privacy: we store an HMAC of the IP, never the address itself. An audit-log
  -- breach must not become a location or identity breach. See
  -- SECURITY_ARCHITECTURE.md section 4.8.
  ip_hash         TEXT        NULL,

  endpoint        TEXT        NULL,
  method          TEXT        NULL,
  event_id        TEXT        NULL,
  session_id_hash TEXT        NULL,

  -- Free-form, but must never contain PII. Application-enforced.
  metadata        JSONB       NOT NULL DEFAULT '{}'::jsonb,

  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT security_events_event_type_chk CHECK (
    event_type IN (
      'RATE_LIMIT_TRIGGERED',
      'DUPLICATE_REQUEST',
      'INVALID_TICKET',
      'INVALID_SIGNATURE',
      'REPLAY_ATTEMPT',
      'QUEUE_BYPASS_ATTEMPT',
      'EXCESSIVE_REQUESTS',
      'MULTIPLE_FAILED_BOOKINGS',
      'TICKET_SCAN_REJECTED',
      'TICKET_SCAN_ACCEPTED',
      'BOT_SIGNAL_DETECTED',
      'CHALLENGE_ISSUED',
      'TEMPORARY_RESTRICTION',
      'IDEMPOTENCY_KEY_REUSE',
      'UNAUTHORIZED_ACCESS_ATTEMPT',
      'KEY_ROTATION'
    )
  ),

  CONSTRAINT security_events_severity_chk CHECK (
    severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
  )
);

-- Dashboard reads are "recent events, newest first, optionally filtered by type
-- or severity". A DESC index on created_at serves that directly.
CREATE INDEX IF NOT EXISTS security_events_created_at_idx
  ON security_events (created_at DESC);

CREATE INDEX IF NOT EXISTS security_events_type_created_idx
  ON security_events (event_type, created_at DESC);

CREATE INDEX IF NOT EXISTS security_events_severity_created_idx
  ON security_events (created_at DESC)
  WHERE severity IN ('HIGH', 'CRITICAL');

-- Per-actor investigation: "everything this user id triggered".
CREATE INDEX IF NOT EXISTS security_events_user_created_idx
  ON security_events (user_id, created_at DESC)
  WHERE user_id IS NOT NULL;

-- Per-event investigation during a sale.
CREATE INDEX IF NOT EXISTS security_events_event_created_idx
  ON security_events (event_id, created_at DESC)
  WHERE event_id IS NOT NULL;


-- =============================================================================
-- 2. audit_logs  (append-only, immutable)
-- =============================================================================
-- Business + security audit trail. This is the evidentiary record: who reserved
-- which seat, which scanner accepted which ticket, which payment was verified.
--
-- IMMUTABILITY IS ENFORCED BY THE DATABASE, NOT BY DISCIPLINE.
-- Application code that "helpfully" rewrites history is the most common way
-- audit logs become worthless, so the prohibition lives in a trigger that no
-- INSERT-only code path can route around. Combined with REVOKE, an ordinary
-- application role cannot mutate history even if it tries.
-- =============================================================================
CREATE TABLE IF NOT EXISTS audit_logs (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

  action      TEXT        NOT NULL,
  actor_id    TEXT        NULL,
  actor_type  TEXT        NOT NULL DEFAULT 'ANONYMOUS',

  target_type TEXT        NULL,
  target_id   TEXT        NULL,
  event_id    TEXT        NULL,

  ip_hash     TEXT        NULL,
  metadata    JSONB       NOT NULL DEFAULT '{}'::jsonb,

  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT audit_logs_actor_type_chk CHECK (
    actor_type IN ('USER', 'ADMIN', 'SYSTEM', 'SCANNER', 'ANONYMOUS')
  )
);

CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx  ON audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS audit_logs_actor_idx       ON audit_logs (actor_id, created_at DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS audit_logs_target_idx      ON audit_logs (target_type, target_id, created_at DESC);
CREATE INDEX IF NOT EXISTS audit_logs_event_idx       ON audit_logs (event_id, created_at DESC) WHERE event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS audit_logs_action_idx      ON audit_logs (action, created_at DESC);

CREATE OR REPLACE FUNCTION audit_logs_reject_mutation() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION
    'audit_logs is append-only; % is not permitted', TG_OP
    USING ERRCODE = '42501';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_logs_no_update ON audit_logs;
CREATE TRIGGER audit_logs_no_update
  BEFORE UPDATE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION audit_logs_reject_mutation();

DROP TRIGGER IF EXISTS audit_logs_no_delete ON audit_logs;
CREATE TRIGGER audit_logs_no_delete
  BEFORE DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION audit_logs_reject_mutation();

-- Belt and braces: the trigger protects the owner role, the grants protect
-- anything that connects as a different role. A retention job must therefore
-- run as a privileged role with an explicit, audited decision — never as the
-- application role.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM PUBLIC;


-- =============================================================================
-- 3. idempotency_records
-- =============================================================================
-- Durable backing store for the idempotency layer.
--
-- Redis is the fast path (it is what makes the claim atomic at low latency).
-- This table is the durable record and the source of truth for keys that
-- mattered: a payment POST whose Redis entry has expired must still not be
-- replayable into a second charge.
--
-- The pair (idempotency_key, endpoint) is unique so the same key may be reused
-- across DIFFERENT endpoints without collision, while reuse within one endpoint
-- is always caught.
-- =============================================================================
CREATE TABLE IF NOT EXISTS idempotency_records (
  id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

  idempotency_key TEXT        NOT NULL,
  endpoint        TEXT        NOT NULL,
  user_id         TEXT        NULL,

  -- Fingerprint of the request this key claimed. Reusing a key with a different
  -- body is a client bug or an attack and must be rejected, not silently served
  -- the wrong cached response. See IdempotencyStore.
  request_hash    TEXT        NOT NULL,

  -- PROCESSING -> SUCCESS | FAILED. Only SUCCESS replays a stored response.
  state           TEXT        NOT NULL DEFAULT 'PROCESSING',

  -- Status code + body captured on completion, replayed verbatim to duplicates.
  response_status INTEGER     NULL,
  response_body   JSONB       NULL,

  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at      TIMESTAMPTZ NOT NULL,

  CONSTRAINT idempotency_records_unique_chk UNIQUE (idempotency_key, endpoint),

  CONSTRAINT idempotency_records_state_chk CHECK (
    state IN ('PROCESSING', 'SUCCESS', 'FAILED')
  ),

  CONSTRAINT idempotency_records_status_chk CHECK (
    response_status IS NULL OR response_status BETWEEN 100 AND 599
  ),

  -- A completed record must carry the response it will replay; an in-flight one
  -- must not. Enforced here so a partial write cannot become a source of
  -- confusing behaviour later.
  CONSTRAINT idempotency_records_completion_chk CHECK (
    (state = 'PROCESSING' AND response_status IS NULL)
    OR
    (state IN ('SUCCESS', 'FAILED') AND response_status IS NOT NULL)
  )
);

CREATE INDEX IF NOT EXISTS idempotency_records_expires_idx
  ON idempotency_records (expires_at);

CREATE INDEX IF NOT EXISTS idempotency_records_user_idx
  ON idempotency_records (user_id, created_at DESC)
  WHERE user_id IS NOT NULL;

-- Sweeps expired records without scanning the live working set.
CREATE INDEX IF NOT EXISTS idempotency_records_live_idx
  ON idempotency_records (created_at DESC)
  WHERE state = 'PROCESSING';

-- Keep updated_at honest without relying on every writer to remember it.
CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS idempotency_records_touch ON idempotency_records;
CREATE TRIGGER idempotency_records_touch
  BEFORE UPDATE ON idempotency_records
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();


-- =============================================================================
-- 4. queue_entries
-- =============================================================================
-- Virtual queue membership for high-demand events.
--
-- (event_id, session_id) is unique: one session occupies exactly one place in
-- one event's queue. Re-joining is therefore idempotent by construction rather
-- than by application-level checking, which is what closes the "join 400 times
-- to jump the queue" attack.
-- =============================================================================
CREATE TABLE IF NOT EXISTS queue_entries (
  id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

  event_id      TEXT        NOT NULL,
  session_id    TEXT        NOT NULL,
  user_id       TEXT        NULL,

  queue_id      TEXT        NOT NULL,
  -- Server-assigned position. Never derived from a client-side countdown.
  position      BIGINT      NOT NULL,

  status        TEXT        NOT NULL DEFAULT 'WAITING',

  joined_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  admitted_at   TIMESTAMPTZ NULL,
  left_at       TIMESTAMPTZ NULL,

  CONSTRAINT queue_entries_unique_chk UNIQUE (event_id, session_id),
  CONSTRAINT queue_entries_queue_id_chk UNIQUE (queue_id),

  CONSTRAINT queue_entries_status_chk CHECK (
    status IN ('WAITING', 'ADMITTED', 'EXPIRED', 'LEFT')
  ),

  -- Position must be positive; a zero or negative position would sort ahead of
  -- everyone and is a queue-bypass primitive.
  CONSTRAINT queue_entries_position_chk CHECK (position > 0),

  -- An ADMITTED row must record when it was admitted.
  CONSTRAINT queue_entries_admitted_chk CHECK (
    status <> 'ADMITTED' OR admitted_at IS NOT NULL
  )
);

-- The admission sweep pulls the next N WAITING rows in position order. This
-- index is the hot path and must be ascending.
CREATE INDEX IF NOT EXISTS queue_entries_admit_idx
  ON queue_entries (event_id, position)
  WHERE status = 'WAITING';

CREATE INDEX IF NOT EXISTS queue_entries_queue_id_idx  ON queue_entries (queue_id);
CREATE INDEX IF NOT EXISTS queue_entries_user_idx     ON queue_entries (user_id, joined_at DESC) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS queue_entries_joined_idx   ON queue_entries (joined_at DESC);
CREATE INDEX IF NOT EXISTS queue_entries_event_status_idx ON queue_entries (event_id, status);


-- =============================================================================
-- 5. ticket_scans  (append-only ledger)
-- =============================================================================
-- Independent evidence of every scan attempt, accepted or rejected.
--
-- This table is NOT the replay-protection mechanism. Replay protection is the
-- atomic CONFIRMED->USED transition in Person 1's ticket store (see
-- TicketRepository.consumeConfirmedTicket). This table is the audit trail beside
-- it, so that when a legitimate customer is turned away at the gate we can prove
-- what happened and reconstruct the sequence.
--
-- Append-only for the same reason as audit_logs, and enforced the same way.
-- =============================================================================
CREATE TABLE IF NOT EXISTS ticket_scans (
  id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

  ticket_id   TEXT        NULL,
  event_id    TEXT        NULL,
  scanner_id  TEXT        NULL,
  actor_id    TEXT        NULL,
  ip_hash     TEXT        NULL,

  outcome     TEXT        NOT NULL,
  reason      TEXT        NULL,

  -- Set when the scan was rejected, to distinguish a forged ticket from a
  -- merely unlucky or impatient one.
  signature_kid TEXT      NULL,

  metadata    JSONB       NOT NULL DEFAULT '{}'::jsonb,
  scanned_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

  CONSTRAINT ticket_scans_outcome_chk CHECK (
    outcome IN ('ACCEPTED', 'REJECTED')
  )
);

CREATE INDEX IF NOT EXISTS ticket_scans_ticket_idx  ON ticket_scans (ticket_id, scanned_at DESC);
CREATE INDEX IF NOT EXISTS ticket_scans_event_idx   ON ticket_scans (event_id, scanned_at DESC) WHERE event_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ticket_scans_scanner_idx ON ticket_scans (scanner_id, scanned_at DESC) WHERE scanner_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS ticket_scans_rejected_idx ON ticket_scans (scanned_at DESC) WHERE outcome = 'REJECTED';

DROP TRIGGER IF EXISTS ticket_scans_no_update ON ticket_scans;
CREATE TRIGGER ticket_scans_no_update
  BEFORE UPDATE ON ticket_scans
  FOR EACH ROW EXECUTE FUNCTION audit_logs_reject_mutation();

DROP TRIGGER IF EXISTS ticket_scans_no_delete ON ticket_scans;
CREATE TRIGGER ticket_scans_no_delete
  BEFORE DELETE ON ticket_scans
  FOR EACH ROW EXECUTE FUNCTION audit_logs_reject_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON ticket_scans FROM PUBLIC;


-- =============================================================================
-- Migration bookkeeping
-- =============================================================================
CREATE TABLE IF NOT EXISTS sec_schema_migrations (
  version     TEXT        PRIMARY KEY,
  applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO sec_schema_migrations (version)
VALUES ('001_security_tables')
ON CONFLICT (version) DO NOTHING;

COMMIT;
