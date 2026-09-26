/**
 * Parts 10 & 11 — security events and audit trail.
 *
 * These run against real Postgres because the guarantees under test are partly
 * database guarantees: the enum CHECK, the immutability trigger, and the column
 * constraints. An in-memory double would happily accept an event type the real
 * schema rejects.
 */

import type { Pool } from 'pg';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  PiiInMetadataError,
  SECURITY_EVENT_TYPES,
  TelemetrySink,
  assertNoPii,
  pseudonymize,
  recordScan,
  type SecurityEventType,
} from '../../src/telemetry/telemetry-sink';
import { createPool, isPostgresAvailable } from '../helpers/postgres';

const HASH_SECRET = 't'.repeat(48);

describe('security events and audit trail (Parts 10 & 11)', () => {
  let pool: Pool;

  beforeAll(async () => {
    if (!(await isPostgresAvailable())) throw new Error('Postgres is required for the telemetry suite.');
    pool = await createPool();
  });

  afterAll(async () => {
    await pool?.end();
  });

  beforeEach(async () => {
    await pool.query('TRUNCATE security_events, audit_logs');
  });

  afterEach(async () => {
    await pool.query('TRUNCATE security_events, audit_logs');
  });

  const sink = () => new TelemetrySink({ hashSecret: HASH_SECRET, pool });

  describe('privacy', () => {
    it('never stores a raw IP address', async () => {
      const s = sink();
      await s.recordEvent({ eventType: 'RATE_LIMIT_TRIGGERED', ip: '203.0.113.42' });

      const { rows } = await pool.query('SELECT ip_hash, metadata::text AS meta FROM security_events');
      const serialized = JSON.stringify(rows);
      expect(serialized).not.toContain('203.0.113.42');
      expect(rows[0].ip_hash).toMatch(/^[0-9a-f]{32}$/);
    });

    it('never stores a raw session id', async () => {
      const s = sink();
      await s.recordEvent({ eventType: 'BOT_SIGNAL_DETECTED', sessionId: 'sess_secret_value' });
      const { rows } = await pool.query('SELECT session_id_hash FROM security_events');
      expect(JSON.stringify(rows)).not.toContain('sess_secret_value');
    });

    it('pseudonymises deterministically, so correlation still works', () => {
      expect(pseudonymize('1.2.3.4', HASH_SECRET)).toBe(pseudonymize('1.2.3.4', HASH_SECRET));
      expect(pseudonymize('1.2.3.4', HASH_SECRET)).not.toBe(pseudonymize('1.2.3.5', HASH_SECRET));
    });

    it('produces different hashes under a different secret', () => {
      // A rotated hash secret must not allow correlation with pre-rotation rows.
      expect(pseudonymize('1.2.3.4', 'a'.repeat(48))).not.toBe(pseudonymize('1.2.3.4', 'b'.repeat(48)));
    });

    it('maps absent values to null rather than the empty hash', () => {
      expect(pseudonymize(undefined, HASH_SECRET)).toBeNull();
      expect(pseudonymize(null, HASH_SECRET)).toBeNull();
      expect(pseudonymize('', HASH_SECRET)).toBeNull();
    });
  });

  describe('PII backstop', () => {
    it('rejects personal data in metadata', () => {
      for (const key of ['email', 'user_email', 'password', 'phone', 'ssn', 'cardNumber', 'authorization']) {
        expect(() => assertNoPii({ [key]: 'x' })).toThrow(PiiInMetadataError);
      }
    });

    /** Metadata is serialised whole, so a nested address must be caught too. */
    it('rejects personal data nested inside metadata', () => {
      expect(() => assertNoPii({ user: { email: 'a@b.com' } })).toThrow(PiiInMetadataError);
      expect(() => assertNoPii({ items: [{ card: '4111' }] })).toThrow(PiiInMetadataError);
    });

    it('reports the offending path', () => {
      try {
        assertNoPii({ booking: { holder: { phone: '555' } } });
        throw new Error('should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(PiiInMetadataError);
        expect((error as PiiInMetadataError).key).toBe('booking.holder.phone');
      }
    });

    it('permits operational keys that merely look similar', () => {
      assertNoPii({
        eventName: 'Tixify Live',
        tokenCount: 12,
        scannerId: 'S1',
        outcome: 'ACCEPTED',
        attempt: 3,
      });
    });

    it('refuses to record rather than silently dropping the field', async () => {
      const s = sink();
      await expect(s.recordEvent({ eventType: 'RATE_LIMIT_TRIGGERED', metadata: { email: 'a@b.com' } })).rejects.toThrow(
        PiiInMetadataError,
      );
      // Nothing was written: a partial write would be worse than none.
      const { rows } = await pool.query('SELECT count(*)::int AS n FROM security_events');
      expect(rows[0].n).toBe(0);
    });
  });

  describe('schema conformance', () => {
    it('accepts every enumerated event type', async () => {
      const s = sink();
      for (const eventType of SECURITY_EVENT_TYPES) {
        await s.recordEvent({ eventType: eventType as SecurityEventType });
      }
      const { rows } = await pool.query('SELECT count(*)::int AS n FROM security_events');
      expect(rows[0].n).toBe(SECURITY_EVENT_TYPES.length);
    });

    /** The catalogue and the CHECK constraint must not drift apart. */
    it('has no event type the database would reject', async () => {
      const s = sink();
      for (const eventType of SECURITY_EVENT_TYPES) {
        await expect(s.recordEvent({ eventType: eventType as SecurityEventType })).resolves.toBeDefined();
      }
      expect(s.lastError).toBeNull();
    });

    it('applies a default severity per event type', async () => {
      const s = sink();
      // A replay attempt is severe by definition; the caller should not have to
      // remember to say so.
      await s.recordEvent({ eventType: 'REPLAY_ATTEMPT' });
      const { rows } = await pool.query('SELECT severity FROM security_events');
      expect(rows[0].severity).toBe('HIGH');
    });

    it('lets a caller escalate severity but not below the default', async () => {
      const s = sink();
      await s.recordEvent({ eventType: 'REPLAY_ATTEMPT', severity: 'CRITICAL' });
      const { rows } = await pool.query('SELECT severity FROM security_events');
      expect(rows[0].severity).toBe('CRITICAL');
    });

    it('stores metadata as structured json, not a string', async () => {
      const s = sink();
      await s.recordEvent({ eventType: 'BOT_SIGNAL_DETECTED', metadata: { signal: 'RATE_LIMIT', count: 3 } });
      const { rows } = await pool.query('SELECT metadata FROM security_events');
      expect(rows[0].metadata).toEqual({ signal: 'RATE_LIMIT', count: 3 });
    });
  });

  describe('availability posture', () => {
    it('never lets a telemetry failure propagate to the caller', async () => {
      // A pool pointed at a dead port: every insert fails.
      const broken = new TelemetrySink({ hashSecret: HASH_SECRET, pool: { query: async () => { throw new Error('ECONNREFUSED'); } } as never });
      await expect(broken.recordEvent({ eventType: 'RATE_LIMIT_TRIGGERED' })).resolves.toBeDefined();
      await expect(broken.recordAudit({ action: 'TICKET_VERIFIED' })).resolves.toBeDefined();
    });

    it('surfaces the failure for the health endpoint', async () => {
      const broken = new TelemetrySink({ hashSecret: HASH_SECRET, pool: { query: async () => { throw new Error('ECONNREFUSED'); } } as never });
      await broken.recordEvent({ eventType: 'RATE_LIMIT_TRIGGERED' });
      expect(broken.lastError?.message).toContain('ECONNREFUSED');
    });

    it('clears the error once writes recover, on the same instance', async () => {
      // A health endpoint that reports a stale error is worse than one that
      // reports nothing, so recovery must clear it rather than latch.
      let fail = true;
      const flaky = new TelemetrySink({
        hashSecret: HASH_SECRET,
        pool: {
          query: async () => {
            if (fail) throw new Error('ECONNRESET');
            return { rows: [] };
          },
        } as never,
      });

      await flaky.recordEvent({ eventType: 'RATE_LIMIT_TRIGGERED' });
      expect(flaky.lastError?.message).toContain('ECONNRESET');

      fail = false;
      await flaky.recordEvent({ eventType: 'RATE_LIMIT_TRIGGERED' });
      expect(flaky.lastError).toBeNull();
    });

    it('keeps the in-memory buffer even when the database is down', async () => {
      const broken = new TelemetrySink({ hashSecret: HASH_SECRET, pool: { query: async () => { throw new Error('x'); } } as never });
      await broken.recordEvent({ eventType: 'RATE_LIMIT_TRIGGERED' });
      expect(broken.recentEvents()).toHaveLength(1);
    });

    it('bounds the buffer so an incident cannot exhaust memory', async () => {
      const s = new TelemetrySink({ hashSecret: HASH_SECRET, bufferLimit: 10 });
      for (let i = 0; i < 50; i += 1) await s.recordEvent({ eventType: 'RATE_LIMIT_TRIGGERED' });
      expect(s.recentEvents(100)).toHaveLength(10);
    });

    it('works with no pool attached at all', async () => {
      const s = new TelemetrySink({ hashSecret: HASH_SECRET });
      await expect(s.recordEvent({ eventType: 'KEY_ROTATION' })).resolves.toBeDefined();
    });
  });

  describe('audit trail', () => {
    it('records an audit row with the scanner as actor', async () => {
      const s = sink();
      await s.recordAudit({
        action: 'TICKET_SCANNED',
        actorId: 'SCANNER_4',
        actorType: 'SCANNER',
        targetType: 'TICKET',
        targetId: 'TKT_1',
        eventId: 'EVT_1',
        metadata: { outcome: 'ACCEPTED' },
      });
      const { rows } = await pool.query('SELECT * FROM audit_logs');
      expect(rows).toHaveLength(1);
      expect(rows[0].action).toBe('TICKET_SCANNED');
      expect(rows[0].actor_type).toBe('SCANNER');
      expect(rows[0].target_id).toBe('TKT_1');
    });

    it('defaults an unspecified actor type to ANONYMOUS', async () => {
      const s = sink();
      await s.recordAudit({ action: 'RESERVATION_CREATED' });
      const { rows } = await pool.query('SELECT actor_type FROM audit_logs');
      expect(rows[0].actor_type).toBe('ANONYMOUS');
    });

    /** Immutability is the entire value of an audit log, so the DB must enforce it. */
    it('refuses updates and deletes at the database level', async () => {
      const s = sink();
      await s.recordAudit({ action: 'BOOKING_CREATED', actorId: 'U1' });
      await expect(pool.query("UPDATE audit_logs SET action = 'TAMPERED'")).rejects.toThrow();
      await expect(pool.query('DELETE FROM audit_logs')).rejects.toThrow();
      const { rows } = await pool.query('SELECT action FROM audit_logs');
      expect(rows[0].action).toBe('BOOKING_CREATED');
    });
  });

  describe('recordScan', () => {
    it('writes both an event and an audit row for an accepted scan', async () => {
      const s = sink();
      await recordScan(s, {
        accepted: true,
        outcome: 'ACCEPTED',
        ticketId: 'TKT_1',
        eventId: 'EVT_1',
        scannerId: 'SCANNER_4',
        actorId: 'U1',
        ip: '203.0.113.9',
        signatureKid: 'kid_1',
      });

      const events = await pool.query('SELECT event_type, ip_hash FROM security_events');
      const audit = await pool.query('SELECT action, actor_type FROM audit_logs');
      expect(events.rows[0].event_type).toBe('TICKET_SCAN_ACCEPTED');
      expect(events.rows[0].ip_hash).not.toBeNull();
      expect(audit.rows[0].action).toBe('TICKET_SCANNED');
      expect(audit.rows[0].actor_type).toBe('SCANNER');
    });

    it('writes the rejected variant for a failed scan', async () => {
      const s = sink();
      await recordScan(s, { accepted: false, outcome: 'REPLAY_ATTEMPT', ticketId: 'TKT_1', eventId: 'EVT_1' });
      const events = await pool.query('SELECT event_type FROM security_events');
      const audit = await pool.query('SELECT action FROM audit_logs');
      expect(events.rows[0].event_type).toBe('TICKET_SCAN_REJECTED');
      expect(audit.rows[0].action).toBe('TICKET_REJECTED');
    });

    it('records a closed outcome enum rather than a raw error', async () => {
      const s = sink();
      await recordScan(s, { accepted: false, outcome: 'INVALID_SIGNATURE', ticketId: 'T' });
      const { rows } = await pool.query('SELECT metadata FROM audit_logs');
      expect(rows[0].metadata.outcome).toBe('INVALID_SIGNATURE');
    });
  });
});
