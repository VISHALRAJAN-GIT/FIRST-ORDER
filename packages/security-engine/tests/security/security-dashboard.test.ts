/**
 * Part 12 — Security dashboard against the real schema.
 *
 * The aggregation queries are the part most likely to be wrong in a way that only
 * shows up on real data volumes, so they run against Postgres with real rows
 * rather than against a mocked pool that would happily accept a bad query.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { SecurityDashboard } from '../../src/dashboard/security-dashboard';
import { SecurityError } from '../../src/core/errors';
import type { AdminAuthorizer, AuthenticatedPrincipal } from '../../src/ports/user-resolver';
import type { SecurityEventType, SecuritySeverity } from '../../src/telemetry/telemetry-sink';
import { createPool, isPostgresAvailable } from '../helpers/postgres';

const ADMIN: AuthenticatedPrincipal = { userId: 'admin-1', roles: ['ADMIN' as const] };
const USER: AuthenticatedPrincipal = { userId: 'user-1', roles: ['USER' as const] };

describe('SecurityDashboard (Part 12)', () => {
  let pool: Pool;
  const now = () => new Date('2026-06-01T12:00:00.000Z');

  const authorizer: AdminAuthorizer = { isAdmin: (p) => p?.roles.includes('ADMIN') ?? false };

  beforeAll(async () => {
    if (!(await isPostgresAvailable())) throw new Error('Postgres is required for the dashboard suite.');
    pool = await createPool();
  });

  afterAll(async () => {
    await pool?.query('TRUNCATE security_events').catch(() => undefined);
    await pool?.end();
  });

  afterEach(async () => {
    await pool.query('TRUNCATE security_events');
  });

  const dashboard = (overrides: Partial<{ authorizer: AdminAuthorizer }> = {}) =>
    new SecurityDashboard({ pool, authorizer: overrides.authorizer ?? authorizer, now });

  const insert = async (row: {
    eventType: SecurityEventType;
    severity: SecuritySeverity;
    userId?: string | null;
    ipHash?: string | null;
    endpoint?: string | null;
    metadata?: Record<string, unknown>;
    ageSeconds?: number;
  }) => {
    const { rows } = await pool.query<{ id: string }>(
      `INSERT INTO security_events
         (event_type, severity, user_id, ip_hash, endpoint, metadata, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, now() - ($7 || ' seconds')::interval)
       RETURNING id`,
      [
        row.eventType,
        row.severity,
        row.userId ?? null,
        row.ipHash ?? null,
        row.endpoint ?? null,
        JSON.stringify(row.metadata ?? {}),
        String(row.ageSeconds ?? 0),
      ],
    );
    return rows[0]!.id;
  };

  describe('authorisation', () => {
    it('refuses a non-admin principal', async () => {
      await expect(dashboard().summary({ principal: USER })).rejects.toBeInstanceOf(SecurityError);
      await expect(dashboard().recentEvents({ principal: USER })).rejects.toBeInstanceOf(SecurityError);
    });

    it('refuses an anonymous caller', async () => {
      await expect(dashboard().summary({ principal: null })).rejects.toBeInstanceOf(SecurityError);
    });

    it('refuses before touching the database', async () => {
      // An unauthorised call must not leak timing information about whether the
      // table exists or is large, so the check happens first.
      const queries: unknown[] = [];
      const spying = new SecurityDashboard({
        pool: { query: async (...args: unknown[]) => { queries.push(args); return { rows: [], rowCount: 0 }; } } as never,
        authorizer,
        now,
      });
      await expect(spying.summary({ principal: USER })).rejects.toBeInstanceOf(SecurityError);
      expect(queries).toHaveLength(0);
    });

    it('re-checks on every call so a revoked admin loses access immediately', async () => {
      let allowed = true;
      const revocable: AdminAuthorizer = { isAdmin: (p) => allowed && (p?.roles.includes('ADMIN') ?? false) };
      const dash = dashboard({ authorizer: revocable });
      await expect(dash.summary({ principal: ADMIN })).resolves.toBeDefined();
      allowed = false;
      await expect(dash.summary({ principal: ADMIN })).rejects.toBeInstanceOf(SecurityError);
    });
  });

  describe('summary', () => {
    it('reports zeroes for every severity when the window is empty', async () => {
      const summary = await dashboard().summary({ principal: ADMIN, windowSeconds: 3_600 });
      expect(summary.totalEvents).toBe(0);
      expect(summary.criticalCount).toBe(0);
      // Every severity present even at zero, so an empty dashboard does not read
      // as missing data when someone is deciding whether they are under attack.
      expect(summary.bySeverity.map((s) => s.severity).sort()).toEqual(['CRITICAL', 'HIGH', 'LOW', 'MEDIUM']);
      expect(summary.bySeverity.every((s) => s.count === 0)).toBe(true);
    });

    it('counts events by type and severity', async () => {
      await insert({ eventType: 'REPLAY_ATTEMPT', severity: 'HIGH' });
      await insert({ eventType: 'REPLAY_ATTEMPT', severity: 'CRITICAL' });
      await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'MEDIUM' });

      const summary = await dashboard().summary({ principal: ADMIN, windowSeconds: 3_600 });
      expect(summary.totalEvents).toBe(3);
      expect(summary.byType).toEqual(
        expect.arrayContaining([
          { eventType: 'REPLAY_ATTEMPT', count: 2 },
          { eventType: 'RATE_LIMIT_TRIGGERED', count: 1 },
        ]),
      );
      expect(summary.criticalCount).toBe(1);
    });

    it('excludes events outside the window', async () => {
      await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'LOW', ageSeconds: 30 });
      await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'LOW', ageSeconds: 7_200 });

      const narrow = await dashboard().summary({ principal: ADMIN, windowSeconds: 60 });
      expect(narrow.totalEvents).toBe(1);
      const wide = await dashboard().summary({ principal: ADMIN, windowSeconds: 86_400 });
      expect(wide.totalEvents).toBe(2);
    });

    it('computes a per-minute rate over the window', async () => {
      for (let i = 0; i < 30; i += 1) await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'LOW' });
      const summary = await dashboard().summary({ principal: ADMIN, windowSeconds: 3_600 });
      expect(summary.eventsPerMinute).toBe(0.5);
    });

    it('buckets the trend by hour', async () => {
      await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'LOW', ageSeconds: 60 });
      await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'LOW', ageSeconds: 120 });
      await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'LOW', ageSeconds: 3_800 });

      const summary = await dashboard().summary({ principal: ADMIN, windowSeconds: 86_400 });
      expect(summary.trend).toHaveLength(2);
      expect(summary.trend.reduce((sum, point) => sum + point.count, 0)).toBe(3);
      // Ordered oldest first so a chart can render it without re-sorting.
      expect(summary.trend[0]!.bucket < summary.trend[1]!.bucket).toBe(true);
    });

    it('ranks the busiest users and addresses', async () => {
      for (let i = 0; i < 3; i += 1) await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'LOW', userId: 'u-busy', ipHash: 'hash-busy' });
      await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'LOW', userId: 'u-quiet', ipHash: 'hash-quiet' });
      // Anonymous events must not appear as a null bucket.
      await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'LOW' });

      const summary = await dashboard().summary({ principal: ADMIN, windowSeconds: 3_600 });
      expect(summary.topUsers[0]).toEqual({ userId: 'u-busy', count: 3 });
      expect(summary.topUsers).toHaveLength(2);
      expect(summary.topIps[0]).toEqual({ ipHash: 'hash-busy', count: 3 });
      expect(summary.topIps.some((row) => row.ipHash === null)).toBe(false);
    });

    it('rejects an out-of-range window', async () => {
      await expect(dashboard().summary({ principal: ADMIN, windowSeconds: 0 })).rejects.toBeInstanceOf(SecurityError);
      await expect(dashboard().summary({ principal: ADMIN, windowSeconds: 10 ** 9 })).rejects.toBeInstanceOf(SecurityError);
      await expect(dashboard().summary({ principal: ADMIN, windowSeconds: 1.5 })).rejects.toBeInstanceOf(SecurityError);
    });
  });

  describe('recentEvents', () => {
    it('returns newest first', async () => {
      const older = await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'LOW', ageSeconds: 120 });
      const newer = await insert({ eventType: 'REPLAY_ATTEMPT', severity: 'HIGH', ageSeconds: 10 });
      const events = await dashboard().recentEvents({ principal: ADMIN, windowSeconds: 3_600 });
      expect(events.map((e) => e.id)).toEqual([newer, older]);
    });

    it('filters by type and by severity', async () => {
      await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'LOW' });
      await insert({ eventType: 'REPLAY_ATTEMPT', severity: 'CRITICAL' });
      await insert({ eventType: 'REPLAY_ATTEMPT', severity: 'HIGH' });

      expect(await dashboard().recentEvents({ principal: ADMIN, eventType: 'REPLAY_ATTEMPT' })).toHaveLength(2);
      expect(await dashboard().recentEvents({ principal: ADMIN, severity: 'CRITICAL' })).toHaveLength(1);
    });

    it('caps the result set', async () => {
      for (let i = 0; i < 12; i += 1) await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'LOW' });
      expect(await dashboard().recentEvents({ principal: ADMIN, limit: 5 })).toHaveLength(5);
    });

    it('clamps a limit above the ceiling', async () => {
      for (let i = 0; i < 12; i += 1) await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'LOW' });
      const bounded = new SecurityDashboard({ pool, authorizer, now, maxLimit: 3 });
      expect(await bounded.recentEvents({ principal: ADMIN, limit: 10_000 })).toHaveLength(3);
    });

    it('rejects a nonsensical limit', async () => {
      await expect(dashboard().recentEvents({ principal: ADMIN, limit: 0 })).rejects.toBeInstanceOf(SecurityError);
      await expect(dashboard().recentEvents({ principal: ADMIN, limit: -1 })).rejects.toBeInstanceOf(SecurityError);
    });

    it('returns metadata alongside the row', async () => {
      await insert({
        eventType: 'REPLAY_ATTEMPT',
        severity: 'HIGH',
        endpoint: 'POST /api/scan',
        userId: 'u-1',
        ipHash: 'hash-1',
        metadata: { reason: 'already scanned' },
      });
      const [event] = await dashboard().recentEvents({ principal: ADMIN });
      expect(event).toMatchObject({
        eventType: 'REPLAY_ATTEMPT',
        severity: 'HIGH',
        endpoint: 'POST /api/scan',
        userId: 'u-1',
        ipHash: 'hash-1',
        metadata: { reason: 'already scanned' },
      });
    });
  });

  describe('subjectHistory', () => {
    it('returns everything one user triggered', async () => {
      await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'MEDIUM', userId: 'u-target' });
      await insert({ eventType: 'IDEMPOTENCY_KEY_REUSE', severity: 'HIGH', userId: 'u-target' });
      await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'LOW', userId: 'u-other' });

      const history = await dashboard().subjectHistory({ principal: ADMIN, userId: 'u-target' });
      expect(history).toHaveLength(2);
      expect(history.every((e) => e.userId === 'u-target')).toBe(true);
    });

    it('accepts an address hash instead of a user', async () => {
      await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'MEDIUM', ipHash: 'hash-x' });
      await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'MEDIUM', ipHash: 'hash-y' });
      expect(await dashboard().subjectHistory({ principal: ADMIN, ipHash: 'hash-x' })).toHaveLength(1);
    });

    it('matches both when both are supplied', async () => {
      await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'MEDIUM', userId: 'u-a', ipHash: 'hash-a' });
      await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'MEDIUM', userId: 'u-a', ipHash: 'hash-b' });
      await insert({ eventType: 'RATE_LIMIT_TRIGGERED', severity: 'MEDIUM', userId: 'u-b', ipHash: 'hash-a' });
      expect(await dashboard().subjectHistory({ principal: ADMIN, userId: 'u-a', ipHash: 'hash-a' })).toHaveLength(1);
    });

    it('requires a subject', async () => {
      await expect(dashboard().subjectHistory({ principal: ADMIN })).rejects.toBeInstanceOf(SecurityError);
    });

    it('returns an empty list for an unknown subject rather than failing', async () => {
      expect(await dashboard().subjectHistory({ principal: ADMIN, userId: 'ghost' })).toEqual([]);
    });
  });

  it('exposes no write path', () => {
    // A dashboard that can write can be used to erase evidence. The read-only
    // surface is asserted here so adding a method is a deliberate act.
    const surface = Object.getOwnPropertyNames(SecurityDashboard.prototype).filter(
      (name) => !name.startsWith('#') && name !== 'constructor',
    );
    expect(surface.sort()).toEqual(['recentEvents', 'subjectHistory', 'summary']);
  });
});
