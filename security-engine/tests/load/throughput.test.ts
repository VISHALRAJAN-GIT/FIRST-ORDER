import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import IORedis from 'ioredis';
import type { Pool } from 'pg';

import { RateLimiter } from '../../src/rate-limit/rate-limiter';
import { ChallengeStore } from '../../src/bot-protection/challenge';
import { VirtualQueue, type QueueStore, type QueueEntry } from '../../src/queue/virtual-queue';
import { wrapIoredis, type RedisLike } from '../../src/ports/redis';
import { createPool, isPostgresAvailable } from '../helpers/postgres';
import { InMemoryRedis } from '../helpers/in-memory-redis';
import { load, report, serializedThresholds, thresholds } from '../helpers/load-driver';

/**
 * Part 16: threshold-gated load tests.
 *
 * These run against the real Redis and the real Postgres, because the entire
 * argument for this engine is that the hot paths are atomic. Measuring an
 * in-memory double would measure the double: an atomic Lua script and three
 * round trips have near-identical cost against a Map and wildly different cost
 * against a socket, so only the real services can tell you whether the atomicity
 * is affordable.
 *
 * What is gated is p95 latency and throughput, and the gate is the point. A
 * benchmark that only prints numbers gets ignored the first time it goes red on
 * someone's laptop.
 */

const REDIS_URL = process.env.TEST_REDIS_URL ?? 'redis://127.0.0.1:6379';
const LIMITS = thresholds();
const QUEUE_LIMITS = serializedThresholds();
const RUN_ID = `load${process.pid}x${Date.now().toString(36)}`;

let redis: RedisLike | null = null;
let pool: Pool | null = null;

async function connectRedis(): Promise<RedisLike | null> {
  try {
    const raw = new IORedis(REDIS_URL, { maxRetriesPerRequest: 2, lazyConnect: true, enableOfflineQueue: false });
    await raw.connect();
    return wrapIoredis(raw as never);
  } catch {
    return null;
  }
}

describe('load: rate limiting (Redis)', () => {
  let limiter: RateLimiter;

  beforeAll(async () => {
    redis = await connectRedis();
    if (!redis) return;
    limiter = new RateLimiter({ redis, keyPrefix: `${RUN_ID}:`, now: () => Date.now() });
  });

  it('sustains a burst well past the per-event limit without p95 blowing up', async () => {
    if (!redis) {
      it.skip('redis unavailable');
      return;
    }
    // The decision latency is what matters, and it must not degrade as the
    // bucket drains - that is the difference between a token bucket and a queue
    // in front of the limiter.
    const result = await load(
      async (index) => {
        await limiter.consume(
          { ip: `10.0.0.${index % 250}`, endpoint: 'POST /api/tickets/verify' },
          { requestsPerSecond: 20, burstLimit: 100, windowSeconds: 60, maxPerWindow: 6000 },
          'IP',
        );
      },
      { total: 2_000, concurrency: 50 },
    );

    report('rate-limit consume', result, LIMITS);
    expect(result.errors).toBe(0);
  });

  it('rejects deterministically once the burst is exhausted', async () => {
    if (!redis) {
      it.skip('redis unavailable');
      return;
    }
    // Correctness under load, not just speed. A run this size will have drained
    // the burst, so nothing further may be granted: if it ever is, the limiter is
    // not a limiter.
    const subject = { ip: '10.9.9.9', endpoint: 'POST /api/tickets/verify' };
    const policy = { requestsPerSecond: 1, burstLimit: 5, windowSeconds: 60, maxPerWindow: 100 };
    const verdicts = await load(() => limiter.consume(subject, policy, 'IP'), { total: 40, concurrency: 8 });

    report('rate-limit exhausted burst', verdicts, LIMITS);
    expect(verdicts.errors).toBe(0);
    const allowed = await Promise.all(Array.from({ length: 20 }, () => limiter.consume(subject, policy, 'IP')));
    expect(allowed.every((v) => !v.allowed)).toBe(true);
  });
});

describe('load: challenge redemption (Redis)', () => {
  it('redeems many distinct tokens concurrently', async () => {
    if (!redis) {
      it.skip('redis unavailable');
      return;
    }
    const store = new ChallengeStore({ redis, keyPrefix: `${RUN_ID}:`, defaultTtlSeconds: 60 });

    const result = await load(
      async () => {
        const subject = { userId: `U_${Math.random().toString(36).slice(2, 10)}`, ip: '203.0.113.1' };
        const issued = await store.issue(subject, 60);
        const verified = await store.verify(issued.token, subject);
        if (!verified.valid) throw new Error('expected a valid redemption');
      },
      { total: 400, concurrency: 25 },
    );

    report('challenge issue+redeem', result, LIMITS);
    expect(result.errors).toBe(0);
  });
});

describe('load: queue join (Postgres)', () => {
  it('assigns strictly increasing positions under contention', async () => {
    if (!(await isPostgresAvailable())) {
      it.skip('postgres unavailable');
      return;
    }
    pool = await createPool(12);

    // A store that satisfies the real contract, so the load runs through the
    // engine's own advisory-lock and upsert path rather than around it.
    const store: QueueStore = {
      async join(input) {
        const client = await pool!.connect();
        try {
          await client.query('BEGIN');
          await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`load-queue:${input.eventId}`]);
          const inserted = await client.query(
            `INSERT INTO queue_entries (queue_id, event_id, session_id, user_id, position, status, joined_at)
             VALUES ($1, $2, $3, $4, (SELECT COALESCE(MAX(position), 0) + 1 FROM queue_entries WHERE event_id = $2), 'WAITING', now())
             ON CONFLICT (event_id, session_id) DO NOTHING
             RETURNING queue_id, position`,
            [`Q_${input.eventId}_${input.sessionId}`, input.eventId, input.sessionId, input.userId ?? null],
          );
          await client.query('COMMIT');
          if (inserted.rowCount && inserted.rowCount > 0) {
            const row = inserted.rows[0] as { queue_id: string; position: number };
            return {
              status: 'QUEUED' as const,
              entry: {
                queueId: row.queue_id,
                eventId: input.eventId,
                sessionId: input.sessionId,
                userId: input.userId,
                position: Number(row.position),
                status: 'WAITING' as QueueEntry['status'],
                joinedAt: new Date().toISOString(),
              } as QueueEntry,
            };
          }
          const existing = await pool!.query(
            'SELECT queue_id, position FROM queue_entries WHERE event_id = $1 AND session_id = $2',
            [input.eventId, input.sessionId],
          );
          const row = existing.rows[0] as { queue_id: string; position: number };
          return {
            status: 'ALREADY_QUEUED' as const,
            entry: {
              queueId: row.queue_id,
              eventId: input.eventId,
              sessionId: input.sessionId,
              userId: input.userId,
              position: Number(row.position),
              status: 'WAITING' as QueueEntry['status'],
              joinedAt: new Date().toISOString(),
            } as QueueEntry,
          };
        } catch (error) {
          await client.query('ROLLBACK');
          throw error;
        } finally {
          client.release();
        }
      },
      async getBySession() {
        return null;
      },
      async getByQueueId() {
        return null;
      },
      async promote() {
        return [];
      },
      async markLeft() {
        return true;
      },
      async size() {
        return 0;
      },
      async aheadOf() {
        return 0;
      },
    };

    const queue = new VirtualQueue({
      store,
      codec: {
        async sign(): Promise<string> {
          return 'load-token';
        },
        async verify(): Promise<boolean> {
          return true;
        },
      } as never,
      redis: new InMemoryRedis(),
      keyPrefix: `${RUN_ID}:`,
      now: () => Date.now(),
      activeSessionCount: async () => 0,
    });

    await pool.query(`DELETE FROM queue_entries WHERE event_id LIKE $1`, [`%${RUN_ID}%`]);

    const result = await load(
      async (index) => {
        await queue.join({ eventId: `EVT_${RUN_ID}`, sessionId: `S_${index}` });
      },
      { total: 150, concurrency: 20 },
    );

    report('queue join (advisory lock)', result, QUEUE_LIMITS);
    expect(result.errors).toBe(0);

    // The invariant the whole feature rests on: no two sessions can be handed the
    // same place in line. Duplicate positions mean the lock did not hold.
    const dupes = await pool.query(
      'SELECT position, count(*) FROM queue_entries WHERE event_id = $1 GROUP BY position HAVING count(*) > 1',
      [`EVT_${RUN_ID}`],
    );
    expect(dupes.rowCount ?? 0).toBe(0);

    const total = await pool.query('SELECT count(*)::int AS n FROM queue_entries WHERE event_id = $1', [`EVT_${RUN_ID}`]);
    expect(total.rows[0]?.n).toBe(150);

    await pool.query('DELETE FROM queue_entries WHERE event_id = $1', [`EVT_${RUN_ID}`]);
  });
});

afterAll(async () => {
  if (pool) await pool.end();
  void redis;
});
