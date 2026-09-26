/**
 * Part 8 + Part 15 (scenario 6) — virtual queue.
 *
 * The race that matters is promotion: sweepers and redeemers interleaving, and
 * the same place being admitted twice. These tests run against real Postgres
 * because the guarantee is `FOR UPDATE SKIP LOCKED` plus a unique index, neither
 * of which an in-memory double can reproduce.
 */

import type { Pool } from 'pg';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import IORedis from 'ioredis';
import { AdmissionTokenCodec, PostgresQueueStore, VirtualQueue } from '../../src/queue/virtual-queue';
import { wrapIoredis, type RedisLike } from '../../src/ports/redis';
import { SecurityError } from '../../src/core/errors';
import { createPool, isPostgresAvailable } from '../helpers/postgres';

const REDIS_URL = process.env.TEST_REDIS_URL ?? 'redis://127.0.0.1:6379';
const RUN_ID = `q${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
const SECRET = 'a'.repeat(48);
const EVENT = 'EVT_HOT';

async function redisAvailable(): Promise<boolean> {
  try {
    const probe = new IORedis(REDIS_URL, { lazyConnect: true, connectTimeout: 1_000, maxRetriesPerRequest: 1 });
    await probe.connect();
    await probe.ping();
    await probe.quit();
    return true;
  } catch {
    return false;
  }
}

describe('virtual queue (Part 8)', () => {
  let pool: Pool;
  let redis: RedisLike;
  let store: PostgresQueueStore;
  let now = 1_700_000_000_000;

  beforeAll(async () => {
    if (!(await isPostgresAvailable())) throw new Error('Postgres is required for the queue suite.');
    if (!(await redisAvailable())) throw new Error('Redis is required for the queue suite.');
    pool = await createPool();
    const client = new IORedis(REDIS_URL, { lazyConnect: true });
    await client.connect();
    redis = wrapIoredis(client as never);
  });

  afterAll(async () => {
    await pool?.query('TRUNCATE queue_entries').catch(() => undefined);
    await pool?.end();
    await redis?.quit();
  });

  beforeEach(async () => {
    await pool.query('TRUNCATE queue_entries');
    now = 1_700_000_000_000;
    store = new PostgresQueueStore(pool);
  });

  afterEach(async () => {
    const keys = await redis.keys(`${RUN_ID}:*`);
    if (keys.length > 0) await redis.delete(keys[0]!);
  });

  const makeQueue = (overrides: Partial<{ admissionRate: number; activationThreshold: number }> = {}) =>
    new VirtualQueue({
      store,
      codec: new AdmissionTokenCodec(SECRET, 120),
      redis,
      keyPrefix: `${RUN_ID}:`,
      now: () => now,
      policy: {
        activationThreshold: overrides.activationThreshold ?? 10,
        admissionRate: overrides.admissionRate ?? 5,
        admissionWindowSeconds: 10,
        tokenTtlSeconds: 120,
        queueTtlSeconds: 900,
      },
      activeSessionCount: async () => 1_000,
    });

  it('assigns strictly increasing, unique positions to concurrent joiners', async () => {
    // 30 simultaneous joins. MAX(position)+1 without a lock would hand several
    // of them the same number.
    const results = await Promise.all(
      Array.from({ length: 30 }, (_u, i) => store.join({ eventId: EVENT, sessionId: `S_${i}` })),
    );
    const positions = results.map((r) => r.entry.position).sort((a, b) => a - b);
    expect(new Set(positions).size).toBe(30);
    expect(positions[0]).toBe(1);
    expect(positions[29]).toBe(30);
  });

  it('is idempotent when the same session joins repeatedly', async () => {
    const first = await store.join({ eventId: EVENT, sessionId: 'S_SAME' });
    for (let i = 0; i < 20; i += 1) {
      const again = await store.join({ eventId: EVENT, sessionId: 'S_SAME' });
      expect(again.status).toBe('ALREADY_QUEUED');
      expect(again.entry.position).toBe(first.entry.position);
    }
    expect(await store.size(EVENT)).toBe(1);
  });

  it('returns the spec QUEUED response shape', async () => {
    const queue = makeQueue();
    const joined = await queue.join({ eventId: EVENT, sessionId: 'S_1' });
    expect(joined.status).toBe('QUEUED');
    expect(typeof joined.queueId).toBe('string');
    expect(joined.position).toBeGreaterThan(0);
  });

  /**
   * Part 15 scenario 6: the queue admission race.
   *
   * Six sweepers race to promote from a queue of 40 with a rate of 5. The
   * invariant is that the union of promoted entries contains no duplicates and
   * nobody is skipped into a second admission.
   */
  it('never promotes the same entry twice under concurrent sweepers', async () => {
    for (let i = 0; i < 40; i += 1) await store.join({ eventId: EVENT, sessionId: `S_${i}` });
    const queue = makeQueue({ admissionRate: 5 });

    const batches = await Promise.all(
      Array.from({ length: 6 }, () => queue.admitNext(EVENT, 5)),
    );

    const tokens = batches.flat();
    const queueIds = tokens.map((t) => t.queueId);
    expect(new Set(queueIds).size).toBe(tokens.length);

    // The rate limiter means the first sweepers get the whole allowance.
    expect(tokens.length).toBe(5);
    expect(tokens.length).toBeLessThanOrEqual(5);

    const stillWaiting = await store.size(EVENT);
    expect(stillWaiting).toBe(35);
  });

  /** Sweepers must be able to keep admitting as the bucket refills. */
  it('admits further batches as the rate bucket refills', async () => {
    for (let i = 0; i < 40; i += 1) await store.join({ eventId: EVENT, sessionId: `S_${i}` });
    const queue = makeQueue({ admissionRate: 5 });

    expect((await queue.admitNext(EVENT, 5)).length).toBe(5);
    expect((await queue.admitNext(EVENT, 5)).length).toBe(0);

    // 5 per 10s = 0.5/s. Advancing 10s refills the whole bucket.
    now += 10_000;
    expect((await queue.admitNext(EVENT, 5)).length).toBe(5);
    expect(await store.size(EVENT)).toBe(30);
  });

  it('promotes in position order, so the front of the queue goes first', async () => {
    const joined = [];
    for (let i = 0; i < 10; i += 1) joined.push((await store.join({ eventId: EVENT, sessionId: `S_${i}` })).entry);
    const queue = makeQueue({ admissionRate: 3 });
    const tokens = await queue.admitNext(EVENT, 3);
    expect(tokens.map((t) => t.position).sort((a, b) => a - b)).toEqual([1, 2, 3]);
    expect(tokens[0]!.sessionId).toBe(joined[0]!.sessionId);
  });

  /** A token is the only thing that opens the protected route. */
  it('rejects a request with no admission token', () => {
    const queue = makeQueue();
    expect(() => queue.assertAdmitted(null, { eventId: EVENT, sessionId: 'S_1' })).toThrow(SecurityError);
  });

  it('rejects a forged token', async () => {
    const queue = makeQueue();
    const entry = (await store.join({ eventId: EVENT, sessionId: 'S_1' })).entry;
    const token = new AdmissionTokenCodec(SECRET, 120).issue(entry, now);
    const forged = { ...token, signature: 'x'.repeat(token.signature.length) };
    expect(() => queue.assertAdmitted(forged, { eventId: EVENT, sessionId: 'S_1' })).toThrow(SecurityError);
  });

  /** A token minted with a different secret must not verify. */
  it('rejects a token signed with a different secret', async () => {
    const entry = (await store.join({ eventId: EVENT, sessionId: 'S_1' })).entry;
    const foreign = new AdmissionTokenCodec('b'.repeat(48), 120).issue(entry, now);
    const queue = makeQueue();
    expect(() => queue.assertAdmitted(foreign, { eventId: EVENT, sessionId: 'S_1' })).toThrow(SecurityError);
  });

  /** A real token replayed against a different event must fail. */
  it('rejects a valid token presented at the wrong event', async () => {
    await store.join({ eventId: EVENT, sessionId: 'S_1' });
    const token = new AdmissionTokenCodec(SECRET, 120).issue(
      (await store.join({ eventId: EVENT, sessionId: 'S_1' })).entry,
      now,
    );
    const queue = makeQueue();
    expect(() => queue.assertAdmitted(token, { eventId: 'EVT_OTHER', sessionId: 'S_1' })).toThrow(SecurityError);
  });

  /** A token shared to another session must fail, or admission is transferable. */
  it('rejects a token presented by a different session', async () => {
    const entry = (await store.join({ eventId: EVENT, sessionId: 'S_OWNER' })).entry;
    const token = new AdmissionTokenCodec(SECRET, 120).issue(entry, now);
    const queue = makeQueue();
    expect(() => queue.assertAdmitted(token, { eventId: EVENT, sessionId: 'S_THIEF' })).toThrow(SecurityError);
  });

  it('expires tokens', async () => {
    const entry = (await store.join({ eventId: EVENT, sessionId: 'S_1' })).entry;
    const token = new AdmissionTokenCodec(SECRET, 60).issue(entry, now);
    const queue = makeQueue();
    expect(() => queue.assertAdmitted(token, { eventId: EVENT, sessionId: 'S_1' })).not.toThrow();
    now += 61_000;
    expect(() => queue.assertAdmitted(token, { eventId: EVENT, sessionId: 'S_1' })).toThrow(SecurityError);
  });

  it('refuses to construct a codec with a weak secret', () => {
    expect(() => new AdmissionTokenCodec('short', 60)).toThrow();
  });

  it('reports status and an informational wait estimate', async () => {
    for (let i = 0; i < 20; i += 1) await store.join({ eventId: EVENT, sessionId: `S_${i}` });
    const queue = makeQueue({ admissionRate: 5 });
    const status = await queue.status(EVENT, 'S_10');
    expect(status.active).toBe(true);
    expect(status.ahead).toBe(10);
    expect(status.size).toBe(20);
    expect(status.estimatedWaitSeconds).toBeGreaterThan(0);
  });

  it('does not activate a queue for a quiet event', async () => {
    const quiet = new VirtualQueue({
      store,
      codec: new AdmissionTokenCodec(SECRET, 120),
      redis,
      keyPrefix: `${RUN_ID}:`,
      now: () => now,
      policy: { activationThreshold: 10, admissionRate: 5, admissionWindowSeconds: 10, tokenTtlSeconds: 120, queueTtlSeconds: 900 },
      activeSessionCount: async () => 2,
    });
    expect(await quiet.isQueueActive('EVT_QUIET')).toBe(false);
  });

  it('removes a session that leaves', async () => {
    await store.join({ eventId: EVENT, sessionId: 'S_1' });
    expect(await store.markLeft(EVENT, 'S_1')).toBe(true);
    expect(await store.size(EVENT)).toBe(0);
  });

  it('keeps events isolated', async () => {
    await store.join({ eventId: 'EVT_A', sessionId: 'S_1' });
    await store.join({ eventId: 'EVT_B', sessionId: 'S_1' });
    expect(await store.size('EVT_A')).toBe(1);
    expect(await store.size('EVT_B')).toBe(1);
  });
});
