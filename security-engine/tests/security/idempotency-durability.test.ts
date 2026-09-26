/**
 * Part 5 — durability and completion-race regressions.
 *
 * These exist because the original implementation had two defects that the
 * existing 13 tests did not reach, both of which could duplicate a real booking:
 *
 *  1. `claim` consulted only Redis, so once the coordination key's TTL expired a
 *     duplicate re-executed even though Postgres still held the SUCCESS record —
 *     contradicting the store's own documented contract.
 *  2. `complete` had no fencing token, so an owner that overran its claim TTL
 *     could record a result against a claim a retry had already taken over.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import IORedis from 'ioredis';
import {
  RedisIdempotencyStore,
  fingerprintRequest,
  type IdempotencyRecord,
} from '../../src/ports/idempotency-store';
import { wrapIoredis, type RedisLike } from '../../src/ports/redis';

const REDIS_URL = process.env.TEST_REDIS_URL ?? 'redis://127.0.0.1:6379';
const RUN_ID = `idm${Date.now().toString(36)}`;
const ENDPOINT = 'POST /api/bookings';

describe('idempotency durability (Part 5)', () => {
  let redis: RedisLike;
  let raw: IORedis;
  /** Stand-in for the Postgres mirror; a Map models the contract exactly. */
  let durableStore = new Map<string, IdempotencyRecord>();
  let nowIso = '2026-01-01T00:00:00.000Z';

  beforeAll(async () => {
    raw = new IORedis(REDIS_URL, { lazyConnect: true });
    await raw.connect();
    redis = wrapIoredis(raw as never);
  });

  afterAll(async () => {
    await raw.quit();
  });

  afterEach(async () => {
    const keys = await redis.keys(`${RUN_ID}:*`);
    for (const key of keys) await redis.delete(key);
    durableStore = new Map();
    nowIso = '2026-01-01T00:00:00.000Z';
  });

  const store = () =>
    new RedisIdempotencyStore({
      redis,
      keyPrefix: `${RUN_ID}:`,
      durable: {
        get: async (key, endpoint) => durableStore.get(`${endpoint}:${key}`) ?? null,
        upsert: async (record) => {
          durableStore.set(`${record.endpoint}:${record.key}`, record);
        },
      },
      nowIso: () => nowIso,
    });

  const hash = fingerprintRequest({ method: 'POST', path: '/api/bookings', body: { seatId: 'A1' } });
  const claimArgs = (requestHash = hash) => ({ key: 'k1', endpoint: ENDPOINT, requestHash, ttlSeconds: 300 });

  /** Expire the coordination key, leaving only the durable record. */
  const expireRedis = async () => {
    for (const key of await redis.keys(`${RUN_ID}:*`)) await redis.delete(key);
  };

  it('executes once, then replays, on the happy path', async () => {
    const s = store();
    const claim = await s.claim(claimArgs());
    expect(claim.claimed).toBe(true);
    if (!claim.claimed) throw new Error('expected to win the claim');

    await s.complete({ ...claimArgs(), claimId: claim.claimId, state: 'SUCCESS', response: { status: 201, body: { id: 'B1' } } });

    const replay = await s.claim(claimArgs());
    expect(replay.claimed).toBe(false);
    if (!replay.claimed && !replay.inFlight && !replay.conflict) {
      expect(replay.record?.response?.body).toEqual({ id: 'B1' });
    }
  });

  /**
   * THE REGRESSION. The coordination key expires, the durable record does not.
   * The duplicate must replay, not execute a second time.
   */
  it('replays from the durable record after the Redis key expires', async () => {
    const s = store();
    const claim = await s.claim(claimArgs());
    if (!claim.claimed) throw new Error('expected to win the claim');
    await s.complete({ ...claimArgs(), claimId: claim.claimId, state: 'SUCCESS', response: { status: 201, body: { id: 'B1' } } });

    await expireRedis();

    const afterExpiry = await s.claim(claimArgs());
    expect(afterExpiry.claimed).toBe(false);
    if (!afterExpiry.claimed && !afterExpiry.inFlight && !afterExpiry.conflict) {
      expect(afterExpiry.record?.state).toBe('SUCCESS');
      expect(afterExpiry.record?.response?.body).toEqual({ id: 'B1' });
    }
  });

  it('reports a conflict for a different request after expiry', async () => {
    const s = store();
    const claim = await s.claim(claimArgs());
    if (!claim.claimed) throw new Error('expected to win the claim');
    await s.complete({ ...claimArgs(), claimId: claim.claimId, state: 'SUCCESS', response: { status: 201, body: {} } });
    await expireRedis();

    const otherHash = fingerprintRequest({ method: 'POST', path: '/api/bookings', body: { seatId: 'ATTACKER_CHOICE' } });
    expect(await s.claim(claimArgs(otherHash))).toEqual({ claimed: false, inFlight: false, conflict: true });
  });

  it('leaves no speculative claim behind when it replays from the mirror', async () => {
    const s = store();
    const claim = await s.claim(claimArgs());
    if (!claim.claimed) throw new Error('expected to win the claim');
    await s.complete({ ...claimArgs(), claimId: claim.claimId, state: 'SUCCESS', response: { status: 201, body: {} } });
    await expireRedis();

    await s.claim(claimArgs());

    // A PROCESSING envelope left on top of the durable result would make the next
    // caller believe the operation is in flight forever.
    expect(await redis.get(`${RUN_ID}:idem:${ENDPOINT}:k1`)).toBeNull();
  });

  it('reads through to the durable record when Redis is empty', async () => {
    const s = store();
    const claim = await s.claim(claimArgs());
    if (!claim.claimed) throw new Error('expected to claim');
    await s.complete({ ...claimArgs(), claimId: claim.claimId, state: 'SUCCESS', response: { status: 201, body: { id: 'B1' } } });
    await expireRedis();

    const record = await s.get('k1', ENDPOINT);
    expect(record?.state).toBe('SUCCESS');
    expect(record?.response?.body).toEqual({ id: 'B1' });
  });

  it('records a truthful createdAt rather than the completion time', async () => {
    const s = store();
    nowIso = '2026-01-01T00:00:00.000Z';
    const claim = await s.claim(claimArgs());
    if (!claim.claimed) throw new Error('expected to claim');
    nowIso = '2026-01-01T00:05:00.000Z';
    await s.complete({ ...claimArgs(), claimId: claim.claimId, state: 'SUCCESS', response: { status: 201, body: {} } });

    const record = await s.get('k1', ENDPOINT);
    expect(record?.createdAt).toBe('2026-01-01T00:00:00.000Z');
    expect(record?.completedAt).toBe('2026-01-01T00:05:00.000Z');
  });

  /**
   * THE SECOND REGRESSION. An owner that overran its TTL completes after a retry
   * has re-claimed the same key with the same request hash. The fencing token
   * must stop the stale owner from recording anything.
   */
  it('does not let a stale completion clobber a re-claim', async () => {
    const s = store();
    const original = await s.claim(claimArgs());
    if (!original.claimed) throw new Error('expected to claim');

    // The original owner stalls past its TTL and the key disappears.
    await redis.delete(`${RUN_ID}:idem:${ENDPOINT}:k1`);

    // A retry legitimately re-claims with the same request.
    const retry = await s.claim(claimArgs());
    expect(retry.claimed).toBe(true);
    if (!retry.claimed) throw new Error('expected the retry to claim');
    expect(retry.claimId).not.toBe(original.claimId);

    // The original owner now finishes and tries to record its result.
    await s.complete({
      ...claimArgs(),
      claimId: original.claimId,
      state: 'SUCCESS',
      response: { status: 201, body: { id: 'STALE' } },
    });

    // The retry's in-flight state must survive: it is still executing, and a
    // duplicate arriving now must be told the operation is in flight rather than
    // handed a result for work that has not finished.
    expect(await s.claim(claimArgs())).toEqual({ claimed: false, inFlight: true });
  });

  it('does not let a stale failure clobber a re-claim either', async () => {
    const s = store();
    const original = await s.claim(claimArgs());
    if (!original.claimed) throw new Error('expected to claim');
    await redis.delete(`${RUN_ID}:idem:${ENDPOINT}:k1`);

    const retry = await s.claim(claimArgs());
    if (!retry.claimed) throw new Error('expected the retry to claim');

    await s.complete({
      ...claimArgs(),
      claimId: original.claimId,
      state: 'FAILED',
      response: { status: 500, body: { error: 'stale' } },
    });

    expect(await s.claim(claimArgs())).toEqual({ claimed: false, inFlight: true });
  });

  it('still completes normally when nobody raced it', async () => {
    const s = store();
    const claim = await s.claim(claimArgs());
    if (!claim.claimed) throw new Error('expected to claim');
    await s.complete({ ...claimArgs(), claimId: claim.claimId, state: 'SUCCESS', response: { status: 201, body: { id: 'B1' } } });
    expect((await s.get('k1', ENDPOINT))?.state).toBe('SUCCESS');
  });

  it('persists a FAILED result so the same key cannot be retried', async () => {
    const s = store();
    const claim = await s.claim(claimArgs());
    if (!claim.claimed) throw new Error('expected to claim');
    await s.complete({ ...claimArgs(), claimId: claim.claimId, state: 'FAILED', response: { status: 402, body: { declined: true } } });
    await expireRedis();

    const afterExpiry = await s.claim(claimArgs());
    expect(afterExpiry.claimed).toBe(false);
    if (!afterExpiry.claimed && !afterExpiry.inFlight && !afterExpiry.conflict) {
      // A failed payment may still have charged the card, so it must not re-run.
      expect(afterExpiry.record?.state).toBe('FAILED');
    }
  });

  it('keeps endpoints isolated', async () => {
    const s = store();
    await s.claim(claimArgs());
    const other = await s.claim({ key: 'k1', endpoint: 'POST /api/cancellations', requestHash: hash, ttlSeconds: 300 });
    expect(other.claimed).toBe(true);
  });

  it('issues a distinct claim token per claim', async () => {
    const s = store();
    const a = await s.claim({ key: 'a', endpoint: ENDPOINT, requestHash: hash, ttlSeconds: 300 });
    const b = await s.claim({ key: 'b', endpoint: ENDPOINT, requestHash: hash, ttlSeconds: 300 });
    if (!a.claimed || !b.claimed) throw new Error('expected both to claim');
    expect(a.claimId).not.toBe(b.claimId);
  });

  it('works with no durable mirror configured', async () => {
    const s = new RedisIdempotencyStore({ redis, keyPrefix: `${RUN_ID}:`, nowIso: () => nowIso });
    const claim = await s.claim(claimArgs());
    if (!claim.claimed) throw new Error('expected to claim');
    await s.complete({ ...claimArgs(), claimId: claim.claimId, state: 'SUCCESS', response: { status: 201, body: {} } });
    expect((await s.get('k1', ENDPOINT))?.state).toBe('SUCCESS');
  });
});
