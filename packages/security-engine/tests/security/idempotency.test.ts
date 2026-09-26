/**
 * Part 5 + Part 15 (scenarios 2 and 3) — idempotency.
 *
 * The central assertion throughout: the handler runs AT MOST ONCE per key. Every
 * other property — replaying responses, 409s, conflict detection — is downstream
 * of that.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import IORedis from 'ioredis';
import {
  IdempotencyGuard,
  validateIdempotencyKey,
  type IdempotencyOutcome,
} from '../../src/idempotency/idempotency-guard';
import { RedisIdempotencyStore, fingerprintRequest, type IdempotentResponse } from '../../src/ports/idempotency-store';
import { wrapIoredis, type RedisLike } from '../../src/ports/redis';
import { SecurityError } from '../../src/core/errors';

/** Narrows a replay outcome so the test can assert on the stored response. */
function replayed(outcome: IdempotencyOutcome): IdempotentResponse {
  if (outcome.kind !== 'REPLAYED') throw new Error(`expected REPLAYED, received ${outcome.kind}`);
  return outcome.response;
}

const REDIS_URL = process.env.TEST_REDIS_URL ?? 'redis://127.0.0.1:6379';
const ENDPOINT = '/api/bookings';

/**
 * A fresh namespace per run. Idempotency records are meant to survive for hours,
 * so reusing fixed keys across runs would make every test replay a result left
 * behind by the previous run — the suite would pass while testing nothing.
 */
const RUN_ID = `run${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;

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

describe('idempotency (Part 5)', () => {
  let redis: RedisLike;
  let store: RedisIdempotencyStore;
  let guard: IdempotencyGuard;
  let handlerCalls: number;

  beforeAll(async () => {
    if (!(await redisAvailable())) {
      throw new Error('Redis is required. Start it with `docker compose -f docker-compose.test.yml up -d redis`.');
    }
    const client = new IORedis(REDIS_URL, { keyPrefix: 'sec-idem-test:', lazyConnect: true });
    await client.connect();
    redis = wrapIoredis(client as never);
  });

  afterAll(async () => {
    await redis?.quit();
  });

  beforeEach(async () => {
    handlerCalls = 0;
    store = new RedisIdempotencyStore({
      redis,
      keyPrefix: `${RUN_ID}:`,
      nowIso: () => new Date().toISOString(),
    });
    guard = new IdempotencyGuard(store, { ttlSeconds: 60, requiredFor: [ENDPOINT] });
  });

  const okHandler = async () => {
    handlerCalls += 1;
    return { status: 201, body: { success: true, bookingId: 'BKG_1' } };
  };

  const ctx = (key: string | undefined, body: unknown = { eventId: 'EVT_1', seatId: 'A1' }) => ({
    method: 'POST',
    path: ENDPOINT,
    idempotencyKey: key,
    body,
  });

  it('executes once and replays the original response for a retry', async () => {
    const first = await guard.execute(ctx('retry-key-0001'), okHandler);
    const second = await guard.execute(ctx('retry-key-0001'), okHandler);

    expect(first.kind).toBe('EXECUTED');
    expect(second.kind).toBe('REPLAYED');
    expect(handlerCalls).toBe(1);
    expect(replayed(second)).toEqual((first as { response: IdempotentResponse }).response);
    expect(replayed(second).status).toBe(201);
  });

  /**
   * Part 15 scenario 3: the same idempotency key sent simultaneously.
   *
   * 40 concurrent requests, one key. Exactly one may reach the handler. This is
   * the case a "check then insert" implementation fails: every caller would see
   * no record and every caller would book.
   */
  it('runs the handler exactly once for 40 concurrent requests sharing a key', async () => {
    const outcomes = await Promise.all(
      Array.from({ length: 40 }, () => guard.execute(ctx('concurrent-key-01'), okHandler)),
    );

    expect(handlerCalls).toBe(1);
    expect(outcomes.filter((o) => o.kind === 'EXECUTED')).toHaveLength(1);
    expect(outcomes.filter((o) => o.kind === 'IN_FLIGHT')).toHaveLength(39);
  });

  /** Part 15 scenario 2: the same booking request sent simultaneously. */
  it('creates one booking when the same request arrives 25 times at once', async () => {
    const outcomes = await Promise.all(
      Array.from({ length: 25 }, () => guard.execute(ctx('same-booking-01'), okHandler)),
    );
    expect(handlerCalls).toBe(1);
    expect(outcomes.filter((o) => o.kind === 'EXECUTED')).toHaveLength(1);
  });

  /** Distinct keys are distinct operations and must not interfere. */
  it('executes independently for distinct keys', async () => {
    const outcomes = await Promise.all(
      Array.from({ length: 20 }, (_u, i) => guard.execute(ctx(`unique-key-${String(i).padStart(4, '0')}`), okHandler)),
    );
    expect(handlerCalls).toBe(20);
    expect(outcomes.every((o) => o.kind === 'EXECUTED')).toBe(true);
  });

  /** Same key, different body: a client bug, and neither replay nor execute is safe. */
  it('flags a conflict when the same key is reused for a different body', async () => {
    await guard.execute(ctx('conflict-key-01', { seatId: 'A1' }), okHandler);
    const outcome = await guard.execute(ctx('conflict-key-01', { seatId: 'B2' }), okHandler);

    expect(outcome.kind).toBe('CONFLICT');
    expect(handlerCalls).toBe(1);
  });

  /** The fingerprint must not be fooled by key ordering. */
  it('produces a stable fingerprint regardless of key order', () => {
    const a = fingerprintRequest({ method: 'post', path: ENDPOINT, body: { x: 1, y: 2 } });
    const b = fingerprintRequest({ method: 'POST', path: ENDPOINT, body: { y: 2, x: 1 } });
    expect(a).toBe(b);
  });

  it('distinguishes different users using the same key', () => {
    const a = fingerprintRequest({ method: 'POST', path: ENDPOINT, body: { seatId: 'A1' }, authenticatedUserId: 'U1' });
    const b = fingerprintRequest({ method: 'POST', path: ENDPOINT, body: { seatId: 'A1' }, authenticatedUserId: 'U2' });
    expect(a).not.toBe(b);
  });

  it('requires a key on protected endpoints', async () => {
    await expect(guard.execute(ctx(undefined), okHandler)).rejects.toThrow(SecurityError);
    expect(handlerCalls).toBe(0);
  });

  it('allows a missing key on unprotected endpoints', async () => {
    const lenient = new IdempotencyGuard(store, { ttlSeconds: 60, requiredFor: ['/api/other'] });
    const outcome = await lenient.execute(ctx(undefined), okHandler);
    expect(outcome.kind).toBe('EXECUTED');
  });

  it('rejects malformed keys instead of normalising them', async () => {
    expect(validateIdempotencyKey('short')).toBe(false);
    expect(validateIdempotencyKey('has spaces in it here')).toBe(false);
    expect(validateIdempotencyKey('a'.repeat(300))).toBe(false);
    expect(validateIdempotencyKey('valid-key-123')).toBe(true);

    await expect(guard.execute(ctx('bad key'), okHandler)).rejects.toThrow(SecurityError);
    expect(handlerCalls).toBe(0);
  });

  /**
   * A handler that throws must not leave the key permanently stuck, but the
   * failure also must not be re-executed under the same key.
   */
  it('records a failure and replays it instead of re-running the handler', async () => {
    let attempts = 0;
    const failing = async () => {
      attempts += 1;
      throw new SecurityError('VALIDATION_FAILED', 'card declined');
    };

    await expect(guard.execute(ctx('failed-key-0001'), failing)).rejects.toThrow(SecurityError);
    const second = await guard.execute(ctx('failed-key-0001'), failing);

    expect(attempts).toBe(1);
    expect(second.kind).toBe('REPLAYED');
    expect(replayed(second).status).toBe(400);
  });

  /** The record must expire, or a key would block its endpoint forever. */
  it('applies a TTL to the claim so a key eventually expires', async () => {
    const shortTtl = new IdempotencyGuard(
      new RedisIdempotencyStore({ redis, keyPrefix: `${RUN_ID}:ttl:`, nowIso: () => new Date().toISOString() }),
      { ttlSeconds: 2, requiredFor: [] },
    );
    await shortTtl.execute(ctx('ttl-key-000001'), okHandler);
    const ttl = await redis.ttl(`${RUN_ID}:ttl:idem:${ENDPOINT}:ttl-key-000001`);
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(2);
  });

  /** The same key on two different endpoints must not collide. */
  it('scopes keys per endpoint', async () => {
    await guard.execute(ctx('shared-key-0001'), okHandler);
    const other = await guard.execute(
      { method: 'POST', path: '/api/payments', idempotencyKey: 'shared-key-0001', body: { amount: 100 } },
      okHandler,
    );
    expect(other.kind).toBe('EXECUTED');
    expect(handlerCalls).toBe(2);
  });
});
