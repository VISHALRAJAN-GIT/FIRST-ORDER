/**
 * Proves the Redis port's atomicity claims against a real Redis.
 *
 * Every one of these operations is a read-modify-write. Each can be implemented
 * as two client round trips that are correct when calls are sequential and wrong
 * when they are not — and the in-memory double cannot reproduce that, because it
 * has no interleaving. So the assertions here are about concurrency, not values.
 */

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import IORedis from 'ioredis';
import { wrapIoredis, type RedisLike } from '../../src/ports/redis';

const REDIS_URL = process.env.TEST_REDIS_URL ?? 'redis://127.0.0.1:6379';

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

describe('redis atomicity (real Redis)', () => {
  let redis: RedisLike;

  beforeAll(async () => {
    if (!(await redisAvailable())) {
      throw new Error(
        'Redis is required. Start it with `docker compose -f docker-compose.test.yml up -d redis` and re-run.',
      );
    }
    const client = new IORedis(REDIS_URL, { keyPrefix: 'sec-test:', lazyConnect: true });
    await client.connect();
    redis = wrapIoredis(client as never);
  });

  afterAll(async () => {
    await redis?.quit();
  });

  /**
   * The regression test for the non-atomic `GET` + `SET` implementation.
   *
   * 100 callers each try to move PROCESSING -> their own unique value. Exactly
   * one may win. A non-atomic compareAndSet lets several callers read PROCESSING
   * before any of them writes, and every one of them then returns true.
   */
  it('lets exactly one of 100 concurrent compareAndSet calls win', async () => {
    const key = 'cas:contended';
    await redis.set(key, 'PROCESSING', 30);

    const results = await Promise.all(
      Array.from({ length: 100 }, (_unused, index) => redis.compareAndSet(key, 'PROCESSING', `WON_${index}`, 30)),
    );

    expect(results.filter(Boolean)).toHaveLength(1);
    const final = await redis.get(key);
    expect(final).toMatch(/^WON_\d+$/);
  });

  it('rejects a compareAndSet whose expectation does not hold', async () => {
    const key = 'cas:wrong-expected';
    await redis.set(key, 'A', 30);
    expect(await redis.compareAndSet(key, 'B', 'C', 30)).toBe(false);
    expect(await redis.get(key)).toBe('A');
  });

  it('does not create a key that does not exist', async () => {
    const key = 'cas:absent';
    await redis.delete(key);
    expect(await redis.compareAndSet(key, 'anything', 'next', 30)).toBe(false);
    expect(await redis.exists(key)).toBe(false);
  });

  /** Concurrent increments must not lose updates. */
  it('does not lose updates across 200 concurrent increments', async () => {
    const key = 'incr:contended';
    await redis.delete(key);
    const results = await Promise.all(Array.from({ length: 200 }, () => redis.increment(key, 30)));
    expect(Math.max(...results)).toBe(200);
    expect(await redis.get(key)).toBe('200');
  });

  /** The TTL is set on creation and must not be reset by later increments. */
  it('sets a TTL on creation and preserves it across increments', async () => {
    const key = 'incr:ttl';
    await redis.delete(key);
    await redis.increment(key, 45);
    const first = await redis.ttl(key);
    expect(first).toBeGreaterThan(0);
    expect(first).toBeLessThanOrEqual(45);

    await new Promise((resolve) => setTimeout(resolve, 1_100));
    await redis.increment(key, 45);
    const second = await redis.ttl(key);
    // A reset would put this back near 45.
    expect(second).toBeLessThanOrEqual(first - 1);
  });

  /** SADD + EXPIRE must not lose members or skip the window. */
  it('adds all members and applies the window under concurrency', async () => {
    const key = 'set:concurrent';
    await redis.delete(key);
    const batches = Array.from({ length: 20 }, (_unused, i) => [`m${i}a`, `m${i}b`, `m${i}c`]);
    await Promise.all(batches.map((members) => redis.addToSet(key, members, 30)));
    expect(await redis.setCardinality(key)).toBe(60);
    expect(await redis.ttl(key)).toBeGreaterThan(0);
  });

  /** The primitive idempotency and queue admission depend on. */
  it('setIfAbsent creates a key exactly once under contention', async () => {
    const key = 'setnx:contended';
    await redis.delete(key);
    const results = await Promise.all(
      Array.from({ length: 50 }, (_unused, index) => redis.setIfAbsent(key, `owner_${index}`, 30)),
    );
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await redis.get(key)).toMatch(/^owner_\d+$/);
  });
});
