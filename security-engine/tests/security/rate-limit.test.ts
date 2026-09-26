/**
 * Part 6 + Part 15 (scenarios 4 and 5) — distributed rate limiting.
 *
 * The assertions are about the SHARED counter, because that is the property an
 * in-memory implementation cannot provide. A test that only checks "the 11th
 * request in one process is rejected" passes against a plain object and proves
 * nothing about a distributed deployment.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import IORedis from 'ioredis';
import { ENDPOINT_POLICIES, RateLimiter, rateLimitedResponse } from '../../src/rate-limit/rate-limiter';
import { wrapIoredis, type RedisLike } from '../../src/ports/redis';
import { SecurityError } from '../../src/core/errors';

const REDIS_URL = process.env.TEST_REDIS_URL ?? 'redis://127.0.0.1:6379';
const RUN_ID = `rl${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;

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

/**
 * The two limits are deliberately different numbers, because they govern
 * different things:
 *
 *   burstLimit (10)  — bucket depth. Bounds an instantaneous spike. With the
 *                      clock frozen, that is the number of requests that can
 *                      succeed back to back.
 *   maxPerWindow(25) — sustained ceiling per 60s. Bounds total volume, and is
 *                      reached only by consuming the bucket over time.
 *
 * Every assertion below names which of the two it is exercising.
 */
const POLICY = { requestsPerSecond: 10, burstLimit: 10, windowSeconds: 60, maxPerWindow: 25 };
const BURST_CEILING = POLICY.burstLimit;
const WINDOW_CEILING = POLICY.maxPerWindow;
const subject = (over: Partial<{ ip: string; userId: string; endpoint: string; eventId: string }> = {}) => ({
  ip: over.ip ?? '203.0.113.9',
  userId: over.userId ?? 'USER_1',
  endpoint: over.endpoint ?? '/api/reservations',
  eventId: over.eventId ?? 'EVT_1',
});

describe('rate limiting (Part 6)', () => {
  let redis: RedisLike;
  let limiter: RateLimiter;
  let now = 1_700_000_000_000;

  beforeAll(async () => {
    if (!(await redisAvailable())) {
      throw new Error('Redis is required. Start it with `docker compose -f docker-compose.test.yml up -d redis`.');
    }
    const client = new IORedis(REDIS_URL, { lazyConnect: true });
    await client.connect();
    redis = wrapIoredis(client as never);
  });

  afterAll(async () => {
    await redis?.quit();
  });

  beforeEach(() => {
    // Fixed, not random: the fixed-window key is derived from the clock, and a
    // random start could land near a 60s boundary and make a test flaky for
    // reasons unrelated to the limiter.
    now = 1_700_000_000_000;
    limiter = new RateLimiter({ redis, keyPrefix: `${RUN_ID}:`, now: () => now });
  });

  it('allows an instantaneous burst up to the bucket depth, then rejects', async () => {
    const verdicts: boolean[] = [];
    for (let i = 0; i < 30; i += 1) {
      verdicts.push((await limiter.consume(subject(), POLICY, 'IP')).allowed);
    }
    // The clock is frozen, so the bucket cannot refill: burstLimit is the ceiling.
    expect(verdicts.filter(Boolean).length).toBe(BURST_CEILING);
    expect(verdicts[BURST_CEILING - 1]).toBe(true);
    expect(verdicts[BURST_CEILING]).toBe(false);
  });

  /**
   * The sustained ceiling is a separate mechanism from the burst ceiling: the
   * bucket refills, but the window keeps counting, so total volume per period is
   * capped even though instantaneous bursts are permitted.
   */
  it('enforces the per-window ceiling as the bucket refills', async () => {
    const target = subject({ ip: '10.4.4.4' });
    let allowed = 0;
    // At 10/s, 100ms refills exactly one token, so the bucket never runs dry.
    for (let i = 0; i < WINDOW_CEILING; i += 1) {
      now += 100;
      if ((await limiter.consume(target, POLICY, 'IP')).allowed) allowed += 1;
    }
    expect(allowed).toBe(WINDOW_CEILING);

    // The bucket has a token again, but the window is full.
    now += 100;
    const blocked = await limiter.consume(target, POLICY, 'IP');
    expect(blocked.allowed).toBe(false);
    expect(blocked.remaining).toBe(0);
  });

  /** Part 15 scenario 4: a large burst from one user. */
  it('caps a large burst from a single user', async () => {
    const verdicts = await Promise.all(
      Array.from({ length: 500 }, () => limiter.consume(subject({ userId: 'U_BURST' }), POLICY, 'USER')),
    );
    expect(verdicts.filter((v) => v.allowed).length).toBe(BURST_CEILING);
    expect(verdicts.filter((v) => !v.allowed).length).toBe(500 - BURST_CEILING);
  });

  /** Part 15 scenario 5: a large burst from one IP. */
  it('caps a large burst from a single IP', async () => {
    const verdicts = await Promise.all(
      Array.from({ length: 500 }, () => limiter.consume(subject({ ip: '198.51.100.7' }), POLICY, 'IP')),
    );
    expect(verdicts.filter((v) => v.allowed).length).toBe(BURST_CEILING);
  });

  /**
   * The point of distributing: the quota is shared, not per-instance.
   * Two limiters over separate "instances" must together allow only the burst
   * ceiling. With a per-process counter this would allow 2x the limit.
   */
  it('shares one quota across separate limiter instances', async () => {
    const instanceA = new RateLimiter({ redis, keyPrefix: `${RUN_ID}:`, now: () => now });
    const instanceB = new RateLimiter({ redis, keyPrefix: `${RUN_ID}:`, now: () => now });
    const target = subject({ ip: '192.0.2.55' });

    const results = await Promise.all([
      ...Array.from({ length: 20 }, () => instanceA.consume(target, POLICY, 'IP')),
      ...Array.from({ length: 20 }, () => instanceB.consume(target, POLICY, 'IP')),
    ]);

    expect(results.filter((v) => v.allowed).length).toBe(BURST_CEILING);
  });

  it('keeps different subjects independent', async () => {
    const a = await limiter.consume(subject({ ip: '10.0.0.1' }), POLICY, 'IP');
    const b = await limiter.consume(subject({ ip: '10.0.0.2' }), POLICY, 'IP');
    expect(a.allowed).toBe(true);
    expect(b.allowed).toBe(true);
  });

  /** The spec's explicit rule: shared networks must not punish everyone. */
  it('does not penalise a second user behind the same IP when keyed on USER', async () => {
    const sharedIp = subject({ ip: '203.0.113.200' });
    for (let i = 0; i < 25; i += 1) {
      await limiter.consume({ ...sharedIp, userId: 'U_FIRST' }, POLICY, 'USER');
    }
    const second = await limiter.consume({ ...sharedIp, userId: 'U_SECOND' }, POLICY, 'USER');
    expect(second.allowed).toBe(true);
  });

  it('refills over time', async () => {
    const target = subject({ ip: '10.1.1.1' });
    for (let i = 0; i < 25; i += 1) await limiter.consume(target, POLICY, 'IP');
    expect((await limiter.consume(target, POLICY, 'IP')).allowed).toBe(false);

    // Move past the fixed window; both counters roll over.
    now += 61_000;
    expect((await limiter.consume(target, POLICY, 'IP')).allowed).toBe(true);
  });

  it('reports remaining budget and a retry hint', async () => {
    const target = subject({ ip: '10.2.2.2' });
    const first = await limiter.consume(target, POLICY, 'IP');
    expect(first.available).toBe(true);
    expect(first.remaining).toBe(WINDOW_CEILING - 1);
    expect(first.retryAfterSeconds).toBe(0);

    for (let i = 0; i < BURST_CEILING; i += 1) await limiter.consume(target, POLICY, 'IP');
    const blocked = await limiter.consume(target, POLICY, 'IP');
    expect(blocked.allowed).toBe(false);
    expect(blocked.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('returns the exact 429 shape the specification requires', () => {
    const response = rateLimitedResponse({
      allowed: false,
      available: true,
      limit: 25,
      remaining: 0,
      retryAfterSeconds: 42,
      resetAt: '2026-01-01T00:00:00.000Z',
      dimension: 'IP',
      policy: 'CUSTOM',
    });
    expect(response.status).toBe(429);
    expect(response.body).toEqual({
      success: false,
      error: { code: 'RATE_LIMITED', message: 'Too many requests. Please try again.' },
    });
    expect(response.headers['Retry-After']).toBe('42');
  });

  it('orders policies from strictest to most permissive', () => {
    const strictness = (p: { requestsPerSecond: number }) => p.requestsPerSecond;
    expect(strictness(ENDPOINT_POLICIES.PAYMENT)).toBeLessThan(strictness(ENDPOINT_POLICIES.AUTH));
    expect(strictness(ENDPOINT_POLICIES.AUTH)).toBeLessThan(strictness(ENDPOINT_POLICIES.RESERVATION));
    expect(strictness(ENDPOINT_POLICIES.RESERVATION)).toBeLessThan(strictness(ENDPOINT_POLICIES.TICKET_VERIFY));
    expect(strictness(ENDPOINT_POLICIES.TICKET_VERIFY)).toBeLessThan(strictness(ENDPOINT_POLICIES.EVENT_LISTING));
    expect(strictness(ENDPOINT_POLICIES.EVENT_LISTING)).toBeLessThan(strictness(ENDPOINT_POLICIES.SEAT_AVAILABILITY));
  });

  /**
   * Fails OPEN by default — the documented asymmetry with ticket verification.
   * A Redis outage must not take down ticket sales.
   */
  it('fails open when Redis is unavailable', async () => {
    const broken = new RateLimiter({
      redis: {
        ...redis,
        eval: async () => { throw new Error('connection refused'); },
      } as RedisLike,
      keyPrefix: `${RUN_ID}:`,
      now: () => now,
    });
    const verdict = await broken.consume(subject({ ip: '10.9.9.9' }), POLICY, 'IP');
    expect(verdict.allowed).toBe(true);
    expect(verdict.available).toBe(false);
  });

  /** ...but endpoints where an unbounded burst IS the attack still block. */
  it('fails closed when the policy demands it', async () => {
    const strict = new RateLimiter({
      redis: { ...redis, eval: async () => { throw new Error('down'); } } as RedisLike,
      keyPrefix: `${RUN_ID}:`,
      now: () => now,
      failClosed: true,
    });
    await expect(strict.consume(subject({ ip: '10.9.9.10' }), POLICY, 'IP')).rejects.toThrow(SecurityError);
  });

  it('does not store raw IP addresses in key names', async () => {
    await limiter.consume(subject({ ip: '203.0.113.250' }), POLICY, 'IP');
    const keys = await redis.keys(`${RUN_ID}:*`);
    expect(keys.length).toBeGreaterThan(0);
    expect(keys.join(' ')).not.toContain('203.0.113.250');
  });
});
