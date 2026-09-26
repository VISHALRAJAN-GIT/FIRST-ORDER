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
      policyId: 'CUSTOM',
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

  /**
   * Regression: the bucket key used to be `rl:bucket:<dimension>:<identity>` with
   * no endpoint, so every endpoint a user touched shared one allowance.
   */
  describe('endpoint and policy namespacing', () => {
    const LENIENT = { requestsPerSecond: 20, burstLimit: 100, windowSeconds: 60, maxPerWindow: 600 };
    const STRICT = { requestsPerSecond: 0.2, burstLimit: 3, windowSeconds: 60, maxPerWindow: 5 };

    // Each test gets its own user so buckets cannot leak between cases; they all
    // share one Redis instance and the key deliberately contains no test id.
    const unique = (name: string) => subject({ userId: `U_NS_${name}`, ip: `198.51.100.${name.length}` });

    it('does not let a lenient endpoint drain a strict one', async () => {
      const user = unique('lenient_drain');

      // A user polling the seat map, which is the read-heavy endpoint.
      for (let i = 0; i < 100; i += 1) {
        await limiter.consume({ ...user, endpoint: '/api/seats' }, LENIENT, 'USER');
      }

      // Their first payment attempt must not be rejected for read traffic.
      const payment = await limiter.consume({ ...user, endpoint: '/api/payment' }, STRICT, 'USER');
      expect(payment.allowed).toBe(true);
      expect(payment.remaining).toBe(STRICT.maxPerWindow - 1);
    });

    it('does not let a strict endpoint throttle a lenient one', async () => {
      const user = unique('strict_drain');
      // Enough to exhaust the strict bucket three times over.
      for (let i = 0; i < 12; i += 1) {
        await limiter.consume({ ...user, endpoint: '/api/auth' }, STRICT, 'USER');
      }
      expect((await limiter.consume({ ...user, endpoint: '/api/seats' }, LENIENT, 'USER')).allowed).toBe(true);
    });

    it('keeps each endpoint at its own per-window ceiling', async () => {
      const user = unique('per_endpoint');
      // Burst deliberately larger than the window ceiling, so the fixed window is
      // the binding constraint and the counter is what is being compared.
      const windowed = { requestsPerSecond: 100, burstLimit: 50, windowSeconds: 60, maxPerWindow: 4 };

      for (let i = 0; i < 4; i += 1) {
        await limiter.consume({ ...user, endpoint: '/api/a' }, windowed, 'USER');
        await limiter.consume({ ...user, endpoint: '/api/b' }, windowed, 'USER');
      }

      // Each endpoint has independently used its own four, so both are now at
      // the ceiling, and each reports zero of its own remaining budget.
      const a = await limiter.consume({ ...user, endpoint: '/api/a' }, windowed, 'USER');
      const b = await limiter.consume({ ...user, endpoint: '/api/b' }, windowed, 'USER');
      expect(a.allowed).toBe(false);
      expect(b.allowed).toBe(false);
      expect(a.remaining).toBe(0);
      expect(b.remaining).toBe(0);

      // A third endpoint is untouched by either.
      expect((await limiter.consume({ ...user, endpoint: '/api/c' }, windowed, 'USER')).allowed).toBe(true);
    });

    it('separates two different policies on the same endpoint', async () => {
      const user = unique('same_endpoint_two_policies');
      const strictVariant = { ...STRICT, maxPerWindow: 2 };
      for (let i = 0; i < 5; i += 1) await limiter.consume({ ...user, endpoint: '/api/reservations' }, STRICT, 'USER');
      // A second, stricter variant of the same route must not inherit the
      // exhausted budget of the first, nor cancel it out.
      expect((await limiter.consume({ ...user, endpoint: '/api/reservations' }, strictVariant, 'USER')).allowed).toBe(true);
    });

    it('shares a bucket between call sites using identical custom policy numbers', async () => {
      const user = unique('shared_custom');
      // Same numbers from two different literal objects must land on one bucket,
      // otherwise swapping a function for an inline literal silently resets the
      // limiter's state.
      for (let i = 0; i < 25; i += 1) {
        await limiter.consume({ ...user, endpoint: '/api/reservations' }, { ...POLICY }, 'USER');
      }
      expect((await limiter.consume({ ...user, endpoint: '/api/reservations' }, { ...POLICY }, 'USER')).allowed).toBe(false);
    });

    it('reports the named policy on the verdict', async () => {
      const verdict = await limiter.consumeFor(unique('named'), 'PAYMENT', 'IP');
      expect(verdict.policy).toBe('PAYMENT');
      expect(verdict.policyId).toBe('PAYMENT');
      expect(verdict.limit).toBe(ENDPOINT_POLICIES.PAYMENT.maxPerWindow);
    });

    it('reports CUSTOM for an inline policy but keeps a stable id', async () => {
      const user = unique('inline');
      const verdict = await limiter.consume({ ...user, endpoint: '/api/x' }, POLICY, 'IP');
      expect(verdict.policy).toBe('CUSTOM');
      // The id is the scoping token: stable across equivalent policy objects so
      // they share a bucket, and distinct for different numbers.
      expect(verdict.policyId).toBe((await limiter.consume({ ...user, endpoint: '/api/x' }, { ...POLICY }, 'IP')).policyId);
      expect(verdict.policyId).not.toBe((await limiter.consume({ ...user, endpoint: '/api/x' }, STRICT, 'IP')).policyId);
    });

    it('does not embed the raw endpoint in the key', async () => {
      await limiter.consume(unique('opaque_endpoint'), POLICY, 'IP');
      const scoped = await limiter.consume(unique('opaque_endpoint'), POLICY, 'IP');
      expect(scoped).toBeDefined();
      expect((await redis.keys(`${RUN_ID}:*`)).join(' ')).not.toContain('reservations');
    });
  });

  it('names the window as the retry source when the window is what rejected', async () => {
    // A generous bucket with a tight per-window ceiling isolates the window path.
    const windowed = { requestsPerSecond: 100, burstLimit: 100, windowSeconds: 60, maxPerWindow: 3 };
    const target = subject({ ip: '10.3.3.3' });
    for (let i = 0; i < 4; i += 1) await limiter.consume(target, windowed, 'IP');
    const rejected = await limiter.consume(target, windowed, 'IP');
    expect(rejected.allowed).toBe(false);
    // The bucket still has credit, so the hint must come from the window, or a
    // client obeys Retry-After, comes back early, and is rejected again. It must
    // also be no longer than the window itself: the key TTL is deliberately twice
    // the window so a key cannot expire mid-window, and reporting that would make
    // every client wait twice as long as it needs to.
    expect(rejected.retryAfterSeconds).toBeGreaterThan(0);
    expect(rejected.retryAfterSeconds).toBeLessThanOrEqual(60);
  });
});
