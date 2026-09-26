/**
 * Part 7 — challenge redemption, against real Redis.
 *
 * The properties under test are the ones that decide whether a challenge is a
 * defence or an outage, so they are tested against the real store rather than a
 * mock: single-use atomicity, subject binding, expiry, and the fact that the
 * plaintext token is never at rest.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import IORedis from 'ioredis';
import { ChallengeStore } from '../../src/bot-protection/challenge';
import { wrapIoredis, type RedisLike } from '../../src/ports/redis';

const REDIS_URL = process.env.TEST_REDIS_URL ?? 'redis://127.0.0.1:6379';
const RUN_ID = `chl${Date.now().toString(36)}`;

describe('ChallengeStore (Part 7 redemption)', () => {
  let raw: IORedis;
  let redis: RedisLike;
  let store: ChallengeStore;
  let now = Date.parse('2026-06-01T12:00:00.000Z');

  beforeAll(async () => {
    raw = new IORedis(REDIS_URL, { lazyConnect: true });
    await raw.connect();
    redis = wrapIoredis(raw as never);
  });

  afterAll(async () => {
    await raw?.quit();
  });

  afterEach(async () => {
    for (const key of await redis.keys(`${RUN_ID}:*`)) await redis.delete(key);
    now = Date.parse('2026-06-01T12:00:00.000Z');
  });

  const build = (overrides: { tokenBytes?: number; defaultTtlSeconds?: number } = {}) =>
    new ChallengeStore({ redis, keyPrefix: `${RUN_ID}:`, now: () => now, ...overrides });

  const buyer = { userId: 'U_BUYER', sessionId: 'S_BUYER', ip: '203.0.113.10' };
  const stranger = { userId: 'U_OTHER', sessionId: 'S_OTHER', ip: '203.0.113.99' };

  describe('issuance', () => {
    it('issues a token that can be redeemed', async () => {
      store = build();
      const issued = await store.issue(buyer);
      expect(issued.token).toMatch(/^chl_/);
      expect(issued.ttlSeconds).toBe(300);
      expect(Date.parse(issued.expiresAt)).toBe(now + 300_000);
      expect(await store.verify(issued.token, buyer)).toMatchObject({ valid: true });
    });

    it('never stores the plaintext token', async () => {
      store = build();
      const issued = await store.issue(buyer);
      // A Redis dump, a slow query log or a KEYS listing must not yield
      // redeemable tokens: Redis holds every live challenge in one place at once.
      const everything = (await redis.keys(`${RUN_ID}:*`)).join(' ');
      expect(everything).not.toContain(issued.token);
      const values = await Promise.all(
        (await redis.keys(`${RUN_ID}:*`)).map((key) => redis.get(key)),
      );
      expect(values.join(' ')).not.toContain(issued.token);
    });

    it('generates distinct tokens', async () => {
      store = build();
      const tokens = new Set<string>();
      for (let i = 0; i < 50; i += 1) tokens.add((await store.issue(buyer)).token);
      expect(tokens.size).toBe(50);
    });

    it('honours a per-issue TTL', async () => {
      store = build();
      const issued = await store.issue(buyer, 30);
      expect(issued.ttlSeconds).toBe(30);
      const ttl = await raw.ttl(keyFor(issued.token));
      expect(ttl).toBeGreaterThan(0);
      expect(ttl).toBeLessThanOrEqual(30);
    });

    it('refuses a subject with no identifier', async () => {
      store = build();
      // An unattributable challenge could be redeemed by anyone holding it.
      await expect(store.issue({})).rejects.toThrow(/at least one/);
    });
  });

  describe('redemption', () => {
    it('accepts a valid token once', async () => {
      store = build();
      const issued = await store.issue(buyer);
      const first = await store.verify(issued.token, buyer);
      expect(first.valid).toBe(true);
      expect(first.valid && first.subject.userId).toBe('U_BUYER');
    });

    it('rejects a second redemption', async () => {
      store = build();
      const issued = await store.issue(buyer);
      await store.verify(issued.token, buyer);
      expect(await store.verify(issued.token, buyer)).toEqual({
        valid: false,
        reason: 'ALREADY_REDEEMED',
      });
    });

    it('rejects a token presented by a different subject', async () => {
      store = build();
      const issued = await store.issue(buyer);
      // A harvested token is worthless to whoever stole it.
      expect(await store.verify(issued.token, stranger)).toMatchObject({
        valid: false,
        reason: 'SUBJECT_MISMATCH',
      });
    });

    it('leaves a token redeemable after a subject mismatch', async () => {
      store = build();
      const issued = await store.issue(buyer);
      await store.verify(issued.token, stranger);
      // Burning it here would let anyone who stole a token destroy the real
      // user's chance of passing the challenge.
      expect((await store.verify(issued.token, buyer)).valid).toBe(true);
    });

    it('rejects a fabricated token', async () => {
      store = build();
      expect(await store.verify('chl_not-a-real-token', buyer)).toEqual({
        valid: false,
        reason: 'UNKNOWN',
      });
    });

    it('rejects an empty or absurdly long token without erroring', async () => {
      store = build();
      expect((await store.verify('', buyer)).valid).toBe(false);
      expect((await store.verify('x'.repeat(10_000), buyer)).valid).toBe(false);
    });

    it('rejects an expired token', async () => {
      store = build();
      // A short TTL and a real wait. Advancing the injected clock would not
      // expire anything: the TTL is enforced by Redis against wall-clock time, so
      // a fake clock can only test the parts of expiry the engine computes itself.
      const issued = await store.issue(buyer, 1);
      await new Promise((resolve) => setTimeout(resolve, 1_200));

      // The answer is UNKNOWN rather than EXPIRED because Redis cannot tell a
      // lapsed key from one that never existed. Inventing the distinction would be
      // a claim about store state the store does not have.
      expect(await store.verify(issued.token, buyer)).toEqual({ valid: false, reason: 'UNKNOWN' });
    });

    it('does not confuse subjects that concatenate to the same string', async () => {
      store = build();
      // userId "a" + sessionId "bc" must not match userId "ab" + sessionId "c".
      const left = { userId: 'a', sessionId: 'bc' };
      const right = { userId: 'ab', sessionId: 'c' };
      const issued = await store.issue(left);
      expect((await store.verify(issued.token, left)).valid).toBe(true);

      const other = await store.issue(right);
      expect((await store.verify(other.token, left)).valid).toBe(false);
    });

    it('binds on every provided identifier, not just the first', async () => {
      store = build();
      const issued = await store.issue({ userId: 'U1', sessionId: 'S1' });
      // Same user, different session: a stolen token bound to a browser session
      // must not work from another one.
      expect((await store.verify(issued.token, { userId: 'U1', sessionId: 'S2' })).valid).toBe(false);
    });

    it('survives a store outage without throwing', async () => {
      const broken = new ChallengeStore({
        redis: { ...redis, eval: async () => { throw new Error('ECONNREFUSED'); } } as RedisLike,
        keyPrefix: `${RUN_ID}:`,
        now: () => now,
      });
      // Failing the redemption would lock out every challenged buyer during a
      // Redis blip, so it degrades to a plain failure the caller can choose on.
      expect(await broken.verify('chl_anything', buyer)).toEqual({ valid: false, reason: 'UNKNOWN' });
    });
  });

  describe('concurrency', () => {
    /**
     * The reason redemption is a Lua script and not GET-then-DEL.
     *
     * A client retrying after a network hiccup is exactly the case where two
     * requests carry the same token at the same moment. With a two-step
     * read-then-delete both would observe a live token and both would succeed.
     */
    it('lets exactly one of many concurrent redemptions win', async () => {
      store = build();
      const issued = await store.issue(buyer);

      const results = await Promise.all(
        Array.from({ length: 24 }, () => store.verify(issued.token, buyer)),
      );

      expect(results.filter((r) => r.valid)).toHaveLength(1);
      expect(results.filter((r) => !r.valid)).toHaveLength(23);
    });

    it('does not let concurrent wrong-subject attempts consume a token', async () => {
      store = build();
      const issued = await store.issue(buyer);

      const attackers = await Promise.all(
        Array.from({ length: 12 }, () => store.verify(issued.token, stranger)),
      );
      expect(attackers.every((r) => !r.valid)).toBe(true);

      // The record survives a flood of wrong-subject reads, so the real user can
      // still pass. A naive implementation that deletes on any lookup would have
      // let twelve wrong guesses cancel the challenge entirely.
      expect((await store.verify(issued.token, buyer)).valid).toBe(true);
    });
  });

  describe('burn and inspection', () => {
    it('burns a token without accepting it', async () => {
      store = build();
      const issued = await store.issue(buyer);
      expect(await store.burn(issued.token)).toBe(true);
      expect((await store.verify(issued.token, buyer)).valid).toBe(false);
    });

    it('reports an outstanding token', async () => {
      store = build();
      const issued = await store.issue(buyer);
      expect(await store.isOutstanding(issued.token)).toBe(true);
      await store.verify(issued.token, buyer);
      expect(await store.isOutstanding(issued.token)).toBe(false);
    });

    it('reports an unknown token as not outstanding', async () => {
      store = build();
      expect(await store.isOutstanding('chl_nope')).toBe(false);
    });
  });

  it('issues high-entropy tokens', async () => {
    // 24 bytes is 192 bits. The failure mode being guarded against is a
    // deployment accidentally lowering this to something guessable.
    store = build({ tokenBytes: 24 });
    const tokens = new Set<string>();
    for (let i = 0; i < 200; i += 1) tokens.add((await store.issue(buyer)).token);
    const lengths = [...tokens].map((t) => Buffer.from(t.slice(4), 'base64url').length);
    expect(Math.min(...lengths)).toBe(24);
  });
});

/**
 * Resolve the internal key for a token.
 *
 * Recomputed the same way the store does it rather than reaching into privates,
 * so the test asserts on the real keyspace layout instead of a mock's idea of it.
 */
function keyFor(token: string): string {
  return `${RUN_ID}:chl:${createHash('sha256').update(token, 'utf8').digest('base64url')}`;
}
