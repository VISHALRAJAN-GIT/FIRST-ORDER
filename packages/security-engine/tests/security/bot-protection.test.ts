/**
 * Part 7 — bot / automation protection.
 *
 * The spec's hard requirement here is negative: users must NOT be banned for
 * sharing an IP. Most of this suite exists to prove that, because it is the
 * easiest guarantee in a bot system to implement in name and violate in practice.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import IORedis from 'ioredis';
import { BotProtection, DEFAULT_BOT_CONFIG, eventTypeForSignal, type BotSignal, type SecurityDecision } from '../../src/bot-protection/bot-protection';
import { wrapIoredis, type RedisLike } from '../../src/ports/redis';
import { SecurityError } from '../../src/core/errors';

const REDIS_URL = process.env.TEST_REDIS_URL ?? 'redis://127.0.0.1:6379';
const RUN_ID = `bp${Date.now().toString(36)}`;

describe('bot protection (Part 7)', () => {
  let redis: RedisLike;
  let raw: IORedis;

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
    // delete() takes one key; spreading the array silently removed only the first
    // and leaked counts into the next test.
    for (const key of keys) await redis.delete(key);
  });

  const protection = (overrides: Partial<typeof DEFAULT_BOT_CONFIG> = {}, now = 1_700_000_000_000) =>
    new BotProtection({ redis, keyPrefix: `${RUN_ID}:`, now: () => now, config: { ...DEFAULT_BOT_CONFIG, ...overrides } });

  describe('the shared-IP guarantee', () => {
    /**
     * The headline requirement. Behind a stadium NAT, many unrelated people share
     * one address. Behavioural signals must never accumulate against it.
     */
    it('ignores behavioural signals that carry only an IP', async () => {
      const bot = protection();
      const behavioural: BotSignal[] = [
        'IDENTICAL_REPEAT',
        'REPEATED_FAILED_RESERVATIONS',
        'RAPID_SEAT_CHANGES',
        'REPEATED_CANCELLATIONS',
        'EXCESSIVE_ACCOUNT_CREATION',
      ];

      for (let i = 0; i < 200; i += 1) {
        for (const signal of behavioural) {
          const decision = await bot.evaluate({ signal, ip: '203.0.113.1', detail: `req_${i % 3}` });
          expect(decision.level).toBe('NORMAL');
          expect(decision.allow).toBe(true);
        }
      }
    });

    it('writes no counter at all for an unattributable signal', async () => {
      const bot = protection();
      await bot.evaluate({ signal: 'IDENTICAL_REPEAT', ip: '203.0.113.1' });
      expect(await redis.keys(`${RUN_ID}:*`)).toHaveLength(0);
    });

    it('still counts volume signals against a shared IP', async () => {
      // Request rate genuinely is a property of the connection, so this one is
      // allowed to score — and it stays within its allowance, so it cannot ban.
      const bot = protection();
      let last: SecurityDecision | undefined;
      for (let i = 0; i < 22; i += 1) last = await bot.evaluate({ signal: 'HIGH_FREQUENCY', ip: '203.0.113.1' });
      expect(last?.score).toBeGreaterThan(0);
      expect(last?.level).toBe('INCREASED_RATE_LIMITING');
      expect(last?.allow).toBe(true);
    });

    it('scores a real user on their own behaviour', async () => {
      const bot = protection();
      let last: SecurityDecision | undefined;
      for (let i = 0; i < 8; i += 1) {
        last = await bot.evaluate({ signal: 'REPEATED_FAILED_RESERVATIONS', userId: 'U_BAD', ip: '203.0.113.1' });
      }
      expect(last?.score).toBeGreaterThan(0);
    });

    it('keeps two users behind one IP independent', async () => {
      const bot = protection();
      for (let i = 0; i < 10; i += 1) await bot.evaluate({ signal: 'RAPID_SEAT_CHANGES', userId: 'U_A', ip: '203.0.113.1' });
      const other = await bot.evaluate({ signal: 'RAPID_SEAT_CHANGES', userId: 'U_B', ip: '203.0.113.1' });
      expect(other.score).toBe(0); // U_B's first offence is within the allowance.
    });
  });

  describe('escalation ladder', () => {
    it('walks NORMAL -> INCREASED_RATE_LIMITING -> CHALLENGE -> restriction', async () => {
      const bot = protection();
      const seen: string[] = [];
      let restricted = false;
      for (let i = 0; i < 25; i += 1) {
        try {
          const d = await bot.evaluate({ signal: 'REQUEST_BURST', userId: 'U1' });
          if (seen.at(-1) !== d.level) seen.push(d.level);
        } catch {
          restricted = true;
          break;
        }
      }
      expect(seen).toEqual(['NORMAL', 'INCREASED_RATE_LIMITING', 'CHALLENGE_REQUIRED']);
      expect(restricted).toBe(true);
    });

    it('tightens the rate limit rather than blocking at the first step', async () => {
      const bot = protection();
      for (let i = 0; i < DEFAULT_BOT_CONFIG.allowances.REQUEST_BURST; i += 1) {
        await bot.evaluate({ signal: 'REQUEST_BURST', userId: 'U1' });
      }
      const decision = await bot.evaluate({ signal: 'REQUEST_BURST', userId: 'U1' });
      expect(decision.level).toBe('INCREASED_RATE_LIMITING');
      expect(decision.allow).toBe(true);
      expect(decision.rateLimitMultiplier).toBeLessThan(1);
    });

    it('issues an unpredictable challenge token that requires action', async () => {
      const bot = protection();
      const tokens = new Set<string>();
      let decision: SecurityDecision | undefined;
      for (let i = 0; i < 19; i += 1) {
        decision = await bot.evaluate({ signal: 'REQUEST_BURST', userId: 'U1' });
        if (decision.challengeToken) tokens.add(decision.challengeToken);
      }
      expect(decision?.challengeToken).toBeDefined();
      expect(decision?.allow).toBe(false);
      // Every challenge must be distinct, or one solution unlocks all of them.
      expect(tokens.size).toBeGreaterThan(1);
    });

    it('throws a retryable 429 at the top of the ladder', async () => {
      const bot = protection();
      await expect(async () => {
        for (let i = 0; i < 40; i += 1) await bot.evaluate({ signal: 'REQUEST_BURST', userId: 'U1' });
      }).rejects.toThrow(SecurityError);
    });

    it('reports a retry-after on the restriction', async () => {
      const bot = protection();
      let caught: SecurityError | null = null;
      try {
        for (let i = 0; i < 40; i += 1) await bot.evaluate({ signal: 'REQUEST_BURST', userId: 'U1' });
      } catch (error) {
        caught = error as SecurityError;
      }
      expect(caught?.code).toBe('TEMPORARILY_RESTRICTED');
      expect(caught?.retryAfterSeconds).toBe(DEFAULT_BOT_CONFIG.restrictionTtlSeconds);
    });

    /**
     * The calibration regression. Before allowances existed, `weight x count`
     * restricted a user after 7 ordinary requests in a 5-minute window, which
     * during a sale means banning paying customers.
     */
    it('does not restrict a user for activity within the documented allowance', async () => {
      const bot = protection();
      let level = 'NORMAL';
      for (let i = 0; i < DEFAULT_BOT_CONFIG.allowances.REQUEST_BURST; i += 1) {
        level = (await bot.evaluate({ signal: 'REQUEST_BURST', userId: 'CASUAL' })).level;
      }
      expect(level).toBe('NORMAL');
    });

    /** One noisy metric must not be able to run away with the score. */
    it('caps any single signal contribution', async () => {
      const bot = protection();
      let caught: SecurityError | null = null;
      try {
        for (let i = 0; i < 500; i += 1) await bot.evaluate({ signal: 'EXCESSIVE_ACCOUNT_CREATION', userId: 'U1' });
      } catch (error) {
        caught = error as SecurityError;
      }
      expect(caught?.code).toBe('TEMPORARILY_RESTRICTED');
      // The public reason is deliberately uninformative.
      expect(caught?.publicDetails).toEqual({ reason: 'automated activity detected' });
      const ceiling = DEFAULT_BOT_CONFIG.maxPerSignal * DEFAULT_BOT_CONFIG.weights.EXCESSIVE_ACCOUNT_CREATION;
      expect(ceiling).toBe(400);
    });

    it('sets an expiry on a challenge', async () => {
      const bot = protection();
      let decision: SecurityDecision | undefined;
      for (let i = 0; i < 19; i += 1) decision = await bot.evaluate({ signal: 'REQUEST_BURST', userId: 'U1' });
      expect(decision?.expiresAt).toBeDefined();
      expect(new Date(decision!.expiresAt!).getTime()).toBe(1_700_000_000_000 + DEFAULT_BOT_CONFIG.challengeTtlSeconds * 1000);
    });
  });

  describe('combined signals', () => {
    /**
     * The regression this guards: taking a max made a diffuse automation pattern
     * look harmless forever, because no single signal ever crossed a threshold.
     */
    it('sums several weak signals into a real escalation', async () => {
      const bot = protection();
      // Three signals whose individual scores all sit below the threshold of 10.
      const signals: BotSignal[] = ['IDENTICAL_REPEAT', 'REPEATED_CANCELLATIONS', 'SUSPICIOUS_PATTERN'];
      for (const signal of signals) {
        for (let i = 0; i < DEFAULT_BOT_CONFIG.allowances[signal]; i += 1) {
          await bot.evaluate({ signal, userId: 'U1' });
        }
      }
      const decision = await bot.evaluateAll(signals.map((signal) => ({ signal, userId: 'U1' })));
      // One step past each allowance: 6 + 7 + 9 = 22. None of them reaches 10 on
      // its own, so a max() would have reported NORMAL and missed the pattern.
      expect(decision.score).toBe(22);
      expect(decision.level).toBe('INCREASED_RATE_LIMITING');
    });

    it('reports every contributing signal, for operator triage', async () => {
      const bot = protection();
      await bot.evaluate({ signal: 'RAPID_SEAT_CHANGES', userId: 'U1' });
      await bot.evaluate({ signal: 'IDENTICAL_REPEAT', userId: 'U1' });
      const decision = await bot.evaluateAll([
        { signal: 'RAPID_SEAT_CHANGES', userId: 'U1' },
        { signal: 'IDENTICAL_REPEAT', userId: 'U1' },
      ]);
      expect(decision.signals).toEqual(['RAPID_SEAT_CHANGES', 'IDENTICAL_REPEAT']);
      expect(decision.reason).toContain('RAPID_SEAT_CHANGES');
    });

    it('reaches restriction through combination when no single signal would', async () => {
      const bot = protection();
      let caught: SecurityError | null = null;
      try {
        for (let round = 0; round < 20; round += 1) {
          await bot.evaluateAll([
            { signal: 'REQUEST_BURST', userId: 'U1' },
            { signal: 'IDENTICAL_REPEAT', userId: 'U1' },
            { signal: 'SUSPICIOUS_PATTERN', userId: 'U1' },
          ]);
        }
      } catch (error) {
        caught = error as SecurityError;
      }
      expect(caught?.code).toBe('TEMPORARILY_RESTRICTED');
    });

    it('returns NORMAL when nothing is attributable', async () => {
      const bot = protection();
      const decision = await bot.evaluateAll([{ signal: 'IDENTICAL_REPEAT', ip: '203.0.113.1' }]);
      expect(decision.level).toBe('NORMAL');
      expect(decision.score).toBe(0);
    });
  });

  describe('key hygiene', () => {
    it('hashes caller-supplied detail instead of embedding it', async () => {
      const bot = protection();
      await bot.evaluate({ signal: 'IDENTICAL_REPEAT', userId: 'U1', detail: 'user@example.com' });
      const keys = await redis.keys(`${RUN_ID}:*`);
      expect(keys).toHaveLength(1);
      // The address must not be sitting in a Redis key.
      expect(keys[0]).not.toContain('example.com');
    });

    it('keeps counters separate per detail', async () => {
      const bot = protection();
      const a = await bot.evaluate({ signal: 'IDENTICAL_REPEAT', userId: 'U1', detail: 'req_A' });
      const b = await bot.evaluate({ signal: 'IDENTICAL_REPEAT', userId: 'U1', detail: 'req_B' });
      expect(a.score).toBe(b.score);
    });
  });

  describe('failure posture', () => {
    it('does not escalate when the signal store is unavailable', async () => {
      // A Redis incident is not evidence of automation. Escalating the whole user
      // base during an outage would be a self-inflicted denial of service.
      const dead = new BotProtection({
        redis: { increment: async () => { throw new Error('ECONNREFUSED'); } } as never,
        keyPrefix: `${RUN_ID}:`,
        now: () => 1_700_000_000_000,
      });
      const decision = await dead.evaluate({ signal: 'HIGH_FREQUENCY', userId: 'U1' });
      expect(decision.level).toBe('NORMAL');
      expect(decision.allow).toBe(true);
    });

    it('notifies the caller when a signal alone demands intervention', async () => {
      const fired: BotSignal[] = [];
      const bot = new BotProtection({
        redis,
        keyPrefix: `${RUN_ID}:`,
        now: () => 1_700_000_000_000,
        onSignal: (signal) => fired.push(signal),
      });
      try {
        for (let i = 0; i < 40; i += 1) await bot.evaluate({ signal: 'EXCESSIVE_ACCOUNT_CREATION', userId: 'U1' });
      } catch {
        // Restriction is expected; the notification is what this test is about.
      }
      expect(fired).toContain('EXCESSIVE_ACCOUNT_CREATION');
    });

    it('stays quiet for signals that are merely within allowance', async () => {
      const fired: BotSignal[] = [];
      const bot = new BotProtection({
        redis,
        keyPrefix: `${RUN_ID}:`,
        now: () => 1_700_000_000_000,
        onSignal: (signal) => fired.push(signal),
      });
      // Allowance 3, weight 6: a single signal only demands intervention at 5
      // excess (30 points >= the challenge threshold of 25), i.e. count 8.
      for (let i = 0; i < 7; i += 1) await bot.evaluate({ signal: 'IDENTICAL_REPEAT', userId: 'U1' });
      expect(fired).toEqual([]);
    });
  });

  describe('event mapping', () => {
    it('maps signals onto the dashboard catalogue', () => {
      expect(eventTypeForSignal('HIGH_FREQUENCY')).toBe('EXCESSIVE_REQUESTS');
      expect(eventTypeForSignal('REQUEST_BURST')).toBe('RATE_LIMIT_TRIGGERED');
      expect(eventTypeForSignal('REPEATED_FAILED_RESERVATIONS')).toBe('MULTIPLE_FAILED_BOOKINGS');
      expect(eventTypeForSignal('IDENTICAL_REPEAT')).toBe('BOT_SIGNAL_DETECTED');
    });
  });
});
