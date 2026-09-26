/**
 * Part 6 — Distributed rate limiting.
 *
 * ## Why this is Lua and not arithmetic in TypeScript
 *
 * The spec's warning is the whole point: an in-memory counter is per-process, so
 * N serverless instances each allow the full quota and the effective limit is
 * N times what was configured. Worse, a check-then-increment has a window, so
 * even a single instance lets a burst through if the requests interleave.
 *
 * Each limiter below is therefore one Lua script that reads and writes on the
 * server. Redis never yields mid-script, so the read-modify-write is indivisible
 * and every instance sees one shared counter.
 *
 * ## Fails OPEN, deliberately
 *
 * This is the exact opposite of ticket verification, and the asymmetry is
 * intentional. Verification failing open admits unpaid people into a stadium.
 * Rate limiting failing open lets a few extra requests through during a Redis
 * outage. The second is a smaller harm than the first, so when Redis is
 * unavailable the limiter reports `unavailable` and the caller decides — and the
 * documented default is to allow.
 *
 * The one exception is `failClosed: true`, used on payment and auth endpoints
 * where an unbounded request burst is itself the attack.
 */

import { SecurityError } from '../core/errors';
import type { RedisLike } from '../ports/redis';

export interface RateLimitPolicy {
  /** Sustained allowance, refilled continuously. */
  readonly requestsPerSecond: number;
  /** Bucket depth, i.e. how large a burst may be. */
  readonly burstLimit: number;
  /** Ceiling on any single window, regardless of refill. */
  readonly windowSeconds: number;
  readonly maxPerWindow: number;
}

export const ENDPOINT_POLICIES = {
  /** Credential checking: strictest, since guessing is the threat. */
  AUTH: { requestsPerSecond: 0.5, burstLimit: 5, windowSeconds: 60, maxPerWindow: 10 },
  /** Payment: very strict. */
  PAYMENT: { requestsPerSecond: 0.2, burstLimit: 3, windowSeconds: 60, maxPerWindow: 5 },
  /** Reservation: strict, because it creates financial exposure. */
  RESERVATION: { requestsPerSecond: 1, burstLimit: 5, windowSeconds: 60, maxPerWindow: 20 },
  /** Ticket verification: controlled. One bad actor scanning fast is a signal. */
  TICKET_VERIFY: { requestsPerSecond: 5, burstLimit: 20, windowSeconds: 60, maxPerWindow: 120 },
  /** Seat availability: high, it is a read-heavy polling endpoint. */
  SEAT_AVAILABILITY: { requestsPerSecond: 20, burstLimit: 100, windowSeconds: 60, maxPerWindow: 600 },
  /** Event listing: moderate. */
  EVENT_LISTING: { requestsPerSecond: 10, burstLimit: 40, windowSeconds: 60, maxPerWindow: 300 },
} as const satisfies Record<string, RateLimitPolicy>;

export type PolicyName = keyof typeof ENDPOINT_POLICIES;

export type RateLimitDimension = 'IP' | 'USER' | 'SESSION' | 'ENDPOINT' | 'EVENT';

export interface RateLimitSubject {
  readonly ip?: string | undefined;
  readonly userId?: string | undefined;
  readonly sessionId?: string | undefined;
  readonly endpoint: string;
  readonly eventId?: string | undefined;
}

export interface RateLimitVerdict {
  readonly allowed: boolean;
  /** False when Redis was unreachable, so the caller can apply its own policy. */
  readonly available: boolean;
  readonly limit: number;
  readonly remaining: number;
  /** Seconds until the caller may retry. */
  readonly retryAfterSeconds: number;
  readonly resetAt: string;
  readonly dimension: RateLimitDimension;
  readonly policy: PolicyName | 'CUSTOM';
}

export interface RateLimiterOptions {
  readonly redis: RedisLike;
  readonly keyPrefix: string;
  readonly now: () => number;
  /**
   * Whether an unreachable Redis blocks. Default false (fail open) — see the
   * file header for why this is the safer default and where it is not.
   */
  readonly failClosed?: boolean;
}

/**
 * Token bucket, evaluated server-side.
 *
 * KEYS[1] bucket
 * ARGV[1] now (ms), ARGV[2] capacity, ARGV[3] refillPerSecond,
 * ARGV[4] cost, ARGV[5] ttlSeconds
 * returns { allowed, remaining, retryAfterMs, resetAt }
 *
 * The refill is computed from elapsed time rather than incremented per request,
 * so an idle client does not accumulate unbounded credit and a client that
 * pauses cannot burst far past its burst limit.
 */
const TOKEN_BUCKET_SCRIPT = `
local key       = KEYS[1]
local now      = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local refill   = tonumber(ARGV[3])
local cost     = tonumber(ARGV[4])
local ttl      = tonumber(ARGV[5])

local bucket = redis.call('HMGET', key, 'tokens', 'updatedAt')
local tokens = tonumber(bucket[1])
local updatedAt = tonumber(bucket[2])

if tokens == nil then
  tokens = capacity
  updatedAt = now
end

local elapsed = math.max(0, now - updatedAt) / 1000
tokens = math.min(capacity, tokens + (elapsed * refill))

local allowed = 0
local retryAfterMs = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
else
  local deficit = cost - tokens
  retryAfterMs = math.ceil((deficit / refill) * 1000)
end

redis.call('HSET', key, 'tokens', tokens, 'updatedAt', now)
redis.call('EXPIRE', key, ttl)

local resetAt = now + math.ceil((capacity / refill) * 1000)
return { allowed, math.floor(tokens), retryAfterMs, resetAt }
`;

/**
 * Fixed window counter, evaluated server-side.
 *
 * KEYS[1] counter, ARGV[1] windowSeconds, ARGV[2] ttlSeconds
 * returns { count, ttl }
 *
 * INCR is atomic on its own, so this needs no read — the count is the reply.
 */
const FIXED_WINDOW_SCRIPT = `
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
end
local ttl = redis.call('TTL', KEYS[1])
return { count, ttl }
`;

function dimensionValue(subject: RateLimitSubject, dimension: RateLimitDimension): string {
  switch (dimension) {
    case 'IP':
      return subject.ip ?? 'unknown';
    case 'USER':
      return subject.userId ?? 'anonymous';
    case 'SESSION':
      return subject.sessionId ?? 'no-session';
    case 'EVENT':
      return subject.eventId ?? 'no-event';
    case 'ENDPOINT':
      return subject.endpoint;
  }
}

/**
 * Never key on raw IP or user id.
 *
 * The stored key is a hash, so Redis never holds a readable IP address and a
 * dump of the keyspace cannot be used to enumerate users. Deterministic within a
 * deployment (so a client keeps one bucket) without being reversible without the
 * secret.
 */
function subjectKey(value: string, secret: string): string {
  // FNV-1a keeps this dependency-free; the secret prevents precomputed reversal.
  let hash = 0x811c9dc5;
  const salted = `${secret}:${value}`;
  for (let i = 0; i < salted.length; i += 1) {
    hash ^= salted.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(36);
}

export class RateLimiter {
  readonly #redis: RedisLike;
  readonly #prefix: string;
  readonly #now: () => number;
  readonly #failClosed: boolean;
  readonly #hashSecret: string;

  constructor(options: RateLimiterOptions) {
    this.#redis = options.redis;
    this.#prefix = options.keyPrefix;
    this.#now = options.now;
    this.#failClosed = options.failClosed ?? false;
    this.#hashSecret = process.env.SECURITY_HASH_SECRET ?? 'dev-only-insecure-secret';
  }

  /**
   * Consume from both a token bucket (controls burst shape) and a fixed window
   * (a hard ceiling per period). Both must pass.
   *
   * Running only the bucket would let a client that pauses accumulate credit and
   * then spend it in one burst; running only the fixed window would reject a
   * legitimate short spike. Together they bound the rate and the burst.
   */
  async consume(
    subject: RateLimitSubject,
    policy: RateLimitPolicy,
    dimension: RateLimitDimension,
    cost = 1,
  ): Promise<RateLimitVerdict> {
    const identity = subjectKey(dimensionValue(subject, dimension), this.#hashSecret);
    const now = this.#now();
    const window = Math.floor(now / 1000 / policy.windowSeconds);

    try {
      const [bucketRaw, windowRaw] = await Promise.all([
        this.#redis.eval(
          TOKEN_BUCKET_SCRIPT,
          [`${this.#prefix}rl:bucket:${dimension}:${identity}`],
          [now, policy.burstLimit, policy.requestsPerSecond, cost, Math.ceil(policy.windowSeconds * 2)],
        ),
        this.#redis.eval(
          FIXED_WINDOW_SCRIPT,
          [`${this.#prefix}rl:window:${dimension}:${identity}:${window}`],
          [policy.windowSeconds, policy.windowSeconds * 2],
        ),
      ]);

      const bucket = (bucketRaw as number[]).map(Number);
      const fixed = (windowRaw as number[]).map(Number);
      const bucketAllowed = bucket[0] === 1;
      const count = fixed[0] ?? 0;
      const windowTtl = Math.max(1, fixed[1] ?? policy.windowSeconds);
      const withinWindow = count <= policy.maxPerWindow;
      const allowed = bucketAllowed && withinWindow;

      const retryAfterSeconds = allowed
        ? 0
        : Math.max(1, Math.ceil((bucket[2] ?? 0) / 1000), windowTtl);

      return {
        allowed,
        available: true,
        limit: policy.maxPerWindow,
        remaining: Math.max(0, policy.maxPerWindow - count),
        retryAfterSeconds,
        resetAt: new Date(bucket[3] ?? now).toISOString(),
        dimension,
        policy: 'CUSTOM',
      };
    } catch {
      // Redis unreachable. Apply the configured posture rather than guessing.
      if (this.#failClosed) {
        throw new SecurityError('SECURITY_DEPENDENCY_UNAVAILABLE', 'Rate limiter backend unavailable', {
          retryAfterSeconds: 5,
        });
      }
      return {
        allowed: true,
        available: false,
        limit: policy.maxPerWindow,
        remaining: policy.maxPerWindow,
        retryAfterSeconds: 0,
        resetAt: new Date(now).toISOString(),
        dimension,
        policy: 'CUSTOM',
      };
    }
  }

  /** Named-policy convenience wrapper, so call sites cannot invent numbers. */
  async consumeFor(
    subject: RateLimitSubject,
    policyName: PolicyName,
    dimension: RateLimitDimension,
    cost = 1,
  ): Promise<RateLimitVerdict> {
    return this.consume(subject, ENDPOINT_POLICIES[policyName], dimension, cost);
  }
}

/** 429 body, exactly the shape the spec requires. */
export function rateLimitedResponse(verdict: RateLimitVerdict): {
  status: number;
  body: Record<string, unknown>;
  headers: Record<string, string>;
} {
  return {
    status: 429,
    body: {
      success: false,
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many requests. Please try again.',
      },
    },
    headers: {
      'Retry-After': String(verdict.retryAfterSeconds),
      'X-RateLimit-Limit': String(verdict.limit),
      'X-RateLimit-Remaining': String(verdict.remaining),
      'X-RateLimit-Reset': verdict.resetAt,
    },
  };
}
