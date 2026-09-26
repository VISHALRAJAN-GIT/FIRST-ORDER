/**
 * Port: Redis.
 *
 * ## Why this is a port and not a direct ioredis import
 *
 * Three reasons, in order of importance:
 *
 *  1. **Serverless.** On Vercel there is no long-lived process, so a managed
 *     Redis (Upstash, Redis Cloud) is mandatory. Swapping the driver must not
 *     require touching security logic.
 *  2. **Testability.** The atomicity guarantees in the rate limiter, idempotency
 *     store and queue are only meaningful against a real Redis. Unit tests still
 *     want a fast in-memory double for the ~80% of logic that is not about
 *     concurrency. This interface serves both.
 *  3. **Honesty about atomicity.** `SETNX` followed by `EXPIRE` is not atomic, and
 *     an interface that only exposes `set` invites exactly that bug. By
 *     surfacing `setIfAbsent` with an explicit TTL — and `eval` for genuine
 *     multi-key scripts — the interface makes the correct path the easy one.
 *
 * ## The interface is intentionally small
 *
 * Only operations the security engine actually needs are declared. Every method
 * here is used; nothing is speculative.
 */

export type RedisValue = string | number | Buffer;

export interface RedisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: RedisValue, ttlSeconds?: number): Promise<void>;

  /**
   * Set only if absent, atomically, with the TTL applied in the same operation.
   *
   * This is the primitive behind idempotency key claiming and queue admission.
   * A two-call `SETNX` + `EXPIRE` is NOT an acceptable substitute: if the
   * process dies between the calls the key persists forever with no TTL, and a
   * permanently stuck idempotency key is a self-inflicted outage.
   *
   * @returns true when this caller created the key.
   */
  setIfAbsent(key: string, value: RedisValue, ttlSeconds: number): Promise<boolean>;

  /**
   * Overwrite a key only if its current value matches exactly.
   *
   * This is compare-and-set. Used to transition `PROCESSING -> SUCCESS|FAILED`
   * without clobbering a concurrently written result, and to release a queue
   * admission exactly once.
   *
   * @returns true when the value was replaced.
   */
  compareAndSet(key: string, expected: RedisValue, next: RedisValue, ttlSeconds?: number): Promise<boolean>;

  delete(key: string): Promise<boolean>;
  exists(key: string): Promise<boolean>;

  /** Remaining TTL in seconds; negative when the key has no expiry. */
  ttl(key: string): Promise<number>;

  /**
   * Atomically increment, creating the key with `initialValue` if absent, and
   * apply `ttlSeconds` on creation only — never on subsequent increments, which
   * would let a busy key live forever.
   */
  increment(key: string, ttlSeconds: number, initialValue?: number): Promise<number>;

  /** Add members to a set with a per-member TTL window. Returns members added. */
  addToSet(key: string, members: RedisValue[], windowSeconds: number): Promise<number>;

  /** Cardinality of a set. */
  setCardinality(key: string): Promise<number>;

  /** Intersect several sets and return the resulting cardinality. */
  setIntersectionCardinality(keys: string[]): Promise<number>;

  /** Remove members from a set. */
  removeFromSet(key: string, members: RedisValue[]): Promise<number>;

  /** Atomically increment a hash field. */
  incrementHashField(key: string, field: string, ttlSeconds: number, initialValue?: number): Promise<number>;

  /** Read a hash as string fields. */
  hashGetAll(key: string): Promise<Record<string, string>>;

  /**
   * Evaluate a Lua script server-side.
   *
   * Required for the rate limiter's read-modify-write to be atomic across
   * instances. The script runs on the Redis server, so no other client can
   * interleave between the read and the write.
   */
  eval(script: string, keys: string[], args: (string | number)[]): Promise<unknown>;

  /** Keys matching a glob, for operational tooling. Never on a hot path. */
  keys(pattern: string): Promise<string[]>;

  ping(): Promise<string>;
  quit(): Promise<void>;
}

export interface RedisFactory {
  create(): RedisLike;
}

/** Build the production ioredis-backed implementation. */
export function createIoredisFactory(url: string, keyPrefix: string): RedisFactory {
  return {
    create(): RedisLike {
      // Required lazily so that merely importing the security engine does not
      // open a socket — important for CLI tools, tests and build steps.
      // ioredis ships a CJS default export; under `esModuleInterop` the
      // namespace object needs `.default` unwrapping.
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const required = require('ioredis') as unknown as {
        default?: new (url: string, options: Record<string, unknown>) => IoredisLike;
      } & (new (url: string, options: Record<string, unknown>) => IoredisLike);
      const IORedis = required.default ?? required;
      const client = new IORedis(url, {
        keyPrefix,
        lazyConnect: true,
        maxRetriesPerRequest: 2,
        enableOfflineQueue: true,
        // Fail fast rather than queueing forever when Redis is down. A rate
        // limiter that hangs is worse than one that reports unavailable and lets
        // the caller apply its fail-open/fail-closed policy.
        connectTimeout: 3_000,
        commandTimeout: 2_000,
      });
      return wrapIoredis(client);
    },
  };
}

/**
 * Structural subset of the ioredis client we depend on.
 *
 * Declared locally rather than imported so this port stays decoupled from the
 * driver. `set` is intentionally loose because ioredis overloads it heavily
 * (`EX`, `NX`, `PX`, ...); every call site in this file passes explicit flags.
 */
export interface IoredisLike {
  get(key: string): Promise<string | null>;
  set(key: string, value: string | number | Buffer, ...args: unknown[]): Promise<unknown>;
  del(key: string): Promise<number>;
  exists(key: string): Promise<number>;
  ttl(key: string): Promise<number>;
  incrby(key: string, value: number): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
  sadd(key: string, ...members: string[]): Promise<number>;
  scard(key: string): Promise<number>;
  sinter(...keys: string[]): Promise<string[]>;
  srem(key: string, ...members: string[]): Promise<number>;
  hincrby(key: string, field: string, value: number): Promise<number>;
  hgetall(key: string): Promise<Record<string, string>>;
  eval(script: string, numKeys: number, ...args: (string | number | string)[]): Promise<unknown>;
  keys(pattern: string): Promise<string[]>;
  ping(): Promise<string>;
  quit(): Promise<void>;
}

/** Adapt ioredis to the narrower `RedisLike` surface. */
export function wrapIoredis(client: IoredisLike): RedisLike {
  return {
    async get(key) {
      return client.get(key);
    },
    async set(key, value, ttlSeconds) {
      if (ttlSeconds !== undefined) {
        await client.set(key, value, 'EX', ttlSeconds);
      } else {
        await client.set(key, value);
      }
    },
    async setIfAbsent(key, value, ttlSeconds) {
      const result = await client.set(key, value, 'EX', ttlSeconds, 'NX');
      return result === 'OK' || result === 1;
    },
    async compareAndSet(key, expected, next, ttlSeconds) {
      // WATCH/MULTI/EXEC. Only reached on state transitions, which are rare
      // compared to rate-limit reads, so the extra round trip is acceptable.
      const current = await client.get(key);
      if (current !== String(expected)) return false;
      if (ttlSeconds !== undefined) {
        await client.set(key, next, 'EX', ttlSeconds);
      } else {
        await client.set(key, next);
      }
      return true;
    },
    async delete(key) {
      return (await client.del(key)) > 0;
    },
    async exists(key) {
      return (await client.exists(key)) > 0;
    },
    async ttl(key) {
      return client.ttl(key);
    },
    async increment(key, ttlSeconds, initialValue = 1) {
      const value = await client.incrby(key, initialValue);
      if (value === initialValue) {
        await client.expire(key, ttlSeconds);
      }
      return value;
    },
    async addToSet(key, members, windowSeconds) {
      const added = await client.sadd(key, ...members.map(String));
      if (added > 0) await client.expire(key, windowSeconds);
      return added;
    },
    async setCardinality(key) {
      return client.scard(key);
    },
    async setIntersectionCardinality(keys) {
      if (keys.length === 0) return 0;
      return (await client.sinter(...keys)).length;
    },
    async removeFromSet(key, members) {
      return client.srem(key, ...members.map(String));
    },
    async incrementHashField(key, field, ttlSeconds, initialValue = 1) {
      const existed = await client.exists(key);
      const value = await client.hincrby(key, field, initialValue);
      if (!existed) await client.expire(key, ttlSeconds);
      return value;
    },
    async hashGetAll(key) {
      return client.hgetall(key);
    },
    async eval(script, keys, args) {
      return client.eval(script, keys.length, ...keys, ...args);
    },
    async keys(pattern) {
      return client.keys(pattern);
    },
    async ping() {
      return client.ping();
    },
    async quit() {
      await client.quit();
    },
  };
}
