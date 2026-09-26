/**
 * In-memory Redis double for unit tests.
 *
 * ## Scope and limits — read this before trusting a green test run
 *
 * This double exists so the ~80% of security logic that is not about concurrency
 * can be tested fast and hermetically. It faithfully implements TTL, `SET NX`,
 * compare-and-set, set intersection, and Lua-script dispatch.
 *
 * It CANNOT prove any concurrency guarantee, because it runs in a single
 * Node process where every operation is effectively serialised. The atomicity
 * claims in this project — one ticket scan succeeds, one idempotency key is
 * claimed, one queue admission per position — are proven only by the suites in
 * `tests/concurrency` and `tests/load`, which run against real Redis and real
 * Postgres via `npm run infra:up`.
 *
 * Anything that claims "exactly one winner" must be tested there, not here.
 */

import type { RedisLike, RedisValue } from '../../src/ports/redis';

interface Entry {
  value: string;
  /** Absolute expiry in ms, or undefined for no TTL. */
  expiresAt: number | undefined;
}

interface SetEntry {
  members: Set<string>;
  expiresAt: number | undefined;
}

interface HashEntry {
  fields: Map<string, number>;
  expiresAt: number | undefined;
}

export class InMemoryRedis implements RedisLike {
  readonly #strings = new Map<string, Entry>();
  readonly #sets = new Map<string, SetEntry>();
  readonly #hashes = new Map<string, HashEntry>();
  #now: number;

  /** Set to make every operation reject, to exercise fail-open/fail-closed paths. */
  failing = false;

  constructor(now = 0) {
    this.#now = now;
  }

  /** Advance the double's clock, expiring keys lazily as Redis does. */
  advance(milliseconds: number): void {
    this.#now += milliseconds;
  }

  get now(): number {
    return this.#now;
  }

  #expired(entry: { expiresAt: number | undefined } | undefined): boolean {
    if (!entry || entry.expiresAt === undefined) return false;
    return this.#now >= entry.expiresAt;
  }

  #liveString(key: string): Entry | undefined {
    const entry = this.#strings.get(key);
    if (this.#expired(entry)) {
      this.#strings.delete(key);
      return undefined;
    }
    return entry;
  }

  #liveSet(key: string): SetEntry | undefined {
    const entry = this.#sets.get(key);
    if (this.#expired(entry)) {
      this.#sets.delete(key);
      return undefined;
    }
    return entry;
  }

  #liveHash(key: string): HashEntry | undefined {
    const entry = this.#hashes.get(key);
    if (this.#expired(entry)) {
      this.#hashes.delete(key);
      return undefined;
    }
    return entry;
  }

  #assertHealthy(): void {
    if (this.failing) throw new Error('InMemoryRedis: simulated connection failure');
  }

  async get(key: string): Promise<string | null> {
    this.#assertHealthy();
    return this.#liveString(key)?.value ?? null;
  }

  async set(key: string, value: RedisValue, ttlSeconds?: number): Promise<void> {
    this.#assertHealthy();
    this.#strings.set(key, {
      value: String(value),
      expiresAt: ttlSeconds === undefined ? undefined : this.#now + ttlSeconds * 1000,
    });
  }

  async setIfAbsent(key: string, value: RedisValue, ttlSeconds: number): Promise<boolean> {
    this.#assertHealthy();
    if (this.#liveString(key)) return false;
    this.#strings.set(key, { value: String(value), expiresAt: this.#now + ttlSeconds * 1000 });
    return true;
  }

  async compareAndSet(key: string, expected: RedisValue, next: RedisValue, ttlSeconds?: number): Promise<boolean> {
    this.#assertHealthy();
    const current = this.#liveString(key);
    if (!current || current.value !== String(expected)) return false;
    this.#strings.set(key, {
      value: String(next),
      expiresAt: ttlSeconds === undefined ? current.expiresAt : this.#now + ttlSeconds * 1000,
    });
    return true;
  }

  async delete(key: string): Promise<boolean> {
    this.#assertHealthy();
    const existed = this.#liveString(key) !== undefined;
    this.#strings.delete(key);
    this.#sets.delete(key);
    this.#hashes.delete(key);
    return existed;
  }

  async exists(key: string): Promise<boolean> {
    this.#assertHealthy();
    return this.#liveString(key) !== undefined || this.#liveSet(key) !== undefined || this.#liveHash(key) !== undefined;
  }

  async ttl(key: string): Promise<number> {
    this.#assertHealthy();
    const entry = this.#liveString(key) ?? this.#liveSet(key) ?? this.#liveHash(key);
    if (!entry) return -2;
    if (entry.expiresAt === undefined) return -1;
    return Math.max(0, Math.ceil((entry.expiresAt - this.#now) / 1000));
  }

  async increment(key: string, ttlSeconds: number, initialValue = 1): Promise<number> {
    this.#assertHealthy();
    const existing = this.#liveString(key);
    const next = (existing ? Number.parseInt(existing.value, 10) : 0) + initialValue;
    // TTL is applied on creation only, mirroring real Redis semantics and the
    // behaviour the production adapter implements.
    this.#strings.set(key, {
      value: String(next),
      expiresAt: existing?.expiresAt ?? this.#now + ttlSeconds * 1000,
    });
    return next;
  }

  async addToSet(key: string, members: RedisValue[], windowSeconds: number): Promise<number> {
    this.#assertHealthy();
    const entry = this.#liveSet(key) ?? { members: new Set<string>(), expiresAt: this.#now + windowSeconds * 1000 };
    let added = 0;
    for (const member of members) {
      if (!entry.members.has(String(member))) {
        entry.members.add(String(member));
        added += 1;
      }
    }
    if (entry.expiresAt === undefined) entry.expiresAt = this.#now + windowSeconds * 1000;
    this.#sets.set(key, entry);
    return added;
  }

  async setCardinality(key: string): Promise<number> {
    this.#assertHealthy();
    return this.#liveSet(key)?.members.size ?? 0;
  }

  async setIntersectionCardinality(keys: string[]): Promise<number> {
    this.#assertHealthy();
    if (keys.length === 0) return 0;
    const [first, ...rest] = keys as [string, ...string[]];
    const base = this.#liveSet(first);
    if (!base) return 0;
    let count = 0;
    for (const member of base.members) {
      if (rest.every((key) => this.#liveSet(key)?.members.has(member))) count += 1;
    }
    return count;
  }

  async removeFromSet(key: string, members: RedisValue[]): Promise<number> {
    this.#assertHealthy();
    const entry = this.#liveSet(key);
    if (!entry) return 0;
    let removed = 0;
    for (const member of members) {
      if (entry.members.delete(String(member))) removed += 1;
    }
    return removed;
  }

  async incrementHashField(key: string, field: string, ttlSeconds: number, initialValue = 1): Promise<number> {
    this.#assertHealthy();
    const entry = this.#liveHash(key) ?? { fields: new Map<string, number>(), expiresAt: this.#now + ttlSeconds * 1000 };
    const next = (entry.fields.get(field) ?? 0) + initialValue;
    entry.fields.set(field, next);
    if (entry.expiresAt === undefined) entry.expiresAt = this.#now + ttlSeconds * 1000;
    this.#hashes.set(key, entry);
    return next;
  }

  async hashGetAll(key: string): Promise<Record<string, string>> {
    this.#assertHealthy();
    const entry = this.#liveHash(key);
    if (!entry) return {};
    return Object.fromEntries([...entry.fields.entries()].map(([field, value]) => [field, String(value)]));
  }

  /**
   * Dispatches the rate-limiter script by its marker comment.
   *
   * A real Redis would execute the Lua. The double recognises the marker and
   * reproduces the same INCR/EXPIRE/TTL sequence, so the *logic under test* is
   * identical — only the execution engine differs. Genuine cross-process atomicity
   * is still proven in tests/concurrency against real Redis.
   */
  async eval(script: string, keys: string[], args: (string | number)[]): Promise<unknown> {
    this.#assertHealthy();

    if (!script.includes('sec:rate-limit')) {
      throw new Error('InMemoryRedis.eval: unrecognised script (no sec:rate-limit marker)');
    }

    const windowSeconds = Number(args[0]);
    const sustainedLimit = Number(args[1]);
    const burstLimit = Number(args[2]);

    const [sustainedKey, burstKey] = keys as [string, string];
    if (!sustainedKey || !burstKey) throw new Error('InMemoryRedis.eval: expected two keys');

    const sustained = await this.increment(sustainedKey, windowSeconds);
    const burst = await this.increment(burstKey, 1);

    const allowed = sustained <= sustainedLimit && burst <= burstLimit ? 1 : 0;
    const remaining = Math.max(0, Math.min(sustainedLimit - sustained, burstLimit - burst));
    const ttl = await this.ttl(sustainedKey);

    return [allowed, remaining, ttl, sustained, burst];
  }

  async keys(pattern: string): Promise<string[]> {
    this.#assertHealthy();
    const regex = new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`);
    const all = [
      ...[...this.#strings.keys()],
      ...[...this.#sets.keys()],
      ...[...this.#hashes.keys()],
    ];
    return all.filter((key) => regex.test(key));
  }

  async ping(): Promise<string> {
    this.#assertHealthy();
    return 'PONG';
  }

  async quit(): Promise<void> {
    /* nothing to close */
  }

  /** Test utility: wipe everything. */
  flush(): void {
    this.#strings.clear();
    this.#sets.clear();
    this.#hashes.clear();
  }

  /** Test utility: inspect raw string keys. */
  debugKeys(): string[] {
    return [...this.#strings.keys()];
  }
}
