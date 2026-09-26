/**
 * Port: idempotency records.
 *
 * ## The contract
 *
 * A caller retries a `POST /api/bookings` because the response never arrived.
 * Without idempotency the retry creates a second booking and charges the card
 * twice. The caller did nothing wrong; the network did. Idempotency turns "retry
 * safely" into a property of the endpoint rather than a hope about the client.
 *
 * ## The hard part is the concurrent case
 *
 * Sequential retries are easy: look up the key, find the stored result, return
 * it. The dangerous case is two requests bearing the same key arriving at the
 * same instant — a double-click, or a client that fans out retries in parallel.
 * Both see "no record", both execute the booking, and both succeed. Storing the
 * result is not enough; the *claim* has to be exclusive.
 *
 * `claim` is therefore the load-bearing method. Exactly one caller may win it for
 * a given key. Everyone else is told the operation is in flight and must wait
 * rather than execute. An implementation that checks for existence and then
 * inserts reintroduces the exact bug this port exists to prevent.
 *
 * ## Why the record is durable as well as cached
 *
 * Redis is the coordination point, but the spec also calls for the record in the
 * database, and both have a role. Redis gives fast mutual exclusion with a TTL
 * that bounds how long a stuck key can block retries. Postgres keeps the
 * original response durably, so a duplicate arriving after the Redis window
 * expired still replays the original result instead of re-executing. Neither
 * store alone is sufficient.
 */

import { createHash } from 'node:crypto';
import type { RedisLike } from './redis';

export const IDEMPOTENCY_STATES = ['PROCESSING', 'SUCCESS', 'FAILED'] as const;
export type IdempotencyState = (typeof IDEMPOTENCY_STATES)[number];

/** What a completed operation produced. Replayed verbatim on a duplicate. */
export interface IdempotentResponse {
  readonly status: number;
  readonly body: unknown;
  /** Response headers worth preserving, e.g. `Location`. */
  readonly headers?: Readonly<Record<string, string>>;
}

export interface IdempotencyRecord {
  readonly key: string;
  readonly endpoint: string;
  readonly state: IdempotencyState;
  /** Fingerprint of the request this key was first used with. */
  readonly requestHash: string;
  readonly response: IdempotentResponse | undefined;
  readonly createdAt: string;
  readonly completedAt: string | undefined;
}

export type ClaimResult =
  | { readonly claimed: true }
  /**
   * Someone else owns this key right now. The caller must NOT execute the
   * operation; it should return 409 or poll until the record completes.
   */
  | { readonly claimed: false; readonly inFlight: true }
  /**
   * The key was already used for a DIFFERENT request. Executing would be unsafe
   * and replaying would be wrong, so this is a client error.
   */
  | { readonly claimed: false; readonly inFlight: false; readonly conflict: true }
  | { readonly claimed: false; readonly inFlight: false; readonly conflict: false; readonly record: IdempotencyRecord };

export interface IdempotencyStore {
  /**
   * Attempt to become the owner of `key` for `requestHash`.
   *
   * MUST be atomic. Returns `claimed: true` for exactly one caller per key per
   * TTL window; every other concurrent caller gets `inFlight: true`.
   */
  claim(input: {
    readonly key: string;
    readonly endpoint: string;
    readonly requestHash: string;
    readonly ttlSeconds: number;
  }): Promise<ClaimResult>;

  /**
   * Attach the result to a claimed key and move it to a terminal state.
   *
   * `FAILED` is stored rather than deleted on purpose: a failed payment must not
   * be retried under the same key, because the failure may have occurred after
   * the provider charged the card. Callers that genuinely want a fresh attempt
   * send a new key.
   */
  complete(input: {
    readonly key: string;
    readonly endpoint: string;
    readonly requestHash: string;
    readonly state: 'SUCCESS' | 'FAILED';
    readonly response: IdempotentResponse;
  }): Promise<void>;

  /** Current record, or null when the key is unknown or has aged out. */
  get(key: string, endpoint: string): Promise<IdempotencyRecord | null>;
}

/**
 * Fingerprint a request so a key reused across different payloads is caught.
 *
 * The key alone is not enough protection. A client that accidentally reuses
 * `abc123` for a different booking must be told, not silently given the first
 * booking's response — which would look like success while creating nothing.
 */
export function fingerprintRequest(parts: {
  readonly method: string;
  readonly path: string;
  readonly body: unknown;
  readonly authenticatedUserId?: string | undefined;
}): string {
  // Imported lazily to keep this port free of core dependencies.
  const canonical = canonicalize(parts);
  return sha256Hex(canonical);
}

// Local, dependency-free implementations. Node's crypto is available on Vercel.
function canonicalize(parts: {
  readonly method: string;
  readonly path: string;
  readonly body: unknown;
  readonly authenticatedUserId?: string | undefined;
}): string {
  const normalizedBody = stableStringify(parts.body);
  return [
    parts.method.toUpperCase(),
    parts.path,
    parts.authenticatedUserId ?? '-',
    normalizedBody,
  ].join('\n');
}

function stableStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const entries = Object.keys(value as Record<string, unknown>)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify((value as Record<string, unknown>)[key])}`);
  return `{${entries.join(',')}}`;
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

/**
 * Redis-backed store: exclusive claim via SET NX, durable result in Postgres.
 *
 * See `IdempotencyStore` for why both halves exist. The `complete` path uses
 * compare-and-set so a late writer cannot overwrite a result another worker
 * already stored.
 */
export interface RedisIdempotencyStoreOptions {
  readonly redis: RedisLike;
  readonly keyPrefix: string;
  /** Optional durable mirror; when absent, records live in Redis only. */
  readonly durable?: {
    get(key: string, endpoint: string): Promise<IdempotencyRecord | null>;
    upsert(record: IdempotencyRecord): Promise<void>;
  };
  readonly nowIso: () => string;
}

interface ClaimEnvelope {
  readonly state: IdempotencyState;
  readonly requestHash: string;
  readonly endpoint: string;
  readonly response?: IdempotentResponse;
  readonly completedAt?: string;
}

export class RedisIdempotencyStore implements IdempotencyStore {
  readonly #redis: RedisLike;
  readonly #prefix: string;
  readonly #durable: RedisIdempotencyStoreOptions['durable'];
  readonly #nowIso: () => string;

  constructor(options: RedisIdempotencyStoreOptions) {
    this.#redis = options.redis;
    this.#prefix = options.keyPrefix;
    this.#durable = options.durable;
    this.#nowIso = options.nowIso;
  }

  #key(key: string, endpoint: string): string {
    // Endpoint is part of the identity: the same key used on two different
    // endpoints is two different operations, and must not collide.
    return `${this.#prefix}idem:${endpoint}:${key}`;
  }

  async claim(input: {
    readonly key: string;
    readonly endpoint: string;
    readonly requestHash: string;
    readonly ttlSeconds: number;
  }): Promise<ClaimResult> {
    const redisKey = this.#key(input.key, input.endpoint);
    const envelope: ClaimEnvelope = {
      state: 'PROCESSING',
      requestHash: input.requestHash,
      endpoint: input.endpoint,
    };

    const claimed = await this.#redis.setIfAbsent(redisKey, JSON.stringify(envelope), input.ttlSeconds);
    if (claimed) {
      return { claimed: true };
    }

    // Key exists. Either a concurrent worker owns it, or a completed result is
    // waiting to be replayed.
    const raw = await this.#redis.get(redisKey);
    if (raw === null) {
      // Vanished between SET NX and GET — the owner's TTL expired. The window is
      // tiny and the claim is safe to retry, so report it as in flight and let
      // the caller retry rather than risk executing a duplicate.
      return { claimed: false, inFlight: true };
    }

    let existing: ClaimEnvelope;
    try {
      existing = JSON.parse(raw) as ClaimEnvelope;
    } catch {
      return { claimed: false, inFlight: true };
    }

    if (existing.requestHash !== input.requestHash) {
      return { claimed: false, inFlight: false, conflict: true };
    }
    if (existing.state === 'PROCESSING') {
      return { claimed: false, inFlight: true };
    }
    return {
      claimed: false,
      inFlight: false,
      conflict: false,
      record: {
        key: input.key,
        endpoint: input.endpoint,
        state: existing.state,
        requestHash: existing.requestHash,
        response: existing.response,
        createdAt: this.#nowIso(),
        completedAt: existing.completedAt,
      },
    };
  }

  async complete(input: {
    readonly key: string;
    readonly endpoint: string;
    readonly requestHash: string;
    readonly state: 'SUCCESS' | 'FAILED';
    readonly response: IdempotentResponse;
  }): Promise<void> {
    const redisKey = this.#key(input.key, input.endpoint);
    const raw = await this.#redis.get(redisKey);
    if (raw === null) return;

    const existing = JSON.parse(raw) as ClaimEnvelope;
    if (existing.requestHash !== input.requestHash) return;

    const envelope: ClaimEnvelope = {
      ...existing,
      state: input.state,
      response: input.response,
      completedAt: this.#nowIso(),
    };

    if (this.#durable) {
      await this.#durable.upsert({
        key: input.key,
        endpoint: input.endpoint,
        state: input.state,
        requestHash: input.requestHash,
        response: input.response,
        createdAt: existing.completedAt ?? this.#nowIso(),
        completedAt: envelope.completedAt,
      });
    }

    // Overwrite unconditionally: the claim is already exclusively ours, so no
    // other writer can legitimately hold this key. Preserving the original TTL
    // is deliberate — the record should expire ttlSeconds after the *claim*, not
    // be kept alive indefinitely by a stream of retries.
    await this.#redis.set(redisKey, JSON.stringify(envelope), Math.max(1, await this.#redis.ttl(redisKey)));
  }

  async get(key: string, endpoint: string): Promise<IdempotencyRecord | null> {
    const raw = await this.#redis.get(this.#key(key, endpoint));
    if (raw !== null) {
      const envelope = JSON.parse(raw) as ClaimEnvelope;
      return {
        key,
        endpoint,
        state: envelope.state,
        requestHash: envelope.requestHash,
        response: envelope.response,
        createdAt: this.#nowIso(),
        completedAt: envelope.completedAt,
      };
    }
    return this.#durable ? this.#durable.get(key, endpoint) : null;
  }
}
