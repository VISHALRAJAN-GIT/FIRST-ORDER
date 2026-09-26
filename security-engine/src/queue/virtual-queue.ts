/**
 * Part 8 — Virtual queue.
 *
 * ## The bypass this has to prevent
 *
 * A queue that only exists in the UI is theatre. If the booking endpoint accepts
 * a request from someone who skipped the queue, then the queue protects nothing
 * and the only people who obey it are the people who would have waited anyway.
 *
 * So admission is a server-side token, checked on the protected route, and the
 * position is a server-assigned integer. Nothing about admission is derived from
 * anything the client holds:
 *
 *   - the countdown a client displays is decoration, never an input;
 *   - the access token is HMAC'd over the queue entry and carries its own
 *     expiry, so it is not guessable and not replayable after it lapses;
 *   - the token is bound to the session that joined, so one person's place
 *     cannot be handed to another.
 *
 * ## The race
 *
 * The dangerous moment is the promotion sweep. A sweeper promoting the next N
 * waiters, and a client redeeming a token, can interleave, and the classic bug
 * is promoting the same entry twice or admitting more people than the capacity.
 * Promotion is therefore a single conditional UPDATE that moves WAITING -> ADMITTED
 * and reports how many rows it actually claimed; the caller never trusts its own
 * count. See `PostgresQueueStore.promote`.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Pool } from 'pg';
import { SecurityError } from '../core/errors';
import type { RedisLike } from '../ports/redis';

export const QUEUE_STATUSES = ['WAITING', 'ADMITTED', 'EXPIRED', 'LEFT'] as const;
export type QueueStatus = (typeof QUEUE_STATUSES)[number];

export interface QueueEntry {
  readonly queueId: string;
  readonly eventId: string;
  readonly sessionId: string;
  readonly userId: string | null;
  /** Server-assigned. Never client-supplied, never derived from a countdown. */
  readonly position: number;
  readonly status: QueueStatus;
  readonly joinedAt: string;
  readonly admittedAt: string | null;
}

export interface AdmissionToken {
  readonly queueId: string;
  readonly eventId: string;
  readonly sessionId: string;
  readonly position: number;
  readonly expiresAt: string;
  readonly signature: string;
}

export interface QueueJoinResult {
  readonly status: 'QUEUED' | 'ALREADY_QUEUED';
  readonly entry: QueueEntry;
}

export interface QueueStore {
  /** Idempotent per (eventId, sessionId) — re-joining must not create a new place. */
  join(input: {
    readonly eventId: string;
    readonly sessionId: string;
    readonly userId?: string | undefined;
  }): Promise<QueueJoinResult>;

  getBySession(eventId: string, sessionId: string): Promise<QueueEntry | null>;
  getByQueueId(queueId: string): Promise<QueueEntry | null>;

  /**
   * Move up to `limit` WAITING entries to ADMITTED, in position order.
   * Must be atomic and must return the number ACTUALLY promoted.
   */
  promote(eventId: string, limit: number): Promise<readonly QueueEntry[]>;

  markLeft(eventId: string, sessionId: string): Promise<boolean>;
  size(eventId: string): Promise<number>;
  /** Entries ahead of this one, i.e. position - 1. */
  aheadOf(eventId: string, position: number): Promise<number>;
}

export interface QueuePolicy {
  /** Concurrent active sessions above which the event is considered hot. */
  readonly activationThreshold: number;
  /** Sessions admitted per admission window. */
  readonly admissionRate: number;
  readonly admissionWindowSeconds: number;
  /** How long an issued admission token stays valid. */
  readonly tokenTtlSeconds: number;
  /** How long a queue place is held before it lapses. */
  readonly queueTtlSeconds: number;
}

export const DEFAULT_QUEUE_POLICY: QueuePolicy = {
  activationThreshold: 500,
  admissionRate: 50,
  admissionWindowSeconds: 10,
  tokenTtlSeconds: 120,
  queueTtlSeconds: 900,
};

/* ------------------------------------------------------------------ tokens */

export class AdmissionTokenCodec {
  readonly #secret: string;
  readonly #tokenTtlSeconds: number;

  constructor(secret: string, tokenTtlSeconds: number) {
    if (secret.length < 32) {
      // A short HMAC secret makes tokens guessable, which is the one property
      // they must never have. Refuse at construction rather than in production.
      throw new Error('Admission token secret must be at least 32 characters');
    }
    this.#secret = secret;
    this.#tokenTtlSeconds = tokenTtlSeconds;
  }

  issue(entry: QueueEntry, now: number): AdmissionToken {
    const expiresAt = new Date(now + this.#tokenTtlSeconds * 1000).toISOString();
    const payload = `${entry.queueId}.${entry.eventId}.${entry.sessionId}.${entry.position}.${expiresAt}`;
    return {
      queueId: entry.queueId,
      eventId: entry.eventId,
      sessionId: entry.sessionId,
      position: entry.position,
      expiresAt,
      signature: createHmac('sha256', this.#secret).update(payload).digest('base64url'),
    };
  }

  /**
   * Verify signature, expiry, event binding and session binding.
   *
   * All four are checked. A valid signature on the wrong event, or belonging to
   * a different session, is not admission — otherwise a token could be shared
   * around or replayed against another event.
   */
  verify(
    token: AdmissionToken,
    context: { readonly eventId: string; readonly sessionId: string; readonly now: number },
  ): { readonly valid: true } | { readonly valid: false; readonly reason: string } {
    const payload = `${token.queueId}.${token.eventId}.${token.sessionId}.${token.position}.${token.expiresAt}`;
    const expected = createHmac('sha256', this.#secret).update(payload).digest('base64url');

    const a = Buffer.from(expected);
    const b = Buffer.from(token.signature);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return { valid: false, reason: 'signature mismatch' };
    }
    if (token.eventId !== context.eventId) return { valid: false, reason: 'wrong event' };
    if (token.sessionId !== context.sessionId) return { valid: false, reason: 'session mismatch' };
    if (Date.parse(token.expiresAt) <= context.now) return { valid: false, reason: 'expired' };
    return { valid: true };
  }
}

export function newQueueId(): string {
  return `q_${randomBytes(16).toString('base64url')}`;
}

/* ------------------------------------------------------------ postgres store */

function assertSafeIdentifier(value: string, label: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_$]*$/.test(value)) {
    throw new Error(`Unsafe ${label} for SQL interpolation: ${JSON.stringify(value)}`);
  }
  return value;
}

export class PostgresQueueStore implements QueueStore {
  readonly #pool: Pool;
  readonly #table: string;

  constructor(pool: Pool, tableName = 'queue_entries') {
    this.#pool = pool;
    this.#table = `"public"."${assertSafeIdentifier(tableName, 'table name')}"`;
  }

  /**
   * Join the queue, idempotently.
   *
   * Two separate hazards are handled here.
   *
   * POSITION ASSIGNMENT MUST BE ATOMIC. `MAX(position) + 1` read outside a lock
   * lets two concurrent joins compute the same number, which produces two people
   * at one place and a queue whose ordering no longer reflects arrival order. A
   * per-event transaction-scoped advisory lock serialises position assignment for
   * one event while leaving different events fully parallel. (The scale-up path,
   * if one event ever needs more join throughput than a lock allows, is a
   * dedicated Postgres sequence per event rather than relaxing this.)
   *
   * RE-JOINING MUST NOT CREATE A NEW PLACE. The unique index on
   * (event_id, session_id) plus ON CONFLICT DO NOTHING makes that a database
   * guarantee, not an application check. A client that hammers /join would
   * otherwise collect a fresh position each time, which is a queue-jumping
   * primitive.
   */
  async join(input: {
    readonly eventId: string;
    readonly sessionId: string;
    readonly userId?: string | undefined;
  }): Promise<QueueJoinResult> {
    const client = await this.#pool.connect();
    try {
      await client.query('BEGIN');
      // hashtext() maps the event id to a bigint lock key. Scoped to the
      // transaction, so it is released automatically even if a statement throws.
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`queue:${input.eventId}`]);

      const inserted = await client.query<QueueRow>(
        `INSERT INTO ${this.#table} (event_id, session_id, user_id, queue_id, position)
         VALUES ($1, $2, $3, $4,
                 (SELECT COALESCE(MAX(position), 0) + 1 FROM ${this.#table} WHERE event_id = $1))
         ON CONFLICT (event_id, session_id) DO NOTHING
         RETURNING id, event_id, session_id, user_id, queue_id, position, status, joined_at, admitted_at`,
        [input.eventId, input.sessionId, input.userId ?? null, newQueueId()],
      );
      await client.query('COMMIT');

      if (inserted.rows[0]) {
        return { status: 'QUEUED', entry: toEntry(inserted.rows[0]) };
      }
      // Conflict: this session already holds a place. Return the existing one.
      const existing = await this.getBySession(input.eventId, input.sessionId);
      if (!existing) throw new Error(`Queue join conflicted but no entry exists for ${input.sessionId}`);
      return { status: 'ALREADY_QUEUED', entry: existing };
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async getBySession(eventId: string, sessionId: string): Promise<QueueEntry | null> {
    const result = await this.#pool.query(
      `SELECT id, event_id, session_id, user_id, queue_id, position, status, joined_at, admitted_at
         FROM ${this.#table} WHERE event_id = $1 AND session_id = $2 LIMIT 1`,
      [eventId, sessionId],
    );
    return result.rows[0] ? toEntry(result.rows[0]) : null;
  }

  async getByQueueId(queueId: string): Promise<QueueEntry | null> {
    const result = await this.#pool.query(
      `SELECT id, event_id, session_id, user_id, queue_id, position, status, joined_at, admitted_at
         FROM ${this.#table} WHERE queue_id = $1 LIMIT 1`,
      [queueId],
    );
    return result.rows[0] ? toEntry(result.rows[0]) : null;
  }

  /**
   * Promote the next `limit` waiters.
   *
   * `FOR UPDATE SKIP LOCKED` is the key: two sweepers running concurrently take
   * disjoint sets of rows instead of blocking on each other and then double
   * counting. The UPDATE's WHERE clause still re-checks status, so a row another
   * sweeper already promoted is not promoted again even if it was read first.
   */
  async promote(eventId: string, limit: number): Promise<readonly QueueEntry[]> {
    const result = await this.#pool.query(
      `WITH candidates AS (
         SELECT id FROM ${this.#table}
          WHERE event_id = $1 AND status = 'WAITING'
          ORDER BY position ASC
          LIMIT $2
          FOR UPDATE SKIP LOCKED
       )
       UPDATE ${this.#table} q
          SET status = 'ADMITTED', admitted_at = now()
         FROM candidates c
        WHERE q.id = c.id AND q.status = 'WAITING'
       RETURNING q.id, q.event_id, q.session_id, q.user_id, q.queue_id, q.position, q.status, q.joined_at, q.admitted_at`,
      [eventId, limit],
    );
    return result.rows.map(toEntry);
  }

  async markLeft(eventId: string, sessionId: string): Promise<boolean> {
    const result = await this.#pool.query(
      `UPDATE ${this.#table} SET status = 'LEFT', left_at = now()
        WHERE event_id = $1 AND session_id = $2 AND status IN ('WAITING','ADMITTED')`,
      [eventId, sessionId],
    );
    return (result.rowCount ?? 0) > 0;
  }

  async size(eventId: string): Promise<number> {
    const result = await this.#pool.query<{ count: string }>(
      `SELECT COUNT(*)::text AS count FROM ${this.#table} WHERE event_id = $1 AND status = 'WAITING'`,
      [eventId],
    );
    return Number(result.rows[0]?.count ?? 0);
  }

  async aheadOf(eventId: string, position: number): Promise<number> {
    const result = await this.#pool.query<{ count: string }>(
      `SELECT COUNT(*)::text AS count FROM ${this.#table}
        WHERE event_id = $1 AND status = 'WAITING' AND position < $2`,
      [eventId, position],
    );
    return Number(result.rows[0]?.count ?? 0);
  }
}

type QueueRow = {
  event_id: string;
  session_id: string;
  user_id: string | null;
  queue_id: string;
  position: string | number;
  status: QueueStatus;
  joined_at: Date | string;
  admitted_at: Date | string | null;
};

function toEntry(row: QueueRow): QueueEntry {
  return {
    queueId: row.queue_id,
    eventId: row.event_id,
    sessionId: row.session_id,
    userId: row.user_id,
    position: Number(row.position),
    status: row.status,
    joinedAt: row.joined_at instanceof Date ? row.joined_at.toISOString() : new Date(row.joined_at).toISOString(),
    admittedAt: row.admitted_at
      ? row.admitted_at instanceof Date
        ? row.admitted_at.toISOString()
        : new Date(row.admitted_at).toISOString()
      : null,
  };
}

/**
 * Grant admission slots, atomically.
 *
 * KEYS[1] bucket
 * ARGV[1] now(ms) ARGV[2] capacity ARGV[3] refillPerSecond
 * ARGV[4] maxWanted ARGV[5] ttlSeconds
 * returns granted
 *
 * The script decides how many admissions this caller may perform and deducts
 * them in the same indivisible step. Doing the read and the deduction from the
 * client would let two sweepers both see a full bucket and together admit double
 * the configured rate — which is precisely the traffic spike the queue exists to
 * absorb.
 */
const ADMIT_BUCKET_SCRIPT = `
local key       = KEYS[1]
local now      = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local refill   = tonumber(ARGV[3])
local want     = tonumber(ARGV[4])
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

local granted = math.floor(tokens)
if granted > want then granted = want end
if granted < 0 then granted = 0 end

tokens = tokens - granted
redis.call('HSET', key, 'tokens', tokens, 'updatedAt', now)
redis.call('EXPIRE', key, ttl)
return granted
`;

/* ------------------------------------------------------------- orchestration */

export interface VirtualQueueOptions {
  readonly store: QueueStore;
  readonly codec: AdmissionTokenCodec;
  readonly redis: RedisLike;
  readonly keyPrefix: string;
  readonly now: () => number;
  readonly policy?: QueuePolicy;
  /** Active-session count per event, supplied by Person 1's booking engine. */
  readonly activeSessionCount: (eventId: string) => Promise<number>;
}

export class VirtualQueue {
  readonly #store: QueueStore;
  readonly #codec: AdmissionTokenCodec;
  readonly #redis: RedisLike;
  readonly #prefix: string;
  readonly #now: () => number;
  readonly #policy: QueuePolicy;
  readonly #activeSessionCount: (eventId: string) => Promise<number>;

  constructor(options: VirtualQueueOptions) {
    this.#store = options.store;
    this.#codec = options.codec;
    this.#redis = options.redis;
    this.#prefix = options.keyPrefix;
    this.#now = options.now;
    this.#policy = options.policy ?? DEFAULT_QUEUE_POLICY;
    this.#activeSessionCount = options.activeSessionCount;
  }

  /** Whether the event is hot enough to require a queue place. */
  async isQueueActive(eventId: string): Promise<boolean> {
    const queued = await this.#store.size(eventId);
    if (queued > 0) return true;
    try {
      return (await this.#activeSessionCount(eventId)) >= this.#policy.activationThreshold;
    } catch {
      // If the booking engine cannot tell us how busy it is, do not invent a
      // queue. Falsely gating a calm event is a worse failure than briefly
      // letting a hot one through, which the rate limiter still covers.
      return false;
    }
  }

  async join(input: {
    readonly eventId: string;
    readonly sessionId: string;
    readonly userId?: string | undefined;
  }): Promise<{ status: 'QUEUED' | 'ALREADY_QUEUED'; queueId: string; position: number }> {
    const result = await this.#store.join(input);
    return {
      // Propagated from the store, not asserted here: whether this was a fresh
      // join is decided by the unique index, and re-reporting it as a new place
      // would tell a client it had moved up the queue when it had not.
      status: result.status,
      queueId: result.entry.queueId,
      position: result.entry.position,
    };
  }

  async status(eventId: string, sessionId: string): Promise<{
    readonly active: boolean;
    readonly entry: QueueEntry | null;
    readonly ahead: number;
    readonly size: number;
    readonly estimatedWaitSeconds: number;
  }> {
    const [entry, size, active] = await Promise.all([
      this.#store.getBySession(eventId, sessionId),
      this.#store.size(eventId),
      this.isQueueActive(eventId),
    ]);
    if (!entry) {
      return { active, entry: null, ahead: 0, size, estimatedWaitSeconds: 0 };
    }
    const ahead = await this.#store.aheadOf(eventId, entry.position);
    return {
      active,
      entry,
      ahead,
      size,
      // Purely informational. The client must not treat this as an authorisation
      // to proceed; admission is decided by promote() and the token.
      estimatedWaitSeconds: Math.ceil((ahead / this.#policy.admissionRate) * this.#policy.admissionWindowSeconds),
    };
  }

  /**
   * Promote as many waiters as the admission rate currently allows.
   *
   * The rate is a Redis token bucket rather than a per-instance counter, so
   * several sweepers together admit only the configured rate. Slots are claimed
   * atomically BEFORE any row is promoted, and rows are then taken with SKIP
   * LOCKED, so a slot is never claimed without a matching row and a row is never
   * promoted twice.
   */
  async admitNext(eventId: string, requested = this.#policy.admissionRate): Promise<readonly AdmissionToken[]> {
    const capacity = this.#policy.admissionRate;
    const refillPerSecond = capacity / this.#policy.admissionWindowSeconds;

    const grantedRaw = await this.#redis.eval(
      ADMIT_BUCKET_SCRIPT,
      [`${this.#prefix}queue:admit:${eventId}`],
      [
        this.#now(),
        capacity,
        refillPerSecond,
        requested,
        Math.ceil(this.#policy.admissionWindowSeconds * 2),
      ],
    );
    const granted = Math.max(0, Math.floor(Number(grantedRaw)));
    if (granted === 0) return [];

    const promoted = await this.#store.promote(eventId, granted);
    const now = this.#now();
    // Tokens are issued only for rows this call actually promoted, so two racing
    // sweepers can never hand out two tokens for the same place.
    return promoted.map((entry) => this.#codec.issue(entry, now));
  }

  /**
   * The gate. Every protected route calls this, and a missing or invalid token is
   * a hard rejection — this is the check that makes the queue real.
   */
  assertAdmitted(
    token: AdmissionToken | null,
    context: { readonly eventId: string; readonly sessionId: string },
  ): void {
    if (!token) {
      throw new SecurityError('QUEUE_BYPASS_ATTEMPT', 'No admission token presented', {
        publicMessage: 'Admission could not be verified.',
      });
    }
    const result = this.#codec.verify(token, { ...context, now: this.#now() });
    if (!result.valid) {
      throw new SecurityError('QUEUE_BYPASS_ATTEMPT', `Admission token rejected: ${result.reason}`, {
        publicDetails: { reason: 'admission token is not valid for this request' },
      });
    }
  }

  async leave(eventId: string, sessionId: string): Promise<boolean> {
    return this.#store.markLeft(eventId, sessionId);
  }
}
