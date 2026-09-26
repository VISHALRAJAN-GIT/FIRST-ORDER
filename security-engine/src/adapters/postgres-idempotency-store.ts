/**
 * Postgres-backed durable mirror for idempotency records (Part 14).
 *
 * ## Why this exists separately from `RedisIdempotencyStore`
 *
 * Redis coordinates; this remembers. The coordination key has a TTL by design —
 * a permanently stuck idempotency key is a self-inflicted outage — but the record
 * of a completed charge must outlive it. Without this table, a duplicate arriving
 * after the window replays nothing and re-executes, which is the duplicate charge
 * the whole feature exists to prevent.
 *
 * ## The write is an upsert, deliberately
 *
 * `upsert` is not a convenience. Two workers can reach completion for the same key
 * when one overruns its claim TTL, and the second write must not fail on the
 * unique constraint or the original caller would see an error after its booking
 * had already succeeded. Last writer wins on identical (key, endpoint), which is
 * correct because both describe the same logical operation.
 *
 * What it must NOT do is let a different request overwrite a stored result, so the
 * conflict clause is guarded on `request_hash`. A key reused with a new payload is
 * rejected by `claim` before it ever reaches here, and the guard makes that
 * guarantee hold even if a caller reaches the mirror directly.
 *
 * ## Expiry is stored, not inferred
 *
 * `expires_at` is written rather than computed from a TTL at read time, so the
 * retention sweep is a plain indexed range scan and cannot drift from the policy
 * that was in force when the record was written.
 */

import type { Pool } from 'pg';
import type { IdempotencyRecord, IdempotencyStore, ClaimResult } from '../ports/idempotency-store';
import type { IdempotentResponse } from '../ports/idempotency-store';

interface IdempotencyRow {
  idempotency_key: string;
  endpoint: string;
  request_hash: string;
  state: 'PROCESSING' | 'SUCCESS' | 'FAILED';
  response_status: number | null;
  response_body: unknown;
  created_at: Date;
  updated_at: Date;
}

function toRecord(row: IdempotencyRow): IdempotencyRecord {
  const response: IdempotentResponse | undefined =
    row.response_status === null
      ? undefined
      : { status: row.response_status, body: row.response_body };

  return {
    key: row.idempotency_key,
    endpoint: row.endpoint,
    state: row.state,
    requestHash: row.request_hash,
    response,
    createdAt: row.created_at.toISOString(),
    completedAt: response ? row.updated_at.toISOString() : undefined,
  };
}

export interface PostgresIdempotencyStoreOptions {
  readonly pool: Pool;
  readonly table?: string;
  /** Retention for stored records. Must be >= the coordination TTL. */
  readonly retentionSeconds?: number;
  /**
   * Called when a record could not be read or written.
   *
   * Reads are best-effort by design: a duplicate that cannot see the mirror
   * degrades to the Redis path rather than failing the request. Writes are
   * reported too, because a silently lost completion is how a duplicate charge
   * happens later, and an operator needs to see it.
   */
  readonly onError?: (operation: 'get' | 'upsert', error: unknown) => void;
}

export class PostgresIdempotencyStore implements IdempotencyStore {
  readonly #pool: Pool;
  readonly #table: string;
  readonly #retentionSeconds: number;
  readonly #onError: PostgresIdempotencyStoreOptions['onError'];

  constructor(options: PostgresIdempotencyStoreOptions) {
    this.#pool = options.pool;
    this.#table = options.table ?? 'idempotency_records';
    this.#retentionSeconds = options.retentionSeconds ?? 86_400;
    this.#onError = options.onError;
  }

  async get(key: string, endpoint: string): Promise<IdempotencyRecord | null> {
    try {
      const { rows } = await this.#pool.query<IdempotencyRow>(
        `SELECT idempotency_key, endpoint, request_hash, state, response_status,
                response_body, created_at, updated_at
           FROM ${this.#table}
          WHERE idempotency_key = $1
            AND endpoint = $2
            AND expires_at > now()`,
        [key, endpoint],
      );
      return rows[0] ? toRecord(rows[0]) : null;
    } catch (error) {
      this.#onError?.('get', error);
      // Degrade to "no durable record" rather than propagating: the Redis
      // coordination path still prevents concurrent double execution, and failing
      // a read here would turn a telemetry-side problem into an outage.
      return null;
    }
  }

  async upsert(record: IdempotencyRecord): Promise<void> {
    const ttl = this.#retentionSeconds;
    try {
      await this.#pool.query(
        `INSERT INTO ${this.#table}
           (idempotency_key, endpoint, request_hash, state, response_status,
            response_body, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7::timestamptz, now()), now() + ($8 || ' seconds')::interval)
         ON CONFLICT (idempotency_key, endpoint) DO UPDATE
            SET state           = EXCLUDED.state,
                response_status = EXCLUDED.response_status,
                response_body   = EXCLUDED.response_body,
                expires_at      = EXCLUDED.expires_at
          WHERE idempotency_records.request_hash = EXCLUDED.request_hash`,
        [
          record.key,
          record.endpoint,
          record.requestHash,
          record.state,
          record.response?.status ?? null,
          record.response === undefined ? null : JSON.stringify(record.response.body),
          record.createdAt,
          String(ttl),
        ],
      );
    } catch (error) {
      this.#onError?.('upsert', error);
      // Swallowed on purpose. This mirror backs up a guarantee that Redis already
      // enforces for the live window; failing the caller's request here would
      // break bookings during a database hiccup. The lost record is reported via
      // onError and is visible to operations.
    }
  }

  /**
   * Redis-only coordination with a Postgres mirror.
   *
   * `claim` is deliberately NOT implemented here: mutual exclusion is the Redis
   * store's job, and a Postgres implementation of it would be a second, weaker
   * version of the same primitive. Callers get the composition instead.
   *
   * `async` so misuse surfaces as a rejected promise rather than a synchronous
   * throw — a caller that forgets to `await` should still get a catchable error
   * instead of an exception from an unrelated line.
   */
  async claim(input: {
    readonly key: string;
    readonly endpoint: string;
    readonly requestHash: string;
    readonly ttlSeconds: number;
  }): Promise<ClaimResult> {
    void input;
    throw new Error(
      'PostgresIdempotencyStore is a durable mirror. Compose it with RedisIdempotencyStore via its durable option rather than calling claim directly.',
    );
  }

  async complete(): Promise<void> {
    throw new Error(
      'PostgresIdempotencyStore is a durable mirror. Completion is coordinated by RedisIdempotencyStore.',
    );
  }

  /**
   * Delete records past their retention.
   *
   * Exposed because retention has to actually happen: an append-only
   * idempotency table grows without bound otherwise, and the table is a
   * liability as much as an asset because it records what was bought.
   */
  async purgeExpired(limit = 1_000): Promise<number> {
    const { rowCount } = await this.#pool.query(
      `DELETE FROM ${this.#table} WHERE id IN (SELECT id FROM ${this.#table} WHERE expires_at <= now() LIMIT $1)`,
      [limit],
    );
    return rowCount ?? 0;
  }
}
