/**
 * Part 14 / Part 5 — the durable idempotency mirror against real Postgres.
 *
 * The durability guarantee is only as good as this table, so it is tested against
 * the real schema, including the CHECK constraints that make a partial write
 * impossible.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import type { Pool } from 'pg';
import { PostgresIdempotencyStore } from '../../src/adapters/postgres-idempotency-store';
import { RedisIdempotencyStore, fingerprintRequest } from '../../src/ports/idempotency-store';
import { wrapIoredis, type RedisLike } from '../../src/ports/redis';
import { createPool, isPostgresAvailable } from '../helpers/postgres';
import IORedis from 'ioredis';

const REDIS_URL = process.env.TEST_REDIS_URL ?? 'redis://127.0.0.1:6379';
const RUN_ID = `pim${Date.now().toString(36)}`;
const ENDPOINT = 'POST /api/bookings';

describe('Postgres idempotency mirror (Part 14)', () => {
  let pool: Pool;
  let redis: RedisLike;
  let raw: IORedis;

  beforeAll(async () => {
    if (!(await isPostgresAvailable())) throw new Error('Postgres is required for the idempotency mirror suite.');
    pool = await createPool();
    raw = new IORedis(REDIS_URL, { lazyConnect: true });
    await raw.connect();
    redis = wrapIoredis(raw as never);
  });

  afterAll(async () => {
    await pool?.query('TRUNCATE idempotency_records').catch(() => undefined);
    await pool?.end();
    await raw?.quit();
  });

  afterEach(async () => {
    await pool.query('TRUNCATE idempotency_records');
    for (const key of await redis.keys(`${RUN_ID}:*`)) await redis.delete(key);
  });

  const mirror = (retentionSeconds = 3_600) =>
    new PostgresIdempotencyStore({ pool, retentionSeconds });

  const hash = fingerprintRequest({ method: 'POST', path: '/api/bookings', body: { seatId: 'A1' } });

  const record = (overrides: Record<string, unknown> = {}) => ({
    key: 'k1',
    endpoint: ENDPOINT,
    state: 'SUCCESS' as const,
    requestHash: hash,
    response: { status: 201, body: { bookingId: 'B1' } },
    createdAt: '2026-01-01T00:00:00.000Z',
    completedAt: '2026-01-01T00:00:01.000Z',
    ...overrides,
  });

  it('stores and reads back a completed record', async () => {
    await mirror().upsert(record());
    const found = await mirror().get('k1', ENDPOINT);
    expect(found?.state).toBe('SUCCESS');
    expect(found?.response?.status).toBe(201);
    expect(found?.response?.body).toEqual({ bookingId: 'B1' });
    expect(found?.requestHash).toBe(hash);
  });

  it('preserves a null body in a stored response', async () => {
    await mirror().upsert(record({ response: { status: 204, body: null } }));
    const found = await mirror().get('k1', ENDPOINT);
    // A JSON null must survive as null rather than becoming undefined, or the
    // replayed response would differ from the original.
    expect(found?.response?.body).toBeNull();
  });

  it('returns null for an unknown key', async () => {
    expect(await mirror().get('nope', ENDPOINT)).toBeNull();
  });

  it('keeps endpoints isolated', async () => {
    await mirror().upsert(record());
    expect(await mirror().get('k1', 'POST /api/cancellations')).toBeNull();
  });

  it('upserts over an existing record rather than failing', async () => {
    const m = mirror();
    await m.upsert(record());
    // A second completion for the same key must not raise: the caller has already
    // succeeded and must not be handed an error afterwards.
    await expect(m.upsert(record({ response: { status: 201, body: { bookingId: 'B1_RETRY' } } }))).resolves.toBeUndefined();
    expect((await m.get('k1', ENDPOINT))?.response?.body).toEqual({ bookingId: 'B1_RETRY' });
  });

  /** A key reused with a different payload must not be overwritten. */
  it('refuses to overwrite a record made for a different request', async () => {
    const m = mirror();
    await m.upsert(record());
    const otherHash = fingerprintRequest({ method: 'POST', path: '/api/bookings', body: { seatId: 'OTHER' } });
    await m.upsert(record({ requestHash: otherHash, response: { status: 201, body: { bookingId: 'HIJACK' } } }));
    expect((await m.get('k1', ENDPOINT))?.requestHash).toBe(hash);
    expect((await m.get('k1', ENDPOINT))?.response?.body).toEqual({ bookingId: 'B1' });
  });

  it('stores an in-flight record without a response', async () => {
    await mirror().upsert(record({ state: 'PROCESSING', response: undefined, completedAt: undefined }));
    const found = await mirror().get('k1', ENDPOINT);
    expect(found?.state).toBe('PROCESSING');
    expect(found?.response).toBeUndefined();
  });

  it('enforces the completion constraint in the database', async () => {
    // A terminal state with no response would replay nothing, so the schema
    // refuses it rather than trusting every writer to be consistent.
    await expect(
      pool.query(
        `INSERT INTO idempotency_records
           (idempotency_key, endpoint, request_hash, state, expires_at)
         VALUES ('bad', $1, $2, 'SUCCESS', now() + interval '1 hour')`,
        [ENDPOINT, hash],
      ),
    ).rejects.toThrow();
  });

  it('does not return records past their retention', async () => {
    const m = mirror(3_600);
    await m.upsert(record());
    await pool.query("UPDATE idempotency_records SET expires_at = now() - interval '1 second'");
    expect(await m.get('k1', ENDPOINT)).toBeNull();
  });

  it('purges expired records', async () => {
    const m = mirror();
    await m.upsert(record());
    await m.upsert(record({ key: 'k2' }));
    expect(await m.purgeExpired()).toBe(0);
    await pool.query("UPDATE idempotency_records SET expires_at = now() - interval '1 second'");
    expect(await m.purgeExpired()).toBe(2);
    expect(await m.get('k1', ENDPOINT)).toBeNull();
  });

  it('degrades to a no-op on a write failure and reports it', async () => {
    const errors: string[] = [];
    const broken = new PostgresIdempotencyStore({
      pool: { query: async () => { throw new Error('ECONNREFUSED'); } } as never,
      onError: (op) => errors.push(op),
    });
    // A mirror outage must not fail a booking that already succeeded.
    await expect(broken.upsert(record())).resolves.toBeUndefined();
    expect(await broken.get('k1', ENDPOINT)).toBeNull();
    expect(errors).toContain('upsert');
    expect(errors).toContain('get');
  });

  it('refuses to be used as a coordinator', async () => {
    await expect(mirror().claim({ key: 'k', endpoint: ENDPOINT, requestHash: hash, ttlSeconds: 60 })).rejects.toThrow(
      /durable mirror/,
    );
  });

  /**
   * The end-to-end guarantee: a duplicate arriving after the coordination key has
   * expired replays from the mirror instead of executing again.
   */
  it('replays a duplicate after the Redis window closes, with no double execution', async () => {
    const m = mirror();
    const store = new RedisIdempotencyStore({ redis, keyPrefix: `${RUN_ID}:`, durable: m, nowIso: () => new Date().toISOString() });

    let executions = 0;
    const execute = async () => {
      const claim = await store.claim({ key: 'k1', endpoint: ENDPOINT, requestHash: hash, ttlSeconds: 300 });
      if (!claim.claimed) {
        if ('record' in claim && claim.record) return claim.record.response;
        throw new Error('unexpected in-flight');
      }
      executions += 1;
      const response = { status: 201, body: { bookingId: 'B1' } };
      await store.complete({ key: 'k1', endpoint: ENDPOINT, requestHash: hash, claimId: claim.claimId, state: 'SUCCESS', response });
      return response;
    };

    expect(await execute()).toEqual({ status: 201, body: { bookingId: 'B1' } });
    expect(executions).toBe(1);

    // The coordination key ages out; the durable record remains.
    for (const key of await redis.keys(`${RUN_ID}:*`)) await redis.delete(key);

    expect(await execute()).toEqual({ status: 201, body: { bookingId: 'B1' } });
    expect(executions).toBe(1);
  });

  /** The mirror must be consulted before a claim is honoured, not after. */
  it('blocks a re-execution when only the mirror remembers the result', async () => {
    const m = mirror();
    const store = new RedisIdempotencyStore({ redis, keyPrefix: `${RUN_ID}:`, durable: m, nowIso: () => new Date().toISOString() });
    await m.upsert(record());

    let executions = 0;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const claim = await store.claim({ key: 'k1', endpoint: ENDPOINT, requestHash: hash, ttlSeconds: 300 });
      if (claim.claimed) executions += 1;
    }
    expect(executions).toBe(0);
  });

  it('rejects a conflicting key reuse against the mirror', async () => {
    const m = mirror();
    const store = new RedisIdempotencyStore({ redis, keyPrefix: `${RUN_ID}:`, durable: m, nowIso: () => new Date().toISOString() });
    await m.upsert(record());

    const otherHash = fingerprintRequest({ method: 'POST', path: '/api/bookings', body: { seatId: 'DIFFERENT' } });
    expect(await store.claim({ key: 'k1', endpoint: ENDPOINT, requestHash: otherHash, ttlSeconds: 300 })).toEqual({
      claimed: false,
      inFlight: false,
      conflict: true,
    });
  });
});
