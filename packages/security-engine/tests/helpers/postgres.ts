/**
 * Postgres test harness.
 *
 * Creates a stand-in `tickets` table that mirrors the contract Person 1's
 * booking engine is expected to provide. It is a TEST FIXTURE, not part of the
 * security schema — the security engine never creates or alters it, exactly as
 * it never touches Person 1's real tables.
 *
 * Having a real table here is what lets tests/concurrency prove the atomic
 * CONFIRMED -> USED transition against Postgres rather than asserting it against
 * a mock that cannot fail the way a database can.
 */

import { Pool, type PoolClient } from 'pg';

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? 'postgres://postgres:postgres@127.0.0.1:5432/tixify';

/**
 * The minimum ticket table the security engine's contract requires.
 *
 * Person 1's real table will have more columns and a different name; what
 * matters is that these columns and this state machine exist, because the
 * security guarantee is expressed in terms of them.
 */
export const FIXTURE_TICKETS_DDL = `
  CREATE TABLE IF NOT EXISTS test_tickets (
    id             TEXT PRIMARY KEY,
    event_id       TEXT        NOT NULL,
    seat_id        TEXT        NOT NULL,
    user_id        TEXT        NOT NULL,
    state          TEXT        NOT NULL DEFAULT 'CONFIRMED',
    version        INTEGER     NOT NULL DEFAULT 1,
    issued_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    used_at        TIMESTAMPTZ NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    signed_payload TEXT        NULL
  );
`;

export async function createPool(max = 20): Promise<Pool> {
  const pool = new Pool({ connectionString: TEST_DATABASE_URL, max });
  await pool.query('SELECT 1');
  return pool;
}

export async function ensureFixtureTables(pool: Pool): Promise<void> {
  await pool.query(FIXTURE_TICKETS_DDL);
  await pool.query('CREATE INDEX IF NOT EXISTS test_tickets_event_idx ON test_tickets (event_id)');
}

export async function resetFixtureTables(pool: Pool): Promise<void> {
  await pool.query('TRUNCATE test_tickets');
}

export interface SeedTicketRow {
  id: string;
  eventId: string;
  seatId?: string;
  userId?: string;
  state?: string;
  version?: number;
  issuedAt?: string;
  expiresAt?: string;
}

export async function seedTickets(pool: Pool, rows: SeedTicketRow[]): Promise<void> {
  for (const row of rows) {
    await pool.query(
      `INSERT INTO test_tickets (id, event_id, seat_id, user_id, state, version, issued_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, COALESCE($7::timestamptz, now()), $8::timestamptz)`,
      [
        row.id,
        row.eventId,
        row.seatId ?? `SEAT_${row.id}`,
        row.userId ?? `USER_${row.id}`,
        row.state ?? 'CONFIRMED',
        row.version ?? 1,
        row.issuedAt ?? null,
        row.expiresAt ?? new Date(Date.now() + 86_400_000).toISOString(),
      ],
    );
  }
}

export async function getTicketRow(pool: Pool, id: string): Promise<Record<string, unknown> | undefined> {
  const result = await pool.query('SELECT * FROM test_tickets WHERE id = $1', [id]);
  return result.rows[0];
}

export async function withTransaction<T>(pool: Pool, fn: (client: PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

/** True when real Postgres is reachable, so suites can skip with a clear reason. */
export async function isPostgresAvailable(): Promise<boolean> {
  try {
    const pool = new Pool({ connectionString: TEST_DATABASE_URL, max: 1, connectionTimeoutMillis: 2_000 });
    await pool.query('SELECT 1');
    await pool.end();
    return true;
  } catch {
    return false;
  }
}
