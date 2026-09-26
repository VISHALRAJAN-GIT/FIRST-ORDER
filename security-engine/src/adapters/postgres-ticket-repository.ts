/**
 * Reference Postgres adapter for `TicketRepository`.
 *
 * ## Why this file exists in the security engine
 *
 * `consumeConfirmedTicket` is the one place in the whole project where a subtle
 * implementation mistake produces a real-world security failure: two people walk
 * through the same gate on one ticket. The contract in
 * `src/ports/ticket-repository.ts` states the requirement, but a comment is not
 * an implementation.
 *
 * So this adapter is both:
 *
 *   1. the reference implementation Person 1 should adapt for their ticket model,
 *      and
 *   2. the code exercised by `tests/concurrency/ticket-scan-race.test.ts` against
 *      a real Postgres, which is what actually demonstrates that the SQL is
 *      atomic under contention.
 *
 * The table name is injected rather than hardcoded so the adapter can be pointed
 * at Person 1's `tickets` table, at a differently-named equivalent, or at a
 * stand-in fixture table in tests.
 */

import type { Pool, QueryResultRow } from 'pg';
import type {
  ConsumeOutcome,
  TicketConsumptionContext,
  TicketRecord,
  TicketRepository,
  TicketState,
} from '../ports/ticket-repository';

export interface PostgresTicketRepositoryOptions {
  readonly pool: Pool;
  /** Physical table backing the ticket store. Identifiers cannot be bound. */
  readonly tableName: string;
  /** Schema, when not `public`. */
  readonly schema?: string;
}

interface TicketRow extends QueryResultRow {
  id: string;
  event_id: string;
  seat_id: string;
  user_id: string;
  state: string;
  version: number;
  issued_at: Date | string;
  expires_at: Date | string;
  used_at: Date | string | null;
}

function toIso(value: Date | string): string {
  return value instanceof Date ? value.toISOString() : new Date(value).toISOString();
}

function toRecord(row: TicketRow): TicketRecord {
  return {
    ticketId: String(row.id),
    eventId: String(row.event_id),
    seatId: String(row.seat_id),
    userId: String(row.user_id),
    state: String(row.state) as TicketState,
    version: Number(row.version),
    issuedAt: toIso(row.issued_at),
    expiresAt: toIso(row.expires_at),
    usedAt: row.used_at ? toIso(row.used_at) : null,
  };
}

/**
 * Reject anything that is not a plain SQL identifier.
 *
 * The table name cannot be a bind parameter, so it is interpolated. This check
 * is what makes that safe: it arrives from configuration, never from a request,
 * and it still refuses anything with a quote, semicolon, comment marker or
 * whitespace in it.
 */
function assertSafeIdentifier(value: string, label: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_$]*$/.test(value)) {
    throw new Error(`Unsafe ${label} for SQL interpolation: ${JSON.stringify(value)}`);
  }
  return value;
}

export class PostgresTicketRepository implements TicketRepository {
  readonly #pool: Pool;
  readonly #qualifiedTable: string;

  constructor(options: PostgresTicketRepositoryOptions) {
    this.#pool = options.pool;
    const table = assertSafeIdentifier(options.tableName, 'table name');
    const schema = options.schema ? assertSafeIdentifier(options.schema, 'schema name') : 'public';
    this.#qualifiedTable = `"${schema}"."${table}"`;
  }

  async findById(ticketId: string): Promise<TicketRecord | null> {
    const result = await this.#pool.query<TicketRow>(
      `SELECT id, event_id, seat_id, user_id, state, version, issued_at, expires_at, used_at
         FROM ${this.#qualifiedTable}
        WHERE id = $1
        LIMIT 1`,
      [ticketId],
    );
    const row = result.rows[0];
    return row ? toRecord(row) : null;
  }

  /**
   * THE ATOMIC TRANSITION.
   *
   * A single conditional UPDATE whose affected-row count is the lock. Under any
   * isolation level Postgres guarantees that concurrent writers to the same row
   * are serialised: the first to commit sees the pre-update state and reports one
   * row affected, and every other transaction re-evaluates the WHERE clause
   * against the committed row, matches nothing, and reports zero.
   *
   * There is deliberately no SELECT before this statement. A read-then-write
   * would open a window between the two statements in which a second scanner
   * reads `CONFIRMED` and also believes it may proceed.
   *
   * `version = $2` is part of the predicate on purpose. It means a QR issued for
   * an older revision of the ticket cannot consume the current one, so a
   * superseded QR is rejected by the same mechanism that prevents replay.
   */
  async consumeConfirmedTicket(
    ticketId: string,
    expectedVersion: number,
    _context: TicketConsumptionContext,
  ): Promise<ConsumeOutcome> {
    const result = await this.#pool.query<TicketRow>(
      `UPDATE ${this.#qualifiedTable}
          SET state      = 'USED',
              used_at    = now(),
              updated_at = now()
        WHERE id      = $1
          AND state  = 'CONFIRMED'
          AND version = $2
      RETURNING id, event_id, seat_id, user_id, state, version, issued_at, expires_at, used_at`,
      [ticketId, expectedVersion],
    );

    if (result.rows.length === 1) {
      return { ok: true, ticket: toRecord(result.rows[0]!) };
    }

    // Zero rows affected. Only now do we pay for a read, to explain which of the
    // possible reasons applied. This path is the exception, not the hot path.
    const existing = await this.findById(ticketId);
    if (!existing) return { ok: false, reason: 'NOT_FOUND' };
    if (existing.state === 'USED') return { ok: false, reason: 'ALREADY_USED', ticket: existing };
    return { ok: false, reason: 'NOT_CONFIRMED', ticket: existing };
  }

  async saveSignedPayload(ticketId: string, envelope: string): Promise<void> {
    // The signed payload is derivable from the ticket record, so persisting it is
    // optional. Provided here for integrators who want to pin the exact bytes
    // that were issued; requires a `signed_payload` column.
    await this.#pool.query(
      `UPDATE ${this.#qualifiedTable} SET signed_payload = $2, updated_at = now() WHERE id = $1`,
      [ticketId, envelope],
    );
  }
}
