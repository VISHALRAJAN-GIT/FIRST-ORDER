/**
 * Part 15 — Concurrency testing. MANDATORY.
 *
 * These are the tests that justify the claim "a ticket can only transition
 * CONFIRMED -> USED once". They run against a real Postgres, because an in-memory
 * double cannot fail the way a database fails: it cannot interleave two
 * transactions, cannot block on a row lock, and cannot make a read-then-write
 * implementation visibly wrong.
 *
 * Each test asserts an INVARIANT rather than a call count, because the invariant
 * is the actual security property. A read-then-write implementation passes any
 * test that only checks "the second call was rejected" when the calls are
 * sequential; it fails the moment they are not.
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';import type { Pool } from 'pg';
import { FakeClock } from '../../src/core/clock';
import { PostgresTicketRepository } from '../../src/adapters/postgres-ticket-repository';
import { TicketIssuer } from '../../src/tickets/ticket-issuer';
import { TicketVerifier } from '../../src/tickets/ticket-verifier';
import { ReplayGuard, type TicketScanRecord } from '../../src/replay/replay-guard';
import { makeSigner, T0 } from '../helpers/fixtures';
import { InMemoryEventRepository } from '../helpers/domain-doubles';
import {
  createPool,
  ensureFixtureTables,
  getTicketRow,
  isPostgresAvailable,
  resetFixtureTables,
  seedTickets,
} from '../helpers/postgres';

/**
 * Part 15 is a MANDATORY part of the specification, so this suite does not skip
 * itself when Postgres is unreachable — it fails. A silently skipped concurrency
 * suite is indistinguishable from a passing one in CI output, which is exactly how
 * an untested atomicity guarantee would reach production.
 */
describe('concurrency: ticket scan atomicity (Part 15)', () => {
  let pool: Pool;
  let repository: PostgresTicketRepository;
  let issuer: TicketIssuer;
  let verifier: TicketVerifier;
  let guard: ReplayGuard;
  const scans: TicketScanRecord[] = [];

  beforeAll(async () => {
    if (!(await isPostgresAvailable())) {
      throw new Error(
        'Postgres is required for the mandatory concurrency suite. Start it with ' +
          '`docker compose -f docker-compose.test.yml up -d postgres` and re-run.',
      );
    }
    pool = await createPool();
    await ensureFixtureTables(pool);
  });

  afterAll(async () => {
    await pool?.end();
  });

  beforeEach(async () => {
    await resetFixtureTables(pool);
    scans.length = 0;

    const clock = new FakeClock(T0);
    const { signer } = makeSigner(clock);
    repository = new PostgresTicketRepository({ pool, tableName: 'test_tickets' });
    issuer = new TicketIssuer({ signer, clock, defaultTtlSeconds: 86_400 });
    verifier = new TicketVerifier({
      signer,
      ticketRepository: repository,
      eventRepository: new InMemoryEventRepository([{ eventId: 'EVT_1' }]),
      clock,
    });
    guard = new ReplayGuard({
      verifier,
      ticketRepository: repository,
      clock,
      ledger: { record: async (record) => { scans.push(record); } },
    });
  });

  /**
   * Test 1 + 7: same ticket scanned simultaneously, and multiple QR scans.
   *
   * 50 concurrent scans of ONE ticket. The invariant: exactly one VALID.
   */
  it('allows exactly one success when 50 scanners hit the same ticket at once', async () => {
    await seedTickets(pool, [{ id: 'TCK_RACE', eventId: 'EVT_1', version: 1 }]);

    const issued = await issuer.issue({
      ticketId: 'TCK_RACE',
      eventId: 'EVT_1',
      seatId: 'SEAT_TCK_RACE',
      version: 1,
      state: 'CONFIRMED',
    });

    const results = await Promise.all(
      Array.from({ length: 50 }, (_unused, index) =>
        guard.scan({ qr: issued.encoded, eventId: 'EVT_1', scannerId: `GATE_${index}` }),
      ),
    );

    const successes = results.filter((result) => result.valid);
    const alreadyUsed = results.filter((result) => result.outcome === 'ALREADY_USED');

    // The security property. Not "about one", not "at least one" â€” exactly one.
    expect(successes).toHaveLength(1);
    expect(alreadyUsed).toHaveLength(49);
    expect(successes.length + alreadyUsed.length).toBe(50);

    // And the database agrees.
    const row = await getTicketRow(pool, 'TCK_RACE');
    expect(row?.state).toBe('USED');
    expect(row?.used_at).not.toBeNull();
  });

  /**
   * Test 1, harder: simultaneous scans through the raw repository, bypassing the
   * verifier entirely. This isolates the atomic UPDATE from all surrounding logic
   * and proves the SQL itself is the thing providing the guarantee.
   */
  it('admits exactly one winner across 100 concurrent raw consume calls', async () => {
    await seedTickets(pool, [{ id: 'TCK_RAW', eventId: 'EVT_1', version: 1 }]);

    const outcomes = await Promise.all(
      Array.from({ length: 100 }, () =>
        repository.consumeConfirmedTicket('TCK_RAW', 1, { eventId: 'EVT_1' }),
      ),
    );

    const ok = outcomes.filter((outcome) => outcome.ok);
    expect(ok).toHaveLength(1);
    expect(outcomes.filter((outcome) => !outcome.ok && outcome.reason === 'ALREADY_USED')).toHaveLength(99);
  });

  /**
   * Two scanners racing in separate transactions, which is what actually happens
   * when gate terminals are separate services with separate connection pools.
   */
  it('serialises two concurrent transactions on the same row', async () => {
    await seedTickets(pool, [{ id: 'TCK_TX', eventId: 'EVT_1', version: 1 }]);

    const results = await Promise.all([
      repository.consumeConfirmedTicket('TCK_TX', 1, { eventId: 'EVT_1' }),
      repository.consumeConfirmedTicket('TCK_TX', 1, { eventId: 'EVT_1' }),
    ]);

    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(results.filter((r) => !r.ok && r.reason === 'ALREADY_USED')).toHaveLength(1);
  });

  /** A QR whose version is stale must not consume the current ticket. */
  it('refuses a superseded version even when the ticket is still CONFIRMED', async () => {
    await seedTickets(pool, [{ id: 'TCK_VER', eventId: 'EVT_1', version: 3 }]);

    const issued = await issuer.issue({
      ticketId: 'TCK_VER',
      eventId: 'EVT_1',
      seatId: 'SEAT_TCK_VER',
      version: 1,
      state: 'CONFIRMED',
    });

    const result = await guard.scan({ qr: issued.encoded, eventId: 'EVT_1' });
    expect(result.valid).toBe(false);

    const row = await getTicketRow(pool, 'TCK_VER');
    expect(row?.state).toBe('CONFIRMED');
    expect(row?.used_at).toBeNull();
  });

  /**
   * Distinct tickets must NOT interfere. A replay guard that serialises
   * everything would pass the tests above while being unusable at a real gate.
   */
  it('allows fully parallel admission of distinct tickets', async () => {
    const ticketIds = Array.from({ length: 40 }, (_unused, index) => `TCK_P${index}`);
    await seedTickets(pool, ticketIds.map((id) => ({ id, eventId: 'EVT_1', version: 1 })));

    const issued = await Promise.all(
      ticketIds.map((ticketId) =>
        issuer.issue({ ticketId, eventId: 'EVT_1', seatId: `SEAT_${ticketId}`, version: 1, state: 'CONFIRMED' }),
      ),
    );

    const results = await Promise.all(
      issued.map((item) => guard.scan({ qr: item.encoded, eventId: 'EVT_1' })),
    );

    expect(results.filter((r) => r.valid)).toHaveLength(40);
  });

  /** Every attempt is recorded, accepted and rejected alike. */
  it('records every scan attempt in the ledger', async () => {
    await seedTickets(pool, [{ id: 'TCK_LEDGER', eventId: 'EVT_1', version: 1 }]);
    const issued = await issuer.issue({
      ticketId: 'TCK_LEDGER',
      eventId: 'EVT_1',
      seatId: 'SEAT_TCK_LEDGER',
      version: 1,
      state: 'CONFIRMED',
    });

    await Promise.all(
      Array.from({ length: 10 }, (_unused, index) =>
        guard.scan({ qr: issued.encoded, eventId: 'EVT_1', scannerId: `GATE_${index}` }),
      ),
    );

    expect(scans).toHaveLength(10);
    expect(scans.filter((scan) => scan.outcome === 'ACCEPTED')).toHaveLength(1);
    expect(scans.filter((scan) => scan.outcome === 'REJECTED')).toHaveLength(9);
  });

  /** An audit-write failure must not reject a legitimate scan. */
  it('still admits when the audit ledger is unavailable', async () => {
    await seedTickets(pool, [{ id: 'TCK_NOAUDIT', eventId: 'EVT_1', version: 1 }]);
    const issued = await issuer.issue({
      ticketId: 'TCK_NOAUDIT',
      eventId: 'EVT_1',
      seatId: 'SEAT_TCK_NOAUDIT',
      version: 1,
      state: 'CONFIRMED',
    });

    const fragileGuard = new ReplayGuard({
      verifier,
      ticketRepository: repository,
      clock: new FakeClock(T0),
      ledger: {
        record: async () => {
          throw new Error('audit database unreachable');
        },
      },
    });

    const result = await fragileGuard.scan({ qr: issued.encoded, eventId: 'EVT_1' });
    expect(result.valid).toBe(true);
  });

  it('reports NOT_FOUND without consuming anything', async () => {
    const issued = await issuer.issue({
      ticketId: 'TCK_MISSING',
      eventId: 'EVT_1',
      seatId: 'SEAT_TCK_MISSING',
      version: 1,
      state: 'CONFIRMED',
    });

    const result = await guard.scan({ qr: issued.encoded, eventId: 'EVT_1' });
    expect(result.outcome).toBe('TICKET_NOT_FOUND');
  });
});
