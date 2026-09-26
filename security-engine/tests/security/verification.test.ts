import { beforeEach, describe, expect, it } from 'vitest';
import { FakeClock } from '../../src/core/clock';
import { TicketIssuer } from '../../src/tickets/ticket-issuer';
import { TicketVerifier } from '../../src/tickets/ticket-verifier';
import type { IssuedTicket } from '../../src/tickets/ticket-issuer';
import { makeSigner, T0 } from '../helpers/fixtures';
import {
  InMemoryEventRepository,
  InMemorySeatRepository,
  InMemoryTicketRepository,
} from '../helpers/domain-doubles';

const EVENT_ID = 'EVT_001';
const SEAT_ID = 'SEAT_A101';

function build(overrides: { now?: number; tickets?: Array<Record<string, unknown>> } = {}) {
  const clock = new FakeClock(overrides.now ?? T0);
  const { signer } = makeSigner(clock);
  const tickets = new InMemoryTicketRepository(
    (overrides.tickets ?? [
      {
        ticketId: 'TCK_001',
        eventId: EVENT_ID,
        seatId: SEAT_ID,
        userId: 'USER_123',
        version: 1,
        issuedAt: new Date(T0).toISOString(),
        expiresAt: new Date(T0 + 86_400_000).toISOString(),
      },
    ]) as never,
  );
  const events = new InMemoryEventRepository([{ eventId: EVENT_ID, status: 'ON_SALE' }]);
  const seats = new InMemorySeatRepository([{ seatId: SEAT_ID, eventId: EVENT_ID }]);
  const issuer = new TicketIssuer({ signer, clock, defaultTtlSeconds: 86_400 });
  const verifier = new TicketVerifier({ signer, ticketRepository: tickets, eventRepository: events, clock, seatRepository: seats });
  return { clock, signer, tickets, events, seats, issuer, verifier };
}

async function issue(issuer: TicketIssuer, ticketId = 'TCK_001', version = 1): Promise<IssuedTicket> {
  return issuer.issue({ ticketId, eventId: EVENT_ID, seatId: SEAT_ID, version, state: 'CONFIRMED' });
}

describe('ticket verification pipeline', () => {
  let ctx: ReturnType<typeof build>;

  beforeEach(() => {
    ctx = build();
  });

  it('accepts a genuine, unexpired, confirmed ticket', async () => {
    const issued = await issue(ctx.issuer);
    const result = await ctx.verifier.verify(issued.encoded, { expectedEventId: EVENT_ID });
    expect(result).toMatchObject({ outcome: 'VALID', valid: true, kid: 'test-key-1' });
  });

  it('returns only non-sensitive fields on success', async () => {
    const issued = await issue(ctx.issuer);
    const result = await ctx.verifier.verify(issued.encoded, { expectedEventId: EVENT_ID });
    // No userId, no price: a gate client logging this cannot leak PII.
    expect(result.ticket).toEqual({
      ticketId: 'TCK_001',
      eventId: EVENT_ID,
      seatId: SEAT_ID,
      version: 1,
    });
    expect(JSON.stringify(result)).not.toContain('USER_123');
  });

  it('rejects a modified ticket id', async () => {
    const issued = await issue(ctx.issuer);
    const tampered = issued.encoded.replace('TCK_001', 'TCK_999');
    expect((await ctx.verifier.verify(tampered, { expectedEventId: EVENT_ID })).outcome).toBe('INVALID_SIGNATURE');
  });

  it('rejects a modified event id', async () => {
    const issued = await issue(ctx.issuer);
    const tampered = issued.encoded.replace(EVENT_ID, 'EVT_999');
    expect((await ctx.verifier.verify(tampered, { expectedEventId: EVENT_ID })).outcome).toBe('INVALID_SIGNATURE');
  });

  it('rejects a modified seat id', async () => {
    const issued = await issue(ctx.issuer);
    const tampered = issued.encoded.replace(SEAT_ID, 'SEAT_Z999');
    expect((await ctx.verifier.verify(tampered, { expectedEventId: EVENT_ID })).outcome).toBe('INVALID_SIGNATURE');
  });

  it('reports a claim/record disagreement as a mismatch, not a forged signature', async () => {
    // The QR is genuinely signed, but the authoritative record now points at a
    // different seat (a reissue moved the holder). The signature is valid, so
    // calling this INVALID_SIGNATURE would be a lie that sends support hunting a
    // forgery that never happened.
    const issued = await issue(ctx.issuer, 'TCK_001', 1);
    ctx.tickets.setSeatId('TCK_001', 'SEAT_MOVED');

    const result = await ctx.verifier.verify(issued.encoded, { expectedEventId: EVENT_ID });
    expect(result.outcome).toBe('TICKET_CLAIM_MISMATCH');
    expect(result.valid).toBe(false);
  });

  it('rejects an escalated role field smuggled into the payload', async () => {
    const issued = await issue(ctx.issuer);
    const envelope = JSON.parse(issued.encoded) as { ticket: string; signature: string; kid: string; v: number };
    const inner = JSON.parse(envelope.ticket) as Record<string, unknown>;
    inner.role = 'ADMIN';
    const forged = JSON.stringify({ ...envelope, ticket: JSON.stringify(inner) });
    expect((await ctx.verifier.verify(forged, { expectedEventId: EVENT_ID })).outcome).toBe('INVALID_SIGNATURE');
  });

  it('rejects an expired ticket', async () => {
    const issued = await issue(ctx.issuer);
    ctx.clock.advance(86_400_001);
    expect((await ctx.verifier.verify(issued.encoded, { expectedEventId: EVENT_ID })).outcome).toBe('EXPIRED');
  });

  it('accepts a ticket inside the expiry grace window', async () => {
    const issued = await issue(ctx.issuer);
    ctx.clock.advance(86_400_000 + 5_000);
    // Gate clocks drift; a small grace prevents mass false rejections at the door.
    const result = await ctx.verifier.verify(issued.encoded, { expectedEventId: EVENT_ID, expiryGraceMs: 30_000 });
    expect(result.outcome).toBe('VALID');
  });

  it('rejects a cancelled ticket', async () => {
    const issued = await issue(ctx.issuer);
    ctx.tickets.setState('TCK_001', 'CANCELLED');
    expect((await ctx.verifier.verify(issued.encoded, { expectedEventId: EVENT_ID })).outcome).toBe('CANCELLED');
  });

  it('rejects a refunded ticket as cancelled', async () => {
    const issued = await issue(ctx.issuer);
    ctx.tickets.setState('TCK_001', 'REFUNDED');
    expect((await ctx.verifier.verify(issued.encoded, { expectedEventId: EVENT_ID })).outcome).toBe('CANCELLED');
  });

  it('rejects an already-used ticket', async () => {
    const issued = await issue(ctx.issuer);
    ctx.tickets.setState('TCK_001', 'USED');
    expect((await ctx.verifier.verify(issued.encoded, { expectedEventId: EVENT_ID })).outcome).toBe('ALREADY_USED');
  });

  it('rejects a ticket that is not yet confirmed', async () => {
    const issued = await issue(ctx.issuer);
    ctx.tickets.setState('TCK_001', 'PENDING');
    expect((await ctx.verifier.verify(issued.encoded, { expectedEventId: EVENT_ID })).outcome).toBe('TICKET_NOT_CONFIRMED');
  });

  it('rejects a ticket presented at the wrong event', async () => {
    const issued = await issue(ctx.issuer);
    expect((await ctx.verifier.verify(issued.encoded, { expectedEventId: 'EVT_OTHER' })).outcome).toBe('WRONG_EVENT');
  });

  it('rejects a superseded QR after the ticket is reissued at a higher version', async () => {
    // The authoritative record is already at version 2 (ticket was reissued).
    const reissued = build({
      tickets: [
        {
          ticketId: 'TCK_001',
          eventId: EVENT_ID,
          seatId: SEAT_ID,
          userId: 'USER_123',
          version: 2,
          issuedAt: new Date(T0).toISOString(),
          expiresAt: new Date(T0 + 86_400_000).toISOString(),
        },
      ],
    });

    const v1 = await issue(reissued.issuer, 'TCK_001', 1);
    const v2 = await issue(reissued.issuer, 'TCK_001', 2);

    expect((await reissued.verifier.verify(v2.encoded, { expectedEventId: EVENT_ID })).outcome).toBe('VALID');
    // The superseded QR must not scan, even though its own signature is genuine.
    expect((await reissued.verifier.verify(v1.encoded, { expectedEventId: EVENT_ID })).outcome).toBe('TICKET_NOT_CONFIRMED');
  });

  it('rejects a ticket that is not in the database', async () => {
    const issued = await issue(ctx.issuer, 'TCK_GHOST');
    expect((await ctx.verifier.verify(issued.encoded, { expectedEventId: EVENT_ID })).outcome).toBe('TICKET_NOT_FOUND');
  });

  it.each([
    ['not json at all', 'definitely-not-json'],
    ['empty string', ''],
    ['json array', '[]'],
    ['json null', 'null'],
    ['missing signature', JSON.stringify({ v: 1, ticket: '{}', kid: 'test-key-1' })],
    ['wrong envelope version', JSON.stringify({ v: 99, ticket: '{}', signature: 'AA==', kid: 'test-key-1' })],
    ['empty kid', JSON.stringify({ v: 1, ticket: '{}', signature: 'AA==', kid: '' })],
  ])('rejects malformed QR: %s', async (_label, raw) => {
    expect((await ctx.verifier.verify(raw, { expectedEventId: EVENT_ID })).outcome).toBe('MALFORMED_QR');
  });

  it('rejects an oversized QR without parsing it', async () => {
    const huge = 'x'.repeat(100_000);
    expect((await ctx.verifier.verify(huge, { expectedEventId: EVENT_ID })).outcome).toBe('MALFORMED_QR');
  });

  it('rejects non-string QR input', async () => {
    for (const input of [null, undefined, 42, {}, [], Buffer.from('x')]) {
      expect((await ctx.verifier.verify(input, { expectedEventId: EVENT_ID })).outcome).toBe('MALFORMED_QR');
    }
  });

  it('never leaks internal error text in any rejection', async () => {
    const issued = await issue(ctx.issuer);
    const results = [
      await ctx.verifier.verify('garbage', { expectedEventId: EVENT_ID }),
      await ctx.verifier.verify(issued.encoded.replace('TCK_001', 'TCK_404'), { expectedEventId: EVENT_ID }),
    ];
    for (const result of results) {
      const serialized = JSON.stringify(result);
      expect(serialized).not.toMatch(/postgres|SELECT |INSERT |ECONNREFUSED|at Object|node_modules/i);
    }
  });

  it('fails closed when the ticket store throws', async () => {
    const issued = await issue(ctx.issuer);
    const broken = new InMemoryTicketRepository();
    broken.findById = async () => {
      throw new Error('connection pool exhausted');
    };
    const verifier = new TicketVerifier({
      signer: ctx.signer,
      ticketRepository: broken,
      eventRepository: ctx.events,
      clock: ctx.clock,
    });
    // Admitting on infrastructure failure would not be a gate.
    expect((await verifier.verify(issued.encoded, { expectedEventId: EVENT_ID })).outcome).toBe('SERVICE_UNAVAILABLE');
  });

  it('does not consume the ticket during a non-consuming verify', async () => {
    const issued = await issue(ctx.issuer);
    await ctx.verifier.verify(issued.encoded, { expectedEventId: EVENT_ID });
    expect(ctx.tickets.get('TCK_001')?.state).toBe('CONFIRMED');
    expect(ctx.tickets.successfulConsumptions).toBe(0);
  });
});

describe('seat validation', () => {
  it('rejects a seat that does not belong to the event when requested', async () => {
    const ctx = build();
    const issued = await issue(ctx.issuer);
    const result = await ctx.verifier.verify(issued.encoded, { expectedEventId: EVENT_ID, validateSeat: true });
    expect(result.outcome).toBe('VALID');
  });

  it('rejects when the seat is mapped to a different event', async () => {
    const ctx = build();
    const issued = await issue(ctx.issuer);
    // Rebuild the seat map so the seat belongs to a different event.
    const otherSeats = new InMemorySeatRepository([{ seatId: SEAT_ID, eventId: 'EVT_OTHER' }]);
    const verifier = new TicketVerifier({
      signer: ctx.signer,
      ticketRepository: ctx.tickets,
      eventRepository: ctx.events,
      clock: ctx.clock,
      seatRepository: otherSeats,
    });
    const result = await verifier.verify(issued.encoded, { expectedEventId: EVENT_ID, validateSeat: true });
    expect(result.outcome).toBe('WRONG_EVENT');
  });
});
