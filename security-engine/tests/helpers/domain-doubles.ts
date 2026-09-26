/**
 * In-memory doubles for the Person 1 domain ports.
 *
 * These stand in for the booking engine while it is being built in parallel.
 * They are deliberately written to the *same contract* as the real adapters, so
 * swapping in Person 1's implementation is a constructor change and nothing else.
 *
 * `InMemoryTicketRepository.consumeConfirmedTicket` implements the atomic
 * transition correctly *by construction* — it is a synchronous compare-and-set
 * inside an async function with no await between the read and the write, so no
 * interleaving is possible. That makes it a valid oracle for the verification
 * pipeline's own logic, but it is still not a proof of cross-process atomicity;
 * that comes from tests/concurrency against real Postgres.
 */

import type {
  ConsumeOutcome,
  TicketConsumptionContext,
  TicketRecord,
  TicketRepository,
  TicketState,
} from '../../src/ports/ticket-repository';
import type { EventRecord, EventRepository, EventStatus, SeatRepository } from '../../src/ports/event-repository';
import type { AuditSink } from '../../src/ports/event-repository';

export interface SeedTicket extends Omit<TicketRecord, 'state'> {
  state?: TicketState;
}

export class InMemoryTicketRepository implements TicketRepository {
  readonly #tickets = new Map<string, TicketRecord>();
  /** Count of successful consumptions, for invariant assertions. */
  successfulConsumptions = 0;
  consumeCallCount = 0;

  constructor(seed: SeedTicket[] = []) {
    for (const ticket of seed) {
      this.#tickets.set(ticket.ticketId, { ...ticket, state: ticket.state ?? 'CONFIRMED' });
    }
  }

  async findById(ticketId: string): Promise<TicketRecord | null> {
    return this.#tickets.get(ticketId) ?? null;
  }

  async consumeConfirmedTicket(
    ticketId: string,
    expectedVersion: number,
    _context: TicketConsumptionContext,
  ): Promise<ConsumeOutcome> {
    this.consumeCallCount += 1;
    const ticket = this.#tickets.get(ticketId);
    if (!ticket) return { ok: false, reason: 'NOT_FOUND' };
    if (ticket.state === 'USED') return { ok: false, reason: 'ALREADY_USED', ticket };
    if (ticket.state !== 'CONFIRMED') return { ok: false, reason: 'NOT_CONFIRMED', ticket };
    if (ticket.version !== expectedVersion) return { ok: false, reason: 'NOT_CONFIRMED', ticket };

    // Synchronous read-modify-write: no await above this line, so this is
    // atomic with respect to other callers in this process.
    const used: TicketRecord = { ...ticket, state: 'USED', usedAt: new Date().toISOString() };
    this.#tickets.set(ticketId, used);
    this.successfulConsumptions += 1;
    return { ok: true, ticket: used };
  }

  async saveSignedPayload(ticketId: string, _envelope: string): Promise<void> {
    if (!this.#tickets.has(ticketId)) throw new Error(`Unknown ticket: ${ticketId}`);
  }

  /** Test helper: force a state without going through consume. */
  setState(ticketId: string, state: TicketState): void {
    const ticket = this.#tickets.get(ticketId);
    if (!ticket) throw new Error(`Unknown ticket: ${ticketId}`);
    this.#tickets.set(ticketId, { ...ticket, state });
  }

  /**
   * Test helper: move a ticket to a different seat, simulating a reissue that
   * reassigns the holder while leaving the old QR's signature cryptographically
   * valid. Used to prove the claim/record mismatch is reported distinctly.
   */
  setSeatId(ticketId: string, seatId: string): void {
    const ticket = this.#tickets.get(ticketId);
    if (!ticket) throw new Error(`Unknown ticket: ${ticketId}`);
    this.#tickets.set(ticketId, { ...ticket, seatId });
  }

  get(ticketId: string): TicketRecord | undefined {
    return this.#tickets.get(ticketId);
  }
}

export class InMemoryEventRepository implements EventRepository {
  readonly #events = new Map<string, EventRecord>();
  readonly #activeCounts = new Map<string, number>();

  constructor(seed: Array<Partial<EventRecord> & { eventId: string }> = []) {
    for (const event of seed) {
      this.#events.set(event.eventId, {
        eventId: event.eventId,
        status: event.status ?? 'ON_SALE',
        name: event.name,
        venueId: event.venueId,
        startsAt: event.startsAt,
      });
    }
  }

  async findById(eventId: string): Promise<EventRecord | null> {
    return this.#events.get(eventId) ?? null;
  }

  async activeRequestCount(eventId: string): Promise<number> {
    return this.#activeCounts.get(eventId) ?? 0;
  }

  setStatus(eventId: string, status: EventStatus): void {
    const event = this.#events.get(eventId);
    if (event) this.#events.set(eventId, { ...event, status });
  }

  setActiveRequestCount(eventId: string, count: number): void {
    this.#activeCounts.set(eventId, count);
  }
}

export class InMemorySeatRepository implements SeatRepository {
  readonly #seats = new Map<string, Set<string>>();

  constructor(seats: Array<{ seatId: string; eventId: string }> = []) {
    for (const seat of seats) {
      const existing = this.#seats.get(seat.seatId) ?? new Set<string>();
      existing.add(seat.eventId);
      this.#seats.set(seat.seatId, existing);
    }
  }

  async seatBelongsToEvent(seatId: string, eventId: string): Promise<boolean> {
    return this.#seats.get(seatId)?.has(eventId) ?? false;
  }
}

export interface RecordedAuditEntry {
  action: string;
  actorId?: string;
  actorType?: string;
  targetType?: string;
  targetId?: string;
  ipHash?: string;
  metadata?: Record<string, string | number | boolean | null>;
  createdAt: string;
}

export class InMemoryAuditSink implements AuditSink {
  readonly entries: RecordedAuditEntry[] = [];

  async record(entry: Parameters<AuditSink['record']>[0]): Promise<void> {
    this.entries.push({ ...entry, createdAt: new Date().toISOString() });
  }

  byAction(action: string): RecordedAuditEntry[] {
    return this.entries.filter((entry) => entry.action === action);
  }

  clear(): void {
    this.entries.length = 0;
  }
}
