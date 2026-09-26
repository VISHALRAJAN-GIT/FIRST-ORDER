/**
 * Port: authoritative ticket state.
 *
 * Person 1 owns the `tickets` table. This interface is the *only* way the
 * security engine reads or advances ticket state. We never query their schema
 * directly, which is what allows the two halves of the project to be built in
 * parallel and merged without schema coordination.
 *
 * ## The one method that carries real weight
 *
 * `consumeConfirmedTicket` is the single most important declaration in this
 * codebase. It must be implemented as a **single atomic conditional write**:
 *
 * ```sql
 * UPDATE tickets
 *    SET state = 'USED', used_at = now(), updated_at = now()
 *  WHERE id = $1 AND state = 'CONFIRMED';
 * ```
 *
 * and the return value must be derived from the affected row count.
 *
 * Implementations that are **not** acceptable, because each admits a double
 * admission under concurrency:
 *
 *   ✗ `SELECT` state, then `UPDATE` unconditionally  → interleaving race
 *   ✗ in-process `Map`/`Set` of consumed ticket ids  → fails across instances
 *   ✗ `SELECT ... FOR UPDATE` held across app logic  → long lock, easy to misuse
 *   ✗ `UPDATE` then check `state` afterwards          → lost update
 *   ✗ best-effort dedupe on a cache                  → cache eviction re-admits
 *
 * The affected-row-count check is the whole mechanism. Under any isolation
 * level, exactly one concurrent transaction can observe the pre-update state and
 * therefore report success. The rest observe zero rows affected.
 */

/** Lifecycle of a ticket. Person 1 defines the real values; these are the ones we depend on. */
export const TICKET_STATES = ['CONFIRMED', 'USED', 'CANCELLED', 'PENDING', 'REFUNDED', 'EXPIRED'] as const;
export type TicketState = (typeof TICKET_STATES)[number];

/** The subset of ticket fields the security engine needs. */
export interface TicketRecord {
  readonly ticketId: string;
  readonly eventId: string;
  readonly seatId: string;
  readonly userId: string;
  readonly state: TicketState;
  readonly version: number;
  readonly issuedAt: string;
  readonly expiresAt: string;
  /** Instant of first scan, or null if never scanned. */
  readonly usedAt?: string | null;
}

/** Context supplied by the verifying gate/terminal, for audit attribution. */
export interface TicketConsumptionContext {
  readonly eventId: string;
  /** Identifier of the scanning device or operator, e.g. `GATE_SCANNER_4`. */
  readonly scannerId?: string;
  /** Session or operator identity, when authenticated. */
  readonly actorId?: string;
  readonly ipHash?: string;
}

export type ConsumeOutcome =
  /** Exactly one caller receives this. */
  | { readonly ok: true; readonly ticket: TicketRecord }
  /** Ticket exists but was already consumed. */
  | { readonly ok: false; readonly reason: 'ALREADY_USED'; readonly ticket?: TicketRecord }
  /** Ticket exists but is not in the `CONFIRMED` state. */
  | { readonly ok: false; readonly reason: 'NOT_CONFIRMED'; readonly ticket?: TicketRecord }
  /** No such ticket. */
  | { readonly ok: false; readonly reason: 'NOT_FOUND' };

export interface TicketRepository {
  /**
   * Read authoritative state without mutating it.
   *
   * Used by the non-consuming `verify` path. Returns `null` when absent, which
   * callers must translate to `TICKET_NOT_FOUND` without leaking existence.
   */
  findById(ticketId: string): Promise<TicketRecord | null>;

  /**
   * Atomically transition `CONFIRMED -> USED`, returning success to exactly one
   * caller. See the contract note at the top of this file — this must be a
   * single conditional UPDATE whose result is the affected row count.
   */
  consumeConfirmedTicket(
    ticketId: string,
    expectedVersion: number,
    context: TicketConsumptionContext,
  ): Promise<ConsumeOutcome>;

  /**
   * Persist a signed QR payload for a ticket.
   *
   * Optional: an implementation may instead mint QR payloads on demand at
   * verification time, since the payload is derivable from the ticket record.
   */
  saveSignedPayload?(ticketId: string, envelope: string): Promise<void>;
}
