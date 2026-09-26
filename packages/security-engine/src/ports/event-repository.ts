/**
 * Ports for the Person 1 domain objects we depend on.
 *
 * Every type here is intentionally minimal. The narrower these interfaces, the
 * less likely a schema change on Person 1's side breaks the security engine, and
 * the less we can accidentally couple ourselves to their internals.
 */

import type { AuthenticatedPrincipal } from './user-resolver';

export const EVENT_STATUSES = ['DRAFT', 'ON_SALE', 'SOLD_OUT', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'] as const;
export type EventStatus = (typeof EVENT_STATUSES)[number];

export interface EventRecord {
  readonly eventId: string;
  readonly name?: string;
  readonly status: EventStatus;
  /** Venue id, when the security engine needs to scope gate operations. */
  readonly venueId?: string;
  readonly startsAt?: string;
}

/** Read-only access to events. Person 1 owns this data. */
export interface EventRepository {
  findById(eventId: string): Promise<EventRecord | null>;
  /**
   * Current number of requests currently in the booking flow for an event.
   *
   * Used to decide when the virtual queue should engage. Implementations that
   * cannot answer cheaply should return a best-effort number — the queue
   * degrades to a no-op rather than failing the request.
   */
  activeRequestCount?(eventId: string): Promise<number>;
}

/** Seat existence/ownership check for a ticket claim. */
export interface SeatRepository {
  seatBelongsToEvent(seatId: string, eventId: string): Promise<boolean>;
}

/**
 * Business-event sink so Person 1's booking activity lands in the security
 * audit trail.
 *
 * Reservation creation, booking creation, payment verification and cancellation
 * are Person 1's events, but the audit trail is ours. This port is how they
 * report them without either side owning the other's tables.
 */
export interface AuditSink {
  record(entry: {
    readonly action: string;
    readonly actorId?: string;
    readonly actorType?: 'USER' | 'ADMIN' | 'SYSTEM' | 'SCANNER' | 'ANONYMOUS';
    readonly targetType?: string;
    readonly targetId?: string;
    readonly ipHash?: string;
    readonly metadata?: Readonly<Record<string, string | number | boolean | null>>;
  }): Promise<void>;

  /**
   * Convenience used by our own middleware, which knows the principal directly.
   * Kept separate so Person 1's adapter does not need to resolve identity.
   */
  recordForPrincipal?(
    principal: AuthenticatedPrincipal | null,
    entry: Parameters<AuditSink['record']>[0],
  ): Promise<void>;
}
