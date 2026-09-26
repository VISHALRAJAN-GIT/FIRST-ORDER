/**
 * Ticket verification pipeline (Part 3).
 *
 * Implements the mandated order exactly, and fails closed at every step:
 *
 *   QR â†’ decode â†’ structural validation â†’ signature verification
 *      â†’ ticket exists â†’ event check â†’ state check â†’ expiry â†’ used check
 *      â†’ ALLOW | REJECT
 *
 * ## Why the order matters
 *
 * Each stage is cheaper and more revealing-to-the-defender than the next, and
 * each one is a precondition for the next being meaningful. Verifying the
 * signature *before* touching the database is the important one: an unsigned or
 * forged payload should never cause a lookup, so a flood of fabricated QRs
 * cannot be used to probe which ticket ids exist. We verify the signature first
 * and only then ask the database anything.
 *
 * ## Non-disclosure
 *
 * The response is a closed enum. It never contains a stack trace, a SQL error,
 * a table name, or a reason phrased in terms of internal state. `WRONG_EVENT`
 * and `TICKET_NOT_FOUND` are separated only because the specification enumerates
 * them as distinct outcomes; beyond that list, the answer is uniform.
 *
 * ## Fail-closed
 *
 * If the signature verifier or the ticket store is unavailable, verification
 * rejects. A gate that admits on infrastructure failure is not a gate. This is
 * the deliberate opposite of the rate limiter, which fails open.
 */

import type { Clock } from '../core/clock';
import type { TicketSigner } from '../crypto/signer';
import type { EventRepository, SeatRepository } from '../ports/event-repository';
import type { TicketRecord, TicketRepository, TicketState } from '../ports/ticket-repository';
import {
  decodeTicketEnvelope,
  parseEnvelopePayload,
  type TicketPayload,
} from './payload';

/**
 * Closed result set. This is a public contract â€” see SECURITY_INTEGRATION.md.
 */
export const VERIFICATION_OUTCOMES = [
  'VALID',
  'ALREADY_USED',
  'EXPIRED',
  'INVALID_SIGNATURE',
  'TICKET_CLAIM_MISMATCH',
  'TICKET_NOT_FOUND',
  'CANCELLED',
  'WRONG_EVENT',
  'TICKET_NOT_CONFIRMED',
  'MALFORMED_QR',
  'SERVICE_UNAVAILABLE',
] as const;

export type VerificationOutcome = (typeof VERIFICATION_OUTCOMES)[number];

export interface VerificationResult {
  readonly outcome: VerificationOutcome;
  readonly valid: boolean;
  /**
   * Populated only on VALID. Deliberately excludes userId and any pricing, so a
   * gate client that logs this cannot leak PII into its own logs.
   */
  readonly ticket?: {
    readonly ticketId: string;
    readonly eventId: string;
    readonly seatId: string;
    readonly version: number;
  };
  /** Key that validated the signature. Useful for key-rotation monitoring. */
  readonly kid?: string;
}

export interface VerifyOptions {
  /**
   * When provided, the ticket must belong to this event. Gate terminals should
   * always set this â€” it is what stops a valid ticket for event A being used to
   * enter event B.
   */
  readonly expectedEventId?: string;
  /** Re-check that the seat really belongs to the event. Extra round trip. */
  readonly validateSeat?: boolean;
  /** Milliseconds of clock skew tolerated on `expiresAt`. */
  readonly expiryGraceMs?: number;
}

export interface TicketVerifierOptions {
  readonly signer: TicketSigner;
  readonly ticketRepository: TicketRepository;
  readonly eventRepository: EventRepository;
  readonly clock: Clock;
  readonly seatRepository?: SeatRepository;
}

const REJECT = (outcome: Exclude<VerificationOutcome, 'VALID'>): VerificationResult => ({
  outcome,
  valid: false,
});

/** Terminal states that mean "this ticket will never be usable". */
const DEAD_STATES = new Set<TicketState>(['CANCELLED', 'REFUNDED']);

export class TicketVerifier {
  readonly #signer: TicketSigner;
  readonly #tickets: TicketRepository;
  readonly #events: EventRepository;
  readonly #seats: SeatRepository | undefined;
  readonly #clock: Clock;

  constructor(options: TicketVerifierOptions) {
    this.#signer = options.signer;
    this.#tickets = options.ticketRepository;
    this.#events = options.eventRepository;
    this.#seats = options.seatRepository;
    this.#clock = options.clock;
  }

  /**
   * Non-consuming verification.
   *
   * Reports whether a ticket is currently valid without redeeming it. Used for
   * "is my ticket OK?" checks before a user travels to the venue. It deliberately
   * does NOT consume, so it cannot be used by an attacker to burn someone's
   * ticket.
   */
  async verify(rawQr: unknown, options: VerifyOptions = {}): Promise<VerificationResult> {
    const parsed = this.#decode(rawQr);
    if ('outcome' in parsed) return parsed.result;

    const { payload, kid } = parsed;

    const signatureCheck = this.#signer.verify(payload, parsed.envelope.signature, parsed.envelope.kid);
    if (!signatureCheck.valid) {
      // Unknown kid, retired key and bad signature are indistinguishable from
      // outside. Internally we know which; the caller does not need to.
      return REJECT('INVALID_SIGNATURE');
    }

    const stateCheck = await this.#checkAuthoritativeState(payload, options);
    if (stateCheck) return stateCheck;

    return { outcome: 'VALID', valid: true, kid, ticket: publicView(payload) };
  }

  /**
   * Consuming verification, backed by the atomic CONFIRMED -> USED transition.
   *
   * Under any concurrency, exactly one caller receives `VALID`. Everyone else
   * receives `ALREADY_USED`. See `TicketRepository.consumeConfirmedTicket` for
   * the mandatory implementation contract.
   */
  async verifyAndConsume(
    rawQr: unknown,
    options: VerifyOptions & { readonly eventId: string; readonly scannerId?: string; readonly actorId?: string } = { eventId: '' },
  ): Promise<VerificationResult> {
    const parsed = this.#decode(rawQr);
    if ('outcome' in parsed) return parsed.result;

    const { payload, kid } = parsed;

    // Signature first, always. Never let an unsigned payload reach the database.
    const signatureCheck = this.#signer.verify(payload, parsed.envelope.signature, parsed.envelope.kid);
    if (!signatureCheck.valid) return REJECT('INVALID_SIGNATURE');

    // Everything below this line is authoritative-state checking, and every one
    // of those checks must happen BEFORE the consume, because consume is
    // irreversible. Checking after would mean we had already burned a valid
    // ticket in order to then reject it.
    const stateCheck = await this.#checkAuthoritativeState(payload, options);
    if (stateCheck) return stateCheck;

    const outcome = await this.#tickets.consumeConfirmedTicket(payload.ticketId, payload.version, {
      eventId: options.eventId,
      scannerId: options.scannerId,
      actorId: options.actorId,
    });

    if (outcome.ok) {
      return { outcome: 'VALID', valid: true, kid, ticket: publicView(payload) };
    }

    switch (outcome.reason) {
      case 'ALREADY_USED':
        return REJECT('ALREADY_USED');
      case 'NOT_CONFIRMED':
        // Distinguish a dead ticket from one that is merely not yet confirmed,
        // since only one of those is worth telling the holder.
        return outcome.ticket && DEAD_STATES.has(outcome.ticket.state)
          ? REJECT('CANCELLED')
          : REJECT('TICKET_NOT_CONFIRMED');
      case 'NOT_FOUND':
        return REJECT('TICKET_NOT_FOUND');
      default:
        return REJECT('TICKET_NOT_CONFIRMED');
    }
  }

  /**
   * Decode + structurally validate.
   *
   * Distinguishes two failure kinds, because they mean different things to
   * whoever has to debug the rejection:
   *
   *   - the ENVELOPE is unreadable (bad JSON, wrong shape) → MALFORMED_QR
   *   - the envelope is well-formed but the inner CLAIM does not validate
   *     (unknown field, altered id, wrong types) → INVALID_SIGNATURE
   *
   * The second case is the interesting one: the QR claims to carry a signed
   * ticket but the claim itself is not something we will verify. Reporting it as
   * a signature failure tells an operator "this was altered", which is the truth.
   */
  #decode(
    rawQr: unknown,
  ):
    | { envelope: ReturnType<typeof decodeTicketEnvelope>; payload: TicketPayload; kid: string }
    | { outcome: 'MALFORMED_QR' | 'INVALID_SIGNATURE'; result: VerificationResult } {
    let envelope;
    try {
      envelope = decodeTicketEnvelope(rawQr);
    } catch {
      return { outcome: 'MALFORMED_QR', result: REJECT('MALFORMED_QR') };
    }

    let payload: TicketPayload;
    try {
      payload = parseEnvelopePayload(envelope);
    } catch {
      return { outcome: 'INVALID_SIGNATURE', result: REJECT('INVALID_SIGNATURE') };
    }

    return { envelope, payload, kid: envelope.kid };
  }

  /**
   * Authoritative-state checks, shared by both verify paths.
   * Returns a rejection, or undefined when the ticket may proceed.
   */
  async #checkAuthoritativeState(
    payload: TicketPayload,
    options: VerifyOptions & { readonly eventId?: string },
  ): Promise<VerificationResult | undefined> {
    const expectedEventId = options.expectedEventId ?? options.eventId;
    if (expectedEventId && payload.eventId !== expectedEventId) {
      // Checked before the database on purpose: this needs no lookup, so a
      // mismatched event never becomes a database probe.
      return REJECT('WRONG_EVENT');
    }

    let ticket: TicketRecord | null;
    try {
      ticket = await this.#tickets.findById(payload.ticketId);
    } catch (error) {
      // Fail closed. We cannot confirm the ticket is genuine, so we do not admit.
      return REJECT('SERVICE_UNAVAILABLE');
    }

    if (!ticket) return REJECT('TICKET_NOT_FOUND');

    // The signature proves the CLAIM is authentic. These checks prove the ticket
    // behind the claim is still in a usable state. A signature alone is not
    // enough â€” a genuine ticket can be cancelled or expire after it is minted.
    if (ticket.eventId !== payload.eventId || ticket.seatId !== payload.seatId) {
      // The signature already passed, so this is NOT a forgery. The signed claim is
      // authentic; it simply disagrees with the authoritative record about which
      // event or seat it refers to.
      //
      // That distinction is load-bearing. Reporting this as INVALID_SIGNATURE would
      // be actively harmful in two directions:
      //
      //   - a genuine holder would be told their ticket is forged, and support
      //     would spend hours hunting an attack that never happened;
      //   - real signature-failure alerting would be diluted by data-integrity
      //     bugs, so the signal that actually indicates tampering gets lost.
      //
      // In practice this fires when a booking is reissued across seats, when a
      // concurrent reissue races a scan, or when the booking service wrote an
      // inconsistent record — all operational faults that need to be fixed, not
      // attacks. It fails closed either way; only the diagnosis differs.
      return REJECT('TICKET_CLAIM_MISMATCH');
    }

    if (ticket.version !== payload.version) {
      // A newer version exists, so this QR has been superseded. Refusing is what
      // stops a superseded QR from being used after a reissue.
      return REJECT('TICKET_NOT_CONFIRMED');
    }

    if (DEAD_STATES.has(ticket.state)) return REJECT('CANCELLED');
    if (ticket.state === 'USED') return REJECT('ALREADY_USED');
    if (ticket.state !== 'CONFIRMED') return REJECT('TICKET_NOT_CONFIRMED');

    const graceMs = options.expiryGraceMs ?? 0;
    const expiresAt = Date.parse(payload.expiresAt);
    if (Number.isNaN(expiresAt)) return REJECT('MALFORMED_QR');
    if (this.#clock.now() > expiresAt + graceMs) return REJECT('EXPIRED');

    if (expectedEventId) {
      let eventExists = true;
      try {
        eventExists = (await this.#events.findById(expectedEventId)) !== null;
      } catch {
        return REJECT('SERVICE_UNAVAILABLE');
      }
      if (!eventExists) return REJECT('WRONG_EVENT');
    }

    if (options.validateSeat && this.#seats) {
      let belongs = false;
      try {
        belongs = await this.#seats.seatBelongsToEvent(payload.seatId, payload.eventId);
      } catch {
        return REJECT('SERVICE_UNAVAILABLE');
      }
      if (!belongs) return REJECT('WRONG_EVENT');
    }

    return undefined;
  }
}

function publicView(payload: TicketPayload): NonNullable<VerificationResult['ticket']> {
  return {
    ticketId: payload.ticketId,
    eventId: payload.eventId,
    seatId: payload.seatId,
    version: payload.version,
  };
}
