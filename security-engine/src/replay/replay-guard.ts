/**
 * Replay protection (Part 4) and the scan ledger.
 *
 * A valid QR must not mean unlimited entry. This module owns the decision that a
 * ticket transitions `CONFIRMED -> USED` exactly once, and records every attempt
 * in an append-only ledger.
 *
 * ## The guarantee
 *
 * ```
 * Scanner A -> SUCCESS
 * Scanner B -> ALREADY_USED
 * ```
 *
 * and never two successes. The mechanism is a single atomic conditional write in
 * `TicketRepository.consumeConfirmedTicket`, whose affected-row count is the
 * lock. There is no read-then-write anywhere on this path, because a
 * read-then-write admits two winners whenever two scanners interleave between
 * the read and the write — which at a busy gate is the normal case, not the
 * exception.
 *
 * ## Why the ledger is separate from the mechanism
 *
 * `ticket_scans` is *not* what prevents replay; the atomic UPDATE is. The ledger
 * is independent evidence. Keeping them separate matters: if the ledger were the
 * mechanism, an attacker who could write to it could un-redeem a ticket, and the
 * audit trail would be the thing enforcing security. Evidence must never be the
 * control.
 *
 * ## Ledger writes never block admission
 *
 * The scan record is written after the transition and failures to write it are
 * swallowed. A database hiccup in the audit path must not turn a legitimate
 * scan at a gate into a rejected entry.
 */

import type { Clock } from '../core/clock';
import type { TicketRepository, TicketConsumptionContext } from '../ports/ticket-repository';
import type { TicketVerifier, VerificationResult, VerifyOptions } from '../tickets/ticket-verifier';

export type ScanOutcome = 'ACCEPTED' | 'REJECTED';

export interface TicketScanRecord {
  readonly ticketId: string | null;
  readonly eventId: string | null;
  readonly scannerId?: string;
  readonly actorId?: string;
  readonly ipHash?: string;
  readonly outcome: ScanOutcome;
  readonly reason?: string;
  readonly signatureKid?: string;
  readonly metadata?: Readonly<Record<string, string | number | boolean>>;
}

export interface ScanLedger {
  record(record: TicketScanRecord): Promise<void>;
}

export interface ReplayGuardOptions {
  readonly verifier: TicketVerifier;
  readonly ticketRepository: TicketRepository;
  readonly ledger?: ScanLedger;
  readonly clock: Clock;
  /** Injected sink for structured security events; see Part 10. */
  readonly onReplayAttempt?: (context: {
    readonly ticketId: string | null;
    readonly eventId: string | null;
    readonly scannerId?: string;
    readonly actorId?: string;
    readonly ipHash?: string;
    readonly reason: string;
  }) => void | Promise<void>;
}

export interface ScanRequest extends VerifyOptions {
  readonly qr: unknown;
  readonly eventId: string;
  readonly scannerId?: string;
  readonly actorId?: string;
  readonly ipHash?: string;
  /** Reject if the seat is not confirmed for this event. Defaults to true at gates. */
  readonly validateSeat?: boolean;
}

export class ReplayGuard {
  readonly #verifier: TicketVerifier;
  readonly #tickets: TicketRepository;
  readonly #ledger: ScanLedger | undefined;
  readonly #clock: Clock;
  readonly #onReplayAttempt: ReplayGuardOptions['onReplayAttempt'];

  constructor(options: ReplayGuardOptions) {
    this.#verifier = options.verifier;
    this.#tickets = options.ticketRepository;
    this.#ledger = options.ledger;
    this.#clock = options.clock;
    this.#onReplayAttempt = options.onReplayAttempt;
  }

  /**
   * Verify and atomically consume a scanned QR.
   *
   * Returns the verification result and records the attempt. Never throws for a
   * rejected ticket — a rejection is a normal, expected outcome that a gate must
   * be able to render.
   */
  async scan(request: ScanRequest): Promise<VerificationResult> {
    let result: VerificationResult;
    let ticketId: string | null = null;
    let kid: string | undefined;

    try {
      result = await this.#verifier.verifyAndConsume(request.qr, {
        expectedEventId: request.eventId,
        eventId: request.eventId,
        validateSeat: request.validateSeat,
        expiryGraceMs: request.expiryGraceMs,
        scannerId: request.scannerId,
        actorId: request.actorId,
      });
      ticketId = result.ticket?.ticketId ?? extractTicketId(request.qr);
      kid = result.kid;
    } catch (error) {
      // An unexpected throw is still a rejection, never an admission.
      result = { outcome: 'SERVICE_UNAVAILABLE', valid: false };
    }

    const outcome: ScanOutcome = result.valid ? 'ACCEPTED' : 'REJECTED';

    await this.#recordScan({
      ticketId,
      eventId: request.eventId,
      scannerId: request.scannerId,
      actorId: request.actorId,
      ipHash: request.ipHash,
      outcome,
      reason: result.valid ? undefined : result.outcome,
      signatureKid: kid,
    });

    if (!result.valid && result.outcome === 'ALREADY_USED') {
      await this.#notifyReplayAttempt({
        ticketId,
        eventId: request.eventId,
        scannerId: request.scannerId,
        actorId: request.actorId,
        ipHash: request.ipHash,
        reason: result.outcome,
      });
    }

    return result;
  }

  /**
   * Ledger write. Failures are swallowed by design — see the class comment.
   * Errors are surfaced through the return value rather than thrown.
   */
  async #recordScan(record: TicketScanRecord): Promise<void> {
    if (!this.#ledger) return;
    try {
      await this.#ledger.record({ ...record, metadata: { at: this.#clock.nowIso() } });
    } catch {
      /* Audit unavailability must not reject a legitimate scan. */
    }
  }

  async #notifyReplayAttempt(context: {
    ticketId: string | null;
    eventId: string | null;
    scannerId?: string;
    actorId?: string;
    ipHash?: string;
    reason: string;
  }): Promise<void> {
    if (!this.#onReplayAttempt) return;
    try {
      await this.#onReplayAttempt(context);
    } catch {
      /* Telemetry must not affect admission. */
    }
  }
}

/**
 * Best-effort ticket id extraction for the ledger, used when verification failed
 * before a ticket was resolved. Purely for the audit trail; the value is never
 * trusted for any decision.
 */
function extractTicketId(rawQr: unknown): string | null {
  try {
    if (typeof rawQr !== 'string') return null;
    const parsed = JSON.parse(rawQr) as { ticket?: unknown };
    if (typeof parsed.ticket !== 'string') return null;
    const inner = JSON.parse(parsed.ticket) as { ticketId?: unknown };
    return typeof inner.ticketId === 'string' ? inner.ticketId : null;
  } catch {
    return null;
  }
}

export type { TicketConsumptionContext };
