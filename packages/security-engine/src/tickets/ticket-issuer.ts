/**
 * Ticket issuance.
 *
 * Turns an authoritative, confirmed ticket into a signed claim plus a scannable
 * QR. This is the only place in the engine that produces signatures, and the
 * private key never appears in anything this module returns.
 *
 * ## What the caller gets
 *
 * `issue` returns the envelope, the canonical string, and a rendered QR. The
 * canonical string is returned deliberately: it is the exact byte sequence the
 * signature covers, so an integrator can store it, log its hash, or hand it to
 * a verifier and prove the two agree without re-deriving it.
 *
 * ## Reissue semantics
 *
 * `version` increments on every issue. A ticket reissued after a cancellation
 * therefore produces a different signed payload, so a QR captured before the
 * reissue fails verification against the current record. That is intentional:
 * a superseded QR must not scan.
 */

import { canonicalizeJson } from '../core/canonicalize';
import type { Clock } from '../core/clock';
import { SecurityError } from '../core/errors';
import type { TicketSigner } from '../crypto/signer';
import { encodeEnvelope, renderQrDataUri, renderQrSvg, type QrRenderOptions } from '../qr/qr-service';
import {
  buildEnvelope,
  validateTicketPayload,
  type TicketEnvelope,
  type TicketPayload,
} from './payload';

export interface IssueTicketInput {
  readonly ticketId: string;
  readonly eventId: string;
  readonly seatId: string;
  /**
   * Absolute expiry. When omitted, computed from the configured TTL and the
   * injected clock. Passed explicitly by tests and by callers replaying an
   * historic ticket.
   */
  readonly expiresAt?: string;
  readonly issuedAt?: string;
  readonly version?: number;
  /**
   * Current ticket state. Only `CONFIRMED` tickets are issued, so a QR for a
   * cancelled or pending ticket cannot be produced by accident.
   */
  readonly state: string;
}

export interface IssuedTicket {
  readonly envelope: TicketEnvelope;
  /** The exact string encoded into the QR. */
  readonly encoded: string;
  /** Canonical payload bytes the signature covers. */
  readonly canonical: string;
  readonly payload: TicketPayload;
  readonly kid: string;
  readonly dataUri: string;
  readonly svg: string;
}

export interface TicketIssuerOptions {
  readonly signer: TicketSigner;
  readonly clock: Clock;
  readonly defaultTtlSeconds: number;
}

const ISSUABLE_STATES = new Set(['CONFIRMED']);

export class TicketIssuer {
  readonly #signer: TicketSigner;
  readonly #clock: Clock;
  readonly #defaultTtlSeconds: number;

  constructor(options: TicketIssuerOptions) {
    this.#signer = options.signer;
    this.#clock = options.clock;
    this.#defaultTtlSeconds = options.defaultTtlSeconds;
  }

  get signer(): TicketSigner {
    return this.#signer;
  }

  async issue(input: IssueTicketInput, qrOptions: QrRenderOptions = {}): Promise<IssuedTicket> {
    if (!ISSUABLE_STATES.has(input.state)) {
      throw new SecurityError(
        'TICKET_NOT_CONFIRMED',
        `Cannot issue a QR for a ticket in state ${input.state}`,
        { publicDetails: { state: input.state } },
      );
    }

    const issuedAt = input.issuedAt ?? this.#clock.nowIso();
    const expiresAt =
      input.expiresAt ?? new Date(this.#clock.now() + this.#defaultTtlSeconds * 1000).toISOString();

    const payload: TicketPayload = {
      ticketId: input.ticketId,
      eventId: input.eventId,
      seatId: input.seatId,
      issuedAt,
      expiresAt,
      version: input.version ?? 1,
    };

    // Validate before signing. A payload that cannot be structurally validated
    // must never receive a signature, or we would be minting evidence for
    // something our own verifier will later reject.
    const validation = validateTicketPayload(payload);
    if (!validation.ok) {
      throw new SecurityError('VALIDATION_FAILED', `Refusing to sign an invalid ticket payload: ${validation.reason}`);
    }

    const { signature, canonical, kid } = this.#signer.sign(payload);
    const envelope = buildEnvelope(canonical, signature, kid);

    const [dataUri, svg] = await Promise.all([
      renderQrDataUri(envelope, qrOptions),
      renderQrSvg(envelope, qrOptions),
    ]);

    return { envelope, encoded: encodeEnvelope(envelope), canonical, payload, kid, dataUri, svg };
  }

  /**
   * Sign a payload without rendering a QR image.
   *
   * Used when the QR is produced downstream (for example by a PDF renderer or a
   * native wallet pass) but the signature must still come from this service.
   */
  signOnly(input: IssueTicketInput): { envelope: TicketEnvelope; encoded: string; canonical: string; kid: string } {
    if (!ISSUABLE_STATES.has(input.state)) {
      throw new SecurityError('TICKET_NOT_CONFIRMED', `Cannot sign a QR for a ticket in state ${input.state}`);
    }

    const issuedAt = input.issuedAt ?? this.#clock.nowIso();
    const expiresAt =
      input.expiresAt ?? new Date(this.#clock.now() + this.#defaultTtlSeconds * 1000).toISOString();

    const payload: TicketPayload = {
      ticketId: input.ticketId,
      eventId: input.eventId,
      seatId: input.seatId,
      issuedAt,
      expiresAt,
      version: input.version ?? 1,
    };

    const validation = validateTicketPayload(payload);
    if (!validation.ok) {
      throw new SecurityError('VALIDATION_FAILED', `Refusing to sign an invalid ticket payload: ${validation.reason}`);
    }

    const { signature, canonical, kid } = this.#signer.sign(payload);
    const envelope = buildEnvelope(canonical, signature, kid);
    return { envelope, encoded: encodeEnvelope(envelope), canonical, kid };
  }

  /** Canonical form of an arbitrary payload, for diagnostics. */
  static canonicalize(payload: unknown): string {
    return canonicalizeJson(payload);
  }
}
