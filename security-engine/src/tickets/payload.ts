/**
 * The signed ticket claim and its envelope.
 *
 * ## What is inside the QR, and what is deliberately not
 *
 * The signed payload carries only the fields a gate scanner needs to make an
 * offline-capable decision plus the fields needed to look the ticket up:
 *
 *   ticketId, eventId, seatId, issuedAt, expiresAt, version
 *
 * `userId` is intentionally **absent**, even though the full ticket record
 * contains it. A QR code is photographed, screenshotted, posted, and handed to
 * strangers; it is the least trustworthy storage surface in the system. Putting
 * a user identifier in it would turn every screenshot into a PII disclosure and
 * every shared ticket into an account-correlation vector. The authoritative
 * user binding is resolved server-side from the ticket record via
 * `TicketRepository`, never from the QR.
 *
 * For the same reason the envelope carries no price, no payment status, no
 * credentials, and no internal identifiers. The gate needs to know a ticket is
 * genuine and unredeemed — nothing more.
 *
 * ## Why the envelope is nested
 *
 * `{ v, ticket, signature }` keeps the signature outside the signed material, so
 * a verifier can re-canonicalize `ticket` and compare without any parsing
 * ambiguity about which bytes were covered. `ticket` is a JSON string rather
 * than a nested object specifically so the byte sequence that gets signed is
 * preserved verbatim between issuance and verification.
 */

import { z } from 'zod';
import { SecurityError } from '../core/errors';

/** Schema version. Bump when the signed payload shape changes incompatibly. */
export const TICKET_PAYLOAD_VERSION = 1;

/** Envelope (outer) version, distinct from the payload version. */
export const TICKET_ENVELOPE_VERSION = 1;

const identifier = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9_-]+$/, 'identifier must be alphanumeric with dash/underscore only');

/**
 * The signed claim. Every field is bounded and pattern-constrained so a hostile
 * payload cannot inflate the canonical string or smuggle control characters into
 * logs and dashboards.
 */
export const ticketPayloadSchema = z.object({
  ticketId: identifier,
  eventId: identifier,
  seatId: identifier,
  /** ISO-8601 instant the ticket was issued. */
  issuedAt: z.string().datetime({ offset: true }),
  /** ISO-8601 instant after which the ticket is invalid. */
  expiresAt: z.string().datetime({ offset: true }),
  /** Monotonic ticket revision; incremented on any reissue. */
  version: z.number().int().positive().max(2 ** 31 - 1),
});

export type TicketPayload = z.infer<typeof ticketPayloadSchema>;

/** The outer, signed-over structure that becomes the QR string. */
export const ticketEnvelopeSchema = z.object({
  v: z.literal(TICKET_ENVELOPE_VERSION),
  /** JSON string of the canonical signed payload. */
  ticket: z.string().min(1).max(4096),
  /** base64 detached Ed25519 signature over the canonicalized `ticket`. */
  signature: z.string().min(1).max(256),
  /** Key id, so the verifier can select a key without guessing. */
  kid: z.string().min(1).max(64),
});

export type TicketEnvelope = z.infer<typeof ticketEnvelopeSchema>;

/** Upper bound on an inbound QR string, to bound parser work. */
export const MAX_QR_LENGTH = 8192;

export type TicketPayloadValidation =
  | { readonly ok: true; readonly payload: TicketPayload }
  | { readonly ok: false; readonly reason: string };

/** Structural validation of a decoded payload. Does not check the signature. */
export function validateTicketPayload(value: unknown): TicketPayloadValidation {
  const result = ticketPayloadSchema.safeParse(value);
  if (result.success) return { ok: true, payload: result.data };
  const first = result.error.issues[0];
  return { ok: false, reason: first ? `${first.path.join('.') || '(root)'}: ${first.message}` : 'invalid' };
}

/**
 * Parse a raw QR string into a validated envelope.
 *
 * The length check happens before `JSON.parse` so a caller cannot make us spend
 * time on an arbitrarily large document.
 */
export function decodeTicketEnvelope(raw: unknown): TicketEnvelope {
  if (typeof raw !== 'string') {
    throw new SecurityError('MALFORMED_QR', 'QR payload must be a string');
  }
  if (raw.length === 0) {
    throw new SecurityError('MALFORMED_QR', 'QR payload is empty');
  }
  if (raw.length > MAX_QR_LENGTH) {
    throw new SecurityError('MALFORMED_QR', 'QR payload exceeds maximum length');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new SecurityError('MALFORMED_QR', 'QR payload is not valid JSON');
  }

  const result = ticketEnvelopeSchema.safeParse(parsed);
  if (!result.success) {
    throw new SecurityError('MALFORMED_QR', 'QR envelope failed structural validation', {
      cause: result.error,
    });
  }
  return result.data;
}

/** Parse the inner `ticket` string back into a validated payload. */
export function parseEnvelopePayload(envelope: TicketEnvelope): TicketPayload {
  let inner: unknown;
  try {
    inner = JSON.parse(envelope.ticket);
  } catch {
    throw new SecurityError('MALFORMED_QR', 'Signed ticket claim is not valid JSON');
  }

  const validation = validateTicketPayload(inner);
  if (!validation.ok) {
    throw new SecurityError('INVALID_TICKET', `Signed ticket claim failed validation: ${validation.reason}`);
  }
  return validation.payload;
}

/** Build the QR string from a canonical payload string and its signature. */
export function buildEnvelope(canonicalTicket: string, signature: string, kid: string): TicketEnvelope {
  return { v: TICKET_ENVELOPE_VERSION, ticket: canonicalTicket, signature, kid };
}

export function serializeEnvelope(envelope: TicketEnvelope): string {
  return JSON.stringify(envelope);
}
