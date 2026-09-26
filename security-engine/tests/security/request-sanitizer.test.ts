/**
 * Part 9 — request validation: never trust client-controlled fields.
 *
 * The bar these tests hold: after sanitization, a handler physically cannot read
 * a client-supplied identity, price, or status, because the field is gone rather
 * than overwritten.
 */

import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import {
  bookingRequestSchema,
  guardProtectedRequest,
  parseOrThrow,
  queueJoinRequestSchema,
  reservationRequestSchema,
  sanitizeBody,
  scanRequestSchema,
} from '../../src/validation/request-sanitizer';
import { CLIENT_CONTROLLED_FIELDS, type UserResolver } from '../../src/ports/user-resolver';
import { SecurityError } from '../../src/core/errors';

/** A resolver that never invents a caller it wasn't given. */
const resolverFor = (userId: string | null): UserResolver => ({
  resolve: async () => (userId === null ? null : { userId, roles: ['USER'] as const }),
});

describe('request sanitizer (Part 9)', () => {
  it('strips every spec-listed client-controlled field', () => {
    const attack: Record<string, unknown> = {
      eventId: 'EVT_1',
      userId: 'victim',
      price: 0,
      paymentStatus: 'PAID',
      ticketStatus: 'CONFIRMED',
      role: 'ADMIN',
      bookingOwner: 'victim',
    };
    const { body, stripped } = sanitizeBody(attack);

    for (const field of ['userId', 'price', 'paymentStatus', 'ticketStatus', 'role', 'bookingOwner']) {
      expect(body).not.toHaveProperty(field);
      expect(stripped).toContain(field);
    }
    // Legitimate fields survive untouched.
    expect(body).toEqual({ eventId: 'EVT_1' });
  });

  it('matches blocked fields case-insensitively', () => {
    const { body, stripped } = sanitizeBody({ EventId: 'EVT_1', UserId: 'x', USERID: 'y', PaYmEnTsTaTuS: 'PAID' });
    expect(body).toEqual({ EventId: 'EVT_1' });
    expect([...stripped].sort()).toEqual(['PaYmEnTsTaTuS', 'USERID', 'UserId']);
  });

  /**
   * The shallow check is the trap. `payment: { amount: 1 }` is the same attack as
   * `amount: 1` one level up, and a top-level-only strip leaves it intact.
   */
  it('strips blocked fields at any depth', () => {
    const { body, stripped } = sanitizeBody({
      eventId: 'EVT_1',
      payment: { amount: 1, method: 'card' },
      booking: { ownerId: 'victim', seats: [{ price: 0, seatId: 'A1' }] },
    });

    expect(body).toEqual({
      eventId: 'EVT_1',
      payment: { method: 'card' },
      booking: { seats: [{ seatId: 'A1' }] },
    });
    expect([...stripped].sort()).toEqual(['booking.ownerId', 'booking.seats[0].price', 'payment.amount']);
  });

  it('sanitizes inside arrays', () => {
    const { body } = sanitizeBody({ items: [{ userId: 'a', sku: 'x' }, { userId: 'b', sku: 'y' }] });
    expect(body).toEqual({ items: [{ sku: 'x' }, { sku: 'y' }] });
  });

  it('does not mutate the caller-supplied body', () => {
    const original = { eventId: 'EVT_1', userId: 'victim' };
    sanitizeBody(original);
    expect(original.userId).toBe('victim');
  });

  /** A deep payload must be rejected, not allowed to blow the stack. */
  it('rejects bodies nested beyond the depth limit', () => {
    let deep: Record<string, unknown> = { userId: 'leaf' };
    for (let i = 0; i < 40; i += 1) deep = { nested: deep };
    expect(() => sanitizeBody(deep, { maxDepth: 8 })).toThrow(SecurityError);
  });

  it('honours caller-supplied extra blocked fields', () => {
    const { body } = sanitizeBody({ eventId: 'E', couponCode: 'FREE' }, { extraBlocked: ['couponCode'] });
    expect(body).toEqual({ eventId: 'E' });
  });

  /**
   * A non-object body is passed through, not coerced to `{}`. Coercion would let
   * `"hello"` satisfy an all-optional schema, converting a malformed request into
   * a valid one. Rejection is the schema's job.
   */
  it('passes non-object input through for the schema to reject', () => {
    expect(sanitizeBody(null).body).toBeNull();
    expect(sanitizeBody('string').body).toBe('string');
    expect(sanitizeBody(42).body).toBe(42);
    expect(sanitizeBody([]).body).toEqual([]);

    const optional = z.strictObject({ note: z.string().optional() });
    expect(() => parseOrThrow(optional, 'string')).toThrow(SecurityError);
    expect(() => parseOrThrow(optional, null)).toThrow(SecurityError);
  });

  it('covers the full blocklist from the port', () => {
    const body: Record<string, unknown> = {};
    for (const field of CLIENT_CONTROLLED_FIELDS) body[field] = 'x';
    // Every single blocked name is gone, leaving an empty object.
    expect(sanitizeBody(body).body).toEqual({});
  });
});

describe('request schemas (Part 9)', () => {
  it('accepts a well-formed reservation', () => {
    const parsed = parseOrThrow(reservationRequestSchema, { eventId: 'EVT_1', seatIds: ['A1', 'A2'], quantity: 2 });
    expect(parsed.seatIds).toEqual(['A1', 'A2']);
  });

  it('rejects unknown fields on money-moving requests', () => {
    // A client-supplied extra field is either a bug or an attempt to smuggle
    // something past a validator that only inspects fields it knows.
    expect(() => parseOrThrow(reservationRequestSchema, { eventId: 'EVT_1', seatIds: ['A1'], coupon: 'X' })).toThrow(
      SecurityError,
    );
  });

  it('rejects an empty seat list', () => {
    expect(() => parseOrThrow(reservationRequestSchema, { eventId: 'EVT_1', seatIds: [] })).toThrow(SecurityError);
  });

  it('bounds seat count and quantity', () => {
    expect(() =>
      parseOrThrow(reservationRequestSchema, {
        eventId: 'EVT_1',
        seatIds: Array.from({ length: 21 }, (_u, i) => `S${i}`),
      }),
    ).toThrow(SecurityError);
    expect(() => parseOrThrow(reservationRequestSchema, { eventId: 'EVT_1', seatIds: ['A1'], quantity: 21 })).toThrow(
      SecurityError,
    );
  });

  it('rejects identifier injection characters', () => {
    expect(() => parseOrThrow(reservationRequestSchema, { eventId: 'EVT_1 OR 1=1', seatIds: ['A1'] })).toThrow(
      SecurityError,
    );
  });

  it('rejects non-integer and non-positive quantities', () => {
    for (const quantity of [0, -1, 1.5, Number.NaN]) {
      expect(() => parseOrThrow(reservationRequestSchema, { eventId: 'EVT_1', seatIds: ['A1'], quantity })).toThrow(
        SecurityError,
      );
    }
  });

  it('validates booking, scan and queue payloads', () => {
    expect(parseOrThrow(bookingRequestSchema, { reservationId: 'R1', paymentMethodId: 'pm_1' }).paymentMethodId).toBe('pm_1');
    expect(() => parseOrThrow(bookingRequestSchema, { reservationId: 'R1' })).toThrow(SecurityError);
    expect(parseOrThrow(scanRequestSchema, { qr: 'data', eventId: 'EVT_1' }).scannerId).toBeUndefined();
    expect(parseOrThrow(queueJoinRequestSchema, { eventId: 'EVT_1' }).admissionToken).toBeUndefined();
  });

  it('bounds QR payload size', () => {
    expect(() => parseOrThrow(scanRequestSchema, { qr: 'x'.repeat(8193), eventId: 'EVT_1' })).toThrow(SecurityError);
  });

  it('reports a public-safe field path, not internals', () => {
    try {
      parseOrThrow(reservationRequestSchema, { eventId: 'EVT_1', seatIds: ['A1'], quantity: 999 });
      throw new Error('should have thrown');
    } catch (error) {
      expect(error).toBeInstanceOf(SecurityError);
      const publicJson = (error as SecurityError).toPublicJSON();
      expect(publicJson.error.code).toBe('VALIDATION_FAILED');
      expect(publicJson.error.details?.field).toBe('quantity');
      // The raw message names the constraint and must not cross the boundary.
      expect(JSON.stringify(publicJson)).not.toContain('zod');
    }
  });
});

describe('guardProtectedRequest (Part 9)', () => {
  const body = {
    eventId: 'EVT_1',
    seatIds: ['A1'],
    userId: 'attacker_claimed_victim',
    price: 1,
    role: 'ADMIN',
  };

  it('returns a sanitized, validated payload with a server-derived principal', async () => {
    const { payload, context, stripped } = await guardProtectedRequest({
      schema: reservationRequestSchema,
      body,
      credential: { session: 'valid' },
      endpoint: 'POST /api/bookings/reserve',
      userResolver: resolverFor('real_user'),
    });

    // The handler cannot see the attacker's claims at all.
    expect(payload).toEqual({ eventId: 'EVT_1', seatIds: ['A1'] });
    expect(context.userId).toBe('real_user');
    expect([...stripped].sort()).toEqual(['price', 'role', 'userId']);
  });

  it('never derives identity from the body', async () => {
    const { context } = await guardProtectedRequest({
      schema: reservationRequestSchema,
      body: { ...body, userId: 'someone_else' },
      credential: {},
      endpoint: 'POST /api/bookings/reserve',
      userResolver: resolverFor('real_user'),
    });
    expect(context.userId).toBe('real_user');
    expect(context.userId).not.toBe('someone_else');
  });

  it('rejects an unauthenticated caller on a protected route', async () => {
    await expect(
      guardProtectedRequest({
        schema: reservationRequestSchema,
        body: { eventId: 'EVT_1', seatIds: ['A1'] },
        credential: null,
        endpoint: 'POST /api/bookings',
        userResolver: resolverFor(null),
      }),
    ).rejects.toThrow(SecurityError);
  });

  it('allows anonymous access when the route opts out', async () => {
    const { context } = await guardProtectedRequest({
      schema: reservationRequestSchema,
      body: { eventId: 'EVT_1', seatIds: ['A1'] },
      credential: null,
      endpoint: 'GET /api/events/EVT_1',
      userResolver: resolverFor(null),
      requireAuth: false,
    });
    expect(context.userId).toBeNull();
  });

  /** Sanitizing before validating stops a shaped authority field from passing. */
  it('validates only the sanitized body', async () => {
    await expect(
      guardProtectedRequest({
        schema: z.strictObject({ eventId: z.string(), userId: z.string() }),
        body: { eventId: 'EVT_1', userId: 'attacker' },
        credential: {},
        endpoint: 'POST /api/x',
        userResolver: resolverFor('u1'),
      }),
    ).rejects.toThrow(SecurityError);
  });

  it('rejects a body that is not an object', async () => {
    await expect(
      guardProtectedRequest({
        schema: reservationRequestSchema,
        body: 'not-a-body',
        credential: {},
        endpoint: 'POST /api/x',
        userResolver: resolverFor('u1'),
      }),
    ).rejects.toThrow(SecurityError);
  });
});
