import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createReservation, BookingError } from "../services/bookingService";
import {
  closeTestDatabase,
  countInventoryByStatus,
  countRows,
  countTicketsForBooking,
  ensureTestDatabase,
  getTestDb,
  resetTestDatabase,
  seedEvent,
  seedUser,
  type SeededEvent,
} from "./helpers/testDb";

/**
 * Concurrency tests for the booking service, run against a real PostgreSQL.
 *
 * Every guarantee asserted here is enforced by the database, not by the
 * application:
 *
 *   - two transactions cannot both update the same inventory row, because
 *     createReservation takes SELECT ... FOR UPDATE on it before checking status
 *   - two transactions for the same buyer cannot both pass the
 *     maxTicketsPerUser check, because it takes SELECT ... FOR UPDATE on the
 *     user row first, serialising that user's reservations
 *   - two transactions locking an overlapping set of seats cannot deadlock,
 *     because the rows are locked in inventory.id order
 *
 * The previous version of this file exercised two async functions defined
 * inside it. Those could not fail for any reason connected to the SQL, which
 * made the suite pass while the guarantees above were unverified.
 *
 * If no PostgreSQL is reachable the whole suite is skipped rather than failed,
 * so `pnpm test` still works on a machine with no infrastructure. Run
 * `pnpm run infra:up` first to exercise it.
 */

let skipReason: string | undefined;
let db: ReturnType<typeof getTestDb>;

beforeAll(async () => {
  skipReason = await ensureTestDatabase();
  if (!skipReason) db = getTestDb();
});

beforeEach(async () => {
  if (skipReason) return;
  await resetTestDatabase();
});

afterAll(async () => {
  if (!skipReason) await closeTestDatabase();
});

/** Run every attempt at once, so they genuinely contend for the same rows. */
async function race<T>(attempts: Array<() => Promise<T>>) {
  const settled = await Promise.allSettled(attempts.map((attempt) => attempt()));
  return settled.map((outcome, index) => {
    if (outcome.status === "fulfilled") return { index, ok: true as const, value: outcome.value };
    return { index, ok: false as const, error: outcome.reason as Error };
  });
}

function successes<T>(results: Array<{ ok: true; value: T } | { ok: false; error: Error }>) {
  return results.filter((r) => r.ok);
}

function failures(results: Array<{ ok: boolean }>) {
  return results.filter((r) => !r.ok);
}

function codeOf(error: Error) {
  return error instanceof BookingError ? error.code : error.message;
}

describe.skipIf(!!skipReason)("createReservation under real contention", () => {
  it("resolves the same seat for exactly one buyer, however many race for it", async () => {
    const seeded: SeededEvent = await seedEvent({ seatCount: 1 });
    const buyers = await Promise.all([seedUser(), seedUser(), seedUser(), seedUser(), seedUser()]);

    const results = await race(
      buyers.map((buyer) => () =>
        createReservation(db, {
          userId: buyer.id,
          eventId: seeded.eventId,
          seatIds: [seeded.seatIds[0]],
        }),
      ),
    );

    // This is the assertion the old test only pretended to make.
    expect(successes(results)).toHaveLength(1);
    expect(failures(results)).toHaveLength(4);
    for (const failure of failures(results)) {
      expect(codeOf(failure.error)).toBe("SEAT_UNAVAILABLE");
    }

    // And the database agrees: the seat is held by exactly one reservation.
    expect(await countInventoryByStatus(seeded.eventId, "RESERVED")).toBe(1);
    expect(await countInventoryByStatus(seeded.eventId, "AVAILABLE")).toBe(0);
  });

  it("holds for a hundred simultaneous buyers on a single seat", async () => {
    const seeded = await seedEvent({ seatCount: 1 });
    const buyers = await Promise.all(Array.from({ length: 100 }, () => seedUser()));

    const results = await race(
      buyers.map((buyer) => () =>
        createReservation(db, {
          userId: buyer.id,
          eventId: seeded.eventId,
          seatIds: [seeded.seatIds[0]],
        }),
      ),
    );

    expect(successes(results)).toHaveLength(1);
    expect(await countInventoryByStatus(seeded.eventId, "RESERVED")).toBe(1);

    // No partial writes: exactly one reservation row for one seat.
    expect(await countRows("reservations")).toBe(1);
  });

  it("never lets one buyer exceed maxTicketsPerUser by racing themselves", async () => {
    // Twelve seats, a limit of two, and five simultaneous two-seat attempts from
    // the same user, each on its own disjoint pair of seats.
    //
    // The disjointness is deliberate: if the attempts overlapped, the losers
    // would fail with SEAT_UNAVAILABLE and the test would pass without ever
    // exercising the limit. Here seat contention cannot be the cause of a
    // failure, so the only thing that can stop four of the five is the
    // user-row lock serialising them in front of the maxTicketsPerUser check.
    const seeded = await seedEvent({ seatCount: 12, maxTicketsPerUser: 2 });
    const buyer = await seedUser();
    const pairs = [
      [seeded.seatIds[0], seeded.seatIds[1]],
      [seeded.seatIds[2], seeded.seatIds[3]],
      [seeded.seatIds[4], seeded.seatIds[5]],
      [seeded.seatIds[6], seeded.seatIds[7]],
      [seeded.seatIds[8], seeded.seatIds[9]],
    ];

    const results = await race(
      pairs.map((seatIds) => () =>
        createReservation(db, { userId: buyer.id, eventId: seeded.eventId, seatIds }),
      ),
    );

    expect(successes(results)).toHaveLength(1);
    for (const failure of failures(results)) {
      expect(codeOf(failure.error)).toBe("PURCHASE_LIMIT_EXCEEDED");
    }
    expect(await countInventoryByStatus(seeded.eventId, "RESERVED")).toBe(2);
    expect(await countInventoryByStatus(seeded.eventId, "AVAILABLE")).toBe(10);
  });

  it("does not deadlock when two buyers request overlapping seat sets", async () => {
    // A and B share a seat. If the FOR UPDATE rows were not locked in
    // inventory.id order, these two transactions would grab their disjoint
    // seats in opposite order and Postgres would abort one with a deadlock
    // error rather than a BookingError.
    const seeded = await seedEvent({ seatCount: 4 });
    const [alice, bob] = await Promise.all([seedUser(), seedUser()]);

    const results = await race([
      () =>
        createReservation(db, {
          userId: alice.id,
          eventId: seeded.eventId,
          seatIds: [seeded.seatIds[0], seeded.seatIds[1]],
        }),
      () =>
        createReservation(db, {
          userId: bob.id,
          eventId: seeded.eventId,
          seatIds: [seeded.seatIds[1], seeded.seatIds[2]],
        }),
    ]);

    // One of them loses the shared seat. Neither may fail with a deadlock.
    expect(successes(results).length).toBeGreaterThanOrEqual(1);
    for (const failure of failures(results)) {
      expect(codeOf(failure.error)).toBe("SEAT_UNAVAILABLE");
      expect(failure.error.message).not.toMatch(/deadlock/i);
    }
  });

  it("splits a contended seat set between concurrent multi-seat buyers", async () => {
    // Three buyers, each asking for two of the same three seats. Exactly one can
    // get both; the others must be rejected wholesale rather than partially
    // reserving a seat, which would strand inventory.
    const seeded = await seedEvent({ seatCount: 3 });
    const buyers = await Promise.all([seedUser(), seedUser(), seedUser()]);

    const results = await race(
      buyers.map((buyer) => () =>
        createReservation(db, {
          userId: buyer.id,
          eventId: seeded.eventId,
          seatIds: [seeded.seatIds[0], seeded.seatIds[1]],
        }),
      ),
    );

    expect(successes(results)).toHaveLength(1);
    expect(await countInventoryByStatus(seeded.eventId, "RESERVED")).toBe(2);
    expect(await countInventoryByStatus(seeded.eventId, "AVAILABLE")).toBe(1);
  });

  it("replays a repeated idempotency key instead of reserving twice", async () => {
    const seeded = await seedEvent({ seatCount: 2 });
    const buyer = await seedUser();
    const key = "same-request-key";

    const [first, second] = await Promise.all([
      createReservation(db, {
        userId: buyer.id,
        eventId: seeded.eventId,
        seatIds: [seeded.seatIds[0]],
        idempotencyKey: key,
      }),
      createReservation(db, {
        userId: buyer.id,
        eventId: seeded.eventId,
        seatIds: [seeded.seatIds[0]],
        idempotencyKey: key,
      }),
    ]);

    // Both callers see the same reservation, and only one seat is held.
    expect(first.id).toBe(second.id);
    expect(await countInventoryByStatus(seeded.eventId, "RESERVED")).toBe(1);
  });

  it("rejects an idempotency key reused for a different request", async () => {
    const seeded = await seedEvent({ seatCount: 3 });
    const buyer = await seedUser();
    const key = "reused-key";

    await createReservation(db, {
      userId: buyer.id,
      eventId: seeded.eventId,
      seatIds: [seeded.seatIds[0]],
      idempotencyKey: key,
    });

    await expect(
      createReservation(db, {
        userId: buyer.id,
        eventId: seeded.eventId,
        seatIds: [seeded.seatIds[1]],
        idempotencyKey: key,
      }),
    ).rejects.toMatchObject({ code: "IDEMPOTENCY_CONFLICT" });
  });
});

describe.skipIf(!!skipReason)("settlement under real contention", () => {
  it("issues exactly one ticket per seat when a payment is settled twice", async () => {
    // A retried payment webhook must not mint a second ticket for the same
    // booking. settlePayment takes SELECT ... FOR UPDATE on the payment row, so
    // the second caller sees SUCCEEDED and returns the first caller's result.
    const { createBooking, createPayment, verifyPayment } = await import("../services/bookingService");

    const seeded = await seedEvent({ seatCount: 2 });
    const buyer = await seedUser();

    const reservation = await createReservation(db, {
      userId: buyer.id,
      eventId: seeded.eventId,
      seatIds: [seeded.seatIds[0]],
    });
    const booking = await createBooking(db, {
      userId: buyer.id,
      reservationId: reservation.id,
    });
    const payment = await createPayment(db, {
      userId: buyer.id,
      reservationId: reservation.id,
      outcome: "success",
    });
    // The provider hands back the id that verifyPayment must be given.
    const providerPaymentId = payment.providerPaymentId;

    const results = await race([
      () => verifyPayment(db, { userId: buyer.id, providerPaymentId }),
      () => verifyPayment(db, { userId: buyer.id, providerPaymentId }),
    ]);

    // Both callers succeed, because settling an already-settled payment is a
    // no-op rather than an error. The assertion that matters is the count.
    expect(successes(results)).toHaveLength(2);
    expect(results.every((r) => r.ok && r.value.status === "SUCCEEDED")).toBe(true);

    expect(await countTicketsForBooking(booking.bookingId)).toBe(1);
    expect(await countRows("tickets")).toBe(1);
    // The seat is sold exactly once, not left reserved.
    expect(await countInventoryByStatus(seeded.eventId, "SOLD")).toBe(1);
    expect(await countInventoryByStatus(seeded.eventId, "RESERVED")).toBe(0);
    expect(payment.bookingId).toBe(booking.bookingId);
  });
});
