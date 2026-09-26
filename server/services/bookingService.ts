import { createHash, randomUUID } from "node:crypto";
import { and, eq, inArray, lte, sql } from "drizzle-orm";
import {
  bookingItems,
  bookings,
  events,
  idempotencyKeys,
  inventory,
  payments,
  reservationItems,
  reservations,
  seats,
  tickets,
  ticketTypes,
  users,
} from "../../drizzle/schema";
import type { Database } from "../db";
import { publishDomainEvent } from "../events";
import { mockPaymentProvider } from "./paymentService";
import { assertReservationTransition, money, reservationExpiry, sumMoney } from "./reservationService";

export class BookingError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = "BookingError";
  }
}

function requestHash(input: unknown) {
  return createHash("sha256").update(JSON.stringify(input)).digest("hex");
}

function asHttpError(error: unknown): never {
  if (error instanceof BookingError) throw error;
  throw error;
}

export async function createReservation(
  db: Database,
  input: { userId: number; eventId: number; seatIds: number[]; idempotencyKey?: string },
) {
  if (!input.seatIds.length || input.seatIds.length > 10) {
    throw new BookingError("INVALID_REQUEST", "Select between 1 and 10 seats.");
  }
  const distinctSeatIds = Array.from(new Set(input.seatIds)).sort((a, b) => a - b);
  const hash = requestHash({ eventId: input.eventId, seatIds: distinctSeatIds });

  return db.transaction(async (tx) => {
    if (input.idempotencyKey) {
      const existing = await tx
        .select()
        .from(idempotencyKeys)
        .where(and(eq(idempotencyKeys.key, input.idempotencyKey), eq(idempotencyKeys.userId, input.userId), eq(idempotencyKeys.operation, "reservation.create")))
        .limit(1);
      if (existing[0]) {
        if (existing[0].requestHash !== hash) throw new BookingError("IDEMPOTENCY_CONFLICT", "This idempotency key was already used for a different request.");
        if (existing[0].responseJson) return JSON.parse(existing[0].responseJson);
      } else {
        await tx.insert(idempotencyKeys).values({ key: input.idempotencyKey, userId: input.userId, operation: "reservation.create", requestHash: hash });
      }
    }

    const eventRows = await tx.select().from(events).where(eq(events.id, input.eventId)).limit(1);
    const event = eventRows[0];
    if (!event) throw new BookingError("EVENT_NOT_FOUND", "Event not found.");
    if (event.status !== "PUBLISHED") throw new BookingError("EVENT_NOT_BOOKABLE", "This event is not currently accepting reservations.");

    // Lock the user row to serialize concurrent purchases by the same user.
    await tx.select({ id: users.id }).from(users).where(eq(users.id, input.userId)).for("update");

    const lockedInventory = await tx
      .select({ inventory, seat: seats })
      .from(inventory)
      .innerJoin(seats, eq(inventory.seatId, seats.id))
      .where(and(eq(inventory.eventId, input.eventId), inArray(inventory.seatId, distinctSeatIds)))
      .orderBy(inventory.id)
      .for("update");

    if (lockedInventory.length !== distinctSeatIds.length) throw new BookingError("SEAT_NOT_FOUND", "One or more selected seats do not exist for this event.");
    if (lockedInventory.some(({ inventory: item }) => item.status !== "AVAILABLE")) throw new BookingError("SEAT_UNAVAILABLE", "One or more selected seats are no longer available.");

    const purchasedRows = await tx
      .select({ count: sql<number>`count(*)` })
      .from(bookingItems)
      .innerJoin(bookings, eq(bookingItems.bookingId, bookings.id))
      .where(and(eq(bookings.userId, input.userId), eq(bookings.eventId, input.eventId), eq(bookings.status, "CONFIRMED")));
    const reservedRows = await tx
      .select({ count: sql<number>`count(*)` })
      .from(reservationItems)
      .innerJoin(reservations, eq(reservationItems.reservationId, reservations.id))
      .where(and(eq(reservations.userId, input.userId), eq(reservations.eventId, input.eventId), inArray(reservations.status, ["RESERVED", "PAYMENT_PENDING"]), sql`${reservations.expiresAt} > NOW()`));
    const totalHeld = Number(purchasedRows[0]?.count ?? 0) + Number(reservedRows[0]?.count ?? 0);
    if (totalHeld + distinctSeatIds.length > event.maxTicketsPerUser) throw new BookingError("PURCHASE_LIMIT_EXCEEDED", `You can reserve at most ${event.maxTicketsPerUser} tickets for this event.`);

    const prices = await tx.select().from(ticketTypes).where(eq(ticketTypes.eventId, input.eventId)).orderBy(ticketTypes.price);
    const fallbackPrice = prices[0]?.price ?? "0.00";
    const expiresAt = reservationExpiry();
    const totalAmount = sumMoney(distinctSeatIds.map(() => fallbackPrice));
    const reservationResult = await tx.insert(reservations).values({ userId: input.userId, eventId: input.eventId, status: "RESERVED", expiresAt, totalAmount: totalAmount.toFixed(2) }).returning({ id: reservations.id });
    const reservationId = reservationResult[0].id;

    for (const { inventory: item } of lockedInventory) {
      await tx.update(inventory).set({ status: "RESERVED", reservationId, updatedAt: new Date() }).where(eq(inventory.id, item.id));
      await tx.insert(reservationItems).values({ reservationId, inventoryId: item.id, unitPrice: fallbackPrice });
    }

    const response = { id: reservationId, eventId: input.eventId, status: "RESERVED" as const, expiresAt, totalAmount, seatIds: distinctSeatIds };
    if (input.idempotencyKey) {
      await tx.update(idempotencyKeys).set({ responseJson: JSON.stringify(response) }).where(and(eq(idempotencyKeys.key, input.idempotencyKey), eq(idempotencyKeys.userId, input.userId), eq(idempotencyKeys.operation, "reservation.create")));
    }
    publishDomainEvent({ type: "ReservationCreated", eventId: input.eventId, reservationId, seatIds: distinctSeatIds, at: new Date().toISOString() });
    publishDomainEvent({ type: "SeatReserved", eventId: input.eventId, reservationId, seatIds: distinctSeatIds, at: new Date().toISOString() });
    return response;
  }).catch(asHttpError);
}

export async function cancelReservation(db: Database, input: { userId: number; reservationId: number }) {
  return db.transaction(async (tx) => {
    const reservationRows = await tx.select().from(reservations).where(and(eq(reservations.id, input.reservationId), eq(reservations.userId, input.userId))).for("update");
    const reservation = reservationRows[0];
    if (!reservation) throw new BookingError("RESERVATION_NOT_FOUND", "Reservation not found.");
    if (!["RESERVED", "PAYMENT_PENDING"].includes(reservation.status)) throw new BookingError("INVALID_REQUEST", "This reservation can no longer be cancelled.");
    assertReservationTransition(reservation.status, "CANCELLED");
    const items = await tx.select().from(reservationItems).where(eq(reservationItems.reservationId, reservation.id));
    const itemInventory = await tx.select({ id: inventory.id, seatId: inventory.seatId }).from(inventory).where(inArray(inventory.id, items.map((item) => item.inventoryId)));
    await tx.update(reservations).set({ status: "CANCELLED", updatedAt: new Date() }).where(eq(reservations.id, reservation.id));
    await tx.update(inventory).set({ status: "AVAILABLE", reservationId: null, updatedAt: new Date() }).where(inArray(inventory.id, items.map((item) => item.inventoryId)));
    publishDomainEvent({ type: "ReservationCancelled", eventId: reservation.eventId, reservationId: reservation.id, seatIds: itemInventory.map((item) => item.seatId), at: new Date().toISOString() });
    publishDomainEvent({ type: "SeatReleased", eventId: reservation.eventId, reservationId: reservation.id, seatIds: itemInventory.map((item) => item.seatId), at: new Date().toISOString() });
    return { id: reservation.id, status: "CANCELLED" as const };
  });
}

export async function expireReservations(db: Database, now = new Date()) {
  const expired = await db.select().from(reservations).where(and(inArray(reservations.status, ["RESERVED", "PAYMENT_PENDING"]), lte(reservations.expiresAt, now)));
  let count = 0;
  for (const reservation of expired) {
    await db.transaction(async (tx) => {
      const locked = await tx.select().from(reservations).where(eq(reservations.id, reservation.id)).for("update");
      if (!locked[0] || !["RESERVED", "PAYMENT_PENDING"].includes(locked[0].status) || locked[0].expiresAt > now) return;
      const items = await tx.select().from(reservationItems).where(eq(reservationItems.reservationId, reservation.id));
      const itemInventory = await tx.select({ id: inventory.id, seatId: inventory.seatId }).from(inventory).where(inArray(inventory.id, items.map((item) => item.inventoryId)));
      await tx.update(reservations).set({ status: "EXPIRED", updatedAt: now }).where(eq(reservations.id, reservation.id));
      await tx.update(inventory).set({ status: "AVAILABLE", reservationId: null, updatedAt: now }).where(inArray(inventory.id, items.map((item) => item.inventoryId)));
      publishDomainEvent({ type: "ReservationExpired", eventId: reservation.eventId, reservationId: reservation.id, seatIds: itemInventory.map((item) => item.seatId), at: now.toISOString() });
      publishDomainEvent({ type: "SeatReleased", eventId: reservation.eventId, reservationId: reservation.id, seatIds: itemInventory.map((item) => item.seatId), at: now.toISOString() });
      count += 1;
    });
  }
  return count;
}

export async function createBooking(db: Database, input: { userId: number; reservationId: number; idempotencyKey?: string }) {
  return db.transaction(async (tx) => {
    const reservationRows = await tx.select().from(reservations).where(and(eq(reservations.id, input.reservationId), eq(reservations.userId, input.userId))).for("update");
    const reservation = reservationRows[0];
    if (!reservation) throw new BookingError("RESERVATION_NOT_FOUND", "Reservation not found.");
    if (reservation.expiresAt <= new Date()) throw new BookingError("RESERVATION_EXPIRED", "Your reservation has expired.");
    if (!["RESERVED", "PAYMENT_PENDING"].includes(reservation.status)) throw new BookingError("PAYMENT_REQUIRED", "This reservation is not available for payment.");
    if (reservation.status === "RESERVED") await tx.update(reservations).set({ status: "PAYMENT_PENDING", updatedAt: new Date() }).where(eq(reservations.id, reservation.id));

    const existing = await tx.select().from(bookings).where(eq(bookings.reservationId, reservation.id)).limit(1);
    if (existing[0]) return { bookingId: existing[0].id, status: existing[0].status };
    const bookingResult = await tx.insert(bookings).values({ userId: input.userId, eventId: reservation.eventId, reservationId: reservation.id, status: "PENDING", totalAmount: reservation.totalAmount }).returning({ id: bookings.id });
    const bookingId = bookingResult[0].id;
    const items = await tx.select().from(reservationItems).where(eq(reservationItems.reservationId, reservation.id));
    const seatIds: number[] = [];
    for (const item of items) {
      const lockedInventory = await tx.select().from(inventory).where(eq(inventory.id, item.inventoryId)).for("update");
      if (!lockedInventory[0] || lockedInventory[0].status !== "RESERVED" || lockedInventory[0].reservationId !== reservation.id) throw new BookingError("SEAT_UNAVAILABLE", "A reserved seat is no longer available.");
      await tx.insert(bookingItems).values({ bookingId, inventoryId: item.inventoryId, unitPrice: item.unitPrice });
      await tx.update(inventory).set({ bookingId, updatedAt: new Date() }).where(eq(inventory.id, item.inventoryId));
      seatIds.push(item.inventoryId);
    }
    return { bookingId, status: "PENDING" as const };
  });
}

export async function createPayment(db: Database, input: { userId: number; reservationId: number; outcome: "success" | "failure"; idempotencyKey?: string }) {
  const reservation = await db.select().from(reservations).where(and(eq(reservations.id, input.reservationId), eq(reservations.userId, input.userId))).limit(1);
  if (!reservation[0]) throw new BookingError("RESERVATION_NOT_FOUND", "Reservation not found.");
  if (reservation[0].expiresAt <= new Date()) throw new BookingError("RESERVATION_EXPIRED", "Your reservation has expired.");
  const booking = await db.select().from(bookings).where(eq(bookings.reservationId, input.reservationId)).limit(1);
  if (!booking[0]) throw new BookingError("PAYMENT_REQUIRED", "Create a booking payment session first.");
  if (input.idempotencyKey) {
    const existing = await db.select().from(payments).where(and(eq(payments.bookingId, booking[0].id), eq(payments.idempotencyKey, input.idempotencyKey))).limit(1);
    if (existing[0]) return existing[0];
  }
  const provider = await mockPaymentProvider.createPayment({ amount: money(reservation[0].totalAmount), reference: String(booking[0].id), outcome: input.outcome });
  await db.insert(payments).values({ bookingId: booking[0].id, reservationId: input.reservationId, provider: "mock", providerPaymentId: provider.providerPaymentId, amount: reservation[0].totalAmount, status: "PENDING", idempotencyKey: input.idempotencyKey ?? null });
  return { ...provider, bookingId: booking[0].id };
}

export async function verifyPayment(db: Database, input: { userId: number; providerPaymentId: string }) {
  const payment = await db.select().from(payments).where(eq(payments.providerPaymentId, input.providerPaymentId)).limit(1);
  if (!payment[0]) throw new BookingError("PAYMENT_FAILED", "Payment not found.");
  const booking = await db.select().from(bookings).where(and(eq(bookings.id, payment[0].bookingId), eq(bookings.userId, input.userId))).limit(1);
  if (!booking[0]) throw new BookingError("UNAUTHORIZED", "Payment does not belong to this user.");
  const result = await mockPaymentProvider.verifyPayment(input.providerPaymentId);
  return settlePayment(db, payment[0].providerPaymentId, result.status);
}

export async function handlePaymentWebhook(db: Database, input: { providerPaymentId: string; status: "SUCCEEDED" | "FAILED" }) {
  const result = await mockPaymentProvider.handleWebhook(input);
  return settlePayment(db, result.providerPaymentId, result.status);
}

async function settlePayment(db: Database, providerPaymentId: string, status: "SUCCEEDED" | "FAILED") {
  return db.transaction(async (tx) => {
    const paymentRows = await tx.select().from(payments).where(eq(payments.providerPaymentId, providerPaymentId)).for("update");
    const payment = paymentRows[0];
    if (!payment) throw new BookingError("PAYMENT_FAILED", "Payment not found.");
    if (payment.status === "SUCCEEDED" || payment.status === "FAILED") return { status: payment.status, bookingId: payment.bookingId, duplicate: true };
    const reservationRows = await tx.select().from(reservations).where(eq(reservations.id, payment.reservationId)).for("update");
    const reservation = reservationRows[0];
    if (!reservation || reservation.expiresAt <= new Date()) {
      await tx.update(payments).set({ status: "FAILED", updatedAt: new Date() }).where(eq(payments.id, payment.id));
      if (reservation) {
        const expiredItems = await tx.select().from(reservationItems).where(eq(reservationItems.reservationId, reservation.id));
        await tx.update(reservations).set({ status: "EXPIRED", updatedAt: new Date() }).where(eq(reservations.id, reservation.id));
        await tx.update(inventory).set({ status: "AVAILABLE", reservationId: null, bookingId: null, updatedAt: new Date() }).where(inArray(inventory.id, expiredItems.map((item) => item.inventoryId)));
      }
      throw new BookingError("RESERVATION_EXPIRED", "The reservation is no longer payable.");
    }
    if (status === "FAILED") {
      await tx.update(payments).set({ status: "FAILED", updatedAt: new Date() }).where(eq(payments.id, payment.id));
      const items = await tx.select().from(reservationItems).where(eq(reservationItems.reservationId, reservation.id));
      const itemInventory = await tx.select({ id: inventory.id, seatId: inventory.seatId }).from(inventory).where(inArray(inventory.id, items.map((item) => item.inventoryId)));
      await tx.update(reservations).set({ status: "PAYMENT_FAILED", updatedAt: new Date() }).where(eq(reservations.id, reservation.id));
      await tx.update(bookings).set({ status: "CANCELLED", updatedAt: new Date() }).where(eq(bookings.id, payment.bookingId));
      await tx.update(inventory).set({ status: "AVAILABLE", reservationId: null, bookingId: null, updatedAt: new Date() }).where(inArray(inventory.id, items.map((item) => item.inventoryId)));
      publishDomainEvent({ type: "PaymentFailed", eventId: reservation.eventId, reservationId: reservation.id, seatIds: itemInventory.map((item) => item.seatId), at: new Date().toISOString() });
      publishDomainEvent({ type: "SeatReleased", eventId: reservation.eventId, reservationId: reservation.id, seatIds: itemInventory.map((item) => item.seatId), at: new Date().toISOString() });
      return { status: "FAILED" as const, bookingId: payment.bookingId, duplicate: false };
    }
    await tx.update(payments).set({ status: "SUCCEEDED", updatedAt: new Date() }).where(eq(payments.id, payment.id));
    await tx.update(reservations).set({ status: "CONFIRMED", updatedAt: new Date() }).where(eq(reservations.id, reservation.id));
    const bookingItemsRows = await tx.select().from(bookingItems).where(eq(bookingItems.bookingId, payment.bookingId));
    const soldSeatIds: number[] = [];
    for (const item of bookingItemsRows) {
      await tx.update(inventory).set({ status: "SOLD", reservationId: null, updatedAt: new Date() }).where(eq(inventory.id, item.inventoryId));
      await tx.insert(tickets).values({ bookingId: payment.bookingId, userId: reservation.userId, eventId: reservation.eventId, inventoryId: item.inventoryId, publicCode: `TIX-${randomUUID().slice(0, 8).toUpperCase()}` });
      const seatRow = await tx.select({ seatId: inventory.seatId }).from(inventory).where(eq(inventory.id, item.inventoryId)).limit(1);
      if (seatRow[0]) soldSeatIds.push(seatRow[0].seatId);
    }
    await tx.update(bookings).set({ status: "CONFIRMED", confirmedAt: new Date(), updatedAt: new Date() }).where(eq(bookings.id, payment.bookingId));
    publishDomainEvent({ type: "BookingConfirmed", eventId: reservation.eventId, reservationId: reservation.id, bookingId: payment.bookingId, seatIds: soldSeatIds, at: new Date().toISOString() });
    publishDomainEvent({ type: "SeatSold", eventId: reservation.eventId, reservationId: reservation.id, bookingId: payment.bookingId, seatIds: soldSeatIds, at: new Date().toISOString() });
    publishDomainEvent({ type: "PaymentSucceeded", eventId: reservation.eventId, reservationId: reservation.id, bookingId: payment.bookingId, at: new Date().toISOString() });
    return { status: "SUCCEEDED" as const, bookingId: payment.bookingId, duplicate: false };
  });
}
