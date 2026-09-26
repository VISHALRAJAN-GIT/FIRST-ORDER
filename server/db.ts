import { and, asc, desc, eq, inArray, lt, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/node-postgres";
import { Pool } from "pg";
import {
  bookings,
  events,
  inventory,
  reservationItems,
  reservations,
  seats,
  ticketTypes,
  tickets,
  users,
  venues,
  type InsertUser,
} from "../drizzle/schema";
import { ENV } from "./_core/env";

let _db: ReturnType<typeof drizzle> | null = null;

export async function getDb() {
  if (!_db && process.env.DATABASE_URL) {
    try {
      _db = drizzle(new Pool({ connectionString: process.env.DATABASE_URL }));
    } catch (error) {
      console.warn("[Database] Failed to connect:", error);
      _db = null;
    }
  }
  return _db;
}

export type Database = NonNullable<Awaited<ReturnType<typeof getDb>>>;

export async function upsertUser(user: InsertUser): Promise<void> {
  if (!user.openId) throw new Error("User openId is required for upsert");
  const db = await getDb();
  if (!db) return;

  const values: InsertUser = {
    openId: user.openId,
    name: user.name ?? null,
    email: user.email ?? null,
    loginMethod: user.loginMethod ?? null,
    lastSignedIn: user.lastSignedIn ?? new Date(),
  };
  const updateSet: Record<string, unknown> = {
    name: values.name,
    email: values.email,
    loginMethod: values.loginMethod,
    lastSignedIn: values.lastSignedIn,
  };

  if (user.role) {
    values.role = user.role;
    updateSet.role = user.role;
  } else if (user.openId === ENV.ownerOpenId) {
    values.role = "admin";
    updateSet.role = "admin";
  }

  await db
    .insert(users)
    .values(values)
    .onConflictDoUpdate({ target: users.openId, set: updateSet });
}

export async function getUserByOpenId(openId: string) {
  const db = await getDb();
  if (!db) return undefined;
  const result = await db.select().from(users).where(eq(users.openId, openId)).limit(1);
  return result[0];
}

export async function listPublishedEvents() {
  const db = await getDb();
  if (!db) return [];
  return db
    .select({
      id: events.id,
      name: events.name,
      slug: events.slug,
      category: events.category,
      description: events.description,
      startTime: events.startTime,
      endTime: events.endTime,
      status: events.status,
      maxTicketsPerUser: events.maxTicketsPerUser,
      venueId: venues.id,
      venueName: venues.name,
      venueAddress: venues.address,
      capacity: venues.capacity,
      // Postgres returns COUNT(*) as bigint, which node-postgres hands back as a
      // string. Cast to int so the client receives a number, as it did on MySQL.
      availableSeats: sql<number>`(SELECT COUNT(*)::int FROM inventory AS availableInventory WHERE availableInventory.eventId = events.id AND availableInventory.status = 'AVAILABLE')`,
    })
    .from(events)
    .innerJoin(venues, eq(events.venueId, venues.id))
    .where(eq(events.status, "PUBLISHED"))
    .orderBy(asc(events.startTime));
}

export async function getEventDetails(eventId: number) {
  const db = await getDb();
  if (!db) return null;
  const event = await db
    .select({
      id: events.id,
      name: events.name,
      slug: events.slug,
      category: events.category,
      description: events.description,
      startTime: events.startTime,
      endTime: events.endTime,
      status: events.status,
      maxTicketsPerUser: events.maxTicketsPerUser,
      venueId: venues.id,
      venueName: venues.name,
      venueAddress: venues.address,
      capacity: venues.capacity,
    })
    .from(events)
    .innerJoin(venues, eq(events.venueId, venues.id))
    .where(eq(events.id, eventId))
    .limit(1);
  if (!event[0]) return null;

  const types = await db.select().from(ticketTypes).where(eq(ticketTypes.eventId, eventId));
  return { ...event[0], ticketTypes: types };
}

export async function getEventSeats(eventId: number) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select({
      inventoryId: inventory.id,
      eventId: inventory.eventId,
      seatId: seats.id,
      section: seats.section,
      row: seats.row,
      number: seats.number,
      seatType: seats.seatType,
      status: inventory.status,
      updatedAt: inventory.updatedAt,
    })
    .from(inventory)
    .innerJoin(seats, eq(inventory.seatId, seats.id))
    .where(eq(inventory.eventId, eventId))
    .orderBy(asc(seats.section), asc(seats.row), asc(seats.number));
}

export async function getReservationDetails(reservationId: number, userId?: number) {
  const db = await getDb();
  if (!db) return null;
  const conditions = [eq(reservations.id, reservationId)];
  if (userId) conditions.push(eq(reservations.userId, userId));
  const reservation = await db
    .select({
      id: reservations.id,
      userId: reservations.userId,
      eventId: reservations.eventId,
      status: reservations.status,
      expiresAt: reservations.expiresAt,
      totalAmount: reservations.totalAmount,
      createdAt: reservations.createdAt,
      eventName: events.name,
      maxTicketsPerUser: events.maxTicketsPerUser,
    })
    .from(reservations)
    .innerJoin(events, eq(reservations.eventId, events.id))
    .where(and(...conditions))
    .limit(1);
  if (!reservation[0]) return null;

  const items = await db
    .select({
      reservationItemId: reservationItems.id,
      inventoryId: inventory.id,
      seatId: seats.id,
      section: seats.section,
      row: seats.row,
      number: seats.number,
      seatType: seats.seatType,
      unitPrice: reservationItems.unitPrice,
    })
    .from(reservationItems)
    .innerJoin(inventory, eq(reservationItems.inventoryId, inventory.id))
    .innerJoin(seats, eq(inventory.seatId, seats.id))
    .where(eq(reservationItems.reservationId, reservationId));

  return { ...reservation[0], items };
}

export async function getBookingDetails(bookingId: number, userId?: number) {
  const db = await getDb();
  if (!db) return null;
  const conditions = [eq(bookings.id, bookingId)];
  if (userId) conditions.push(eq(bookings.userId, userId));
  const booking = await db
    .select({
      id: bookings.id,
      userId: bookings.userId,
      eventId: bookings.eventId,
      reservationId: bookings.reservationId,
      status: bookings.status,
      totalAmount: bookings.totalAmount,
      confirmedAt: bookings.confirmedAt,
      eventName: events.name,
      startTime: events.startTime,
      venueName: venues.name,
    })
    .from(bookings)
    .innerJoin(events, eq(bookings.eventId, events.id))
    .innerJoin(venues, eq(events.venueId, venues.id))
    .where(and(...conditions))
    .limit(1);
  if (!booking[0]) return null;

  const ticketRows = await db
    .select({
      id: tickets.id,
      publicCode: tickets.publicCode,
      status: tickets.status,
      inventoryId: inventory.id,
      section: seats.section,
      row: seats.row,
      number: seats.number,
      seatType: seats.seatType,
    })
    .from(tickets)
    .innerJoin(inventory, eq(tickets.inventoryId, inventory.id))
    .innerJoin(seats, eq(inventory.seatId, seats.id))
    .where(eq(tickets.bookingId, bookingId));
  return { ...booking[0], tickets: ticketRows };
}

export async function listUserBookings(userId: number) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select({
      id: bookings.id,
      eventId: bookings.eventId,
      eventName: events.name,
      startTime: events.startTime,
      venueName: venues.name,
      status: bookings.status,
      totalAmount: bookings.totalAmount,
      confirmedAt: bookings.confirmedAt,
    })
    .from(bookings)
    .innerJoin(events, eq(bookings.eventId, events.id))
    .innerJoin(venues, eq(events.venueId, venues.id))
    .where(eq(bookings.userId, userId))
    .orderBy(desc(bookings.createdAt));
}

export async function listUserTickets(userId: number) {
  const db = await getDb();
  if (!db) return [];
  return db
    .select({
      id: tickets.id,
      publicCode: tickets.publicCode,
      status: tickets.status,
      bookingId: bookings.id,
      eventId: events.id,
      eventName: events.name,
      startTime: events.startTime,
      venueName: venues.name,
      section: seats.section,
      row: seats.row,
      number: seats.number,
    })
    .from(tickets)
    .innerJoin(bookings, eq(tickets.bookingId, bookings.id))
    .innerJoin(events, eq(tickets.eventId, events.id))
    .innerJoin(venues, eq(events.venueId, venues.id))
    .innerJoin(inventory, eq(tickets.inventoryId, inventory.id))
    .innerJoin(seats, eq(inventory.seatId, seats.id))
    .where(eq(tickets.userId, userId))
    .orderBy(desc(tickets.createdAt));
}

export async function getPublicTicket(publicCode: string) {
  const db = await getDb();
  if (!db) return null;
  const rows = await db
    .select({
      id: tickets.id,
      publicCode: tickets.publicCode,
      status: tickets.status,
      bookingId: bookings.id,
      eventId: events.id,
      eventName: events.name,
      description: events.description,
      startTime: events.startTime,
      endTime: events.endTime,
      venueName: venues.name,
      venueAddress: venues.address,
      section: seats.section,
      row: seats.row,
      number: seats.number,
      seatType: seats.seatType,
    })
    .from(tickets)
    .innerJoin(bookings, eq(tickets.bookingId, bookings.id))
    .innerJoin(events, eq(tickets.eventId, events.id))
    .innerJoin(venues, eq(events.venueId, venues.id))
    .innerJoin(inventory, eq(tickets.inventoryId, inventory.id))
    .innerJoin(seats, eq(inventory.seatId, seats.id))
    .where(eq(tickets.publicCode, publicCode))
    .limit(1);
  return rows[0] ?? null;
}

export async function listAdminReservations() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(reservations).orderBy(desc(reservations.createdAt)).limit(100);
}

export async function listAdminBookings() {
  const db = await getDb();
  if (!db) return [];
  return db.select().from(bookings).orderBy(desc(bookings.createdAt)).limit(100);
}

export async function listAdminInventory(eventId: number) {
  const db = await getDb();
  if (!db) return [];
  return getEventSeats(eventId);
}

export async function listOrganizerEvents(userId: number) {
  const db = await getDb();
  if (!db) return [];
  return db.select({
    id: events.id,
    name: events.name,
    category: events.category,
    status: events.status,
    startTime: events.startTime,
    endTime: events.endTime,
    venueName: venues.name,
    venueAddress: venues.address,
    capacity: venues.capacity,
  }).from(events).innerJoin(venues, eq(events.venueId, venues.id)).where(eq(events.organizerId, userId)).orderBy(desc(events.createdAt));
}

export const dbUtils = { and, asc, desc, eq, inArray, lt, sql };
