import "dotenv/config";
import { and, eq } from "drizzle-orm";
import { getDb } from "./db";
import { events, inventory, seats, ticketTypes, users, venues } from "../drizzle/schema";

async function main() {
  const db = await getDb();
  if (!db) throw new Error("DATABASE_URL is required to seed tixify");

  const existingVenue = (await db.select().from(venues).where(eq(venues.name, "Main Arena")).limit(1))[0];
  const venueId = existingVenue?.id ?? (await db.insert(venues).values({ name: "Main Arena", address: "1 Tixify Way, Mumbai", capacity: 60 }).returning({ id: venues.id }))[0].id;
  const existingEvent = (await db.select().from(events).where(eq(events.slug, "techfest-2026")).limit(1))[0];
  const eventId = existingEvent?.id ?? (await db.insert(events).values({
    venueId,
    name: "TechFest 2026",
    slug: "techfest-2026",
    category: "Technology",
    description: "A high-energy night of future-facing talks, live demos, and builder culture.",
    startTime: new Date(Date.now() + 21 * 24 * 60 * 60 * 1000),
    endTime: new Date(Date.now() + 21 * 24 * 60 * 60 * 1000 + 5 * 60 * 60 * 1000),
    status: "PUBLISHED",
    maxTicketsPerUser: 4,
  }).returning({ id: events.id }))[0].id;

  const typeRows = await db.select().from(ticketTypes).where(eq(ticketTypes.eventId, eventId));
  if (!typeRows.length) {
    await db.insert(ticketTypes).values([
      { eventId, name: "VIP", price: "149.00", quantity: 20, maxPerUser: 4 },
      { eventId, name: "PREMIUM", price: "89.00", quantity: 20, maxPerUser: 4 },
      { eventId, name: "STANDARD", price: "49.00", quantity: 20, maxPerUser: 4 },
    ]);
  }

  for (const section of ["A", "B", "C"]) {
    for (let number = 101; number <= 120; number += 1) {
      const seat = (await db.select().from(seats).where(and(eq(seats.venueId, venueId), eq(seats.section, section), eq(seats.row, section), eq(seats.number, number))).limit(1))[0];
      const seatId = seat?.id ?? (await db.insert(seats).values({ venueId, section, row: section, number, seatType: section === "A" ? "VIP" : section === "B" ? "PREMIUM" : "STANDARD" }).returning({ id: seats.id }))[0].id;
      const currentInventory = (await db.select().from(inventory).where(and(eq(inventory.eventId, eventId), eq(inventory.seatId, seatId))).limit(1))[0];
      if (!currentInventory) await db.insert(inventory).values({ eventId, seatId, status: "AVAILABLE" });
    }
  }

  const seedUsers = [
    { openId: "tixify-demo-user", name: "Demo User", email: "demo.user@example.test", loginMethod: "seed" as const, role: "user" as const },
    { openId: "tixify-demo-admin", name: "Demo Admin", email: "demo.admin@example.test", loginMethod: "seed" as const, role: "admin" as const },
  ];
  for (const user of seedUsers) {
    await db.insert(users).values(user).onConflictDoUpdate({ target: users.openId, set: { name: user.name, email: user.email, role: user.role } });
  }
  console.log(JSON.stringify({ eventId, venueId, seats: 60, seededUsers: seedUsers.map((user) => user.email) }));
}

main().then(() => process.exit(0)).catch((error) => { console.error(error); process.exitCode = 1; });
