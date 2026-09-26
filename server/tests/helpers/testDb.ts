import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Pool } from "pg";
import { drizzle } from "drizzle-orm/node-postgres";
import { sql } from "drizzle-orm";
import * as schema from "../../../drizzle/schema";
import { venues, events, seats, inventory, ticketTypes, users } from "../../../drizzle/schema";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");

/**
 * A real PostgreSQL database for the concurrency tests.
 *
 * The tests that used to live at server/tests/concurrency.test.ts asserted that
 * two hand-written async functions in the same file could not both win. That is
 * a property of the test file, not of the booking service: it never opened a
 * connection, so it stayed green no matter what the SQL did. Everything that
 * makes concurrent booking safe here is enforced by Postgres -- SELECT ... FOR
 * UPDATE on the user row, SELECT ... FOR UPDATE on the inventory rows in id
 * order, and the unique constraint on idempotency keys -- and none of it is
 * observable from a single-threaded double.
 *
 * So the tests run against a real server. They use a database of their own,
 * tixify_app_test, so a destructive truncate can never touch development data.
 */

const ADMIN_URL =
  process.env.TEST_DATABASE_ADMIN_URL ??
  process.env.ADMIN_DATABASE_URL ??
  "postgres://postgres:postgres@127.0.0.1:5432/postgres";

const TEST_DB_NAME = process.env.TEST_DATABASE_NAME ?? "tixify_app_test";

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ??
  (() => {
    const url = new URL(ADMIN_URL);
    url.pathname = `/${TEST_DB_NAME}`;
    return url.toString();
  })();

/** Undefined when no server is reachable, which is what the suites skip on. */
let pool: Pool | undefined;
let unavailable: string | undefined;

async function pgClient() {
  const { default: pg } = await import("pg");
  return new pg.Client({ connectionString: ADMIN_URL });
}

/**
 * Create the test database if it is missing and apply the schema.
 *
 * The baseline is applied by reading drizzle/0000_postgres_baseline.sql and
 * splitting on the marker drizzle-kit writes between statements, rather than by
 * shelling out to drizzle-kit, so a test run does not depend on a CLI being
 * resolvable and the schema applied is exactly the committed one.
 */
export async function ensureTestDatabase(): Promise<string | undefined> {
  if (unavailable) return unavailable;
  if (pool) return undefined;

  let admin;
  try {
    admin = await pgClient();
    await admin.connect();
  } catch (error) {
    unavailable = (error as Error).message;
    return unavailable;
  }

  try {
    const { rows } = await admin.query("SELECT 1 FROM pg_database WHERE datname = $1", [
      TEST_DB_NAME,
    ]);
    if (rows.length === 0) {
      // CREATE DATABASE cannot be parameterised, hence the quoted identifier.
      // The name comes from our own environment, not from a request.
      await admin.query(`CREATE DATABASE "${TEST_DB_NAME.replace(/"/g, '""')}"`);
    }
  } finally {
    await admin.end();
  }

  pool = new Pool({ connectionString: TEST_DATABASE_URL, max: 20 });
  await applySchema();
  return undefined;
}

/**
 * Apply the committed baseline, skipping it if the tables are already there.
 *
 * The test database is reused between runs on purpose, so this is a no-op after
 * the first one. Re-running the baseline would fail on CREATE TYPE for a type
 * that already exists.
 */
async function applySchema() {
  const client = await pool!.connect();
  try {
    const { rows } = await client.query(
      "SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'users'",
    );
    if (rows.length > 0) return;

    const baseline = await readFile(
      resolve(repoRoot, "drizzle", "0000_postgres_baseline.sql"),
      "utf8",
    );
    // drizzle-kit separates statements with this marker; the file may or may
    // not end with one, hence the filter.
    for (const statement of baseline.split("--> statement-breakpoint").filter((s) => s.trim())) {
      await client.query(statement);
    }
  } finally {
    client.release();
  }
}

export type TestDatabase = ReturnType<typeof drizzle<typeof schema>>;

export function getTestDb(): TestDatabase {
  if (!pool) throw new Error("ensureTestDatabase() must resolve before getTestDb()");
  return drizzle(pool, { schema });
}

export async function closeTestDatabase() {
  await pool?.end();
  pool = undefined;
}

/**
 * Empty every table the booking service touches.
 *
 * TRUNCATE ... CASCADE in one statement, so the foreign keys between
 * reservationItems, bookings, payments and inventory cannot block the reset and
 * the tables stay consistent with each other for the next test.
 */
export async function resetTestDatabase() {
  const db = getTestDb();
  await db.execute(sql`
    TRUNCATE TABLE
      "reservationItems", "reservations", "bookingItems", "bookings",
      "payments", "tickets", "idempotencyKeys",
      "inventory", "seats", "ticketTypes", "events", "venues", "users"
    RESTART IDENTITY CASCADE
  `);
}

export type SeededEvent = {
  eventId: number;
  seatIds: number[];
  inventoryIds: number[];
  maxTicketsPerUser: number;
  price: string;
};

/** Create a published event with `seatCount` bookable seats. */
export async function seedEvent(options?: {
  seatCount?: number;
  maxTicketsPerUser?: number;
  price?: string;
  organizerId?: number;
}): Promise<SeededEvent> {
  const db = getTestDb();
  const seatCount = options?.seatCount ?? 6;
  const price = options?.price ?? "50.00";

  const [venue] = await db
    .insert(venues)
    .values({ name: "Test Venue", address: "1 Test Street", capacity: seatCount })
    .returning({ id: venues.id });

  const [event] = await db
    .insert(events)
    .values({
      venueId: venue.id,
      organizerId: options?.organizerId ?? null,
      name: "Test Event",
      slug: `test-event-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      category: "Technology",
      description: "An event that exists so that races can be run against it.",
      startTime: new Date(Date.now() + 86_400_000),
      endTime: new Date(Date.now() + 90_000_000),
      status: "PUBLISHED",
      maxTicketsPerUser: options?.maxTicketsPerUser ?? 4,
    })
    .returning({ id: events.id });

  await db.insert(ticketTypes).values({
    eventId: event.id,
    name: "General Admission",
    price,
    quantity: seatCount,
    maxPerUser: options?.maxTicketsPerUser ?? 4,
  });

  const seatRows = await db
    .insert(seats)
    .values(
      Array.from({ length: seatCount }, (_, index) => ({
        venueId: venue.id,
        section: "A",
        row: String.fromCharCode(65 + Math.floor(index / 10)),
        number: (index % 10) + 1,
        seatType: "STANDARD" as const,
      })),
    )
    .returning({ id: seats.id });

  const inventoryRows = await db
    .insert(inventory)
    .values(
      seatRows.map((seat) => ({
        eventId: event.id,
        seatId: seat.id,
        status: "AVAILABLE" as const,
      })),
    )
    .returning({ id: inventory.id });

  return {
    eventId: event.id,
    seatIds: seatRows.map((seat) => seat.id),
    inventoryIds: inventoryRows.map((row) => row.id),
    maxTicketsPerUser: options?.maxTicketsPerUser ?? 4,
    price,
  };
}

export async function seedUser(role: "user" | "admin" = "user") {
  const db = getTestDb();
  const [user] = await db
    .insert(users)
    .values({
      openId: `test-open-id-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`,
      name: "Test User",
      email: `test-${Math.random().toString(36).slice(2, 10)}@example.com`,
      role,
    })
    .returning({ id: users.id, role: users.role });
  return user;
}

/** How many of an event's inventory rows are in a given status. */
export async function countInventoryByStatus(eventId: number, status: string) {
  const db = getTestDb();
  // drizzle-orm 0.44 returns a QueryResult from execute(); the array of rows is
  // on its `rows` property.
  const result = await db.execute(
    sql`SELECT status::text AS status, count(*)::int AS count
        FROM "inventory" WHERE "eventId" = ${eventId} GROUP BY status`,
  );
  const match = result.rows.find((row) => (row as { status: string }).status === status);
  return match ? Number((match as { count: number }).count) : 0;
}

/** Which reservation, if any, currently holds this inventory row. */
export async function reservationIdForInventory(inventoryId: number) {
  const db = getTestDb();
  const result = await db.execute(
    sql`SELECT "reservationId" FROM "inventory" WHERE id = ${inventoryId}`,
  );
  const row = result.rows[0] as { reservationId: number | null } | undefined;
  return row?.reservationId ?? null;
}

/** Exact row count, for assertions that must not depend on grouping. */
export async function countRows(table: "reservations" | "tickets" | "payments") {
  const db = getTestDb();
  // The table name comes from the union above, never from input, so it is safe
  // to inline; identifiers cannot be parameterised.
  const result = await db.execute(
    sql.raw(`SELECT count(*)::int AS count FROM "${table}"`),
  );
  return Number((result.rows[0] as { count: number }).count);
}

/** Exact row count of tickets belonging to one booking. */
export async function countTicketsForBooking(bookingId: number) {
  const db = getTestDb();
  const result = await db.execute(
    sql`SELECT count(*)::int AS count FROM "tickets" WHERE "bookingId" = ${bookingId}`,
  );
  return Number((result.rows[0] as { count: number }).count);
}
