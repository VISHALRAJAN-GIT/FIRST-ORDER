CREATE TYPE "public"."booking_status" AS ENUM('PENDING', 'CONFIRMED', 'CANCELLED');--> statement-breakpoint
CREATE TYPE "public"."event_status" AS ENUM('DRAFT', 'PUBLISHED', 'SOLD_OUT', 'CANCELLED', 'COMPLETED');--> statement-breakpoint
CREATE TYPE "public"."inventory_status" AS ENUM('AVAILABLE', 'RESERVED', 'SOLD', 'CANCELLED');--> statement-breakpoint
CREATE TYPE "public"."payment_status" AS ENUM('PENDING', 'SUCCEEDED', 'FAILED', 'REFUNDED');--> statement-breakpoint
CREATE TYPE "public"."reservation_status" AS ENUM('RESERVED', 'PAYMENT_PENDING', 'CONFIRMED', 'EXPIRED', 'PAYMENT_FAILED', 'CANCELLED');--> statement-breakpoint
CREATE TYPE "public"."seat_type" AS ENUM('VIP', 'PREMIUM', 'STANDARD');--> statement-breakpoint
CREATE TYPE "public"."ticket_status" AS ENUM('VALID', 'CANCELLED');--> statement-breakpoint
CREATE TYPE "public"."user_role" AS ENUM('user', 'admin');--> statement-breakpoint
CREATE TABLE "bookingItems" (
	"id" serial PRIMARY KEY NOT NULL,
	"bookingId" integer NOT NULL,
	"inventoryId" integer NOT NULL,
	"unitPrice" numeric(10, 2) NOT NULL,
	"createdAt" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "bookings" (
	"id" serial PRIMARY KEY NOT NULL,
	"userId" integer NOT NULL,
	"eventId" integer NOT NULL,
	"reservationId" integer NOT NULL,
	"status" "booking_status" DEFAULT 'PENDING' NOT NULL,
	"totalAmount" numeric(10, 2) NOT NULL,
	"confirmedAt" timestamp with time zone,
	"createdAt" timestamp with time zone DEFAULT now() NOT NULL,
	"updatedAt" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "bookings_reservationId_unique" UNIQUE("reservationId")
);
--> statement-breakpoint
CREATE TABLE "events" (
	"id" serial PRIMARY KEY NOT NULL,
	"venueId" integer NOT NULL,
	"organizerId" integer,
	"name" varchar(180) NOT NULL,
	"slug" varchar(180) NOT NULL,
	"category" varchar(64) DEFAULT 'Technology' NOT NULL,
	"description" text NOT NULL,
	"startTime" timestamp with time zone NOT NULL,
	"endTime" timestamp with time zone NOT NULL,
	"status" "event_status" DEFAULT 'DRAFT' NOT NULL,
	"maxTicketsPerUser" integer DEFAULT 4 NOT NULL,
	"createdAt" timestamp with time zone DEFAULT now() NOT NULL,
	"updatedAt" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "events_slug_unique" UNIQUE("slug")
);
--> statement-breakpoint
CREATE TABLE "idempotencyKeys" (
	"id" serial PRIMARY KEY NOT NULL,
	"key" varchar(128) NOT NULL,
	"userId" integer NOT NULL,
	"operation" varchar(80) NOT NULL,
	"requestHash" varchar(128) NOT NULL,
	"responseJson" text,
	"createdAt" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "inventory" (
	"id" serial PRIMARY KEY NOT NULL,
	"eventId" integer NOT NULL,
	"seatId" integer NOT NULL,
	"status" "inventory_status" DEFAULT 'AVAILABLE' NOT NULL,
	"reservationId" integer,
	"bookingId" integer,
	"updatedAt" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "payments" (
	"id" serial PRIMARY KEY NOT NULL,
	"bookingId" integer NOT NULL,
	"reservationId" integer NOT NULL,
	"provider" varchar(48) DEFAULT 'mock' NOT NULL,
	"providerPaymentId" varchar(128) NOT NULL,
	"amount" numeric(10, 2) NOT NULL,
	"status" "payment_status" DEFAULT 'PENDING' NOT NULL,
	"idempotencyKey" varchar(128),
	"createdAt" timestamp with time zone DEFAULT now() NOT NULL,
	"updatedAt" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "payments_providerPaymentId_unique" UNIQUE("providerPaymentId")
);
--> statement-breakpoint
CREATE TABLE "reservationItems" (
	"id" serial PRIMARY KEY NOT NULL,
	"reservationId" integer NOT NULL,
	"inventoryId" integer NOT NULL,
	"unitPrice" numeric(10, 2) NOT NULL,
	"createdAt" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "reservations" (
	"id" serial PRIMARY KEY NOT NULL,
	"userId" integer NOT NULL,
	"eventId" integer NOT NULL,
	"status" "reservation_status" DEFAULT 'RESERVED' NOT NULL,
	"expiresAt" timestamp with time zone NOT NULL,
	"totalAmount" numeric(10, 2) NOT NULL,
	"createdAt" timestamp with time zone DEFAULT now() NOT NULL,
	"updatedAt" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "seats" (
	"id" serial PRIMARY KEY NOT NULL,
	"venueId" integer NOT NULL,
	"section" varchar(32) NOT NULL,
	"row" varchar(32) NOT NULL,
	"number" integer NOT NULL,
	"seatType" "seat_type" DEFAULT 'STANDARD' NOT NULL,
	"createdAt" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "ticketTypes" (
	"id" serial PRIMARY KEY NOT NULL,
	"eventId" integer NOT NULL,
	"name" varchar(80) NOT NULL,
	"price" numeric(10, 2) NOT NULL,
	"quantity" integer NOT NULL,
	"maxPerUser" integer DEFAULT 4 NOT NULL,
	"createdAt" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "tickets" (
	"id" serial PRIMARY KEY NOT NULL,
	"bookingId" integer NOT NULL,
	"userId" integer NOT NULL,
	"eventId" integer NOT NULL,
	"inventoryId" integer NOT NULL,
	"publicCode" varchar(64) NOT NULL,
	"status" "ticket_status" DEFAULT 'VALID' NOT NULL,
	"createdAt" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tickets_publicCode_unique" UNIQUE("publicCode")
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" serial PRIMARY KEY NOT NULL,
	"openId" varchar(64) NOT NULL,
	"name" text,
	"email" varchar(320),
	"loginMethod" varchar(64),
	"role" "user_role" DEFAULT 'user' NOT NULL,
	"createdAt" timestamp with time zone DEFAULT now() NOT NULL,
	"updatedAt" timestamp with time zone DEFAULT now() NOT NULL,
	"lastSignedIn" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "users_openId_unique" UNIQUE("openId")
);
--> statement-breakpoint
CREATE TABLE "venues" (
	"id" serial PRIMARY KEY NOT NULL,
	"name" varchar(160) NOT NULL,
	"address" varchar(255) NOT NULL,
	"capacity" integer NOT NULL,
	"createdAt" timestamp with time zone DEFAULT now() NOT NULL,
	"updatedAt" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "bookingItems" ADD CONSTRAINT "bookingItems_bookingId_bookings_id_fk" FOREIGN KEY ("bookingId") REFERENCES "public"."bookings"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "bookingItems" ADD CONSTRAINT "bookingItems_inventoryId_inventory_id_fk" FOREIGN KEY ("inventoryId") REFERENCES "public"."inventory"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "bookings" ADD CONSTRAINT "bookings_userId_users_id_fk" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "bookings" ADD CONSTRAINT "bookings_eventId_events_id_fk" FOREIGN KEY ("eventId") REFERENCES "public"."events"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "bookings" ADD CONSTRAINT "bookings_reservationId_reservations_id_fk" FOREIGN KEY ("reservationId") REFERENCES "public"."reservations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "events" ADD CONSTRAINT "events_venueId_venues_id_fk" FOREIGN KEY ("venueId") REFERENCES "public"."venues"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "events" ADD CONSTRAINT "events_organizerId_users_id_fk" FOREIGN KEY ("organizerId") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "idempotencyKeys" ADD CONSTRAINT "idempotencyKeys_userId_users_id_fk" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "inventory" ADD CONSTRAINT "inventory_eventId_events_id_fk" FOREIGN KEY ("eventId") REFERENCES "public"."events"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "inventory" ADD CONSTRAINT "inventory_seatId_seats_id_fk" FOREIGN KEY ("seatId") REFERENCES "public"."seats"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "payments" ADD CONSTRAINT "payments_bookingId_bookings_id_fk" FOREIGN KEY ("bookingId") REFERENCES "public"."bookings"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "payments" ADD CONSTRAINT "payments_reservationId_reservations_id_fk" FOREIGN KEY ("reservationId") REFERENCES "public"."reservations"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "reservationItems" ADD CONSTRAINT "reservationItems_reservationId_reservations_id_fk" FOREIGN KEY ("reservationId") REFERENCES "public"."reservations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "reservationItems" ADD CONSTRAINT "reservationItems_inventoryId_inventory_id_fk" FOREIGN KEY ("inventoryId") REFERENCES "public"."inventory"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "reservations" ADD CONSTRAINT "reservations_userId_users_id_fk" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "reservations" ADD CONSTRAINT "reservations_eventId_events_id_fk" FOREIGN KEY ("eventId") REFERENCES "public"."events"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "seats" ADD CONSTRAINT "seats_venueId_venues_id_fk" FOREIGN KEY ("venueId") REFERENCES "public"."venues"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticketTypes" ADD CONSTRAINT "ticketTypes_eventId_events_id_fk" FOREIGN KEY ("eventId") REFERENCES "public"."events"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tickets" ADD CONSTRAINT "tickets_bookingId_bookings_id_fk" FOREIGN KEY ("bookingId") REFERENCES "public"."bookings"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tickets" ADD CONSTRAINT "tickets_userId_users_id_fk" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tickets" ADD CONSTRAINT "tickets_eventId_events_id_fk" FOREIGN KEY ("eventId") REFERENCES "public"."events"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tickets" ADD CONSTRAINT "tickets_inventoryId_inventory_id_fk" FOREIGN KEY ("inventoryId") REFERENCES "public"."inventory"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "booking_items_unique_idx" ON "bookingItems" USING btree ("bookingId","inventoryId");--> statement-breakpoint
CREATE INDEX "booking_items_booking_idx" ON "bookingItems" USING btree ("bookingId");--> statement-breakpoint
CREATE INDEX "bookings_user_idx" ON "bookings" USING btree ("userId");--> statement-breakpoint
CREATE INDEX "bookings_event_idx" ON "bookings" USING btree ("eventId");--> statement-breakpoint
CREATE INDEX "events_status_idx" ON "events" USING btree ("status");--> statement-breakpoint
CREATE INDEX "events_start_time_idx" ON "events" USING btree ("startTime");--> statement-breakpoint
CREATE UNIQUE INDEX "idempotency_key_operation_idx" ON "idempotencyKeys" USING btree ("key","userId","operation");--> statement-breakpoint
CREATE INDEX "idempotency_user_idx" ON "idempotencyKeys" USING btree ("userId");--> statement-breakpoint
CREATE UNIQUE INDEX "inventory_event_seat_idx" ON "inventory" USING btree ("eventId","seatId");--> statement-breakpoint
CREATE INDEX "inventory_status_idx" ON "inventory" USING btree ("eventId","status");--> statement-breakpoint
CREATE INDEX "inventory_reservation_idx" ON "inventory" USING btree ("reservationId");--> statement-breakpoint
CREATE INDEX "payments_booking_idx" ON "payments" USING btree ("bookingId");--> statement-breakpoint
CREATE UNIQUE INDEX "payments_idempotency_idx" ON "payments" USING btree ("idempotencyKey");--> statement-breakpoint
CREATE UNIQUE INDEX "reservation_items_unique_idx" ON "reservationItems" USING btree ("reservationId","inventoryId");--> statement-breakpoint
CREATE INDEX "reservation_items_reservation_idx" ON "reservationItems" USING btree ("reservationId");--> statement-breakpoint
CREATE INDEX "reservations_user_idx" ON "reservations" USING btree ("userId");--> statement-breakpoint
CREATE INDEX "reservations_event_idx" ON "reservations" USING btree ("eventId");--> statement-breakpoint
CREATE INDEX "reservations_status_idx" ON "reservations" USING btree ("status");--> statement-breakpoint
CREATE INDEX "reservations_expiry_idx" ON "reservations" USING btree ("expiresAt");--> statement-breakpoint
CREATE UNIQUE INDEX "seats_venue_identity_idx" ON "seats" USING btree ("venueId","section","row","number");--> statement-breakpoint
CREATE INDEX "seats_venue_idx" ON "seats" USING btree ("venueId");--> statement-breakpoint
CREATE INDEX "ticket_types_event_idx" ON "ticketTypes" USING btree ("eventId");--> statement-breakpoint
CREATE UNIQUE INDEX "ticket_types_event_name_idx" ON "ticketTypes" USING btree ("eventId","name");--> statement-breakpoint
CREATE INDEX "tickets_booking_idx" ON "tickets" USING btree ("bookingId");--> statement-breakpoint
CREATE INDEX "tickets_user_idx" ON "tickets" USING btree ("userId");--> statement-breakpoint
CREATE INDEX "users_email_idx" ON "users" USING btree ("email");