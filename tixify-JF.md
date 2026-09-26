# tixify-JF

Tixify is a full-stack event discovery and ticket booking platform built around fair, server-authoritative seat reservations. This folder contains the complete Tixify application, including the public event experience, live inventory, checkout, digital ticket wallet, QR verification, and organizer workspace.

## What Tixify does

- Discover published events with search, category, date, availability, and sort filters.
- View event details and a live seat map.
- Reserve seats for a limited five-minute checkout window.
- Complete a server-verified payment flow with idempotency protections.
- Generate confirmed bookings and digital tickets.
- Display real scannable QR codes in booking receipts and the ticket wallet.
- Route QR scans to a public ticket verification page.
- Download a self-contained HTML pass containing QR codes for every ticket.
- Let authenticated users create organizer-owned events, save drafts, and publish events.

## Organizer workspace

The organizer studio is available at `/organizer` and is also linked from the homepage through **Host an event** and **Organize**.

An organizer can provide:

- Event name and category
- Public event description
- Venue name and address
- Start and end date/time
- Ticket price
- Total ticket/seat slots
- Maximum tickets per attendee

The server creates the venue, event ownership record, ticket type, physical seat rows, and available inventory in one database transaction. Organizers can save a draft or publish immediately. Drafts can later be published only by their owner.

## Main user flows

### Event discovery

The homepage reads published events from the API and derives live availability from inventory. Users can search event names, descriptions, and venues, then filter by category, date range, or available seats.

### Reservation and checkout

1. A user selects seats on an event seat map.
2. The server validates availability and creates a reservation.
3. Inventory rows are updated transactionally and held for five minutes.
4. Checkout displays a live countdown.
5. Payment is created and verified server-side.
6. Successful payment confirms the booking, marks inventory as sold, and creates tickets.
7. Failed or expired payment releases the reservation and inventory.

### Ticket scanning

Ticket QR values point to `/ticket/:publicCode`. The public verification page resolves the code through `publicTickets.get` and displays the event, venue, seat, ticket status, and a verification state. No user login is required for entrance verification.

## Technology stack

- React 19 + Vite
- TypeScript
- Tailwind CSS 4
- Express
- tRPC 11
- Drizzle ORM
- PostgreSQL database (shared with the Person 2 security engine)
- Manus OAuth authentication
- Vitest
- `qrcode` for QR generation
- Wouter for client-side routing

## Project structure

```text
client/
  src/
    components/       Reusable UI, including TicketQr
    lib/              tRPC client and tested discovery/countdown helpers
    pages/            Home, event, checkout, booking, tickets, organizer, and verification pages
    App.tsx           Route map
    index.css         Tixify visual design system

drizzle/
  schema.ts           Users, events, venues, seats, inventory, reservations, payments, bookings, tickets
  migrations/         Generated schema migrations

server/
  db.ts               Drizzle query helpers
  routers.ts          Typed public, protected, organizer, and admin API procedures
  services/           Reservation, payment, and booking lifecycle logic
  seed.ts             Repeatable development seed data

shared/
  const.ts             Shared application constants

docs/
  ARCHITECTURE.md      System architecture
  API_CONTRACT.md      tRPC API contract
  BOOKING_FLOW.md      Reservation and payment lifecycle
  CONCURRENCY.md       Row locking and oversell prevention
  DATABASE_SCHEMA.md   Database design
  REALTIME.md          Inventory event stream
  SECURITY_INTEGRATION.md  Future security-engine integration boundary
```

## Local development

### Prerequisites

- Node.js 22 or newer
- pnpm 10 or newer
- PostgreSQL database
- Manus OAuth credentials or a configured local authentication environment

### Install dependencies

```bash
pnpm install
```

### Configure environment

Copy the example environment file and fill in values through your local secret-management workflow:

```bash
cp .env.example .env
```

Important variables include:

- `DATABASE_URL`
- `JWT_SECRET`
- `VITE_APP_ID`
- `OAUTH_SERVER_URL`
- `VITE_OAUTH_PORTAL_URL`
- `OWNER_OPEN_ID`
- `OWNER_NAME`

Never commit real secrets or production `.env` files.

### Database

Generate migrations after schema changes:

```bash
pnpm drizzle-kit generate
```

Review the generated SQL before applying it. For local development, use the project database migration workflow:

```bash
pnpm db:push
```

Seed repeatable demo data:

```bash
pnpm db:seed
```

The seed includes the TechFest 2026 demo event, venue seating, ticket types, and demo accounts.

### Run the app

```bash
pnpm dev
```

The development server serves the React frontend and Express/tRPC API from one process.

## Validation commands

```bash
pnpm check   # TypeScript validation
pnpm test    # Unit, concurrency, countdown, discovery, and QR tests
pnpm build   # Production frontend and server build
```

The current suite covers:

- Auth logout behavior
- Reservation transitions and expiry math
- Concurrency and oversell protection models
- Countdown formatting and progress calculations
- Discovery filtering and sorting
- QR payload generation

## API areas

- `events.list`, `events.get`, `events.seats` — public discovery and seat map data
- `organizer.events` — authenticated organizer-owned event list
- `organizer.createEvent` — transactional event, venue, ticket, seat, and inventory creation
- `organizer.publishEvent` — owner-only draft publishing
- `reservations.create`, `reservations.get`, `reservations.cancel`, `reservations.expire`
- `payments.create`, `payments.verify`, `payments.webhook`
- `bookings.create`, `bookings.get`, `bookings.mine`
- `tickets.mine`, `tickets.get`
- `publicTickets.get` — public QR ticket verification
- `admin.*` — protected operational views and legacy admin actions

## Security and data rules

- Seat availability is authoritative in the database, not in client state.
- Reservation and payment transitions are validated server-side.
- Idempotency keys prevent duplicate reservation/payment operations.
- Organizer event listing and publishing are authenticated and owner-scoped.
- Public QR verification exposes only the event and ticket details required at entrance.
- Timestamps are persisted as UTC-compatible database timestamps and localized for display.
- Ticket bytes are not stored in the database; QR codes are generated from public ticket URLs.

## Deployment notes

Tixify is designed to run as a single Node/Express web process behind a managed runtime. The realtime inventory stream currently uses an internal event bus for the single-instance deployment seam. For multi-instance deployment, replace that bus with Redis or another shared pub/sub layer as described in `docs/REALTIME.md`.

## License

This project is maintained as part of the FIRST-ORDER repository. Add the repository’s final license terms before public distribution.
