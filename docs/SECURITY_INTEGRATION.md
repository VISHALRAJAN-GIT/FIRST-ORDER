# Security Engine Integration Guide

For Person 1's application team. This is the wiring guide: what to construct, in
what order, and which decisions are yours rather than the engine's.

`SECURITY_ARCHITECTURE.md` explains *why* the engine is shaped this way. This
document is only about connecting it to an application.

---

## 1. What you get

The engine is a library, not a service. It has no HTTP server, no scheduler and
no opinion about your framework. You construct the components you need, pass
them your repositories, and either call them directly or mount the Part 13
router.

| Part | Component | Import |
| --- | --- | --- |
| 2-3 | `TicketSigner`, `TicketVerifier`, `TicketIssuer` | `tickets` |
| 3 | `ReplayGuard` | `replay` |
| 4 | `IdempotencyGuard` + `RedisIdempotencyStore` | `idempotency` |
| 5 | `BotProtection`, `ChallengeStore` | `bot-protection` |
| 6 | `RateLimiter` | `rate-limit` |
| 7 | `VirtualQueue` | `queue` |
| 9 | `sanitizeBody`, `parseOrThrow` | `validation` |
| 11 | `TelemetrySink` | `telemetry` |
| 12 | `SecurityDashboard` | `dashboard` |
| 13 | `SecurityApi` | `api` |

Everything is re-exported from the package root:

```ts
import { TicketVerifier, SecurityApi, RateLimiter } from '@first-order/security-engine';
```

---

## 2. The three interfaces you must implement

The engine never talks to your database. You implement these; the engine calls
them. This is deliberate — it is what lets the engine be tested against
in-memory doubles and what keeps the security tables owned by Person 2 while
your tables stay yours.

```ts
// Who is this request from? Return null for anonymous — do not throw.
interface UserResolver {
  resolve(credential: unknown): Promise<AuthenticatedPrincipal | null>;
}

// Authoritative ticket state. The engine holds a signed QR; you hold the truth.
interface TicketRepository {
  // Non-consuming read. Return null when absent — the engine translates that to
  // TICKET_NOT_FOUND without leaking existence.
  findById(ticketId: string): Promise<TicketRecord | null>;

  // Must be ONE atomic statement. See below.
  consumeConfirmedTicket(
    ticketId: string,
    expectedVersion: number,
    context: { eventId: string; scannerId?: string; actorId?: string; ipHash?: string },
  ): Promise<
    | { ok: true; ticket: TicketRecord }
    | { ok: false; reason: 'ALREADY_USED' | 'NOT_CONFIRMED'; ticket?: TicketRecord }
    | { ok: false; reason: 'NOT_FOUND' }
  >;

  // Optional: persist the signed envelope so verification does not re-sign.
  saveSignedPayload?(ticketId: string, envelope: string): Promise<void>;
}

// Active booking sessions, used to decide when the queue engages.
interface EventRepository {
  findById(eventId: string): Promise<EventRecord | null>;
  activeSessionCount(eventId: string): Promise<number>;
}
```

`AuthenticatedPrincipal` uses a **plural** `roles` array. There is no `role`
field. Admin is the string `'ADMIN'`.

### The one that matters most

`consumeConfirmedTicket` is the whole replay-prevention guarantee, and it is
yours to get right:

```sql
UPDATE tickets
   SET state = 'USED', used_at = $3, version = version + 1
 WHERE id = $1
   AND version = $2
   AND state = 'CONFIRMED'
 RETURNING *;
```

Three properties are required:

1. **One statement.** A `SELECT` then an `UPDATE` has a race between them.
2. **Guarded on `state` and `version`.** This is what makes two concurrent scans
   of the same QR produce exactly one winner.
3. **Return `{ ok: true }` only if a row changed.** Zero rows means the ticket
   was already `USED`, not `CONFIRMED`, or is gone — distinguish those with a
   follow-up read *if* you need to, but never let the follow-up decide the
   outcome.

If your implementation cannot do this atomically, do not ship the engine and
assume the problem is handled — a non-atomic `consumeConfirmedTicket` silently
turns replay prevention off.

---

## 3. Wiring order

Roughly the order things fail in, so a misconfiguration surfaces immediately
rather than under load.

### 3.1 Keys

```ts
import { KeyRing, generateKeyPair } from '@first-order/security-engine';

const keyRing = KeyRing.fromConfig({
  publicKey: process.env.SECURITY_PUBLIC_KEY,
  // ...the rest of your config
});
```

A `KeyRing` holds one key per `kid` and an `activeKid`. A leaked signing key
means forged tickets, so keys belong on disk or in a secret manager — never in
an env var shared with unrelated config, and never in a database row. The engine
tolerates a retired `kid` for `expiryGraceMs` so tickets issued just before a
rotation still validate.

### 3.2 Redis

```ts
const redis = wrapIoredis(new IORedis(process.env.REDIS_URL!));
```

Redis is required for rate limiting, idempotency, the queue and challenges. It
is not required for ticket verification, which is deliberately dependency-free so
a Redis outage cannot close the gates.

### 3.3 Postgres

```ts
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
await runSecurityMigrations(pool);
```

Run the security migration separately from your app migrations. The engine owns
`security_events`, `audit_logs`, `idempotency_records`, `queue_entries`,
`ticket_scans` and `sec_schema_migrations`; your migration tool should not try to
own them.

### 3.4 Durable idempotency (optional but recommended)

```ts
const mirror = new PostgresIdempotencyStore({ pool, encryptionKey });
const idempotency = new IdempotencyGuard({
  store: new RedisIdempotencyStore({ redis, mirror, namespace: 'booking' }),
});
```

The guard fences every claim with a monotonically increasing token, so a client
retry after a timeout cannot get a second execution. With the mirror, a Redis
flush mid-request cannot lose a completed operation.

`PostgresIdempotencyStore` must **not** be used as the primary store — it
fences correctly but is not fast. Use it as the mirror behind
`RedisIdempotencyStore`.

### 3.5 Tickets

```ts
const verifier = new TicketVerifier({
  signer, ticketRepository, eventRepository, clock,
  seatRepository,   // recommended: catches a valid ticket for the wrong seat
});
```

### 3.6 Queue

```ts
const queue = new VirtualQueue({
  store, codec, redis, keyPrefix: 'q:',
  activeSessionCount: (eventId) => eventRepository.activeSessionCount(eventId),
});
```

`activeSessionCount` is how the queue knows whether to engage. Returning a stale
or always-zero number means the queue never opens under load, or opens when it
should not.

### 3.7 The Part 13 router

```ts
const security = new SecurityApi({
  verifier,
  replayGuard,
  queue,
  userResolver,
  authorizer: new ConfiguredAdminAuthorizer(new Set(adminUserIds)),
  dashboard, rateLimiter, telemetry,
});
```

`handle()` takes a plain object and returns a plain object. It never throws.

#### Express

```ts
import express from 'express';
import { securityMiddleware } from '@first-order/security-engine';

const app = express();
app.use(express.json());

app.use(
  '/',
  securityMiddleware({
    api: security,
    credentialFrom: (req) => req.headers.authorization,
  }),
);
```

`express` is **not** a dependency of this package. The adapter is structurally
typed, so nothing is installed unless you want it.

#### Anything else

```ts
const res = await security.handle({
  method: req.method,
  path: req.url.split('?')[0],
  query: parseQuery(req.url),
  headers: req.headers,
  body: req.body,   // must be parsed; a raw string is rejected with a 400
  ip: req.socket.remoteAddress,
  credential: extractToken(req),
});
```

The five fields are the whole interface. Read `req.query` once and pass a plain
object — Express 5 makes it a getter, and a framework object retained past the
request is a use-after-free.

---

## 4. Endpoints

| Method | Path | Auth | Rate-limit policy |
| --- | --- | --- | --- |
| POST | `/api/tickets/verify` | anonymous | `TICKET_VERIFY` |
| POST | `/api/tickets/scan` | authenticated | `TICKET_VERIFY` |
| GET | `/api/security/status` | admin | `EVENT_LISTING` |
| GET | `/api/security/events` | admin | `EVENT_LISTING` |
| GET | `/api/queue/:eventId/status` | authenticated | `EVENT_LISTING` |
| POST | `/api/queue/:eventId/join` | authenticated | `RESERVATION` |
| POST | `/api/queue/:eventId/leave` | authenticated | `RESERVATION` |

`/api/tickets/verify` **does not consume** the ticket. It is a read, safe to call
before a purchase. Only `/api/tickets/scan` consumes.

### Status codes

| Code | Meaning |
| --- | --- |
| 401 | No credential on a gated route |
| 403 | Authenticated, but not an admin |
| 404 | No such route |
| 405 | Route exists under a different method (`Allow` is set) |
| 409 | `ALREADY_USED`, `CANCELLED` |
| 410 | `EXPIRED` |
| 422 | Any other verification rejection |
| 429 | Rate limited; `Retry-After` is set |
| 501 | Admin routes with no `dashboard` configured |
| 503 | Rate limiting failed closed, or `SERVICE_UNAVAILABLE` |

A non-admin gets 403 and an anonymous caller gets 401 **on the same route**.
Returning 403 to an anonymous prober confirms the resource exists and implies a
different credential is worth trying.

---

## 5. Things that will bite you

**Challenges are single-use and bound to a subject.** `CHALLENGE_REQUIRED`
returns a token. The client must send it back on the next request, and the
subject (user, session, IP) must match. Redeeming it from a different subject
returns an indistinguishable failure and leaves the token live for its rightful
owner. Presenting it twice returns `ALREADY_REDEEMED` internally — but all
challenge failures collapse to one public error, so do not branch on the reason.

**`scannerId` is server-derived.** It is not accepted from a request body,
because a client that can name its own scanner can forge which gate scanned a
ticket. If your kiosk design needs a shared device id, put it in the principal,
not the body.

**Rate-limit buckets are namespaced by endpoint and policy.** Two endpoints with
different policies get different buckets. If you see an unexpected 429, read the
`policy` field in the response before assuming a bug.

**Bodies are sanitized, then validated strictly.** Client-controlled fields
(`userId`, `role`, `isAdmin`, `price`, `amount`, …) are stripped before your
handler-equivalent runs, and a stripped-then-unknown field is a 400. Do not
expect a field you send to survive.

**Queue positions are assigned inside a Postgres advisory lock.** 150 concurrent
joins produce 150 distinct positions. Throughput is ~230/s per event, which is a
deliberate consequence of serialising position assignment — see the load suite
for the measured numbers.

**Every response is `cache-control: no-store`.** Do not override it for the
verification routes. A cached verification result is replayable by a shared
proxy.

---

## 6. Failure posture

| Dependency down | Behaviour |
| --- | --- |
| Redis | Rate limiting **fails open**; queue and challenges unavailable; ticket verification unaffected |
| Postgres | Ticket consumption and queue **fail closed** — admission stops |
| Signature key missing | Verification **fails closed** for that `kid` |

Verification is the one path with no Redis dependency, on purpose. A Redis blip
must not stop real people getting through a gate.

Set `failClosedOnRateLimitUnavailable: true` to reverse the rate-limit default.
Verification routes stay open regardless — see the comment in `SecurityApi`.

---

## 7. Tests

```bash
npm run infra:up      # Redis + Postgres
npm run infra:wait
npm run migrate
npm test              # unit + integration
npm run test:load     # threshold-gated p95/throughput, opt-in
```

`npm test` excludes the load suite on purpose. Its thresholds are calibrated for
a container-backed CI box, and a performance gate that goes red on a laptop gets
deleted. Run it in CI as its own step.

Override the load gate per environment:

```bash
LOAD_MAX_P95_MS=120 LOAD_MIN_THROUGHPUT=500 npm run test:load
```

---

## 8. Still outstanding

- [ ] **Same-booking race target.** The engine holds a lock per idempotency key;
      the double-booking case needs Person 1's seat-inventory repository to be a
      real constraint, not a read-then-write. Until that exists, "one seat, one
      winner" is asserted at the engine layer and not end to end.
- [ ] **Concrete adapters.** Every port above has a test double and, for
      tickets, a Postgres adapter. `UserResolver`, `EventRepository` and
      `QueueStore` still need Person 1's real implementations.
- [ ] **Key distribution.** `FileKeyStore` is fine for one host. Multi-region
      needs a shared store and a `kid` scheme agreed with the ticket issuer.
