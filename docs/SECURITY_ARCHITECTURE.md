# FIRST-ORDER / TIXIFY-VR — Security Engine Architecture

> **Owner:** Person 2 (Security Engineer)
> **Scope:** Security & protection layer only.
> **Explicitly out of scope:** the core booking engine, and any AI/ML fraud detection.

---

## 1. Why this document exists

Person 1 is building the core booking platform (users, events, venues, seats,
inventory, reservations, bookings, payments). Person 2 owns a **modular security
layer** that attaches to those booking APIs through documented interfaces.

This creates a hard constraint that shapes the entire design:

> Person 1 must be able to integrate the security layer **without rewriting the
> booking engine**, and Person 2 must be able to build it **without seeing
> Person 1's code**.

We cannot depend on each other's internals. So the security engine is built as a
**ports-and-adapters (hexagonal) module**. Everything Person 1 owns is reached
through an *interface we define* and Person 1 *implements*. Everything we own is
implemented behind an interface Person 1 *calls*.

---

## 2. Layer model

The spec's conceptual diagram resolves into three vertical concerns that all
funnel down into one observability spine.

```
                          SECURITY ENGINE
                                 │
        ┌────────────────────────┼────────────────────────┐
        ↓                        ↓                        ↓
 Ticket Security           Request Security          Traffic Security
        │                        │                        │
 ┌──────┴──────┐          ┌──────┴──────┐          ┌──────┴──────┐
 │             │          │             │          │             │
 Ed25519    QR          Idempotency  Duplicate    Rate         Virtual
 signing    validation   layer        detection   Limiting     Queue
 │          │            │            │           │            │
 Replay     Ticket       Replay       Burst      Adapters     Admission
 guard      state        protection   control                tokens
 │          │            │            │           │            │
 └──────────┴────────────┴──────┬─────┴───────────┴────────────┘
                                 ↓
                        Security Events
                                 ↓
                        Audit System
                                 ↓
                   Admin Dashboard (read-only)
```

### Ownership boundary

| Concern | Owner | Lives in |
| --- | --- | --- |
| users, events, venues, seats, inventory | Person 1 | `booking-engine` |
| reservations, bookings, payments | Person 1 | `booking-engine` |
| ticket signing, QR validation | **Person 2** | `security-engine` |
| idempotency, rate limiting, bot protection | **Person 2** | `security-engine` |
| virtual queue, admission tokens | **Person 2** | `security-engine` |
| security events, audit, monitoring | **Person 2** | `security-engine` |

**We never write to Person 1's tables.** We own five security tables
(`AuditLog`, `SecurityEvent`, `IdempotencyRecord`, `QueueEntry`, `TicketScan`)
and nothing else. Where we need Person 1's data we read it through a port.

---

## 3. The integration seam

This is the single most important architectural decision, so it gets stated
precisely.

### 3.1 Ports we define (Person 1 implements)

These are TypeScript interfaces. Person 1 writes adapters. We ship reference
adapters for local development and tests.

| Port | Purpose | Person 1 provides |
| --- | --- | --- |
| `TicketRepository` | Read authoritative ticket state | Adapter over their ticket model |
| `EventRepository` | Read event existence / status | Adapter over their event model |
| `UserResolver` | Derive the authenticated user server-side | Adapter over their auth/session |
| `SeatRepository` | Validate seat ownership on a ticket | Adapter over their seat model |
| `AuditSink` | Persist Person 1's business events into our audit trail | Thin write into `AuditLog` |
| `RedisClient` | Shared Redis connection | Connection factory |

### 3.2 Contracts we expose (Person 1 calls)

| Export | Purpose |
| --- | --- |
| `createTicketSigner` | Sign ticket payloads (server-side only) |
| `verifyTicketEnvelope` | Verify QR envelope signature + structure |
| `idempotencyMiddleware` | Wrap critical POSTs |
| `rateLimitMiddleware` | Distributed rate limiting |
| `botProtectionMiddleware` | Deterministic anti-automation |
| `virtualQueue` | Queue join / status / admission |
| `requestSanitizer` | Strip client-controlled authority fields |
| `securityEventEmitter` | Emit structured security events |
| `securityAuditLog` | Append-only audit writes |
| `securityRouter` | `POST /api/tickets/verify`, `POST /api/tickets/scan`, … |

### 3.3 The rule that prevents all merge conflicts

Person 1's code must never import security internals, and our code must never
import booking internals. Traffic crosses the seam in exactly three ways:

1. **Inbound HTTP** — our middleware sits in front of their handlers.
2. **Inbound port call** — we ask them for state via a port they implemented.
3. **Outbound event** — we emit a security event; they may subscribe.

Anything else is a design error. See `SECURITY_INTEGRATION.md` for the concrete
header names, Redis key names, and error codes.

---

## 4. Component design

### 4.1 Cryptographic tickets (Parts 1–2)

- **Ed25519** asymmetric signatures. Private key server-side only, never in a
  frontend bundle, never in a QR code.
- Signature is computed over a **canonicalized** payload — deterministic key
  ordering, no whitespace, no float formatting ambiguity — so the same logical
  ticket always yields byte-identical signed output.
- The QR carries only `{ v, ticket, signature }`. No userId, no price, no
  payment data, no credentials. A QR is a *proof of claim*, not a data leak.
- Key rotation is supported via a **key ring**: the signer publishes a `kid`, the
  verifier accepts any key in the ring, and old keys stay valid until their
  retire-after date passes. This lets us rotate without invalidating live tickets.

### 4.2 Ticket validation and replay (Parts 3–4)

Validation is a strict pipeline. It fails closed — any unrecognised condition
rejects rather than admits.

```
QR → decode → structural validation → signature verification
   → ticket exists → event exists → state check → expiry check → used check
   → ALLOW | REJECT
```

Response codes are a closed enum (`VALID`, `ALREADY_USED`, `EXPIRED`,
`INVALID_SIGNATURE`, `TICKET_NOT_FOUND`, `CANCELLED`, `WRONG_EVENT`). The
endpoint does not leak *why* something is invalid beyond that enum — no
"user 123 has no tickets" oracle, no stack traces, no DB error strings.

**Replay protection is the security-critical part.** `CONFIRMED → USED` must
happen exactly once, even when two gate scanners fire within the same
millisecond. This is enforced with a single atomic conditional write:

```sql
UPDATE tickets SET state = 'USED', used_at = now()
WHERE id = $1 AND state = 'CONFIRMED';
```

The row count *is* the lock. Exactly one caller sees `rowCount = 1`; every other
caller sees `0` and gets `ALREADY_USED`. No `SELECT` then `UPDATE` (that races),
no advisory lock on the hot path, no in-process mutex (that fails across
instances). This is the only pattern we accept.

Note: the `tickets` table is Person 1's. The atomic transition is exposed as the
`TicketRepository` port so the guarantee is *specified* in our contract and
*implemented* on their side. We additionally keep our own append-only
`TicketScan` ledger as independent evidence.

### 4.3 Idempotency (Part 5)

Redis-backed, `PROCESSING → SUCCESS | FAILED`, with a TTL.

The first request to claim a key wins the claim via `SET NX`. Losers do **not**
execute the operation — they either wait briefly for the winner's result or
receive `409`/`425`. This prevents double-clicks, client retries, network-level
retries, and deliberate duplicate submission.

Critically, the stored response is a **fingerprint of the request** (hash of
method + path + body). Reusing an idempotency key with a *different* body is a
client bug or an attack, and is rejected with `IDEMPOTENCY_KEY_REUSE` rather
than silently returning the wrong cached result.

### 4.4 Distributed rate limiting (Part 6)

Never in-process. A Vercel/serverless deployment has no shared memory between
instances, so an in-memory counter is not merely imprecise — it is a
**complete bypass**: N instances means N× the intended limit.

Implemented in Redis as a **sliding-window counter** via a Lua script, so the
read-increment-write sequence is atomic. Rate-limit dimensions are orthogonal
keys, each with its own policy: IP, authenticated user, endpoint, event, session.

Limits are configuration, not constants. `REQUESTS_PER_SECOND`, `BURST_LIMIT`,
`WINDOW_SECONDS` and per-endpoint overrides all come from the environment.
Over-limit returns `429` with a machine-readable `RATE_LIMITED` code and
`Retry-After`.

Fail-closed vs fail-open: rate limiting **fails open** on Redis outage (we would
rather serve traffic than take the site down), but ticket *signature
verification* and *replay* **fail closed** (we would rather reject than admit a
forged ticket). That asymmetry is deliberate and is the single most important
judgement call in this document.

### 4.5 Bot / automation protection (Part 7)

Deterministic signals only. No ML, no behavioural model, no fingerprinting.

Signals: request frequency, burst size, repeated identical requests, repeated
failed reservations, rapid seat churn, cancellation loops, account-creation
rate, per-session volume.

**We never ban on IP alone.** University campuses, corporate NATs, and mobile
carriers put thousands of legitimate users behind one address; an IP-only ban
during a ticket drop is a self-inflicted denial of service. IP is one input
among several, and never sufficient on its own.

The pipeline escalates rather than hard-blocking:

```
NORMAL → INCREASED_RATE_LIMITING → CHALLENGE → TEMPORARY_RESTRICTION
```

Decisions flow through a `SecurityDecision` interface so the policy is
configurable in one place rather than scattered `if (suspicious) block()` calls.

### 4.6 Virtual queue (Part 8)

When an event crosses a configurable concurrency threshold, requests are
admitted through a queue rather than being met with 429s.

Admission tokens are opaque, server-validated, expiring, and bound to
session/user. **Position is computed server-side.** A client-rendered countdown
is a UX affordance and is never a security control — an attacker simply never
renders it.

Queue-bypass attempts (presenting a token that is expired, forged, for another
event, or replayed) emit `QUEUE_BYPASS_ATTEMPT` and are rejected.

### 4.7 Request sanitization (Part 9)

`userId`, `price`, `paymentStatus`, `ticketStatus`, `role`, and `bookingOwner`
are **never** read from the request body. The authenticated principal is derived
server-side and any client-supplied instance of these fields is stripped before
the handler sees it. If Person 1 already does this correctly, our middleware is
a no-op and we do not duplicate it.

### 4.8 Security events and audit (Parts 10–11)

One normalized event envelope with a closed `eventType` enum, `severity`, and
free-form `metadata`.

PII discipline: we store `ipHash` (HMAC with a server-side pepper), never a raw
IP. We do not store email, name, or payment data. A breach of the security log
should not become a breach of user data.

The audit trail is **append-only**. No update path, no delete path, enforced by
`REVOKE UPDATE, DELETE` on the table in the migration — not by application
discipline, which is not a security control.

### 4.9 Dashboard (Part 12)

Read-only aggregates over security events. Admin-authorized. Exposes the counters
in the spec plus a recent-events feed. Counters come from Redis rolling
counters, not from scanning the audit table.

---

## 5. Data model (Part 14)

Raw SQL migrations, no ORM. Five tables, all security-owned:

| Table | Purpose | Key constraint |
| --- | --- | --- |
| `security_events` | Normalized security events | index on `(event_type, created_at)` |
| `audit_logs` | Append-only business + security audit | `REVOKE UPDATE, DELETE` |
| `idempotency_records` | Durable idempotency state (Redis is the fast path) | `UNIQUE (key, endpoint)` |
| `queue_entries` | Virtual queue membership | `UNIQUE (event_id, session_id)` |
| `ticket_scans` | Append-only scan ledger | index on `(ticket_id, scanned_at)` |

Person 1's `users` / `events` / `bookings` / `tickets` tables are **referenced
by id only, never created, never altered, never joined into** — we call the port
instead. This keeps the security module independently deployable and makes
Person 1's schema free to change without breaking us.

---

## 6. Deployment posture (Vercel)

Target runtime is serverless, which has one dominant consequence:

> **There is no shared process memory. Every piece of security state that matters
> must live in Redis or Postgres.**

Consequences already designed in:

- Rate limiting, idempotency, and queue state are all Redis-backed.
- The Ed25519 private key is read from an environment variable at cold start and
  is never bundled into client assets. Vercel env vars are encrypted at rest and
  masked from build output.
- Postgres access uses a pooled connection string. Serverless functions open
  connections per invocation; an unpooled URL will exhaust connections under
  load. Use a pooler (Supabase pool mode / PgBouncer) with a serverless driver.
- Audit and security events are written with buffered batch inserts to avoid
  exhausting the connection budget on high-volume paths.
- The module is stateless and horizontally safe, so it scales to N instances
  with no coordination.

---

## 7. Testing strategy

### 7.1 Concurrency (Part 15) — mandatory, against real infrastructure

Mocked tests cannot prove atomicity, so concurrency tests run against **real
Redis and real Postgres in Docker**. The seven mandated races:

1. Same ticket scanned simultaneously
2. Same booking request sent simultaneously
3. Same idempotency key sent simultaneously
4. Large request volume from one user
5. Large request volume from one IP
6. Queue admission race
7. Multiple QR scans

The load-bearing assertion is invariant, not a count: across N concurrent
scans of one ticket, **exactly one** succeeds. Any implementation that returns
two `SUCCESS` results fails the suite.

### 7.2 Security (Part 16)

Fifteen cases, each with an explicit expected result: tampered payload, forged
signature, expired, cancelled, already-used, replay, duplicate idempotency key,
malformed request, rate-limit exceeded, queue bypass, unauthorized dashboard
access, forged user id, modified ticket id, modified event id, modified seat id.

### 7.3 Load

100 / 500 / 1000 / 5000 requests against the rate limiter, idempotency, ticket
validation, and queue. Measures response time, rejection rate, successes, and
Redis/DB error counts. **The system must remain consistent under load** — that
is the pass criterion, not raw throughput.

---

## 8. Security principles (non-negotiable)

1. Never trust the client.
2. Never store secrets in frontend code.
3. Never put signing private keys in frontend code.
4. Never rely on IP alone for abuse detection.
5. Never use frontend state as authoritative security state.
6. Never allow replayed tickets.
7. Never allow duplicate state transitions.
8. Never use in-memory rate limiting in a distributed deployment.
9. Never expose sensitive internal errors.
10. Always validate input.
11. Always enforce authorization server-side.
12. Prefer fail-closed behaviour for security-critical operations.

---

## 9. Acceptance criteria

Tracked as a checklist in `SECURITY_INTEGRATION.md` §11. The two that actually
matter for integration are:

- Concurrent ticket scans allow **only one** success.
- Person 1 can integrate the security layer **without rewriting the booking
  engine**.
