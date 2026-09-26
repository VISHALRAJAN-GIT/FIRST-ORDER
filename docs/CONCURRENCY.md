# Concurrency strategy

## Same seat

`reservations.create` uses a single database transaction and `SELECT ... FOR UPDATE` on every requested event inventory row. It then re-reads status while the locks are held. If two users request the same seat, only one transaction observes `AVAILABLE` and commits the `RESERVED` update. The other waits, observes `RESERVED`, and returns `SEAT_UNAVAILABLE`. The unique `(eventId, seatId)` constraint provides a second database-level guard.

## Same-user purchase limit

The transaction locks the authenticated `users` row before counting confirmed booking items and active reservation items for the event. Concurrent requests from the same user therefore serialize even when they target different seats. The check includes both confirmed tickets and non-expired active holds.

## Payment settlement

Payment rows and reservations are locked during settlement. Terminal payment states are idempotent. The unique reservation-to-booking relationship and unique booking-item relationship protect against duplicate booking and duplicate ticket allocation.

## Test plan

The required load tests should run against a real PostgreSQL instance, not an in-memory mock. For one event seat, start 100, 500, and 1,000 concurrent requests and assert one successful reservation and zero duplicate inventory rows. For a four-ticket user limit, run `3+3`, `4+4`, `2+2+2`, and `1+1+1+1+1` request races and assert the final confirmed plus active held count is never above four. Expiration and duplicate webhook tests should assert that inventory is released once and tickets are generated once.
