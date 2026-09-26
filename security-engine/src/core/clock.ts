/**
 * Injectable clock.
 *
 * Every time-dependent decision in this engine — ticket expiry, rate-limit
 * windows, idempotency TTL, queue token lifetime, bot signal decay — reads the
 * clock through this interface rather than calling `Date.now()` directly.
 *
 * That is not ceremony. Expiry tests are otherwise either slow or flaky, and
 * the concurrency suite has to place many events on both sides of a boundary at
 * the same instant. A fake clock makes those deterministic.
 */

export interface Clock {
  /** Milliseconds since the Unix epoch. */
  now(): number;
  /** Current instant as an ISO-8601 string, for signed payloads. */
  nowIso(): string;
}

export const systemClock: Clock = {
  now: () => Date.now(),
  nowIso: () => new Date().toISOString(),
};

/** Manually advanced clock for tests. */
export class FakeClock implements Clock {
  private current: number;

  constructor(start: number | string | Date = 0) {
    this.current = typeof start === 'number' ? start : new Date(start).getTime();
  }

  now(): number {
    return this.current;
  }

  nowIso(): string {
    return new Date(this.current).toISOString();
  }

  /** Move the clock forward (or backward, with a negative value). */
  advance(milliseconds: number): this {
    this.current += milliseconds;
    return this;
  }

  advanceSeconds(seconds: number): this {
    return this.advance(seconds * 1000);
  }

  set(instant: number | string | Date): this {
    this.current = typeof instant === 'number' ? instant : new Date(instant).getTime();
    return this;
  }
}
