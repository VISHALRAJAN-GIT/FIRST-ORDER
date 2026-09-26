import { performance } from 'node:perf_hooks';

import { expect } from 'vitest';

/**
 * Minimal load driver for Part 16.
 *
 * No k6, no autocannon: the thing being measured is a handful of library calls
 * against a local Redis and Postgres, and a benchmark harness that can measure a
 * local socket round trip is mostly measuring the harness. What is actually
 * wanted is a *regression* alarm - "this got an order of magnitude slower
 * because someone replaced a Lua script with three round trips" - and that needs
 * a stable relative number far more than it needs laboratory accuracy.
 */
export interface LoadResult {
  readonly operations: number;
  readonly durationMs: number;
  readonly throughputPerSecond: number;
  readonly p50Ms: number;
  readonly p95Ms: number;
  readonly p99Ms: number;
  readonly maxMs: number;
  readonly errors: number;
}

/**
 * Runs `total` operations at a fixed concurrency and returns the distribution.
 *
 * Latencies are recorded per operation rather than per batch, so p95 reflects
 * the operation a user actually waits for. Batching would hide a tail: if 99 of
 * 100 operations are instant and one takes 2s because it waited on a lock, a
 * per-batch timer records one 2s sample out of one and reports a p95 of 2s,
 * while per-operation records 1% at 2s and puts the p95 where it belongs.
 */
export async function load(
  operation: (index: number) => Promise<unknown>,
  options: { readonly total: number; readonly concurrency: number },
): Promise<LoadResult> {
  const { total, concurrency } = options;
  const latencies: number[] = [];
  let errors = 0;
  let next = 0;

  const started = performance.now();
  await Promise.all(
    Array.from({ length: Math.min(concurrency, total) }, async () => {
      for (;;) {
        const index = next++;
        if (index >= total) return;
        const at = performance.now();
        try {
          await operation(index);
        } catch {
          // Counted rather than thrown. A load test that aborts on the first
          // connection reset reports a latency it never measured, and an error
          // rate of 100% with a beautiful p95 is not a useful result.
          errors += 1;
        }
        latencies.push(performance.now() - at);
      }
    }),
  );
  const durationMs = performance.now() - started;

  latencies.sort((a, b) => a - b);
  const at = (q: number): number => latencies[Math.min(latencies.length - 1, Math.floor(latencies.length * q))] ?? 0;

  return {
    operations: total,
    durationMs,
    throughputPerSecond: durationMs > 0 ? (total / durationMs) * 1000 : 0,
    p50Ms: at(0.5),
    p95Ms: at(0.95),
    p99Ms: at(0.99),
    maxMs: latencies[latencies.length - 1] ?? 0,
    errors,
  };
}

/**
 * Thresholds, overridable per run.
 *
 * The defaults are deliberately loose - loose enough to survive a laptop running
 * a container, a virus scanner and a browser - because a load gate that fails
 * intermittently gets deleted, and a deleted gate is worse than no gate. The
 * numbers are still tight enough to catch the regressions that actually happen in
 * this codebase: an added round trip, an N+1, a lost Lua script, a missing index.
 *
 * CI tightens these via environment variables. The committed defaults are a
 * floor, not a target.
 */
export interface Thresholds {
  readonly maxP95Ms: number;
  readonly minThroughputPerSecond: number;
  readonly maxErrorRate: number;
}

export function thresholds(overrides: Partial<Thresholds> = {}): Thresholds {
  const num = (value: string | undefined, fallback: number): number => {
    const parsed = value === undefined ? Number.NaN : Number(value);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
  };
  return {
    maxP95Ms: num(process.env.LOAD_MAX_P95_MS, overrides.maxP95Ms ?? 250),
    minThroughputPerSecond: num(process.env.LOAD_MIN_THROUGHPUT, overrides.minThroughputPerSecond ?? 200),
    maxErrorRate: num(process.env.LOAD_MAX_ERROR_RATE, overrides.maxErrorRate ?? 0),
  };
}

/**
 * Limits for a serialized critical section, such as the queue's per-event
 * advisory lock.
 *
 * Deliberately looser than the shared gate, and that is not a loophole. A Redis
 * token bucket is an independent decision per request and is expected to scale
 * with cores; a queue join takes a per-event lock on purpose, so its latency is
 * bounded by the number of people ahead of you in line rather than by the
 * machine. Holding that path to the same 250ms as a Redis round trip would mean
 * either a flaky gate on a busy CI box or a limit so loose it catches nothing.
 * It still has to be fast enough that a sold-out event does not turn its own
 * queue into the outage.
 */
export function serializedThresholds(overrides: Partial<Thresholds> = {}): Thresholds {
  return thresholds({
    maxP95Ms: Number(process.env.LOAD_QUEUE_MAX_P95_MS ?? 400),
    minThroughputPerSecond: Number(process.env.LOAD_QUEUE_MIN_THROUGHPUT ?? 80),
    ...overrides,
  });
}

/** One line per result, so a CI log shows the numbers even when the gate passes. */
export function report(label: string, result: LoadResult, limits: Thresholds): void {
  const line = [
    label.padEnd(34),
    `n=${String(result.operations).padStart(5)}`,
    `${result.throughputPerSecond.toFixed(0).padStart(6)} ops/s`,
    `p50=${result.p50Ms.toFixed(1).padStart(6)}ms`,
    `p95=${result.p95Ms.toFixed(1).padStart(6)}ms`,
    `p99=${result.p99Ms.toFixed(1).padStart(6)}ms`,
    `max=${result.maxMs.toFixed(1).padStart(7)}ms`,
    result.errors > 0 ? `errors=${result.errors}` : '',
  ]
    .filter(Boolean)
    .join('  ');
  // eslint-disable-next-line no-console -- the point of a load gate is the log line
  console.log(line);
  expect(result.p95Ms, `${label} p95 within ${limits.maxP95Ms}ms`).toBeLessThanOrEqual(limits.maxP95Ms);
  expect(result.throughputPerSecond, `${label} throughput`).toBeGreaterThanOrEqual(limits.minThroughputPerSecond);
  const errorRate = result.errors / result.operations;
  expect(errorRate, `${label} error rate`).toBeLessThanOrEqual(limits.maxErrorRate);
}

