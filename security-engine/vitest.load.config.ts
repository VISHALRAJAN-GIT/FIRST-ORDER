import { defineConfig } from 'vitest/config';

/**
 * Config for `npm run test:load`.
 *
 * A separate file rather than a flag, because vitest merges a CLI `--exclude`
 * with the one in the main config instead of replacing it - so the main config's
 * `tests/load/**` exclusion would still apply and the run would find nothing.
 *
 * The base config exists to keep the performance gate out of `npm test` on a
 * developer laptop; this one exists to put it back on purpose, with the same
 * serial-execution and connection settings the real services need.
 */
export default defineConfig({
  test: {
    environment: 'node',
    globals: false,
    include: ['tests/load/**/*.test.ts'],
    // Same reasoning as the base config: these hold real Redis and Postgres
    // connections and are time-sensitive, so they must not race each other.
    fileParallelism: false,
    testTimeout: 120_000,
    hookTimeout: 60_000,
    teardownTimeout: 15_000,
  },
});
