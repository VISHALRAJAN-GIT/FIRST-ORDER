import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    globals: false,
    include: ['tests/**/*.test.ts'],
    // The load suite is opt-in via `npm run test:load`. Its thresholds are
    // calibrated for a container-backed CI box, and running them on every
    // `npm test` means a developer on a laptop with a browser and a virus scanner
    // sees the gate go red for reasons that have nothing to do with the code. A
    // perf gate that fails intermittently gets deleted, and a deleted gate is
    // worse than none. CI runs it as its own step.
    exclude: ['tests/load/**', 'node_modules/**'],
    // Concurrency and load suites are genuinely time-sensitive and hold real
    // connections. Running files in parallel would have them contend for the same
    // Redis keys and Postgres rows, turning infrastructure limits into flaky
    // assertion failures.
    fileParallelism: false,
    testTimeout: 30_000,
    hookTimeout: 30_000,
    teardownTimeout: 15_000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov', 'html'],
      include: ['src/**/*.ts'],
      exclude: ['src/index.ts', 'src/**/*.d.ts'],
    },
  },
});
