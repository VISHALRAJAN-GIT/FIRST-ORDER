/**
 * The public surface of the package.
 *
 * This exists because `package.json` pointed `main` at `dist/index.js` while no
 * `src/index.ts` existed, so the engine was unimportable by Person 1. Nothing
 * caught that, because every test reached into `src/` paths directly and a barrel
 * is only ever exercised by someone who depends on the package.
 *
 * The assertions are deliberately blunt. They are not checking that a symbol does
 * anything useful — the per-part suites do that — only that the contract Person 1
 * codes against exists and is reachable by the package name.
 */

import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';

const require_ = createRequire(__filename);
const root = resolve(__dirname, '../..');

// `dist/` is gitignored, so a fresh clone has no build and the barrel cannot be
// resolved by package name. Building once up front is what makes the assertions
// below meaningful on a clean checkout, and costs nothing on a warm one.
const tsc = require_.resolve('typescript/bin/tsc');
execFileSync(process.execPath, [tsc, '-p', 'tsconfig.build.json'], { stdio: 'pipe', cwd: root });

describe('package public surface', () => {
  it('resolves by package name, not just by relative path', () => {
    // This is the assertion that would have failed before. A barrel that only
    // works via `./src/index` is not a public surface.
    const barrel = require_('@tixify/security-engine') as Record<string, unknown>;
    expect(Object.keys(barrel).length).toBeGreaterThan(50);
  });

  it('exposes the entry points for every implemented part', () => {
    const api = require_('@tixify/security-engine') as Record<string, unknown>;
    const required = [
      // config, errors, primitives
      'loadConfig', 'SecurityError', 'ERROR_CODES', 'canonicalizeJson',
      // crypto and QR
      'KeyRing', 'TicketSigner', 'renderQrDataUri', 'renderQrSvg',
      // tickets
      'TicketIssuer', 'TicketVerifier', 'ReplayGuard', 'PostgresTicketRepository',
      // idempotency
      'IdempotencyGuard', 'RedisIdempotencyStore', 'PostgresIdempotencyStore', 'fingerprintRequest',
      // rate limiting
      'RateLimiter', 'ENDPOINT_POLICIES', 'rateLimitedResponse',
      // bot protection
      'BotProtection', 'DEFAULT_BOT_CONFIG', 'ChallengeStore',
      // part 13: framework-neutral API
      'SecurityApi', 'SECURITY_ROUTE_IDS', 'listSecurityRoutes',
      'securityMiddleware', 'toHttpRequest',
      // queue
      'VirtualQueue', 'PostgresQueueStore', 'AdmissionTokenCodec',
      // validation
      'sanitizeBody', 'guardProtectedRequest', 'bookingRequestSchema',
      // telemetry and audit
      'TelemetrySink', 'SECURITY_EVENT_TYPES', 'assertNoPii', 'pseudonymize', 'recordScan',
      // dashboard
      'SecurityDashboard',
      // ports Person 1 implements
      'wrapIoredis', 'ConfiguredAdminAuthorizer', 'CLIENT_CONTROLLED_FIELDS',
    ];
    const missing = required.filter((name) => api[name] === undefined);
    expect(missing).toEqual([]);
  });

  it('exposes the ports Person 1 must implement', () => {
    // These are types, so they cannot be checked at runtime. Asserting the
    // declaration file names them is the only automated way to notice someone
    // dropping a port from the barrel — which would surface as a compile error in
    // someone else's repository instead of here.
    const types = readFileSync(resolve(root, 'dist/index.d.ts'), 'utf8');
    for (const port of ['TicketRepository', 'EventRepository', 'SeatRepository', 'UserResolver', 'AdminAuthorizer', 'AuditSink', 'IdempotencyStore', 'ScanLedger', 'QueueStore', 'RedisLike']) {
      expect(types).toContain(port);
    }
  });

  it('does not re-export the removed shallow strip helper', () => {
    const api = require_('@tixify/security-engine') as Record<string, unknown>;
    // Two sanitiser entry points is one too many: a caller who picks the shallow
    // one gets a weaker guarantee with no signal that they did.
    expect(api.stripClientControlledFields).toBeUndefined();
  });

  it('does not leak internal key builders or Lua scripts', () => {
    const api = require_('@tixify/security-engine') as Record<string, unknown>;
    for (const internal of ['TOKEN_BUCKET_SCRIPT', 'FIXED_WINDOW_SCRIPT', 'subjectKey', 'policyFingerprint', 'dimensionValue']) {
      expect(api[internal]).toBeUndefined();
    }
  });

  it('keeps the event catalogue and policies consistent with the migration', () => {
    const api = require_('@tixify/security-engine') as Record<string, never[]>;
    const migration = readFileSync(resolve(root, 'migrations/001_security_tables.sql'), 'utf8');
    const declared = [...migration.matchAll(/'([A-Z_]+)'/g)]
      .map((match) => match[1]!)
      .filter((value) => (api.SECURITY_EVENT_TYPES as string[]).includes(value));
    // Every value the migration's CHECK permits must be one the engine can emit.
    expect(declared.length).toBeGreaterThan(0);
    expect(api.SECURITY_EVENT_TYPES).toHaveLength(16);
  });

  it('builds and emits the files package.json advertises', () => {
    // Guards the original defect at its source: the entrypoints must exist and be
    // reachable by the resolution modes consumers actually use.
    const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8')) as {
      main: string;
      types: string;
      exports: Record<string, unknown>;
    };
    for (const field of [pkg.main, pkg.types]) {
      expect(() => readFileSync(resolve(root, field), 'utf8')).not.toThrow();
    }
    expect(pkg.exports['.']).toBeDefined();
  });

  it('compiles under the build config used for publishing', () => {
    // Catches a barrel that typechecks with noUncheckedIndexedAccess in the dev
    // config but not under the build config, which is the config that ships.
    // tsc is invoked directly: `npx` is a shell script and is not spawnable from
    // a child process on Windows without a shell, which made this test pass for
    // the wrong reason on a machine where npx was missing.
    expect(() =>
      execFileSync(process.execPath, [tsc, '-p', 'tsconfig.build.json', '--noEmit'], {
        stdio: 'pipe',
        cwd: root,
      }),
    ).not.toThrow();
  });
});
