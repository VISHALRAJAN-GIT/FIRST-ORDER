/**
 * Shared test fixtures.
 *
 * Key generation happens per test run rather than being checked in, so no test
 * key can ever be mistaken for, or promoted into, a real signing key. Test keys
 * are generated in-process and never touch disk.
 */

import { generateKeyPairSync } from 'node:crypto';
import { FakeClock } from '../../src/core/clock';
import { KeyRing } from '../../src/crypto/key-store';
import { TicketSigner } from '../../src/crypto/signer';
import type { SecurityConfig } from '../../src/config/env';

const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export interface TestKeyPair {
  readonly kid: string;
  readonly privateKeyBase64: string;
  readonly publicKeyBase64: string;
}

export function generateTestKeyPair(kid = 'test-key-1'): TestKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    kid,
    privateKeyBase64: privateKey
      .export({ format: 'der', type: 'pkcs8' })
      .subarray(PKCS8_PREFIX.length)
      .toString('base64'),
    publicKeyBase64: publicKey
      .export({ format: 'der', type: 'spki' })
      .subarray(SPKI_PREFIX.length)
      .toString('base64'),
  };
}

export function makeSigner(
  clock: FakeClock,
  keyPair: TestKeyPair = generateTestKeyPair(),
): { signer: TicketSigner; keyRing: KeyRing; keyPair: TestKeyPair } {
  const keyRing = new KeyRing(
    [{ kid: keyPair.kid, publicKey: toPublicKeyObject(keyPair.publicKeyBase64), retireAt: undefined }],
    keyPair.kid,
  );
  const signer = new TicketSigner({ privateKeyBase64: keyPair.privateKeyBase64, keyRing, clock });
  return { signer, keyRing, keyPair };
}

function toPublicKeyObject(base64: string) {
  // Imported lazily to keep this helper free of crypto plumbing at the top level.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { createPublicKey } = require('node:crypto') as typeof import('node:crypto');
  return createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, Buffer.from(base64, 'base64')]),
    format: 'der',
    type: 'spki',
  });
}

/** Deterministic config for tests: no production paths, fast windows. */
export function testConfig(overrides: Partial<SecurityConfig> = {}): SecurityConfig {
  const base: SecurityConfig = {
    nodeEnv: 'test',
    logLevel: 'error',
    isProduction: false,
    ticket: {
      privateKey: undefined,
      publicKey: undefined,
      keyId: 'test-key-1',
      trustedKeyIds: new Set(['test-key-1']),
      retireAt: undefined,
      ttlSeconds: 3600,
    },
    redis: {
      url: 'redis://127.0.0.1:6379',
      keyPrefix: 'test:sec',
      rateLimitFailOpen: true,
    },
    database: {
      url: 'postgres://postgres:postgres@127.0.0.1:5432/tixify',
      poolMax: 10,
      ssl: false,
    },
    rateLimit: {
      defaults: { requestsPerSecond: 10, burstLimit: 20, windowSeconds: 1 },
      policies: {},
    },
    idempotency: { ttlSeconds: 3600, waitMs: 50 },
    bot: {
      enabled: true,
      challengeThreshold: 40,
      restrictThreshold: 80,
      signalWindowSeconds: 300,
      maxFailedBookings: 5,
      maxAccountCreation: 3,
      temporaryRestrictionSeconds: 900,
    },
    queue: { enabled: true, maxConcurrent: 100, tokenTtlSeconds: 120, admissionBatchSize: 10 },
    privacy: { ipHashPepper: 'test-pepper' },
    admin: { userIds: new Set(['admin-1']) },
    events: { bufferSize: 10, flushIntervalMs: 50 },
  };

  return { ...base, ...overrides } as SecurityConfig;
}

/** Fixed epoch for deterministic timestamps in assertions. */
export const T0 = Date.parse('2026-01-01T00:00:00.000Z');
