/**
 * Environment configuration.
 *
 * Parsed once, validated at boot, and frozen. Every tunable in the security
 * engine arrives through here — the spec is explicit that limits are
 * configuration, not constants, and that keys are never hardcoded.
 *
 * Two different failure policies live here on purpose:
 *
 *   - SECURITY-critical config (signing keys) fails LOUDLY at startup. A process
 *     that cannot sign tickets must never accept traffic pretending to be safe.
 *   - Deploy-shaped config (Redis, database) is validated but the *connection*
 *     is lazy, so the module can be imported in a test or a CLI without a live
 *     dependency.
 */

import { z } from 'zod';

/** Accepts `true/false/1/0/yes/no` and coerces to boolean. */
const booleanFromEnv = z
  .union([z.boolean(), z.string()])
  .transform((value) => {
    if (typeof value === 'boolean') return value;
    return ['1', 'true', 'yes', 'on'].includes(value.trim().toLowerCase());
  });

const positiveInt = (fallback: number) =>
  z.coerce.number().int().positive().default(fallback);

const nonNegativeInt = (fallback: number) =>
  z.coerce.number().int().nonnegative().default(fallback);

/** `requests:burst:window` triple, e.g. `2:5:10`. */
const policyTriple = z
  .string()
  .regex(/^\d+:\d+:\d+$/, 'expected format requests_per_second:burst_limit:window_seconds')
  .transform((value) => {
    const [requestsPerSecond, burstLimit, windowSeconds] = value.split(':').map(Number) as [
      number,
      number,
      number,
    ];
    return { requestsPerSecond, burstLimit, windowSeconds };
  });

const optionalKey = z
  .string()
  .optional()
  .transform((value) => {
    const trimmed = value?.trim();
    return trimmed && trimmed.length > 0 ? trimmed : undefined;
  });

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),

  // --- Ed25519 signing -----------------------------------------------------
  TICKET_SIGNING_PRIVATE_KEY: optionalKey,
  TICKET_SIGNING_PUBLIC_KEY: optionalKey,
  TICKET_SIGNING_KEY_ID: z.string().min(1).default('key-1'),
  TICKET_SIGNING_TRUSTED_KEY_IDS: z.string().default(''),
  TICKET_SIGNING_RETIRE_AT: z.string().optional(),
  TICKET_TTL_SECONDS: positiveInt(86_400),

  // --- Redis ---------------------------------------------------------------
  REDIS_URL: z.string().min(1).default('redis://localhost:6379'),
  REDIS_KEY_PREFIX: z.string().min(1).default('tixify:sec'),
  RATE_LIMIT_FAIL_OPEN: booleanFromEnv.default(true),

  // --- Postgres ------------------------------------------------------------
  DATABASE_URL: z.string().min(1).default('postgres://postgres:postgres@localhost:5432/tixify'),
  DATABASE_POOL_MAX: positiveInt(10),
  DATABASE_SSL: booleanFromEnv.default(false),

  // --- Privacy -------------------------------------------------------------
  IP_HASH_PEPPER: z.string().default('change-me-in-production'),

  // --- Rate limiting -------------------------------------------------------
  RATE_LIMIT_REQUESTS_PER_SECOND: positiveInt(20),
  RATE_LIMIT_BURST_LIMIT: positiveInt(40),
  RATE_LIMIT_WINDOW_SECONDS: positiveInt(1),

  RATE_LIMIT_POLICY_AUTH: policyTriple.optional(),
  RATE_LIMIT_POLICY_RESERVATION: policyTriple.optional(),
  RATE_LIMIT_POLICY_PAYMENT: policyTriple.optional(),
  RATE_LIMIT_POLICY_TICKET_VERIFY: policyTriple.optional(),
  RATE_LIMIT_POLICY_EVENT_LISTING: policyTriple.optional(),
  RATE_LIMIT_POLICY_SEAT_AVAILABILITY: policyTriple.optional(),

  // --- Idempotency ---------------------------------------------------------
  IDEMPOTENCY_TTL_SECONDS: positiveInt(86_400),
  IDEMPOTENCY_WAIT_MS: nonNegativeInt(2_000),

  // --- Bot protection ------------------------------------------------------
  BOT_PROTECTION_ENABLED: booleanFromEnv.default(true),
  BOT_CHALLENGE_THRESHOLD: positiveInt(40),
  BOT_RESTRICT_THRESHOLD: positiveInt(80),
  BOT_SIGNAL_WINDOW_SECONDS: positiveInt(300),
  BOT_MAX_FAILED_BOOKINGS: positiveInt(5),
  BOT_MAX_ACCOUNT_CREATION: positiveInt(3),
  BOT_TEMPORARY_RESTRICTION_SECONDS: positiveInt(900),

  // --- Virtual queue -------------------------------------------------------
  QUEUE_ENABLED: booleanFromEnv.default(true),
  QUEUE_MAX_CONCURRENT: positiveInt(2_000),
  QUEUE_TOKEN_TTL_SECONDS: positiveInt(120),
  QUEUE_ADMISSION_BATCH_SIZE: positiveInt(50),

  // --- Admin ---------------------------------------------------------------
  SECURITY_ADMIN_USER_IDS: z.string().default(''),

  // --- Events --------------------------------------------------------------
  SECURITY_EVENT_BUFFER_SIZE: positiveInt(100),
  SECURITY_EVENT_FLUSH_INTERVAL_MS: positiveInt(2_000),
});

export type RatePolicy = {
  requestsPerSecond: number;
  burstLimit: number;
  windowSeconds: number;
};

export type SecurityEnv = z.infer<typeof envSchema> & {
  ratePolicies: Readonly<Record<string, RatePolicy>>;
  trustedKeyIds: ReadonlySet<string>;
  adminUserIds: ReadonlySet<string>;
};

export type SecurityConfig = Readonly<{
  nodeEnv: 'development' | 'test' | 'production';
  logLevel: 'debug' | 'info' | 'warn' | 'error';
  isProduction: boolean;

  ticket: Readonly<{
    privateKey: string | undefined;
    publicKey: string | undefined;
    keyId: string;
    trustedKeyIds: ReadonlySet<string>;
    retireAt: number | undefined;
    ttlSeconds: number;
  }>;

  redis: Readonly<{
    url: string;
    keyPrefix: string;
    rateLimitFailOpen: boolean;
  }>;

  database: Readonly<{
    url: string;
    poolMax: number;
    ssl: boolean;
  }>;

  rateLimit: Readonly<{
    defaults: RatePolicy;
    policies: Readonly<Record<string, RatePolicy>>;
  }>;

  idempotency: Readonly<{
    ttlSeconds: number;
    waitMs: number;
  }>;

  bot: Readonly<{
    enabled: boolean;
    challengeThreshold: number;
    restrictThreshold: number;
    signalWindowSeconds: number;
    maxFailedBookings: number;
    maxAccountCreation: number;
    temporaryRestrictionSeconds: number;
  }>;

  queue: Readonly<{
    enabled: boolean;
    maxConcurrent: number;
    tokenTtlSeconds: number;
    admissionBatchSize: number;
  }>;

  privacy: Readonly<{
    ipHashPepper: string;
  }>;

  admin: Readonly<{
    userIds: ReadonlySet<string>;
  }>;

  events: Readonly<{
    bufferSize: number;
    flushIntervalMs: number;
  }>;
}>;

function parseRatePolicies(env: z.infer<typeof envSchema>): Record<string, RatePolicy> {
  const named: Array<[string, RatePolicy | undefined]> = [
    ['auth', env.RATE_LIMIT_POLICY_AUTH],
    ['reservation', env.RATE_LIMIT_POLICY_RESERVATION],
    ['payment', env.RATE_LIMIT_POLICY_PAYMENT],
    ['ticket_verify', env.RATE_LIMIT_POLICY_TICKET_VERIFY],
    ['event_listing', env.RATE_LIMIT_POLICY_EVENT_LISTING],
    ['seat_availability', env.RATE_LIMIT_POLICY_SEAT_AVAILABILITY],
  ];

  const policies: Record<string, RatePolicy> = {};
  for (const [name, policy] of named) {
    if (policy) policies[name] = Object.freeze({ ...policy });
  }
  return Object.freeze(policies);
}

function parseSet(raw: string): ReadonlySet<string> {
  return new Set(
    raw
      .split(',')
      .map((part) => part.trim())
      .filter((part) => part.length > 0),
  );
}

function parseInstant(raw: string | undefined): number | undefined {
  if (!raw) return undefined;
  const parsed = Date.parse(raw);
  if (Number.isNaN(parsed)) {
    throw new Error(`Invalid TICKET_SIGNING_RETIRE_AT timestamp: ${raw}`);
  }
  return parsed;
}

function buildConfig(env: z.infer<typeof envSchema>): SecurityConfig {
  const retireAt = parseInstant(env.TICKET_SIGNING_RETIRE_AT);

  const trustedKeyIds = new Set<string>(parseSet(env.TICKET_SIGNING_TRUSTED_KEY_IDS));
  // The active key is always trusted for verification, even if the operator
  // forgot to list it.
  trustedKeyIds.add(env.TICKET_SIGNING_KEY_ID);

  return Object.freeze({
    nodeEnv: env.NODE_ENV,
    logLevel: env.LOG_LEVEL,
    isProduction: env.NODE_ENV === 'production',

    ticket: Object.freeze({
      privateKey: env.TICKET_SIGNING_PRIVATE_KEY,
      publicKey: env.TICKET_SIGNING_PUBLIC_KEY,
      keyId: env.TICKET_SIGNING_KEY_ID,
      trustedKeyIds,
      retireAt,
      ttlSeconds: env.TICKET_TTL_SECONDS,
    }),

    redis: Object.freeze({
      url: env.REDIS_URL,
      keyPrefix: env.REDIS_KEY_PREFIX,
      rateLimitFailOpen: env.RATE_LIMIT_FAIL_OPEN,
    }),

    database: Object.freeze({
      url: env.DATABASE_URL,
      poolMax: env.DATABASE_POOL_MAX,
      ssl: env.DATABASE_SSL,
    }),

    rateLimit: Object.freeze({
      defaults: Object.freeze({
        requestsPerSecond: env.RATE_LIMIT_REQUESTS_PER_SECOND,
        burstLimit: env.RATE_LIMIT_BURST_LIMIT,
        windowSeconds: env.RATE_LIMIT_WINDOW_SECONDS,
      }),
      policies: Object.freeze(parseRatePolicies(env)),
    }),

    idempotency: Object.freeze({
      ttlSeconds: env.IDEMPOTENCY_TTL_SECONDS,
      waitMs: env.IDEMPOTENCY_WAIT_MS,
    }),

    bot: Object.freeze({
      enabled: env.BOT_PROTECTION_ENABLED,
      challengeThreshold: env.BOT_CHALLENGE_THRESHOLD,
      restrictThreshold: env.BOT_RESTRICT_THRESHOLD,
      signalWindowSeconds: env.BOT_SIGNAL_WINDOW_SECONDS,
      maxFailedBookings: env.BOT_MAX_FAILED_BOOKINGS,
      maxAccountCreation: env.BOT_MAX_ACCOUNT_CREATION,
      temporaryRestrictionSeconds: env.BOT_TEMPORARY_RESTRICTION_SECONDS,
    }),

    queue: Object.freeze({
      enabled: env.QUEUE_ENABLED,
      maxConcurrent: env.QUEUE_MAX_CONCURRENT,
      tokenTtlSeconds: env.QUEUE_TOKEN_TTL_SECONDS,
      admissionBatchSize: env.QUEUE_ADMISSION_BATCH_SIZE,
    }),

    privacy: Object.freeze({ ipHashPepper: env.IP_HASH_PEPPER }),

    admin: Object.freeze({ userIds: parseSet(env.SECURITY_ADMIN_USER_IDS) }),

    events: Object.freeze({
      bufferSize: env.SECURITY_EVENT_BUFFER_SIZE,
      flushIntervalMs: env.SECURITY_EVENT_FLUSH_INTERVAL_MS,
    }),
  });
}

export class ConfigurationError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'ConfigurationError';
  }
}

/**
 * Validate and freeze configuration from an environment-shaped record.
 *
 * Refuses to load in production if a signing key is missing, or if the
 * placeholder pepper is still in place. Failing here is the correct outcome:
 * a deploy that cannot sign tickets or cannot hash IPs safely should not start.
 */
export function loadConfig(source: NodeJS.ProcessEnv = process.env): SecurityConfig {
  const parsed = envSchema.safeParse(source);

  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((issue) => `  - ${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('\n');
    throw new ConfigurationError(`Invalid security engine configuration:\n${issues}`);
  }

  const env = parsed.data;
  const config = buildConfig(env);

  if (config.isProduction) {
    const problems: string[] = [];
    if (!config.ticket.privateKey) problems.push('TICKET_SIGNING_PRIVATE_KEY is required in production');
    if (!config.ticket.publicKey) problems.push('TICKET_SIGNING_PUBLIC_KEY is required in production');
    if (config.privacy.ipHashPepper === 'change-me-in-production') {
      problems.push('IP_HASH_PEPPER must be changed from its placeholder value in production');
    }
    if (config.admin.userIds.size === 0) {
      problems.push('SECURITY_ADMIN_USER_IDS must list at least one admin in production');
    }
    if (problems.length > 0) {
      throw new ConfigurationError(
        `Refusing to start in production with unsafe configuration:\n${problems
          .map((problem) => `  - ${problem}`)
          .join('\n')}`,
      );
    }
  }

  return config;
}

let cached: SecurityConfig | undefined;

/** Process-wide configuration singleton. */
export function getConfig(): SecurityConfig {
  if (!cached) cached = loadConfig();
  return cached;
}

/** Test seam: install a configuration for the current process. */
export function setConfig(config: SecurityConfig): void {
  cached = config;
}

export function resetConfig(): void {
  cached = undefined;
}
