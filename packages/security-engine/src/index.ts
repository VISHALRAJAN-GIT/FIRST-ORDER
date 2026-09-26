/**
 * Public surface of `@tixify/security-engine`.
 *
 * ## Why this file exists
 *
 * `package.json` pointed `main` and `types` at `dist/index.js` and
 * `dist/index.d.ts`, which were never generated, because there was no
 * `src/index.ts`. The package could not be imported by anything — including its
 * own tests, which all reached into `src/` paths instead. That is a real
 * integration blocker rather than a packaging nicety: Person 1 has no way to
 * depend on this engine until an entrypoint exists.
 *
 * ## What is deliberately not exported
 *
 * - `clientControlledFields` internals and the removed shallow strip helper. Two
 *   sanitiser entry points is one too many, and a second one is how a caller ends
 *   up with the weaker guarantee while believing they have the stronger one.
 * - The Lua scripts and internal key builders. They are implementation detail of
 *   correctness, and a caller who can construct a bucket key can collide with
 *   one on purpose.
 * - The durable-mirror internals. `PostgresIdempotencyStore` is exported because
 *   it is the production composition, but its `claim`/`complete` throw by design;
 *   callers compose it with `RedisIdempotencyStore`.
 *
 * Everything below is either a documented part of the 16-part specification or a
 * port that Person 1 has to implement to plug in.
 */

// --- Part 1: configuration, errors, shared primitives -----------------------
export { loadConfig, getConfig, setConfig, resetConfig } from './config/env';
export type { SecurityConfig, SecurityEnv, RatePolicy } from './config/env';
export { ConfigurationError } from './config/env';

export {
  ERROR_CODES,
  SecurityError,
  isSecurityError,
  rateLimited,
  toSecurityError,
} from './core/errors';
export type { SecurityErrorCode, SecurityErrorOptions } from './core/errors';

export { canonicalizeJson, canonicalEquals, CanonicalizationError } from './core/canonicalize';
export type { JsonPrimitive, JsonValue, JsonObject } from './core/canonicalize';

export { systemClock, FakeClock } from './core/clock';
export type { Clock } from './core/clock';

// --- Part 2: signing keys and QR -------------------------------------------
export { KeyRing, generateKeyPair, derivePublicKeyBase64 } from './crypto/key-store';
export type { VerificationKey, GeneratedKeyPair } from './crypto/key-store';

export { TicketSigner } from './crypto/signer';
export type {
  TicketSignerOptions,
  SignatureFailureReason,
  SignatureVerification,
} from './crypto/signer';

export {
  renderQrDataUri,
  renderQrBuffer,
  renderQrSvg,
  encodeEnvelope,
} from './qr/qr-service';
export type { QrRenderOptions, RenderedQr, QRErrorCorrectionLevel } from './qr/qr-service';

// --- Parts 3 and 4: ticket payload, issuance, verification, replay ---------
export {
  TICKET_PAYLOAD_VERSION,
  TICKET_ENVELOPE_VERSION,
  MAX_QR_LENGTH,
  ticketPayloadSchema,
  ticketEnvelopeSchema,
  validateTicketPayload,
  decodeTicketEnvelope,
  parseEnvelopePayload,
  buildEnvelope,
  serializeEnvelope,
} from './tickets/payload';
export type {
  TicketPayload,
  TicketEnvelope,
  TicketPayloadValidation,
} from './tickets/payload';

export { TicketIssuer } from './tickets/ticket-issuer';
export type { IssueTicketInput, IssuedTicket, TicketIssuerOptions } from './tickets/ticket-issuer';

export { TicketVerifier, VERIFICATION_OUTCOMES } from './tickets/ticket-verifier';
export type {
  VerificationOutcome,
  VerificationResult,
  VerifyOptions,
  TicketVerifierOptions,
} from './tickets/ticket-verifier';

export { ReplayGuard } from './replay/replay-guard';
export type {
  ScanOutcome,
  // Aliased: `./validation/request-sanitizer` also exports a `ScanRequest`, and
  // that one is the validated HTTP body. This is the command the guard executes.
  ScanRequest as ScanCommand,
  ScanLedger,
  TicketScanRecord,
  ReplayGuardOptions,
} from './replay/replay-guard';

export { PostgresTicketRepository } from './adapters/postgres-ticket-repository';
export type { PostgresTicketRepositoryOptions } from './adapters/postgres-ticket-repository';

export { recordScan } from './telemetry/telemetry-sink';

// --- Part 5: idempotency ----------------------------------------------------
export { IdempotencyGuard, validateIdempotencyKey, DEFAULT_IDEMPOTENCY_TTL_SECONDS } from './idempotency/idempotency-guard';
export type { IdempotencyConfig, IdempotencyContext, IdempotencyOutcome } from './idempotency/idempotency-guard';

export {
  RedisIdempotencyStore,
  fingerprintRequest,
  IDEMPOTENCY_STATES,
} from './ports/idempotency-store';
export type {
  IdempotencyStore,
  IdempotencyRecord,
  IdempotencyState,
  IdempotentResponse,
  ClaimResult,
  RedisIdempotencyStoreOptions,
} from './ports/idempotency-store';

export { PostgresIdempotencyStore } from './adapters/postgres-idempotency-store';
export type { PostgresIdempotencyStoreOptions } from './adapters/postgres-idempotency-store';

// --- Part 6: rate limiting --------------------------------------------------
export {
  RateLimiter,
  ENDPOINT_POLICIES,
  rateLimitedResponse,
} from './rate-limit/rate-limiter';
export type {
  RateLimitPolicy,
  RateLimitVerdict,
  RateLimitSubject,
  RateLimitDimension,
  RateLimiterOptions,
  PolicyName,
} from './rate-limit/rate-limiter';

// --- Part 7: bot protection -------------------------------------------------
export {
  BotProtection,
  DEFAULT_BOT_CONFIG,
  PROTECTION_LEVELS,
  BOT_SIGNALS,
  eventTypeForSignal,
} from './bot-protection/bot-protection';
export type {
  ProtectionLevel,
  BotSignal,
  BotObservation,
  SecurityDecision,
  BotProtectionConfig,
  BotProtectionOptions,
} from './bot-protection/bot-protection';

/* ---------------------------------------------------------------- Part 13 */

export { SecurityApi, SECURITY_ROUTE_IDS, listSecurityRoutes } from './api/security-api';
export type {
  SecurityApiOptions,
  SecurityRouteId,
  TicketVerificationPort,
  TicketScanPort,
  QueuePort,
} from './api/security-api';
export type { SecurityHttpRequest, SecurityHttpResponse, HttpHeaders } from './api/http-types';
export { securityMiddleware, toHttpRequest } from './api/express-adapter';
export type { ExpressLikeRequest, ExpressLikeResponse, ExpressAdapterOptions } from './api/express-adapter';

export { DEFAULT_SEVERITIES } from './bot-protection/bot-signal-types';

export { ChallengeStore } from './bot-protection/challenge';
export type {
  ChallengeSubject,
  ChallengeResult,
  ChallengeFailure,
  IssuedChallenge,
  ChallengeStoreOptions,
} from './bot-protection/challenge';

// --- Part 8: virtual queue --------------------------------------------------
export {
  VirtualQueue,
  PostgresQueueStore,
  AdmissionTokenCodec,
  newQueueId,
  DEFAULT_QUEUE_POLICY,
  QUEUE_STATUSES,
} from './queue/virtual-queue';
export type {
  QueueStatus,
  QueueEntry,
  QueueStore,
  QueuePolicy,
  QueueJoinResult,
  AdmissionToken,
  VirtualQueueOptions,
} from './queue/virtual-queue';

// --- Part 9: request validation --------------------------------------------
export {
  sanitizeBody,
  buildAuthoritativeContext,
  guardProtectedRequest,
  parseOrThrow,
  reservationRequestSchema,
  bookingRequestSchema,
  scanRequestSchema,
  queueJoinRequestSchema,
} from './validation/request-sanitizer';
export type {
  SanitizeResult,
  AuthoritativeContext,
  ReservationRequest,
  BookingRequest,
  ScanRequest,
} from './validation/request-sanitizer';

// --- Parts 10 and 11: telemetry and audit ----------------------------------
export {
  TelemetrySink,
  SECURITY_EVENT_TYPES,
  SEVERITIES,
  AUDIT_ACTIONS,
  ACTOR_TYPES,
  assertNoPii,
  pseudonymize,
  PiiInMetadataError,
} from './telemetry/telemetry-sink';
export type {
  SecurityEvent,
  SecurityEventType,
  SecurityEventInput,
  SecuritySeverity,
  AuditLog,
  AuditLogInput,
  AuditAction,
  ActorType,
  TelemetryOptions,
} from './telemetry/telemetry-sink';

// --- Part 12: dashboard -----------------------------------------------------
export { SecurityDashboard } from './dashboard/security-dashboard';
export type {
  DashboardSummary,
  DashboardOptions,
  SecurityDashboardQuery,
  RecentEvent,
  EventCount,
  SeverityCount,
  TrendPoint,
} from './dashboard/security-dashboard';

// --- Ports Person 1 implements ---------------------------------------------
export { wrapIoredis, createIoredisFactory } from './ports/redis';
export type { RedisLike, RedisFactory, RedisValue, IoredisLike } from './ports/redis';

export { ConfiguredAdminAuthorizer, USER_ROLES, CLIENT_CONTROLLED_FIELDS } from './ports/user-resolver';
export type {
  UserResolver,
  UserRole,
  AuthenticatedPrincipal,
  AdminAuthorizer,
  ClientControlledField,
} from './ports/user-resolver';

export { TICKET_STATES } from './ports/ticket-repository';
export type {
  TicketRepository,
  TicketRecord,
  TicketState,
  ConsumeOutcome,
  TicketConsumptionContext,
} from './ports/ticket-repository';

export { EVENT_STATUSES } from './ports/event-repository';
export type {
  EventRepository,
  SeatRepository,
  AuditSink,
  EventRecord,
  EventStatus,
} from './ports/event-repository';
