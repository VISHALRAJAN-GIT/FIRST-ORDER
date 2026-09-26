import { z } from 'zod';

import { SecurityError, type SecurityErrorCode } from '../core/errors';
import type { SecurityDashboard } from '../dashboard/security-dashboard';
import type { RateLimiter, RateLimitDimension } from '../rate-limit/rate-limiter';
import { rateLimitedResponse } from '../rate-limit/rate-limiter';
import type { ScanRequest } from '../replay/replay-guard';
import type { VerificationResult } from '../tickets/ticket-verifier';
import type { TelemetrySink } from '../telemetry/telemetry-sink';
import { SECURITY_EVENT_TYPES, SEVERITIES } from '../telemetry/telemetry-sink';
import { sanitizeBody, parseOrThrow } from '../validation/request-sanitizer';
import type { AdminAuthorizer, AuthenticatedPrincipal, UserResolver } from '../ports/user-resolver';
import { jsonResponse, queryValue, type SecurityHttpRequest, type SecurityHttpResponse } from './http-types';

/**
 * Stable route identifiers.
 *
 * These are used as the rate-limit `endpoint` component and written to
 * telemetry. They are identifiers, not URLs: if the host mounts the router under
 * a different prefix, the bucket a request lands in must not change, or a
 * deployment that moves its routes silently resets every rate limit.
 */
export const SECURITY_ROUTE_IDS = [
  'tickets.verify',
  'tickets.scan',
  'security.status',
  'security.events',
  'queue.status',
  'queue.join',
  'queue.leave',
] as const;

export type SecurityRouteId = (typeof SECURITY_ROUTE_IDS)[number];

type Access = 'anonymous' | 'authenticated' | 'admin';

interface RouteDefinition {
  readonly id: SecurityRouteId;
  readonly method: 'GET' | 'POST';
  /** Path template, `:name` marks a parameter. */
  readonly path: string;
  readonly access: Access;
  readonly policy: 'TICKET_VERIFY' | 'EVENT_LISTING' | 'RESERVATION';
}

const ROUTES: readonly RouteDefinition[] = [
  { id: 'tickets.verify', method: 'POST', path: '/api/tickets/verify', access: 'anonymous', policy: 'TICKET_VERIFY' },
  { id: 'tickets.scan', method: 'POST', path: '/api/tickets/scan', access: 'authenticated', policy: 'TICKET_VERIFY' },
  { id: 'security.status', method: 'GET', path: '/api/security/status', access: 'admin', policy: 'EVENT_LISTING' },
  { id: 'security.events', method: 'GET', path: '/api/security/events', access: 'admin', policy: 'EVENT_LISTING' },
  { id: 'queue.status', method: 'GET', path: '/api/queue/:eventId/status', access: 'authenticated', policy: 'EVENT_LISTING' },
  { id: 'queue.join', method: 'POST', path: '/api/queue/:eventId/join', access: 'authenticated', policy: 'RESERVATION' },
  { id: 'queue.leave', method: 'POST', path: '/api/queue/:eventId/leave', access: 'authenticated', policy: 'RESERVATION' },
];

/** Every route the engine serves, for a host that wants to build its own table. */
export function listSecurityRoutes(): readonly { id: SecurityRouteId; method: string; path: string }[] {
  return ROUTES.map((r) => ({ id: r.id, method: r.method, path: r.path }));
}

export interface SecurityApiOptions {
  readonly verifier: TicketVerificationPort;
  readonly replayGuard: TicketScanPort;
  readonly queue: QueuePort;
  readonly userResolver: UserResolver;
  readonly authorizer: AdminAuthorizer;
  /** Optional: the admin read routes return 501 without it. */
  readonly dashboard?: SecurityDashboard | undefined;
  /** Optional: without it no request is rate limited. */
  readonly rateLimiter?: RateLimiter | undefined;
  /** Optional: without it nothing is recorded. */
  readonly telemetry?: TelemetrySink | undefined;
  /**
   * What to do when Redis is unreachable and the rate limiter cannot decide.
   * Defaults to false, matching the limiter's own default. Verification routes
   * are exempt either way - see `#rateLimit`.
   */
  readonly failClosedOnRateLimitUnavailable?: boolean;
}

/**
 * The three collaborators, described by what the API needs rather than by which
 * class implements them.
 *
 * `TicketVerifier`, `ReplayGuard` and `VirtualQueue` all satisfy these
 * structurally, so existing wiring is unchanged. The point is the other
 * direction: Person 1 can supply their own adapter, and this package has no
 * reason to grow a dependency on a concrete implementation for the sake of a
 * type annotation. A handler that takes `VirtualQueue` cannot be tested without
 * a Redis connection or a full class instance, and neither of those is what this
 * layer is doing.
 */
export interface TicketVerificationPort {
  verify(
    rawQr: unknown,
    options?: { readonly expectedEventId?: string; readonly validateSeat?: boolean; readonly expiryGraceMs?: number },
  ): Promise<VerificationResult>;
}

export interface TicketScanPort {
  scan(request: ScanRequest): Promise<VerificationResult>;
}

export interface QueuePort {
  status(
    eventId: string,
    sessionId: string,
  ): Promise<{
    readonly active: boolean;
    readonly entry: unknown;
    readonly ahead: number;
    readonly size: number;
    readonly estimatedWaitSeconds: number;
  }>;
  join(input: { readonly eventId: string; readonly sessionId: string; readonly userId?: string | undefined }): Promise<{
    readonly status: 'QUEUED' | 'ALREADY_QUEUED';
    readonly queueId: string;
    readonly position: number;
  }>;
  leave(eventId: string, sessionId: string): Promise<boolean>;
}

const EVENT_ID = z.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/);

/**
 * Client body for ticket verification and scanning.
 *
 * `scannerId` is deliberately absent, even though the shared `scanRequestSchema`
 * offers it. A client that can name its own scanner can forge which gate scanned
 * a ticket, which corrupts the audit trail and lets one person launder another's
 * entry as an operator action. It is derived from the authenticated principal
 * instead, and because this is a `strictObject` a body that sends it gets a 400
 * rather than having it quietly ignored.
 */
const ticketBodySchema = z.strictObject({
  qr: z.string().min(1).max(8192),
  eventId: EVENT_ID,
  validateSeat: z.boolean().optional(),
  expiryGraceMs: z.number().int().min(0).max(300_000).optional(),
});

const eventsQuerySchema = z.strictObject({
  windowSeconds: z.coerce.number().int().min(60).max(7 * 24 * 60 * 60).optional(),
  eventType: z.enum(SECURITY_EVENT_TYPES).optional(),
  severity: z.enum(SEVERITIES).optional(),
  limit: z.coerce.number().int().min(1).max(500).optional(),
});

/** Maps an internal outcome to the error code the client sees. */
const OUTCOME_TO_CODE: Readonly<Record<string, SecurityErrorCode>> = {
  ALREADY_USED: 'TICKET_ALREADY_USED',
  EXPIRED: 'TICKET_EXPIRED',
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  TICKET_CLAIM_MISMATCH: 'TICKET_CLAIM_MISMATCH',
  TICKET_NOT_FOUND: 'TICKET_NOT_FOUND',
  CANCELLED: 'TICKET_CANCELLED',
  WRONG_EVENT: 'WRONG_EVENT',
  TICKET_NOT_CONFIRMED: 'TICKET_NOT_CONFIRMED',
  MALFORMED_QR: 'MALFORMED_QR',
  REPLAY_ATTEMPT: 'REPLAY_ATTEMPT',
  SERVICE_UNAVAILABLE: 'SECURITY_DEPENDENCY_UNAVAILABLE',
};

const OUTCOME_STATUS: Readonly<Record<string, number>> = {
  ALREADY_USED: 409,
  EXPIRED: 410,
  WRONG_EVENT: 403,
  TICKET_CLAIM_MISMATCH: 403,
  TICKET_NOT_CONFIRMED: 403,
  CANCELLED: 409,
  TICKET_NOT_FOUND: 404,
  SERVICE_UNAVAILABLE: 503,
};

function toPublicError(result: VerificationResult, message: string): SecurityError {
  const code = OUTCOME_TO_CODE[result.outcome] ?? 'INVALID_TICKET';
  return new SecurityError(code, `${message}: ${result.outcome}`, {
    status: OUTCOME_STATUS[result.outcome] ?? (result.outcome === 'VALID' ? 400 : 422),
    // `outcome` is echoed because it is our own vocabulary and the gate operator
    // needs to know why a scan failed. It carries no information about *which*
    // ticket or who holds it.
    publicDetails: { outcome: result.outcome },
  });
}

/**
 * Part 13.
 *
 * A `handle(request) -> response` router with no framework dependency. Every
 * path returns a response; `handle` does not throw. That is the property the
 * host needs, because a middleware that can throw forces every host adapter to
 * reimplement error handling, and the version that forgets is the one that
 * leaks a stack trace.
 */
export class SecurityApi {
  readonly #verifier: TicketVerificationPort;
  readonly #replay: TicketScanPort;
  readonly #queue: QueuePort;
  readonly #users: UserResolver;
  readonly #authorizer: AdminAuthorizer;
  readonly #dashboard: SecurityDashboard | undefined;
  readonly #limiter: RateLimiter | undefined;
  readonly #telemetry: TelemetrySink | undefined;
  readonly #failClosed: boolean;

  constructor(options: SecurityApiOptions) {
    this.#verifier = options.verifier;
    this.#replay = options.replayGuard;
    this.#queue = options.queue;
    this.#users = options.userResolver;
    this.#authorizer = options.authorizer;
    this.#dashboard = options.dashboard;
    this.#limiter = options.rateLimiter;
    this.#telemetry = options.telemetry;
    this.#failClosed = options.failClosedOnRateLimitUnavailable ?? false;
  }

  async handle(request: SecurityHttpRequest): Promise<SecurityHttpResponse> {
    const method = (request.method ?? '').toUpperCase();
    const path = normalizePath(request.path);

    const matched = this.#match(method, path);
    if (!matched.ok) {
      // Path exists under a different method? That is a 405, and saying so is more
      // use to a host debugging a mount than a flat 404. It leaks only which of
      // our own routes exist, which is not a secret.
      if (matched.pathExists) {
        return jsonResponse(405, { success: false, error: { code: 'VALIDATION_FAILED', message: 'Method not allowed.' } }, { allow: matched.allow });
      }
      return this.#fail(404, 'VALIDATION_FAILED', 'Not found.');
    }

    const { route, params } = matched;

    try {
      const principal = await this.#users.resolve(request.credential);

      const accessError = this.#checkAccess(route, principal);
      if (accessError) {
        await this.#record('UNAUTHORIZED_ACCESS_ATTEMPT', 'MEDIUM', request, {
          route: route.id,
          path: path,
          required: route.access,
        });
        return accessError;
      }

      const limited = await this.#rateLimit(route, request, principal, params);
      if (limited) return limited;

      return await this.#dispatch(route, params, request, principal);
    } catch (error) {
      if (error instanceof SecurityError) {
        return jsonResponse(error.status, error.toPublicJSON(), this.#errorHeaders(error));
      }
      // Anything not already a SecurityError is a bug, and the client is told as
      // little as possible. `message` and `stack` stay in the server log.
      await this.#record('EXCESSIVE_REQUESTS', 'LOW', request, { route: route.id, unexpected: true });
      return jsonResponse(500, {
        success: false,
        error: { code: 'INTERNAL_ERROR', message: 'Request could not be processed.' },
      });
    }
  }

  /* ---------------------------------------------------------------- routing */

  #match(
    method: string,
    path: string,
  ): { ok: true; route: RouteDefinition; params: Readonly<Record<string, string>> } | { ok: false; pathExists: boolean; allow: string } {
    const allowed = new Set<string>();
    for (const route of ROUTES) {
      const params = matchPath(route.path, path);
      if (params === null) continue;
      if (route.method === method) return { ok: true, route, params };
      allowed.add(route.method);
    }
    return { ok: false, pathExists: allowed.size > 0, allow: [...allowed].join(', ') };
  }

  async #dispatch(
    route: RouteDefinition,
    params: Readonly<Record<string, string>>,
    request: SecurityHttpRequest,
    principal: AuthenticatedPrincipal | null,
  ): Promise<SecurityHttpResponse> {
    switch (route.id) {
      case 'tickets.verify':
        return this.#verifyTicket(request);
      case 'tickets.scan':
        return this.#scanTicket(request, principal);
      case 'security.status':
        return this.#securityStatus(principal);
      case 'security.events':
        return this.#securityEvents(request, principal);
      case 'queue.status':
        return this.#queueStatus(params.eventId ?? '', principal);
      case 'queue.join':
        return this.#queueJoin(params.eventId ?? '', principal);
      case 'queue.leave':
        return this.#queueLeave(params.eventId ?? '', principal);
    }
  }

  /* --------------------------------------------------------------- handlers */

  async #verifyTicket(request: SecurityHttpRequest): Promise<SecurityHttpResponse> {
    const body = this.#body(request, ticketBodySchema);
    // `verify` not `verifyAndConsume`: this endpoint is a read the app may make
    // before a purchase, and consuming here would let anyone burn a ticket by
    // asking about it.
    const result = await this.#verifier.verify(body.qr, {
      expectedEventId: body.eventId,
      validateSeat: body.validateSeat,
      expiryGraceMs: body.expiryGraceMs,
    });

    if (!result.valid) {
      await this.#record('INVALID_TICKET', 'MEDIUM', request, { outcome: result.outcome, endpoint: 'verify' });
      throw toPublicError(result, 'Ticket verification failed');
    }

    // The ticket block deliberately omits userId and pricing, as documented on
    // VerificationResult: a client that logs this response cannot leak PII.
    return jsonResponse(200, { success: true, data: { outcome: result.outcome, ticket: result.ticket, kid: result.kid } });
  }

  async #scanTicket(
    request: SecurityHttpRequest,
    principal: AuthenticatedPrincipal | null,
  ): Promise<SecurityHttpResponse> {
    const body = this.#body(request, ticketBodySchema);

    const result = await this.#replay.scan({
      qr: body.qr,
      eventId: body.eventId,
      validateSeat: body.validateSeat,
      expiryGraceMs: body.expiryGraceMs,
      // Server-derived, never from the body. See `ticketBodySchema`.
      scannerId: principal?.userId,
      actorId: principal?.userId,
    });

    if (!result.valid) {
      await this.#record('TICKET_SCAN_REJECTED', 'MEDIUM', request, {
        outcome: result.outcome,
        eventId: body.eventId,
        scannerId: principal?.userId,
      });
      throw toPublicError(result, 'Ticket scan rejected');
    }

    await this.#record('TICKET_SCAN_ACCEPTED', 'LOW', request, {
      eventId: body.eventId,
      ticketId: result.ticket?.ticketId,
      scannerId: principal?.userId,
    });

    return jsonResponse(200, { success: true, data: { outcome: result.outcome, ticket: result.ticket, kid: result.kid } });
  }

  async #securityStatus(principal: AuthenticatedPrincipal | null): Promise<SecurityHttpResponse> {
    const dashboard = this.#requireDashboard();
    return jsonResponse(200, { success: true, data: await dashboard.summary({ principal }) });
  }

  async #securityEvents(
    request: SecurityHttpRequest,
    principal: AuthenticatedPrincipal | null,
  ): Promise<SecurityHttpResponse> {
    const dashboard = this.#requireDashboard();
    const query = parseOrThrow(eventsQuerySchema, collectEventsQuery(request));
    return jsonResponse(200, {
      success: true,
      data: await dashboard.recentEvents({
        principal,
        windowSeconds: query.windowSeconds,
        eventType: query.eventType,
        severity: query.severity,
        limit: query.limit,
      }),
    });
  }

  async #queueStatus(eventId: string, principal: AuthenticatedPrincipal | null): Promise<SecurityHttpResponse> {
    const sessionId = this.#requireSession(principal);
    const status = await this.#queue.status(this.#requireEventId(eventId), sessionId);
    return jsonResponse(200, { success: true, data: { eventId, ...status } });
  }

  async #queueJoin(eventId: string, principal: AuthenticatedPrincipal | null): Promise<SecurityHttpResponse> {
    const sessionId = this.#requireSession(principal);
    const joined = await this.#queue.join({ eventId: this.#requireEventId(eventId), sessionId, userId: principal?.userId });
    // 200 for both QUEUED and ALREADY_QUEUED. Re-joining is a normal client
    // retry, and a 409 would push clients into error handling for a success.
    return jsonResponse(200, { success: true, data: { eventId, ...joined } });
  }

  async #queueLeave(eventId: string, principal: AuthenticatedPrincipal | null): Promise<SecurityHttpResponse> {
    const sessionId = this.#requireSession(principal);
    const left = await this.#queue.leave(this.#requireEventId(eventId), sessionId);
    if (!left) {
      // Not an error: leaving a queue you are not in leaves the queue in the state
      // you wanted. 404 here would make an idempotent cleanup call look broken.
      return jsonResponse(200, { success: true, data: { eventId, left: false } });
    }
    return jsonResponse(200, { success: true, data: { eventId, left: true } });
  }

  /* -------------------------------------------------------------- accessors */

  #requireDashboard(): SecurityDashboard {
    if (!this.#dashboard) {
      throw new SecurityError('SECURITY_DEPENDENCY_UNAVAILABLE', 'No dashboard configured', {
        status: 501,
        publicMessage: 'Not available.',
      });
    }
    return this.#dashboard;
  }

  #requireSession(principal: AuthenticatedPrincipal | null): string {
    if (!principal?.sessionId) {
      // Authenticated but unbindable. A queue entry is keyed by session, so
      // without one there is nothing to join *as*, and silently using the userId
      // would let one user act for several sessions at once.
      throw new SecurityError('VALIDATION_FAILED', 'Queue operations require a session', {
        publicDetails: { field: 'sessionId' },
      });
    }
    return principal.sessionId;
  }

  #requireEventId(eventId: string): string {
    const parsed = EVENT_ID.safeParse(eventId);
    if (!parsed.success) {
      throw new SecurityError('VALIDATION_FAILED', 'Invalid eventId in path', {
        publicDetails: { field: 'eventId' },
      });
    }
    return parsed.data;
  }

  /* ------------------------------------------------------------- access/rate */

  #checkAccess(route: RouteDefinition, principal: AuthenticatedPrincipal | null): SecurityHttpResponse | null {
    if (route.access === 'anonymous') return null;
    if (principal === null) {
      // 401, for every gated route. This is checked before the admin test on
      // purpose: with no credential at all the answer is "authenticate", and
      // returning 403 there tells an anonymous prober that the resource exists and
      // that a different credential would be worth trying.
      return jsonResponse(401, {
        success: false,
        error: { code: 'UNAUTHORIZED', message: 'Authentication required.' },
      });
    }
    if (route.access === 'authenticated') return null;
    if (this.#authorizer.isAdmin(principal)) return null;
    // 403 rather than 401 for an authenticated non-admin: 401 would invite a
    // client to retry with a different credential, which tells them the
    // credential they sent was accepted.
    return jsonResponse(403, {
      success: false,
      error: { code: 'FORBIDDEN', message: 'Administrator access required.' },
    });
  }

  async #rateLimit(
    route: RouteDefinition,
    request: SecurityHttpRequest,
    principal: AuthenticatedPrincipal | null,
    params: Readonly<Record<string, string>>,
  ): Promise<SecurityHttpResponse | null> {
    if (!this.#limiter) return null;

    const dimensions: RateLimitDimension[] = ['IP'];
    if (principal?.sessionId) dimensions.push('SESSION');
    if (principal?.userId) dimensions.push('USER');

    const eventId = params.eventId ?? undefined;
    const endpoint = `${route.method} ${route.path}`;

    for (const dimension of dimensions) {
      const verdict = await this.#limiter.consumeFor(
        { ip: request.ip, userId: principal?.userId, sessionId: principal?.sessionId, endpoint, eventId },
        route.policy,
        dimension,
      );

      if (verdict.allowed) continue;

      if (!verdict.available) {
        if (this.#failClosed && !VERIFICATION_ROUTES.has(route.id)) {
          // Verification and scanning stay open on purpose: a Redis blip closing
          // the gates stops real people getting into the venue, which is a worse
          // outcome than letting a determined attacker through.
          return this.#fail(503, 'SECURITY_DEPENDENCY_UNAVAILABLE', 'Request could not be rate limited.');
        }
        continue;
      }

      await this.#record('RATE_LIMIT_TRIGGERED', 'LOW', request, {
        route: route.id,
        dimension,
        policy: verdict.policy,
      });
      return jsonResponse(429, rateLimitedResponse(verdict));
    }
    return null;
  }

  /* ---------------------------------------------------------------- helpers */

  #body<T extends z.ZodTypeAny>(request: SecurityHttpRequest, schema: T): z.infer<T> {
    if (request.body === undefined || request.body === null) {
      throw new SecurityError('VALIDATION_FAILED', 'Request body required');
    }
    // A string body means the host did not parse it. Guessing at JSON here would
    // mean two different parse behaviours in production and in tests.
    if (typeof request.body === 'string') {
      throw new SecurityError('VALIDATION_FAILED', 'Request body must be pre-parsed, not a raw string');
    }
    // Sanitized before validated, so a body carrying `role` or `isAdmin` is
    // stripped first and then fails the strict schema as an unknown key - the
    // client is told its body was wrong, not that we ignored a field.
    const sanitized = sanitizeBody(request.body, { extraBlocked: ['scannerId'] });
    return parseOrThrow(schema, sanitized.body);
  }

  #errorHeaders(error: SecurityError): Record<string, string> {
    return error.retryAfterSeconds !== undefined
      ? { 'retry-after': String(error.retryAfterSeconds) }
      : {};
  }

  #fail(status: number, code: SecurityErrorCode, message: string): SecurityHttpResponse {
    return jsonResponse(status, { success: false, error: { code, message } });
  }

  async #record(
    eventType: Parameters<TelemetrySink['recordEvent']>[0]['eventType'],
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
    request: SecurityHttpRequest,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    if (!this.#telemetry) return;
    // Fire and forget, and never allowed to change the response. A telemetry
    // outage must not turn a valid scan into a 500, and `recordEvent` throwing on
    // PII would otherwise surface as a failed request.
    try {
      await this.#telemetry.recordEvent({
        eventType,
        severity,
        ip: request.ip,
        method: (request.method ?? '').toUpperCase(),
        endpoint: request.path,
        metadata,
      });
    } catch {
      /* ignored on purpose */
    }
  }
}

const VERIFICATION_ROUTES: ReadonlySet<SecurityRouteId> = new Set(['tickets.verify', 'tickets.scan']);

/** Trims a trailing slash, collapses duplicates, and strips any query string. */
function normalizePath(raw: string | undefined): string {
  const withoutQuery = (raw ?? '').split('?')[0] ?? '';
  const collapsed = withoutQuery.replace(/\/{2,}/g, '/');
  if (collapsed.length > 1 && collapsed.endsWith('/')) return collapsed.slice(0, -1);
  return collapsed || '/';
}

/** Returns captured params, or null when the pattern does not match. */
function matchPath(pattern: string, path: string): Record<string, string> | null {
  const patternParts = pattern.split('/').filter(Boolean);
  const pathParts = path.split('/').filter(Boolean);
  if (patternParts.length !== pathParts.length) return null;

  const params: Record<string, string> = {};
  for (let i = 0; i < patternParts.length; i += 1) {
    const expected = patternParts[i] as string;
    const actual = pathParts[i] as string;
    if (expected.startsWith(':')) {
      // A param is captured raw and validated by the handler, not here. Decoding
      // here would let `%2F` smuggle a path separator past the segment count.
      if (actual.length === 0) return null;
      params[expected.slice(1)] = actual;
      continue;
    }
    if (expected !== actual) return null;
  }
  return params;
}

/** Only the keys the events route understands, so an unexpected query is a 400. */
function collectEventsQuery(request: SecurityHttpRequest): Record<string, string | undefined> {
  const source = request.query ?? {};
  const out: Record<string, string | undefined> = {};
  for (const key of ['windowSeconds', 'eventType', 'severity', 'limit']) {
    const value = queryValue(source, key);
    if (value !== undefined) out[key] = value;
  }
  return out;
}
