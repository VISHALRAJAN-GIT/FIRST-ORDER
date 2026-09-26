/**
 * Closed error taxonomy for the security engine.
 *
 * Two rules govern everything here:
 *
 *  1. Error *codes* are a public, stable contract. They are safe to return to a
 *     client and are documented in SECURITY_INTEGRATION.md.
 *  2. Error *messages* are for operators and logs only. They may name internal
 *     systems, and must never be serialized into an HTTP response body. This is
 *     the mechanism that keeps us from leaking "user 42 does not exist" or a
 *     Postgres constraint name to an attacker probing the verify endpoint.
 */

export const ERROR_CODES = [
  'RATE_LIMITED',
  'IDEMPOTENCY_KEY_REUSE',
  'IDEMPOTENCY_IN_PROGRESS',
  'INVALID_SIGNATURE',
  'INVALID_TICKET',
  'TICKET_CLAIM_MISMATCH',
  'TICKET_NOT_FOUND',
  'TICKET_EXPIRED',
  'TICKET_ALREADY_USED',
  'TICKET_CANCELLED',
  'WRONG_EVENT',
  'TICKET_NOT_CONFIRMED',
  'MALFORMED_QR',
  'REPLAY_ATTEMPT',
  'QUEUE_BYPASS_ATTEMPT',
  'QUEUE_TOKEN_INVALID',
  'QUEUE_TOKEN_EXPIRED',
  'UNAUTHORIZED',
  'FORBIDDEN',
  'TEMPORARILY_RESTRICTED',
  'CHALLENGE_REQUIRED',
  'VALIDATION_FAILED',
  'SECURITY_DEPENDENCY_UNAVAILABLE',
  'INTERNAL_ERROR',
] as const;

export type SecurityErrorCode = (typeof ERROR_CODES)[number];

export interface SecurityErrorOptions {
  /** Public-safe detail. Safe to return to the client verbatim. */
  readonly publicMessage?: string;
  /** Extra fields safe to expose. Never include internal identifiers. */
  readonly publicDetails?: Record<string, string | number | boolean>;
  /** Suggested HTTP status. Defaults to 400. */
  readonly status?: number;
  /** Seconds the client should wait before retrying. */
  readonly retryAfterSeconds?: number;
  /** Underlying error, retained for logs only. */
  readonly cause?: unknown;
}

const DEFAULT_STATUS: Record<SecurityErrorCode, number> = {
  RATE_LIMITED: 429,
  IDEMPOTENCY_KEY_REUSE: 409,
  IDEMPOTENCY_IN_PROGRESS: 409,
  INVALID_SIGNATURE: 400,
  INVALID_TICKET: 400,
  TICKET_CLAIM_MISMATCH: 409,
  TICKET_NOT_FOUND: 404,
  TICKET_EXPIRED: 410,
  TICKET_ALREADY_USED: 409,
  TICKET_CANCELLED: 409,
  WRONG_EVENT: 409,
  TICKET_NOT_CONFIRMED: 409,
  MALFORMED_QR: 400,
  REPLAY_ATTEMPT: 409,
  QUEUE_BYPASS_ATTEMPT: 403,
  QUEUE_TOKEN_INVALID: 403,
  QUEUE_TOKEN_EXPIRED: 403,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  TEMPORARILY_RESTRICTED: 429,
  CHALLENGE_REQUIRED: 403,
  VALIDATION_FAILED: 400,
  SECURITY_DEPENDENCY_UNAVAILABLE: 503,
  INTERNAL_ERROR: 500,
};

/** Base class for every error the security engine raises deliberately. */
export class SecurityError extends Error {
  readonly code: SecurityErrorCode;
  readonly status: number;
  readonly publicMessage: string;
  readonly publicDetails: Record<string, string | number | boolean> | undefined;
  readonly retryAfterSeconds: number | undefined;

  constructor(code: SecurityErrorCode, message: string, options: SecurityErrorOptions = {}) {
    super(message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = 'SecurityError';
    this.code = code;
    this.status = options.status ?? DEFAULT_STATUS[code] ?? 400;
    this.publicMessage = options.publicMessage ?? DEFAULT_PUBLIC_MESSAGE[code] ?? 'Request could not be processed.';
    this.publicDetails = options.publicDetails;
    this.retryAfterSeconds = options.retryAfterSeconds;
  }

  /**
   * The only shape permitted to cross the network boundary. Deliberately
   * excludes `message` and `stack`, which is the point.
   */
  toPublicJSON(): {
    success: false;
    error: {
      code: SecurityErrorCode;
      message: string;
      details?: Record<string, string | number | boolean>;
      retryAfterSeconds?: number;
    };
  } {
    return {
      success: false,
      error: {
        code: this.code,
        message: this.publicMessage,
        ...(this.publicDetails ? { details: this.publicDetails } : {}),
        ...(this.retryAfterSeconds !== undefined ? { retryAfterSeconds: this.retryAfterSeconds } : {}),
      },
    };
  }
}

/**
 * Public messages are intentionally uniform. "Invalid signature" and "unknown
 * ticket" are separated only because the spec enumerates them as distinct
 * outcomes; beyond that list, an attacker learns nothing about why a scan
 * failed or what exists on the system.
 */
const DEFAULT_PUBLIC_MESSAGE: Partial<Record<SecurityErrorCode, string>> = {
  RATE_LIMITED: 'Too many requests. Please try again.',
  IDEMPOTENCY_KEY_REUSE: 'This idempotency key was already used with a different request.',
  IDEMPOTENCY_IN_PROGRESS: 'An identical request is already being processed.',
  INVALID_SIGNATURE: 'Ticket signature could not be verified.',
  INVALID_TICKET: 'Ticket is not valid.',
  TICKET_CLAIM_MISMATCH: 'Ticket is not valid.',
  TICKET_NOT_FOUND: 'Ticket not found.',
  TICKET_EXPIRED: 'Ticket has expired.',
  TICKET_ALREADY_USED: 'Ticket has already been used.',
  TICKET_CANCELLED: 'Ticket has been cancelled.',
  WRONG_EVENT: 'Ticket is not valid for this event.',
  TICKET_NOT_CONFIRMED: 'Ticket is not confirmed.',
  MALFORMED_QR: 'QR code could not be read.',
  REPLAY_ATTEMPT: 'This ticket has already been scanned.',
  QUEUE_BYPASS_ATTEMPT: 'Admission could not be verified.',
  QUEUE_TOKEN_INVALID: 'Admission token is not valid.',
  QUEUE_TOKEN_EXPIRED: 'Admission token has expired.',
  UNAUTHORIZED: 'Authentication required.',
  FORBIDDEN: 'You do not have access to this resource.',
  TEMPORARILY_RESTRICTED: 'Access temporarily restricted. Please try again later.',
  CHALLENGE_REQUIRED: 'Additional verification is required.',
  VALIDATION_FAILED: 'Request is invalid.',
  SECURITY_DEPENDENCY_UNAVAILABLE: 'Service temporarily unavailable. Please try again.',
  INTERNAL_ERROR: 'Something went wrong. Please try again.',
};

export function isSecurityError(error: unknown): error is SecurityError {
  return error instanceof SecurityError;
}

export function rateLimited(options: SecurityErrorOptions = {}): SecurityError {
  return new SecurityError('RATE_LIMITED', 'Rate limit exceeded', options);
}

/**
 * Wrap an unknown thrown value as a SecurityError so nothing internal escapes
 * to the HTTP layer. Anything that is not already a deliberate SecurityError is
 * treated as an internal fault and reported generically.
 */
export function toSecurityError(error: unknown): SecurityError {
  if (isSecurityError(error)) return error;
  return new SecurityError('INTERNAL_ERROR', 'Unhandled security engine error', {
    publicMessage: DEFAULT_PUBLIC_MESSAGE.INTERNAL_ERROR,
    cause: error,
  });
}
