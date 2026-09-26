/**
 * Part 9 — Request signature / validation: never trust client-controlled fields.
 *
 * The spec lists the fields a client must never be believed about — `userId`,
 * `price`, `paymentStatus`, `ticketStatus`, `role`, `bookingOwner` — and says the
 * backend should derive authoritative values instead.
 *
 * ## Strip, then derive
 *
 * The sanitizer REMOVES these fields from the inbound body and reports what it
 * removed, and the handler receives only the sanitized body plus a
 * server-derived principal. It does not merely overwrite them, because a field
 * that survives into a handler is a field a future maintainer will eventually
 * read by accident, and "we overwrite it today" is not a property a codebase can
 * rely on.
 *
 * ## The spec's escape hatch
 *
 * "If Person 1 already implements this correctly, do not duplicate it." That is
 * why this is a standalone, opt-in middleware rather than something wired into
 * every route: if the booking engine already derives identity and price from its
 * own authoritative reads, this adds nothing but a second place to get it wrong.
 * The adapter belongs at the boundary, and the decision to mount it belongs to
 * whoever owns the route.
 *
 * Nested objects are sanitized too. A `payment: { amount: 9999 }` is the same
 * attack as a top-level one, and a shallow strip would miss it.
 */

import { z } from 'zod';
import {
  CLIENT_CONTROLLED_FIELDS,
  type AuthenticatedPrincipal,
  type UserResolver,
} from '../ports/user-resolver';
import { SecurityError } from '../core/errors';

/** Case-insensitive match, because attackers vary case to slip past a blocklist. */
const BLOCKED = new Set(CLIENT_CONTROLLED_FIELDS.map((f) => f.toLowerCase()));

export interface SanitizeResult {
  /**
   * The sanitized body.
   *
   * Typed `unknown` on purpose: a non-object body is passed through untouched
   * rather than coerced to `{}`. Coercing would let `"hello"` satisfy a schema
   * whose fields are all optional, turning a malformed request into a valid one
   * inside the middleware meant to protect the route. Rejecting a non-object is
   * the schema's job, and it does it with a useful error.
   */
  readonly body: unknown;
  /** Every blocked key removed, at any depth. Surfaced so it can be logged. */
  readonly stripped: readonly string[];
}

/**
 * Remove client-controlled authority fields, recursively.
 *
 * Recursion is depth-bounded: a deeply nested body is itself a denial-of-service
 * vector, and an unbounded recursion would turn a malicious payload into a stack
 * overflow inside the middleware meant to protect the route.
 */
export function sanitizeBody(
  input: unknown,
  options: { readonly maxDepth?: number; readonly extraBlocked?: readonly string[] } = {},
): SanitizeResult {
  const maxDepth = options.maxDepth ?? 8;
  const blocked = new Set([...BLOCKED, ...(options.extraBlocked ?? []).map((f) => f.toLowerCase())]);
  const stripped: string[] = [];

  const walk = (value: unknown, depth: number, path: string): unknown => {
    if (depth > maxDepth) {
      throw new SecurityError('VALIDATION_FAILED', `Request body nested deeper than ${maxDepth} levels`, {
        publicMessage: 'Request is invalid.',
      });
    }
    if (Array.isArray(value)) return value.map((item, i) => walk(item, depth + 1, `${path}[${i}]`));
    if (value === null || typeof value !== 'object') return value;

    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      if (blocked.has(key.toLowerCase())) {
        stripped.push(path ? `${path}.${key}` : key);
        continue;
      }
      output[key] = walk(child, depth + 1, path ? `${path}.${key}` : key);
    }
    return output;
  };

  const body = walk(input, 0, '');
  return { body, stripped };
}

export interface AuthoritativeContext {
  /** Resolved server-side. The client's claim about who they are is ignored. */
  readonly principal: AuthenticatedPrincipal | null;
  readonly userId: string | null;
  /** Path the request was matched on, used for audit context. */
  readonly endpoint: string;
  readonly ip?: string | undefined;
  readonly requestId?: string | undefined;
}

/**
 * Build the authoritative context from a verified credential.
 *
 * There is deliberately no code path that reads identity from the body or from a
 * client-settable header. `UserResolver` implementations must derive the
 * principal from something the client cannot forge; see the port's documentation
 * for why a header-reading implementation is a vulnerability with an interface.
 */
export async function buildAuthoritativeContext(
  userResolver: UserResolver,
  credential: unknown,
  endpoint: string,
  extra: { readonly ip?: string | undefined; readonly requestId?: string | undefined } = {},
): Promise<AuthoritativeContext> {
  const principal = await userResolver.resolve(credential);
  return {
    principal,
    userId: principal?.userId ?? null,
    endpoint,
    ip: extra.ip,
    requestId: extra.requestId,
  };
}

/**
 * Schemas for the operations the security engine mediates.
 *
 * Each is `.strict()` for the same reason the ticket payload is: an unexpected
 * field on a money-moving request is either a bug or an attempt to smuggle
 * something past a validator that only looks at fields it knows.
 */
export const reservationRequestSchema = z.strictObject({
  eventId: z.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/),
  seatIds: z.array(z.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/)).min(1).max(20),
  quantity: z.number().int().positive().max(20).optional(),
});

export const bookingRequestSchema = z.strictObject({
  reservationId: z.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/),
  paymentMethodId: z.string().min(1).max(256),
});

export const scanRequestSchema = z.strictObject({
  qr: z.string().min(1).max(8192),
  eventId: z.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/),
  scannerId: z.string().min(1).max(128).optional(),
});

export const queueJoinRequestSchema = z.strictObject({
  eventId: z.string().min(1).max(128).regex(/^[A-Za-z0-9_-]+$/),
  admissionToken: z.string().max(2048).optional(),
});

export type ReservationRequest = z.infer<typeof reservationRequestSchema>;
export type BookingRequest = z.infer<typeof bookingRequestSchema>;
export type ScanRequest = z.infer<typeof scanRequestSchema>;

/** Validate and convert a Zod failure into a public-safe SecurityError. */
export function parseOrThrow<T extends z.ZodTypeAny>(schema: T, value: unknown): z.infer<T> {
  const result = schema.safeParse(value);
  if (result.success) return result.data;

  const first = result.error.issues[0];
  // The field path is echoed to the client because it describes the client's own
  // input, not our internal state. The message is our own text, not a raw error.
  throw new SecurityError('VALIDATION_FAILED', `Request failed validation: ${first?.message ?? 'invalid'}`, {
    publicDetails: first?.path.length ? { field: first.path.join('.') } : undefined,
  });
}

/**
 * The full guard for a money-moving request: sanitize, validate, resolve identity.
 *
 * Order matters. Sanitizing first means the validator never sees a
 * client-supplied `userId` and cannot be tricked into accepting a body whose
 * authority fields are shaped to pass a loose schema.
 */
export async function guardProtectedRequest<T extends z.ZodTypeAny>(input: {
  readonly schema: T;
  readonly body: unknown;
  readonly credential: unknown;
  readonly endpoint: string;
  readonly userResolver: UserResolver;
  readonly ip?: string | undefined;
  readonly requireAuth?: boolean;
  readonly extraBlocked?: readonly string[];
}): Promise<{ readonly payload: z.infer<T>; readonly context: AuthoritativeContext; readonly stripped: readonly string[] }> {
  const { body, stripped } = sanitizeBody(input.body, { extraBlocked: input.extraBlocked });
  const payload = parseOrThrow(input.schema, body);
  const context = await buildAuthoritativeContext(input.userResolver, input.credential, input.endpoint, {
    ip: input.ip,
  });

  if (input.requireAuth !== false && context.principal === null) {
    throw new SecurityError('UNAUTHORIZED', `Authentication required for ${input.endpoint}`);
  }

  return { payload, context, stripped };
}
