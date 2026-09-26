/**
 * Port: server-side identity resolution.
 *
 * This is the enforcement point for the spec's rule "never trust the client".
 * The security engine never reads a user id, role, or ownership flag from a
 * request body, query string, or header that the client can freely set. It asks
 * this port who the caller is, and uses only the answer.
 *
 * ## What NOT to implement
 *
 * A `UserResolver` that reads `x-user-id` from the request is not an
 * implementation, it is a vulnerability with an interface. Whoever writes the
 * adapter must derive identity from a credential the client cannot forge — a
 * verified session cookie, a JWT validated against the server's key or JWKS, or
 * mTLS. That is Person 1's responsibility, and it is stated here because the
 * security engine's guarantees are only as strong as this port.
 */

export const USER_ROLES = ['USER', 'SCANNER', 'ADMIN'] as const;
export type UserRole = (typeof USER_ROLES)[number];

export interface AuthenticatedPrincipal {
  readonly userId: string;
  readonly roles: readonly UserRole[];
  /** Session id when the caller has one, used for queue binding and bot signals. */
  readonly sessionId?: string;
  readonly email?: string;
}

/**
 * Fields a client must never be able to influence directly.
 *
 * The request sanitizer strips every one of these from inbound bodies before a
 * handler sees them, and derives the authoritative value server-side instead.
 */
export const CLIENT_CONTROLLED_FIELDS = [
  'userId',
  'user_id',
  'userID',
  'ownerId',
  'bookingOwner',
  'booking_owner',
  'price',
  'amount',
  'total',
  'totalAmount',
  'paymentStatus',
  'payment_status',
  'ticketStatus',
  'ticket_status',
  'role',
  'roles',
  'isAdmin',
  'is_admin',
  'admin',
  'seatPrice',
  'discount',
] as const;

export type ClientControlledField = (typeof CLIENT_CONTROLLED_FIELDS)[number];

/**
 * Resolve the caller from a verified credential.
 *
 * `credential` is the framework-level credential object (an Express `Request`,
 * a FastAPI `Request`, a Fetch `Request`) rather than a bare header bag, so the
 * adapter can read whatever its framework needs for signature or session
 * verification. Implementations MUST NOT treat client-supplied identity headers
 * as authoritative.
 */
export interface UserResolver {
  /**
   * Return the authenticated principal, or `null` when the request is anonymous.
   * Must not throw for anonymous callers — absence of a credential is a normal
   * state, not an error.
   */
  resolve(credential: unknown): Promise<AuthenticatedPrincipal | null>;

  /** True when the principal carries the admin role. */
  isAdmin?(principal: AuthenticatedPrincipal | null): boolean;
}

/** Authoritative user ids permitted to read the security dashboard. */
export interface AdminAuthorizer {
  isAdmin(principal: AuthenticatedPrincipal | null): boolean;
}

/**
 * Default authorizer driven by configuration (`SECURITY_ADMIN_USER_IDS`).
 *
 * Note this is an explicit allow-list rather than a role check. Admin access to
 * security telemetry is sensitive enough — it reveals defensive posture and
 * attack patterns — that it should not be inherited implicitly from a broad role
 * that other parts of the application also grant.
 */
export class ConfiguredAdminAuthorizer implements AdminAuthorizer {
  readonly #adminIds: ReadonlySet<string>;

  constructor(adminIds: ReadonlySet<string>) {
    this.#adminIds = adminIds;
  }

  isAdmin(principal: AuthenticatedPrincipal | null): boolean {
    if (!principal) return false;
    if (this.#adminIds.size > 0) return this.#adminIds.has(principal.userId);
    // No allow-list configured: fall back to an explicit ADMIN role, but only in
    // non-production, where `loadConfig` already refuses to start.
    return principal.roles.includes('ADMIN');
  }
}

/** Strip every client-controlled authority field from an object, in place. */
export function stripClientControlledFields<T extends Record<string, unknown>>(
  input: T,
  extraFields: readonly string[] = [],
): { sanitized: T; stripped: string[] } {
  const blocked = new Set<string>([...CLIENT_CONTROLLED_FIELDS, ...extraFields]);
  const stripped: string[] = [];

  for (const key of Object.keys(input)) {
    if (blocked.has(key)) {
      delete input[key];
      stripped.push(key);
    }
  }

  return { sanitized: input, stripped };
}
