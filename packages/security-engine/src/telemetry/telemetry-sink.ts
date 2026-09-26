/**
 * Part 10 — Security events, and Part 11 — audit trail.
 *
 * ## Two records, deliberately not one
 *
 * They look similar and are kept apart on purpose:
 *
 *   SecurityEvent  high volume, short retention, feeds the dashboard and
 *                  alerting. "A rate limit fired." Signal, not evidence.
 *   AuditLog       lower volume, long retention, is the evidentiary record.
 *                  "Scanner 4 accepted ticket ABC at 18:32." Proof.
 *
 * Merging them would force one retention policy on two very different jobs, and
 * would mean either the dashboard is scanning an immutable evidence table or the
 * evidence table is full of noise that must be deleted to stay affordable.
 *
 * ## Privacy
 *
 * IP addresses are never stored. They are HMAC'd with a server-side secret, so
 * correlation ("these 400 requests share an address") still works while the
 * database leak does not become a location leak. The same applies to session
 * ids. The spec asks for `ipHash` for exactly this reason.
 *
 * `assertNoPii` is a runtime backstop, not decoration: metadata is assembled by
 * many different call sites and one of them will eventually pass an email
 * address.
 */

import { createHmac } from 'node:crypto';
import type { Pool } from 'pg';

/** The spec's enumerated event types, plus the ones the engine adds. */
export const SECURITY_EVENT_TYPES = [
  'RATE_LIMIT_TRIGGERED',
  'DUPLICATE_REQUEST',
  'INVALID_TICKET',
  'INVALID_SIGNATURE',
  'REPLAY_ATTEMPT',
  'QUEUE_BYPASS_ATTEMPT',
  'EXCESSIVE_REQUESTS',
  'MULTIPLE_FAILED_BOOKINGS',
  'TICKET_SCAN_REJECTED',
  'TICKET_SCAN_ACCEPTED',
  'BOT_SIGNAL_DETECTED',
  'CHALLENGE_ISSUED',
  'TEMPORARY_RESTRICTION',
  'IDEMPOTENCY_KEY_REUSE',
  'UNAUTHORIZED_ACCESS_ATTEMPT',
  'KEY_ROTATION',
] as const;

export type SecurityEventType = (typeof SECURITY_EVENT_TYPES)[number];

export const SEVERITIES = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as const;
export type SecuritySeverity = (typeof SEVERITIES)[number];

export const AUDIT_ACTIONS = [
  'TICKET_GENERATED',
  'TICKET_VERIFIED',
  'TICKET_REJECTED',
  'TICKET_SCANNED',
  'RESERVATION_CREATED',
  'RESERVATION_EXPIRED',
  'BOOKING_CREATED',
  'PAYMENT_VERIFIED',
  'CANCELLATION',
  'RATE_LIMIT_TRIGGERED',
  'QUEUE_JOINED',
  'QUEUE_ADMITTED',
  'QUEUE_LEFT',
  'SECURITY_EVENT',
  'IDEMPOTENT_REPLAY',
] as const;

export type AuditAction = (typeof AUDIT_ACTIONS)[number];

export const ACTOR_TYPES = ['USER', 'ADMIN', 'SYSTEM', 'SCANNER', 'ANONYMOUS'] as const;
export type ActorType = (typeof ACTOR_TYPES)[number];

/** Default severity per event type, so call sites cannot under-report by omission. */
const DEFAULT_SEVERITY: Record<SecurityEventType, SecuritySeverity> = {
  RATE_LIMIT_TRIGGERED: 'LOW',
  DUPLICATE_REQUEST: 'LOW',
  INVALID_TICKET: 'MEDIUM',
  INVALID_SIGNATURE: 'HIGH',
  REPLAY_ATTEMPT: 'HIGH',
  QUEUE_BYPASS_ATTEMPT: 'HIGH',
  EXCESSIVE_REQUESTS: 'MEDIUM',
  MULTIPLE_FAILED_BOOKINGS: 'MEDIUM',
  TICKET_SCAN_REJECTED: 'LOW',
  TICKET_SCAN_ACCEPTED: 'LOW',
  BOT_SIGNAL_DETECTED: 'MEDIUM',
  CHALLENGE_ISSUED: 'LOW',
  TEMPORARY_RESTRICTION: 'MEDIUM',
  IDEMPOTENCY_KEY_REUSE: 'LOW',
  UNAUTHORIZED_ACCESS_ATTEMPT: 'HIGH',
  KEY_ROTATION: 'MEDIUM',
};

/** Metadata keys that indicate the caller passed personal data through. */
const PII_KEY_PATTERN =
  /(^|_)(email|password|passwd|secret|token|authorization|cookie|phone|address|dob|ssn|card|cardnumber|cvv|name|fullname)($|_)/i;

export class PiiInMetadataError extends Error {
  constructor(public readonly key: string) {
    super(`Security event metadata must not contain personal data (offending key: ${key})`);
    this.name = 'PiiInMetadataError';
  }
}

/**
 * Reject personal data in metadata.
 *
 * Recursive because the whole object is serialised into the row. A top-level-only
 * check would wave through `metadata: { user: { email } }` and then store the
 * address, which defeats the point of hashing the IP column on the next column
 * over. Depth-bounded for the same reason the request sanitizer is: unbounded
 * recursion over attacker-influenced JSON is a stack-overflow vector.
 *
 * Throwing rather than stripping: silently dropping a field the caller believed
 * they were recording produces a log that is quietly wrong, and the caller never
 * learns. A loud failure is the point.
 */
export function assertNoPii(metadata: Record<string, unknown>, maxDepth = 8): void {
  const walk = (value: unknown, depth: number, path: string): void => {
    if (depth > maxDepth) {
      throw new PiiInMetadataError(`${path || '<root>'}.<too deeply nested>`);
    }
    if (value === null || typeof value !== 'object') return;

    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      const where = path ? `${path}.${key}` : key;
      if (PII_KEY_PATTERN.test(key)) throw new PiiInMetadataError(where);
      if (child !== null && typeof child === 'object') walk(child, depth + 1, where);
    }
  };

  walk(metadata, 0, '');
}

/** Pseudonymise an address or session id. Deterministic within a deployment. */
export function pseudonymize(value: string | undefined | null, secret: string): string | null {
  if (value === undefined || value === null || value === '') return null;
  return createHmac('sha256', secret).update(value).digest('hex').slice(0, 32);
}

export interface SecurityEventInput {
  readonly eventType: SecurityEventType;
  readonly userId?: string | undefined;
  readonly ip?: string | undefined;
  readonly endpoint?: string | undefined;
  readonly method?: string | undefined;
  readonly eventId?: string | undefined;
  readonly sessionId?: string | undefined;
  readonly metadata?: Record<string, unknown>;
  /** Overrides the type's default. Use when context makes an event worse. */
  readonly severity?: SecuritySeverity;
}

export interface SecurityEvent extends Required<Omit<SecurityEventInput, 'userId' | 'ip' | 'endpoint' | 'method' | 'eventId' | 'sessionId' | 'severity'>> {
  readonly id?: string;
  readonly userId: string | null;
  readonly ipHash: string | null;
  readonly endpoint: string | null;
  readonly method: string | null;
  readonly eventId: string | null;
  readonly sessionIdHash: string | null;
  readonly severity: SecuritySeverity;
  readonly createdAt: string;
}

export interface AuditLogInput {
  readonly action: AuditAction;
  readonly actorId?: string | undefined;
  readonly actorType?: ActorType;
  readonly targetType?: string | undefined;
  readonly targetId?: string | undefined;
  readonly eventId?: string | undefined;
  readonly ip?: string | undefined;
  readonly metadata?: Record<string, unknown>;
}

export interface AuditLog {
  readonly id?: string;
  readonly action: AuditAction;
  readonly actorId: string | null;
  readonly actorType: ActorType;
  readonly targetType: string | null;
  readonly targetId: string | null;
  readonly eventId: string | null;
  readonly ipHash: string | null;
  readonly metadata: Record<string, unknown>;
  readonly createdAt: string;
}

export interface TelemetryOptions {
  /** HMAC secret for pseudonymisation. Must be a real secret in production. */
  readonly hashSecret: string;
  readonly pool?: Pool;
  /**
   * When no pool is configured the sinks are no-ops that keep the in-memory
   * buffer. Lets the whole pipeline be exercised in unit tests without a
   * database, and keeps a telemetry failure from breaking a ticket scan.
   */
  readonly bufferLimit?: number;
}

/**
 * Emits security events and audit entries.
 *
 * ## Telemetry must never break the operation it describes
 *
 * A scan is not rejected because the audit insert failed. The scanner is
 * standing in front of a queue of people, and turning a database hiccup into a
 * "service unavailable" at the gate is a worse outcome than a gap in the log.
 * Every write is therefore best-effort, and the failure is reported to the
 * caller through `lastError` for the health endpoint rather than thrown.
 *
 * Ticket VERIFICATION is the deliberate exception and fails closed, because
 * admitting an unverified ticket is the harm this whole project exists to
 * prevent. That asymmetry is intentional and is enforced by the verifier, not
 * here.
 */
export class TelemetrySink {
  readonly #pool: Pool | undefined;
  readonly #hashSecret: string;
  readonly #bufferLimit: number;
  readonly #events: SecurityEvent[] = [];
  readonly #audit: AuditLog[] = [];
  #lastError: Error | null = null;

  constructor(options: TelemetryOptions) {
    this.#pool = options.pool;
    this.#hashSecret = options.hashSecret;
    this.#bufferLimit = options.bufferLimit ?? 1_000;
  }

  get lastError(): Error | null {
    return this.#lastError;
  }

  /** In-memory view, for tests and the dashboard when no database is attached. */
  recentEvents(limit = 50): SecurityEvent[] {
    return this.#events.slice(-limit).reverse();
  }

  recentAudit(limit = 50): AuditLog[] {
    return this.#audit.slice(-limit).reverse();
  }

  async recordEvent(input: SecurityEventInput): Promise<SecurityEvent> {
    assertNoPii(input.metadata ?? {});
    const severity = input.severity ?? DEFAULT_SEVERITY[input.eventType];
    const event: SecurityEvent = {
      eventType: input.eventType,
      severity,
      userId: input.userId ?? null,
      ipHash: pseudonymize(input.ip, this.#hashSecret),
      endpoint: input.endpoint ?? null,
      method: input.method ?? null,
      eventId: input.eventId ?? null,
      sessionIdHash: pseudonymize(input.sessionId, this.#hashSecret),
      metadata: input.metadata ?? {},
      createdAt: new Date().toISOString(),
    };

    this.#push(this.#events, event);
    await this.#write(
      `INSERT INTO security_events
         (event_type, severity, user_id, ip_hash, endpoint, method, event_id, session_id_hash, metadata)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [
        event.eventType,
        event.severity,
        event.userId,
        event.ipHash,
        event.endpoint,
        event.method,
        event.eventId,
        event.sessionIdHash,
        JSON.stringify(event.metadata),
      ],
    );
    return event;
  }

  async recordAudit(input: AuditLogInput): Promise<AuditLog> {
    assertNoPii(input.metadata ?? {});
    const entry: AuditLog = {
      action: input.action,
      actorId: input.actorId ?? null,
      actorType: input.actorType ?? 'ANONYMOUS',
      targetType: input.targetType ?? null,
      targetId: input.targetId ?? null,
      eventId: input.eventId ?? null,
      ipHash: pseudonymize(input.ip, this.#hashSecret),
      metadata: input.metadata ?? {},
      createdAt: new Date().toISOString(),
    };

    this.#push(this.#audit, entry);
    await this.#write(
      `INSERT INTO audit_logs
         (action, actor_id, actor_type, target_type, target_id, event_id, ip_hash, metadata)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [
        entry.action,
        entry.actorId,
        entry.actorType,
        entry.targetType,
        entry.targetId,
        entry.eventId,
        entry.ipHash,
        JSON.stringify(entry.metadata),
      ],
    );
    return entry;
  }

  /** Best-effort write. A telemetry outage is never propagated to the caller. */
  async #write(sql: string, params: unknown[]): Promise<void> {
    if (!this.#pool) return;
    try {
      await this.#pool.query(sql, params);
      this.#lastError = null;
    } catch (error) {
      this.#lastError = error instanceof Error ? error : new Error(String(error));
    }
  }

  #push<T>(buffer: T[], entry: T): void {
    buffer.push(entry);
    // Bounded, because an unbounded in-memory buffer is a memory-exhaustion
    // vector during exactly the incident it exists to record.
    if (buffer.length > this.#bufferLimit) buffer.splice(0, buffer.length - this.#bufferLimit);
  }
}

/** Convenience: record a scan outcome as both a security event and an audit row. */
export async function recordScan(
  sink: TelemetrySink,
  input: {
    readonly accepted: boolean;
    readonly outcome: string;
    readonly ticketId?: string | undefined;
    readonly eventId?: string | undefined;
    readonly scannerId?: string | undefined;
    readonly actorId?: string | undefined;
    readonly ip?: string | undefined;
    readonly signatureKid?: string | undefined;
  },
): Promise<void> {
  await sink.recordEvent({
    eventType: input.accepted ? 'TICKET_SCAN_ACCEPTED' : 'TICKET_SCAN_REJECTED',
    userId: input.actorId,
    ip: input.ip,
    eventId: input.eventId,
    // The reason is a closed enum, never a raw error message, so nothing
    // internal leaks into a row someone will later read in a dashboard.
    metadata: { outcome: input.outcome, scannerId: input.scannerId ?? null },
  });

  await sink.recordAudit({
    action: input.accepted ? 'TICKET_SCANNED' : 'TICKET_REJECTED',
    actorId: input.scannerId ?? input.actorId,
    actorType: input.scannerId ? 'SCANNER' : 'USER',
    targetType: 'TICKET',
    targetId: input.ticketId,
    eventId: input.eventId,
    ip: input.ip,
    metadata: { outcome: input.outcome, signatureKid: input.signatureKid ?? null },
  });
}
