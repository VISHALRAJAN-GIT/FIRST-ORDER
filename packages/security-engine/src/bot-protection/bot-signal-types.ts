/**
 * Shared types for the bot-protection layer.
 *
 * Kept in their own module so the event catalogue and the protection pipeline do
 * not import each other: telemetry records what happened, bot protection decides
 * what to do, and neither needs to know about the other's internals.
 */

export type { SecurityEventType } from '../telemetry/telemetry-sink';

/**
 * Severity hints for bot signals.
 *
 * Exported for the telemetry layer; the canonical per-event-type defaults live
 * in `telemetry-sink.ts` and take precedence when a caller does not override.
 */
export const DEFAULT_SEVERITIES = {
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
} as const;
