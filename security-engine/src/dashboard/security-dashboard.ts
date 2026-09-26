/**
 * Part 12 — Security dashboard.
 *
 * ## Who this is for
 *
 * An operator answering one of three questions:
 *
 *   1. Is the system under attack right now?
 *   2. What happened during the sale that just ended?
 *   3. Why was this particular person challenged or rate limited?
 *
 * The queries here are shaped by those questions rather than by whatever the
 * tables happen to contain, and the indexes in the migration were chosen to match
 * (notably the partial index on high and critical severities, and the DESC index
 * on created_at that the recent-events query relies on).
 *
 * ## Aggregation is done in SQL, deliberately
 *
 * Counting in application code would pull every event row into memory to produce
 * a single number, which is fine at ten thousand rows and a denial of service at
 * ten million. The counts, rates and top-N lists are all computed by the database
 * and bounded by a window.
 *
 * ## Read-only and admin-gated
 *
 * This type exposes no write path at all, and `isAdmin` is checked before every
 * query rather than once at construction: a long-lived dashboard instance whose
 * authorisation changed must stop working immediately, not at the next restart.
 *
 * The dashboard reveals defensive posture and attack patterns, so it is gated
 * behind an explicit admin allow-list rather than a broad role that other parts of
 * the application also grant.
 */

import type { Pool } from 'pg';
import type { AdminAuthorizer, AuthenticatedPrincipal } from '../ports/user-resolver';
import { SecurityError } from '../core/errors';
import { SEVERITIES, type SecurityEventType, type SecuritySeverity } from '../telemetry/telemetry-sink';

export interface DashboardOptions {
  readonly pool: Pool;
  readonly authorizer: AdminAuthorizer;
  /** Hard ceiling on returned rows, so a dashboard call cannot dump a table. */
  readonly maxLimit?: number;
  readonly defaultLimit?: number;
  /** Injected so rate and window maths is testable without waiting. */
  readonly now?: () => Date;
}

/** One row of the recent-events feed. */
export interface RecentEvent {
  readonly id: string;
  readonly eventType: SecurityEventType;
  readonly severity: SecuritySeverity;
  readonly userId: string | null;
  readonly ipHash: string | null;
  readonly endpoint: string | null;
  readonly eventId: string | null;
  readonly metadata: Record<string, unknown>;
  readonly createdAt: string;
}

export interface EventCount {
  readonly eventType: SecurityEventType;
  readonly count: number;
}

export interface SeverityCount {
  readonly severity: SecuritySeverity;
  readonly count: number;
}

export interface TrendPoint {
  /** UTC hour bucket, ISO-8601. */
  readonly bucket: string;
  readonly count: number;
}

export interface DashboardSummary {
  readonly windowSeconds: number;
  readonly totalEvents: number;
  readonly byType: readonly EventCount[];
  readonly bySeverity: readonly SeverityCount[];
  readonly criticalCount: number;
  /** Events per minute across the window. */
  readonly eventsPerMinute: number;
  readonly trend: readonly TrendPoint[];
  readonly topUsers: readonly { readonly userId: string; readonly count: number }[];
  readonly topIps: readonly { readonly ipHash: string; readonly count: number }[];
  readonly generatedAt: string;
}

export interface SecurityDashboardQuery {
  readonly principal: AuthenticatedPrincipal | null;
  readonly windowSeconds?: number;
  readonly eventType?: SecurityEventType;
  readonly severity?: SecuritySeverity;
  readonly limit?: number;
}

const MAX_WINDOW_SECONDS = 7 * 24 * 60 * 60;

export class SecurityDashboard {
  readonly #pool: Pool;
  readonly #authorizer: AdminAuthorizer;
  readonly #maxLimit: number;
  readonly #defaultLimit: number;
  readonly #now: () => Date;

  constructor(options: DashboardOptions) {
    this.#pool = options.pool;
    this.#authorizer = options.authorizer;
    this.#maxLimit = options.maxLimit ?? 200;
    this.#defaultLimit = options.defaultLimit ?? 50;
    this.#now = options.now ?? (() => new Date());
  }

  #authorize(principal: AuthenticatedPrincipal | null): void {
    if (!this.#authorizer.isAdmin(principal)) {
      // 404 rather than 403 is a deliberate choice by the caller, not here: this
      // throws FORBIDDEN and the HTTP layer decides what to disclose.
      throw new SecurityError('FORBIDDEN', 'Security dashboard access denied');
    }
  }

  #clampLimit(limit: number | undefined): number {
    if (limit === undefined) return this.#defaultLimit;
    if (!Number.isInteger(limit) || limit < 1) {
      throw new SecurityError('VALIDATION_FAILED', 'limit must be a positive integer');
    }
    return Math.min(limit, this.#maxLimit);
  }

  #window(windowSeconds: number | undefined): number {
    if (windowSeconds === undefined) return 24 * 60 * 60;
    if (!Number.isInteger(windowSeconds) || windowSeconds < 1 || windowSeconds > MAX_WINDOW_SECONDS) {
      throw new SecurityError('VALIDATION_FAILED', `windowSeconds must be between 1 and ${MAX_WINDOW_SECONDS}`);
    }
    return windowSeconds;
  }

  /** Newest-first event feed, optionally filtered by type or severity. */
  async recentEvents(query: SecurityDashboardQuery): Promise<readonly RecentEvent[]> {
    this.#authorize(query.principal);
    const limit = this.#clampLimit(query.limit);

    const conditions = [`created_at > now() - ($1 || ' seconds')::interval`];
    const params: unknown[] = [String(this.#window(query.windowSeconds))];

    if (query.eventType) {
      params.push(query.eventType);
      conditions.push(`event_type = $${params.length}`);
    }
    if (query.severity) {
      params.push(query.severity);
      conditions.push(`severity = $${params.length}`);
    }
    params.push(limit);

    const { rows } = await this.#pool.query<{
      id: string;
      event_type: SecurityEventType;
      severity: SecuritySeverity;
      user_id: string | null;
      ip_hash: string | null;
      endpoint: string | null;
      event_id: string | null;
      metadata: Record<string, unknown>;
      created_at: Date;
    }>(
      `SELECT id, event_type, severity, user_id, ip_hash, endpoint, event_id, metadata, created_at
         FROM security_events
        WHERE ${conditions.join(' AND ')}
        ORDER BY created_at DESC
        LIMIT $${params.length}`,
      params,
    );

    return rows.map((row) => ({
      id: String(row.id),
      eventType: row.event_type,
      severity: row.severity,
      userId: row.user_id,
      ipHash: row.ip_hash,
      endpoint: row.endpoint,
      eventId: row.event_id,
      metadata: row.metadata,
      createdAt: row.created_at.toISOString(),
    }));
  }

  /**
   * Aggregate view over a window.
   *
   * One round trip for the whole summary: three independent aggregates are issued
   * concurrently rather than sequentially, because a dashboard that takes three
   * sequential query latencies is a dashboard nobody leaves open.
   */
  async summary(query: SecurityDashboardQuery): Promise<DashboardSummary> {
    this.#authorize(query.principal);
    const windowSeconds = this.#window(query.windowSeconds);
    // $1 rather than interpolation. The window is already validated, but a value
    // pasted into the statement text is a value that has to stay validated after
    // the next edit, and the parameter costs nothing.
    const since = `now() - ($1 || ' seconds')::interval`;
    const windowParam = [String(windowSeconds)];

    const [byType, bySeverity, critical, total, trend, topUsers, topIps] = await Promise.all([
      this.#pool.query<{ event_type: SecurityEventType; count: string }>(
        `SELECT event_type, count(*) AS count
           FROM security_events
          WHERE created_at > ${since}
          GROUP BY event_type
          ORDER BY count(*) DESC`,
        windowParam,
      ),
      this.#pool.query<{ severity: SecuritySeverity; count: string }>(
        `SELECT severity, count(*) AS count
           FROM security_events
          WHERE created_at > ${since}
          GROUP BY severity`,
        windowParam,
      ),
      this.#pool.query<{ count: string }>(
        `SELECT count(*) AS count FROM security_events
          WHERE created_at > ${since} AND severity = 'CRITICAL'`,
        windowParam,
      ),
      this.#pool.query<{ count: string }>(
        `SELECT count(*) AS count FROM security_events WHERE created_at > ${since}`,
        windowParam,
      ),
      this.#pool.query<{ bucket: Date; count: string }>(
        `SELECT date_trunc('hour', created_at) AS bucket, count(*) AS count
           FROM security_events
          WHERE created_at > ${since}
          GROUP BY bucket
          ORDER BY bucket`,
        windowParam,
      ),
      this.#pool.query<{ user_id: string; count: string }>(
        `SELECT user_id, count(*) AS count
           FROM security_events
          WHERE created_at > ${since} AND user_id IS NOT NULL
          GROUP BY user_id
          ORDER BY count(*) DESC
          LIMIT 10`,
        windowParam,
      ),
      this.#pool.query<{ ip_hash: string; count: string }>(
        `SELECT ip_hash, count(*) AS count
           FROM security_events
          WHERE created_at > ${since} AND ip_hash IS NOT NULL
          GROUP BY ip_hash
          ORDER BY count(*) DESC
          LIMIT 10`,
        windowParam,
      ),
    ]);

    const totalEvents = Number(total.rows[0]?.count ?? 0);

    // Every severity is reported, including the zeroes. A dashboard that omits
    // CRITICAL when the count is zero reads as "no data" rather than "none", which
    // is the wrong thing to show someone deciding whether they are under attack.
    const severityCounts = new Map(bySeverity.rows.map((r) => [r.severity, Number(r.count)]));
    const bySeverityFilled = SEVERITIES.map((severity) => ({
      severity,
      count: severityCounts.get(severity) ?? 0,
    }));

    return {
      windowSeconds,
      totalEvents,
      byType: byType.rows.map((r) => ({ eventType: r.event_type, count: Number(r.count) })),
      bySeverity: bySeverityFilled,
      criticalCount: Number(critical.rows[0]?.count ?? 0),
      eventsPerMinute: Math.round((totalEvents / windowSeconds) * 60 * 100) / 100,
      trend: trend.rows.map((r) => ({ bucket: r.bucket.toISOString(), count: Number(r.count) })),
      // Pseudonymous identifiers only: the dashboard shows correlation, never an
      // address or an account holder's identity beyond the internal user id.
      topUsers: topUsers.rows.map((r) => ({ userId: r.user_id, count: Number(r.count) })),
      topIps: topIps.rows.map((r) => ({ ipHash: r.ip_hash, count: Number(r.count) })),
      generatedAt: this.#now().toISOString(),
    };
  }

  /**
   * Everything one user or address triggered, newest first.
   *
   * This is the "why was this person challenged" query, and it is the reason the
   * dashboard can be read-only: investigation is a filter over the same event
   * stream, not a separate privileged capability.
   */
  async subjectHistory(
    query: SecurityDashboardQuery & { readonly userId?: string; readonly ipHash?: string },
  ): Promise<readonly RecentEvent[]> {
    this.#authorize(query.principal);
    if (!query.userId && !query.ipHash) {
      throw new SecurityError('VALIDATION_FAILED', 'subjectHistory requires a userId or an ipHash');
    }

    const conditions: string[] = [];
    const params: unknown[] = [];
    if (query.userId) {
      params.push(query.userId);
      conditions.push(`user_id = $${params.length}`);
    }
    if (query.ipHash) {
      params.push(query.ipHash);
      conditions.push(`ip_hash = $${params.length}`);
    }
    params.push(this.#clampLimit(query.limit));

    const { rows } = await this.#pool.query<{
      id: string;
      event_type: SecurityEventType;
      severity: SecuritySeverity;
      user_id: string | null;
      ip_hash: string | null;
      endpoint: string | null;
      event_id: string | null;
      metadata: Record<string, unknown>;
      created_at: Date;
    }>(
      `SELECT id, event_type, severity, user_id, ip_hash, endpoint, event_id, metadata, created_at
         FROM security_events
        WHERE ${conditions.join(' AND ')}
        ORDER BY created_at DESC
        LIMIT $${params.length}`,
      params,
    );

    return rows.map((row) => ({
      id: String(row.id),
      eventType: row.event_type,
      severity: row.severity,
      userId: row.user_id,
      ipHash: row.ip_hash,
      endpoint: row.endpoint,
      eventId: row.event_id,
      metadata: row.metadata,
      createdAt: row.created_at.toISOString(),
    }));
  }
}
