import { beforeEach, describe, expect, it, vi } from 'vitest';

import { SecurityApi, listSecurityRoutes } from '../../src/api/security-api';
import type { QueuePort, TicketScanPort, TicketVerificationPort } from '../../src/api/security-api';
import type { SecurityHttpRequest, SecurityHttpResponse } from '../../src/api/http-types';
import { securityMiddleware, toHttpRequest } from '../../src/api/express-adapter';
import { FakeClock } from '../../src/core/clock';
import { ConfiguredAdminAuthorizer, type AuthenticatedPrincipal, type UserResolver } from '../../src/ports/user-resolver';
import { TelemetrySink, type SecurityEventInput } from '../../src/telemetry/telemetry-sink';
import type { VerificationResult } from '../../src/tickets/ticket-verifier';
import { makeSigner, T0 } from '../helpers/fixtures';

const EVENT_ID = 'EVT_001';
const BUYER: AuthenticatedPrincipal = { userId: 'U_BUYER', roles: ['USER'], sessionId: 'S_BUYER' };
const SCANNER: AuthenticatedPrincipal = { userId: 'U_GATE_7', roles: ['USER'], sessionId: 'S_GATE' };
const ADMIN: AuthenticatedPrincipal = { userId: 'U_ADMIN', roles: ['ADMIN'], sessionId: 'S_ADMIN' };

/* ------------------------------------------------------------------ doubles */

function accept(overrides: Partial<VerificationResult> = {}): VerificationResult {
  return {
    outcome: 'VALID',
    valid: true,
    kid: 'test-key-1',
    ticket: { ticketId: 'TCK_1', eventId: EVENT_ID, seatId: 'SEAT_A1', version: 1 },
    ...overrides,
  } as VerificationResult;
}

function reject(outcome: string): VerificationResult {
  return { outcome, valid: false } as VerificationResult;
}

class StubVerifier implements TicketVerificationPort {
  readonly calls: unknown[] = [];
  result: VerificationResult = accept();
  async verify(rawQr: unknown, options?: unknown): Promise<VerificationResult> {
    this.calls.push({ rawQr, options });
    return this.result;
  }
}

class StubScanner implements TicketScanPort {
  readonly calls: unknown[] = [];
  result: VerificationResult = accept();
  async scan(request: unknown): Promise<VerificationResult> {
    this.calls.push(request);
    return this.result;
  }
}

class StubQueue implements QueuePort {
  readonly joins: unknown[] = [];
  readonly leaves: unknown[] = [];
  readonly statuses: unknown[] = [];
  joinResult: { status: 'QUEUED' | 'ALREADY_QUEUED'; queueId: string; position: number } = {
    status: 'QUEUED',
    queueId: 'Q_1',
    position: 4,
  };
  leaveResult = true;
  async status(eventId: string, sessionId: string) {
    this.statuses.push({ eventId, sessionId });
    return { active: true, entry: { queueId: 'Q_1', position: 4 }, ahead: 3, size: 40, estimatedWaitSeconds: 120 };
  }
  async join(input: { eventId: string; sessionId: string; userId?: string | undefined }) {
    this.joins.push(input);
    return this.joinResult;
  }
  async leave(eventId: string, sessionId: string): Promise<boolean> {
    this.leaves.push({ eventId, sessionId });
    return this.leaveResult;
  }
}

class StubUsers implements UserResolver {
  constructor(private readonly byToken: ReadonlyMap<unknown, AuthenticatedPrincipal | null> = new Map()) {}
  async resolve(credential: unknown): Promise<AuthenticatedPrincipal | null> {
    return this.byToken.get(credential) ?? null;
  }
}

class CapturingTelemetry {
  readonly events: SecurityEventInput[] = [];
  constructor(private readonly fail = false) {}
  async recordEvent(input: SecurityEventInput) {
    this.events.push(input);
    if (this.fail) throw new Error('telemetry is down');
    return input as never;
  }
}

/* -------------------------------------------------------------------- setup */

function build(
  options: {
    users?: UserResolver;
    telemetry?: CapturingTelemetry;
    dashboard?: unknown;
    verifier?: StubVerifier;
    scanner?: StubScanner;
    queue?: StubQueue;
  } = {},
) {
  const verifier = options.verifier ?? new StubVerifier();
  const scanner = options.scanner ?? new StubScanner();
  const queue = options.queue ?? new StubQueue();
  const telemetry = options.telemetry ?? new CapturingTelemetry();
  const users =
    options.users ??
    new StubUsers(
      new Map<unknown, AuthenticatedPrincipal | null>([
        ['buyer', BUYER],
        ['scanner', SCANNER],
        ['admin', ADMIN],
        ['nosession', { userId: 'U_NOSESSION', roles: ['USER'] }],
        ['member', { userId: 'U_MEMBER', roles: ['USER'], sessionId: 'S_MEMBER' }],
      ]),
    );

  const api = new SecurityApi({
    verifier,
    replayGuard: scanner,
    queue,
    userResolver: users,
    authorizer: new ConfiguredAdminAuthorizer(new Set(['U_ADMIN'])),
    telemetry: telemetry as unknown as TelemetrySink,
    dashboard: options.dashboard as never,
  });

  return { api, verifier, scanner, queue, telemetry };
}

function req(
  method: string,
  path: string,
  extra: Partial<SecurityHttpRequest> = {},
): SecurityHttpRequest {
  return { method, path, ip: '203.0.113.7', ...extra };
}

const QR = 'data:text/plain;base64,UEFZ';

/* --------------------------------------------------------------------- tests */

describe('SecurityApi (Part 13)', () => {
  let ctx: ReturnType<typeof build>;

  beforeEach(() => {
    ctx = build();
  });

  describe('routing', () => {
    it('exposes exactly the seven specified routes', () => {
      expect(listSecurityRoutes().map((r) => `${r.method} ${r.path}`)).toEqual([
        'POST /api/tickets/verify',
        'POST /api/tickets/scan',
        'GET /api/security/status',
        'GET /api/security/events',
        'GET /api/queue/:eventId/status',
        'POST /api/queue/:eventId/join',
        'POST /api/queue/:eventId/leave',
      ]);
    });

    it('404s an unknown path', async () => {
      const res = await ctx.api.handle(req('GET', '/api/nope'));
      expect(res.status).toBe(404);
    });

    it('405s a known path with the wrong method, and says which', async () => {
      const res = await ctx.api.handle(req('GET', '/api/tickets/verify'));
      expect(res.status).toBe(405);
      expect(res.headers.allow).toBe('POST');
    });

    it('does not let a missing prefix change which route is reached', async () => {
      // A host that mounts under /v1 must still get the queue handler, not a 404.
      const res = await ctx.api.handle(req('GET', '/api/queue/EVT_001/status', { credential: 'buyer' }));
      expect(res.status).toBe(200);
    });

    it('normalizes a trailing slash and duplicate separators', async () => {
      const res = await ctx.api.handle(req('GET', '/api/queue//EVT_001/status/', { credential: 'buyer' }));
      expect(res.status).toBe(200);
      expect(ctx.queue.statuses[0]).toEqual({ eventId: 'EVT_001', sessionId: 'S_BUYER' });
    });
  });

  describe('ticket verification', () => {
    it('returns the outcome and the non-sensitive ticket block', async () => {
      const res = await ctx.api.handle(
        req('POST', '/api/tickets/verify', { body: { qr: QR, eventId: EVENT_ID } }),
      );
      expect(res.status).toBe(200);
      const body = res.body as { data: { outcome: string; ticket: Record<string, unknown> } };
      expect(body.data.outcome).toBe('VALID');
      // No userId, no pricing: a client logging this response leaks nothing.
      expect(Object.keys(body.data.ticket).sort()).toEqual(['eventId', 'seatId', 'ticketId', 'version']);
    });

    it('scopes verification to the claimed event', async () => {
      await ctx.api.handle(req('POST', '/api/tickets/verify', { body: { qr: QR, eventId: EVENT_ID } }));
      expect((ctx.verifier.calls[0] as { options: { expectedEventId: string } }).options.expectedEventId).toBe(EVENT_ID);
    });

    it('never consumes a ticket, because this route is a read', async () => {
      // The scanner port is what consumes. If verify started consuming, anyone
      // could burn a ticket by asking about it.
      await ctx.api.handle(req('POST', '/api/tickets/verify', { body: { qr: QR, eventId: EVENT_ID } }));
      expect(ctx.scanner.calls).toHaveLength(0);
    });

    it('maps each rejection outcome to a distinct status', async () => {
      const cases: Array<[string, number]> = [
        ['ALREADY_USED', 409],
        ['EXPIRED', 410],
        ['WRONG_EVENT', 403],
        ['TICKET_CLAIM_MISMATCH', 403],
        ['TICKET_NOT_FOUND', 404],
        ['SERVICE_UNAVAILABLE', 503],
        ['MALFORMED_QR', 422],
      ];
      for (const [outcome, status] of cases) {
        ctx.verifier.result = reject(outcome);
        const res = await ctx.api.handle(req('POST', '/api/tickets/verify', { body: { qr: QR, eventId: EVENT_ID } }));
        expect(res.status, outcome).toBe(status);
      }
    });

    it('never leaks an internal message or stack', async () => {
      ctx.verifier.result = reject('ALREADY_USED');
      const res = await ctx.api.handle(req('POST', '/api/tickets/verify', { body: { qr: QR, eventId: EVENT_ID } }));
      const serialized = JSON.stringify(res.body);
      expect(serialized).not.toMatch(/at \w+ \(|Error:|\.ts:\d+/);
      expect(res.body).toMatchObject({ success: false, error: { code: 'TICKET_ALREADY_USED' } });
    });
  });

  describe('request bodies', () => {
    it('rejects a raw string body instead of guessing at JSON', async () => {
      const res = await ctx.api.handle(req('POST', '/api/tickets/verify', { body: '{"qr":"x"}' }));
      expect(res.status).toBe(400);
      expect(ctx.verifier.calls).toHaveLength(0);
    });

    it('ignores a body that tries to set its own scannerId', async () => {
      // Stripped, not rejected: that is the sanitizer's contract. What matters is
      // that the scan is attributed to the credential, not to the request.
      const res = await ctx.api.handle(
        req('POST', '/api/tickets/scan', {
          credential: 'scanner',
          body: { qr: QR, eventId: EVENT_ID, scannerId: 'U_GATE_1' },
        }),
      );
      expect(res.status).toBe(200);
      expect(ctx.scanner.calls[0]).toMatchObject({ scannerId: 'U_GATE_7' });
      expect(JSON.stringify(ctx.scanner.calls[0])).not.toContain('U_GATE_1');
    });

    it('ignores client-controlled authority fields', async () => {
      // An attacker sending isAdmin must gain nothing. Stripping achieves that, so
      // the request proceeds as the anonymous caller it actually is.
      const res = await ctx.api.handle(
        req('POST', '/api/tickets/verify', { body: { qr: QR, eventId: EVENT_ID, isAdmin: true, role: 'ADMIN' } }),
      );
      expect(res.status).toBe(200);
      expect(JSON.stringify(ctx.verifier.calls[0])).not.toMatch(/isAdmin|ADMIN/);
    });

    it('ignores a client-supplied price rather than trusting it', async () => {
      await ctx.api.handle(
        req('POST', '/api/tickets/verify', { body: { qr: QR, eventId: EVENT_ID, price: 0, total: 0 } }),
      );
      expect(JSON.stringify(ctx.verifier.calls[0])).not.toMatch(/price|total/);
    });

    it('rejects a field that is neither stripped nor allowed', async () => {
      // Strict, so a typo or an attempt at an unimplemented field is a visible 400
      // rather than a silently ignored value.
      const res = await ctx.api.handle(
        req('POST', '/api/tickets/verify', { body: { qr: QR, eventId: EVENT_ID, expectedEventId: 'EVT_OTHER' } }),
      );
      expect(res.status).toBe(400);
    });

    it('requires a body at all', async () => {
      expect((await ctx.api.handle(req('POST', '/api/tickets/verify'))).status).toBe(400);
    });
  });

  describe('scanning', () => {
    it('derives the scanner from the credential, not the request', async () => {
      const res = await ctx.api.handle(
        req('POST', '/api/tickets/scan', { credential: 'scanner', body: { qr: QR, eventId: EVENT_ID } }),
      );
      expect(res.status).toBe(200);
      expect(ctx.scanner.calls[0]).toMatchObject({ scannerId: 'U_GATE_7', actorId: 'U_GATE_7' });
    });

    it('401s an anonymous scan', async () => {
      const res = await ctx.api.handle(req('POST', '/api/tickets/scan', { body: { qr: QR, eventId: EVENT_ID } }));
      expect(res.status).toBe(401);
      expect(ctx.scanner.calls).toHaveLength(0);
    });

    it('records an accepted scan', async () => {
      await ctx.api.handle(req('POST', '/api/tickets/scan', { credential: 'scanner', body: { qr: QR, eventId: EVENT_ID } }));
      expect(ctx.telemetry.events.map((e) => e.eventType)).toContain('TICKET_SCAN_ACCEPTED');
    });

    it('records a rejected scan with its outcome', async () => {
      ctx.scanner.result = reject('REPLAY_ATTEMPT');
      const res = await ctx.api.handle(
        req('POST', '/api/tickets/scan', { credential: 'scanner', body: { qr: QR, eventId: EVENT_ID } }),
      );
      expect(res.status).toBe(422);
      expect(ctx.telemetry.events).toContainEqual(
        expect.objectContaining({ eventType: 'TICKET_SCAN_REJECTED', metadata: expect.objectContaining({ outcome: 'REPLAY_ATTEMPT' }) }),
      );
    });
  });

  describe('admin surface', () => {
    it('403s a non-admin on the dashboard', async () => {
      const res = await ctx.api.handle(req('GET', '/api/security/status', { credential: 'member' }));
      expect(res.status).toBe(403);
      expect(res.body).toMatchObject({ error: { code: 'FORBIDDEN' } });
    });

    it('401s an anonymous caller, which is a different answer from 403', async () => {
      const res = await ctx.api.handle(req('GET', '/api/security/status'));
      expect(res.status).toBe(401);
    });

    it('records the unauthorized attempt', async () => {
      await ctx.api.handle(req('GET', '/api/security/events', { credential: 'member' }));
      expect(ctx.telemetry.events).toContainEqual(
        expect.objectContaining({ eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT', severity: 'MEDIUM' }),
      );
    });

    it('never reaches the dashboard for a non-admin', async () => {
      const summary = vi.fn();
      ctx = build({ dashboard: { summary, recentEvents: vi.fn() } });
      await ctx.api.handle(req('GET', '/api/security/status', { credential: 'member' }));
      expect(summary).not.toHaveBeenCalled();
    });

    it('501s rather than crashing when no dashboard is configured', async () => {
      const res = await ctx.api.handle(req('GET', '/api/security/status', { credential: 'admin' }));
      expect(res.status).toBe(501);
    });

    it('serves the summary to an admin', async () => {
      const summary = vi.fn().mockResolvedValue({ total: 4 });
      ctx = build({ dashboard: { summary, recentEvents: vi.fn() } });
      const res = await ctx.api.handle(req('GET', '/api/security/status', { credential: 'admin' }));
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ data: { total: 4 } });
    });

    it('validates the events query instead of forwarding junk', async () => {
      const recentEvents = vi.fn().mockResolvedValue([]);
      ctx = build({ dashboard: { summary: vi.fn(), recentEvents } });
      const bad = await ctx.api.handle(
        req('GET', '/api/security/events', { credential: 'admin', query: { limit: '99999' } }),
      );
      expect(bad.status).toBe(400);
      expect(recentEvents).not.toHaveBeenCalled();
    });

    it('ignores an unrelated query key rather than forwarding it', async () => {
      const recentEvents = vi.fn().mockResolvedValue([]);
      ctx = build({ dashboard: { summary: vi.fn(), recentEvents } });
      const res = await ctx.api.handle(
        req('GET', '/api/security/events', { credential: 'admin', query: { limit: '10', sql: 'DROP TABLE' } }),
      );
      expect(res.status).toBe(200);
      expect(Object.keys(recentEvents.mock.calls[0]?.[0] ?? {})).not.toContain('sql');
    });
  });

  describe('queue', () => {
    it('joins on behalf of the session, not a supplied id', async () => {
      const res = await ctx.api.handle(req('POST', '/api/queue/EVT_001/join', { credential: 'buyer' }));
      expect(res.status).toBe(200);
      expect(ctx.queue.joins[0]).toEqual({ eventId: 'EVT_001', sessionId: 'S_BUYER', userId: 'U_BUYER' });
    });

    it('reports a re-join as success, not a conflict', async () => {
      ctx.queue.joinResult = { status: 'ALREADY_QUEUED', queueId: 'Q_1', position: 4 };
      const res = await ctx.api.handle(req('POST', '/api/queue/EVT_001/join', { credential: 'buyer' }));
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ data: { status: 'ALREADY_QUEUED' } });
    });

    it('rejects a principal with no session, because a queue entry needs one', async () => {
      const res = await ctx.api.handle(req('POST', '/api/queue/EVT_001/join', { credential: 'nosession' }));
      expect(res.status).toBe(400);
      expect(ctx.queue.joins).toHaveLength(0);
    });

    it('401s an anonymous queue join', async () => {
      expect((await ctx.api.handle(req('POST', '/api/queue/EVT_001/join'))).status).toBe(401);
    });

    it('rejects a path eventId that is not a plain identifier', async () => {
      for (const bad of ['..', 'E%2FVT', 'EVT 001']) {
        const res = await ctx.api.handle(req('POST', `/api/queue/${bad}/join`, { credential: 'buyer' }));
        expect(res.status, bad).toBe(400);
      }
      expect(ctx.queue.joins).toHaveLength(0);
    });

    it('treats leaving a queue you are not in as a success', async () => {
      ctx.queue.leaveResult = false;
      const res = await ctx.api.handle(req('POST', '/api/queue/EVT_001/leave', { credential: 'buyer' }));
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ data: { left: false } });
    });

    it('serves status for the caller own session', async () => {
      const res = await ctx.api.handle(req('GET', '/api/queue/EVT_001/status', { credential: 'buyer' }));
      expect(res.status).toBe(200);
      expect(res.body).toMatchObject({ data: { eventId: 'EVT_001', ahead: 3, size: 40 } });
    });
  });

  describe('resilience', () => {
    it('returns 500 rather than throwing when a handler faults', async () => {
      const queue = new StubQueue();
      queue.status = async () => {
        throw new TypeError('cannot read property of undefined');
      };
      ctx = build({ queue });
      const res = await ctx.api.handle(req('GET', '/api/queue/EVT_001/status', { credential: 'buyer' }));
      expect(res.status).toBe(500);
      expect(JSON.stringify(res.body)).not.toMatch(/cannot read property|TypeError/);
    });

    it('still answers when telemetry is broken', async () => {
      ctx = build({ telemetry: new CapturingTelemetry(true) });
      const res = await ctx.api.handle(
        req('POST', '/api/tickets/scan', { credential: 'scanner', body: { qr: QR, eventId: EVENT_ID } }),
      );
      // A telemetry outage must not turn a valid scan into a failure.
      expect(res.status).toBe(200);
    });

    it('marks every response no-store', async () => {
      const res = await ctx.api.handle(req('POST', '/api/tickets/verify', { body: { qr: QR, eventId: EVENT_ID } }));
      expect(res.headers['cache-control']).toBe('no-store');
    });
  });
});

describe('Express adapter (Part 13)', () => {
  it('translates and writes status, headers and body', async () => {
    const api = new SecurityApi({
      verifier: new StubVerifier(),
      replayGuard: new StubScanner(),
      queue: new StubQueue(),
      userResolver: new StubUsers(),
      authorizer: new ConfiguredAdminAuthorizer(new Set()),
    });
    const response = { statusCode: 0, headers: {} as Record<string, string>, body: undefined as unknown };
    const handler = securityMiddleware({ api });

    await handler(
      { method: 'POST', path: '/api/tickets/verify', body: { qr: QR, eventId: EVENT_ID }, headers: {}, ip: '1.2.3.4' },
      {
        status(code: number) {
          response.statusCode = code;
          return this;
        },
        setHeader(name: string, value: string) {
          response.headers[name] = value;
        },
        json(body: unknown) {
          response.body = body;
          return this;
        },
      },
    );

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type'] ?? '').toContain('application/json');
    expect(response.body).toMatchObject({ success: true });
  });

  it('reads the credential from the host extractor when given one', async () => {
    const http = toHttpRequest(
      { method: 'GET', path: '/api/queue/EVT_001/status', headers: { authorization: 'Bearer tok' } },
      (request) => request.headers?.authorization,
    );
    expect(http.credential).toBe('Bearer tok');
  });

  it('drops a non-string query value rather than stringifying it', () => {
    // qs with allowDots can produce an object here; "[object Object]" must not
    // reach the validator.
    const http = toHttpRequest({ method: 'GET', path: '/x', query: { a: { b: 1 }, c: '2' } });
    expect(http.query).toEqual({ c: '2' });
  });
});
