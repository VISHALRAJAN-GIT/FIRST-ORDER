import type { SecurityHttpRequest, SecurityHttpResponse } from './http-types';
import type { SecurityApi } from './security-api';

/**
 * Optional Express adapter.
 *
 * Structurally typed rather than importing from `express`, deliberately:
 *
 * - `express` is not a dependency of this package. Person 1 may be on Fastify,
 *   Hono, Koa or a bare `node:http` server, and a hard dependency would force
 *   that choice on them. Express installs this optional peer and gets the
 *   convenience; everyone else pays nothing.
 * - The structural types below are the whole surface used. They are assignable
 *   from Express's own `Request`/`Response` shapes, so no cast is needed at the
 *   call site, and an upgrade to Express 5 that changes a signature surfaces as a
 *   compile error here rather than as a runtime surprise.
 *
 * A host that is not on Express should not use this file at all - see
 * `docs/SECURITY_INTEGRATION.md`.
 */

/** The subset of an Express request this adapter reads. */
export interface ExpressLikeRequest {
  readonly method: string;
  readonly path: string;
  readonly query?: unknown;
  readonly headers?: Record<string, string | string[] | undefined>;
  readonly body?: unknown;
  readonly ip?: string | undefined;
  /** Set by the host's own session middleware before this adapter runs. */
  securityCredential?: unknown;
}

/** The subset of an Express response this adapter writes. */
export interface ExpressLikeResponse {
  status(code: number): ExpressLikeResponse;
  setHeader(name: string, value: string): unknown;
  json(body: unknown): unknown;
  /** Optional: only checked on the failure path. */
  readonly headersSent?: boolean;
}

export interface ExpressAdapterOptions {
  readonly api: SecurityApi;
  /**
   * Extract the raw credential from the request. The engine never parses
   * credentials, so the host must say which header or cookie carries it - that
   * decision belongs with the host's auth stack, not here.
   */
  readonly credentialFrom?: (request: ExpressLikeRequest) => unknown;
}

/**
 * Returns an Express handler for the whole security surface.
 *
 * Errors are not propagated: `SecurityApi.handle` never throws, so an `await`
 * here cannot miss a `try`/`catch`, and the adapter does not need one. It still
 * guards against an adapter-level fault - a serialisation failure in `res.json`,
 * say - by returning 500 rather than leaving the request hanging, which an
 * unhandled rejection in async Express 4 would do.
 */
export function securityMiddleware(options: ExpressAdapterOptions) {
  const { api, credentialFrom } = options;

  return async function securityHandler(
    request: ExpressLikeRequest,
    response: ExpressLikeResponse,
  ): Promise<void> {
    try {
      const result = await api.handle(toHttpRequest(request, credentialFrom));
      for (const [name, value] of Object.entries(result.headers)) {
        response.setHeader(name, value);
      }
      response.status(result.status).json(result.body);
    } catch {
      // Reaching here means the response is not a security verdict, so it must
      // not look like one either.
      if (!response.headersSent) {
        response
          .status(500)
          .json({ success: false, error: { code: 'INTERNAL_ERROR', message: 'Request could not be processed.' } });
      }
    }
  };
}

/** Translates an Express-shaped request into the transport-neutral one. */
export function toHttpRequest(
  request: ExpressLikeRequest,
  credentialFrom?: (request: ExpressLikeRequest) => unknown,
): SecurityHttpRequest {
  return {
    method: request.method,
    path: request.path,
    // Express 5 makes `req.query` a getter, so it is read once here rather than
    // being stored. Express 4's default `query` object is a null-prototype map,
    // which the handlers only read by key.
    query: normalizeQuery(request.query),
    headers: request.headers,
    body: request.body,
    ip: request.ip,
    credential: credentialFrom ? credentialFrom(request) : request.securityCredential,
  };
}

/** Copies an Express query bag into a plain object with a single value per key. */
function normalizeQuery(raw: unknown): Record<string, string | string[] | undefined> {
  if (raw === null || typeof raw !== 'object') return {};
  const out: Record<string, string | string[] | undefined> = {};
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    if (typeof value === 'string') {
      out[key] = value;
      continue;
    }
    if (Array.isArray(value) && value.every((v) => typeof v === 'string')) {
      out[key] = value as string[];
      continue;
    }
    // Anything else is a parser artefact (a nested object from qs's `allowDots`).
    // Dropped rather than stringified, so a crafted query cannot reach zod as
    // `"[object Object]"`.
  }
  return out;
}

export type { SecurityHttpResponse };
