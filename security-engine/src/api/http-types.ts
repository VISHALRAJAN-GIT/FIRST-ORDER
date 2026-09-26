/**
 * Transport-neutral request and response shapes.
 *
 * Part 13 is specified as "framework-neutral API handlers", and the practical
 * meaning of that is narrower than it sounds. It is not "no framework is
 * involved" - the host application will always have one - it is that this
 * package must not make a *choice* of framework, because Person 1's stack is not
 * fixed and a choice baked in here would be a choice they cannot undo without
 * forking the engine.
 *
 * So the boundary is deliberately dumb: plain data in, plain data out. A host
 * adapter (see `express-adapter.ts`) translates its own objects into these and
 * back. Anything richer - a `Request`, a `Response`, a context object, anything
 * with a lifecycle - would be a framework leaking in, and the first adapter
 * written would be the one that could not be replaced.
 */

export type HttpHeaderValue = string | string[] | undefined;
export type HttpHeaders = Readonly<Record<string, HttpHeaderValue>>;

export interface SecurityHttpRequest {
  /** Upper-case method, e.g. `POST`. */
  readonly method: string;
  /** Path only, no query string, e.g. `/api/queue/E_1/status`. */
  readonly path: string;
  readonly query?: Readonly<Record<string, string | string[] | undefined>>;
  readonly headers?: HttpHeaders;
  /** Already-parsed body. A raw string is rejected by the handlers, not coerced. */
  readonly body?: unknown;
  /** Client address, when the host can determine it. */
  readonly ip?: string | undefined;
  /**
   * The raw credential (session cookie, bearer token, whatever the host uses),
   * passed straight to `UserResolver`. The engine never parses it.
   */
  readonly credential?: unknown;
}

export interface SecurityHttpResponse {
  readonly status: number;
  /** Always lowercase keys. `content-type` is always present. */
  readonly headers: Readonly<Record<string, string>>;
  readonly body: unknown;
}

/** Case-insensitive single header read. Arrays collapse to the first value. */
export function headerValue(headers: HttpHeaders | undefined, name: string): string | undefined {
  if (!headers) return undefined;
  const wanted = name.toLowerCase();
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== wanted) continue;
    if (Array.isArray(value)) return value[0];
    return value;
  }
  return undefined;
}

/** First value of a query parameter, tolerating the `?a=1&a=2` shape. */
export function queryValue(
  query: Readonly<Record<string, string | string[] | undefined>> | undefined,
  name: string,
): string | undefined {
  if (!query) return undefined;
  const value = query[name];
  if (Array.isArray(value)) return value[0];
  return value;
}

export function jsonResponse(
  status: number,
  body: unknown,
  extraHeaders: Readonly<Record<string, string>> = {},
): SecurityHttpResponse {
  return {
    status,
    // `no-store` on every response, including successes. A cached 429 or a cached
    // verification result is a security problem: the first is a decision that has
    // since expired, the second can be replayed by a shared cache to someone who
    // was never verified.
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extraHeaders },
    body,
  };
}
