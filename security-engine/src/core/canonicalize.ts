/**
 * Canonical JSON serialization.
 *
 * A digital signature is only meaningful if both signer and verifier derive the
 * exact same byte string from the same logical object. `JSON.stringify` does not
 * guarantee that: key order follows insertion order, and it throws or silently
 * mangles values we never want inside a signed structure (undefined, NaN,
 * Infinity, -0).
 *
 * So signatures are always computed over a *canonical* encoding produced here:
 *   - object keys sorted lexicographically by UTF-16 code unit
 *   - no insignificant whitespace
 *   - `undefined` object values omitted (they are absent, not null)
 *   - `undefined` array entries encoded as null (JSON has no other option)
 *   - non-finite numbers rejected outright
 *   - -0 normalized to 0
 *
 * Only JSON primitives are permitted inside signed payloads. Dates are encoded
 * as ISO-8601 strings by the caller, never as Date objects, because a Date
 * serializes differently depending on whether it survived a parse/stringify
 * round trip.
 */

/** Thrown when a value cannot be canonically encoded. */
export class CanonicalizationError extends Error {
  readonly path: string;

  constructor(message: string, path: string) {
    super(`${message} (at ${path || '<root>'})`);
    this.name = 'CanonicalizationError';
    this.path = path;
  }
}

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

function canonicalizeString(value: string, path: string): string {
  // Escaping is delegated to JSON.stringify, which is spec-correct and
  // deterministic for strings. Lone surrogates are rejected because they are
  // not valid UTF-8 and different runtimes encode them differently.
  if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value)) {
    throw new CanonicalizationError('String contains an unpaired surrogate', path);
  }
  return JSON.stringify(value);
}

function canonicalizeNumber(value: number, path: string): string {
  if (!Number.isFinite(value)) {
    throw new CanonicalizationError(`Non-finite number cannot be signed (${value})`, path);
  }
  // -0 and 0 are the same value but stringify differently.
  return JSON.stringify(value === 0 ? 0 : value);
}

function canonicalize(value: unknown, path: string): string {
  if (value === null) return 'null';

  switch (typeof value) {
    case 'string':
      return canonicalizeString(value, path);
    case 'number':
      return canonicalizeNumber(value, path);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'undefined':
      throw new CanonicalizationError('Undefined is not a canonical value', path);
    case 'bigint':
      throw new CanonicalizationError('BigInt is not a canonical value', path);
    case 'function':
    case 'symbol':
      throw new CanonicalizationError(`${typeof value} is not a canonical value`, path);
    default:
      break;
  }

  if (Array.isArray(value)) {
    // Array order is significant and is preserved. Holes and explicit undefined
    // both encode as null, matching JSON.stringify semantics.
    const items = value.map((item, index) =>
      item === undefined ? 'null' : canonicalize(item, `${path}[${index}]`),
    );
    return `[${items.join(',')}]`;
  }

  if (value instanceof Date) {
    throw new CanonicalizationError(
      'Date objects are not canonical; pass an ISO-8601 string instead',
      path,
    );
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new CanonicalizationError(
      `Only plain objects may be signed (received ${value?.constructor?.name ?? 'unknown'})`,
      path,
    );
  }

  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  const entries: string[] = [];
  for (const key of keys) {
    const child = record[key];
    if (child === undefined) continue; // absent, not null
    entries.push(`${canonicalizeString(key, path)}:${canonicalize(child, path ? `${path}.${key}` : key)}`);
  }
  return `{${entries.join(',')}}`;
}

/** Produce the canonical byte string that will be signed or hashed. */
export function canonicalizeJson(value: unknown): string {
  return canonicalize(value, '');
}

/** Deep structural equality using canonical encoding. */
export function canonicalEquals(a: unknown, b: unknown): boolean {
  try {
    return canonicalizeJson(a) === canonicalizeJson(b);
  } catch {
    return false;
  }
}
