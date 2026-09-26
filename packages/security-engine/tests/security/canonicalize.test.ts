import { describe, expect, it } from 'vitest';
import { canonicalizeJson, CanonicalizationError, canonicalEquals } from '../../src/core/canonicalize';

describe('canonicalizeJson', () => {
  it('produces identical output regardless of key insertion order', () => {
    const a = { ticketId: 'T1', eventId: 'E1', seatId: 'S1' };
    const b = { seatId: 'S1', eventId: 'E1', ticketId: 'T1' };
    expect(canonicalizeJson(a)).toBe(canonicalizeJson(b));
  });

  it('sorts keys lexicographically at every nesting depth', () => {
    const value = { b: { z: 1, a: 2 }, a: [{ d: 4, c: 3 }] };
    expect(canonicalizeJson(value)).toBe('{"a":[{"c":3,"d":4}],"b":{"a":2,"z":1}}');
  });

  it('emits no insignificant whitespace', () => {
    expect(canonicalizeJson({ a: 1, b: [1, 2] })).toBe('{"a":1,"b":[1,2]}');
  });

  it('omits undefined object values, treating them as absent rather than null', () => {
    expect(canonicalizeJson({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  it('encodes undefined array entries as null, matching JSON semantics', () => {
    expect(canonicalizeJson([1, undefined, 3])).toBe('[1,null,3]');
  });

  it('normalizes -0 to 0', () => {
    expect(canonicalizeJson({ v: -0 })).toBe('{"v":0}');
    expect(canonicalizeJson({ v: 0 })).toBe('{"v":0}');
  });

  it('distinguishes 0 from -0 nowhere in the output', () => {
    expect(canonicalEquals({ v: -0 }, { v: 0 })).toBe(true);
  });

  it('escapes strings per JSON spec', () => {
    expect(canonicalizeJson({ s: 'a"b\\c\nd' })).toBe('{"s":"a\\"b\\\\c\\nd"}');
  });

  it('preserves array order, which is semantically significant', () => {
    expect(canonicalizeJson([3, 1, 2])).toBe('[3,1,2]');
    expect(canonicalEquals([3, 1, 2], [1, 2, 3])).toBe(false);
  });

  it.each([
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
  ])('rejects %s rather than signing an unrepresentable value', (_label, value) => {
    expect(() => canonicalizeJson({ v: value })).toThrow(CanonicalizationError);
  });

  it('rejects Date objects, which serialize inconsistently across round trips', () => {
    expect(() => canonicalizeJson({ at: new Date() })).toThrow(CanonicalizationError);
  });

  it('rejects non-plain objects', () => {
    class Custom {
      value = 1;
    }
    expect(() => canonicalizeJson({ c: new Custom() })).toThrow(CanonicalizationError);
  });

  it('rejects BigInt and symbols', () => {
    expect(() => canonicalizeJson({ b: 1n })).toThrow(CanonicalizationError);
    expect(() => canonicalizeJson({ s: Symbol('x') })).toThrow(CanonicalizationError);
  });

  it('rejects unpaired surrogates, which are not valid UTF-8', () => {
    expect(() => canonicalizeJson({ s: '\uD800' })).toThrow(CanonicalizationError);
  });

  it('accepts null-prototype objects', () => {
    const value = Object.create(null) as Record<string, unknown>;
    value.a = 1;
    expect(canonicalizeJson(value)).toBe('{"a":1}');
  });

  it('handles deeply nested structures without stack issues at realistic depth', () => {
    let value: unknown = { leaf: true };
    for (let i = 0; i < 50; i += 1) value = { child: value };
    expect(() => canonicalizeJson(value)).not.toThrow();
  });
});
