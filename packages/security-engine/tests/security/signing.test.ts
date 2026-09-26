import { describe, expect, it } from 'vitest';
import { FakeClock } from '../../src/core/clock';
import { SecurityError } from '../../src/core/errors';
import { KeyRing, generateKeyPair, derivePublicKeyBase64, toPublicKeyObject } from '../../src/crypto/key-store';
import { TicketSigner } from '../../src/crypto/signer';
import { generateTestKeyPair, makeSigner, T0 } from '../helpers/fixtures';

describe('Ed25519 ticket signing', () => {
  it('signs and verifies a payload', () => {
    const clock = new FakeClock(T0);
    const { signer } = makeSigner(clock);
    const payload = { ticketId: 'T1', eventId: 'E1', seatId: 'S1', issuedAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-01-02T00:00:00.000Z', version: 1 };

    const { signature, kid } = signer.sign(payload);
    expect(signer.verify(payload, signature, kid)).toEqual({ valid: true, kid: 'test-key-1' });
  });

  it('produces a signature independent of the caller key ordering', () => {
    const clock = new FakeClock(T0);
    const { signer } = makeSigner(clock);
    const a = { ticketId: 'T1', eventId: 'E1', seatId: 'S1', issuedAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-01-02T00:00:00.000Z', version: 1 };
    const b = { version: 1, expiresAt: '2026-01-02T00:00:00.000Z', issuedAt: '2026-01-01T00:00:00.000Z', seatId: 'S1', eventId: 'E1', ticketId: 'T1' };

    // Ed25519 is deterministic, so reordered-but-identical input must yield a
    // byte-identical signature. This is the property that lets a verifier
    // re-derive the payload without knowing how the issuer built it.
    expect(signer.sign(a).signature).toBe(signer.sign(b).signature);
  });

  it('rejects a tampered field', () => {
    const clock = new FakeClock(T0);
    const { signer } = makeSigner(clock);
    const payload = { ticketId: 'T1', eventId: 'E1', seatId: 'S1', issuedAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-01-02T00:00:00.000Z', version: 1 };
    const { signature, kid } = signer.sign(payload);

    const tampered = { ...payload, seatId: 'S2' };
    const result = signer.verify(tampered, signature, kid);
    expect(result.valid).toBe(false);
  });

  it('rejects an added field', () => {
    const clock = new FakeClock(T0);
    const { signer } = makeSigner(clock);
    const payload = { ticketId: 'T1', eventId: 'E1', seatId: 'S1', issuedAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-01-02T00:00:00.000Z', version: 1 };
    const { signature, kid } = signer.sign(payload);

    // Privilege-escalation attempt: smuggle `role: ADMIN` into a signed claim.
    const escalated = { ...payload, role: 'ADMIN' };
    expect(signer.verify(escalated, signature, kid).valid).toBe(false);
  });

  it('rejects a signature from a different key', () => {
    const clock = new FakeClock(T0);
    const alice = makeSigner(clock);
    const mallory = makeSigner(clock, generateTestKeyPair('mallory-key'));
    const payload = { ticketId: 'T1', eventId: 'E1', seatId: 'S1', issuedAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-01-02T00:00:00.000Z', version: 1 };

    const forged = mallory.signer.sign(payload);
    expect(alice.signer.verify(payload, forged.signature, forged.kid).valid).toBe(false);
  });

  it('never throws on hostile input, returning a reason instead', () => {
    const clock = new FakeClock(T0);
    const { signer } = makeSigner(clock);

    // This sits on the public attack surface; an unhandled throw here is a DoS.
    expect(signer.verify({}, undefined, undefined).valid).toBe(false);
    expect(signer.verify({}, '', '').valid).toBe(false);
    expect(signer.verify({ a: 1 }, 'not-base64!!', 'k').valid).toBe(false);
    expect(signer.verify({ a: 1 }, 'AAAA', 'unknown-kid').valid).toBe(false);
    expect(signer.verify({ bad: Symbol('x') }, 'AAAA', 'test-key-1').valid).toBe(false);
  });

  it('rejects an implausibly short signature without invoking the verifier', () => {
    const clock = new FakeClock(T0);
    const { signer } = makeSigner(clock);
    expect(signer.verify({ a: 1 }, 'AA==', 'test-key-1')).toEqual({
      valid: false,
      reason: 'MALFORMED_ENVELOPE',
    });
  });

  it('refuses to sign a payload that is not canonically encodable', () => {
    const clock = new FakeClock(T0);
    const { signer } = makeSigner(clock);
    expect(() => signer.sign({ when: new Date() })).toThrow(SecurityError);
  });
});

describe('key rotation', () => {
  it('verifies tickets signed by a retired-but-not-yet-expired key after cutover', () => {
    const clock = new FakeClock(T0);
    const oldKey = generateTestKeyPair('key-1');
    const newKey = generateTestKeyPair('key-2');

    // Verifier knows both keys.
    const keyRing = new KeyRing(
      [
        { kid: 'key-1', publicKey: toPublicKeyObject(oldKey.publicKeyBase64), retireAt: undefined },
        { kid: 'key-2', publicKey: toPublicKeyObject(newKey.publicKeyBase64), retireAt: undefined },
      ],
      'key-1',
    );
    const issuer = new TicketSigner({ privateKeyBase64: oldKey.privateKeyBase64, keyRing, clock });

    const payload = { ticketId: 'T1', eventId: 'E1', seatId: 'S1', issuedAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-01-02T00:00:00.000Z', version: 1 };
    const oldSignature = issuer.sign(payload);
    expect(issuer.verify(payload, oldSignature.signature, 'key-1').valid).toBe(true);

    // Step 2: cut over to the new key. New tickets use key-2...
    keyRing.setActiveKey('key-2');
    expect(issuer.activeKeyId).toBe('key-2');

    // ...but a ticket already in a user's wallet still verifies under key-1.
    expect(issuer.verify(payload, oldSignature.signature, 'key-1').valid).toBe(true);
  });

  it('rejects a retired key once its retirement instant passes', () => {
    const clock = new FakeClock(T0);
    const keyPair = generateTestKeyPair('key-1');
    const retireAt = T0 + 60_000;

    const keyRing = new KeyRing(
      [{ kid: 'key-1', publicKey: toPublicKeyObject(keyPair.publicKeyBase64), retireAt }],
      'key-1',
    );
    const signer = new TicketSigner({ privateKeyBase64: keyPair.privateKeyBase64, keyRing, clock });
    const payload = { ticketId: 'T1', eventId: 'E1', seatId: 'S1', issuedAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-01-02T00:00:00.000Z', version: 1 };
    const { signature } = signer.sign(payload);

    expect(signer.verify(payload, signature, 'key-1').valid).toBe(true);

    clock.set(retireAt);
    expect(signer.verify(payload, signature, 'key-1')).toEqual({ valid: false, reason: 'RETIRED_KEY' });
  });

  it('reports an unknown kid distinctly from a retired one internally', () => {
    const clock = new FakeClock(T0);
    const { signer } = makeSigner(clock);
    const payload = { ticketId: 'T1', eventId: 'E1', seatId: 'S1', issuedAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-01-02T00:00:00.000Z', version: 1 };
    const { signature } = signer.sign(payload);

    expect(signer.verify(payload, signature, 'key-999')).toEqual({ valid: false, reason: 'UNKNOWN_KID' });
  });

  it('rotates a key at runtime via retire()', () => {
    const clock = new FakeClock(T0);
    const keyPair = generateTestKeyPair('key-1');
    const keyRing = new KeyRing(
      [{ kid: 'key-1', publicKey: toPublicKeyObject(keyPair.publicKeyBase64), retireAt: undefined }],
      'key-1',
    );
    const signer = new TicketSigner({ privateKeyBase64: keyPair.privateKeyBase64, keyRing, clock });
    const payload = { ticketId: 'T1', eventId: 'E1', seatId: 'S1', issuedAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-01-02T00:00:00.000Z', version: 1 };
    const { signature } = signer.sign(payload);

    keyRing.retire('key-1', T0 + 1000);
    clock.set(T0 + 999);
    expect(signer.verify(payload, signature, 'key-1').valid).toBe(true);
    clock.set(T0 + 1000);
    expect(signer.verify(payload, signature, 'key-1').valid).toBe(false);
  });
});

describe('key material handling', () => {
  it('derives the public key from the private key alone', () => {
    const pair = generateTestKeyPair();
    expect(derivePublicKeyBase64(pair.privateKeyBase64)).toBe(pair.publicKeyBase64);
  });

  it('emits a usable key pair from the generator', () => {
    const generated = generateKeyPair('key-9');
    expect(Buffer.from(generated.privateKeyBase64, 'base64')).toHaveLength(32);
    expect(Buffer.from(generated.publicKeyBase64, 'base64')).toHaveLength(32);

    const clock = new FakeClock(T0);
    const keyRing = new KeyRing(
      [{ kid: 'key-9', publicKey: toPublicKeyObject(generated.publicKeyBase64), retireAt: undefined }],
      'key-9',
    );
    const signer = new TicketSigner({ privateKeyBase64: generated.privateKeyBase64, keyRing, clock });
    const payload = { ticketId: 'T1', eventId: 'E1', seatId: 'S1', issuedAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-01-02T00:00:00.000Z', version: 1 };
    const { signature } = signer.sign(payload);
    expect(signer.verify(payload, signature, 'key-9').valid).toBe(true);
  });

  it('accepts PEM as well as base64 raw key material', () => {
    // Operators paste keys from secret managers that preserve PEM armour.
    const { generateKeyPairSync, createPublicKey, createPrivateKey } = require('node:crypto') as typeof import('node:crypto');
    const { privateKey, publicKey } = generateKeyPairSync('ed25519');
    const privatePem = (privateKey.export({ format: 'pem', type: 'pkcs8' }) as string).toString();
    const publicPem = (publicKey.export({ format: 'pem', type: 'spki' }) as string).toString();

    const keyRing = new KeyRing(
      [{ kid: 'pem-key', publicKey: createPublicKey(publicPem), retireAt: undefined }],
      'pem-key',
    );
    const clock = new FakeClock(T0);
    const signer = new TicketSigner({ privateKeyBase64: privatePem, keyRing, clock });
    const payload = { ticketId: 'T1', eventId: 'E1', seatId: 'S1', issuedAt: '2026-01-01T00:00:00.000Z', expiresAt: '2026-01-02T00:00:00.000Z', version: 1 };
    const { signature } = signer.sign(payload);
    expect(signer.verify(payload, signature, 'pem-key').valid).toBe(true);
  });

  it('rejects key material of the wrong length rather than silently mis-verifying', () => {
    expect(() => derivePublicKeyBase64(Buffer.from('too-short').toString('base64'))).toThrow(/32 raw bytes/);
  });
});
