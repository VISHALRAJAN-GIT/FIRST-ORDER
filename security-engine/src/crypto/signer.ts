/**
 * Ed25519 ticket signer.
 *
 * Signs a canonicalized ticket payload and verifies signatures against the key
 * ring. Verification is constant-shape: the function returns a boolean, never
 * throws on attacker-controlled input, and never reveals *why* verification
 * failed beyond a coarse internal reason.
 *
 * ## Key rotation strategy
 *
 * Rotation is a three-step operation with no downtime and no invalidation of
 * tickets that are still in a user's wallet:
 *
 *   1. **Prepare.** Generate a new key pair (`npm run keys:generate`). Add its
 *      PUBLIC key to the verifier's ring via `KeyRing.addVerificationKey` with a
 *      `retireAt` set to `now + max_ticket_ttl`. Old key stays active.
 *   2. **Cut over.** Call `KeyRing.setActiveKey(newKid)`. New signatures now use
 *      the new key. Verification still accepts both, so in-flight tickets are
 *      unaffected.
 *   3. **Retire.** Once no ticket signed with the old key can still be valid
 *      (i.e. past `old_retireAt`), remove the old public key. Verification of
 *      the old key now fails closed.
 *
 * `retireAt` must always be at least `TICKET_TTL_SECONDS` in the future at the
 * moment the key stops being used for signing. Setting it earlier retroactively
 * invalidates live tickets and locks out real users at the gate.
 */

import { createVerify, KeyObject, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { canonicalizeJson, CanonicalizationError } from '../core/canonicalize';
import { SecurityError } from '../core/errors';
import type { Clock } from '../core/clock';
import { KeyRing, toPrivateKeyObject } from './key-store';

/** Ed25519 signatures are always 64 bytes. No other length is valid. */
const ED25519_SIGNATURE_BYTES = 64;

/** Reason a signature check failed. Internal only — never returned to clients. */
export type SignatureFailureReason =
  | 'MALFORMED_ENVELOPE'
  | 'MISSING_SIGNATURE'
  | 'UNKNOWN_KID'
  | 'RETIRED_KEY'
  | 'SIGNATURE_MISMATCH'
  | 'CANONICALIZATION_FAILED'
  | 'KEY_UNAVAILABLE';

export type SignatureVerification =
  | { readonly valid: true; readonly kid: string }
  | { readonly valid: false; readonly reason: SignatureFailureReason };

export interface TicketSignerOptions {
  readonly privateKeyBase64: string;
  readonly keyRing: KeyRing;
  readonly clock: Clock;
}

export class TicketSigner {
  readonly #privateKey: KeyObject;
  readonly #keyRing: KeyRing;
  readonly #clock: Clock;

  constructor(options: TicketSignerOptions) {
    this.#privateKey = toPrivateKeyObject(options.privateKeyBase64);
    this.#keyRing = options.keyRing;
    this.#clock = options.clock;

    const active = this.#keyRing.activeKeyId;
    if (!active) {
      throw new SecurityError('INTERNAL_ERROR', 'KeyRing has no active signing key id');
    }
  }

  get keyRing(): KeyRing {
    return this.#keyRing;
  }

  get activeKeyId(): string {
    const kid = this.#keyRing.activeKeyId;
    if (!kid) throw new SecurityError('INTERNAL_ERROR', 'KeyRing has no active signing key id');
    return kid;
  }

  /**
   * Sign an arbitrary JSON payload.
   *
   * Returns base64 detached signature plus the canonical bytes that were signed.
   * The canonical bytes are returned so a caller (or a test) can prove exactly
   * what was covered by the signature, independent of key ordering at the call
   * site.
   */
  sign(payload: unknown): { signature: string; canonical: string; kid: string } {
    const kid = this.activeKeyId;
    let canonical: string;
    try {
      canonical = canonicalizeJson(payload);
    } catch (error) {
      if (error instanceof CanonicalizationError) {
        throw new SecurityError('VALIDATION_FAILED', `Ticket payload is not signable: ${error.message}`, {
          cause: error,
        });
      }
      throw error;
    }

    const signature = cryptoSign(null, Buffer.from(canonical, 'utf8'), this.#privateKey);
    return { signature: signature.toString('base64'), canonical, kid };
  }

  /**
   * Verify a detached signature against the key ring.
   *
   * Never throws. Any malformed input yields `{ valid: false }` rather than an
   * exception, because this function sits directly on the public attack surface
   * and an unhandled throw there is a denial-of-service vector.
   */
  verify(
    payload: unknown,
    signatureBase64: string | undefined,
    kid: string | undefined,
  ): SignatureVerification {
    if (typeof signatureBase64 !== 'string' || signatureBase64.length === 0) {
      return { valid: false, reason: 'MISSING_SIGNATURE' };
    }

    const resolved = this.#keyRing.resolveForVerification(kid, this.#clock.now());
    if (!resolved.ok) {
      return { valid: false, reason: resolved.reason === 'RETIRED' ? 'RETIRED_KEY' : 'UNKNOWN_KID' };
    }

    let canonical: string;
    try {
      canonical = canonicalizeJson(payload);
    } catch {
      return { valid: false, reason: 'CANONICALIZATION_FAILED' };
    }

    let signature: Buffer;
    try {
      signature = Buffer.from(signatureBase64, 'base64');
    } catch {
      return { valid: false, reason: 'MALFORMED_ENVELOPE' };
    }
    // An Ed25519 signature is always exactly 64 bytes. Enforcing that up front
    // rejects truncated, padded, or algorithm-confused input before the verifier
    // is invoked, and keeps every bad-signature path on one uniform answer.
    if (signature.length !== ED25519_SIGNATURE_BYTES) {
      return { valid: false, reason: 'MALFORMED_ENVELOPE' };
    }

    let ok = false;
    try {
      ok = cryptoVerify(null, Buffer.from(canonical, 'utf8'), resolved.key.publicKey, signature);
    } catch {
      // Malformed key material or signature encoding. Same answer as a mismatch.
      return { valid: false, reason: 'SIGNATURE_MISMATCH' };
    }

    return ok ? { valid: true, kid: resolved.key.kid } : { valid: false, reason: 'SIGNATURE_MISMATCH' };
  }
}

export { createVerify };
