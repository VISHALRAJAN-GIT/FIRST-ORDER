/**
 * Ed25519 key handling and the verification key ring.
 *
 * Two things this module exists to guarantee:
 *
 *  1. The private key never leaves the server. It is held in a closure, is not
 *     attached to any exported object, and `toJSON` on the store deliberately
 *     omits it so it cannot be serialized into a log line or an error report.
 *
 *  2. Rotation does not invalidate live tickets. Every signature carries a `kid`,
 *     and the verifier accepts any key in the ring whose retirement date has not
 *     passed. That means keys can be rotated on a schedule while tickets issued
 *     under the previous key keep working until they naturally expire.
 *
 * Keys are accepted as PEM, or as base64 of the 32-byte raw Ed25519 key. The raw
 * form is what `npm run keys:generate` emits, because it survives copy/paste
 * through environment variable UIs that mangle PEM armour.
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, KeyObject } from 'node:crypto';

/** PKCS#8 prefix for an Ed25519 private key carrying a raw 32-byte seed. */
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
/** SPKI prefix for an Ed25519 public key carrying a raw 32-byte point. */
const SPKI_ED25519_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

const ED25519_RAW_LENGTH = 32;

function isPem(value: string): boolean {
  return value.includes('-----BEGIN');
}

/** Build a KeyObject from a PEM string or from base64-encoded raw key material. */
function toPrivateKeyObject(material: string): KeyObject {
  if (isPem(material)) {
    return createPrivateKey(material);
  }
  let raw: Buffer;
  try {
    raw = Buffer.from(material, 'base64');
  } catch {
    throw new Error('Ticket signing private key is neither valid PEM nor base64');
  }
  if (raw.length !== ED25519_RAW_LENGTH) {
    throw new Error(
      `Ticket signing private key must be ${ED25519_RAW_LENGTH} raw bytes (base64) or a PEM Ed25519 key; received ${raw.length} bytes`,
    );
  }
  return createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, raw]),
    format: 'der',
    type: 'pkcs8',
  });
}

function toPublicKeyObject(material: string): KeyObject {
  if (isPem(material)) {
    return createPublicKey(material);
  }
  let raw: Buffer;
  try {
    raw = Buffer.from(material, 'base64');
  } catch {
    throw new Error('Ticket signing public key is neither valid PEM nor base64');
  }
  if (raw.length !== ED25519_RAW_LENGTH) {
    throw new Error(
      `Ticket signing public key must be ${ED25519_RAW_LENGTH} raw bytes (base64) or a PEM Ed25519 key; received ${raw.length} bytes`,
    );
  }
  return createPublicKey({
    key: Buffer.concat([SPKI_ED25519_PREFIX, raw]),
    format: 'der',
    type: 'spki',
  });
}

export interface VerificationKey {
  readonly kid: string;
  readonly publicKey: KeyObject;
  /**
   * Instant after which signatures from this key are rejected. `undefined` means
   * the key never retires on its own.
   */
  readonly retireAt: number | undefined;
}

export interface GeneratedKeyPair {
  readonly kid: string;
  /** base64 of the 32-byte seed. Server-side only. */
  readonly privateKeyBase64: string;
  /** base64 of the 32-byte public point. Safe to distribute to verifiers. */
  readonly publicKeyBase64: string;
  readonly createdAt: string;
}

/** Derive the base64 public key from a private key without needing both. */
export function derivePublicKeyBase64(privateKeyBase64: string): string {
  const privateKey = toPrivateKeyObject(privateKeyBase64);
  const publicKey = createPublicKey(privateKey);
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  return spki.subarray(SPKI_ED25519_PREFIX.length).toString('base64');
}

/** Generate a fresh signing key pair. Used by `npm run keys:generate`. */
export function generateKeyPair(kid: string): GeneratedKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const spki = publicKey.export({ format: 'der', type: 'spki' });
  return {
    kid,
    privateKeyBase64: (privateKey.export({ format: 'der', type: 'pkcs8' }) as Buffer)
      .subarray(PKCS8_ED25519_PREFIX.length)
      .toString('base64'),
    publicKeyBase64: spki.subarray(SPKI_ED25519_PREFIX.length).toString('base64'),
    createdAt: new Date().toISOString(),
  };
}

/**
 * The ring of keys accepted for verification.
 *
 * Signing uses exactly one active key. Verification accepts every key present,
 * which is what makes zero-downtime rotation possible.
 */
export class KeyRing {
  readonly #keys = new Map<string, VerificationKey>();
  #activeKid: string | undefined;

  constructor(keys: VerificationKey[] = [], activeKid?: string) {
    for (const key of keys) this.#keys.set(key.kid, Object.freeze(key));
    if (activeKid) this.#activeKid = activeKid;
  }

  static fromConfig(config: {
    readonly publicKey: string | undefined;
    readonly keyId: string;
    readonly trustedKeyIds: ReadonlySet<string>;
    readonly retireAt: number | undefined;
  }): KeyRing {
    if (!config.publicKey) {
      return new KeyRing([], config.keyId);
    }
    const publicKeyObject = toPublicKeyObject(config.publicKey);
    return new KeyRing(
      [
        {
          kid: config.keyId,
          publicKey: publicKeyObject,
          retireAt: config.retireAt,
        },
      ],
      config.keyId,
    );
  }

  /**
   * Add a key that is trusted for verification only. Used to load the outgoing
   * public key during a rotation so tickets signed before the cutover still pass.
   */
  addVerificationKey(kid: string, publicKeyMaterial: string, retireAt?: number): this {
    this.#keys.set(kid, Object.freeze({ kid, publicKey: toPublicKeyObject(publicKeyMaterial), retireAt }));
    return this;
  }

  /** Point signing at a different key without discarding the others. */
  setActiveKey(kid: string): this {
    this.#activeKid = kid;
    return this;
  }

  get activeKeyId(): string | undefined {
    return this.#activeKid;
  }

  has(kid: string): boolean {
    return this.#keys.has(kid);
  }

  get keyIds(): string[] {
    return [...this.#keys.keys()];
  }

  /**
   * Resolve a kid for verification.
   *
   * Returns a reason rather than throwing, because the caller must translate this
   * into the public `INVALID_SIGNATURE` outcome without disclosing whether the
   * kid was unknown, untrusted, or retired — all three are the same answer to an
   * attacker.
   */
  resolveForVerification(
    kid: string | undefined,
    now: number,
  ): { ok: true; key: VerificationKey } | { ok: false; reason: 'UNKNOWN_KID' | 'RETIRED' } {
    if (!kid) return { ok: false, reason: 'UNKNOWN_KID' };
    const key = this.#keys.get(kid);
    if (!key) return { ok: false, reason: 'UNKNOWN_KID' };
    if (key.retireAt !== undefined && now >= key.retireAt) {
      return { ok: false, reason: 'RETIRED' };
    }
    return { ok: true, key };
  }

  /** Explicitly retire a key at an instant, forcing its signatures to be rejected. */
  retire(kid: string, retireAt: number): this {
    const key = this.#keys.get(kid);
    if (!key) throw new Error(`Cannot retire unknown key id: ${kid}`);
    this.#keys.set(kid, Object.freeze({ ...key, retireAt }));
    return this;
  }
}

export { toPrivateKeyObject, toPublicKeyObject };
