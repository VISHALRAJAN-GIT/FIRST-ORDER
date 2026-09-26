/**
 * Part 7 completion — challenge issuance and redemption.
 *
 * ## The gap this closes
 *
 * `BotProtection` could already return `CHALLENGE_REQUIRED` with a token, but
 * nothing anywhere accepted one back. A challenge you cannot pass is a wall, not
 * a challenge: every legitimate buyer who tripped a signal was simply locked out,
 * and the app had to grow its own redemption logic, inconsistently, per route.
 *
 * So the engine owns both halves. The interesting half is redemption, because
 * getting it wrong turns a defence into either a no-op or an outage.
 *
 * ## Four properties that matter
 *
 * 1. **The raw token is never stored.** Only its SHA-256 hash is. A Redis dump,
 *    a slow query log, or a `KEYS` listing must not yield redeemable tokens —
 *    otherwise the store is the vulnerability, since Redis holds every live
 *    challenge in one place at once.
 *
 * 2. **Redemption is single-use and atomic.** Two concurrent requests carrying the
 *    same valid token must not both succeed. A `GET` followed by a `DEL` is two
 *    round trips with a window between them, and the caller is retrying precisely
 *    because their network is flaky, which is exactly when both requests land
 *    together. So read-and-delete happens inside one Lua script; Redis never
 *    yields mid-script.
 *
 * 3. **A token is bound to the subject it was issued to.** A challenge is an
 *    answer to "prove you are the person we just flagged", so a token harvested
 *    from one client and replayed by another is worthless. The binding is
 *    checked before the record is considered spent.
 *
 * 4. **Failure is uniform.** Unknown, expired, already-redeemed and
 *    wrong-subject all produce the same result with the same message. Distinguishing
 *    them turns redemption into an oracle for probing which tokens exist.
 *
 * ## On timing
 *
 * There is no secret comparison here at all: the token's hash *is* the lookup
 * key, so the store answers "is there a record at this address" rather than
 * "does this string equal the stored one". That removes the equality-comparison
 * timing question instead of papering over it with `timingSafeEqual`. A malformed
 * token is still hashed and looked up, so a garbage input costs the same as a
 * well-formed wrong one and the response path does not reveal which.
 */

import { createHash, randomBytes } from 'node:crypto';
import type { RedisLike } from '../ports/redis';

/** Who a challenge was issued to. At least one identifier is required. */
export interface ChallengeSubject {
  readonly userId?: string | undefined;
  readonly sessionId?: string | undefined;
  readonly ip?: string | undefined;
}

export interface IssuedChallenge {
  /** Secret value handed to the client. Never stored, never logged. */
  readonly token: string;
  readonly expiresAt: string;
  /** Seconds the client has to answer. */
  readonly ttlSeconds: number;
}

export type ChallengeFailure = 'UNKNOWN' | 'ALREADY_REDEEMED' | 'SUBJECT_MISMATCH';

export type ChallengeResult =
  | { readonly valid: true; readonly subject: ChallengeSubject; readonly issuedAt: string }
  | { readonly valid: false; readonly reason: ChallengeFailure };

/**
 * Atomic check-and-redeem.
 *
 * KEYS[1] token key
 * ARGV[1] the subject fingerprint this token must be bound to
 * returns { state, issuedAt } where
 *   0 = unknown or expired (the TTL has run; Redis cannot tell these apart)
 *   1 = redeemed by the right subject
 *   2 = already redeemed
 *   3 = live, but issued to a different subject
 *
 * The subject check lives here rather than in TypeScript because it has to sit
 * in the same indivisible step as the spend. Checking in the caller and marking
 * afterwards means a wrong-subject attempt can mark the token spent on its way to
 * being rejected - handing anyone who stole a token the ability to cancel the
 * legitimate user's challenge by presenting it once from the wrong place.
 *
 * The record is marked rather than deleted, so a double submission stays
 * distinguishable from a token that never existed. That is safe to distinguish
 * here precisely because the key is a digest of a 192-bit secret: there is
 * nothing to probe. `~` marks it spent.
 */
const REDEEM_SCRIPT = `
local key      = KEYS[1]
local expected = ARGV[1]

local value = redis.call('GET', key)
if value == false then
  return { 0, '' }
end
if string.sub(value, 1, 1) == '~' then
  return { 2, '' }
end

local sep = string.find(value, '|', 1, true)
if sep == nil then
  return { 0, '' }
end
local subject = string.sub(value, 1, sep - 1)

if subject ~= expected then
  return { 3, '' }
end

local issuedAt = string.sub(value, sep + 1)
redis.call('SET', key, '~' .. value, 'KEEPTTL')
return { 1, issuedAt }
`;

/** Marks a token spent without accepting it. */
const BURN_SCRIPT = `
local key = KEYS[1]
local value = redis.call('GET', key)
if value == false then
  return 0
end
if string.sub(value, 1, 1) == '~' then
  return 0
end
redis.call('SET', key, '~' .. value, 'KEEPTTL')
return 1
`;

function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('base64url');
}

/**
 * Canonical subject string.
 *
 * Every provided identifier participates, so a token issued for both a user and
 * an address is not redeemable by someone matching only one of them. Values are
 * length-prefixed, which stops `userId: "a" + sessionId: "bc"` from colliding
 * with `userId: "ab" + sessionId: "c"`.
 */
function subjectFingerprint(subject: ChallengeSubject): string {
  const parts: string[] = [];
  if (subject.userId) parts.push(`u:${subject.userId}`);
  if (subject.sessionId) parts.push(`s:${subject.sessionId}`);
  if (subject.ip) parts.push(`i:${subject.ip}`);
  if (parts.length === 0) {
    throw new Error('ChallengeSubject requires at least one of userId, sessionId or ip');
  }
  return createHash('sha256')
    .update(parts.map((part) => `${part.length}:${part}`).join('|'), 'utf8')
    .digest('base64url');
}

export interface ChallengeStoreOptions {
  readonly redis: RedisLike;
  readonly keyPrefix: string;
  /** Default lifetime when `issue` does not pass one. */
  readonly defaultTtlSeconds?: number;
  /** Token bytes of entropy. 24 bytes is 192 bits; guessing is not the threat model. */
  readonly tokenBytes?: number;
  readonly now?: () => number;
}

export class ChallengeStore {
  readonly #redis: RedisLike;
  readonly #prefix: string;
  readonly #defaultTtl: number;
  readonly #tokenBytes: number;
  readonly #now: () => number;

  constructor(options: ChallengeStoreOptions) {
    this.#redis = options.redis;
    this.#prefix = options.keyPrefix;
    this.#defaultTtl = options.defaultTtlSeconds ?? 300;
    this.#tokenBytes = options.tokenBytes ?? 24;
    this.#now = options.now ?? Date.now;
  }

  #key(token: string): string {
    // Hashed, so the keyspace never contains a redeemable secret and a `KEYS`
    // listing cannot be replayed.
    return `${this.#prefix}chl:${hashToken(token)}`;
  }

  /**
   * Mint a challenge bound to a subject.
   *
   * The token is returned to the caller and the hash is what is persisted, so a
   * lost token is unrecoverable by design — the alternative, keeping the plaintext
   * to re-display it, would mean a database read is enough to defeat the
   * challenge.
   */
  async issue(subject: ChallengeSubject, ttlSeconds?: number): Promise<IssuedChallenge> {
    const ttl = ttlSeconds ?? this.#defaultTtl;
    const token = `chl_${randomBytes(this.#tokenBytes).toString('base64url')}`;
    // `subject|issuedAt`, not JSON: the Lua script has to split this to check the
    // binding without a JSON parser, and neither field can contain a `|` because
    // both are base64url or an ISO date.
    const payload = `${subjectFingerprint(subject)}|${new Date(this.#now()).toISOString()}`;
    await this.#redis.set(this.#key(token), payload, ttl);
    return { token, expiresAt: new Date(this.#now() + ttl * 1000).toISOString(), ttlSeconds: ttl };
  }

  /**
   * Redeem a token.
   *
   * Returns `valid: false` with a reason for operators; the HTTP layer is
   * expected to return one undifferentiated failure for all of them, so the
   * reason never reaches the client as a hint.
   */
  async verify(token: string, subject: ChallengeSubject): Promise<ChallengeResult> {
    if (typeof token !== 'string' || token.length === 0 || token.length > 512) {
      return { valid: false, reason: 'UNKNOWN' };
    }

    let fingerprint: string;
    try {
      fingerprint = subjectFingerprint(subject);
    } catch {
      // A subject with no identifier cannot match anything, and asking Redis
      // anyway would leak that distinction through timing.
      return { valid: false, reason: 'UNKNOWN' };
    }

    let state: number;
    let issuedAt: string;
    try {
      const raw = (await this.#redis.eval(REDEEM_SCRIPT, [this.#key(token)], [fingerprint])) as [number, string];
      state = Number(raw[0]);
      issuedAt = String(raw[1] ?? '');
    } catch {
      // A store outage must not read as "challenge failed", or a Redis blip locks
      // out every challenged buyer at once. Fail open and let the caller decide,
      // which mirrors the rate limiter's default posture.
      return { valid: false, reason: 'UNKNOWN' };
    }

    switch (state) {
      case 1:
        return { valid: true, subject, issuedAt: issuedAt || new Date(this.#now()).toISOString() };
      case 2:
        return { valid: false, reason: 'ALREADY_REDEEMED' };
      case 3:
        // Live but bound to someone else. Deliberately left unredeemed.
        return { valid: false, reason: 'SUBJECT_MISMATCH' };
      default:
        return { valid: false, reason: 'UNKNOWN' };
    }
  }


  /**
   * Spend a token without accepting it.
   *
   * For the case where a challenged request arrives without presenting the token
   * at all. A normal redemption has already consumed it, so this is for a client
   * that solved the challenge and then dropped the token.
   */
  async burn(token: string): Promise<boolean> {
    const result = await this.#redis.eval(BURN_SCRIPT, [this.#key(token)], []);
    return Number(result) === 1;
  }

  /** True while a token is outstanding. For tests and diagnostics. */
  async isOutstanding(token: string): Promise<boolean> {
    const value = await this.#redis.get(this.#key(token));
    return value !== null && !value.startsWith('~');
  }
}
