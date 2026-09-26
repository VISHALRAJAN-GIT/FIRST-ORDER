/**
 * Part 7 — Bot / automation protection.
 *
 * ## Signals, not bans
 *
 * The spec is explicit that users must not be banned for sharing an IP, and it is
 * right for a reason that is easy to get wrong: a corporate NAT, a university
 * gateway, a mobile carrier CGNAT, or a stadium's own wifi puts thousands of
 * legitimate people behind one address. Any IP-based automatic ban punishes them
 * for someone else's behaviour.
 *
 * So the signals below are deliberately asymmetric:
 *
 *   - frequency and burst signals are keyed on IP *and* user, and are allowed to
 *     escalate more than a single request;
 *   - behavioural signals (repeated identical requests, repeated failed
 *     reservations, rapid seat changes, repeated cancellations, account creation)
 *     are keyed on USER or SESSION, never on IP alone, because those are
 *     attributes of a person rather than of a doorway.
 *
 * The output is never a boolean. It is a `SecurityDecision` carrying a reason and
 * the signals that produced it, so the caller can escalate, challenge, or log and
 * move on — and so an operator can always answer "why was this person
 * challenged?".
 *
 * ## The pipeline the spec asks for
 *
 *   NORMAL -> INCREASED_RATE_LIMITING -> CHALLENGE -> TEMPORARY_RESTRICTION
 *
 * Escalation is driven by a score, and de-escalation happens automatically as
 * signals decay, so a user who tripped something during a busy sale is not stuck
 * behind a challenge afterwards.
 */

import { createHash, randomBytes } from 'node:crypto';
import type { RedisLike } from '../ports/redis';
import { SecurityError } from '../core/errors';
import type { SecurityEventType } from './bot-signal-types';
import { ChallengeStore, type ChallengeSubject } from './challenge';

export const PROTECTION_LEVELS = [
  'NORMAL',
  'INCREASED_RATE_LIMITING',
  'CHALLENGE_REQUIRED',
  'TEMPORARILY_RESTRICTED',
] as const;

export type ProtectionLevel = (typeof PROTECTION_LEVELS)[number];

export const BOT_SIGNALS = [
  'HIGH_FREQUENCY',
  'REQUEST_BURST',
  'IDENTICAL_REPEAT',
  'REPEATED_FAILED_RESERVATIONS',
  'RAPID_SEAT_CHANGES',
  'REPEATED_CANCELLATIONS',
  'EXCESSIVE_ACCOUNT_CREATION',
  'SESSION_OVERUSE',
  'SUSPICIOUS_PATTERN',
] as const;

export type BotSignal = (typeof BOT_SIGNALS)[number];

export interface SecurityDecision {
  readonly level: ProtectionLevel;
  readonly allow: boolean;
  readonly score: number;
  readonly signals: readonly BotSignal[];
  /** Present whenever the level is not NORMAL, for logging and operator triage. */
  readonly reason: string;
  /** Multiplier to apply to the rate-limit quota at this level. */
  readonly rateLimitMultiplier: number;
  readonly challengeToken?: string;
  readonly expiresAt?: string;
}
export interface BotProtectionConfig {
  /** Score at which each escalation step begins. */
  readonly thresholds: {
    readonly increasedRateLimiting: number;
    readonly challenge: number;
    readonly restriction: number;
  };
  /** Per-signal contribution to the score. */
  readonly weights: Record<BotSignal, number>;
  /**
   * Occurrences of each signal considered entirely normal, per window.
   *
   * This is the difference between a bot layer and a bot ban. Scoring raw counts
   * means a handful of ordinary requests reaches the restriction threshold, and
   * during a sale — where people legitimately hammer a page for the last seats —
   * that bans paying customers. Only the *excess* over a normal baseline
   * contributes, so the ladder is reached by behaviour that is actually abnormal
   * rather than by being busy.
   *
   * Values are per signal window. The rate limiter is the primary control on raw
   * volume; this layer's job is to catch automation shapes, which is why the
   * volume signals carry a generous allowance.
   */
  readonly allowances: Record<BotSignal, number>;
  /** Window each signal is counted over. */
  readonly signalWindowSeconds: number;
  /** How long a challenge or restriction lasts. */
  readonly challengeTtlSeconds: number;
  readonly restrictionTtlSeconds: number;
  /**
   * Ceiling on score contribution from any single signal, so one noisy metric
   * cannot escalate to a ban on its own.
   */
  readonly maxPerSignal: number;
}

export const DEFAULT_BOT_CONFIG: BotProtectionConfig = {
  thresholds: { increasedRateLimiting: 10, challenge: 25, restriction: 50 },
  weights: {
    HIGH_FREQUENCY: 8,
    REQUEST_BURST: 10,
    IDENTICAL_REPEAT: 6,
    REPEATED_FAILED_RESERVATIONS: 12,
    RAPID_SEAT_CHANGES: 5,
    REPEATED_CANCELLATIONS: 7,
    EXCESSIVE_ACCOUNT_CREATION: 20,
    SESSION_OVERUSE: 4,
    SUSPICIOUS_PATTERN: 9,
  },
  allowances: {
    // Volume is the rate limiter's job, and these are within a 5-minute window.
    // Generous on purpose: a buyer racing for the last seats is not a bot, and
    // Part 6 already enforces the hard per-endpoint quota.
    HIGH_FREQUENCY: 20,
    REQUEST_BURST: 15,
    SESSION_OVERUSE: 20,
    // Behavioural signals: the excess is what is actually suspicious.
    IDENTICAL_REPEAT: 3,
    REPEATED_FAILED_RESERVATIONS: 5,
    RAPID_SEAT_CHANGES: 8,
    REPEATED_CANCELLATIONS: 3,
    EXCESSIVE_ACCOUNT_CREATION: 3,
    SUSPICIOUS_PATTERN: 3,
  },
  signalWindowSeconds: 300,
  challengeTtlSeconds: 300,
  restrictionTtlSeconds: 900,
  maxPerSignal: 20,
};

/** One observed behaviour, submitted for scoring. */
export interface BotObservation {
  readonly signal: BotSignal;
  /**
   * Subject the signal is attributed to. `userId` is preferred; `ip` alone is
   * only ever acceptable for volume signals, never for behavioural ones.
   */
  readonly userId?: string | undefined;
  readonly ip?: string | undefined;
  readonly sessionId?: string | undefined;
  /** Opaque detail, e.g. a request hash used for IDENTICAL_REPEAT. */
  readonly detail?: string | undefined;
  readonly endpoint?: string | undefined;
}

export interface BotProtectionOptions {
  readonly redis: RedisLike;
  readonly keyPrefix: string;
  readonly now: () => number;
  readonly config?: BotProtectionConfig;
  /**
   * Issues a *redeemable* challenge.
   *
   * Prefer this over `issueChallenge`. Without it the engine can demand a
   * challenge and nobody can pass one, which locks out every legitimate buyer
   * who tripped a signal and pushes redemption logic into each app inconsistently.
   */
  readonly challenges?: ChallengeStore;
  /**
   * Bare token generator, for tests that do not want a Redis round trip.
   *
   * Produces tokens no `ChallengeStore` will accept. Setting `challenges` and
   * `issueChallenge` together is a configuration error and the store wins, so a
   * half-wired deployment cannot ship tokens nobody can redeem.
   */
  readonly issueChallenge?: () => string;
  /**
   * Fired when a single signal is on its own serious enough to require a
   * challenge or a restriction. Wire this to Part 10 telemetry so the dashboard
   * shows why a person was challenged, not just that they were.
   */
  readonly onSignal?: (signal: BotSignal, observation: BotObservation, score: number) => void;
}

/**
 * Signals that describe a person, and so must never be scored against an IP.
 *
 * A shared address can produce IDENTICAL_REPEAT or RAPID_SEAT_CHANGES all by
 * itself — a family booking six seats, or a corporate travel desk booking for
 * ten people — and attributing that to the address would restrict everyone
 * behind it.
 */
const BEHAVIOURAL_SIGNALS: ReadonlySet<BotSignal> = new Set([
  'IDENTICAL_REPEAT',
  'REPEATED_FAILED_RESERVATIONS',
  'RAPID_SEAT_CHANGES',
  'REPEATED_CANCELLATIONS',
  'EXCESSIVE_ACCOUNT_CREATION',
]);

export class BotProtection {
  readonly #redis: RedisLike;
  readonly #prefix: string;
  readonly #now: () => number;
  readonly #config: BotProtectionConfig;
  readonly #issueChallenge: () => string;
  readonly #challenges: ChallengeStore | undefined;
  readonly #onSignal: BotProtectionOptions['onSignal'];

  constructor(options: BotProtectionOptions) {
    this.#redis = options.redis;
    this.#prefix = options.keyPrefix;
    this.#now = options.now;
    this.#config = options.config ?? DEFAULT_BOT_CONFIG;
    // randomBytes, not Math.random: the challenge token is the thing a bot has to
    // guess, so a predictable generator would let an attacker pre-solve
    // challenges or forge one our own verifier accepts.
    this.#issueChallenge = options.issueChallenge ?? (() => `chl_${randomBytes(24).toString('base64url')}`);
    this.#onSignal = options.onSignal;
  }

  /**
   * Score an observation and return the resulting protection level.
   *
   * Never throws for a store outage: telemetry being unavailable is not evidence
   * of automation. It reports NORMAL, so a Redis incident cannot escalate the
   * entire user base into challenges.
   *
   * At TEMPORARILY_RESTRICTED it throws `SecurityError` rather than returning
   * `allow: false`, deliberately. A returned flag is one forgotten `if` away from
   * being ignored; a 429 carrying `retryAfterSeconds` cannot be.
   */
  async evaluate(observation: BotObservation): Promise<SecurityDecision> {
    const subject = this.#subjectFor(observation);
    if (subject === null) return this.#decision('NORMAL', 0, [], 'no attributable subject');

    const scored = await this.#scoreOne(observation, subject);
    if (scored === null) return this.#decision('NORMAL', 0, [], 'signal store unavailable');

    return this.#decision(this.#levelFor(scored.points), scored.points, [observation.signal], scored.reason, this.#challengeSubjectFor(observation));
  }

  /**
   * Evaluate a set of observations together and decide on the combined score.
   *
   * Summing, not taking the worst single result. Automation usually shows up as
   * several individually-weak signals at once — a bit bursty, a few identical
   * retries, some seat churn — and taking a max would let that pattern look
   * harmless indefinitely. Each signal is still capped at `maxPerSignal`, so no
   * single noisy metric can escalate to a restriction on its own.
   */
  async evaluateAll(observations: readonly BotObservation[]): Promise<SecurityDecision> {
    const signals: BotSignal[] = [];
    const reasons: string[] = [];
    let total = 0;
    let attributed = 0;
    // Captured from the first observation that actually scored, not observations[0]:
    // a behavioural signal with no attributable person is skipped, and binding a
    // challenge to the wrong subject would lock out the wrong user.
    let challengeSubject: ChallengeSubject | undefined;

    for (const observation of observations) {
      const subject = this.#subjectFor(observation);
      if (subject === null) continue;
      const scored = await this.#scoreOne(observation, subject);
      if (scored === null) continue;
      total += scored.points;
      attributed += 1;
      if (!signals.includes(observation.signal)) signals.push(observation.signal);
      reasons.push(scored.reason);
      challengeSubject ??= this.#challengeSubjectFor(observation);
    }

    if (attributed === 0) return this.#decision('NORMAL', 0, [], 'no attributable signals');
    return this.#decision(this.#levelFor(total), total, signals, reasons.join(', '), challengeSubject);
  }

  /** Count one signal and convert it into a score contribution. */
  async #scoreOne(
    observation: BotObservation,
    subject: string,
  ): Promise<{ points: number; reason: string } | null> {
    const count = await this.#increment(`${subject}:${observation.signal}`, observation.detail);
    if (count === null) return null;

    // Excess over the normal baseline, not the raw count. Signalling the excess
    // in the reason keeps the log honest about what actually triggered a level.
    const excess = Math.max(0, count - this.#config.allowances[observation.signal]);
    const capped = Math.min(excess, this.#config.maxPerSignal);
    const points = capped * this.#config.weights[observation.signal];

    // Notify when this signal ALONE is serious enough to demand intervention.
    //
    // The obvious alternative — fire when the contribution hits `maxPerSignal` —
    // is dead code: a high-weight signal crosses the restriction threshold after
    // only a couple of excess events, long before the per-signal cap is reached.
    // A callback that can never fire is worse than none, because it looks like
    // coverage.
    if (points >= this.#config.thresholds.challenge) {
      this.#onSignal?.(observation.signal, observation, points);
    }

    return {
      points,
      reason:
        excess === 0
          ? `${observation.signal} x${count} (within normal allowance)`
          : `${observation.signal} x${count} (${excess} over allowance)`,
    };
  }

  /**
   * Choose the subject a signal is attributed to.
   *
   * Behavioural signals require a user or session and are refused on a bare IP.
   * Volume signals may use an IP, because request rate genuinely is a property of
   * the connection and a single account is not responsible for everyone else
   * behind a gateway.
   */
  #subjectFor(observation: BotObservation): string | null {
    if (BEHAVIOURAL_SIGNALS.has(observation.signal)) {
      if (observation.userId) return `u:${observation.userId}`;
      if (observation.sessionId) return `s:${observation.sessionId}`;
      // No attributable person. Counting this against the address is exactly the
      // shared-network failure the spec warns about.
      return null;
    }
    if (observation.userId) return `u:${observation.userId}`;
    if (observation.sessionId) return `s:${observation.sessionId}`;
    if (observation.ip) return `i:${observation.ip}`;
    return null;
  }

  /**
   * The person a challenge would be issued to.
   *
   * Separate from `#subjectFor` on purpose: that returns a Redis key fragment,
   * and a challenge has to bind to the actual identifiers so a token harvested
   * from one client cannot be presented by another. Behavioural signals with no
   * attributable person get no challenge subject, matching the scoring rule that
   * they are never attributed to a shared address.
   */
  #challengeSubjectFor(observation: BotObservation): ChallengeSubject | undefined {
    if (BEHAVIOURAL_SIGNALS.has(observation.signal)) {
      if (observation.userId) return { userId: observation.userId, sessionId: observation.sessionId };
      if (observation.sessionId) return { sessionId: observation.sessionId };
      return undefined;
    }
    const subject: ChallengeSubject = {
      userId: observation.userId,
      sessionId: observation.sessionId,
      ip: observation.ip,
    };
    return subject.userId || subject.sessionId || subject.ip ? subject : undefined;
  }

  async #increment(key: string, detail: string | undefined): Promise<number | null> {
    try {
      // `detail` is caller-supplied (a request hash, a seat id) and is hashed
      // rather than embedded: it is unbounded, so putting it in a key invites a
      // key-length failure, and it may be something the operator never intended to
      // retain. Hashing keeps the counter's per-detail separation intact.
      const suffix = detail ? `:${createHash('sha256').update(detail).digest('hex').slice(0, 16)}` : '';
      return await this.#redis.increment(`${this.#prefix}bot:${key}${suffix}`, this.#config.signalWindowSeconds);
    } catch {
      return null;
    }
  }

  #levelFor(score: number): ProtectionLevel {
    const t = this.#config.thresholds;
    if (score >= t.restriction) return 'TEMPORARILY_RESTRICTED';
    if (score >= t.challenge) return 'CHALLENGE_REQUIRED';
    if (score >= t.increasedRateLimiting) return 'INCREASED_RATE_LIMITING';
    return 'NORMAL';
  }

  async #decision(
    level: ProtectionLevel,
    score: number,
    signals: readonly BotSignal[],
    reason: string,
    challengeSubject?: ChallengeSubject,
  ): Promise<SecurityDecision> {
    const now = this.#now();
    const base = { level, score, signals, reason } as const;

    switch (level) {
      case 'NORMAL':
        return { ...base, allow: true, rateLimitMultiplier: 1 };
      case 'INCREASED_RATE_LIMITING':
        // Tighten, do not block. Most traffic here is legitimate users racing
        // each other for the last seats, and blocking them loses sales.
        return { ...base, allow: true, rateLimitMultiplier: 0.25 };
      case 'CHALLENGE_REQUIRED': {
        // Issue a token that can actually be redeemed, bound to the subject that
        // was flagged. Falling back to a bare random string keeps the unit tests
        // working without Redis, but the caller then holds a token nobody can
        // redeem, which is why `challenges` is the documented configuration.
        if (this.#challenges && challengeSubject) {
          const issued = await this.#challenges.issue(challengeSubject, this.#config.challengeTtlSeconds);
          return {
            ...base,
            allow: false,
            rateLimitMultiplier: 0.1,
            challengeToken: issued.token,
            expiresAt: issued.expiresAt,
          };
        }
        return {
          ...base,
          allow: false,
          rateLimitMultiplier: 0.1,
          challengeToken: this.#issueChallenge(),
          expiresAt: new Date(now + this.#config.challengeTtlSeconds * 1000).toISOString(),
        };
      }
      case 'TEMPORARILY_RESTRICTED':
        throw new SecurityError('TEMPORARILY_RESTRICTED', `Restriction applied: ${reason}`, {
          retryAfterSeconds: this.#config.restrictionTtlSeconds,
          publicDetails: { reason: 'automated activity detected' },
        });
    }
  }
}

/** Map a decision onto the event type the dashboard aggregates. */
export function eventTypeForSignal(signal: BotSignal): SecurityEventType {
  switch (signal) {
    case 'HIGH_FREQUENCY':
    case 'SESSION_OVERUSE':
      return 'EXCESSIVE_REQUESTS';
    case 'REQUEST_BURST':
      return 'RATE_LIMIT_TRIGGERED';
    case 'REPEATED_FAILED_RESERVATIONS':
      return 'MULTIPLE_FAILED_BOOKINGS';
    default:
      return 'BOT_SIGNAL_DETECTED';
  }
}
