/**
 * Part 5 — Idempotency / duplicate request protection.
 *
 * Wraps a state-changing handler so that a repeated `Idempotency-Key` returns
 * the original outcome instead of performing the operation twice.
 *
 * ## What this protects against
 *
 * Double clicks, client retries, mobile network re-sends, and deliberate
 * duplicate submissions. The first three are ordinary operational noise; the
 * fourth is an attack. All four produce the same shape — the same logical
 * request arriving more than once — and all four are handled by the same
 * mechanism.
 *
 * ## The three outcomes, and why they differ
 *
 *   - First use          -> execute the handler, store the result, return it.
 *   - Same key, same body, still running -> 409, do NOT execute. A concurrent
 *     worker owns this operation; running it too would double-book.
 *   - Same key, different body -> 422. The client has a bug. Replaying the first
 *     response would report success for a booking that was never made, and
 *     executing would be wrong too, so neither is an option.
 *   - Same key, same body, already finished -> replay the stored response
 *     verbatim, including its status code.
 *
 * ## Fails closed
 *
 * If the idempotency store is unreachable, the operation is refused. The
 * alternative — proceeding without a claim — means the exact double-execution
 * this layer exists to prevent, silently, during an incident.
 */

import { SecurityError } from '../core/errors';
import {
  fingerprintRequest,
  type IdempotencyStore,
  type IdempotentResponse,
} from '../ports/idempotency-store';

export interface IdempotencyConfig {
  /** How long a key is retained. Long enough to outlive any sane client retry. */
  readonly ttlSeconds: number;
  /**
   * Endpoints that require the header. A missing key on a protected endpoint is
   * an error rather than a silent pass-through.
   */
  readonly requiredFor: readonly string[];
}

export const DEFAULT_IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60;

export interface IdempotencyContext {
  readonly method: string;
  readonly path: string;
  readonly idempotencyKey: string | undefined;
  readonly body: unknown;
  readonly authenticatedUserId?: string | undefined;
}

export type IdempotencyOutcome =
  | { readonly kind: 'EXECUTED'; readonly response: IdempotentResponse }
  | { readonly kind: 'REPLAYED'; readonly response: IdempotentResponse }
  | { readonly kind: 'IN_FLIGHT' }
  | { readonly kind: 'CONFLICT' };

/** Upper bound on a client-supplied key, to keep Redis keys bounded. */
const MAX_KEY_LENGTH = 255;
const KEY_PATTERN = /^[A-Za-z0-9._:-]{8,255}$/;

export function validateIdempotencyKey(key: unknown): key is string {
  return typeof key === 'string' && key.length <= MAX_KEY_LENGTH && KEY_PATTERN.test(key);
}

export class IdempotencyGuard {
  readonly #store: IdempotencyStore;
  readonly #config: IdempotencyConfig;

  constructor(store: IdempotencyStore, config: IdempotencyConfig = { ttlSeconds: DEFAULT_IDEMPOTENCY_TTL_SECONDS, requiredFor: [] }) {
    this.#store = store;
    this.#config = config;
  }

  isRequired(path: string): boolean {
    return this.#config.requiredFor.includes(path);
  }

  /**
   * Run `handler` at most once per idempotency key.
   *
   * The handler is only invoked when this caller won the claim. Every other path
   * returns without calling it, which is the property that makes retries safe.
   */
  async execute(
    context: IdempotencyContext,
    handler: () => Promise<IdempotentResponse>,
  ): Promise<IdempotencyOutcome> {
    const { path, method, idempotencyKey, body } = context;

    if (idempotencyKey === undefined) {
      if (this.isRequired(path)) {
        throw new SecurityError('VALIDATION_FAILED', `Idempotency-Key is required for ${method} ${path}`, {
          publicMessage: 'This endpoint requires an Idempotency-Key header.',
        });
      }
      const response = await handler();
      return { kind: 'EXECUTED', response };
    }

    if (!validateIdempotencyKey(idempotencyKey)) {
      // Reject rather than normalise. Silently rewriting a key would let two
      // different keys collapse into one, or a malformed key bypass the layer.
      throw new SecurityError('VALIDATION_FAILED', 'Malformed Idempotency-Key', {
        publicMessage: 'Idempotency-Key is malformed.',
      });
    }

    const requestHash = fingerprintRequest({
      method,
      path,
      body,
      authenticatedUserId: context.authenticatedUserId,
    });

    const claim = await this.#store.claim({
      key: idempotencyKey,
      endpoint: path,
      requestHash,
      ttlSeconds: this.#config.ttlSeconds,
    });

    if (!claim.claimed) {
      if (claim.inFlight) return { kind: 'IN_FLIGHT' };
      if ('conflict' in claim && claim.conflict) return { kind: 'CONFLICT' };
      if ('record' in claim && claim.record) {
        return { kind: 'REPLAYED', response: claim.record.response as IdempotentResponse };
      }
      // Unreachable in practice; treat as in-flight rather than executing.
      return { kind: 'IN_FLIGHT' };
    }

    let response: IdempotentResponse;
    try {
      response = await handler();
    } catch (error) {
      // Record the failure so a retry under the same key replays the error
      // instead of re-running a payment that may already have been captured.
      const failure: IdempotentResponse = {
        status: error instanceof SecurityError ? error.status : 500,
        body: error instanceof SecurityError ? error.toPublicJSON() : { success: false, error: { code: 'INTERNAL_ERROR', message: 'Something went wrong. Please try again.' } },
      };
      await this.#store
        .complete({ key: idempotencyKey, endpoint: path, requestHash, claimId: claim.claimId, state: 'FAILED', response: failure })
        .catch(() => {
          // Best effort. A lost FAILED record means a retry re-executes, which is
          // the lesser evil compared to failing the original request after the
          // side effect already happened.
        });
      throw error;
    }

    await this.#store.complete({
      key: idempotencyKey,
      endpoint: path,
      requestHash,
      claimId: claim.claimId,
      state: 'SUCCESS',
      response,
    });

    return { kind: 'EXECUTED', response };
  }
}
